"""The agent loop: one run of one alert against one backend.

The loop owns the limits, the tool dispatch and the validation; a backend only
answers one request at a time. A run has two phases: investigation turns in
which the model may request read-only lookups through the run's evidence log,
then a final call without tools whose reply must match ModelDraft and cite
only evidence the run showed the model (triage.citations), with one repair
attempt. The result is a draft, never a verdict: only the later guardrail
stage may turn it into a TriageSummary.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Callable

from pydantic import ValidationError

from .backends.base import Backend, BackendError, ChatReply, ChatRequest, ToolCall, serialize_request
from .citations import EMPTY_FIELD, UNCITABLE, Citable, check_citations, citable_from_views, generator_schema
from .config import Settings
from .enrich import enrich
from .evidence import EvidenceLog
from .prompt import (
    CONTEXT_TOKENS, FINAL_INSTRUCTION, HINT_EMPTY_FIELD, HINT_KEEP, HINT_SOURCE_FORM,
    HINT_SOURCES_REQUIRED, HINT_UNCITABLE, INVESTIGATION_INSTRUCTION, INVESTIGATION_MAX_OUTPUT_TOKENS,
    MAX_OUTPUT_TOKENS, REPAIR_TEMPLATE, TOOL_RESULT_MAX_BYTES,
    dumps, enrichment_view, fits, initial_messages, render_assistant, render_result, token_bound,
    tool_specs,
)
from .schemas import (
    Alert, AgentResult, DraftContainment, DraftMissing, DraftSeverity, DraftSources, DraftStep,
    DraftTechnique, EvidenceOrigin, ModelCallRecord, ModelDraft, ModelPhase, StopReason,
)
from .tools import build_tools
from .tools.registry import Tool

RESERVED_FINAL_CALLS = 2  # the final call and one repair
MAX_PROBLEMS = 10

# The gateway echoes unknown names in its error, and names become part of
# evidence IDs and the history, so only this fixed shape is passed on.
_TOOL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_DRAFT_FIELDS = frozenset().union(*(
    m.model_fields for m in (ModelDraft, DraftTechnique, DraftSeverity, DraftStep,
                             DraftContainment, DraftMissing, DraftSources)))


@dataclass(frozen=True)
class Limits:
    # Values may be lowered (evaluation ablations), never raised: the
    # worst-case budget test is computed for these maxima.
    max_model_calls: int = 6
    max_tool_calls: int = 6
    max_tool_calls_per_turn: int = 3
    run_timeout_s: float = 900.0
    request_timeout_s: float = 300.0

    def __post_init__(self) -> None:
        if not (2 <= self.max_model_calls <= 6 and 0 <= self.max_tool_calls <= 6
                and 1 <= self.max_tool_calls_per_turn <= 3
                and self.run_timeout_s > 0 and self.request_timeout_s > 0):
            raise ValueError("limits may be lowered from their defaults, never raised")

    @property
    def max_investigation_turns(self) -> int:
        return 0 if self.max_tool_calls == 0 else self.max_model_calls - RESERVED_FINAL_CALLS


class _Stop(Exception):
    def __init__(self, reason: StopReason) -> None:
        self.reason = reason


def normalize_call(call: ToolCall) -> ToolCall:
    """The only form of a model's tool call that the loop uses."""
    name = call.name if isinstance(call.name, str) and _TOOL_NAME.fullmatch(call.name) else "invalid_tool_name"
    arguments = call.arguments
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
        except (ValueError, RecursionError):
            parsed = None
        if isinstance(parsed, dict):
            arguments = parsed
    # Anything that is still not a dict goes to the gateway unchanged, which
    # returns invalid_input.
    return ToolCall(name=name, arguments=arguments)


def _structural_problems(error: ValidationError) -> list[str]:
    # Field names chosen by the model may be copied from alert text, so only
    # our own field names, list indexes and Pydantic's fixed error codes are kept.
    problems = []
    for err in error.errors():
        path = ".".join(str(p) if isinstance(p, int) or p in _DRAFT_FIELDS else "<unknown>"
                        for p in err["loc"])
        problems.append(f"{path or '(root)'}: {err['type']}")
    return problems


def cap_problems(problems: list[str]) -> list[str]:
    """At most MAX_PROBLEMS problems, then a count of the rest."""
    if len(problems) > MAX_PROBLEMS:
        return problems[:MAX_PROBLEMS] + [f"and {len(problems) - MAX_PROBLEMS} more"]
    return problems


def sanitized_problems(error: ValidationError) -> list[str]:
    """Validation problems that are safe to send back to the model, capped."""
    return cap_problems(_structural_problems(error))


def repair_message(problems: list[str]) -> str:
    """The repair request: the capped problems, then the hints they trigger and HINT_KEEP.

    Each hint is our own fixed text, included once if any problem's path and
    code trigger it; nothing from the failed reply is echoed.
    """
    pairs = [(path, code) for path, _, code in (p.rpartition(": ") for p in problems)]
    triggered = [
        (HINT_SOURCES_REQUIRED,
         any(path.endswith(".sources") and code in ("missing", "too_short") for path, code in pairs)),
        (HINT_SOURCE_FORM,
         any(".sources." in path and code not in (UNCITABLE, EMPTY_FIELD) for path, code in pairs)),
        (HINT_UNCITABLE, any(code == UNCITABLE for _, code in pairs)),
        (HINT_EMPTY_FIELD, any(code == EMPTY_FIELD for _, code in pairs)),
    ]
    hints = [hint for hint, hit in triggered if hit] + [HINT_KEEP]
    return REPAIR_TEMPLATE.format(problems="; ".join(cap_problems(problems)), hints=" ".join(hints))


def finding_counts(text: str) -> dict[str, int] | None:
    """Findings per kind in a final or repair reply, parsed leniently.

    For observability and evaluation only (did a repair drop findings?);
    never used to accept or reject a reply.
    """
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(parsed, dict):
        return None
    counts = {"technique": 1 if parsed.get("technique") is not None else 0,
              "severity": 1 if parsed.get("severity") is not None else 0}
    for key in ("next_steps", "containment", "missing_data"):
        value = parsed.get(key)
        counts[key] = len(value) if isinstance(value, list) else 0
    return counts


def run_agent(alert: Alert, backend: Backend, *, settings: Settings | None = None,
              tools: dict[str, Tool] | None = None, limits: Limits | None = None,
              clock: Callable[[], float] = time.monotonic) -> AgentResult:
    limits = limits or Limits()
    start = clock()
    tools = tools or build_tools(settings)
    log = EvidenceLog(tools)
    enrichment = enrich(alert, log, settings)
    evidence_origin: dict[str, EvidenceOrigin] = {r.evidence_id: "enrichment" for r in log.results}
    messages = initial_messages(alert, enrichment)
    # What the model is shown, kept as objects so citability never depends on
    # parsing message text. enrichment_view() is a pure function of the
    # enrichment, so this is the view serialized into the user message.
    view = enrichment_view(enrichment)
    tool_renders: list[dict] = []
    model_calls: list[ModelCallRecord] = []
    tool_calls_run = 0
    validation_errors: list[str] = []

    def chat(phase: ModelPhase, specs: list[dict] | None, schema: dict | None,
             citable: Citable | None = None) -> ChatReply:
        # A request gets no more than the time left in the run, and a call that
        # ends after the run deadline stops the run, whatever it returned.
        remaining = limits.run_timeout_s - (clock() - start)
        request_messages, max_output_tokens = list(messages), MAX_OUTPUT_TOKENS
        if phase == "investigate":
            # The instruction is added to this request only, never to the
            # stored history: each investigation request carries one copy, at
            # the end, and final and repair requests carry none, so their
            # content and context budget are unchanged.
            request_messages.append({"role": "user", "content": INVESTIGATION_INSTRUCTION})
            max_output_tokens = INVESTIGATION_MAX_OUTPUT_TOKENS
        request = ChatRequest(
            messages=request_messages, tools=specs, response_schema=schema,
            max_output_tokens=max_output_tokens, context_tokens=CONTEXT_TOKENS,
            timeout_s=min(limits.request_timeout_s, remaining), alert=alert, enrichment=enrichment,
            citable=citable)
        # Preflight: never send a request after the deadline or one that would
        # not fit; Ollama would truncate it with only a server-side warning.
        if remaining <= 0 or not fits(request):
            raise _Stop("budget_exceeded")
        record = ModelCallRecord(phase=phase, request_bytes=len(serialize_request(request)),
                                 token_bound=token_bound(request), input_tokens=None, output_tokens=None)
        model_calls.append(record)
        try:
            reply = backend.chat(request)
        except BackendError:
            # Recorded as a stop reason only; the message is not kept. No retry.
            late = clock() - start >= limits.run_timeout_s
            raise _Stop("budget_exceeded" if late else "backend_error") from None
        record.input_tokens, record.output_tokens = reply.input_tokens, reply.output_tokens
        # Observational only: the loop's control flow, acceptance and stop
        # reasons never depend on it, and a truncated reply is not treated as
        # a lost tool call.
        record.truncated = reply.truncated
        if clock() - start >= limits.run_timeout_s:
            raise _Stop("budget_exceeded")  # the reply is discarded
        return reply

    def result(stop_reason: StopReason, draft: ModelDraft | None = None) -> AgentResult:
        return AgentResult(
            alert_id=alert.alert_id, backend=backend.name, stop_reason=stop_reason, draft=draft,
            enrichment=enrichment, evidence=log.results, evidence_origin=evidence_origin,
            model_calls=model_calls, tool_calls=tool_calls_run, validation_errors=validation_errors)

    try:
        # Investigation. A reply without tool calls ends it; its text is discarded.
        specs = tool_specs(tools)
        turns = 0
        while turns < limits.max_investigation_turns and tool_calls_run < limits.max_tool_calls:
            turns += 1
            reply = chat("investigate", specs, None)
            if not reply.tool_calls:
                break
            room = min(limits.max_tool_calls_per_turn, limits.max_tool_calls - tool_calls_run)
            # Normalize first; the raw names and arguments are not used after this.
            accepted = [normalize_call(c) for c in reply.tool_calls[:room]]
            record = model_calls[-1]
            record.tool_calls_requested = len(reply.tool_calls)
            record.tool_calls_run = len(accepted)
            # Dropped calls are not run and not added to the history.
            record.tool_calls_dropped = len(reply.tool_calls) - len(accepted)
            messages.append(render_assistant(accepted))
            for call in accepted:
                found = log.call(call.name, call.arguments)
                # A repeat of an enrichment lookup keeps "enrichment".
                evidence_origin.setdefault(found.evidence_id, "model")
                tool_calls_run += 1  # repeats served from the log count too
                rendered = render_result(found, TOOL_RESULT_MAX_BYTES)
                tool_renders.append(rendered)
                messages.append({"role": "tool", "tool_name": call.name, "content": dumps(rendered)})

        # Final call, then one repair. Tool calls in these replies are ignored.
        # No lookups happen after this point, so one citable set serves both.
        messages.append({"role": "user", "content": FINAL_INSTRUCTION})
        citable = citable_from_views(view, tool_renders, log.results, set(tools))
        schema = generator_schema(citable)
        for phase in ("final", "repair"):
            reply = chat(phase, None, schema, citable)
            model_calls[-1].finding_counts = finding_counts(reply.text)
            # A reply is accepted only if its structure is valid and every
            # citation is eligible; there is no partial acceptance.
            try:
                draft = ModelDraft.model_validate_json(reply.text)
            except ValidationError as e:
                problems = _structural_problems(e)
            else:
                problems = check_citations(draft, citable, alert)
                if not problems:
                    return result("completed", draft)
            validation_errors = cap_problems(problems)
            if phase == "final":
                # The failed reply itself is not added to the history.
                messages.append({"role": "user", "content": repair_message(problems)})
        return result("invalid_output")
    except _Stop as stop:
        return result(stop.reason)
