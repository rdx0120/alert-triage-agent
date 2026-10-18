"""The agent loop: one run of one alert against one backend.

The loop owns the limits, the tool dispatch and the validation; a backend only
answers one request at a time. A run has two phases: investigation turns in
which the model may request read-only lookups through the run's evidence log,
then a final call without tools whose reply must match ModelDraft, with one
repair attempt. The result is a draft, never a verdict: only the later
guardrail stage may turn it into a TriageSummary.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Callable

from pydantic import ValidationError

from .backends.base import Backend, BackendError, ChatReply, ChatRequest, ToolCall, serialize_request
from .config import Settings
from .enrich import enrich
from .evidence import EvidenceLog
from .prompt import (
    CONTEXT_TOKENS, FINAL_INSTRUCTION, MAX_OUTPUT_TOKENS, REPAIR_TEMPLATE, TOOL_RESULT_MAX_BYTES,
    dumps, fits, initial_messages, render_assistant, render_result, token_bound, tool_specs,
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


def sanitized_problems(error: ValidationError) -> list[str]:
    """Validation problems that are safe to send back to the model.

    Field names chosen by the model may be copied from alert text, so only our
    own field names, list indexes and Pydantic's fixed error codes are echoed.
    """
    problems = []
    for err in error.errors():
        path = ".".join(str(p) if isinstance(p, int) or p in _DRAFT_FIELDS else "<unknown>"
                        for p in err["loc"])
        problems.append(f"{path or '(root)'}: {err['type']}")
    if len(problems) > MAX_PROBLEMS:
        problems = problems[:MAX_PROBLEMS] + [f"and {len(problems) - MAX_PROBLEMS} more"]
    return problems


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
    model_calls: list[ModelCallRecord] = []
    tool_calls_run = 0
    validation_errors: list[str] = []

    def chat(phase: ModelPhase, specs: list[dict] | None, schema: dict | None) -> ChatReply:
        request = ChatRequest(
            messages=list(messages), tools=specs, response_schema=schema,
            max_output_tokens=MAX_OUTPUT_TOKENS, context_tokens=CONTEXT_TOKENS,
            timeout_s=limits.request_timeout_s, alert=alert, enrichment=enrichment)
        # Preflight: never send a request after the deadline or one that would
        # not fit; Ollama would truncate it with only a server-side warning.
        if clock() - start >= limits.run_timeout_s or not fits(request):
            raise _Stop("budget_exceeded")
        record = ModelCallRecord(phase=phase, request_bytes=len(serialize_request(request)),
                                 token_bound=token_bound(request), input_tokens=None, output_tokens=None)
        model_calls.append(record)
        try:
            reply = backend.chat(request)
        except BackendError:
            # Recorded as a stop reason only; the message is not kept. No retry.
            raise _Stop("backend_error") from None
        record.input_tokens, record.output_tokens = reply.input_tokens, reply.output_tokens
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
                messages.append({"role": "tool", "tool_name": call.name,
                                 "content": dumps(render_result(found, TOOL_RESULT_MAX_BYTES))})

        # Final call, then one repair. Tool calls in these replies are ignored.
        messages.append({"role": "user", "content": FINAL_INSTRUCTION})
        schema = ModelDraft.model_json_schema()
        for phase in ("final", "repair"):
            reply = chat(phase, None, schema)
            try:
                draft = ModelDraft.model_validate_json(reply.text)
            except ValidationError as e:
                validation_errors = sanitized_problems(e)
            else:
                return result("completed", draft)
            if phase == "final":
                # The failed reply itself is not added to the history.
                messages.append({"role": "user",
                                 "content": REPAIR_TEMPLATE.format(problems="; ".join(validation_errors))})
        return result("invalid_output")
    except _Stop as stop:
        return result(stop.reason)
