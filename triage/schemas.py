"""Data shapes for everything that crosses a trust boundary.

Three boundaries, three models:
  Alert         untrusted input from the SIEM
  ToolResult    what a read-only tool returned (trusted, but may be empty)
  TriageSummary the final output, after code-enforced guardrails

Pydantic does the validation; `extra="forbid"` means an unexpected field is
an error, not something silently ignored.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --- Severity ------------------------------------------------------------

Severity = Literal["informational", "low", "medium", "high", "critical"]
SEVERITY_ORDER: list[str] = ["informational", "low", "medium", "high", "critical"]


def severity_rank(s: str) -> int:
    return SEVERITY_ORDER.index(s)


def max_severity(a: str, b: str) -> str:
    """Higher of two severities. Used for policy floors: the LLM can raise, never lower."""
    return a if severity_rank(a) >= severity_rank(b) else b


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- Input ---------------------------------------------------------------

TECHNIQUE_ID_PATTERN = r"^T\d{4}(\.\d{3})?$"
CVE_PATTERN = r"^CVE-\d{4}-\d{4,7}$"
HOST_PATTERN = r"^[A-Za-z0-9._-]{1,64}$"
ALERT_ID_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"

# Raw event fields are attacker-influenced strings. Cap their size so one
# huge command line can't blow the token budget.
MAX_FIELD_CHARS = 4096


class Alert(Strict):
    """Canonical alert. Wazuh / Sigma-style inputs are normalized into this."""

    alert_id: str = Field(pattern=ALERT_ID_PATTERN)
    source: Literal["sigma", "wazuh", "cloudtrail", "synthetic"]
    rule_id: str = Field(min_length=1, max_length=128)
    rule_title: str = Field(max_length=256)
    rule_level: Severity
    rule_tags: list[str] = Field(default_factory=list, max_length=20)
    host: str | None = Field(default=None, max_length=64)
    user: str | None = Field(default=None, max_length=256)
    timestamp: str | None = Field(default=None, max_length=64)
    cves: list[str] = Field(default_factory=list, max_length=20)
    # The raw event. Values only; everything in here is treated as untrusted data.
    event: dict[str, str | int | float | bool | None] = Field(default_factory=dict, max_length=50)
    # Problems found while normalizing; fixed-template messages that name a
    # known field, never its value.
    ingest_warnings: list[str] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def _cap_event_values(self) -> "Alert":
        for k, v in self.event.items():
            if isinstance(v, str) and len(v) > MAX_FIELD_CHARS:
                self.event[k] = v[:MAX_FIELD_CHARS] + "...[truncated]"
        return self

    def attack_tags(self) -> list[str]:
        """Technique IDs from Sigma-style tags: 'attack.t1059.001' -> 'T1059.001'."""
        out = []
        for t in self.rule_tags:
            t = t.lower()
            if t.startswith("attack.t") and t[8:9].isdigit():
                out.append(t.removeprefix("attack.").upper())
        return out


# --- Tool results --------------------------------------------------------

ToolStatus = Literal["ok", "not_found", "invalid_input", "error"]


class ToolResult(Strict):
    """Every tool call returns one of these, logged with a stable evidence ID.

    Invariant: status "ok" always carries data; any other status carries none.
    An empty answer is never "ok", so silence can't pass as success.
    """

    evidence_id: str
    tool: str
    args: dict[str, Any]
    status: ToolStatus
    data: dict[str, Any] | None = None
    error: str | None = None

    @model_validator(mode="after")
    def _status_matches_data(self) -> "ToolResult":
        if self.status == "ok" and not self.data:
            raise ValueError("status 'ok' requires non-empty data")
        if self.status != "ok" and self.data is not None:
            raise ValueError(f"status '{self.status}' must not carry data")
        return self


# --- Enrichment ----------------------------------------------------------

GapKind = Literal["technique", "asset", "vulnerability", "runbook"]
GapReason = Literal["not_on_alert", "not_found", "over_cap", "lookup_failed", "invalid_input"]


class Gap(Strict):
    """Something enrichment could not determine.

    kind and reason are fixed enums and evidence_id is our own identifier, so
    no alert text can reach later stages through a gap.
    """

    kind: GapKind
    reason: GapReason
    evidence_id: str | None = None   # the lookup that produced the gap, if any


class TechniqueResolution(Strict):
    requested: str = Field(pattern=TECHNIQUE_ID_PATTERN)   # retired ID from the alert
    resolved: str = Field(pattern=TECHNIQUE_ID_PATTERN)    # current replacement
    evidence_ids: list[str]                                 # both lookups


class Enrichment(Strict):
    alert_id: str
    status: Literal["complete", "degraded"]
    techniques: list[str]                  # current ATT&CK IDs with an ok lookup, alert order, unique
    resolutions: list[TechniqueResolution] = []
    runbook_query: str | None = None       # built from ATT&CK lookup results only
    evidence: list[ToolResult]             # every lookup, in call order, unique evidence IDs
    gaps: list[Gap] = []


# --- Model draft and agent run ---------------------------------------------

# Our own evidence IDs: a tool name and 16 hex digits (registry.evidence_id).
EVIDENCE_ID_PATTERN = r"^[a-z][a-z0-9_]{0,63}:[0-9a-f]{16}$"
AlertField = Literal["rule_id", "rule_level", "rule_tags", "rule_title",
                     "host", "user", "timestamp", "cves", "event"]

EvidenceIdStr = Annotated[str, Field(pattern=EVIDENCE_ID_PATTERN)]

# Must be at least the number of gaps enrichment can produce, so the rule-based
# baseline can report every gap even when all lookups fail.
MAX_MISSING_DATA = 16


# Structure only: an alert-field name or a string shaped like an evidence ID.
Source = Union[AlertField, EvidenceIdStr]

# Up to 10 evidence IDs plus the 9 alert fields.
MAX_SOURCES = 19


class DraftSources(Strict):
    """What a finding relies on: evidence IDs, alert-field names, or both.

    Structure only: whether a source is eligible for this run is decided by
    triage.citations.check_citations, which the agent loop applies to every
    final and repair reply.
    """

    sources: list[Source] = Field(min_length=1, max_length=MAX_SOURCES)


class DraftTechnique(DraftSources):
    technique_id: str = Field(pattern=TECHNIQUE_ID_PATTERN)


class DraftSeverity(DraftSources):
    value: Severity
    rationale: str = Field(max_length=600)


class DraftStep(DraftSources):
    step: str = Field(max_length=300)


class DraftContainment(DraftSources):
    action: str = Field(max_length=300)
    # Literal[True]: a False here fails validation. The model can suggest, never approve.
    requires_human_approval: Literal[True] = True


class DraftMissing(DraftSources):
    kind: Literal["technique", "asset", "vulnerability", "runbook", "other"]
    description: str = Field(max_length=200)


class ModelDraft(Strict):
    """What a backend returns for one alert: unchecked model output.

    It has no field that closes, dismisses or approves anything. Only the
    later guardrail stage may turn it into a TriageSummary.
    """

    technique: DraftTechnique | None = None
    severity: DraftSeverity
    next_steps: list[DraftStep] = Field(max_length=8)
    containment: list[DraftContainment] = Field(max_length=5)
    missing_data: list[DraftMissing] = Field(max_length=MAX_MISSING_DATA)


StopReason = Literal["completed", "budget_exceeded", "backend_error", "invalid_output"]
EvidenceOrigin = Literal["enrichment", "model"]
ModelPhase = Literal["investigate", "final", "repair"]
FinishReason = Literal["stop", "length", "other"]
ReplyKind = Literal["tool_calls", "text", "empty"]
# Why a backend call raised. Closed list; anything else is "_OTHER"
# (OpenTelemetry's fallback). Never the error message.
BackendErrorType = Literal["timeout", "connection_failed", "http_status", "response_too_large",
                           "malformed_response", "server_error", "workers_busy",
                           "worker_start_failed", "_OTHER"]
ToolView = Literal["full", "capped", "omitted", "not_shown"]
BudgetDetail = Literal["deadline_before_request", "request_over_context_budget",
                       "deadline_during_request", "deadline_after_reply"]
SHA256_PATTERN = r"^[0-9a-f]{64}$"
RUN_ID_PATTERN = r"^[0-9a-f]{32}$"


class ModelCallRecord(Strict):
    phase: ModelPhase
    request_bytes: int          # len(serialize_request(request)), the bytes sent
    token_bound: int            # upper bound on the request's tokens
    input_tokens: int | None    # as reported by the backend, if it reports them
    output_tokens: int | None
    tool_calls_requested: int = 0
    tool_calls_run: int = 0
    tool_calls_dropped: int = 0
    finding_counts: dict[str, int] | None = None  # final and repair replies; for evaluation only
    truncated: bool = False     # the reply stopped at its output limit; for evaluation only
    turn: int | None = None                  # investigation turn, 1-based; None for final/repair
    start_s: float | None = None             # offset from run start, observational timer
    duration_s: float | None = None          # duration of backend.chat()
    # Digest of the serialize_request() bytes only (messages, tools, schema),
    # not the full HTTP body, which also carries the model and options.
    request_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    finish_reason: FinishReason | None = None
    reply: ReplyKind | None = None           # None when backend.chat() raised
    reply_text_bytes: int | None = None      # size only, never the text
    # Digest of the reply text only; tool calls are not covered, so tool-only
    # replies with empty text all share the empty-string digest.
    reply_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    accepted: bool | None = None             # final/repair: passed validation and citation checks
    problems: list[str] | None = None        # final/repair: sanitized, capped; [] when accepted
    error_type: BackendErrorType | None = None


class ToolCallRecord(Strict):
    """One lookup the run made, as metadata: never its arguments or data."""
    evidence_id: str = Field(pattern=EVIDENCE_ID_PATTERN)
    # As recorded by the gateway: the loop's normalized name, so an
    # unoffered name the model asked for is kept but shape-limited.
    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    requested_by: EvidenceOrigin      # who asked for this call
    status: ToolStatus
    turn: int                         # 0 for enrichment, else the investigation turn
    repeat: bool = False              # served from the evidence log, not run again
    start_s: float | None = None      # model-requested calls only
    duration_s: float | None = None
    view: ToolView
    view_string_cap: int | None = None   # byte cap applied to its strings
    view_strings_cut: int | None = None  # strings that cap shortened
    view_bytes: int | None = None        # size of the view, as the budget measures it


class AgentResult(Strict):
    alert_id: str
    backend: str
    stop_reason: StopReason
    draft: ModelDraft | None
    enrichment: Enrichment
    evidence: list[ToolResult]                  # every lookup of the run, call order
    evidence_origin: dict[str, EvidenceOrigin]  # evidence ID -> who asked for it
    model_calls: list[ModelCallRecord]
    tool_calls: int
    validation_errors: list[str] = []           # sanitized paths from the last failed validation
    run_id: str | None = Field(default=None, pattern=RUN_ID_PATTERN)
    started_at: str | None = None            # UTC, ISO 8601 with milliseconds, "Z" suffix
    duration_s: float | None = None
    enrichment_duration_s: float | None = None
    model: str | None = None                 # the backend's model name, if it has one
    budget_detail: BudgetDetail | None = None   # set only when stop_reason is budget_exceeded
    tool_records: list[ToolCallRecord] = []

    @model_validator(mode="after")
    def _draft_only_when_completed(self) -> "AgentResult":
        if (self.draft is not None) != (self.stop_reason == "completed"):
            raise ValueError("a draft is present if and only if stop_reason is 'completed'")
        return self

    @model_validator(mode="after")
    def _budget_detail_only_on_budget_stop(self) -> "AgentResult":
        # run_agent always sets one on a budget stop; this rejects the reverse.
        if self.budget_detail is not None and self.stop_reason != "budget_exceeded":
            raise ValueError("budget_detail is set only when stop_reason is 'budget_exceeded'")
        return self


# --- Output --------------------------------------------------------------

# What supports a technique label, never whether the behaviour happened:
# rule_mapping = the detection rule's own ATT&CK mapping, resolved to a
# current technique; lookup_only = model-proposed, backed only by a lookup
# the model requested; none = no supported technique.
TechniqueBasis = Literal["rule_mapping", "lookup_only", "none"]
FindingOrigin = Literal["rule", "model", "none"]
MissingOrigin = Literal["enrichment", "model"]
SummaryStatus = Literal["triaged", "insufficient_data", "budget_exceeded", "error"]
# Fixed order: anomalies are listed in this order, each at most once.
Anomaly = Literal["draft_unavailable", "draft_invalid", "draft_citation_invalid",
                  "severity_raised_to_rule_floor",
                  "technique_not_current_attack", "technique_not_looked_up",
                  "technique_not_bound_to_evidence", "missing_data_model_absence_only"]


class SeverityFinding(Strict):
    value: Severity
    rule_floor: Severity       # the detection rule's level; value is never below it
    origin: Literal["rule", "model"]
    rationale: str = Field(max_length=600)
    sources: list[Source] = Field(max_length=MAX_SOURCES)


class TechniqueFinding(Strict):
    technique_id: str | None = Field(default=None, pattern=TECHNIQUE_ID_PATTERN)
    name: str | None = None    # from the local ATT&CK snapshot, never the model
    basis: TechniqueBasis
    origin: FindingOrigin
    sources: list[Source] = Field(default_factory=list, max_length=MAX_SOURCES)


class AssetFinding(Strict):
    # Every field comes from the asset lookup, never the model.
    host: str | None
    criticality: Literal["low", "medium", "high", "critical", "unknown"]
    exposure: Literal["internal", "internet-facing", "unknown"]
    owner: str | None = None
    sources: list[Source] = Field(default_factory=list, max_length=MAX_SOURCES)


class NextStep(Strict):
    step: str = Field(max_length=300)
    sources: list[Source] = Field(min_length=1, max_length=MAX_SOURCES)


class ContainmentAction(Strict):
    action: str = Field(max_length=300)
    sources: list[Source] = Field(default_factory=list, max_length=MAX_SOURCES)
    # Literal[True]: a False here fails validation. The agent can suggest, never approve.
    requires_human_approval: Literal[True] = True


class MissingItem(Strict):
    kind: Literal["technique", "asset", "vulnerability", "runbook", "other"]
    description: str = Field(max_length=200)
    origin: MissingOrigin
    sources: list[Source] = Field(default_factory=list, max_length=MAX_SOURCES)


class TriageSummary(Strict):
    """The output after code-enforced guardrails (triage.guardrails).

    Every finding records whether it came from the rule, from enrichment or
    from the model. Severity is never below the rule's level, asset facts
    and enrichment gaps come only from code, and containment always needs
    human approval.
    """
    alert_id: str = Field(pattern=ALERT_ID_PATTERN)
    run_id: str = Field(pattern=RUN_ID_PATTERN)
    status: SummaryStatus
    backend: Literal["ollama", "heuristic", "unknown"]
    severity: SeverityFinding
    technique: TechniqueFinding
    asset: AssetFinding
    next_steps: list[NextStep] = Field(default_factory=list)
    containment: list[ContainmentAction] = Field(default_factory=list)
    missing_data: list[MissingItem] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)
    injection_suspected: bool = False   # set by the planned tripwire (G2); always False until then
