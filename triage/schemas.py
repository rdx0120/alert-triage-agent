"""Data shapes for everything that crosses a trust boundary.

Three boundaries, three models:
  Alert         untrusted input from the SIEM
  ToolResult    what a read-only tool returned (trusted, but may be empty)
  TriageSummary the final output, after code-enforced guardrails

Pydantic does the validation; `extra="forbid"` means an unexpected field is
an error, not something silently ignored.
"""

from __future__ import annotations

from typing import Any, Literal

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


# --- Output --------------------------------------------------------------

Confidence = Literal["confirmed", "likely", "unknown"]


class TechniqueFinding(Strict):
    technique_id: str | None = Field(default=None, pattern=TECHNIQUE_ID_PATTERN)
    name: str | None = None
    confidence: Confidence
    evidence_ids: list[str] = Field(default_factory=list)


class SeverityFinding(Strict):
    value: Severity
    rule_floor: Severity  # set by code from the detection rule; the final value is never below it
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)


class AssetFinding(Strict):
    host: str | None
    criticality: Literal["low", "medium", "high", "critical", "unknown"]
    exposure: Literal["internal", "internet-facing", "unknown"]
    owner: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class NextStep(Strict):
    step: str
    evidence_ids: list[str] = Field(default_factory=list)


class ContainmentAction(Strict):
    action: str
    # Literal[True]: a False here fails validation. The agent can suggest, never approve.
    requires_human_approval: Literal[True] = True


class TriageSummary(Strict):
    alert_id: str
    status: Literal["triaged", "insufficient_data", "budget_exceeded", "error"]
    plan: str = ""
    technique: TechniqueFinding
    severity: SeverityFinding
    asset: AssetFinding
    next_steps: list[NextStep] = Field(default_factory=list)
    containment: list[ContainmentAction] = Field(default_factory=list)
    missing_data: list[str] = Field(default_factory=list)
    injection_suspected: bool = False
    anomalies: list[str] = Field(default_factory=list)
    model: str = ""
