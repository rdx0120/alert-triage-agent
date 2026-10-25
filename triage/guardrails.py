"""The deterministic output guardrails: one agent run in, one TriageSummary out.

This stage runs after the agent loop and decides everything from the run
record (evidence log, tool views, evidence origin), never from message text.
It enforces:
  - fail-closed statuses: a run that did not complete, or whose draft fails
    the structure or citation re-check, keeps only code-owned findings;
  - the severity floor: the final severity is never below the rule's level;
  - the ATT&CK allow-list with evidence binding: a model technique is kept
    only if it is current in the local snapshot, was looked up and shown with
    its data in this run, and is cited by that lookup or, for the rule's own
    techniques, by the rule's tags;
  - code-owned asset facts and enrichment gaps: the model cannot change them;
  - absence provenance: a missing-data finding resting only on lookups the
    model made fail is dropped.
Every intervention is recorded as a fixed anomaly code. Whether free text
(rationale, steps, containment) follows from its sources is not checked here;
that is measured in evaluation.

Exceptions raised by this module's own code are not caught, as in enrich.py.
"""

from __future__ import annotations

from typing import get_args

from pydantic import ValidationError

from .citations import ALERT_FIELDS, _is_empty
from .config import Settings, get_settings
from .prompt import clean
from .schemas import (
    AgentResult, Alert, Anomaly, AssetFinding, ContainmentAction, MissingItem, ModelDraft, NextStep,
    SeverityFinding, SummaryStatus, TechniqueFinding, ToolResult, TriageSummary, severity_rank,
)
from .tools import build_tools
from .tools.attack import is_valid_technique
from .tools.registry import Tool

RAISED_RATIONALE = "Raised to the detection rule's level; the draft's severity was lower."
NO_DRAFT_RATIONALE = "No accepted draft; severity is the detection rule's level."

# The alert field each kind of gap depends on.
_GAP_FIELD = {"technique": "rule_tags", "runbook": "rule_tags", "asset": "host", "vulnerability": "cves"}
_CRITICALITY = get_args(AssetFinding.model_fields["criticality"].annotation)
_EXPOSURE = get_args(AssetFinding.model_fields["exposure"].annotation)


def _attack_lookup(results: list[ToolResult], technique_id: str) -> ToolResult | None:
    """The first ok attack_lookup result for technique_id, if any."""
    return next((r for r in results if r.tool == "attack_lookup" and r.status == "ok"
                 and r.data.get("technique_id") == technique_id), None)


def _name(result: ToolResult | None) -> str | None:
    name = result.data.get("name") if result is not None else None
    return clean(name) if isinstance(name, str) else None


def build_summary(result: AgentResult, alert: Alert, settings: Settings | None = None,
                  tools: dict[str, Tool] | None = None) -> TriageSummary:
    # Caller errors, not draft problems. The messages carry no value.
    if alert.alert_id != result.alert_id:
        raise ValueError("alert does not match the run's alert_id")
    if result.run_id is None:
        raise ValueError("result has no run_id")
    attack_path = (settings or get_settings()).data_dir / "attack_techniques.json"
    # The same allow-list rule as citations.citable_from_views(): a result
    # whose tool was not offered (the gateway's unknown-tool error) is never citable.
    allowed_tools = set(tools) if tools is not None else set(build_tools(settings))
    backend = result.backend.partition(":")[0]
    anomalies: set[str] = set()

    evidence = {r.evidence_id: r for r in result.evidence}
    # Visibility from the run's view records, never from message text. A
    # data_omitted stub ("omitted") or an unpacked result ("not_shown") showed no data.
    shown_with_data = {t.evidence_id for t in result.tool_records if t.view in ("full", "capped")}
    # Failed lookups reach the model through the enrichment view's gaps and resolutions.
    in_enrichment_view = ({g.evidence_id for g in result.enrichment.gaps if g.evidence_id is not None}
                          | {eid for res in result.enrichment.resolutions for eid in res.evidence_ids})

    def support(eid: str) -> bool:
        r = evidence.get(eid)
        return (r is not None and r.tool in allowed_tools and r.status == "ok"
                and eid in shown_with_data)

    def absence(eid: str) -> bool:
        r = evidence.get(eid)
        return (r is not None and r.tool in allowed_tools and r.status != "ok"
                and (eid in shown_with_data or eid in in_enrichment_view))

    def model_absence(eid: str) -> bool:
        r = evidence.get(eid)
        return r is not None and r.status != "ok" and result.evidence_origin.get(eid) == "model"

    allowed: dict[str, str] = {}  # current technique ID -> evidence ID of its shown ok lookup
    for r in result.evidence:
        tid = r.data.get("technique_id") if r.status == "ok" else None
        if (r.tool == "attack_lookup" and r.evidence_id in shown_with_data and isinstance(tid, str)
                and is_valid_technique(attack_path, tid)):
            allowed.setdefault(tid, r.evidence_id)
    rule_techniques = result.enrichment.techniques

    # Usable draft: structure, then the citation re-check against the run record.
    draft: ModelDraft | None = None
    if result.stop_reason != "completed":
        anomalies.add("draft_unavailable")
    elif not isinstance(result.draft, ModelDraft):
        anomalies.add("draft_invalid")
    else:
        # Revalidated because a result can be changed after the run without
        # validation (attribute assignment, model_copy).
        try:
            candidate = ModelDraft.model_validate(result.draft.model_dump())
        except ValidationError:
            anomalies.add("draft_invalid")
        else:
            if _citations_ok(candidate, alert, support, absence):
                draft = candidate
            else:
                anomalies.add("draft_citation_invalid")

    # Status.
    status: SummaryStatus
    if draft is not None:
        status = "triaged" if result.enrichment.status == "complete" else "insufficient_data"
    elif result.stop_reason == "budget_exceeded":
        status = "budget_exceeded"
    else:
        status = "error"

    # Severity floor: the model can raise severity, never lower it.
    if draft is None:
        severity = SeverityFinding(value=alert.rule_level, rule_floor=alert.rule_level, origin="rule",
                                   rationale=NO_DRAFT_RATIONALE, sources=["rule_level"])
    elif severity_rank(draft.severity.value) < severity_rank(alert.rule_level):
        anomalies.add("severity_raised_to_rule_floor")
        severity = SeverityFinding(value=alert.rule_level, rule_floor=alert.rule_level, origin="rule",
                                   rationale=RAISED_RATIONALE, sources=["rule_level"])
    else:
        severity = SeverityFinding(value=draft.severity.value, rule_floor=alert.rule_level, origin="model",
                                   rationale=clean(draft.severity.rationale),
                                   sources=list(draft.severity.sources))

    # Technique: allow-list and evidence binding, else the rule's technique.
    technique = None
    if draft is not None and draft.technique is not None:
        t, sources = draft.technique.technique_id, draft.technique.sources
        if not is_valid_technique(attack_path, t):
            anomalies.add("technique_not_current_attack")
        elif t not in allowed:
            anomalies.add("technique_not_looked_up")
        elif not (allowed[t] in sources or (t in rule_techniques and "rule_tags" in sources)):
            anomalies.add("technique_not_bound_to_evidence")
        else:
            technique = TechniqueFinding(
                technique_id=t, name=_name(evidence[allowed[t]]), origin="model",
                basis="rule_mapping" if t in rule_techniques else "lookup_only", sources=list(sources))
    if technique is None and rule_techniques:
        t = rule_techniques[0]
        # Enrichment lists a technique only if its attack_lookup was ok.
        lookup = _attack_lookup(result.enrichment.evidence, t)
        technique = TechniqueFinding(
            technique_id=t, name=_name(lookup), origin="rule", basis="rule_mapping",
            sources=["rule_tags"] + ([lookup.evidence_id] if lookup is not None else []))
    elif technique is None:
        technique = TechniqueFinding(technique_id=None, name=None, basis="none", origin="none")

    # Asset: code-owned, from the lookup of the alert's own host only.
    asset_result = next((r for r in result.evidence if r.tool == "asset_context" and r.status == "ok"
                         and r.args.get("host") == alert.host), None)
    if asset_result is not None:
        data = asset_result.data
        owner = data.get("owner")
        asset = AssetFinding(
            host=alert.host,
            criticality=data.get("criticality") if data.get("criticality") in _CRITICALITY else "unknown",
            exposure=data.get("exposure") if data.get("exposure") in _EXPOSURE else "unknown",
            # Cleaning keeps the summary serializable; it changes no provenance.
            owner=clean(owner) if isinstance(owner, str) else None,
            sources=[asset_result.evidence_id])
    else:
        asset = AssetFinding(host=alert.host, criticality="unknown", exposure="unknown")

    # Text and lists from the draft. Model text is copied only into these
    # fields and the severity rationale, always through clean().
    next_steps: list[NextStep] = []
    containment: list[ContainmentAction] = []
    if draft is not None:
        next_steps = [NextStep(step=clean(s.step), sources=list(s.sources)) for s in draft.next_steps]
        containment = [ContainmentAction(action=clean(c.action), sources=list(c.sources))
                       for c in draft.containment]

    # Missing data: every enrichment gap from code, then the model's own items.
    missing = [
        MissingItem(kind=gap.kind, description=f"{gap.kind}: {gap.reason.replace('_', ' ')}",
                    origin="enrichment",
                    sources=([gap.evidence_id] if gap.evidence_id is not None else []) + [_GAP_FIELD[gap.kind]])
        for gap in result.enrichment.gaps
    ]
    code_owned = {(m.kind, m.description) for m in missing}
    if draft is not None:
        for item in draft.missing_data:
            # A lookup the model made fail is not evidence that data is missing.
            if all(s not in ALERT_FIELDS and model_absence(s) for s in item.sources):
                anomalies.add("missing_data_model_absence_only")
                continue
            description = clean(item.description)
            if (item.kind, description) in code_owned:
                continue
            missing.append(MissingItem(kind=item.kind, description=description, origin="model",
                                       sources=list(item.sources)))

    return TriageSummary(
        alert_id=alert.alert_id, run_id=result.run_id, status=status,
        backend=backend if backend in ("ollama", "heuristic") else "unknown",
        severity=severity, technique=technique, asset=asset, next_steps=next_steps,
        containment=containment, missing_data=missing,
        anomalies=[a for a in get_args(Anomaly) if a in anomalies])


def _citations_ok(draft: ModelDraft, alert: Alert, support, absence) -> bool:
    """Every source of the draft is citable for its finding in this run.

    Asserting findings need an alert field with a value or evidence shown with
    its data; missing_data may also cite any alert field or a failed lookup
    the model was shown.
    """
    asserting = [draft.technique, draft.severity, *draft.next_steps, *draft.containment]
    for finding in asserting:
        if finding is None:
            continue
        for s in finding.sources:
            citable = not _is_empty(getattr(alert, s)) if s in ALERT_FIELDS else support(s)
            if not citable:
                return False
    for finding in draft.missing_data:
        for s in finding.sources:
            if not (s in ALERT_FIELDS or support(s) or absence(s)):
                return False
    return True
