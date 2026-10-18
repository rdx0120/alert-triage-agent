"""The rule-based baseline (DD-008), as a backend.

It reads only request.alert and request.enrichment, never the prompt, so alert
text addressed to a model cannot change its answer. It requests no tools,
takes the technique from enrichment and the severity from the rule level, and
reports every enrichment gap as missing data.

Every source it cites is checkable: an evidence ID against the run's log and
an alert field against the alert, including absence (no host, no CVEs).
"""

from __future__ import annotations

from ..schemas import (
    DraftMissing, DraftSeverity, DraftStep, DraftTechnique, Enrichment, ModelDraft,
)
from .base import ChatReply, ChatRequest

# The alert field each kind of gap depends on.
_GAP_FIELD = {"technique": "rule_tags", "runbook": "rule_tags", "asset": "host", "vulnerability": "cves"}


class HeuristicBackend:
    name = "heuristic"

    def chat(self, request: ChatRequest) -> ChatReply:
        if request.response_schema is None:
            return ChatReply()  # investigation turn: no tool calls
        draft = _draft(request.alert.rule_level, request.enrichment)
        return ChatReply(text=draft.model_dump_json())


def _draft(rule_level: str, enrichment: Enrichment) -> ModelDraft:
    technique = None
    if enrichment.techniques:
        tid = enrichment.techniques[0]
        # Enrichment lists a technique only if its attack_lookup was ok.
        lookup = next(r for r in enrichment.evidence
                      if r.tool == "attack_lookup" and r.status == "ok"
                      and r.args.get("technique_id") == tid)
        technique = DraftTechnique(technique_id=tid, evidence_ids=[lookup.evidence_id],
                                   alert_fields=["rule_tags"])

    next_steps = []
    runbook = next((r for r in enrichment.evidence
                    if r.tool == "runbook_search" and r.status == "ok"), None)
    if runbook is not None:
        next_steps.append(DraftStep(
            step=f"Follow the triage steps in runbook {runbook.data['hits'][0]['runbook']}.",
            evidence_ids=[runbook.evidence_id]))

    missing = [
        DraftMissing(kind=gap.kind, description=f"{gap.kind}: {gap.reason.replace('_', ' ')}",
                     evidence_ids=[gap.evidence_id] if gap.evidence_id else [],
                     alert_fields=[_GAP_FIELD[gap.kind]])
        for gap in enrichment.gaps
    ]

    return ModelDraft(
        technique=technique,
        severity=DraftSeverity(
            value=rule_level,
            rationale="Severity is the detection rule's level; the rule-based baseline does not adjust it.",
            alert_fields=["rule_level"]),
        next_steps=next_steps,
        containment=[],
        missing_data=missing,
    )
