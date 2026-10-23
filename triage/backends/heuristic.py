"""The rule-based baseline (DD-008), as a backend.

It reads only request.alert, request.enrichment and request.citable, never the
prompt, so alert text addressed to a model cannot change its answer. It requests no tools,
takes the technique from enrichment and the severity from the rule level, and
reports every enrichment gap as missing data.

It cites only evidence IDs in request.citable, the evidence this run showed a
model, and alert fields: a missing-data finding may cite absence (a failed
lookup that was shown, no host, no CVEs). Without a citable set it cites alert
fields only, so it never cites evidence the run did not show.
"""

from __future__ import annotations

from ..citations import Citable
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
        citable = request.citable if request.citable is not None else Citable()
        draft = _draft(request.alert.rule_level, request.enrichment, citable)
        return ChatReply(text=draft.model_dump_json())


def _draft(rule_level: str, enrichment: Enrichment, citable: Citable) -> ModelDraft:
    support = citable.support_set
    either = support | citable.absence_set
    technique = None
    if enrichment.techniques:
        tid = enrichment.techniques[0]
        # Enrichment lists a technique only if its attack_lookup was ok.
        lookup = next(r for r in enrichment.evidence
                      if r.tool == "attack_lookup" and r.status == "ok"
                      and r.args.get("technique_id") == tid)
        cited = [lookup.evidence_id] if lookup.evidence_id in support else []
        technique = DraftTechnique(technique_id=tid, sources=cited + ["rule_tags"])

    next_steps = []
    runbook = next((r for r in enrichment.evidence
                    if r.tool == "runbook_search" and r.status == "ok"), None)
    # The step rests only on the runbook result, so it is given only if that was shown.
    if runbook is not None and runbook.evidence_id in support:
        next_steps.append(DraftStep(
            step=f"Follow the triage steps in runbook {runbook.data['hits'][0]['runbook']}.",
            sources=[runbook.evidence_id]))

    missing = [
        DraftMissing(kind=gap.kind, description=f"{gap.kind}: {gap.reason.replace('_', ' ')}",
                     sources=([gap.evidence_id] if gap.evidence_id in either else []) + [_GAP_FIELD[gap.kind]])
        for gap in enrichment.gaps
    ]

    return ModelDraft(
        technique=technique,
        severity=DraftSeverity(
            value=rule_level,
            rationale="Severity is the detection rule's level; the rule-based baseline does not adjust it.",
            sources=["rule_level"]),
        next_steps=next_steps,
        containment=[],
        missing_data=missing,
    )
