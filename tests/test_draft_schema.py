"""ModelDraft and AgentResult: the shape of unchecked model output and of a run."""

import pytest
from pydantic import ValidationError

from triage.schemas import (
    AgentResult, DraftContainment, DraftMissing, DraftSeverity, DraftStep, DraftTechnique,
    Enrichment, ModelDraft,
)

EID = "attack_lookup:0123456789abcdef"

# Minimal valid content for each draft model, without its sources.
FINDINGS = {
    DraftTechnique: {"technique_id": "T1059.001"},
    DraftSeverity: {"value": "high", "rationale": "rule level"},
    DraftStep: {"step": "Check the parent process."},
    DraftContainment: {"action": "Isolate the host."},
    DraftMissing: {"kind": "asset", "description": "asset: not found"},
}


def _draft(**overrides):
    base = {"severity": {"value": "low", "rationale": "r", "alert_fields": ["rule_level"]},
            "next_steps": [], "containment": [], "missing_data": []}
    return {**base, **overrides}


@pytest.mark.parametrize("model", FINDINGS, ids=lambda m: m.__name__)
def test_finding_without_sources_rejected(model):
    """An uncited finding cannot be checked, so it is rejected."""
    with pytest.raises(ValidationError, match="must cite evidence_ids or alert_fields"):
        model(**FINDINGS[model])
    with pytest.raises(ValidationError):
        model(**FINDINGS[model], evidence_ids=[], alert_fields=[])
    assert model(**FINDINGS[model], evidence_ids=[EID]).evidence_ids == [EID]
    assert model(**FINDINGS[model], alert_fields=["host"]).alert_fields == ["host"]


@pytest.mark.parametrize("bad", [
    "attack_lookup:01234567",               # 8 hex characters
    "attack_lookup:0123456789ABCDEF",       # uppercase
    ":0123456789abcdef",                    # missing tool part
    "0123456789abcdef",                     # no separator
    "attack_lookup:0123456789abcdef\n",     # trailing newline
    "Attack_lookup:0123456789abcdef",       # tool names are lowercase
])
def test_bad_evidence_id_shapes_rejected(bad):
    """Only our own evidence-ID shape can be cited; anything else is not from this run."""
    with pytest.raises(ValidationError):
        DraftStep(step="s", evidence_ids=[bad])


def test_unknown_alert_field_rejected():
    """Alert-field citations name a fixed set of fields, not arbitrary text."""
    with pytest.raises(ValidationError):
        DraftStep(step="s", alert_fields=["command_line"])


def test_unknown_fields_rejected():
    """A model cannot add fields the later stages would not check."""
    with pytest.raises(ValidationError):
        ModelDraft.model_validate(_draft(verdict="false_positive"))
    with pytest.raises(ValidationError):
        DraftStep(step="s", alert_fields=["host"], confidence="high")


def test_containment_cannot_be_preapproved():
    """The model can suggest containment, never approve it."""
    with pytest.raises(ValidationError):
        DraftContainment(action="Isolate the host.", alert_fields=["host"], requires_human_approval=False)
    assert DraftContainment(action="a", alert_fields=["host"]).requires_human_approval is True


@pytest.mark.parametrize("model, field, cap", [
    (DraftSeverity, "rationale", 600),
    (DraftStep, "step", 300),
    (DraftContainment, "action", 300),
    (DraftMissing, "description", 200),
])
def test_string_caps(model, field, cap):
    """Over-long model strings are rejected, not passed on."""
    args = {**FINDINGS[model], "alert_fields": ["host"]}
    model(**{**args, field: "x" * cap})
    with pytest.raises(ValidationError):
        model(**{**args, field: "x" * (cap + 1)})


@pytest.mark.parametrize("field, cap, item", [
    ("next_steps", 8, {"step": "s", "alert_fields": ["host"]}),
    ("containment", 5, {"action": "a", "alert_fields": ["host"]}),
    ("missing_data", 10, {"kind": "other", "description": "d", "alert_fields": ["event"]}),
])
def test_list_caps(field, cap, item):
    """A model cannot flood the draft with findings."""
    ModelDraft.model_validate(_draft(**{field: [item] * cap}))
    with pytest.raises(ValidationError):
        ModelDraft.model_validate(_draft(**{field: [item] * (cap + 1)}))


def test_source_list_caps():
    """Citation lists are bounded too."""
    DraftStep(step="s", evidence_ids=[EID] * 10, alert_fields=["host"] * 9)
    with pytest.raises(ValidationError):
        DraftStep(step="s", evidence_ids=[EID] * 11)
    with pytest.raises(ValidationError):
        DraftStep(step="s", alert_fields=["host"] * 10)


def test_model_draft_has_no_verdict_field():
    """The draft has no field that closes, dismisses or approves an alert."""
    assert set(ModelDraft.model_fields) == {"technique", "severity", "next_steps", "containment", "missing_data"}


def _result(**overrides):
    enrichment = Enrichment(alert_id="a", status="complete", techniques=[], evidence=[])
    base = {"alert_id": "a", "backend": "heuristic", "stop_reason": "completed",
            "draft": ModelDraft.model_validate(_draft()), "enrichment": enrichment,
            "evidence": [], "evidence_origin": {}, "model_calls": [], "tool_calls": 0}
    return AgentResult(**{**base, **overrides})


def test_agent_result_draft_only_when_completed():
    """A stopped run cannot carry a draft, and a completed one must."""
    assert _result().stop_reason == "completed"
    assert _result(stop_reason="budget_exceeded", draft=None).draft is None
    for reason in ("budget_exceeded", "backend_error", "invalid_output"):
        with pytest.raises(ValidationError):
            _result(stop_reason=reason)
    with pytest.raises(ValidationError):
        _result(draft=None)
