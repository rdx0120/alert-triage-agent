"""ModelDraft and AgentResult: the shape of unchecked model output and of a run."""

import pytest
from pydantic import ValidationError

from triage.enrich import MAX_CVES, MAX_TECHNIQUES
from triage.schemas import (
    MAX_MISSING_DATA, MAX_SOURCES, AgentResult, DraftContainment, DraftMissing, DraftSeverity,
    DraftStep, DraftTechnique, Enrichment, ModelDraft,
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
    base = {"severity": {"value": "low", "rationale": "r", "sources": ["rule_level"]},
            "next_steps": [], "containment": [], "missing_data": []}
    return {**base, **overrides}


@pytest.mark.parametrize("model", FINDINGS, ids=lambda m: m.__name__)
def test_finding_without_sources_rejected(model):
    """An uncited finding cannot be checked, so sources is required and non-empty."""
    with pytest.raises(ValidationError) as missing:
        model(**FINDINGS[model])
    assert [(e["loc"], e["type"]) for e in missing.value.errors()] == [(("sources",), "missing")]
    with pytest.raises(ValidationError) as empty:
        model(**FINDINGS[model], sources=[])
    assert [(e["loc"], e["type"]) for e in empty.value.errors()] == [(("sources",), "too_short")]
    assert model(**FINDINGS[model], sources=[EID]).sources == [EID]
    assert model(**FINDINGS[model], sources=["host"]).sources == ["host"]
    assert model(**FINDINGS[model], sources=[EID, "host"]).sources == [EID, "host"]


@pytest.mark.parametrize("model", FINDINGS, ids=lambda m: m.__name__)
@pytest.mark.parametrize("bad", [
    "the PowerShell event",                 # free text
    None,
    {"evidence_id": EID},                   # an object instead of a string
    ["host"],
    7,
])
def test_source_items_must_be_field_names_or_evidence_ids(model, bad):
    """A source is an alert-field name or an evidence-ID-shaped string, nothing else."""
    with pytest.raises(ValidationError):
        model(**FINDINGS[model], sources=[bad])


@pytest.mark.parametrize("old", ["evidence_ids", "alert_fields"])
def test_old_citation_keys_rejected(old):
    """The replaced two-list form is not accepted, even alongside sources."""
    with pytest.raises(ValidationError):
        DraftStep(step="s", **{old: ["host"]})
    with pytest.raises(ValidationError):
        DraftStep(step="s", sources=["host"], **{old: ["host"]})


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
        DraftStep(step="s", sources=[bad])


def test_unknown_alert_field_rejected():
    """Alert-field citations name a fixed set of fields, not arbitrary text."""
    with pytest.raises(ValidationError):
        DraftStep(step="s", sources=["command_line"])


def test_unknown_fields_rejected():
    """A model cannot add fields the later stages would not check."""
    with pytest.raises(ValidationError):
        ModelDraft.model_validate(_draft(verdict="false_positive"))
    with pytest.raises(ValidationError):
        DraftStep(step="s", sources=["host"], confidence="high")


def test_containment_cannot_be_preapproved():
    """The model can suggest containment, never approve it."""
    with pytest.raises(ValidationError):
        DraftContainment(action="Isolate the host.", sources=["host"], requires_human_approval=False)
    assert DraftContainment(action="a", sources=["host"]).requires_human_approval is True


@pytest.mark.parametrize("model, field, cap", [
    (DraftSeverity, "rationale", 600),
    (DraftStep, "step", 300),
    (DraftContainment, "action", 300),
    (DraftMissing, "description", 200),
])
def test_string_caps(model, field, cap):
    """Over-long model strings are rejected, not passed on."""
    args = {**FINDINGS[model], "sources": ["host"]}
    model(**{**args, field: "x" * cap})
    with pytest.raises(ValidationError):
        model(**{**args, field: "x" * (cap + 1)})


@pytest.mark.parametrize("field, cap, item", [
    ("next_steps", 8, {"step": "s", "sources": ["host"]}),
    ("containment", 5, {"action": "a", "sources": ["host"]}),
    ("missing_data", MAX_MISSING_DATA, {"kind": "other", "description": "d", "sources": ["event"]}),
])
def test_list_caps(field, cap, item):
    """A model cannot flood the draft with findings."""
    ModelDraft.model_validate(_draft(**{field: [item] * cap}))
    with pytest.raises(ValidationError):
        ModelDraft.model_validate(_draft(**{field: [item] * (cap + 1)}))


def test_missing_data_cap_covers_every_enrichment_gap():
    """The rule-based baseline reports every gap, so the cap must hold the most enrichment can produce."""
    # Techniques and CVEs: one gap per looked-up item plus one over_cap; one asset and one runbook gap.
    most_gaps = (MAX_TECHNIQUES + 1) + 1 + (MAX_CVES + 1) + 1
    assert most_gaps <= MAX_MISSING_DATA


def test_source_list_caps():
    """Citation lists are bounded too."""
    assert MAX_SOURCES == 19
    DraftStep(step="s", sources=[EID] * 10 + ["host"] * 9)
    with pytest.raises(ValidationError):
        DraftStep(step="s", sources=[EID] * 10 + ["host"] * 10)


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
