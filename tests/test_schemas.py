import json

import pytest
from pydantic import ValidationError

from triage.schemas import (
    ACTION_MAX, LENGTH_LIMIT_MARKER, MISSING_DESCRIPTION_MAX, RATIONALE_MAX, STEP_MAX,
    Alert, ContainmentAction, DraftContainment, DraftMissing, DraftSeverity, DraftStep, MissingItem, NextStep,
    SeverityFinding, ToolResult, TriageSummary, max_severity,
)


def make_alert(**over):
    base = dict(alert_id="a1", source="sigma", rule_id="r1", rule_title="t", rule_level="high",
                rule_tags=["attack.execution", "attack.t1059.001"], host="CLINIC-FRONT01")
    return Alert(**(base | over))


def test_attack_tags_extracts_technique_ids_only():
    assert make_alert().attack_tags() == ["T1059.001"]


def test_unknown_alert_field_is_rejected():
    with pytest.raises(ValidationError):
        make_alert(verdict="benign")  # extra="forbid": attacker can't smuggle in output fields


def test_long_event_value_is_truncated():
    a = make_alert(event={"CommandLine": "A" * 10_000})
    assert len(a.event["CommandLine"]) < 4200
    assert a.event["CommandLine"].endswith("[truncated]")


def test_containment_cannot_skip_human_approval():
    with pytest.raises(ValidationError):
        ContainmentAction(action="isolate host", requires_human_approval=False)
    assert ContainmentAction(action="isolate host").requires_human_approval is True


def test_ok_result_must_carry_data():
    with pytest.raises(ValidationError):
        ToolResult(evidence_id="x:1", tool="x", args={}, status="ok", data={})


def test_failed_result_must_not_carry_data():
    with pytest.raises(ValidationError):
        ToolResult(evidence_id="x:1", tool="x", args={}, status="error", data={"a": 1})


@pytest.mark.parametrize("a,b,expected", [("low", "high", "high"), ("critical", "medium", "critical"), ("low", "low", "low")])
def test_max_severity(a, b, expected):
    assert max_severity(a, b) == expected


# --- Length-limit marker (DD-030) ----------------------------------------------

M = LENGTH_LIMIT_MARKER


def _rationale(text, origin="model"):
    return SeverityFinding(value="high", rule_floor="high", origin=origin, rationale=text, sources=["rule_level"])


def _step(text):
    return NextStep(step=text, sources=["host"])


def _action(text):
    return ContainmentAction(action=text, sources=["host"])


def _missing(text, origin="model"):
    return MissingItem(kind="other", description=text, origin=origin, sources=["user"])


FIELDS = [(_rationale, RATIONALE_MAX), (_step, STEP_MAX), (_action, ACTION_MAX), (_missing, MISSING_DESCRIPTION_MAX)]
FIELD_IDS = ["rationale", "step", "action", "missing_description"]


def test_the_summary_limits_equal_the_draft_limits():
    """The output-side limits are the draft's, so only the marker is ever extra."""
    for model, field, limit in [(DraftSeverity, "rationale", RATIONALE_MAX), (DraftStep, "step", STEP_MAX),
                                (DraftContainment, "action", ACTION_MAX),
                                (DraftMissing, "description", MISSING_DESCRIPTION_MAX)]:
        assert model.model_json_schema()["properties"][field]["maxLength"] == limit
    assert M == " [length limit]" and M.isascii()


@pytest.mark.parametrize("make, limit", FIELDS, ids=FIELD_IDS)
def test_marked_text_is_accepted(make, limit):
    """Text within the limit, with or without one trailing marker, is valid."""
    for text in ["x", "x" * limit, "x" * limit + M, "x" * 10 + M, M, "x" * (limit - len(M)) + M + M]:
        make(text)


@pytest.mark.parametrize("make, limit", FIELDS, ids=FIELD_IDS)
def test_unmarked_text_keeps_the_original_limit(make, limit):
    """Only the marker may go past the limit; anything else over it is refused."""
    for text in ["x" * (limit + 1),                     # one over, no marker
                 "x" * (limit + 1) + M,                 # the marker does not excuse longer text
                 "x" * limit + M + "x",                 # the marker must be the very end
                 "x" * (limit + len(M)),                # a bound-length string that is not marked
                 "x" * (limit - len(M)) + M + M + "x"]:
        with pytest.raises(ValidationError):
            make(text)


def test_code_owned_text_cannot_carry_the_marker():
    """The marker is only for model text: rule and tripwire rationales and enrichment gaps refuse it."""
    for origin in ("rule", "tripwire"):
        _rationale("Fixed text.", origin=origin)
        with pytest.raises(ValidationError):
            _rationale("Fixed text." + M, origin=origin)
    _missing("asset: not found", origin="enrichment")
    with pytest.raises(ValidationError):
        _missing("asset: not found" + M, origin="enrichment")
    _rationale("Model text." + M, origin="model")
    _missing("Model text." + M, origin="model")


def _summary(text):
    return TriageSummary(
        alert_id="a1", run_id="0" * 32, status="triaged", backend="ollama",
        severity={"value": "high", "rule_floor": "high", "origin": "model",
                  "rationale": "r" * RATIONALE_MAX + M, "sources": ["rule_level"]},
        technique={"technique_id": None, "basis": "none", "origin": "none"},
        asset={"host": "CLINIC-FRONT01", "criticality": "unknown", "exposure": "unknown"},
        next_steps=[{"step": text, "sources": ["host"]}],
        containment=[{"action": "a" * ACTION_MAX + M, "sources": ["host"]}],
        missing_data=[{"kind": "other", "description": "d" * MISSING_DESCRIPTION_MAX + M, "origin": "model",
                       "sources": ["user"]}],
    )


def test_the_rule_holds_through_serialization_and_reloading():
    """A marked summary survives a JSON round trip; a reloaded one is checked again."""
    summary = _summary("s" * STEP_MAX + M)
    data = summary.model_dump_json()
    assert TriageSummary.model_validate_json(data) == summary
    assert TriageSummary.model_validate(json.loads(data)) == summary
    tampered = json.loads(data)
    tampered["next_steps"][0]["step"] = "s" * (STEP_MAX + len(M))   # same length, no marker
    with pytest.raises(ValidationError):
        TriageSummary.model_validate(tampered)
    with pytest.raises(ValidationError):
        TriageSummary.model_validate_json(json.dumps(tampered))
    tampered = json.loads(data)
    tampered["severity"]["origin"] = "tripwire"                      # marker on code-owned text
    with pytest.raises(ValidationError):
        TriageSummary.model_validate(tampered)
