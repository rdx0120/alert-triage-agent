import pytest
from pydantic import ValidationError

from triage.schemas import Alert, ContainmentAction, ToolResult, max_severity


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
