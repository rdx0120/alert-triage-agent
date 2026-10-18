"""EvidenceLog: records every gateway result once, in call order, keyed by evidence ID."""

from pydantic import BaseModel, ConfigDict

from triage.evidence import EvidenceLog
from triage.tools.registry import Tool, evidence_id


class EchoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str


def counting_tools():
    calls = []

    def echo(args: EchoArgs) -> dict:
        calls.append(args.value)
        return {"value": args.value}

    return {"echo": Tool("echo", "test tool", EchoArgs, echo)}, calls


def test_records_results_in_call_order_and_returns_a_copy():
    tools, _ = counting_tools()
    log = EvidenceLog(tools)
    a = log.call("echo", {"value": "a"})
    b = log.call("echo", {"value": "b"})
    assert log.results == [a, b]
    log.results.clear()
    assert log.results == [a, b]


def test_same_tool_and_args_recorded_once_and_tool_called_once():
    tools, calls = counting_tools()
    log = EvidenceLog(tools)
    first = log.call("echo", {"value": "a"})
    second = log.call("echo", {"value": "a"})
    assert first == second
    assert len(log.results) == 1
    assert calls == ["a"]


def test_dedup_key_equals_returned_evidence_id():
    tools, _ = counting_tools()
    log = EvidenceLog(tools)
    result = log.call("echo", {"value": "a"})
    assert list(log._results) == [result.evidence_id] == [evidence_id("echo", {"value": "a"})]


def test_unknown_tool_is_a_recorded_error():
    tools, _ = counting_tools()
    log = EvidenceLog(tools)
    result = log.call("delete_everything", {"path": "/"})
    assert result.status == "error"
    assert log.results == [result]


def test_ids_and_get_reflect_recorded_results():
    tools, _ = counting_tools()
    log = EvidenceLog(tools)
    a = log.call("echo", {"value": "a"})
    bad = log.call("echo", {"wrong": "field"})
    assert bad.status == "invalid_input"
    assert log.ids() == {a.evidence_id, bad.evidence_id}
    assert log.get(a.evidence_id) == a
    assert log.get(bad.evidence_id) == bad
    assert log.get("echo:00000000") is None
