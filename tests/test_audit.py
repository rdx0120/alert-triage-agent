"""The audit log: a metadata-only JSONL projection of a run, and its file checks."""

import dataclasses
import hashlib
import json
import os
import stat
import threading
import types
from datetime import datetime, timedelta, timezone

import pytest

from test_prompt import run_worst_case
from triage import agent, audit
from triage.agent import Limits, run_agent
from triage.audit import audit_records, dumps_line, write_audit_log
from triage.backends import BackendError, ChatReply, HeuristicBackend, ToolCall, serialize_request
from triage.config import REPO_ROOT
from triage.ingest import load_alert
from triage.schemas import Alert, DraftSeverity, Gap, ModelDraft

SAMPLES = sorted((REPO_ROOT / "samples" / "alerts").glob("*/*.json"))
POWERSHELL = REPO_ROOT / "samples" / "alerts" / "wazuh" / "encoded_powershell.json"
MARKER = "ZQXMARKER7731"
ENDPOINT = "http://192.0.2.10:11434"   # documentation address (RFC 5737)
RUN_ID = "0123456789abcdef" * 2
WALL = datetime(2026, 1, 2, 5, 4, 5, 678901, tzinfo=timezone(timedelta(hours=2)))
VALID = ModelDraft(severity=DraftSeverity(value="high", rationale="r", sources=["rule_level"]),
                   next_steps=[], containment=[], missing_data=[]).model_dump_json()
FABRICATED = "alert_metadata:" + "0123456789abcdef"

COMMON_KEYS = ["timestamp", "event.name", "triage.audit.schema_version", "gen_ai.conversation.id", "triage.seq",
               "gen_ai.operation.name"]
RUN_KEYS = COMMON_KEYS + [
    "gen_ai.agent.name", "gen_ai.provider.name", "gen_ai.request.model", "error.type", "triage.alert.id",
    "triage.alert.source", "triage.rule.id", "triage.rule.level", "triage.ingest_warnings.count",
    "triage.enrichment.status", "triage.enrichment.gaps", "triage.enrichment.duration_s", "triage.stop_reason",
    "triage.budget_detail", "triage.duration_s", "triage.model_calls.count", "triage.tool_calls.count",
    "triage.draft.severity", "triage.draft.technique_id", "triage.draft.findings", "triage.validation_errors",
]
MODEL_CALL_KEYS = COMMON_KEYS + [
    "gen_ai.provider.name", "gen_ai.request.model", "gen_ai.request.max_tokens", "gen_ai.output.type",
    "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens", "gen_ai.response.finish_reasons", "error.type",
    "triage.phase", "triage.turn", "triage.start_s", "triage.duration_s", "triage.request.bytes",
    "triage.request.token_bound", "triage.request.sha256", "triage.reply.kind", "triage.reply.text_bytes",
    "triage.reply.sha256", "triage.reply.truncated", "triage.tool_calls.requested", "triage.tool_calls.run",
    "triage.tool_calls.dropped", "triage.validation.accepted", "triage.validation.problems",
    "triage.finding_counts",
]
LOOKUP_KEYS = COMMON_KEYS + [
    "gen_ai.tool.name", "gen_ai.tool.type", "error.type", "triage.evidence.id", "triage.requested_by",
    "triage.tool.status", "triage.turn", "triage.repeat", "triage.start_s", "triage.duration_s",
    "triage.view.state", "triage.view.string_cap", "triage.view.strings_cut", "triage.view.bytes",
]
KEYS = {"triage.run": RUN_KEYS, "triage.model_call": MODEL_CALL_KEYS, "triage.tool_call": LOOKUP_KEYS}


class ScriptedBackend:
    """Returns pre-set replies in order (raising any that are exceptions) and records every request."""

    name = "scripted"

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def chat(self, request):
        self.requests.append(request)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class CountingTimer:
    """Returns n * n / 10 on its n-th read (from 0), so every interval has its own length."""

    def __init__(self):
        self.reads = 0

    def __call__(self):
        value = self.reads * self.reads / 10
        self.reads += 1
        return value


class FakeClock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now


class ClockBackend:
    """Moves the fake clock to a set time during the call, then returns or raises the reply."""

    name = "clock"

    def __init__(self, clock, at, reply):
        self.clock, self.at, self.reply = clock, at, reply

    def chat(self, request):
        self.clock.now = self.at
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


def _load(path):
    return load_alert(path.read_text(encoding="utf-8"), fmt=path.parent.name)


def _powershell():
    return _load(POWERSHELL)


def _calls(*pairs):
    return ChatReply(tool_calls=[ToolCall(name, args) for name, args in pairs])


def _attack(tid):
    return ("attack_lookup", {"technique_id": tid})


def _run(alert, replies, settings, tools, **kwargs):
    backend = ScriptedBackend(replies)
    return run_agent(alert, backend, settings=settings, tools=tools, **kwargs), backend


def _draft_citing(*sources, **findings):
    draft = {"severity": {"value": "high", "rationale": "r", "sources": list(sources)},
             "next_steps": [], "containment": [], "missing_data": [], **findings}
    return ChatReply(text=json.dumps(draft))


def _invalid_with_marker():
    draft = json.loads(VALID)
    draft[MARKER] = "x"
    draft["severity"]["rationale"] = "r" * 601
    return json.dumps(draft)


def _heuristic(settings, tools, **kwargs):
    alert = _powershell()
    return run_agent(alert, HeuristicBackend(), settings=settings, tools=tools, **kwargs), alert


def _lines(path):
    data = path.read_bytes()
    data.decode("ascii")
    assert data.endswith(b"\n")
    return [json.loads(line) for line in data.decode("ascii").splitlines()]


def _sha(data):
    return hashlib.sha256(data).hexdigest()


# --- Scenarios ------------------------------------------------------------

def _completed_with_lookups(settings, tools, monkeypatch):
    replies = [_calls(_attack("T1003"), _attack("T1059.001")), _calls(("attack_lookup", ["bad"])),
               ChatReply(), ChatReply(text=VALID)]
    return _run(_powershell(), replies, settings, tools)[0]


def _repaired(settings, tools, monkeypatch):
    return _run(_powershell(), [ChatReply(), _draft_citing(FABRICATED), _draft_citing("rule_level")],
                settings, tools)[0]


def _invalid_output(settings, tools, monkeypatch):
    replies = [ChatReply(), ChatReply(text=_invalid_with_marker()), _draft_citing("rule_level", FABRICATED)]
    return _run(_powershell(), replies, settings, tools)[0]


def _backend_error(settings, tools, monkeypatch):
    return _run(_powershell(), [_calls(_attack("T1003")), BackendError("boom", error_type="timeout")],
                settings, tools)[0]


def _deadline_before_request(settings, tools, monkeypatch):
    times = [0.0]
    clock = lambda: times.pop(0) if times else 901.0  # noqa: E731
    return _run(_powershell(), [ChatReply(text=VALID)], settings, tools, clock=clock)[0]


def _over_context_budget(settings, tools, monkeypatch):
    monkeypatch.setattr(agent, "CONTEXT_TOKENS", 4_000)
    return _run(_powershell(), [ChatReply(text=VALID)], settings, tools)[0]


def _deadline_during_request(settings, tools, monkeypatch):
    clock = FakeClock()
    return run_agent(_powershell(), ClockBackend(clock, 901.0, BackendError("late")), settings=settings,
                     tools=tools, clock=clock)


def _deadline_after_reply(settings, tools, monkeypatch):
    clock = FakeClock()
    return run_agent(_powershell(), ClockBackend(clock, 901.0, ChatReply(text=VALID)), settings=settings,
                     tools=tools, limits=Limits(max_tool_calls=0), clock=clock)


SCENARIOS = [
    (_completed_with_lookups, "completed"), (_repaired, "completed"), (_invalid_output, "invalid_output"),
    (_backend_error, "backend_error"), (_deadline_before_request, "budget_exceeded"),
    (_over_context_budget, "budget_exceeded"), (_deadline_during_request, "budget_exceeded"),
    (_deadline_after_reply, "budget_exceeded"),
]
SCENARIO_IDS = ["completed", "repair", "invalid_output", "backend_error", "deadline_before_request",
                "request_over_context_budget", "deadline_during_request", "deadline_after_reply"]


# --- Structure ------------------------------------------------------------

def _check_structure(result, records):
    """Records must be the run, enrichment lookups, then each model call followed by its turn's lookups."""
    def lookup(r):
        return ("triage.tool_call", r.evidence_id, r.turn)

    expected = [("triage.run",)] + [lookup(r) for r in result.tool_records if r.requested_by == "enrichment"]
    for call in result.model_calls:
        expected.append(("triage.model_call", call.phase, call.turn))
        expected += [lookup(r) for r in result.tool_records if r.requested_by == "model" and r.turn == call.turn]
    actual = []
    for record in records:
        if record["event.name"] == "triage.run":
            actual.append(("triage.run",))
        elif record["event.name"] == "triage.model_call":
            actual.append(("triage.model_call", record["triage.phase"], record["triage.turn"]))
        else:
            actual.append(("triage.tool_call", record["triage.evidence.id"], record["triage.turn"]))
    assert actual == expected
    assert len(records) == 1 + len(result.tool_records) + len(result.model_calls)
    assert [r["triage.seq"] for r in records] == list(range(len(records)))
    assert all(r["triage.audit.schema_version"] == 2 for r in records)
    assert all(r["gen_ai.conversation.id"] == result.run_id for r in records)
    for record in records:
        assert list(record) == KEYS[record["event.name"]]


@pytest.mark.parametrize("scenario,reason", SCENARIOS, ids=SCENARIO_IDS)
def test_record_order_and_keys(scenario, reason, monkeypatch, settings, tools):
    """Every stop must give the run record, then lookups and model calls in order, each once, with fixed keys."""
    result = scenario(settings, tools, monkeypatch)
    assert result.stop_reason == reason
    alert = _powershell()
    records = audit_records(result, alert)
    _check_structure(result, records)
    assert records[0]["triage.stop_reason"] == reason
    assert records[0]["triage.budget_detail"] == result.budget_detail


def test_model_lookups_follow_their_turn(settings, tools):
    """Model-requested lookups must follow the model call of their turn, after the enrichment lookups."""
    result = _completed_with_lookups(settings, tools, None)
    records = audit_records(result, _powershell())
    events = [(r["event.name"], r.get("triage.requested_by"), r["triage.turn"] if "triage.turn" in r else None)
              for r in records]
    enrichment = sum(1 for r in result.tool_records if r.requested_by == "enrichment")
    assert events[1:1 + enrichment] == [("triage.tool_call", "enrichment", 0)] * enrichment
    assert events[1 + enrichment:] == [
        ("triage.model_call", None, 1), ("triage.tool_call", "model", 1), ("triage.tool_call", "model", 1),
        ("triage.model_call", None, 2), ("triage.tool_call", "model", 2),
        ("triage.model_call", None, 3), ("triage.model_call", None, None),
    ]


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_heuristic_samples_project(path, settings, tools):
    """The baseline run of every sample must project in order with fixed keys."""
    alert = _load(path)
    result = run_agent(alert, HeuristicBackend(), settings=settings, tools=tools)
    records = audit_records(result, alert)
    _check_structure(result, records)
    assert records[0]["gen_ai.provider.name"] == "heuristic"
    for record in records:
        dumps_line(record)


def test_exact_values(settings, tools):
    """A scripted run with an injected timer and wall clock must project to these exact values."""
    replies = [dataclasses.replace(_calls(_attack("T1003")), text="look", input_tokens=900, output_tokens=12,
                                   finish_reason="stop"),
               ChatReply(finish_reason="length", truncated=True), ChatReply(text=VALID, finish_reason="stop")]
    result, backend = _run(_powershell(), replies, settings, tools, timer=CountingTimer(),
                           wall_clock=lambda: WALL, run_id=RUN_ID)
    assert result.stop_reason == "completed"
    records = audit_records(result, _powershell())
    common = {"triage.audit.schema_version": 2, "gen_ai.conversation.id": RUN_ID}
    run = records[0]
    assert run == {
        "timestamp": "2026-01-02T03:04:05.678Z", "event.name": "triage.run", **common, "triage.seq": 0,
        "gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "alert-triage-agent",
        "gen_ai.provider.name": "unknown", "gen_ai.request.model": None, "error.type": None,
        "triage.alert.id": "1782897262.104512", "triage.alert.source": "wazuh", "triage.rule.id": "100010",
        "triage.rule.level": "high", "triage.ingest_warnings.count": 0, "triage.enrichment.status": "complete",
        "triage.enrichment.gaps": [], "triage.enrichment.duration_s": 0.3, "triage.stop_reason": "completed",
        "triage.budget_detail": None, "triage.duration_s": 12.1, "triage.model_calls.count": 3,
        "triage.tool_calls.count": 1, "triage.draft.severity": "high", "triage.draft.technique_id": None,
        "triage.draft.findings": {"technique": 0, "next_steps": 0, "containment": 0, "missing_data": 0},
        "triage.validation_errors": [],
    }
    enrichment = [r for r in result.tool_records if r.requested_by == "enrichment"]
    n = len(enrichment)
    for i, (record, source) in enumerate(zip(records[1:1 + n], enrichment), start=1):
        assert record == {
            "timestamp": "2026-01-02T03:04:05.678Z", "event.name": "triage.tool_call", **common, "triage.seq": i,
            "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": source.tool,
            "gen_ai.tool.type": "function", "error.type": None, "triage.evidence.id": source.evidence_id,
            "triage.requested_by": "enrichment", "triage.tool.status": "ok", "triage.turn": 0,
            "triage.repeat": False, "triage.start_s": None, "triage.duration_s": None,
            "triage.view.state": source.view, "triage.view.string_cap": source.view_string_cap,
            "triage.view.strings_cut": source.view_strings_cut, "triage.view.bytes": source.view_bytes,
        }
    first, lookup, second, final = records[1 + n:]
    requests = [serialize_request(r) for r in backend.requests]
    model_call = {"event.name": "triage.model_call", **common, "gen_ai.operation.name": "chat",
                  "gen_ai.provider.name": "unknown", "gen_ai.request.model": None, "error.type": None}
    assert first == {
        **model_call, "timestamp": "2026-01-02T03:04:06.578Z", "triage.seq": n + 1,
        "gen_ai.request.max_tokens": 384, "gen_ai.output.type": "text", "gen_ai.usage.input_tokens": 900,
        "gen_ai.usage.output_tokens": 12, "gen_ai.response.finish_reasons": ["stop"],
        "triage.phase": "investigate", "triage.turn": 1, "triage.start_s": 0.9, "triage.duration_s": 0.7,
        "triage.request.bytes": len(requests[0]), "triage.request.token_bound": result.model_calls[0].token_bound,
        "triage.request.sha256": _sha(requests[0]), "triage.reply.kind": "tool_calls",
        "triage.reply.text_bytes": 4, "triage.reply.sha256": _sha(b"look"), "triage.reply.truncated": False,
        "triage.tool_calls.requested": 1, "triage.tool_calls.run": 1, "triage.tool_calls.dropped": 0,
        "triage.validation.accepted": None, "triage.validation.problems": None, "triage.finding_counts": None,
    }
    (model_lookup,) = [r for r in result.tool_records if r.requested_by == "model"]
    assert lookup == {
        "timestamp": "2026-01-02T03:04:08.178Z", "event.name": "triage.tool_call", **common, "triage.seq": n + 2,
        "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "attack_lookup",
        "gen_ai.tool.type": "function", "error.type": None, "triage.evidence.id": model_lookup.evidence_id,
        "triage.requested_by": "model", "triage.tool.status": "ok", "triage.turn": 1, "triage.repeat": False,
        "triage.start_s": 2.5, "triage.duration_s": 1.1, "triage.view.state": model_lookup.view,
        "triage.view.string_cap": model_lookup.view_string_cap,
        "triage.view.strings_cut": model_lookup.view_strings_cut, "triage.view.bytes": model_lookup.view_bytes,
    }
    assert model_lookup.view in ("full", "capped") and model_lookup.view_bytes > 0
    assert second == {
        **model_call, "timestamp": "2026-01-02T03:04:10.578Z", "triage.seq": n + 3,
        "gen_ai.request.max_tokens": 384, "gen_ai.output.type": "text", "gen_ai.usage.input_tokens": None,
        "gen_ai.usage.output_tokens": None, "gen_ai.response.finish_reasons": ["length"],
        "triage.phase": "investigate", "triage.turn": 2, "triage.start_s": 4.9, "triage.duration_s": 1.5,
        "triage.request.bytes": len(requests[1]), "triage.request.token_bound": result.model_calls[1].token_bound,
        "triage.request.sha256": _sha(requests[1]), "triage.reply.kind": "empty",
        "triage.reply.text_bytes": 0, "triage.reply.sha256": _sha(b""), "triage.reply.truncated": True,
        "triage.tool_calls.requested": 0, "triage.tool_calls.run": 0, "triage.tool_calls.dropped": 0,
        "triage.validation.accepted": None, "triage.validation.problems": None, "triage.finding_counts": None,
    }
    assert final == {
        **model_call, "timestamp": "2026-01-02T03:04:13.778Z", "triage.seq": n + 4,
        "gen_ai.request.max_tokens": 1_024, "gen_ai.output.type": "json", "gen_ai.usage.input_tokens": None,
        "gen_ai.usage.output_tokens": None, "gen_ai.response.finish_reasons": ["stop"],
        "triage.phase": "final", "triage.turn": None, "triage.start_s": 8.1, "triage.duration_s": 1.9,
        "triage.request.bytes": len(requests[2]), "triage.request.token_bound": result.model_calls[2].token_bound,
        "triage.request.sha256": _sha(requests[2]), "triage.reply.kind": "text",
        "triage.reply.text_bytes": len(VALID), "triage.reply.sha256": _sha(VALID.encode("utf-8")),
        "triage.reply.truncated": False, "triage.tool_calls.requested": 0, "triage.tool_calls.run": 0,
        "triage.tool_calls.dropped": 0, "triage.validation.accepted": True, "triage.validation.problems": [],
        "triage.finding_counts": {"technique": 0, "severity": 1, "next_steps": 0, "containment": 0,
                                  "missing_data": 0},
    }


def test_error_types(settings, tools):
    """A failed call's error type and a failed lookup's status must be the records' error.type."""
    replies = [_calls(("attack_lookup", ["bad"]), ("delete_host", {"host": "x"})),
               BackendError("boom", error_type="timeout")]
    result, _ = _run(_powershell(), replies, settings, tools)
    records = audit_records(result, _powershell())
    assert records[0]["error.type"] == "timeout"
    assert [(r["event.name"], r["error.type"]) for r in records[-4:]] == [
        ("triage.model_call", None), ("triage.tool_call", "invalid_input"), ("triage.tool_call", "error"),
        ("triage.model_call", "timeout")]
    assert all(r["error.type"] is None for r in records[1:-4])


@pytest.mark.parametrize("name,provider", [
    ("ollama:qwen3.5:9b", "ollama"), ("heuristic", "heuristic"), ("scripted", "unknown"),
    ("ollamax:qwen", "unknown"), ("", "unknown"), (f"{MARKER}:ollama", "unknown"),
])
def test_provider_from_closed_list(name, provider, settings, tools):
    """The provider must come from a closed list and the backend string must never be written."""
    backend = ScriptedBackend([ChatReply(), ChatReply(text=VALID)])
    backend.name = name
    alert = _powershell()
    result = run_agent(alert, backend, settings=settings, tools=tools)
    assert result.backend == name
    records = audit_records(result, alert)
    assert {r["gen_ai.provider.name"] for r in records if "gen_ai.provider.name" in r} == {provider}
    text = "".join(dumps_line(r) for r in records)
    if name not in ("heuristic", ""):
        assert name not in text


# --- Identifiers and filters -------------------------------------------------

@pytest.mark.parametrize("rule_id,kept", [
    ("100010", True), ("5b8e1a2c-6f3d-4b7a-9c1e-2d4f6a8b0c1e", True),
    ("rule 1", False), ("rule\n1", False), (".rule", False), ("r" * 129, False),
])
def test_rule_id_filter(rule_id, kept, settings, tools):
    """A rule ID is written only if it matches the strict pattern."""
    result, alert = _heuristic(settings, tools)
    alert = alert.model_copy(update={"rule_id": rule_id})
    records = audit_records(result, alert)
    assert records[0]["triage.rule.id"] == (rule_id if kept else None)


@pytest.mark.parametrize("model", [
    "qwen3.5:9b", "registry.ollama.ai/library/qwen:9b", "llama3.1:8b-instruct-q4_K_M", "qwen3.5",
])
def test_model_name_kept(model, settings, tools):
    """An ordinary model name must be written on the run and model-call records."""
    result, alert = _heuristic(settings, tools)
    records = audit_records(result.model_copy(update={"model": model}), alert)
    assert {r["gen_ai.request.model"] for r in records if "gen_ai.request.model" in r} == {model}


@pytest.mark.parametrize("model", [
    ENDPOINT, "192.0.2.10:11434", "192.0.2.10", "2001:db8::1", "2001:db8::abcd", "::1", "[2001:db8::1]:11434",
    "localhost:11434", "ollama.example.internal:11434", "http://ollama.example.internal",
    "model:7",   # a digits-only tag is treated as a port and written as null
    "qwen 9b", "m" * 129,
])
def test_model_name_that_looks_like_an_address_is_null(model, settings, tools):
    """Regression test for endpoint privacy: an address-like or malformed model name must be written as null."""
    result, alert = _heuristic(settings, tools)
    records = audit_records(result.model_copy(update={"model": model}), alert)
    assert {r["gen_ai.request.model"] for r in records if "gen_ai.request.model" in r} == {None}
    assert model not in "".join(dumps_line(r) for r in records)


def test_alert_id_out_of_pattern_is_null(settings, tools):
    """An alert ID that bypassed its pattern must be written as null."""
    result, alert = _heuristic(settings, tools)
    bad = f"bad id {MARKER}"
    records = audit_records(result.model_copy(update={"alert_id": bad}), alert.model_copy(update={"alert_id": bad}))
    assert records[0]["triage.alert.id"] is None
    assert MARKER not in "".join(dumps_line(r) for r in records)


def test_technique_id_out_of_pattern_is_null(settings, tools):
    """A draft technique ID that bypassed its pattern must be written as null."""
    result, alert = _heuristic(settings, tools)
    assert audit_records(result, alert)[0]["triage.draft.technique_id"] == "T1059.001"
    result = result.model_copy(deep=True)
    result.draft.technique.technique_id = f"T1059 {MARKER}"
    records = audit_records(result, alert)
    assert records[0]["triage.draft.technique_id"] is None
    assert records[0]["triage.draft.findings"]["technique"] == 1
    assert MARKER not in "".join(dumps_line(r) for r in records)


@pytest.mark.parametrize("scenario", [_repaired, _invalid_output], ids=["repair", "invalid_output"])
def test_loop_problems_are_kept(scenario, settings, tools):
    """Every problem string the loop produces must be written unchanged."""
    result = scenario(settings, tools, None)
    records = audit_records(result, _powershell())
    assert records[0]["triage.validation_errors"] == result.validation_errors
    calls = [r for r in records if r["event.name"] == "triage.model_call"]
    assert [c["triage.validation.problems"] for c in calls] == [c.problems for c in result.model_calls]
    assert any(c.problems for c in result.model_calls)
    assert "<unrecognized>" not in json.dumps(records)


def test_loop_problems_cover_capping_and_root(settings, tools):
    """The capped count and the root-level problem must be written unchanged."""
    bad = json.dumps({"missing_data": [{"kind": "x", "description": "d", "sources": ["event"]}] * 10})
    result, _ = _run(_powershell(), [ChatReply(), ChatReply(text=bad), ChatReply(text="not json")], settings, tools)
    records = audit_records(result, _powershell())
    assert records[0]["triage.validation_errors"] == ["(root): json_invalid"]
    final = [r for r in records if r.get("triage.phase") == "final"][0]
    assert final["triage.validation.problems"] == result.model_calls[1].problems
    assert final["triage.validation.problems"][-1] == "and 3 more"


@pytest.mark.parametrize("problem", ['severity."x": missing', "severity sources: missing", "severity: Missing",
                                     f"severity: {MARKER.lower()} extra"])
def test_unrecognized_problems_are_replaced(problem, settings, tools):
    """A problem string outside the known shape must be written as <unrecognized>."""
    result = _repaired(settings, tools, None).model_copy(deep=True)
    result.validation_errors = ["severity: missing", problem]
    result.model_calls[1].problems = [problem]
    records = audit_records(result, _powershell())
    assert records[0]["triage.validation_errors"] == ["severity: missing", "<unrecognized>"]
    final = [r for r in records if r.get("triage.phase") == "final"][0]
    assert final["triage.validation.problems"] == ["<unrecognized>"]


@pytest.mark.parametrize("counts", [
    {"technique": 1, "severity": 1, "next_steps": 0, "containment": 0, "missing_data": 0, "extra": 1},
    {"technique": 1, "severity": 1, "next_steps": 0, "containment": 0},
    {"technique": 1, "severity": 1, "next_steps": -1, "containment": 0, "missing_data": 0},
    {"technique": True, "severity": 1, "next_steps": 0, "containment": 0, "missing_data": 0},
    {"technique": "1", "severity": 1, "next_steps": 0, "containment": 0, "missing_data": 0},
    None, [],
], ids=["extra_key", "missing_key", "negative", "bool", "string", "none", "list"])
def test_bad_finding_counts_are_null(counts):
    """Finding counts with the wrong keys or a value that is not a non-negative int must be written as null."""
    assert audit._finding_counts(counts) is None


def test_finding_counts_kept_in_fixed_order():
    """Well-formed finding counts must be written with the fixed key order."""
    counts = {"missing_data": 2, "containment": 0, "next_steps": 3, "severity": 1, "technique": 0}
    assert list(audit._finding_counts(counts).items()) == [
        ("technique", 0), ("severity", 1), ("next_steps", 3), ("containment", 0), ("missing_data", 2)]


# --- Fail closed -----------------------------------------------------------

def _tampered_model_call(result):
    result = result.model_copy(deep=True)
    result.model_calls[0].finish_reason = "weird"
    return result


def _tampered_tool_record(result):
    result = result.model_copy(deep=True)
    result.tool_records[0].view = "everything"
    return result


def _orphan_lookup(result):
    result = result.model_copy(deep=True)
    result.tool_records[0].requested_by = "model"
    result.tool_records[0].turn = 9   # no model call has this turn
    return result


@pytest.mark.parametrize("tamper", [
    _tampered_model_call, _tampered_tool_record, _orphan_lookup,
    lambda r: r.model_copy(update={"run_id": None}),
    lambda r: r.model_copy(update={"started_at": None}),
    lambda r: r.model_copy(update={"started_at": "2026-01-02T03:04:05Z"}),
    lambda r: r.model_copy(update={"started_at": "2026-01-02T03:04:05.678Z\n"}),
    lambda r: r.model_copy(update={"started_at": "2026-13-45T03:04:05.678Z"}),
    lambda r: r.model_copy(update={"duration_s": None}),
    lambda r: r.model_copy(update={"enrichment_duration_s": None}),
    lambda r: r.model_copy(update={"alert_id": "another-alert"}),
], ids=["model_call", "tool_record", "orphan_lookup", "no_run_id", "no_started_at", "started_at_no_ms",
        "started_at_newline", "started_at_invalid_date", "no_duration", "no_enrichment_duration", "other_alert"])
def test_invalid_result_writes_nothing(tamper, tmp_path, settings, tools):
    """A result outside its schema or not matching the alert must raise before any file or directory exists."""
    result, alert = _heuristic(settings, tools)
    bad = tamper(result)
    with pytest.raises(ValueError) as raised:
        audit_records(bad, alert)
    assert "weird" not in str(raised.value) and "everything" not in str(raised.value)
    path = tmp_path / "logs" / "audit.jsonl"
    with pytest.raises(ValueError):
        write_audit_log(bad, alert, path)
    assert not path.parent.exists()


def test_nan_duration_writes_nothing(tmp_path, settings, tools):
    """A NaN duration must fail serialization and nothing may be written."""
    result, alert = _heuristic(settings, tools)
    bad = result.model_copy(update={"duration_s": float("nan")})
    with pytest.raises(ValueError):
        dumps_line(audit_records(bad, alert)[0])
    path = tmp_path / "audit.jsonl"
    with pytest.raises(ValueError):
        write_audit_log(bad, alert, path)
    assert not path.exists()


NAN = float("nan")
# (object, field, value): every run-level value the projection writes, set
# after construction, where Pydantic does not validate assignment.
RUN_FIELD_TAMPERS = (
    [("alert", f, MARKER) for f in ("source", "rule_level")]
    + [("severity", "value", MARKER), ("enrichment", "status", MARKER)]
    + [("result", f, MARKER) for f in ("stop_reason", "budget_detail")]
    + [("result", f, v) for f in ("duration_s", "enrichment_duration_s")
       for v in (MARKER, True, -1.0, NAN, float("inf"))]
    + [("result", "tool_calls", v) for v in (MARKER, True, -1, NAN)]
    + [(o, f, v) for o, f in (("alert", "ingest_warnings"), ("result", "validation_errors"),
                              ("draft", "next_steps"), ("draft", "containment"), ("draft", "missing_data"))
       for v in (MARKER, (MARKER,))]
    # A marker string is a valid backend, and the backend is never written.
    + [("result", "backend", [MARKER])]
)


def _assert_run_field_refused(result, alert, tmp_path):
    with pytest.raises(ValueError) as raised:
        audit_records(result, alert)
    assert str(raised.value) == "a run-level field is outside its schema"
    assert MARKER not in str(raised.value)
    path = tmp_path / "logs" / "audit.jsonl"
    with pytest.raises(ValueError):
        write_audit_log(result, alert, path)
    assert not path.parent.exists()


@pytest.mark.parametrize("obj,field,value", RUN_FIELD_TAMPERS,
                         ids=[f"{o}.{f}-{v!r}" for o, f, v in RUN_FIELD_TAMPERS])
def test_run_field_outside_schema_writes_nothing(obj, field, value, tmp_path, settings, tools):
    """Regression test: a run-level value assigned outside its schema must raise a fixed message, writing nothing."""
    result, alert = _heuristic(settings, tools)
    result, alert = result.model_copy(deep=True), alert.model_copy(deep=True)
    assert result.draft is not None
    targets = {"alert": alert, "result": result, "enrichment": result.enrichment, "draft": result.draft,
               "severity": result.draft.severity}
    setattr(targets[obj], field, value)
    _assert_run_field_refused(result, alert, tmp_path)


@pytest.mark.parametrize("kind,reason", [(MARKER, MARKER), ("technique", MARKER), (MARKER, "not_found")])
def test_gap_outside_schema_writes_nothing(kind, reason, tmp_path, settings, tools):
    """Regression test: a gap built without validation must raise a fixed message, writing nothing."""
    result, alert = _heuristic(settings, tools)
    result = result.model_copy(deep=True)
    result.enrichment.gaps.append(Gap.model_construct(kind=kind, reason=reason))
    _assert_run_field_refused(result, alert, tmp_path)


def test_line_over_cap_writes_nothing(monkeypatch, tmp_path, settings, tools):
    """A line over the size cap must raise and nothing may be written."""
    result, alert = _heuristic(settings, tools)
    monkeypatch.setattr(audit, "MAX_AUDIT_LINE_BYTES", 300)
    path = tmp_path / "audit.jsonl"
    with pytest.raises(ValueError, match="MAX_AUDIT_LINE_BYTES"):
        write_audit_log(result, alert, path)
    assert not path.exists()


def test_worst_case_lines_fit(settings, tools):
    """Every line of the worst-case constructed run must fit the shipped line cap."""
    result, backend = run_worst_case(settings, tools)
    alert = backend.requests[0].alert
    lines = [dumps_line(r) for r in audit_records(result, alert)]
    sizes = [len(line.encode("ascii")) for line in lines]
    print(f"\nworst-case audit log: {len(lines)} lines, largest {max(sizes)} bytes")
    assert len(lines) == 1 + len(result.tool_records) + len(result.model_calls)
    assert max(sizes) <= audit.MAX_AUDIT_LINE_BYTES


# --- Privacy ----------------------------------------------------------------

class MarkedBackend(ScriptedBackend):
    """A scripted backend whose name, model and endpoint all carry text that must not be logged."""

    name = f"ollama:{MARKER}"
    model = f"qwen {MARKER}"
    endpoint = ENDPOINT


def test_nothing_untrusted_is_written(tmp_path, settings, tools):
    """No alert text, tool arguments or data, reply text, error message, backend name, model or endpoint may be written."""
    original = tools["runbook_search"].func
    marked = {**tools, "runbook_search": dataclasses.replace(
        tools["runbook_search"], func=lambda args: {"hits": [{"text": MARKER}]} if MARKER in args.query
        else original(args))}
    alert = Alert(alert_id="p-1", source="synthetic", rule_id="r-1", rule_title=f"Rule {MARKER}",
                  rule_level="high", rule_tags=["attack.t1059.001", f"tag.{MARKER}"], user=f"user {MARKER}",
                  timestamp=f"2026 {MARKER}", event={"CommandLine": f"-enc {MARKER}", MARKER: MARKER},
                  ingest_warnings=[f"warning {MARKER}"])
    lookups = _calls(("attack_lookup", {"technique_id": MARKER}), ("runbook_search", {"query": f"q {MARKER}"}),
                     ("delete_host", {MARKER: MARKER}))
    draft = {"severity": {"value": "high", "rationale": f"because {MARKER}", "sources": [FABRICATED]},
             "next_steps": [{"step": f"step {MARKER}", "sources": ["rule_level"]}],
             "containment": [{"action": f"isolate {MARKER}", "sources": ["rule_level"]}],
             "missing_data": [{"kind": "other", "description": f"missing {MARKER}", "sources": ["rule_level"]}]}
    replies = [dataclasses.replace(lookups, text=f"investigating {MARKER}"), ChatReply(text=f"done {MARKER}"),
               ChatReply(text=json.dumps(draft)), BackendError(f"ollama {ENDPOINT}: {MARKER}", error_type=MARKER)]
    backend = MarkedBackend(replies)
    result = run_agent(alert, backend, settings=settings, tools=marked)
    assert result.stop_reason == "backend_error"
    assert any(r.status == "ok" and MARKER in json.dumps(r.data) for r in result.evidence)  # the data existed
    assert any(MARKER in serialize_request(r).decode("utf-8") for r in backend.requests)   # and reached the model
    path = tmp_path / "audit.jsonl"
    assert write_audit_log(result, alert, path) == 1 + len(result.tool_records) + len(result.model_calls)
    data = path.read_bytes()
    assert MARKER.lower().encode() not in data.lower()
    assert b"192.0.2.10" not in data
    records = _lines(path)
    assert records[0]["gen_ai.provider.name"] == "ollama" and records[0]["gen_ai.request.model"] is None
    assert records[-1]["error.type"] == "_OTHER"


def test_lone_surrogates_written_as_ascii(tmp_path, settings, tools):
    """Lone surrogates in tool arguments and reply text must leave an ASCII log whose lines all parse."""
    replies = [dataclasses.replace(_calls(("runbook_search", {"query": "q\ud800"})), text="bad\udfff"),
               ChatReply(text="x\ud800y"), ChatReply(text="bad\ud800text"), ChatReply(text=VALID)]
    result, _ = _run(_powershell(), replies, settings, tools)
    assert result.stop_reason == "completed"
    path = tmp_path / "audit.jsonl"
    count = write_audit_log(result, _powershell(), path)
    records = _lines(path)
    assert len(records) == count


def test_dumps_line_escapes_lone_surrogates():
    """A lone surrogate must be escaped to ASCII and parse back to the same string."""
    line = dumps_line({"value": "a\ud800b\n"})
    assert line.isascii() and line.count("\n") == 1 and line.endswith("\n")
    assert json.loads(line) == {"value": "a\ud800b\n"}


# --- Writer -------------------------------------------------------------------

@pytest.fixture
def umask_022():
    old = os.umask(0o022)
    yield
    os.umask(old)


def _deterministic(settings, tools):
    alert = _powershell()
    result = run_agent(alert, HeuristicBackend(), settings=settings, tools=tools, timer=CountingTimer(),
                       wall_clock=lambda: WALL, run_id=RUN_ID)
    return result, alert


def test_new_file_and_directory_modes_and_append(umask_022, tmp_path, settings, tools):
    """A new log must be 0o600 in a new 0o700 directory, and a second run must append after the first."""
    result, alert = _deterministic(settings, tools)
    path = tmp_path / "logs" / "audit.jsonl"
    first = write_audit_log(result, alert, path)
    assert first == 1 + len(result.tool_records) + len(result.model_calls)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    once = path.read_bytes()
    assert write_audit_log(result, alert, path) == first
    data = path.read_bytes()
    assert data == once + once
    lines = data.split(b"\n")
    assert lines[-1] == b"" and len(lines) == 2 * first + 1
    for line in lines[:-1]:
        assert line.isascii()
        json.loads(line)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_same_inputs_give_identical_output(tmp_path, settings, tools):
    """Two runs with the same injected inputs must write byte-identical logs."""
    paths = [tmp_path / "a.jsonl", tmp_path / "b.jsonl"]
    for path in paths:
        result, alert = _deterministic(settings, tools)
        write_audit_log(result, alert, path)
    assert paths[0].read_bytes() == paths[1].read_bytes()


def _existing(path, mode=0o600, content=b"existing\n"):
    path.write_bytes(content)
    os.chmod(path, mode)
    return content


def _unchanged(path, content, mode):
    assert path.read_bytes() == content and stat.S_IMODE(os.lstat(path).st_mode) == mode


def test_symlink_refused(tmp_path, settings, tools):
    """A symlink at the log path must not be followed, and its target must be unchanged."""
    result, alert = _heuristic(settings, tools)
    outside = tmp_path / "outside" / "target.txt"
    outside.parent.mkdir()
    content = _existing(outside)
    logs = tmp_path / "logs"
    logs.mkdir(mode=0o700)
    (logs / "audit.jsonl").symlink_to(outside)
    with pytest.raises(OSError):
        write_audit_log(result, alert, logs / "audit.jsonl")
    _unchanged(outside, content, 0o600)
    assert (logs / "audit.jsonl").is_symlink()


def test_fifo_refused_without_hanging(tmp_path, settings, tools):
    """A FIFO at the log path must be refused promptly instead of blocking the writer."""
    result, alert = _heuristic(settings, tools)
    path = tmp_path / "audit.jsonl"
    os.mkfifo(path, 0o600)
    errors = []

    def write():
        try:
            write_audit_log(result, alert, path)
        except OSError as e:
            errors.append(e)

    worker = threading.Thread(target=write, daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(errors) == 1
    assert stat.S_ISFIFO(os.lstat(path).st_mode)


def test_directory_at_path_refused(tmp_path, settings, tools):
    """A directory at the log path must be refused."""
    result, alert = _heuristic(settings, tools)
    path = tmp_path / "audit.jsonl"
    path.mkdir(mode=0o700)
    with pytest.raises(OSError):
        write_audit_log(result, alert, path)
    assert list(path.iterdir()) == []


def test_group_readable_file_refused(tmp_path, settings, tools):
    """An existing log with group or other permissions must be refused, never chmod-ed."""
    result, alert = _heuristic(settings, tools)
    path = tmp_path / "audit.jsonl"
    content = _existing(path, 0o644)
    with pytest.raises(PermissionError):
        write_audit_log(result, alert, path)
    _unchanged(path, content, 0o644)


def test_file_owned_by_another_user_refused(monkeypatch, tmp_path, settings, tools):
    """An existing log owned by another user must be refused by the file check itself."""
    result, alert = _heuristic(settings, tools)
    path = tmp_path / "audit.jsonl"
    content = _existing(path)
    real = os.fstat

    def other_owner(fd):
        st = real(fd)
        return types.SimpleNamespace(st_mode=st.st_mode, st_uid=st.st_uid + 1)

    with monkeypatch.context() as m:
        m.setattr(os, "fstat", other_owner)
        with pytest.raises(PermissionError):
            write_audit_log(result, alert, path)
    _unchanged(path, content, 0o600)


def test_directory_owned_by_another_user_refused(monkeypatch, tmp_path, settings, tools):
    """A log directory owned by another user must be refused."""
    result, alert = _heuristic(settings, tools)
    logs = tmp_path / "logs"
    logs.mkdir(mode=0o700)
    real = os.lstat

    def other_owner(p, *args, **kwargs):
        st = real(p, *args, **kwargs)
        if os.fspath(p) == os.fspath(logs):
            return types.SimpleNamespace(st_mode=st.st_mode, st_uid=st.st_uid + 1)
        return st

    with monkeypatch.context() as m:
        m.setattr(os, "lstat", other_owner)
        with pytest.raises(PermissionError):
            write_audit_log(result, alert, logs / "audit.jsonl")
    assert list(logs.iterdir()) == []


def test_world_writable_directory_refused(tmp_path, settings, tools):
    """A log directory others can write to must be refused, never chmod-ed."""
    result, alert = _heuristic(settings, tools)
    logs = tmp_path / "logs"
    logs.mkdir()
    os.chmod(logs, 0o777)
    with pytest.raises(PermissionError):
        write_audit_log(result, alert, logs / "audit.jsonl")
    assert list(logs.iterdir()) == [] and stat.S_IMODE(logs.stat().st_mode) == 0o777


@pytest.mark.parametrize("link_mode", [None, 0o700], ids=["linux_mode", "owner_only_mode"])
def test_symlinked_directory_refused(link_mode, monkeypatch, tmp_path, settings, tools):
    """A log directory that is a symlink to a directory must be refused, whatever the link's own mode."""
    result, alert = _heuristic(settings, tools)
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "logs"
    link.symlink_to(real, target_is_directory=True)
    real_lstat = os.lstat

    def owner_only(p, *args, **kwargs):
        # Some systems (BSD, macOS) let a symlink have its own mode; then
        # only the file-type check refuses it.
        st = real_lstat(p, *args, **kwargs)
        if os.fspath(p) == os.fspath(link):
            return types.SimpleNamespace(st_mode=stat.S_IFLNK | link_mode, st_uid=st.st_uid)
        return st

    with monkeypatch.context() as m:
        if link_mode is not None:
            m.setattr(os, "lstat", owner_only)
        with pytest.raises(PermissionError):
            write_audit_log(result, alert, link / "audit.jsonl")
    assert list(real.iterdir()) == []


def test_missing_grandparent_raises(tmp_path, settings, tools):
    """Only the log's own directory may be created; a missing grandparent must raise."""
    result, alert = _heuristic(settings, tools)
    with pytest.raises(FileNotFoundError):
        write_audit_log(result, alert, tmp_path / "a" / "b" / "audit.jsonl")
    assert not (tmp_path / "a").exists()


def test_write_error_propagates(monkeypatch, tmp_path, settings, tools):
    """An error from os.write must propagate to the caller."""
    result, alert = _heuristic(settings, tools)

    def full(fd, data):
        raise OSError(28, "No space left on device")

    with monkeypatch.context() as m:
        m.setattr(os, "write", full)
        with pytest.raises(OSError, match="No space"):
            write_audit_log(result, alert, tmp_path / "audit.jsonl")


def test_write_without_progress_raises_promptly(monkeypatch, tmp_path, settings, tools):
    """Regression test: an os.write that returns 0 must raise OSError instead of looping forever."""
    result, alert = _heuristic(settings, tools)
    errors = []

    def write():
        try:
            write_audit_log(result, alert, tmp_path / "audit.jsonl")
        except Exception as e:
            errors.append(e)

    with monkeypatch.context() as m:
        m.setattr(os, "write", lambda fd, data: 0)
        worker = threading.Thread(target=write, daemon=True)
        worker.start()
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(errors) == 1 and type(errors[0]) is OSError
    assert str(errors[0]) == "audit log write made no progress"


def test_partial_writes_give_identical_output(monkeypatch, tmp_path, settings, tools):
    """Short writes of at most 7 bytes must still give a log byte-identical to a normal write."""
    real = os.write
    result, alert = _deterministic(settings, tools)
    write_audit_log(result, alert, tmp_path / "normal.jsonl")
    calls = []

    def short(fd, data):
        calls.append(1)
        return real(fd, data[:7])

    with monkeypatch.context() as m:
        m.setattr(os, "write", short)
        write_audit_log(result, alert, tmp_path / "short.jsonl")
    normal = (tmp_path / "normal.jsonl").read_bytes()
    assert (tmp_path / "short.jsonl").read_bytes() == normal
    assert len(calls) == -(-len(normal) // 7)


def test_without_o_nofollow_writes_nothing(monkeypatch, tmp_path, settings, tools):
    """Where O_NOFOLLOW is unavailable the writer must refuse before creating anything."""
    result, alert = _heuristic(settings, tools)
    monkeypatch.delattr(os, "O_NOFOLLOW")
    path = tmp_path / "logs" / "audit.jsonl"
    with pytest.raises(OSError, match="O_NOFOLLOW"):
        write_audit_log(result, alert, path)
    assert not path.parent.exists()
