"""The audit log's triage.summary record: codes and counts only, version 2 (DD-023)."""

import json
import os
import shutil
import warnings
from datetime import datetime, timedelta
from typing import get_args

import pytest

from test_audit import COMMON_KEYS, MARKER, POWERSHELL, RUN_ID, SAMPLES, WALL, CountingTimer, _load, _lines
from triage import audit
from triage.agent import run_agent
from triage.audit import audit_records, dumps_line, write_audit_log
from triage.backends import HeuristicBackend
from triage.config import REPO_ROOT
from triage.guardrails import build_summary
from triage.schemas import Anomaly, ContainmentAction, InjectionSignal, MissingItem, NextStep

V1_FIXTURE = REPO_ROOT / "tests" / "data" / "audit_v1_heuristic.jsonl"
SUMMARY_KEYS = COMMON_KEYS + [
    "triage.summary.status", "triage.severity.value", "triage.severity.rule_floor", "triage.severity.origin",
    "triage.severity.sources", "triage.technique.id", "triage.technique.basis", "triage.technique.origin",
    "triage.asset.criticality", "triage.asset.exposure", "triage.findings", "triage.anomalies",
    "triage.injection.suspected", "triage.injection.signals",
]


def _fixture_run(settings, tools):
    alert = _load(POWERSHELL)
    result = run_agent(alert, HeuristicBackend(), settings=settings, tools=tools, timer=CountingTimer(),
                       wall_clock=lambda: WALL, run_id=RUN_ID)
    return result, alert, build_summary(result, alert, settings=settings, tools=tools)


def _private_dir(tmp_path):
    d = tmp_path / "logs"
    d.mkdir(mode=0o700)
    os.chmod(d, 0o700)
    return d


def test_without_summary_matches_version_1_except_the_version(settings, tools):
    """Without a summary, any record content other than the version differs from the version-1 writer."""
    result, alert, _ = _fixture_run(settings, tools)
    v1 = [json.loads(line) for line in V1_FIXTURE.read_text(encoding="ascii").splitlines()]
    now = audit_records(result, alert)
    assert [r["triage.audit.schema_version"] for r in v1] == [1] * len(v1)
    assert now == [{**r, "triage.audit.schema_version": 2} for r in v1]


def test_summary_record(settings, tools):
    """The summary record is missing, misplaced, has other keys or carries values not taken from the summary."""
    result, alert, summary = _fixture_run(settings, tools)
    without = audit_records(result, alert)
    records = audit_records(result, alert, summary=summary)
    assert records[:-1] == without
    record = records[-1]
    assert list(record) == SUMMARY_KEYS
    started = datetime.strptime(result.started_at, "%Y-%m-%dT%H:%M:%S.%fZ")
    assert record["timestamp"] == (started + timedelta(seconds=result.duration_s)).isoformat(
        timespec="milliseconds") + "Z"
    assert record["event.name"] == "triage.summary" and record["gen_ai.operation.name"] == "invoke_agent"
    assert record["triage.seq"] == len(without) and record["triage.audit.schema_version"] == 2
    assert record["gen_ai.conversation.id"] == RUN_ID
    s = summary
    assert {k: record[k] for k in SUMMARY_KEYS[len(COMMON_KEYS):]} == {
        "triage.summary.status": s.status, "triage.severity.value": s.severity.value,
        "triage.severity.rule_floor": s.severity.rule_floor, "triage.severity.origin": s.severity.origin,
        "triage.severity.sources": s.severity.sources, "triage.technique.id": s.technique.technique_id,
        "triage.technique.basis": s.technique.basis, "triage.technique.origin": s.technique.origin,
        "triage.asset.criticality": s.asset.criticality, "triage.asset.exposure": s.asset.exposure,
        "triage.findings": {"next_steps": len(s.next_steps), "containment": len(s.containment),
                            "missing_data_enrichment": sum(m.origin == "enrichment" for m in s.missing_data),
                            "missing_data_model": sum(m.origin == "model" for m in s.missing_data)},
        "triage.anomalies": s.anomalies, "triage.injection.suspected": s.injection_suspected,
        "triage.injection.signals": s.injection_signals,
    }


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_sample_summary_projects(path, settings, tools):
    """A sample's summary record is missing, has other keys or fails to serialize."""
    alert = _load(path)
    result = run_agent(alert, HeuristicBackend(), settings=settings, tools=tools)
    summary = build_summary(result, alert, settings=settings, tools=tools)
    records = audit_records(result, alert, summary=summary)
    assert [r["event.name"] for r in records].count("triage.summary") == 1
    assert list(records[-1]) == SUMMARY_KEYS
    for r in records:
        dumps_line(r)


def test_version_2_appends_after_version_1(tmp_path, settings, tools):
    """Appending version-2 records changes existing version-1 lines or leaves lines without their own version."""
    result, alert, summary = _fixture_run(settings, tools)
    path = _private_dir(tmp_path) / "audit.jsonl"
    shutil.copyfile(V1_FIXTURE, path)
    os.chmod(path, 0o600)
    before = path.read_bytes()
    written = write_audit_log(result, alert, path, summary=summary)
    after = path.read_bytes()
    assert after.startswith(before)
    records = _lines(path)
    v1 = before.count(b"\n")
    assert written == len(records) - v1 == 1 + len(result.tool_records) + len(result.model_calls) + 1
    assert [r["triage.audit.schema_version"] for r in records] == [1] * v1 + [2] * written
    assert records[-1]["event.name"] == "triage.summary"


def _assigned(summary, field, value):
    # Assignment after construction is not validated.
    copy = summary.model_copy()
    object.__setattr__(copy, field, value)
    return copy


INVALID = "summary is not a valid TriageSummary"
MISMATCH = "summary does not match the run"
BAD_SUMMARIES = [
    ("dict", lambda s: s.model_dump(), INVALID),
    ("status", lambda s: _assigned(s, "status", f"bogus {MARKER}"), INVALID),
    ("asset", lambda s: _assigned(s, "asset", object()), INVALID),
    ("alert_id", lambda s: s.model_copy(update={"alert_id": "other-alert"}), MISMATCH),
    ("run_id", lambda s: s.model_copy(update={"run_id": "f" * 32}), MISMATCH),
    ("line_cap", lambda s: s.model_copy(update={"anomalies": [max(get_args(Anomaly), key=len)] * 300}),
     "audit record exceeds MAX_AUDIT_LINE_BYTES"),
]


@pytest.mark.parametrize("make,message", [(m, msg) for _, m, msg in BAD_SUMMARIES],
                         ids=[name for name, _, _ in BAD_SUMMARIES])
def test_bad_summary_writes_nothing(make, message, tmp_path, settings, tools):
    """An invalid, mismatched or oversized summary writes a byte, creates a file or echoes input."""
    result, alert, summary = _fixture_run(settings, tools)
    bad = make(summary)
    missing = tmp_path / "new" / "audit.jsonl"
    existing = _private_dir(tmp_path) / "audit.jsonl"
    shutil.copyfile(V1_FIXTURE, existing)
    os.chmod(existing, 0o600)
    before = existing.read_bytes()
    with warnings.catch_warnings():
        warnings.simplefilter("error")   # a serializer warning would quote the value
        for path in (missing, existing):
            with pytest.raises(ValueError) as raised:
                write_audit_log(result, alert, path, summary=bad)
            assert str(raised.value) == message and MARKER not in str(raised.value)
    assert not missing.parent.exists()
    assert existing.read_bytes() == before


def test_summary_text_never_written(tmp_path, settings, tools):
    """Model text, the technique name, or the asset host or owner reaches the log."""
    result, alert, summary = _fixture_run(settings, tools)
    marked = summary.model_copy(update={
        "severity": summary.severity.model_copy(update={"rationale": f"because {MARKER}"}),
        "technique": summary.technique.model_copy(update={"name": f"name {MARKER}"}),
        "asset": summary.asset.model_copy(update={"host": f"host-{MARKER}", "owner": f"Owner {MARKER}"}),
        "next_steps": [NextStep(step=f"step {MARKER}", sources=["rule_level"])],
        "containment": [ContainmentAction(action=f"isolate {MARKER}")],
        "missing_data": [MissingItem(kind="other", description=f"missing {MARKER}", origin="model")]})
    assert marked.model_dump_json().count(MARKER) == 7
    path = _private_dir(tmp_path) / "audit.jsonl"
    write_audit_log(result, alert, path, summary=marked)
    data = path.read_bytes()
    assert MARKER.lower().encode() not in data.lower()
    assert _lines(path)[-1]["triage.findings"] == {"next_steps": 1, "containment": 1,
                                                   "missing_data_enrichment": 0, "missing_data_model": 1}


def test_summary_values_written_as_plain_str(settings, tools):
    """A str subclass assigned to a summary field is written as itself instead of its validated value."""
    class Sneaky(str):
        pass
    result, alert, summary = _fixture_run(settings, tools)
    bad = summary.model_copy(update={"severity": summary.severity.model_copy(
        update={"sources": [Sneaky("rule_level")]})})
    record = audit_records(result, alert, summary=bad)[-1]
    assert [type(s) for s in record["triage.severity.sources"]] == [str]


def test_largest_summary_record_fits(settings, tools):
    """The largest summary record within the schema's own caps exceeds the line cap."""
    result, alert, summary = _fixture_run(settings, tools)
    sources = ["a" + "b" * 63 + f":{n:016x}" for n in range(19)]
    big = summary.model_copy(update={
        "status": "insufficient_data",
        "severity": summary.severity.model_copy(update={"value": "informational", "rule_floor": "informational",
                                                        "origin": "tripwire", "sources": sources}),
        "technique": summary.technique.model_copy(update={"technique_id": "T1234.567", "basis": "rule_mapping",
                                                          "origin": "model"}),
        "asset": summary.asset.model_copy(update={"criticality": "critical", "exposure": "internet-facing"}),
        "anomalies": [max(get_args(Anomaly), key=len)] * 9,
        "injection_suspected": True, "injection_signals": [max(get_args(InjectionSignal), key=len)] * 8,
        "next_steps": [NextStep(step="s", sources=["rule_level"])] * 8,
        "containment": [ContainmentAction(action="c")] * 5,
        "missing_data": ([MissingItem(kind="other", description="d", origin="enrichment")] * 14
                         + [MissingItem(kind="other", description="d", origin="model")] * 16)})
    size = len(dumps_line(audit_records(result, alert, summary=big)[-1]).encode("ascii"))
    print(f"\nlargest summary record: {size} bytes")
    assert size <= audit.MAX_AUDIT_LINE_BYTES
