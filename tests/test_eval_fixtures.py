"""Fixture builder for the evaluation tests, and checks on the fixtures themselves.

The fixture files hold hand-written patches and hand-written expectations
(tests/data/eval). This module turns them into pass directories the way the
harness will lay them out: an H record, a summary and an audit log per run,
and a hash-chained ledger. The ledger writer here is test code written
independently of records.verify_ledger, so a shared mistake in both would
have to be made twice.

Other test_eval_* modules import this one as `import test_eval_fixtures`.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from evaluation import records
from evaluation.common import load_h2
from triage.schemas import TriageSummary

DATA = Path(__file__).resolve().parent / "data" / "eval"
SCORER_FIXTURES = DATA / "scorer_fixtures.json"
AGGREGATE_FIXTURE = DATA / "aggregate_fixture.json"
REPO = Path(__file__).resolve().parent.parent
SAMPLE = REPO / "samples" / "alerts" / "sigma" / "password_spray.json"
TIMESTAMP = "2026-01-01T00:00:00.000Z"

# Written out here rather than imported, so the builder does not inherit a
# mistake in the module it tests.
H_KEY_ORDER = ("version", "pass_id", "position", "case_id", "role", "repeat", "backend", "started_at",
               "ended_at", "exit_status", "signal", "class", "reason", "run_id", "runbook_hits", "checks",
               "server_restarts", "cli_message", "stderr_nonempty", "files")
CHECK_KEY_ORDER = ("attempts", "code", "python", "embedder", "ollama", "server_settings", "disk")
SCAN_RULES = ("inline-allow", "ipv4", "ipv6", "email", "url-host", "phone", "ssn")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="ascii"))


def scorer_doc() -> dict:
    return load_json(SCORER_FIXTURES)


def aggregate_doc() -> dict:
    return load_json(AGGREGATE_FIXTURE)


def canonical(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii") + b"\n"


def merge(target, patch):
    """RFC 7386 merge for objects, except that a null sets the member to null.

    The fixtures need null values (a run with no hits, a run with no draft),
    and none of them removes a member, so the deletion rule is not used.
    """
    if not isinstance(patch, dict) or not isinstance(target, dict):
        return copy.deepcopy(patch)
    out = copy.deepcopy(target)
    for key, value in patch.items():
        out[key] = merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) \
            else copy.deepcopy(value)
    return out


def run_id_for(pass_id: str, position: int) -> str:
    return hashlib.sha256(f"{pass_id}/{position}".encode("ascii")).hexdigest()[:32]


def ip_documentation_address() -> str:
    # Built at run time: a committed fixture never holds an address.
    return ".".join(("192", "0", "2", "10"))


def summary_record(s: dict, run_id: str, seq: int) -> dict:
    """The triage.summary audit record for S, from the shared-field table, in triage's key order."""
    missing = s["missing_data"]
    return {
        "timestamp": TIMESTAMP, "event.name": "triage.summary", "triage.audit.schema_version": 2,
        "gen_ai.conversation.id": run_id, "triage.seq": seq, "gen_ai.operation.name": "invoke_agent",
        "triage.summary.status": s["status"],
        "triage.severity.value": s["severity"]["value"],
        "triage.severity.rule_floor": s["severity"]["rule_floor"],
        "triage.severity.origin": s["severity"]["origin"],
        "triage.severity.sources": list(s["severity"]["sources"]),
        "triage.technique.id": s["technique"].get("technique_id"),
        "triage.technique.basis": s["technique"]["basis"],
        "triage.technique.origin": s["technique"]["origin"],
        "triage.asset.criticality": s["asset"]["criticality"],
        "triage.asset.exposure": s["asset"]["exposure"],
        "triage.findings": {
            "next_steps": len(s["next_steps"]),
            "containment": len(s["containment"]),
            "missing_data_enrichment": len([m for m in missing if m["origin"] == "enrichment"]),
            "missing_data_model": len([m for m in missing if m["origin"] == "model"]),
        },
        "triage.anomalies": list(s["anomalies"]),
        "triage.injection.suspected": s["injection_suspected"],
        "triage.injection.signals": list(s["injection_signals"]),
    }


@dataclass
class Run:
    position: int
    case_id: str
    role: str
    repeat: int
    h: dict
    s: dict | None
    audit: list[dict] | None


@dataclass
class Pass:
    pass_id: str
    sequence: str
    runs: list[Run]
    end_class: str
    public: bool
    items: list[dict] = field(default_factory=list)
    ledger: str = "valid"


def build_run(base: dict, cases: dict, pass_id: str, sequence: str, entry: dict, spec: dict) -> Run:
    """One run from the base records, the case and the spec's S, A and H patches."""
    position, cid = entry["position"], entry["case_id"]
    case = cases[cid]
    run_id = run_id_for(pass_id, position)
    s_patch = spec.get("S", {})
    s = None
    if s_patch is not None:
        s = merge(base["S"], {"alert_id": case["alert_id"], "run_id": run_id,
                              "severity": {"rule_floor": case["rule_level"]}})
        s = merge(s, s_patch)
    a_spec = spec.get("A", {})
    audit = None
    if a_spec != "absent":
        a_spec = {"run": {}, "tools": [{}], "summary": "derived", "model_calls": 1, **a_spec}
        audit = []
        if a_spec["run"] != "absent":
            audit.append(merge(base["A"]["triage.run"], a_spec["run"]))
        audit += [merge(base["A"]["triage.tool_call"], patch) for patch in a_spec["tools"]]
        audit += [copy.deepcopy(base["A"]["triage.model_call"]) for _ in range(a_spec["model_calls"])]
        if s is not None and a_spec["summary"] != "absent":
            record = summary_record(s, run_id, 0)
            if isinstance(a_spec["summary"], dict):
                record = merge(record, a_spec["summary"])
            audit.append(record)
    h = merge(base["H"], {
        "pass_id": pass_id, "position": position, "case_id": cid, "role": entry["role"],
        "repeat": entry["repeat"], "backend": "heuristic" if sequence == "baseline" else "ollama",
        "run_id": run_id if s is None else s["run_id"],
        "files": {"summary": s is not None, "audit": audit is not None}})
    h = merge(h, spec.get("H", {}))
    conversation = s["run_id"] if s is not None else (h["run_id"] or run_id)
    for seq, record in enumerate(audit or []):
        record["gen_ai.conversation.id"] = conversation
        record["triage.seq"] = seq
    h = {key: h[key] for key in H_KEY_ORDER}
    h["checks"] = {key: h["checks"][key] for key in CHECK_KEY_ORDER}
    h["files"] = {"summary": h["files"]["summary"], "audit": h["files"]["audit"]}
    return Run(position, cid, entry["role"], entry["repeat"], h, s, audit)


def ledger_bytes(runs: list[Run], end_class: str, *, broken: bool = False) -> bytes:
    """A reference ledger: canonical lines, seq from 1, each prev the SHA-256 of the previous line."""
    events = [("pass_start", None, None, None)]
    for run in runs:
        events.append(("run_start", run.position, run.case_id, None))
        events.append(("run_end", run.position, run.case_id, run.h["class"]))
    events.append(("pass_end", None, None, end_class))
    lines, prev = [], "0" * 64
    for seq, (event, position, cid, cls) in enumerate(events, start=1):
        if broken and seq == len(events):
            prev = "f" * 64
        line = canonical({"seq": seq, "event": event, "position": position, "case_id": cid,
                          "class": cls, "prev": prev})
        lines.append(line)
        prev = hashlib.sha256(line).hexdigest()
    return b"".join(lines)


def summary_bytes(s: dict, public: bool) -> bytes:
    if public:
        return canonical(s)
    # The original text: each placeholder replaced by the value it stood for.
    text = canonical(s).decode("ascii")
    for n in range(1, 10):
        text = text.replace(f"<<REDACTED:ipv4:{n}>>", ip_documentation_address())
    return text.encode("ascii")


@dataclass
class Written:
    directory: Path
    kwargs: dict


def write_pass(root: Path, spec: Pass) -> Written:
    """Write the pass directory and its redaction records; return load_pass's keyword arguments."""
    directory = root / spec.pass_id
    directory.mkdir(parents=True)
    for run in spec.runs:
        stem = directory / f"run-{run.position:04d}"
        Path(f"{stem}.harness.json").write_bytes(canonical(run.h))
        if run.s is not None:
            Path(f"{stem}.summary.json").write_bytes(summary_bytes(run.s, spec.public))
        if run.audit is not None:
            Path(f"{stem}.audit.jsonl").write_bytes(b"".join(canonical(r) for r in run.audit))
    (directory / "ledger.jsonl").write_bytes(ledger_bytes(spec.runs, spec.end_class,
                                                          broken=spec.ledger == "broken_chain"))
    if spec.public:
        path = root / f"{spec.pass_id}.redactions.json"
        path.write_bytes(canonical({"version": 1, "items": spec.items}))
        kwargs = {"public": True, "redactions": path}
    else:
        scan = root / f"{spec.pass_id}.scan-items.json"
        scan_data = canonical({"version": 1, "items": [
            {"n": i["n"], "file": i["file"], "pointer": i["pointer"], "rule": i["rule"]}
            for i in spec.items if i["rule"] in SCAN_RULES]})
        scan.write_bytes(scan_data)
        classification = root / f"{spec.pass_id}.classification.json"
        classification.write_bytes(canonical({
            "version": 1, "scan_sha256": hashlib.sha256(scan_data).hexdigest(),
            "items": {str(i["n"]): i["classification"] for i in spec.items if i["rule"] in SCAN_RULES}}))
        kwargs = {"public": False, "scan_items": scan, "classification": classification}
    return Written(directory, kwargs)


# --- Inputs as validated models ----------------------------------------------

def models(doc: dict, order: dict):
    registry = records.Registry.model_validate(doc["registry"])
    labels = records.Labels.model_validate(doc["labels"])
    return registry, labels, records.Order.model_validate(order)


def load(written: Written, doc: dict, order: dict, sequence: str, *, fixture: bool = True):
    registry, labels, order_model = models(doc, order)
    return records.load_pass(written.directory, registry=registry, labels=labels, order=order_model,
                             sequence=sequence, fixture=fixture, **written.kwargs)


# --- Scorer fixtures (tests/data/eval/scorer_fixtures.json) -------------------------------------------------------

def scorer_order(doc: dict, first: str) -> dict:
    """A fixture-mode order (k = 2) whose rounds start with the fixture's case."""
    tests = [c["case_id"] for c in doc["registry"]["cases"] if c["family"] != "dev"]
    round_ = [first] + [c for c in tests if c != first]

    def sequence(roles):
        entries = [{"position": 1, "case_id": "fx-dev1", "role": "warmup", "repeat": 1}]
        for r, role in enumerate(roles, start=1):
            for cid in round_:
                entries.append({"position": len(entries) + 1, "case_id": cid, "role": role, "repeat": r})
        return entries

    return {"version": 1, "seed": "2" * 64, "k": 2, "baseline": sequence(["scored", "determinism"]),
            "model": sequence(["scored", "scored"])}


def scorer_pass(doc: dict, fixture: dict, *, public: bool | None = None) -> tuple[Pass, dict]:
    """The pass for one scorer fixture: warm-up, the fixture's run, and its optional second run."""
    sequence = fixture["sequence"]
    pass_id = f"{sequence}-001"
    order = scorer_order(doc, fixture["case_id"])
    entries = order[sequence]
    cases = {c["case_id"]: c for c in doc["registry"]["cases"]}
    total = len(cases) - 1
    specs = {1: {}, 2: {"S": fixture["S"], "A": fixture["A"], "H": fixture["H"]}}
    if "second" in fixture:
        for position in range(3, 2 + total):
            specs[position] = {}
        specs[2 + total] = fixture["second"]
    runs = [build_run(doc["base"], cases, pass_id, sequence, entries[p - 1], specs[p]) for p in sorted(specs)]
    items = fixture.get("public", [])
    spec = Pass(pass_id, sequence, runs, "incomplete", public=bool(items) if public is None else public,
                items=items, ledger=fixture.get("ledger", "valid"))
    return spec, order


def scorer_fixtures() -> list[dict]:
    return scorer_doc()["fixtures"]


# --- Aggregation fixture (tests/data/eval/aggregate_fixture.json) -----------------------------------------------------

def aggregate_passes(doc: dict, base: dict) -> list[Pass]:
    cases = {c["case_id"]: c for c in doc["registry"]["cases"]}
    out = []
    for p in doc["passes"]:
        entries = doc["order"][p["sequence"]][: p["stop_after"]]
        runs = [build_run(base, cases, p["pass_id"], p["sequence"], e, p["runs"].get(str(e["position"]), {}))
                for e in entries]
        out.append(Pass(p["pass_id"], p["sequence"], runs, p["end_class"], public=p["mode"] == "public",
                        items=p["redactions"]))
    return out


def all_runs() -> list[Run]:
    doc = scorer_doc()
    runs = []
    for fixture in doc["fixtures"]:
        runs += scorer_pass(doc, fixture)[0].runs
    runs += [r for p in aggregate_passes(aggregate_doc(), doc["base"]) for r in p.runs]
    return runs


# --- Tests -----------------------------------------------------------------------

def _invalid_on_purpose(fixture: dict) -> bool:
    return "validation s-schema" in fixture["covers"]


def _without_placeholders(s: dict) -> dict:
    text = json.dumps(s)
    for rule in SCAN_RULES:
        for n in range(1, 10):
            text = text.replace(f"<<REDACTED:{rule}:{n}>>", "")
    return json.loads(text)


def test_every_effective_summary_validates():
    doc = scorer_doc()
    for fixture in doc["fixtures"]:
        spec, _ = scorer_pass(doc, fixture)
        for run in spec.runs:
            if run.s is None or (run.position == 2 and _invalid_on_purpose(fixture)):
                continue
            # A public summary validates through its removal copy.
            TriageSummary.model_validate(_without_placeholders(run.s) if spec.public else run.s)
    for p in aggregate_passes(aggregate_doc(), doc["base"]):
        for run in p.runs:
            if run.s is not None:
                TriageSummary.model_validate(_without_placeholders(run.s))


def test_the_schema_fixture_is_invalid_and_the_public_one_only_through_its_removal_copy():
    doc = scorer_doc()
    by_name = {f["name"]: f for f in doc["fixtures"]}
    spec, _ = scorer_pass(doc, by_name["defect-s-schema"])
    with pytest.raises(ValueError):
        TriageSummary.model_validate(spec.runs[1].s)
    spec, _ = scorer_pass(doc, by_name["public-placeholder-over-limit"])
    with pytest.raises(ValueError):
        TriageSummary.model_validate(spec.runs[1].s)
    TriageSummary.model_validate(_without_placeholders(spec.runs[1].s))


@pytest.fixture(scope="module")
def reference_key_sets(settings, tools):
    """Key sets of a real heuristic run's audit records, by event name."""
    from triage.agent import run_agent
    from triage.audit import audit_records
    from triage.backends import HeuristicBackend
    from triage.guardrails import build_summary
    from triage.ingest import load_alert

    alert = load_alert(SAMPLE.read_bytes(), "sigma")
    result = run_agent(alert, HeuristicBackend(), settings=settings, tools=tools)
    summary = build_summary(result, alert, settings, tools)
    keys: dict[str, set] = {}
    nested = None
    for record in audit_records(result, alert, summary=summary):
        keys.setdefault(record["event.name"], set()).add(frozenset(record))
        if record["event.name"] == "triage.summary":
            nested = frozenset(record["triage.findings"])
    return keys, nested


def test_audit_records_have_a_real_runs_key_sets(reference_key_sets, no_network):
    keys, nested = reference_key_sets
    assert no_network.attempts == []
    assert set(keys) == {"triage.run", "triage.tool_call", "triage.model_call", "triage.summary"}
    assert all(len(v) == 1 for v in keys.values())
    reference = {name: next(iter(v)) for name, v in keys.items()}
    # Every allow-listed audit field and every shared field is in the real records.
    assert records.A_RUN_PATHS <= reference["triage.run"]
    assert records.A_TOOL_PATHS <= reference["triage.tool_call"]
    for path, _ in records.SHARED_FIELDS:
        assert path[0] in reference["triage.summary"]
        if len(path) == 2:
            assert path[1] in nested
    for run in all_runs():
        for record in run.audit or []:
            assert frozenset(record) == reference[record["event.name"]], (run.case_id, record["event.name"])
            if record["event.name"] == "triage.summary":
                assert frozenset(record["triage.findings"]) == nested


def test_fixtures_follow_their_own_rules():
    names = [f["name"] for f in scorer_fixtures()]
    assert len(names) == len(set(names))
    for fixture in scorer_fixtures():
        assert fixture["covers"] and all(isinstance(c, str) and c for c in fixture["covers"])
        assert fixture["case_id"].startswith("fx-")
    cases = [c["case_id"] for c in scorer_doc()["registry"]["cases"] + aggregate_doc()["registry"]["cases"]]
    assert all(c.startswith("fx-") for c in cases)


REQUIRED_COVERS = (
    "triage decisions: severity_agree", "triage decisions: under", "triage decisions: over by floor", "triage decisions: over by model", "triage decisions: over by tripwire",
    "triage decisions: technique in the set", "triage decisions: technique null with an empty set (ok)",
    "triage decisions: technique null with a non-empty set (not ok)", "triage decisions: status equal", "triage decisions: status unequal",
    "triage decisions: retrieval top hit equal", "triage decisions: retrieval empty with none (ok)",
    "triage decisions: retrieval empty with a runbook expected (not ok)", "triage decisions: non-empty hits with none expected (not ok)",
    "no output without S and with an A-run record", "no output with no A", "every triage-decision row false",
    "objectives no valid draft", "edge case: empty technique", "edge case: no runbook hit",
    "edge case: floor equal to label (agreement, not over)", "edge case: origin tripwire",
    "edge case: marker inside backticks (occurred, mentioned-not-placed)", "draft valid", "draft_invalid",
    "draft_citation_invalid", "draft_unavailable", "output integrity: completed", "output integrity: budget_exceeded", "output integrity: budget detail",
    "output integrity: backend error type", "output integrity: invalid_output", "output integrity: model searches 0", "output integrity: model searches 2",
    "tripwire: flagged", "tripwire: not flagged", "tripwire: signals", "tripwire: origin tripwire counted as raised",
    "marker objective: marker only in the rationale (mentioned-not-placed)",
    "marker objective: marker inside a longer step (mentioned-not-placed)",
    "marker objective: a step exactly Ref: marker (followed, effective)",
    "marker objective: the same step with surrounding spaces (followed)", "severity objective without a draft, target at the floor",
    "severity objective raised by the tripwire (followed, not effective)", "clean-twin control produces the target", "O-T occurred, followed, effective",
    "O-T origin rule (occurred, not effective)", "public mode removal copy",
)
RULE_IDS = ("ledger", "h-binding", "b4-rule-1", "b4-rule-2", "s-schema", "s-binding", "s-invariant", "b4-rule-3",
            "b4-rule-4", "b4-rule-5", "hits-null", "determinism", "tripwire-consistency")


def test_fixtures_cover_every_required_row():
    covers = {c for f in scorer_fixtures() for c in f["covers"]}
    assert set(REQUIRED_COVERS) <= covers
    for rule in RULE_IDS:
        assert f"validation {rule}" in covers
    # b4-rule-4: one fixture per shared field.
    shared = [f for f in scorer_fixtures() if any(c.startswith("shared field ") for c in f["covers"])]
    assert len(shared) == len(records.SHARED_FIELDS)


def test_fixture_files_are_ascii_and_clean_under_the_synthetic_data_rules():
    h2 = load_h2()
    for path in (SCORER_FIXTURES, AGGREGATE_FIXTURE, DATA / "report_expected.md"):
        data = path.read_bytes()
        assert all(b in (9, 10) or 32 <= b <= 126 for b in data), path.name
        rel = path.relative_to(REPO).as_posix()
        assert h2.check_content(rel, data, h2.path_class(rel)) == [], path.name
