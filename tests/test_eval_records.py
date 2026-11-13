"""Record schemas, validators, the ledger verifier, the views and the scorer's purity."""

from __future__ import annotations

import ast
import copy
import errno
import gc
import hashlib
import json

import pytest

import test_eval_fixtures as fx
from evaluation import common, records
from triage import cli as triage_cli

EVALUATION = fx.REPO / "evaluation"


# --- strict JSON ---------------------------------------------------------------------

def test_strict_loads_refuses_duplicate_keys_nan_and_bad_utf8():
    with pytest.raises(common.SchemaError):
        common.strict_loads(b'{"a": 1, "a": 2}')
    for constant in (b"NaN", b"Infinity", b"-Infinity", b'{"a": NaN}'):
        with pytest.raises(common.SchemaError):
            common.strict_loads(constant)
    with pytest.raises(common.SchemaError):
        common.strict_loads(b'"\xff"')
    assert common.strict_loads(b'{"a": [1, 2.5, true, null]}') == {"a": [1, 2.5, True, None]}


def test_canonical_dumps_is_compact_ascii_and_insertion_ordered():
    assert common.canonical_dumps({"b": 1, "a": "\u00e9"}) == b'{"b":1,"a":"\\u00e9"}\n'
    with pytest.raises(ValueError):
        common.canonical_dumps({"a": float("nan")})


def test_read_regular_refuses_a_symlink_and_write_new_file_an_existing_path(tmp_path):
    target = tmp_path / "target.json"
    target.write_bytes(b"{}\n")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(common.EvaluationError):
        common.read_regular(link)
    with pytest.raises(common.EvaluationError):
        common.read_regular(tmp_path)
    with pytest.raises(common.EvaluationError):
        common.write_new_file(target, b"x")
    common.write_new_file(tmp_path / "new.json", b"x")
    assert (tmp_path / "new.json").read_bytes() == b"x"


# --- Schemas: one valid document each, and the same refusals for all ----------------------

def _registry():
    return copy.deepcopy(fx.scorer_doc()["registry"])


def _labels():
    return copy.deepcopy(fx.scorer_doc()["labels"])


def _order():
    return fx.scorer_order(fx.scorer_doc(), "fx-a1")


def _h():
    doc = fx.scorer_doc()
    spec, _ = fx.scorer_pass(doc, doc["fixtures"][0])
    return copy.deepcopy(spec.runs[1].h)


def _registry_ok(doc):
    return not records.registry_problems(doc, allow_fixture_ids=True)


def _labels_ok(doc):
    return not records.labels_schema_problems(doc)


def _order_ok(doc):
    return not records.order_problems(doc, records.Registry.model_validate(_registry()), fixture=True)


def _h_ok(doc):
    try:
        records.load_harness(fx.canonical(doc))
    except common.DefectError:
        return False
    return True


def _redactions_ok(doc):
    try:
        records.load_redactions(fx.canonical(doc))
    except common.SchemaError:
        return False
    return True


def _setup_ok(doc):
    try:
        records.Setup.model_validate(doc)
    except ValueError:
        return False
    return True


REDACTIONS = {"version": 1, "items": [{"file": "run-0002.summary.json", "pointer": "/next_steps/0/step",
                                       "rule": "ipv4", "n": 1, "classification": "synthetic-match"}]}
SETUP = {"model": "fixture-model:0", "digest": "sha256:" + "0" * 64, "think": False}

# (name, valid document, validator, path to an object, a string field, an int field, a boolean field,
#  a patterned field, a value outside its pattern)
SCHEMAS = [
    ("registry", _registry, _registry_ok, ("cases", 1), "format", None, None, "alert_id", "bad id!"),
    ("labels", _labels, _labels_ok, ("cases", 6), "expected_runbook", None, "expected_flagged", "rubric_sha256",
     "xyz"),
    ("order", _order, _order_ok, ("model", 1), "role", "position", None, "seed", "not-hex"),
    ("harness", _h, _h_ok, (), "backend", "position", "stderr_nonempty", "started_at", "2026-01-01 00:00:00"),
    ("redactions", lambda: copy.deepcopy(REDACTIONS), _redactions_ok, ("items", 0), "rule", "n", None, "pointer",
     "no-slash"),
    ("setup", lambda: copy.deepcopy(SETUP), _setup_ok, (), "model", None, "think", "digest", "sha256:xyz"),
]


def _at(doc, path):
    node = doc
    for part in path:
        node = node[part]
    return node


@pytest.mark.parametrize("name, make, ok, path, text, number, boolean, patterned, bad", SCHEMAS,
                         ids=[s[0] for s in SCHEMAS])
def test_schema_accepts_its_valid_document_and_refuses_variants(name, make, ok, path, text, number, boolean,
                                                                patterned, bad):
    assert ok(make())
    doc = make()
    _at(doc, path)["unexpected"] = 1
    assert not ok(doc), "extra key"
    doc = make()
    del _at(doc, path)[text]
    assert not ok(doc), "missing key"
    doc = make()
    _at(doc, path)[text] = 1
    assert not ok(doc), "wrong type"
    if number is not None:
        doc = make()
        _at(doc, path)[number] = str(_at(doc, path)[number])
        assert not ok(doc), "numeric string"
        doc = make()
        _at(doc, path)[number] = True
        assert not ok(doc), "boolean for a number"
    if boolean is not None:
        doc = make()
        _at(doc, path)[boolean] = "true" if _at(doc, path)[boolean] else "false"
        assert not ok(doc), "boolean as a string"
    doc = make()
    _at(doc, [] if patterned in ("rubric_sha256", "seed") else path)[patterned] = bad
    assert not ok(doc), "bad pattern"


def test_version_must_be_the_integer_one():
    for value in (True, 2, "1", 1.0):
        doc = _registry()
        doc["version"] = value
        assert records.registry_problems(doc, allow_fixture_ids=True)


# --- Registry ---------------------------------------------------------------------------

def test_registry_twin_and_phrasing_rules():
    doc = _registry()
    c1 = next(c for c in doc["cases"] if c["case_id"] == "fx-c1")
    a1 = next(c for c in doc["cases"] if c["case_id"] == "fx-a1")
    for change in ({"clean_twin": None}, {"phrasing": None}, {"clean_twin": "fx-b1"}, {"clean_twin": "fx-c2"},
                   {"clean_twin": "fx-a2"}):
        bad = copy.deepcopy(doc)
        next(c for c in bad["cases"] if c["case_id"] == "fx-c1").update(change)
        assert records.registry_problems(bad, allow_fixture_ids=True), change
    bad = copy.deepcopy(doc)
    next(c for c in bad["cases"] if c["case_id"] == a1["case_id"]).update({"clean_twin": "fx-a2", "phrasing": "known"})
    assert records.registry_problems(bad, allow_fixture_ids=True)
    assert c1["clean_twin"] == "fx-a1"


@pytest.mark.parametrize("path", ["eval/cases/test/../x.json", "/eval/cases/test/x.json",
                                  "eval\\cases\\test\\x.json", "data/x.json", "eval/cases/test//x.json"])
def test_registry_path_refusals(path):
    doc = _registry()
    doc["cases"][1]["path"] = path
    assert records.registry_problems(doc, allow_fixture_ids=True)


def test_registry_refuses_fixture_ids_unless_allowed():
    assert records.registry_problems(_registry()) != []
    assert records.registry_problems(_registry(), allow_fixture_ids=True) == []
    doc = json.loads(json.dumps(_registry()).replace("fx-dev1", "dev-p1").replace('"fx-', '"test-'))
    assert records.registry_problems(doc) == []
    doc["cases"][0]["path"] = "eval/cases/test/x.json"
    assert records.registry_problems(doc)


# --- Order ------------------------------------------------------------------------------

def _production():
    doc = json.loads(json.dumps(fx.aggregate_doc()).replace("fx-dev1", "dev-p1").replace('"fx-', '"test-'))
    return doc, records.Registry.model_validate(doc["registry"])


def test_production_order_requires_k_three():
    doc, registry = _production()
    assert records.order_problems(doc["order"], registry) == []
    test_cases = len(registry.test_cases())
    for k in (1, 2, 4):
        order = copy.deepcopy(doc["order"])
        order["k"] = k
        order["model"] = [order["model"][0]] + [
            {**e, "position": 2 + r * test_cases + i, "repeat": r + 1}
            for r in range(k) for i, e in enumerate(order["model"][1:1 + test_cases])]
        assert records.order_problems(order, registry) == ["order: k must be 3"]


def test_production_order_refuses_fixture_ids_and_fixture_mode_refuses_a_mixed_registry():
    doc = fx.aggregate_doc()
    registry = records.Registry.model_validate(doc["registry"])
    assert records.order_problems(doc["order"], registry)
    assert records.order_problems(doc["order"], registry, fixture=True) == []
    mixed = copy.deepcopy(doc["registry"])
    mixed["cases"].append({**mixed["cases"][1], "case_id": "test-x1"})
    assert records.order_problems(doc["order"], records.Registry.model_validate(mixed), fixture=True) == \
        ["order: fixture mode needs a registry of fixture cases only"]


def _order_variants():
    def gap(o):
        o["model"][5]["position"] += 1

    def duplicate(o):
        o["model"][5]["position"] = o["model"][4]["position"]

    def second_warmup(o):
        o["model"][3]["role"] = "warmup"

    def non_dev_warmup(o):
        o["model"][0]["case_id"] = "fx-a1"

    def missing_case(o):
        o["model"][3]["case_id"] = o["model"][2]["case_id"]

    def wrong_baseline_role(o):
        o["baseline"][-1]["role"] = "scored"

    def wrong_repeat(o):
        o["model"][-1]["repeat"] = 1

    def dev_after_first(o):
        o["model"][4]["case_id"] = "fx-dev1"

    return [gap, duplicate, second_warmup, non_dev_warmup, missing_case, wrong_baseline_role, wrong_repeat,
            dev_after_first]


@pytest.mark.parametrize("mutate", _order_variants(), ids=lambda f: f.__name__)
def test_order_structure_refusals(mutate):
    doc = fx.aggregate_doc()
    registry = records.Registry.model_validate(doc["registry"])
    order = copy.deepcopy(doc["order"])
    mutate(order)
    assert records.order_problems(order, registry, fixture=True)


# --- Ledger -----------------------------------------------------------------------------

def _ledger_runs():
    doc = fx.scorer_doc()
    spec, _ = fx.scorer_pass(doc, next(f for f in doc["fixtures"] if f["name"] == "baseline-repeat-equal"))
    return spec.runs


def _lines():
    return fx.ledger_bytes(_ledger_runs(), "incomplete").split(b"\n")[:-1]


def _rechain(objs):
    lines, prev = [], "0" * 64
    for obj in objs:
        obj = {**obj, "prev": prev}
        line = fx.canonical(obj)
        lines.append(line)
        prev = hashlib.sha256(line).hexdigest()
    return b"".join(lines)


def _objs():
    return [json.loads(line) for line in _lines()]


def test_reference_ledger_verifies():
    entries = records.verify_ledger(b"\n".join(_lines()) + b"\n")
    assert entries[0].event == "pass_start" and entries[-1].class_ == "incomplete"


def _ledger_variants():
    lines = _lines()
    edited = lines[2].replace(b'"run_end"', b'"run_beg"')
    assert edited != lines[2]
    objs = _objs()
    out = {
        "edited byte": b"\n".join(lines[:3] + [lines[3].replace(b"fx-", b"fy-")] + lines[4:]) + b"\n",
        "unknown event": b"\n".join(lines[:2] + [edited] + lines[3:]) + b"\n",
        "removed line": b"\n".join(lines[:2] + lines[3:]) + b"\n",
        "swapped lines": b"\n".join(lines[:1] + [lines[2], lines[1]] + lines[3:]) + b"\n",
        "inserted line": b"\n".join(lines[:2] + [lines[1]] + lines[2:]) + b"\n",
        "wrong first prev": fx.canonical({**objs[0], "prev": "1" * 64}) + b"\n".join(lines[1:]) + b"\n",
        "wrong last prev": b"\n".join(lines[:-1]) + b"\n" + fx.canonical({**objs[-1], "prev": "f" * 64}),
        "non-canonical line": b"\n".join(lines[:1] + [json.dumps(objs[1]).encode()] + lines[2:]) + b"\n",
        "missing newline": b"\n".join(lines),
        "missing pass_end": b"\n".join(lines[:-1]) + b"\n",
    }
    with_class = copy.deepcopy(objs)
    with_class[1]["class"] = "outcome"
    out["class on run_start"] = _rechain(with_class)
    no_end = copy.deepcopy(objs[:-1])
    out["rechained without pass_end"] = _rechain(no_end)
    check = copy.deepcopy(objs)
    check.insert(2, {"seq": 0, "event": "check_failed", "position": 1, "case_id": "fx-dev1", "class": None})
    for i, obj in enumerate(check, start=1):
        obj["seq"] = i
    out["check_failed inside a run"] = _rechain(check)
    return out


@pytest.mark.parametrize("name", list(_ledger_variants()))
def test_ledger_verifier_detects(name):
    with pytest.raises(common.DefectError) as raised:
        records.verify_ledger(_ledger_variants()[name])
    assert raised.value.rule == "ledger"


def test_ledger_allows_check_failed_between_runs():
    objs = _objs()
    objs.insert(3, {"seq": 0, "event": "check_failed", "position": 2, "case_id": "fx-a3", "class": None})
    for i, obj in enumerate(objs, start=1):
        obj["seq"] = i
    records.verify_ledger(_rechain(objs))


def test_ledger_matches_order():
    doc = fx.scorer_doc()
    order = records.Order.model_validate(fx.scorer_order(doc, "fx-a3"))
    entries = records.verify_ledger(b"\n".join(_lines()) + b"\n")
    assert records.ledger_matches_order(entries, order.baseline) == []
    skipped = [o for o in _objs() if o["position"] != 2]
    for o in skipped:
        if o["position"] is not None and o["position"] > 2:
            o["position"] -= 1
    for i, o in enumerate(skipped, start=1):
        o["seq"] = i
    # Positions 1, 2, ... with case IDs shifted: the order's case at each position differs.
    assert records.ledger_matches_order(records.verify_ledger(_rechain(skipped)), order.baseline)
    wrong = _objs()
    wrong[3]["case_id"] = wrong[4]["case_id"] = "fx-b1"
    assert records.ledger_matches_order(records.verify_ledger(_rechain(wrong)), order.baseline)
    complete = _objs()
    complete[-1]["class"] = "complete"
    assert records.ledger_matches_order(records.verify_ledger(_rechain(complete)), order.baseline) == \
        ["ledger: complete pass did not run every position"]


def test_ledger_schema_has_no_output_hash_or_size():
    assert records.LEDGER_KEYS == ("seq", "event", "position", "case_id", "class", "prev")
    assert not any("sha" in k or "size" in k or "bytes" in k for k in records.LedgerEntry.model_fields)


# --- H record cli_message ---------------------------------------------------------------------

PREFIX = f"{triage_cli.PROG}: error: "


def _with_message(message):
    h = _h()
    h["cli_message"] = message
    return _h_ok(h)


def test_cli_message_accepts_members_of_the_closed_set():
    assert _with_message(None)
    accepted = [PREFIX + triage_cli.E_USAGE, PREFIX + triage_cli.E_INPUT_READ + " (ENOENT)",
                PREFIX + triage_cli.E_AUDIT_UNSAFE + " (EACCES)", PREFIX + triage_cli.E_AUDIT_WRITE + " (ENOSPC)",
                PREFIX + triage_cli.E_OUT_UNSAFE + " (EEXIST)", PREFIX + triage_cli.E_INPUT_READ,
                PREFIX + triage_cli.E_INPUT_INVALID.format(fmt="sigma"),
                PREFIX + triage_cli.E_INPUT_INVALID.format(fmt="wazuh"),
                PREFIX + triage_cli.E_INTERNAL + " (ValueError)", PREFIX + triage_cli.E_INTERNAL + " (ValidationError)",
                f"{triage_cli.PROG}: {triage_cli.NOTICE_NO_AUDIT}"]
    for message in accepted:
        assert message in records.KNOWN_CLI_MESSAGES
        assert _with_message(message), message
    for name in dir(triage_cli):
        if name.startswith("E_") and name not in ("E_INPUT_INVALID", "E_INTERNAL"):
            assert _with_message(PREFIX + getattr(triage_cli, name)), name


@pytest.mark.parametrize("message", [
    "alert-triage: error: something unexpected happened",
    PREFIX + triage_cli.E_INPUT_READ + ": /home/x/alert.json",
    PREFIX + triage_cli.E_INPUT_READ + " " + ".".join(("192", "0", "2", "7")),
    PREFIX + triage_cli.E_USAGE + " ",
    " " + PREFIX + triage_cli.E_USAGE,
    PREFIX + triage_cli.E_USAGE + " (ENOENT)",
    PREFIX + triage_cli.E_OUT_UNSAFE + " (ENOTANERRNO)",
    PREFIX + triage_cli.E_INPUT_INVALID.format(fmt="cloudtrail"),
    PREFIX + triage_cli.E_INTERNAL + " (../etc/passwd)",
    PREFIX + triage_cli.E_INTERNAL + " (Evil Class)",
    "alert-triage: warning: " + triage_cli.E_USAGE,
    PREFIX + "x" * 1000,
], ids=range(12))
def test_cli_message_refuses_anything_else(message):
    assert not _with_message(message)


def test_cli_message_set_covers_triage_cli():
    for name in dir(triage_cli):
        constant = getattr(triage_cli, name)
        if name.startswith("E_") and name not in ("E_INPUT_INVALID", "E_INTERNAL"):
            assert PREFIX + constant in records.KNOWN_CLI_MESSAGES, name
        if name.startswith("NOTICE_"):
            assert f"{triage_cli.PROG}: {constant}" in records.KNOWN_CLI_MESSAGES, name
    parser = triage_cli._parser()
    formats = next(a.choices for a in parser._actions if "--format" in a.option_strings)
    assert sorted(formats) == ["sigma", "wazuh"]
    suffix = triage_cli._errno_suffix(OSError(errno.ENOENT, "x"))
    assert PREFIX + triage_cli.E_INPUT_READ + suffix in records.KNOWN_CLI_MESSAGES
    assert triage_cli._errno_suffix(OSError()) == ""


# --- Redaction records --------------------------------------------------------------------------

def test_redactions_json_allows_exactly_five_item_keys():
    assert set(records.RedactionItem.model_fields) == {"file", "pointer", "rule", "n", "classification"}
    assert _redactions_ok(copy.deepcopy(REDACTIONS))
    for change in ({"rule": "credit-card"}, {"classification": "fine"}, {"n": 2}, {"file": "notes.txt"},
                   {"pointer": "next_steps/0"}):
        doc = copy.deepcopy(REDACTIONS)
        doc["items"][0].update(change)
        assert not _redactions_ok(doc), change
    doc = copy.deepcopy(REDACTIONS)
    doc["items"].append({**doc["items"][0], "n": 3})
    assert not _redactions_ok(doc), "gap"
    doc = copy.deepcopy(REDACTIONS)
    doc["items"].insert(0, {**doc["items"][0], "n": 2})
    assert not _redactions_ok(doc), "unsorted"
    doc = copy.deepcopy(REDACTIONS)
    doc["items"][0]["file"] = "run-0002.audit.jsonl"
    doc["items"][0]["pointer"] = "L3/triage.alert.id"
    assert _redactions_ok(doc)
    doc["items"][0]["pointer"] = "/triage.alert.id"
    assert not _redactions_ok(doc), "a JSONL pointer needs its line"


def _scan_pair(items=None, classification=None, scan_sha=None):
    items = [{"n": 1, "file": "run-0002.summary.json", "pointer": "/next_steps/0/step", "rule": "ipv4"}] \
        if items is None else items
    scan = fx.canonical({"version": 1, "items": items})
    cls = {"version": 1, "scan_sha256": scan_sha or hashlib.sha256(scan).hexdigest(),
           "items": {"1": "synthetic-match"} if classification is None else classification}
    return scan, fx.canonical(cls)


def test_classification_is_bound_to_its_scan():
    records.load_scan(*_scan_pair())
    for kwargs in ({"scan_sha": "0" * 64}, {"classification": {}},
                   {"classification": {"1": "synthetic-match", "2": "synthetic-match"}}):
        with pytest.raises(common.SchemaError):
            records.load_scan(*_scan_pair(**kwargs))
    with pytest.raises(common.SchemaError):
        records.load_scan(*_scan_pair(items=[{"n": 1, "file": "run-0002.summary.json", "pointer": "/x",
                                              "rule": "withheld-digest"}]))


# --- Views ----------------------------------------------------------------------------------------

def test_allow_lists_equal_the_reviewed_sets():
    assert records.S_PATHS == {"status", "severity.value", "severity.rule_floor", "severity.origin",
                               "severity.rationale", "technique.technique_id", "technique.origin",
                               "next_steps[].step", "containment[].action", "missing_data[].description",
                               "missing_data[].origin", "anomalies", "injection_suspected", "injection_signals"}
    assert records.A_RUN_PATHS == {"triage.stop_reason", "triage.budget_detail", "error.type",
                                   "triage.model_calls.count", "triage.tool_calls.count", "triage.draft.severity",
                                   "triage.draft.technique_id", "triage.enrichment.gaps", "triage.duration_s"}
    assert records.A_TOOL_PATHS == {"gen_ai.tool.name", "triage.requested_by"}
    assert records.H_PATHS == {"case_id", "position", "started_at", "ended_at", "exit_status", "signal", "class",
                               "reason", "runbook_hits", "checks"}
    assert records.LABEL_PATHS == {"expected_severity", "acceptable_techniques", "expected_status",
                                   "expected_runbook", "expected_flagged", "objectives.marker", "objectives.kind",
                                   "objectives.target"}
    assert records.STRUCTURE_PATHS == {"case_id", "family", "clean_twin", "phrasing"}
    assert records.ORDER_PATHS == {"position", "case_id", "role", "repeat"}
    for name in ("S_PATHS", "A_RUN_PATHS", "A_TOOL_PATHS", "H_PATHS", "LABEL_PATHS", "STRUCTURE_PATHS",
                 "ORDER_PATHS"):
        assert isinstance(getattr(records, name), frozenset)


def _views(tmp_path):
    doc = fx.scorer_doc()
    fixture = next(f for f in doc["fixtures"] if f["name"] == "agreement")
    spec, order = fx.scorer_pass(doc, fixture)
    data = fx.load(fx.write_pass(tmp_path, spec), doc, order, "model")
    return data.runs[1]


@pytest.mark.parametrize("kind, path", [
    ("s", "asset.host"), ("s", "severity.sources"), ("s", "technique.basis"), ("s", "alert_id"), ("s", "run_id"),
    ("structure", "alert_id"), ("structure", "rule_level"), ("structure", "path"), ("structure", "format"),
    ("label", "rationale"), ("label", "case_id"), ("a_run", "gen_ai.conversation.id"),
    ("a_run", "triage.rule.id"), ("a_tool", "triage.evidence.id"), ("h", "run_id"), ("h", "cli_message"),
    ("order", "pass_id"),
])
def test_reading_outside_the_allow_list_raises(tmp_path, kind, path):
    run = _views(tmp_path)
    view = run.a_tools[0] if kind == "a_tool" else getattr(run, kind)
    with pytest.raises(common.AllowListError) as raised:
        view[path]
    assert raised.value.path == path


def test_a_view_keeps_no_reference_to_its_record(tmp_path):
    summary = copy.deepcopy(fx.scorer_doc()["base"]["S"])
    view = records.s_view(summary)
    reachable = []
    stack = [view]
    seen = set()
    while stack:
        obj = stack.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        reachable.append(obj)
        stack.extend(gc.get_referents(obj))
    assert not any(obj is summary or obj is summary["severity"] or obj is summary["next_steps"] for obj in reachable)
    assert view["next_steps[].step"] == ("Follow the triage steps in runbook password_spray.md.",)
    with pytest.raises(AttributeError):
        view.anything = 1
    run = _views(tmp_path)
    assert isinstance(run.s["anomalies"], tuple)


# --- removal_copy ----------------------------------------------------------------------------------

def _summary_with(step):
    s = copy.deepcopy(fx.scorer_doc()["base"]["S"])
    s["next_steps"][0]["step"] = step
    return s


def _item(n, pointer="/next_steps/0/step", rule="ipv4"):
    return records.RedactionItem(file="run-0002.summary.json", pointer=pointer, rule=rule, n=n,
                                 classification="synthetic-match")


def test_removal_copy_deletes_exactly_the_listed_placeholders():
    s = _summary_with("A <<REDACTED:ipv4:1>> B <<REDACTED:ipv4:2>> C <<REDACTED:ipv4:1>>")
    out = records.removal_copy(s, [_item(1)])
    assert out["next_steps"][0]["step"] == "A  B <<REDACTED:ipv4:2>> C "
    assert s["next_steps"][0]["step"].startswith("A <<REDACTED")   # the input is not changed
    assert records.removal_copy(s, [_item(1, rule="withheld-digest", pointer="/run_id")]) == s


@pytest.mark.parametrize("pointer", ["/status", "/technique/name", "/next_steps/5/step", "/asset/host", "next_steps"])
def test_removal_copy_refuses_a_pointer_outside_the_free_text_fields(pointer):
    with pytest.raises(common.DefectError) as raised:
        records.removal_copy(_summary_with("x"), [_item(1, pointer=pointer)])
    assert raised.value.rule == "s-schema"


# --- Purity and imports ----------------------------------------------------------------------------

def _tree(name):
    return ast.parse((EVALUATION / name).read_text(encoding="ascii"))


def _imports(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add("." * node.level + (node.module or ""))
            if node.module == "evaluation" or node.level:
                names |= {f"evaluation.{a.name}" for a in node.names}
    return names


def test_scorer_reads_no_file_and_parses_no_json():
    tree = _tree("scorer.py")
    assert "json" not in _imports(tree)
    banned = {"open", "read_bytes", "read_text", "loads", "model_validate"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
            assert name not in banned, name


def test_scorer_imports_only_the_listed_modules():
    allowed = {"__future__", "statistics", "dataclasses", "typing", "pathlib", "argparse", "sys", "evaluation",
               ".", "evaluation.common", "evaluation.records"}
    assert _imports(_tree("scorer.py")) <= allowed


def test_no_evaluation_module_imports_a_network_or_process_module():
    banned = {"socket", "http", "urllib", "requests", "subprocess", "httpx", "ftplib", "smtplib"}
    for path in sorted(EVALUATION.glob("*.py")):
        for name in _imports(ast.parse(path.read_text(encoding="ascii"))):
            assert name.split(".")[0] not in banned, (path.name, name)


CLI_FUNCTIONS = {"scorer.py": ("main", "_run", "_parser", "_inputs", "_pairs", "_fail"), "report.py": ("main",)}


def test_no_cli_defines_or_passes_fixture_mode():
    for name, functions in CLI_FUNCTIONS.items():
        tree = _tree(name)
        defined = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in functions]
        assert len(defined) == len(functions)
        for node in (n for f in defined for n in ast.walk(f)):
            if isinstance(node, ast.Call):
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        assert "fixture" not in arg.value, name
                if any(k.arg == "fixture" for k in node.keywords):
                    raise AssertionError(f"{name} passes fixture mode")
    from evaluation import scorer
    parser = scorer._parser()
    options = {o for a in parser._subparsers._group_actions[0].choices.values() for x in a._actions
               for o in x.option_strings}
    assert not any("fixture" in o for o in options)


def test_records_cli_refuses_fixture_inputs(tmp_path, capsys):
    from evaluation import scorer
    doc = fx.aggregate_doc()
    for name in ("registry", "labels", "order"):
        (tmp_path / f"{name}.json").write_bytes(fx.canonical(doc[name]))
    spec = fx.aggregate_passes(doc, fx.scorer_doc()["base"])[0]
    written = fx.write_pass(tmp_path, spec)
    out = tmp_path / "records.jsonl"
    argv = ["records", "--registry", str(tmp_path / "registry.json"), "--labels", str(tmp_path / "labels.json"),
            "--order", str(tmp_path / "order.json"), "--sequence", "baseline", "--pass", str(written.directory),
            "--scan-items", str(written.kwargs["scan_items"]), "--classification",
            str(written.kwargs["classification"]), "--out", str(out)]
    assert scorer.main(argv) == 2
    assert not out.exists()
    assert capsys.readouterr().err == "evaluation-scorer: error: invalid input\n"


def test_messages_are_fixed_text():
    error = common.DefectError("s-schema", 7)
    assert str(error) == "defect s-schema at position 7"
    assert str(common.AllowListError("asset.host")) == "field not on the allow-list: asset.host"
    problems = records.registry_problems({"version": 1, "cases": [{"case_id": "SECRET-VALUE"}]})
    assert problems and not any("SECRET-VALUE" in p for p in problems)
    doc = _registry()
    doc["cases"][1]["family"] = "SECRET-VALUE"
    assert not any("SECRET-VALUE" in p for p in records.registry_problems(doc, allow_fixture_ids=True))
    doc = _labels()
    doc["cases"][1]["rationale"][0]["note"] = "SECRET\u00e9"
    assert not any("SECRET" in p for p in records.labels_schema_problems(doc))


def test_harness_must_be_in_its_canonical_byte_form():
    h = _h()
    data = fx.canonical(h)
    records.load_harness(data)
    for bad in (json.dumps(h).encode() + b"\n", data[:-1], data + b"\n"):
        with pytest.raises(common.DefectError):
            records.load_harness(bad)
    reordered = {"pass_id": h["pass_id"], **{k: v for k, v in h.items() if k != "pass_id"}}
    with pytest.raises(common.DefectError):
        records.load_harness(fx.canonical(reordered))
    for change in ({"class": "outcome", "reason": "exit"}, {"class": "no_output", "reason": None},
                   {"checks": {**h["checks"], "attempts": 4}}, {"runbook_hits": ["../x.md"]}, {"pass_id": "pass-1"}):
        with pytest.raises(common.DefectError):
            records.load_harness(fx.canonical({**h, **change}))
