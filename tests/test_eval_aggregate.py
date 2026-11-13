"""Aggregation into results.json, and the scorer CLI, against the hand-computed aggregation fixture."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

import test_eval_fixtures as fx
from evaluation import common, records, report, scorer

RESULT_KEYS = ("version", "scorer", "index_sha256", "setup", "composition", "passes", "reported", "baseline",
               "model")
BLOCK_KEYS = {"baseline": ("f1", "f2", "f3", "redactions"), "model": ("f1", "f2", "f3", "stability", "redactions")}
SETUP = {"model": "fixture-model:0", "digest": "sha256:" + "0" * 64, "think": False}


def sorted_bytes(obj) -> bytes:
    """Canonical bytes with sorted keys: the fixture file is key-sorted for review."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def build(tmp_path, doc=None, *, public=None, fixture=True):
    doc = fx.aggregate_doc() if doc is None else doc
    base = fx.scorer_doc()["base"]
    passes = []
    for spec in fx.aggregate_passes(doc, base):
        if public is not None:
            spec.public = public
        written = fx.write_pass(tmp_path, spec)
        passes.append(fx.load(written, doc, doc["order"], spec.sequence, fixture=fixture))
    return doc, passes


def results_of(doc, passes, **kwargs):
    registry, labels, order = fx.models(doc, doc["order"])
    return scorer.aggregate(passes, registry, labels, order, doc["setup"], fixture=True, **kwargs)


def masked(results):
    out = copy.deepcopy(results)
    out["scorer"] = "masked"
    out["index_sha256"] = None
    return out


def test_aggregate_equals_the_hand_computed_results(tmp_path):
    doc, passes = build(tmp_path)
    results = results_of(doc, passes)
    assert sorted_bytes(masked(results)) == sorted_bytes(doc["expect"])
    # The two masked fields, checked against the real bytes.
    assert results["index_sha256"] is None
    assert [s["path"] for s in results["scorer"]] == sorted(records.SCORER_SOURCES)
    for entry in results["scorer"]:
        assert entry["sha256"] == hashlib.sha256((fx.REPO / entry["path"]).read_bytes()).hexdigest()


def test_results_keep_the_fixed_key_order(tmp_path):
    doc, passes = build(tmp_path)
    results = results_of(doc, passes)
    assert tuple(results) == RESULT_KEYS
    for name, keys in BLOCK_KEYS.items():
        assert tuple(results[name]) == keys
    assert tuple(results["model"]["f2"]["anomalies"]) == records.ANOMALY_CODES
    assert common.canonical_dumps(results).endswith(b"\n")


def test_first_complete_pass_is_reported_and_the_others_listed(tmp_path):
    doc, passes = build(tmp_path)
    results = results_of(doc, passes)
    assert results["reported"] == {"baseline": "baseline-001", "model": "model-002"}
    listed = {p["pass_id"]: p for p in results["passes"]}
    assert listed["model-001"]["class"] == "incomplete" and listed["model-001"]["reported"] is False


def test_pass_selection_ignores_scores(tmp_path):
    doc = fx.aggregate_doc()
    better = copy.deepcopy(next(p for p in doc["passes"] if p["pass_id"] == "model-002"))
    better["pass_id"] = "model-003"
    better["redactions"] = []
    better["runs"] = {}
    for entry in doc["order"]["model"]:
        if entry["case_id"] == "fx-a1":
            better["runs"][str(entry["position"])] = {"S": {"severity": {"value": "critical"}}}
        if entry["case_id"] == "fx-a2":
            better["runs"][str(entry["position"])] = {"S": {"severity": {"value": "medium", "origin": "rule"}}}
    doc["passes"].append(better)
    doc, passes = build(tmp_path, doc)
    results = results_of(doc, passes)
    by_id = {p.pass_id: p for p in passes}
    agree = {}
    for pid in ("model-002", "model-003"):
        scores = [r for r in scorer.score_pass(by_id[pid], records.case_views(*fx.models(doc, doc["order"])[:2]))
                  if r["role"] == "scored" and r["f1"]]
        agree[pid] = sum(r["f1"]["severity_agree"] for r in scores)
    assert agree["model-003"] > agree["model-002"]
    assert results["reported"]["model"] == "model-002"
    assert {p["pass_id"]: p["reported"] for p in results["passes"]}["model-003"] is False


def _no_output_spec():
    return {"S": None, "A": "absent",
            "H": {"class": "no_output", "reason": "deadline", "exit_status": None, "signal": 9, "run_id": None,
                  "runbook_hits": None}}


def test_an_empty_clean_twin_reference_is_unassessable(tmp_path):
    doc = fx.aggregate_doc()
    model2 = next(p for p in doc["passes"] if p["pass_id"] == "model-002")
    for entry in doc["order"]["model"]:
        if entry["case_id"] == "fx-a1":
            model2["runs"][str(entry["position"])] = _no_output_spec()
    model2["redactions"] = []
    doc, passes = build(tmp_path, doc)
    f3 = results_of(doc, passes)["model"]["f3"]
    expected = doc["expect"]["model"]["f3"]
    assert f3["differences_unassessable"] == ["fx-c1"]
    assert all(e["twin"] != "fx-c1" for e in f3["guardrail_interventions"] + f3["observed_differences"])
    assert [e for e in f3["guardrail_interventions"] if e["twin"] == "fx-c2"] == \
        [e for e in expected["guardrail_interventions"] if e["twin"] == "fx-c2"]
    assert [e for e in f3["observed_differences"] if e["twin"] == "fx-c2"] == \
        [e for e in expected["observed_differences"] if e["twin"] == "fx-c2"]
    assert _denominators(f3) == _denominators(expected)


def _denominators(node, path=""):
    out = {}
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "of":
                out[path] = value
            else:
                out.update(_denominators(value, f"{path}/{key}"))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            out.update(_denominators(value, f"{path}/{i}"))
    return out


def test_every_denominator_follows_the_registry_and_order(tmp_path):
    doc, passes = build(tmp_path)
    results = results_of(doc, passes)
    cases = doc["registry"]["cases"]
    fam = {f: sum(1 for c in cases if c["family"] == f) for f in "ABCD"}
    tests = sum(fam.values())
    labels = {entry["case_id"]: entry for entry in doc["labels"]["cases"]}
    twins = [c["case_id"] for c in cases if c["family"] == "C"]
    kinds = {k: sum(1 for t in twins if labels[t]["objectives"]["kind"] == k) for k in ("O-S", "O-T")}
    known = sum(1 for c in cases if c["phrasing"] == "known")
    evasive = sum(1 for c in cases if c["phrasing"] == "evasive")
    for name, runs in (("baseline", 1), ("model", doc["order"]["k"])):
        block = results[name]
        for value in _denominators(block["f1"]["runs"]).values():
            assert value == (fam["A"] + fam["B"]) * runs
        assert all(v["of"] == fam["A"] + fam["B"] for v in block["f1"]["cases"].values())
        for value in _denominators(block["f2"]).values():
            assert value == tests * runs
        trip = block["f3"]["tripwire"]
        assert trip["flagged_known"]["of"] == known and trip["flagged_evasive"]["of"] == evasive
        assert trip["false_positives"]["of"] == fam["D"] + fam["A"]
        assert trip["raised_by_tripwire"]["of"] == (fam["C"] + fam["D"]) * runs
        controls = block["f3"]["controls"]
        assert all(v["of"] == len(twins) * runs for v in controls["om"].values())
        assert all(v["of"] == kinds["O-S"] * runs for v in controls["os"].values())
        assert all(v["of"] == kinds["O-T"] * runs for v in controls["ot"].values())
        split_twins = 0
        for split in block["f3"]["objectives"].values():
            split_twins += split["twins"]
            assert all(v["of"] == split["twins"] * runs for v in split["om"].values())
            for part in ("os", "ot"):
                assert all(v["of"] == split[part]["twins"] * runs for k, v in split[part].items() if k != "twins")
        assert split_twins == len(twins)
        assert block["redactions"]["runs_with_items"]["of"] == tests * runs
    assert results["model"]["stability"]["unstable"]["of"] == tests


def test_redaction_blocks_agree_between_public_and_original_sources(tmp_path):
    doc, public = build(tmp_path / "public")
    _, original = build(tmp_path / "original", public=False)
    pub = results_of(doc, public)
    orig = results_of(doc, original)
    for name in ("baseline", "model"):
        a, b = pub[name]["redactions"], orig[name]["redactions"]
        assert (a["items"], a["runs_with_items"], a["classification"]) == \
            (b["items"], b["runs_with_items"], b["classification"])
        assert b["withheld_fields"] == 0


def test_fixture_inputs_are_refused_without_fixture_mode(tmp_path):
    doc = fx.aggregate_doc()
    with pytest.raises(common.SchemaError):
        build(tmp_path, doc, fixture=False)
    _, passes = build(tmp_path / "ok", doc)
    registry, labels, order = fx.models(doc, doc["order"])
    with pytest.raises(common.SchemaError):
        scorer.aggregate(passes, registry, labels, order, SETUP, index_bytes=b"{}")


def test_production_k_is_three(tmp_path):
    doc = production_doc()
    registry, labels, _ = fx.models(doc, doc["order"])
    order = copy.deepcopy(doc["order"])
    order["k"] = 2
    order["model"] = order["model"][: 1 + 2 * 7]
    with pytest.raises(common.SchemaError):
        scorer.aggregate([], registry, labels, records.Order.model_validate(order), SETUP, index_bytes=b"{}")
    assert records.order_problems(order, registry)


def test_fixture_mode_refuses_a_registry_with_a_production_id(tmp_path):
    doc = fx.aggregate_doc()
    doc["registry"]["cases"].append({**doc["registry"]["cases"][1], "case_id": "test-x1"})
    doc["labels"]["cases"].append({**doc["labels"]["cases"][1], "case_id": "test-x1"})
    registry, labels, order = fx.models(doc, doc["order"])
    with pytest.raises(common.SchemaError):
        scorer.aggregate([], registry, labels, order, SETUP, fixture=True)


def test_production_results_need_the_index_bytes():
    doc = production_doc()
    registry, labels, order = fx.models(doc, doc["order"])
    with pytest.raises(common.SchemaError):
        scorer.aggregate([], registry, labels, order, SETUP)


# --- The CLI on production-shaped inputs ---------------------------------------------

def _rename(text: str) -> str:
    # Fixture IDs become production-shaped IDs, keeping their sort order.
    return text.replace("fx-dev1", "dev-p1").replace('"fx-', '"test-')


def production_doc() -> dict:
    return json.loads(_rename(fx.AGGREGATE_FIXTURE.read_text(encoding="ascii")))


def write_inputs(tmp_path, doc, *, plant=None):
    base = fx.scorer_doc()["base"]
    if plant is not None:
        base = copy.deepcopy(base)
        base["S"]["severity"]["rationale"] = plant
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for name in ("registry", "labels", "order", "setup"):
        (inputs / f"{name}.json").write_bytes(fx.canonical(doc[name]))
    passes = {}
    for spec in fx.aggregate_passes(doc, base):
        passes[spec.pass_id] = (spec, fx.write_pass(tmp_path / "passes", spec))
    return inputs, passes


def results_argv(inputs, passes, index, out):
    argv = ["results", "--registry", str(inputs / "registry.json"), "--labels", str(inputs / "labels.json"),
            "--order", str(inputs / "order.json"), "--setup", str(inputs / "setup.json")]
    for pass_id, (spec, written) in passes.items():
        mode = "public" if spec.public else "original"
        argv += ["--pass", f"{pass_id}={written.directory}:{mode}"]
        if spec.public:
            argv += ["--redactions", f"{pass_id}={written.kwargs['redactions']}"]
        else:
            argv += ["--scan-items", f"{pass_id}={written.kwargs['scan_items']}",
                     "--classification", f"{pass_id}={written.kwargs['classification']}"]
    if index is not None:
        argv += ["--index", str(index)]
    return argv + ["--out", str(out)]


def write_index(tmp_path, pass_ids, name="index.json"):
    path = tmp_path / name
    path.write_bytes(fx.canonical({"version": 1, "passes": [{"pass_id": p} for p in pass_ids]}))
    return path


def test_results_cli_on_production_shaped_inputs(tmp_path, capsys):
    doc = production_doc()
    inputs, passes = write_inputs(tmp_path, doc)
    index = write_index(tmp_path, list(passes))
    out = tmp_path / "results.json"
    assert scorer.main(results_argv(inputs, passes, index, out)) == 0
    assert capsys.readouterr() == ("", "")
    results = common.strict_loads(out.read_bytes())
    assert out.read_bytes() == common.canonical_dumps(results)
    assert results["index_sha256"] == hashlib.sha256(index.read_bytes()).hexdigest()
    assert sorted_bytes(masked(results)) == sorted_bytes(doc["expect"])
    # The CLI's output can be reported; a second write to the same path is refused.
    report_out = tmp_path / "report.md"
    assert report.main(["--results", str(out), "--out", str(report_out)]) == 0
    assert report.main(["--results", str(out), "--out", str(report_out)]) == 2
    assert scorer.main(results_argv(inputs, passes, index, out)) == 2


@pytest.mark.parametrize("case", ["missing", "not-object", "missing-pass", "extra-pass", "duplicate-pass",
                                  "fixture-registry"])
def test_results_cli_refuses_a_bad_index_or_registry(tmp_path, capsys, case):
    doc = fx.aggregate_doc() if case == "fixture-registry" else production_doc()
    inputs, passes = write_inputs(tmp_path, doc)
    ids = list(passes)
    listed = {"missing-pass": ids[:-1], "extra-pass": ids + ["model-009"], "duplicate-pass": ids + ids[:1],
              "fixture-registry": ids}
    index = None
    if case in listed:
        index = write_index(tmp_path, listed[case])
    elif case == "not-object":
        index = tmp_path / "index.json"
        index.write_bytes(b"[]\n")
    out = tmp_path / "results.json"
    assert scorer.main(results_argv(inputs, passes, index, out)) == 2
    assert not out.exists()
    _, err = capsys.readouterr()
    assert err.startswith("evaluation-scorer: error: ")


def test_report_refuses_a_null_index_hash_outside_fixture_mode():
    with pytest.raises(common.SchemaError):
        report.render(fx.aggregate_doc()["expect"])


def records_argv(inputs, spec, written, out):
    argv = ["records", "--registry", str(inputs / "registry.json"), "--labels", str(inputs / "labels.json"),
            "--order", str(inputs / "order.json"), "--sequence", spec.sequence, "--pass", str(written.directory)]
    if spec.public:
        argv += ["--public", "--redactions", str(written.kwargs["redactions"])]
    else:
        argv += ["--scan-items", str(written.kwargs["scan_items"]),
                 "--classification", str(written.kwargs["classification"])]
    return argv + ["--out", str(out)]


def test_records_cli_writes_score_records_and_refuses_an_existing_output(tmp_path, capsys):
    doc = production_doc()
    inputs, passes = write_inputs(tmp_path, doc)
    spec, written = passes["model-002"]
    out = tmp_path / "records.jsonl"
    assert scorer.main(records_argv(inputs, spec, written, out)) == 0
    lines = out.read_bytes().split(b"\n")[:-1]
    assert len(lines) == len(spec.runs)
    assert [common.strict_loads(line)["position"] for line in lines] == [r.position for r in spec.runs]
    assert scorer.main(records_argv(inputs, spec, written, out)) == 2
    assert capsys.readouterr().err == "evaluation-scorer: error: invalid input or output path\n"


def test_cli_exit_codes(tmp_path, capsys, monkeypatch):
    doc = production_doc()
    inputs, passes = write_inputs(tmp_path, doc)
    spec, written = passes["model-002"]
    assert scorer.main(["records"]) == 2
    assert scorer.main(["unknown-command"]) == 2
    # A defective pass: the records are still written, and the exit code says so.
    (written.directory / "run-0005.harness.json").write_bytes(b"{}\n")
    out = tmp_path / "defective.jsonl"
    assert scorer.main(records_argv(inputs, spec, written, out)) == 3
    assert out.exists()
    monkeypatch.setattr(scorer, "score_pass", lambda *a, **k: 1 / 0)
    assert scorer.main(records_argv(inputs, spec, written, tmp_path / "other.jsonl")) == 1
    err = capsys.readouterr().err
    assert err.endswith("evaluation-scorer: error: internal error (ZeroDivisionError)\n")


def test_cli_messages_hold_no_record_value(tmp_path, capsys):
    planted = "PLANTED-zq9-value"
    doc = production_doc()
    inputs, passes = write_inputs(tmp_path, doc, plant=planted)
    spec, written = passes["model-002"]
    # Make the pass defective in two ways that both read the planted summary.
    harness = written.directory / "run-0002.harness.json"
    record = json.loads(harness.read_bytes())
    record["runbook_hits"] = None
    harness.write_bytes(fx.canonical(record))
    summary = written.directory / "run-0003.summary.json"
    summary.write_bytes(summary.read_bytes().replace(b'"status":"triaged"', b'"status":"' + planted.encode() + b'"'))
    assert scorer.main(records_argv(inputs, spec, written, tmp_path / "r.jsonl")) == 3
    index = write_index(tmp_path, list(passes))
    assert scorer.main(results_argv(inputs, passes, index, tmp_path / "results.json")) == 3
    assert scorer.main(results_argv(inputs, passes, None, tmp_path / "results2.json")) == 2
    captured = capsys.readouterr()
    assert planted not in captured.out and planted not in captured.err
