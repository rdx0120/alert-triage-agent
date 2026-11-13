"""Per-run scoring against the hand-written fixtures (tests/data/eval/scorer_fixtures.json)."""

from __future__ import annotations

import copy

import pytest

import test_eval_fixtures as fx
from evaluation import common, records, scorer

RECORD_KEYS = ("pass_id", "position", "case_id", "family", "role", "repeat", "class", "f1", "f2", "f3",
               "objectives", "stability")
F1_KEYS = ("severity_agree", "over_floor", "over_model", "over_tripwire", "under", "technique_ok", "status_ok",
           "retrieval_ok")
F2_KEYS = ("draft", "anomalies", "stop_reason", "budget_detail", "error_type", "model_calls", "tool_calls",
           "model_searches", "duration_s")
F3_KEYS = ("flagged", "signals", "raised_by_tripwire")
STABILITY_KEYS = ("severity", "technique", "status", "top_hit", "om_effective")


def score(tmp_path, fixture, *, public=None):
    doc = fx.scorer_doc()
    spec, order = fx.scorer_pass(doc, fixture, public=public)
    written = fx.write_pass(tmp_path, spec)
    data = fx.load(written, doc, order, spec.sequence)
    registry, labels, _ = fx.models(doc, order)
    return data, scorer.score_pass(data, records.case_views(registry, labels))


@pytest.mark.parametrize("fixture", fx.scorer_fixtures(), ids=lambda f: f["name"])
def test_fixture_scores_as_written(tmp_path, fixture):
    data, scores = score(tmp_path, fixture)
    expected = fixture["expect"]
    defects = [{"rule": rule, "position": position} for rule, position in data.defects]
    by_position = {r["position"]: r for r in scores}
    if "defect" in expected:
        assert defects == [{"rule": expected["defect"], "position": expected["position"]}]
        assert data.pass_class == "defective"
        if "record" in expected:
            assert by_position[2] == expected["record"]
        return
    assert defects == []
    assert data.pass_class == "incomplete"
    assert by_position[2] == expected


def test_score_records_keep_the_fixed_key_order(tmp_path):
    for i, fixture in enumerate(fx.scorer_fixtures()):
        _, scores = score(tmp_path / str(i), fixture)
        for record in scores:
            assert tuple(record) == RECORD_KEYS
            assert record["f1"] is None or tuple(record["f1"]) == F1_KEYS
            assert tuple(record["f2"]) == F2_KEYS
            assert tuple(record["f3"]) == F3_KEYS
            assert tuple(record["stability"]) == STABILITY_KEYS


def _fixture(name):
    return next(f for f in fx.scorer_fixtures() if f["name"] == name)


def test_load_pass_collects_every_defect(tmp_path):
    fixture = copy.deepcopy(_fixture("agreement"))
    fixture["H"] = {"repeat": 2, "runbook_hits": None}
    data, _ = score(tmp_path, fixture)
    assert [rule for rule, _ in data.defects] == ["h-binding", "hits-null"]


@pytest.mark.parametrize("end_class, expected", [("complete", "defective"), ("incomplete", "defective"),
                                                 ("void", "void")])
def test_pass_class_is_the_worst_of_the_ledger_class_and_defective(tmp_path, end_class, expected):
    doc = fx.scorer_doc()
    fixture = _fixture("defect-hits-null")
    spec, order = fx.scorer_pass(doc, fixture)
    spec.end_class = end_class
    if end_class == "complete":
        # A complete pass ran every position; only the defect makes it defective.
        cases = {c["case_id"]: c for c in doc["registry"]["cases"]}
        entries = order["model"]
        specs = {p: {} for p in range(1, len(entries) + 1)}
        specs[2] = {"H": fixture["H"]}
        spec.runs = [fx.build_run(doc["base"], cases, "model-001", "model", entries[p - 1], specs[p])
                     for p in sorted(specs)]
    data = fx.load(fx.write_pass(tmp_path, spec), doc, order, "model")
    assert data.ledger_class == end_class
    assert data.pass_class == expected


def test_a_clean_incomplete_pass_keeps_its_ledger_class(tmp_path):
    data, _ = score(tmp_path, _fixture("agreement"))
    assert data.defects == () and data.pass_class == "incomplete"


def test_public_and_original_modes_give_identical_score_records(tmp_path):
    fixture = _fixture("public-placeholder-over-limit")
    _, public = score(tmp_path / "public", fixture, public=True)
    _, original = score(tmp_path / "original", fixture, public=False)
    assert scorer.records_jsonl(public) == scorer.records_jsonl(original)


def test_a_public_summary_whose_removal_copy_is_invalid_is_a_schema_defect(tmp_path):
    fixture = copy.deepcopy(_fixture("public-placeholder-over-limit"))
    step = fixture["S"]["next_steps"][0]["step"]
    # Still over 300 characters once the listed placeholder is removed.
    fixture["S"]["next_steps"][0]["step"] = step + "x" * 30
    data, _ = score(tmp_path, fixture, public=True)
    assert [rule for rule, _ in data.defects] == ["s-schema"]


def test_determinism_in_public_mode_compares_removal_copies(tmp_path):
    doc = fx.scorer_doc()
    fixture = copy.deepcopy(_fixture("baseline-repeat-equal"))
    fixture["S"] = {"next_steps": [{"step": "Block <<REDACTED:ipv4:1>> now.", "sources": ["rule_id"]}]}
    fixture["second"] = {"S": {"next_steps": [{"step": "Block <<REDACTED:ipv4:2>> now.", "sources": ["rule_id"]}]}}
    fixture["public"] = [
        {"file": "run-0002.summary.json", "pointer": "/next_steps/0/step", "rule": "ipv4", "n": 1,
         "classification": "synthetic-match"},
        {"file": "run-0010.summary.json", "pointer": "/next_steps/0/step", "rule": "ipv4", "n": 2,
         "classification": "synthetic-match"}]
    spec, order = fx.scorer_pass(doc, fixture)
    data = fx.load(fx.write_pass(tmp_path, spec), doc, order, "baseline")
    assert data.defects == ()
    # The same placeholders in original mode stand for the same address: also equal.
    spec.public = False
    data = fx.load(fx.write_pass(tmp_path / "original", spec), doc, order, "baseline")
    assert data.defects == ()


def test_scoring_reads_only_views(tmp_path):
    data, _ = score(tmp_path, _fixture("agreement"))
    run = data.runs[1]
    for view in (run.order, run.structure, run.label, run.h, run.s, run.a_run, *run.a_tools):
        assert isinstance(view, records.View)
    with pytest.raises(common.AllowListError):
        run.s["asset.host"]
