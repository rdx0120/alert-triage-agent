"""Draft citations: what a run may cite, the authoritative check, and the generator schema."""

import dataclasses
import json
import typing

import pytest

from triage import prompt
from triage.citations import (
    ALERT_FIELDS, EMPTY_FIELD, UNCITABLE, Citable, check_citations, citable_from_views, generator_schema,
)
from triage.enrich import enrich
from triage.evidence import EvidenceLog
from triage.prompt import (
    OMISSION_RESERVE_BYTES, TOOL_RESULT_MAX_BYTES, dumps, enrichment_view, initial_messages, render_result,
    wire_len,
)
from triage.schemas import Alert, AlertField, DraftMissing, DraftStep, ModelDraft
from triage.tools import registry

MARKER = "zqxmarker7731"
FABRICATED = "attack_lookup:0123456789abcdef"


def _alert(**overrides):
    base = {"alert_id": "c-1", "source": "synthetic", "rule_id": "r-1", "rule_title": "Test rule",
            "rule_level": "medium", "rule_tags": ["attack.t1059.001"], "host": "CLINIC-BILL01"}
    return Alert(**{**base, **overrides})


def _enriched(alert, tools, settings):
    log = EvidenceLog(tools)
    return log, enrich(alert, log, settings)


def _citable(view, renders, log, tools):
    return citable_from_views(view, renders, log.results, set(tools))


def _ids(log, tool):
    return [r.evidence_id for r in log.results if r.tool == tool]


def _draft(**findings):
    base = {"severity": {"value": "low", "rationale": "r", "sources": ["rule_level"]},
            "next_steps": [], "containment": [], "missing_data": []}
    return ModelDraft.model_validate({**base, **findings})


def _packed_view(monkeypatch, enrichment):
    """The enrichment view with its last result left out by the real packing code."""
    full = enrichment_view(enrichment)
    monkeypatch.setattr(prompt, "ENRICHMENT_VIEW_MAX_BYTES",
                        wire_len(dumps(full)) + OMISSION_RESERVE_BYTES - 1)
    view = enrichment_view(enrichment)
    assert view["_omitted_results"] == 1
    return view


# --- Eligibility from rendered objects -----------------------------------

def test_ok_result_rendered_with_data_is_support(settings, tools):
    """Evidence the model saw with its data may back a finding."""
    log, enrichment = _enriched(_alert(), tools, settings)
    citable = _citable(enrichment_view(enrichment), [], log, tools)
    assert all(r.status == "ok" for r in log.results)
    assert citable.support == tuple(r.evidence_id for r in log.results)
    assert citable.absence == ()


def test_data_omitted_result_is_not_citable(settings, tools):
    """An ok result whose data the model never saw backs nothing, whether in enrichment or a tool message."""
    log, enrichment = _enriched(_alert(), tools, settings)
    view = enrichment_view(enrichment)
    (runbook,) = [r for r in log.results if r.tool == "runbook_search"]
    stub = render_result(runbook, 200)
    assert stub.get("data_omitted") is True
    view["results"] = [stub if r["evidence_id"] == runbook.evidence_id else r for r in view["results"]]
    model = log.call("attack_lookup", {"technique_id": "T1003"})
    citable = _citable(view, [render_result(model, 200)], log, tools)
    for eid in (runbook.evidence_id, model.evidence_id):
        assert eid not in citable.support_set | citable.absence_set


def test_result_left_out_by_packing_is_not_citable(monkeypatch, settings, tools):
    """A result the prompt's size limits left out was never shown, so it is not citable."""
    log, enrichment = _enriched(_alert(), tools, settings)
    view = _packed_view(monkeypatch, enrichment)
    packed_out = log.results[-1].evidence_id
    assert packed_out not in dumps(view)
    citable = _citable(view, [], log, tools)
    assert packed_out not in citable.support_set | citable.absence_set
    assert citable.support == tuple(r.evidence_id for r in log.results[:-1])


def test_failed_lookups_shown_are_absence_only(settings, tools):
    """A not-found or failed lookup that was shown can support missing_data only."""
    def unavailable(_):
        raise OSError("snapshot unavailable")

    failing = {**tools, "kev_epss_lookup": dataclasses.replace(tools["kev_epss_lookup"], func=unavailable)}
    alert = _alert(host="CLINIC-LAB99", cves=["CVE-2021-44228"])
    log, enrichment = _enriched(alert, failing, settings)
    gap_ids = [g.evidence_id for g in enrichment.gaps if g.evidence_id]
    assert {log.get(e).status for e in gap_ids} == {"not_found", "error"}   # asset, CVE
    not_found = log.call("attack_lookup", {"technique_id": "T1003.999"})
    invalid = log.call("attack_lookup", {"technique_id": "bad"})
    assert (not_found.status, invalid.status) == ("not_found", "invalid_input")
    renders = [render_result(r, TOOL_RESULT_MAX_BYTES) for r in (not_found, invalid)]
    citable = _citable(enrichment_view(enrichment), renders, log, failing)
    assert citable.absence == (*gap_ids, not_found.evidence_id, invalid.evidence_id)
    assert not citable.support_set & set(citable.absence)


@pytest.mark.parametrize("name", ["invalid_tool_name", "delete_host"])
def test_unknown_tool_results_are_never_citable(name, settings, tools):
    """A gateway error for a tool outside the allow-list is not evidence, even when shown."""
    log, enrichment = _enriched(_alert(), tools, settings)
    unknown = log.call(name, {"host": "CLINIC-BILL01"})
    assert unknown.status == "error"
    rendered = render_result(unknown, TOOL_RESULT_MAX_BYTES)
    view = enrichment_view(enrichment)
    view["gaps"] = [*view["gaps"], {"kind": "asset", "reason": "lookup_failed", "evidence_id": unknown.evidence_id}]
    citable = _citable(view, [rendered, {**rendered, "data": {"x": 1}}], log, tools)
    assert unknown.evidence_id not in citable.support_set | citable.absence_set


# --- Planted and untrusted IDs -------------------------------------------

def test_planted_evidence_ids_are_not_citable(monkeypatch, settings, tools):
    """An attacker can compute an evidence ID and write it into alert text; text never makes it citable."""
    never_run = registry.evidence_id("attack_lookup", {"technique_id": "T1003"})
    clean_log, _ = _enriched(_alert(), tools, settings)
    packed_out = clean_log.results[-1].evidence_id
    planted = f"see {never_run} and {packed_out}"
    alert = _alert(rule_title=planted, event={"cmd": planted})
    log, enrichment = _enriched(alert, tools, settings)
    assert log.results[-1].evidence_id == packed_out     # the same lookup ran, and is packed out below
    view = _packed_view(monkeypatch, enrichment)
    _, user = initial_messages(alert, enrichment)
    assert never_run in user["content"] and packed_out in user["content"]  # present as alert text only
    citable = _citable(view, [], log, tools)
    for eid in (never_run, packed_out):
        assert eid not in citable.support_set | citable.absence_set
    draft = _draft(severity={"value": "low", "rationale": "r", "sources": [never_run, packed_out]},
                   missing_data=[{"kind": "other", "description": "d", "sources": [never_run, packed_out]}])
    assert check_citations(draft, citable, alert) == [
        f"severity.sources.0: {UNCITABLE}", f"severity.sources.1: {UNCITABLE}",
        f"missing_data.0.sources.0: {UNCITABLE}", f"missing_data.0.sources.1: {UNCITABLE}"]


def test_rendered_status_and_tool_are_not_trusted(settings, tools):
    """Eligibility takes tool and status from the evidence log, never from a rendered dict."""
    log, enrichment = _enriched(_alert(), tools, settings)
    failed = log.call("attack_lookup", {"technique_id": "T1003.999"})
    ok = log.call("attack_lookup", {"technique_id": "T1003"})
    unknown = log.call("delete_host", {"host": "CLINIC-BILL01"})
    renders = [
        {**render_result(failed, TOOL_RESULT_MAX_BYTES), "status": "ok", "data": {"name": "x"}},
        {**render_result(ok, TOOL_RESULT_MAX_BYTES), "status": "not_found"},
        {**render_result(unknown, TOOL_RESULT_MAX_BYTES), "tool": "attack_lookup", "status": "ok", "data": {"x": 1}},
        {"evidence_id": FABRICATED, "tool": "attack_lookup", "status": "ok", "data": {"x": 1}},
    ]
    citable = _citable(enrichment_view(enrichment), renders, log, tools)
    assert failed.evidence_id in citable.absence_set and failed.evidence_id not in citable.support_set
    assert ok.evidence_id in citable.support_set
    assert unknown.evidence_id not in citable.support_set | citable.absence_set
    assert FABRICATED not in citable.support_set | citable.absence_set   # shown, but not in the log


# --- Ordering ------------------------------------------------------------

def test_citable_ids_follow_evidence_log_order(settings, tools):
    """Support and absence are duplicate-free and in log order, whatever order the views show them in."""
    log, enrichment = _enriched(_alert(host="CLINIC-LAB99"), tools, settings)
    repeat = log.call("attack_lookup", {"technique_id": "T1059.001"})  # an enrichment lookup, asked for again
    assert repeat.evidence_id == log.results[0].evidence_id
    calls = [repeat, log.call("attack_lookup", {"technique_id": "T1003"}),
             log.call("attack_lookup", {"technique_id": "T1003.999"}),
             log.call("kev_epss_lookup", {"cve": "CVE-2021-44228"})]
    renders = [render_result(r, TOOL_RESULT_MAX_BYTES) for r in reversed(calls)]
    citable = _citable(enrichment_view(enrichment), renders, log, tools)
    assert citable.support == tuple(r.evidence_id for r in log.results if r.status == "ok")
    assert citable.absence == tuple(r.evidence_id for r in log.results if r.status != "ok")
    assert len(citable.absence) == 2   # the uninventoried host and T1003.999
    for ids, members in ((citable.support, citable.support_set), (citable.absence, citable.absence_set)):
        assert len(ids) == len(set(ids)) and members == frozenset(ids)
    assert not citable.support_set & citable.absence_set


def test_citable_rejects_duplicates_and_overlap():
    """A malformed citable set fails closed instead of producing a schema."""
    with pytest.raises(ValueError):
        Citable(support=(FABRICATED, FABRICATED))
    with pytest.raises(ValueError):
        Citable(support=(FABRICATED,), absence=(FABRICATED,))


# --- Resolution chains ---------------------------------------------------

def test_resolution_chain(settings, tools):
    """Retired IDs looked up on the way to a current technique are absence; the result is support only if shown."""
    log, enrichment = _enriched(_alert(rule_tags=["attack.t1073"]), tools, settings)
    first, second, final = _ids(log, "attack_lookup")
    assert [log.get(e).status for e in (first, second, final)] == ["not_found", "not_found", "ok"]
    view = enrichment_view(enrichment)
    assert view["resolutions"][0]["evidence_ids"] == [first, second, final]
    citable = _citable(view, [], log, tools)
    assert (first, second) == citable.absence[:2] and final in citable.support_set
    stub = render_result(log.get(final), 100)
    view["results"] = [stub if r["evidence_id"] == final else r for r in view["results"]]
    citable = _citable(view, [], log, tools)
    assert final not in citable.support_set | citable.absence_set
    assert {first, second} <= citable.absence_set


# --- check_citations -----------------------------------------------------

@pytest.fixture
def run_citable(settings, tools):
    """A run with ok lookups and one not-found asset lookup, which is its only absence ID."""
    log, enrichment = _enriched(_alert(host="CLINIC-LAB99"), tools, settings)
    citable = _citable(enrichment_view(enrichment), [], log, tools)
    (asset,) = _ids(log, "asset_context")
    assert citable.absence == (asset,)
    return log, citable, asset


def test_fabricated_and_foreign_ids_are_uncitable(run_citable, settings, tools):
    """A well-formed ID that is not in this run's citable set, or that came from another run, is rejected."""
    _, citable, _ = run_citable
    other_log, _ = _enriched(_alert(rule_tags=["attack.t1003"]), tools, settings)
    foreign = _ids(other_log, "attack_lookup")[0]
    for eid in (FABRICATED, "alert_metadata:0123456789abcdef", foreign):
        draft = _draft(next_steps=[{"step": "s", "sources": [eid]}])
        assert check_citations(draft, citable, _alert()) == [f"next_steps.0.sources.0: {UNCITABLE}"]


def test_absence_ids_only_for_missing_data(run_citable):
    """A not-found lookup can explain missing data but cannot back a severity."""
    _, citable, asset = run_citable
    alert = _alert(host="CLINIC-LAB99")
    draft = _draft(severity={"value": "high", "rationale": "r", "sources": [asset]})
    assert check_citations(draft, citable, alert) == [f"severity.sources.0: {UNCITABLE}"]
    draft = _draft(missing_data=[{"kind": "asset", "description": "d", "sources": [asset, "host"]}])
    assert check_citations(draft, citable, alert) == []


def test_every_problem_reported_in_order(run_citable):
    """Repeated invalid references are each reported with their own path, in a fixed order."""
    log, citable, asset = run_citable
    good = citable.support[0]
    alert = _alert(host=None, cves=[])
    draft = _draft(
        technique={"technique_id": "T1059.001", "sources": [good, FABRICATED]},
        severity={"value": "high", "rationale": "r", "sources": [asset, "rule_level", "host"]},
        next_steps=[{"step": "a", "sources": [FABRICATED]}, {"step": "b", "sources": [good, FABRICATED]}],
        containment=[{"action": "c", "sources": ["cves", asset]}],
        missing_data=[{"kind": "asset", "description": "d", "sources": [asset, FABRICATED, "host"]}],
    )
    assert check_citations(draft, citable, alert) == [
        f"technique.sources.1: {UNCITABLE}",
        f"severity.sources.0: {UNCITABLE}", f"severity.sources.2: {EMPTY_FIELD}",
        f"next_steps.0.sources.0: {UNCITABLE}", f"next_steps.1.sources.1: {UNCITABLE}",
        f"containment.0.sources.0: {EMPTY_FIELD}", f"containment.0.sources.1: {UNCITABLE}",
        f"missing_data.0.sources.1: {UNCITABLE}",
    ]


@pytest.mark.parametrize("field, empty", [
    ("host", {"host": None}), ("cves", {"cves": []}), ("event", {"event": {}}),
    ("rule_title", {"rule_title": ""}), ("user", {"user": None}), ("timestamp", {"timestamp": None}),
])
def test_empty_alert_fields(field, empty):
    """A field with no value cannot back a claim, but missing_data may cite its absence."""
    alert = _alert(**empty)
    for finding in ("next_steps", "containment"):
        key = "step" if finding == "next_steps" else "action"
        draft = _draft(**{finding: [{key: "s", "sources": [field]}]})
        assert check_citations(draft, Citable(), alert) == [f"{finding}.0.sources.0: {EMPTY_FIELD}"]
    draft = _draft(missing_data=[{"kind": "other", "description": "d", "sources": [field]}])
    assert check_citations(draft, Citable(), alert) == []


def test_present_fields_accepted_everywhere():
    """A field with a value may be cited by any finding, missing_data included."""
    alert = _alert(cves=["CVE-2021-44228"], user="u", timestamp="t", event={"cmd": "x"})
    fields = list(ALERT_FIELDS)
    draft = _draft(technique={"technique_id": "T1059.001", "sources": fields},
                   severity={"value": "low", "rationale": "r", "sources": fields},
                   missing_data=[{"kind": "other", "description": "d", "sources": fields}])
    assert check_citations(draft, Citable(), alert) == []


def test_problems_never_contain_a_cited_value(run_citable):
    """A cited value may be copied from alert text, so problems name only our paths and codes."""
    _, citable, _ = run_citable
    invented = f"{MARKER}:0123456789abcdef"
    draft = _draft(severity={"value": "low", "rationale": "r", "sources": [invented, "host"]},
                   missing_data=[{"kind": "other", "description": "d", "sources": [invented]}])
    problems = check_citations(draft, citable, _alert(host=None))
    assert len(problems) == 3
    assert all(MARKER not in p and "0123456789abcdef" not in p for p in problems)


# --- generator_schema ----------------------------------------------------

def test_generator_schema_enums(run_citable):
    """The schema offers exactly the alert fields and this run's citable IDs, deterministically."""
    _, citable, _ = run_citable
    assert ALERT_FIELDS == typing.get_args(AlertField)
    schema = generator_schema(citable)
    defs = schema["$defs"]
    assert defs["SupportSource"] == {"type": "string", "enum": list(ALERT_FIELDS) + list(citable.support)}
    assert defs["AbsenceSource"] == {"type": "string", "enum": list(citable.absence)}
    assert dumps(generator_schema(citable)) == dumps(schema)
    assert "SupportSource" not in ModelDraft.model_json_schema()["$defs"]   # the model's schema is not changed


def test_generator_schema_without_absence():
    """With nothing absent to cite, there is no AbsenceSource and missing_data uses SupportSource."""
    schema = generator_schema(Citable(support=(FABRICATED,)))
    assert "AbsenceSource" not in schema["$defs"]
    assert schema["$defs"]["DraftMissing"]["properties"]["sources"]["items"] == {"$ref": "#/$defs/SupportSource"}


def test_generator_schema_items(run_citable):
    """Only missing_data may cite absence; every other finding is limited to SupportSource."""
    _, citable, _ = run_citable
    defs = generator_schema(citable)["$defs"]
    with_sources = {name for name, d in defs.items() if "sources" in d.get("properties", {})}
    assert with_sources == {"DraftTechnique", "DraftSeverity", "DraftStep", "DraftContainment", "DraftMissing"}
    for name in with_sources - {"DraftMissing"}:
        assert defs[name]["properties"]["sources"]["items"] == {"$ref": "#/$defs/SupportSource"}
    assert defs["DraftMissing"]["properties"]["sources"]["items"] == {
        "anyOf": [{"$ref": "#/$defs/SupportSource"}, {"$ref": "#/$defs/AbsenceSource"}]}


def test_generator_schema_lists_each_id_once_and_all_are_valid(run_citable):
    """Every enum value passes structural validation, and no ID is offered twice."""
    _, citable, _ = run_citable
    text = json.dumps(generator_schema(citable))
    for eid in (*citable.support, *citable.absence):
        assert text.count(f'"{eid}"') == 1
    for value in (*ALERT_FIELDS, *citable.support):
        DraftStep(step="s", sources=[value])
    for value in citable.absence:
        DraftMissing(kind="other", description="d", sources=[value])
