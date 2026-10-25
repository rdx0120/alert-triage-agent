"""Fail-closed consistency: checks that hold under python -O, revalidation that
never quotes input, strict types in the audit run record, and the gap packing
the citation re-check relies on (H1b)."""

import json
import os
import subprocess
import sys
import warnings

import pytest

from test_audit import MARKER, _assert_run_field_refused, _heuristic
from triage.audit import audit_records
from triage.config import REPO_ROOT
from triage.guardrails import build_summary
from triage.prompt import ENRICHMENT_VIEW_MAX_BYTES, _section_bytes, enrichment_view
from triage.schemas import Enrichment, Gap, TechniqueResolution, ToolResult

TRIPWIRE = REPO_ROOT / "triage" / "tripwire.py"

# Runs in a fresh "python -O" process. It loads tripwire.py's source, applies
# one replacement and executes it as a new module, so the repository's file is
# never changed. It prints the RuntimeError's message, or IMPORTED if the
# module loaded. No assert here: -O would remove it.
PROBE = """
import json, sys, types
if sys.flags.optimize != 1:
    print("NOT OPTIMIZED")
    sys.exit(0)
path, old, new = json.loads(sys.argv[1])
source = open(path, encoding="utf-8").read()
if source.count(old) != 1:
    print("NO MATCH")
    sys.exit(0)
module = types.ModuleType("triage._tripwire_probe")
module.__package__ = "triage"
sys.modules[module.__name__] = module   # @dataclass looks its module up here
try:
    exec(compile(source.replace(old, new), path, "exec"), module.__dict__)
except RuntimeError as error:
    print(error)
else:
    print("IMPORTED")
"""


def _probe(old, new):
    out = subprocess.run([sys.executable, "-O", "-c", PROBE, json.dumps([str(TRIPWIRE), old, new])],
                         capture_output=True, text=True, cwd=REPO_ROOT,
                         env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
                         timeout=60)
    assert out.returncode == 0, out.stderr[-500:]
    return out.stdout.strip()


@pytest.mark.parametrize("old,new,message", [
    ('    "suppression": (', '    "suppressed": (', "tripwire patterns do not match the InjectionSignal codes"),
    ('SCANNED_FIELDS = ("rule_title", "user", "timestamp", "event")',
     'SCANNED_FIELDS = ("rule_title", "user", "timestamp", "event", "not_a_field")',
     "tripwire scanned fields are not all AlertField names"),
], ids=["patterns", "scanned_fields"])
def test_tripwire_consistency_checks_hold_under_optimize(old, new, message):
    """Under python -O, a corrupted tripwire table imports instead of failing with its fixed message."""
    assert _probe(old, new) == message


def test_unmodified_tripwire_imports_under_optimize():
    """The unmodified tripwire fails to import under python -O."""
    assert _probe('SCANNED_FIELDS = ("rule_title"', 'SCANNED_FIELDS = ("rule_title"') == "IMPORTED"


# --- Revalidation never quotes the value -------------------------------------

@pytest.mark.parametrize("records,field", [("model_calls", "turn"), ("tool_records", "turn")])
def test_audit_revalidation_quotes_nothing(records, field, settings, tools):
    """A wrongly typed record value is quoted in a serializer warning, or not refused."""
    result, alert = _heuristic(settings, tools)
    result = result.model_copy(deep=True)
    object.__setattr__(getattr(result, records)[0], field, MARKER)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(ValueError) as raised:
            audit_records(result, alert)
    assert str(raised.value) == "a model call or lookup record is outside its schema"


def test_guardrails_revalidation_quotes_nothing(settings, tools):
    """A wrongly typed draft value is quoted in a serializer warning, or accepted."""
    result, alert = _heuristic(settings, tools)
    result = result.model_copy(deep=True)
    object.__setattr__(result.draft, "severity", MARKER)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        summary = build_summary(result, alert, settings, tools)
    assert summary.status == "error" and "draft_invalid" in summary.anomalies
    assert MARKER not in summary.model_dump_json()


# --- Strict types in the audit run record --------------------------------------

class AlwaysEqual(str):
    """Text that claims to equal anything, so it passes a membership test."""

    def __eq__(self, other):
        return True

    __hash__ = str.__hash__


@pytest.mark.parametrize("obj,field", [
    ("alert", "source"), ("alert", "rule_level"), ("severity", "value"), ("enrichment", "status"),
    ("result", "stop_reason"), ("result", "budget_detail"),
])
def test_run_enum_must_be_plain_str(obj, field, tmp_path, settings, tools):
    """A str subclass that equals everything passes a run-level enum check and its text is written."""
    result, alert = _heuristic(settings, tools)
    result, alert = result.model_copy(deep=True), alert.model_copy(deep=True)
    targets = {"alert": alert, "result": result, "enrichment": result.enrichment, "severity": result.draft.severity}
    setattr(targets[obj], field, AlwaysEqual(MARKER))
    _assert_run_field_refused(result, alert, tmp_path)


@pytest.mark.parametrize("field", ["kind", "reason"])
def test_gap_enum_must_be_plain_str(field, tmp_path, settings, tools):
    """A gap whose kind or reason is a str subclass that equals everything is written."""
    result, alert = _heuristic(settings, tools)
    result = result.model_copy(deep=True)
    values = {"kind": "asset", "reason": "not_found", field: AlwaysEqual(MARKER)}
    result.enrichment.gaps.append(Gap.model_construct(**values))
    _assert_run_field_refused(result, alert, tmp_path)


@pytest.mark.parametrize("gaps", [5, None, "gaps", [object()], [{"kind": "asset", "reason": "not_found"}]],
                         ids=["int", "none", "str", "object", "dict"])
def test_gaps_container_gives_the_fixed_message(gaps, tmp_path, settings, tools):
    """A replaced gaps container raises TypeError or AttributeError instead of the fixed message."""
    result, alert = _heuristic(settings, tools)
    result = result.model_copy(deep=True)
    object.__setattr__(result.enrichment, "gaps", gaps)
    _assert_run_field_refused(result, alert, tmp_path)


# --- Gap packing the citation re-check relies on --------------------------------

def test_largest_gap_and_resolution_sections_are_never_packed_out():
    """A cap change lets enrichment_view() drop a gap or resolution that build_summary() treats as shown."""
    def eid(n):
        return "a" + "b" * 63 + f":{n:016x}"   # the longest evidence ID the pattern allows
    techniques = [f"T{1000 + n}.{100 + n}" for n in range(5)]
    # The most gaps enrichment can produce: 5 technique and 5 CVE lookups, an
    # over_cap gap for each, plus asset and runbook; the longest reason.
    gaps = ([Gap(kind="technique", reason="lookup_failed", evidence_id=eid(n)) for n in range(5)]
            + [Gap(kind="technique", reason="over_cap")]
            + [Gap(kind="vulnerability", reason="lookup_failed", evidence_id=eid(10 + n)) for n in range(5)]
            + [Gap(kind="vulnerability", reason="over_cap")]
            + [Gap(kind="asset", reason="lookup_failed", evidence_id=eid(20)),
               Gap(kind="runbook", reason="lookup_failed", evidence_id=eid(21))])
    resolutions = [TechniqueResolution(requested=f"T{2000 + n}.{200 + n}", resolved=techniques[n],
                                       evidence_ids=[eid(30 + 4 * n + k) for k in range(4)]) for n in range(5)]
    assert len(gaps) == 14
    ok = ToolResult(evidence_id=eid(99), tool="attack_lookup", args={}, status="ok", data={"name": "x"})
    enrichment = Enrichment(alert_id="a", status="degraded", techniques=techniques, resolutions=resolutions,
                            evidence=[ok], gaps=gaps)
    view = enrichment_view(enrichment)
    assert "_omitted" not in view
    assert view["gaps"] == [g.model_dump() for g in gaps]
    assert view["resolutions"] == [r.model_dump() for r in resolutions]
    assert view["results"]   # packing reached the results, after every gap and resolution
    shown = {g["evidence_id"] for g in view["gaps"] if g["evidence_id"]} | {
        i for r in view["resolutions"] for i in r["evidence_ids"]}
    in_view = {g.evidence_id for g in gaps if g.evidence_id} | {i for r in resolutions for i in r.evidence_ids}
    assert shown == in_view
    head = {k: view[k] for k in ("status", "techniques", "resolutions", "gaps")}
    print(f"\ngaps and resolutions section: {_section_bytes(head)} of {ENRICHMENT_VIEW_MAX_BYTES} bytes")
