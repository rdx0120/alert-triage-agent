"""The evaluation dataset: registry, case files, labels and run order (DD-034).

These tests check the committed dataset against the rules it was written under
(eval/rubric.md and the dataset validators in evaluation/labels.py and
evaluation/records.py), so a later edit to a case, a label or the order fails
here. They read files only and run no backend. The validators themselves are
tested in tests/test_eval_*.py; this file applies them to the real dataset.
"""

import json
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from evaluation import identity, labels, manifest, order, records
from evaluation.common import canonical_dumps, read_regular
from triage.config import REPO_ROOT
from triage.ingest import load_alert
from triage.tripwire import injection_signals

EVAL = REPO_ROOT / "eval"
SIGMA_RULES = REPO_ROOT / "vendor" / "sigma-detection-pack" / "rules"
_GIT_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR")


@pytest.fixture(scope="module")
def registry():
    return records.load_registry(EVAL / "cases.json")


@pytest.fixture(scope="module")
def label_set():
    return records.load_labels(EVAL / "labels.json")


def _case_bytes(case) -> bytes:
    return read_regular(REPO_ROOT / case.path)


def test_registry_is_valid_and_matches_its_case_files(registry):
    """A registry entry is malformed, or its alert ID or rule level differs from its case file."""
    doc = json.loads((EVAL / "cases.json").read_text(encoding="utf-8"))
    assert records.registry_problems(doc) == []
    assert labels.registry_binding_problems(registry, REPO_ROOT) == []


def test_the_dataset_has_the_approved_composition(registry):
    """The dataset is not 10 development cases and 30 test cases (14 A, 5 B, 8 C, 3 D)."""
    dev = sorted(c.path for c in registry.cases if c.family == "dev")
    samples = sorted(str(p.relative_to(REPO_ROOT).as_posix()) for p in (REPO_ROOT / "samples" / "alerts").glob("*/*.json"))
    assert dev == samples and len(dev) == 10
    tests = registry.test_cases()
    assert Counter(c.family for c in tests) == {"A": 14, "B": 5, "C": 8, "D": 3}
    assert Counter(c.phrasing for c in tests if c.family == "C") == {"known": 4, "evasive": 4}
    assert {c.format for c in tests} == {"sigma", "wazuh"}
    on_disk = sorted(p.relative_to(REPO_ROOT).as_posix() for p in (EVAL / "cases" / "test").iterdir())
    assert on_disk == sorted(c.path for c in tests)


def test_every_vendored_rule_has_a_test_case(registry):
    """A vendored Sigma rule is not exercised by any test case."""
    rule_ids = set()
    for path in SIGMA_RULES.glob("*.yml"):
        ids = [line.split(":", 1)[1].strip() for line in path.read_text(encoding="utf-8").splitlines()
               if line.startswith("id:")]
        assert len(ids) == 1
        rule_ids.add(ids[0])
    used = {json.loads(_case_bytes(c))["rule"]["id"] for c in registry.test_cases() if c.format == "sigma"}
    assert len(rule_ids) == 7 and rule_ids <= used


def test_labels_follow_the_schema_and_the_rubric(registry, label_set):
    """A label is malformed, names another rubric, or breaks a rubric or objective rule."""
    doc = json.loads((EVAL / "labels.json").read_text(encoding="utf-8"))
    assert records.labels_schema_problems(doc) == []
    rubric = read_regular(EVAL / "rubric.md")
    assert labels.labels_problems(label_set, registry, rubric, root=REPO_ROOT) == []


SEVERITIES = ("informational", "low", "medium", "high", "critical")


def _rubric_severity(alert, assets, kev) -> str:
    """eval/rubric.md section 2, applied to one parsed alert."""
    level = SEVERITIES.index(alert.rule_level)
    in_kev = any(kev.get(cve, {}).get("in_kev") for cve in alert.cves)
    asset = assets.get(alert.host.upper()) if alert.host else None
    if asset is not None:
        if asset["criticality"] in ("high", "critical") or asset["exposure"] == "internet-facing":
            level += 1
        elif asset["criticality"] == "low" and asset["exposure"] == "internal" and not in_kev:
            level -= 1
    if in_kev:
        level += 1
    return SEVERITIES[max(0, min(len(SEVERITIES) - 1, level))]


def _rubric_techniques(alert, retired) -> list[str]:
    """eval/rubric.md section 3: the rule's techniques, each retired ID replaced as the snapshot records."""
    out = set()
    for tid in alert.attack_tags():
        seen = set()
        while tid is not None and tid in retired and tid not in seen:
            seen.add(tid)
            tid = retired[tid]
        if tid is not None:
            out.add(tid)
    return sorted(out)


def test_labels_apply_the_rubric_tables_without_departures(registry, label_set):
    """A label's severity, techniques or status differs from what rubric sections 2 to 4 give.

    No label departs from the tables, so every one must equal the computed value.
    A future departure must change this test together with its rationale entry.
    """
    assets = {a["host"].upper(): a for a in json.loads((REPO_ROOT / "data" / "assets.json").read_text())["assets"]}
    kev = json.loads((REPO_ROOT / "data" / "kev_epss_snapshot.json").read_text())["cves"]
    retired = json.loads((REPO_ROOT / "data" / "attack_techniques.json").read_text())["retired"]
    by_label = label_set.by_id()
    for case in registry.cases:
        alert = load_alert(_case_bytes(case), case.format)
        label = by_label[case.case_id]
        assert label.expected_severity == _rubric_severity(alert, assets, kev), case.case_id
        assert label.acceptable_techniques == _rubric_techniques(alert, retired), case.case_id
        assert label.expected_status == "triaged", case.case_id


def test_each_twin_differs_from_its_clean_twin_only_in_injected_text(registry):
    """A twin differs from its clean twin outside attacker-writable string values, or not at all."""
    by_id = registry.by_id()
    for case in registry.cases:
        if case.family != "C":
            continue
        clean = by_id[case.clean_twin]
        assert labels.twin_diff(_case_bytes(clean), _case_bytes(case), case.format) != []


def test_each_phrasing_is_in_the_class_its_registry_entry_names(registry, label_set):
    """A known phrasing does not match the tripwire, or an evasive one does."""
    by_label = label_set.by_id()
    for case in registry.cases:
        if case.family != "C":
            continue
        suspected = injection_signals(load_alert(_case_bytes(case), case.format)).suspected
        assert suspected == (case.phrasing == "known") == by_label[case.case_id].expected_flagged


def _frozen_paths() -> list[str]:
    """The manifest's file list once it is committed; before that, the tracked files it will list."""
    path = EVAL / "manifest.json"
    if path.exists():
        return [f.path for f in manifest.load_manifest(read_regular(path)).files]
    if not (REPO_ROOT / ".git").exists() or shutil.which("git") is None:
        pytest.skip("not a Git checkout: the tracked files cannot be listed")
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV}
    out = subprocess.run(["git", "-C", str(REPO_ROOT), "ls-files", "-z"], capture_output=True, env=env,
                         check=True).stdout
    return sorted(p for p in (os.fsdecode(x) for x in out.split(b"\0") if x) if p not in identity.EXCLUDED)


def test_each_marker_appears_only_in_its_own_twin_and_label(registry, label_set):
    """A marker is missing from its twin, outside the injected text, or present in another frozen input."""
    frozen = _frozen_paths()
    assert "eval/labels.json" in frozen and "eval/cases.json" in frozen
    assert labels.marker_scope_problems(label_set, registry, REPO_ROOT, frozen) == []


def test_the_order_is_valid_and_regenerates_from_its_seed(registry):
    """The order breaks the order rules, or differs from what its seed and warm-up generate."""
    data = read_regular(EVAL / "order.json")
    doc = json.loads(data)
    assert records.order_problems(doc, registry) == []
    assert canonical_dumps(order.generate(registry, doc["seed"], doc["model"][0]["case_id"])) == data


def test_test_case_hosts_are_in_the_inventory_or_declared(registry):
    """A test case names a host that is neither in data/assets.json nor declared unknown in its provenance."""
    assets = {a["host"] for a in json.loads((REPO_ROOT / "data" / "assets.json").read_text())["assets"]}
    entries = {e["path"]: e for e in json.loads((REPO_ROOT / "provenance.json").read_text())["files"]}
    found = []
    for case in registry.test_cases():
        host = load_alert(_case_bytes(case), case.format).host
        if host is not None and host not in assets and host not in entries[case.path].get("unknown_hosts", []):
            found.append(case.case_id)
    assert found == []
