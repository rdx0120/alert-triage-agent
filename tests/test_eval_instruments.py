"""Instrument fixity: the list, the fixtures digest and the check against a recorded list."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

import pytest

import test_eval_doubles as dbl
from evaluation import instruments


@pytest.fixture
def clone(tmp_path, tmp_path_factory):
    return dbl.make_clone(tmp_path, tmp_path_factory, n_tests=1)


def tool(clone, *args):
    return subprocess.run([sys.executable, "-s", "-B", "-P", str(clone.path / "evaluation" / "instruments.py"),
                           *args, "--clone", os.path.realpath(clone.path)], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "HOME": str(clone.path.parent)})


def commit(clone):
    dbl.git(clone.path, "add", "-A")
    dbl.git(clone.path, "commit", "-q", "-m", "change")


def test_the_list_covers_exactly_the_instrument_set_sorted(clone):
    out = tool(clone, "list")
    assert out.returncode == 0, out.stderr
    lines = out.stdout.splitlines()
    paths = [line.split("  ", 1)[1] for line in lines]
    tracked = dbl.git(clone.path, "ls-files").splitlines()
    expected = sorted(p for p in tracked if p.startswith(("evaluation/", "tests/data/eval/")) or p == "eval/rubric.md"
                      or (p.startswith("tests/test_eval_") and p.endswith(".py") and "/" not in p[6:]))
    assert paths == expected
    assert "tests/data/eval/scorer_fixtures.json" in paths and "evaluation/instruments.py" in paths
    for line in lines:
        digest, path = line.split("  ", 1)
        assert digest == hashlib.sha256((clone.path / path).read_bytes()).hexdigest()


def test_the_list_refuses_a_dirty_clone(clone):
    (clone.path / "untracked.txt").write_text("x")
    out = tool(clone, "list")
    assert out.returncode == 2 and out.stderr == "instruments: error: code: working tree is not clean\n"


def test_the_fixtures_digest_is_stable_and_tracks_behaviour_not_comments(clone, monkeypatch):
    first = tool(clone, "fixtures-digest")
    assert first.returncode == 0, first.stderr
    assert tool(clone, "fixtures-digest").stdout == first.stdout
    monkeypatch.setattr(sys, "dont_write_bytecode", True)   # keep the clone free of bytecode
    assert first.stdout.strip() == instruments.fixtures_digest(str(clone.path))
    scorer = clone.path / "evaluation" / "scorer.py"
    scorer.write_text(scorer.read_text() + "\n# A comment changes no behaviour.\n")
    commit(clone)
    assert tool(clone, "fixtures-digest").stdout == first.stdout
    fixtures = clone.path / "tests" / "data" / "eval" / "scorer_fixtures.json"
    doc = json.loads(fixtures.read_text())
    doc["fixtures"][0]["S"] = dict(doc["fixtures"][0].get("S") or {}, status="insufficient_data")
    fixtures.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    commit(clone)
    changed = tool(clone, "fixtures-digest")
    assert changed.returncode == 0 and changed.stdout != first.stdout


def test_check_reports_every_difference_and_passes_only_when_equal(clone, tmp_path):
    recorded = tmp_path / "recorded.txt"
    recorded.write_text(tool(clone, "list").stdout)
    assert tool(clone, "check", "--recorded", str(recorded)).returncode == 0
    (clone.path / "evaluation" / "added.py").write_text("x = 1\n")
    (clone.path / "eval" / "rubric.md").write_text((clone.path / "eval" / "rubric.md").read_text() + "\n")
    dbl.git(clone.path, "rm", "-q", "tests/test_eval_order.py")
    commit(clone)
    out = tool(clone, "check", "--recorded", str(recorded))
    assert out.returncode == 3
    assert out.stdout.splitlines() == ["changed eval/rubric.md", "added evaluation/added.py",
                                       "removed tests/test_eval_order.py"]


def test_check_refuses_a_malformed_recorded_list(clone, tmp_path):
    recorded = tmp_path / "recorded.txt"
    recorded.write_text("not a list line\n")
    out = tool(clone, "check", "--recorded", str(recorded))
    assert out.returncode == 2 and "malformed" in out.stderr
