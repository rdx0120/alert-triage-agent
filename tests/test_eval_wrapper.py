"""The run wrapper changes nothing the CLI does, and records exactly the enrichment search's runbooks."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from evaluation import run_one

REPO = Path(os.path.realpath(Path(__file__).resolve().parent.parent))
WRAPPER = REPO / "evaluation" / "run_one.py"
DEV_CASES = sorted([("sigma", p) for p in (REPO / "samples" / "alerts" / "sigma").glob("*.json")]
                   + [("wazuh", p) for p in (REPO / "samples" / "alerts" / "wazuh").glob("*.json")])
VOLATILE = ("timestamp", "gen_ai.conversation.id", "triage.duration_s", "triage.enrichment.duration_s",
            "triage.start_s")


def child_env(home: Path, embedder: str = "hashing") -> dict:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONHASHSEED": "0",
           "TRIAGE_BACKEND": "heuristic", "TRIAGE_EMBEDDER": embedder, "OLLAMA_HOST": "http://127.0.0.1:11434"}
    if embedder == "minilm":
        env["TRIAGE_EMBEDDING_MODEL_DIR"] = str(REPO / "models" / "all-MiniLM-L6-v2")
    return env


def scratch(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.mkdir(mode=0o700)
    return Path(os.path.realpath(path))


def run_wrapper(work: Path, fmt: str, case: Path, *, env=None, clone=REPO, wrapper=WRAPPER, umask=-1):
    cmd = [sys.executable, "-s", "-B", "-P", str(wrapper), "--clone", str(clone), "--hits-out",
           str(work / "hits.json"), "--", "--format", fmt, str(case), "--audit-log", str(work / "audit.jsonl")]
    return subprocess.run(cmd, env=env or child_env(work), cwd=work, capture_output=True, umask=umask)


def run_cli(work: Path, fmt: str, case: Path, *, env=None):
    cmd = [sys.executable, "-s", "-B", "-P", "-m", "triage", "--format", fmt, str(case), "--audit-log",
           str(work / "audit.jsonl")]
    return subprocess.run(cmd, env=env or child_env(work), cwd=work, capture_output=True)


def summary_without_run_id(stdout: bytes) -> dict:
    obj = json.loads(stdout)
    obj.pop("run_id")
    return obj


def audit_without_volatile(path: Path) -> list[dict]:
    lines = []
    for line in path.read_text().splitlines():
        obj = json.loads(line)
        for key in VOLATILE:
            obj.pop(key, None)
        lines.append(obj)
    return lines


def _equivalent(tmp_path, fmt, case, embedder="hashing"):
    a, b = scratch(tmp_path, "wrapper"), scratch(tmp_path, "cli")
    wrapped = run_wrapper(a, fmt, case, env=child_env(a, embedder))
    direct = run_cli(b, fmt, case, env=child_env(b, embedder))
    assert wrapped.returncode == direct.returncode
    assert wrapped.stderr == direct.stderr
    assert summary_without_run_id(wrapped.stdout) == summary_without_run_id(direct.stdout)
    assert audit_without_volatile(a / "audit.jsonl") == audit_without_volatile(b / "audit.jsonl")
    hits = json.loads((a / "hits.json").read_text())
    assert hits["calls"] == 1 and hits["run_id"] == json.loads(wrapped.stdout)["run_id"]


@pytest.mark.parametrize("fmt, case", DEV_CASES, ids=lambda x: x.stem if isinstance(x, Path) else x)
def test_the_wrapper_and_the_cli_give_the_same_run(tmp_path, fmt, case):
    _equivalent(tmp_path, fmt, case)


@pytest.mark.slow
@pytest.mark.parametrize("fmt, case", DEV_CASES, ids=lambda x: x.stem if isinstance(x, Path) else x)
def test_the_wrapper_and_the_cli_give_the_same_run_with_minilm(tmp_path, fmt, case):
    _equivalent(tmp_path, fmt, case, embedder="minilm")


def test_there_are_ten_development_cases():
    assert len(DEV_CASES) == 10


# --- The hits record ------------------------------------------------------------------------

def record(tool, by, evidence_id):
    return SimpleNamespace(tool=tool, requested_by=by, evidence_id=evidence_id)


def evidence(evidence_id, status, names=()):
    data = {"hits": [{"runbook": n, "score": 0.5} for n in names]} if status == "ok" else None
    return SimpleNamespace(evidence_id=evidence_id, status=status, data=data)


def result(records_, evidences, run_id="0" * 32):
    return SimpleNamespace(tool_records=records_, enrichment=SimpleNamespace(evidence=evidences), run_id=run_id)


@pytest.mark.parametrize("status, expected", [("ok", ["a.md", "b.md"]), ("not_found", []), ("error", []),
                                              ("invalid_input", [])])
def test_hits_follow_the_enrichment_search_status(status, expected):
    r = result([record("runbook_search", "enrichment", "runbook_search:1")],
               [evidence("runbook_search:1", status, ("a.md", "b.md"))])
    assert run_one.hits_record(r, calls=1) == {"calls": 1, "run_id": "0" * 32, "runbook_hits": expected}


def test_no_enrichment_search_records_no_hits():
    assert run_one.hits_record(result([], []), calls=1)["runbook_hits"] == []


def test_a_model_requested_search_is_ignored():
    r = result([record("runbook_search", "model", "runbook_search:2"),
                record("runbook_search", "enrichment", "runbook_search:1")],
               [evidence("runbook_search:2", "ok", ("x.md",)), evidence("runbook_search:1", "ok", ("a.md",))])
    assert run_one.hits_record(r, calls=1)["runbook_hits"] == ["a.md"]


def test_two_enrichment_searches_are_a_wrapper_failure():
    r = result([record("runbook_search", "enrichment", "runbook_search:1"),
                record("runbook_search", "enrichment", "runbook_search:3")],
               [evidence("runbook_search:1", "ok", ("a.md",)), evidence("runbook_search:3", "ok", ("a.md",))])
    with pytest.raises(run_one.WrapperError):
        run_one.hits_record(r, calls=1)


def test_no_observed_result_gives_null_hits():
    assert run_one.hits_record(None, calls=0) == {"calls": 0, "run_id": None, "runbook_hits": None}


def test_a_real_run_records_the_enrichment_hits(tmp_path):
    work = scratch(tmp_path, "w")
    proc = run_wrapper(work, "sigma", REPO / "samples" / "alerts" / "sigma" / "password_spray.json")
    assert proc.returncode == 0
    hits = json.loads((work / "hits.json").read_text())
    assert hits["runbook_hits"] and all(h.endswith(".md") for h in hits["runbook_hits"])


def test_an_invalid_alert_records_null_hits(tmp_path):
    work = scratch(tmp_path, "w")
    case = work / "bad.json"
    case.write_text("{}")
    proc = run_wrapper(work, "sigma", case)
    assert proc.returncode == 3
    assert json.loads((work / "hits.json").read_text()) == {"calls": 0, "run_id": None, "runbook_hits": None}


# --- Refusals ------------------------------------------------------------------------------

def test_a_mismatched_clone_exits_70_without_a_run(tmp_path):
    # The other directory holds a triage package too, so only the --clone check stops the run.
    other = scratch(tmp_path, "other")
    shutil.copytree(REPO / "triage", other / "triage")
    shutil.copytree(REPO / "data", other / "data")
    work = scratch(tmp_path, "w")
    proc = run_wrapper(work, "sigma", REPO / "samples" / "alerts" / "sigma" / "password_spray.json",
                       clone=other)
    assert proc.returncode == 70 and proc.stdout == b""
    assert not (work / "audit.jsonl").exists() and not (work / "hits.json").exists()


def test_triage_outside_the_clone_exits_70_without_a_run(tmp_path):
    fake = scratch(tmp_path, "fake")
    (fake / "evaluation").mkdir()
    shutil.copy(WRAPPER, fake / "evaluation" / "run_one.py")
    work = scratch(tmp_path, "w")
    proc = run_wrapper(work, "sigma", REPO / "samples" / "alerts" / "sigma" / "password_spray.json", clone=fake,
                       wrapper=fake / "evaluation" / "run_one.py")
    assert proc.returncode == 70 and proc.stdout == b""
    assert not (work / "audit.jsonl").exists()


def test_the_hits_record_is_0600_whatever_the_umask(tmp_path):
    work = scratch(tmp_path, "w")
    proc = run_wrapper(work, "sigma", REPO / "samples" / "alerts" / "sigma" / "password_spray.json", umask=0)
    assert proc.returncode == 0
    assert stat.S_IMODE(os.stat(work / "hits.json").st_mode) == 0o600


def test_an_existing_hits_file_makes_the_wrapper_fail_and_is_left_alone(tmp_path):
    work = scratch(tmp_path, "w")
    (work / "hits.json").write_bytes(b"before")
    proc = run_wrapper(work, "sigma", REPO / "samples" / "alerts" / "sigma" / "password_spray.json")
    assert proc.returncode == 70
    assert (work / "hits.json").read_bytes() == b"before"
