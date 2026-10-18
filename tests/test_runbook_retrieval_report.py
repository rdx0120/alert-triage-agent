"""The retrieval report runs over every sample and prints its totals. Scores are
measured, not asserted."""

import os
import subprocess
import sys

from triage.config import REPO_ROOT


def test_report_runs_with_hashing_embedder():
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "runbook_retrieval_report.py"), "--embedder", "hashing"],
        capture_output=True, text=True, cwd=REPO_ROOT, check=False,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
    )
    assert proc.returncode == 0, proc.stderr
    assert "coverage (samples with a runbook query): 9/10" in proc.stdout
    assert any(line.startswith("embedder: ") for line in proc.stdout.splitlines())
