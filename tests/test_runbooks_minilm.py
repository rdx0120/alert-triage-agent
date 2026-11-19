"""Real-embedding retrieval checks, with the real libraries and no network (DD-027).

They need `pip install -e .[embeddings]` and the model acquired once with
scripts/fetch_embedding_model.py, so they are skipped by default. Run with:
pytest -m slow. A skip is not a pass: the N1 compatibility gate requires
these tests to run.

Nothing here imports sentence-transformers or huggingface_hub before the
loader does, because the loader must set offline mode before the first
import.
"""

import importlib.util
import json
import socket
import subprocess
import sys

import pytest

from triage.config import REPO_ROOT, Settings
from triage.embedding_model import ModelUnavailable, load_manifest, verify_model_dir
from triage.tools import build_tools, run_tool

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def model_dir():
    if importlib.util.find_spec("sentence_transformers") is None:
        pytest.skip("sentence-transformers is not installed (install the embeddings extra)")
    directory = Settings().embedding_model_dir
    try:
        verify_model_dir(directory, load_manifest())
    except ModelUnavailable:
        pytest.skip("the embedding model has not been acquired: run scripts/fetch_embedding_model.py")
    return directory


@pytest.mark.parametrize("query,expected", [
    # Paraphrases with little word overlap: this is what the hashing embedder can't do.
    ("someone killed the antivirus process", "edr_agent_tampering.md"),
    ("many accounts got wrong-password attempts from one address", "password_spray.md"),
    ("user granted a third-party app access to their mailbox", "new_oauth_app_authorized.md"),
])
def test_semantic_match(model_dir, no_network, query, expected):
    """The real model, loaded offline, misses a paraphrase or tries to open a connection."""
    tools = build_tools(Settings(embedder="minilm", embedding_model_dir=model_dir))
    r = run_tool(tools, "runbook_search", {"query": query})
    assert r.status == "ok" and r.data["hits"][0]["runbook"] == expected
    assert no_network.attempts == []


def test_real_library_runs_in_offline_mode(model_dir, no_network):
    """After a real load, huggingface_hub is not in offline mode, or a connection was attempted."""
    tools = build_tools(Settings(embedder="minilm", embedding_model_dir=model_dir))
    assert run_tool(tools, "runbook_search", {"query": "encoded powershell"}).status in ("ok", "not_found")
    assert sys.modules["huggingface_hub.constants"].HF_HUB_OFFLINE is True
    assert no_network.attempts == []


def test_network_guard_works_in_this_environment(no_network):
    """The guard lets a connection through here, so the empty records above would prove nothing."""
    with pytest.raises(OSError):
        socket.create_connection(("192.0.2.1", 9), timeout=1)
    assert no_network.attempts == ["create_connection"]


def test_a_minilm_run_writes_nothing_to_stderr(model_dir, tmp_path):
    """A clean MiniLM run writes anything to stderr, such as a weight-loading progress bar.

    The environment is built from nothing, as the evaluation harness builds it, so
    nothing the caller exports reaches the run: only the loader can turn the bars off.
    """
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONHASHSEED": "0",
           "TRIAGE_BACKEND": "heuristic", "TRIAGE_EMBEDDER": "minilm",
           "TRIAGE_EMBEDDING_MODEL_DIR": str(model_dir), "OLLAMA_HOST": "http://127.0.0.1:11434"}
    alert = REPO_ROOT / "samples" / "alerts" / "wazuh" / "encoded_powershell.json"
    done = subprocess.run([sys.executable, "-s", "-B", "-P", "-m", "triage", "--format", "wazuh", str(alert),
                           "--audit-log", str(tmp_path / "audit.jsonl")],
                          env=env, cwd=tmp_path, capture_output=True, timeout=600)
    assert done.returncode == 0
    assert done.stderr == b""
    assert json.loads(done.stdout)["status"] == "triaged"
    audit = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    searches = [r for r in audit if r.get("gen_ai.tool.name") == "runbook_search"]
    assert [r["triage.tool.status"] for r in searches] == ["ok"]   # the model was loaded and searched
