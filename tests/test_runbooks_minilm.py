"""Real-embedding retrieval checks. Needs `pip install -e .[embeddings]` and a one-time
model download, so they're skipped by default. Run with: pytest -m slow"""

import pytest

from triage.config import Settings
from triage.tools import build_tools, run_tool

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def minilm_tools():
    pytest.importorskip("sentence_transformers")
    return build_tools(Settings(embedder="minilm"))


@pytest.mark.parametrize("query,expected", [
    # Paraphrases with little word overlap: this is what the hashing embedder can't do.
    ("someone killed the antivirus process", "edr_agent_tampering.md"),
    ("many accounts got wrong-password attempts from one address", "password_spray.md"),
    ("user granted a third-party app access to their mailbox", "new_oauth_app_authorized.md"),
])
def test_semantic_match(minilm_tools, query, expected):
    r = run_tool(minilm_tools, "runbook_search", {"query": query})
    assert r.status == "ok" and r.data["hits"][0]["runbook"] == expected
