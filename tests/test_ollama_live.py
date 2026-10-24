"""Live smoke test against a running Ollama server: python -m pytest -m ollama -s.

Checks only that every sample run ends with a recorded stop reason and that the
prompt tokens Ollama reports stay within the byte-based bound (DD-013). No
quality assertions.
"""

import dataclasses
import json
import os
import typing

import pytest

from triage.agent import run_agent
from triage.audit import write_audit_log
from triage.backends import OllamaBackend, make_backend
from triage.config import REPO_ROOT, get_settings
from triage.ingest import load_alert
from triage.schemas import StopReason

pytestmark = [
    pytest.mark.ollama,
    pytest.mark.skipif(not os.environ.get("OLLAMA_MODEL"),
                       reason="needs a running Ollama server; set OLLAMA_MODEL (and OLLAMA_HOST if not local)"),
]

SAMPLES = sorted((REPO_ROOT / "samples" / "alerts").glob("*/*.json"))


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_live_sample(path, tmp_path):
    """A real model run ends with a stop reason, and its prompts never exceed the byte-based token bound."""
    settings = get_settings()
    # Built from OLLAMA_HOST, OLLAMA_MODEL and OLLAMA_THINK, whatever TRIAGE_BACKEND says.
    backend = make_backend(dataclasses.replace(settings, backend="ollama"))
    assert isinstance(backend, OllamaBackend)
    alert = load_alert(path.read_text(encoding="utf-8"), fmt=path.parent.name)
    result = run_agent(alert, backend, settings=settings)
    calls = " ".join(f"{c.phase}:in={c.input_tokens},out={c.output_tokens},bound={c.token_bound}"
                     for c in result.model_calls)
    print(f"\n{path.parent.name}/{path.name} stop={result.stop_reason} "
          f"model_calls={len(result.model_calls)} tool_calls={result.tool_calls} {calls}")
    assert result.stop_reason in typing.get_args(StopReason)
    for call in result.model_calls:
        if call.input_tokens is not None:
            assert call.input_tokens <= call.token_bound
    log = tmp_path / "audit.jsonl"
    count = write_audit_log(result, alert, log)
    records = [json.loads(line) for line in log.read_text(encoding="ascii").splitlines()]
    assert records[0]["event.name"] == "triage.run"
    assert records[0]["triage.stop_reason"] == result.stop_reason
    assert count == len(records) == 1 + len(result.tool_records) + len(result.model_calls)
