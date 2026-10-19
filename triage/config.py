"""Settings from environment variables. One place to look for every knob."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _path(name: str, default: Path) -> Path:
    return Path(os.environ.get(name, str(default)))


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: _path("TRIAGE_DATA_DIR", REPO_ROOT / "data"))
    runbook_dir: Path = field(
        default_factory=lambda: _path("TRIAGE_RUNBOOK_DIR", REPO_ROOT / "vendor" / "sigma-detection-pack" / "runbooks")
    )
    # "minilm" = sentence-transformers all-MiniLM-L6-v2 (real retrieval)
    # "hashing" = offline bag-of-words hashing (tests/CI, no model download)
    embedder: str = field(default_factory=lambda: os.environ.get("TRIAGE_EMBEDDER", "minilm"))
    # "heuristic" = the rule-based baseline; "ollama" = a local model over HTTP
    backend: str = field(default_factory=lambda: os.environ.get("TRIAGE_BACKEND", "heuristic"))
    ollama_host: str = field(default_factory=lambda: os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    # No default model: the evaluation host chooses it.
    ollama_model: str = field(default_factory=lambda: os.environ.get("OLLAMA_MODEL", ""))
    # "" = not sent (the model's own default), "true" or "false"
    ollama_think: str = field(default_factory=lambda: os.environ.get("OLLAMA_THINK", ""))


def get_settings() -> Settings:
    return Settings()
