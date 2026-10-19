"""Model backends: one chat() interface; the agent loop does everything else."""

from ..config import Settings, get_settings
from .base import Backend, BackendError, ChatReply, ChatRequest, ToolCall, serialize_request
from .heuristic import HeuristicBackend
from .ollama import OllamaBackend

_THINK = {"": None, "true": True, "false": False}


def make_backend(settings: Settings | None = None) -> Backend:
    """The backend the settings name; a bad setting fails here, before any alert."""
    settings = settings or get_settings()
    if settings.backend == "heuristic":
        return HeuristicBackend()
    if settings.backend == "ollama":
        if settings.ollama_think not in _THINK:
            raise ValueError("OLLAMA_THINK: must be empty, 'true' or 'false'")
        return OllamaBackend(settings.ollama_host, settings.ollama_model,
                             think=_THINK[settings.ollama_think])
    raise ValueError("TRIAGE_BACKEND: must be 'heuristic' or 'ollama'")


__all__ = ["Backend", "BackendError", "ChatReply", "ChatRequest", "ToolCall",
           "HeuristicBackend", "OllamaBackend", "make_backend", "serialize_request"]
