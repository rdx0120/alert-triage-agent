"""The one interface every model backend implements.

A backend answers one request. The agent loop (triage/agent.py) owns the
limits, the tool dispatch and the validation of what comes back.

Messages and tool specs use the Ollama /api/chat wire format, so the bytes the
context budget measures are the bytes a backend sends:
  system / user:  {"role": ..., "content": str}
  assistant:      {"role": "assistant", "content": "",
                   "tool_calls": [{"function": {"name": str, "arguments": dict}}]}
  tool result:    {"role": "tool", "tool_name": str, "content": str}
  tool spec:      {"type": "function", "function": {"name", "description", "parameters"}}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..schemas import Alert, Enrichment


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: Any  # as returned by the model; untrusted


@dataclass(frozen=True)
class ChatRequest:
    messages: list[dict]
    tools: list[dict] | None
    response_schema: dict | None
    max_output_tokens: int
    context_tokens: int
    timeout_s: float
    # For the rule-based backend only; never serialized or sent to a model.
    alert: Alert
    enrichment: Enrichment


@dataclass(frozen=True)
class ChatReply:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int | None = None
    output_tokens: int | None = None


class BackendError(Exception):
    """The model could not be reached or replied unusably.

    The loop records only that it happened, never the message: it may carry
    model output or endpoint details.
    """


class Backend(Protocol):
    """A backend must return or raise within request.timeout_s; the loop cannot
    interrupt a backend that ignores it."""

    name: str

    def chat(self, request: ChatRequest) -> ChatReply: ...


def serialize_request(request: ChatRequest) -> bytes:
    """The prompt-bearing bytes of a request, exactly as a backend sends them.

    The Ollama adapter must send this serialization; the context budget is
    measured on it.
    """
    return json.dumps(
        {"messages": request.messages, "tools": request.tools, "format": request.response_schema},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
