"""The tool allow-list and the single function that runs a tool.

Every tool call goes through run_tool(), which:
  1. rejects any tool name not in TOOLS (allow-list),
  2. validates arguments against the tool's Pydantic model,
  3. catches exceptions and turns them into status "error" (fail closed),
  4. stamps a deterministic evidence ID so the summary can cite it.

The model never calls a Python function directly; it can only ask for one
of these names with JSON arguments.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from ..schemas import ToolResult


class NotFound(Exception):
    """Raised by a tool when the lookup worked but there is no answer."""


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    args_model: type[BaseModel]
    func: Callable[[BaseModel], dict[str, Any]]

    def json_schema(self) -> dict[str, Any]:
        """The schema handed to the LLM's tool-calling API."""
        return {"name": self.name, "description": self.description, "input_schema": self.args_model.model_json_schema()}


def evidence_id(tool: str, args: dict[str, Any]) -> str:
    """Same tool + same args -> same ID, so citations are reproducible across runs."""
    # Long enough that matching an existing ID by brute force is impractical.
    digest = hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()[:16]
    return f"{tool}:{digest}"


def run_tool(tools: dict[str, Tool], name: str, raw_args: dict[str, Any]) -> ToolResult:
    args_for_id = raw_args if isinstance(raw_args, dict) else {"_raw": str(raw_args)}
    eid = evidence_id(name, args_for_id)

    def result(status: str, data: dict | None = None, error: str | None = None) -> ToolResult:
        return ToolResult(evidence_id=eid, tool=name, args=args_for_id, status=status, data=data, error=error)

    tool = tools.get(name)
    if tool is None:
        return result("error", error=f"tool '{name}' is not on the allow-list")

    try:
        args = tool.args_model.model_validate(raw_args)
    except ValidationError as e:
        # Keep the message short and free of the raw (untrusted) input.
        fields = ", ".join(".".join(map(str, err["loc"])) or "args" for err in e.errors())
        return result("invalid_input", error=f"invalid arguments: {fields}")

    try:
        data = tool.func(args)
    except NotFound as e:
        return result("not_found", error=str(e) or "no matching record")
    except Exception as e:  # noqa: BLE001 - any tool failure is reported, never swallowed
        return result("error", error=f"{type(e).__name__}: {e}")

    if not data:
        return result("not_found", error="tool returned no data")
    return result("ok", data=data)
