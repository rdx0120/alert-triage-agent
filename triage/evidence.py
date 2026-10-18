"""EvidenceLog: every tool result from one triage run, keyed by evidence ID.

One log per triage run. Enrichment fills it first; later stages (agent loop,
output validation) use the same log, so "evidence from this run" is ids().
A citation to an ID that is not in the log did not come from this run.
"""

from __future__ import annotations

from typing import Any

from .schemas import ToolResult
from .tools import registry
from .tools.registry import Tool


class EvidenceLog:
    def __init__(self, tools: dict[str, Tool]) -> None:
        self._tools = tools
        # dicts keep insertion order, so values() is call order.
        self._results: dict[str, ToolResult] = {}

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        """Run a tool through the gateway and record the result.

        The same tool and arguments always produce the same evidence ID, so a
        repeated call returns the recorded result instead of running the tool
        again. The key is computed exactly as run_tool() computes it, so it is
        the returned ToolResult's evidence_id.
        """
        args_for_id = args if isinstance(args, dict) else {"_raw": str(args)}
        key = registry.evidence_id(name, args_for_id)
        if key in self._results:
            return self._results[key]
        result = registry.run_tool(self._tools, name, args)
        self._results[key] = result
        return result

    @property
    def results(self) -> list[ToolResult]:
        """A copy of the recorded results, in call order."""
        return list(self._results.values())

    def ids(self) -> set[str]:
        return set(self._results)

    def get(self, evidence_id: str) -> ToolResult | None:
        return self._results.get(evidence_id)
