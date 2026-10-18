"""EvidenceLog: every tool result from one triage run, keyed by evidence ID.

One log per triage run. Enrichment fills it first; later stages (agent loop,
output validation) use the same log, so "evidence from this run" is ids().
A citation to an ID that is not in the log did not come from this run.
"""

from __future__ import annotations

import json
from typing import Any

from .schemas import ToolResult
from .tools import registry
from .tools.registry import Tool


class EvidenceCollisionError(RuntimeError):
    """Two different lookups produced the same evidence ID."""


class EvidenceLog:
    def __init__(self, tools: dict[str, Tool]) -> None:
        self._tools = tools
        # dicts keep insertion order, so values() is call order.
        self._results: dict[str, ToolResult] = {}  # evidence ID -> result
        self._ids_by_call: dict[tuple[str, str], str] = {}  # call key -> evidence ID
        self._calls_by_id: dict[str, tuple[str, str]] = {}  # evidence ID -> call key

    def call(self, name: str, args: dict[str, Any]) -> ToolResult:
        """Run a tool through the gateway and record the result.

        De-duplication is on the exact call: the tool name plus the arguments
        serialized exactly as registry.evidence_id() serializes them. A
        repeated call returns the recorded result instead of running the tool
        again. It is not on the evidence ID, because a crafted argument (an
        alert's host comes from event data) could be brute-forced to share an
        ID with a real lookup and then be served that lookup's result.

        If a new result's evidence ID is already recorded for a different
        call, EvidenceCollisionError is raised (fail closed): a citation must
        identify exactly one lookup, so no result is returned or overwritten.
        """
        args_for_id = args if isinstance(args, dict) else {"_raw": str(args)}
        call_key = (name, json.dumps(args_for_id, sort_keys=True, default=str))
        if call_key in self._ids_by_call:
            return self._results[self._ids_by_call[call_key]]
        result = registry.run_tool(self._tools, name, args)
        eid = result.evidence_id
        if eid in self._calls_by_id:
            # The message names no argument values: they may be attacker-controlled.
            raise EvidenceCollisionError("evidence ID already recorded for a different call")
        self._results[eid] = result
        self._ids_by_call[call_key] = eid
        self._calls_by_id[eid] = call_key
        return result

    @property
    def results(self) -> list[ToolResult]:
        """A copy of the recorded results, in call order."""
        return list(self._results.values())

    def ids(self) -> set[str]:
        return set(self._results)

    def get(self, evidence_id: str) -> ToolResult | None:
        return self._results.get(evidence_id)
