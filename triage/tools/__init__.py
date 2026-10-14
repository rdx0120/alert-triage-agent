"""Builds the allow-list. These four read-only tools are the agent's entire reach.

No tool writes, deletes, executes, or makes a network call at triage time:
all data comes from local snapshots built ahead of time by scripts/.
"""

from __future__ import annotations

from ..config import Settings, get_settings
from . import assets, attack, kev_epss, runbooks
from .registry import Tool, run_tool

__all__ = ["build_tools", "run_tool", "Tool"]


def build_tools(settings: Settings | None = None) -> dict[str, Tool]:
    s = settings or get_settings()
    tools = [
        Tool("attack_lookup", attack.DESCRIPTION, attack.AttackArgs,
             attack.make_attack_lookup(s.data_dir / "attack_techniques.json")),
        Tool("kev_epss_lookup", kev_epss.DESCRIPTION, kev_epss.KevEpssArgs,
             kev_epss.make_kev_epss_lookup(s.data_dir / "kev_epss_snapshot.json")),
        Tool("asset_context", assets.DESCRIPTION, assets.AssetArgs,
             assets.make_asset_context(s.data_dir / "assets.json")),
        Tool("runbook_search", runbooks.DESCRIPTION, runbooks.RunbookArgs,
             runbooks.make_runbook_search(s.runbook_dir, s.embedder)),
    ]
    return {t.name: t for t in tools}
