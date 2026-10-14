"""asset_context: owner, criticality and exposure for a host, from the synthetic inventory."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..schemas import HOST_PATTERN
from .registry import NotFound

DESCRIPTION = (
    "Get business context for a host from the asset inventory: role, owner, criticality, "
    "network exposure and whether it handles sensitive data."
)


class AssetArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Strict pattern: hostnames only. A value like "HOST01; ignore previous instructions"
    # is rejected before it reaches the lookup.
    host: str = Field(pattern=HOST_PATTERN, description="Hostname, e.g. CLINIC-FRONT01")


@lru_cache(maxsize=4)
def load_assets(path: Path) -> dict[str, dict]:
    rows = json.loads(path.read_text(encoding="utf-8"))["assets"]
    if not rows:
        raise RuntimeError(f"asset inventory at {path} is empty")
    return {r["host"].upper(): r for r in rows}


def make_asset_context(path: Path):
    def asset_context(args: AssetArgs) -> dict:
        assets = load_assets(path)
        row = assets.get(args.host.upper())
        if row is None:
            # An unknown host is a finding in itself (unmanaged device?), not a reason to guess.
            raise NotFound(f"host {args.host} is not in the asset inventory")
        return dict(row)

    return asset_context
