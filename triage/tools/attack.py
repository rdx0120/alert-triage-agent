"""attack_lookup: MITRE ATT&CK technique details from the local snapshot."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..schemas import TECHNIQUE_ID_PATTERN
from .registry import NotFound

DESCRIPTION = (
    "Look up a MITRE ATT&CK Enterprise technique or sub-technique by ID (e.g. T1059.001). "
    "Returns name, tactics, platforms and a short description."
)


class AttackArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique_id: str = Field(pattern=TECHNIQUE_ID_PATTERN, description="ATT&CK ID like T1059 or T1059.001")


@lru_cache(maxsize=4)
def load_attack(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not data.get("techniques"):
        raise RuntimeError(f"ATT&CK data at {path} has no techniques")
    return data


def make_attack_lookup(path: Path):
    def attack_lookup(args: AttackArgs) -> dict:
        data = load_attack(path)
        tid = args.technique_id.upper()
        if tid in data["techniques"]:
            return {"technique_id": tid, **data["techniques"][tid]}
        if tid in data["retired"]:
            replacement = data["retired"][tid]
            hint = f"; ATT&CK replaced it with {replacement}" if replacement else ""
            raise NotFound(f"{tid} is revoked or deprecated in current ATT&CK{hint}")
        raise NotFound(f"{tid} is not an ATT&CK Enterprise technique")

    return attack_lookup


def is_valid_technique(path: Path, technique_id: str) -> bool:
    """Allow-list check for technique IDs the model puts in its output."""
    return technique_id.upper() in load_attack(path)["techniques"]


def replacement_for(path: Path, technique_id: str) -> str | None:
    """Replacement ID recorded for a revoked/deprecated technique, else None."""
    return load_attack(path)["retired"].get(technique_id.upper())
