"""Shrink the MITRE ATT&CK Enterprise STIX bundle (~50 MB) into a small lookup file.

Usage (pin a release tag so the lookup is reproducible):
    curl -sSfo enterprise-attack.json \
      "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v20.0/enterprise-attack/enterprise-attack.json"
    python scripts/build_attack_subset.py enterprise-attack.json data/attack_techniques.json --release v20.0

Keeps every current technique and sub-technique (so the file doubles as the
allow-list for validating technique IDs the model outputs). Revoked and
deprecated techniques are dropped from the lookup but their IDs are kept
under "retired" (with the replacement ID when ATT&CK records one), so the
agent can tell "old ID" apart from "made-up ID".
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MAX_DESCRIPTION_CHARS = 600


def first_paragraph(text: str) -> str:
    para = (text or "").strip().split("\n\n")[0]
    return para[:MAX_DESCRIPTION_CHARS]


def attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build(bundle: dict, source_sha256: str = "", release: str | None = None) -> dict:
    objects = bundle["objects"]
    patterns = {o["id"]: o for o in objects if o.get("type") == "attack-pattern"}
    # STIX "revoked-by" relationships point an old technique at its replacement.
    replaced_by = {
        o["source_ref"]: attack_id(patterns[o["target_ref"]])
        for o in objects
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by"
        and o["source_ref"] in patterns and o["target_ref"] in patterns
    }

    techniques: dict[str, dict] = {}
    retired: dict[str, str | None] = {}
    for obj in patterns.values():
        tid = attack_id(obj)
        if not tid:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            retired[tid] = replaced_by.get(obj["id"])
            continue
        techniques[tid] = {
            "name": obj["name"],
            "tactics": sorted(p["phase_name"] for p in obj.get("kill_chain_phases", [])),
            "platforms": obj.get("x_mitre_platforms", []),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "description": first_paragraph(obj.get("description", "")),
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        }

    if not techniques:
        # Silence is not success: an empty output file would make every lookup "not_found".
        raise SystemExit("No techniques parsed; is this an ATT&CK STIX bundle?")

    # The bundle itself carries no release number, so record the tag it was
    # downloaded from plus what identifies it regardless: newest timestamp and file hash.
    latest = max(o.get("modified", "") for o in objects)
    return {
        "meta": {
            "source": "mitre/cti enterprise-attack.json",
            "release": release,
            "source_sha256": source_sha256,
            "latest_object_modified": latest,
            "technique_count": len(techniques),
        },
        "techniques": dict(sorted(techniques.items())),
        "retired": {k: v for k, v in sorted(retired.items()) if k not in techniques},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Build data/attack_techniques.json from an ATT&CK STIX bundle")
    ap.add_argument("src", type=Path)
    ap.add_argument("dst", type=Path)
    ap.add_argument("--release", help="the mitre/cti tag the bundle came from, e.g. v20.0")
    a = ap.parse_args()
    src, dst = a.src, a.dst
    raw = src.read_bytes()
    out = build(json.loads(raw), hashlib.sha256(raw).hexdigest(), a.release)
    dst.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"ATT&CK {a.release or '(unpinned)'}: "
          f"{out['meta']['technique_count']} techniques, {len(out['retired'])} retired IDs -> {dst}")


if __name__ == "__main__":
    main()
