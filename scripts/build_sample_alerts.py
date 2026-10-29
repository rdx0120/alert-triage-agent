"""Build synthetic Sigma-match sample alerts from the vendored rules and fixtures.

One sample per rule whose fixture file has at least one true_positive event.
Only true_positive events are used: false_positive fixtures are events the
rule must NOT match, so they are not alerts.

Writing also refreshes the samples' sha256 in provenance.json (DD-028). It
never adds an entry or touches an entry's class or source: what a file is
stays a reviewed, manual declaration.

Usage:
    python scripts/build_sample_alerts.py           # write samples/alerts/sigma/*.json
    python scripts/build_sample_alerts.py --check   # exit 1 if the committed samples differ
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PACK = REPO_ROOT / "vendor" / "sigma-detection-pack"
OUT_DIR = REPO_ROOT / "samples" / "alerts" / "sigma"
PROVENANCE = REPO_ROOT / "provenance.json"


def _synthetic_data():
    """scripts/synthetic_data.py, loaded by path so this works as a script and when imported."""
    spec = importlib.util.spec_from_file_location("synthetic_data", REPO_ROOT / "scripts" / "synthetic_data.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("synthetic_data", module)
    spec.loader.exec_module(module)
    return module


def refresh_provenance(provenance: Path, root: Path, rel_paths: list[str]) -> None:
    """Refresh the sha256 of existing entries for rel_paths; nothing else changes."""
    sd = _synthetic_data()
    doc = json.loads(provenance.read_text(encoding="utf-8"))
    files = {rel: (root / rel).read_bytes() for rel in rel_paths}
    provenance.write_text(sd.render(sd.update_hashes(doc, files)), encoding="utf-8")


def build_sigma_samples(rules_dir: Path, fixtures_dir: Path) -> dict[str, dict]:
    """Return {rule_stem: sigma_match_dict} for every rule with true_positive fixtures."""
    samples = {}
    for rule_path in sorted(rules_dir.glob("*.yml")):
        fixture_path = fixtures_dir / f"{rule_path.stem}.json"
        if not fixture_path.exists():
            continue
        events = json.loads(fixture_path.read_text(encoding="utf-8")).get("true_positive", [])
        if not events:
            continue
        # safe_load only: yaml.load can construct arbitrary Python objects.
        rule = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        sample = {
            "alert_id": "sigma-" + rule_path.stem.replace("_", "-"),
            "rule": {"id": rule["id"], "title": rule["title"], "level": rule["level"], "tags": rule["tags"]},
            "event": events[0],
        }
        if len(events) > 1:
            # A correlation rule fired over several events: keep the first as
            # the representative event and summarize the rest.
            times = [e["event.time"] for e in events]
            fields = {k: None for e in events for k in e}  # ordered union of field names
            distinct = {}
            for field in fields:
                values = {json.dumps(e.get(field), sort_keys=True) for e in events}
                if len(values) > 1:
                    distinct[field] = len(values)
            sample["aggregate"] = {
                "match_count": len(events),
                "first_seen": min(times),
                "last_seen": max(times),
                "distinct": distinct,
            }
        samples[rule_path.stem] = sample
    return samples


def render(sample: dict) -> str:
    return json.dumps(sample, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="report differences instead of writing")
    args = parser.parse_args(argv)

    rules_dir, fixtures_dir = PACK / "rules", PACK / "fixtures"
    samples = build_sigma_samples(rules_dir, fixtures_dir)
    skipped = sorted(p.stem for p in rules_dir.glob("*.yml") if p.stem not in samples)
    for stem in skipped:
        print(f"skipped {stem}: no fixture with true_positive events")

    if args.check:
        expected = {f"{stem}.json": render(s) for stem, s in samples.items()}
        actual = {p.name: p.read_text(encoding="utf-8") for p in OUT_DIR.glob("*.json")}
        diffs = []
        for name in sorted(expected.keys() | actual.keys()):
            if name not in actual:
                diffs.append(f"missing: {name}")
            elif name not in expected:
                diffs.append(f"unexpected: {name}")
            elif actual[name] != expected[name]:
                diffs.append(f"differs: {name}")
        for d in diffs:
            print(d)
        print(f"{len(expected)} samples checked, {len(diffs)} differences")
        return 1 if diffs else 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for stem, sample in samples.items():
        (OUT_DIR / f"{stem}.json").write_text(render(sample), encoding="utf-8")
    written = [(OUT_DIR / f"{stem}.json").relative_to(REPO_ROOT).as_posix() for stem in samples]
    refresh_provenance(PROVENANCE, REPO_ROOT, written)
    print(f"wrote {len(samples)} samples to {OUT_DIR.relative_to(REPO_ROOT)} and refreshed their provenance hashes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
