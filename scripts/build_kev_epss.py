"""Build a local KEV + EPSS snapshot so lookups are offline and reproducible.

Usage:
    python scripts/build_kev_epss.py data/kev_epss_snapshot.json
    python scripts/build_kev_epss.py data/kev_epss_snapshot.json --kev-file kev.json --no-epss

KEV parsing and the EPSS batching mirror kev-epss-prioritizer's enrich/
modules (same feeds, same "knownRansomwareCampaignUse == Known" rule, same
100-CVE EPSS batches). Standard library only.

EPSS is fetched for every KEV CVE plus any CVE listed in
data/cves_of_interest.txt. A CVE outside that set gets epss = null, which the
lookup reports as unknown rather than as "low risk".
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100
EXTRA_CVES = Path(__file__).resolve().parent.parent / "data" / "cves_of_interest.txt"


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "alert-triage-agent"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def parse_kev(blob: dict) -> dict[str, dict]:
    out = {}
    for v in blob.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").upper()
        if cve:
            out[cve] = {
                "in_kev": True,
                "kev_date_added": v.get("dateAdded"),
                "kev_vendor": v.get("vendorProject"),
                "kev_product": v.get("product"),
                "kev_name": v.get("vulnerabilityName"),
                "kev_known_ransomware": str(v.get("knownRansomwareCampaignUse", "")).strip().lower() == "known",
            }
    if not out:
        raise SystemExit("KEV feed parsed to zero entries; refusing to write an empty snapshot")
    return out


def fetch_epss(cves: list[str]) -> tuple[dict[str, dict], str | None]:
    scores, score_date = {}, None
    for i in range(0, len(cves), BATCH_SIZE):
        batch = ",".join(cves[i:i + BATCH_SIZE])
        for row in fetch_json(f"{EPSS_API}?cve={batch}").get("data", []):
            scores[row["cve"].upper()] = {"epss": float(row["epss"]), "epss_percentile": float(row["percentile"])}
            score_date = row.get("date", score_date)
    return scores, score_date


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--kev-file", type=Path, help="use a downloaded KEV JSON instead of fetching")
    ap.add_argument("--no-epss", action="store_true", help="skip EPSS (scores recorded as null)")
    args = ap.parse_args()

    kev_blob = json.loads(args.kev_file.read_text(encoding="utf-8")) if args.kev_file else fetch_json(KEV_URL)
    cves = parse_kev(kev_blob)

    extra = []
    if EXTRA_CVES.exists():
        extra = [l.strip().upper() for l in EXTRA_CVES.read_text().splitlines() if l.strip() and not l.startswith("#")]
    for cve in extra:
        cves.setdefault(cve, {"in_kev": False})

    epss_date = None
    if not args.no_epss:
        scores, epss_date = fetch_epss(sorted(cves))
        for cve, s in scores.items():
            cves.setdefault(cve, {"in_kev": False}).update(s)
    for rec in cves.values():
        rec.setdefault("epss", None)
        rec.setdefault("epss_percentile", None)

    snapshot = {
        "meta": {
            "kev_catalog_version": kev_blob.get("catalogVersion"),
            "kev_count": kev_blob.get("count"),
            "epss_date": epss_date,  # null means EPSS was not fetched
            "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "cves": dict(sorted(cves.items())),
    }
    args.out.write_text(json.dumps(snapshot, indent=1) + "\n", encoding="utf-8")
    print(f"KEV {snapshot['meta']['kev_catalog_version']}: {len(cves)} CVEs, EPSS date {epss_date} -> {args.out}")


if __name__ == "__main__":
    main()
