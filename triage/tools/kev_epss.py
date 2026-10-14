"""kev_epss_lookup: CISA KEV membership and FIRST EPSS score for a CVE, from the local snapshot."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..schemas import CVE_PATTERN

DESCRIPTION = (
    "Check whether a CVE is in the CISA Known Exploited Vulnerabilities catalog and get its "
    "EPSS exploitation-probability score. EPSS may be unknown."
)


class KevEpssArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve: str = Field(pattern=CVE_PATTERN, description="CVE ID like CVE-2021-44228")


@lru_cache(maxsize=4)
def load_snapshot(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not data.get("cves"):
        raise RuntimeError(f"KEV/EPSS snapshot at {path} is empty")
    return data


def make_kev_epss_lookup(path: Path):
    def kev_epss_lookup(args: KevEpssArgs) -> dict:
        snap = load_snapshot(path)
        meta = snap["meta"]
        rec = snap["cves"].get(args.cve.upper())
        # The KEV catalog is a complete list, so absence from it is a real answer ("not in KEV").
        # EPSS is only fetched for a subset, so absence there is "unknown", not "low".
        out = {
            "cve": args.cve.upper(),
            "in_kev": bool(rec and rec.get("in_kev")),
            "kev_catalog_version": meta.get("kev_catalog_version"),
            "epss": rec.get("epss") if rec else None,
            "epss_percentile": rec.get("epss_percentile") if rec else None,
            "epss_date": meta.get("epss_date"),
        }
        if rec and rec.get("in_kev"):
            out.update({k: rec[k] for k in ("kev_date_added", "kev_vendor", "kev_product", "kev_name", "kev_known_ransomware")})
        out["unknown_fields"] = [k for k in ("epss", "epss_percentile") if out[k] is None]
        return out

    return kev_epss_lookup
