"""Deterministic enrichment: every lookup an alert's trusted fields justify, run
by code before any model sees the alert.

Lookup arguments come only from validated fields: technique IDs from the
rule's ATT&CK mapping (alert.attack_tags()), the host (which passed the
hostname allow-list at ingestion) and CVEs from the scanner field. Event data,
the rule title and the user are attacker-influenced and never become lookup
arguments, so alert text cannot choose what is looked up.

Anything that could not be determined is recorded as a Gap with a fixed kind
and reason. A failed lookup marks the result "degraded"; "not found" is a
finding and leaves it "complete". Enrichment decides no severity and adds no
free text.

Exceptions raised by this module's own code are not caught: an unexpected
error must propagate rather than return a partial result marked complete.
Tool failures are already converted to error results by the gateway.
"""

from __future__ import annotations

from .config import Settings, get_settings
from .evidence import EvidenceLog
from .schemas import Alert, Enrichment, Gap, GapKind, TechniqueResolution, ToolResult
from .tools.attack import replacement_for

MAX_TECHNIQUES = 5
MAX_CVES = 5
MAX_RUNBOOK_TECHNIQUES = 3
MAX_REPLACEMENT_HOPS = 3
RUNBOOK_TOP_K = 3

_GAP_REASON = {"not_found": "not_found", "error": "lookup_failed", "invalid_input": "invalid_input"}


def _gap(kind: GapKind, result: ToolResult) -> Gap:
    """Gap for a lookup whose status is not ok, citing that lookup."""
    return Gap(kind=kind, reason=_GAP_REASON[result.status], evidence_id=result.evidence_id)


def enrich(alert: Alert, log: EvidenceLog, settings: Settings | None = None) -> Enrichment:
    s = settings or get_settings()
    attack_path = s.data_dir / "attack_techniques.json"
    gaps: list[Gap] = []
    techniques: list[str] = []
    names: dict[str, str] = {}  # technique ID -> name from its ok attack_lookup result
    resolutions: list[TechniqueResolution] = []

    # 1. Techniques, from rule metadata only.
    tags = list(dict.fromkeys(alert.attack_tags()))
    if not tags:
        gaps.append(Gap(kind="technique", reason="not_on_alert"))
    for tid in tags[:MAX_TECHNIQUES]:
        result = log.call("attack_lookup", {"technique_id": tid})
        chain = [result]
        resolved_id = tid
        seen = {tid}
        # A revoked or deprecated ID: follow what ATT&CK replaced it with, since
        # a replacement can itself be retired (T1073 -> T1574.002 -> T1574.001).
        # Every lookup in the chain is kept as evidence. The chain stops at a
        # repeated ID or after MAX_REPLACEMENT_HOPS lookups, so bad snapshot
        # data cannot loop or fan out.
        while (result.status == "not_found" and len(chain) <= MAX_REPLACEMENT_HOPS
               and (replacement := replacement_for(attack_path, resolved_id))
               and replacement not in seen):
            seen.add(replacement)
            resolved_id = replacement
            result = log.call("attack_lookup", {"technique_id": resolved_id})
            chain.append(result)
        current: tuple[str, ToolResult] | None = None
        if result.status == "ok":
            current = (resolved_id, result)
            if len(chain) > 1:
                resolutions.append(TechniqueResolution(
                    requested=tid, resolved=resolved_id,
                    evidence_ids=[r.evidence_id for r in chain]))
        else:
            # Includes a cycle or an exhausted hop budget: the last lookup was
            # not_found, so the gap is not_found and cites that lookup.
            gaps.append(_gap("technique", result))
        # Two tags can resolve to the same current ID; keep it once.
        if current is not None and current[0] not in names:
            techniques.append(current[0])
            names[current[0]] = current[1].data["name"]
    if len(tags) > MAX_TECHNIQUES:
        gaps.append(Gap(kind="technique", reason="over_cap"))

    # 2. Asset. not_found means the host is not in the inventory: a finding, not a failure.
    if alert.host is None:
        gaps.append(Gap(kind="asset", reason="not_on_alert"))
    else:
        result = log.call("asset_context", {"host": alert.host})
        if result.status != "ok":
            gaps.append(_gap("asset", result))

    # 3. Vulnerabilities. Most alerts carry no CVE; that is not missing information.
    for cve in alert.cves[:MAX_CVES]:
        result = log.call("kev_epss_lookup", {"cve": cve})
        if result.status != "ok":
            gaps.append(_gap("vulnerability", result))
    if len(alert.cves) > MAX_CVES:
        gaps.append(Gap(kind="vulnerability", reason="over_cap"))

    # 4. Runbook. The query is built from ATT&CK lookup results (ID and name),
    # never from alert text: attacker-worded alerts must not choose which
    # runbook guidance is shown.
    runbook_query = None
    if not techniques:
        gaps.append(Gap(kind="runbook", reason="not_on_alert"))
    else:
        runbook_query = " ".join(f"{tid} {names[tid]}" for tid in techniques[:MAX_RUNBOOK_TECHNIQUES])
        result = log.call("runbook_search", {"query": runbook_query, "top_k": RUNBOOK_TOP_K})
        if result.status != "ok":
            gaps.append(_gap("runbook", result))

    degraded = any(g.reason in ("lookup_failed", "invalid_input") for g in gaps)
    return Enrichment(
        alert_id=alert.alert_id,
        status="degraded" if degraded else "complete",
        techniques=techniques,
        resolutions=resolutions,
        runbook_query=runbook_query,
        evidence=log.results,
        gaps=gaps,
    )
