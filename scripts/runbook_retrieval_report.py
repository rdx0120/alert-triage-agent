"""Measure runbook retrieval on the sample alerts after deterministic enrichment.

For every sample alert: enrich it with a fresh evidence log, then compare the
runbook_search results with the expected runbook below. This measures; it does
not assert. It exits 0 whatever the scores are, and non-zero only if the
expected table and samples/ disagree, so a sample cannot be skipped silently.

Usage:
    python scripts/runbook_retrieval_report.py --embedder hashing|minilm
"""

from __future__ import annotations

import argparse
import sys

from triage.config import REPO_ROOT, Settings
from triage.enrich import enrich
from triage.evidence import EvidenceLog
from triage.ingest import load_alert
from triage.tools import build_tools
from triage.tools.runbooks import get_index

SAMPLES = REPO_ROOT / "samples" / "alerts"

# Ground truth for this report only. None: no technique, so no query is expected.
EXPECTED: dict[str, str | None] = {
    "sigma/edr_agent_tampering": "edr_agent_tampering.md",
    "sigma/mail_forwarding_rule_created": "mail_forwarding_rule_created.md",
    "sigma/new_oauth_app_authorized": "new_oauth_app_authorized.md",
    "sigma/password_spray": "password_spray.md",
    "sigma/super_admin_role_granted": "super_admin_role_granted.md",
    "sigma/suspicious_encoded_powershell": "suspicious_encoded_powershell.md",
    "wazuh/edr_tampering": "edr_agent_tampering.md",
    "wazuh/encoded_powershell": "suspicious_encoded_powershell.md",
    "wazuh/unknown_host_powershell": "suspicious_encoded_powershell.md",
    "wazuh/vulnerability_log4shell": None,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--embedder", choices=["hashing", "minilm"], required=True)
    args = parser.parse_args(argv)

    paths = {f"{p.parent.name}/{p.stem}": p for p in sorted(SAMPLES.glob("*/*.json"))}
    missing_expected = sorted(set(paths) - set(EXPECTED))
    missing_samples = sorted(set(EXPECTED) - set(paths))
    if missing_expected or missing_samples:
        for name in missing_expected:
            print(f"error: sample {name} has no expected runbook", file=sys.stderr)
        for name in missing_samples:
            print(f"error: expected sample {name} is not in samples/alerts", file=sys.stderr)
        return 1

    settings = Settings(embedder=args.embedder)
    tools = build_tools(settings)
    total = with_query = top1 = top3 = 0
    # query -> True only if its top-1 result was correct for every sample that produced it
    query_top1: dict[str, bool] = {}

    for name, path in paths.items():
        alert = load_alert(path.read_text(encoding="utf-8"), fmt=path.parent.name)
        enrichment = enrich(alert, EvidenceLog(tools), settings)
        expected = EXPECTED[name]
        query = enrichment.runbook_query
        hits = next((r.data["hits"] for r in enrichment.evidence
                     if r.tool == "runbook_search" and r.status == "ok"), [])
        runbooks = [h["runbook"] for h in hits]
        correct1 = bool(runbooks) and runbooks[0] == expected
        rank = runbooks.index(expected) + 1 if expected in runbooks else None

        total += 1
        if query is not None:
            with_query += 1
            top1 += correct1
            top3 += rank is not None
            query_top1[query] = query_top1.get(query, True) and correct1

        print(f"{name} | query: {query or '(none)'} | top 3: {', '.join(runbooks) or '(none)'} | "
              f"top-1 correct: {'yes' if correct1 else 'no'} | "
              f"expected rank: {rank if rank is not None else 'not in top 3'}")

    print(f"samples: {total}")
    print(f"coverage (samples with a runbook query): {with_query}/{total}")
    print(f"correct top-1: {top1}/{with_query} eligible ({top1}/{total} overall)")
    print(f"correct in top 3: {top3}/{with_query} eligible ({top3}/{total} overall)")
    print(f"distinct queries: {len(query_top1)} (correct top-1: {sum(query_top1.values())}/{len(query_top1)})")
    print(f"embedder: {get_index(settings.runbook_dir, settings.embedder, settings.embedding_model_dir).embedder.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
