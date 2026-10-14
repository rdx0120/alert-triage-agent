# alert-triage-agent

A read-only LLM agent that triages security alerts into a structured
investigation summary, with guardrails enforced in code rather than in the
prompt. Lab / portfolio project: all alerts, hosts and inventory are synthetic.

> **Status: weekend 1 in progress.** Schemas, data snapshots and the four
> read-only tools are built and tested. The agent loop, guardrail
> post-validation, FastAPI service and eval are next. No results are claimed yet.

## Design in one paragraph

The agent sees untrusted input (alert fields) and has read access to context
(ATT&CK, KEV/EPSS, an asset inventory, runbooks). It is deliberately **unable
to change state**: no tool writes, deletes, executes or calls the network at
triage time. Every tool call goes through one allow-listed, schema-validated
function that returns a `ToolResult` with a stable evidence ID, and an empty
answer is never reported as success.

## What exists so far

| Piece | File | Notes |
|---|---|---|
| Schemas | `triage/schemas.py` | `Alert` (untrusted input), `ToolResult`, `TriageSummary`. `extra="forbid"` everywhere; `requires_human_approval` can only be `True`. |
| Tool allow-list | `triage/tools/registry.py` | `run_tool()`: allow-list → Pydantic arg validation → call → fail closed on error/empty → evidence ID. |
| `attack_lookup` | `triage/tools/attack.py` | ATT&CK v20.0, 706 techniques. Revoked IDs return `not_found` with the replacement ID. |
| `kev_epss_lookup` | `triage/tools/kev_epss.py` | CISA KEV snapshot (catalog 2026.10.13, 1,741 CVEs). Missing EPSS is reported as unknown, never as low. |
| `asset_context` | `triage/tools/assets.py` | 10-host synthetic inventory. Unknown host → `not_found`. Strict hostname pattern. |
| `runbook_search` | `triage/tools/runbooks.py` | Section-level chunks of the 7 Sigma runbooks (43 chunks), FAISS `IndexFlatIP`, minimum-score cutoff → `not_found` instead of a weak match. |
| Data builders | `scripts/` | Rebuild the ATT&CK and KEV/EPSS snapshots from the public sources. |

## Setup (Windows Git Bash or Linux)

```bash
python -m venv .venv
source .venv/Scripts/activate      # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev,embeddings]"
pytest                              # fast suite, offline (hashing embedder)
pytest -m slow                      # real MiniLM retrieval; downloads ~90 MB once
```

Fill in EPSS scores (the committed snapshot has KEV only):

```bash
python scripts/build_kev_epss.py data/kev_epss_snapshot.json
```

## Notes and decisions

- **Two embedders.** `minilm` (sentence-transformers all-MiniLM-L6-v2) is the
  real one. `hashing` is a word-overlap stand-in so tests and CI run offline
  and deterministically; it is not used for triage. The MiniLM score
  threshold (0.30) is a starting value to calibrate on the eval set.
- **Snapshots, not live APIs.** Lookups read local files built by `scripts/`,
  so eval runs are reproducible and triage never makes network calls.
- **Vendored Sigma content.** See `vendor/sigma-detection-pack/SOURCE.md`.
  `tests/test_vendor_rules.py` checks rule tags against current ATT&CK and
  currently flags one stale tag (T1562.001, revoked and replaced by T1685).

## Roadmap

- Weekend 1 (rest): sample alerts, deterministic pre-enrichment, agent loop
  (Claude backend + offline heuristic backend), JSONL audit log.
- Weekend 2: spotlighting, severity policy floors, evidence-ID and ATT&CK
  output validation, fail-closed statuses, FastAPI, Docker, CI with the
  secure-pipeline gate.
- Weekend 3: labeled eval set and scoring, threat model, results here.
