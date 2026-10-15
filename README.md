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

## Run it

Needs Python 3.11+ on Linux, macOS or Windows. Nothing here depends on a
particular editor or AI tool.

```bash
git clone https://github.com/rdx0120/alert-triage-agent.git
cd alert-triage-agent
python -m venv .venv
source .venv/bin/activate            # Windows Git Bash: source .venv/Scripts/activate
pip install -e ".[dev]"              # add ,embeddings for real retrieval
pytest                               # fast suite, offline (hashing embedder)
pytest -m slow                       # real MiniLM retrieval; downloads ~90 MB once
```

On Linux without an NVIDIA GPU, install the CPU-only PyTorch build before the
`embeddings` extra; otherwise pip pulls several GB of CUDA libraries you won't use:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[dev,embeddings]"
```

Settings come from environment variables; `.env.example` lists them.

Fill in EPSS scores (the committed snapshot has KEV only):

```bash
python scripts/build_kev_epss.py data/kev_epss_snapshot.json
```

## Where it runs

| Task | Environment |
|---|---|
| Development, unit tests, retrieval tests, Docker builds | Cloud development VM (any Linux box works) |
| Ollama integration, final eval, latency numbers | Ubuntu VM in a home lab, next to the Ollama server |
| CI | GitHub Actions |

The model server is never exposed to the internet: eval runs from a clone of
this repo on the same private network. See `docs/DECISIONS.md` (D9).

## Notes and decisions

Full reasoning for each choice is in [`docs/DECISIONS.md`](docs/DECISIONS.md).

- **Two embedders.** `minilm` (sentence-transformers all-MiniLM-L6-v2) is the
  real one. `hashing` is a word-overlap stand-in so tests and CI run offline
  and deterministically; it is not used for triage. The MiniLM score
  threshold (0.30) is a starting value to calibrate on the eval set.
- **Snapshots, not live APIs.** Lookups read local files built by `scripts/`,
  so eval runs are reproducible and triage never makes network calls.
- **Vendored Sigma content.** See `vendor/sigma-detection-pack/SOURCE.md`.
  `tests/test_vendor_rules.py` checks rule tags and runbook ATT&CK headers
  against current ATT&CK, since runbook text is returned to the model.

## Roadmap

- **Weekend 1 (rest):** sample alerts, deterministic pre-enrichment, backend
  interface (offline heuristic backend + Ollama backend; Claude API later),
  agent loop with step and tool-call caps, JSONL audit log.
- **Weekend 2:** spotlighting of alert fields, injection tripwire, severity
  policy floors, evidence-ID and ATT&CK output validation, fail-closed
  statuses, FastAPI `POST /triage`, Docker, GitHub Actions CI with the
  secure-pipeline gate.
- **Weekend 3:** labeled eval set and scoring script, eval run against Ollama
  on the lab VM, threat model, results here.
