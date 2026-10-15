# alert-triage-agent — working rules

Portfolio project (P8): a read-only LLM agent that triages security alerts into a
structured summary, with guardrails enforced in code. Owner: RoHaN. Lab work only;
never describe it as deployed at an employer.

## Hard rules
1. **Synthetic or public data only.** No employer data, PHI, real hostnames, IPs or logs.
2. **Honest numbers only.** Never invent, estimate or round up metrics. README results
   come only from eval runs that were actually executed and whose raw output is committed.
3. **The owner must be able to explain every line in an interview.** Prefer plain,
   readable Python. No LangGraph, CrewAI, LangChain or `instructor`. Ask before adding
   any new dependency.
4. **Read-only agent.** No tool may write, delete, execute or make network calls at
   triage time. Containment suggestions always carry `requires_human_approval: true`.
5. **Small scope.** If something threatens the 2–3 weekend timeline, stop and propose
   moving it to "Future work" instead of building it.
6. **The project must not depend on Claude Code.** Anyone must be able to clone it and
   run it with the README alone. No required `.claude/` hooks, no instructions that only
   make sense inside a Claude session.

## How we work
- **Development happens in Claude Code cloud sessions** (claude.ai/code) on
  `rdx0120/alert-triage-agent`. Work on a branch, open a pull request, and let the owner
  review and merge. Never push to `main` directly.
- **One milestone step per PR.** Run `pytest` before opening the PR and paste the
  result into the PR description.
- **Keep the owner in the loop.** Before building anything with a real design choice,
  explain the options and trade-offs in plain language and wait for a decision. After
  building, add or update an entry in `docs/DECISIONS.md` (what, why, trade-off, and a
  one-sentence interview answer). Explain security controls in terms of the threat they
  stop.
- Explain non-obvious code in short comments aimed at a security engineer, not an ML expert.
- Every guardrail gets a test. Every fail-closed path gets a test.
- Do not edit `vendor/sigma-detection-pack/` by hand. To update it, re-copy from
  github.com/rdx0120/sigma-detection-pack and update the commit hash in its `SOURCE.md`.
- Don't commit secrets, `.env`, `logs/` or model files.

## Where things run
| Task | Where | Notes |
|---|---|---|
| Code, unit tests, hashing-embedder tests | Cloud session | Default network access is enough |
| MiniLM retrieval tests (`pytest -m slow`) | Cloud session | Needs Hugging Face domains on the environment's allowlist |
| EPSS snapshot (`scripts/build_kev_epss.py`) | Cloud session | Needs `api.first.org` on the allowlist |
| Docker build / `docker compose up` | Cloud session | Docker is pre-installed in the cloud VM |
| Agent loop development | Cloud session | Uses the offline `heuristic` backend and recorded model responses in tests |
| Real Ollama integration, final eval, latency | Owner's Ubuntu VM (Proxmox, Ollama installed) | Cloud sessions can't reach it. Clone the repo on the VM and run there. Never expose Ollama's port to the internet |
| CI | GitHub Actions | Independent of Claude Code |

If a task can't run in the cloud, say why and propose the simplest alternative before
asking the owner to install anything. Prefer the Ubuntu VM over the owner's Windows PC.

## Decisions already made (details in docs/DECISIONS.md)
- **LLM backend:** Ollama first, Claude API later, behind one interface. Plus an offline
  `heuristic` backend (rule tag → technique, rule level → severity) for CI and as the
  eval baseline the LLM must beat.
- **Embeddings:** all-MiniLM-L6-v2 for real runs; `hashing` embedder for tests/CI.
  FAISS `IndexFlatIP`. MiniLM score cutoff (0.30) is uncalibrated.
- **Data:** ATT&CK pinned to v20.0; KEV snapshot (EPSS filled by
  `scripts/build_kev_epss.py`). Lookups read local snapshots only.
- **Tools** go through `triage/tools/registry.run_tool()`: allow-list, Pydantic args,
  fail closed on error or empty result, deterministic evidence IDs.
- **Theme:** "silence is not success" — an empty or failed lookup is reported as
  missing data, never filled in by the model.

## Commands
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"           # add ,embeddings for real retrieval
pytest                            # fast suite, offline
pytest -m slow                    # real MiniLM retrieval
```

## Status and next steps
Done: schemas, ATT&CK/KEV data, four read-only tools, 33 tests.

Next (weekend 1, in order):
1. Sample alerts (from the vendored Sigma fixtures) + `from_wazuh()` normalizer.
2. Deterministic pre-enrichment: rule tags → attack_lookup, host → asset_context,
   CVEs → kev_epss_lookup, before the LLM sees anything.
3. Backend interface + heuristic backend + Ollama backend (`OLLAMA_HOST` from env).
4. Agent loop: step cap (6), tool-call cap (8), JSONL audit log using OpenTelemetry
   GenAI field names (`gen_ai.operation.name`, `gen_ai.tool.name`, ...).

Weekend 2: spotlighting/datamarking of alert fields, injection tripwire, severity
policy floors (final = max(LLM, rule floor)), evidence-ID and ATT&CK-ID output
validation, `insufficient_data` / `budget_exceeded` statuses, FastAPI `POST /triage`,
Docker, GitHub Actions CI with the secure-pipeline gate.

Weekend 3: ~30 labeled eval alerts (pinned before first run: ≥6 injection twins,
≥5 missing-data), scoring script, eval run on the Ubuntu VM against Ollama, threat
model (OWASP LLM 2025, OWASP Agentic 2026, MITRE ATLAS, STRIDE), README results.
