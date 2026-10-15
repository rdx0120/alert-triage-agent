# alert-triage-agent — working rules

Portfolio project (P8): a read-only LLM agent that triages security alerts into a
structured summary, with guardrails enforced in code. Owner: RoHaN. Lab work only;
never describe it as deployed at an employer.

## Hard rules
1. **Synthetic or public data only.** No employer data, PHI, real hostnames, IPs or logs.
2. **Honest numbers only.** Never invent, estimate or round up metrics. README results
   come only from `eval/` runs that were actually executed and committed.
3. **The owner must be able to explain every line in an interview.** Prefer plain,
   readable Python. No LangGraph, CrewAI, LangChain or `instructor`. Ask before adding
   any new dependency.
4. **Read-only agent.** No tool may write, delete, execute or make network calls at
   triage time. Containment suggestions always carry `requires_human_approval: true`.
5. **Small scope.** If something threatens the 2–3 weekend timeline, stop and propose
   moving it to "Future work" instead of building it.

## How to work
- Work in small steps: one module or feature at a time, then run `pytest`, then stop
  and summarize what changed and why before moving on.
- Explain non-obvious code in short comments aimed at a security engineer, not an ML expert.
- Every guardrail gets a test. Every fail-closed path gets a test.
- Do not edit `vendor/sigma-detection-pack/` by hand. To update it, re-copy from
  github.com/rdx0120/sigma-detection-pack and update the commit hash in its `SOURCE.md`.
- Don't commit secrets, `.env`, `logs/` or model files.

## Decisions already made
- **LLM backend:** Ollama first (local, free). Claude API is a later, optional backend
  behind the same interface. Also an offline `heuristic` backend (rule tag → technique,
  rule level → severity) for CI and as the eval baseline the LLM must beat.
- **Embeddings:** sentence-transformers all-MiniLM-L6-v2 for real runs; `hashing`
  embedder for tests/CI. FAISS `IndexFlatIP`. MiniLM score cutoff (0.30) is uncalibrated.
- **Data:** ATT&CK pinned to v20.0; KEV snapshot (EPSS filled by
  `scripts/build_kev_epss.py`). Lookups read local snapshots only.
- **Tools** go through `triage/tools/registry.run_tool()`: allow-list, Pydantic args,
  fail closed on error or empty result, deterministic evidence IDs.
- **Theme:** "silence is not success" — an empty or failed lookup is reported as
  missing data, never filled in by the model.

## Commands
```bash
pytest              # fast suite, offline
pytest -m slow      # real MiniLM retrieval (needs the embeddings extra)
```

## Status and next steps
Done: schemas, ATT&CK/KEV data, four read-only tools, 33 tests.

Next (weekend 1, in order):
1. Sample alerts (from the vendored Sigma fixtures) + `from_wazuh()` normalizer.
2. Deterministic pre-enrichment: rule tags → attack_lookup, host → asset_context,
   CVEs → kev_epss_lookup, before the LLM sees anything.
3. Backend interface + Ollama backend + heuristic backend.
4. Agent loop: step cap (6), tool-call cap (8), JSONL audit log using OpenTelemetry
   GenAI field names (`gen_ai.operation.name`, `gen_ai.tool.name`, ...).

Weekend 2: spotlighting/datamarking of alert fields, injection tripwire, severity
policy floors (final = max(LLM, rule floor)), evidence-ID and ATT&CK-ID output
validation, `insufficient_data` / `budget_exceeded` statuses, FastAPI `POST /triage`,
Docker, CI with the secure-pipeline gate.

Weekend 3: ~30 labeled eval alerts (pinned before first run: ≥6 injection twins,
≥5 missing-data), scoring script, threat model (OWASP LLM 2025, OWASP Agentic 2026,
MITRE ATLAS, STRIDE), README results.
