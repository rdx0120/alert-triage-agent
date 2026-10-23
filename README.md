# alert-triage-agent

A read-only LLM agent that turns a security alert into a structured
investigation summary: likely MITRE ATT&CK technique, severity, the evidence
behind each finding, next investigative steps, and an explicit list of what
could not be determined.

The design assumes the model can be misled. Alert fields are attacker-
influenced text, so the security controls live in code around the model rather
than in the prompt: the agent has no tools that can change anything, every tool
call passes through a validating gateway, and empty or failed lookups are
reported as missing data instead of being filled in.

> **Status:** early development. The data layer, the tool gateway, the four
> read-only tools, alert ingestion, deterministic enrichment, the agent loop
> and the rule-based baseline backend are implemented and tested. An Ollama
> backend for local models is implemented and tested against a simulated
> server; it has not yet been run against a model. Output guardrails, the
> service and evaluation are planned; see [Roadmap](#roadmap). No evaluation
> results are published yet.

**Scope.** Lab project. All alerts, hosts and inventory data are synthetic;
threat-intelligence data comes from public sources. It is not a production
service.

## Architecture

```
 alert JSON (untrusted)
        │
        ▼
 ┌─────────────────────────────┐
 │ normalize + validate        │  Wazuh 4.x and Sigma inputs, size caps     [implemented]
 └─────────────┬───────────────┘
               ▼
 ┌─────────────────────────────┐
 │ deterministic enrichment    │  rule tags → ATT&CK, host → asset,         [implemented]
 │ (code, before any model)    │  CVEs → KEV/EPSS, techniques → runbooks
 └─────────────┬───────────────┘
               ▼
 ┌─────────────────────────────┐      ┌──────────────────────────────────┐
 │ LLM agent loop              │─────▶│ run_tool() gateway               │ [implemented]
 │ step and tool-call caps     │      │ allow-list · argument schemas ·  │
 └─────────────┬───────────────┘      │ fail-closed · evidence IDs       │
               │                      └───────────────┬──────────────────┘
               │                                      ▼
               │                      attack_lookup · kev_epss_lookup ·   [implemented]
               │                      asset_context · runbook_search
               ▼                      (local, read-only snapshots)
 ┌─────────────────────────────┐
 │ output guardrails (code)    │  evidence-ID check · ATT&CK ID check ·     [planned]
 │                             │  severity floor · human-approval flag
 └─────────────┬───────────────┘
               ▼
 TriageSummary (JSON + Markdown)  ·  JSONL audit log
```

### Trust boundaries

| Input | Trust | Handling |
|---|---|---|
| Alert fields (command lines, usernames, paths) | Untrusted | Validated and size-capped; strict patterns before reaching any lookup; sent in a separate prompt section that the instructions describe as data; spotlighting (datamarking) is planned. The model may still be influenced by this text, so the output is not trusted either |
| Local snapshots (ATT&CK, KEV/EPSS, assets, runbooks) | Trusted, versioned | Built offline by `scripts/`, with source version and hash recorded |
| Model output | Untrusted | Schema-validated draft (`ModelDraft`); every finding lists sources, and a draft is accepted only if each cited evidence ID was shown to the model in this run and each cited alert field is present (missing-data findings may cite absence). Whether a citation supports its claim is not checked |

## Security controls

| Control | Threat addressed | Status |
|---|---|---|
| No state-changing tools: tools cannot write, delete, execute or make network calls | Prompt injection turning into actions | Implemented |
| Tool allow-list and Pydantic argument validation in a single gateway | Tool misuse; injected text reaching lookups | Implemented |
| `requires_human_approval` fixed to `true` by the schema | Autonomous containment | Implemented |
| Fail closed: an `ok` result must carry data; errors, empty and unknown results are distinct statuses | Silent failures read as "nothing found" | Implemented |
| Untrusted input not echoed in validation errors | Re-injection through error messages | Implemented |
| Raw alert caps: 256 KiB per alert (checked before parsing), nesting depth 5, 50 event fields, 4,096 characters per field | Oversized or deeply nested input | Implemented |
| Invalid UTF-8 and unpaired surrogates replaced with U+FFFD; repeated JSON keys keep the first value; both counted in `ingest_warnings` | Alerts kept from triage by malformed text; values overwritten through repeated keys | Implemented |
| Techniques and CVEs read only from rule metadata and scanner fields, never from event text | Attacker text steering severity or lookups | Implemented |
| Hostname and alert-ID allow-list patterns; ingestion problems reported as `ingest_warnings` | Injected identifiers; silently dropped fields | Implemented |
| Revoked ATT&CK IDs resolved to their replacement | Stale technique mappings | Implemented |
| Enrichment lookups take arguments only from rule metadata and allow-listed identifiers; the runbook query is built from ATT&CK data, never alert text | Attacker text choosing lookups or retrieved guidance | Implemented |
| "Not found" recorded as a gap; a failed lookup marks the enrichment degraded | Broken lookups read as "nothing found" | Implemented |
| Runbook retrieval with a minimum similarity score | Irrelevant context presented as guidance | Implemented |
| Spotlighting (datamarking) of alert fields | Indirect prompt injection | Planned |
| Injection tripwire raising severity | Alerts that address the model | Planned |
| Severity floor: final severity never below the detection rule's level | Injection downgrading an alert | Planned |
| Draft citations restricted to evidence shown in this run and checked before a draft is accepted; unknown-tool errors and evidence left out of the prompt are not citable | Fabricated provenance | Implemented |
| ATT&CK ID allow-list on output; citation relevance | Hallucinated findings | Planned |
| Model-call, tool-call and time limits; prompts bounded in bytes so they fit the context window, with output space reserved | Unbounded consumption; silent context truncation | Implemented |
| Model-requested lookups recorded separately from enrichment | Untraceable model-steered evidence | Implemented |
| Model endpoint must be an `http(s)` URL without credentials, path or query; no proxy or redirect handling; TLS verified | Alert data sent somewhere unintended | Implemented |
| Hard per-request deadline (never more than the time left in the run), bounded worker threads, 1 MiB reply cap; malformed replies are backend errors | Hung or hostile model endpoint | Implemented |
| JSONL audit log of every tool call and model response (OpenTelemetry GenAI field names) | Lack of accountability | Planned |

A full threat model (STRIDE, OWASP Top 10 for LLM Applications 2025, OWASP Top
10 for Agentic Applications, MITRE ATLAS) is planned in `docs/threat-model.md`.

## Components

| Component | Location | Notes |
|---|---|---|
| Schemas | `triage/schemas.py` | `Alert`, `ToolResult`, `TriageSummary`; unknown fields rejected |
| Ingestion | `triage/ingest.py` | Wazuh 4.x and Sigma-match normalizers; explicit format; rejects alerts without rule metadata |
| Sample alerts | `samples/alerts/` | Synthetic Wazuh and Sigma inputs; Sigma samples generated from the vendored rule fixtures |
| Enrichment | `triage/enrich.py`, `triage/evidence.py` | Deterministic lookups before the model; shared evidence log; explicit gaps; `complete` / `degraded` status |
| Agent loop | `triage/agent.py`, `triage/prompt.py` | Two phases (investigation with capped tool calls, then a schema-constrained draft); byte budgets; fixed stop reasons |
| Model backends | `triage/backends/` | One `chat()` interface; rule-based baseline; Ollama over `http.client` with hard deadlines (not yet run against a model) |
| Tool gateway | `triage/tools/registry.py` | Allow-list, argument validation, error handling, deterministic evidence IDs |
| `attack_lookup` | `triage/tools/attack.py` | ATT&CK Enterprise v20.0; retired IDs return their replacement |
| `kev_epss_lookup` | `triage/tools/kev_epss.py` | CISA KEV membership and FIRST EPSS score; missing EPSS reported as unknown |
| `asset_context` | `triage/tools/assets.py` | Synthetic 10-host inventory; unknown hosts reported as not found |
| `runbook_search` | `triage/tools/runbooks.py` | Section-level chunks, all-MiniLM-L6-v2 embeddings, FAISS exact search |
| Data builders | `scripts/` | Rebuild the ATT&CK and KEV/EPSS snapshots from public sources |

Design rationale for each choice is recorded in
[`docs/design-decisions.md`](docs/design-decisions.md).

## Installation

Requires Python 3.11 or later.

```bash
git clone https://github.com/rdx0120/alert-triage-agent.git
cd alert-triage-agent
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"              # add ,embeddings for semantic runbook search
```

On Linux without an NVIDIA GPU, install the CPU-only PyTorch build before the
`embeddings` extra; otherwise pip pulls several GB of CUDA libraries you won't use:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[dev,embeddings]"
```

Configuration is read from environment variables; `.env.example` lists them
with their defaults.

## Testing

```bash
python -m pytest              # offline suite; uses a deterministic hashing embedder
python -m pytest -m slow      # retrieval tests with the real embedding model (~90 MB download)
python -m pytest -m ollama -s # live smoke test; needs OLLAMA_MODEL (and OLLAMA_HOST if not local)
```

The live test runs every sample alert against the configured model and
checks only that each run ends with a recorded stop reason and that the
prompt tokens Ollama reports stay within the byte-based bound. Run it on
the host that serves the model, against `http://localhost:11434`
(DD-009).

`python -m pytest` runs the tests with the interpreter the project is
installed in, which avoids picking up a different `pytest` on `PATH`.

Refresh the threat-intelligence snapshots:

```bash
python scripts/build_kev_epss.py data/kev_epss_snapshot.json
python scripts/build_attack_subset.py <enterprise-attack.json> data/attack_techniques.json --release v20.0
```

## Roadmap

| Capability | Contents | Status |
|---|---|---|
| Data and tools | Schemas, versioned snapshots, four read-only tools, tool gateway | Implemented |
| Alert ingestion | Sample alerts from the Sigma rule fixtures; Wazuh alert normalizer | Implemented |
| Deterministic enrichment | Code-driven lookups before the model runs | Implemented |
| Agent loop and model backends | Agent loop, limits, the rule-based baseline and the Ollama backend are implemented. Claude API (optional) and the audit log are planned | Partial |
| Guardrails | Tool-side controls (allow-list, argument validation, fail-closed results) are implemented. Spotlighting, injection tripwire, severity floors, output evidence and ATT&CK validation, and summary-level fail-closed statuses are planned | Partial |
| Service and packaging | FastAPI `POST /triage`, CLI, Docker, GitHub Actions CI with security scanning | Planned |
| Evaluation and threat model | Labeled synthetic alert set with injection and missing-data cases, scoring against the rule-based baseline, published results | Planned |

## Limitations

- Synthetic and public data only; behaviour on real alert volumes is untested.
- Local models are weaker at tool use than hosted frontier models; results will
  be reported per backend.
- Planned injection tests are hand-written and non-adaptive; they show
  resistance to known patterns, not to a determined attacker.
- The runbook similarity threshold is a starting value, not yet calibrated.
- Not a replacement for an analyst: every recommendation requires human review.

## Data sources and attribution

- **MITRE ATT&CK®** Enterprise v20.0, processed into `data/attack_techniques.json`.
  © 2026 The MITRE Corporation. This work is reproduced and distributed with
  the permission of The MITRE Corporation. See the
  [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
- **CISA Known Exploited Vulnerabilities Catalog**, from
  [cisagov/kev-data](https://github.com/cisagov/kev-data).
- **FIRST EPSS** scores, from the [EPSS API](https://www.first.org/epss/).
- **Detection rules and runbooks** vendored from
  [rdx0120/sigma-detection-pack](https://github.com/rdx0120/sigma-detection-pack);
  see `vendor/sigma-detection-pack/SOURCE.md` for the pinned commit.

## License

MIT. See [LICENSE](LICENSE). Third-party data remains under its own terms (above).
