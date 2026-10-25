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
> read-only tools, alert ingestion, deterministic enrichment, the agent loop,
> the rule-based baseline backend, the output guardrails (including the
> injection tripwire and spotlighting), the Markdown summary renderer and the
> metadata-only audit writer are implemented and tested. An Ollama backend for
> local models is implemented and tested against a simulated server. The
> service and evaluation are planned; see [Roadmap](#roadmap). No evaluation
> or model results are published yet.

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
 │ output guardrails (code)    │  citation re-check · ATT&CK allow-list ·   [implemented]
 │                             │  severity floor · injection tripwire ·
 │                             │  fail-closed statuses · human approval
 └─────────────┬───────────────┘
               ▼
 TriageSummary (JSON + Markdown)  ·  JSONL audit log
```

### Trust boundaries

| Input | Trust | Handling |
|---|---|---|
| Alert fields (command lines, usernames, paths) | Untrusted | Validated and size-capped; strict patterns before reaching any lookup; sent in a separate prompt section that the instructions describe as data; in that section every whitespace character is datamarked as `ˆ` (spotlighting). The model may still be influenced by this text, so the output is not trusted either |
| Local snapshots (ATT&CK, KEV/EPSS, assets, runbooks) | Trusted, versioned | Built offline by `scripts/`, with source version and hash recorded |
| Model output | Untrusted | Schema-validated draft (`ModelDraft`); every finding lists sources, and a draft is accepted only if each cited evidence ID was shown to the model in this run and each cited alert field is present (missing-data findings may cite absence). The output guardrails then re-check every citation, bind a technique to its own lookup, keep severity at or above the rule's level and take asset facts and gaps from code; whether free text follows from its sources is not checked |

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
| Spotlighting (datamarking): in the model's view of untrusted alert text every whitespace character is shown as `ˆ`, and the system prompt says marked text is data; caret obfuscation and invisible characters are preserved | Indirect prompt injection | Implemented |
| Injection tripwire: alert text addressed to an AI system (instruction overrides, chat markup, verdict steering and similar, matched after Unicode normalization) sets `injection_suspected`, lists the signals and raises severity to at least high | Alerts that address the model | Implemented |
| Severity floor: final severity never below the detection rule's level; a draft below it is raised and flagged | Injection downgrading an alert | Implemented |
| Draft citations restricted to evidence shown in this run and checked before a draft is accepted; unknown-tool errors and evidence left out of the prompt are not citable | Fabricated provenance | Implemented |
| ATT&CK allow-list on output: a technique must be current in the local snapshot, looked up and shown in this run, and cited by its lookup or the rule's tags; otherwise the rule's technique is used and the rejection flagged | Hallucinated findings | Implemented |
| Citation relevance: technique claims are bound to their evidence and asset facts and enrichment gaps come from code; whether free text follows from its sources is measured in evaluation | Unsupported claims | Partial |
| Model-call, tool-call and time limits; prompts bounded in bytes so they fit the context window, with output space reserved; investigation turns limited to 384 output tokens | Unbounded consumption; silent context truncation | Implemented |
| Model-requested lookups recorded separately from enrichment | Untraceable model-steered evidence | Implemented |
| Model endpoint must be an `http(s)` URL without credentials, path or query; no proxy or redirect handling; TLS verified | Alert data sent somewhere unintended | Implemented |
| Hard per-request deadline (never more than the time left in the run), bounded worker threads, 1 MiB reply cap; malformed replies are backend errors | Hung or hostile model endpoint | Implemented |
| Markdown summary: only fixed template text is Markdown; every value is shown as code (fenced blocks and code spans that the value cannot close); control, format, surrogate and line or paragraph separator characters are shown as `<U+XXXX>`; model output is labelled; an oversized summary is rejected, never truncated. Targets CommonMark/GFM. The renderer (`triage.render.render_markdown`) is implemented and callable; calling it from the CLI and service is planned | Markdown injection in tickets, wikis and chat: remote images, links, raw HTML, forged headings, bidi reordering | Partial |
| Metadata-only JSONL audit log of every lookup and model call (OpenTelemetry GenAI field names) and, when the caller passes it, the guardrails' summary as codes and counts: no prompts, model text, tool arguments, tool data, error messages or endpoint, and no summary text, technique name, asset host or owner; owner-only, append-only file. The writer (`triage.audit.write_audit_log`) is implemented and callable; `run_agent()` does not write a log by itself, and calling it for every run from the CLI and service is planned | Lack of accountability; sensitive data in logs | Partial |

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
| Model backends | `triage/backends/` | One `chat()` interface; rule-based baseline; Ollama over `http.client` with hard deadlines (no model results published yet) |
| Output guardrails | `triage/guardrails.py`, `triage/tripwire.py` | Build the `TriageSummary`: severity floor, ATT&CK allow-list with evidence binding, code-owned asset and gaps, citation re-check, injection tripwire, fail-closed statuses |
| Markdown rendering | `triage/render.py` | `render_markdown(summary)`: a fixed Markdown document for CommonMark/GFM renderers, with every value shown as code; fixed-message `ValueError` for an invalid or oversized summary. Called explicitly; not yet called automatically |
| Audit log | `triage/audit.py` | Metadata-only JSONL projection of a run, and optionally of its summary, with fixed keys; refuses unsafe files and directories. Called explicitly with a run's result; not yet called automatically |
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
| Agent loop and model backends | Agent loop, limits, the rule-based baseline and the Ollama backend are implemented. The metadata-only audit writer is implemented and callable, but not yet called automatically. Claude API (optional) and writing the audit log for every run from the CLI and service are planned | Partial |
| Guardrails | Tool-side controls (allow-list, argument validation, fail-closed results) are implemented. Output guardrails (severity floor, ATT&CK allow-list with evidence binding, code-owned asset and gaps, citation re-check, fail-closed summary statuses) are implemented. The injection tripwire and spotlighting are implemented. The Markdown summary renderer is implemented and callable, but not yet called automatically | Partial |
| Service and packaging | FastAPI `POST /triage`, CLI, Docker, GitHub Actions CI with security scanning | Planned |
| Evaluation and threat model | Labeled synthetic alert set with injection and missing-data cases, scoring against the rule-based baseline, published results | Planned |

## Limitations

- Synthetic and public data only; behaviour on real alert volumes is untested.
- Local models are weaker at tool use than hosted frontier models; results will
  be reported per backend.
- Planned injection tests are hand-written and non-adaptive; they show
  resistance to known patterns, not to a determined attacker.
- The runbook similarity threshold is a starting value, not yet calibrated.
- The Markdown summary targets CommonMark/GFM renderers. Other markup
  dialects, such as Slack mrkdwn or Jira wiki markup, parse text
  differently and are not covered.
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
