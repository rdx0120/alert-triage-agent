# alert-triage-agent

[![ci](https://github.com/rdx0120/alert-triage-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/rdx0120/alert-triage-agent/actions/workflows/ci.yml)

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
> injection tripwire and spotlighting), the Markdown summary renderer, the
> metadata-only audit writer and the command-line runner are implemented and
> tested. An Ollama backend for local models is implemented and tested
> against a simulated server. The service and evaluation are planned; see
> [Roadmap](#roadmap). No evaluation or model results are published yet.

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
| Embedding model pinned to one upstream revision and loaded only from a local directory that matches `data/embedding_model.json` byte for byte: ten files, safetensors weights only, no remote code, offline mode enforced; only `scripts/fetch_embedding_model.py` contacts the Hugging Face Hub, when the operator runs it | Model supply chain; network access at triage time | Implemented |
| Hard per-request deadline (never more than the time left in the run), bounded worker threads, 1 MiB reply cap; malformed replies are backend errors | Hung or hostile model endpoint | Implemented |
| Markdown summary: only fixed template text is Markdown; every value is shown as code (fenced blocks and code spans that the value cannot close); control, format, surrogate and line or paragraph separator characters are shown as `<U+XXXX>`; model output is labelled; an oversized summary is rejected, never truncated. Targets CommonMark/GFM. The CLI renders every `--out` summary with it (`triage.render.render_markdown`); the service is planned | Markdown injection in tickets, wikis and chat: remote images, links, raw HTML, forged headings, bidi reordering | Implemented |
| Secret scan of every reachable commit, merges and all refs included, in CI with a pinned, checksum-verified gitleaks and synthetic controls that prove detection, history coverage and that no suppression applies; data-bearing files restricted to documentation IP ranges, reserved domains and declared hosts, each bound to an exact `provenance.json` entry by its SHA-256 (DD-028) | Secrets or real data committed to the public repository | Implemented |
| Metadata-only JSONL audit log of every lookup and model call (OpenTelemetry GenAI field names) and, when the caller passes it, the guardrails' summary as codes and counts: no prompts, model text, tool arguments, tool data, error messages or endpoint, and no summary text, technique name, asset host or owner; owner-only, append-only file, opened through its checked directory, locked against concurrent writers, rolled back on a failed write and synced to disk. The CLI appends to it before printing or writing anything for every run, unless `--no-audit-log` is given; `run_agent()` itself writes nothing, and the service is planned | Lack of accountability; sensitive data in logs | Implemented |

The threat model is in [`docs/threat-model.md`](docs/threat-model.md). It
classifies the threats found along the data flow and its seven trust
boundaries with STRIDE, and maps them to the OWASP Top 10 for LLM
Applications 2026, the OWASP Top 10 for Agentic Applications 2026 and MITRE
ATLAS 2026.09. Each threat has one status, its controls and its residual
risk, and each control is marked as backed by tests, by committed
configuration or only by written policy. `tests/test_threat_model.py`
checks the document's structure, that every cited test and path exists and
that every framework identifier is a known one; it does not check that a
control works. Two threats are open: the KEV snapshot is built from a
moving upstream source without hash verification (T18); and the developer
install is not hash-pinned (T27). Committed secrets and real data (T30) are
Partial: every reachable commit is scanned for secrets and data-bearing
files are checked and declared (DD-028), but pattern rules cannot prove that
free text holds no real personal data, and the scan is not yet a required
check. The embedding model is pinned and loaded offline (T20, Partial: the
real libraries are checked by a manual slow test, not in CI).
Accepted risks are accepted at laboratory level only, not as a production
risk acceptance.

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
| Markdown rendering | `triage/render.py` | `render_markdown(summary)`: a fixed Markdown document for CommonMark/GFM renderers, with every value shown as code; fixed-message `ValueError` for an invalid or oversized summary. Called by the CLI for `--out` |
| Audit log | `triage/audit.py`, `triage/files.py` | Metadata-only JSONL projection of a run, and optionally of its summary, with fixed keys; refuses unsafe files and directories. Called by the CLI for every run |
| Command-line runner | `triage/cli.py` | `python -m triage` or `alert-triage`: one alert end to end; ASCII-only summary JSON on standard output, optional `--out` files, the audit log first; fixed exit codes and error messages |
| Tool gateway | `triage/tools/registry.py` | Allow-list, argument validation, error handling, deterministic evidence IDs |
| `attack_lookup` | `triage/tools/attack.py` | ATT&CK Enterprise v20.0; retired IDs return their replacement |
| `kev_epss_lookup` | `triage/tools/kev_epss.py` | CISA KEV membership and FIRST EPSS score; missing EPSS reported as unknown |
| `asset_context` | `triage/tools/assets.py` | Synthetic 10-host inventory; unknown hosts reported as not found |
| `runbook_search` | `triage/tools/runbooks.py`, `triage/embedding_model.py` | Section-level chunks, all-MiniLM-L6-v2 embeddings from a pinned, verified local copy, FAISS exact search |
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

With the `embeddings` extra, acquire the embedding model once. This is the
only step that contacts the Hugging Face Hub: it downloads the ten files of
the revision pinned in `data/embedding_model.json` (about 91 MB), checks each
file's size and SHA-256, and installs them in `models/all-MiniLM-L6-v2/`
(or `TRIAGE_EMBEDDING_MODEL_DIR`). It uses no Hugging Face account or token.

```bash
python scripts/fetch_embedding_model.py
```

Triage then loads the model only from that directory, offline, and only if
it still matches the manifest exactly (DD-027).

Configuration is read from environment variables; `.env.example` lists them
with their defaults.

## Usage

```bash
python -m triage --format wazuh samples/alerts/wazuh/encoded_powershell.json --out out
```

The summary is printed as one line of ASCII-only JSON. With `--out`,
`out/<run_id>.json` and `out/<run_id>.md` (the safe Markdown) are written as
well. Every run first appends its metadata-only audit records to
`logs/audit.jsonl`; `--audit-log FILE` chooses another file, and
`--no-audit-log` runs without one. The backend comes from the environment
(`.env.example`); the default is the rule-based baseline. The default
embedder needs the acquired model (Installation); if the model is missing or
does not match its manifest, the CLI stops with exit code 2 before reading
the alert. Without the `embeddings` extra, set `TRIAGE_EMBEDDER=hashing`.
The same command is installed as `alert-triage`.

| Exit code | Meaning |
|---|---|
| 0 | A summary was produced; its `status` says whether triage completed |
| 1 | Internal error |
| 2 | Invalid arguments or configuration |
| 3 | The alert input was rejected |
| 4 | The audit log could not be used; nothing was printed or written |
| 5 | The output files or standard output could not be written |
| 130 | Interrupted; output files this run had created are removed |

Error messages are fixed text and never contain alert content, model output,
paths or the model endpoint. A failed or interrupted run removes the output
files it created; a crash, `kill -9` or power loss while writing can still
leave a partial file. The audit log and `--out` need a POSIX system
(tested on Linux); elsewhere, use `--no-audit-log` without `--out`. Keep both
in a directory tree only you can change: the CLI checks the directory itself
and the files, not the directories above it.

## Testing

```bash
python -m pytest              # offline suite; uses a deterministic hashing embedder
python -m pytest -m slow      # real embedding model, offline; needs the extra and the acquired model
python -m pytest -m ollama -s # live smoke test; needs OLLAMA_MODEL (and OLLAMA_HOST if not local)
```

The live test runs every sample alert against the configured model and
checks only that each run ends with a recorded stop reason and that the
prompt tokens Ollama reports stay within the byte-based bound. Run it on
the host that serves the model, against `http://localhost:11434`
(DD-009).

`python -m pytest` runs the tests with the interpreter the project is
installed in, which avoids picking up a different `pytest` on `PATH`.

CI (`.github/workflows/ci.yml`) runs the offline suite, the sample check, the
tests with `fcntl` hidden and a console-script smoke run on Python 3.11, 3.12
and 3.13 for every pull request and every push to `main` (DD-025). It
installs only the hash-pinned `requirements/ci.lock`, uses no secrets and a
read-only token, and never runs the slow or Ollama tests. After changing
dependencies in `pyproject.toml`, regenerate the lock with
[uv](https://docs.astral.sh/uv/), a tool used only for this step, not a
project dependency:

```bash
uv pip compile pyproject.toml requirements/build.in --extra dev --generate-hashes --universal --python-version 3.11 -o requirements/ci.lock
```

A second CI job, `secrets`, scans every reachable commit for secrets with
gitleaks v8.30.1, a release binary verified by SHA-256 and used only in CI
(DD-028). `scripts/secret_scan.py` first runs synthetic controls on
throwaway repositories, then the full scan, and fails if the scanner's
commit count differs from one computed independently with git. The offline
suite checks the scan script with a fake scanner, and checks that every file
in the git index follows the synthetic-data rules of its path and that every
data-bearing file has an exact entry in `provenance.json`. After editing a
data file, update its `sha256` there; after regenerating the Sigma samples,
`scripts/build_sample_alerts.py` does that for them.

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
| Agent loop and model backends | Agent loop, limits, the rule-based baseline and the Ollama backend are implemented. The metadata-only audit writer is implemented, and the CLI writes the audit log for every run. Claude API (optional) and the service are planned | Partial |
| Guardrails | Tool-side controls (allow-list, argument validation, fail-closed results) are implemented. Output guardrails (severity floor, ATT&CK allow-list with evidence binding, code-owned asset and gaps, citation re-check, fail-closed summary statuses) are implemented. The injection tripwire and spotlighting are implemented. The Markdown summary renderer is implemented and used by the CLI | Partial |
| Service and packaging | The CLI (`python -m triage`, `alert-triage`) and GitHub Actions CI for the offline suite are implemented. Secret scanning of the full history runs in CI. FastAPI `POST /triage`, Docker and dependency and container scanning are planned | Partial |
| Evaluation and threat model | The threat model (`docs/threat-model.md`) is implemented. A labeled synthetic alert set with injection and missing-data cases, scoring against the rule-based baseline, and published results are planned | Partial |

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
