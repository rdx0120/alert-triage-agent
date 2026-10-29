# Threat model

This document models the threats to alert-triage-agent as it is implemented
today, the controls that address them and the risk that remains. It covers
the command-line runner and everything it runs, the local data it reads, and
the supply chain that builds and tests it. Components that are still planned
(the HTTP service, Docker packaging, the optional Claude API backend,
security scanning and any production Wazuh integration) are listed in
[Future attack surfaces](#future-attack-surfaces) and are not modelled.

`tests/test_threat_model.py` checks this document against the repository:
every cited test and path must exist, every status must be one of the five
below, every framework identifier must be a known one, and the text must be
ASCII. It does not check that a cited test proves what the text says; that is
the job of review.

## Method

1. A data-flow model with numbered elements and seven trust boundaries.
2. Threat-driven STRIDE classification. Threats were identified by following
   the data flow across each trust boundary and through each element, and
   each threat is classified with the STRIDE categories it involves
   (Spoofing, Tampering, Repudiation, Information disclosure, Denial of
   service, Elevation of privilege). This is not an exhaustive matrix of
   every element and category: an element and category with no threat below
   is not a claim that no such threat exists. Framework entries judged not to
   apply are listed under [Not applicable](#not-applicable) with their
   reasons.
3. A threat register. Each threat has one status, its controls, the evidence
   for each control and the residual risk.
4. A mapping to three frameworks, made only where an entry fits directly.

No numeric risk scores, likelihoods or impact ratings are given: nothing in
this project measures them. Status and residual risk are stated in words.

### Frameworks

| Framework | Edition | Identifier form used here |
|---|---|---|
| OWASP Top 10 for LLM Applications | 2026 (published 4 August 2026) | `LLM01:2026` |
| OWASP Top 10 for Agentic Applications | 2026 (announced 9 December 2025) | `Agentic 2026: ASI01` |
| MITRE ATLAS | Release 2026.09 (15 September 2026) | `ATLAS 2026.09: AML.T0051.001` |

The 2026 LLM list renumbers most 2025 entries. For readers of 2025 mappings:

| 2026 | 2025 |
|---|---|
| LLM01:2026 Prompt Injection | LLM01:2025 |
| LLM02:2026 Sensitive Information Disclosure | LLM02:2025 |
| LLM03:2026 Excessive Agency | LLM06:2025 |
| LLM04:2026 Supply Chain | LLM03:2025 |
| LLM05:2026 Data and Model Poisoning | LLM04:2025 |
| LLM06:2026 Unbounded Consumption | LLM10:2025 |
| LLM07:2026 Misinformation | LLM09:2025 |
| LLM08:2026 Hidden Context Exposure | LLM07:2025 System Prompt Leakage, broadened |
| LLM09:2026 Vector and Embedding Weaknesses | LLM08:2025 |
| LLM10:2026 Improper Output Handling | LLM05:2025 |

### Status and evidence

Every threat has exactly one status:

| Status | Meaning |
|---|---|
| Mitigated | Every control the status relies on is implemented and has a test |
| Partial | At least one control is implemented and tested; a stated gap remains |
| Open | A known weakness with no adequate control yet; a fix is planned |
| Accepted | A stated residual risk judged acceptable for the synthetic laboratory scope only, with its kind and reason; laboratory-level, not a formal or production risk acceptance (see [Risk acceptance](#risk-acceptance)) |
| Not applicable | The threat cannot arise in this system; the reason is given |

Every control carries one evidence class:

| Class | Meaning |
|---|---|
| `[test]` | Implemented, and the cited tests fail if it stops working |
| `[config]` | A committed file enforces it, but no test checks that file |
| `[policy]` | A written rule (`CLAUDE.md`, the README) applied in review; nothing checks it automatically |

Only `[test]` controls count toward Mitigated or Partial. A threat whose
controls are only `[config]` or `[policy]` is Accepted or Open, with the gap
stated. An Accepted or Open threat may also cite tests, for the parts that
are tested.

## System model

### Elements

| ID | Element | Type | Code |
|---|---|---|---|
| E1 | Alert producer: the monitored host and its Wazuh or Sigma pipeline | External, attacker-influenced | - |
| E2 | Operator: runs the CLI, sets the environment | External, trusted | - |
| E3 | Model server (Ollama) | External; its output is untrusted | - |
| E4 | Downstream consumer: analyst, ticket, wiki, chat | External | - |
| E5 | Public sources: MITRE ATT&CK, CISA KEV, FIRST EPSS, sigma-detection-pack, PyPI | External, build time | `scripts/` |
| E6 | Contributors and CI: pull requests, AI coding agents, GitHub Actions | External, development time | `.github/workflows/ci.yml` |
| E7 | Hugging Face Hub | External; reached only by the operator's acquisition step (T20) | `scripts/fetch_embedding_model.py` |
| P1 | Command-line runner | Process | `triage/cli.py` |
| P2 | Ingestion and normalization | Process | `triage/ingest.py`, `triage/schemas.py` |
| P3 | Deterministic enrichment | Process | `triage/enrich.py`, `triage/evidence.py` |
| P4 | Agent loop and prompt building | Process | `triage/agent.py`, `triage/prompt.py` |
| P5 | Tool gateway and the four tools | Process | `triage/tools/registry.py`, `triage/tools/` |
| P6 | Model backends | Process | `triage/backends/heuristic.py`, `triage/backends/ollama.py` |
| P7 | Output guardrails and injection tripwire | Process | `triage/guardrails.py`, `triage/tripwire.py`, `triage/citations.py` |
| P8 | Markdown renderer | Process | `triage/render.py` |
| P9 | Audit writer and file safety | Process | `triage/audit.py`, `triage/files.py` |
| D1 | Snapshots: ATT&CK, KEV/EPSS, asset inventory | Data store | `data/` |
| D2 | Runbooks and rule fixtures | Data store | `vendor/sigma-detection-pack/` |
| D3 | Audit log | Data store | `logs/audit.jsonl` by default |
| D4 | Output files from `--out` | Data store | `<run_id>.json`, `<run_id>.md` |
| D5 | Embedding model directory, checked against `data/embedding_model.json` | Data store, outside git | `models/all-MiniLM-L6-v2/` by default |
| D6 | Dependency lock and installed environment | Data store | `requirements/ci.lock` |

### Data flow

```
TB1 alert input
[E1 alert producer] --> (P1 CLI) --> (P2 ingest) --> (P3 enrich) --+
[E2 operator] --args, env--^                                        |
                                                                    v
TB2 model server                                            (P4 agent loop)
[E3 model server] <====== prompts / replies ======>          |         |
                                                             v         |
                    (P5 gateway + four tools) <-- lookups from P3, P4  |
                      |             |              |                   |
                [D1 data]    [D2 runbooks]   [D5 model dir]            |
                                                   :                   |
TB7 (operator acquisition only)                    :<.... [E7 HF Hub]  |
                                                                       v
                                         (P7 guardrails) --> (P8 renderer)
TB3 output                                                     |
[E4 consumer] <------- summary JSON and Markdown --------------+
TB4 local files                                                |
[D3 audit log] <-- (P9 audit + files) --> [D4 out files] <-----+

Build and development time:
[E5 public sources] ==TB5==> scripts/, vendor copy --> [D1], [D2], [D6]
[E6 contributors, CI] ==TB6==> repository and workflow
```

### Trust boundaries

| ID | Boundary | What crosses it | Direction of trust |
|---|---|---|---|
| TB1 | Alert input | Alert JSON from E1 into P1 and P2 | Untrusted in |
| TB2 | Model server | Prompts to E3; replies back into P4 | Data out; untrusted text in |
| TB3 | Output | Summary JSON and Markdown to E4 | Rendered so a consumer can show it safely |
| TB4 | Local filesystem | Audit and output files; other local users | The checked directory and file are trusted only after checks |
| TB5 | Build-time supply chain | Public data, rules, runbooks and packages into D1, D2 and D6 | Trusted after review, by pinned version or hash |
| TB6 | Development and CI | Code and workflow changes into the repository | Trusted after review and CI |
| TB7 | Model acquisition | Embedding model files from E7 into D5, by the operator's acquisition step only | Trusted only after every file matches the committed manifest |

**TB7, the embedding model.** The operator acquires the model once with
`scripts/fetch_embedding_model.py`, the only code in this project that
contacts the Hugging Face Hub. It downloads exactly the ten files listed in
`data/embedding_model.json` at the pinned revision, without a token, checks
each file's size and SHA-256, and installs them as plain files in a local
directory (D5). The Hub can redirect a download to its CDN or Xet storage
hosts; the recorded hashes, not the hosts, are what make the bytes
trustworthy. At triage time nothing crosses TB7: the model is loaded only
from that directory, by its absolute path, after it matches the manifest
exactly, with offline mode enforced and without pickle weights or remote
code (T20, DD-027). With `TRIAGE_EMBEDDER=hashing`, used by the offline
tests and CI, no model is loaded at all.

## Threat register

### T01 Indirect prompt injection through alert fields

- Status: Partial
- Boundary: TB1, TB2. Elements: P4, P7. STRIDE: Tampering.
- Frameworks: LLM01:2026; Agentic 2026: ASI01; ATLAS 2026.09: AML.T0051.001, AML.T0068
- Threat: an attacker who controls text on the monitored host (a command
  line, a file name, a user name) writes instructions to the model, to steer
  the summary: a benign verdict, a lower severity, misleading next steps.
- Controls:
  - [test] Untrusted alert text is sent in its own prompt section with every whitespace character datamarked, and the system prompt says marked text is data: `tests/test_prompt.py::test_untrusted_text_only_in_its_section`, `tests/test_prompt.py::test_every_whitespace_character_is_shown_as_datamark`, `tests/test_prompt.py::test_system_prompt_describes_the_datamark`, `tests/test_ollama_backend.py::test_agent_run_sends_datamarked_alert_text`
  - [test] The tripwire flags alert text addressed to an AI system, scanning the full alert after Unicode normalization: `tests/test_tripwire.py::test_injection_phrases_match`, `tests/test_tripwire.py::test_ordinary_alert_text_does_not_match`, `tests/test_guardrails.py::test_tripwire_scans_the_full_alert`
  - [test] Asset facts and enrichment gaps come from code, not from the draft: `tests/test_guardrails.py::test_draft_cannot_influence_asset`, `tests/test_guardrails.py::test_missing_data_provenance`
  - [test] The rule-based baseline never reads the prompt: `tests/test_agent.py::test_heuristic_ignores_injected_text`
- Residual: whether the model's free text follows from its sources is not
  checked in code. Datamarking reduces injection success; it does not prevent
  it. The tripwire matches known phrasings and can be evaded by new ones. The
  injection tests are hand-written and non-adaptive. Severity is covered by
  T04.

### T02 Injection turned into actions

- Status: Partial
- Boundary: TB1, TB2. Elements: P4, P5. STRIDE: Elevation of privilege.
- Frameworks: LLM03:2026; Agentic 2026: ASI02; ATLAS 2026.09: AML.T0053, AML.T0086, AML.T0101
- Threat: injected text makes the agent change something: isolate a host,
  delete data, run a command, send data elsewhere.
- Controls:
  - [test] The production tool set is exactly four lookups, and evidence from any other tool is not citable: `tests/test_guardrails.py::test_default_allow_list_is_the_production_tools`, `tests/test_tools.py::test_tool_not_on_allow_list_is_refused`, `tests/test_agent.py::test_unknown_tool_name_is_a_gateway_error`
  - [test] Network modules are imported only by the model adapter: `tests/test_ollama_backend.py::test_network_code_only_in_adapter`
  - [test] Containment suggestions always require human approval: `tests/test_schemas.py::test_containment_cannot_skip_human_approval`, `tests/test_draft_schema.py::test_containment_cannot_be_preapproved`, `tests/test_guardrails.py::test_containment_needs_human_approval`
  - [policy] Each of the four tools only reads local snapshots or an in-memory index and cannot write, delete or execute (DD-001); this is established by review of `triage/tools/`, not by a test.
- Residual: no test checks that the tools stay read-only. Adding a tool makes
  the tool-set test fail until that test is changed, which forces a review,
  but a change inside an existing tool is caught only by review. The
  network-import test checks the project's own imports only, not third-party
  libraries (see T20).

### T03 Attacker text choosing lookups or retrieved guidance

- Status: Partial
- Boundary: TB1. Elements: P3, P5. STRIDE: Tampering.
- Frameworks: LLM01:2026, LLM09:2026; Agentic 2026: ASI06; ATLAS 2026.09: AML.T0066
- Threat: alert text decides which records are looked up or which runbook
  text is shown, so the model sees evidence chosen by the attacker.
- Controls:
  - [test] Enrichment arguments come only from rule metadata and allow-listed identifiers, and the runbook query is built from ATT&CK data: `tests/test_enrich.py::test_alert_text_never_reaches_lookup_arguments`, `tests/test_enrich.py::test_no_alert_text_in_gaps_or_resolutions`
  - [test] Model-requested lookups pass the same argument validation and are recorded apart from enrichment: `tests/test_agent.py::test_bad_arguments_are_invalid_input`, `tests/test_agent.py::test_model_lookup_origin_and_repeats`
- Residual: the model writes its own runbook queries, and the model may be
  influenced by alert text (T01). The runbook corpus is fixed and trusted
  (T18), so such a query can choose among existing sections, not add text.

### T04 An alert downgraded or buried by injection

- Status: Partial
- Boundary: TB1, TB2. Elements: P7. STRIDE: Tampering.
- Frameworks: LLM01:2026; Agentic 2026: ASI01; ATLAS 2026.09: AML.T0051.001
- Threat: injected text gets a serious alert reported as low severity or
  benign, so it is not investigated.
- Controls:
  - [test] Severity floor: the final severity is never below the detection rule's level, and a lower draft is raised and flagged: `tests/test_guardrails.py::test_severity_floor_pairs`, `tests/test_guardrails.py::test_injection_style_downgrade`
  - [test] A tripwire match raises severity to at least high: `tests/test_guardrails.py::test_tripwire_raises_low_rule_to_high`, `tests/test_guardrails.py::test_floor_and_tripwire_together`
  - [test] A run that did not complete is never reported as triaged: `tests/test_guardrails.py::test_stop_reasons_fail_closed`
- Residual: the severity value is protected; the narrative is not. The
  rationale and next steps can still describe the activity as benign, and an
  injection the tripwire misses can still keep severity at the rule's level
  when it should be higher.

### T05 Oversized, deeply nested or malformed input

- Status: Mitigated
- Boundary: TB1. Elements: P1, P2. STRIDE: Denial of service, Tampering.
- Frameworks: LLM06:2026; ATLAS 2026.09: AML.T0029
- Threat: an alert built to exhaust memory or time, crash the parser, or
  hide a value behind a repeated key or broken encoding.
- Controls:
  - [test] Size cap checked before parsing, nesting depth, field count and field length limits: `tests/test_ingest_wazuh.py::test_load_alert_size_cap_checked_before_parsing`, `tests/test_ingest_wazuh.py::test_load_alert_rejects_deeply_nested_json`, `tests/test_ingest_wazuh.py::test_more_than_max_fields_keeps_exactly_max`, `tests/test_ingest_wazuh.py::test_long_values_capped_by_alert_model`
  - [test] Invalid UTF-8 and lone surrogates replaced, the first of repeated keys kept, and both counted: `tests/test_ingest_wazuh.py::test_invalid_utf8_in_command_line_replaced_not_rejected`, `tests/test_ingest_wazuh.py::test_repeated_key_keeps_first_value`, `tests/test_ingest_sigma.py::test_event_keys_colliding_after_surrogate_replacement_keep_first_value`
  - [test] A FIFO given as input is refused without hanging, and the tripwire scans adversarial input quickly: `tests/test_cli.py::test_fifo_input_is_refused_without_hanging`, `tests/test_tripwire.py::test_adversarial_alert_scans_quickly`
- Residual: none known within the stated limits.

### T06 Forged identifiers from event text

- Status: Mitigated
- Boundary: TB1. Elements: P2, P3. STRIDE: Spoofing, Tampering.
- Frameworks: LLM01:2026
- Threat: event text supplies a host name, alert ID, CVE or technique, to
  pull another asset's context or a chosen technique into the summary.
- Controls:
  - [test] Techniques and CVEs are read only from rule metadata and scanner fields: `tests/test_ingest_wazuh.py::test_event_text_never_adds_techniques_or_cves`, `tests/test_ingest_sigma.py::test_event_text_never_adds_techniques_or_cves`
  - [test] Host and alert ID allow-list patterns: `tests/test_ingest_wazuh.py::test_invalid_agent_name_leaves_host_empty_and_keeps_evidence`, `tests/test_ingest_wazuh.py::test_trailing_newline_fails_allow_lists`, `tests/test_ingest_sigma.py::test_invalid_alert_id_rejected`, `tests/test_tools.py::test_asset_injection_in_host_is_rejected`
- Residual: none known.

### T07 Re-injection through error and warning messages

- Status: Mitigated
- Boundary: TB1, TB2. Elements: P1, P2, P4, P5. STRIDE: Tampering, Information disclosure.
- Frameworks: LLM01:2026
- Threat: an error message quotes attacker text back to the model, the
  terminal or a log, where it is read as trusted text.
- Controls:
  - [test] Validation and rejection messages never contain input: `tests/test_tools.py::test_extra_argument_name_is_not_echoed`, `tests/test_agent.py::test_extra_argument_names_are_not_echoed`, `tests/test_agent.py::test_repair_message_is_sanitized`, `tests/test_ingest_wazuh.py::test_rejection_messages_never_contain_input`, `tests/test_ingest_wazuh.py::test_warnings_never_contain_input_keys_or_values`, `tests/test_citations.py::test_problems_never_contain_a_cited_value`
  - [test] Every CLI message is fixed ASCII text: `tests/test_cli.py::test_every_message_is_fixed_ascii_text`
- Residual: none known.

### T08 Fabricated provenance

- Status: Partial
- Boundary: TB2. Elements: P4, P7. STRIDE: Repudiation, Tampering.
- Frameworks: LLM07:2026; Agentic 2026: ASI09; ATLAS 2026.09: AML.T0067.000
- Threat: the model cites evidence it was never shown, or invents an
  evidence ID, so a claim looks supported when it is not.
- Controls:
  - [test] Only evidence shown in this run is citable; planted, foreign and unknown-tool IDs are not: `tests/test_citations.py::test_fabricated_and_foreign_ids_are_uncitable`, `tests/test_citations.py::test_planted_evidence_ids_are_not_citable`, `tests/test_citations.py::test_unknown_tool_results_are_never_citable`
  - [test] A draft with a fabricated citation is repaired once, then rejected: `tests/test_agent.py::test_fabricated_id_is_repaired`, `tests/test_agent.py::test_fabricated_id_twice_is_invalid_output`
  - [test] The guardrails re-check every citation: `tests/test_guardrails.py::test_citation_recheck`
- Residual: evidence IDs are checked; whether the cited evidence supports the
  free text is not. That is to be measured in the planned evaluation.

### T09 Hallucinated or unsupported technique

- Status: Mitigated
- Boundary: TB2. Elements: P7. STRIDE: Tampering.
- Frameworks: LLM07:2026
- Threat: the summary names an ATT&CK technique that does not exist, is
  retired, or was never looked up in this run.
- Controls:
  - [test] A technique must be current in the snapshot, looked up and shown in this run, and cited by its lookup or the rule's tags; otherwise the rule's technique is used and the rejection flagged: `tests/test_guardrails.py::test_technique_rejections`, `tests/test_guardrails.py::test_model_lookup_technique_is_lookup_only`, `tests/test_guardrails.py::test_rule_technique_cited_with_rule_tags`
- Residual: none known for the technique field.

### T10 Hostile, hung or impersonated model endpoint

- Status: Partial
- Boundary: TB2. Elements: P6. STRIDE: Spoofing, Tampering, Denial of service.
- Frameworks: LLM06:2026; ATLAS 2026.09: AML.T0029
- Threat: the model server, or something answering in its place, sends
  oversized, malformed, slow or endless replies, or redirects the client.
- Controls:
  - [test] The endpoint must be an http or https URL with a host and no credentials, path or query; redirects are not followed; proxy settings are ignored: `tests/test_ollama_backend.py::test_invalid_endpoints`, `tests/test_ollama_backend.py::test_redirect_not_followed`, `tests/test_ollama_backend.py::test_proxy_settings_ignored`
  - [test] Hard deadlines, a 1 MiB reply cap, bounded worker threads, malformed replies as backend errors: `tests/test_ollama_backend.py::test_watchdog_deadline`, `tests/test_ollama_backend.py::test_https_slow_body_deadline`, `tests/test_ollama_backend.py::test_oversized_reply`, `tests/test_ollama_backend.py::test_repeated_timeouts_do_not_accumulate_workers`, `tests/test_ollama_backend.py::test_bad_reply_is_backend_error`
  - [config] https uses the standard library's default TLS context, with certificate and hostname checks: `triage/backends/ollama.py`
- Residual: plain http is accepted, because the endpoint is expected on the
  same host (DD-009); over a network, http gives no server authentication.
  No test presents an untrusted certificate. Whatever a hostile server
  writes inside a valid reply is handled as untrusted model output (T01, T08,
  T15).

### T11 Alert data sent somewhere unintended

- Status: Mitigated
- Boundary: TB2. Elements: P1, P6, P9. STRIDE: Information disclosure.
- Frameworks: LLM02:2026
- Threat: alert content leaves the host through a proxy, a redirect, a
  credentialed or rewritten URL, or appears in logs and messages with the
  endpoint.
- Controls:
  - [test] Endpoint validation, no redirects, no proxies: `tests/test_ollama_backend.py::test_invalid_endpoints`, `tests/test_ollama_backend.py::test_redirect_not_followed`, `tests/test_ollama_backend.py::test_proxy_settings_ignored`
  - [test] The endpoint is never written to the audit log or printed: `tests/test_audit.py::test_nothing_untrusted_is_written`, `tests/test_audit.py::test_model_name_that_looks_like_an_address_is_null`, `tests/test_cli.py::test_every_message_is_fixed_ascii_text`
- Residual: the operator chooses `OLLAMA_HOST` and is trusted to choose the
  intended server.

### T12 Unbounded consumption

- Status: Mitigated
- Boundary: TB2. Elements: P4, P6. STRIDE: Denial of service.
- Frameworks: LLM06:2026; ATLAS 2026.09: AML.T0034.002, AML.T0029
- Threat: the model loops on tool calls or long turns, or the run never
  ends.
- Controls:
  - [test] Model-call, tool-call, per-turn and investigation-turn caps that callers cannot raise: `tests/test_agent.py::test_total_tool_call_cap`, `tests/test_agent.py::test_per_turn_cap_drops_extra_calls`, `tests/test_agent.py::test_investigation_turn_cap`, `tests/test_agent.py::test_limits_cannot_be_raised`
  - [test] A run deadline that every request respects: `tests/test_agent.py::test_deadline_stops_before_next_call`, `tests/test_agent.py::test_request_timeout_within_run`, `tests/test_agent.py::test_runtime_budget_backstop`
- Residual: enrichment counts against the run deadline but is not
  interrupted by it; the slowest enrichment step is verifying and loading
  the local embedding model (T20), which makes no network request.

### T13 Silent context truncation

- Status: Mitigated
- Boundary: TB2. Elements: P4. STRIDE: Tampering, Repudiation.
- Frameworks: LLM06:2026
- Threat: a prompt overflows the context window and evidence is dropped
  without anyone knowing, or an alert is padded so its decisive part is cut.
- Controls:
  - [test] Prompts are bounded in bytes with output space reserved, and omissions are counted: `tests/test_prompt.py::test_pack_keeps_order_counts_omissions_and_never_skips_ahead`, `tests/test_prompt.py::test_worst_case_budget_constructed`, `tests/test_prompt.py::test_worst_case_numbers_with_datamarking`
  - [test] Gaps and resolutions are never packed out, and evidence left out of the prompt is not citable: `tests/test_fail_closed.py::test_largest_gap_and_resolution_sections_are_never_packed_out`, `tests/test_citations.py::test_result_left_out_by_packing_is_not_citable`
- Residual: the byte bound is tested against the model's reported token
  counts only in the live test, which CI does not run.

### T14 Context disclosure through the summary

- Status: Accepted
- Boundary: TB2, TB3. Elements: P4. STRIDE: Information disclosure.
- Frameworks: LLM08:2026, LLM02:2026; ATLAS 2026.09: AML.T0056, AML.T0057
- Threat: injected text makes the model repeat its system prompt or other
  context (inventory records, runbook text) in the summary.
- Controls:
  - [policy] Nothing secret is placed in the prompt, and no control depends on the prompt staying secret; every control is in code (DD-001, DD-019).
- Residual: accepted for the laboratory scope (see
  [Risk acceptance](#risk-acceptance)). The context holds the alert, public reference data and
  the synthetic inventory, and the summary goes to the same analysts who can
  read those. A deployment with a real inventory would need to revisit this.

### T15 Markdown injection downstream

- Status: Partial
- Boundary: TB3. Elements: P8, P1. STRIDE: Tampering, Information disclosure.
- Frameworks: LLM10:2026; Agentic 2026: ASI09; ATLAS 2026.09: AML.T0077
- Threat: model or alert text in the summary renders as active Markdown in a
  ticket, wiki or chat: remote images that leak data, links, raw HTML, forged
  headings, or bidirectional reordering.
- Controls:
  - [test] Fixed template, every value shown as code, invisible and control characters as code points, size limit: `tests/test_render.py::test_markdown_attack_stays_inert`, `tests/test_render.py::test_separators_and_controls_are_shown_as_code_points`, `tests/test_render.py::test_output_cap`
  - [test] Model text never reaches the terminal raw; standard output is ASCII-only JSON: `tests/test_cli.py::test_model_text_cannot_reach_the_terminal_raw`
- Residual: CommonMark and GFM only; Slack mrkdwn, Jira wiki markup and other
  dialects are not covered. A consumer of the JSON must escape its values for
  its own display.

### T16 Analyst over-trust

- Status: Partial
- Boundary: TB3. Elements: E4, P7. STRIDE: none (human factor).
- Frameworks: LLM07:2026; Agentic 2026: ASI09
- Threat: a confident summary is accepted without review, including a wrong
  one or one shaped by injection.
- Controls:
  - [test] Containment needs human approval; degraded enrichment is reported as insufficient data; missing data is listed with code-owned provenance: `tests/test_guardrails.py::test_containment_needs_human_approval`, `tests/test_guardrails.py::test_degraded_enrichment_is_insufficient_data`, `tests/test_guardrails.py::test_missing_data_provenance`
  - [test] The rendered summary keeps every section label, including empty ones: `tests/test_render.py::test_empty_sections_keep_their_labels`
  - [policy] The README states that every recommendation requires human review.
- Residual: how analysts actually use the summary is not studied.

### T17 A failure read as "nothing found"

- Status: Mitigated
- Boundary: TB2. Elements: P3, P5, P7. STRIDE: Tampering, Repudiation.
- Frameworks: LLM07:2026; Agentic 2026: ASI08
- Threat: a failed or empty lookup, or a failed model call, is reported as a
  clean result, so a reader concludes there is nothing to find.
- Controls:
  - [test] Distinct statuses; `ok` must carry data; tool exceptions become errors: `tests/test_schemas.py::test_ok_result_must_carry_data`, `tests/test_tools.py::test_empty_return_is_not_found_not_ok`, `tests/test_tools.py::test_exception_in_tool_fails_closed`, `tests/test_tools.py::test_kev_empty_snapshot_fails_closed`
  - [test] A failed lookup marks enrichment degraded and later steps still run: `tests/test_enrich.py::test_failed_lookups_degrade_and_later_steps_still_run`
  - [test] Fail-closed summary statuses, and a backend error is a summary, not a crash: `tests/test_guardrails.py::test_stop_reasons_fail_closed`, `tests/test_cli.py::test_backend_error_is_a_summary_not_a_failure`
- Residual: none known.

### T18 Poisoned snapshot or runbook

- Status: Open
- Boundary: TB5. Elements: D1, D2, P5. STRIDE: Tampering.
- Frameworks: LLM05:2026, LLM09:2026; Agentic 2026: ASI04, ASI06; ATLAS 2026.09: AML.T0070, AML.T0010.002
- Threat: a compromised upstream source, or a malicious change, puts false
  technique data, a false asset record or injected instructions into the
  snapshots or runbooks, which the model then reads as trusted context.
- Controls:
  - [policy] Snapshots are rebuilt offline by `scripts/` and committed with their source version; the ATT&CK builder records the source file's SHA-256: `scripts/build_attack_subset.py`, `scripts/build_kev_epss.py`
  - [policy] The vendored rules and runbooks are pinned to a commit and never edited by hand (`CLAUDE.md`): `vendor/sigma-detection-pack/SOURCE.md`
  - [test] Vendored rule tags and runbook headers must be current ATT&CK IDs, and the Sigma samples must match their generator: `tests/test_vendor_rules.py::test_rule_tags_are_current_attack_ids`, `tests/test_vendor_rules.py::test_runbook_attack_headers_are_current_ids`, `tests/test_samples.py::test_sigma_samples_match_generator`
  - [test] Trusted sections are deliberately not datamarked: `tests/test_prompt.py::test_metadata_and_enrichment_are_not_datamarked`
- Residual: open. Integrity rests on review of the pull request that
  changes the data; nothing verifies a snapshot or runbook when it is loaded,
  runbook text is not datamarked, and the tripwire does not scan it. The
  tests above catch stale identifiers, not injected text. The KEV builder
  reads the moving upstream `develop` branch and records the catalog version
  but no source hash, and review of a large data diff is a weak check. A
  false KEV or EPSS value changes only what the model reads, because no
  guardrail uses it, but this is a real supply-chain exposure and is not
  accepted. Planned fix, separately authorized: build from a pinned upstream
  revision, verify the source file's hash, and keep every data update a
  reviewed pull request.

### T19 Irrelevant runbook text shown as guidance

- Status: Partial
- Boundary: TB5. Elements: P5. STRIDE: Tampering.
- Frameworks: LLM09:2026
- Threat: retrieval returns the least-bad section for an unrelated query,
  and the model treats it as guidance.
- Controls:
  - [test] A minimum similarity score; nothing above it is `not_found`: `tests/test_tools.py::test_runbook_search_irrelevant_query_is_not_found`, `tests/test_runbooks_minilm.py::test_semantic_match`
- Residual: the threshold for the real embedder is a starting value, not
  calibrated. `tests/test_runbooks_minilm.py::test_semantic_match` is a slow
  test, not run in CI.

### T20 Unpinned or remote embedding model at triage time

- Status: Partial
- Boundary: TB7. Elements: P5, D5, E7. STRIDE: Tampering, Denial of service, Information disclosure.
- Frameworks: LLM04:2026; Agentic 2026: ASI04; ATLAS 2026.09: AML.T0010.003, AML.T0011.000
- Threat: the runbook index loads a model other than the reviewed one,
  fetches one from the Hub at triage time, or loads pickle weights or remote
  code. A changed model alters what guidance the model is shown; a fetch at
  triage time adds a network dependency and reveals use of the model; pickle
  weights or remote code would run code from the download.
- Controls:
  - [test] The model is pinned in a committed manifest (repository, revision, license, ten files with size and SHA-256, safetensors weights only), read strictly: `tests/test_embedding_model.py::test_manifest_pins_the_safetensors_model`, `tests/test_embedding_model.py::test_malformed_manifest_is_refused`
  - [test] The local directory must match the manifest exactly, with no extra, hidden, linked or cache files, and an unverified directory never reaches the library: `tests/test_embedding_model.py::test_unexpected_contents_are_refused`, `tests/test_embedding_model.py::test_unverified_directory_is_never_loaded`
  - [test] Loading is local and offline: an absolute path, `local_files_only`, no remote code, safetensors only, offline mode set before the first import and checked after it: `tests/test_embedding_model.py::test_loader_passes_only_local_offline_arguments`, `tests/test_embedding_model.py::test_relative_setting_reaches_the_library_as_an_absolute_path`, `tests/test_embedding_model.py::test_offline_mode_is_set_before_import`, `tests/test_embedding_model.py::test_library_imported_without_offline_mode_is_refused`
  - [test] A full CLI run with the default embedder makes no outbound connection, and a missing or altered model stops the CLI with exit code 2 or fails closed in the tool: `tests/test_embedding_model.py::test_no_connection_during_a_minilm_run`, `tests/test_embedding_model.py::test_network_guard_catches_a_connection`, `tests/test_embedding_model.py::test_cli_refuses_a_missing_or_altered_model`, `tests/test_embedding_model.py::test_runbook_search_reports_an_unavailable_model_as_an_error`
  - [test] Only the operator's acquisition script contacts the Hub; it requests only the manifest's files at the pinned revision, without credentials, and installs verified plain files or nothing: `tests/test_embedding_model.py::test_triage_never_imports_the_hub_or_its_download_functions`, `tests/test_fetch_embedding_model.py::test_downloads_are_bounded_pinned_and_tokenless`, `tests/test_fetch_embedding_model.py::test_installs_exactly_the_manifest_files_as_regular_files`, `tests/test_fetch_embedding_model.py::test_a_failure_installs_nothing`
  - [test] With the real libraries, retrieval works offline and no connection is attempted. These are slow tests, run by hand on the floor and the latest supported dependency combinations, not in CI: `tests/test_runbooks_minilm.py::test_semantic_match`, `tests/test_runbooks_minilm.py::test_real_library_runs_in_offline_mode`
- Residual: the tests in CI use stand-in libraries; the real libraries'
  offline behaviour is checked only by the slow tests, by hand, and a later
  library release could change it, so they are repeated on every dependency
  change. The socket guard sees connections made through Python's socket
  module only; offline mode is what covers native code. A process running as
  the operator could replace the model between verification and load, which
  is out of scope. The pinned model's own retrieval quality is a matter for
  evaluation (T19).

### T21 Tool argument injection by the model

- Status: Mitigated
- Boundary: TB2. Elements: P5. STRIDE: Tampering, Elevation of privilege.
- Frameworks: LLM03:2026; Agentic 2026: ASI02; ATLAS 2026.09: AML.T0053
- Threat: the model passes extra arguments, oversized values or malformed
  identifiers to a tool, or a malformed tool name.
- Controls:
  - [test] Pydantic argument models with extra fields forbidden and strict patterns and limits: `tests/test_tools.py::test_extra_argument_is_invalid_input`, `tests/test_tools.py::test_attack_malformed_id_is_invalid`, `tests/test_tools.py::test_kev_malformed_cve_is_invalid`, `tests/test_tools.py::test_runbook_search_top_k_capped`
  - [test] Malformed tool names and arguments from the model are replaced or rejected: `tests/test_agent.py::test_malformed_tool_names_are_replaced`, `tests/test_agent.py::test_bad_arguments_are_invalid_input`
- Residual: none known.

### T22 Audit log tampering, symlink or race attacks

- Status: Partial
- Boundary: TB4. Elements: P9, D3. STRIDE: Tampering, Repudiation.
- Frameworks: none applies directly.
- Threat: another local user, or a race, redirects the audit log through a
  link, swaps its directory, interleaves writes or reads it.
- Controls:
  - [test] The file and its directory are opened without following links, and refused when the file is group-readable, the directory is world-writable, or either is owned by another user, including a directory swapped for a link after the check: `tests/test_audit.py::test_symlink_refused`, `tests/test_audit.py::test_group_readable_file_refused`, `tests/test_audit.py::test_file_owned_by_another_user_refused`, `tests/test_audit.py::test_world_writable_directory_refused`, `tests/test_audit_files.py::test_directory_replaced_by_a_symlink_after_check_refused`
  - [test] Concurrent writers are locked, and a failed write is rolled back: `tests/test_audit_files.py::test_concurrent_writers_leave_whole_lines`, `tests/test_audit_files.py::test_failed_write_is_rolled_back`
- Residual: the log is not tamper-evident: a process running as its owner
  can rewrite it undetected. The directories above the log's own directory
  are trusted, not checked.

### T23 Sensitive data in logs

- Status: Mitigated
- Boundary: TB4. Elements: P9, D3, P1. STRIDE: Information disclosure.
- Frameworks: LLM02:2026
- Threat: alert content, model text, tool data or the endpoint end up in the
  audit log or on standard error.
- Controls:
  - [test] The audit log is a metadata-only projection with fixed keys: `tests/test_audit.py::test_nothing_untrusted_is_written`, `tests/test_audit_summary.py::test_summary_text_never_written`, `tests/test_agent.py::test_run_record_never_holds_untrusted_text`
  - [test] Alert text reaches neither standard error nor the log: `tests/test_cli.py::test_alert_text_reaches_neither_stderr_nor_the_log`
- Residual: none known.

### T24 Output files overwriting or following a link

- Status: Partial
- Boundary: TB4. Elements: P1, D4. STRIDE: Tampering.
- Frameworks: none applies directly.
- Threat: `--out` overwrites an existing file, writes through a link, or
  leaves a half-written pair that a consumer reads.
- Controls:
  - [test] New files only, an unsafe directory stops the run before the model, and a failure or interrupt removes the files this run created: `tests/test_cli.py::test_collision_keeps_the_existing_file`, `tests/test_cli.py::test_unsafe_output_directory_stops_before_the_model`, `tests/test_cli.py::test_second_file_failure_removes_only_this_runs_files`, `tests/test_cli.py::test_interrupt_during_second_output_removes_this_runs_files`
- Residual: a crash, `kill -9` or power loss while writing can still leave a
  partial file.

### T25 A run that leaves no record

- Status: Mitigated
- Boundary: TB4. Elements: P1. STRIDE: Repudiation.
- Frameworks: none applies directly.
- Threat: a run produces a summary with no audit record of what it did.
- Controls:
  - [test] The audit record is written before anything is printed or written, and a failed append means no outputs: `tests/test_cli.py::test_audit_preflight_stops_before_the_model`, `tests/test_cli.py::test_audit_append_failure_means_no_outputs`
  - [test] Running without a log needs `--no-audit-log` and prints a notice: `tests/test_cli.py::test_no_audit_log_is_explicit_and_noted`
- Residual: the trusted operator can run without a log, explicitly and with
  a notice. Passing that flag needs the operator's own account, which is out
  of scope (see [Not applicable](#not-applicable)).

### T26 An interrupted append blocks later runs

- Status: Accepted
- Boundary: TB4. Elements: P9, D3. STRIDE: Denial of service.
- Frameworks: none applies directly.
- Threat: an interrupt between partial writes leaves a log that does not end
  in a newline; every later append refuses that log until it is repaired.
- Controls:
  - [test] A log that does not end in a newline is refused rather than extended: `tests/test_audit_files.py::test_log_ending_without_newline_refused`
- Residual: accepted for the laboratory scope (see
  [Risk acceptance](#risk-acceptance)). Refusing is the fail-closed choice; repair is manual.

### T27 Compromised Python dependency

- Status: Open
- Boundary: TB5. Elements: D6. STRIDE: Tampering.
- Frameworks: LLM04:2026; Agentic 2026: ASI04; ATLAS 2026.09: AML.T0010.001
- Threat: a malicious or substituted package version runs inside the
  project, in CI or on a developer machine.
- Controls:
  - [config] CI installs only the hash-pinned lock with `--require-hashes`, then runs `pip check` (DD-025): `requirements/ci.lock`, `.github/workflows/ci.yml`
- Residual: open. CI is hash-pinned, but no test checks that the workflow
  keeps using the lock, and the README developer install
  (`pip install -e ".[dev]"`) resolves current versions at install time
  without hashes. The developer-machine exposure is not accepted. Planned
  fix, separately authorized: make the hash-pinned locked install the
  recommended developer workflow in the README, not an optional alternative.
  CI also downloads one binary outside the lock: gitleaks v8.30.1 for the
  `secrets` job (DD-028), checked against a SHA-256 taken from that
  release's checksums file and run only in that job, with a read-only token.

### T28 CI takeover from a pull request

- Status: Accepted
- Boundary: TB6. Elements: E6. STRIDE: Elevation of privilege.
- Frameworks: none applies directly.
- Threat: a pull request runs code with write access or secrets, or a
  third-party action is replaced.
- Controls:
  - [config] `pull_request` only, never `pull_request_target`; a read-only token; no secrets; no stored checkout credentials; actions pinned by commit SHA; no cache or uploaded artifacts (DD-025): `.github/workflows/ci.yml`
  - [policy] Branch protection and the repository's Actions settings are managed by the owner outside the repository.
- Residual: accepted for the laboratory scope (see
  [Risk acceptance](#risk-acceptance)). The properties hold in the committed workflow
  and were checked in review, but no test checks them, so a later change
  that weakens the workflow is caught only by review.

### T29 Hidden or deceptive source changes

- Status: Partial
- Boundary: TB6. Elements: E6. STRIDE: Tampering.
- Frameworks: none applies directly.
- Threat: a change hides code or text from reviewers with bidirectional
  controls, invisible characters or other look-alike text (Trojan Source).
- Controls:
  - [test] Every tracked text file is checked for format, separator, surrogate, private-use and stray control characters: `tests/test_source_hygiene.py::test_tracked_text_files_hold_no_forbidden_characters`, `tests/test_source_hygiene.py::test_forbidden_character_in_a_tracked_file_is_reported`
  - [policy] Every change goes through a pull request and review (`CLAUDE.md`).
- Residual: confusable characters that are not in those categories (for
  example homoglyphs) and deceptive logic are caught only by review.

### T30 Real or sensitive data committed

- Status: Open
- Boundary: TB6. Elements: E6. STRIDE: Information disclosure.
- Frameworks: LLM02:2026
- Threat: a real alert, host name, address, credential or personal data is
  committed to the public repository.
- Controls:
  - [policy] Synthetic or public data only, and never secrets, `.env` or `logs/` (`CLAUDE.md`, hard rule 1 and Conventions).
  - [config] `.gitignore` excludes `.env` and `logs/`: `.gitignore`
- Residual: open. Nothing scans commits for secrets or real data, so rule 1
  and review are the only safeguards. Committing real or sensitive data to a
  public repository is not accepted as a residual risk; this stays open until
  scanning is in place, which is planned before the labeled evaluation
  dataset is created.

## Not applicable

| Framework entry | Reason |
|---|---|
| Agentic 2026: ASI03 Identity and Privilege Abuse | The agent holds no credentials or identity and acts for no user |
| Agentic 2026: ASI05 Unexpected Code Execution | No tool executes code; triage parses JSON only; the one YAML parser is `yaml.safe_load` in a build script |
| Agentic 2026: ASI07 Insecure Inter-Agent Communication | There is one agent and no other agent to talk to |
| Agentic 2026: ASI10 Rogue Agents | A run is bounded, has no persistence and no state-changing tools |
| Agentic 2026: ASI06, memory | No memory persists across runs; in-run context poisoning is covered by T03, T06 and T18 |
| STRIDE Spoofing of the operator (E2) | The operator is trusted; anyone with the operator's account is out of scope |

## Risk acceptance

Accepted means laboratory-level acceptance: the residual risk was judged
acceptable, in the design review of this document, for the synthetic,
non-production laboratory scope stated in the README, for the reason given.
It is not a formal risk acceptance by a risk owner, and it does not extend to
production use, real alert data or a real inventory. Each item is reviewed
again before any of those, or before the service is built. The table says
what kind of acceptance each one is, so that a missing test is not mistaken
for an accepted vulnerability.

| Item | Kind | Accepted residual risk | Why it is acceptable in this scope |
|---|---|---|---|
| T14 | No security boundary crossed in this scope | Injected text can make the model repeat its context in the summary | The context holds the alert, public reference data and the synthetic inventory, and no secrets; the summary goes to the same operator who supplied the alert. Remote-image and link exfiltration through the rendered summary is covered by T15 |
| T26 | Known defect that fails closed | An interrupt during an append can leave a partial line; later appends refuse the log until it is repaired by hand | Only the operator's account can interrupt the process. Refusing is the fail-closed choice: no record is silently lost or merged |
| T28 | Coverage gap; the control is in place | No test checks the workflow's security properties | The properties were verified in review and in the CI runs; a weakening change is a pull request that review must catch |
| - | Latent defect, not reachable today | Lone surrogates in model tool arguments make `AgentResult.model_dump_json()` raise | No code path calls it today; it is to be fixed in the service milestone, whose code will call it |
| - | Platform limitation that fails closed | Windows runs without an audit log or `--out` | The CLI refuses those options there rather than write unsafely, and the README says so |

Not accepted, and Open: T18 (unpinned, unverified KEV source and unverified
reference data), T27 (unpinned developer install) and T30 (real or sensitive
data committed to the public repository, until scanning is in place).

## Residual risks and open findings

| Item | Threat | Status | Planned handling |
|---|---|---|---|
| Real libraries' offline behaviour checked only by hand, in the slow tests; a library release could change it | T20 | Partial | Repeat the slow tests on every dependency change |
| Tools' read-only behaviour established by review, not by a test | T02 | Partial | None planned yet |
| Free text not checked against its sources | T01, T08 | Partial | Measured in the planned evaluation |
| Tripwire evadable; injection tests non-adaptive | T01 | Partial | Evaluation set with injection cases |
| Severity protected, narrative not | T04 | Partial | Evaluation set |
| Plain http to the model server; no untrusted-certificate test | T10 | Partial | Revisit if the model server leaves the host |
| Runbook threshold not calibrated | T19 | Partial | Evaluation |
| KEV source unpinned and unverified; snapshots and runbooks not checked on load; runbook text not datamarked | T18 | Open | Pinned upstream revision, verified source hash, reviewed data updates (separate authorization) |
| Audit log not tamper-evident | T22 | Partial | Revisit with the service |
| Partial output file after a crash | T24 | Partial | None planned |
| Developer install not hash-pinned; CI use of the lock not tested | T27 | Open | Locked install as the recommended developer workflow (separate authorization) |
| Workflow security properties not tested | T28 | Accepted | Workflow-properties test (separate authorization) |
| No secret or real-data scanning | T30 | Open | Secret and real-data scanning, before the labeled evaluation dataset is created |
| Interrupted append blocks later runs | T26 | Accepted | Manual repair |
| Non-CommonMark renderers | T15 | Partial | None planned |
| Lone surrogates in model tool arguments make `AgentResult.model_dump_json()` raise; the CLI never calls it | - | Accepted | Fix with the service |
| Windows runs without an audit log or `--out` | - | Accepted | None planned |

## Future attack surfaces

Modelled when each is designed, not before:

- The HTTP service: authentication, rate limits, request size limits, tenant
  separation and the audit writer called from a long-running process.
- Docker packaging: base image provenance, user and filesystem permissions.
- The optional Claude API backend: credentials, data sent off the host,
  provider-side retention.
- A production Wazuh integration: real alert volumes, real inventory data and
  write access that the agent itself must still not have.
