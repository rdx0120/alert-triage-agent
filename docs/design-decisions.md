# Design decisions

Each record states the context, the decision, and its consequences, including
the costs accepted. Records are numbered in the order they were made; a
superseded decision is marked rather than deleted.

---

## DD-001: The agent cannot change state

**Context.** The agent reads attacker-influenced text such as command lines,
usernames and file paths. Prompt-injection defenses reduce the chance that such
text redirects the model, but none eliminate it. An agent that combines
untrusted input, access to sensitive context and the ability to act is the
highest-risk configuration (Meta's "Agents Rule of Two"; Willison's "lethal
trifecta").

**Decision.** No tool writes, deletes, executes commands or makes network calls
at triage time. Containment steps are returned as suggestions, and the output
schema only accepts `requires_human_approval: true`.

**Consequences.** Injected text cannot make the system change anything, because
no available tool is capable of it. This narrows the impact of injection; it
does not remove it. A successful injection can still:

- produce a wrong or downgraded verdict that an analyst trusts and acts on, or
  dismisses;
- place links or markup in the summary that could expose context to a third
  party if a client renders them;
- drive excessive model and tool usage.

These residual risks are the focus of the remaining controls: output
validation and severity floors (planned), usage caps (planned), and the threat
model. Every recommendation still needs an analyst to act on it.

---

## DD-002: A single gateway for all tool calls

**Context.** The model chooses which tools to call and with which arguments.
Arguments may be derived from untrusted alert content.

**Decision.** The model can only request a tool by name. `run_tool()` checks
the name against an allow-list, validates arguments against a Pydantic model
with strict patterns (for example, hostnames), converts every exception into an
error result, and stamps each result with a deterministic evidence ID.
Validation errors name the failing field but do not repeat the input.

**Consequences.** One choke point to test and audit. Injected text such as
`PC01; ignore previous instructions` is rejected before it reaches a lookup and
is not reflected back to the model. Each new tool needs an argument model.

---

## DD-003: An empty result is never a success

**Context.** A common failure in security tooling is a control that completes
without error but had no data to work with: a rule that never fires, a scan that
reaches a fraction of its targets. In an LLM pipeline, a missing lookup invites
the model to fill the gap with a plausible guess.

**Decision.** `ToolResult` enforces that status `ok` always carries data.
Failed, empty and unknown lookups return `error`, `not_found` or
`invalid_input` with no data. The summary schema has explicit `unknown`
confidence values and a `missing_data` list.

**Consequences.** More alerts will be reported as having insufficient data.
That is the intended behaviour: the summary states what could not be checked.

---

## DD-004: Local, versioned snapshots instead of live APIs

**Context.** Tool lookups that call external APIs at triage time make results
irreproducible, add a network path an attacker could influence, and are subject
to rate limits.

**Decision.** ATT&CK, KEV/EPSS and the asset inventory are read from local files
built ahead of time by `scripts/`. ATT&CK is pinned to release v20.0; each
snapshot records its source version, build time and, where available, a content
hash.

**Consequences.** Lookups are reproducible across evaluation runs, and the tools
make no outbound calls. The only network traffic during triage is the request
to the configured model backend. Snapshots go stale until they are rebuilt.

---

## DD-005: Retired ATT&CK IDs are tracked with their replacements

**Context.** ATT&CK revokes and deprecates techniques between releases. A lookup
that only knows current IDs cannot distinguish an outdated ID from an invented
one.

**Decision.** The ATT&CK snapshot keeps revoked and deprecated IDs together with
the replacement recorded by STIX `revoked-by` relationships. Looking up
`T1562.001` returns "revoked; replaced by T1685". A test checks every vendored
rule tag and runbook header against current ATT&CK.

**Consequences.** Model output can be validated against the real dataset, and
drift in the vendored detection content is caught by tests. When this was first
built, it identified one rule tagged with a revoked technique, which was
corrected upstream.

---

## DD-006: Runbook retrieval uses section chunks, exact search and a score cutoff

**Context.** The runbook corpus is small: seven runbooks, about forty sections.
Analysts read runbooks by section ("Triage steps", "Known false positives").

**Decision.** Runbooks are split at `##` headings, embedded with
all-MiniLM-L6-v2, and searched with FAISS `IndexFlatIP` (exact cosine
similarity on normalized vectors). Results below a minimum score are dropped; if
none remain, the tool returns `not_found`.

**Consequences.** Exact search is instant at this size, so approximate indexes
or a vector database would add complexity without benefit. The cutoff reduces the
chance of irrelevant sections being presented as guidance. Its value (0.30) is
provisional until calibrated against the evaluation set.

---

## DD-007: A deterministic embedder for the test suite

**Context.** The real embedding model is a ~90 MB download and its scores vary
slightly across library versions, which makes tests slow and non-deterministic.

**Decision.** The default test suite uses a hashing (bag-of-words) embedder with
no external downloads. Tests that exercise the real model are marked `slow` and
run separately.

**Consequences.** The default suite runs offline and gives identical results on
every machine. It verifies the retrieval pipeline, not retrieval quality; the
`slow` tests cover the latter.

---

## DD-008: Local model first, measured against a rule-based baseline

**Context.** The value of an LLM in triage has to be demonstrated, not assumed.
Local inference keeps alert data on the host and has no per-call cost.

**Decision.** Model backends sit behind one interface. The first backend is a
local model served by Ollama; a hosted API backend is optional. A rule-based
backend maps rule tags to techniques and rule levels to severity without any
model; it serves as the offline backend for CI and as the evaluation baseline.

**Consequences.** Results will be reported against the baseline, including any
metric where the LLM does not improve on it. Local models are weaker at tool
calling than hosted frontier models, which is expected to lower scores.

---

## DD-009: The model endpoint is never exposed; evaluation runs beside it

**Context.** The local model server runs on a private network. Ollama's API has
no authentication by default.

**Decision.** The model server is never published to the internet. Evaluation
and integration runs execute on the same private network, from a clean clone of
this repository.

**Consequences.** No unauthenticated inference endpoint is exposed, and running
from a clean clone confirms the project works from its documented setup alone.
Evaluation requires access to that network.

---

## DD-010: Support Python 3.11 and later; do not pin a single version

**Context.** The development and evaluation environments run different Python
versions (3.13 and 3.12, the Ubuntu 24.04 default).

**Decision.** `pyproject.toml` declares `requires-python = ">=3.11"`. CI will
run the test suite on 3.12 and 3.13.

**Consequences.** No environment needs a non-default Python install, and both
versions are verified. The container image will still pin one version, chosen
when packaging is added.

---

## DD-011: Alert ingestion separates trusted rule metadata from untrusted event data

**Context.** Alerts arrive from Wazuh (4.x JSON) or as Sigma rule matches. The
rule ID, level and ATT&CK mapping come from the detection rule set; event data
(command lines, usernames, paths, log text) is attacker-influenced. The rule
title sits in between: Wazuh rule descriptions can embed decoded event fields
through `$(field)` substitution. The rule level becomes the severity floor, so
it must not be guessed.

**Decision.** The caller states the input format; there is no auto-detection.
An alert is rejected if its rule ID, title or level is missing or invalid.
Wazuh levels map to severities as 0-3 informational, 4-6 low, 7-9 medium,
10-13 high and 14-16 critical, following Wazuh's level descriptions. Technique
IDs are read only from rule metadata and CVEs only from the scanner's
vulnerability field, never by matching event text. Event data is copied
verbatim within size limits: 256 KiB per raw alert (checked before parsing;
enough for a maximum-length Windows command line recorded twice), nesting depth
5, 50 fields, 4,096 characters per field and 64 characters for timestamps.
Values that would otherwise force a rejection without being essential, such as
an over-long rule title, a malformed hostname or more than 20 tags, are
truncated or left empty and recorded in `ingest_warnings`, using fixed messages
that never repeat input values. Correlated Sigma matches become one alert that
carries the match count, first and last timestamps and distinct-value counts;
a field that varies across the correlated events is not reported as the
alert's user or host.

**Consequences.** Event text cannot add techniques or CVEs, cannot change the
rule level recorded on the alert, and cannot reach tool lookups through the
host field. (Keeping the final severity at or above that level is a separate,
planned output control.) Attacker-influenced values cannot get an alert
rejected by being too long. Evidence is preserved exactly as received,
including any injection attempt, so analysts and later guardrails can see it.
Alerts without usable rule metadata are refused rather than triaged on a
guessed severity; a refusal is an error the caller must report, never a silent
drop. Other input formats, such as Wazuh 5.x findings, need their own
normalizer.

---

## DD-012: Deterministic enrichment before the model, with explicit gaps

**Context.** Triage needs the same context for every alert: ATT&CK details,
asset context, KEV/EPSS data and the relevant runbook. Letting the model decide
which lookups to run makes results vary between runs and lets attacker-worded
alert text influence what is looked up. A lookup that finds nothing and a
lookup that fails must also not look the same.

**Decision.** Code runs a fixed sequence of read-only lookups before any model
call: up to 5 techniques from the rule's ATT&CK mapping, the asset if the alert
has a valid host, up to 5 CVEs from the scanner field, and one runbook search
returning up to 3 results. Lookup arguments come only from rule metadata and
allow-listed identifiers. The runbook query is built from the ATT&CK lookup
results (ID and technique name), never from alert text. A retired technique is
resolved by following its recorded replacements (up to 3 steps), and every
lookup in the chain is kept as evidence. Every result goes into one evidence
log per triage run. Evidence IDs are deterministic and carry 64 bits of
SHA-256; the log de-duplicates on the exact tool and arguments, and an ID that
would identify two different lookups raises an error instead of being shared.
Anything that could not be determined is recorded as a gap with a fixed kind
and reason (not on the alert, not found, over the cap, lookup failed, invalid
input) and the evidence ID it came from. A failed lookup marks the enrichment
`degraded`; "not found", such as a host missing from the inventory, is a
finding and leaves it `complete`.

**Consequences.** The same alert always produces the same evidence, so
evaluation runs are reproducible and later output checks have a fixed set of
evidence IDs to validate citations against. Attacker text cannot choose which
lookups run or which runbook guidance is retrieved. Building the runbook query
from technique names alone can rank a related runbook first; enrichment returns
up to 3 results, and retrieval quality is measured with
`scripts/runbook_retrieval_report.py` rather than assumed. Enrichment collects
facts only; severity decisions belong to the output controls.

---

## DD-013: One agent loop with fixed budgets; the model returns a draft, not a verdict

**Context.** DD-008 puts every model behind one interface and adds a
rule-based baseline. The model reads attacker-influenced alert text, so the
number of model calls, the tools it can request and the size of what it is
sent have to be bounded by code. When a prompt is longer than the context
window, Ollama truncates it and records only a server-side warning, so a
context limit that code does not enforce fails silently. The checks that make
a model's findings trustworthy (citations, ATT&CK validation, a severity floor)
belong to a later milestone.

**Decision.** Our code runs one agent loop; each backend implements a single
`chat()` call. A run has two phases: up to 4 investigation turns in which the
model may request the four read-only tools through the run's evidence log (at
most 6 tool calls, 3 per turn), then one final call without tools whose reply
must match the `ModelDraft` schema, with one repair attempt. The final call
and the repair are reserved within the limit of 6 model calls. Every request
is measured in UTF-8 bytes exactly as serialized; counting at most one token
per byte plus fixed template allowances, it must leave room for 1,024 output
tokens in a 32,768-token context. Alert data, enrichment results, tool results
and the model's tool calls enter the prompt as views with fixed byte caps, so
a worst-case alert fits by construction; a test builds that case, and a
runtime check stops an over-budget request before it is sent. Untrusted alert
text has its own section, which the instructions describe as data. Each
finding in the draft cites evidence IDs, the alert fields it relies on, or
both, and the draft has no field that closes or dismisses an alert. Each
evidence ID is recorded as coming from enrichment or from a model request. A
run ends with one of four stop reasons (`completed`, `budget_exceeded`,
`backend_error`, `invalid_output`); backend errors are not retried. The
rule-based baseline is a backend: it requests no tools, takes the technique
from enrichment and the severity from the rule level, and cites the alert
fields and lookups it used. Tools still make no network calls; only a model
backend reaches the model endpoint (DD-001, DD-009).

**Consequences.** A model cannot make unbounded calls or tool requests, and
alert text can neither push evidence out of the context window unnoticed nor
get an alert refused for being too large. The byte bound is conservative, so
the context size is larger than typical prompts need; it and the time limits
(900 seconds per run, 300 per request) are starting values to be confirmed on
the evaluation host. The model sees capped views: a long event field is
truncated in the prompt, while the full event stays on the alert.
Model-requested lookups can steer the draft, for example by retrieving a
runbook's false-positive guidance out of context; the draft is unchecked model
output until the output guardrails exist, and nothing at this stage treats it
as a verdict. A single-call mode with no tool calls lets evaluation compare the
model with and without investigation.
