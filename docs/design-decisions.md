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
that never repeat input values. Invalid UTF-8 bytes and unpaired UTF-16
surrogates are replaced with U+FFFD rather than rejected, and when a JSON
object repeats a key, including two keys that become identical after
replacement, the first value is kept; both are counted in `ingest_warnings`.
Correlated Sigma matches become one alert that carries the match count, first
and last timestamps and distinct-value counts; a field that varies across the
correlated events is not reported as the alert's user or host.

**Consequences.** Event text cannot add techniques or CVEs, cannot change the
rule level recorded on the alert, and cannot reach tool lookups through the
host field. (Keeping the final severity at or above that level is a separate,
planned output control.) Attacker-influenced values cannot get an alert
rejected by being too long or by containing text that is not valid Unicode.
Evidence is preserved exactly as received, including any injection attempt, so
analysts and later guardrails can see it. The exceptions are undecodable bytes
and unpaired surrogates, which become U+FFFD (the source SIEM keeps the
original), and repeated keys, of which only the first value is kept. Alerts
without usable rule metadata are refused rather than triaged on a guessed
severity; a refusal is an error the caller must report, never a silent drop.
Other input formats, such as Wazuh 5.x findings, need their own normalizer.

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

The citation format and checks are superseded by DD-015.

---

## DD-014: The Ollama adapter is a thin, fail-closed HTTP client with hard deadlines

**Context.** The local model is reached over HTTP on a private network
(DD-009). The adapter is the only code that makes a network call at triage
time, so it decides what leaves the process and what is accepted back. A socket
timeout bounds each wait for data, not a whole request: a server that keeps
sending a byte at a time, or a name lookup that hangs, could hold a request far
past its limit, and the agent run's limit was checked only between model calls.

**Decision.** The adapter uses Python's `http.client`, which has no proxy or
redirect handling, and verifies TLS for `https`. The endpoint must be an `http`
or `https` URL with a host and no credentials, path, query or fragment; any
such host is accepted, so alert data goes wherever `OLLAMA_HOST` points.
Requests carry the messages, tool specs and schema that the context budget
measured, with fixed options: the context and output sizes from DD-013,
temperature 0 and a fixed seed. Each request runs in a worker thread that
keeps the connection's socket from the moment it connects; the caller waits no
longer than the request's deadline, then shuts that socket down, which also
wakes a read blocked on the response body, and reports a backend error. No
more than 2 request workers exist at once; when both are held by requests that
timed out, a new request fails at once instead of starting another. A
request's deadline is the smaller of 300 seconds and the time left in the run,
and the loop checks the run deadline again after every call, so a call that
ends after it stops the run as `budget_exceeded`. A status other than 200, a
reply over 1 MiB, or a reply that is not the expected JSON is a backend error
with a fixed message. Reply bodies are never stored or logged, and errors are
not retried.

**Consequences.** A call to the adapter returns within its deadline whatever
the server does, and unfinished workers cannot accumulate. A worker blocked on
its connection ends as soon as the socket is shut down, but not every worker
is guaranteed to end promptly: one blocked in a name lookup ends when the
system resolver gives up, and while 2 are pending the adapter refuses new
requests, which the run reports as a backend error. The run limit holds for
backends that honour their deadline, as both current backends do; the loop
cannot interrupt a backend that ignores it and can only classify its late
return as `budget_exceeded`. A model that reaches its output limit returns
truncated text, which then fails validation. The model and its options are
chosen on the evaluation host, where the live smoke test also checks that the
prompt token count Ollama reports never exceeds the byte-based bound.

---

## DD-015: Draft citations are drawn from the run's evidence and checked against it

**Context.** A draft is only useful if each finding can be traced to what this
run looked up or to the alert itself. Two private trials on synthetic samples
showed why a schema alone is not enough: with optional citation lists the model
left findings uncited, and with a single list checked only for format it cited
correctly formatted evidence IDs that did not exist. Evidence IDs are
deterministic, so an ID can also be copied into alert text by an attacker.

**Decision.** Every finding lists its sources in one required, non-empty list;
a source is an evidence ID or one of nine alert-field names. Which evidence IDs
are citable is decided from the results this run rendered into the prompt:
technique, severity, step and containment findings may cite only successful
results whose data the model was shown, and missing-data findings may also cite
failed or not-found lookups that were shown. Results from tools outside the
allow-list, results left out of the prompt by its size limits and IDs that
appear only in alert text are never citable. The schema sent with the final and
repair requests lists only the citable IDs and the alert-field names. Every
final and repair reply is then checked against the same set, and an alert field
may be cited only when it has a value, except by missing-data findings. A reply
that fails gets the existing single repair attempt, with fixed hints that ask
for corrected sources rather than deleted findings; a repair that still fails
ends the run as `invalid_output` with no draft. The number of findings in each
attempt is recorded for evaluation and never affects acceptance.

**Consequences.** An accepted draft cannot cite evidence the run did not show
the model, and the check holds even for a backend that ignores the schema.
Whether a cited source actually supports its finding is not checked; that is a
question for evaluation, alongside the planned severity floor and ATT&CK output
controls. A model that cannot cite correctly produces `invalid_output` rather
than a draft with unsupported claims. The schema grows with the number of
citable results; the worst-case budget test covers the largest possible set.

---

## DD-016: Investigation turns have their own output limit and instruction

**Context.** In private runs on synthetic samples, the model often answered an
investigation turn with free text instead of a tool call. That text is
discarded, but it was generated up to the full 1,024-token output limit, which
took minutes on CPU. Final and repair requests have little context headroom
left (DD-015), so any fix must not add to them.

**Decision.** Investigation requests reserve and allow 384 output tokens, enough
for three tool calls with long arguments; final and repair requests keep 1,024.
Each investigation request also ends with a fixed instruction to reply with
tool calls only. The instruction is added to the request and never stored in
the conversation history, so final and repair requests are unchanged in content
and size. Each model call records whether its reply stopped at the output limit;
the record is for evaluation and never changes what the loop does.

**Consequences.** A turn that writes text instead of calling a tool costs at
most 384 output tokens instead of 1,024. A reply that needs more than 384 tokens
for its tool calls is cut off, and its tool calls may be lost; the truncation
record shows how often that happens, and the limit is revisited from real-model
observations. The instruction can be ignored by a model; the output limit still
bounds the cost.

---

## DD-017: Each run records what it did, as metadata

**Context.** An audit log is planned (README, Security controls). It needs to
know, for each run, every model call and lookup in order: timing, size, why a
reply ended, whether it was accepted and why not, and how each lookup result
reached the model. Private runs on synthetic samples showed these are the facts
needed to judge a run, including investigation turns that write text instead of
calling a tool, replies cut at the output limit, and runbook results shortened
in the prompt.

**Decision.** The agent loop records this on `AgentResult` and never writes
files. Each model call records its turn, timing, a SHA-256 digest of the
prompt as the context budget measures it (messages, tool specs and schema, not
the full HTTP body), the backend's finish reason, the kind and size of the
reply with a digest of its text (not its tool calls), the validation outcome
with the sanitized problems, and,
when the call failed, an error type from a closed list. Each lookup records who
requested it, its status, whether it was a repeat, and whether its result was
shown in full, with shortened strings (and at which cap), as a stub, or not at
all. The run records its ID, start time, durations, model name and, for a
budget stop, which limit stopped it. Timing uses a separate clock from the
deadlines, so measuring cannot change when a run stops. No field holds alert
text, prompt text, model text, tool arguments or tool data, and error messages
are still never kept.

**Consequences.** Every run can be reviewed afterwards without re-running it,
and the audit log becomes a projection of this record. Digests let someone
holding a separate transcript check which prompt and reply text a run used;
they do not prove the full HTTP request or the reply's tool calls. Model
text that is never kept cannot be inspected later; capturing content is a
separate, opt-in decision. The fields are observational only: control flow,
limits and acceptance do not read them.

---

## DD-018: The audit log is a metadata-only JSONL projection of the run record

**Context.** DD-017 records what each run did. An audit log must keep that
outside the process for later review, and it will be read and shipped by
people and systems that should not see alert data, prompts or model output.
Log files are also an attack surface: a planted symlink, a FIFO or a
world-writable file can redirect, block or expose what is written.

**Decision.** `triage/audit.py` turns a run record into one JSON line per
operation: the run, each lookup, each model call. Field names follow the
OpenTelemetry GenAI semantic conventions (Development status, as of
semantic-conventions-genai commit `9ffc7e0`), with project fields under
`triage.*` and a schema version. Each record is built from named fields with
a fixed key set. Identifiers are written only if they match strict patterns,
problems only in their sanitized form, and the provider from a closed list.
Prompts, messages, model text, tool arguments, tool data, error messages,
the backend name and the model endpoint are never written. The metadata
records are revalidated first, and any failure writes nothing. Lines are
ASCII-only JSON of bounded size. The file is opened append-only without
following symlinks or blocking on a FIFO, must be a regular file owned by the
user with no group or other permissions, and sits in a directory with the
same ownership and no group or other write access; anything else is refused,
never repaired. `run_agent()` does not write the log: the caller passes the
run's result to `write_audit_log()`, so the loop stays free of file I/O.

**Consequences.** A run can be reviewed and shipped to a log store without
carrying alert data or model output. Digests let a separately kept
transcript be matched to its run; they cover the serialized prompt and the
reply text only. The log is not tamper-evident, assumes one writer per file
and checks only the file and its parent directory; production use needs an
append-only store. Until the CLI and service call the writer for every run, a
run is logged only if its caller writes it. A model name that looks like an
address (an IP address, or a name ending in a digits-only tag such as a port)
is written as null, so the endpoint never reaches the log. Field names may
change while the conventions are in development; the schema version marks
changes.

The summary record and schema version 2 are added in DD-023.

Run-level enum values must be plain strings, and the gaps container a list of
gaps, so a substituted value is refused with the fixed message instead of
being written or raising another error.

Writers no longer have to be one per file: each append holds an exclusive lock
on the file, waiting at most ten seconds for it. The file is opened relative
to a descriptor of its checked directory, so the directory cannot be swapped
between the check and the open; its ancestors are still trusted. A failed
write or sync is rolled back to the file's previous size, and a log whose last
record is partial is refused, not appended to. Before the writer returns,
and while it still holds the lock, the records, the file's entry in its
directory and the directory's entry in its parent are synced to disk on
every append, so no writer relies on another writer's unfinished sync. A
directory another writer created first is checked like any existing one. A
run result whose containers are not the expected types is refused with a
fixed message.

---

## DD-019: Output guardrails turn a run into a summary, and code has the last word

**Context.** An accepted draft cites only evidence the run showed the model
(DD-015), but it is still model output. Injected alert text can argue a
severity down; a model can name a technique that does not exist, is retired,
or was never looked up; and a citation can point at real evidence that says
nothing about the claim. Asset facts and enrichment gaps reach the output
only if the model restates them, and a model can make a lookup fail on
purpose and cite the failure as missing data.

**Decision.** `build_summary()` runs after the agent loop and always returns a
`TriageSummary`. The final severity is never below the detection rule's
level; a lower draft is raised to it, with a fixed rationale and an anomaly.
A technique is kept only if it is current in the local ATT&CK snapshot, was
looked up and shown with its data in this run, and is cited by that lookup or,
for the rule's own techniques, by the rule's tags; otherwise the rule's
technique is used, or none. The asset finding and every enrichment gap come
from code, never the model. A missing-data finding that rests only on lookups
the model made fail is dropped. Every draft citation is re-checked against
the run record before use. Runs that did not complete, or whose draft fails
the re-check, get a fail-closed status and only code-owned findings. Every
finding records whether it came from the rule, enrichment or the model, and
every intervention is recorded as a fixed anomaly code.

**Consequences.** A model can raise severity but never lower it, cannot add an
unknown or unsupported technique, and cannot change what is known about the
asset. Findings that code cannot verify (steps, containment, rationale) are
kept as model output, cite their sources, and are judged in evaluation;
containment still needs human approval. Spotlighting and an injection
tripwire (planned) address the injection itself; this stage limits what a
successful injection can change. The technique's `basis` says what supports
the label (the rule's ATT&CK mapping, a model-requested lookup, or nothing),
never that the behaviour occurred; whether an alert is a true positive is not
decided here.

The planned tripwire and spotlighting are implemented in DD-020 and DD-021.

---

## DD-020: An injection tripwire flags alert text addressed to an AI system and escalates

**Context.** Alert fields such as the rule title, user and event values can be
written by an attacker, and an attacker who knows alerts are triaged by a
model can write text aimed at it. The output guardrails (DD-019) already stop
such text from lowering severity below the rule's level or changing asset
facts, but an injected alert at its rule's level passed unnoticed, and
`injection_suspected` was never set.

**Decision.** `triage/tripwire.py` scans the attacker-writable fields (rule
title, user, timestamp, event keys and string values), each separately,
after Unicode NFKC normalization, removal of invisible format characters,
whitespace collapsing and case-folding. Eight fixed signals cover instruction
overrides, new instructions, prompt exfiltration, role assignment, addressing
an AI, chat markup, verdict steering and requests not to escalate. Only the
signal codes and the field names are recorded, never the matched text. The
scan covers the full canonical alert, not the capped view the prompt shows,
so it detects suspicious content in the alert, not proof that the model saw
or obeyed it. When any signal matches, the summary sets
`injection_suspected`, lists the signals, and raises severity to at least
high with a fixed rationale citing the matched fields; severity already at or
above high is unchanged. Model-derived findings are not changed (DD-019
governs them).

**Consequences.** An alert that tries to talk to the triage model is
escalated and visibly flagged, whatever the model replied and whether or not
the run completed. Patterns are a tripwire, not a classifier: paraphrases
they do not cover pass unflagged, and a benign field that happens to match is
over-escalated, which is the safe direction for a single alert. Raising to
high can add analyst workload, through false positives or through an
attacker deliberately generating noisy alerts; the recorded signals and
fields let analysts and later tuning see why, and the formal evaluation
measures detection and false-positive rates. The tripwire adds no input text
to the summary, but model-derived findings may still quote alert text. The
model still reads the injected text; spotlighting (planned) addresses that.

Spotlighting is implemented in DD-021.

The consistency checks between the patterns, the signal codes and the scanned
fields raise at import, so they also hold under `python -O`.

---

## DD-021: Untrusted alert text is datamarked in the prompt

**Context.** The system prompt tells the model that `untrusted_alert_data`
may be attacker-written, but the text itself reached the model as ordinary
prose, so injected instructions looked like any other instruction. The
tripwire (DD-020) flags such alerts afterwards; it does not change what the
model reads.

**Decision.** In the model's view of untrusted alert text (rule title, user,
timestamp, event keys and values), every whitespace character is replaced by
`ˆ` (U+02C6), following the datamarking form of spotlighting, and the system
prompt says this marks the text as data. Marking is applied before byte
capping, so every cap still bounds the section. The marker is not `^`,
because cmd.exe uses it in caret obfuscation; invisible format characters
such as bidi overrides are kept, because they can be evidence. The alert,
the tripwire, the summary and the audit log are unchanged.

**Consequences.** Injected text in the prompt is visibly different from the
system's instructions. The system prompt grows by 31 bytes, leaving 124
tokens of headroom in the final and repair requests. The kind of whitespace
(tab, newline or space) and a `ˆ` already in the data cannot be told apart in
the model's view; the analyst and the tripwire use the original alert.
Request bytes change for every run, and whether datamarking lowers injection
success for a given model is measured in the formal evaluation.

---

## DD-022: The Markdown summary is a fixed template with every value shown as code

**Context.** The summary holds model text, which can quote attacker-written
alert text, and strings from local data. Rendered as ordinary Markdown in a
ticket, wiki or chat, such text can load a remote image, inject HTML or
links, forge a heading such as "Verdict: benign", or reorder the display
with bidi controls. The output schema bounds free text but not the number of
findings or the length of the technique name and the asset host and owner.

**Decision.** `render_markdown()` produces a fixed template whose only
Markdown is its own text. Free text goes in fenced code blocks opened with a
run of `~` longer than any run in the content; short values go in inline
code spans delimited by a backtick run longer than any in the value.
Control, format, surrogate and line and paragraph separator characters
(categories Cc, Cf, Cs, Zl and Zp, so U+2028 and U+2029 as well) are shown
as `<U+XXXX>`, except a newline inside a fenced block. There are no tables,
because a pipe splits a table cell even inside a code span. Headings label
model output, and a fixed footer states that containment needs human
approval. The summary is revalidated first. Renderer limits (8 next steps,
5 containment suggestions, 30 missing-data items, 9 anomalies, 8 signals,
and 256 characters for the technique name and the asset host and owner) and
a 192 KiB output cap bound the result. A summary over them raises a
fixed-message `ValueError` and is never truncated. The output schema is
unchanged.

**Consequences.** Values are inert in CommonMark and GFM renderers and
cannot create structure; other dialects, such as Slack mrkdwn and Jira wiki
markup, are not covered. Values are harder to read than prose, and literal
text such as `<U+2028>` looks the same as an escaped character. The limits
follow the pipeline's caps and tests tie them together, so a later cap
change must update the renderer. Rendering does not make model text true;
the labels and footer say so. The renderer is called explicitly; calling it
from the CLI and service is planned.

---

## DD-023: The audit log records the guardrails' summary as codes and counts

**Context.** The audit log (DD-018) records what the agent loop did, but not
what the output guardrails decided afterwards: the final severity, the
technique decision, the anomalies and the injection flag. The summary also
holds model text and strings from local data, such as an asset owner, which
can name a person and must not reach the log.

**Decision.** `audit_records()` and `write_audit_log()` take an optional,
keyword-only `summary`. When one is given, a final `triage.summary` record
follows the run's records. It holds only codes, identifiers and counts: the
status; the severity value, rule floor, origin and sources; the technique ID,
basis and origin; the asset criticality and exposure; counts of next steps,
containment suggestions and missing-data items by origin; the anomalies; and
the injection flag and signals. The rationale, steps, actions, missing-data
descriptions, technique name and asset host and owner are never written. The
summary is revalidated and must have the run's alert ID and run ID; otherwise
a fixed-message `ValueError` is raised before anything is written. The record
carries the run's end as its timestamp, because the guardrails are not timed.
`AUDIT_SCHEMA_VERSION` becomes 2.

**Consequences.** A reviewer can see from the log alone what the guardrails
decided and why a run was flagged, without seeing model or alert text. The
other record types are unchanged apart from the version, and each line
carries its own version, so a file can hold version-1 and version-2 records
and a consumer reads the version per line. A caller that has only the run can
still write the log without a summary. The writer is still called explicitly;
writing the log for every run from the CLI and service is planned.

---

## DD-024: The CLI runs one alert end to end, audit first, with fixed errors

**Context.** The renderer and the audit writer existed but nothing called
them, and the evaluation needs one entry point that produces every output the
same way. A command line adds its own risks: messages from argparse,
ingestion or the file layer can echo alert text, paths or the endpoint;
model text on a terminal can carry escape sequences; output files can
collide, be redirected or be left half-written; and several runs can append
to one log at once.

**Decision.** `python -m triage --format {wazuh,sigma} ALERT` reads one alert
(a regular file or standard input, at most 256 KiB), runs the agent and the
guardrails, and prints the summary as one line of ASCII-only JSON. Settings
come only from the environment. The audit log (`logs/audit.jsonl` by
default) is appended before anything is printed or written; `--no-audit-log`
must be given explicitly and is noted on standard error. With `--out DIR`,
`<run_id>.json` and `<run_id>.md` are created exclusively in a checked
directory, all or nothing: on a failure or an interrupt, only the files this
run created are removed. File names come from the run ID, never from alert data. Directories
are checked before the model runs and again when used. Every failure prints
one fixed message, at most with an `errno` name or an exception class name,
and exits with a fixed code: 0 for a produced summary whatever its status, 1
internal, 2 usage or configuration, 3 input, 4 audit log, 5 outputs, 130
interrupted. The audit log and `--out` need POSIX; elsewhere the CLI is
standard output only.

**Consequences.** Every CLI run is audited unless the operator opts out, and
no output exists without its audit record. Error messages carry no detail
from lower layers, so diagnosing a rejected alert needs `load_alert()`
directly. A backend failure is a summary with status `error`, not a CLI
failure. The directories above the log and output directories are trusted,
not checked. The cleanup handles exceptions and interrupts, not crashes: a
`kill -9` or power loss while writing can still leave a partial output file.
Windows can run the CLI only without an audit log and without `--out`; input
files are opened there without the POSIX-only flags, with the same
regular-file check and size limit.

---

## DD-025: CI runs the offline suite read-only, from a hash-pinned lock

**Context.** Every change was tested by hand before review, on one machine
and one Python version. CI runs code from pull requests, which makes it an
attack surface of its own: workflows triggered with write access or secrets
next to untrusted code, unpinned third-party actions, poisoned caches and
expressions that inject text into shell steps are the usual ways in.

**Decision.** One GitHub Actions workflow runs on pushes to `main` and on
pull requests to `main`, never on `pull_request_target` or `workflow_run`.
One job, on `ubuntu-24.04` with Python 3.11, 3.12 and 3.13, installs the
hash-pinned `requirements/ci.lock` with `pip --require-hashes --no-deps`
(the build backend included, so the editable install uses no build
isolation and downloads nothing unpinned), runs `pip check`, the offline
suite, the sample check, the tests with `fcntl` hidden and a console-script
smoke run. The token can only read the repository; no secret is used; the
checkout keeps no credentials; only `actions/checkout` and
`actions/setup-python` are used, each pinned to a full commit SHA of a
release at least 14 days old; no user-controlled expression appears in a
shell step; nothing is cached or uploaded; a step fails the job if any
`OLLAMA_*` variable is set. The lock is generated with `uv pip compile` on
a developer machine; uv is a tool, not a project dependency.

**Consequences.** A pull request from a fork can change the workflow it
runs, but only with a read-only token and no secrets. Dependency versions
change only through a reviewed change to the lock. The slow, Ollama and
model-dependent paths are not covered by CI, nor is Windows. Branch
protection and the repository's Actions settings are configured by the
owner outside the repository; the required checks are added only after
the workflow has reported them. Security scanning is planned with the
service.

---

## DD-026: The threat model cites its evidence, and a test checks the citations

**Context.** The README lists the security controls but not the threats
behind them, what each control leaves uncovered, or what is accepted. A
threat model that cites tests and files drifts as the code changes, and a
status such as "mitigated" means little unless it is tied to evidence. The
frameworks it maps to also change: the 2026 OWASP LLM list renumbers most
2025 entries.

**Decision.** `docs/threat-model.md` identifies threats by following the
data flow across seven trust boundaries, one of them the current run-time
fetch of the embedding model, and classifies each threat with STRIDE. The
classification is threat-driven, not an exhaustive matrix of every element
and category. Each threat has exactly one status from a fixed set, and each
control one evidence class: `[test]`, `[config]` or `[policy]`. Only tested
controls support a Mitigated or Partial status. An Accepted risk is one
judged acceptable for the synthetic laboratory scope only, and the
document states the kind of each acceptance, so that a missing test is
not read as an accepted vulnerability. Framework entries are mapped only where they fit directly, with the edition
in each identifier (OWASP LLM 2026, OWASP Agentic 2026, MITRE ATLAS
2026.09). There are no numeric risk scores. `tests/test_threat_model.py`
checks, with the standard library, that threat IDs are in order, statuses
and evidence classes are from the fixed sets and follow the status rules,
every cited test is defined where cited, every cited path exists, every
framework identifier is a known one, and the document is ASCII.

**Consequences.** Renaming or removing a cited test or file fails the suite
until the document is updated. The test checks references and structure,
not whether a control works: whether a cited test proves its claim remains
a review question. The threat model records findings and does not fix
them. Four threats are open: T18, the unpinned and unverified KEV
source; T20, the embedding model fetched at triage time, which has its
own milestone; T27, the unpinned developer install; and T30, committed
secrets or real data, until scanning is in place. Accepted risks are
accepted at laboratory level only, not as a formal or production risk
acceptance, and are reviewed again before real data, a real inventory or
the service. Moving to a newer framework
edition is a deliberate change to the document and the test's lists.
Planned components are modelled when they are designed.

---

## DD-027: The embedding model is pinned, verified and loaded offline

**Context.** `runbook_search` used `sentence-transformers/all-MiniLM-L6-v2`
by name, so the first triage in a process could contact the Hugging Face Hub
and load whatever the model repository held that day (threat T20). Reading
the libraries showed three further facts. sentence-transformers before 3.4.1
asks the Hub for model information on every load, whatever
`local_files_only` says; a relative path such as `models/all-MiniLM-L6-v2`
is a valid Hub repository ID, while an absolute path is rejected before any
request. huggingface_hub reads its offline switch only once, when it is
imported. And the upstream repository also holds pickle, TensorFlow, ONNX
and OpenVINO weights and a training script, none of which the model needs.

**Decision.** `data/embedding_model.json` pins the repository, the revision
and the license, and lists exactly ten files with their sizes and SHA-256
values, safetensors weights only. Their values were measured from the
downloaded bytes and cross-checked against the Hub's own records: Git blob
IDs for the nine ordinary files, LFS size and SHA-256 for the weights.
`scripts/fetch_embedding_model.py`, run by the operator, is the only code
that contacts the Hub. It requests only those files at that revision,
without a token, with every Hugging Face cache redirected to a temporary
directory, and installs them as new plain files only after each one
matches; anything else installs nothing. At triage time
`triage/embedding_model.py` verifies the directory against the manifest
(exactly those files, regular, no links, no extras) and loads it by its
absolute path with `local_files_only=True`, `trust_remote_code=False` and
`use_safetensors=True`, after setting offline mode before the first import
and refusing to load if the library is not in offline mode. The CLI checks
the directory with its configuration and exits with code 2 if it is missing
or does not match. The dependency floor stays at sentence-transformers 3.0.

**Consequences.** A triage run makes no request to the Hub, and the model
cannot change without a reviewed change to the manifest. The model is now
an explicit installation step; without it the default embedder stops the
CLI with a fixed message, and tests and CI keep using the hashing embedder.
Every process hashes about 90 MB when it first loads the model. The tests in
CI use stand-in libraries and a socket guard; the real libraries' offline
behaviour is checked by slow tests run by hand on the floor and the latest
dependency combinations, so T20 is Partial rather than Mitigated, and those
tests are repeated whenever the dependencies change. The Hub may serve
downloads from its CDN or Xet storage hosts; only the recorded hashes are
trusted. Changing the model or its revision means measuring and reviewing a
new manifest.

---

## DD-028: Every reachable commit is scanned for secrets, and data-bearing files are checked and declared

**Context.** CLAUDE.md rule 1 (synthetic or public data only) and the ban on
committed secrets were enforced only by review (threat T30). A scanner's
own documentation was not enough to rely on. Reading the gitleaks v8.30.1
source showed the following:

- **No merge diffs by default.** Its default `git log` command shows no
  diff for merge commits, so content introduced only by a merge (a conflict
  resolution) is never scanned.
- **The "commits scanned" count** includes commits whose only change
  removes lines.
- **Inline suppression.** A line containing the inline allow comment is
  suppressed unless `--ignore-gitleaks-allow` is passed.
- **Other configuration sources.** Environment variables and the scanned
  directory's own files can replace or narrow the configuration.
- **The ignore file.** `.gitleaksignore` in the scanned directory is always
  loaded, and the whole line is the fingerprint.

Git applies working-tree attributes to every historical commit, so one
`*.json -diff` line would make every JSON change binary and invisible to the
scanner.

**Decision.** A `secrets` CI job, read-only and with no outputs, scans the
full reachable history: `fetch-depth: 0`, every ref and
`--diff-merges=first-parent`.
- **The binary.** It installs the gitleaks v8.30.1 release binary, verified
  against the SHA-256 in that release's checksums file.
- **The invocation.** `scripts/secret_scan.py` runs gitleaks with a fixed
  argument list and environment:
  - the explicit repository `.gitleaks.toml`, which must be exactly the
    default rules;
  - `--ignore-gitleaks-allow`;
  - an empty working directory and ignore path;
  - no system or global git configuration.
- **Refusals before scanning.** The script refuses:
  - a shallow clone;
  - a local attributes file;
  - any `GITLEAKS_*` variable.
- **The controls.** Before the real scan, the same invocation must pass
  fourteen synthetic controls on throwaway repositories, each with
  generated, never-committed tokens:
  - detection;
  - history;
  - merges;
  - unmerged refs;
  - the five-rule panel;
  - the inline comment;
  - an exact ignore;
  - the commit count.
- **The coverage check.** Gitleaks' commit count must equal a count computed
  independently from `git log --numstat` under the same options. A binary
  entry fails closed.
- **The stale-ignore check.** A rescan of a mirror without the ignore file
  must find exactly the ignored fingerprints.

`tests/test_synthetic_data.py` reads every file from the git index and
applies path-class rules (`scripts/synthetic_data.py`):

| Class | Paths | Rules |
|---|---|---|
| Data-bearing | `data/`, `samples/`, `tests/data/`, the vendored fixtures, `eval/` | IP addresses only in documentation or loopback ranges; reserved email and URL domains, plus exact per-file hosts; 555-01xx phone numbers only; no SSN shapes; no binaries |
| Reference | The vendored rules and runbooks | As data-bearing, plus a list of ten public hosts |
| Everything else | Code, tests, docs | The IP and email rules only |

The rules run on every raw line and again on every decoded string of a JSON,
JSONL or YAML file, so an escape such as `\u0038` cannot hide a value. Every
value of a repeated key is checked, not only the last one a parser keeps.
YAML is walked as its node graph, each node once, so an alias that refers back
to itself cannot loop and alias expansion cannot grow. A file of those types
that cannot be decoded completely (malformed, nested too deeply, or holding a
binary scalar) fails in every class. An address is
judged by the address ranges wherever it appears, URL and host fields
included, and no message repeats a rejected value.

Two further rules apply to every tracked file:
- no file holds the inline allow comment;
- no file may be a `.gitattributes`.

`eval/results/` is reserved and rejected until its evaluation-output class
is built.

Each data-bearing and reference file has one entry in `provenance.json`,
with its exact path, content SHA-256, class (synthetic or public) and a
source for public data. `provenance.json` is the only metadata file:
- it declares no hash of itself;
- the commit binds it;
- it is still scanned and schema-checked.

`scripts/build_sample_alerts.py` refreshes only the hashes of the samples
it generates.

**Consequences.**
- **What fails the check:**
  - a secret in any default format, in the added lines of any text file at
    any reachable commit, merges included;
  - a routable address, real email domain or undeclared host in a
    data-bearing file;
  - a data file that is new or edited without its own provenance entry.
- **Limits.**
  - It cannot detect real personal data in free text, or secrets in
    formats no rule knows or in skipped file types.
  - It checks history for secrets only, and checks real-data forms only in
    the current tree.
  - The provenance declaration is true only as far as review makes it.
  - A secret already published stays exposed; rotation is the remedy.
- **The binary** is a CI-only download outside the lock; the project still
  installs and tests without it, and the offline tests use a fake.
- **Upgrading gitleaks** means re-reading its source for these behaviours.
- **Each data change** also changes `provenance.json`.
