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
