# Design decisions

Short records of the choices behind this project: what was decided, why, what it
costs, and how to explain it in one or two sentences. Newest at the bottom.

---

## D1. The agent is read-only

**Decision.** The agent can look things up but cannot change anything: no tool writes,
deletes, executes commands or calls the network while triaging. Containment steps are
suggestions with `requires_human_approval: true`, and the schema rejects `false`.

**Why.** The agent reads attacker-controlled text (command lines, usernames, file
paths). If that text contains instructions ("ignore previous instructions…"), the worst
case should be a wrong summary, not a wrong action. Meta's "Agents Rule of Two" makes the
same point: an agent should have at most two of (untrusted input, sensitive data,
ability to change state). This one has the first two and is denied the third.

**Trade-off.** Less automation. An analyst still has to act on every recommendation.

**Interview answer.** "I assumed prompt injection would sometimes succeed, so I removed
the agent's ability to do anything with it. The remaining risk is a misleading summary,
and the other controls target that."

---

## D2. One gateway for every tool call

**Decision.** The model never calls Python functions directly. It asks for a tool by
name, and `run_tool()` checks the name against an allow-list, validates the arguments
with Pydantic, catches every exception, and stamps the result with an evidence ID.

**Why.** One choke point is easier to test and audit than four tools that each validate
themselves. Strict argument patterns stop injected text from reaching a lookup (a host
value like `PC01; ignore previous instructions` is rejected), and error messages don't
echo the untrusted input back to the model.

**Trade-off.** Adding a tool means writing an argument model, which is a little extra code.

**Interview answer.** "Tool calls go through an allow-list and schema validation, the
same way you'd treat any API input from an untrusted client."

---

## D3. Empty is never success

**Decision.** A tool result marked `ok` must contain data. Errors, empty results and
unknown records come back as `error`, `not_found` or `invalid_input`, and a validator
enforces that pairing.

**Why.** The failure I've seen most in security tooling is a control that runs cleanly
and finds nothing because it never had the data: a rule that never fired, a scan that
reached a fraction of its targets. If a lookup comes back empty, the summary must say
"unknown", not let the model guess.

**Trade-off.** More results end up as "insufficient data", which looks less impressive
but is more honest.

**Interview answer.** "Silence is not success. The agent has to say what it couldn't
check, and that's enforced by a schema rule, not by asking the model nicely."

---

## D4. Local snapshots instead of live APIs

**Decision.** ATT&CK, KEV/EPSS and the asset inventory are read from local files built
ahead of time by `scripts/`. ATT&CK is pinned to release v20.0, and each snapshot
records its source version and hash.

**Why.** Reproducible evals (the same input gives the same lookups next month), no
network access at triage time (one less way to leak data or be steered to an
attacker's URL), and no rate limits.

**Trade-off.** Data goes stale until the scripts are re-run.

**Interview answer.** "Triage is offline and deterministic on the lookup side, so when
results change I know it was the model, not the data."

---

## D5. Retired ATT&CK IDs are tracked, not just dropped

**Decision.** The ATT&CK snapshot keeps revoked and deprecated IDs with their
replacement. Looking up `T1562.001` returns "revoked; replaced by T1685".

**Why.** It separates an outdated ID from an invented one. Building it surfaced a real
issue: one of my own Sigma rules was tagged with a technique ATT&CK had since revoked.
A test now checks every vendored rule tag and runbook header against current ATT&CK.

**Trade-off.** None worth noting.

**Interview answer.** "Validating the model's technique IDs against the real ATT&CK data
caught drift in my own detection content before it caught the model."

---

## D6. Runbook retrieval: section chunks, exact search, a score cutoff

**Decision.** Each runbook is split at its `##` headings, embedded with
all-MiniLM-L6-v2, and searched with FAISS `IndexFlatIP` (exact cosine similarity).
Results below a minimum score are dropped, and if nothing is left the tool returns
`not_found`.

**Why.** Sections match how an analyst reads a runbook ("Triage steps", "Known false
positives"). With ~40 chunks, exact search is instant, so approximate indexes or a
vector database would add complexity for nothing. The cutoff stops the tool from
returning the least-bad irrelevant runbook.

**Trade-off.** The cutoff value needs calibration on the eval set; until then it's a guess.

**Interview answer.** "It's RAG at the scale the problem needs: exact search over a few
dozen chunks, and it says 'no match' rather than returning noise."

---

## D7. A fake embedder for tests

**Decision.** Tests use a word-hashing embedder that needs no model download. Real
retrieval tests with MiniLM are marked `slow` and run separately.

**Why.** The fast suite runs offline and gives the same answer every time, in CI or on
any machine.

**Trade-off.** The fast suite only proves the retrieval plumbing works, not that MiniLM
retrieves well. The `slow` tests cover that.

**Interview answer.** "I separated testing the pipeline from testing the model, so CI
stays fast and deterministic."

---

## D8. Ollama first, with a rule-based baseline

**Decision.** The first model backend is a local model through Ollama; the Claude API
comes later behind the same interface. There is also a `heuristic` backend that maps
rule tags to techniques and rule levels to severity, with no LLM.

**Why.** Ollama costs nothing per run and keeps alert data local. The heuristic backend
lets CI run without any model, and it's the baseline: if the LLM can't beat a few lines
of rules on some metric, the README says so.

**Trade-off.** Local models are weaker at tool calling than frontier APIs, so scores
will be lower. That's a finding to report, not hide.

**Interview answer.** "I measured the LLM against a dumb baseline, because 'uses an LLM'
isn't a result."

---

## D9. Develop in the cloud, evaluate next to the model

**Decision.** Code and tests are written in Claude Code cloud sessions. Final
integration and eval runs happen on a separate Ubuntu VM that hosts Ollama, by cloning
the repo there.

**Why.** Cloud sessions can't reach a private home-lab network. Exposing Ollama to the
internet to bridge that gap would publish an unauthenticated API, so the code goes to
the model instead. Running the eval from a plain clone also proves the project works
without the tools used to build it.

**Trade-off.** Eval runs need a few manual commands on the VM.

**Interview answer.** "The model server never leaves my lab network; the eval runs
next to it from a clean clone."

---

## D10. Python versions: support 3.11+, don't pin

**Decision.** `pyproject.toml` keeps `requires-python = ">=3.11"`. Development
runs on Python 3.13 (cloud VM) and the evaluation VM runs 3.12 (Ubuntu 24.04's
default). From weekend 2, CI runs the test suite on both 3.12 and 3.13.

**Why.** Pinning one version would force an extra Python install on one of the
two machines. Testing both proves the code doesn't depend on either.

**Trade-off.** Two CI jobs instead of one. The Docker image will still pin a
single version; that choice is made in weekend 2.

**Interview answer.** "I support the Python versions my environments actually
run and test both in CI, rather than pinning to whichever one I happened to
develop on."
