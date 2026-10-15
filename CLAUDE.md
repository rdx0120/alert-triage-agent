# Contributor guide for AI coding agents

Engineering rules for automated contributors (e.g. Claude Code) working in this
repository. Human contributors should follow the same rules. Project overview:
`README.md`. Design rationale: `docs/design-decisions.md`.

## Hard rules
1. **Synthetic or public data only.** Never add real alerts, logs, hostnames,
   IP addresses, personal or health data.
2. **Measured results only.** Never invent, estimate or round metrics. Results
   in the README come only from evaluation runs whose raw output is committed.
3. **Read-only agent.** No tool may write, delete, execute or make network calls
   at triage time. Containment suggestions always carry
   `requires_human_approval: true`.
4. **Keep it simple.** Plain, readable Python. No agent frameworks (LangChain,
   LangGraph, CrewAI) or structured-output wrappers (`instructor`). Propose any
   new dependency before adding it.
5. **No dependency on AI tooling.** The project must install, run and test from
   the README alone. Nothing under `.claude/` may be required.

## Conventions
- All tool calls go through `triage/tools/registry.run_tool()`. New tools need a
  Pydantic argument model and tests for the ok, not-found, invalid-input and
  error paths.
- Every guardrail and every fail-closed path has a test.
- Changes with a real design choice are proposed before they are built. Once
  built, record them in `docs/design-decisions.md` (Context, Decision,
  Consequences).
- Comments explain *why*, for a security-engineering reader.
- `vendor/sigma-detection-pack/` is not edited by hand. To update it, re-copy
  from github.com/rdx0120/sigma-detection-pack and update the commit hash in its
  `SOURCE.md`.
- Never commit secrets, `.env`, `logs/` or model files.
- Work on a branch and open a pull request; do not push to `main`. One logical
  change per pull request, with test results in the description.

## Commands
```bash
pip install -e ".[dev]"     # add ,embeddings for semantic runbook search
python -m pytest            # offline suite
python -m pytest -m slow    # real embedding model
```
