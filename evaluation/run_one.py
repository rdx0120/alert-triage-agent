"""Run the unchanged triage command line once, and record which runbooks enrichment returned.

The harness starts this file once per run, in a fresh process:

    python -s -B -P <clone>/evaluation/run_one.py --clone <clone> --hits-out <file> -- <CLI argv>

It observes triage.cli.run_agent without changing what it does: the
original is called with the same arguments and its result is returned
unchanged. Only the runbook names of the enrichment search are recorded,
because the summary does not carry them; no score, section or text is kept.

This file imports only the standard library and triage, so it can be
reviewed on its own.
"""

from __future__ import annotations

import json
import os
import sys

WRAPPER_FAILURE = 70


class WrapperError(Exception):
    """The wrapper could not do its own job; the run is a defect, never an outcome."""


def hits_record(result, *, calls: int) -> dict:
    """The hits record for an observed AgentResult, or for none (result is None)."""
    if result is None:
        return {"calls": calls, "run_id": None, "runbook_hits": None}
    searches = [r for r in result.tool_records
                if r.tool == "runbook_search" and r.requested_by == "enrichment"]
    if len(searches) > 1:
        raise WrapperError("more than one enrichment runbook search")
    hits: list[str] = []
    if searches:
        record = searches[0]
        matches = [e for e in result.enrichment.evidence if e.evidence_id == record.evidence_id]
        if len(matches) != 1:
            raise WrapperError("the enrichment search has no single evidence entry")
        evidence = matches[0]
        if evidence.status == "ok":
            hits = [hit["runbook"] for hit in evidence.data["hits"]]
    return {"calls": calls, "run_id": result.run_id, "runbook_hits": hits}


def _fail(message: str) -> int:
    print(f"run_one: error: {message}", file=sys.stderr)
    return WRAPPER_FAILURE


def _write_hits(path: str, record: dict) -> None:
    from triage import files
    data = json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii") + b"\n"
    parent = os.path.dirname(path)
    # Mode 0600 at creation, O_EXCL, no link followed, synced.
    dir_fd = files.open_private_dir(parent, what="hits", create=False)
    try:
        files.write_new_files(dir_fd, parent, [(os.path.basename(path), data)], what="hits")
    finally:
        os.close(dir_fd)


def main(argv: list[str]) -> int:
    if len(argv) < 5 or argv[0] != "--clone" or argv[2] != "--hits-out" or argv[4] != "--":
        return _fail("invalid arguments")
    clone, hits_out, cli_argv = argv[1], argv[3], argv[5:]
    own_root = os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if clone != own_root:
        return _fail("--clone is not the clone this wrapper runs from")
    # With -P nothing else was prepended; the clean-tree check guarantees the
    # clone root holds only tracked files and two allowed ignored directories.
    sys.path.insert(0, clone)
    try:
        import triage
        import triage.cli as cli
    except Exception:
        return _fail("triage could not be imported")
    if not os.path.realpath(triage.__file__).startswith(clone + os.sep):
        return _fail("triage does not resolve inside the clone")

    original = cli.run_agent
    observed: list = []

    def observer(*args, **kwargs):
        result = original(*args, **kwargs)
        observed.append(result)
        return result

    cli.run_agent = observer
    code = cli.main(cli_argv)
    if len(observed) > 1:
        return _fail("run_agent was called more than once")
    try:
        record = hits_record(observed[0] if observed else None, calls=len(observed))
        _write_hits(hits_out, record)
    except Exception:
        return _fail("the hits record could not be written")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
