"""Run classification: a pure function from what the runner observed to a run class.

Every started run gets an H record and a run_end ledger entry, so the ledger
stays valid. When what was observed is a defect of the code or the runner
(the wrapper's own failure, an unreadable output, a missing hits record),
the run is recorded as no_output and the defect is carried by the pass
class instead. A run is never retried.
"""

from __future__ import annotations

from dataclasses import dataclass

from evaluation import records
from evaluation.common import EvaluationError

CLI_EXIT_CODES = (1, 2, 3, 4, 5, 130)
WRAPPER_FAILURE = 70
PASS_RANK = {"complete": 0, "incomplete": 1, "defective": 2, "void": 3}


@dataclass(frozen=True)
class Observed:
    exit_status: int | None
    signal: int | None
    deadline: bool
    interrupted: bool
    stdout: bytes
    hits: dict | None        # the parsed hits record, or None if absent or invalid
    runner_error: bool       # the runner failed while the run was in flight


@dataclass(frozen=True)
class Result:
    run_class: str           # "outcome" or "no_output"
    reason: str | None       # null exactly for outcome
    pass_cause: str | None   # "defective", "incomplete" or None


def _summary_ok(stdout: bytes) -> bool:
    try:
        records.load_summary(stdout)
    except EvaluationError:
        return False
    return True


def classify(o: Observed) -> Result:
    """The first matching row decides."""
    if o.runner_error:
        return Result("no_output", "signal" if o.signal is not None else "exit", "defective")
    if o.interrupted:
        return Result("no_output", "interrupted", "incomplete")
    if o.deadline:
        return Result("no_output", "deadline", None)
    if o.signal is not None:
        return Result("no_output", "signal", None)
    if o.exit_status == WRAPPER_FAILURE:
        return Result("no_output", "exit", "defective")
    if o.exit_status != 0 and o.exit_status not in CLI_EXIT_CODES:
        return Result("no_output", "exit", "defective")
    if o.hits is None:
        return Result("no_output", "exit", "defective")
    if o.exit_status == 0:
        if _summary_ok(o.stdout):
            return Result("outcome", None, None)
        return Result("no_output", "exit", "defective")
    return Result("no_output", "exit", None)


def worst(*classes: str) -> str:
    return max(classes, key=lambda c: PASS_RANK[c])
