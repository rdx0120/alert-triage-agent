"""Instrument fixity: the hashes of the evaluation's code, tests and fixtures, and a digest of their behaviour.

    python -s -B -P <clone>/evaluation/instruments.py list --clone PATH
    python -s -B -P <clone>/evaluation/instruments.py fixtures-digest --clone PATH
    python -s -B -P <clone>/evaluation/instruments.py check --clone PATH --recorded FILE

The owner records the list and the digest independently of the commit. A
later change shows up in `check`; a change that does not alter behaviour
(a comment, say) leaves the fixtures digest equal, because the digest covers
only what the scorer and the report produce from the hand-written fixtures,
never a source hash.
"""

from __future__ import annotations

if __name__ == "__main__":
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.realpath(__file__))))

import copy
import hashlib
import importlib.util
import re
import sys
import tempfile
from pathlib import Path

from evaluation import identity
from evaluation.common import EvaluationError, canonical_dumps, read_regular

TEST_RE = re.compile(r"^tests/test_eval_[^/]*\.py$")
LIST_LINE_RE = re.compile(r"^([0-9a-f]{64})  (\S+)$")


class Differences(EvaluationError):
    """The recorded list differs from the clone."""


def in_set(path: str) -> bool:
    return (path.startswith("evaluation/") or path == "eval/rubric.md" or TEST_RE.fullmatch(path) is not None
            or path.startswith("tests/data/eval/"))


def _clean(clone: str) -> None:
    problems = identity.clean_tree_problems(clone)
    if problems:
        raise identity.CheckRefused(problems[0])


def instrument_list(clone: str) -> list[tuple[str, str]]:
    _clean(clone)
    return [(h, p) for p, _mode, h in identity.tracked_files(clone) if in_set(p)]


def list_text(entries: list[tuple[str, str]]) -> str:
    return "".join(f"{h}  {p}\n" for h, p in entries)


def _load_fixture_builder(clone: str):
    path = Path(clone) / "tests" / "test_eval_fixtures.py"
    # A private module name: the test suite's own test_eval_fixtures module is never replaced.
    spec = importlib.util.spec_from_file_location("_eval_fixtures_builder", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fixtures_digest(clone: str) -> str:
    """SHA-256 over every scorer fixture's outcome and score records, the aggregate results and the report."""
    from evaluation import records, report, scorer
    fx = _load_fixture_builder(clone)
    out = hashlib.sha256()
    doc = fx.scorer_doc()
    with tempfile.TemporaryDirectory(prefix="eval-digest-") as tmp:
        for i, fixture in enumerate(doc["fixtures"]):
            spec, order = fx.scorer_pass(doc, fixture)
            written = fx.write_pass(Path(tmp) / f"s{i}", spec)
            data = fx.load(written, doc, order, spec.sequence)
            registry, labels, _ = fx.models(doc, order)
            scores = scorer.score_pass(data, records.case_views(registry, labels))
            out.update(canonical_dumps({"name": fixture["name"], "pass_class": data.pass_class,
                                        "defects": [{"rule": r, "position": p} for r, p in data.defects]}))
            out.update(scorer.records_jsonl(scores))
        agg = fx.aggregate_doc()
        passes = []
        for spec in fx.aggregate_passes(agg, doc["base"]):
            written = fx.write_pass(Path(tmp) / "aggregate", spec)
            passes.append(fx.load(written, agg, agg["order"], spec.sequence, fixture=True))
        registry, labels, order = fx.models(agg, agg["order"])
        results = scorer.aggregate(passes, registry, labels, order, agg["setup"], fixture=True)
        masked = copy.deepcopy(results)
        masked["scorer"] = "masked"
        out.update(canonical_dumps(masked))
        out.update(report.render(masked, fixture=True).encode("ascii"))
    return out.hexdigest()


def differences(recorded: bytes, current: list[tuple[str, str]]) -> list[str]:
    try:
        text = recorded.decode("ascii")
    except UnicodeDecodeError:
        raise identity.UsageRefused("the recorded list is not ASCII") from None
    old = {}
    for line in text.split("\n"):
        if not line:
            continue
        match = LIST_LINE_RE.fullmatch(line)
        if match is None:
            raise identity.UsageRefused("the recorded list has a malformed line")
        old[match.group(2)] = match.group(1)
    new = {p: h for h, p in current}
    lines = []
    for path in sorted(set(old) | set(new)):
        if path not in new:
            lines.append(f"removed {path}")
        elif path not in old:
            lines.append(f"added {path}")
        elif old[path] != new[path]:
            lines.append(f"changed {path}")
    return lines


def _body(argv) -> int:
    parser = identity.Parser(prog="evaluation/instruments.py", allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=identity.Parser)
    for name in ("list", "fixtures-digest", "check"):
        cmd = sub.add_parser(name, allow_abbrev=False)
        cmd.add_argument("--clone", required=True)
        if name == "check":
            cmd.add_argument("--recorded", required=True)
    args = parser.parse_args(argv)
    if not identity.clone_ok(args.clone, __file__):
        raise identity.UsageRefused("--clone must be the clone this tool runs from")
    if args.command == "list":
        sys.stdout.write(list_text(instrument_list(args.clone)))
        return 0
    if args.command == "fixtures-digest":
        _clean(args.clone)
        print(fixtures_digest(args.clone))
        return 0
    try:
        recorded = read_regular(args.recorded)
    except EvaluationError:
        raise identity.UsageRefused("the recorded list cannot be read") from None
    lines = differences(recorded, instrument_list(args.clone))
    for line in lines:
        print(line)
    return 3 if lines else 0


def main(argv=None) -> int:
    return identity.run_cli("instruments", _body, sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())
