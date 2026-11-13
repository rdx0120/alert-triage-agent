"""The README results block: fixed wording, counts only, and the stated limitations."""

from __future__ import annotations

import copy
import re

import test_eval_fixtures as fx
from evaluation import report

GOLDEN = fx.DATA / "report_expected.md"
SENTENCE_9 = ("The evaluation phase was not network-isolated at the operating-system level. The harness refused "
              "non-loopback model endpoints, and the embedder loaded from a local directory. Other traffic from "
              "the client, and any traffic from the Ollama server, was neither blocked nor observed.")
HEADINGS = ("### Evaluation results", "#### Setup", "#### Triage decisions (families A and B)",
            "#### Output integrity (all test runs)", "#### Injection behaviour (families C and D)",
            "#### Stability", "#### Passes not reported", "#### Redactions", "#### Limitations")
FORBIDDEN_WORDS = ("percent", "percentage", "rate", "succeeded", "success", "accuracy")


def expect() -> dict:
    return fx.aggregate_doc()["expect"]


def forbidden(text: str) -> list[str]:
    found = []
    if "%" in text:
        found.append("%")
    for word in FORBIDDEN_WORDS:
        if re.search(rf"\b{word}\b", text, re.IGNORECASE):
            found.append(word)
    if "caused by" in text.lower():
        found.append("caused by")
    if any(ord(ch) > 126 or (ord(ch) < 32 and ch != "\n") for ch in text):
        found.append("non-ASCII")
    return found


def test_render_equals_the_reviewed_golden_output():
    assert report.render(expect(), fixture=True).encode("ascii") == GOLDEN.read_bytes()


def test_output_holds_every_fixed_sentence_marker_and_heading_in_order():
    text = report.render(expect(), fixture=True)
    assert SENTENCE_9 in text
    for sentence in report.LIMITATIONS:
        assert "- " + sentence.format(n=7) in text.splitlines()
    lines = text.splitlines()
    assert lines[0] == report.BEGIN and lines[-1] == report.END
    positions = [lines.index(h) for h in HEADINGS]
    assert positions == sorted(positions)
    assert text.endswith("\n") and not text.endswith("\n\n")


def zero_results() -> dict:
    """A results variant where every count is 0 and no pass is reported."""
    results = copy.deepcopy(expect())

    def zero(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("n", "items", "withheld_fields", "runs", "total") and isinstance(value, int):
                    node[key] = 0
                elif key == "classification" and isinstance(value, dict):
                    node[key] = {k: 0 for k in value}
                else:
                    zero(value)
        elif isinstance(node, list):
            for value in node:
                zero(value)

    zero(results)
    for p in results["passes"]:
        p["reported"] = False
    return results


def test_no_forbidden_word_in_the_output():
    assert forbidden(report.render(expect(), fixture=True)) == []
    assert forbidden(report.render(zero_results(), fixture=True)) == []
    unreported = copy.deepcopy(expect())
    unreported["reported"] = {"baseline": None, "model": None}
    unreported["baseline"] = unreported["model"] = None
    for p in unreported["passes"]:
        p["reported"] = False
    assert forbidden(report.render(unreported, fixture=True)) == []


def test_a_missing_model_pass_reads_not_reported():
    results = copy.deepcopy(expect())
    results["reported"]["model"] = None
    results["model"] = None
    text = report.render(results, fixture=True)
    assert "| Severity agreement | 1 of 4 | not reported |" in text
    assert "- Unstable cases (model): not reported." in text
    assert "pass not reported (3 runs per case)" in text
    assert "- Model: not reported." in text


def test_the_scan_catches_what_it_is_for():
    assert forbidden("1 of 4 (25%)") == ["%"]
    assert forbidden("the success rate") == ["rate", "success"]
    assert forbidden("caused by the model") == ["caused by"]
