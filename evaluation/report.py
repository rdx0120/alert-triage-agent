"""The README results block, rendered from results.json alone.

The wording is fixed: counts are printed as "n of N", the limitation
sentences are constants, and the network limitation is stated word for word.
Nothing here computes a number; it only prints what results.json holds, so
the published text cannot say more than the measured counts.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import get_args

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from evaluation import common
else:
    from . import common

from triage.schemas import Anomaly  # noqa: E402 - after the script-mode path set-up

ANOMALY_CODES = get_args(Anomaly)

BEGIN = "<!-- evaluation-results:begin -->"
END = "<!-- evaluation-results:end -->"
NOT_REPORTED = "not reported"

LIMITATIONS = (
    "This is a {n}-case synthetic pilot: every alert and inventory record is synthetic, and the labels were written by the project's designer.",
    "The injections are hand-written and do not adapt to the model.",
    "One local model was evaluated, on a CPU virtual machine.",
    "Free text is measured only by the compliance markers; a plausible but wrong next step or rationale is not measured.",
    "No causal attribution is made: objective counts are reported next to the clean-twin controls.",
    "Runbook retrieval is scored at the uncalibrated starting threshold.",
    "Model reply text was not retained. The audit log records only each reply's size and SHA-256, and the published evidence withholds those values for any run that needed a redaction.",
    "The published evidence is checked for internal consistency, but it cannot show that no other run or pass took place outside the recorded evidence; that rests on one designated environment, pass identifiers assigned in sequence, and the owner's attestation.",
    "The evaluation phase was not network-isolated at the operating-system level. The harness refused non-loopback model endpoints, and the embedder loaded from a local directory. Other traffic from the client, and any traffic from the Ollama server, was neither blocked nor observed.",
    "Results are published as measured, including any below the heuristic baseline.",
)

F1_ROWS = (
    ("severity_agree", "Severity agreement"),
    ("over_floor", "Over-severity at the rule floor"),
    ("over_model", "Over-severity chosen by the model"),
    ("over_tripwire", "Over-severity raised by the tripwire"),
    ("under", "Under-severity"),
    ("technique_ok", "Technique acceptable"),
    ("status_ok", "Status correct"),
    ("retrieval_ok", "Runbook retrieval correct"),
    ("no_output", "No output"),
)
DRAFT_ROWS = (
    ("valid", "Valid draft"), ("draft_invalid", "Draft invalid"),
    ("draft_citation_invalid", "Draft with an invalid citation"),
    ("draft_unavailable", "Draft unavailable"),
)
STOP_ROWS = (("completed", "Stopped: completed"), ("budget_exceeded", "Stopped: budget exceeded"),
             ("backend_error", "Stopped: backend error"), ("invalid_output", "Stopped: invalid output"))
# The breakdown printed under a stop reason: (stop reason, key of its breakdown).
STOP_DETAILS = {"budget_exceeded": "by_detail", "backend_error": "by_type"}
SPLITS = (("flagged", "flagged by the tripwire"), ("not_flagged", "not flagged by the tripwire"),
          ("unknown", "tripwire result unknown"))


def _cell(count) -> str:
    if count is None:
        return NOT_REPORTED
    return f"{count['n']} of {count['of']}"


def _get(block, *path):
    node = block
    for key in path:
        if node is None:
            return None
        node = node[key]
    return node


def _row(label: str, baseline, model) -> str:
    return f"| {label} | {_cell(baseline)} | {_cell(model)} |"


def render(results: dict, *, fixture: bool = False) -> str:
    """Render the results block. A null index hash is refused outside fixture mode."""
    if results.get("index_sha256") is None and not fixture:
        raise common.SchemaError("results without a verified index hash cannot be reported")
    comp = results["composition"]
    setup = results["setup"]
    base, model = results["baseline"], results["model"]
    rep = results["reported"]
    lines = [BEGIN, "### Evaluation results", ""]
    lines.append(f"Measured on this {comp['test_cases']}-case synthetic pilot "
                 f"(families: A {comp['A']}, B {comp['B']}, C {comp['C']}, D {comp['D']}).")
    lines += ["", "#### Setup",
              f"- Baseline: the heuristic backend, pass {rep['baseline'] or NOT_REPORTED} (1 run per case).",
              f"- Model: {setup['model']} at digest {setup['digest']}, thinking disabled, "
              f"pass {rep['model'] or NOT_REPORTED} ({comp['k']} runs per case).",
              "- Development cases were used only for checks and are not reported.",
              "", "#### Triage decisions (families A and B)",
              "| Metric | Baseline | Model |", "|---|---|---|"]
    for key, label in F1_ROWS:
        lines.append(_row(label, _get(base, "f1", "runs", key), _get(model, "f1", "runs", key)))
    lines += ["", "#### Output integrity (all test runs)", "| Count | Baseline | Model |", "|---|---|---|"]
    for key, label in DRAFT_ROWS:
        lines.append(_row(label, _get(base, "f2", "draft", key), _get(model, "f2", "draft", key)))
    # The fixed anomaly order, never the order a results file happens to hold.
    for code in ANOMALY_CODES:
        lines.append(_row(f"Anomaly `{code}`", _get(base, "f2", "anomalies", code), _get(model, "f2", "anomalies", code)))
    for key, label in STOP_ROWS:
        lines.append(_row(label, _get(base, "f2", "stop_reason", key), _get(model, "f2", "stop_reason", key)))
        if key in STOP_DETAILS:
            lines += _detail_rows(label, base, model, key, STOP_DETAILS[key])
    lines.append(_row("No output", _get(base, "f2", "no_output"), _get(model, "f2", "no_output")))
    lines += ["", "#### Injection behaviour (families C and D)", "| Tripwire | Baseline | Model |", "|---|---|---|"]
    for key, label in (("flagged_known", "Known phrasings flagged"), ("flagged_evasive", "Evasive phrasings flagged"),
                       ("false_positives", "Clean or benign cases flagged"),
                       ("raised_by_tripwire", "Runs with severity raised by the tripwire")):
        lines.append(_row(label, _get(base, "f3", "tripwire", key), _get(model, "f3", "tripwire", key)))
    lines += ["", "| Objective | Baseline | Model |", "|---|---|---|"]
    for split, split_label in SPLITS:
        for part, name in (("om", "Marker step"), ("os", "Severity downgrade"), ("ot", "Technique substitution")):
            b = _get(base, "f3", "objectives", split, part, "effective")
            m = _get(model, "f3", "objectives", split, part, "effective")
            lines.append(f"| {name}, {split_label} | {_objective(b)} | {_objective(m)} |")
    lines += ["", "| Control | Baseline | Model |", "|---|---|---|"]
    for part, name in (("om", "Marker in clean-twin output"), ("os", "Downgrade target in clean-twin output"),
                       ("ot", "Substitute technique in clean-twin output")):
        b = _get(base, "f3", "controls", part, "occurred")
        m = _get(model, "f3", "controls", part, "occurred")
        lines.append(f"| {name} | {_control(b)} | {_control(m)} |")
    for label, block in (("Baseline", base), ("Model", model)):
        if block is None:
            continue
        f3 = block["f3"]
        lines += ["", f"{label} guardrail interventions on twins:"]
        lines += [f"- {e['twin']}: {', '.join('`' + c + '`' for c in e['codes'])}" for e in f3["guardrail_interventions"]] or ["- None."]
        lines += [f"{label} observed differences from the clean twin:"]
        lines += [f"- {e['twin']}, {e['field']}: {e['runs']} of {e['of']} runs" for e in f3["observed_differences"]] or ["- None."]
        if f3["differences_unassessable"]:
            lines.append(f"- Not assessable (no clean-twin output): {', '.join(f3['differences_unassessable'])}.")
    lines += ["", "#### Stability",
              f"- Unstable cases (model): {_cell(_get(model, 'stability', 'unstable'))}."]
    lines += ["", "#### Passes not reported"]
    others = [p for p in results["passes"] if not p["reported"]]
    lines += [f"- {p['pass_id']}: {p['class']}" for p in others] or ["- None."]
    lines += ["", "#### Redactions"]
    for label, block in (("Baseline", base), ("Model", model)):
        if block is None:
            lines.append(f"- {label}: {NOT_REPORTED}.")
            continue
        red = block["redactions"]
        classes = ", ".join(f"{code} {red['classification'][code]}" for code in common.CLASSIFICATION_CODES)
        lines.append(f"- {label}: items {red['items']}; runs with items {_cell(red['runs_with_items'])}; "
                     f"{classes}; withheld fields {red['withheld_fields']}.")
    lines += ["", "#### Limitations"]
    lines += [f"- {sentence.format(n=comp['test_cases'])}" for sentence in LIMITATIONS]
    lines.append(END)
    return "\n".join(lines) + "\n"


def _detail_rows(label: str, base, model, key: str, breakdown: str) -> list[str]:
    """One row per detail or error type under a stop reason, in sorted order."""
    blocks = [b for b in (base, model) if b is not None]
    names = sorted({name for b in blocks for name in b["f2"]["stop_reason"][key][breakdown]})

    def cell(block, name):
        if block is None:
            return None
        reason = block["f2"]["stop_reason"][key]
        return {"n": reason[breakdown].get(name, 0), "of": reason["of"]}

    return [_row(f"{label}, `{name}`", cell(base, name), cell(model, name)) for name in names]


def _objective(count) -> str:
    if count is None:
        return NOT_REPORTED
    return f"objective met (as defined) in {count['n']} of {count['of']} runs"


def _control(count) -> str:
    if count is None:
        return NOT_REPORTED
    return f"target produced in {count['n']} of {count['of']} clean-twin runs"


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # noqa: ARG002 - argparse messages quote values
        raise _Usage()


class _Usage(Exception):
    pass


def main(argv=None) -> int:
    parser = _Parser(prog="evaluation/report.py", allow_abbrev=False)
    parser.add_argument("--results", required=True)
    parser.add_argument("--out", required=True)
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
        results = common.strict_loads(common.read_regular(args.results))
        common.write_new_file(args.out, render(results).encode("ascii"))
        return 0
    except _Usage:
        message, code = "invalid arguments", 2
    except common.EvaluationError:
        message, code = "invalid input or output path", 2
    except Exception as error:  # never the message: it can hold record content
        message, code = f"internal error ({type(error).__name__})", 1
    print(f"evaluation-report: error: {message}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
