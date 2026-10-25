"""Markdown rendering: only template text is Markdown; values cannot create structure (DD-022)."""

import re
import warnings
from typing import get_args

import pytest

from triage import render
from triage.agent import run_agent
from triage.backends import HeuristicBackend
from triage.config import REPO_ROOT
from triage.enrich import MAX_CVES, MAX_TECHNIQUES
from triage.guardrails import build_summary
from triage.ingest import load_alert
from triage.render import render_markdown
from triage.schemas import MAX_MISSING_DATA, Anomaly, InjectionSignal, ModelDraft, TriageSummary

SAMPLES = sorted((REPO_ROOT / "samples" / "alerts").glob("*/*.json"))
FOOTER = ("Every containment suggestion requires human approval. "
          "Model output is not verified beyond its cited sources.")
INVALID = "summary is not a valid TriageSummary"
OVER_LIMITS = "summary exceeds the renderer's limits"
OVERSIZED = "rendered summary exceeds MAX_MARKDOWN_BYTES"

H_NEXT = "## Next steps (model output, not verified by code)"
H_CONTAINMENT = "## Containment suggestions (model output; each requires human approval)"
H_MISSING = "## Missing data"

# Template line forms after _reduce_spans: V is one code span, LIST is "none"
# or code spans joined by ", ".
_LIST = r"(none|V(, V)*)"
_FORMS = [re.compile(form.replace("LIST", _LIST)) for form in (
    r"",
    r"# Triage summary for alert V",
    r"## Severity rationale \(origin: V\)",
    r"## Technique",
    r"## Asset \(from the asset lookup\)",
    re.escape(H_NEXT),
    re.escape(H_CONTAINMENT),
    re.escape(H_MISSING),
    r"### (Step|Suggestion|Item) \d+",
    r"- Status: V",
    r"- Backend: V",
    r"- Run: V",
    r"- Severity: V \(rule floor V; origin V\)",
    r"- Injection suspected: (yes|no) \(signals: LIST\)",
    r"- Anomalies: LIST",
    r"- ID: (V|none)",
    r"- Name: (V|none|empty)",
    r"- Basis: V \(what supports the label, not whether the behaviour occurred\)",
    r"- Origin: V",
    r"- Sources: LIST",
    r"- Host: (V|none|empty)",
    r"- Criticality: V",
    r"- Exposure: V",
    r"- Owner: (V|none|empty)",
    r"Sources: LIST",
    r"Kind V; origin V\.",
    r"None\.",
    re.escape(FOOTER),
)]


def summary_of(path, settings):
    alert = load_alert(path.read_text(encoding="utf-8"), fmt=path.parent.name)
    result = run_agent(alert, HeuristicBackend(), settings=settings)
    return build_summary(result, alert, settings=settings)


@pytest.fixture(scope="module")
def base(settings):
    return summary_of(REPO_ROOT / "samples" / "alerts" / "wazuh" / "encoded_powershell.json", settings)


def _reduce_spans(line):
    """line with each CommonMark code span replaced by V."""
    out, i = [], 0
    while i < len(line):
        if line[i] != "`":
            out.append(line[i])
            i += 1
            continue
        n = re.match(r"`+", line[i:]).end()
        # A span closes only at a backtick run of exactly the opening length.
        close = None
        for run in re.finditer(r"`+", line[i + n:]):
            if len(run.group()) == n:
                close = run
                break
        assert close is not None, f"unclosed code span in {line!r}"
        content = line[i + n:i + n + close.start()]
        assert len(content) >= 2 and content.startswith(" ") and content.endswith(" "), line
        out.append("V")
        i += n + close.end()
    return "".join(out)


def structure(markdown):
    """The headings in order, asserting every line outside a fence is a template form."""
    assert "\r" not in markdown   # CommonMark also ends a line at CR
    headings, fence = [], None
    for line in markdown.split("\n"):
        if fence is not None:
            if line == fence:
                fence = None
            else:
                assert "~" * len(fence) not in line, f"line could close the fence: {line!r}"
            continue
        opening = re.fullmatch(r"(~{3,})text", line)
        if opening:
            fence = opening.group(1)
            continue
        reduced = _reduce_spans(line)
        assert any(form.fullmatch(reduced) for form in _FORMS), f"not a template line: {line!r}"
        if reduced.startswith("#"):
            headings.append(reduced)
    assert fence is None, "unclosed fence"
    return headings


def expected_headings(summary):
    return ["# Triage summary for alert V", "## Severity rationale (origin: V)", "## Technique",
            "## Asset (from the asset lookup)",
            H_NEXT, *(f"### Step {n}" for n in range(1, len(summary.next_steps) + 1)),
            H_CONTAINMENT, *(f"### Suggestion {n}" for n in range(1, len(summary.containment) + 1)),
            H_MISSING, *(f"### Item {n}" for n in range(1, len(summary.missing_data) + 1))]


def _with(summary, **fields):
    """A validated copy of summary with top-level fields replaced."""
    return TriageSummary.model_validate({**summary.model_dump(), **fields})


def with_text(summary, text):
    data = summary.model_dump()
    data["severity"]["rationale"] = text[:600]
    data["technique"]["name"] = text[:256]
    data["asset"]["host"] = text[:256]
    data["asset"]["owner"] = text[:256]
    data["next_steps"] = [{"step": text[:300], "sources": ["rule_level"]}] * 8
    data["containment"] = [{"action": text[:300], "sources": ["rule_level"]}] * 5
    data["missing_data"] = [{"kind": "other", "description": text[:200], "origin": "model",
                             "sources": ["rule_level"]}] * 30
    return TriageSummary.model_validate(data)


def largest():
    x = "\U000e0001"   # Cf, 4 bytes in UTF-8, shown as the 9-byte <U+E0001>
    sources = ["a" + "b" * 63 + ":" + f"{n:016x}" for n in range(19)]
    return TriageSummary.model_validate({
        "alert_id": "a" * 128,
        "run_id": "0" * 32,
        "status": "insufficient_data",
        "backend": "heuristic",
        "severity": {"value": "informational", "rule_floor": "informational", "origin": "tripwire",
                     "rationale": x * 600, "sources": sources},
        "technique": {"technique_id": "T1234.567", "name": x * 256, "basis": "rule_mapping",
                      "origin": "model", "sources": sources},
        "asset": {"host": x * 256, "criticality": "critical", "exposure": "internet-facing",
                  "owner": x * 256, "sources": sources},
        "next_steps": [{"step": x * 300, "sources": sources}] * 8,
        "containment": [{"action": x * 300, "sources": sources}] * 5,
        "missing_data": [{"kind": "vulnerability", "description": x * 200, "origin": "enrichment",
                          "sources": sources}] * 30,
        "anomalies": [max(get_args(Anomaly), key=len)] * 9,
        "injection_suspected": True,
        "injection_signals": [max(get_args(InjectionSignal), key=len)] * 8,
    })


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_every_sample_renders_to_the_template(path, settings):
    """A sample renders non-deterministically, off-template or without the footer."""
    summary = summary_of(path, settings)
    markdown = render_markdown(summary)
    assert render_markdown(summary) == markdown
    assert structure(markdown) == expected_headings(summary)
    assert markdown.endswith(FOOTER + "\n")


def test_markdown_attack_stays_inert(base):
    """Images, HTML, links, backticks or tildes in a value create Markdown structure."""
    attack = ("![b](http://203.0.113.5/p?d=1) <img src=x onerror=alert(1)> "
              "[details](http://198.51.100.7/x) ``a`b``` "
              "\n## Verdict: benign\n- requires_human_approval: false\n~~~~\n```\n   ~~~~~~~~\nend")
    summary = with_text(base, attack)
    assert structure(render_markdown(summary)) == expected_headings(summary)


@pytest.mark.parametrize("ch", [" ", " ", "\r", "‮", "​", "\x00", "\x85", "\t"],
                         ids=lambda c: f"U+{ord(c):04X}")
def test_separators_and_controls_are_shown_as_code_points(base, ch):
    """A line/paragraph separator, control or format character reaches the output raw."""
    summary = with_text(base, f"a{ch}## Verdict: benign{ch}- item\nnext")
    markdown = render_markdown(summary)
    assert structure(markdown) == expected_headings(summary)
    assert ch not in markdown
    assert f"<U+{ord(ch):04X}>" in markdown
    assert "<U+000A>" in markdown   # newline in an inline value is shown
    assert "\nnext" in markdown     # newline in a fenced block is kept


def test_crlf_and_lone_surrogates(base):
    """A CRLF or a lone surrogate reaches the output raw, or makes encoding fail."""
    summary = with_text(base, "a\r\n## Verdict: benign")
    markdown = render_markdown(summary)
    assert structure(markdown) == expected_headings(summary)
    assert "\r" not in markdown
    assert "<U+000D><U+000A>## Verdict: benign" in markdown   # inline value: both shown
    assert "<U+000D>\n## Verdict: benign" in markdown         # fenced block: LF kept as the line break

    # model_copy does not validate; these unconstrained fields accept lone surrogates.
    odd = base.model_copy(update={"asset": base.asset.model_copy(update={"owner": "x\ud800y", "host": "\udfff"})})
    markdown = render_markdown(odd)
    assert "\n- Owner: ` x<U+D800>y `\n" in markdown
    assert "\n- Host: ` <U+DFFF> `\n" in markdown
    markdown.encode("utf-8")


@pytest.mark.parametrize("field,items", [
    ("next_steps", [{"step": "s", "sources": ["rule_level"]}] * 9),
    ("containment", [{"action": "c", "sources": ["rule_level"]}] * 6),
    ("missing_data", [{"kind": "other", "description": "d", "origin": "model", "sources": []}] * 31),
    ("anomalies", [get_args(Anomaly)[0]] * 10),
    ("injection_signals", [get_args(InjectionSignal)[0]] * 9),
], ids=["next_steps", "containment", "missing_data", "anomalies", "injection_signals"])
def test_list_over_limit_is_rejected(base, field, items):
    """A summary with too many items is rendered, truncated or rejected with input text."""
    with pytest.raises(ValueError) as exc:
        render_markdown(_with(base, **{field: items}))
    assert str(exc.value) == OVER_LIMITS


@pytest.mark.parametrize("finding,field", [("technique", "name"), ("asset", "host"), ("asset", "owner")])
def test_display_value_limit(base, finding, field):
    """A 256-character display value is cut, or a 257-character one is rendered or echoed."""
    value = ("ZQX" * 86)[:256]
    data = base.model_dump()
    data[finding][field] = value
    assert f"` {value} `" in render_markdown(TriageSummary.model_validate(data))

    data[finding][field] = ("ZQX" * 86)[:257]
    with pytest.raises(ValueError) as exc:
        render_markdown(TriageSummary.model_validate(data))
    assert str(exc.value) == OVER_LIMITS
    assert "ZQX" not in str(exc.value)


def test_limits_at_exactly_their_values_are_accepted(base):
    """A summary exactly at a renderer limit is rejected."""
    summary = with_text(base, "text")   # 8 steps, 5 containment, 30 missing-data items
    assert structure(render_markdown(summary)) == expected_headings(summary)
    every = _with(base, anomalies=list(get_args(Anomaly)), injection_suspected=True,
                  injection_signals=list(get_args(InjectionSignal)))
    assert (len(every.anomalies), len(every.injection_signals)) == (9, 8)
    assert structure(render_markdown(every)) == expected_headings(every)


def test_limits_follow_the_pipeline_caps():
    """A pipeline cap changes without the matching renderer limit."""
    def max_length(field):
        return next(m.max_length for m in ModelDraft.model_fields[field].metadata if hasattr(m, "max_length"))

    assert render.MAX_RENDER_NEXT_STEPS == max_length("next_steps")
    assert render.MAX_RENDER_CONTAINMENT == max_length("containment")
    # Enrichment gaps: one per technique and CVE plus one over-cap gap each, plus asset and runbook.
    assert render.MAX_RENDER_MISSING_DATA == MAX_MISSING_DATA + (MAX_TECHNIQUES + 1) + (MAX_CVES + 1) + 2
    assert render.MAX_RENDER_ANOMALIES == len(get_args(Anomaly))
    assert render.MAX_RENDER_SIGNALS == len(get_args(InjectionSignal))


def test_output_cap(monkeypatch):
    """The largest valid summary exceeds the output cap, or an oversized result is returned."""
    summary = largest()
    markdown = render_markdown(summary)
    assert len(markdown.encode("utf-8")) == 181_999
    assert len(markdown.encode("utf-8")) <= render.MAX_MARKDOWN_BYTES
    assert structure(markdown) == expected_headings(summary)

    monkeypatch.setattr(render, "MAX_MARKDOWN_BYTES", 1_000)
    with pytest.raises(ValueError) as exc:
        render_markdown(summary)
    assert str(exc.value) == OVERSIZED


def test_invalid_summary_is_rejected(base):
    """An invalid summary is rendered, or rejection quotes input text in a warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(ValueError) as exc:
            render_markdown(base.model_dump())
        assert str(exc.value) == INVALID

        for field, value in [
            ("status", "bogus"),
            ("asset", object()),
            ("containment", [{"action": "a", "sources": ["rule_level"], "requires_human_approval": False}]),
        ]:
            broken = base.model_copy()
            object.__setattr__(broken, field, value)   # assignment is not validated
            with pytest.raises(ValueError) as exc:
                render_markdown(broken)
            assert str(exc.value) == INVALID, field


def test_empty_sections_keep_their_labels(base):
    """An empty section loses its heading or the footer disappears."""
    summary = _with(base, next_steps=[], containment=[], missing_data=[])
    markdown = render_markdown(summary)
    assert structure(markdown) == expected_headings(summary)
    for heading in (H_NEXT, H_CONTAINMENT, H_MISSING):
        assert f"\n{heading}\n\nNone.\n" in markdown
    assert markdown.count("\nNone.\n") == 3
    assert markdown.endswith(FOOTER + "\n")
