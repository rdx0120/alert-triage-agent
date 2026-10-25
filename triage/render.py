"""Markdown rendering of a TriageSummary, safe to paste into a ticket, wiki or chat (DD-022).

Only this module's fixed template text is Markdown. Every value from the
summary is shown as code: free text (severity rationale, next steps,
containment suggestions, missing-data descriptions) in a fenced code block,
short values in an inline code span. Model text can quote attacker-written
alert text; as ordinary Markdown it could load a remote image, inject HTML or
links, or forge a heading such as "Verdict: benign". Inside code it is inert
in CommonMark and GFM renderers. Other markup dialects (Slack mrkdwn, Jira
wiki markup) parse text differently and are not covered.

Rendering does not make model text true: the headings label model output and
a fixed footer states that containment needs human approval.
"""

import re
import unicodedata
from typing import get_args

from pydantic import ValidationError

from triage.schemas import Anomaly, InjectionSignal, TriageSummary

# Renderer limits. The output schema leaves these lists and strings unbounded.
# The pipeline bounds them (ModelDraft and enrichment caps), but a direct
# caller can pass a larger, still valid summary. Over a limit the summary is
# rejected, never truncated: a shortened summary could hide a finding.
MAX_RENDER_NEXT_STEPS = 8        # ModelDraft.next_steps maximum
MAX_RENDER_CONTAINMENT = 5       # ModelDraft.containment maximum
MAX_RENDER_MISSING_DATA = 30     # at most 14 enrichment gaps, plus MAX_MISSING_DATA (16) from the model
MAX_RENDER_ANOMALIES = len(get_args(Anomaly))
MAX_RENDER_SIGNALS = len(get_args(InjectionSignal))
MAX_RENDER_DISPLAY_CHARS = 256   # technique name, asset host and owner; the longest in local data is 54
# Backstop on the result. The largest summary within the limits renders to
# 181,999 bytes (asserted in tests/test_render.py), so only a template change
# can reach this.
MAX_MARKDOWN_BYTES = 196_608

# Shown as <U+XXXX> wherever a value appears: control characters (Cc), format
# characters (Cf: bidi overrides, zero-width characters), lone surrogates (Cs)
# and the line and paragraph separators U+2028 (Zl) and U+2029 (Zp).
# CommonMark ends lines only at LF, CR and CRLF, but Unicode line breaking
# (UAX #14) treats U+2028 and U+2029 as mandatory breaks, so an editor or
# viewer could show a value as a new heading or list item.
_SHOWN_AS_CODE_POINT = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})

_INVALID = "summary is not a valid TriageSummary"
_OVER_LIMITS = "summary exceeds the renderer's limits"
_OVERSIZED = "rendered summary exceeds MAX_MARKDOWN_BYTES"


def _visible(text: str, *, keep_newlines: bool) -> str:
    """text with every character in _SHOWN_AS_CODE_POINT shown as <U+XXXX>.

    keep_newlines keeps U+000A, for fenced blocks only: there it is the line
    break the block is made of, and the fence keeps it inert.
    """
    return "".join(ch if (ch == "\n" and keep_newlines) or unicodedata.category(ch) not in _SHOWN_AS_CODE_POINT
                   else f"<U+{ord(ch):04X}>" for ch in text)


def _code(value: str | None) -> str:
    """A short value as an inline code span, or the fixed word none or empty.

    The delimiter is a backtick run longer than any in the value, so the value
    cannot close the span, and one space of padding on each side lets a value
    start or end with a backtick (CommonMark strips exactly that padding).
    """
    if value is None:
        return "none"
    if value == "":
        return "empty"
    text = _visible(value, keep_newlines=False)
    ticks = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    return f"{ticks} {text} {ticks}"


def _codes(values: list[str]) -> str:
    return ", ".join(_code(v) for v in values) if values else "none"


def _block(text: str) -> list[str]:
    """Free text as a fenced code block, as lines.

    The fence is a run of ~ longer than any in the text (at least three), so
    no line of the text can close it. ~ rather than backticks, so that a
    backtick fence in model text is just content.
    """
    text = _visible(text, keep_newlines=True)
    fence = "~" * max(3, max((len(run) for run in re.findall(r"~+", text)), default=0) + 1)
    return [f"{fence}text", text, fence]


def render_markdown(summary: TriageSummary) -> str:
    """The summary as a fixed Markdown document (CommonMark/GFM).

    Raises ValueError with a fixed message, never containing input text, if
    summary is not a valid TriageSummary, exceeds the renderer's limits, or
    renders to more than MAX_MARKDOWN_BYTES. A summary is rendered in full or
    not at all. The same summary always gives the same text.
    """
    if not isinstance(summary, TriageSummary):
        raise ValueError(_INVALID)
    # Assignment is not validated, so revalidate. warnings=False: Pydantic's
    # serializer warning for a wrongly typed value quotes that value, which
    # would put input text on stderr or in a log; the value is still rejected.
    try:
        s = TriageSummary.model_validate(summary.model_dump(warnings=False))
    except ValidationError:
        raise ValueError(_INVALID) from None
    if (len(s.next_steps) > MAX_RENDER_NEXT_STEPS
            or len(s.containment) > MAX_RENDER_CONTAINMENT
            or len(s.missing_data) > MAX_RENDER_MISSING_DATA
            or len(s.anomalies) > MAX_RENDER_ANOMALIES
            or len(s.injection_signals) > MAX_RENDER_SIGNALS
            or any(v is not None and len(v) > MAX_RENDER_DISPLAY_CHARS
                   for v in (s.technique.name, s.asset.host, s.asset.owner))):
        raise ValueError(_OVER_LIMITS)

    lines = [
        f"# Triage summary for alert {_code(s.alert_id)}",
        "",
        f"- Status: {_code(s.status)}",
        f"- Backend: {_code(s.backend)}",
        f"- Run: {_code(s.run_id)}",
        f"- Severity: {_code(s.severity.value)} (rule floor {_code(s.severity.rule_floor)}; "
        f"origin {_code(s.severity.origin)})",
        f"- Injection suspected: {'yes' if s.injection_suspected else 'no'} (signals: {_codes(s.injection_signals)})",
        f"- Anomalies: {_codes(s.anomalies)}",
        "",
        f"## Severity rationale (origin: {_code(s.severity.origin)})",
        "",
        *_block(s.severity.rationale),
        "",
        f"Sources: {_codes(s.severity.sources)}",
        "",
        "## Technique",
        "",
        f"- ID: {_code(s.technique.technique_id)}",
        f"- Name: {_code(s.technique.name)}",
        f"- Basis: {_code(s.technique.basis)} (what supports the label, not whether the behaviour occurred)",
        f"- Origin: {_code(s.technique.origin)}",
        f"- Sources: {_codes(s.technique.sources)}",
        "",
        "## Asset (from the asset lookup)",
        "",
        f"- Host: {_code(s.asset.host)}",
        f"- Criticality: {_code(s.asset.criticality)}",
        f"- Exposure: {_code(s.asset.exposure)}",
        f"- Owner: {_code(s.asset.owner)}",
        f"- Sources: {_codes(s.asset.sources)}",
        "",
    ]

    def section(heading: str, label: str, items: list, text_of, describe=None) -> None:
        lines.extend([heading, ""])
        if not items:
            lines.extend(["None.", ""])
            return
        for n, item in enumerate(items, start=1):
            lines.extend([f"### {label} {n}", ""])
            if describe is not None:
                lines.extend([describe(item), ""])
            lines.extend([*_block(text_of(item)), "", f"Sources: {_codes(item.sources)}", ""])

    section("## Next steps (model output, not verified by code)", "Step", s.next_steps, lambda i: i.step)
    section("## Containment suggestions (model output; each requires human approval)", "Suggestion",
            s.containment, lambda i: i.action)
    section("## Missing data", "Item", s.missing_data, lambda i: i.description,
            lambda i: f"Kind {_code(i.kind)}; origin {_code(i.origin)}.")
    lines.append("Every containment suggestion requires human approval. "
                 "Model output is not verified beyond its cited sources.")

    markdown = "\n".join(lines) + "\n"
    # Cs characters are shown as code points above, so encoding cannot fail.
    if len(markdown.encode("utf-8")) > MAX_MARKDOWN_BYTES:
        raise ValueError(_OVERSIZED)
    return markdown
