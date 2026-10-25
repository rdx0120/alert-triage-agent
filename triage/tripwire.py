"""A deterministic tripwire for alert text addressed to an AI system.

It reads only the attacker-writable alert fields, never model output or tool
data. It records which signals matched and in which fields, never the matched
text. A match is a reason to escalate, not proof of an attack.

It scans the full canonical alert, not the capped prompt view, so it can flag
text the model never saw: a match means the alert contains suspicious text,
not that the model encountered or obeyed it.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import get_args

from .schemas import AlertField, Alert, InjectionSignal

# A short, bounded gap between key words. Text is a single line after
# normalizing, so "." never needs to cross a newline.
_GAP = r".{0,40}?"

PATTERNS: dict[str, str] = {
    "instruction_override": (
        r"\b(?:ignore|disregard|forget)\b" + _GAP
        + r"\b(?:previous|prior|above|earlier|preceding|all|any|your|the|system)\b" + _GAP
        + r"\b(?:instructions?|prompts?|rules?|guidelines?|directives?|context)\b"),
    "new_instructions": (
        r"\b(?:new|updated|revised|real|actual)\s(?:instructions?|directives?|system\sprompt)\b"),
    "prompt_exfiltration": (
        r"\b(?:reveal|print|show|repeat|output|leak|dump)\b" + _GAP
        + r"\b(?:your|the)\s(?:system\sprompt|hidden\sprompt|initial\sprompt|instructions)\b"),
    "role_assignment": (
        r"\b(?:you\sare\s(?:now\s)?|act\sas|pretend\s(?:to\sbe|you\sare)|from\snow\son\syou)" + _GAP
        + r"\b(?:ai|assistant|language\smodel|llm|chatbot|gpt|analyst|triage)\b"),
    "ai_address": (
        r"\b(?:dear|attention|hey|hello|note\sto(?:\sthe)?)\s"
        r"(?:ai|assistant|llm|chatgpt|gpt|claude|copilot|gemini|model|triage\s(?:bot|agent|system))\b"
        r"|\b(?:ai|llm)\s(?:triage|analyst|assistant|agent|model)s?\s?[:,]"),
    "chat_markup": (
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id)\|>"
        r"|\[/?inst\]|<<\s?/?sys\s?>>|</?\s?(?:system|assistant)\s?>"
        r"|(?:^|\s)#{2,}\s?(?:system|instructions?|assistant)\b|\b(?:system|assistant)\s?:\s?you\b"),
    "verdict_steering": (
        r"\b(?:mark|classify|label|treat|report|flag|rate|score|consider)\b" + _GAP
        + r"\b(?:this|it|the\s(?:alert|event|incident|activity))\b" + _GAP
        + r"\bas\s(?:a\s)?(?:benign|false\spositive|safe|harmless|informational|low(?:\sseverity)?"
          r"|not\smalicious|legitimate|expected)\b"),
    "suppression": (
        r"\b(?:do\snot|don'?t|never|no\sneed\sto)\s"
        r"(?:alert|report|escalate|flag|notify|raise|investigate|open\sa\sticket)\b"),
}

# The signal codes are a schema literal; the patterns must name the same codes
# in the same order, so the summary lists signals in a fixed order. An
# explicit raise, not assert: python -O removes asserts, and a mismatch must
# stop the import in every mode.
if list(PATTERNS) != list(get_args(InjectionSignal)):
    raise RuntimeError("tripwire patterns do not match the InjectionSignal codes")
_COMPILED = [(code, re.compile(pattern)) for code, pattern in PATTERNS.items()]

# The alert fields an attacker can write. Identifiers, tags, host and CVEs are
# pattern-validated or come from the rule set, so they are not scanned.
SCANNED_FIELDS = ("rule_title", "user", "timestamp", "event")
if not all(f in get_args(AlertField) for f in SCANNED_FIELDS):
    raise RuntimeError("tripwire scanned fields are not all AlertField names")


def normalize(text: str) -> str:
    # NFKC folds compatibility forms (full-width letters, ligatures, styled
    # mathematical letters) to their plain equivalents.
    text = unicodedata.normalize("NFKC", text)
    # Format characters (zero-width spaces and joiners, bidi overrides) are
    # invisible and can split a key word so that it no longer matches.
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    # Newlines, tabs and runs of spaces can split a phrase across lines;
    # one space keeps the patterns simple and "." within a single line.
    text = re.sub(r"\s+", " ", text).strip()
    # Case-folding handles mixed case and the few case-insensitive forms
    # lower() misses.
    return text.casefold()


@dataclass(frozen=True)
class TripwireResult:
    signals: tuple[str, ...]   # InjectionSignal codes, in PATTERNS order, unique
    fields: tuple[str, ...]    # AlertField names where a signal matched, in AlertField order, unique

    @property
    def suspected(self) -> bool:
        return bool(self.signals)


def injection_signals(alert: Alert) -> TripwireResult:
    """The signals that match the alert's attacker-writable fields.

    Each string is scanned separately, so a match never spans two fields or
    two event values. Only the code and the field name are kept.
    """
    strings: list[tuple[str, str]] = [
        (name, value) for name, value in (("rule_title", alert.rule_title), ("user", alert.user),
                                          ("timestamp", alert.timestamp))
        if isinstance(value, str)
    ]
    for key, value in alert.event.items():
        strings.append(("event", key))
        # Numbers, booleans and None cannot carry a phrase.
        if isinstance(value, str):
            strings.append(("event", value))

    signals: set[str] = set()
    fields: set[str] = set()
    for field, value in strings:
        text = normalize(value)
        for code, pattern in _COMPILED:
            if pattern.search(text):
                signals.add(code)
                fields.add(field)
    return TripwireResult(signals=tuple(code for code in PATTERNS if code in signals),
                          fields=tuple(f for f in get_args(AlertField) if f in fields))
