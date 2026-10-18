"""Alert ingestion: turn a raw Wazuh 4.x alert or a Sigma rule match into an Alert.

Trust boundary. The rule ID, level and ATT&CK mapping are trusted rule
metadata from the SIEM's own rule set; the level decides the alert's severity
floor, so they are required and validated strictly: an alert without them is
rejected rather than triaged on a guessed severity. The rule title is also
required, but it can contain substituted event data (Wazuh rule descriptions
embed decoded fields through `$(field)`), so later stages must treat it as
untrusted text; an over-long title is truncated, not rejected. Everything under
Wazuh's `data` object and the Sigma `event` object is attacker-influenced
(command lines, usernames, paths, log text). It is copied verbatim, within size
limits and apart from the malformed-text repair described in load_alert, and is
never mined for technique IDs or CVEs.

The caller states the format; there is no auto-detection, because a guess
made from attacker-influenced fields could pick the wrong trust rules.

Error messages and warnings use fixed templates that name a known field path
and the problem. They never repeat an input value or an input key, because
either could carry an injection payload into logs or the model's context.

Sigma match input format (one JSON object per alert):

    {
      "alert_id": optional string (else derived from rule ID and event),
      "rule": {"id": str, "title": str,
               "level": "informational" | "low" | "medium" | "high" | "critical",
               "tags": [str, ...]},
      "event": {...},          # the matched event (first event for correlations)
      "aggregate": optional {"match_count": int >= 1, "first_seen": str,
                             "last_seen": str, "distinct": {field: int}}
    }
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Callable, Literal, Sequence

from pydantic import ValidationError

from .schemas import (
    ALERT_ID_PATTERN,
    CVE_PATTERN,
    HOST_PATTERN,
    SEVERITY_ORDER,
    TECHNIQUE_ID_PATTERN,
    Alert,
    Severity,
)

# A maximum-length Windows command line (32,767 characters) appears twice in a
# Wazuh alert, in data.win.eventdata.commandLine and again, with extra JSON
# escaping, in full_log, which can exceed 64 KiB. A lower cap would let an
# attacker keep a real alert from triage. The per-field, field-count and depth
# caps below still bound what reaches later stages.
MAX_RAW_ALERT_BYTES = 256 * 1024
MAX_DEPTH = 5
MAX_EVENT_KEYS = 50  # must equal the max_length of Alert.event
MAX_KEY_CHARS = 128
MAX_WARNINGS = 20  # must equal the max_length of Alert.ingest_warnings
MAX_USER_CHARS = 256  # must equal the max_length of Alert.user
MAX_TITLE_CHARS = 256  # must equal the max_length of Alert.rule_title
MAX_TIMESTAMP_CHARS = 64  # must equal the max_length of Alert.timestamp
MAX_TAGS = 20  # must equal the max_length of Alert.rule_tags
TRUNCATION_MARKER = "...[truncated]"  # same marker the Alert model uses for event values

SIGMA_TAG_PATTERN = r"^[a-z0-9._-]{1,64}$"

# Candidate event fields, in priority order. These names are constants, so a
# warning may name them; keys found in the input are never named.
SIGMA_HOST_FIELDS = ("ComputerName", "Computer", "Hostname", "host.name")
SIGMA_USER_FIELDS = ("User", "actor.email", "target.email", "user.name", "SubjectUserName")
SIGMA_TIME_FIELDS = ("event.time", "UtcTime", "@timestamp")
WAZUH_USER_FIELDS = ("data.win.eventdata.user", "data.srcuser", "data.dstuser")
# Wazuh fields outside `data` that are useful evidence, in the order they go into the event.
WAZUH_EVENT_FIELDS = ("full_log", "location", "decoder.name", "agent.id", "agent.name", "agent.ip", "rule.groups")


class IngestError(ValueError):
    """The alert must be rejected. The message names fields, never values."""


# --- Entry point ---------------------------------------------------------


def load_alert(text: str | bytes, fmt: Literal["wazuh", "sigma"]) -> Alert:
    """Parse one raw alert of the stated format. The entry point for untrusted raw input.

    Applies the size cap before parsing, and replaces malformed text (invalid
    UTF-8, unpaired surrogates) and drops repeated keys before from_wazuh or
    from_sigma_match see the parsed object.
    """
    # Malformed text and repeated keys can come from attacker-influenced input.
    # Rejecting malformed text would let an attacker keep an alert from triage,
    # and json.loads on its own keeps the last value of a repeated key, so a
    # later key would silently overwrite an earlier one. Instead, malformed
    # text becomes U+FFFD, the first value of a repeated key is kept, and both
    # are reported as counts in ingest_warnings.
    if fmt not in ("wazuh", "sigma"):
        raise IngestError("fmt: must be 'wazuh' or 'sigma'")
    surrogates = 0
    if isinstance(text, str):
        # A str can hold lone surrogates, which UTF-8 cannot encode.
        text, surrogates = _SURROGATE.subn("\ufffd", text)
        data = text.encode("utf-8")
    elif isinstance(text, bytes):
        data = text
    else:
        raise IngestError("input: must be str or bytes")
    # Checked before json.loads so an oversized payload never reaches the parser.
    if len(data) > MAX_RAW_ALERT_BYTES:
        raise IngestError(f"input: larger than {MAX_RAW_ALERT_BYTES} bytes")
    try:
        decoded = data.decode("utf-8")
        invalid_bytes = 0
    except UnicodeDecodeError:
        # surrogateescape maps each invalid byte to its own placeholder
        # (U+DC80-U+DCFF), so two different malformed keys stay distinct until
        # replacement and duplicate detection run together in the object hook.
        # Decoding with replacement first would let json.loads merge them before
        # any check. At this point the text can contain surrogates only from
        # surrogateescape, so the count is exact.
        decoded = data.decode("utf-8", errors="surrogateescape")
        invalid_bytes = len(_ESCAPED_BYTE.findall(decoded))
    hook = _ObjectHook()
    try:
        raw = json.loads(
            decoded,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
            parse_int=_parse_int,
            object_pairs_hook=hook,
        )
    except (ValueError, RecursionError):
        # ValueError covers bad JSON (including invalid bytes outside a string)
        # and NaN/Infinity; RecursionError covers arrays nested tens of
        # thousands deep, which fit inside the size cap.
        raise IngestError("input: not valid JSON") from None
    if not isinstance(raw, dict):
        raise IngestError("input: top-level JSON value must be an object")
    # The hook replaced both invalid-byte placeholders and surrogates that came
    # from JSON escapes such as \ud800; only the latter are unpaired surrogates.
    unpaired_surrogates = surrogates + hook.replaced - invalid_bytes
    parse_warnings = []
    if invalid_bytes:
        parse_warnings.append(f"input: {_count(invalid_bytes, 'invalid UTF-8 byte')} replaced with U+FFFD")
    if unpaired_surrogates:
        parse_warnings.append(f"input: {_count(unpaired_surrogates, 'unpaired surrogate')} replaced with U+FFFD")
    if hook.duplicates:
        parse_warnings.append(f"input: {_count(hook.duplicates, 'duplicate key')} dropped (first kept)")
    if fmt == "wazuh":
        return from_wazuh(raw, parse_warnings=parse_warnings)
    return from_sigma_match(raw, parse_warnings=parse_warnings)


_SURROGATE = re.compile("[\ud800-\udfff]")
_ESCAPED_BYTE = re.compile("[\udc80-\udcff]")


class _ObjectHook:
    """json.loads object_pairs_hook: replaces lone surrogates and keeps the first of repeated keys.

    Replacement and duplicate detection happen in one place, before the object
    exists, so neither a malformed key nor a repeated key can overwrite an
    earlier value. Counts come only from these mechanisms: a U+FFFD that was
    already in the input is never counted.
    """

    def __init__(self) -> None:
        self.replaced = 0
        self.duplicates = 0

    def __call__(self, pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            key = self._text(key)
            # Values of dropped keys are still processed, so every replacement
            # is counted and the unpaired-surrogate count stays exact.
            if isinstance(value, str):
                value = self._text(value)
            elif isinstance(value, list):
                self._list(value)
            # Objects in a value were already processed by their own hook call.
            if key in obj:
                self.duplicates += 1
                continue
            obj[key] = value
        return obj

    def _text(self, s: str) -> str:
        # json.loads joins valid escaped pairs into one character, so any
        # surrogate left here is unpaired or an invalid-byte placeholder.
        s, n = _SURROGATE.subn("\ufffd", s)
        self.replaced += n
        return s

    def _list(self, items: list) -> None:
        # An explicit stack rather than recursion: lists can nest as deep as the
        # parser allows. The lists are fresh from the parser, so they are edited in place.
        stack = [items]
        while stack:
            current = stack.pop()
            for i, item in enumerate(current):
                if isinstance(item, str):
                    current[i] = self._text(item)
                elif isinstance(item, list):
                    stack.append(item)


def _reject_constant(name: str) -> Any:
    # json.loads accepts NaN, Infinity and -Infinity, which are not valid JSON;
    # letting them through would make every later JSON output invalid.
    raise ValueError("non-standard JSON constant")


# Two kinds of valid JSON number do not fit a Python number. A float literal
# such as 1e999 parses to inf, which would make every later JSON output
# invalid, like NaN above. An integer longer than Python's int conversion
# limit (4,300 digits) makes int() raise ValueError. Unlike NaN, both are
# valid JSON, and event data is attacker-influenced: rejecting them would let
# one crafted field keep the whole alert from triage. So the number is kept as
# the exact text received. Trusted fields still fail closed: a rule.level that
# arrives as text is not an int and is rejected by wazuh_level_to_severity.
def _parse_float(text: str) -> float | str:
    value = float(text)
    return value if math.isfinite(value) else text


def _parse_int(text: str) -> int | str:
    try:
        return int(text)
    except ValueError:
        return text


# --- Wazuh 4.x -----------------------------------------------------------


def wazuh_level_to_severity(level: int) -> Severity:
    """Wazuh rule level (0-16) to severity, following Wazuh's level descriptions."""
    # bool is a subclass of int; True must not pass as level 1.
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 16:
        raise IngestError("rule.level: must be an integer from 0 to 16")
    if level <= 3:
        return "informational"
    if level <= 6:
        return "low"
    if level <= 9:
        return "medium"
    if level <= 13:
        return "high"
    return "critical"


def from_wazuh(raw: dict, *, parse_warnings: Sequence[str] = ()) -> Alert:
    """Normalize a parsed Wazuh 4.x alert.

    Callers with untrusted raw input use load_alert, which applies the size cap
    and replaces malformed text before this function sees the parsed object.
    """
    warnings = _Warnings(parse_warnings)
    alert_id = _require_str(raw, "id")
    rule_id = _require_str(raw, "rule.id")
    rule_title = _title(raw, "rule.description", warnings)
    rule_level = wazuh_level_to_severity(_get(raw, "rule.level"))

    # Techniques come only from the rule's own MITRE mapping.
    rule_tags: list[str] = []
    mitre_ids = _get(raw, "rule.mitre.id")
    if mitre_ids is not None:
        if isinstance(mitre_ids, list):
            bad = 0
            for t in mitre_ids:
                if isinstance(t, str) and re.fullmatch(TECHNIQUE_ID_PATTERN, t):
                    rule_tags.append("attack." + t.lower())
                else:
                    bad += 1
            if bad:
                warnings.add(f"rule.mitre.id: {_count(bad, 'malformed technique ID')} dropped")
            rule_tags = _cap_tags(rule_tags, "rule.mitre.id", warnings)
        else:
            warnings.add("rule.mitre.id: not a list; ignored")

    host = _host(_get(raw, "agent.name"), "agent.name", warnings, warn_if_missing=True)
    user = _user(lambda name: _get(raw, name), WAZUH_USER_FIELDS, warnings)
    timestamp = _timestamp(_get(raw, "timestamp"), "timestamp", warnings)

    # CVEs come only from the vulnerability detector's field, never from event text.
    cves: list[str] = []
    cve = _get(raw, "data.vulnerability.cve")
    if cve is not None:
        if isinstance(cve, str) and re.fullmatch(CVE_PATTERN, cve):
            cves.append(cve)
        else:
            warnings.add("data.vulnerability.cve: malformed CVE ID dropped")

    flat = _Flattener()
    for path in WAZUH_EVENT_FIELDS:
        value = _get(raw, path)
        if value is not None:
            flat.add(path, value, depth=path.count("."))
    data = raw.get("data")
    if isinstance(data, dict):
        flat.add("data", data, depth=0)
    elif data is not None:
        warnings.add("data: not an object; ignored")
    flat.report(warnings)

    return _build(
        alert_id=alert_id,
        source="wazuh",
        rule_id=rule_id,
        rule_title=rule_title,
        rule_level=rule_level,
        rule_tags=rule_tags,
        host=host,
        user=user,
        timestamp=timestamp,
        cves=cves,
        event=flat.out,
        ingest_warnings=warnings.items,
    )


# --- Sigma match ---------------------------------------------------------


def from_sigma_match(raw: dict, *, parse_warnings: Sequence[str] = ()) -> Alert:
    """Normalize a parsed Sigma rule match (format in the module docstring).

    Callers with untrusted raw input use load_alert, which applies the size cap
    and replaces malformed text before this function sees the parsed object.
    """
    warnings = _Warnings(parse_warnings)
    rule_id = _require_str(raw, "rule.id")
    rule_title = _title(raw, "rule.title", warnings)
    rule_level = _get(raw, "rule.level")
    if rule_level not in SEVERITY_ORDER:
        raise IngestError("rule.level: must be one of " + ", ".join(SEVERITY_ORDER))

    rule_tags: list[str] = []
    tags = _get(raw, "rule.tags")
    if tags is not None:
        if isinstance(tags, list):
            bad = 0
            for t in tags:
                if isinstance(t, str) and re.fullmatch(SIGMA_TAG_PATTERN, t):
                    rule_tags.append(t)
                else:
                    bad += 1
            if bad:
                warnings.add(f"rule.tags: {_count(bad, 'malformed tag')} dropped")
            rule_tags = _cap_tags(rule_tags, "rule.tags", warnings)
        else:
            warnings.add("rule.tags: not a list; ignored")

    event = raw.get("event")
    if not isinstance(event, dict):
        warnings.add("event: missing or not an object; no event fields")
        event = {}

    alert_id = raw.get("alert_id")
    if alert_id is None:
        # Deterministic, so the same match always gets the same ID.
        digest = hashlib.sha256(json.dumps({"rule_id": rule_id, "event": event}, sort_keys=True).encode("utf-8"))
        alert_id = "sigma-" + digest.hexdigest()[:16]
    elif not (isinstance(alert_id, str) and re.fullmatch(ALERT_ID_PATTERN, alert_id)):
        raise IngestError("alert_id: must match " + ALERT_ID_PATTERN)

    aggregate = raw.get("aggregate")
    if aggregate is not None and not _valid_aggregate(aggregate):
        warnings.add("aggregate: malformed; dropped")
        aggregate = None

    flat = _Flattener()
    flat.add(None, event, depth=0)
    if aggregate is not None:
        flat.add(
            "aggregate",
            {
                "match_count": aggregate["match_count"],
                "first_seen": aggregate["first_seen"],
                "last_seen": aggregate["last_seen"],
                "distinct": aggregate["distinct"],
            },
            depth=0,
        )
    flat.report(warnings)
    # Looked up in the flattened event, so "host.name" matches both a literal
    # dotted key and a nested {"host": {"name": ...}} object.
    fields = flat.out
    host_field = next((f for f in SIGMA_HOST_FIELDS if fields.get(f) is not None), None)
    host = _host(fields.get(host_field), f"event.{host_field}", warnings, warn_if_missing=False) if host_field else None
    user_field = next((f for f in SIGMA_USER_FIELDS if isinstance(fields.get(f), str)), None)
    user = _user(fields.get, (user_field,), warnings, prefix="event.") if user_field else None
    if aggregate is not None:
        # The event is only the first of the correlated events. If the chosen
        # field varies across them (11 accounts in a password spray), naming the
        # first value as the alert's user or host would misrepresent the alert.
        # The distinct count stays in the event as aggregate.distinct.<field>.
        distinct = aggregate["distinct"]
        if distinct.get(host_field, 1) > 1:
            host = None
        if distinct.get(user_field, 1) > 1:
            user = None
        timestamp = _timestamp(aggregate["first_seen"], "aggregate.first_seen", warnings)
    else:
        time_field = next((f for f in SIGMA_TIME_FIELDS if isinstance(fields.get(f), str)), None)
        timestamp = _timestamp(fields[time_field], f"event.{time_field}", warnings) if time_field else None

    return _build(
        alert_id=alert_id,
        source="sigma",
        rule_id=rule_id,
        rule_title=rule_title,
        rule_level=rule_level,
        rule_tags=rule_tags,
        host=host,
        user=user,
        timestamp=timestamp,
        cves=[],  # the Sigma rules used here carry no CVE field
        event=fields,
        ingest_warnings=warnings.items,
    )


def _valid_aggregate(agg: Any) -> bool:
    if not isinstance(agg, dict) or set(agg) != {"match_count", "first_seen", "last_seen", "distinct"}:
        return False
    count = agg["match_count"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        return False
    if not isinstance(agg["first_seen"], str) or not isinstance(agg["last_seen"], str):
        return False
    distinct = agg["distinct"]
    if not isinstance(distinct, dict):
        return False
    return all(isinstance(n, int) and not isinstance(n, bool) and n >= 1 for n in distinct.values())


# --- Shared helpers ------------------------------------------------------


class _Warnings:
    """De-duplicated, capped list of fixed-template warnings."""

    def __init__(self, first: Sequence[str] = ()) -> None:
        self.items: list[str] = []
        # Parse warnings go in first, so the cap can never push them out.
        for message in first:
            self.add(message)

    def add(self, message: str) -> None:
        if message not in self.items and len(self.items) < MAX_WARNINGS:
            self.items.append(message)


class _Flattener:
    """Flatten nested objects into dotted keys, within depth, key-size and count limits.

    Values are copied verbatim: no stripping, escaping or normalization. The
    Alert model applies the per-field character cap afterwards. Drops are
    counted, never named, because input keys are attacker-influenced too.
    """

    def __init__(self) -> None:
        self.out: dict[str, Any] = {}
        self.too_deep = 0
        self.long_keys = 0
        self.duplicates = 0
        self.too_many = 0

    def add(self, key: str | None, value: Any, depth: int) -> None:
        """Add `value` under `key`; `depth` is the number of objects enclosing it below the alert root."""
        if isinstance(value, dict):
            if depth + 1 > MAX_DEPTH:
                self.too_deep += 1
                return
            for k, v in value.items():
                self.add(k if key is None else f"{key}.{k}", v, depth + 1)
            return
        if key is None:
            return
        if len(key) > MAX_KEY_CHARS:
            self.long_keys += 1
            return
        if key in self.out:
            # Flattening can make two input fields collide ("a.b" and {"a": {"b"}}).
            # First one wins, so a later field cannot overwrite an earlier one.
            self.duplicates += 1
            return
        if len(self.out) >= MAX_EVENT_KEYS:
            self.too_many += 1
            return
        if isinstance(value, list):
            value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        self.out[key] = value

    def report(self, warnings: _Warnings) -> None:
        if self.too_deep:
            warnings.add(f"event: {_count(self.too_deep, 'nested object')} dropped (deeper than {MAX_DEPTH} levels)")
        if self.long_keys:
            warnings.add(f"event: {_count(self.long_keys, 'field')} dropped (name longer than {MAX_KEY_CHARS} characters)")
        if self.duplicates:
            warnings.add(f"event: {_count(self.duplicates, 'field')} dropped (duplicate name after flattening)")
        if self.too_many:
            warnings.add(f"event: {_count(self.too_many, 'field')} dropped (more than {MAX_EVENT_KEYS} fields)")


def _get(obj: Any, path: str) -> Any:
    """Follow a dotted path through nested objects; None if any step is missing."""
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


def _require_str(raw: dict, path: str) -> str:
    value = _get(raw, path)
    if not isinstance(value, str) or not value:
        raise IngestError(f"{path}: missing or not a non-empty string")
    return value


def _title(raw: dict, path: str, warnings: _Warnings) -> str:
    # Required, but not trusted: Wazuh substitutes decoded event fields into
    # rule descriptions, so an attacker can make the title long. Truncating
    # instead of rejecting means a long value cannot keep the alert from triage.
    value = _require_str(raw, path)
    if len(value) > MAX_TITLE_CHARS:
        warnings.add(f"{path}: longer than {MAX_TITLE_CHARS} characters; truncated")
        return value[: MAX_TITLE_CHARS - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER
    return value


def _timestamp(value: Any, path: str, warnings: _Warnings) -> str | None:
    # The Sigma timestamp comes from event data. Too long to store: leave it
    # empty rather than reject the alert.
    if not isinstance(value, str):
        return None
    if len(value) > MAX_TIMESTAMP_CHARS:
        warnings.add(f"{path}: longer than {MAX_TIMESTAMP_CHARS} characters; timestamp left empty")
        return None
    return value


def _cap_tags(tags: list[str], path: str, warnings: _Warnings) -> list[str]:
    # Keep the first MAX_TAGS valid tags rather than reject the whole alert.
    if len(tags) > MAX_TAGS:
        warnings.add(f"{path}: {_count(len(tags) - MAX_TAGS, 'tag')} beyond the first {MAX_TAGS} dropped")
        return tags[:MAX_TAGS]
    return tags


def _host(value: Any, path: str, warnings: _Warnings, warn_if_missing: bool) -> str | None:
    # The host is used as a tool lookup key, so only allow-listed characters
    # pass. An invalid value stays visible in the event as evidence.
    if value is None:
        if warn_if_missing:
            warnings.add(f"{path}: missing; host left empty")
        return None
    if isinstance(value, str) and re.fullmatch(HOST_PATTERN, value):
        return value
    warnings.add(f"{path}: not a valid hostname; host left empty")
    return None


def _user(lookup: Callable[[str], Any], fields: tuple[str, ...], warnings: _Warnings, prefix: str = "") -> str | None:
    """First string value among the candidate fields."""
    for name in fields:
        value = lookup(name)
        if isinstance(value, str):
            # Too long to store: leave it empty rather than reject the alert,
            # so an attacker cannot suppress an alert with a long username.
            if len(value) > MAX_USER_CHARS:
                warnings.add(f"{prefix}{name}: longer than {MAX_USER_CHARS} characters; user left empty")
                return None
            return value
    return None


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _build(**fields: Any) -> Alert:
    try:
        return Alert(**fields)
    except ValidationError as e:
        # Report only top-level Alert field names and error types. Pydantic's
        # messages and deeper locations can include input values or event keys.
        problems = sorted({f"{err['loc'][0]}: {err['type']}" for err in e.errors() if err["loc"]})
        raise IngestError("invalid alert: " + "; ".join(problems or ["validation failed"])) from None
