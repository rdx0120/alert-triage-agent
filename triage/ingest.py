"""Alert ingestion: turn a raw Wazuh 4.x alert or a Sigma rule match into an Alert.

Trust boundary. Rule metadata (rule ID, title, level, ATT&CK mapping) comes
from the SIEM's own rule set and decides the alert's severity floor, so it is
required and validated strictly: an alert without it is rejected rather than
triaged on a guessed severity. Everything under Wazuh's `data` object and the
Sigma `event` object is attacker-influenced (command lines, usernames, paths,
log text). It is copied verbatim, within size limits, and is never mined for
technique IDs or CVEs.

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
import re
from typing import Any, Callable, Literal

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

MAX_RAW_ALERT_BYTES = 64 * 1024
MAX_DEPTH = 5
MAX_EVENT_KEYS = 50  # must equal the max_length of Alert.event
MAX_KEY_CHARS = 128
MAX_WARNINGS = 20  # must equal the max_length of Alert.ingest_warnings
MAX_USER_CHARS = 256  # must equal the max_length of Alert.user

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
    """Parse one raw alert of the stated format. Applies the size cap before parsing."""
    if fmt not in ("wazuh", "sigma"):
        raise IngestError("fmt: must be 'wazuh' or 'sigma'")
    if isinstance(text, str):
        data = text.encode("utf-8")
    elif isinstance(text, bytes):
        data = text
    else:
        raise IngestError("input: must be str or bytes")
    # Checked before json.loads so an oversized payload never reaches the parser.
    if len(data) > MAX_RAW_ALERT_BYTES:
        raise IngestError(f"input: larger than {MAX_RAW_ALERT_BYTES} bytes")
    try:
        raw = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        # ValueError covers bad UTF-8 and bad JSON; RecursionError covers
        # arrays nested tens of thousands deep, which fit inside the size cap.
        raise IngestError("input: not valid JSON") from None
    if not isinstance(raw, dict):
        raise IngestError("input: top-level JSON value must be an object")
    return from_wazuh(raw) if fmt == "wazuh" else from_sigma_match(raw)


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


def from_wazuh(raw: dict) -> Alert:
    """Normalize a parsed Wazuh 4.x alert. Callers with raw text use load_alert (size cap)."""
    warnings = _Warnings()
    alert_id = _require_str(raw, "id")
    rule_id = _require_str(raw, "rule.id")
    rule_title = _require_str(raw, "rule.description")
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
        else:
            warnings.add("rule.mitre.id: not a list; ignored")

    host = _host(_get(raw, "agent.name"), "agent.name", warnings, warn_if_missing=True)
    user = _user(lambda name: _get(raw, name), WAZUH_USER_FIELDS, warnings)
    timestamp = _get(raw, "timestamp")
    timestamp = timestamp if isinstance(timestamp, str) else None

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


def from_sigma_match(raw: dict) -> Alert:
    """Normalize a parsed Sigma rule match (format in the module docstring)."""
    warnings = _Warnings()
    rule_id = _require_str(raw, "rule.id")
    rule_title = _require_str(raw, "rule.title")
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
    user = _user(fields.get, SIGMA_USER_FIELDS, warnings, prefix="event.")
    if aggregate is not None:
        timestamp = aggregate["first_seen"]
    else:
        timestamp = next((fields[f] for f in SIGMA_TIME_FIELDS if isinstance(fields.get(f), str)), None)

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

    def __init__(self) -> None:
        self.items: list[str] = []

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
