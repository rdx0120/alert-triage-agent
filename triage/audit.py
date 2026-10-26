"""The audit log: a metadata-only projection of an AgentResult into JSONL.

One JSON line per operation: the run, each lookup, each model call, and, when
the caller passes it, the guardrails' summary. Field names follow the
OpenTelemetry GenAI semantic conventions, with project fields under triage.*.
Every record is built from named fields with a fixed key set, so the log never
holds content: no alert text, prompts, messages, model text, tool arguments,
tool data, error messages, the backend name or the endpoint, and from the
summary no free text, technique name, asset host or owner.

run_agent() does not write the log; the caller passes the run's result to
write_audit_log(), so the loop stays free of file I/O.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import time
from datetime import datetime, timedelta
from typing import get_args

try:
    import fcntl
except ImportError:   # not on Windows; write_audit_log() then refuses to run
    fcntl = None

from pydantic import ValidationError

from . import files
from .backends.ollama import MODEL_NAME_PATTERN
from .prompt import INVESTIGATION_MAX_OUTPUT_TOKENS, MAX_OUTPUT_TOKENS
from .schemas import (
    ALERT_ID_PATTERN, RUN_ID_PATTERN, TECHNIQUE_ID_PATTERN, AgentResult, Alert, BudgetDetail, DraftSeverity,
    DraftTechnique, Enrichment, Gap, GapKind, GapReason, ModelCallRecord, ModelDraft, Severity, StopReason,
    ToolCallRecord, TriageSummary,
)

# 2: adds the optional triage.summary record (DD-023). Records of other types
# are unchanged from version 1, and each line carries its own version.
AUDIT_SCHEMA_VERSION = 2
AGENT_NAME = "alert-triage-agent"
MAX_AUDIT_LINE_BYTES = 8_192
# How long an append waits for another writer's lock before giving up.
LOCK_TIMEOUT_S = 10.0
PROVIDERS = ("ollama", "heuristic")
RULE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
PROBLEM_PATTERN = r"^(?:\(root\)|[a-z_<>][a-z0-9_<>]*(?:\.[a-z0-9_<>]+)*): [a-z_]+$|^and [0-9]+ more$"
STARTED_AT_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
FINDING_KEYS = ("technique", "severity", "next_steps", "containment", "missing_data")

_STARTED_AT_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class AuditLockTimeout(OSError):
    """Another writer held the audit log's lock for longer than LOCK_TIMEOUT_S."""


class AuditLogIncomplete(OSError):
    """The audit log does not end with a newline, so its last record is partial."""


class AuditRollbackFailed(OSError):
    """A failed append could not be undone; the log may end in a partial record."""


class AuditNotDurable(OSError):
    """The records were written and synced, but a directory sync failed."""


def _matches(pattern: str, value: object) -> bool:
    # fullmatch, because "$" would let re.match accept a trailing newline.
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _provider(backend: str) -> str:
    # A closed list: the backend string itself may name a model or anything
    # else a caller chose, so it is never written.
    provider = backend.partition(":")[0]
    return provider if provider in PROVIDERS else "unknown"


def _model(value: object) -> str | None:
    # The audit log promises never to hold the model endpoint, and the Ollama
    # pattern allows ":" and "/", so an address would otherwise pass. A model
    # whose tag is only digits is also written as null; that errs on the side
    # of not logging. A bracketed IPv6 address with a port already fails
    # MODEL_NAME_PATTERN.
    if not _matches(MODEL_NAME_PATTERN, value) or "://" in value:
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return None
    tail = value.rpartition(":")[2]
    if tail.isascii() and tail.isdigit():
        return None
    return value


def _problems(problems: list[str]) -> list[str]:
    # The loop already sanitizes problems; this keeps only their known shape,
    # so a problem string that ever carried other text is not written.
    return [p if _matches(PROBLEM_PATTERN, p) else "<unrecognized>" for p in problems]


def _finding_counts(value: object) -> dict[str, int] | None:
    if not isinstance(value, dict) or set(value) != set(FINDING_KEYS):
        return None
    if not all(type(v) is int and v >= 0 for v in value.values()):   # type(): a bool is not a count
        return None
    return {k: value[k] for k in FINDING_KEYS}


def _is_duration(value: object) -> bool:
    # type(): a bool is not a duration; NaN, infinity and negatives are not times.
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _member(value: object, allowed: tuple) -> bool:
    # type(): a str subclass can override __eq__ to pass the membership test,
    # and json.dumps would then write its real text.
    return type(value) is str and value in allowed


def _well_formed(result: object, alert: object) -> bool:
    # The containers the projection reads, checked before any value, so a
    # replaced one gives the fixed message instead of a TypeError or
    # AttributeError. The values inside are checked afterwards.
    if not isinstance(result, AgentResult) or not isinstance(alert, Alert):
        return False
    draft = result.draft
    return (
        isinstance(result.enrichment, Enrichment)
        and isinstance(result.model_calls, list) and all(isinstance(r, ModelCallRecord) for r in result.model_calls)
        and isinstance(result.tool_records, list) and all(isinstance(r, ToolCallRecord) for r in result.tool_records)
        and (draft is None or (isinstance(draft, ModelDraft) and isinstance(draft.severity, DraftSeverity)
                               and (draft.technique is None or isinstance(draft.technique, DraftTechnique))))
    )


def _run_values_in_schema(result: AgentResult, alert: Alert) -> bool:
    # Every run-level value the projection writes, or whose length it writes.
    # The allowed sets come from the schema, so they cannot drift from it.
    draft = result.draft
    gaps = result.enrichment.gaps
    return (
        _member(alert.source, get_args(Alert.model_fields["source"].annotation))
        and _member(alert.rule_level, get_args(Severity))
        and (draft is None or _member(draft.severity.value, get_args(Severity)))
        and _member(result.enrichment.status, get_args(Enrichment.model_fields["status"].annotation))
        # The container first, so a replaced one fails here with the fixed
        # message instead of a TypeError or AttributeError below.
        and isinstance(gaps, list) and all(isinstance(g, Gap) for g in gaps)
        and all(_member(g.kind, get_args(GapKind)) and _member(g.reason, get_args(GapReason)) for g in gaps)
        and _member(result.stop_reason, get_args(StopReason))
        and (result.budget_detail is None or _member(result.budget_detail, get_args(BudgetDetail)))
        and _is_duration(result.duration_s)
        and _is_duration(result.enrichment_duration_s)
        and type(result.tool_calls) is int and result.tool_calls >= 0
        and isinstance(alert.ingest_warnings, list)
        and isinstance(result.validation_errors, list)
        and (draft is None or all(isinstance(v, list) for v in (draft.next_steps, draft.containment,
                                                                draft.missing_data)))
        and isinstance(result.backend, str)
    )


def _checked_summary(summary: object, result: AgentResult) -> TriageSummary:
    """A validated copy of summary, which must belong to this run."""
    if not isinstance(summary, TriageSummary):
        raise ValueError("summary is not a valid TriageSummary")
    # Assignment is not validated, so revalidate; the copy is what is
    # projected, and Pydantic returns exact str values and the schema's own
    # Literal values. warnings=False: a serializer warning for a wrongly typed
    # value quotes that value.
    try:
        checked = TriageSummary.model_validate(summary.model_dump(warnings=False))
    except ValidationError:
        raise ValueError("summary is not a valid TriageSummary") from None
    if checked.alert_id != result.alert_id or checked.run_id != result.run_id:
        raise ValueError("summary does not match the run")
    return checked


def _timestamp(started: datetime, offset: float | None) -> str:
    moment = started + timedelta(seconds=offset or 0)
    return moment.isoformat(timespec="milliseconds") + "Z"


def audit_records(result: AgentResult, alert: Alert, *, summary: TriageSummary | None = None) -> list[dict]:
    """The run's audit records, in line order: the run, enrichment lookups, then each model call and its lookups.

    With a summary, a final triage.summary record follows: the guardrails'
    decision as codes and counts. The summary must belong to the run.
    """
    # Fixed messages: the values come from the caller and are not echoed.
    if not _well_formed(result, alert):
        raise ValueError("the run result is not well-formed")
    if alert.alert_id != result.alert_id:
        raise ValueError("alert does not match the run")
    if not _matches(RUN_ID_PATTERN, result.run_id):
        raise ValueError("run_id must be 32 lowercase hexadecimal characters")
    if not _matches(STARTED_AT_PATTERN, result.started_at):
        raise ValueError("started_at must be UTC ISO 8601 with milliseconds and a Z suffix")
    try:
        started = datetime.strptime(result.started_at, _STARTED_AT_FORMAT)
    except ValueError:
        raise ValueError("started_at must be UTC ISO 8601 with milliseconds and a Z suffix") from None
    if result.duration_s is None or result.enrichment_duration_s is None:
        raise ValueError("the run has no recorded durations")
    # The loop assigns some fields after construction and Pydantic does not
    # validate assignment, so nothing is written unless every record is
    # within its schema. The validated copies are the ones projected.
    try:
        # warnings=False: a serializer warning for a wrongly typed value
        # quotes that value; the value is still rejected by validation.
        model_calls = [ModelCallRecord.model_validate(r.model_dump(warnings=False)) for r in result.model_calls]
        tool_records = [ToolCallRecord.model_validate(r.model_dump(warnings=False)) for r in result.tool_records]
    except ValidationError:
        raise ValueError("a model call or lookup record is outside its schema") from None
    # Same reason for the values the run record takes directly from the
    # result and the alert: nothing reaches the log unless every value
    # written is within its schema.
    if not _run_values_in_schema(result, alert):
        raise ValueError("a run-level field is outside its schema")
    checked = None if summary is None else _checked_summary(summary, result)

    provider = _provider(result.backend)
    model = _model(result.model)
    records: list[dict] = []
    lookups = 0

    def add(offset: float | None, event: str, operation: str, fields: dict) -> None:
        records.append({
            "timestamp": _timestamp(started, offset),
            "event.name": event,
            "triage.audit.schema_version": AUDIT_SCHEMA_VERSION,
            "gen_ai.conversation.id": result.run_id,
            "triage.seq": len(records),
            "gen_ai.operation.name": operation,
            **fields,
        })

    def lookup(r: ToolCallRecord) -> None:
        nonlocal lookups
        lookups += 1
        add(r.start_s, "triage.tool_call", "execute_tool", {
            "gen_ai.tool.name": r.tool,
            "gen_ai.tool.type": "function",
            "error.type": r.status if r.status in ("invalid_input", "error") else None,
            "triage.evidence.id": r.evidence_id,
            "triage.requested_by": r.requested_by,
            "triage.tool.status": r.status,
            "triage.turn": r.turn,
            "triage.repeat": r.repeat,
            "triage.start_s": r.start_s,
            "triage.duration_s": r.duration_s,
            "triage.view.state": r.view,
            "triage.view.string_cap": r.view_string_cap,
            "triage.view.strings_cut": r.view_strings_cut,
            "triage.view.bytes": r.view_bytes,
        })

    draft = result.draft
    technique_id = draft.technique.technique_id if draft and draft.technique else None
    add(0, "triage.run", "invoke_agent", {
        "gen_ai.agent.name": AGENT_NAME,
        "gen_ai.provider.name": provider,
        "gen_ai.request.model": model,
        "error.type": model_calls[-1].error_type if model_calls else None,
        "triage.alert.id": alert.alert_id if _matches(ALERT_ID_PATTERN, alert.alert_id) else None,
        "triage.alert.source": alert.source,
        "triage.rule.id": alert.rule_id if _matches(RULE_ID_PATTERN, alert.rule_id) else None,
        "triage.rule.level": alert.rule_level,
        "triage.ingest_warnings.count": len(alert.ingest_warnings),
        "triage.enrichment.status": result.enrichment.status,
        "triage.enrichment.gaps": [f"{g.kind}:{g.reason}" for g in result.enrichment.gaps],
        "triage.enrichment.duration_s": result.enrichment_duration_s,
        "triage.stop_reason": result.stop_reason,
        "triage.budget_detail": result.budget_detail,
        "triage.duration_s": result.duration_s,
        "triage.model_calls.count": len(result.model_calls),
        "triage.tool_calls.count": result.tool_calls,
        "triage.draft.severity": draft.severity.value if draft else None,
        "triage.draft.technique_id": technique_id if _matches(TECHNIQUE_ID_PATTERN, technique_id) else None,
        "triage.draft.findings": {
            "technique": 0 if draft.technique is None else 1, "next_steps": len(draft.next_steps),
            "containment": len(draft.containment), "missing_data": len(draft.missing_data),
        } if draft else None,
        "triage.validation_errors": _problems(result.validation_errors),
    })

    for r in tool_records:
        if r.requested_by == "enrichment":
            lookup(r)
    for call in model_calls:
        investigate = call.phase == "investigate"
        # request.sha256 covers the serialized prompt (messages, tools,
        # schema), not the HTTP body; reply.sha256 covers the reply text, not
        # its tool calls.
        add(call.start_s, "triage.model_call", "chat", {
            "gen_ai.provider.name": provider,
            "gen_ai.request.model": model,
            # The limits the loop sets for each phase.
            "gen_ai.request.max_tokens": INVESTIGATION_MAX_OUTPUT_TOKENS if investigate else MAX_OUTPUT_TOKENS,
            "gen_ai.output.type": "text" if investigate else "json",
            "gen_ai.usage.input_tokens": call.input_tokens,
            "gen_ai.usage.output_tokens": call.output_tokens,
            "gen_ai.response.finish_reasons": [call.finish_reason] if call.finish_reason is not None else None,
            "error.type": call.error_type,
            "triage.phase": call.phase,
            "triage.turn": call.turn,
            "triage.start_s": call.start_s,
            "triage.duration_s": call.duration_s,
            "triage.request.bytes": call.request_bytes,
            "triage.request.token_bound": call.token_bound,
            "triage.request.sha256": call.request_sha256,
            "triage.reply.kind": call.reply,
            "triage.reply.text_bytes": call.reply_text_bytes,
            "triage.reply.sha256": call.reply_sha256,
            "triage.reply.truncated": call.truncated,
            "triage.tool_calls.requested": call.tool_calls_requested,
            "triage.tool_calls.run": call.tool_calls_run,
            "triage.tool_calls.dropped": call.tool_calls_dropped,
            "triage.validation.accepted": call.accepted,
            "triage.validation.problems": None if call.problems is None else _problems(call.problems),
            "triage.finding_counts": _finding_counts(call.finding_counts),
        })
        for r in tool_records:
            if r.requested_by == "model" and r.turn == call.turn:
                lookup(r)

    if lookups != len(result.tool_records):
        raise ValueError("every lookup must appear exactly once in the audit log")

    if checked is not None:
        # The guardrails run after the loop and are not timed, so the record
        # carries the run's end. Only codes, IDs and counts: never the
        # rationale, steps, actions, missing-data descriptions, the technique
        # name, or the asset host and owner (an owner can be a person).
        add(result.duration_s, "triage.summary", "invoke_agent", {
            "triage.summary.status": checked.status,
            "triage.severity.value": checked.severity.value,
            "triage.severity.rule_floor": checked.severity.rule_floor,
            "triage.severity.origin": checked.severity.origin,
            "triage.severity.sources": list(checked.severity.sources),
            "triage.technique.id": checked.technique.technique_id,
            "triage.technique.basis": checked.technique.basis,
            "triage.technique.origin": checked.technique.origin,
            "triage.asset.criticality": checked.asset.criticality,
            "triage.asset.exposure": checked.asset.exposure,
            "triage.findings": {
                "next_steps": len(checked.next_steps),
                "containment": len(checked.containment),
                "missing_data_enrichment": sum(1 for m in checked.missing_data if m.origin == "enrichment"),
                "missing_data_model": sum(1 for m in checked.missing_data if m.origin == "model"),
            },
            "triage.anomalies": list(checked.anomalies),
            "triage.injection.suspected": checked.injection_suspected,
            "triage.injection.signals": list(checked.injection_signals),
        })
    return records


def dumps_line(record: dict) -> str:
    """One record as one JSONL line, at most MAX_AUDIT_LINE_BYTES."""
    # ASCII-only, so lone surrogates, control characters and newlines are
    # escaped and one record is always one line.
    line = json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n"
    if len(line.encode("ascii")) > MAX_AUDIT_LINE_BYTES:
        raise ValueError("audit record exceeds MAX_AUDIT_LINE_BYTES")
    return line


def write_audit_log(result: AgentResult, alert: Alert, path: str | os.PathLike, *,
                    summary: TriageSummary | None = None) -> int:
    """Append the run's audit records to path, and the summary record if summary is given.

    Returns the number of lines written. On return, the records, the file's
    entry in its directory and the directory's entry in its parent are synced
    to disk, whichever writer created them. A failed append is rolled back to
    the file's previous size.

    Writers that use this function exclude each other with an exclusive lock.
    Only the file and its parent directory are checked, the directory's
    ancestors are trusted, and the log is not tamper-evident: production use
    needs an append-only store.
    """
    # Everything is built and serialized first, so any error raises before
    # the file system is touched.
    lines = [dumps_line(r) for r in audit_records(result, alert, summary=summary)]
    data = "".join(lines).encode("ascii")
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("audit log needs O_NOFOLLOW, which this platform lacks")
    if fcntl is None or not files.supported():
        raise OSError("audit log needs O_DIRECTORY, dir_fd and file locking, which this platform lacks")
    parent, name = os.path.split(os.fspath(path))
    try:
        files.single_component(name)
    except ValueError:
        raise ValueError("audit log path must end in a file name") from None
    directory = parent or "."
    dir_fd = files.open_private_dir(directory, what="audit log", create=True)
    try:
        fd = files.open_private_file(dir_fd, name, what="audit log", append=True)
        try:
            _lock(fd)
            _append(fd, data)
            # Still under the lock, so a later writer cannot report success
            # before these entries are durable.
            try:
                files.sync_dir_and_parent(dir_fd, directory)
            except OSError:
                raise AuditNotDurable("audit records were written, but their directory entries "
                                      "may not be durable") from None
        finally:
            os.close(fd)   # also releases the lock
    finally:
        os.close(dir_fd)
    return len(lines)


def _lock(fd: int) -> None:
    deadline = time.monotonic() + LOCK_TIMEOUT_S
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise AuditLockTimeout("audit log is locked by another writer") from None
            time.sleep(0.05)


def _append(fd: int, data: bytes) -> None:
    # Under the lock. A log whose last record is partial (a crash during an
    # earlier write) is refused, not appended to: gluing a new record onto it
    # would corrupt both. The operator repairs it by truncating it to its last
    # newline.
    size = os.fstat(fd).st_size
    if size and os.pread(fd, 1, size - 1) != b"\n":
        raise AuditLogIncomplete("audit log ends without a newline")
    try:
        files.write_all(fd, data, what="audit log")
        os.fsync(fd)
    except OSError:
        # Undo this append, then report the original error.
        try:
            os.ftruncate(fd, size)
            os.fsync(fd)
        except OSError:
            raise AuditRollbackFailed("audit log write failed and could not be rolled back; "
                                      "it may end in a partial record") from None
        raise
