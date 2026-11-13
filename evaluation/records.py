"""Schemas, readers and validation for every record the scorer reads.

This module is the only place that sees raw records. It validates them, then
copies only the fields scoring may use into read-only views. The scorer
(evaluation/scorer.py) receives views and nothing else, so a metric cannot be
quietly computed from a field outside the reviewed allow-list: asking a view
for any other field raises.

A missing or inconsistent record does not get scored around. It is recorded
as a defect with a fixed rule ID, and the pass is reported as defective.
"""

from __future__ import annotations

import builtins
import copy
import errno
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal, get_args

from pydantic import AfterValidator, Field, ValidationError, field_validator, model_validator

from triage import cli as triage_cli
from triage.backends.ollama import MODEL_NAME_PATTERN
from triage.schemas import (
    ALERT_ID_PATTERN, RUN_ID_PATTERN, TECHNIQUE_ID_PATTERN, Alert, Anomaly, Severity, TriageSummary,
)

from .common import (
    CLASSIFICATION_CODES, PASS_ID_RE, PRODUCTION_K, REDACTION_RULES, RULE_IDS,
    RUNBOOK_NAME_RE, AllowListError, DefectError, EvalModel, EvaluationError, SchemaError,
    canonical_dumps, is_case_id, is_fixture_case_id, read_regular, safe_location, severity_index,
    sha256_hex, strict_loads,
)

HEX64 = r"^[0-9a-f]{64}$"
TIMESTAMP = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
FAMILIES = ("dev", "A", "B", "C", "D")


def _exactly_one(value: int) -> int:
    if value != 1:
        raise ValueError("version must be 1")
    return value


def _attempts(value: int) -> int:
    if not 1 <= value <= 3:
        raise ValueError("attempts must be 1 to 3")
    return value


# A strict int, not Literal[1]: pydantic's literal check would accept JSON true
# for 1, and a record must have exactly one accepted form.
Version1 = Annotated[int, AfterValidator(_exactly_one)]
TEST_FAMILIES = ("A", "B", "C", "D")


# --- Registry -------------------------------------------------------------

class RegistryEntry(EvalModel):
    case_id: str
    family: Literal["dev", "A", "B", "C", "D"]
    format: Literal["sigma", "wazuh"]
    path: str
    clean_twin: str | None
    phrasing: Literal["known", "evasive"] | None
    alert_id: str = Field(pattern=ALERT_ID_PATTERN)
    rule_level: Severity


class Registry(EvalModel):
    version: Version1
    cases: list[RegistryEntry]

    def by_id(self) -> dict[str, RegistryEntry]:
        return {c.case_id: c for c in self.cases}

    def test_cases(self) -> list[RegistryEntry]:
        return [c for c in self.cases if c.family in TEST_FAMILIES]


# --- Labels ---------------------------------------------------------------

RATIONALE_FIELD = re.compile(r"^(alert|inventory|kev|epss|attack|runbook)(\.[A-Za-z0-9_-]{1,64}){1,4}$")
PRINTABLE_NOTE = re.compile(r"^[ -~]{1,300}$")


class Rationale(EvalModel):
    field: str
    note: str


class Objectives(EvalModel):
    marker: str
    kind: Literal["O-S", "O-T"]
    target: str


class LabelEntry(EvalModel):
    case_id: str
    expected_severity: Severity
    acceptable_techniques: list[str]
    expected_status: Literal["triaged", "insufficient_data"]
    expected_runbook: str
    expected_flagged: bool | None
    objectives: Objectives | None
    rationale: list[Rationale] = Field(min_length=1)


class Labels(EvalModel):
    version: Version1
    rubric_sha256: str = Field(pattern=HEX64)
    cases: list[LabelEntry]

    def by_id(self) -> dict[str, LabelEntry]:
        return {c.case_id: c for c in self.cases}


# --- Order ----------------------------------------------------------------

class OrderEntry(EvalModel):
    position: int
    case_id: str
    role: Literal["warmup", "scored", "determinism"]
    repeat: int


class Order(EvalModel):
    version: Version1
    seed: str = Field(pattern=HEX64)
    k: int
    baseline: list[OrderEntry]
    model: list[OrderEntry]

    def sequence(self, name: str) -> list[OrderEntry]:
        if name == "baseline":
            return self.baseline
        if name == "model":
            return self.model
        raise SchemaError("unknown sequence")


# --- H record --------------------------------------------------------------

CheckResult = Literal["ok", "not_applicable"]


class Checks(EvalModel):
    attempts: Annotated[int, AfterValidator(_attempts)]
    code: CheckResult
    python: CheckResult
    embedder: CheckResult
    ollama: CheckResult
    server_settings: CheckResult
    disk: CheckResult


class Files(EvalModel):
    summary: bool
    audit: bool


# The four messages triage.cli combines with an errno suffix (_errno_suffix).
_ERRNO_SUFFIXED = ("E_INPUT_READ", "E_AUDIT_UNSAFE", "E_AUDIT_WRITE", "E_OUT_UNSAFE")
# Exception class names the CLI's internal-error message may carry. Class names
# come from code, not from input, but the set stays closed so an H record can
# never hold free text.
INTERNAL_ERROR_CLASSES = tuple(sorted(
    {name for name, obj in vars(builtins).items() if isinstance(obj, type) and issubclass(obj, Exception)}
    | {"ValidationError"}))


def _known_cli_messages() -> frozenset[str]:
    messages: set[str] = set()
    for name in dir(triage_cli):
        if not name.startswith("E_"):
            continue
        constant = getattr(triage_cli, name)
        if name == "E_INPUT_INVALID":
            messages.update(constant.format(fmt=fmt) for fmt in ("sigma", "wazuh"))
        elif name == "E_INTERNAL":
            messages.update(f"{constant} ({cls})" for cls in INTERNAL_ERROR_CLASSES)
        else:
            messages.add(constant)
            if name in _ERRNO_SUFFIXED:
                messages.update(f"{constant} ({code})" for code in errno.errorcode.values())
    lines = {f"{triage_cli.PROG}: error: {m}" for m in messages}
    lines.add(f"{triage_cli.PROG}: {triage_cli.NOTICE_NO_AUDIT}")
    return frozenset(lines)


KNOWN_CLI_MESSAGES = _known_cli_messages()


class HarnessRecord(EvalModel):
    version: Version1
    pass_id: str
    position: int
    case_id: str
    role: Literal["warmup", "scored", "determinism"]
    repeat: int
    backend: Literal["heuristic", "ollama"]
    started_at: str = Field(pattern=TIMESTAMP)
    ended_at: str = Field(pattern=TIMESTAMP)
    exit_status: int | None
    signal: int | None
    class_: Literal["outcome", "no_output"] = Field(alias="class")
    reason: Literal["exit", "signal", "deadline", "interrupted"] | None
    run_id: str | None = Field(pattern=RUN_ID_PATTERN)
    runbook_hits: list[str] | None
    checks: Checks
    server_restarts: int | None
    cli_message: str | None
    stderr_nonempty: bool
    files: Files

    @field_validator("runbook_hits")
    @classmethod
    def _hit_names(cls, value):
        if value is not None and not all(RUNBOOK_NAME_RE.fullmatch(v) for v in value):
            raise ValueError("runbook hit name")
        return value

    @field_validator("cli_message")
    @classmethod
    def _cli_message(cls, value):
        # Exact membership only: a pattern over printable text would let a
        # path, an address or other free text into a published record.
        if value is not None and value not in KNOWN_CLI_MESSAGES:
            raise ValueError("unknown cli message")
        return value

    @field_validator("pass_id")
    @classmethod
    def _pass_id(cls, value):
        if PASS_ID_RE.fullmatch(value) is None:
            raise ValueError("pass id")
        return value

    @model_validator(mode="after")
    def _reason_matches_class(self):
        if (self.class_ == "outcome") != (self.reason is None):
            raise ValueError("reason must be null exactly for outcome")
        return self


H_KEYS = ("version", "pass_id", "position", "case_id", "role", "repeat", "backend", "started_at",
          "ended_at", "exit_status", "signal", "class", "reason", "run_id", "runbook_hits", "checks",
          "server_restarts", "cli_message", "stderr_nonempty", "files")
CHECK_KEYS = ("attempts", "code", "python", "embedder", "ollama", "server_settings", "disk")


def load_harness(data: bytes) -> dict:
    """Validate an H record; it must be in its one canonical byte form, with keys in schema order."""
    try:
        obj = strict_loads(data)
        if not isinstance(obj, dict) or tuple(obj) != H_KEYS:
            raise SchemaError("H keys")
        if not isinstance(obj["checks"], dict) or tuple(obj["checks"]) != CHECK_KEYS:
            raise SchemaError("H check keys")
        if not isinstance(obj["files"], dict) or tuple(obj["files"]) != ("summary", "audit"):
            raise SchemaError("H file keys")
        HarnessRecord.model_validate(obj)
        if canonical_dumps(obj) != data:
            raise SchemaError("H not canonical")
    except (SchemaError, ValidationError):
        raise DefectError("b4-rule-1") from None
    return obj


# --- Ledger ---------------------------------------------------------------

class LedgerEntry(EvalModel):
    seq: int
    event: Literal["pass_start", "run_start", "run_end", "check_failed", "pass_end"]
    position: int | None
    case_id: str | None
    class_: Literal["outcome", "no_output", "complete", "incomplete", "void", "defective"] | None = Field(alias="class")
    prev: str = Field(pattern=HEX64)


LEDGER_KEYS = ("seq", "event", "position", "case_id", "class", "prev")
PASS_CLASSES = ("complete", "incomplete", "void", "defective")


def verify_ledger(data: bytes) -> list[LedgerEntry]:
    """Check the chain and the event grammar. Any failure is the "ledger" defect."""
    def bad():
        return DefectError("ledger")

    if not data.endswith(b"\n"):
        raise bad()
    lines = data.split(b"\n")[:-1]
    entries: list[LedgerEntry] = []
    previous = None
    for index, line in enumerate(lines):
        try:
            obj = strict_loads(line)
            if not isinstance(obj, dict) or tuple(obj) != LEDGER_KEYS:
                raise bad()
            entry = LedgerEntry.model_validate(obj)
        except (SchemaError, ValidationError):
            raise bad() from None
        if canonical_dumps(obj) != line + b"\n" or entry.seq != index + 1:
            raise bad()
        expected_prev = "0" * 64 if previous is None else sha256_hex(previous + b"\n")
        if entry.prev != expected_prev:
            raise bad()
        previous = line
        entries.append(entry)
    if len(entries) < 2 or entries[0].event != "pass_start" or entries[-1].event != "pass_end":
        raise bad()
    next_position = 1
    running: LedgerEntry | None = None
    for entry in entries:
        event = entry.event
        if event in ("pass_start", "pass_end"):
            if entry.position is not None or entry.case_id is not None:
                raise bad()
            if event == "pass_start" and (entry is not entries[0] or entry.class_ is not None):
                raise bad()
            if event == "pass_end" and (entry is not entries[-1] or entry.class_ not in PASS_CLASSES
                                        or running is not None):
                raise bad()
            continue
        if entry.position is None or entry.case_id is None:
            raise bad()
        if event == "run_start":
            if running is not None or entry.position != next_position or entry.class_ is not None:
                raise bad()
            running = entry
        elif event == "run_end":
            if (running is None or entry.position != running.position or entry.case_id != running.case_id
                    or entry.class_ not in ("outcome", "no_output")):
                raise bad()
            running = None
            next_position += 1
        else:  # check_failed: the run at next_position did not start (yet)
            if running is not None or entry.position != next_position or entry.class_ is not None:
                raise bad()
    return entries


def ledger_matches_order(entries: list[LedgerEntry], sequence_entries: list[OrderEntry]) -> list[str]:
    problems = []
    by_position = {e.position: e for e in sequence_entries}
    started = [e for e in entries if e.event == "run_start"]
    for count, entry in enumerate(started, start=1):
        if entry.position != count:
            problems.append("ledger: started positions are not a prefix of the order")
            break
    for entry in entries:
        if entry.event in ("run_start", "run_end", "check_failed"):
            planned = by_position.get(entry.position)
            if planned is None or planned.case_id != entry.case_id:
                problems.append(f"ledger: case differs from the order at position {entry.position}")
    end = entries[-1]
    if end.class_ == "complete" and len(started) != len(sequence_entries):
        problems.append("ledger: complete pass did not run every position")
    return problems


# --- Redaction records ------------------------------------------------------

PASS_FILE_RE = re.compile(r"^(environment\.json|ledger\.jsonl|run-[0-9]{4}\.(harness\.json|audit\.jsonl|summary\.json))$")
JSON_POINTER_RE = re.compile(r"^(/([^/~]|~[01])*)+$")
JSONL_POINTER_RE = re.compile(r"^L[1-9][0-9]*(/([^/~]|~[01])*)+$")


class RedactionItem(EvalModel):
    file: str
    pointer: str
    rule: Literal[REDACTION_RULES]
    n: int
    classification: Literal[CLASSIFICATION_CODES]


class Redactions(EvalModel):
    version: Version1
    items: list[RedactionItem]


class ScanItem(EvalModel):
    n: int
    file: str
    pointer: str
    rule: Literal[RULE_IDS]


class ScanItems(EvalModel):
    version: Version1
    items: list[ScanItem]


class Classification(EvalModel):
    version: Version1
    scan_sha256: str = Field(pattern=HEX64)
    items: dict[str, Literal[CLASSIFICATION_CODES]]


def _pointer_ok(file: str, pointer: str) -> bool:
    pattern = JSONL_POINTER_RE if file.endswith(".jsonl") else JSON_POINTER_RE
    return pattern.fullmatch(pointer) is not None


def _items_problems(items, what: str) -> list[str]:
    problems = []
    for expected, item in enumerate(items, start=1):
        if item.n != expected:
            problems.append(f"{what}: n must count 1, 2, ... in order")
            break
    for item in items:
        if PASS_FILE_RE.fullmatch(item.file) is None:
            problems.append(f"{what}: item {item.n} names a file outside the fixed set")
        elif not _pointer_ok(item.file, item.pointer):
            problems.append(f"{what}: item {item.n} has an invalid pointer")
    return problems


def load_redactions(data: bytes) -> Redactions:
    try:
        obj = strict_loads(data)
        doc = Redactions.model_validate(obj)
    except (SchemaError, ValidationError):
        raise SchemaError("redactions.json does not match its schema") from None
    problems = _items_problems(doc.items, "redactions.json")
    if problems:
        raise SchemaError(problems[0])
    return doc


def load_scan(scan_data: bytes, classification_data: bytes) -> tuple[ScanItems, Classification]:
    """The private scan list and the owner's classification, bound to it by hash."""
    try:
        scan = ScanItems.model_validate(strict_loads(scan_data))
        classification = Classification.model_validate(strict_loads(classification_data))
    except (SchemaError, ValidationError):
        raise SchemaError("scan or classification does not match its schema") from None
    problems = _items_problems(scan.items, "scan/items.json")
    if problems:
        raise SchemaError(problems[0])
    if classification.scan_sha256 != sha256_hex(scan_data):
        raise SchemaError("classification is stale: its scan_sha256 differs")
    if set(classification.items) != {str(item.n) for item in scan.items}:
        raise SchemaError("classification keys differ from the scan items")
    return scan, classification


# --- Schema problems with safe locations ----------------------------------

def _model_fields(*models) -> frozenset[str]:
    names: set[str] = set()
    for model in models:
        for name, info in model.model_fields.items():
            names.add(info.alias or name)
    return frozenset(names)


KNOWN_FIELDS = _model_fields(RegistryEntry, Registry, Rationale, Objectives, LabelEntry, Labels,
                             OrderEntry, Order)


def _schema_problems(model, doc, what: str) -> tuple[object | None, list[str]]:
    try:
        return model.model_validate(doc), []
    except ValidationError as error:
        return None, [f"{what}: schema error ({e['type']}) at {safe_location(e['loc'], KNOWN_FIELDS)}"
                      for e in error.errors(include_url=False, include_input=False)]


_PATH_PREFIXES_DEV = ("samples/alerts/sigma/", "samples/alerts/wazuh/")
_PATH_PREFIX_TEST = "eval/cases/test/"


def _path_ok(path: str) -> bool:
    if not path or path.startswith("/") or "\\" in path:
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def registry_problems(doc, *, allow_fixture_ids: bool = False) -> list[str]:
    """Structural checks of the case registry. The binding to case files is in labels.py."""
    registry, problems = _schema_problems(Registry, doc, "registry")
    if registry is None:
        return problems
    seen: set[str] = set()
    for i, case in enumerate(registry.cases):
        cid = case.case_id
        id_ok = is_case_id(cid) or (allow_fixture_ids and is_fixture_case_id(cid))
        if not id_ok:
            problems.append(f"registry: case {i} has an invalid case ID")
            continue
        if cid in seen:
            problems.append(f"registry: duplicate case ID {cid}")
        seen.add(cid)
        if is_case_id(cid) and cid.startswith("dev-") != (case.family == "dev"):
            problems.append(f"registry: {cid} prefix does not match its family")
        if not _path_ok(case.path):
            problems.append(f"registry: {cid} has an invalid path")
        else:
            dev_path = case.path.startswith(_PATH_PREFIXES_DEV)
            test_path = case.path.startswith(_PATH_PREFIX_TEST)
            if is_fixture_case_id(cid):
                if not (dev_path or test_path):
                    problems.append(f"registry: {cid} path is outside the case trees")
            elif case.family == "dev" and not dev_path:
                problems.append(f"registry: {cid} path is outside samples/alerts")
            elif case.family != "dev" and not test_path:
                problems.append(f"registry: {cid} path is outside eval/cases/test")
        is_c = case.family == "C"
        if (case.clean_twin is not None) != is_c or (case.phrasing is not None) != is_c:
            problems.append(f"registry: {cid} clean_twin and phrasing must be set exactly for family C")
    by_id = registry.by_id()
    twins_of: dict[str, str] = {}
    for case in registry.cases:
        if case.family != "C" or case.clean_twin is None:
            continue
        clean = by_id.get(case.clean_twin)
        if clean is None or clean.family != "A":
            problems.append(f"registry: {case.case_id} clean_twin is not a family-A case")
        elif case.clean_twin in twins_of:
            problems.append(f"registry: {case.clean_twin} is the clean twin of two cases")
        else:
            twins_of[case.clean_twin] = case.case_id
    return problems


def labels_schema_problems(doc) -> list[str]:
    """Structural checks of the labels file. Semantic checks are in labels.py."""
    labels, problems = _schema_problems(Labels, doc, "labels")
    if labels is None:
        return problems
    seen: set[str] = set()
    for i, label in enumerate(labels.cases):
        cid = label.case_id
        if not (is_case_id(cid) or is_fixture_case_id(cid)):
            problems.append(f"labels: entry {i} has an invalid case ID")
            continue
        if cid in seen:
            problems.append(f"labels: duplicate entry for {cid}")
        seen.add(cid)
        techniques = label.acceptable_techniques
        if not all(re.fullmatch(TECHNIQUE_ID_PATTERN, t) for t in techniques):
            problems.append(f"labels: {cid} has an invalid technique ID")
        if techniques != sorted(set(techniques)):
            problems.append(f"labels: {cid} techniques must be unique and sorted")
        if label.expected_runbook != "none" and RUNBOOK_NAME_RE.fullmatch(label.expected_runbook) is None:
            problems.append(f"labels: {cid} expected_runbook is not a runbook name or none")
        objectives = label.objectives
        if objectives is not None:
            if objectives.kind == "O-S" and objectives.target not in ("informational", "low", "medium", "high", "critical"):
                problems.append(f"labels: {cid} O-S target is not a severity")
            if objectives.kind == "O-T" and re.fullmatch(TECHNIQUE_ID_PATTERN, objectives.target) is None:
                problems.append(f"labels: {cid} O-T target is not a technique ID")
        for j, entry in enumerate(label.rationale):
            if RATIONALE_FIELD.fullmatch(entry.field) is None:
                problems.append(f"labels: {cid} rationale {j} field is not in the accepted form")
            elif entry.field.startswith("alert.") and entry.field.split(".")[1] not in Alert.model_fields:
                problems.append(f"labels: {cid} rationale {j} names an unknown alert field")
            if PRINTABLE_NOTE.fullmatch(entry.note) is None:
                problems.append(f"labels: {cid} rationale {j} note must be 1 to 300 printable ASCII characters")
    return problems


def order_problems(doc, registry: Registry, *, fixture: bool = False) -> list[str]:
    """Check an order against the registry.

    Production mode (the default, and the only mode any CLI uses) requires
    k = 3 and a registry without fixture IDs. Fixture mode is accepted only
    for a registry whose every case is a fixture case, so it can never be
    used to validate production data.
    """
    order, problems = _schema_problems(Order, doc, "order")
    if order is None:
        return problems
    ids = [c.case_id for c in registry.cases]
    if fixture:
        if not ids or not all(is_fixture_case_id(i) for i in ids):
            return problems + ["order: fixture mode needs a registry of fixture cases only"]
        if not 1 <= order.k <= 9:
            problems.append("order: fixture k must be between 1 and 9")
    else:
        if any(is_fixture_case_id(i) for i in ids):
            return problems + ["order: a production registry holds fixture case IDs"]
        if order.k != PRODUCTION_K:
            problems.append(f"order: k must be {PRODUCTION_K}")
    dev = {c.case_id for c in registry.cases if c.family == "dev"}
    tests = [c.case_id for c in registry.test_cases()]
    test_set = set(tests)
    total = len(tests)
    if total == 0:
        return problems + ["order: the registry has no test cases"]
    for name, rounds in (("baseline", 2), ("model", order.k)):
        entries = order.sequence(name)
        if [e.position for e in entries] != list(range(1, 2 + rounds * total)):
            problems.append(f"order: {name} positions must run 1 to {1 + rounds * total}")
            continue
        first = entries[0]
        if first.role != "warmup" or first.case_id not in dev or first.repeat != 1:
            problems.append(f"order: {name} position 1 must be the only warm-up, a dev case, repeat 1")
        for r in range(1, rounds + 1):
            block = entries[1 + (r - 1) * total: 1 + r * total]
            if sorted(e.case_id for e in block) != sorted(test_set) or len({e.case_id for e in block}) != total:
                problems.append(f"order: {name} round {r} must hold every test case exactly once")
            role = "determinism" if (name == "baseline" and r == 2) else "scored"
            if any(e.role != role for e in block):
                problems.append(f"order: {name} round {r} must have role {role}")
            if any(e.repeat != r for e in block):
                problems.append(f"order: {name} round {r} must have repeat {r}")
    return problems


# --- Summaries and audit lines ----------------------------------------------

FREE_TEXT_POINTER = re.compile(r"^/(severity/rationale|next_steps/[0-9]+/step|containment/[0-9]+/action|missing_data/[0-9]+/description)$")


def parse_summary(data: bytes) -> dict:
    if not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise DefectError("s-schema")
    try:
        obj = strict_loads(data[:-1])
    except SchemaError:
        raise DefectError("s-schema") from None
    if not isinstance(obj, dict):
        raise DefectError("s-schema")
    return obj


def validate_summary(obj: dict) -> None:
    try:
        TriageSummary.model_validate(obj)
    except ValidationError:
        raise DefectError("s-schema") from None


def load_summary(data: bytes) -> dict:
    """Parse and validate one summary line. Returns the parsed dict, not the model."""
    obj = parse_summary(data)
    validate_summary(obj)
    return obj


def _resolve(obj, pointer: str):
    parts = pointer.split("/")[1:]
    parent = obj
    for part in parts[:-1]:
        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    last = parts[-1]
    return parent, (int(last) if isinstance(parent, list) else last)


def removal_copy(summary: dict, items) -> dict:
    """A copy with each listed placeholder deleted, used only to validate a public summary.

    Deleting makes every redacted string shorter than its original, so the
    original's length limits still hold. Scoring reads the public text itself.
    """
    out = copy.deepcopy(summary)
    for item in items:
        if item.rule == "withheld-digest":
            continue
        if FREE_TEXT_POINTER.fullmatch(item.pointer) is None:
            raise DefectError("s-schema")
        try:
            parent, key = _resolve(out, item.pointer)
            value = parent[key]
        except (KeyError, IndexError, TypeError, ValueError):
            raise DefectError("s-schema") from None
        if not isinstance(value, str):
            raise DefectError("s-schema")
        parent[key] = value.replace(f"<<REDACTED:{item.rule}:{item.n}>>", "")
    return out


def load_audit(data: bytes) -> list[dict]:
    if not data.endswith(b"\n"):
        raise DefectError("b4-rule-3")
    records = []
    for line in data.split(b"\n")[:-1]:
        try:
            obj = strict_loads(line)
        except SchemaError:
            raise DefectError("b4-rule-3") from None
        if (not isinstance(obj, dict) or not isinstance(obj.get("event.name"), str)
                or not isinstance(obj.get("gen_ai.conversation.id"), str)):
            raise DefectError("b4-rule-3")
        records.append(obj)
    return records


# --- Views ----------------------------------------------------------------

S_PATHS = frozenset({
    "status", "severity.value", "severity.rule_floor", "severity.origin", "severity.rationale",
    "technique.technique_id", "technique.origin", "next_steps[].step", "containment[].action",
    "missing_data[].description", "missing_data[].origin", "anomalies", "injection_suspected",
    "injection_signals"})
A_RUN_PATHS = frozenset({
    "triage.stop_reason", "triage.budget_detail", "error.type", "triage.model_calls.count",
    "triage.tool_calls.count", "triage.draft.severity", "triage.draft.technique_id",
    "triage.enrichment.gaps", "triage.duration_s"})
A_TOOL_PATHS = frozenset({"gen_ai.tool.name", "triage.requested_by"})
H_PATHS = frozenset({"case_id", "position", "started_at", "ended_at", "exit_status", "signal", "class",
                     "reason", "runbook_hits", "checks"})
LABEL_PATHS = frozenset({"expected_severity", "acceptable_techniques", "expected_status", "expected_runbook",
                         "expected_flagged", "objectives.marker", "objectives.kind", "objectives.target"})
STRUCTURE_PATHS = frozenset({"case_id", "family", "clean_twin", "phrasing"})
ORDER_PATHS = frozenset({"position", "case_id", "role", "repeat"})


def _freeze(value):
    if isinstance(value, list | tuple):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    return value


class View:
    """A read-only copy of exactly the allow-listed fields of one record.

    It keeps no reference to the record it was built from, and asking for any
    path not on its list raises AllowListError.
    """

    __slots__ = ("_kind", "_values")

    def __init__(self, kind: str, allowed: frozenset[str], values: dict) -> None:
        if set(values) != set(allowed):
            raise AssertionError("a view must hold exactly its allow-list")
        object.__setattr__(self, "_kind", kind)
        object.__setattr__(self, "_values", MappingProxyType({k: _freeze(v) for k, v in values.items()}))

    def __getitem__(self, path: str):
        try:
            return self._values[path]
        except KeyError:
            raise AllowListError(path) from None

    def __setattr__(self, name, value):
        raise AttributeError("a view is read-only")

    @property
    def kind(self) -> str:
        return self._kind

    def __repr__(self) -> str:
        return f"View({self._kind})"


def s_view(summary: dict) -> View:
    sev, tech = summary["severity"], summary["technique"]
    return View("S", S_PATHS, {
        "status": summary["status"],
        "severity.value": sev["value"],
        "severity.rule_floor": sev["rule_floor"],
        "severity.origin": sev["origin"],
        "severity.rationale": sev["rationale"],
        "technique.technique_id": tech.get("technique_id"),
        "technique.origin": tech["origin"],
        "next_steps[].step": [x["step"] for x in summary["next_steps"]],
        "containment[].action": [x["action"] for x in summary["containment"]],
        "missing_data[].description": [x["description"] for x in summary["missing_data"]],
        "missing_data[].origin": [x["origin"] for x in summary["missing_data"]],
        "anomalies": summary["anomalies"],
        "injection_suspected": summary["injection_suspected"],
        "injection_signals": summary["injection_signals"],
    })


def a_run_view(record: dict) -> View:
    try:
        return View("A-run", A_RUN_PATHS, {path: record[path] for path in A_RUN_PATHS})
    except KeyError:
        raise DefectError("b4-rule-3") from None


def a_tool_view(record: dict) -> View:
    try:
        return View("A-tool", A_TOOL_PATHS, {path: record[path] for path in A_TOOL_PATHS})
    except KeyError:
        raise DefectError("b4-rule-3") from None


def h_view(record: dict) -> View:
    return View("H", H_PATHS, {path: record[path] for path in H_PATHS})


def label_view(label: LabelEntry) -> View:
    objectives = label.objectives
    return View("label", LABEL_PATHS, {
        "expected_severity": label.expected_severity,
        "acceptable_techniques": list(label.acceptable_techniques),
        "expected_status": label.expected_status,
        "expected_runbook": label.expected_runbook,
        "expected_flagged": label.expected_flagged,
        "objectives.marker": None if objectives is None else objectives.marker,
        "objectives.kind": None if objectives is None else objectives.kind,
        "objectives.target": None if objectives is None else objectives.target,
    })


def structure_view(entry: RegistryEntry) -> View:
    return View("structure", STRUCTURE_PATHS, {
        "case_id": entry.case_id, "family": entry.family,
        "clean_twin": entry.clean_twin, "phrasing": entry.phrasing})


def order_view(entry: OrderEntry) -> View:
    return View("order", ORDER_PATHS, {
        "position": entry.position, "case_id": entry.case_id, "role": entry.role, "repeat": entry.repeat})


# --- load_pass --------------------------------------------------------------

# Shared fields between the triage.summary audit record and the summary
# (key path in the record, function of the parsed summary), from
# triage/audit.py: the finding counts sit in one nested "triage.findings" object.
SHARED_FIELDS = (
    (("triage.summary.status",), lambda s: s["status"]),
    (("triage.severity.value",), lambda s: s["severity"]["value"]),
    (("triage.severity.rule_floor",), lambda s: s["severity"]["rule_floor"]),
    (("triage.severity.origin",), lambda s: s["severity"]["origin"]),
    (("triage.severity.sources",), lambda s: s["severity"]["sources"]),
    (("triage.technique.id",), lambda s: s["technique"].get("technique_id")),
    (("triage.technique.basis",), lambda s: s["technique"]["basis"]),
    (("triage.technique.origin",), lambda s: s["technique"]["origin"]),
    (("triage.asset.criticality",), lambda s: s["asset"]["criticality"]),
    (("triage.asset.exposure",), lambda s: s["asset"]["exposure"]),
    (("triage.findings", "next_steps"), lambda s: len(s["next_steps"])),
    (("triage.findings", "containment"), lambda s: len(s["containment"])),
    (("triage.findings", "missing_data_enrichment"),
     lambda s: sum(m["origin"] == "enrichment" for m in s["missing_data"])),
    (("triage.findings", "missing_data_model"), lambda s: sum(m["origin"] == "model" for m in s["missing_data"])),
    (("triage.anomalies",), lambda s: s["anomalies"]),
    (("triage.injection.suspected",), lambda s: s["injection_suspected"]),
    (("triage.injection.signals",), lambda s: s["injection_signals"]),
)
_MISSING = object()


def _record_value(record: dict, path: tuple[str, ...]):
    """The value at a key path in an audit record, or _MISSING."""
    node = record
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return _MISSING
        node = node[key]
    return node


def _same(a, b) -> bool:
    """Equal and of the same JSON type, so a true is never taken for a 1."""
    if isinstance(a, list):
        return isinstance(b, list) and len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


DRAFT_CODES = ("draft_unavailable", "draft_invalid", "draft_citation_invalid")
ANOMALY_CODES = get_args(Anomaly)
CLASS_RANK = {"complete": 0, "incomplete": 1, "defective": 2, "void": 3}


@dataclass(frozen=True)
class RunData:
    position: int
    order: View
    structure: View
    label: View
    h: View | None
    s: View | None
    a_run: View | None
    a_tools: tuple[View, ...]


@dataclass(frozen=True)
class RedactionCounts:
    # (position, classification) for each H2-rule item, and the withheld-field count.
    items: tuple[tuple[int, str], ...]
    withheld: tuple[int, ...]


@dataclass(frozen=True)
class PassData:
    pass_id: str
    sequence: str
    ledger_class: str | None
    pass_class: str
    defects: tuple[tuple[str, int | None], ...]
    runs: tuple[RunData, ...]
    redactions: RedactionCounts
    k: int


def _run_name(position: int, kind: str) -> str:
    return f"run-{position:04d}.{kind}"


def _canonical_summary(obj: dict) -> bytes:
    clean = {k: v for k, v in obj.items() if k != "run_id"}
    return json.dumps(clean, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _strip_listed_placeholders(obj: dict, items) -> dict:
    """A copy with exactly the listed placeholders deleted, for the determinism comparison.

    Only the placeholder an item names is removed. Any other placeholder-shaped
    text (one the model wrote, say) stays, so a difference in it is still seen.
    """
    out = copy.deepcopy(obj)
    for item in items:
        if item.rule == "withheld-digest" or FREE_TEXT_POINTER.fullmatch(item.pointer) is None:
            continue
        try:
            parent, key = _resolve(out, item.pointer)
            if isinstance(parent[key], str):
                parent[key] = parent[key].replace(f"<<REDACTED:{item.rule}:{item.n}>>", "")
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return out


def _check_inputs(registry: Registry, labels: Labels, order: Order, fixture: bool) -> None:
    problems = order_problems(order.model_dump(), registry, fixture=fixture)
    if problems:
        raise SchemaError(problems[0])
    missing = set(registry.by_id()) - set(labels.by_id())
    if missing:
        raise SchemaError("labels: a registry case has no label")


def load_pass(pass_dir, *, registry: Registry, labels: Labels, order: Order, sequence: str,
              public: bool, redactions=None, scan_items=None, classification=None,
              fixture: bool = False) -> PassData:
    """Read one pass directory, run every validation check, and build the views.

    Every defect is collected, not only the first. Input errors (wrong
    arguments, invalid registry, labels or order) raise SchemaError instead,
    because they are not properties of the pass.
    """
    pass_dir = Path(pass_dir)
    pass_id = pass_dir.name
    if PASS_ID_RE.fullmatch(pass_id) is None or not pass_id.startswith(sequence + "-"):
        raise SchemaError("pass directory name must be a pass ID of this sequence")
    _check_inputs(registry, labels, order, fixture)
    entries_planned = order.sequence(sequence)
    by_position = {e.position: e for e in entries_planned}
    cases = registry.by_id()
    label_by_id = labels.by_id()

    # Redaction data for this pass.
    if public:
        if redactions is None or scan_items is not None or classification is not None:
            raise SchemaError("a public pass needs redactions.json only")
        red = load_redactions(read_regular(redactions))
        red_items = red.items
        h2_items = [(i.file, i.classification) for i in red_items if i.rule in RULE_IDS]
        withheld_files = [i.file for i in red_items if i.rule == "withheld-digest"]
    else:
        if redactions is not None or scan_items is None or classification is None:
            raise SchemaError("an original pass needs scan items and a classification")
        scan, cls = load_scan(read_regular(scan_items), read_regular(classification))
        red_items = []
        h2_items = [(i.file, cls.items[str(i.n)]) for i in scan.items]
        withheld_files = []

    defects: list[tuple[str, int | None]] = []

    def defect(rule: str, position: int | None) -> None:
        if (rule, position) not in defects:
            defects.append((rule, position))

    # Check 1: the ledger.
    ledger_class = None
    started_positions: list[int] = []
    ended_class: dict[int, str] = {}   # position -> the class its run_end records
    try:
        entries = verify_ledger(read_regular(pass_dir / "ledger.jsonl"))
        if ledger_matches_order(entries, entries_planned):
            defect("ledger", None)
        ledger_class = entries[-1].class_
        started_positions = [e.position for e in entries if e.event == "run_start"]
        ended_class = {e.position: e.class_ for e in entries if e.event == "run_end"}
    except EvaluationError:
        defect("ledger", None)
        started_positions = [p for p in sorted(by_position) if (pass_dir / _run_name(p, "harness.json")).exists()]
    started = set(started_positions)
    for position in sorted(by_position):
        if position not in started and (pass_dir / _run_name(position, "harness.json")).exists():
            defect("ledger", position)

    runs: list[RunData] = []
    summaries: dict[int, dict] = {}   # position -> parsed public (or original) summary
    for position in started_positions:
        planned = by_position.get(position)
        if planned is None:
            defect("ledger", position)
            continue
        case = cases[planned.case_id]
        try:
            h = load_harness(read_regular(pass_dir / _run_name(position, "harness.json")))
        except DefectError:
            defect("b4-rule-1", position)
            continue
        except EvaluationError:
            defect("b4-rule-1", position)
            continue
        expected_backend = "heuristic" if sequence == "baseline" else "ollama"
        if (h["pass_id"] != pass_id or h["position"] != position or h["case_id"] != planned.case_id
                or h["role"] != planned.role or h["repeat"] != planned.repeat or h["backend"] != expected_backend):
            defect("h-binding", position)
        cls_ = h["class"]
        # The ledger and the H record are written separately; if they disagree
        # on how the run ended, neither can be trusted for this position.
        if position in ended_class and ended_class[position] != cls_:
            defect("ledger", position)
        summary_path = pass_dir / _run_name(position, "summary.json")
        audit_path = pass_dir / _run_name(position, "audit.jsonl")
        has_summary = summary_path.exists() or summary_path.is_symlink()
        has_audit = audit_path.exists() or audit_path.is_symlink()
        # H states which output files its run left; a file added or removed
        # afterwards makes H describe a different run.
        if h["files"]["summary"] != has_summary or h["files"]["audit"] != has_audit:
            defect("h-binding", position)

        s_obj = None
        if cls_ == "no_output" and has_summary:
            defect("b4-rule-2", position)
        if cls_ == "outcome" and not has_summary:
            defect("s-schema", position)
        if cls_ == "outcome" and has_summary:
            try:
                s_obj = parse_summary(read_regular(summary_path))
                file_items = [i for i in red_items if i.file == summary_path.name]
                validate_summary(removal_copy(s_obj, file_items) if public else s_obj)
            except EvaluationError:
                defect("s-schema", position)
                s_obj = None

        audit = None
        if has_audit:
            try:
                audit = load_audit(read_regular(audit_path))
            except EvaluationError:
                defect("b4-rule-3", position)
        run_records = [r for r in (audit or []) if r["event.name"] == "triage.run"]
        if audit is not None and len(run_records) != 1:
            defect("b4-rule-3", position)
        if s_obj is not None and audit is None:
            defect("b4-rule-3", position)

        a_run = None
        a_tools: list[View] = []
        if audit is not None and len(run_records) == 1:
            try:
                a_run = a_run_view(run_records[0])
                a_tools = [a_tool_view(r) for r in audit if r["event.name"] == "triage.tool_call"]
            except DefectError:
                defect("b4-rule-3", position)
                a_run, a_tools = None, []

        s = None
        if s_obj is not None:
            # Check 4 binding.
            run_ids = {r["gen_ai.conversation.id"] for r in (audit or [])}
            if (s_obj["alert_id"] != case.alert_id or s_obj["run_id"] != h["run_id"]
                    or (audit is not None and run_ids != {s_obj["run_id"]})):
                defect("s-binding", position)
            # Check 5 invariants.
            sev = s_obj["severity"]
            rank = severity_index
            anomalies = s_obj["anomalies"]
            if (sev["rule_floor"] != case.rule_level or rank(sev["value"]) < rank(sev["rule_floor"])
                    or (sev["origin"] == "rule" and sev["value"] != sev["rule_floor"])
                    or (sev["origin"] == "tripwire" and (sev["value"] != "high" or rank(sev["rule_floor"]) >= rank("high")))
                    or sum(a in DRAFT_CODES for a in anomalies) > 1):
                defect("s-invariant", position)
            # Check 7: the triage.summary record.
            summary_records = [r for r in (audit or []) if r["event.name"] == "triage.summary"]
            if audit is not None:
                if len(summary_records) != 1:
                    defect("b4-rule-4", position)
                else:
                    record = summary_records[0]
                    for path, get in SHARED_FIELDS:
                        value = _record_value(record, path)
                        if value is _MISSING or not _same(value, get(s_obj)):
                            defect("b4-rule-4", position)
                            break
            # Check 8.
            if a_run is not None and not any(a in DRAFT_CODES for a in anomalies) and a_run["triage.draft.severity"] is None:
                defect("b4-rule-5", position)
            # Check 9.
            if h["runbook_hits"] is None:
                defect("hits-null", position)
            s = s_view(s_obj)
            summaries[position] = s_obj

        runs.append(RunData(
            position=position, order=order_view(planned), structure=structure_view(case),
            label=label_view(label_by_id[planned.case_id]), h=h_view(h), s=s,
            a_run=a_run, a_tools=tuple(a_tools)))

    run_by_position = {r.position: r for r in runs}

    # Check 10: baseline determinism.
    if sequence == "baseline":
        scored = {e.case_id: e.position for e in entries_planned if e.role == "scored"}
        repeat = {e.case_id: e.position for e in entries_planned if e.role == "determinism"}
        for cid, p1 in scored.items():
            p2 = repeat.get(cid)
            if p2 is None or p1 not in run_by_position or p2 not in run_by_position:
                continue
            a, b = summaries.get(p1), summaries.get(p2)
            if (a is None) != (b is None):
                defect("determinism", p2)
                continue
            if a is None:
                continue
            if public:
                a = _strip_listed_placeholders(a, [i for i in red_items if i.file == _run_name(p1, "summary.json")])
                b = _strip_listed_placeholders(b, [i for i in red_items if i.file == _run_name(p2, "summary.json")])
            if _canonical_summary(a) != _canonical_summary(b):
                defect("determinism", p2)

    # Check 11: tripwire consistency within a case.
    seen: dict[str, tuple] = {}
    for position in sorted(summaries):
        cid = by_position[position].case_id
        obj = summaries[position]
        value = (obj["injection_suspected"], tuple(obj["injection_signals"]))
        if cid in seen and seen[cid] != value:
            defect("tripwire-consistency", position)
        seen.setdefault(cid, value)

    # Redaction counts, by run position.
    def position_of(file: str) -> int | None:
        match = re.fullmatch(r"run-([0-9]{4})\..+", file)
        return int(match.group(1)) if match else None

    counts = RedactionCounts(
        items=tuple((position_of(f), c) for f, c in h2_items),
        withheld=tuple(position_of(f) for f in withheld_files))

    base = ledger_class if ledger_class in CLASS_RANK else "defective"
    pass_class = base
    if defects and CLASS_RANK["defective"] > CLASS_RANK[base]:
        pass_class = "defective"
    return PassData(pass_id=pass_id, sequence=sequence, ledger_class=ledger_class, pass_class=pass_class,
                    defects=tuple(defects), runs=tuple(runs), redactions=counts, k=order.k)


# --- Case views and input loaders (for the scorer CLI) -----------------------

def case_views(registry: Registry, labels: Labels) -> dict[str, tuple[View, View]]:
    """Structure and label views for every registry case, keyed by case ID."""
    label_by_id = labels.by_id()
    return {c.case_id: (structure_view(c), label_view(label_by_id[c.case_id])) for c in registry.cases}


def _load_json(path) -> object:
    try:
        return strict_loads(read_regular(path))
    except EvaluationError:
        raise SchemaError("an input file cannot be read as JSON") from None


def load_registry(path, *, allow_fixture_ids: bool = False) -> Registry:
    doc = _load_json(path)
    problems = registry_problems(doc, allow_fixture_ids=allow_fixture_ids)
    if problems:
        raise SchemaError(problems[0])
    return Registry.model_validate(doc)


def load_labels(path) -> Labels:
    doc = _load_json(path)
    problems = labels_schema_problems(doc)
    if problems:
        raise SchemaError(problems[0])
    return Labels.model_validate(doc)


def load_order(path, registry: Registry) -> Order:
    """Production mode only: the CLIs never load a fixture order."""
    doc = _load_json(path)
    problems = order_problems(doc, registry)
    if problems:
        raise SchemaError(problems[0])
    return Order.model_validate(doc)


def _think_off(value: bool) -> bool:
    if value is not False:
        raise ValueError("think must be false")
    return value


class Setup(EvalModel):
    model: str = Field(pattern=MODEL_NAME_PATTERN)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    think: Annotated[bool, AfterValidator(_think_off)]


def load_setup(path) -> dict:
    try:
        setup = Setup.model_validate(_load_json(path))
    except ValidationError:
        raise SchemaError("setup does not match its schema") from None
    return {"model": setup.model, "digest": setup.digest, "think": False}


def load_index(path) -> tuple[bytes, tuple[str, ...]]:
    """The pass index: its exact bytes (to hash) and the pass IDs it lists."""
    try:
        data = read_regular(path)
        doc = strict_loads(data)
    except EvaluationError:
        raise SchemaError("index cannot be read as JSON") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("passes"), list):
        raise SchemaError("index must be an object with a passes list")
    ids = []
    for entry in doc["passes"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("pass_id"), str) \
                or PASS_ID_RE.fullmatch(entry["pass_id"]) is None:
            raise SchemaError("index pass entries need a valid pass_id")
        ids.append(entry["pass_id"])
    if len(set(ids)) != len(ids):
        raise SchemaError("index lists a pass twice")
    return data, tuple(ids)


SCORER_SOURCES = ("evaluation/common.py", "evaluation/records.py", "evaluation/scorer.py")


def source_hashes() -> list[dict]:
    """SHA-256 of the committed scorer sources, recorded in results.json."""
    from .common import REPO_ROOT
    return [{"path": p, "sha256": sha256_hex(read_regular(REPO_ROOT / p))} for p in sorted(SCORER_SOURCES)]
