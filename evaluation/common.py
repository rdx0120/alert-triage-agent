"""Conventions shared by the evaluation modules.

Everything here is about refusing ambiguity. Evaluation inputs are compared
byte for byte and hashed, so each record has exactly one accepted encoding,
every file is read without following links, and no error message carries a
value read from a record: a record can hold model-written or alert text, and
an error path must not become a way to publish it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from triage.config import REPO_ROOT
from triage.schemas import SEVERITY_ORDER, severity_rank

__all__ = [
    "REPO_ROOT", "RUNBOOK_DIR", "ATTACK_SNAPSHOT", "PRODUCTION_K", "EvalModel",
    "EvaluationError", "SchemaError", "DefectError", "AllowListError",
    "canonical_dumps", "strict_loads", "sha256_hex", "read_regular", "write_new_file",
    "CASE_ID_RE", "FIXTURE_CASE_ID_RE", "PASS_ID_RE", "MARKER_RE", "RULE_IDS",
    "REDACTION_RULES", "CLASSIFICATION_CODES", "PLACEHOLDER_RE", "RUNBOOK_NAME_RE",
    "runbook_names", "load_h2", "SEVERITY_ORDER", "severity_index",
    "is_case_id", "is_fixture_case_id",
]

# The evaluation reads only the frozen tree, never a directory chosen by an
# environment variable, so a stray TRIAGE_RUNBOOK_DIR cannot change a label check.
RUNBOOK_DIR = REPO_ROOT / "vendor" / "sigma-detection-pack" / "runbooks"
ATTACK_SNAPSHOT = REPO_ROOT / "data" / "attack_techniques.json"

# The approved number of model runs per test case. Production orders, passes
# and results must use it; only fixture-mode calls in tests may use another.
PRODUCTION_K = 3


class EvalModel(BaseModel):
    """Base for every evaluation schema.

    strict=True stops type coercion, so "1" is never read as 1 and a boolean
    is never read as a string: a record that only parses after coercion is a
    different record from the one that was hashed.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class EvaluationError(Exception):
    """Base error. Messages are fixed text plus identifiers, never record values."""


class SchemaError(EvaluationError):
    """An input does not match its schema."""


class DefectError(EvaluationError):
    """A pass defect: the pass is reported as defective instead of being scored."""

    def __init__(self, rule: str, position: int | None = None) -> None:
        where = "" if position is None else f" at position {position}"
        super().__init__(f"defect {rule}{where}")
        self.rule = rule
        self.position = position


class AllowListError(EvaluationError):
    """Scoring asked for a field that is not on the reviewed allow-list."""

    def __init__(self, path: str) -> None:
        # The path is a name the caller's code asked for, not record content.
        super().__init__(f"field not on the allow-list: {path}")
        self.path = path


def canonical_dumps(obj: object) -> bytes:
    """The one accepted byte form: compact, ASCII, insertion-ordered keys, a newline."""
    return json.dumps(obj, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii") + b"\n"


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            # A repeated key hides one value from a reader that keeps the other.
            raise SchemaError("duplicate key")
        out[key] = value
    return out


def _no_constant(_name: str) -> object:
    raise SchemaError("non-finite number")


def strict_loads(data: bytes) -> object:
    """Parse JSON from strict UTF-8, refusing repeated keys and NaN or Infinity."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SchemaError("not UTF-8") from None
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except SchemaError:
        raise
    except (ValueError, RecursionError):
        raise SchemaError("not valid JSON") from None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: str | os.PathLike) -> bytes:
    """Read a regular file without following a final symlink.

    The single file reader of the evaluation modules: a symlink or a device in
    a pass directory could make a check read something other than the evidence.
    """
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise EvaluationError("cannot open a regular file") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise EvaluationError("not a regular file")
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_new_file(path: str | os.PathLike, data: bytes) -> None:
    """Create a new file and write it durably. An existing path is refused, never replaced."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError:
        raise EvaluationError("cannot create the output file") from None
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


CASE_ID_RE = re.compile(r"^(dev|test)-[a-z0-9]+(-[a-z0-9]+)*$")
FIXTURE_CASE_ID_RE = re.compile(r"^fx-[a-z0-9]+(-[a-z0-9]+)*$")
PASS_ID_RE = re.compile(r"^(baseline|model)-[0-9]{3}$")
MARKER_RE = re.compile(r"^[A-Z0-9]{3}-[A-Z0-9]{6}$")
RULE_IDS = ("inline-allow", "ipv4", "ipv6", "email", "url-host", "phone", "ssn")
REDACTION_RULES = RULE_IDS + ("withheld-digest",)
CLASSIFICATION_CODES = ("synthetic-match", "model-real-looking", "suspected-real-data", "suspected-credential")
PLACEHOLDER_RE = re.compile(r"<<REDACTED:(inline-allow|ipv4|ipv6|email|url-host|phone|ssn):([1-9][0-9]{0,5})>>")
RUNBOOK_NAME_RE = re.compile(r"^[a-z0-9_]{1,64}\.md$")

MAX_ID_LENGTH = 48


def is_case_id(value: object) -> bool:
    return isinstance(value, str) and len(value) <= MAX_ID_LENGTH and CASE_ID_RE.fullmatch(value) is not None


def is_fixture_case_id(value: object) -> bool:
    return isinstance(value, str) and len(value) <= MAX_ID_LENGTH and FIXTURE_CASE_ID_RE.fullmatch(value) is not None


def runbook_names() -> tuple[str, ...]:
    """The vendored runbook file names: the only values an expected runbook may take."""
    names = []
    for entry in os.scandir(RUNBOOK_DIR):
        if not entry.name.endswith(".md"):
            continue
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            raise EvaluationError("a runbook is not a regular file")
        if RUNBOOK_NAME_RE.fullmatch(entry.name) is None:
            raise EvaluationError("a runbook file name is outside the accepted form")
        names.append(entry.name)
    return tuple(sorted(names))


_H2 = None


def load_h2():
    """The repository's synthetic-data rules (scripts/synthetic_data.py), imported read-only.

    Loaded by path, as its own tests do, so the evaluation uses exactly the
    rules the tree is checked with instead of a copy that could drift.
    """
    global _H2
    if _H2 is None:
        path = REPO_ROOT / "scripts" / "synthetic_data.py"
        spec = importlib.util.spec_from_file_location("_eval_h2_rules", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module   # its dataclasses need the module registered
        spec.loader.exec_module(module)
        _H2 = module
    return _H2


def severity_index(severity: str) -> int:
    """Position of a severity in the fixed order (triage.schemas.severity_rank)."""
    return severity_rank(severity)


def safe_location(loc: tuple, known: frozenset[str]) -> str:
    """A schema-error location with every unknown key replaced by '?'.

    Pydantic locations can contain key names taken from the document, so only
    integers and field names the schemas define are shown.
    """
    parts = []
    for part in loc:
        if isinstance(part, int):
            parts.append(str(part))
        elif isinstance(part, str) and part in known:
            parts.append(part)
        else:
            parts.append("?")
    return "/".join(parts) or "?"


def is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False
