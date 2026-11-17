"""Evidence checks, scans, redaction and closure for publishing a pass.

A pass's original/ directory is the runner's output and is never modified.
Publication builds a separate public copy in which flagged spans inside the
four free-text summary fields are replaced by numbered placeholders, and in
which the request and reply digests and sizes of a run with a redaction are
withheld. Every other flag stops publication, because only those four fields
carry model or enrichment text; anything else comes from synthetic inputs or
from the instruments and a flag there is an incident, not something to hide.

The synthetic-data rules and the secret scanner's helpers are imported from
the repository's own scripts, never copied, so publication uses exactly the
rules the tree is checked with.
"""

from __future__ import annotations

import collections
import contextlib
import copy
import importlib.util
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass

from triage import files as tfiles

from evaluation import identity, records
from evaluation.common import (
    PLACEHOLDER_RE, REPO_ROOT, RULE_IDS, EvaluationError, SchemaError, canonical_dumps, load_h2, read_regular,
    sha256_hex, strict_loads,
)
from evaluation.ledger import write_in

PUBLIC_EXTRA = ("redactions.json", "files.sha256")
HASH_LINE_RE = re.compile(r"^([0-9a-f]{64})  (\S+)$")
RUN_FILE_RE = re.compile(r"^run-([0-9]{4})\.")
FIELD_ORDER = ("severity", "next_steps", "containment", "missing_data")
FREE_TEXT = {"severity": "rationale", "next_steps": "step", "containment": "action", "missing_data": "description"}
DIGEST_KEYS = ("triage.request.sha256", "triage.request.bytes", "triage.reply.sha256", "triage.reply.text_bytes")
RULE_OF_MESSAGE = (
    ("inline scanner allow comment", "inline-allow"),
    ("IPv4 address", "ipv4"),
    ("IPv6 address", "ipv6"),
    ("email address", "email"),
    ("URL host", "url-host"),
    ("phone number", "phone"),
    ("SSN-shaped", "ssn"),
)


class PublishRefused(EvaluationError):
    """Publication stops: nothing public is written."""


# --- Descriptor-anchored directories ----------------------------------------------------
# A directory is opened once, with O_NOFOLLOW and O_DIRECTORY, and checked with
# fstat on that descriptor; every file in it is then listed, examined and read
# through the same descriptor. A symlinked directory is refused, and one swapped
# after the check is never the one that is read.

def real_directory_fd(path, *, what: str, dir_fd: int | None = None) -> int:
    """A descriptor for path: a real directory (never a symlink) owned by the effective user."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, dir_fd=dir_fd)
    except OSError:
        raise PublishRefused(f"{what}: not a real directory") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            raise PublishRefused(f"{what}: not a real directory owned by this user")
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextlib.contextmanager
def opened_directory(directory, *, what: str):
    """Use an int as a descriptor already checked by the caller; open and check a path."""
    if isinstance(directory, int):
        yield directory
        return
    fd = real_directory_fd(directory, what=what)
    try:
        yield fd
    finally:
        os.close(fd)


def read_in(dir_fd: int, name: str) -> bytes:
    """Read a regular file in an open directory without following a symlink."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
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


# --- File rules and hash lists --------------------------------------------------------

def ledger_positions(directory) -> list[int] | None:
    """Positions with a run_start entry, or None when the ledger cannot be read as a chain."""
    try:
        with opened_directory(directory, what="files") as fd:
            entries = records.verify_ledger(read_in(fd, "ledger.jsonl"))
    except EvaluationError:
        return None
    return [e.position for e in entries if e.event == "run_start"]


def file_problems(directory, order_positions, *, public: bool) -> list[str]:
    """Design's file rules: only regular, non-empty, UTF-8 files with fixed names; required files present."""
    try:
        with opened_directory(directory, what="files") as fd:
            return _file_problems(fd, order_positions, public=public)
    except PublishRefused as error:
        return [str(error)]


def _file_problems(dir_fd: int, order_positions, *, public: bool) -> list[str]:
    problems = []
    allowed_extra = PUBLIC_EXTRA if public else ()
    positions = set(order_positions)
    names = []
    try:
        entries = list(os.scandir(dir_fd))
    except OSError:
        return ["files: the directory cannot be read"]
    for entry in entries:
        name = entry.name
        if entry.is_symlink():
            problems.append(f"files: {_safe(name)} is a symlink")
            continue
        if entry.is_dir(follow_symlinks=False):
            problems.append(f"files: {_safe(name)} is a directory")
            continue
        if not entry.is_file(follow_symlinks=False):
            problems.append(f"files: {_safe(name)} is not a regular file")
            continue
        if records.PASS_FILE_RE.fullmatch(name) is None and name not in allowed_extra:
            problems.append("files: a file name is outside the fixed set")
            continue
        match = RUN_FILE_RE.match(name)
        if match and int(match.group(1)) not in positions:
            problems.append(f"files: {name} is not a position of the order")
            continue
        try:
            data = read_in(dir_fd, name)
        except EvaluationError:
            problems.append(f"files: {name} cannot be read")
            continue
        if not data:
            problems.append(f"files: {name} is empty")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"files: {name} is not UTF-8")
        names.append(name)
    for required in ("environment.json", "ledger.jsonl") + (("redactions.json",) if public else ()):
        if required not in names:
            problems.append(f"files: {required} is missing")
    started = ledger_positions(dir_fd) if "ledger.jsonl" in names else None
    if started is not None:
        for position in started:
            if f"run-{position:04d}.harness.json" not in names:
                problems.append(f"files: run-{position:04d}.harness.json is missing")
    return problems


def _safe(name: str) -> str:
    return name if records.PASS_FILE_RE.fullmatch(name) or name in PUBLIC_EXTRA else "an entry"


def file_hashes(directory, exclude=()) -> dict[str, str]:
    out = {}
    with opened_directory(directory, what="files") as fd:
        for name in sorted(os.listdir(fd)):
            if name in exclude:
                continue
            if stat.S_ISLNK(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
                raise PublishRefused(f"files: {_safe(name)} is a symlink")
            out[name] = sha256_hex(read_in(fd, name))
    return out


def hash_list(directory, exclude=()) -> bytes:
    return "".join(f"{h}  {n}\n" for n, h in file_hashes(directory, exclude).items()).encode("ascii")


def parse_hash_list(data: bytes) -> dict[str, str]:
    out = {}
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise PublishRefused("hash list: not ASCII") from None
    if not text.endswith("\n"):
        raise PublishRefused("hash list: does not end with a newline")
    names = []
    for line in text.split("\n")[:-1]:
        match = HASH_LINE_RE.fullmatch(line)
        if match is None:
            raise PublishRefused("hash list: a line is malformed")
        names.append(match.group(2))
        out[match.group(2)] = match.group(1)
    if names != sorted(set(names)):
        raise PublishRefused("hash list: names must be sorted and unique")
    return out


def hash_list_problems(directory, data: bytes, exclude=()) -> list[str]:
    """The list must cover exactly the directory's files, each with its current hash."""
    try:
        listed = parse_hash_list(data)
        observed = file_hashes(directory, exclude)
    except EvaluationError as error:
        return [str(error)]
    if set(listed) != set(observed):
        return ["hash list: the file set differs"]
    return [f"hash list: {name} differs" for name in sorted(listed) if listed[name] != observed[name]]


# --- Completed originals: modes and ownership ----------------------------------------------
# The runner sets these modes with fchmod when the pass ends, so they are exact
# whatever the umask. Permissions do not stop the owning user; a changed mode is
# still evidence that someone touched the originals, so it refuses.

ORIGINAL_DIR_MODE = 0o500
ORIGINAL_FILE_MODE = 0o400


def original_mode_problems(pass_fd: int) -> list[str]:
    """original/ is 0500, every file in it and the hash list are 0400, all owned by this user."""
    problems = []
    me = os.geteuid()
    try:
        orig_fd = real_directory_fd("original", what="originals", dir_fd=pass_fd)
    except PublishRefused as error:
        return [str(error)]
    try:
        if stat.S_IMODE(os.fstat(orig_fd).st_mode) != ORIGINAL_DIR_MODE:
            problems.append("originals: original/ mode changed")
        for name in sorted(os.listdir(orig_fd)):
            st = os.stat(name, dir_fd=orig_fd, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != me:
                problems.append(f"originals: {_safe(name)} is not a regular file owned by this user")
            elif stat.S_IMODE(st.st_mode) != ORIGINAL_FILE_MODE:
                problems.append(f"originals: {_safe(name)} mode changed")
    finally:
        os.close(orig_fd)
    try:
        st = os.stat("files.original.sha256", dir_fd=pass_fd, follow_symlinks=False)
    except OSError:
        return problems + ["originals: the hash list is missing"]
    if not stat.S_ISREG(st.st_mode) or st.st_uid != me:
        problems.append("originals: the hash list is not a regular file owned by this user")
    elif stat.S_IMODE(st.st_mode) != ORIGINAL_FILE_MODE:
        problems.append("originals: the hash list mode changed")
    return problems


# --- The verified named copy ------------------------------------------------------------------

@contextlib.contextmanager
def named_copy(source_dir: str, pass_id: str, hashes: dict[str, str], *, public: bool, positions):
    """A private temporary copy of a pass directory whose last path component is the pass ID.

    records.load_pass takes the pass ID from the directory name, while the
    store keeps the runner's output in <pass-id>/original/. The copy holds
    exactly the permitted files. Each source file must have the hash it was
    verified with, and each copy is read back and must have that hash too,
    so the scorer reads the same bytes the hash lists cover. The copy is
    removed afterwards; a failure to remove it is reported.
    """
    src_fd = real_directory_fd(source_dir, what="copy")
    try:
        yield from _named_copy(src_fd, pass_id, hashes, public=public, positions=positions)
    finally:
        os.close(src_fd)


def _named_copy(src_fd: int, pass_id: str, hashes: dict[str, str], *, public: bool, positions):
    problems = file_problems(src_fd, positions, public=public)
    if problems:
        raise PublishRefused(problems[0])
    names = sorted(n for n in os.listdir(src_fd) if n != "files.sha256")
    if set(names) != set(hashes) - {"files.sha256"}:
        raise PublishRefused("copy: the file set differs from the verified hashes")
    tmp = tempfile.mkdtemp(prefix="eval-copy-")
    failed = False
    try:
        target = os.path.join(tmp, pass_id)
        fd = tfiles.open_private_dir(target, what="copy", create=True)
        try:
            for name in names:
                data = read_in(src_fd, name)
                if sha256_hex(data) != hashes[name]:
                    raise PublishRefused(f"copy: {name} differs from its verified hash")
                write_in(fd, target, [(name, data)], what="copy")
                if sha256_hex(read_regular(os.path.join(target, name))) != hashes[name]:
                    raise PublishRefused(f"copy: the copy of {name} differs from its verified hash")
        finally:
            os.close(fd)
        yield target
    except BaseException:
        failed = True
        raise
    finally:
        try:
            shutil.rmtree(tmp)
        except OSError:
            if not failed:
                raise PublishRefused("copy: the temporary copy could not be removed") from None
            print("publish: warning: a temporary copy could not be removed", file=sys.stderr)


# --- Scanners ---------------------------------------------------------------------------------

_SECRET_SCAN = None


def load_secret_scan():
    """scripts/secret_scan.py, imported by path and registered, as load_h2 does for the data rules."""
    global _SECRET_SCAN
    if _SECRET_SCAN is None:
        path = REPO_ROOT / "scripts" / "secret_scan.py"
        spec = importlib.util.spec_from_file_location("_eval_secret_scan", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _SECRET_SCAN = module
    return _SECRET_SCAN


def gitleaks_argv(binary: str, source: str, config: str, empty_dir: str, report: str) -> list[str]:
    return [binary, "dir", source, "--config", config, "--redact", "--no-banner", "--ignore-gitleaks-allow",
            "--exit-code", "1", "--gitleaks-ignore-path", empty_dir, "--report-format", "json",
            "--report-path", report]


def gitleaks_findings(binary: str, directory: str, config: str) -> int:
    """The number of findings, never their contents. Anything unexpected fails closed."""
    ss = load_secret_scan()
    try:
        ss.check_version(binary)
    except Exception:
        raise PublishRefused("gitleaks: version check failed") from None
    with tempfile.TemporaryDirectory(prefix="eval-gitleaks-") as tmp:
        tmp = os.path.realpath(tmp)
        empty, home = os.path.join(tmp, "empty"), os.path.join(tmp, "home")
        os.mkdir(empty, 0o700)
        os.mkdir(home, 0o700)
        report = os.path.join(tmp, "report.json")
        argv = gitleaks_argv(binary, os.path.realpath(directory), os.path.realpath(config), empty, report)
        try:
            code, _, _ = identity.run_allowed(argv, env=ss.scan_env(home), timeout=900, cwd=empty, gitleaks=binary)
        except EvaluationError:
            raise PublishRefused("gitleaks: the scan did not complete") from None
        if code not in (0, 1):
            raise PublishRefused("gitleaks: unexpected exit code")
        try:
            findings = json.loads(read_regular(report).decode("utf-8"))
        except (EvaluationError, ValueError, UnicodeDecodeError):
            raise PublishRefused("gitleaks: no readable report") from None
    if not isinstance(findings, list):
        raise PublishRefused("gitleaks: report is not a list")
    # Exit 1 is also gitleaks' error code, so it must agree with the report.
    if (code == 1) != bool(findings):
        raise PublishRefused("gitleaks: exit code disagrees with the report")
    return len(findings)


def h2_problems(name: str, data: bytes) -> list[str]:
    h2 = load_h2()
    return h2.check_content(name, data, h2.DATA, h2.FileRules())


# --- Spans ------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Span:
    start: int
    end: int
    rule: str


def _line_spans(line: str, offset: int) -> list[Span]:
    h2 = load_h2()
    rules = h2.FileRules()
    found = []
    i = line.find(h2.INLINE_ALLOW)
    while i >= 0:
        found.append(Span(offset + i, offset + i + len(h2.INLINE_ALLOW), "inline-allow"))
        i = line.find(h2.INLINE_ALLOW, i + 1)
    for m in h2.IPV4_RE.finditer(line):
        if not h2._ipv4_ok(m.group(1)):
            found.append(Span(offset + m.start(1), offset + m.end(1), "ipv4"))
    for m in h2.IPV6_RE.finditer(line):
        if not h2._ipv6_ok(m.group(1)):
            found.append(Span(offset + m.start(1), offset + m.end(1), "ipv6"))
    for m in h2.EMAIL_RE.finditer(line):
        if not h2.is_reserved_host(m.group(1)):
            found.append(Span(offset + m.start(), offset + m.end(), "email"))
    for m in h2.URL_RE.finditer(line):
        host = h2._host_of(m.group(1))
        if host and not h2._host_ok(host, h2.DATA, rules):
            found.append(Span(offset + m.start(1), offset + m.end(1), "url-host"))
    for m in h2.PHONE_RE.finditer(line):
        if not (m.group(3) == "555" and 100 <= int(m.group(4)) <= 199):
            found.append(Span(offset + m.start(), offset + m.end(), "phone"))
    for m in h2.SSN_RE.finditer(line):
        found.append(Span(offset + m.start(), offset + m.end(), "ssn"))
    return found


def raw_spans(text: str) -> list[Span]:
    spans, offset = [], 0
    for line in text.split("\n"):
        spans += _line_spans(line, offset)
        offset += len(line) + 1
    return spans


def spans(text: str) -> list[Span]:
    """Flagged spans of one decoded string, overlapping spans merged, in start order."""
    merged: list[Span] = []
    for span in sorted(raw_spans(text), key=lambda s: (s.start, s.end)):
        if merged and span.start < merged[-1].end:
            last = merged[-1]
            rule = min((last.rule, span.rule), key=RULE_IDS.index)
            merged[-1] = Span(last.start, max(last.end, span.end), rule)
        else:
            merged.append(span)
    return merged


def line_rule_ids(line: str) -> set[str]:
    """The rule IDs _line_rules reports for one line, for the agreement check."""
    h2 = load_h2()
    out = set()
    for message in h2._line_rules(line, h2.DATA, h2.FileRules()):
        for prefix, rule in RULE_OF_MESSAGE:
            if message.startswith(prefix):
                out.add(rule)
    return out


# --- Scan -------------------------------------------------------------------------------------

def free_text_fields(summary: dict) -> list[tuple[str, str]]:
    """(pointer, value) of the four free-text fields, in the fixed field order."""
    out = []
    severity = summary.get("severity")
    if isinstance(severity, dict) and isinstance(severity.get("rationale"), str):
        out.append(("/severity/rationale", severity["rationale"]))
    for name in FIELD_ORDER[1:]:
        values = summary.get(name)
        if isinstance(values, list):
            for i, item in enumerate(values):
                if isinstance(item, dict) and isinstance(item.get(FREE_TEXT[name]), str):
                    out.append((f"/{name}/{i}/{FREE_TEXT[name]}", item[FREE_TEXT[name]]))
    return out


def _resolve(obj, pointer: str):
    parent, key = None, None
    node = obj
    for part in pointer.split("/")[1:]:
        part = part.replace("~1", "/").replace("~0", "~")
        parent = node
        key = int(part) if isinstance(node, list) else part
        node = node[key]
    return parent, key


def _replace_spans(value: str, found: list[tuple[Span, str]]) -> str:
    for span, placeholder in sorted(found, key=lambda x: x[0].start, reverse=True):
        value = value[:span.start] + placeholder + value[span.end:]
    return value


def scan(original_dir: str) -> tuple[list[dict], list[dict]]:
    """The scan items (public form) and private items for every flagged span; refuses a flag elsewhere."""
    summaries = sorted(n for n in os.listdir(original_dir) if n.endswith(".summary.json"))
    found: list[tuple[str, int, int, str, Span, str]] = []   # file, line, field index, pointer, span, file sha
    parsed: dict[str, tuple[dict, bytes]] = {}
    for name in summaries:
        data = read_regular(os.path.join(original_dir, name))
        obj = _canonical_object(data)
        parsed[name] = (obj, data)
        for index, (pointer, value) in enumerate(free_text_fields(obj)):
            for span in spans(value):
                found.append((name, 1, index, pointer, span, sha256_hex(data)))
    found.sort(key=lambda f: (f[0], f[1], f[2], f[4].start))
    items, private = [], []
    by_pointer: dict[tuple[str, str], list[tuple[Span, str]]] = {}
    for n, (name, _line, _index, pointer, span, file_sha) in enumerate(found, start=1):
        items.append({"n": n, "file": name, "pointer": pointer, "rule": span.rule})
        _, value = _value(parsed[name][0], pointer)
        private.append({"n": n, "file": name, "pointer": pointer, "rule": span.rule, "start": span.start,
                        "end": span.end, "text": value[span.start:span.end], "file_sha256": file_sha})
        by_pointer.setdefault((name, pointer), []).append((span, f"<<REDACTED:{span.rule}:{n}>>"))
    # Every other place must be clean: each file, with its spans replaced, gives no flag.
    for name in sorted(os.listdir(original_dir)):
        data = read_regular(os.path.join(original_dir, name))
        if name in parsed:
            obj = copy.deepcopy(parsed[name][0])
            for (file, pointer), reps in by_pointer.items():
                if file == name:
                    parent, key = _resolve(obj, pointer)
                    parent[key] = _replace_spans(parent[key], reps)
            data = canonical_dumps(obj)
        if h2_problems(name, data):
            raise PublishRefused(f"scan: a flag outside the redactable fields ({name})")
    return items, private


def _value(obj: dict, pointer: str):
    parent, key = _resolve(obj, pointer)
    return parent, parent[key]


def _canonical_object(data: bytes) -> dict:
    try:
        obj = strict_loads(data)
    except SchemaError:
        raise PublishRefused("redaction: a summary is not valid JSON") from None
    if not isinstance(obj, dict) or canonical_dumps(obj) != data:
        raise PublishRefused("redaction: a summary is not in canonical form")
    return obj


def scan_items_bytes(items: list[dict]) -> bytes:
    """The scan list, validated on its own before it is written (no classification exists yet)."""
    data = canonical_dumps({"version": 1, "items": items})
    try:
        doc = records.ScanItems.model_validate(strict_loads(data))
    except Exception:
        raise EvaluationError("scan: the item list does not match its schema") from None
    if canonical_dumps(doc.model_dump()) != data:
        raise EvaluationError("scan: the item list is not in canonical form")
    for expected, item in enumerate(doc.items, start=1):
        if item.n != expected:
            raise EvaluationError("scan: item numbers must count 1, 2, ... in order")
        if records.PASS_FILE_RE.fullmatch(item.file) is None or not item.file.endswith(".summary.json"):
            raise EvaluationError("scan: an item names a file outside the summaries")
        if records.JSON_POINTER_RE.fullmatch(item.pointer) is None \
                or records.FREE_TEXT_POINTER.fullmatch(item.pointer) is None:
            raise EvaluationError("scan: an item pointer is outside the free-text fields")
    return data


# --- Redaction and withholding -------------------------------------------------------------------

def redact_summary(data: bytes, private_items: list[dict]) -> bytes:
    obj = _canonical_object(data)
    by_pointer: dict[str, list[tuple[Span, str]]] = {}
    for item in private_items:
        span = Span(item["start"], item["end"], item["rule"])
        by_pointer.setdefault(item["pointer"], []).append((span, f"<<REDACTED:{item['rule']}:{item['n']}>>"))
    for pointer, reps in by_pointer.items():
        parent, key = _resolve(obj, pointer)
        if not isinstance(parent[key], str):
            raise PublishRefused("redaction: an item does not point at a string")
        for span, _ in reps:
            if parent[key][span.start:span.end] != next(i["text"] for i in private_items
                                                        if i["pointer"] == pointer and i["start"] == span.start):
                raise PublishRefused("redaction: a span no longer matches the original")
        parent[key] = _replace_spans(parent[key], reps)
    return canonical_dumps(obj)


def withhold_digests(name: str, data: bytes, classification: str) -> tuple[bytes, list[dict]]:
    """Null the four digest and size fields of every model-call record; return the withheld items."""
    if not data.endswith(b"\n"):
        raise PublishRefused("redaction: an audit file does not end with a newline")
    out, items = [], []
    for number, line in enumerate(data.split(b"\n")[:-1], start=1):
        try:
            obj = strict_loads(line)
        except SchemaError:
            raise PublishRefused("redaction: an audit line is not valid JSON") from None
        if not isinstance(obj, dict) or canonical_dumps(obj) != line + b"\n":
            raise PublishRefused("redaction: an audit line is not in canonical form")
        if obj.get("event.name") == "triage.model_call":
            for key in DIGEST_KEYS:
                if key not in obj:
                    raise PublishRefused("redaction: a model-call record lacks a digest field")
                obj[key] = None
                items.append({"file": name, "pointer": f"L{number}/{key}", "rule": "withheld-digest",
                              "classification": classification})
        out.append(canonical_dumps(obj))
    return b"".join(out), items


# --- Closure -------------------------------------------------------------------------------------

def _diff(a, b, pointer: str, out: list[str]) -> None:
    if type(a) is not type(b):
        out.append(pointer)
    elif isinstance(a, dict):
        if list(a) != list(b):
            out.append(pointer)
            return
        for key in a:
            _diff(a[key], b[key], f"{pointer}/{key.replace('~', '~0').replace('/', '~1')}", out)
    elif isinstance(a, list):
        if len(a) != len(b):
            out.append(pointer)
            return
        for i, (x, y) in enumerate(zip(a, b)):
            _diff(x, y, f"{pointer}/{i}", out)
    elif a != b:
        out.append(pointer)


def _escape(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _strings(obj, pointer: str = ""):
    """Every string as (kind, pointer, value); kind is "value" or "key", so a key never shares a pointer."""
    if isinstance(obj, str):
        yield "value", pointer, obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield "key", f"{pointer}/{_escape(key)}", key
            yield from _strings(value, f"{pointer}/{_escape(key)}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _strings(value, f"{pointer}/{i}")


def _documents(name: str, data: bytes):
    """(pointer prefix, parsed document) for a JSON file, or for each line of a JSONL file."""
    if name.endswith(".jsonl"):
        return [(f"L{n}", strict_loads(line)) for n, line in enumerate(data.split(b"\n")[:-1], start=1)]
    return [("", strict_loads(data))]


def _placeholder_problems(name: str, data: bytes, file_items: list[dict]) -> list[str]:
    """Every placeholder occurrence is bound to exactly one listed item at its pointer, and vice versa.

    Counts, not sets: two occurrences of the same placeholder at a pointer with
    one item refuse, and so does a placeholder in an object key or in any file
    or line that has no listed item (a withheld digest lists no placeholder).
    """
    problems = []
    expected: dict[str, collections.Counter] = {}
    for item in file_items:
        if item["rule"] in RULE_IDS:
            expected.setdefault(item["pointer"], collections.Counter())[(item["rule"], item["n"])] += 1
    seen = set()
    for prefix, doc in _documents(name, data):
        for kind, pointer, value in _strings(doc, prefix):
            found = collections.Counter((m.group(1), int(m.group(2))) for m in PLACEHOLDER_RE.finditer(value))
            if kind == "key":
                if found:
                    problems.append(f"closure: {name} holds a placeholder in an object key")
                continue
            seen.add(pointer)
            if found != expected.get(pointer, collections.Counter()):
                problems.append(f"closure: {name} {pointer} placeholders differ from the listed items")
    for pointer in sorted(set(expected) - seen):
        problems.append(f"closure: {name} {pointer} is not a string")
    return problems


def _structural_problems(public_dir: str, items: list[dict], original_dir: str) -> list[str]:
    problems = []
    by_file: dict[str, list[dict]] = {}
    for item in items:
        by_file.setdefault(item["file"], []).append(item)
    for name in sorted(os.listdir(public_dir)):
        if name in PUBLIC_EXTRA:
            continue
        public = read_regular(os.path.join(public_dir, name))
        original_path = os.path.join(original_dir, name)
        if not os.path.lexists(original_path):
            problems.append(f"closure: {name} has no original")
            continue
        original = read_regular(original_path)
        file_items = by_file.get(name, [])
        # Every public file, with or without items, JSON or JSONL.
        problems += _placeholder_problems(name, public, file_items)
        if not file_items:
            if public != original:
                problems.append(f"closure: {name} differs from its original without a listed item")
            continue
        listed = {i["pointer"] for i in file_items}
        if name.endswith(".jsonl"):
            p_lines, o_lines = public.split(b"\n"), original.split(b"\n")
            if len(p_lines) != len(o_lines):
                problems.append(f"closure: {name} changed outside the listed pointers")
                continue
            for number, (p, o) in enumerate(zip(p_lines[:-1], o_lines[:-1]), start=1):
                diffs: list[str] = []
                p_obj, o_obj = strict_loads(p), strict_loads(o)
                _diff(o_obj, p_obj, f"L{number}", diffs)
                for d in diffs:
                    if d not in listed:
                        problems.append(f"closure: {name} changed outside the listed pointers")
                for pointer in (x for x in listed if x.startswith(f"L{number}/")):
                    key = pointer.split("/", 1)[1]
                    if p_obj.get(key, 0) is not None:
                        problems.append(f"closure: {name} has a listed digest that is not withheld")
            continue
        p_obj, o_obj = strict_loads(public), strict_loads(original)
        diffs = []
        _diff(o_obj, p_obj, "", diffs)
        if any(d not in listed for d in diffs):
            problems.append(f"closure: {name} changed outside the listed pointers")
    return problems


def closure_problems(public_dir: str, items: list[dict], original_dir: str, *, gitleaks_binary: str,
                     gitleaks_config: str) -> list[str]:
    """Both scanners on the public copy first, then every redaction is where it is listed and nowhere else."""
    problems = []
    for name in sorted(os.listdir(public_dir)):
        try:
            if h2_problems(name, read_regular(os.path.join(public_dir, name))):
                problems.append(f"closure: the synthetic-data rules flag {name}")
        except EvaluationError:
            problems.append(f"closure: {name} cannot be read")
    try:
        if gitleaks_findings(gitleaks_binary, public_dir, gitleaks_config):
            problems.append("closure: the secret scanner reports a finding")
    except Exception:
        problems.append("closure: the secret scanner did not complete")
    try:
        problems += _structural_problems(public_dir, items, original_dir)
    except EvaluationError:
        problems.append("closure: a public file cannot be compared with its original")
    return problems


# --- Markers ---------------------------------------------------------------------------------------

def marker_overlap_problems(private_items: list[dict], markers: list[str], strings: dict) -> list[str]:
    """No span may intersect any occurrence of any labelled marker in the same decoded line.

    strings maps (file, pointer) to the original decoded string the items point into.
    """
    problems = []
    for item in private_items:
        value = strings[(item["file"], item["pointer"])]
        start, end = item["start"], item["end"]
        line_start = value.rfind("\n", 0, start) + 1
        line_end = value.find("\n", start)
        line_end = len(value) if line_end < 0 else line_end
        line = value[line_start:line_end]
        for marker in markers:
            i = line.find(marker)
            while i >= 0:
                occ_start, occ_end = line_start + i, line_start + i + len(marker)
                if start < occ_end and occ_start < end:
                    problems.append(f"markers: a redaction overlaps a marker ({item['file']} {item['pointer']} "
                                    f"{item['rule']})")
                    break
                i = line.find(marker, i + 1)
    return problems
