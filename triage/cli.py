"""Command-line runner: one alert in, a summary out, every run audited (DD-024).

    python -m triage --format {wazuh,sigma} ALERT [--out DIR] [--audit-log FILE | --no-audit-log]

Standard output gets the summary as one line of ASCII-only JSON, so model
text can never put a raw control or format character on a terminal. With
--out, DIR/<run_id>.json and DIR/<run_id>.md are created as well, all or
nothing: a failure or an interrupt removes the files this run created (a
crash or kill -9 mid-write can still leave a partial file). The audit log is
written first: nothing is printed or created unless the append succeeded,
except with an explicit --no-audit-log.

Standard error gets at most one fixed line per failure (and a fixed notice
under --no-audit-log). No message from argparse, ingestion, a backend or the
file layer is ever forwarded: those can carry alert text, model text, paths
or the endpoint.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import stat
import sys
import uuid
from typing import BinaryIO, TextIO

from . import audit, files
from .agent import run_agent
from .audit import AuditLockTimeout, AuditLogIncomplete, AuditNotDurable, AuditRollbackFailed, write_audit_log
from .backends import make_backend
from .config import get_settings
from .embedding_model import ModelUnavailable, load_manifest, verify_model_dir
from .guardrails import build_summary
from .ingest import MAX_RAW_ALERT_BYTES, IngestError, load_alert
from .render import render_markdown
from .tools import build_tools

PROG = "alert-triage"
DEFAULT_AUDIT_LOG = os.path.join("logs", "audit.jsonl")

# Exit codes (the contract in DD-024).
OK, INTERNAL, USAGE, INPUT, AUDIT, OUTPUT, INTERRUPTED = 0, 1, 2, 3, 4, 5, 130

# Every message the CLI can print. Each is fixed text; the only additions are
# an errno name, an exception class name or the validated --format choice.
E_USAGE = "invalid arguments"
E_CONFIG = "invalid configuration"
E_EMBEDDING_MODEL = ModelUnavailable.MESSAGE
E_INPUT_READ = "cannot read the alert input"
E_INPUT_TYPE = "alert input is not a regular file or standard input"
E_INPUT_SIZE = f"alert input is larger than {MAX_RAW_ALERT_BYTES} bytes"
E_INPUT_INVALID = "alert input is not a valid {fmt} alert"
E_AUDIT_UNSAFE = "audit log is not safe or not writable"
E_AUDIT_LOCKED = "audit log is locked by another writer"
E_AUDIT_INCOMPLETE = "audit log ends without a newline"
E_AUDIT_WRITE = "audit log could not be written; it was left as it was"
E_AUDIT_PARTIAL = "audit log write failed and may end in a partial record"
E_AUDIT_DURABLE = "audit records were written, but a directory entry may not be durable"
E_AUDIT_PLATFORM = "audit logging needs a POSIX platform; use --no-audit-log"
E_OUT_UNSAFE = "output directory is not safe or not writable"
E_OUT_EXISTS = "an output file already exists"
E_OUT_REMOVED = "output files could not be written and were removed"
E_OUT_LEFT = "output files could not be written; some could not be removed"
E_OUT_PLATFORM = "--out needs a POSIX platform"
E_OUT_RENDER = "the summary could not be rendered"
E_STDOUT = "standard output could not be written"
E_INTERNAL = "internal error"
E_INTERRUPTED = "interrupted"
E_INTERRUPTED_LEFT = "interrupted; some output files could not be removed"
NOTICE_NO_AUDIT = "audit log disabled"


class Failure(Exception):
    """A run that ends with one fixed message and an exit code."""

    def __init__(self, code: int, message: str, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.cause = cause


class _Parser(argparse.ArgumentParser):
    # argparse's own errors quote the offending value (an invalid choice, an
    # unknown option), so they are replaced by one fixed message.
    def error(self, message: str):  # noqa: ARG002 - the message is deliberately dropped
        raise Failure(USAGE, E_USAGE)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog=PROG, allow_abbrev=False,
                     description="Triage one security alert with the read-only agent and print its summary.")
    parser.add_argument("alert", metavar="ALERT", help="alert JSON file, or - for standard input")
    parser.add_argument("--format", required=True, choices=["wazuh", "sigma"], help="the alert's format")
    parser.add_argument("--out", metavar="DIR", help="also write DIR/<run_id>.json and DIR/<run_id>.md")
    logging = parser.add_mutually_exclusive_group()
    logging.add_argument("--audit-log", metavar="FILE", default=DEFAULT_AUDIT_LOG,
                         help=f"append the run's audit records here (default: {DEFAULT_AUDIT_LOG})")
    logging.add_argument("--no-audit-log", action="store_true", help="run without an audit log")
    return parser


def _new_run_id() -> str:
    # One place for the run ID, so tests can fix it.
    return uuid.uuid4().hex


def _audit_supported() -> bool:
    return audit.fcntl is not None and files.supported()


def _errno_suffix(error: BaseException | None) -> str:
    code = getattr(error, "errno", None)
    return f" ({errno.errorcode[code]})" if isinstance(code, int) and code in errno.errorcode else ""


# --- Preflight: advisory only; every check is repeated when the files are used ---

def _preflight_audit(path: str) -> None:
    parent, name = os.path.split(path)
    try:
        files.single_component(name)
        dir_fd = files.open_private_dir(parent or ".", what="audit log", create=True)
    except (OSError, ValueError) as error:
        raise Failure(AUDIT, E_AUDIT_UNSAFE + _errno_suffix(error)) from None
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
        except FileNotFoundError:
            return
        except OSError as error:
            raise Failure(AUDIT, E_AUDIT_UNSAFE + _errno_suffix(error)) from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                raise Failure(AUDIT, E_AUDIT_UNSAFE)
            if st.st_size and os.pread(fd, 1, st.st_size - 1) != b"\n":
                raise Failure(AUDIT, E_AUDIT_INCOMPLETE)
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)


def _preflight_out(path: str) -> None:
    try:
        os.close(files.open_private_dir(path, what="output", create=True))
    except OSError as error:
        raise Failure(OUTPUT, E_OUT_UNSAFE + _errno_suffix(error)) from None


# --- Input -------------------------------------------------------------------

def _read_limited(stream: BinaryIO) -> bytes:
    # One byte over the limit is enough to know the input is too large.
    chunks, total = [], 0
    while total <= MAX_RAW_ALERT_BYTES:
        chunk = stream.read(MAX_RAW_ALERT_BYTES + 1 - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > MAX_RAW_ALERT_BYTES:
        raise Failure(INPUT, E_INPUT_SIZE)
    return b"".join(chunks)


# O_NONBLOCK: a FIFO without a writer must not hang the run. O_NONBLOCK and
# O_CLOEXEC exist only on POSIX and O_BINARY only on Windows, so each is used
# where it exists; Windows has no FIFO at a file path. The regular-file check
# and the size limit below apply everywhere. Read at call time, so a test can
# remove the POSIX flags.
def _input_flags() -> int:
    return (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0))


def _read_alert(path: str, stdin: BinaryIO) -> bytes:
    if path == "-":
        try:
            return _read_limited(stdin)
        except OSError:
            raise Failure(INPUT, E_INPUT_READ) from None
    try:
        fd = os.open(path, _input_flags())
    except OSError as error:
        raise Failure(INPUT, E_INPUT_READ + _errno_suffix(error)) from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Failure(INPUT, E_INPUT_TYPE)
        with os.fdopen(os.dup(fd), "rb") as stream:
            return _read_limited(stream)
    except OSError as error:
        raise Failure(INPUT, E_INPUT_READ + _errno_suffix(error)) from None
    finally:
        os.close(fd)


# --- Writes --------------------------------------------------------------------

def _append_audit(result, alert, summary, path: str) -> None:
    try:
        write_audit_log(result, alert, path, summary=summary)
    except AuditLockTimeout:
        raise Failure(AUDIT, E_AUDIT_LOCKED) from None
    except AuditLogIncomplete:
        raise Failure(AUDIT, E_AUDIT_INCOMPLETE) from None
    except AuditRollbackFailed:
        raise Failure(AUDIT, E_AUDIT_PARTIAL) from None
    except AuditNotDurable:
        raise Failure(AUDIT, E_AUDIT_DURABLE) from None
    except PermissionError as error:
        raise Failure(AUDIT, E_AUDIT_UNSAFE + _errno_suffix(error)) from None
    except (OSError, ValueError) as error:
        # The writer builds every line before touching the file and rolls a
        # failed append back, so the log is as it was.
        raise Failure(AUDIT, E_AUDIT_WRITE + _errno_suffix(error)) from None


def _write_outputs(path: str, run_id: str, summary_json: bytes, markdown: bytes) -> None:
    try:
        dir_fd = files.open_private_dir(path, what="output", create=True)
    except OSError as error:
        raise Failure(OUTPUT, E_OUT_UNSAFE + _errno_suffix(error)) from None
    try:
        # Names from the validated run ID only, never from alert data.
        files.write_new_files(dir_fd, path, [(f"{run_id}.json", summary_json), (f"{run_id}.md", markdown)],
                              what="output")
    except files.FilesNotWritten as error:
        if error.interrupted:
            raise Failure(INTERRUPTED, E_INTERRUPTED if error.removed else E_INTERRUPTED_LEFT) from None
        if not error.removed:
            raise Failure(OUTPUT, E_OUT_LEFT) from None
        raise Failure(OUTPUT, E_OUT_EXISTS if error.collision else E_OUT_REMOVED) from None
    finally:
        os.close(dir_fd)


def _summary_json(summary) -> bytes:
    # ASCII-only: ANSI escapes, bidi overrides and lone surrogates in model
    # text are written as JSON escapes (model_dump_json() would raise on a
    # lone surrogate).
    text = json.dumps(summary.model_dump(mode="json"), ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    return (text + "\n").encode("ascii")


# --- Main -----------------------------------------------------------------------

def run(argv: list[str], stdin: BinaryIO, stdout: BinaryIO, stderr: TextIO) -> int:
    args = _parser().parse_args(argv)
    if args.no_audit_log:
        print(f"{PROG}: {NOTICE_NO_AUDIT}", file=stderr)
    elif not _audit_supported():
        raise Failure(AUDIT, E_AUDIT_PLATFORM)
    if args.out is not None and not files.supported():
        raise Failure(OUTPUT, E_OUT_PLATFORM)

    try:
        settings = get_settings()
        backend = make_backend(settings)
        tools = build_tools(settings)
    except Exception:
        raise Failure(USAGE, E_CONFIG) from None
    if settings.embedder == "minilm":
        # Checked here, before the audit log, the alert or the model, so a missing
        # or altered model is a configuration error, not a degraded summary.
        # Loading verifies again, and never downloads (DD-027).
        try:
            verify_model_dir(settings.embedding_model_dir, load_manifest())
        except ModelUnavailable:
            raise Failure(USAGE, E_EMBEDDING_MODEL) from None

    if not args.no_audit_log:
        _preflight_audit(args.audit_log)
    if args.out is not None:
        _preflight_out(args.out)

    raw = _read_alert(args.alert, stdin)
    try:
        alert = load_alert(raw, fmt=args.format)
    except IngestError:
        raise Failure(INPUT, E_INPUT_INVALID.format(fmt=args.format)) from None

    result = run_agent(alert, backend, settings=settings, tools=tools, run_id=_new_run_id())
    summary = build_summary(result, alert, settings, tools)

    # Every byte is built before anything is written.
    rendered: tuple[bytes, bytes] | None = None
    try:
        rendered = (_summary_json(summary),
                    render_markdown(summary).encode("utf-8") if args.out is not None else b"")
    except (ValueError, UnicodeError):
        pass   # reported after the audit append, which still records the run

    if not args.no_audit_log:
        _append_audit(result, alert, summary, args.audit_log)
    if rendered is None:
        raise Failure(OUTPUT, E_OUT_RENDER)
    summary_json, markdown = rendered
    if args.out is not None:
        _write_outputs(args.out, summary.run_id, summary_json, markdown)
    try:
        stdout.write(summary_json)
        stdout.flush()
    except OSError:
        raise Failure(OUTPUT, E_STDOUT) from None
    return OK


def main(argv: list[str] | None = None) -> int:
    stderr = sys.stderr
    try:
        return run(sys.argv[1:] if argv is None else argv, sys.stdin.buffer, sys.stdout.buffer, stderr)
    except Failure as failure:
        code, message = failure.code, failure.message
    except KeyboardInterrupt:
        code, message = INTERRUPTED, E_INTERRUPTED
    except Exception as error:   # never the message or traceback: they can hold input
        code, message = INTERNAL, f"{E_INTERNAL} ({type(error).__name__})"
    if code == OUTPUT and message == E_STDOUT:
        _silence_stdout()
    print(f"{PROG}: error: {message}", file=stderr)
    return code


def _silence_stdout() -> None:
    # After a broken pipe, point standard output at /dev/null so the
    # interpreter's final flush does not print its own error.
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
    except (OSError, ValueError, AttributeError):
        pass
