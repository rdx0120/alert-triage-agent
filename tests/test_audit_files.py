"""Audit-log file safety for concurrent CLI use: directory descriptors, locking,
rollback, durability and well-formed input (DD-018)."""

import os
import stat
import subprocess
import sys
import threading
import time

import pytest

from test_audit import MARKER, _deterministic, _heuristic, _lines
from triage import audit, files
from triage.audit import (AuditLockTimeout, AuditLogIncomplete, AuditNotDurable, AuditRollbackFailed,
                          write_audit_log)
from triage.config import REPO_ROOT

try:
    import fcntl
except ImportError:   # Windows: the audit writer refuses to run there
    fcntl = None

# The writer needs POSIX (O_NOFOLLOW, O_DIRECTORY, dir_fd, flock); elsewhere
# these tests are skipped, and the writer's own refusal is what applies.
posix_only = pytest.mark.skipif(fcntl is None or not files.supported(),
                                reason="the audit writer needs POSIX file operations")


def _logged(tmp_path, settings, tools):
    """A log directory and a log that already holds one run's records."""
    result, alert = _deterministic(settings, tools)
    path = tmp_path / "logs" / "audit.jsonl"
    count = write_audit_log(result, alert, path)
    return result, alert, path, count


# --- Names and directories ------------------------------------------------------

@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "x\0y", 5])
def test_only_single_components_are_opened(name):
    """A name with a separator, a dot name or a NUL is opened relative to a directory descriptor."""
    with pytest.raises(ValueError, match="^file name must be a single path component$"):
        files.single_component(name)


@posix_only
@pytest.mark.parametrize("suffix", ["/", "/.."])
def test_path_must_end_in_a_file_name(suffix, tmp_path, settings, tools):
    """A log path ending in a separator or a dot name is accepted, or creates a directory."""
    result, alert = _heuristic(settings, tools)
    with pytest.raises(ValueError, match="^audit log path must end in a file name$"):
        write_audit_log(result, alert, str(tmp_path / "logs") + suffix)
    assert not (tmp_path / "logs").exists()


@posix_only
def test_directory_swapped_after_check_refused(monkeypatch, tmp_path, settings, tools):
    """A directory replaced between its lstat check and its open is used anyway."""
    result, alert = _heuristic(settings, tools)
    logs, other = tmp_path / "logs", tmp_path / "other"
    logs.mkdir(mode=0o700)
    other.mkdir(mode=0o700)
    real = os.lstat

    def swapped(p, *args, **kwargs):
        # What lstat saw is another directory than the one later opened.
        return real(other if os.fspath(p) == os.fspath(logs) else p, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(os, "lstat", swapped)
        with pytest.raises(PermissionError, match="^audit log directory must be ours"):
            write_audit_log(result, alert, logs / "audit.jsonl")
    assert list(logs.iterdir()) == [] and list(other.iterdir()) == []


@posix_only
def test_directory_replaced_by_a_symlink_after_check_refused(monkeypatch, tmp_path, settings, tools):
    """A directory that becomes a symlink between its lstat check and its open is followed."""
    result, alert = _heuristic(settings, tools)
    real_dir, link = tmp_path / "real", tmp_path / "logs"
    real_dir.mkdir(mode=0o700)
    link.symlink_to(real_dir, target_is_directory=True)
    real = os.lstat

    def as_if_checked_before_the_swap(p, *args, **kwargs):
        return real(real_dir if os.fspath(p) == os.fspath(link) else p, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(os, "lstat", as_if_checked_before_the_swap)
        with pytest.raises(PermissionError, match="^audit log directory must be ours"):
            write_audit_log(result, alert, link / "audit.jsonl")
    assert list(real_dir.iterdir()) == []


@posix_only
@pytest.mark.parametrize("name", ["../escape.jsonl", "sub/x.jsonl", ".."])
def test_file_helper_refuses_multi_component_names(name, tmp_path):
    """open_private_file() opens a name that leaves its directory."""
    inner = tmp_path / "inner"
    inner.mkdir(mode=0o700)
    dir_fd = files.open_private_dir(str(inner), what="test", create=False)
    try:
        with pytest.raises(ValueError, match="^file name must be a single path component$"):
            files.open_private_file(dir_fd, name, what="test", append=True)
    finally:
        os.close(dir_fd)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["inner"] and list(inner.iterdir()) == []


@posix_only
def test_platform_without_safe_opens_writes_nothing(monkeypatch, tmp_path, settings, tools):
    """Where dir_fd opens or file locking are missing, the writer creates something before refusing."""
    result, alert = _heuristic(settings, tools)
    path = tmp_path / "logs" / "audit.jsonl"
    for patch in (lambda m: m.setattr(files, "supported", lambda: False), lambda m: m.setattr(audit, "fcntl", None)):
        with monkeypatch.context() as m:
            patch(m)
            with pytest.raises(OSError, match="^audit log needs O_DIRECTORY, dir_fd and file locking"):
                write_audit_log(result, alert, path)
        assert not path.parent.exists()


# --- Locking ----------------------------------------------------------------------

@posix_only
def test_lock_timeout_writes_nothing(monkeypatch, tmp_path, settings, tools):
    """A writer appends while another holds the lock, or waits without bound."""
    result, alert, path, _ = _logged(tmp_path, settings, tools)
    before = path.read_bytes()
    monkeypatch.setattr(audit, "LOCK_TIMEOUT_S", 0.2)
    holder = os.open(path, os.O_RDONLY)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        started = time.monotonic()
        with pytest.raises(AuditLockTimeout, match="^audit log is locked by another writer$"):
            write_audit_log(result, alert, path)
        assert time.monotonic() - started < 5
    finally:
        os.close(holder)
    assert path.read_bytes() == before


@posix_only
def test_writer_waits_for_a_released_lock(tmp_path, settings, tools):
    """A lock released within the timeout makes the writer fail instead of waiting for it."""
    result, alert, path, count = _logged(tmp_path, settings, tools)
    holder = os.open(path, os.O_RDONLY)
    fcntl.flock(holder, fcntl.LOCK_EX)
    releaser = threading.Timer(0.3, os.close, args=(holder,))
    releaser.start()
    try:
        assert write_audit_log(result, alert, path) == count
    finally:
        releaser.join()
    assert len(_lines(path)) == 2 * count


CONCURRENT = """
import sys
from datetime import datetime, timezone
from triage.agent import run_agent
from triage.audit import write_audit_log
from triage.backends import HeuristicBackend
from triage.config import REPO_ROOT, Settings
from triage.ingest import load_alert
from triage.tools import build_tools
settings = Settings(embedder="hashing")
tools = build_tools(settings)
sample = REPO_ROOT / "samples" / "alerts" / "wazuh" / "encoded_powershell.json"
alert = load_alert(sample.read_text(encoding="utf-8"), fmt="wazuh")
result = run_agent(alert, HeuristicBackend(), settings=settings, tools=tools)
for _ in range(int(sys.argv[2])):
    write_audit_log(result, alert, sys.argv[1])
"""


@posix_only
def test_concurrent_writers_leave_whole_lines(tmp_path):
    """Two processes appending to one log interleave inside a line or lose records."""
    path = tmp_path / "logs" / "audit.jsonl"
    path.parent.mkdir(mode=0o700)
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    procs = [subprocess.Popen([sys.executable, "-c", CONCURRENT, str(path), "15"], env=env) for _ in range(2)]
    assert [p.wait(timeout=120) for p in procs] == [0, 0]
    records = _lines(path)
    runs = [r for r in records if r["event.name"] == "triage.run"]
    assert len(runs) == 30
    per_run = len(records) // 30
    assert len(records) == 30 * per_run
    # Each run's records stay together and in order.
    for start in range(0, len(records), per_run):
        block = records[start:start + per_run]
        assert [r["triage.seq"] for r in block] == list(range(per_run))
        assert len({r["gen_ai.conversation.id"] for r in block}) == 1


# --- Partial records and rollback -------------------------------------------------

@posix_only
def test_log_ending_without_newline_refused(tmp_path, settings, tools):
    """A log whose last record is partial gets a new record glued onto it."""
    result, alert, path, _ = _logged(tmp_path, settings, tools)
    with open(path, "ab") as f:
        f.write(b'{"partial')
    before = path.read_bytes()
    with pytest.raises(AuditLogIncomplete, match="^audit log ends without a newline$"):
        write_audit_log(result, alert, path)
    assert path.read_bytes() == before


@posix_only
def test_failed_write_is_rolled_back(monkeypatch, tmp_path, settings, tools):
    """A write that fails part-way leaves its partial bytes in the log."""
    result, alert, path, _ = _logged(tmp_path, settings, tools)
    before = path.read_bytes()
    real = os.write
    calls = []

    def fail_second(fd, data):
        calls.append(1)
        if len(calls) == 1:
            return real(fd, data[:7])
        raise OSError(28, "No space left on device")

    with monkeypatch.context() as m:
        m.setattr(os, "write", fail_second)
        with pytest.raises(OSError, match="No space"):
            write_audit_log(result, alert, path)
    assert path.read_bytes() == before


@posix_only
def test_failed_fsync_is_rolled_back(monkeypatch, tmp_path, settings, tools):
    """An append whose fsync fails stays in the log as if it had succeeded."""
    result, alert, path, _ = _logged(tmp_path, settings, tools)
    before = path.read_bytes()
    real = os.fsync
    calls = []

    def fail_first(fd):
        calls.append(fd)
        if len(calls) == 1:
            raise OSError(5, "Input/output error")
        return real(fd)

    with monkeypatch.context() as m:
        m.setattr(os, "fsync", fail_first)
        with pytest.raises(OSError, match="Input/output error"):
            write_audit_log(result, alert, path)
    assert path.read_bytes() == before


@posix_only
def test_failed_rollback_is_reported(monkeypatch, tmp_path, settings, tools):
    """A rollback that fails is reported as the original error, hiding a possible partial record."""
    result, alert, path, _ = _logged(tmp_path, settings, tools)

    def fail(*args):
        raise OSError(5, "Input/output error")

    with monkeypatch.context() as m:
        m.setattr(os, "write", fail)
        m.setattr(os, "ftruncate", fail)
        with pytest.raises(AuditRollbackFailed) as raised:
            write_audit_log(result, alert, path)
    assert str(raised.value) == ("audit log write failed and could not be rolled back; "
                                 "it may end in a partial record")


# --- Durability ---------------------------------------------------------------------

def _record_fsyncs(monkeypatch):
    """Records, for each fsync, whether its descriptor is a directory and its inode."""
    real = os.fsync
    seen = []

    def recording(fd):
        st = os.stat(fd)
        seen.append((stat.S_ISDIR(st.st_mode), st.st_ino))
        return real(fd)

    monkeypatch.setattr(os, "fsync", recording)
    return seen


@posix_only
@pytest.mark.parametrize("state", ["new_directory", "new_file", "existing_file"])
def test_every_append_syncs_file_directory_and_parent(state, monkeypatch, tmp_path, settings, tools):
    """An append returns before its file, the file's directory entry and the directory's entry are synced."""
    result, alert = _deterministic(settings, tools)
    path = tmp_path / "logs" / "audit.jsonl"
    if state != "new_directory":
        path.parent.mkdir(mode=0o700)
    if state == "existing_file":
        write_audit_log(result, alert, path)
    seen = _record_fsyncs(monkeypatch)
    write_audit_log(result, alert, path)
    # The same three syncs whoever created the file or directory, so no writer
    # relies on another writer's sync.
    assert seen == [(False, path.stat().st_ino), (True, path.parent.stat().st_ino), (True, tmp_path.stat().st_ino)]


@posix_only
def test_directory_syncs_happen_under_the_lock(monkeypatch, tmp_path, settings, tools):
    """The lock is released before the directory syncs, so another writer can report success first."""
    result, alert = _heuristic(settings, tools)
    path = tmp_path / "logs" / "audit.jsonl"
    path.parent.mkdir(mode=0o700)
    real = os.fsync
    locked_during_dir_sync = []

    def probing(fd):
        if stat.S_ISDIR(os.stat(fd).st_mode):
            probe = os.open(path, os.O_RDONLY)
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                locked_during_dir_sync.append(True)
            else:
                locked_during_dir_sync.append(False)
            finally:
                os.close(probe)
        return real(fd)

    monkeypatch.setattr(os, "fsync", probing)
    write_audit_log(result, alert, path)
    assert locked_during_dir_sync == [True, True]


@posix_only
@pytest.mark.parametrize("which", ["directory", "parent"])
def test_directory_sync_failure_keeps_the_records(which, monkeypatch, tmp_path, settings, tools):
    """A failed directory or parent fsync is ignored, or rolls back records that are already synced."""
    result, alert = _heuristic(settings, tools)
    logs = tmp_path / "logs"
    logs.mkdir(mode=0o700)
    target = (logs if which == "directory" else tmp_path).stat().st_ino
    real = os.fsync

    def fail_on(fd):
        if os.stat(fd).st_ino == target:
            raise OSError(5, "Input/output error")
        return real(fd)

    with monkeypatch.context() as m:
        m.setattr(os, "fsync", fail_on)
        with pytest.raises(AuditNotDurable, match="^audit records were written, but their directory entries"):
            write_audit_log(result, alert, logs / "audit.jsonl")
    assert len(_lines(logs / "audit.jsonl")) == 1 + len(result.tool_records) + len(result.model_calls)


# --- First-time creation race -----------------------------------------------------------

def _competing_mkdir(monkeypatch, create):
    """Makes os.mkdir behave as if another writer created the path just after our lstat."""
    real = os.mkdir

    def racing(path, mode=0o777, *args, **kwargs):
        create(path, real)
        raise FileExistsError(17, "File exists", os.fspath(path))

    monkeypatch.setattr(os, "mkdir", racing)


@posix_only
def test_directory_created_by_another_writer_is_used(monkeypatch, tmp_path, settings, tools):
    """A directory another writer created between our lstat and our mkdir makes the append fail."""
    result, alert = _heuristic(settings, tools)
    path = tmp_path / "logs" / "audit.jsonl"
    _competing_mkdir(monkeypatch, lambda p, real: real(p, 0o700))
    seen = _record_fsyncs(monkeypatch)
    assert write_audit_log(result, alert, path) == 1 + len(result.tool_records) + len(result.model_calls)
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    # The parent is synced by this writer too, not left to the one that made the directory.
    assert seen[-1] == (True, tmp_path.stat().st_ino)


@posix_only
@pytest.mark.parametrize("planted", ["symlink", "group_writable", "file"])
def test_unsafe_path_created_by_another_writer_is_refused(planted, monkeypatch, tmp_path, settings, tools):
    """Something unsafe created at the path between our lstat and our mkdir is used."""
    result, alert = _heuristic(settings, tools)
    path = tmp_path / "logs" / "audit.jsonl"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)

    def plant(p, real):
        if planted == "symlink":
            os.symlink(elsewhere, p, target_is_directory=True)
        elif planted == "group_writable":
            real(p, 0o700)
            os.chmod(p, 0o770)
        else:
            open(p, "w").close()

    _competing_mkdir(monkeypatch, plant)
    with pytest.raises(PermissionError, match="^audit log directory must be ours"):
        write_audit_log(result, alert, path)
    assert list(elsewhere.iterdir()) == []
    if planted == "group_writable":
        assert list(path.parent.iterdir()) == []


FIRST_APPEND = """
import sys, time
from pathlib import Path
from triage.agent import run_agent
from triage.audit import write_audit_log
from triage.backends import HeuristicBackend
from triage.config import REPO_ROOT, Settings
from triage.ingest import load_alert
from triage.tools import build_tools
settings = Settings(embedder="hashing")
tools = build_tools(settings)
sample = REPO_ROOT / "samples" / "alerts" / "wazuh" / "encoded_powershell.json"
alert = load_alert(sample.read_text(encoding="utf-8"), fmt="wazuh")
result = run_agent(alert, HeuristicBackend(), settings=settings, tools=tools)
go = Path(sys.argv[2])
while not go.exists():   # start together, so the first appends race
    time.sleep(0.001)
write_audit_log(result, alert, sys.argv[1])
"""


@posix_only
def test_concurrent_first_appends_all_succeed(tmp_path):
    """Writers that find the log directory missing at the same moment fail or lose records."""
    path = tmp_path / "logs" / "audit.jsonl"
    go = tmp_path / "go"
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    procs = [subprocess.Popen([sys.executable, "-c", FIRST_APPEND, str(path), str(go)], env=env,
                              stderr=subprocess.PIPE) for _ in range(4)]
    time.sleep(2.0)   # let every process load and wait at the start line
    go.touch()
    codes = [p.wait(timeout=120) for p in procs]
    assert codes == [0, 0, 0, 0], [p.stderr.read()[-300:] for p in procs]
    records = _lines(path)
    runs = [r for r in records if r["event.name"] == "triage.run"]
    assert len(runs) == 4 and len(records) % 4 == 0
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700 and stat.S_IMODE(path.stat().st_mode) == 0o600


# --- Well-formed input ----------------------------------------------------------------

MALFORMED = [
    ("result", lambda r, a: (object(), a)),
    ("alert", lambda r, a: (r, object())),
    ("enrichment", lambda r, a: (_set(r, "enrichment", object()), a)),
    ("model_calls_int", lambda r, a: (_set(r, "model_calls", 5), a)),
    ("model_calls_item", lambda r, a: (_set(r, "model_calls", [object()]), a)),
    ("tool_records_none", lambda r, a: (_set(r, "tool_records", None), a)),
    ("tool_records_item", lambda r, a: (_set(r, "tool_records", [1]), a)),
    ("draft", lambda r, a: (_set(r, "draft", object()), a)),
    ("draft_severity", lambda r, a: (_set(r.draft, "severity", object()) and r, a)),
    ("draft_technique", lambda r, a: (_set(r.draft, "technique", MARKER) and r, a)),
]


def _set(obj, field, value):
    object.__setattr__(obj, field, value)
    return obj


@pytest.mark.parametrize("make", [m for _, m in MALFORMED], ids=[n for n, _ in MALFORMED])
def test_malformed_run_result_gives_the_fixed_message(make, tmp_path, settings, tools):
    """A replaced container raises TypeError or AttributeError, or writes something."""
    result, alert = _heuristic(settings, tools)
    bad_result, bad_alert = make(result.model_copy(deep=True), alert)
    path = tmp_path / "logs" / "audit.jsonl"
    with pytest.raises(ValueError) as raised:
        write_audit_log(bad_result, bad_alert, path)
    assert str(raised.value) == "the run result is not well-formed"
    assert not path.parent.exists()
