"""The command-line runner end to end, with the rule-based backend (DD-024)."""

import io
import json
import os
import re
import stat
import subprocess
import sys

import pytest

from test_audit import ScriptedBackend
from triage import audit, cli, files
from triage.backends import BackendError, ChatReply, HeuristicBackend
from triage.config import REPO_ROOT
from triage.render import render_markdown
from triage.schemas import TriageSummary

try:
    import fcntl
except ImportError:
    fcntl = None

POWERSHELL = REPO_ROOT / "samples" / "alerts" / "wazuh" / "encoded_powershell.json"
SIGMA = sorted((REPO_ROOT / "samples" / "alerts" / "sigma").glob("*.json"))[0]
MARKER = "ZQXMARKER7731"
RUN_ID = "0123456789abcdef" * 2
MESSAGES = {v for k, v in vars(cli).items() if k.startswith("E_")} - {cli.E_INPUT_INVALID}
MESSAGES |= {cli.E_INPUT_INVALID.format(fmt=f) for f in ("wazuh", "sigma")}
posix_only = pytest.mark.skipif(fcntl is None or not files.supported(),
                                reason="the audit log and --out need POSIX file operations")


@pytest.fixture(autouse=True)
def environment(monkeypatch, tmp_path):
    for name in ("TRIAGE_BACKEND", "TRIAGE_EMBEDDER", "OLLAMA_HOST", "OLLAMA_MODEL", "OLLAMA_THINK"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TRIAGE_EMBEDDER", "hashing")
    monkeypatch.setenv("TRIAGE_BACKEND", "heuristic")
    monkeypatch.chdir(tmp_path)


class Run:
    def __init__(self, code, stdout, stderr):
        self.code, self.stdout, self.stderr = code, stdout, stderr


class BrokenPipe(io.RawIOBase):
    def writable(self):
        return True

    def write(self, data):
        raise BrokenPipeError(32, "Broken pipe")


def invoke(monkeypatch, *argv, stdin=b"", stdout=None):
    """cli.main() in-process with its standard streams captured."""
    out = io.BytesIO() if stdout is None else stdout
    err = io.StringIO()
    wrapped_in, wrapped_out = io.TextIOWrapper(io.BytesIO(stdin)), io.TextIOWrapper(out)
    with monkeypatch.context() as m:
        m.setattr(sys, "stdin", wrapped_in)
        m.setattr(sys, "stdout", wrapped_out)
        m.setattr(sys, "stderr", err)
        code = cli.main(list(argv))
    captured = out.getvalue() if stdout is None else b""
    wrapped_in.detach()
    wrapped_out.detach()   # so closing the wrappers never closes the captured buffer
    return Run(code, captured, err.getvalue())


def assert_fixed(stderr, message, *, notice=False):
    """Standard error is exactly the fixed lines expected, nothing else."""
    assert message in MESSAGES or re.sub(r" \((?:E[A-Z0-9]+|[A-Za-z_]+Error|[A-Za-z_]+)\)$", "", message) in MESSAGES
    expected = (f"{cli.PROG}: {cli.NOTICE_NO_AUDIT}\n" if notice else "") + f"{cli.PROG}: error: {message}\n"
    assert stderr == expected
    assert MARKER not in stderr


class Counting(HeuristicBackend):
    """The rule-based backend, counting its calls."""

    calls = 0

    def chat(self, request):
        Counting.calls += 1
        return super().chat(request)


@pytest.fixture
def counting(monkeypatch):
    Counting.calls = 0
    monkeypatch.setattr(cli, "make_backend", lambda settings: Counting())
    return Counting


def _records(path):
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def _check_success(run, tmp_path, *, out=None, audit_log=None):
    assert run.code == cli.OK
    assert run.stdout.endswith(b"\n") and run.stdout.count(b"\n") == 1 and run.stdout.isascii()
    summary = TriageSummary.model_validate_json(run.stdout)
    if out is not None:
        assert sorted(p.name for p in out.iterdir()) == [f"{summary.run_id}.json", f"{summary.run_id}.md"]
        assert (out / f"{summary.run_id}.json").read_bytes() == run.stdout
        assert (out / f"{summary.run_id}.md").read_text(encoding="utf-8") == render_markdown(summary)
        for p in out.iterdir():
            assert stat.S_IMODE(p.stat().st_mode) == 0o600
    if audit_log is not None:
        records = _records(audit_log)
        assert records[0]["event.name"] == "triage.run" and records[-1]["event.name"] == "triage.summary"
        assert {r["gen_ai.conversation.id"] for r in records} == {summary.run_id}
        assert stat.S_IMODE(audit_log.stat().st_mode) == 0o600
        assert stat.S_IMODE(audit_log.parent.stat().st_mode) == 0o700
    return summary


# --- Success ----------------------------------------------------------------------

@posix_only
def test_end_to_end_as_a_module(tmp_path):
    """python -m triage fails, writes to standard error, or outputs that differ from each other."""
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT), "TRIAGE_EMBEDDER": "hashing", "TRIAGE_BACKEND": "heuristic"}
    proc = subprocess.run([sys.executable, "-m", "triage", "--format", "wazuh", str(POWERSHELL), "--out", "out"],
                          cwd=tmp_path, env=env, capture_output=True, timeout=120)
    assert proc.stderr == b""
    run = Run(proc.returncode, proc.stdout, "")
    summary = _check_success(run, tmp_path, out=tmp_path / "out", audit_log=tmp_path / "logs" / "audit.jsonl")
    assert summary.status == "triaged" and summary.backend == "heuristic"


@posix_only
def test_standard_input_and_sigma(monkeypatch, tmp_path):
    """An alert on standard input, or a Sigma alert, is not triaged like a file."""
    run = invoke(monkeypatch, "--format", "sigma", "-", stdin=SIGMA.read_bytes())
    assert run.stderr == ""
    _check_success(run, tmp_path, audit_log=tmp_path / "logs" / "audit.jsonl")


@posix_only
def test_explicit_audit_log_path(monkeypatch, tmp_path):
    """--audit-log is ignored, or the default log is written as well."""
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--audit-log", "elsewhere/run.jsonl")
    _check_success(run, tmp_path, audit_log=tmp_path / "elsewhere" / "run.jsonl")
    assert not (tmp_path / "logs").exists()


def test_no_audit_log_is_explicit_and_noted(monkeypatch, tmp_path):
    """--no-audit-log writes a log, stays silent about it, or changes the summary."""
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--no-audit-log")
    assert run.stderr == f"{cli.PROG}: {cli.NOTICE_NO_AUDIT}\n"
    _check_success(run, tmp_path)
    assert list(tmp_path.iterdir()) == []


@posix_only
def test_alert_text_reaches_neither_stderr_nor_the_log(monkeypatch, tmp_path):
    """Alert text appears on standard error or in the audit log."""
    raw = json.loads(POWERSHELL.read_text(encoding="utf-8"))
    raw["rule"]["description"] = f"{raw['rule']['description']} {MARKER}"
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps(raw), encoding="utf-8")
    run = invoke(monkeypatch, "--format", "wazuh", str(alert))
    _check_success(run, tmp_path, audit_log=tmp_path / "logs" / "audit.jsonl")
    assert run.stderr == ""
    assert MARKER not in (tmp_path / "logs" / "audit.jsonl").read_text(encoding="ascii")


@posix_only
def test_backend_error_is_a_summary_not_a_failure(monkeypatch, tmp_path):
    """A failing backend makes the CLI fail, or its error text reaches an output."""
    class Failing(HeuristicBackend):
        def chat(self, request):
            raise BackendError(f"unreachable {MARKER}")

    monkeypatch.setattr(cli, "make_backend", lambda settings: Failing())
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out")
    summary = _check_success(run, tmp_path, out=tmp_path / "out", audit_log=tmp_path / "logs" / "audit.jsonl")
    assert summary.status == "error" and run.stderr == ""
    for p in [*(tmp_path / "out").iterdir(), tmp_path / "logs" / "audit.jsonl"]:
        assert MARKER not in p.read_text(encoding="utf-8")


@posix_only
def test_model_text_cannot_reach_the_terminal_raw(monkeypatch, tmp_path):
    """An ANSI escape or bidi override in model text reaches standard output raw."""
    hostile = f"{MARKER} {chr(0x1B)}[31mred {chr(0x202E)}reversed {chr(0x2028)}line"
    draft = {"severity": {"value": "high", "rationale": hostile, "sources": ["rule_level"]},
             "next_steps": [], "containment": [], "missing_data": []}
    monkeypatch.setattr(cli, "make_backend",
                        lambda settings: ScriptedBackend([ChatReply(), ChatReply(text=json.dumps(draft))]))
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out")
    summary = _check_success(run, tmp_path, out=tmp_path / "out")
    assert summary.severity.rationale == hostile                 # the text is kept, escaped
    assert all(b < 0x80 for b in run.stdout) and b"\x1b" not in run.stdout
    markdown = (tmp_path / "out" / f"{summary.run_id}.md").read_text(encoding="utf-8")
    assert "<U+001B>" in markdown and "<U+202E>" in markdown and "<U+2028>" in markdown
    assert run.stderr == ""


@posix_only
def test_concurrent_runs_share_one_log(tmp_path):
    """Two CLI runs appending to one log at once interleave or lose records."""
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT), "TRIAGE_EMBEDDER": "hashing", "TRIAGE_BACKEND": "heuristic"}
    procs = [subprocess.Popen([sys.executable, "-m", "triage", "--format", "wazuh", str(POWERSHELL)],
                              cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(3)]
    outs = [p.communicate(timeout=120) for p in procs]
    assert [p.returncode for p in procs] == [0, 0, 0] and all(err == b"" for _, err in outs)
    records = _records(tmp_path / "logs" / "audit.jsonl")
    ids = [TriageSummary.model_validate_json(out).run_id for out, _ in outs]
    assert sorted(r["gen_ai.conversation.id"] for r in records if r["event.name"] == "triage.summary") == sorted(ids)


# --- Usage, configuration and input -------------------------------------------------

@pytest.mark.parametrize("argv", [
    ["--format", f"x{MARKER}", "alert.json"],
    [f"--bogus-{MARKER}", "--format", "wazuh", "alert.json"],
    [],
    ["--format", "wazuh"],
    ["--format", "wazuh", "a.json", "--audit-log", f"{MARKER}.jsonl", "--no-audit-log"],
    ["--form", "wazuh", "a.json"],
], ids=["bad_format", "unknown_option", "nothing", "no_alert", "both_audit_flags", "abbreviation"])
def test_argument_errors_are_fixed(argv, monkeypatch, tmp_path, counting):
    """An argument error echoes the argument, runs the model or writes something."""
    run = invoke(monkeypatch, *argv)
    assert run.code == cli.USAGE and run.stdout == b""
    assert_fixed(run.stderr, cli.E_USAGE)
    assert counting.calls == 0 and list(tmp_path.iterdir()) == []


def test_configuration_error_is_fixed(monkeypatch, tmp_path):
    """A bad backend setting is echoed, or the run goes ahead."""
    monkeypatch.setenv("TRIAGE_BACKEND", f"x{MARKER}")
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--no-audit-log")
    assert run.code == cli.USAGE and run.stdout == b""
    assert_fixed(run.stderr, cli.E_CONFIG, notice=True)
    assert list(tmp_path.iterdir()) == []


@posix_only
@pytest.mark.parametrize("kind", ["missing", "directory", "oversized_file", "oversized_stdin",
                                  "invalid_json", "wrong_format"])
def test_input_errors_are_fixed(kind, monkeypatch, tmp_path, counting):
    """Bad input is echoed, hangs, runs the model or leaves output."""
    stdin, fmt = b"", "wazuh"
    path = tmp_path / f"input-{MARKER}"
    expected = {"missing": cli.E_INPUT_READ + " (ENOENT)", "directory": cli.E_INPUT_TYPE,
                "oversized_file": cli.E_INPUT_SIZE, "oversized_stdin": cli.E_INPUT_SIZE,
                "invalid_json": cli.E_INPUT_INVALID.format(fmt="wazuh"),
                "wrong_format": cli.E_INPUT_INVALID.format(fmt="wazuh")}[kind]
    if kind == "directory":
        path.mkdir()
    elif kind == "oversized_file":
        path.write_bytes(b" " * (cli.MAX_RAW_ALERT_BYTES + 1))
    elif kind == "oversized_stdin":
        stdin, path = b" " * (cli.MAX_RAW_ALERT_BYTES + 1), "-"
    elif kind == "invalid_json":
        path.write_text('{"rule": "' + MARKER, encoding="utf-8")
    elif kind == "wrong_format":
        path.write_bytes(SIGMA.read_bytes())
    run = invoke(monkeypatch, "--format", fmt, str(path), "--out", "out", stdin=stdin)
    assert run.code == cli.INPUT and run.stdout == b""
    assert_fixed(run.stderr, expected)
    assert counting.calls == 0
    assert list((tmp_path / "out").iterdir()) == [] and not (tmp_path / "logs" / "audit.jsonl").exists()


@posix_only
def test_fifo_input_is_refused_without_hanging(tmp_path):
    """A FIFO without a writer hangs the run, or is read as an alert."""
    fifo = tmp_path / f"input-{MARKER}"
    os.mkfifo(fifo)
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT), "TRIAGE_EMBEDDER": "hashing", "TRIAGE_BACKEND": "heuristic"}
    # A subprocess with a timeout, so a regression fails the test instead of hanging the suite.
    proc = subprocess.run([sys.executable, "-m", "triage", "--format", "wazuh", str(fifo), "--no-audit-log"],
                          cwd=tmp_path, env=env, capture_output=True, timeout=60)
    assert proc.returncode == cli.INPUT and proc.stdout == b""
    assert_fixed(proc.stderr.decode("ascii"), cli.E_INPUT_TYPE, notice=True)


# --- Audit log -----------------------------------------------------------------------

@posix_only
@pytest.mark.parametrize("kind", ["group_writable_dir", "path_without_name", "incomplete_log"])
def test_audit_preflight_stops_before_the_model(kind, monkeypatch, tmp_path, counting):
    """An unusable audit log is found only after the model ran, or the log is changed."""
    logs = tmp_path / f"logs-{MARKER}"
    logs.mkdir(mode=0o700)
    target = logs / "audit.jsonl"
    expected = cli.E_AUDIT_UNSAFE
    if kind == "group_writable_dir":
        os.chmod(logs, 0o770)
    elif kind == "path_without_name":
        target = str(logs) + "/"
    else:
        target.write_bytes(b'{"partial')
        os.chmod(target, 0o600)
        expected = cli.E_AUDIT_INCOMPLETE
    before = sorted(p.name for p in logs.iterdir())
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--audit-log", str(target), "--out", "out")
    assert run.code == cli.AUDIT and run.stdout == b""
    assert_fixed(run.stderr, expected)
    assert counting.calls == 0 and sorted(p.name for p in logs.iterdir()) == before
    if kind == "incomplete_log":
        assert target.read_bytes() == b'{"partial'


@posix_only
def test_locked_audit_log_means_no_outputs(monkeypatch, tmp_path):
    """A run whose audit append cannot get the lock still prints or writes its outputs."""
    first = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL))
    assert first.code == cli.OK
    log = tmp_path / "logs" / "audit.jsonl"
    before = log.read_bytes()
    monkeypatch.setattr(audit, "LOCK_TIMEOUT_S", 0.2)
    holder = os.open(log, os.O_RDONLY)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out")
    finally:
        os.close(holder)
    assert run.code == cli.AUDIT and run.stdout == b""
    assert_fixed(run.stderr, cli.E_AUDIT_LOCKED)
    assert log.read_bytes() == before and list((tmp_path / "out").iterdir()) == []


@posix_only
@pytest.mark.parametrize("error,message", [
    (OSError(28, "No space left on device"), cli.E_AUDIT_WRITE + " (ENOSPC)"),
    (audit.AuditRollbackFailed("x"), cli.E_AUDIT_PARTIAL),
    (audit.AuditNotDurable("x"), cli.E_AUDIT_DURABLE),
    (PermissionError(13, f"Permission denied: {MARKER}"), cli.E_AUDIT_UNSAFE + " (EACCES)"),
    (ValueError(f"bad {MARKER}"), cli.E_AUDIT_WRITE),
], ids=["write_error", "rollback_failed", "not_durable", "permission", "value"])
def test_audit_append_failure_means_no_outputs(error, message, monkeypatch, tmp_path):
    """A failed audit append is echoed, or outputs are still written or printed."""
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(cli, "write_audit_log", fail)
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out")
    assert run.code == cli.AUDIT and run.stdout == b""
    assert_fixed(run.stderr, message)
    assert list((tmp_path / "out").iterdir()) == []


@pytest.mark.parametrize("extra,code,message", [
    ([], cli.AUDIT, cli.E_AUDIT_PLATFORM),
    (["--no-audit-log", "--out", "out"], cli.OUTPUT, cli.E_OUT_PLATFORM),
    (["--no-audit-log"], cli.OK, None),
], ids=["audit", "out", "stdout_only"])
def test_unsupported_platform_is_stdout_only(extra, code, message, monkeypatch, tmp_path, counting):
    """Without POSIX file operations, the CLI writes files anyway, or refuses a standard-output-only run."""
    monkeypatch.setattr(files, "supported", lambda: False)
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), *extra)
    assert run.code == code
    if message is None:
        assert run.stderr == f"{cli.PROG}: {cli.NOTICE_NO_AUDIT}\n"
        TriageSummary.model_validate_json(run.stdout)
    else:
        assert run.stdout == b"" and counting.calls == 0
        assert_fixed(run.stderr, message, notice="--no-audit-log" in extra)
    assert list(tmp_path.iterdir()) == []


# --- Outputs -------------------------------------------------------------------------

@posix_only
def test_unsafe_output_directory_stops_before_the_model(monkeypatch, tmp_path, counting):
    """An unusable --out directory is found only after the model ran."""
    out = tmp_path / f"out-{MARKER}"
    out.mkdir(mode=0o700)
    os.chmod(out, 0o770)
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", str(out))
    assert run.code == cli.OUTPUT and run.stdout == b""
    assert_fixed(run.stderr, cli.E_OUT_UNSAFE)
    assert counting.calls == 0 and list(out.iterdir()) == []
    assert not (tmp_path / "logs" / "audit.jsonl").exists()


@pytest.fixture
def fixed_run_id(monkeypatch):
    monkeypatch.setattr(cli, "_new_run_id", lambda: RUN_ID)
    return RUN_ID


@posix_only
def test_collision_keeps_the_existing_file(monkeypatch, tmp_path, fixed_run_id):
    """A name collision modifies or removes the existing file, or leaves this run's other file behind."""
    out = tmp_path / "out"
    out.mkdir(mode=0o700)
    (out / f"{RUN_ID}.md").write_bytes(b"keep")
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out")
    assert run.code == cli.OUTPUT and run.stdout == b""
    assert_fixed(run.stderr, cli.E_OUT_EXISTS)
    assert sorted(p.name for p in out.iterdir()) == [f"{RUN_ID}.md"] and (out / f"{RUN_ID}.md").read_bytes() == b"keep"
    # Audit first: the run is recorded even though its outputs were not written.
    records = _records(tmp_path / "logs" / "audit.jsonl")
    assert records[-1]["event.name"] == "triage.summary" and records[-1]["gen_ai.conversation.id"] == RUN_ID


@posix_only
@pytest.mark.parametrize("unlink_fails", [False, True], ids=["removed", "removal_failed"])
def test_second_file_failure_removes_only_this_runs_files(unlink_fails, monkeypatch, tmp_path, fixed_run_id):
    """A failed second output leaves the first, or touches a file this run did not create."""
    out = tmp_path / "out"
    out.mkdir(mode=0o700)
    (out / "other.txt").write_bytes(b"unrelated")
    real_write_all, real_unlink = files.write_all, os.unlink
    calls = []

    def fail_second(fd, data, *, what):
        if what == "output":   # the audit append uses write_all too
            calls.append(what)
            if len(calls) == 2:
                raise OSError(28, "No space left on device")
        return real_write_all(fd, data, what=what)

    def failing_unlink(name, *args, **kwargs):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(files, "write_all", fail_second)
    if unlink_fails:
        monkeypatch.setattr(os, "unlink", failing_unlink)
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out")
    monkeypatch.setattr(os, "unlink", real_unlink)
    assert run.code == cli.OUTPUT and run.stdout == b""
    assert_fixed(run.stderr, cli.E_OUT_LEFT if unlink_fails else cli.E_OUT_REMOVED)
    left = sorted(p.name for p in out.iterdir())
    assert left == (sorted(["other.txt", f"{RUN_ID}.json", f"{RUN_ID}.md"]) if unlink_fails else ["other.txt"])
    assert (out / "other.txt").read_bytes() == b"unrelated" and len(calls) == 2
    assert _records(tmp_path / "logs" / "audit.jsonl")[-1]["gen_ai.conversation.id"] == RUN_ID


@posix_only
def test_outputs_are_synced_with_their_directory(monkeypatch, tmp_path):
    """An output file, its directory or the directory's parent is not synced before success is reported."""
    real = os.fsync
    synced = []

    def recording(fd):
        synced.append(os.stat(fd).st_ino)
        return real(fd)

    monkeypatch.setattr(os, "fsync", recording)
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out", "--no-audit-log")
    summary = _check_success(run, tmp_path, out=tmp_path / "out")
    out = tmp_path / "out"
    expected = [(out / f"{summary.run_id}.json").stat().st_ino, (out / f"{summary.run_id}.md").stat().st_ino,
                out.stat().st_ino, tmp_path.stat().st_ino]
    assert synced == expected


@posix_only
def test_directory_made_unsafe_after_preflight_is_refused(monkeypatch, tmp_path):
    """Passing preflight is trusted at write time, so a directory changed during the run is used."""
    out = tmp_path / "out"
    real = cli.run_agent

    def run_then_loosen(*args, **kwargs):
        result = real(*args, **kwargs)
        os.chmod(out, 0o770)   # after preflight, before the outputs are written
        return result

    monkeypatch.setattr(cli, "run_agent", run_then_loosen)
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out")
    assert run.code == cli.OUTPUT and run.stdout == b""
    assert_fixed(run.stderr, cli.E_OUT_UNSAFE)
    assert list(out.iterdir()) == []


@posix_only
def test_broken_standard_output_keeps_the_written_pair(monkeypatch, tmp_path):
    """A broken pipe on standard output is ignored, or removes the complete output pair."""
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out", stdout=BrokenPipe())
    assert run.code == cli.OUTPUT
    assert_fixed(run.stderr, cli.E_STDOUT)
    assert len(list((tmp_path / "out").iterdir())) == 2


@posix_only
def test_render_failure_after_the_audit_append(monkeypatch, tmp_path):
    """A summary that cannot be rendered goes unrecorded, or a partial output is written."""
    def fail(summary):
        raise ValueError(f"cannot {MARKER}")

    monkeypatch.setattr(cli, "render_markdown", fail)
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out")
    assert run.code == cli.OUTPUT and run.stdout == b""
    assert_fixed(run.stderr, cli.E_OUT_RENDER)
    assert list((tmp_path / "out").iterdir()) == []
    assert _records(tmp_path / "logs" / "audit.jsonl")[-1]["event.name"] == "triage.summary"


@posix_only
@pytest.mark.parametrize("unlink_fails", [False, True], ids=["removed", "removal_failed"])
def test_interrupt_during_second_output_removes_this_runs_files(unlink_fails, monkeypatch, tmp_path, fixed_run_id):
    """An interrupt while writing the second output leaves this run's files, or touches another file."""
    out = tmp_path / "out"
    out.mkdir(mode=0o700)
    (out / "other.txt").write_bytes(b"unrelated")
    real_write_all = files.write_all
    calls = []

    def interrupt_second(fd, data, *, what):
        if what == "output":
            calls.append(what)
            if len(calls) == 2:
                raise KeyboardInterrupt
        return real_write_all(fd, data, what=what)

    def failing_unlink(name, *args, **kwargs):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(files, "write_all", interrupt_second)
    with monkeypatch.context() as m:
        if unlink_fails:
            m.setattr(os, "unlink", failing_unlink)
        run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out")
    assert run.code == cli.INTERRUPTED and run.stdout == b""
    assert_fixed(run.stderr, cli.E_INTERRUPTED_LEFT if unlink_fails else cli.E_INTERRUPTED)
    left = sorted(p.name for p in out.iterdir())
    assert left == (sorted(["other.txt", f"{RUN_ID}.json", f"{RUN_ID}.md"]) if unlink_fails else ["other.txt"])
    assert (out / "other.txt").read_bytes() == b"unrelated" and len(calls) == 2
    # The audit append came first and stays.
    assert _records(tmp_path / "logs" / "audit.jsonl")[-1]["gen_ai.conversation.id"] == RUN_ID


@posix_only
def test_other_exceptions_also_clean_up(tmp_path):
    """An exception other than OSError or KeyboardInterrupt leaves this call's files, or is swallowed."""
    out = tmp_path / "out"
    out.mkdir(mode=0o700)
    dir_fd = files.open_private_dir(str(out), what="output", create=False)
    real = files.write_all
    calls = []

    def fail_second(fd, data, *, what):
        calls.append(1)
        if len(calls) == 2:
            raise MemoryError
        return real(fd, data, what=what)

    try:
        files.write_all = fail_second
        with pytest.raises(MemoryError):
            files.write_new_files(dir_fd, str(out), [("a.json", b"{}\n"), ("a.md", b"# a\n")], what="output")
    finally:
        files.write_all = real
        os.close(dir_fd)
    assert list(out.iterdir()) == []


# --- Without the POSIX open flags (R7) ---------------------------------------------------

@pytest.fixture
def without_posix_flags(monkeypatch):
    """Simulates Windows for the input path: no O_NONBLOCK or O_CLOEXEC, and no safe dir_fd writers."""
    monkeypatch.delattr(os, "O_NONBLOCK", raising=False)
    monkeypatch.delattr(os, "O_CLOEXEC", raising=False)
    monkeypatch.setattr(files, "supported", lambda: False)


def test_file_input_works_without_posix_flags(without_posix_flags, monkeypatch, tmp_path):
    """A file path fails to open where O_NONBLOCK and O_CLOEXEC do not exist."""
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--no-audit-log")
    assert run.code == cli.OK and run.stderr == f"{cli.PROG}: {cli.NOTICE_NO_AUDIT}\n"
    TriageSummary.model_validate_json(run.stdout)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("kind", ["device", "oversized"])
def test_input_checks_hold_without_posix_flags(kind, without_posix_flags, monkeypatch, tmp_path, counting):
    """Without the POSIX flags, a device or an oversized file is read anyway."""
    if kind == "device":
        path, expected = os.devnull, cli.E_INPUT_TYPE
    else:
        path, expected = tmp_path / "big.json", cli.E_INPUT_SIZE
        path.write_bytes(b" " * (cli.MAX_RAW_ALERT_BYTES + 1))
    run = invoke(monkeypatch, "--format", "wazuh", str(path), "--no-audit-log")
    assert run.code == cli.INPUT and run.stdout == b""
    assert_fixed(run.stderr, expected, notice=True)
    assert counting.calls == 0


# --- Unexpected errors -----------------------------------------------------------------

@posix_only
@pytest.mark.parametrize("error,code,message", [
    (RuntimeError(f"boom {MARKER}"), cli.INTERNAL, f"{cli.E_INTERNAL} (RuntimeError)"),
    (KeyboardInterrupt(), cli.INTERRUPTED, cli.E_INTERRUPTED),
], ids=["internal", "interrupt"])
def test_unexpected_errors_write_nothing(error, code, message, monkeypatch, tmp_path):
    """An unexpected error or an interrupt echoes its text, or leaves a record or output behind."""
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(cli, "build_summary", fail)
    run = invoke(monkeypatch, "--format", "wazuh", str(POWERSHELL), "--out", "out")
    assert run.code == code and run.stdout == b""
    assert_fixed(run.stderr, message)
    assert list((tmp_path / "out").iterdir()) == [] and not (tmp_path / "logs" / "audit.jsonl").exists()


def test_every_message_is_fixed_ascii_text():
    """A CLI message carries a placeholder other than the format, or non-ASCII text."""
    for message in MESSAGES:
        assert message.isascii() and "{" not in message
