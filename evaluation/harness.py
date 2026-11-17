"""The pass runner: execute the frozen order, one fresh process per run, and keep the evidence.

Started as

    python -s -B -P <clone>/evaluation/harness.py run --clone PATH --store PATH --pass PASS_ID
        --merge-sha HEX40 --merge-tree HEX40

Before every run it checks the code, the interpreter and its packages, the
embedder and, for model passes, the model server and its service
configuration against the manifest. It then records the run in the ledger
before starting it, starts the child with an environment built from nothing,
and moves the child's output into the pass's original/ directory without
altering a byte. The order is executed exactly: no skip, no reorder, no
extra run, no retry of a started run, no resume. The first cause that makes
the pass incomplete, void or defective ends the loop.
"""

from __future__ import annotations

if __name__ == "__main__":
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.realpath(__file__))))

import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from triage import files as tfiles
from triage.schemas import RUN_ID_PATTERN

from evaluation import classify as classify_mod
from evaluation import identity, manifest as manifest_mod, probe, records
from evaluation.common import (
    PASS_ID_RE, RUNBOOK_NAME_RE, EvaluationError, canonical_dumps, read_regular, sha256_hex, strict_loads,
)
from evaluation.endpoint import EndpointRefused, canonical_url, parse_endpoint
from evaluation.ledger import LedgerWriter, write_in

RUN_DEADLINE_S = 900 + 120
OUT_CAP = 1 << 20
ERR_CAP = 64 << 10
CHECK_ATTEMPTS = 3
HEX40 = re.compile(r"^[0-9a-f]{40}$")
_RUN_ID = re.compile(RUN_ID_PATTERN)


class HarnessRefused(EvaluationError):
    """The pass cannot start: nothing has been created."""


@dataclass
class Hooks:
    """Internal seams for the tests. The command line never builds one."""
    freeze: object = None
    resolved_root: object = identity.default_resolved_root
    systemctl: str = identity.SYSTEMCTL
    spawn: object = None
    deadline_s: float = RUN_DEADLINE_S
    clock: object = time.monotonic
    sleep: object = time.sleep
    retry_wait_s: float = 60.0
    writer: object = None


def _now() -> str:
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


# --- The store ---------------------------------------------------------------------

def store_problems(store: str, clone: str) -> list[str]:
    try:
        st = os.lstat(store)
    except OSError:
        return ["store: not found"]
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return ["store: must be a real directory"]
    if st.st_uid != os.geteuid():
        return ["store: must be owned by the user running the harness"]
    if st.st_mode & 0o077:
        return ["store: must not be group- or other-accessible"]
    real, clone_real = os.path.realpath(store), os.path.realpath(clone)
    if real == clone_real or real.startswith(clone_real + os.sep):
        return ["store: must be outside the clone"]
    return []


def pass_id_problems(store: str, pass_id: str) -> list[str]:
    """Pass IDs are assigned in sequence, and an existing pass directory is never reused."""
    if PASS_ID_RE.fullmatch(pass_id) is None:
        return ["pass: invalid pass ID"]
    sequence, number = pass_id.split("-")
    highest = 0
    for name in os.listdir(store):
        if PASS_ID_RE.fullmatch(name) and name.startswith(sequence + "-"):
            highest = max(highest, int(name.split("-")[1]))
    if os.path.lexists(os.path.join(store, pass_id)) or int(number) != highest + 1:
        return ["pass: pass ID is not the next in its sequence"]
    return []


# --- The child -------------------------------------------------------------------------

def child_env(*, scratch: str, backend: str, execution, clone: str, endpoint_url: str) -> dict[str, str]:
    env = {"PATH": "/usr/bin:/bin", "HOME": scratch, "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONHASHSEED": "0",
           "TRIAGE_BACKEND": backend, "TRIAGE_EMBEDDER": execution.embedder}
    if execution.embedder == "minilm":
        env["TRIAGE_EMBEDDING_MODEL_DIR"] = os.path.join(clone, *identity.MODEL_SUBDIR)
    env["OLLAMA_HOST"] = endpoint_url
    if backend == "ollama":
        env["OLLAMA_MODEL"] = execution.ollama.model
        env["OLLAMA_THINK"] = "false"
    return env


def child_argv(clone: str, scratch: str, case) -> list[str]:
    return [sys.executable, "-s", "-B", "-P", os.path.join(clone, "evaluation", "run_one.py"), "--clone", clone,
            "--hits-out", os.path.join(scratch, "hits.json"), "--", "--format", case.format,
            os.path.join(clone, case.path), "--audit-log", os.path.join(scratch, "audit.jsonl")]


def default_spawn(argv: list[str], env: dict, scratch: str) -> subprocess.Popen:
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, cwd=scratch, close_fds=True, start_new_session=True, shell=False)


def read_hits(path: str) -> dict | None:
    """The hits record if it exists and has exactly the expected shape, else None."""
    try:
        obj = strict_loads(read_regular(path))
    except EvaluationError:
        return None
    if not isinstance(obj, dict) or tuple(obj) != ("calls", "run_id", "runbook_hits"):
        return None
    calls, run_id, hits = obj["calls"], obj["run_id"], obj["runbook_hits"]
    if type(calls) is not int or calls not in (0, 1):
        return None
    if run_id is not None and (not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None):
        return None
    if hits is not None and (not isinstance(hits, list)
                             or not all(isinstance(h, str) and RUNBOOK_NAME_RE.fullmatch(h) for h in hits)):
        return None
    if (calls == 0) != (run_id is None) or (calls == 0) != (hits is None):
        return None
    return obj


def last_cli_message(stderr: bytes) -> str | None:
    """The CLI's last error line if it is one of the CLI's own fixed messages, else null."""
    try:
        text = stderr.decode("utf-8")
    except UnicodeDecodeError:
        return None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if not lines:
        return None
    return lines[-1] if lines[-1] in records.KNOWN_CLI_MESSAGES else None


# --- Checks -------------------------------------------------------------------------

class _Pass:
    """State of one pass while it runs."""

    def __init__(self, clone, store, pass_id, merge_sha, merge_tree, hooks):
        self.clone, self.store, self.pass_id = clone, store, pass_id
        self.merge_sha, self.merge_tree = merge_sha, merge_tree
        self.hooks = hooks
        self.sequence = pass_id.split("-")[0]
        self.backend = "heuristic" if self.sequence == "baseline" else "ollama"
        self.model_pass = self.backend == "ollama"
        self.server_restarts = 0 if self.model_pass else None
        self.reference = None   # (main_pid, start_monotonic) of the model server
        self.interrupted = False
        self.runs_started = 0

    # Each returns a list of problems; empty means passed.
    def code_check(self) -> list[str]:
        return identity.code_problems(self.clone, [f.model_dump() for f in self.manifest.files],
                                      self.merge_sha, self.merge_tree, resolved_root=self.hooks.resolved_root)

    def python_check(self) -> list[str]:
        try:
            observed = identity.python_identity(self.clone, freeze=self.hooks.freeze)
        except EvaluationError as error:
            return [str(error)]
        problems = identity.freeze_problems(observed["freeze"])
        if problems:
            return problems
        if observed != self.manifest.execution.python.model_dump():
            return ["python: interpreter or package list differs from the manifest"]
        return []

    def embedder_check(self) -> tuple[list[str], str]:
        try:
            return [], identity.embedder_check(self.manifest.execution.embedder, self.clone)
        except EvaluationError as error:
            return [str(error)], "ok"

    def ollama_check(self) -> list[str]:
        try:
            observed = probe.ollama_identity(self.endpoint, self.manifest.execution.ollama.model)
        except EvaluationError as error:
            return [str(error)]
        if observed != self.manifest.execution.ollama.model_dump():
            return ["ollama: server or model identity differs from the manifest"]
        return []

    def server_check(self) -> list[str]:
        try:
            state = identity.read_unit(self.manifest.execution.server.unit, self.hooks.systemctl)
            manager = identity.manager_environment(self.hooks.systemctl)
        except EvaluationError as error:
            return [str(error)]
        problems = identity.server_problems(state, manager, self.manifest.execution.server.model_dump())
        if not problems:
            observed = (state.main_pid, state.start_monotonic)
            if self.reference is not None and observed != self.reference:
                self.server_restarts += 1
            self.reference = observed
        return problems

    def group_check(self) -> tuple[list[str], dict]:
        results = {}
        problems = self.python_check()
        results["python"] = "ok"
        emb_problems, results["embedder"] = self.embedder_check()
        problems += emb_problems
        if self.model_pass:
            problems += self.ollama_check()
            problems += self.server_check()
            results["ollama"] = results["server_settings"] = "ok"
        else:
            results["ollama"] = results["server_settings"] = "not_applicable"
        try:
            identity.disk_check(self.store)
        except EvaluationError as error:
            problems.append(str(error))
        results["disk"] = "ok"
        return problems, results


def _fchmod_in(dir_fd: int, name: str, mode: int) -> None:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _move_audit(scratch_fd: int, orig_fd: int, name: str) -> bool:
    """Move the child's audit file into original/ under its fixed name; bytes are never touched."""
    try:
        st = os.stat("audit.jsonl", dir_fd=scratch_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
        raise EvaluationError("audit output is not a regular file")
    # link then unlink: unlike rename, link never replaces an existing file.
    os.link("audit.jsonl", name, src_dir_fd=scratch_fd, dst_dir_fd=orig_fd, follow_symlinks=False)
    os.unlink("audit.jsonl", dir_fd=scratch_fd)
    _fchmod_in(orig_fd, name, 0o400)
    return True


def hash_list_bytes(dir_fd: int) -> bytes:
    lines = []
    for name in sorted(os.listdir(dir_fd)):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
        try:
            chunks = []
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(fd)
        lines.append(f"{sha256_hex(b''.join(chunks))}  {name}\n")
    return "".join(lines).encode("ascii")


def execute_pass(clone: str, store: str, pass_id: str, merge_sha: str, merge_tree: str, *,
                 hooks: Hooks | None = None) -> str:
    """Run one pass. Returns the pass class. HarnessRefused means nothing was created."""
    hooks = hooks or Hooks()
    clone = os.path.realpath(clone)
    if HEX40.fullmatch(merge_sha or "") is None or HEX40.fullmatch(merge_tree or "") is None:
        raise HarnessRefused("pass: merge commit and tree must be 40 hex digits")
    try:
        endpoint = parse_endpoint(os.environ.get("OLLAMA_HOST"))
    except EndpointRefused:
        raise HarnessRefused("model endpoint must be a loopback literal and port") from None
    problems = store_problems(store, clone) or pass_id_problems(store, pass_id)
    if problems:
        raise HarnessRefused(problems[0])
    try:
        registry = records.load_registry(os.path.join(clone, "eval", "cases.json"))
        order = records.load_order(os.path.join(clone, "eval", "order.json"), registry)
        manifest_bytes = read_regular(os.path.join(clone, "eval", "manifest.json"))
        manifest = manifest_mod.load_manifest(manifest_bytes)
    except EvaluationError:
        raise HarnessRefused("pass: frozen inputs cannot be loaded") from None

    p = _Pass(clone, store, pass_id, merge_sha, merge_tree, hooks)
    p.manifest, p.endpoint = manifest, endpoint
    endpoint_url = canonical_url(endpoint)
    cases = registry.by_id()
    registered_paths = {c.path for c in registry.cases}

    pass_dir = os.path.join(store, pass_id)
    orig_dir = os.path.join(pass_dir, "original")
    pass_fd = tfiles.open_private_dir(pass_dir, what="pass", create=True)
    orig_fd = tfiles.open_private_dir(orig_dir, what="original", create=True)
    ledger = LedgerWriter(orig_fd, orig_dir)
    started_at = _now()

    def on_signal(signum, frame):
        p.interrupted = True

    previous = {s: signal.signal(s, on_signal) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        if p.model_pass:
            try:
                state = identity.read_unit(manifest.execution.server.unit, hooks.systemctl)
                p.reference = (state.main_pid, state.start_monotonic)
            except EvaluationError:
                p.reference = None
        ledger.append("pass_start", None, None, None)
        pass_class = _run_loop(p, order.sequence(p.sequence), cases, registered_paths, ledger, orig_fd, orig_dir,
                               endpoint_url)
        pass_class = _pass_end(p, pass_class, ledger, pass_fd, pass_dir, orig_fd, orig_dir, started_at,
                               manifest_bytes)
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)
        ledger.abandon()
        os.close(orig_fd)
        os.close(pass_fd)
    return pass_class


def _run_loop(p: _Pass, entries, cases, registered_paths, ledger, orig_fd, orig_dir, endpoint_url) -> str:
    first_check = True
    for entry in entries:
        if p.interrupted:
            return "incomplete"
        code = p.code_check()
        if code:
            ledger.append("check_failed", entry.position, entry.case_id, None)
            return "incomplete" if first_check else "void"
        attempts = 0
        while True:
            attempts += 1
            problems, results = p.group_check()
            if not problems or attempts >= CHECK_ATTEMPTS:
                break
            p.hooks.sleep(p.hooks.retry_wait_s)
        if problems:
            ledger.append("check_failed", entry.position, entry.case_id, None)
            return "incomplete"
        first_check = False
        checks = {"attempts": attempts, "code": "ok", **results}
        checks = {key: checks[key] for key in records.CHECK_KEYS}
        cause = _one_run(p, entry, cases[entry.case_id], registered_paths, checks, ledger, orig_fd, orig_dir,
                         endpoint_url)
        if cause is not None:
            return cause
    return "complete"


def _one_run(p: _Pass, entry, case, registered_paths, checks, ledger, orig_fd, orig_dir, endpoint_url):
    stem = f"run-{entry.position:04d}"
    ledger.append("run_start", entry.position, entry.case_id, None)
    p.runs_started += 1
    scratch = os.path.join(p.store, p.pass_id, f"scratch-{entry.position:04d}")
    scratch_fd = tfiles.open_private_dir(scratch, what="scratch", create=True)
    started_at = _now()
    collected = None
    runner_error = False
    try:
        argv = child_argv(p.clone, scratch, case)
        if not identity.child_argv_ok(argv, p.clone, lambda rel: rel in registered_paths):
            raise EvaluationError("child argument vector refused")
        env = child_env(scratch=scratch, backend=p.backend, execution=p.manifest.execution, clone=p.clone,
                        endpoint_url=endpoint_url)
        proc = (p.hooks.spawn or default_spawn)(argv, env, scratch)
        collected = identity.collect(proc, deadline_s=p.hooks.deadline_s, out_cap=OUT_CAP, err_cap=ERR_CAP,
                                     interrupted=lambda: p.interrupted, clock=p.hooks.clock, sleep=p.hooks.sleep)
        runner_error = collected.over_cap
    except (EvaluationError, OSError):
        runner_error = True
    ended_at = _now()
    exit_status = collected.exit_status if collected else None
    sig = collected.signal if collected else None
    exit_ending = (collected is not None and not collected.deadline and not collected.interrupted
                   and sig is None)
    hits = read_hits(os.path.join(scratch, "hits.json")) if exit_ending and not runner_error else None
    observed = classify_mod.Observed(
        exit_status=exit_status, signal=sig, deadline=bool(collected and collected.deadline),
        interrupted=bool(collected and collected.interrupted), stdout=collected.stdout if collected else b"",
        hits=hits, runner_error=runner_error)
    result = classify_mod.classify(observed)

    has_audit = has_summary = False
    try:
        has_audit = _move_audit(scratch_fd, orig_fd, f"{stem}.audit.jsonl")
    except (EvaluationError, OSError):
        result = classify_mod.Result("no_output", "signal" if sig is not None else "exit", "defective")
    if result.run_class == "outcome":
        try:
            write_in(orig_fd, orig_dir, [(f"{stem}.summary.json", observed.stdout)], what="summary")
            _fchmod_in(orig_fd, f"{stem}.summary.json", 0o400)
            has_summary = True
        except (EvaluationError, OSError):
            result = classify_mod.Result("no_output", "exit", "defective")

    h = {
        "version": 1, "pass_id": p.pass_id, "position": entry.position, "case_id": entry.case_id,
        "role": entry.role, "repeat": entry.repeat, "backend": p.backend, "started_at": started_at,
        "ended_at": ended_at, "exit_status": exit_status, "signal": sig, "class": result.run_class,
        "reason": result.reason, "run_id": hits["run_id"] if hits else None,
        "runbook_hits": hits["runbook_hits"] if hits else None, "checks": checks,
        "server_restarts": p.server_restarts,
        "cli_message": last_cli_message(collected.stderr) if collected else None,
        "stderr_nonempty": bool(collected and collected.stderr),
        "files": {"summary": has_summary, "audit": has_audit},
    }
    data = canonical_dumps(h)
    try:
        records.load_harness(data)   # the 1a reader must accept it before it is written
    except EvaluationError:
        # A record the reader refuses is a runner defect: keep only fixed values.
        result = classify_mod.Result("no_output", "signal" if sig is not None else "exit", "defective")
        h.update({"class": "no_output", "reason": result.reason, "run_id": None, "runbook_hits": None,
                  "cli_message": None})
        data = canonical_dumps(h)
        records.load_harness(data)
    write_in(orig_fd, orig_dir, [(f"{stem}.harness.json", data)], what="harness")
    _fchmod_in(orig_fd, f"{stem}.harness.json", 0o400)
    ledger.append("run_end", entry.position, entry.case_id, result.run_class)
    os.close(scratch_fd)
    shutil.rmtree(scratch)
    return result.pass_cause


def _end_check(p: _Pass) -> str:
    if p.code_check():
        return "code"
    if p.python_check():
        return "python"
    if p.embedder_check()[0]:
        return "embedder"
    if p.model_pass:
        if p.ollama_check():
            return "ollama"
        if p.server_check():
            return "server_settings"
    return "ok"


def _pass_end(p: _Pass, pass_class, ledger, pass_fd, pass_dir, orig_fd, orig_dir, started_at, manifest_bytes):
    end_check = _end_check(p)
    # A pass whose first check failed never started, so it stays incomplete;
    # the re-check voids only a pass in which a run started.
    if end_check != "ok" and p.runs_started:
        pass_class = classify_mod.worst(pass_class, "void")
    head, head_tree = identity.head_and_tree(p.clone)
    execution = p.manifest.execution
    env = {"version": 1, "pass_id": p.pass_id, "backend": p.backend, "merge_sha": p.merge_sha,
           "merge_tree": p.merge_tree, "head": head, "head_tree": head_tree,
           "manifest_sha256": sha256_hex(manifest_bytes), "python": execution.python.model_dump(),
           "embedder": execution.embedder,
           "ollama": execution.ollama.model_dump() if p.model_pass else None,
           "server": execution.server.model_dump() if p.model_pass else None,
           "server_restarts": p.server_restarts, "started_at": started_at, "ended_at": _now(),
           "end_check": end_check}
    writer = p.hooks.writer or (lambda name: None)
    writer("environment.json")
    write_in(orig_fd, orig_dir, [("environment.json", canonical_dumps(env))], what="environment")
    _fchmod_in(orig_fd, "environment.json", 0o400)
    writer("pass_end")
    ledger.append("pass_end", None, None, pass_class)
    ledger.close_and_verify()
    _fchmod_in(orig_fd, "ledger.jsonl", 0o400)
    writer("files.original.sha256")
    write_in(pass_fd, pass_dir, [("files.original.sha256", hash_list_bytes(orig_fd))], what="hash list")
    _fchmod_in(pass_fd, "files.original.sha256", 0o400)
    os.fchmod(orig_fd, 0o500)
    for name in os.listdir(pass_fd):
        if name.startswith("scratch-"):
            shutil.rmtree(os.path.join(pass_dir, name))
    return pass_class


def _body(argv) -> int:
    parser = identity.Parser(prog="evaluation/harness.py", allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=identity.Parser)
    run = sub.add_parser("run", allow_abbrev=False)
    for name in ("--clone", "--store", "--pass", "--merge-sha", "--merge-tree"):
        run.add_argument(name, required=True)
    args = parser.parse_args(argv)
    if not identity.clone_ok(args.clone, __file__):
        raise identity.UsageRefused("--clone must be the clone this tool runs from")
    pass_class = execute_pass(args.clone, args.store, args.__dict__["pass"], args.merge_sha, args.merge_tree)
    print(f"harness: pass {args.__dict__['pass']} {pass_class}")
    return 0 if pass_class == "complete" else 3


def main(argv=None) -> int:
    return identity.run_cli("harness", _body, sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())
