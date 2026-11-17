"""The checks that run before every evaluation run, and the one way to start a helper process.

A run is only evidence of the frozen system if the code, the interpreter,
its installed packages, the embedding model and (for model passes) the
model server are the ones recorded in the manifest. These functions observe
each of them and report every difference as a fixed message. They never
repair anything and never echo an observed value: a value can come from the
environment of the machine, and an error path must not publish it.

Helper processes are limited to a fixed allow-list of argument vectors and
run with an environment built from nothing, so a variable such as
GIT_DIR, PIP_INDEX_URL or GITLEAKS_CONFIG in the operator's shell cannot
change what is observed, and no helper can fetch, install or contact a
remote host.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass

from evaluation.common import EvaluationError, read_regular, sha256_hex
from evaluation.endpoint import server_host_ok

SYSTEMCTL = "/usr/bin/systemctl"
UNIT_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}\.service$")
GIT_PREFIX = ("git", "-c", "core.fsmonitor=false", "-C")
GIT_TAILS = (
    ("ls-files", "-z", "-s"),
    ("rev-parse", "HEAD"),
    ("rev-parse", "HEAD^{tree}"),
    ("status", "--porcelain=v1", "-z", "--ignored", "--untracked-files=all"),
)
PIP_TAIL = ("-I", "-m", "pip", "freeze", "--all", "--isolated", "--disable-pip-version-check", "--no-input")
SHOW_PROPERTIES = ("ActiveState", "MainPID", "ExecMainStartTimestampMonotonic", "Environment",
                   "EnvironmentFiles", "ExecStart")
SHOW_TAIL = ("--no-pager", "--property=" + ",".join(SHOW_PROPERTIES))
# The two ignored directories a clean evaluation clone may hold: the
# embedding model and the editable-install metadata. Nothing else.
IGNORED_ALLOWED = ("models/all-MiniLM-L6-v2/", "alert_triage_agent.egg-info/")
EXCLUDED = ("eval/manifest.json", "provenance.json")
MODEL_SUBDIR = ("models", "all-MiniLM-L6-v2")
MIN_FREE_BYTES = 512 * 2 ** 20
FREEZE_TIMEOUT_S = 60.0
CAP_BYTES = 8 << 20


class CheckRefused(EvaluationError):
    """A check failed or could not be carried out."""


# --- Command-line plumbing shared by the evaluation tools ---------------------------

class UsageRefused(EvaluationError):
    """Bad arguments. argparse's own messages can quote an argument, so they are never shown."""


class Parser(argparse.ArgumentParser):
    def error(self, message):  # noqa: D401 - argparse hook
        raise UsageRefused("invalid arguments")


def clone_ok(clone_arg: str, script_file: str) -> bool:
    """--clone must be the real path of the clone this script was started from."""
    root = os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(script_file))))
    return clone_arg == root


def run_cli(prog: str, body, argv) -> int:
    """Run a tool's body and map every failure to a fixed message and exit code.

    0 success, 2 refused, 3 a pass or publication refusal (the body returns
    it), 1 internal error. Exception messages are fixed text by convention;
    an unexpected exception shows only its class name.
    """
    try:
        if not runner_flags_ok():
            raise UsageRefused("must be started with python -s -B -P")
        return body(argv)
    except EvaluationError as error:
        print(f"{prog}: error: {error}", file=sys.stderr)
        return 2
    except Exception as error:   # never the message: it can hold observed text
        print(f"{prog}: error: internal error ({type(error).__name__})", file=sys.stderr)
        return 1


# --- The allow-list -----------------------------------------------------------------

def _is_real_abs(path: object) -> bool:
    return (isinstance(path, str) and os.path.isabs(path) and "\0" not in path
            and os.path.realpath(path) == path)


def _gitleaks_dir_ok(argv: list[str], binary: str) -> bool:
    if len(argv) != 16 or argv[0] != binary or argv[1] != "dir":
        return False
    fixed = {3: "--config", 5: "--redact", 6: "--no-banner", 7: "--ignore-gitleaks-allow", 8: "--exit-code",
             9: "1", 10: "--gitleaks-ignore-path", 12: "--report-format", 13: "json", 14: "--report-path"}
    if any(argv[i] != value for i, value in fixed.items()):
        return False
    return all(_is_real_abs(argv[i]) for i in (2, 4, 11, 15))


def argv_ok(argv: object, *, systemctl: str = SYSTEMCTL, gitleaks: str | None = None) -> bool:
    """True only for the argument vectors in the fixed table."""
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        return False
    if tuple(argv[:4]) == GIT_PREFIX and len(argv) >= 6:
        return _is_real_abs(argv[4]) and tuple(argv[5:]) in GIT_TAILS
    if argv[0] == sys.executable:
        return tuple(argv[1:]) == PIP_TAIL
    if argv[0] == systemctl and _is_real_abs(systemctl):
        if argv[1:] == ["show-environment"]:
            return True
        return (len(argv) == 5 and argv[1] == "show" and UNIT_RE.fullmatch(argv[2]) is not None
                and tuple(argv[3:]) == SHOW_TAIL)
    if gitleaks is not None and _is_real_abs(gitleaks) and argv[0] == gitleaks:
        return argv[1:] == ["version"] or _gitleaks_dir_ok(argv, gitleaks)
    return False


def child_argv_ok(argv: object, clone: str, case_path_ok) -> bool:
    """The run child's argument vector, in its one fixed shape.

    case_path_ok applies the registry's path rule to the case path relative
    to the clone, so a child can only be given a registered case file.
    """
    if not isinstance(argv, list) or len(argv) != 15 or not all(isinstance(a, str) for a in argv):
        return False
    if not _is_real_abs(clone):
        return False
    head = [sys.executable, "-s", "-B", "-P", os.path.join(clone, "evaluation", "run_one.py"), "--clone", clone,
            "--hits-out"]
    if argv[:8] != head or argv[9:11] != ["--", "--format"] or argv[11] not in ("sigma", "wazuh"):
        return False
    scratch = os.path.dirname(argv[8])
    if not _is_real_abs(scratch) or argv[8] != os.path.join(scratch, "hits.json"):
        return False
    if argv[13] != "--audit-log" or argv[14] != os.path.join(scratch, "audit.jsonl"):
        return False
    prefix = clone + os.sep
    return argv[12].startswith(prefix) and bool(case_path_ok(argv[12][len(prefix):]))


# --- Fixed environments -------------------------------------------------------------

def git_env(home: str) -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "HOME": home, "LANG": "C", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null"}


def pip_env(home: str) -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "HOME": home, "LANG": "C"}


def systemctl_env() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"}


# --- Starting and collecting a process ------------------------------------------------

@dataclass
class Collected:
    exit_status: int | None
    signal: int | None
    stdout: bytes
    stderr: bytes
    over_cap: bool
    deadline: bool
    interrupted: bool


def _reader(stream, cap: int, sink: list, flag: dict, key: str) -> None:
    total = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        if total + len(chunk) > cap:
            sink.append(chunk[: cap - total])
            flag[key] = True
            break
        sink.append(chunk)
        total += len(chunk)


def kill_group(proc: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def collect(proc: subprocess.Popen, *, deadline_s: float, out_cap: int, err_cap: int,
            interrupted=lambda: False, clock=time.monotonic, sleep=time.sleep, grace_s: float = 10.0) -> Collected:
    """Wait for proc, reading both pipes up to their caps.

    Over a cap, at the deadline, or on an operator interrupt the whole group
    is stopped: SIGTERM, then SIGKILL after the grace period. Output beyond a
    cap is never kept.
    """
    out: list[bytes] = []
    err: list[bytes] = []
    flags: dict[str, bool] = {}
    threads = [threading.Thread(target=_reader, args=(proc.stdout, out_cap, out, flags, "out"), daemon=True),
               threading.Thread(target=_reader, args=(proc.stderr, err_cap, err, flags, "err"), daemon=True)]
    for t in threads:
        t.start()
    start = clock()
    reason = None
    while proc.poll() is None:
        if flags:
            reason = "cap"
        elif interrupted():
            reason = "interrupt"
        elif clock() - start >= deadline_s:
            reason = "deadline"
        if reason is not None:
            break
        sleep(0.02)
    if reason is not None and proc.poll() is None:
        kill_group(proc, signal.SIGTERM)
        stop = clock()
        while proc.poll() is None and clock() - stop < grace_s:
            sleep(0.02)
        if proc.poll() is None:
            kill_group(proc, signal.SIGKILL)
        proc.wait()
    elif reason is None:
        # A process that exited may have left children holding the pipes.
        kill_group(proc, signal.SIGKILL)
    for t in threads:
        t.join(timeout=5)
    code = proc.returncode
    return Collected(
        exit_status=code if code is not None and code >= 0 else None,
        signal=-code if code is not None and code < 0 else None,
        stdout=b"".join(out), stderr=b"".join(err), over_cap=bool(flags) or reason == "cap",
        deadline=reason == "deadline", interrupted=reason == "interrupt")


def run_allowed(argv: list[str], *, env: dict, timeout: float, cwd: str | None = None, out_cap: int = CAP_BYTES,
                systemctl: str = SYSTEMCTL, gitleaks: str | None = None) -> tuple[int, bytes, bytes]:
    """Run one allow-listed helper. Anything outside the table is refused before a process exists."""
    if not argv_ok(argv, systemctl=systemctl, gitleaks=gitleaks):
        raise CheckRefused("process not on the allow-list")
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=dict(env), cwd=cwd, close_fds=True, start_new_session=True, shell=False)
    except OSError:
        raise CheckRefused("process could not be started") from None
    done = collect(proc, deadline_s=timeout, out_cap=out_cap, err_cap=out_cap, grace_s=2.0)
    if done.over_cap:
        raise CheckRefused("process output over its limit")
    if done.deadline:
        raise CheckRefused("process timed out")
    if done.exit_status is None:
        raise CheckRefused("process ended by a signal")
    return done.exit_status, done.stdout, done.stderr


def _private_home():
    return tempfile.TemporaryDirectory(prefix="eval-home-")


def _git(clone: str, *tail: str) -> bytes:
    with _private_home() as home:
        code, out, _ = run_allowed(list(GIT_PREFIX) + [clone, *tail], env=git_env(home), timeout=120)
    if code != 0:
        raise CheckRefused("code: git could not read the clone")
    return out


# --- Code identity ------------------------------------------------------------------

def default_resolved_root(name: str) -> str:
    """The real directory that holds the imported package `name`."""
    module = sys.modules.get(name) or __import__(name)
    return os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(module.__file__))))


def tracked_files(clone: str) -> list[tuple[str, str, str]]:
    """(path, mode, sha256 of the bytes on disk) for every tracked entry, sorted by path."""
    out = _git(clone, "ls-files", "-z", "-s")
    entries = []
    for raw in out.split(b"\0"):
        if not raw:
            continue
        try:
            meta, path_b = raw.split(b"\t", 1)
            mode, _obj, stage = meta.decode("ascii").split(" ")
            path = path_b.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise CheckRefused("code: tracked entry cannot be read") from None
        if mode not in ("100644", "100755") or stage != "0":
            raise CheckRefused(f"code: tracked entry mode not allowed ({path})")
        full = os.path.join(clone, path)
        try:
            st = os.lstat(full)
        except OSError:
            raise CheckRefused(f"code: tracked file missing on disk ({path})") from None
        if not stat.S_ISREG(st.st_mode):
            raise CheckRefused(f"code: tracked entry mode not allowed ({path})")
        # The mode is the one git records; a change on disk alone shows in the status check.
        entries.append((path, mode, sha256_hex(read_regular(full))))
    entries.sort()
    return entries


def file_problems(clone: str, manifest_files: list[dict]) -> list[str]:
    """Steps 1 and 2: the tracked set, modes and content equal the manifest's, outside the excluded paths."""
    try:
        observed = {p: (m, h) for p, m, h in tracked_files(clone) if p not in EXCLUDED}
    except CheckRefused as error:
        return [str(error)]
    expected = {f["path"]: (f["mode"], f["sha256"]) for f in manifest_files}
    problems = []
    for path in sorted(set(observed) | set(expected)):
        if path not in observed:
            problems.append(f"code: tracked file missing ({path})")
        elif path not in expected:
            problems.append(f"code: tracked file extra ({path})")
        elif observed[path] != expected[path]:
            problems.append(f"code: tracked file differs ({path})")
    return problems


def clean_tree_problems(clone: str) -> list[str]:
    """Steps 4 and 5: nothing untracked or modified, and no bytecode anywhere."""
    try:
        out = _git(clone, "status", "--porcelain=v1", "-z", "--ignored", "--untracked-files=all")
    except CheckRefused as error:
        return [str(error)]
    problems = []
    for raw in out.split(b"\0"):
        if not raw:
            continue
        try:
            entry = raw.decode("utf-8")
        except UnicodeDecodeError:
            entry = ""
        if not entry.startswith("!! ") or not entry[3:].startswith(IGNORED_ALLOWED):
            problems.append("code: working tree is not clean")
            break
    # A planted bytecode file can be loaded in place of its source, so any
    # __pycache__ or .pyc refuses, ignored directories included.
    for _root, dirs, names in os.walk(clone, followlinks=False):
        if "__pycache__" in dirs or any(n.endswith(".pyc") for n in names):
            problems.append("code: bytecode found in the clone")
            break
    return problems


def code_problems(clone: str, manifest_files: list[dict], merge_sha: str, merge_tree: str, *,
                  resolved_root=default_resolved_root) -> list[str]:
    problems = file_problems(clone, manifest_files)
    try:
        head = _git(clone, "rev-parse", "HEAD").strip().decode("ascii")
        tree = _git(clone, "rev-parse", "HEAD^{tree}").strip().decode("ascii")
    except (CheckRefused, UnicodeDecodeError):
        return problems + ["code: git could not read the clone"]
    if head != merge_sha:
        problems.append("code: HEAD differs from the recorded merge commit")
    if tree != merge_tree:
        problems.append("code: HEAD tree differs from the recorded merge tree")
    problems += clean_tree_problems(clone)
    real = os.path.realpath(clone)
    for name in ("triage", "evaluation"):
        if resolved_root(name) != real:
            problems.append(f"code: package {name} does not resolve inside the clone")
    return problems


def head_and_tree(clone: str) -> tuple[str, str]:
    head = _git(clone, "rev-parse", "HEAD").strip().decode("ascii")
    tree = _git(clone, "rev-parse", "HEAD^{tree}").strip().decode("ascii")
    return head, tree


# --- Python identity ---------------------------------------------------------------

# A slash that starts a token: an absolute path. A VCS URL's slashes follow ':'.
ABS_PATH_RE = re.compile(r"(?:^|[\s=@])/")


def real_freeze() -> str:
    with _private_home() as home:
        code, out, _ = run_allowed([sys.executable, *PIP_TAIL], env=pip_env(home), timeout=FREEZE_TIMEOUT_S)
    if code != 0:
        raise CheckRefused("python: package list could not be read")
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        raise CheckRefused("python: package list is not UTF-8") from None


def normalize_freeze(text: str, clone: str) -> list[str]:
    """The freeze text with the clone's path replaced by <clone>, one entry per line, every line kept."""
    text = text.replace(os.path.realpath(clone), "<clone>")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    for number, line in enumerate(lines, start=1):
        if ABS_PATH_RE.search(line) or "file:" in line or "~/" in line:
            raise CheckRefused(f"python: freeze line {number} holds a local path")
    return lines


def python_identity(clone: str, *, freeze=None) -> dict:
    text = (freeze or real_freeze)()
    return {"version": sys.version, "cache_tag": sys.implementation.cache_tag, "machine": platform.machine(),
            "freeze": normalize_freeze(text, clone)}


def runner_flags_ok() -> bool:
    return bool(sys.flags.no_user_site and sys.flags.dont_write_bytecode and getattr(sys.flags, "safe_path", False))


# --- Embedder and disk ---------------------------------------------------------------

def embedder_check(name: str, clone: str) -> str:
    if name == "hashing":
        return "not_applicable"
    if name != "minilm":
        raise CheckRefused("embedder: unknown embedder")
    from triage.embedding_model import ModelUnavailable, load_manifest, verify_model_dir
    try:
        verify_model_dir(os.path.join(clone, *MODEL_SUBDIR), load_manifest())
    except ModelUnavailable:
        raise CheckRefused("embedder: model directory does not match its manifest") from None
    return "ok"


def disk_check(store: str) -> None:
    if shutil.disk_usage(store).free < MIN_FREE_BYTES:
        raise CheckRefused("disk: less than 512 MiB free in the store")


# --- Server settings (the model server's service configuration) ---------------------

@dataclass(frozen=True)
class UnitState:
    active_state: str
    main_pid: int
    start_monotonic: int
    environment: tuple[str, ...]
    environment_files: str
    exec_path: str
    exec_argv: tuple[str, ...]


def _parse_exec_start(value: str) -> tuple[str, tuple[str, ...]]:
    if value.count("{") != 1 or value.count("}") != 1 or not value.startswith("{ ") or not value.endswith(" }"):
        raise CheckRefused("server: property ExecStart cannot be read")
    fields: dict[str, str] = {}
    for part in value[2:-2].split(" ; "):
        key, sep, val = part.partition("=")
        if not sep or key in fields:
            raise CheckRefused("server: property ExecStart cannot be read")
        fields[key] = val
    if "path" not in fields or "argv[]" not in fields or not fields["argv[]"]:
        raise CheckRefused("server: property ExecStart cannot be read")
    return fields["path"], tuple(fields["argv[]"].split(" "))


def parse_show(text: str) -> UnitState:
    values: dict[str, str] = {}
    for line in text.split("\n"):
        if line == "":
            continue
        key, sep, value = line.partition("=")
        if not sep or key not in SHOW_PROPERTIES:
            raise CheckRefused("server: unexpected property line")
        if key in values:
            raise CheckRefused(f"server: property {key} repeated")
        values[key] = value
    for key in SHOW_PROPERTIES:
        if key not in values:
            raise CheckRefused(f"server: property {key} missing")
    try:
        main_pid = int(values["MainPID"])
        start = int(values["ExecMainStartTimestampMonotonic"])
    except ValueError:
        raise CheckRefused("server: property MainPID cannot be read") from None
    environment = values["Environment"]
    if any(ch in environment for ch in "\"'\\"):
        raise CheckRefused("server: property Environment cannot be read")
    entries = tuple(environment.split(" ")) if environment else ()
    if any(e == "" for e in entries):
        raise CheckRefused("server: property Environment cannot be read")
    path, argv = _parse_exec_start(values["ExecStart"])
    return UnitState(values["ActiveState"], main_pid, start, entries, values["EnvironmentFiles"], path, argv)


def read_unit(unit: str, systemctl: str = SYSTEMCTL) -> UnitState:
    if UNIT_RE.fullmatch(unit) is None:
        raise CheckRefused("server: unit name not allowed")
    code, out, _ = run_allowed([systemctl, "show", unit, *SHOW_TAIL], env=systemctl_env(), timeout=30,
                               systemctl=systemctl)
    if code != 0:
        raise CheckRefused("server: unit could not be read")
    try:
        return parse_show(out.decode("utf-8"))
    except UnicodeDecodeError:
        raise CheckRefused("server: unit could not be read") from None


def manager_environment(systemctl: str = SYSTEMCTL) -> list[str]:
    code, out, _ = run_allowed([systemctl, "show-environment"], env=systemctl_env(), timeout=30, systemctl=systemctl)
    if code != 0:
        raise CheckRefused("server: manager environment could not be read")
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        raise CheckRefused("server: manager environment could not be read") from None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    return lines


def server_problems(state: UnitState, manager_env: list[str], expected: dict) -> list[str]:
    """Compare the observed service configuration with the manifest's, after the contract."""
    problems = []
    if state.active_state != "active":
        problems.append("server: unit is not active")
    if state.environment_files != "":
        problems.append("server: unit lists an environment file")
    unit_env = list(state.environment)
    contract = (env_problems(unit_env, where="unit") + env_problems(manager_env, where="manager")
                + exec_problems(state.exec_path, list(state.exec_argv)))
    if contract:
        return problems + contract
    if unit_env != list(expected["environment"]):
        problems.append("server: unit environment differs from the manifest")
    if list(manager_env) != list(expected["manager_environment"]):
        problems.append("server: manager environment differs from the manifest")
    if state.exec_path != expected["exec_start"]["path"] or list(state.exec_argv) != list(expected["exec_start"]["argv"]):
        problems.append("server: ExecStart differs from the manifest")
    return problems


# --- The publication contract for identity values -------------------------------------
# Every execution-identity value is published in clear in the manifest and in
# environment.json. A value outside these shapes is refused, never rewritten,
# so a private path, a URL credential or an unreviewed setting cannot be
# frozen or published. Widening any entry is a reviewed design change.

FREEZE_SHAPES = (
    re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?==[A-Za-z0-9][A-Za-z0-9.+!_-]*$"),
    re.compile(r"^-e <clone>$"),
    re.compile(r"^-e git\+https://github\.com/rdx0120/alert-triage-agent(\.git)?@[0-9a-f]{40}#egg=alert_triage_agent$"),
    re.compile(r"^#[A-Za-z0-9 ._()=+!-]*$"),
)

_DIGITS_1_9 = re.compile(r"^[0-9]{1,9}$")
_BOOLEAN = re.compile(r"^(0|1|true|false)$")
_DURATION = re.compile(r"^(-1|[0-9]+[smh]?)$")
PATH_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")


def _path_ok(value: str) -> bool:
    parts = value.split(":")
    return bool(value) and all(p in PATH_DIRS for p in parts)


ENV_GRAMMAR = {
    "OLLAMA_HOST": server_host_ok,
    "OLLAMA_CONTEXT_LENGTH": _DIGITS_1_9.fullmatch,
    "OLLAMA_NUM_PARALLEL": _DIGITS_1_9.fullmatch,
    "OLLAMA_MAX_LOADED_MODELS": _DIGITS_1_9.fullmatch,
    "OLLAMA_MAX_QUEUE": _DIGITS_1_9.fullmatch,
    "OLLAMA_FLASH_ATTENTION": _BOOLEAN.fullmatch,
    "OLLAMA_DEBUG": _BOOLEAN.fullmatch,
    "OLLAMA_NOPRUNE": _BOOLEAN.fullmatch,
    "OLLAMA_SCHED_SPREAD": _BOOLEAN.fullmatch,
    "OLLAMA_KV_CACHE_TYPE": re.compile(r"^(f16|q8_0|q4_0)$").fullmatch,
    "OLLAMA_KEEP_ALIVE": _DURATION.fullmatch,
    "OLLAMA_LOAD_TIMEOUT": _DURATION.fullmatch,
    "CUDA_VISIBLE_DEVICES": re.compile(r"^[0-9]+(,[0-9]+)*$").fullmatch,
    "LANG": re.compile(r"^[A-Za-z]{1,8}(_[A-Za-z]{2})?(\.[A-Za-z0-9-]{1,16})?$").fullmatch,
    "LC_ALL": re.compile(r"^[A-Za-z]{1,8}(_[A-Za-z]{2})?(\.[A-Za-z0-9-]{1,16})?$").fullmatch,
    "PATH": _path_ok,
}
EXEC_PATHS = ("/usr/bin/ollama", "/usr/local/bin/ollama")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def freeze_problems(lines: list[str]) -> list[str]:
    return [f"contract: freeze line {n} is not publishable"
            for n, line in enumerate(lines, start=1)
            if not isinstance(line, str) or not any(shape.fullmatch(line) for shape in FREEZE_SHAPES)]


def env_problems(entries: list[str], *, where: str) -> list[str]:
    problems = []
    for entry in entries:
        name, sep, value = entry.partition("=") if isinstance(entry, str) else ("", "", "")
        if not sep or _NAME_RE.fullmatch(name) is None:
            problems.append(f"contract: {where} environment has a malformed entry")
            continue
        grammar = ENV_GRAMMAR.get(name)
        if grammar is None or not grammar(value):
            problems.append(f"contract: {where} variable {name} is not publishable")
    return problems


def exec_problems(path: str, argv: list[str]) -> list[str]:
    if path not in EXEC_PATHS or list(argv) != [path, "serve"]:
        return ["contract: ExecStart is not publishable"]
    return []


def execution_contract_problems(execution: dict) -> list[str]:
    """The contract over a whole execution identity (the manifest builder and the publication build)."""
    problems = freeze_problems(execution["python"]["freeze"])
    server = execution.get("server")
    if server is not None:
        problems += env_problems(server["environment"], where="unit")
        problems += env_problems(server["manager_environment"], where="manager")
        problems += exec_problems(server["exec_start"]["path"], server["exec_start"]["argv"])
    return problems
