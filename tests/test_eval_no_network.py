"""No network, install or pull path in the evaluation tools, and one way to start a process."""

from __future__ import annotations

import ast
import socket
import sys
from pathlib import Path

import pytest

from evaluation import endpoint, identity, probe

EVAL = Path(__file__).resolve().parent.parent / "evaluation"
NEW_MODULES = ("endpoint", "identity", "probe", "manifest", "order", "run_one", "classify", "ledger", "harness",
               "evidence", "publish", "instruments")
CLIS = ("harness", "manifest", "order", "publish", "instruments")
CLONE = str(Path(__file__).resolve().parent.parent)


def _tree(name: str) -> ast.Module:
    return ast.parse((EVAL / f"{name}.py").read_text(encoding="utf-8"))


def test_the_probe_refuses_an_unknown_request_without_a_socket(monkeypatch):
    def no_socket(*args, **kwargs):
        raise AssertionError("a socket was created")
    monkeypatch.setattr(socket, "socket", no_socket)
    for key in ("pull", "push", "create", "delete", "copy", "VERSION", ""):
        with pytest.raises(probe.ProbeRefused):
            probe.request(endpoint.Endpoint("127.0.0.1", 11434), key)


def test_the_probe_table_is_exactly_three_requests():
    assert probe.REQUESTS == {"version": ("GET", "/api/version"), "tags": ("GET", "/api/tags"),
                              "show": ("POST", "/api/show")}


def git(*tail):
    return ["git", "-c", "core.fsmonitor=false", "-C", CLONE, *tail]


ACCEPTED = [
    git("ls-files", "-z", "-s"), git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}"),
    git("status", "--porcelain=v1", "-z", "--ignored", "--untracked-files=all"),
    [sys.executable, *identity.PIP_TAIL],
    [identity.SYSTEMCTL, "show", "ollama.service", *identity.SHOW_TAIL],
    [identity.SYSTEMCTL, "show-environment"],
]


@pytest.mark.parametrize("argv", ACCEPTED, ids=lambda a: " ".join(a[4:6]) if a[0] == "git" else a[-1][:20])
def test_the_allow_list_accepts_its_shapes(argv):
    assert identity.argv_ok(argv)


REFUSED = [
    git("fetch"), git("clone", "x"), git("pull"), git("push"), git("remote", "-v"), git("config", "--list"),
    git("submodule", "update"), git("ls-files", "-z", "-s", "--others"), git("-z", "ls-files", "-s"),
    git("status", "--porcelain=v1"), ["git", "-C", CLONE, "rev-parse", "HEAD"],
    ["git", "-c", "core.fsmonitor=false", "-C", "relative", "rev-parse", "HEAD"],
    [sys.executable, "-m", "pip", "install", "x"], [sys.executable, "-I", "-m", "pip", "download", "x"],
    [sys.executable, "-I", "-m", "pip", "freeze"], [sys.executable, *identity.PIP_TAIL, "--path", "/x"],
    [identity.SYSTEMCTL, "start", "ollama.service"], [identity.SYSTEMCTL, "stop", "ollama.service"],
    [identity.SYSTEMCTL, "restart", "ollama.service"],
    [identity.SYSTEMCTL, "show", "ollama", *identity.SHOW_TAIL],
    [identity.SYSTEMCTL, "show", "ollama.service", "--no-pager"],
    ["/bin/sh", "-c", "git status"], ["git status"], [], "git status",
]


@pytest.mark.parametrize("argv", REFUSED, ids=lambda a: str(a)[-40:])
def test_the_allow_list_refuses_everything_else(argv):
    assert not identity.argv_ok(argv)
    with pytest.raises(identity.CheckRefused):
        identity.run_allowed(argv if isinstance(argv, list) else [argv], env={}, timeout=5)


def test_gitleaks_shapes_need_the_configured_binary(tmp_path):
    binary = str(tmp_path.resolve() / "gitleaks")
    d = str(tmp_path.resolve())
    good = [binary, "dir", d, "--config", d, "--redact", "--no-banner", "--ignore-gitleaks-allow", "--exit-code",
            "1", "--gitleaks-ignore-path", d, "--report-format", "json", "--report-path", d]
    assert identity.argv_ok(good, gitleaks=binary) and identity.argv_ok([binary, "version"], gitleaks=binary)
    assert not identity.argv_ok(good)
    assert not identity.argv_ok([binary, "git", *good[2:]], gitleaks=binary)
    assert not identity.argv_ok(good + ["--log-level", "debug"], gitleaks=binary)
    assert not identity.argv_ok(good[:5] + good[6:], gitleaks=binary)


# --- Static scans --------------------------------------------------------------------------------

def _imports(tree: ast.Module) -> set[str]:
    """Every imported module as a full dotted name; `from x import y` also gives `x.y`."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
            names.update(f"{node.module}.{a.name}" for a in node.names)
    return names


NETWORK_OR_PROCESS = {"socket", "http", "urllib", "requests", "subprocess", "httpx", "ftplib", "smtplib",
                      "aiohttp", "asyncio", "multiprocessing", "pty", "telnetlib", "xmlrpc"}
# The exact exceptions: the allow-listed helpers and run child, and the identity probe.
EXCEPTIONS = {"identity": {"subprocess"}, "harness": {"subprocess"}, "probe": {"http.client", "http"}}


def unapproved(name: str, tree: ast.Module) -> set[str]:
    found = {i for i in _imports(tree) if i.split(".")[0] in NETWORK_OR_PROCESS}
    allowed = EXCEPTIONS.get(name, set())
    if name == "probe":
        # `import http.client` only: no other http submodule, and no `from http import ...`.
        froms = {f"http.{a.name}" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module == "http"
                 for a in n.names}
        return (found - allowed) | froms
    return found - allowed


def _calls(tree: ast.Module) -> list[ast.Call]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call)]


def _dotted(node) -> str:
    if isinstance(node, ast.Attribute):
        return _dotted(node.value) + "." + node.attr
    if isinstance(node, ast.Name):
        return node.id
    return "?"


def test_only_the_exact_exceptions_import_a_process_or_network_module():
    for path in sorted(EVAL.glob("*.py")):
        name = path.stem
        tree = _tree(name)
        assert unapproved(name, tree) == set(), name
        imports = _imports(tree)
        assert ("subprocess" in imports) == (name in ("identity", "harness")), name
        assert ("http.client" in imports) == (name == "probe"), name


@pytest.mark.parametrize("name, source", [
    ("scorer", "import subprocess"), ("records", "import http.client"), ("evidence", "from subprocess import run"),
    ("probe", "import subprocess"), ("probe", "from http import client"), ("probe", "import http.server"),
    ("identity", "import http.client"), ("harness", "import socket"), ("publish", "import urllib.request"),
    ("instruments", "import multiprocessing"), ("new_module", "import requests"),
])
def test_an_unapproved_import_anywhere_in_evaluation_is_rejected(name, source):
    assert unapproved(name, ast.parse(source))


@pytest.mark.parametrize("name, source", [("identity", "import subprocess"), ("harness", "import subprocess"),
                                          ("probe", "import http.client")])
def test_the_exceptions_themselves_are_accepted(name, source):
    assert unapproved(name, ast.parse(source)) == set()


def test_processes_start_only_through_the_allow_list_or_the_checked_child():
    starters = {"subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
                "subprocess.check_output", "os.system", "os.popen", "os.execv", "os.execve", "os.spawnv",
                "os.posix_spawn", "os.fork"}
    for name in NEW_MODULES:
        tree = _tree(name)
        found = []
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for call in _calls(fn):
                if _dotted(call.func) in starters:
                    found.append(fn.name)
        if name == "identity":
            assert found == ["run_allowed"]
        elif name == "harness":
            assert found == ["default_spawn"]
            # The spawn is reached only after the child argv check.
            source = (EVAL / "harness.py").read_text()
            body = source[source.index("def _one_run"):source.index("def _end_check")]
            assert body.index("child_argv_ok") < body.index(".spawn or default_spawn")
        else:
            assert found == [], name


FORBIDDEN_STRINGS = {"fetch", "pull", "push", "clone", "install", "download", "/api/pull", "/api/push",
                     "/api/create", "/api/delete", "/api/copy"}


def test_no_string_constant_names_a_forbidden_operation():
    for name in NEW_MODULES:
        for node in ast.walk(_tree(name)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value not in FORBIDDEN_STRINGS, (name, node.value)


def test_files_are_created_only_through_triage_files():
    for name in NEW_MODULES:
        tree = _tree(name)
        for call in _calls(tree):
            func = _dotted(call.func)
            assert not func.endswith("write_new_file"), name
            if func == "os.open":
                flags = ast.unparse(call.args[1]) if len(call.args) > 1 else ""
                assert "O_CREAT" not in flags, name
            if func == "open":
                mode = call.args[1].value if len(call.args) > 1 and isinstance(call.args[1], ast.Constant) else "r"
                assert set(mode) <= {"r", "b"}, name
            assert func not in ("Path.write_bytes", "Path.write_text") and not func.endswith(".write_bytes") \
                and not func.endswith(".write_text"), name


def test_the_command_lines_never_build_hooks():
    for name in CLIS:
        tree = _tree(name)
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in ("_body", "main")]:
            for call in _calls(fn):
                assert _dotted(call.func) not in ("Hooks", "harness.Hooks"), name
                assert all(k.arg != "hooks" for k in call.keywords), name
