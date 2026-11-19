"""The evaluation host's dependency locks (DD-032), checked offline.

Three files, each installed from exactly one index: requirements/eval-pip.lock
(PyPI), requirements/eval-torch.lock (the PyTorch CPU index) and
requirements/eval.lock (PyPI). They pin the exact set that passed the
real-model tests. These tests keep them hash-pinned, single-purpose and in
step with requirements/eval.in and with CI's requirements/ci.lock; they do
not download anything.
"""

import re

import pytest
from packaging.markers import Marker
from packaging.utils import canonicalize_name

from triage.config import REPO_ROOT

REQUIREMENTS = REPO_ROOT / "requirements"
EVAL_LOCKS = ("eval-pip.lock", "eval-torch.lock", "eval.lock")
PYPI = "https://pypi.org/simple"
PYTORCH_CPU = "https://download.pytorch.org/whl/cpu"
# The evaluation host, for evaluating ci.lock's environment markers.
HOST = {"python_version": "3.12", "python_full_version": "3.12.3", "sys_platform": "linux",
        "platform_system": "Linux", "platform_machine": "x86_64", "os_name": "posix",
        "implementation_name": "cpython", "platform_python_implementation": "CPython", "extra": ""}
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)(?:\s*;\s*(.+?))?$")
HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def entries(name):
    """Each requirement of a lock or input file: (logical line without options, hashes, raw line)."""
    lines = (REQUIREMENTS / name).read_text(encoding="ascii").splitlines()
    logical, current = [], ""
    for line in lines:
        text = line.split("#", 1)[0] if not line.lstrip().startswith("--hash") else line
        if line.lstrip().startswith("#"):
            continue
        current += " " + text.rstrip().removesuffix("\\")
        if not line.rstrip().endswith("\\"):
            if current.strip():
                logical.append(current.strip())
            current = ""
    result = []
    for line in logical:
        hashes = HASH.findall(line)
        requirement = HASH.sub("", line).strip()
        result.append((requirement, hashes, line))
    return result


def pins(name):
    """{canonical name: (version, marker or None, hashes)} of a lock file."""
    out = {}
    for requirement, hashes, _ in entries(name):
        match = PIN.fullmatch(requirement)
        assert match, f"{name}: not an exact pin: {requirement[:60]}"
        n, version, marker = match.groups()
        out.setdefault(canonicalize_name(n), []).append((version, marker, frozenset(hashes)))
    return out


def host_pins(name):
    """The pins of a lock that apply on the evaluation host, one per package."""
    out = {}
    for n, versions in pins(name).items():
        live = [(v, h) for v, marker, h in versions if marker is None or Marker(marker).evaluate(HOST)]
        assert len(live) <= 1, f"{name}: {n} is pinned twice for the host"
        if live:
            out[n] = live[0]
    return out


@pytest.mark.parametrize("name", EVAL_LOCKS)
def test_every_evaluation_requirement_is_an_exact_hashed_pin(name):
    """A requirement is not name==version, carries a marker, or has no hash, so pip would install unverified bytes."""
    found = entries(name)
    assert found
    for requirement, hashes, _ in found:
        match = PIN.fullmatch(requirement)
        assert match and match.group(3) is None, f"{name}: {requirement[:60]}"
        assert hashes, f"{name}: {requirement} has no hash"


@pytest.mark.parametrize("name", EVAL_LOCKS + ("eval.in",))
def test_no_evaluation_file_chooses_an_index(name):
    """A file names an index, a link source or another file, so the install command no longer decides the source."""
    for requirement, _, _ in entries(name):
        assert not requirement.startswith("-"), f"{name}: option line {requirement.split()[0]}"
        assert "://" not in requirement and " @ " not in requirement, f"{name}: URL requirement"


@pytest.mark.parametrize("name, index", [("eval-pip.lock", PYPI), ("eval-torch.lock", PYTORCH_CPU),
                                         ("eval.lock", PYPI)])
def test_documented_install_names_one_index(name, index):
    """The documented command for a lock names another index, or more than one, or does not enforce hashes."""
    text = (REQUIREMENTS / name).read_text(encoding="ascii")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    command = (f"python -m pip install --isolated --require-hashes --no-deps --index-url {index} "
               f"-r requirements/{name}")
    assert command in readme
    if name != "eval.lock":   # eval.lock's header is uv's; its command is in the README
        assert command in text
    for line in readme.splitlines():
        if f"-r requirements/{name}" in line:
            assert line.count("--index-url") == 1 and "--extra-index-url" not in line


def test_pip_and_torch_locks_hold_one_package_each():
    """The pip or torch lock holds anything else, or torch is not the CPU-only build with one wheel hash."""
    assert set(pins("eval-pip.lock")) == {"pip"}
    ((version, _, hashes),) = pins("eval-torch.lock")["torch"]
    assert set(pins("eval-torch.lock")) == {"torch"}
    assert version.endswith("+cpu") and len(hashes) == 1


def test_no_package_is_in_two_evaluation_locks():
    """A package is pinned in two evaluation locks, so the install order would decide its version."""
    seen = {}
    for name in EVAL_LOCKS:
        for package in pins(name):
            assert package not in seen, f"{package} is in {seen.get(package)} and {name}"
            seen[package] = name


def test_eval_lock_pins_exactly_eval_in():
    """eval.lock pins a different set or version than eval.in, the reviewed list of tested versions."""
    wanted = {n: v for n, ((v, _, _),) in pins("eval.in").items()}
    locked = {n: v for n, ((v, _, _),) in pins("eval.lock").items()}
    assert locked == wanted
    assert all(not hashes for ((_, _, hashes),) in pins("eval.in").values())


def test_packages_shared_with_ci_lock_are_identical():
    """A package in both eval.lock and ci.lock has a different version or file hashes on the host than CI tests."""
    ci, evaluation = host_pins("ci.lock"), host_pins("eval.lock")
    shared = sorted(set(ci) & set(evaluation))
    assert len(shared) >= 10   # pydantic, numpy, faiss-cpu, pytest and the rest of CI's core
    for package in shared:
        assert evaluation[package] == ci[package], package
    # Everything CI installs on the host is in the evaluation environment too.
    assert set(ci) <= set(evaluation)
