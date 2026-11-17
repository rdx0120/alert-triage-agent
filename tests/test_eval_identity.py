"""Code, interpreter, model and server identity checks, and the publication contract at the pre-run point."""

from __future__ import annotations

import json
import os
import sys

import pytest

import test_eval_doubles as dbl
from evaluation import harness, identity, manifest, probe

ollama_stub = dbl.ollama_stub


@pytest.fixture
def clone(tmp_path, tmp_path_factory):
    return dbl.make_clone(tmp_path, tmp_path_factory)


@pytest.fixture(scope="module")
def ro_clone(tmp_path_factory):
    """A clone the tests below only read."""
    return dbl.make_clone(tmp_path_factory.mktemp("ro"), tmp_path_factory)


def code(clone, *, sha=None, tree=None):
    m = manifest.load_manifest(clone.manifest_bytes)
    real = os.path.realpath(clone.path)
    return identity.code_problems(str(clone.path), [f.model_dump() for f in m.files], sha or clone.merge_sha,
                                  tree or clone.merge_tree, resolved_root=lambda name: real)


def commit(clone, message="change"):
    dbl.git(clone.path, "add", "-A")
    dbl.git(clone.path, "commit", "-q", "-m", message)
    return (dbl.git(clone.path, "rev-parse", "HEAD").strip(), dbl.git(clone.path, "rev-parse", "HEAD^{tree}").strip())


def test_the_clean_committed_clone_passes(clone):
    assert code(clone) == []


def test_an_allowed_ignored_model_file_passes(clone):
    (clone.path / "models" / "all-MiniLM-L6-v2").mkdir(parents=True)
    (clone.path / "models" / "all-MiniLM-L6-v2" / "config.json").write_text("{}")
    assert code(clone) == []


def test_a_changed_byte_is_reported(clone):
    path = clone.path / "triage" / "agent.py"
    path.write_bytes(path.read_bytes() + b"\n")
    sha, tree = commit(clone)
    assert "code: tracked file differs (triage/agent.py)" in code(clone, sha=sha, tree=tree)


def test_a_mode_change_is_reported(clone):
    os.chmod(clone.path / "triage" / "agent.py", 0o755)
    sha, tree = commit(clone)
    assert "code: tracked file differs (triage/agent.py)" in code(clone, sha=sha, tree=tree)


def test_an_added_tracked_file_is_reported(clone):
    (clone.path / "triage" / "extra.py").write_text("x = 1\n")
    sha, tree = commit(clone)
    assert "code: tracked file extra (triage/extra.py)" in code(clone, sha=sha, tree=tree)


def test_a_removed_tracked_file_is_reported(clone):
    dbl.git(clone.path, "rm", "-q", "triage/render.py")
    sha, tree = commit(clone)
    assert "code: tracked file missing (triage/render.py)" in code(clone, sha=sha, tree=tree)


def test_a_different_head_and_tree_are_reported(clone):
    assert code(clone, sha="0" * 40) == ["code: HEAD differs from the recorded merge commit"]
    assert code(clone, tree="0" * 40) == ["code: HEAD tree differs from the recorded merge tree"]


def test_an_untracked_file_is_reported(clone):
    (clone.path / "notes.txt").write_text("x")
    assert code(clone) == ["code: working tree is not clean"]


def test_an_ignored_file_outside_the_two_directories_is_reported(clone):
    (clone.path / "logs").mkdir()
    (clone.path / "logs" / "run.log").write_text("x")
    assert code(clone) == ["code: working tree is not clean"]


def test_a_pycache_directory_is_reported(clone):
    (clone.path / "triage" / "__pycache__").mkdir()
    (clone.path / "triage" / "__pycache__" / "agent.cpython-312.pyc").write_bytes(b"x")
    assert "code: bytecode found in the clone" in code(clone)


def test_a_pyc_file_in_an_ignored_directory_is_reported(clone):
    (clone.path / "models" / "all-MiniLM-L6-v2").mkdir(parents=True)
    (clone.path / "models" / "all-MiniLM-L6-v2" / "shadow.pyc").write_bytes(b"x")
    assert code(clone) == ["code: bytecode found in the clone"]


def test_a_tracked_symlink_is_reported(clone):
    os.symlink("agent.py", clone.path / "triage" / "link.py")
    sha, tree = commit(clone)
    assert code(clone, sha=sha, tree=tree) == ["code: tracked entry mode not allowed (triage/link.py)"]


def test_packages_resolving_outside_the_clone_are_reported(clone):
    m = manifest.load_manifest(clone.manifest_bytes)
    problems = identity.code_problems(str(clone.path), [f.model_dump() for f in m.files], clone.merge_sha,
                                      clone.merge_tree, resolved_root=lambda name: "/elsewhere")
    assert problems == ["code: package triage does not resolve inside the clone",
                        "code: package evaluation does not resolve inside the clone"]


# --- Python identity ------------------------------------------------------------------------

def a_pass(clone, tmp_path, *, freeze=None, systemctl=None, endpoint=None, pass_id="baseline-001"):
    hooks = clone.hooks()
    if freeze is not None:
        hooks.freeze = freeze
    if systemctl is not None:
        hooks.systemctl = systemctl
    p = harness._Pass(str(clone.path), str(dbl.private_dir(tmp_path / "store")), pass_id, clone.merge_sha,
                      clone.merge_tree, hooks)
    p.manifest = manifest.load_manifest(clone.manifest_bytes)
    p.endpoint = endpoint
    return p


def test_the_frozen_python_identity_passes(ro_clone, tmp_path):
    assert a_pass(ro_clone, tmp_path).python_check() == []


def test_a_changed_interpreter_version_is_reported(ro_clone, tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "version", sys.version + " changed")
    assert a_pass(ro_clone, tmp_path).python_check() == ["python: interpreter or package list differs from the manifest"]


@pytest.mark.parametrize("change", ["version", "added", "removed", "editable"])
def test_the_full_freeze_text_is_compared(ro_clone, tmp_path, change):
    base = dbl.freeze_text(ro_clone.path)
    text = {"version": base.replace("pydantic==2.9.2", "pydantic==2.9.3"),
            "added": base + "extra==1.0\n",
            "removed": base.replace("annotated-types==0.7.0\n", ""),
            "editable": base.replace(f"-e {os.path.realpath(ro_clone.path)}",
                                     "-e git+https://github.com/rdx0120/alert-triage-agent@" + "1" * 40
                                     + "#egg=alert_triage_agent")}[change]
    assert a_pass(ro_clone, tmp_path, freeze=lambda: text).python_check() == [
        "python: interpreter or package list differs from the manifest"]


@pytest.mark.parametrize("line", ["-e /home/someone/project", "pkg @ file:///opt/pkg.whl", "-e ~/project",
                                  "pkg==1.0 --hash=/x"])
def test_a_line_that_keeps_a_local_path_refuses(ro_clone, tmp_path, line):
    text = dbl.freeze_text(ro_clone.path) + line + "\n"
    problems = a_pass(ro_clone, tmp_path, freeze=lambda: text).python_check()
    assert problems == ["python: freeze line 4 holds a local path"]


def test_normalization_removes_the_clone_path(ro_clone):
    lines = identity.normalize_freeze(dbl.freeze_text(ro_clone.path), str(ro_clone.path))
    assert "-e <clone>" in lines and not any(os.path.realpath(ro_clone.path) in line for line in lines)


def test_the_real_freeze_command_runs_and_normalizes(ro_clone):
    text = identity.real_freeze()
    assert text
    lines = identity.normalize_freeze(text, str(ro_clone.path))
    assert lines and not any(os.path.realpath(ro_clone.path) in line for line in lines)


# --- Ollama identity --------------------------------------------------------------------------

@pytest.fixture
def stub_clone(tmp_path, tmp_path_factory, ollama_stub):
    exe = dbl.execution_dict(tmp_path / "clone")
    exe["ollama"] = probe.ollama_identity(ollama_stub.endpoint(), "qwen3:8b")
    return dbl.make_clone(tmp_path, tmp_path_factory, execution=exe)


def test_the_frozen_model_identity_passes(stub_clone, tmp_path, ollama_stub):
    assert a_pass(stub_clone, tmp_path, endpoint=ollama_stub.endpoint()).ollama_check() == []


@pytest.mark.parametrize("change", [("version", "0.12.4"), ("digest", "b" * 64), ("parameters", "temperature 1"),
                                    ("template", "{{ .System }}"), ("format", "ggml"), ("family", "llama"),
                                    ("parameter_size", "7B"), ("quantization_level", "Q8_0")])
def test_each_changed_model_field_is_reported(stub_clone, tmp_path, ollama_stub, change):
    key, value = change
    if key in ("format", "family", "parameter_size", "quantization_level"):
        ollama_stub.identity["details"][key] = value
    else:
        ollama_stub.identity[key] = value
    assert a_pass(stub_clone, tmp_path, endpoint=ollama_stub.endpoint()).ollama_check() == [
        "ollama: server or model identity differs from the manifest"]


def test_two_tags_entries_with_the_model_name_refuse(stub_clone, tmp_path, ollama_stub):
    ollama_stub.identity["extra_tags"] = [{"name": "qwen3:8b", "digest": "c" * 64}]
    assert a_pass(stub_clone, tmp_path, endpoint=ollama_stub.endpoint()).ollama_check() == [
        "probe: the model is not listed exactly once"]


def test_a_body_over_one_mebibyte_refuses(stub_clone, tmp_path, ollama_stub):
    ollama_stub.override["/api/version"] = json.dumps({"version": "x" * (1 << 20)}).encode()
    assert a_pass(stub_clone, tmp_path, endpoint=ollama_stub.endpoint()).ollama_check() == [
        "probe: version answer is over 1 MiB"]


# --- Server settings --------------------------------------------------------------------------

@pytest.fixture
def fake(tmp_path):
    return dbl.make_systemctl(tmp_path / "bin")


def server(clone, tmp_path, fake):
    return a_pass(clone, tmp_path, systemctl=fake.path, pass_id="model-001").server_check()


def test_the_frozen_server_settings_pass(ro_clone, tmp_path, fake):
    assert server(ro_clone, tmp_path, fake) == []


@pytest.mark.parametrize("changes, message", [
    ({"environment": ["OLLAMA_HOST=127.0.0.1:11434", "OLLAMA_CONTEXT_LENGTH=4096"]},
     "server: unit environment differs from the manifest"),
    ({"environment": ["OLLAMA_HOST=127.0.0.1:11434"]}, "server: unit environment differs from the manifest"),
    ({"environment": ["OLLAMA_HOST=127.0.0.1:11434", "OLLAMA_CONTEXT_LENGTH=8192", "OLLAMA_NUM_PARALLEL=2"]},
     "server: unit environment differs from the manifest"),
    ({"manager": ["LANG=C.UTF-8"]}, "server: manager environment differs from the manifest"),
    ({"manager": ["LANG=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin", "LC_ALL=C"]},
     "server: manager environment differs from the manifest"),
    ({"exec_path": "/usr/local/bin/ollama", "exec_argv": ["/usr/local/bin/ollama", "serve"]},
     "server: ExecStart differs from the manifest"),
    ({"environment_files": "/etc/ollama.env (ignore_errors=no)"}, "server: unit lists an environment file"),
    ({"active": "inactive"}, "server: unit is not active"),
])
def test_each_changed_server_setting_is_reported(ro_clone, tmp_path, fake, changes, message):
    fake.set(**changes)
    assert message in server(ro_clone, tmp_path, fake)


@pytest.mark.parametrize("raw, message", [
    ("ActiveState=active\nMainPID=1\nExecMainStartTimestampMonotonic=1\nEnvironment=OLLAMA_HOST=\"127.0.0.1:1\"\n"
     "EnvironmentFiles=\nExecStart={ path=/usr/bin/ollama ; argv[]=/usr/bin/ollama serve }\n",
     "server: property Environment cannot be read"),
    ("ActiveState=active\nMainPID=1\nExecMainStartTimestampMonotonic=1\nEnvironment=\nEnvironmentFiles=\n"
     "ExecStart={ path=/usr/bin/ollama ; argv[]=/usr/bin/ollama serve } ; { path=/usr/bin/ollama ; argv[]=x }\n",
     "server: property ExecStart cannot be read"),
    ("ActiveState=active\nMainPID=1\nExecMainStartTimestampMonotonic=1\nEnvironment=\nEnvironmentFiles=\n",
     "server: property ExecStart missing"),
    ("ActiveState=active\nActiveState=active\nMainPID=1\nExecMainStartTimestampMonotonic=1\nEnvironment=\n"
     "EnvironmentFiles=\nExecStart={ path=/usr/bin/ollama ; argv[]=/usr/bin/ollama serve }\n",
     "server: property ActiveState repeated"),
])
def test_unreadable_service_output_fails_closed(ro_clone, tmp_path, fake, raw, message):
    fake.set(raw_show=raw)
    assert server(ro_clone, tmp_path, fake) == [message]


def test_a_changed_main_pid_counts_a_restart_and_is_not_a_failure(ro_clone, tmp_path, fake):
    p = a_pass(ro_clone, tmp_path, systemctl=fake.path, pass_id="model-001")
    assert p.server_check() == [] and p.server_restarts == 0
    fake.set(main_pid=5151, start=2000)
    assert p.server_check() == [] and p.server_restarts == 1
    assert p.server_check() == [] and p.server_restarts == 1


# --- The publication contract at the pre-run point --------------------------------------------

REFUSED_FREEZE = [
    "pkg @ https://example.invalid/pkg.whl",
    "-e git+https://user:token" + "@" + "github.com/rdx0120/alert-triage-agent@" + "1" * 40 + "#egg=alert_triage_agent",
    "-e git+https://github.com/someone/other@" + "1" * 40 + "#egg=alert_triage_agent",
    "-e git+https://github.com/rdx0120/alert-triage-agent@1234567#egg=alert_triage_agent",
    "-e <clone> --config-settings x",
    "# from a/b", "# by me@host", "# see: here", "# ~home",
]


@pytest.mark.parametrize("line", REFUSED_FREEZE)
def test_unpublishable_freeze_lines_refuse_before_comparison(ro_clone, tmp_path, line):
    text = dbl.freeze_text(ro_clone.path) + line + "\n"
    problems = a_pass(ro_clone, tmp_path, freeze=lambda: text).python_check()
    assert problems == ["contract: freeze line 4 is not publishable"]
    assert line not in problems[0]


REFUSED_ENV = [
    "OLLAMA_MODELS=/srv/models", "OLLAMA_ORIGINS=*", "HTTPS_PROXY=http://proxy.invalid:3128", "HOME=/root",
    "MY_SETTING=1", "OLLAMA_HOST=0.0.0.0:11434", "PATH=/home/someone/bin:/usr/bin",
    "OLLAMA_CONTEXT_LENGTH=8k", "OLLAMA_CONTEXT_LENGTH=1234567890", "OLLAMA_FLASH_ATTENTION=yes",
    "OLLAMA_KV_CACHE_TYPE=q5_1", "OLLAMA_KEEP_ALIVE=5d", "CUDA_VISIBLE_DEVICES=GPU-0", "LANG=en_US.UTF-8@euro",
    "PATH=", "malformed",
]


@pytest.mark.parametrize("entry", REFUSED_ENV)
@pytest.mark.parametrize("where", ["unit", "manager"])
def test_unpublishable_environment_entries_refuse(ro_clone, tmp_path, fake, entry, where):
    base = dbl.default_unit_state()
    if where == "unit":
        fake.set(environment=base["environment"] + [entry])
    else:
        fake.set(manager=base["manager"] + [entry])
    problems = server(ro_clone, tmp_path, fake)
    assert problems and all(p.startswith("contract:") for p in problems)
    value = entry.partition("=")[2]
    if len(value) >= 2:
        assert all(value not in p for p in problems)


@pytest.mark.parametrize("path, argv", [
    ("/usr/bin/env", ["/usr/bin/env", "ollama", "serve"]),
    ("/usr/bin/ollama", ["/usr/bin/ollama", "serve", "--verbose"]),
    ("/home/someone/bin/ollama", ["/home/someone/bin/ollama", "serve"]),
])
def test_unpublishable_exec_start_refuses(ro_clone, tmp_path, fake, path, argv):
    fake.set(exec_path=path, exec_argv=argv)
    problems = server(ro_clone, tmp_path, fake)
    assert problems == ["contract: ExecStart is not publishable"]


def test_allowed_values_pass_the_contract():
    assert identity.freeze_problems(["pydantic==2.9.2", "-e <clone>", "# Editable install (from main)",
                                     "-e git+https://github.com/rdx0120/alert-triage-agent.git@" + "f" * 40
                                     + "#egg=alert_triage_agent"]) == []
    entries = ["OLLAMA_HOST=[::1]:11434", "OLLAMA_NUM_PARALLEL=1", "OLLAMA_DEBUG=false", "OLLAMA_KV_CACHE_TYPE=q8_0",
               "OLLAMA_KEEP_ALIVE=-1", "OLLAMA_LOAD_TIMEOUT=5m", "CUDA_VISIBLE_DEVICES=0,1", "LANG=C.UTF-8",
               "LC_ALL=en_US.UTF-8", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    assert identity.env_problems(entries, where="unit") == []
    assert identity.exec_problems("/usr/local/bin/ollama", ["/usr/local/bin/ollama", "serve"]) == []
