"""The manifest builder and verifier, the observer, and the publication contract at the builder."""

from __future__ import annotations

import copy
import json
import os
import stat
import subprocess
import sys

import pytest

import test_eval_doubles as dbl
import test_eval_identity as ti
from evaluation import identity, manifest
from evaluation.common import canonical_dumps

ollama_stub = dbl.ollama_stub


@pytest.fixture(scope="module")
def ro_clone(tmp_path_factory):
    return dbl.make_clone(tmp_path_factory.mktemp("ro"), tmp_path_factory)


def test_the_exclusion_list_is_exactly_the_two_paths_and_no_file_is_missing_or_extra(ro_clone):
    m = manifest.load_manifest(ro_clone.manifest_bytes)
    assert m.excluded == ["eval/manifest.json", "provenance.json"]
    tracked = sorted(p for p in dbl.git(ro_clone.path, "ls-files").splitlines())
    assert [f.path for f in m.files] == [p for p in tracked if p not in m.excluded]
    assert manifest.file_problems(str(ro_clone.path), m) == []


def test_the_builder_output_is_canonical_and_accepted(ro_clone):
    assert canonical_dumps(json.loads(ro_clone.manifest_bytes)) == ro_clone.manifest_bytes


@pytest.mark.parametrize("excluded", [["eval/manifest.json"], ["eval/manifest.json", "provenance.json", "x"],
                                      ["provenance.json", "eval/manifest.json"]])
def test_a_different_exclusion_list_is_refused(ro_clone, excluded):
    doc = json.loads(ro_clone.manifest_bytes)
    doc["excluded"] = excluded
    with pytest.raises(manifest.ManifestRefused):
        manifest.load_manifest(canonical_dumps(doc))


def test_a_missing_or_extra_tracked_file_is_reported(ro_clone):
    doc = json.loads(ro_clone.manifest_bytes)
    removed = doc["files"].pop(0)
    doc["files"].append({"path": "zz/extra.py", "mode": "100644", "sha256": "0" * 64})
    problems = manifest.file_problems(str(ro_clone.path), manifest.load_manifest(canonical_dumps(doc)))
    assert f"code: tracked file extra ({removed['path']})" in problems
    assert "code: tracked file missing (zz/extra.py)" in problems


def test_a_non_canonical_manifest_is_refused(ro_clone):
    with pytest.raises(manifest.ManifestRefused):
        manifest.load_manifest(json.dumps(json.loads(ro_clone.manifest_bytes), indent=1).encode())


def test_the_builder_refuses_a_dirty_tree(tmp_path, tmp_path_factory):
    clone = dbl.make_clone(tmp_path, tmp_path_factory)
    (clone.path / "untracked.txt").write_text("x")
    with pytest.raises(manifest.ManifestRefused):
        manifest.build(str(clone.path), manifest.Execution.model_validate(dbl.execution_dict(clone.path)))


def _execution_with(ro_clone, *, freeze_line=None, unit_entry=None, manager_entry=None, exec_start=None):
    exe = copy.deepcopy(dbl.execution_dict(ro_clone.path))
    if freeze_line is not None:
        exe["python"]["freeze"].append(freeze_line)
    if unit_entry is not None:
        exe["server"]["environment"].append(unit_entry)
    if manager_entry is not None:
        exe["server"]["manager_environment"].append(manager_entry)
    if exec_start is not None:
        exe["server"]["exec_start"] = {"path": exec_start[0], "argv": exec_start[1]}
    return manifest.Execution.model_validate(exe)


@pytest.mark.parametrize("line", ti.REFUSED_FREEZE)
def test_the_builder_refuses_unpublishable_freeze_lines(ro_clone, line):
    with pytest.raises(manifest.ManifestRefused) as info:
        manifest.build(str(ro_clone.path), _execution_with(ro_clone, freeze_line=line))
    assert line not in str(info.value)


@pytest.mark.parametrize("entry", ti.REFUSED_ENV)
@pytest.mark.parametrize("where", ["unit", "manager"])
def test_the_builder_refuses_unpublishable_environment_entries(ro_clone, entry, where):
    kwargs = {"unit_entry": entry} if where == "unit" else {"manager_entry": entry}
    with pytest.raises(manifest.ManifestRefused) as info:
        manifest.build(str(ro_clone.path), _execution_with(ro_clone, **kwargs))
    value = entry.partition("=")[2]
    if len(value) >= 2:
        assert value not in str(info.value)


@pytest.mark.parametrize("path, argv", [("/usr/bin/env", ["/usr/bin/env", "ollama", "serve"]),
                                        ("/usr/bin/ollama", ["/usr/bin/ollama", "serve", "--verbose"]),
                                        ("/home/someone/ollama", ["/home/someone/ollama", "serve"])])
def test_the_builder_refuses_unpublishable_exec_start(ro_clone, path, argv):
    with pytest.raises(manifest.ManifestRefused):
        manifest.build(str(ro_clone.path), _execution_with(ro_clone, exec_start=(path, argv)))


def test_allowed_values_appear_in_clear_in_the_manifest(ro_clone):
    text = ro_clone.manifest_bytes.decode()
    for value in ("OLLAMA_CONTEXT_LENGTH=8192", "PATH=/usr/local/bin:/usr/bin:/bin", "/usr/bin/ollama",
                  "-e <clone>", "pydantic==2.9.2", "sha256:" + "a" * 64):
        assert value in text


def test_observe_writes_what_the_runner_then_observes(tmp_path, ro_clone, ollama_stub):
    fake = dbl.make_systemctl(tmp_path / "bin")
    endpoint = ollama_stub.endpoint()
    exe = manifest.observe(str(ro_clone.path), unit="ollama.service", model="qwen3:8b", embedder="hashing",
                           endpoint=endpoint, freeze=lambda: dbl.freeze_text(ro_clone.path), systemctl=fake.path)
    out = tmp_path / "out"
    out.mkdir(mode=0o700)
    data = canonical_dumps(exe.model_dump())
    from evaluation.ledger import write_private
    write_private(out / "execution.json", data, what="execution")
    assert manifest.load_execution((out / "execution.json").read_bytes()) == exe
    state = identity.read_unit("ollama.service", fake.path)
    assert identity.server_problems(state, identity.manager_environment(fake.path), exe.server.model_dump()) == []
    assert exe.ollama.model_dump() == __import__("evaluation.probe", fromlist=["x"]).ollama_identity(endpoint,
                                                                                                   "qwen3:8b")
    assert exe.python.freeze == identity.normalize_freeze(dbl.freeze_text(ro_clone.path), str(ro_clone.path))


def test_observe_refuses_an_unpublishable_server_setting(tmp_path, ro_clone, ollama_stub):
    fake = dbl.make_systemctl(tmp_path / "bin")
    fake.set(environment=["OLLAMA_MODELS=/srv/models"])
    with pytest.raises(manifest.ManifestRefused):
        manifest.observe(str(ro_clone.path), unit="ollama.service", model="qwen3:8b", embedder="hashing",
                         endpoint=ollama_stub.endpoint(), freeze=lambda: dbl.freeze_text(ro_clone.path),
                         systemctl=fake.path)


def test_the_build_command_writes_a_private_manifest_whatever_the_umask(ro_clone, tmp_path):
    out = dbl.private_dir(tmp_path / "out")
    exe = out / "execution.json"
    from evaluation.ledger import write_private
    write_private(exe, canonical_dumps(dbl.execution_dict(ro_clone.path)), what="execution")
    proc = subprocess.run([sys.executable, "-s", "-B", "-P", str(ro_clone.path / "evaluation" / "manifest.py"),
                           "build", "--clone", os.path.realpath(ro_clone.path), "--execution", str(exe), "--out",
                           str(out / "manifest.json")], capture_output=True, text=True, umask=0,
                          env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})
    assert proc.returncode == 0, proc.stderr
    assert stat.S_IMODE(os.stat(out / "manifest.json").st_mode) == 0o600
    # The freeze and HEAD of the committed clone do not change the file list, so the builds agree.
    assert json.loads((out / "manifest.json").read_bytes())["files"] == json.loads(ro_clone.manifest_bytes)["files"]


def test_the_build_command_refuses_a_clone_it_is_not_in(ro_clone, tmp_path):
    proc = subprocess.run([sys.executable, "-s", "-B", "-P", str(ro_clone.path / "evaluation" / "manifest.py"),
                           "build", "--clone", str(tmp_path), "--execution", "x", "--out", "y"],
                          capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert proc.returncode == 2
    assert proc.stderr == "manifest: error: --clone must be the clone this tool runs from\n"


def test_the_tools_refuse_to_run_without_their_interpreter_flags(ro_clone):
    proc = subprocess.run([sys.executable, str(ro_clone.path / "evaluation" / "manifest.py"), "build"],
                          capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert proc.returncode == 2 and proc.stderr == "manifest: error: must be started with python -s -B -P\n"
