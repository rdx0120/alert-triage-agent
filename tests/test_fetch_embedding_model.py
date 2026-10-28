"""scripts/fetch_embedding_model.py installs exactly the verified files, or nothing (DD-027).

No network: a fake huggingface_hub, written to a temporary directory, stands
in for the real one. Like the real library it reads its settings when it is
imported, returns snapshot paths that are symlinks into a blobs/ directory,
and leaves lock and metadata files beside them. It records every call and the
environment it saw at import.
"""

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

from triage.config import REPO_ROOT
from triage.embedding_model import Manifest, ModelFile, verify_model_dir

pytestmark = pytest.mark.skipif(not hasattr(os, "symlink") or os.name != "posix",
                                reason="the fake cache uses POSIX symlinks, as the real one does")

REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
PATHS = ["modules.json", "config_sentence_transformers.json", "sentence_bert_config.json", "config.json",
         "model.safetensors", "tokenizer.json", "tokenizer_config.json", "vocab.txt",
         "special_tokens_map.json", "1_Pooling/config.json"]
CONTENT = {p: f"stand-in for {p}\n".encode() for p in PATHS}
MANIFEST = Manifest("sentence-transformers/all-MiniLM-L6-v2", REVISION, "apache-2.0", tuple(
    ModelFile(p, len(d), hashlib.sha256(d).hexdigest()) for p, d in CONTENT.items()))
TOKENS = ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HF_OIDC_RESOURCE", "HF_OIDC_ID_TOKEN")
WATCHED = ("HF_HOME", "HF_HUB_CACHE", "HF_XET_CACHE", "HF_TOKEN_PATH", "HF_HUB_DISABLE_IMPLICIT_TOKEN",
           "HF_HUB_DISABLE_TELEMETRY", "HF_ENDPOINT") + TOKENS

FAKE_CONSTANTS = '''import os
ENDPOINT = os.getenv("HF_ENDPOINT", "https://huggingface.co").rstrip("/")
HF_HUB_DISABLE_IMPLICIT_TOKEN = os.environ.get("HF_HUB_DISABLE_IMPLICIT_TOKEN", "").upper() in {"1", "ON", "YES", "TRUE"}
if os.environ.get("FAKE_MODE") == "ignores_settings":
    HF_HUB_DISABLE_IMPLICIT_TOKEN = False
'''
FAKE_HUB = '''import hashlib, json, os
from pathlib import Path
from . import constants

MODE = os.environ.get("FAKE_MODE", "ok")
if MODE == "import_error":
    raise OSError("cannot open /home/operator/secret-project/.cache/hub")
if MODE == "import_interrupt":
    raise KeyboardInterrupt
CONTENT = {k: bytes.fromhex(v) for k, v in json.loads(Path(os.environ["FAKE_CONTENT"]).read_text()).items()}


def _log(**record):
    with open(os.environ["FAKE_LOG"], "a") as f:
        f.write(json.dumps(record) + "\\n")


_log(event="import", env={k: os.environ.get(k) for k in json.loads(os.environ["FAKE_WATCHED"])})
_calls = 0


def hf_hub_download(repo_id, filename, *, revision=None, cache_dir=None, token=None, **extra):
    global _calls
    _calls += 1
    _log(event="download", repo_id=repo_id, filename=filename, revision=revision, cache_dir=cache_dir,
         token=repr(token), extra=sorted(extra))
    if MODE == "interrupt" and _calls == 3:
        raise KeyboardInterrupt
    if MODE == "error":
        raise OSError("connection to https://cdn.example.invalid/secret-path failed")
    data = CONTENT[filename]
    if MODE == "mismatch" and filename == "vocab.txt":
        data = data[:-1] + b"?"
    root = Path(cache_dir) / "models--sentence-transformers--all-MiniLM-L6-v2"
    blob = root / "blobs" / hashlib.sha256(data).hexdigest()
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(data)
    (blob.parent / (blob.name + ".lock")).write_text("")
    snapshot = root / "snapshots" / revision / filename
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    (root / "refs").mkdir(exist_ok=True)
    (root / "refs" / "main").write_text(revision)
    if MODE == "not_a_file" and filename == "config.json":
        snapshot.mkdir()
    elif MODE == "outside_cache" and filename == "config.json":
        # Inside the temporary directory, but outside the dedicated cache.
        other = Path(cache_dir).parent / "elsewhere" / filename
        other.parent.mkdir(parents=True, exist_ok=True)
        other.write_bytes(data)
        snapshot.symlink_to(other)
    else:
        snapshot.symlink_to(blob)
    if MODE == "poison_stage" and _calls == len(CONTENT):
        (Path(cache_dir).parent / "stage" / "extra.txt").write_text("not in the manifest")
    return str(snapshot)
'''


def _load_script():
    spec = importlib.util.spec_from_file_location("fetch_embedding_model", REPO_ROOT / "scripts" / "fetch_embedding_model.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fetch(tmp_path, monkeypatch):
    """Run the script in-process against the fake library; returns (exit code, stdout, stderr, log, target)."""
    saved_environ = dict(os.environ)
    for name in list(sys.modules):
        if name.split(".")[0] == "huggingface_hub":
            monkeypatch.delitem(sys.modules, name)
    fakes = tmp_path / "fakes" / "huggingface_hub"
    fakes.mkdir(parents=True)
    (fakes / "__init__.py").write_text(FAKE_HUB)
    (fakes / "constants.py").write_text(FAKE_CONSTANTS)
    monkeypatch.syspath_prepend(str(fakes.parent))
    content = tmp_path / "content.json"
    content.write_text(json.dumps({k: v.hex() for k, v in CONTENT.items()}))
    log = tmp_path / "log.jsonl"
    target = tmp_path / "models" / "all-MiniLM-L6-v2"
    script = _load_script()

    def prepare(mode="ok", env=None):
        os.environ.update({"FAKE_MODE": mode, "FAKE_CONTENT": str(content), "FAKE_LOG": str(log),
                           "FAKE_WATCHED": json.dumps(WATCHED)})
        # Credentials in the caller's environment must never reach the library.
        os.environ.update({name: "parent-credential" for name in TOKENS})
        os.environ.pop("HF_ENDPOINT", None)
        os.environ.update(env or {})

    def run(mode="ok", env=None):
        prepare(mode, env)
        code = script.main(["--target", str(target)], manifest=MANIFEST)
        events = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        for name in list(sys.modules):   # a second run imports afresh, as a new process would
            if name.split(".")[0] == "huggingface_hub":
                del sys.modules[name]
        return code, events, target

    run.script, run.prepare, run.target, run.log = script, prepare, target, log
    yield run
    for name in list(sys.modules):
        if name.split(".")[0] == "huggingface_hub":
            del sys.modules[name]
    os.environ.clear()
    os.environ.update(saved_environ)


def _leftovers(target: Path) -> list[str]:
    return sorted(p.name for p in target.parent.iterdir() if p.name != target.name) if target.parent.exists() else []


def test_installs_exactly_the_manifest_files_as_regular_files(fetch, capsys):
    """The installed model holds a symlink, lock file, cache metadata or any file the manifest does not list."""
    code, events, target = fetch()
    assert code == 0 and capsys.readouterr().out == "installed and verified\n"
    assert verify_model_dir(target, MANIFEST) == target
    entries = sorted(str(p.relative_to(target)) for p in target.rglob("*"))
    assert entries == sorted(PATHS + ["1_Pooling"])
    assert not [p for p in target.rglob("*") if p.is_symlink()]
    assert _leftovers(target) == []


def test_downloads_are_bounded_pinned_and_tokenless(fetch):
    """The script asks for another file or revision, passes a token or another option, or caches outside its temporary directory."""
    code, events, target = fetch()
    assert code == 0
    downloads = [e for e in events if e["event"] == "download"]
    assert [e["filename"] for e in downloads] == PATHS
    assert all(e["revision"] == REVISION and e["token"] == "False" and e["extra"] == [] for e in downloads)
    assert all(e["repo_id"] == "sentence-transformers/all-MiniLM-L6-v2" for e in downloads)
    cache_dirs = {e["cache_dir"] for e in downloads}
    assert len(cache_dirs) == 1
    cache = Path(cache_dirs.pop())
    assert cache.name == "cache" and cache.parent.parent == target.parent and cache.parent.name.startswith(".fetch-")


def test_library_is_imported_isolated_and_without_credentials(fetch):
    """huggingface_hub is imported with a cache outside the temporary directory, an implicit token, telemetry or a credential."""
    code, events, target = fetch()
    env = next(e for e in events if e["event"] == "import")["env"]
    assert all(env[name] is None for name in TOKENS)
    assert env["HF_HUB_DISABLE_IMPLICIT_TOKEN"] == "1" and env["HF_HUB_DISABLE_TELEMETRY"] == "1"
    assert env["HF_ENDPOINT"] == "https://huggingface.co"
    homes = {Path(env[name]).parent for name in ("HF_HOME", "HF_HUB_CACHE", "HF_XET_CACHE", "HF_TOKEN_PATH")}
    assert len(homes) == 1 and homes.pop().parent == target.parent


@pytest.mark.parametrize("mode,message", [
    ("outside_cache", "a downloaded file resolved outside the dedicated cache directory"),
    ("mismatch", "a downloaded file does not match the manifest"),
    ("not_a_file", "a downloaded file does not match the manifest"),
    ("poison_stage", "the staged model does not match the manifest"),
    ("ignores_settings", "huggingface_hub did not apply the endpoint or implicit-token setting"),
    ("error", "a download failed"),
])
def test_a_failure_installs_nothing(fetch, capsys, mode, message):
    """A rejected or failed download leaves a model directory, a temporary directory or an unfixed message."""
    code, events, target = fetch(mode)
    err = capsys.readouterr().err
    assert code == 1 and err == f"fetch_embedding_model: error: {message}\n"
    assert "cdn.example.invalid" not in err and "secret-path" not in err
    assert not os.path.lexists(target) and _leftovers(target) == []


def test_interrupt_installs_nothing(fetch):
    """An interrupt during the downloads leaves a model directory or a temporary directory behind."""
    with pytest.raises(KeyboardInterrupt):
        fetch("interrupt")
    assert not os.path.lexists(fetch.target) and _leftovers(fetch.target) == []


def test_existing_verified_model_is_left_unchanged(fetch, capsys):
    """A second run replaces or downloads again over a model that already verifies."""
    fetch()
    target = fetch.target
    before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in target.rglob("*") if p.is_file()}
    capsys.readouterr()
    code, events, _ = fetch()
    assert code == 0 and capsys.readouterr().out == "already installed and verified; nothing changed\n"
    assert not [e for e in events[len(PATHS) + 1:] if e["event"] == "download"]
    assert {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in target.rglob("*") if p.is_file()} == before


def test_existing_mismatched_target_is_refused_unchanged(fetch, capsys):
    """A target that does not match the manifest is overwritten, extended or deleted."""
    target = fetch.target
    target.mkdir(parents=True)
    (target / "pytorch_model.bin").write_bytes(b"\x80\x04")
    code, events, _ = fetch()
    assert code == 1
    assert capsys.readouterr().err == ("fetch_embedding_model: error: "
                                       "the target exists and does not match the manifest; nothing changed\n")
    assert sorted(p.name for p in target.iterdir()) == ["pytorch_model.bin"] and events == []


def test_foreign_endpoint_is_refused_before_import(fetch, capsys):
    """HF_ENDPOINT pointing at another host lets the library be imported or a download start."""
    code, events, target = fetch(env={"HF_ENDPOINT": "https://mirror.example.invalid"})
    assert code == 1 and events == [] and not os.path.lexists(target)
    assert capsys.readouterr().err == "fetch_embedding_model: error: HF_ENDPOINT is not the official Hub endpoint\n"


def test_library_already_imported_is_refused(fetch, capsys):
    """A huggingface_hub imported before the script could apply its settings is used anyway."""
    fetch.prepare()
    import huggingface_hub  # noqa: F401 - the fake, imported early

    code = fetch.script.main(["--target", str(fetch.target)], manifest=MANIFEST)
    assert code == 1 and not os.path.lexists(fetch.target)
    assert capsys.readouterr().err == ("fetch_embedding_model: error: "
                                       "huggingface_hub was imported before its settings could be applied\n")


SECRET = "/home/operator/secret-project"


def _assert_nothing_installed(fetch, err, message):
    assert err == f"fetch_embedding_model: error: {message}\n" and SECRET not in err
    assert not os.path.lexists(fetch.target) and _leftovers(fetch.target) == []


def test_library_import_failure_is_a_fixed_message(fetch, capsys):
    """A huggingface_hub that fails while being imported leaks its own message or installs something."""
    code, events, target = fetch("import_error")
    assert code == 1
    _assert_nothing_installed(fetch, capsys.readouterr().err, "huggingface_hub could not be imported")


def test_interrupt_during_library_import_is_not_swallowed(fetch):
    """An interrupt while huggingface_hub is being imported is turned into an ordinary error."""
    with pytest.raises(KeyboardInterrupt):
        fetch("import_interrupt")
    assert not os.path.lexists(fetch.target) and _leftovers(fetch.target) == []


def test_write_failure_installs_nothing(fetch, capsys, monkeypatch):
    """A failed write to the staging directory raises a traceback, leaks a path or installs something."""
    real, calls = fetch.script._write_new, []

    def failing(path, data):
        calls.append(path)
        if len(calls) == 3:
            raise OSError(28, "No space left on device", f"{SECRET}/stage/config.json")
        real(path, data)

    monkeypatch.setattr(fetch.script, "_write_new", failing)
    code, events, target = fetch()
    assert code == 1 and len(calls) == 3
    _assert_nothing_installed(fetch, capsys.readouterr().err, "the model could not be written to the staging directory")


def test_unreadable_cached_file_installs_nothing(fetch, capsys, monkeypatch):
    """A downloaded file that cannot be read raises a traceback, leaks a path or installs something."""
    real = Path.read_bytes

    def unreadable(self):
        if self.name != "content.json" and "cache" in self.parts and self.parent.name == "blobs":
            raise PermissionError(13, "Permission denied", f"{SECRET}/cache/blob")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", unreadable)
    code, events, target = fetch()
    assert code == 1
    _assert_nothing_installed(fetch, capsys.readouterr().err, "a downloaded file could not be read")


def test_temporary_directory_failure_installs_nothing(fetch, capsys, monkeypatch):
    """A temporary directory that cannot be created raises a traceback or leaks a path."""
    def refuse(*args, **kwargs):
        raise PermissionError(13, "Permission denied", SECRET)

    monkeypatch.setattr(fetch.script.tempfile, "mkdtemp", refuse)
    code, events, target = fetch()
    assert code == 1 and events == []
    _assert_nothing_installed(fetch, capsys.readouterr().err,
                              "the target's parent or the temporary directory could not be created")


def test_rename_failure_installs_nothing(fetch, capsys, monkeypatch):
    """A failed final rename leaves a model directory or a temporary directory behind."""
    def refuse(src, dst):
        raise OSError(18, "Invalid cross-device link", SECRET)

    monkeypatch.setattr(fetch.script.os, "rename", refuse)
    code, events, target = fetch()
    assert code == 1
    _assert_nothing_installed(fetch, capsys.readouterr().err,
                              "the verified model could not be moved into place; nothing was installed")


def test_unsynced_install_is_reported_as_installed(fetch, capsys, monkeypatch):
    """A failed sync after the rename is reported as nothing installed, or as success."""
    real = fetch.script._fsync_dir

    def failing(path):
        if Path(path) == fetch.target.parent:
            raise OSError(5, "Input/output error", SECRET)
        real(path)

    monkeypatch.setattr(fetch.script, "_fsync_dir", failing)
    code, events, target = fetch()
    err = capsys.readouterr().err
    assert code == 1 and SECRET not in err
    assert err == ("fetch_embedding_model: error: the model was installed and verified, "
                   "but its directory entry may not be durable; run again to confirm\n")
    assert verify_model_dir(target, MANIFEST) == target and _leftovers(target) == []


def test_unexpected_error_is_a_fixed_message(fetch, capsys, monkeypatch):
    """An unexpected exception prints its own message or traceback, or leaves a temporary directory."""
    def broken(tmp):
        raise RuntimeError(f"state of {SECRET} is inconsistent")

    monkeypatch.setattr(fetch.script, "_isolate", broken)
    code, events, target = fetch()
    assert code == 1
    _assert_nothing_installed(fetch, capsys.readouterr().err, "unexpected error (RuntimeError)")
