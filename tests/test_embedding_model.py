"""The pinned embedding model is loaded only from a verified local directory, offline (DD-027).

These tests run without the real model and without the network. Fake
sentence_transformers and huggingface_hub packages are written to a temporary
directory and imported in their place: the fake huggingface_hub reads
HF_HUB_OFFLINE when it is imported, as the real one does, and the fake
SentenceTransformer records how it was constructed.
"""

import ast
import hashlib
import io
import json
import os
import socket
import sys
from pathlib import Path

import pytest

from triage import cli, embedding_model
from triage.config import REPO_ROOT, Settings
from triage.embedding_model import ModelUnavailable, load_manifest, verify_model_dir
from triage.enrich import enrich
from triage.evidence import EvidenceLog
from triage.ingest import load_alert
from triage.tools import build_tools, run_tool, runbooks

REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
SAFETENSORS_SHA256 = "53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db"
PATHS = ["modules.json", "config_sentence_transformers.json", "sentence_bert_config.json", "config.json",
         "model.safetensors", "tokenizer.json", "tokenizer_config.json", "vocab.txt",
         "special_tokens_map.json", "1_Pooling/config.json"]
SAMPLE = REPO_ROOT / "samples" / "alerts" / "wazuh" / "encoded_powershell.json"
LIBRARIES = ("sentence_transformers", "huggingface_hub")

FAKE_HUB_CONSTANTS = '''import os
HF_HUB_OFFLINE = os.environ.get("HF_HUB_OFFLINE", "").upper() in {"1", "ON", "YES", "TRUE"}
ENV_AT_IMPORT = {k: os.environ.get(k) for k in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY")}
'''
FAKE_SENTENCE_TRANSFORMERS = '''import huggingface_hub.constants  # the real library imports huggingface_hub too
from triage.tools.runbooks import HashingEmbedder

CALLS = []


class SentenceTransformer:
    def __init__(self, model_name_or_path, **kwargs):
        CALLS.append((model_name_or_path, kwargs))
        self._embedder = HashingEmbedder()

    def encode(self, texts, normalize_embeddings=True, convert_to_numpy=True):
        return self._embedder.embed(list(texts))
'''


@pytest.fixture
def isolated(monkeypatch):
    """No embedding library imported, and the environment and index cache restored afterwards."""
    saved_environ = dict(os.environ)
    for name in list(sys.modules):
        if name.split(".")[0] in LIBRARIES:
            monkeypatch.delitem(sys.modules, name)
    runbooks.get_index.cache_clear()
    yield
    for name in list(sys.modules):
        if name.split(".")[0] in LIBRARIES:
            del sys.modules[name]
    os.environ.clear()
    os.environ.update(saved_environ)
    runbooks.get_index.cache_clear()


@pytest.fixture
def fake_library(tmp_path, monkeypatch, isolated):
    """Install the fake libraries on sys.path; returns a function that gives the fake module once imported."""
    root = tmp_path / "fakes"
    (root / "huggingface_hub").mkdir(parents=True)
    (root / "huggingface_hub" / "__init__.py").write_text("from . import constants\n")
    (root / "huggingface_hub" / "constants.py").write_text(FAKE_HUB_CONSTANTS)
    (root / "sentence_transformers").mkdir()
    (root / "sentence_transformers" / "__init__.py").write_text(FAKE_SENTENCE_TRANSFORMERS)
    monkeypatch.syspath_prepend(str(root))
    return lambda: sys.modules.get("sentence_transformers")


@pytest.fixture
def model(tmp_path, monkeypatch):
    """A verified ten-file model directory with small stand-in contents, and its manifest in place of the real one."""
    directory = tmp_path / "model"
    files = []
    for path in PATHS:
        data = f"stand-in for {path}\n".encode()
        target = directory / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files.append({"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest_path = tmp_path / "embedding_model.json"
    manifest_path.write_text(json.dumps({"repo_id": "sentence-transformers/all-MiniLM-L6-v2", "revision": REVISION,
                                         "license": "apache-2.0", "files": files}))
    monkeypatch.setattr(embedding_model, "MANIFEST_PATH", manifest_path)
    return directory, load_manifest(manifest_path)


# --- The committed manifest ----------------------------------------------------------

def test_manifest_pins_the_safetensors_model():
    """The committed manifest is not the reviewed pin: revision, license, file set, weights or formats differ."""
    manifest = load_manifest()
    assert (manifest.repo_id, manifest.revision, manifest.license) == (
        "sentence-transformers/all-MiniLM-L6-v2", REVISION, "apache-2.0")
    assert [f.path for f in manifest.files] == PATHS
    weights = next(f for f in manifest.files if f.path == "model.safetensors")
    assert (weights.size, weights.sha256) == (90868376, SAFETENSORS_SHA256)
    assert manifest.directories == {"1_Pooling"}
    assert not [f for f in manifest.files if Path(f.path).suffix in embedding_model.FORBIDDEN_SUFFIXES]


@pytest.mark.parametrize("change", [
    "not json", "extra key", "short revision", "uppercase sha256", "zero size", "boolean size", "duplicate path",
    "absolute path", "dot-dot path", "hidden path", "pickle weights", "python file", "no files",
])
def test_malformed_manifest_is_refused(tmp_path, change):
    """A manifest with an unexpected shape, value, path or file format is accepted."""
    good = {"repo_id": "a/b", "revision": REVISION, "license": "apache-2.0",
            "files": [{"path": "model.safetensors", "size": 4, "sha256": "0" * 64}]}
    entry = good["files"][0]
    text = None
    if change == "not json":
        text = "{"
    elif change == "extra key":
        good["mirror"] = "x"
    elif change == "short revision":
        good["revision"] = REVISION[:12]
    elif change == "uppercase sha256":
        entry["sha256"] = "A" * 64
    elif change == "zero size":
        entry["size"] = 0
    elif change == "boolean size":
        entry["size"] = True
    elif change == "duplicate path":
        good["files"].append(dict(entry))
    elif change == "no files":
        good["files"] = []
    else:
        entry["path"] = {"absolute path": "/etc/passwd", "dot-dot path": "../model.safetensors",
                         "hidden path": ".cache/model.safetensors", "pickle weights": "pytorch_model.bin",
                         "python file": "modeling.py"}[change]
    path = tmp_path / "manifest.json"
    path.write_text(text if text is not None else json.dumps(good))
    with pytest.raises(ModelUnavailable):
        load_manifest(path)


# --- The local directory -------------------------------------------------------------

def test_verified_directory_is_returned_absolute(model, monkeypatch):
    """A directory that matches the manifest is refused, or its path is not returned absolute."""
    directory, manifest = model
    monkeypatch.chdir(directory.parent)
    root = verify_model_dir(Path(directory.name), manifest)
    assert root.is_absolute() and root == directory


def _break(directory: Path, change: str) -> Path:
    """Apply one unexpected change to a verified model directory; the path to verify."""
    if change == "missing file":
        (directory / "vocab.txt").unlink()
    elif change == "extra file":
        (directory / "notes.txt").write_text("x")
    elif change == "extra pickle weights":
        (directory / "pytorch_model.bin").write_bytes(b"\x80\x04")
    elif change == "hidden file":
        (directory / ".hidden").write_text("x")
    elif change == "cache metadata":
        (directory / ".cache" / "huggingface").mkdir(parents=True)
    elif change == "lock file":
        (directory / "model.safetensors.lock").write_text("")
    elif change == "extra directory":
        (directory / "2_Dense").mkdir()
    elif change == "size mismatch":
        (directory / "config.json").write_bytes(b"{}")
    elif change == "hash mismatch":
        data = (directory / "config.json").read_bytes()
        (directory / "config.json").write_bytes(bytes([data[0] ^ 1]) + data[1:])
    elif change == "symlinked file":
        real = directory.parent / "elsewhere.json"
        real.write_bytes((directory / "config.json").read_bytes())
        (directory / "config.json").unlink()
        (directory / "config.json").symlink_to(real)
    elif change == "symlinked subdirectory":
        (directory / "1_Pooling").rename(directory.parent / "pooling")
        (directory / "1_Pooling").symlink_to(directory.parent / "pooling", target_is_directory=True)
    elif change == "symlinked root":
        directory.rename(directory.parent / "real-model")
        directory.symlink_to(directory.parent / "real-model", target_is_directory=True)
    elif change == "fifo instead of a file":
        (directory / "vocab.txt").unlink()
        os.mkfifo(directory / "vocab.txt")
    elif change == "file instead of the directory":
        return directory / "config.json"
    elif change == "absent":
        return directory.parent / "no-such-model"
    return directory


@pytest.mark.parametrize("change", [
    "missing file", "extra file", "extra pickle weights", "hidden file", "cache metadata", "lock file",
    "extra directory", "size mismatch", "hash mismatch", "symlinked file", "symlinked subdirectory",
    "symlinked root", "fifo instead of a file", "file instead of the directory", "absent",
])
def test_unexpected_contents_are_refused(model, change):
    """A model directory that differs from the manifest in any way is accepted."""
    # Windows needs extra privileges for symlinks and has no FIFOs at a path.
    if change in ("symlinked file", "symlinked subdirectory", "symlinked root", "fifo instead of a file") \
            and os.name != "posix":
        pytest.skip("POSIX symlinks and FIFOs")
    directory, manifest = model
    path = _break(directory, change)
    with pytest.raises(ModelUnavailable) as caught:
        verify_model_dir(path, manifest)
    assert str(caught.value) == ModelUnavailable.MESSAGE and str(directory) not in str(caught.value)


# --- Loading ---------------------------------------------------------------------------

def test_loader_passes_only_local_offline_arguments(model, fake_library):
    """The model is constructed from something other than its absolute local path, or without the offline arguments."""
    directory, manifest = model
    embedding_model.load_sentence_transformer(directory, manifest)
    (path, kwargs), = fake_library().CALLS
    assert path == str(directory) and Path(path).is_absolute()
    assert kwargs == {"local_files_only": True, "trust_remote_code": False, "model_kwargs": {"use_safetensors": True}}


def test_relative_setting_reaches_the_library_as_an_absolute_path(model, fake_library, monkeypatch):
    """A relative model directory is passed on as given, which older libraries would treat as a Hub repo ID."""
    directory, manifest = model
    monkeypatch.chdir(directory.parent)
    embedding_model.load_sentence_transformer(Path(directory.name), manifest)
    (path, _), = fake_library().CALLS
    assert path == str(directory) and Path(path).is_absolute()


def test_offline_mode_is_set_before_import(model, fake_library):
    """huggingface_hub is first imported without offline mode, telemetry off and the transformers switch."""
    directory, manifest = model
    embedding_model.load_sentence_transformer(directory, manifest)
    constants = sys.modules["huggingface_hub.constants"]
    assert constants.HF_HUB_OFFLINE is True
    assert constants.ENV_AT_IMPORT == embedding_model.OFFLINE_VARIABLES


def test_library_imported_without_offline_mode_is_refused(model, fake_library):
    """A library already imported in online mode still gets the model loaded."""
    directory, manifest = model
    os.environ.pop("HF_HUB_OFFLINE", None)
    os.environ.pop("TRANSFORMERS_OFFLINE", None)
    import huggingface_hub  # noqa: F401 - imported early, online, as another component might

    with pytest.raises(ModelUnavailable):
        embedding_model.load_sentence_transformer(directory, manifest)
    assert fake_library() is None or fake_library().CALLS == []


def test_unverified_directory_is_never_loaded(model, fake_library):
    """A directory that fails verification still reaches the library."""
    directory, manifest = model
    (directory / "pytorch_model.bin").write_bytes(b"\x80\x04")
    with pytest.raises(ModelUnavailable):
        embedding_model.load_sentence_transformer(directory, manifest)
    assert fake_library() is None


def test_missing_library_is_unavailable(model, isolated, monkeypatch):
    """Without sentence-transformers installed, loading fails with something other than the fixed error."""
    directory, manifest = model
    monkeypatch.setitem(sys.modules, "sentence_transformers", None)   # makes the import raise ImportError
    with pytest.raises(ModelUnavailable):
        embedding_model.load_sentence_transformer(directory, manifest)


def test_library_failure_message_is_fixed(model, fake_library):
    """A failure inside the library reaches the caller with its own message, which can hold a path."""
    directory, manifest = model
    (directory.parent / "fakes" / "sentence_transformers" / "__init__.py").write_text(
        "import huggingface_hub.constants\n"
        "class SentenceTransformer:\n"
        "    def __init__(self, path, **kwargs):\n"
        "        raise OSError('cannot read ' + path)\n")
    with pytest.raises(ModelUnavailable) as caught:
        embedding_model.load_sentence_transformer(directory, manifest)
    assert str(caught.value) == ModelUnavailable.MESSAGE


SECRET_PATH = "/home/operator/secret-project/models"


def _fake_import_raises(directory: Path, statement: str) -> None:
    (directory.parent / "fakes" / "sentence_transformers" / "__init__.py").write_text(
        "import huggingface_hub.constants\n" + statement + "\n")


def test_library_import_failure_is_the_fixed_error(model, fake_library):
    """A library that fails while being imported leaks its own message, which can hold a path."""
    directory, manifest = model
    _fake_import_raises(directory, f"raise OSError('cannot open {SECRET_PATH}/cache.bin')")
    with pytest.raises(ModelUnavailable) as caught:
        embedding_model.load_sentence_transformer(directory, manifest)
    error = caught.value
    assert str(error) == ModelUnavailable.MESSAGE and SECRET_PATH not in repr(error)
    assert error.__cause__ is None and error.__suppress_context__


def test_library_import_failure_reaches_the_tool_as_the_fixed_error(model, fake_library):
    """runbook_search reports a failed library import with the library's own text."""
    directory, _ = model
    _fake_import_raises(directory, f"raise RuntimeError('{SECRET_PATH} is not writable')")
    tools = build_tools(Settings(embedder="minilm", embedding_model_dir=directory))
    result = run_tool(tools, "runbook_search", {"query": "encoded powershell"})
    assert result.status == "error" and result.error == f"ModelUnavailable: {ModelUnavailable.MESSAGE}"
    assert SECRET_PATH not in json.dumps(result.model_dump())


def test_interrupt_during_library_import_is_not_swallowed(model, fake_library):
    """An interrupt while the library is imported is turned into an ordinary error."""
    directory, manifest = model
    _fake_import_raises(directory, "raise KeyboardInterrupt")
    with pytest.raises(KeyboardInterrupt):
        embedding_model.load_sentence_transformer(directory, manifest)


# --- Fail closed in the tool, the enrichment and the CLI ----------------------------------

def test_runbook_search_reports_an_unavailable_model_as_an_error(tmp_path, isolated):
    """runbook_search with a missing model returns something other than an error result with the fixed message."""
    tools = build_tools(Settings(embedder="minilm", embedding_model_dir=tmp_path / "missing"))
    result = run_tool(tools, "runbook_search", {"query": "encoded powershell"})
    assert result.status == "error" and result.error == f"ModelUnavailable: {ModelUnavailable.MESSAGE}"


def test_enrichment_is_degraded_without_the_model(tmp_path, isolated):
    """Enrichment with a missing model is reported complete."""
    settings = Settings(embedder="minilm", embedding_model_dir=tmp_path / "missing")
    alert = load_alert(SAMPLE.read_text(encoding="utf-8"), fmt="wazuh")
    enrichment = enrich(alert, EvidenceLog(build_tools(settings)), settings)
    assert enrichment.status == "degraded"
    assert any(r.tool == "runbook_search" and r.status == "error" for r in enrichment.evidence)


def _cli(monkeypatch, tmp_path, *argv):
    out, err = io.BytesIO(), io.StringIO()
    wrapped = io.TextIOWrapper(out)
    with monkeypatch.context() as m:
        m.setattr(sys, "stdout", wrapped)
        m.setattr(sys, "stderr", err)
        m.chdir(tmp_path)
        code = cli.main(list(argv))
    wrapped.flush()
    wrapped.detach()
    return code, out.getvalue(), err.getvalue()


def _point_cli_at(monkeypatch, directory):
    monkeypatch.setenv("TRIAGE_EMBEDDER", "minilm")
    monkeypatch.setenv("TRIAGE_BACKEND", "heuristic")
    monkeypatch.setenv("TRIAGE_EMBEDDING_MODEL_DIR", str(directory))


@pytest.mark.parametrize("state", ["missing", "altered"])
def test_cli_refuses_a_missing_or_altered_model(model, tmp_path, monkeypatch, isolated, state):
    """The CLI runs with a missing or altered model instead of stopping with exit 2 and the fixed message."""
    directory, _ = model
    if state == "altered":
        (directory / "pytorch_model.bin").write_bytes(b"\x80\x04")
    _point_cli_at(monkeypatch, directory if state == "altered" else tmp_path / "none")
    code, stdout, stderr = _cli(monkeypatch, tmp_path, "--format", "wazuh", str(SAMPLE), "--no-audit-log")
    assert (code, stdout) == (cli.USAGE, b"")
    assert stderr == f"{cli.PROG}: {cli.NOTICE_NO_AUDIT}\n{cli.PROG}: error: {cli.E_EMBEDDING_MODEL}\n"


@pytest.mark.skipif(not cli._audit_supported(), reason="the audit log needs POSIX file operations")
def test_model_check_comes_before_the_audit_log(model, tmp_path, monkeypatch, isolated):
    """A missing model still creates the audit log or its directory before the CLI stops."""
    _point_cli_at(monkeypatch, tmp_path / "none")
    log = tmp_path / "logs" / "audit.jsonl"
    code, stdout, stderr = _cli(monkeypatch, tmp_path, "--format", "wazuh", str(SAMPLE), "--audit-log", str(log))
    assert (code, stdout, stderr) == (cli.USAGE, b"", f"{cli.PROG}: error: {cli.E_EMBEDDING_MODEL}\n")
    assert not log.exists() and not log.parent.exists()


# --- No network ----------------------------------------------------------------------------

def test_no_connection_during_a_minilm_run(model, fake_library, tmp_path, monkeypatch, no_network):
    """A full CLI run with the minilm embedder and the rule-based backend tries to open a connection."""
    directory, _ = model
    _point_cli_at(monkeypatch, directory)
    code, stdout, stderr = _cli(monkeypatch, tmp_path, "--format", "wazuh", str(SAMPLE), "--no-audit-log")
    assert code == cli.OK and no_network.attempts == []
    assert fake_library() is not None and len(fake_library().CALLS) == 1   # the fake model was really used
    assert json.loads(stdout)["status"] in ("triaged", "insufficient_data")


def test_network_guard_catches_a_connection(no_network):
    """The guard used above lets a connection attempt through, so its empty record would prove nothing."""
    with pytest.raises(OSError):
        socket.create_connection(("192.0.2.1", 9), timeout=1)
    with pytest.raises(OSError):
        socket.getaddrinfo("example.invalid", 443)
    with socket.socket() as s, pytest.raises(OSError):
        s.connect(("192.0.2.1", 9))
    assert no_network.attempts == ["create_connection", "getaddrinfo", "connect"]


def test_triage_never_imports_the_hub_or_its_download_functions():
    """Code under triage/ imports huggingface_hub or names a Hub download function."""
    offenders = []
    for path in sorted((REPO_ROOT / "triage").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            names = ([a.name for a in node.names] if isinstance(node, ast.Import)
                     else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            if any(n.split(".")[0] == "huggingface_hub" for n in names):
                offenders.append(path.name)
        if "hf_hub_download" in source or "snapshot_download" in source:
            offenders.append(path.name)
    assert offenders == []
