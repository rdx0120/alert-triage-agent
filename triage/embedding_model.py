"""The pinned embedding model: its manifest, the local-directory check, and offline loading (DD-027).

At triage time the all-MiniLM-L6-v2 model is loaded only from a local
directory whose contents match data/embedding_model.json byte for byte: ten
files of one pinned upstream revision, safetensors weights only. Nothing here
contacts the Hugging Face Hub, and nothing here can download a model; only
scripts/fetch_embedding_model.py does, when the operator runs it.

Why each layer exists, from the most to the least library-independent:
1. The directory is verified before every load: exactly the manifest's files,
   regular files only, each with its recorded size and SHA-256. An extra
   pytorch_model.bin (pickle) or a bundled .py file is refused, so neither can
   be loaded or run.
2. Offline mode is enforced. huggingface_hub reads HF_HUB_OFFLINE once, when
   it is imported, so it is set before the first import, and the load is
   refused if the imported library is not in offline mode (for example after
   an earlier import without it). In offline mode the library's HTTP session
   refuses every request.
3. The model is loaded by its absolute path. sentence-transformers before
   3.4.1 asks the Hub for model information on every load, whatever
   local_files_only says; huggingface_hub rejects an absolute path as a repo
   ID before sending anything, while a relative path such as
   models/all-MiniLM-L6-v2 would be a valid repo ID.
4. local_files_only=True, trust_remote_code=False and use_safetensors=True,
   which cover the same ground from sentence-transformers 3.4.1 on.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .config import REPO_ROOT

MANIFEST_PATH = REPO_ROOT / "data" / "embedding_model.json"

# Set before huggingface_hub is first imported; it reads them only then.
OFFLINE_VARIABLES = {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1"}

# Weight and code formats that are never part of the model directory.
FORBIDDEN_SUFFIXES = frozenset({".bin", ".pt", ".pth", ".pkl", ".h5", ".ot", ".onnx", ".py", ".msgpack"})

_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CHUNK = 1 << 20


class ModelUnavailable(Exception):
    """The local model is missing, does not match its manifest, or cannot be loaded offline.

    The message is fixed: it never names a path, a file or library output.
    """

    MESSAGE = "embedding model is missing or does not match its manifest"

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


@dataclass(frozen=True)
class ModelFile:
    path: str      # relative POSIX path inside the model directory
    size: int
    sha256: str


@dataclass(frozen=True)
class Manifest:
    repo_id: str
    revision: str
    license: str
    files: tuple[ModelFile, ...]

    @property
    def directories(self) -> frozenset[str]:
        """Every directory below the root that the files need, as relative POSIX paths."""
        return frozenset(str(p) for f in self.files for p in PurePosixPath(f.path).parents if str(p) != ".")


def _valid_relative_path(path: object) -> bool:
    if not isinstance(path, str) or not path or not path.isascii() or "\\" in path:
        return False
    parts = PurePosixPath(path).parts
    return (not path.startswith("/") and all(p not in ("", ".", "..") and not p.startswith(".") for p in parts)
            and PurePosixPath(path).suffix.lower() not in FORBIDDEN_SUFFIXES)


def load_manifest(path: Path | None = None) -> Manifest:
    """The committed manifest, checked strictly; anything unexpected is ModelUnavailable."""
    try:
        data = json.loads(Path(path or MANIFEST_PATH).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) != {"repo_id", "revision", "license", "files"}:
            raise ValueError
        repo_id, revision, license_, entries = data["repo_id"], data["revision"], data["license"], data["files"]
        if not (isinstance(repo_id, str) and repo_id.count("/") == 1 and isinstance(license_, str)
                and isinstance(revision, str) and _HEX40.fullmatch(revision) and isinstance(entries, list) and entries):
            raise ValueError
        files = []
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
                raise ValueError
            size, digest = entry["size"], entry["sha256"]
            if (not _valid_relative_path(entry["path"]) or type(size) is not int or size <= 0
                    or not isinstance(digest, str) or not _HEX64.fullmatch(digest)):
                raise ValueError
            files.append(ModelFile(entry["path"], size, digest))
        if len({f.path for f in files}) != len(files):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise ModelUnavailable() from None
    return Manifest(repo_id, revision, license_, tuple(files))


def _sha256_of(path: Path, size: int) -> str | None:
    """The SHA-256 of a regular file of exactly `size` bytes, opened without following a link; else None."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != size:
            return None
        digest = hashlib.sha256()
        while chunk := os.read(fd, _CHUNK):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _check_tree(root: Path, manifest: Manifest) -> None:
    expected_files = {f.path: f for f in manifest.files}
    expected_dirs = manifest.directories
    seen: set[str] = set()
    pending = [""]
    while pending:
        relative = pending.pop()
        directory = root / relative if relative else root
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode):   # lstat: a symlink is never a directory here
            raise ModelUnavailable()
        with os.scandir(directory) as entries:
            for entry in entries:
                name = f"{relative}/{entry.name}" if relative else entry.name
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode) and name in expected_dirs:
                    pending.append(name)
                elif stat.S_ISREG(mode) and name in expected_files:
                    seen.add(name)
                else:
                    # A symlink, FIFO, device, hidden file, cache metadata, lock
                    # file or any other entry the manifest does not list.
                    raise ModelUnavailable()
    if seen != set(expected_files):
        raise ModelUnavailable()
    # The walk above refused every link inside the directory, so these opens
    # only reach the listed files; each is hashed in full.
    for f in manifest.files:
        if _sha256_of(root.joinpath(*PurePosixPath(f.path).parts), f.size) != f.sha256:
            raise ModelUnavailable()


def verify_model_dir(path: Path | str, manifest: Manifest) -> Path:
    """The model directory's absolute path, once its contents match the manifest exactly."""
    try:
        root = Path(path).absolute()
        _check_tree(root, manifest)
        return root
    except ModelUnavailable:
        raise
    except (OSError, ValueError):
        raise ModelUnavailable() from None


def load_sentence_transformer(path: Path | str, manifest: Manifest | None = None):
    """A SentenceTransformer loaded from the verified local directory, offline; else ModelUnavailable."""
    root = verify_model_dir(path, manifest or load_manifest())
    if "huggingface_hub" not in sys.modules:
        os.environ.update(OFFLINE_VARIABLES)
    try:
        from sentence_transformers import SentenceTransformer  # optional dependency
    except Exception:  # noqa: BLE001 - not installed, or failed while importing; its text can hold paths
        # Exception, not BaseException: an interrupt still propagates.
        raise ModelUnavailable() from None
    constants = sys.modules.get("huggingface_hub.constants")
    if constants is None or getattr(constants, "HF_HUB_OFFLINE", False) is not True:
        raise ModelUnavailable()
    try:
        return SentenceTransformer(str(root), local_files_only=True, trust_remote_code=False,
                                   model_kwargs={"use_safetensors": True})
    except Exception:  # noqa: BLE001 - library errors can carry paths; the message stays fixed
        raise ModelUnavailable() from None
