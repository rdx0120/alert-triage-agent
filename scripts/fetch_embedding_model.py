"""Acquire the pinned embedding model into a local directory (DD-027).

Usage (needs the embeddings extra):
    python scripts/fetch_embedding_model.py [--target DIR]

The only code in this project that contacts the Hugging Face Hub. It
downloads exactly the ten files listed in data/embedding_model.json at the
pinned revision, checks each one's size and SHA-256, and installs them as
plain files into DIR (default: TRIAGE_EMBEDDING_MODEL_DIR, or
models/all-MiniLM-L6-v2). Triage then loads the model only from there, offline.

How the bytes reach DIR, and why:
- Every Hugging Face cache, the Xet chunk cache included, is redirected into
  a new temporary directory next to DIR before huggingface_hub is imported
  (the library reads these settings only at import). Nothing is left in
  ~/.cache.
- No token is sent or looked up: the model is public, implicit tokens are
  disabled, token variables are removed from this process, and every call
  passes token=False. HF_ENDPOINT must be the official Hub, because it would
  redirect every API request. Individual downloads can still be redirected by
  the Hub to its CDN or Xet storage hosts; the size and SHA-256 checks below
  are what make the bytes trustworthy, wherever they came from.
- hf_hub_download returns paths into its cache, which are symlinks into a
  blobs/ directory beside lock and metadata files. Each returned path must
  resolve inside the dedicated cache directory; its verified bytes are then
  written as a new regular file into a separate, clean staging directory, so
  no symlink, lock file or cache metadata can reach DIR.
- The staging directory is checked with the same function triage uses, then
  renamed into place in one step.

What a failure leaves behind:
- Any failure or interrupt before the rename (a download, a read, a write, a
  hash, the staging check, the rename itself) leaves no DIR.
- After the rename, the parent directory is synced so that the new entry
  survives a crash. If that sync fails, DIR is in place and verified, but its
  entry may not be durable: the script says so and exits 1. Running it again
  confirms the model, because an existing DIR that verifies is left as it is.
- The temporary directory is removed on every path; only a failure of that
  removal itself could leave it behind.

An existing DIR that already matches the manifest is left as it is; one that
does not match is refused and left unchanged.

Exit status: 0 when DIR holds the verified model and its entry was synced, 1
otherwise. Every message is fixed text: no library message, path or URL is
printed, because those can hold local paths or storage URLs.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath

from triage.config import get_settings
from triage.embedding_model import Manifest, ModelUnavailable, load_manifest, verify_model_dir

ENDPOINT = "https://huggingface.co"
# Token sources huggingface_hub reads implicitly (environment, OIDC exchange).
TOKEN_VARIABLES = ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HF_OIDC_RESOURCE", "HF_OIDC_ID_TOKEN")

M_INSTALLED = "installed and verified"
M_PRESENT = "already installed and verified; nothing changed"
E_PREFIX = "fetch_embedding_model: error: "
E_IMPORTED = "huggingface_hub was imported before its settings could be applied"
E_ENDPOINT = "HF_ENDPOINT is not the official Hub endpoint"
E_EXISTS = "the target exists and does not match the manifest; nothing changed"
E_LIBRARY = "huggingface_hub is not installed (install the embeddings extra)"
E_LIBRARY_FAILED = "huggingface_hub could not be imported"
E_PREPARE = "the target's parent or the temporary directory could not be created"
E_SETTINGS = "huggingface_hub did not apply the endpoint or implicit-token setting"
E_DOWNLOAD = "a download failed"
E_OUTSIDE = "a downloaded file resolved outside the dedicated cache directory"
E_READ = "a downloaded file could not be read"
E_MISMATCH = "a downloaded file does not match the manifest"
E_STAGE_WRITE = "the model could not be written to the staging directory"
E_STAGE = "the staged model does not match the manifest"
E_INSTALL = "the verified model could not be moved into place; nothing was installed"
E_NOT_DURABLE = "the model was installed and verified, but its directory entry may not be durable; run again to confirm"
E_UNEXPECTED = "unexpected error"


class FetchError(Exception):
    pass


def _write_new(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o644)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _isolate(tmp: Path) -> None:
    """Point every Hugging Face cache and the token file into tmp; no implicit token, no telemetry."""
    for name in TOKEN_VARIABLES:
        os.environ.pop(name, None)
    os.environ.update({
        "HF_ENDPOINT": ENDPOINT,
        "HF_HOME": str(tmp / "home"),
        "HF_HUB_CACHE": str(tmp / "hub-cache"),
        "HF_XET_CACHE": str(tmp / "xet-cache"),
        "HF_TOKEN_PATH": str(tmp / "no-token"),
        "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
    })


def _download(manifest: Manifest, tmp: Path) -> Path:
    """Download, check and stage every manifest file; the staging directory, verified."""
    try:
        from huggingface_hub import constants, hf_hub_download
    except ImportError:
        raise FetchError(E_LIBRARY) from None
    except Exception:  # noqa: BLE001 - its text can hold paths; an interrupt still propagates
        raise FetchError(E_LIBRARY_FAILED) from None
    if (getattr(constants, "ENDPOINT", None) != ENDPOINT
            or getattr(constants, "HF_HUB_DISABLE_IMPLICIT_TOKEN", None) is not True):
        raise FetchError(E_SETTINGS)
    cache = (tmp / "cache").resolve()
    stage = tmp / "stage"
    try:
        stage.mkdir(mode=0o755)
        for directory in sorted(manifest.directories):
            (stage / directory).mkdir(mode=0o755, parents=True)
    except OSError:
        raise FetchError(E_STAGE_WRITE) from None
    for f in manifest.files:
        try:
            local = hf_hub_download(manifest.repo_id, f.path, revision=manifest.revision,
                                    cache_dir=str(cache), token=False)
        except Exception:  # noqa: BLE001 - library errors can carry URLs and paths
            raise FetchError(E_DOWNLOAD) from None
        try:
            resolved = Path(local).resolve()
            inside = resolved.is_relative_to(cache)
            regular = inside and resolved.is_file()
            data = resolved.read_bytes() if regular else b""
        except (OSError, TypeError, ValueError):
            raise FetchError(E_READ) from None
        if not inside:
            raise FetchError(E_OUTSIDE)
        if not regular:
            raise FetchError(E_MISMATCH)
        if len(data) != f.size or hashlib.sha256(data).hexdigest() != f.sha256:
            raise FetchError(E_MISMATCH)
        try:
            _write_new(stage.joinpath(*PurePosixPath(f.path).parts), data)
        except OSError:
            raise FetchError(E_STAGE_WRITE) from None
    try:
        for directory in sorted(manifest.directories):
            _fsync_dir(stage / directory)
        _fsync_dir(stage)
    except OSError:
        raise FetchError(E_STAGE_WRITE) from None
    try:
        return verify_model_dir(stage, manifest)
    except ModelUnavailable:
        raise FetchError(E_STAGE) from None


def fetch(target: Path, manifest: Manifest) -> str:
    """Install the verified model at target; the fixed result message, or FetchError."""
    if "huggingface_hub" in sys.modules:
        raise FetchError(E_IMPORTED)
    if os.environ.get("HF_ENDPOINT", ENDPOINT).rstrip("/") != ENDPOINT:
        raise FetchError(E_ENDPOINT)
    target = target.absolute()
    if os.path.lexists(target):
        try:
            verify_model_dir(target, manifest)
        except ModelUnavailable:
            raise FetchError(E_EXISTS) from None
        return M_PRESENT
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # Next to the target, so the final rename never crosses filesystems.
        tmp = Path(tempfile.mkdtemp(prefix=".fetch-embedding-model-", dir=target.parent))
    except OSError:
        raise FetchError(E_PREPARE) from None
    try:
        _isolate(tmp)
        stage = _download(manifest, tmp)
        try:
            os.rename(stage, target)
        except OSError:
            raise FetchError(E_INSTALL) from None
        # From here on the verified model is in place; only durability can fail.
        try:
            _fsync_dir(target.parent)
        except OSError:
            raise FetchError(E_NOT_DURABLE) from None
        return M_INSTALLED
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None, manifest: Manifest | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", type=Path, default=None,
                        help="model directory (default: TRIAGE_EMBEDDING_MODEL_DIR or models/all-MiniLM-L6-v2)")
    args = parser.parse_args(argv)
    try:
        manifest = manifest or load_manifest()
        print(fetch(args.target or get_settings().embedding_model_dir, manifest))
        return 0
    except ModelUnavailable:
        print(E_PREFIX + ModelUnavailable.MESSAGE, file=sys.stderr)
    except FetchError as error:
        print(E_PREFIX + str(error), file=sys.stderr)
    except Exception as error:  # noqa: BLE001 - never the message or traceback: they can hold paths
        print(f"{E_PREFIX}{E_UNEXPECTED} ({type(error).__name__})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
