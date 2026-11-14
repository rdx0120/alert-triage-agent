"""The pass ledger writer, and the one way the evaluation creates a file.

The ledger records each run before it starts and its class when it ends.
Each line carries the SHA-256 of the line before it, so an edited, removed,
reordered or inserted line breaks the chain. It holds no output hash, size
or time: those would let a published ledger reveal something about a
redacted output.

Every file the evaluation creates goes through triage.files: created with
O_EXCL and O_NOFOLLOW, mode 0600 whatever the umask, in a directory that is
ours and not group- or other-writable. A file is never replaced.
"""

from __future__ import annotations

import os

from triage import files as tfiles

from evaluation.common import EvaluationError, canonical_dumps, sha256_hex
from evaluation import records


class WriteRefused(EvaluationError):
    """A file could not be created privately."""


def write_private(path: str | os.PathLike, data: bytes, *, what: str) -> None:
    """Create path as a new private file holding data, synced. An existing path is refused."""
    path = os.fspath(path)
    parent = os.path.dirname(os.path.abspath(path))
    name = os.path.basename(path)
    try:
        dir_fd = tfiles.open_private_dir(parent, what=what, create=False)
    except (OSError, ValueError):
        raise WriteRefused(f"{what}: output directory is not private") from None
    try:
        tfiles.write_new_files(dir_fd, parent, [(name, data)], what=what)
    except (OSError, ValueError):
        raise WriteRefused(f"{what}: file could not be created") from None
    finally:
        os.close(dir_fd)


def write_in(dir_fd: int, dir_path: str, items: list[tuple[str, bytes]], *, what: str) -> None:
    """Create files in an already-open private directory."""
    try:
        tfiles.write_new_files(dir_fd, dir_path, items, what=what)
    except (OSError, ValueError):
        raise WriteRefused(f"{what}: file could not be created") from None


class LedgerWriter:
    def __init__(self, dir_fd: int, dir_path: str) -> None:
        self._dir_fd = dir_fd
        self._dir_path = dir_path
        try:
            self._fd = tfiles.open_private_file(dir_fd, "ledger.jsonl", what="ledger", append=False)
        except (OSError, ValueError):
            raise WriteRefused("ledger: file could not be created") from None
        self._seq = 0
        self._prev = "0" * 64
        self._closed = False

    def append(self, event: str, position: int | None, case_id: str | None, cls: str | None) -> None:
        if self._closed:
            raise WriteRefused("ledger: the pass has ended")
        obj = {"seq": self._seq + 1, "event": event, "position": position, "case_id": case_id,
               "class": cls, "prev": self._prev}
        records.LedgerEntry.model_validate(obj)
        line = canonical_dumps(obj)
        try:
            tfiles.write_all(self._fd, line, what="ledger")
            os.fsync(self._fd)
        except OSError:
            raise WriteRefused("ledger: line could not be written") from None
        self._seq += 1
        self._prev = sha256_hex(line)
        if event == "pass_end":
            self._closed = True

    def close_and_verify(self) -> None:
        """Close the only write descriptor, then require the 1a verifier to accept the file."""
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        fd = os.open("ledger.jsonl", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._dir_fd)
        try:
            chunks = []
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(fd)
        records.verify_ledger(b"".join(chunks))

    def abandon(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
