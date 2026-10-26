"""Private directories and files, opened without following symlinks (DD-018).

Used for the audit log, and later for the CLI's output files. Every file is
opened relative to a descriptor of its already-checked directory, so the
directory cannot be swapped for a symlink between the check and the open,
and only a single path component is ever opened relative to it.

Assumed, not checked: the directory's ancestors are not writable by other
users. Needs POSIX: O_NOFOLLOW, O_DIRECTORY and dir_fd support.
"""

from __future__ import annotations

import os
import stat


def supported() -> bool:
    """Whether this platform has what these functions need."""
    return (hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd)


def single_component(name: str) -> str:
    """name, if it is one path component that is not "." or ".."; else ValueError."""
    if (not isinstance(name, str) or name in ("", ".", "..") or "/" in name or "\0" in name
            or (os.altsep is not None and os.altsep in name)):
        raise ValueError("file name must be a single path component")
    return name


def open_private_dir(path: str, *, what: str, create: bool) -> int:
    """A descriptor for path, which must be our own real directory, not group or other writable.

    With create, a missing directory is made with mode 0700, never its
    parents: a missing parent raises. Another process may create it first;
    the directory is then checked like any existing one. what names the
    directory in the fixed error message; it is a code constant, never input.
    The caller syncs the directory and its parent (sync_dir_and_parent) when
    it needs their entries durable.
    """
    refused = f"{what} directory must be ours, a real directory, not group or other writable"
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass   # created by another writer since the lstat; checked below
        before = os.lstat(path)
    if not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid() or before.st_mode & 0o022:
        raise PermissionError(refused)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise PermissionError(refused) from None
    try:
        # os.stat on the descriptor, the same object the files will be opened in.
        after = os.stat(fd)
        if ((after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISDIR(after.st_mode)
                or after.st_uid != os.geteuid() or after.st_mode & 0o022):
            raise PermissionError(refused)
    except BaseException:
        os.close(fd)
        raise
    return fd


def open_private_file(dir_fd: int, name: str, *, what: str, append: bool) -> int:
    """A descriptor for writing name in dir_fd: our own regular file, no group or other permissions.

    With append, the file is opened for appending and created if missing;
    without, it must not exist yet (O_EXCL). A new file gets mode 0600; an
    existing one is checked and refused if it does not qualify, never
    chmod-ed. No symlink is followed, and a FIFO without a reader fails to
    open instead of hanging.
    """
    single_component(name)
    # Append mode opens read-write so the caller can check the last byte.
    access = os.O_RDWR | os.O_APPEND if append else os.O_WRONLY | os.O_EXCL
    flags = access | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise PermissionError(f"{what} must be our regular file with no group or other permissions")
    except BaseException:
        os.close(fd)
        raise
    return fd


class FilesNotWritten(OSError):
    """write_new_files() failed or was interrupted. Every file it created is removed unless removed is False.

    collision is True when a name already existed: that file was not created
    here and is never touched. interrupted is True when the cause was a
    KeyboardInterrupt.
    """

    def __init__(self, message: str, *, collision: bool, removed: bool, interrupted: bool = False) -> None:
        super().__init__(message)
        self.collision = collision
        self.removed = removed
        self.interrupted = interrupted


def write_new_files(dir_fd: int, path: str, items: list[tuple[str, bytes]], *, what: str) -> None:
    """Create each (name, data) in dir_fd (at path) exclusively, write and sync it; then sync the directories.

    All or nothing: if any step fails or is interrupted, the files created by
    this call are removed, and only those. An OSError or a KeyboardInterrupt
    becomes FilesNotWritten (interrupted says which); any other exception is
    re-raised after the cleanup. A file that already existed makes O_EXCL fail,
    so it is never written, followed or removed. This is exception cleanup,
    not crash atomicity: SIGKILL or power loss mid-write can still leave
    partial files.
    """
    created: list[str] = []
    try:
        for name, data in items:
            fd = open_private_file(dir_fd, name, what=what, append=False)
            created.append(name)
            try:
                write_all(fd, data, what=what)
                os.fsync(fd)
            finally:
                os.close(fd)
        sync_dir_and_parent(dir_fd, path)
    except BaseException as error:
        removed = True
        for name in created:
            try:
                os.unlink(name, dir_fd=dir_fd)
            except OSError:
                removed = False
        if isinstance(error, KeyboardInterrupt):
            raise FilesNotWritten(f"{what} writing was interrupted", collision=False, removed=removed,
                                  interrupted=True) from None
        if isinstance(error, OSError):
            raise FilesNotWritten(f"{what} could not be written", collision=isinstance(error, FileExistsError),
                                  removed=removed) from None
        raise


def write_all(fd: int, data: bytes, *, what: str) -> None:
    """Write every byte; a write that makes no progress raises instead of looping."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(f"{what} write made no progress")
        view = view[written:]


def sync_dir_and_parent(dir_fd: int, path: str) -> None:
    """Sync the directory open as dir_fd (at path), then its parent.

    A file's entry is durable only once its directory is synced, and a new
    directory's entry only once its parent is. Syncing both every time, not
    only when this process created them, means a caller never relies on
    another process's unfinished sync. The parent is opened by path: its
    ancestors are trusted, and only a sync is done through it.
    """
    os.fsync(dir_fd)
    parent = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
