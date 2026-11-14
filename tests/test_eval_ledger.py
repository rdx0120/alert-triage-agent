"""The ledger writer, and private file creation."""

from __future__ import annotations

import os
import stat

import pytest

from evaluation import ledger, records
from triage import files as tfiles


@pytest.fixture
def directory(tmp_path):
    path = tmp_path / "orig"
    path.mkdir(mode=0o700)
    fd = tfiles.open_private_dir(str(path), what="test", create=False)
    yield path, fd
    os.close(fd)


def write_pass(writer):
    writer.append("pass_start", None, None, None)
    writer.append("run_start", 1, "dev-a", None)
    writer.append("run_end", 1, "dev-a", "outcome")
    writer.append("check_failed", 2, "test-b", None)
    writer.append("pass_end", None, None, "incomplete")


def test_a_written_ledger_verifies_and_is_canonical(directory):
    path, fd = directory
    writer = ledger.LedgerWriter(fd, str(path))
    assert stat.S_IMODE(os.stat(path / "ledger.jsonl").st_mode) == 0o600
    write_pass(writer)
    writer.close_and_verify()
    data = (path / "ledger.jsonl").read_bytes()
    entries = records.verify_ledger(data)
    assert [e.event for e in entries] == ["pass_start", "run_start", "run_end", "check_failed", "pass_end"]
    import json
    for line in data.splitlines():
        assert tuple(json.loads(line)) == records.LEDGER_KEYS
    assert b"sha256" not in data and b"bytes" not in data


def test_an_append_after_pass_end_refuses(directory):
    path, fd = directory
    writer = ledger.LedgerWriter(fd, str(path))
    write_pass(writer)
    with pytest.raises(ledger.WriteRefused):
        writer.append("run_start", 3, "test-c", None)
    writer.close_and_verify()


def test_an_existing_ledger_is_never_reopened(directory):
    path, fd = directory
    (path / "ledger.jsonl").write_bytes(b"x")
    with pytest.raises(ledger.WriteRefused):
        ledger.LedgerWriter(fd, str(path))
    assert (path / "ledger.jsonl").read_bytes() == b"x"


def test_a_line_the_reader_would_refuse_is_never_written(directory):
    path, fd = directory
    writer = ledger.LedgerWriter(fd, str(path))
    with pytest.raises(Exception):
        writer.append("run_begin", 1, "dev-a", None)
    assert (path / "ledger.jsonl").read_bytes() == b""
    writer.abandon()


# --- Creation mode ------------------------------------------------------------------

@pytest.fixture
def no_umask():
    old = os.umask(0)
    yield
    os.umask(old)


def test_files_are_created_0600_whatever_the_umask(directory, no_umask, monkeypatch):
    path, fd = directory
    seen = []
    real_open = os.open

    def recording_open(name, flags, mode=0o777, *, dir_fd=None):
        result = real_open(name, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT:
            seen.append((name, mode, stat.S_IMODE(os.fstat(result).st_mode)))
        return result

    monkeypatch.setattr(os, "open", recording_open)
    ledger.LedgerWriter(fd, str(path)).abandon()
    ledger.write_private(path / "one.json", b"{}\n", what="test")
    ledger.write_in(fd, str(path), [("two.json", b"{}\n")], what="test")
    monkeypatch.undo()
    assert [(n, m, actual) for n, m, actual in seen] == [("ledger.jsonl", 0o600, 0o600), ("one.json", 0o600, 0o600),
                                                         ("two.json", 0o600, 0o600)]


def test_write_private_refuses_an_existing_path_and_a_symlink(tmp_path):
    out = tmp_path / "out"
    out.mkdir(mode=0o700)
    (out / "exists").write_bytes(b"old")
    with pytest.raises(ledger.WriteRefused):
        ledger.write_private(out / "exists", b"new", what="test")
    assert (out / "exists").read_bytes() == b"old"
    os.symlink(tmp_path / "target", out / "link")
    with pytest.raises(ledger.WriteRefused):
        ledger.write_private(out / "link", b"new", what="test")
    assert not (tmp_path / "target").exists()


def test_write_private_refuses_a_group_writable_parent(tmp_path):
    out = tmp_path / "shared"
    out.mkdir()
    os.chmod(out, 0o770)
    with pytest.raises(ledger.WriteRefused):
        ledger.write_private(out / "file", b"x", what="test")
    assert list(out.iterdir()) == []


@pytest.mark.skipif(os.geteuid() != 0, reason="needs to create a directory owned by another user")
def test_write_private_refuses_another_users_parent(tmp_path):
    out = tmp_path / "theirs"
    out.mkdir(mode=0o700)
    os.chown(out, 12345, 12345)
    with pytest.raises(ledger.WriteRefused):
        ledger.write_private(out / "file", b"x", what="test")
    assert list(out.iterdir()) == []
