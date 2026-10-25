"""Source hygiene: no tracked text file holds raw invisible or control characters.

Raw format characters (bidi overrides, zero-width characters), line and
paragraph separators, surrogates, private-use characters and stray control
characters can make source read differently from how it runs (the "Trojan
Source" pattern, CVE-2021-42574) or hide text from a reviewer. Tests that
need such characters write them as escape sequences or with chr().
"""

import os
import shutil
import subprocess
import unicodedata
from pathlib import Path

import pytest

from triage.config import REPO_ROOT

# Unicode categories never allowed raw: format, line separator, paragraph
# separator, surrogate, private use. Controls (Cc) are allowed only as
# newline, tab, and the CR of a CRLF line ending (a Windows checkout with
# core.autocrlf), which git normalizes on commit.
FORBIDDEN_CATEGORIES = frozenset({"Cf", "Zl", "Zp", "Cs", "Co"})
ALLOWED_CONTROLS = frozenset({"\n", "\t"})
# Tracked files with these suffixes are binary and not scanned. Every other
# tracked file must be strict UTF-8 text, so an undecodable file fails
# instead of being skipped.
BINARY_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz"})
# Variables that could point git at another repository or index.
_GIT_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR")


def tracked_files(root: Path) -> list[str]:
    """The paths git tracks under root, from the index (git ls-files -z)."""
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV}
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, env=env, check=True)
    return sorted(os.fsdecode(p) for p in out.stdout.split(b"\0") if p)


def violations(root: Path, paths: list[str]) -> list[str]:
    """One "path:line: U+XXXX" entry per forbidden character; never the text around it."""
    found = []
    for rel in paths:
        path = root / rel
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        if path.is_symlink() or not path.is_file():
            found.append(f"{rel}: not a regular file")
            continue
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            found.append(f"{rel}: not UTF-8")
            continue
        for number, line in enumerate(text.replace("\r\n", "\n").split("\n"), start=1):
            for ch in line:
                category = unicodedata.category(ch)
                if category in FORBIDDEN_CATEGORIES or (category == "Cc" and ch not in ALLOWED_CONTROLS):
                    found.append(f"{rel}:{number}: U+{ord(ch):04X}")
    return found


def test_tracked_text_files_hold_no_forbidden_characters():
    """A tracked text file holds a raw format, separator, surrogate, private-use or stray control character."""
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not a Git checkout: the tracked files cannot be listed")
    paths = tracked_files(REPO_ROOT)
    assert "README.md" in paths and "triage/agent.py" in paths   # the listing is the repository's
    assert violations(REPO_ROOT, paths) == []


@pytest.fixture
def scratch_repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    return tmp_path


def test_forbidden_character_in_a_tracked_file_is_reported(scratch_repo):
    """A raw private-use, separator, bidi or lone CR character goes unreported, or its text is echoed."""
    marker = "ZQXMARKER7731"
    a_py = f"x = 1  # {chr(0xE000)}\ns = '{marker}{chr(0x2028)}{marker}'  # {chr(0x202E)}\n"
    (scratch_repo / "a.py").write_text(a_py, encoding="utf-8")
    b_md = f"box drawing {chr(0x2500)}, a middle dot {chr(0xB7)} and a datamark {chr(0x2C6)}\n"
    (scratch_repo / "b.md").write_text(b_md, encoding="utf-8")
    (scratch_repo / "c.txt").write_text(f"lone CR{chr(13)}here\r\nCRLF line\r\n", encoding="utf-8", newline="")
    (scratch_repo / "untracked.py").write_text(f"y = '{chr(0x200B)}'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(scratch_repo), "add", "a.py", "b.md", "c.txt"], check=True)
    paths = tracked_files(scratch_repo)
    assert paths == ["a.py", "b.md", "c.txt"]   # untracked.py is never listed
    found = violations(scratch_repo, paths)
    assert found == ["a.py:1: U+E000", "a.py:2: U+2028", "a.py:2: U+202E", "c.txt:1: U+000D"]
    assert marker not in "".join(found)


def test_undecodable_or_missing_tracked_file_is_reported(scratch_repo):
    """A tracked file that is not UTF-8 text, or is missing, is skipped instead of reported."""
    (scratch_repo / "bad.txt").write_bytes(b"\xff\xfe")
    (scratch_repo / "gone.txt").write_text("x\n", encoding="utf-8")
    (scratch_repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00")
    subprocess.run(["git", "-C", str(scratch_repo), "add", "."], check=True)
    (scratch_repo / "gone.txt").unlink()
    found = violations(scratch_repo, tracked_files(scratch_repo))
    assert found == ["bad.txt: not UTF-8", "gone.txt: not a regular file"]
