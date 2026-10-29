"""Scan every reachable commit for secrets with a pinned gitleaks (DD-028, threat T30).

Runs in CI (the `secrets` job). The scanner binary is a CI-only dependency:
the project installs, runs and tests without it, and the offline tests use a
fake executable.

What one run does, failing closed at every step:
1. refuses a shallow clone, a local git attributes file, and any GITLEAKS_*
   variable in its own environment;
2. checks the scanner version, the exact `.gitleaks.toml` and the format of
   `.gitleaksignore`;
3. runs the synthetic controls C1 to C14 in throwaway repositories, with the
   repository's own configuration and the same options as the full scan;
4. scans the full reachable history, merges included;
5. compares gitleaks' "N commits scanned" with a count computed independently
   from `git log --numstat` under the same options and environment;
6. rescans a mirror without the ignore file, and requires its findings to equal
   the ignore file's fingerprints exactly (no new and no stale entries).

Output is redacted: rule IDs, paths, commits and line numbers, never a value.
Nothing is uploaded; reports live in a temporary directory.

Usage:
    python scripts/secret_scan.py --gitleaks PATH [--repo DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import string
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

GITLEAKS_VERSION = "8.30.1"
# The scan's git options, passed whole through --log-opts (gitleaks then drops
# its defaults, sources/git.go:75). --diff-merges=first-parent shows each merge
# commit's own changes; without it, content introduced only by a merge (a
# conflict resolution) is never shown to the scanner.
LOG_OPTS = ("--full-history", "--all", "--diff-filter=tuxdb", "--diff-merges=first-parent")
CONFIG_NAME = ".gitleaks.toml"
IGNORE_NAME = ".gitleaksignore"
APPROVED_CONFIG = {"extend": {"useDefault": True}}
COMMIT_MARK = "\x01"
COUNT_RE = re.compile(r"(\d+) commits scanned\.")
FINGERPRINT_RE = re.compile(r"[0-9a-f]{40}:[^:\s*?\[\]]+:[a-z0-9-]+:\d+")
CONTROL_IDENTITY = ("-c", "user.name=scan-control", "-c", "user.email=control@example.invalid",
                    "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false")


class ScanError(Exception):
    """A check failed; the message is safe to print (no secret values)."""


class BinaryEntry(ScanError):
    """git reported a binary change, which gitleaks would not scan."""


# --- Fixed invocation ---------------------------------------------------------

def scan_env(home: str) -> dict[str, str]:
    """The only environment git and gitleaks see.

    No GITLEAKS_CONFIG or GITLEAKS_CONFIG_TOML (they would replace the
    configuration), and no system or global git configuration (an
    attributes file or diff driver there could mark text files binary for
    every commit, hiding them from the scan and from the count alike).
    """
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def gitleaks_args(binary: str, source: str, config: str, ignore_dir: str, report: str) -> list[str]:
    """The exact argument list. No --enable-rule, --baseline-path or --log-level."""
    return [
        binary, "git", source,
        "--config", config,
        "--redact",
        "--no-banner",
        "--ignore-gitleaks-allow",
        "--exit-code", "1",
        "--gitleaks-ignore-path", ignore_dir,
        "--report-format", "json",
        "--report-path", report,
        "--log-opts=" + " ".join(LOG_OPTS),
    ]


@dataclass
class Scan:
    findings: list[dict]
    scanned: int


def run_gitleaks(binary: str, source: Path, config: Path) -> Scan:
    """Scan source with config; working directory and ignore path are empty directories."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        empty, home = tmp_path / "empty", tmp_path / "home"
        empty.mkdir()
        home.mkdir()
        report = tmp_path / "report.json"
        proc = subprocess.run(gitleaks_args(binary, str(source), str(config), str(empty), str(report)),
                              cwd=empty, env=scan_env(str(home)), capture_output=True, text=True, timeout=900)
        if proc.returncode not in (0, 1):
            raise ScanError(f"gitleaks exited {proc.returncode}")
        try:
            findings = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise ScanError("gitleaks wrote no readable report") from None
        if not isinstance(findings, list):
            raise ScanError("gitleaks report is not a list")
        # Exit 1 is also gitleaks' error code, so it must agree with the report.
        if (proc.returncode == 1) != bool(findings):
            raise ScanError(f"gitleaks exit code {proc.returncode} does not match {len(findings)} findings")
        return Scan(findings=findings, scanned=parse_scanned_count(proc.stderr))


def parse_scanned_count(log: str) -> int:
    counts = COUNT_RE.findall(log)
    if len(counts) != 1:
        raise ScanError("gitleaks log has no single 'commits scanned' line")
    return int(counts[0])


def git(repo: Path, *args: str, env: dict[str, str], check: bool = True) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise ScanError(f"git {args[0]} failed")
    return proc.stdout


# --- Coverage: the independent expected count (H2 amendment A, A1) -------------

def expected_commits(numstat: str) -> set[str]:
    """Commits that should yield at least one gitleaks fragment.

    Input is `git log <LOG_OPTS> --numstat --format=<COMMIT_MARK>%H`. gitleaks
    yields one fragment per text hunk of every file that is not deleted and
    not binary, and counts the commit even when the hunk only removes lines
    (detect/detect.go:218 runs before the empty check at :236). So a commit
    counts when any numstat line has added + deleted > 0. Pure renames, mode
    changes and new empty files have no hunk ("0 0"); deleted files are not
    listed (the d filter). A binary entry ("-") fails closed: gitleaks would
    skip that file, and the count would still agree.
    """
    counted: set[str] = set()
    current = None
    for line in numstat.splitlines():
        if line.startswith(COMMIT_MARK):
            current = line[1:].strip()
            continue
        if not line.strip():
            continue
        parts = line.split("\t", 2)
        if len(parts) != 3 or current is None:
            raise ScanError("unexpected numstat line")
        added, deleted, path = parts
        if added == "-" or deleted == "-":
            raise BinaryEntry(f"binary change at {current[:12]} in {path}: gitleaks would not scan it")
        if int(added) + int(deleted) > 0:
            counted.add(current)
    return counted


def numstat(repo: Path, env: dict[str, str]) -> str:
    return git(repo, "log", *LOG_OPTS, "--numstat", f"--format={COMMIT_MARK}%H", env=env)


def excluded_kinds(repo: Path, counted: set[str], env: dict[str, str]) -> dict[str, int]:
    """Reachable commits that are not counted, by kind (reported, not checked)."""
    parents = {}
    for line in git(repo, "rev-list", "--all", "--parents", env=env).splitlines():
        sha, *ps = line.split()
        parents[sha] = len(ps)
    statuses: dict[str, list[str]] = {}
    current = None
    for line in git(repo, "log", "--full-history", "--all", "--diff-merges=first-parent", "--name-status",
                    f"--format={COMMIT_MARK}%H", env=env).splitlines():
        if line.startswith(COMMIT_MARK):
            current = line[1:].strip()
            statuses[current] = []
        elif line.strip() and current is not None:
            statuses[current].append(line.split("\t", 1)[0])
    kinds = {"empty": 0, "deletion-only": 0, "no-hunk-only": 0, "merge-no-change": 0}
    for sha in parents.keys() - counted:
        st = statuses.get(sha, [])
        if not st:
            kinds["merge-no-change" if parents[sha] > 1 else "empty"] += 1
        elif all(s == "D" for s in st):
            kinds["deletion-only"] += 1
        else:
            kinds["no-hunk-only"] += 1
    return kinds


# --- Repository checks ----------------------------------------------------------

def check_not_shallow(repo: Path, env: dict[str, str]) -> None:
    if git(repo, "rev-parse", "--is-shallow-repository", env=env).strip() != "false":
        raise ScanError("shallow clone: the full history cannot be scanned")


def check_no_info_attributes(repo: Path, env: dict[str, str]) -> None:
    path = git(repo, "rev-parse", "--git-path", "info/attributes", env=env).strip()
    full = Path(path) if os.path.isabs(path) else repo / path
    if full.exists():
        raise ScanError("a local git attributes file exists; it could hide files from the scan")


def check_own_environment(environ: dict[str, str]) -> None:
    names = sorted(k for k in environ if k.startswith("GITLEAKS_"))
    if names:
        raise ScanError(f"GITLEAKS_ variables are set ({', '.join(names)}); the scan uses only its own configuration")


def check_version(binary: str) -> None:
    with tempfile.TemporaryDirectory() as home:
        out = subprocess.run([binary, "version"], env=scan_env(home), capture_output=True, text=True, timeout=60)
    if out.returncode != 0 or out.stdout.strip() != GITLEAKS_VERSION:
        raise ScanError(f"gitleaks version is not {GITLEAKS_VERSION}")


def config_problems(text: str) -> list[str]:
    """The configuration must be exactly [extend] useDefault = true (comments allowed)."""
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [f"{CONFIG_NAME}: not valid TOML"]
    if doc != APPROVED_CONFIG:
        return [f"{CONFIG_NAME}: must be exactly [extend] useDefault = true; no disabled rules, "
                "rules, allow-lists, paths or other keys"]
    return []


def ignore_fingerprints(text: str) -> tuple[set[str], list[str]]:
    """Exact commit fingerprints, each directly after a '# ' reason line.

    gitleaks uses the whole line as the fingerprint (detect/detect.go:169-190),
    so a reason cannot share the line; it goes on the line before.
    """
    fingerprints: set[str] = set()
    problems: list[str] = []
    previous = ""
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line and not line.startswith("#"):
            if not FINGERPRINT_RE.fullmatch(line):
                problems.append(f"{IGNORE_NAME}:{number}: not an exact commit:path:rule-id:line fingerprint")
            elif not (previous.startswith("# ") and len(previous) > 2):
                problems.append(f"{IGNORE_NAME}:{number}: fingerprint without a '# reason' line before it")
            else:
                fingerprints.add(line)
        previous = line
    return fingerprints, problems


def stale_problems(found: set[str], ignored: set[str]) -> list[str]:
    problems = [f"finding not in {IGNORE_NAME}: {fp}" for fp in sorted(found - ignored)]
    problems += [f"stale {IGNORE_NAME} entry (no longer found): {fp}" for fp in sorted(ignored - found)]
    return problems


def finding_lines(findings: list[dict]) -> list[str]:
    return [f"{f.get('RuleID')} {f.get('File')}:{f.get('StartLine')} commit {str(f.get('Commit'))[:12]}"
            for f in findings]


# --- Synthetic controls (H2 revision 2, 4.6; amendment A) -------------------------
# Every value is generated at runtime and never committed, so neither push
# protection nor GitHub's own scanning ever sees one. They are random, so
# they match no account.

ALNUM = string.ascii_letters + string.digits


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def token(rule: str) -> str:
    if rule == "github-pat":
        return "ghp_" + _rand(ALNUM, 36)
    if rule == "aws-access-token":
        return "AKIA" + _rand(string.ascii_uppercase[:-1] + "234567", 16)   # never ends in EXAMPLE
    if rule == "slack-bot-token":
        return "xoxb-" + _rand(string.digits, 12) + "-" + _rand(string.digits, 12) + "-" + _rand(ALNUM, 24)
    if rule == "gitlab-pat":
        return "glpat-" + _rand(ALNUM, 20)
    if rule == "private-key":
        body = "\n".join(_rand(ALNUM + "+/", 64) for _ in range(3))
        return "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END " + "PRIVATE KEY-----"
    raise ValueError(rule)


class ControlRepo:
    """A throwaway repository built with plain git under the scan environment."""

    def __init__(self, path: Path, env: dict[str, str]):
        self.path, self.env = path, env
        self._git("init", "-q")

    def _git(self, *args: str, check: bool = True) -> str:
        proc = subprocess.run(["git", *CONTROL_IDENTITY, "-C", str(self.path), *args],
                              env=self.env, capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise ScanError(f"control repository: git {args[0]} failed")
        return proc.stdout

    def write(self, name: str, text: str) -> None:
        (self.path / name).write_text(text, encoding="utf-8")

    def commit(self, message: str, *, allow_empty: bool = False) -> str:
        self._git("add", "-A")
        self._git("commit", "-q", "-m", message, *(["--allow-empty"] if allow_empty else []))
        return self._git("rev-parse", "HEAD").strip()

    def run(self, *args: str, check: bool = True) -> str:
        return self._git(*args, check=check)


def _has(scan: Scan, rule: str, commit: str) -> bool:
    return any(f.get("RuleID") == rule and f.get("Commit") == commit for f in scan.findings)


def run_controls(binary: str, config: Path) -> list[tuple[str, bool, str]]:
    """Run C1 to C14; returns (name, passed, detail) for each."""
    results: list[tuple[str, bool, str]] = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        home = tmp_path / "home"
        home.mkdir()
        env = scan_env(str(home))
        counter = iter(range(100))

        def repo() -> ControlRepo:
            path = tmp_path / f"r{next(counter)}"
            path.mkdir()
            return ControlRepo(path, env)

        def scan(r: ControlRepo) -> Scan:
            s = run_gitleaks(binary, r.path, config)
            # C4: in every control repository, gitleaks' count equals the
            # independently computed one.
            expected = len(expected_commits(numstat(r.path, env)))
            if s.scanned != expected:
                results.append(("C4 count consistency", False, f"{r.path.name}: scanned {s.scanned}, expected {expected}"))
            return s

        # C1 and C10: a token in the root commit's only file.
        r = repo()
        r.write("a.txt", token("github-pat") + "\n")
        root = r.commit("root")
        s = scan(r)
        results.append(("C1 rule", _has(s, "github-pat", root), "github-pat at the root commit"))
        results.append(("C10 root-commit introduction", _has(s, "github-pat", root), "root commit scanned"))

        # C2: added in commit 2, deleted in commit 3.
        r = repo()
        r.write("readme.txt", "benign\n")
        r.commit("one")
        r.write("b.txt", token("github-pat") + "\n")
        added = r.commit("two")
        r.run("rm", "-q", "b.txt")
        r.commit("three")
        results.append(("C2 deleted later", _has(scan(r), "github-pat", added), "reported at the adding commit"))

        # C5: clean content gives no finding.
        r = repo()
        r.write("notes.txt", "nothing secret here\n")
        r.commit("clean")
        s = scan(r)
        results.append(("C5 negative", not s.findings, f"{len(s.findings)} findings"))

        # C7: the inline allow comment has no effect.
        r = repo()
        r.write("c.txt", token("github-pat") + "  # " + "gitleaks" + ":allow\n")
        c = r.commit("inline")
        results.append(("C7 inline suppression ignored", _has(scan(r), "github-pat", c), "reported despite the comment"))

        # C8: five rule families are active under the repository's configuration.
        r = repo()
        panel = ("github-pat", "aws-access-token", "private-key", "slack-bot-token", "gitlab-pat")
        for i, rule in enumerate(panel):
            r.write(f"p{i}.txt", token(rule) + "\n")
        c = r.commit("panel")
        s = scan(r)
        missing = [rule for rule in panel if not _has(s, rule, c)]
        results.append(("C8 rule panel", not missing, "missing: " + ", ".join(missing) if missing else "all five reported"))

        # C9: an exact fingerprint suppresses exactly one finding.
        r = repo()
        r.write("d.txt", token("github-pat") + "\n" + token("github-pat") + "\n")
        c = r.commit("two tokens")
        r.write(IGNORE_NAME, f"# reason: control\n{c}:d.txt:github-pat:1\n")   # untracked, loaded by path
        s = scan(r)
        lines = {f.get("StartLine") for f in s.findings if f.get("RuleID") == "github-pat"}
        results.append(("C9 exact ignore", lines == {2}, f"github-pat findings on lines {sorted(lines)}"))

        # C11: an empty commit and a whole-file deletion change neither the
        # finding nor the expected count.
        r = repo()
        r.write("e.txt", token("github-pat") + "\n")
        r.write("other.txt", "benign\n")
        c = r.commit("token")
        r.commit("empty", allow_empty=True)
        r.run("rm", "-q", "other.txt")
        r.commit("delete a whole file")
        s = scan(r)
        ok = _has(s, "github-pat", c) and len(expected_commits(numstat(r.path, env))) == 1 and s.scanned == 1
        results.append(("C11 empty and deletion-only commits", ok, f"scanned {s.scanned}, expected 1"))

        # C12: a token introduced only by a merge's conflict resolution.
        r = repo()
        r.write("f.txt", "base\n")
        r.commit("base")
        r.run("checkout", "-q", "-b", "side")
        r.write("f.txt", "one\n")
        r.commit("side")
        r.run("checkout", "-q", "main")
        r.write("f.txt", "two\n")
        r.commit("main")
        r.run("merge", "-q", "--no-ff", "side", check=False)   # conflicts by design
        r.write("f.txt", token("github-pat") + "\n")
        merge = r.commit("resolve")
        results.append(("C12 merge-only introduction", _has(scan(r), "github-pat", merge), "reported at the merge commit"))

        # C13: a token only on a branch never merged into the checked-out commit.
        r = repo()
        r.write("g.txt", "benign\n")
        r.commit("main")
        r.run("checkout", "-q", "-b", "unmerged")
        r.write("h.txt", token("github-pat") + "\n")
        c = r.commit("unmerged")
        r.run("checkout", "-q", "main")
        results.append(("C13 unmerged branch", _has(scan(r), "github-pat", c), "--all covers other refs"))

        # C14: removal-only hunks count; whole-file deletions, pure renames and
        # new empty files do not. The written count is 2.
        r = repo()
        secret = token("github-pat")
        r.write("a.txt", secret + "\nsecond line\nthird line\n")
        r.write("b.txt", "benign\n")
        c = r.commit("root")
        r.write("a.txt", secret + "\nthird line\n")
        r.commit("remove one line")
        r.run("rm", "-q", "b.txt")
        r.commit("delete a whole file")
        r.run("mv", "a.txt", "c.txt")
        r.commit("pure rename")
        r.write("e.txt", "")
        r.commit("new empty file")
        s = scan(r)
        expected = len(expected_commits(numstat(r.path, env)))
        ok = s.scanned == 2 and expected == 2 and _has(s, "github-pat", c)
        results.append(("C14 removal-only counted", ok, f"scanned {s.scanned}, expected {expected}, written 2"))

    results.append(("C3 repository configuration", True, f"every control ran with {config.name}"))
    if not any(name.startswith("C4") for name, _, _ in results):
        results.append(("C4 count consistency", True, "scanned equals expected in every control repository"))
    return sorted(results, key=lambda r: int(r[0].split()[0][1:]))


# --- Main ------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gitleaks", required=True, help="path to the pinned gitleaks binary")
    parser.add_argument("--repo", default=".", help="repository to scan (default: current directory)")
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()
    binary = str(Path(args.gitleaks).resolve())
    config = repo / CONFIG_NAME

    try:
        check_own_environment(dict(os.environ))
        with tempfile.TemporaryDirectory() as home:
            env = scan_env(home)
            check_not_shallow(repo, env)
            check_no_info_attributes(repo, env)
            check_version(binary)
            problems = config_problems(config.read_text(encoding="utf-8"))
            ignore_path = repo / IGNORE_NAME
            ignored, ignore_problems = ignore_fingerprints(
                ignore_path.read_text(encoding="utf-8") if ignore_path.exists() else "")
            problems += ignore_problems
            if problems:
                raise ScanError("; ".join(problems))

            print(f"gitleaks {GITLEAKS_VERSION}; log options: {' '.join(LOG_OPTS)}")
            controls = run_controls(binary, config)
            for name, passed, detail in controls:
                print(f"{'PASS' if passed else 'FAIL'} {name}: {detail}")
            if not all(passed for _, passed, _ in controls):
                raise ScanError("a synthetic control failed")

            scan = run_gitleaks(binary, repo, config)
            counted = expected_commits(numstat(repo, env))
            reachable = int(git(repo, "rev-list", "--all", "--count", env=env).strip())
            kinds = excluded_kinds(repo, counted, env)
            print(f"coverage: expected {len(counted)}, scanned {scan.scanned}, reachable {reachable}, "
                  "excluded " + ", ".join(f"{k} {v}" for k, v in kinds.items()))
            unresolved = [f for f in scan.findings if f.get("Fingerprint") not in ignored]
            print(f"findings: {len(scan.findings)} reported after exact ignores, {len(unresolved)} unresolved")
            for line in finding_lines(scan.findings):
                print(f"  {line}")
            if scan.scanned != len(counted):
                raise ScanError("gitleaks' commit count differs from the expected count")
            if scan.findings:
                raise ScanError("unresolved findings; see revision 2 section 6 before any change")

            with tempfile.TemporaryDirectory() as tmp:
                mirror = Path(tmp) / "mirror.git"
                subprocess.run(["git", "clone", "-q", "--mirror", str(repo), str(mirror)],
                               env=env, check=True, capture_output=True)
                bare = run_gitleaks(binary, mirror, config)
            stale = stale_problems({f.get("Fingerprint") for f in bare.findings}, ignored)
            print(f"stale-ignore check: {len(bare.findings)} findings without the ignore file, "
                  f"{len(ignored)} ignore entries, {len(stale)} problems")
            if stale:
                raise ScanError("; ".join(stale))
    except ScanError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("secret scan passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
