"""scripts/secret_scan.py: the fixed invocation, the coverage count, and every fail-closed path (DD-028).

These tests never run gitleaks: a fake executable records how it was called.
The real binary runs only in the CI `secrets` job, where the synthetic
controls C1 to C14 prove what these tests cannot (that the pinned scanner
actually detects, counts and suppresses as its source says).
"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path

import pytest
import yaml

from triage.config import REPO_ROOT

_spec = importlib.util.spec_from_file_location("secret_scan", REPO_ROOT / "scripts" / "secret_scan.py")
ss = importlib.util.module_from_spec(_spec)
sys.modules["secret_scan"] = ss   # dataclasses need the module registered
_spec.loader.exec_module(ss)

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
needs_posix = pytest.mark.skipif(os.name != "posix", reason="the fake scanner is a POSIX script")


# --- The fixed invocation ---------------------------------------------------------

def test_gitleaks_args_are_exact():
    assert ss.gitleaks_args("/bin/gl", "/repo", "/repo/.gitleaks.toml", "/empty", "/tmp/r.json") == [
        "/bin/gl", "git", "/repo",
        "--config", "/repo/.gitleaks.toml",
        "--redact",
        "--no-banner",
        "--ignore-gitleaks-allow",
        "--exit-code", "1",
        "--gitleaks-ignore-path", "/empty",
        "--report-format", "json",
        "--report-path", "/tmp/r.json",
        "--log-opts=--full-history --all --diff-filter=tuxdb --diff-merges=first-parent",
    ]


def test_gitleaks_args_never_narrow_the_scan():
    args = ss.gitleaks_args("gl", "r", "c", "e", "p")
    for flag in ("--enable-rule", "--baseline-path", "--max-target-megabytes", "--log-level", "--no-git"):
        assert not any(a.startswith(flag) for a in args)


def test_log_opts_cover_merges_and_every_ref():
    assert ss.LOG_OPTS == ("--full-history", "--all", "--diff-filter=tuxdb", "--diff-merges=first-parent")


def test_scan_environment_is_exact(monkeypatch):
    monkeypatch.setenv("GITLEAKS_CONFIG", "/elsewhere.toml")
    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    env = ss.scan_env("/home-x")
    assert env == {"PATH": os.environ["PATH"], "HOME": "/home-x",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}


def test_gitleaks_variables_in_the_job_fail_closed():
    with pytest.raises(ss.ScanError, match="GITLEAKS_CONFIG"):
        ss.check_own_environment({"PATH": "/bin", "GITLEAKS_CONFIG": "x"})
    with pytest.raises(ss.ScanError, match="GITLEAKS_CONFIG_TOML"):
        ss.check_own_environment({"GITLEAKS_CONFIG_TOML": "x"})
    ss.check_own_environment({"PATH": "/bin"})


# --- A fake gitleaks ------------------------------------------------------------------

@pytest.fixture
def fake(tmp_path):
    """A fake scanner configured by fake.json beside it; it records each call to calls.jsonl."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    script = bin_dir / "gitleaks"
    script.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import json, os, sys
        here = os.path.dirname(os.path.abspath(__file__))
        cfg = json.load(open(os.path.join(here, "fake.json")))
        with open(os.path.join(here, "calls.jsonl"), "a") as log:
            log.write(json.dumps({{"argv": sys.argv[1:], "cwd": os.getcwd(), "env": dict(os.environ)}}) + "\\n")
        if sys.argv[1:] == ["version"]:
            print(cfg.get("version", "8.30.1"))
            sys.exit(0)
        args = sys.argv[1:]
        if cfg.get("write_report", True):
            with open(args[args.index("--report-path") + 1], "w") as f:
                json.dump(cfg.get("findings", []), f)
        sys.stderr.write(cfg.get("log", "4:52PM INF 3 commits scanned.\\n"))
        sys.exit(cfg.get("exit", 0))
        """), encoding="utf-8")
    script.chmod(0o755)

    class Fake:
        path = str(script)

        @staticmethod
        def configure(**cfg):
            (bin_dir / "fake.json").write_text(json.dumps(cfg), encoding="utf-8")

        @staticmethod
        def calls():
            log = bin_dir / "calls.jsonl"
            return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    Fake.configure()
    return Fake


FINDING = {"RuleID": "github-pat", "Commit": "a" * 40, "File": "x.txt", "StartLine": 1,
           "Secret": "REDACTED", "Match": "REDACTED", "Fingerprint": "a" * 40 + ":x.txt:github-pat:1"}


@needs_posix
def test_run_gitleaks_uses_empty_directories_and_the_fixed_environment(fake, tmp_path):
    fake.configure(findings=[FINDING], exit=1)
    scan = ss.run_gitleaks(fake.path, tmp_path, tmp_path / ".gitleaks.toml")
    assert scan.scanned == 3 and scan.findings == [FINDING]
    (call,) = fake.calls()
    args = call["argv"]
    ignore_dir = args[args.index("--gitleaks-ignore-path") + 1]
    assert call["cwd"] == ignore_dir and os.path.basename(ignore_dir) == "empty"
    assert args[args.index("--config") + 1] == str(tmp_path / ".gitleaks.toml")
    assert set(call["env"]) - {"PWD", "SHLVL", "_", "LC_CTYPE"} == {"PATH", "HOME", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"}


@needs_posix
@pytest.mark.parametrize("cfg, message", [
    ({"exit": 2}, "exited 2"),
    ({"write_report": False}, "no readable report"),
    ({"exit": 1}, "does not match"),                          # an error exit with an empty report
    ({"findings": [FINDING], "exit": 0}, "does not match"),
    ({"log": "no count here\n"}, "commits scanned"),
    ({"log": "1 commits scanned.\n2 commits scanned.\n"}, "commits scanned"),
])
def test_run_gitleaks_fails_closed(fake, tmp_path, cfg, message):
    fake.configure(**cfg)
    with pytest.raises(ss.ScanError, match=message):
        ss.run_gitleaks(fake.path, tmp_path, tmp_path / "c.toml")


@needs_posix
def test_version_must_be_the_pinned_one(fake):
    ss.check_version(fake.path)
    fake.configure(version="8.30.0")
    with pytest.raises(ss.ScanError, match="not 8.30.1"):
        ss.check_version(fake.path)


def test_parse_scanned_count():
    assert ss.parse_scanned_count("\x1b[90m4:52PM\x1b[0m INF 34 commits scanned.\n") == 34


def test_finding_lines_never_carry_a_value():
    lines = ss.finding_lines([{**FINDING, "Secret": "ghp_x", "Match": "ghp_x"}])
    assert lines == ["github-pat x.txt:1 commit aaaaaaaaaaaa"]


# --- The expected count (H2 amendment A, A1) ---------------------------------------------

M = ss.COMMIT_MARK


@pytest.mark.parametrize("numstat, expected", [
    (f"{M}c1\n\n3\t0\tf.txt\n", {"c1"}),                 # lines added
    (f"{M}c2\n\n0\t1\tf.txt\n", {"c2"}),                 # removal-only hunk in a retained file: counted
    (f"{M}c3\n", set()),                                 # whole-file deletion (not listed) or empty commit
    (f"{M}c4\n\n0\t0\tf.txt => h.txt\n", set()),         # pure rename: no hunk
    (f"{M}c5\n\n0\t0\te.txt\n", set()),                  # new empty file: no hunk
    (f"{M}c6\n\n0\t0\ta\n2\t0\tb\n{M}c7\n", {"c6"}),
])
def test_expected_commits_rows(numstat, expected):
    assert ss.expected_commits(numstat) == expected


def test_binary_entry_fails_closed():
    with pytest.raises(ss.BinaryEntry, match="j.json"):
        ss.expected_commits(f"{M}c6\n\n-\t-\tj.json\n")


def test_malformed_numstat_fails_closed():
    with pytest.raises(ss.ScanError):
        ss.expected_commits("3\t0\tf.txt\n")   # no commit header


@pytest.fixture
def control(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    home = tmp_path / "home"
    home.mkdir()
    env = ss.scan_env(str(home))
    path = tmp_path / "repo"
    path.mkdir()
    return ss.ControlRepo(path, env)


def _expected(repo):
    return ss.expected_commits(ss.numstat(repo.path, repo.env))


@needs_git
def test_expected_count_against_real_git(control):
    """The C14 history, computed by git: removal-only counts; deletion, rename and empty file do not."""
    control.write("a.txt", "one\ntwo\nthree\n")
    control.write("b.txt", "benign\n")
    root = control.commit("root")
    control.write("a.txt", "one\nthree\n")
    removal = control.commit("remove a line")
    control.run("rm", "-q", "b.txt")
    control.commit("delete a whole file")
    control.run("mv", "a.txt", "c.txt")
    control.commit("pure rename")
    control.write("e.txt", "")
    control.commit("new empty file")
    control.commit("empty", allow_empty=True)
    assert _expected(control) == {root, removal}
    kinds = ss.excluded_kinds(control.path, {root, removal}, control.env)
    assert kinds == {"empty": 1, "deletion-only": 1, "no-hunk-only": 2, "merge-no-change": 0}


@needs_git
def test_expected_count_includes_merge_changes(control):
    control.write("f.txt", "base\n")
    control.commit("base")
    control.run("checkout", "-q", "-b", "side")
    control.write("g.txt", "side\n")
    control.commit("side")
    control.run("checkout", "-q", "main")
    control.run("merge", "-q", "--no-ff", "--no-edit", "side")
    merge = control.run("rev-parse", "HEAD").strip()
    assert merge in _expected(control)   # first-parent diff shows the merged change


@needs_git
def test_attributes_that_mark_text_binary_fail_closed(control):
    """H2 amendment A, A2: an attribute applies to all history and would blind scan and count together."""
    control.write("j.json", "{}\n")
    control.commit("json")
    control.write(".gitattributes", "*.json -diff\n")   # not even committed
    with pytest.raises(ss.BinaryEntry):
        _expected(control)


@needs_git
def test_local_info_attributes_fail_closed(control):
    ss.check_no_info_attributes(control.path, control.env)
    info = control.path / ".git" / "info"
    info.mkdir(exist_ok=True)
    (info / "attributes").write_text("*.json -diff\n", encoding="utf-8")
    with pytest.raises(ss.ScanError, match="attributes"):
        ss.check_no_info_attributes(control.path, control.env)


@needs_git
def test_shallow_clone_is_refused(control, tmp_path):
    control.write("a.txt", "1\n")
    control.commit("one")
    control.write("a.txt", "2\n")
    control.commit("two")
    ss.check_not_shallow(control.path, control.env)
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", control.path.as_uri(), str(shallow)],
                   env=control.env, check=True, capture_output=True)
    with pytest.raises(ss.ScanError, match="shallow"):
        ss.check_not_shallow(shallow, control.env)


# --- Configuration and ignore file (revision 2, 4.3) ----------------------------------

def test_repository_configuration_is_the_approved_one():
    text = (REPO_ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    assert ss.config_problems(text) == []
    assert tomllib.loads(text) == {"extend": {"useDefault": True}}


@pytest.mark.parametrize("text", [
    "[extend]\nuseDefault = true\ndisabledRules = [\"generic-api-key\"]\n",
    "[extend]\nuseDefault = true\n[allowlist]\npaths = ['''data/''']\n",
    "[extend]\nuseDefault = true\n[[allowlists]]\ncommits = [\"abc\"]\n",
    "[extend]\nuseDefault = true\n[[rules]]\nid = \"x\"\nregex = '''x'''\n",
    "[extend]\nuseDefault = false\n",
    "[extend]\npath = \"other.toml\"\n",
    "",
    "not toml [",
])
def test_any_other_configuration_fails(text):
    assert ss.config_problems(text)


def test_repository_ignore_file_is_well_formed_and_empty():
    fingerprints, problems = ss.ignore_fingerprints((REPO_ROOT / ".gitleaksignore").read_text(encoding="utf-8"))
    assert fingerprints == set() and problems == []


def test_exact_fingerprint_with_reason_is_accepted():
    fp = "b" * 40 + ":data/x.json:generic-api-key:12"
    assert ss.ignore_fingerprints(f"# header\n\n# reason: a hash, not a key\n{fp}\n") == ({fp}, [])


@pytest.mark.parametrize("text", [
    "b" * 40 + ":data/x.json:generic-api-key:12\n",                               # no reason line
    "# reason: x\ndata/x.json:generic-api-key:12\n",                             # global, not commit-bound
    "# reason: x\n" + "b" * 40 + ":data/*.json:generic-api-key:12\n",            # a wildcard
    "# reason: x\n" + "b" * 40 + ":data/x.json:generic-api-key:12 # inline\n",   # gitleaks would read the whole line
    "# reason: x\n" + "B" * 40 + ":data/x.json:generic-api-key:12\n",
    "#\n" + "b" * 40 + ":data/x.json:generic-api-key:12\n",                       # an empty reason
])
def test_bad_ignore_entries_fail(text):
    _fingerprints, problems = ss.ignore_fingerprints(text)
    assert problems


def test_stale_and_new_entries_are_both_problems():
    a, b = "a" * 40 + ":x:r:1", "b" * 40 + ":y:r:2"
    assert ss.stale_problems({a}, {a}) == []
    assert any("not in" in p for p in ss.stale_problems({a, b}, {a}))
    assert any("stale" in p for p in ss.stale_problems({a}, {a, b}))


# --- main fails closed before scanning ---------------------------------------------------

@needs_posix
def test_main_refuses_gitleaks_variables(fake, monkeypatch, capsys):
    monkeypatch.setenv("GITLEAKS_CONFIG", "/x.toml")
    assert ss.main(["--gitleaks", fake.path, "--repo", str(REPO_ROOT)]) == 1
    assert "GITLEAKS_" in capsys.readouterr().err
    assert fake.calls() == []


@needs_posix
@needs_git
def test_main_refuses_a_changed_configuration(fake, control, monkeypatch, capsys):
    monkeypatch.delenv("GITLEAKS_CONFIG", raising=False)
    control.write(".gitleaks.toml", "[extend]\nuseDefault = true\ndisabledRules = [\"github-pat\"]\n")
    control.commit("config")
    assert ss.main(["--gitleaks", fake.path, "--repo", str(control.path)]) == 1
    assert ".gitleaks.toml" in capsys.readouterr().err
    assert [c["argv"] for c in fake.calls()] == [["version"]]   # nothing was scanned


# --- Controls ------------------------------------------------------------------------------

@pytest.mark.parametrize("rule, pattern", [
    ("github-pat", r"ghp_[0-9a-zA-Z]{36}"),
    ("aws-access-token", r"AKIA[A-Z2-7]{16}"),
    ("slack-bot-token", r"xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
    ("gitlab-pat", r"glpat-[\w-]{20}"),
    ("private-key", "-----BEGIN " + r"PRIVATE KEY-----\n[A-Za-z0-9+/\n]{64,}\n-----END " + "PRIVATE KEY-----"),
])
def test_control_tokens_match_their_rule_and_are_random(rule, pattern):
    first, second = ss.token(rule), ss.token(rule)
    assert re.fullmatch(pattern, first) and first != second
    assert not first.endswith("EXAMPLE")


# --- The CI job ------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def secrets_job():
    workflow = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    return workflow["jobs"]["secrets"]


def test_secrets_job_is_read_only_and_full_depth(secrets_job):
    assert secrets_job["permissions"] == {"contents": "read"}
    checkout = secrets_job["steps"][0]
    assert re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkout["uses"])
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}
    text = json.dumps(secrets_job)
    for forbidden in ("upload-artifact", "codeql", "sarif", "github-script", "secrets."):
        assert forbidden not in text.lower()


def test_secrets_job_pins_the_binary_and_runs_the_scan(secrets_job):
    # Not GITLEAKS_* names: the scan refuses those in its environment.
    assert secrets_job["env"]["PINNED_GITLEAKS_VERSION"] == ss.GITLEAKS_VERSION
    assert re.fullmatch(r"[0-9a-f]{64}", secrets_job["env"]["PINNED_GITLEAKS_SHA256"])
    runs = "\n".join(step.get("run", "") for step in secrets_job["steps"])
    assert "sha256sum -c" in runs
    assert "--is-shallow-repository" in runs
    assert "scripts/secret_scan.py" in runs
    assert not any(name.startswith("GITLEAKS_") for name in secrets_job.get("env", {}))
