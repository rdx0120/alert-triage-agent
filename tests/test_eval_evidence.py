"""File rules, the secret-scanner driver, and the span finder against the synthetic-data rules."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

import test_eval_doubles as dbl
from evaluation import evidence
from evaluation.common import canonical_dumps, load_h2

H2 = load_h2()
# A URL whose user information is also an email address; built so this file holds neither.
USER_URL = "http://user" + "@" + "corp-mail.net/path"


@pytest.fixture(scope="module")
def published(tmp_path_factory):
    return dbl.production_pass(tmp_path_factory.mktemp("pub"), tmp_path_factory)


@pytest.fixture
def copy_dir(published, tmp_path):
    """A writable copy of the pass's original/ directory."""
    target = tmp_path / "original"
    shutil.copytree(published.original, target)
    os.chmod(target, 0o700)
    for name in os.listdir(target):
        os.chmod(target / name, 0o600)
    return target


POSITIONS = range(1, 7)


# --- File rules ---------------------------------------------------------------------------------

def test_the_pass_directory_follows_the_file_rules(copy_dir):
    assert evidence.file_problems(str(copy_dir), POSITIONS, public=False) == []


@pytest.mark.parametrize("change, message", [
    ("symlink", "files: run-0007.summary.json is a symlink"),
    ("empty", "files: run-0002.summary.json is empty"),
    ("non-utf8", "files: run-0002.summary.json is not UTF-8"),
    ("subdirectory", "files: an entry is a directory"),
    ("name", "files: a file name is outside the fixed set"),
    ("position", "files: run-0099.harness.json is not a position of the order"),
    ("missing-h", "files: run-0003.harness.json is missing"),
    ("missing-environment", "files: environment.json is missing"),
])
def test_each_file_rule_is_enforced(copy_dir, change, message):
    if change == "symlink":
        os.symlink("run-0001.summary.json", copy_dir / "run-0007.summary.json")
    elif change == "empty":
        (copy_dir / "run-0002.summary.json").write_bytes(b"")
    elif change == "non-utf8":
        (copy_dir / "run-0002.summary.json").write_bytes(b"\xff\xfe")
    elif change == "subdirectory":
        (copy_dir / "extra").mkdir()
    elif change == "name":
        (copy_dir / "notes.txt").write_text("x")
    elif change == "position":
        (copy_dir / "run-0099.harness.json").write_text("{}")
    elif change == "missing-h":
        (copy_dir / "run-0003.harness.json").unlink()
    else:
        (copy_dir / "environment.json").unlink()
    assert message in evidence.file_problems(str(copy_dir), POSITIONS, public=False)


def test_public_directories_also_need_redactions_json(copy_dir):
    assert "files: redactions.json is missing" in evidence.file_problems(str(copy_dir), POSITIONS, public=True)


def test_the_hash_list_covers_every_file_and_never_itself(copy_dir):
    data = evidence.hash_list(str(copy_dir))
    assert evidence.hash_list_problems(str(copy_dir), data) == []
    assert b"files.original.sha256" not in data
    (copy_dir / "ledger.jsonl").write_bytes(b"changed\n")
    assert evidence.hash_list_problems(str(copy_dir), data) == ["hash list: ledger.jsonl differs"]
    (copy_dir / "extra.json").write_text("{}")
    assert evidence.hash_list_problems(str(copy_dir), data) == ["hash list: the file set differs"]


# --- The secret-scanner driver --------------------------------------------------------------------

@pytest.fixture
def gitleaks(tmp_path):
    return dbl.make_gitleaks(tmp_path / "gl")


def test_the_gitleaks_argv_and_environment_are_exact(copy_dir, gitleaks, tmp_path):
    config = tmp_path / "config.toml"
    config.write_text("")
    assert evidence.gitleaks_findings(gitleaks.path, str(copy_dir), str(config)) == 0
    version, scan = gitleaks.calls()
    assert version["argv"] == ["version"]
    argv = scan["argv"]
    empty = argv[10]
    report = argv[14]
    assert [gitleaks.path] + argv == evidence.gitleaks_argv(gitleaks.path, os.path.realpath(copy_dir),
                                                           os.path.realpath(config), empty, report)
    assert argv[:2] == ["dir", os.path.realpath(copy_dir)] and scan["cwd"] == empty
    env = {k: v for k, v in scan["env"].items() if k not in ("PWD", "SHLVL", "_", "LC_CTYPE")}
    assert set(env) == {"PATH", "HOME", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"}
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == "/dev/null"


def test_findings_are_counted_never_shown(copy_dir, gitleaks, tmp_path):
    gitleaks.set(findings=[{"RuleID": "generic-api-key", "Secret": "REDACTED"}] * 2)
    assert evidence.gitleaks_findings(gitleaks.path, str(copy_dir), str(tmp_path)) == 2


@pytest.mark.parametrize("config", [{"exit": 2}, {"exit": 0, "findings": [{"x": 1}]}, {"exit": 1},
                                    {"report": "missing"}, {"report": "garbage"}, {"version": "8.29.0"}])
def test_the_driver_fails_closed(copy_dir, gitleaks, tmp_path, config):
    gitleaks.set(**config)
    with pytest.raises(evidence.PublishRefused):
        evidence.gitleaks_findings(gitleaks.path, str(copy_dir), str(tmp_path))


# --- Spans ---------------------------------------------------------------------------------------

def generated_lines() -> list[str]:
    """One line per rule, plus allowed look-alikes, built at run time."""
    ip = dbl.private_ipv4()
    return [
        f"note {H2.INLINE_ALLOW} here", f"Block {ip} now", "Block " + ":".join(("2600", "1f18", "abcd", "", "1")) + " now",
        f"Mail {dbl.real_email()} today", "See https://intranet.corp-mail.net/x", f"Call {dbl.phone_number()}",
        "SSN " + "-".join(("123", "45", "6789")), "Block 192.0.2.10 and 2001:db8::1",
        "Mail analyst@example.com", "Call 212-555-0123", "Visit https://example.org/a", "plain text",
        f"{ip} and {dbl.real_email()} and {dbl.phone_number()}", USER_URL,
    ]


@pytest.mark.parametrize("line", generated_lines())
def test_a_line_has_a_span_of_a_rule_exactly_when_the_rules_report_it(line):
    assert {s.rule for s in evidence.raw_spans(line)} == evidence.line_rule_ids(line)


@pytest.mark.parametrize("line", generated_lines())
def test_after_replacement_the_rules_report_nothing(line):
    text = line
    for span in sorted(evidence.spans(line), key=lambda s: s.start, reverse=True):
        text = text[:span.start] + f"<<REDACTED:{span.rule}:1>>" + text[span.end:]
    assert H2._line_rules(text, H2.DATA, H2.FileRules()) == []


def test_spans_are_found_per_line_with_offsets_in_the_whole_string():
    ip = dbl.private_ipv4()
    text = f"first line\nBlock {ip}"
    (span,) = evidence.spans(text)
    assert text[span.start:span.end] == ip


def test_overlapping_spans_merge_and_keep_the_first_rule_in_the_fixed_order():
    line = USER_URL
    raw = evidence.raw_spans(line)
    assert {s.rule for s in raw} == {"email", "url-host"}
    (merged,) = evidence.spans(line)
    assert merged.rule == "email"
    assert merged.start == min(s.start for s in raw) and merged.end == max(s.end for s in raw)


# --- Flags outside the four free-text fields --------------------------------------------------------

def _edit_json(path: Path, edit) -> None:
    obj = json.loads(path.read_bytes())
    edit(obj)
    path.write_bytes(canonical_dumps(obj))


@pytest.mark.parametrize("where", ["s-field", "s-key", "audit", "harness", "ledger", "environment"])
def test_a_flag_outside_the_redactable_fields_refuses(copy_dir, where):
    ip = dbl.private_ipv4()
    if where == "s-field":
        _edit_json(copy_dir / "run-0002.summary.json", lambda o: o["asset"].__setitem__("owner", ip))
    elif where == "s-key":
        _edit_json(copy_dir / "run-0002.summary.json", lambda o: o.__setitem__(ip, 1))
    elif where == "audit":
        lines = (copy_dir / "run-0002.audit.jsonl").read_bytes().split(b"\n")
        first = json.loads(lines[0])
        first["triage.alert.id"] = ip
        (copy_dir / "run-0002.audit.jsonl").write_bytes(b"\n".join([canonical_dumps(first)[:-1]] + lines[1:]))
    elif where == "harness":
        (copy_dir / "run-0002.harness.json").write_bytes(
            (copy_dir / "run-0002.harness.json").read_bytes().replace(b'"pass_id"', f'"{ip}":1,"pass_id"'.encode()))
    elif where == "ledger":
        (copy_dir / "ledger.jsonl").write_bytes((copy_dir / "ledger.jsonl").read_bytes() + f"{ip}\n".encode())
    else:
        _edit_json(copy_dir / "environment.json", lambda o: o.__setitem__("ended_at", ip))
    with pytest.raises(evidence.PublishRefused) as info:
        evidence.scan(str(copy_dir))
    assert ip not in str(info.value)


def test_a_flag_inside_a_free_text_field_is_an_item(copy_dir):
    ip = dbl.private_ipv4()
    _edit_json(copy_dir / "run-0002.summary.json",
               lambda o: o["severity"].__setitem__("rationale", f"Seen from {ip} twice"))
    items, private = evidence.scan(str(copy_dir))
    assert items == [{"n": 1, "file": "run-0002.summary.json", "pointer": "/severity/rationale", "rule": "ipv4"}]
    assert private[0]["text"] == ip and list(private[0]) == ["n", "file", "pointer", "rule", "start", "end", "text",
                                                            "file_sha256"]


def test_items_are_numbered_by_file_then_field_order_then_start(copy_dir):
    ip, mail = dbl.private_ipv4(), dbl.real_email()
    _edit_json(copy_dir / "run-0003.summary.json",
               lambda o: o["next_steps"][0].__setitem__("step", f"Ask {mail} about {ip}"))
    _edit_json(copy_dir / "run-0002.summary.json",
               lambda o: o["severity"].__setitem__("rationale", f"From {ip}"))
    items, _ = evidence.scan(str(copy_dir))
    assert [(i["n"], i["file"], i["pointer"], i["rule"]) for i in items] == [
        (1, "run-0002.summary.json", "/severity/rationale", "ipv4"),
        (2, "run-0003.summary.json", "/next_steps/0/step", "email"),
        (3, "run-0003.summary.json", "/next_steps/0/step", "ipv4")]


def test_a_non_canonical_summary_cannot_be_redacted(copy_dir):
    obj = json.loads((copy_dir / "run-0002.summary.json").read_bytes())
    (copy_dir / "run-0002.summary.json").write_text(json.dumps(obj, indent=1) + "\n")
    with pytest.raises(evidence.PublishRefused):
        evidence.scan(str(copy_dir))
