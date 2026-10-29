"""Synthetic or public data only (CLAUDE.md rule 1; DD-028, threat T30).

The tree test reads every file from the git index, so it checks exactly what
would be committed. The rule tests build each forbidden value at runtime, so
this file never holds one and passes its own rules.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys

import pytest

from triage.config import REPO_ROOT
from triage.ingest import load_alert

_spec = importlib.util.spec_from_file_location("synthetic_data", REPO_ROOT / "scripts" / "synthetic_data.py")
sd = importlib.util.module_from_spec(_spec)
sys.modules["synthetic_data"] = sd   # dataclasses need the module registered
_spec.loader.exec_module(sd)

_GIT_ENV = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR")


def index_files(root):
    """{path: (mode, content bytes)} for every entry in the git index."""
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV}
    listing = subprocess.run(["git", "-C", str(root), "ls-files", "-s", "-z"], capture_output=True,
                             env=env, check=True).stdout
    entries = []
    for item in filter(None, listing.split(b"\0")):
        meta, path = item.split(b"\t", 1)
        mode, obj, _stage = meta.split()
        entries.append((os.fsdecode(path), mode.decode(), obj.decode()))
    batch = "".join(f"{obj}\n" for _, mode, obj in entries if mode != "160000").encode()
    out = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"], input=batch, capture_output=True,
                         env=env, check=True).stdout
    files, pos = {}, 0
    for path, mode, obj in entries:
        if mode == "160000":
            files[path] = (mode, b"")
            continue
        header_end = out.index(b"\n", pos)
        size = int(out[pos:header_end].split()[2])
        files[path] = (mode, out[header_end + 1:header_end + 1 + size])
        pos = header_end + 1 + size + 1
    return files


@pytest.fixture(scope="module")
def tree():
    if not (REPO_ROOT / ".git").exists() or shutil.which("git") is None:
        pytest.skip("not a Git checkout: the index cannot be read")
    files = index_files(REPO_ROOT)
    assert "README.md" in files and "triage/agent.py" in files   # the listing is the repository's
    return files


@pytest.fixture(scope="module")
def provenance(tree):
    return json.loads(tree[sd.PROVENANCE][1].decode("utf-8"))


# --- The current tree ------------------------------------------------------------

def test_tracked_files_follow_the_rules_of_their_class(tree, provenance):
    """A tracked file breaks the synthetic-data rule of its path class."""
    entries = {e["path"]: e for e in provenance["files"]}
    found = []
    for path, (mode, data) in sorted(tree.items()):
        cls = sd.path_class(path)
        if cls in (sd.DATA, sd.REFERENCE, sd.METADATA) and mode != "100644":
            found.append(f"{path}: data-bearing path must be a regular non-executable file (mode {mode})")
        found += sd.check_content(path, data, cls, sd.file_rules(entries.get(path)))
    assert found == []


def test_every_data_bearing_file_has_an_exact_provenance_entry(tree, provenance):
    """A data-bearing or reference file has no entry, a stale hash, or the provenance names a missing file."""
    files = {path: data for path, (_mode, data) in tree.items()}
    assert sd.provenance_problems(provenance, files) == []


def test_sample_alert_hosts_are_in_the_inventory_or_declared(tree, provenance):
    """A sample alert names a host that is neither in data/assets.json nor declared unknown."""
    assets = {a["host"] for a in json.loads(tree["data/assets.json"][1])["assets"]}
    entries = {e["path"]: e for e in provenance["files"]}
    checked, found = 0, []
    for path, (_mode, data) in sorted(tree.items()):
        if not path.startswith("samples/alerts/") or not path.endswith(".json"):
            continue
        fmt = path.split("/")[2]
        host = load_alert(data.decode("utf-8"), fmt=fmt).host
        checked += 1
        if host is not None and host not in assets and host not in entries[path].get("unknown_hosts", []):
            found.append(f"{path}: host not in the inventory or the entry's unknown_hosts")
    assert checked == 10 and found == []


def test_reference_hosts_each_have_a_reason():
    assert len(sd.REFERENCE_HOSTS) == 10 and all(sd.REFERENCE_HOSTS.values())


# --- The rules, one fixture each (control C6) ---------------------------------------

def _dot(*parts):
    return ".".join(parts)


PRIVATE_V4 = _dot("10", "1", "2", "3")
ROUTABLE_V4 = _dot("8", "8", "4", "4")
LINK_LOCAL_V6 = "fe80" + "::1"
GLOBAL_V6 = "2606" + ":4700::1111"
REAL_EMAIL = "someone" + "@" + _dot("corp", "com")
REAL_HOST = _dot("intranet", "corp", "com")


@pytest.mark.parametrize("text, rule", [
    (f"src {PRIVATE_V4} dst", "IPv4"),
    (f"resolver {ROUTABLE_V4}.", "IPv4"),
    (f"addr {LINK_LOCAL_V6} here", "IPv6"),
    (f"addr {GLOBAL_V6}", "IPv6"),
    (f"mail {REAL_EMAIL}", "email"),
    ("note " + "gitleaks" + ":allow", "inline scanner allow"),
])
@pytest.mark.parametrize("cls", [sd.DATA, sd.REFERENCE, sd.METADATA, sd.OTHER])
def test_rules_for_every_class_fire(text, rule, cls):
    found = sd.check_content("x/file.txt", text.encode(), cls)
    assert len(found) == 1 and rule in found[0]


@pytest.mark.parametrize("text, rule", [
    (f"see https://{REAL_HOST}/page", "URL host"),
    ("call 405-" + "867-5309", "phone"),
    ("ssn 123-" + "45-6789", "SSN"),
])
@pytest.mark.parametrize("cls", [sd.DATA, sd.REFERENCE, sd.METADATA])
def test_strict_rules_fire_in_data_bearing_classes(text, rule, cls):
    found = sd.check_content("x/file.txt", text.encode(), cls)
    assert len(found) == 1 and rule in found[0]


@pytest.mark.parametrize("text", [
    f"see https://{REAL_HOST}/page", "call 405-" + "867-5309", "ssn 123-" + "45-6789",
])
def test_strict_rules_do_not_apply_to_code_and_docs(text):
    assert sd.check_content("docs/x.md", text.encode(), sd.OTHER) == []


@pytest.mark.parametrize("text", [
    "hosts 192.0.2.10, 198.51.100.7, 203.0.113.250, 127.0.0.1 and 0.0.0.0",
    "v6 2001:db8::1, [2001:db8:0:1::5]:443, ::1 and ::",
    "mail analyst@clinic.example, a@b.test, c@example.com, d@x.example.org, e@y.invalid",
    "urls https://portal.clinic.test/x and http://localhost:11434 and https://example.net",
    "phone 555-0100 and (405) 555-0199",
    "version 1.2.3 and 300.1.1.1 and 1.2.3.4.5",
    "time 12:30:45",
])
def test_allowed_forms_pass_in_data(text):
    assert sd.check_content("data/x.txt", text.encode(), sd.DATA) == []


def test_reference_hosts_are_allowed_only_in_reference_content():
    text = b"see https://attack.mitre.org/techniques/T1059/"
    assert sd.check_content("vendor/sigma-detection-pack/runbooks/x.md", text, sd.REFERENCE) == []
    assert sd.check_content(sd.PROVENANCE, json.dumps({"s": text.decode()}).encode(), sd.METADATA) == []
    found = sd.check_content("data/x.md", text, sd.DATA)
    assert len(found) == 1 and "URL host" in found[0]


def test_permitted_hosts_are_per_file():
    text = json.dumps({"u": "see https://mail.google.com/settings"}).encode()
    assert sd.check_content("data/x.json", text, sd.DATA, sd.FileRules(frozenset({"mail.google.com"}))) == []
    assert len(sd.check_content("data/x.json", text, sd.DATA)) == 1


def test_json_host_fields_are_checked_in_data():
    doc = json.dumps({"agent": {"hostname": REAL_HOST}, "host": "CLINIC-FRONT01"}).encode()
    found = sd.check_content("data/x.json", doc, sd.DATA)
    assert len(found) == 1 and "host field" in found[0]


def test_binary_content_is_rejected_in_data_bearing_paths():
    found = sd.check_content("samples/x.bin", b"\xff\xfe\x00binary", sd.DATA)
    assert len(found) == 1 and "binary" in found[0]
    assert sd.check_content("docs/x.bin", b"\xff\xfe\x00binary", sd.OTHER) == []


def test_gitattributes_is_rejected_anywhere():
    """H2 amendment A, A2: diff attributes would hide files from the scan and the count alike."""
    for path in (".gitattributes", "docs/.gitattributes"):
        found = sd.check_content(path, b"*.json -diff\n", sd.path_class(path))
        assert any("gitattributes" in f for f in found)


def test_eval_results_are_reserved():
    """H2 amendment A, A4: eval-output is fail-closed until E1b implements it."""
    path = "eval/results/pass-001/files.sha256"
    assert sd.path_class(path) == sd.EVAL_OUTPUT
    found = sd.check_content(path, b"clean text\n", sd.EVAL_OUTPUT)
    assert len(found) == 1 and "reserved" in found[0]


def test_violation_messages_never_quote_the_value():
    """No rejected value appears in a message: addresses, emails, URL hosts, host fields, phones."""
    phone = "(212)" + "867-5309"
    text = json.dumps({"note": f"{PRIVATE_V4} {REAL_EMAIL} https://{REAL_HOST}/p {phone}",
                       "hostname": _dot("db", "corp", "net")})
    found = sd.check_content("data/x.json", text.encode(), sd.DATA)
    rules = {"IPv4", "email", "URL host", "host field", "phone"}
    assert all(any(rule in f for f in found) for rule in rules), found
    for value in (PRIVATE_V4, REAL_EMAIL, REAL_HOST, _dot("db", "corp", "net"), "867-5309", "corp"):
        assert not any(value in f for f in found)


# --- Escaped and parsed values (review finding I1) --------------------------------------

def _escaped(value):
    """value written as backslash-u escapes, so no line rule can see it in the raw text."""
    return "".join(f"\\u{ord(c):04x}" for c in value)


@pytest.mark.parametrize("key, value, rule", [
    ("host", ROUTABLE_V4, "host field"),
    ("note", ROUTABLE_V4, "IPv4"),
    ("note", PRIVATE_V4, "IPv4"),
    ("note", GLOBAL_V6, "IPv6"),
    ("note", REAL_EMAIL, "email"),
    ("note", "https://" + REAL_HOST + "/x", "URL host"),
    ("note", "gitleaks" + ":allow", "inline scanner allow"),
])
def test_escaped_values_in_json_are_decoded_and_checked(key, value, rule):
    raw = '{"%s": "%s"}' % (key, _escaped(value))
    assert value not in raw and json.loads(raw)[key] == value
    found = sd.check_content("data/x.json", raw.encode(), sd.DATA)
    assert any(rule in f for f in found), found


def test_escaped_documentation_address_passes():
    raw = '{"host": "%s", "note": "%s"}' % (_escaped("192.0.2.8"), _escaped("ops@clinic.example"))
    assert sd.check_content("data/x.json", raw.encode(), sd.DATA) == []


@pytest.mark.parametrize("host, ok", [
    (ROUTABLE_V4, False), (PRIVATE_V4, False), (LINK_LOCAL_V6, False),
    ("192.0.2.8", True), ("127.0.0.1", True), ("2001:db8::8", True),
])
def test_ip_host_fields_and_url_hosts_are_judged_by_the_address_ranges(host, ok):
    field = json.dumps({"host": host}).encode()
    url_host = f"[{host}]" if ":" in host else host
    url = json.dumps({"u": f"http://{url_host}:80/"}).encode()
    for data in (field, url):
        assert (sd.check_content("data/x.json", data, sd.DATA) == []) == ok


def test_escaped_values_in_jsonl_and_yaml_are_checked():
    jsonl = '{"a": 1}\n{"note": "%s"}\n' % _escaped(ROUTABLE_V4)
    assert any("IPv4" in f for f in sd.check_content("tests/data/x.jsonl", jsonl.encode(), sd.DATA))
    yml = 'title: x\nnote: "%s"\n' % _escaped(REAL_EMAIL)   # YAML double quotes decode it too
    assert any("email" in f for f in sd.check_content("vendor/sigma-detection-pack/rules/x.yml",
                                                       yml.encode(), sd.REFERENCE))


def test_unparseable_structured_data_fails_closed():
    found = sd.check_content("data/x.json", b'{"note": "unterminated', sd.DATA)
    assert len(found) == 1 and "does not parse" in found[0]


@pytest.mark.parametrize("text", [
    "(212)" + "867-5309", "(212) " + "867-5309", "212-" + "867-5309", "212." + "867.5309",
    "+1 212-" + "867-5309", "+1(212)" + "867-5309", "1-212-" + "867-5309",
])
def test_phone_forms_are_detected(text):
    found = sd.check_content("data/x.txt", f"call {text} now".encode(), sd.DATA)
    assert len(found) == 1 and "phone" in found[0]


@pytest.mark.parametrize("text", [
    "(212)" + "555-0150", "(212) 555-0100", "212-555-0199", "+1 405.555.0123",
])
def test_reserved_phone_forms_pass(text):
    assert sd.check_content("data/x.txt", f"call {text} now".encode(), sd.DATA) == []


@pytest.mark.parametrize("path, cls", [
    ("provenance.json", sd.METADATA),
    ("data/assets.json", sd.DATA),
    ("samples/alerts/wazuh/x.json", sd.DATA),
    ("tests/data/x.jsonl", sd.DATA),
    ("vendor/sigma-detection-pack/fixtures/x.json", sd.DATA),
    ("eval/cases/x.json", sd.DATA),
    ("eval/results/p/x.json", sd.EVAL_OUTPUT),
    ("vendor/sigma-detection-pack/rules/x.yml", sd.REFERENCE),
    ("vendor/sigma-detection-pack/runbooks/x.md", sd.REFERENCE),
    ("vendor/sigma-detection-pack/SOURCE.md", sd.OTHER),
    ("tests/test_x.py", sd.OTHER),
    ("README.md", sd.OTHER),
])
def test_path_classes(path, cls):
    assert sd.path_class(path) == cls


# --- Provenance ----------------------------------------------------------------------

def _doc(*entries):
    return {"version": 1, "files": list(entries)}


def _entry(path, data, **extra):
    return {"path": path, "sha256": sd.sha256(data), "class": "synthetic", **extra}


FILES = {"data/a.json": b"{}\n", "README.md": b"# r\n", sd.PROVENANCE: b"{}\n"}


def test_valid_provenance_passes():
    assert sd.provenance_problems(_doc(_entry("data/a.json", FILES["data/a.json"])), FILES) == []


@pytest.mark.parametrize("doc, needle", [
    (_doc(), "no provenance entry"),                                                  # a new file without an entry
    (_doc(_entry("data/a.json", b"old\n")), "sha256 does not match"),                 # an edit without a hash update
    (_doc(_entry("data/a.json", b"{}\n"), _entry("data/gone.json", b"x")), "not tracked"),
    (_doc(_entry("data/a.json", b"{}\n"), _entry("README.md", b"# r\n")), "not in a data-bearing"),
    (_doc(_entry("data/a.json", b"{}\n"), _entry(sd.PROVENANCE, b"{}\n")), "must not declare itself"),
    (_doc({**_entry("data/a.json", b"{}\n"), "path": "data/*.json"}), "exact relative path"),
    (_doc({**_entry("data/a.json", b"{}\n"), "sha256": "ABC"}), "64 lowercase hex"),
    (_doc({**_entry("data/a.json", b"{}\n"), "class": "real"}), "class must be"),
    (_doc({**_entry("data/a.json", b"{}\n"), "class": "public"}), "needs a source"),
    (_doc({**_entry("data/a.json", b"{}\n"), "owner": "x"}), "unknown keys"),
    (_doc(_entry("data/a.json", b"{}\n"), _entry("data/a.json", b"{}\n")), "duplicate"),
    ({"version": 2, "files": []}, "top level"),
    ({"files": []}, "top level"),
])
def test_provenance_problems_are_reported(doc, needle):
    problems = sd.provenance_problems(doc, FILES)
    assert any(needle in p for p in problems), problems


def test_provenance_file_itself_is_scanned_by_the_strict_rules():
    """H2 amendment A, A3: the metadata class is never hashed, but always scanned."""
    data = json.dumps({"version": 1, "files": [], "x": PRIVATE_V4}).encode()
    assert sd.check_content(sd.PROVENANCE, data, sd.path_class(sd.PROVENANCE))


def test_update_hashes_changes_only_sha256():
    entry = {"path": "data/a.json", "sha256": "0" * 64, "class": "public", "source": "s",
             "permitted_hosts": ["h.example"], "notes": "n"}
    out = sd.update_hashes(_doc(entry), {"data/a.json": b"new\n"})
    assert out["files"][0] == {**entry, "sha256": sd.sha256(b"new\n")}
    assert entry["sha256"] == "0" * 64   # the input is not modified


def test_update_hashes_never_adds_an_entry():
    with pytest.raises(KeyError):
        sd.update_hashes(_doc(), {"data/new.json": b"{}\n"})
