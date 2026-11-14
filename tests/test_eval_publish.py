"""Publication: scan, build and verify-original, every refusal, closure, withholding, markers and stage separation."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path

import pytest

import test_eval_doubles as dbl
from evaluation import evidence, publish, records
from evaluation.common import canonical_dumps, load_h2, strict_loads

BASE_SOURCES = ["runbook_search:b0db39e5155934cc"]
MARKER = "QX7-K2M9TP"
OTHER_MARKER = "ZK4-R8W2MN"
TWIN = 6   # baseline position of the family-C twin with MARKER


def steps(*texts):
    return {"S": {"next_steps": [{"step": t, "sources": BASE_SOURCES} for t in texts]}}


def worked_example():
    return {TWIN: steps(f"Ref: {MARKER}", f"Block {dbl.private_ipv4()} at the edge firewall ({MARKER})")}


@pytest.fixture
def gl(tmp_path):
    return dbl.make_gitleaks(tmp_path / "gl")


def setup(tmp_path, tmp_path_factory, specs=None, **kwargs):
    return dbl.production_pass(tmp_path, tmp_path_factory, specs=specs, **kwargs)


def paths(pub):
    return publish.Paths(str(pub.store), pub.pass_id)


def scan(pub, gl):
    return publish.run_scan(str(pub.clone.path), paths(pub), gl.path)


def build(pub, gl):
    return publish.run_build(str(pub.clone.path), paths(pub), gl.path)


def scanned(tmp_path, tmp_path_factory, gl, specs=None, code="model-real-looking", **kwargs):
    pub = setup(tmp_path, tmp_path_factory, specs, **kwargs)
    scan(pub, gl)
    dbl.classify_all(pub, code)
    return pub


def assert_refused(pub, gl, message):
    with pytest.raises(evidence.PublishRefused) as info:
        build(pub, gl)
    assert str(info.value) == message or message in str(info.value)
    assert not (pub.root / "public").exists() and not (pub.root / "public.tmp").exists()


def originals_hash(pub) -> str:
    return hashlib.sha256((pub.root / "files.original.sha256").read_bytes()).hexdigest()


# --- A successful build ------------------------------------------------------------------------

def test_the_worked_example_publishes_with_equal_score_records(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl, worked_example())
    assert build(pub, gl) == 5
    public = pub.root / "public"
    red = json.loads((public / "redactions.json").read_bytes())["items"]
    name = f"run-{TWIN:04d}"
    assert red[0] == {"file": f"{name}.summary.json", "pointer": "/next_steps/1/step", "rule": "ipv4", "n": 1,
                      "classification": "model-real-looking"}
    assert [(i["n"], i["rule"], i["pointer"]) for i in red[1:]] == [
        (2, "withheld-digest", "L3/triage.request.sha256"), (3, "withheld-digest", "L3/triage.request.bytes"),
        (4, "withheld-digest", "L3/triage.reply.sha256"), (5, "withheld-digest", "L3/triage.reply.text_bytes")]
    s = json.loads((public / f"{name}.summary.json").read_bytes())
    assert s["next_steps"][1]["step"] == f"Block <<REDACTED:ipv4:1>> at the edge firewall ({MARKER})"
    assert s["next_steps"][0]["step"] == f"Ref: {MARKER}"
    # Runs without an item are byte for byte the originals.
    for other in ("run-0001.summary.json", "run-0002.audit.jsonl", "ledger.jsonl", "environment.json"):
        assert (public / other).read_bytes() == pub.read(other)
    # The public copy verifies: hash list, closure, equal scores.
    assert evidence.hash_list_problems(str(public), (public / "files.sha256").read_bytes(),
                                       exclude=("files.sha256",)) == []
    count, counts = publish.run_verify(str(pub.clone.path), paths(pub), originals_hash(pub))
    assert count == 1 and counts["model-real-looking"] == 1


def test_withheld_digests_only_for_runs_with_an_item(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl, worked_example())
    build(pub, gl)
    public = pub.root / "public"
    lines = [json.loads(line) for line in (public / f"run-{TWIN:04d}.audit.jsonl").read_bytes().splitlines()]
    calls = [line for line in lines if line["event.name"] == "triage.model_call"]
    assert calls and all(c[k] is None for c in calls for k in evidence.DIGEST_KEYS)
    for position in range(1, TWIN):
        name = f"run-{position:04d}.audit.jsonl"
        assert (public / name).read_bytes() == pub.read(name)


def test_redaction_counts_agree_between_the_public_and_original_copies(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl, worked_example())
    build(pub, gl)
    registry, labels, order = publish.frozen_inputs(str(pub.clone.path))
    p = paths(pub)
    hashes = evidence.parse_hash_list((pub.root / "files.original.sha256").read_bytes())
    public_hashes = evidence.parse_hash_list((pub.root / "public" / "files.sha256").read_bytes())
    with evidence.named_copy(p.original, p.pass_id, hashes, public=False, positions=range(1, 16)) as d:
        original = records.load_pass(d, registry=registry, labels=labels, order=order, sequence="baseline",
                                     public=False, scan_items=p.scan_items, classification=p.classification)
    with evidence.named_copy(p.public, p.pass_id, public_hashes, public=True, positions=range(1, 16)) as d:
        public = records.load_pass(d, registry=registry, labels=labels, order=order, sequence="baseline",
                                   public=True, redactions=os.path.join(d, "redactions.json"))
    assert public.redactions.items == original.redactions.items == ((TWIN, "model-real-looking"),)
    assert public.redactions.withheld == (TWIN,) * 4


def test_a_pass_without_items_publishes_unchanged(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl)
    assert build(pub, gl) == 0
    public = pub.root / "public"
    for name in os.listdir(pub.original):
        assert (public / name).read_bytes() == pub.read(name)
    assert json.loads((public / "redactions.json").read_bytes()) == {"version": 1, "items": []}


# --- Each build refusal --------------------------------------------------------------------------------

def test_refusal_1_the_original_hash_list_does_not_verify(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl)
    pub.tamper("run-0002.harness.json", pub.read("run-0002.harness.json"), relist=False)
    listing = pub.root / "files.original.sha256"
    os.chmod(listing, 0o600)
    listing.write_bytes(listing.read_bytes().replace(b"run-0002.harness.json", b"run-0002.harness.jsom"))
    assert_refused(pub, gl, "hash list: the file set differs")


def test_refusal_1_the_ledger_chain_does_not_verify(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl)
    pub.tamper("ledger.jsonl", pub.read("ledger.jsonl").replace(b'"seq":2', b'"seq":3', 1))
    assert_refused(pub, gl, "originals: the ledger chain does not verify")


def test_refusal_2_the_file_rules_fail(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl)
    pub.tamper("notes.txt", b"x")
    calls = len(gl.calls())
    assert_refused(pub, gl, "files: a file name is outside the fixed set")
    assert len(gl.calls()) == calls   # refused before the secret scan


def test_refusal_3_the_secret_scanner_reports_a_finding(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl)
    gl.set(findings=[{"RuleID": "x"}], only="original")
    assert_refused(pub, gl, "build: the secret scanner reports a finding in the originals")


def test_refusal_4_a_flag_outside_the_redactable_fields(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl)
    h = json.loads(pub.read("run-0002.harness.json"))
    pub.tamper("run-0002.harness.json", canonical_dumps(h).replace(b'"pass_id"', b'"%s":1,"pass_id"'
                                                                   % dbl.private_ipv4().encode()))
    assert_refused(pub, gl, "scan: a flag outside the redactable fields (run-0002.harness.json)")


@pytest.mark.parametrize("change", ["stale", "unclassified", "extra-key", "bad-code", "missing"])
def test_refusal_5_the_classification_does_not_match_the_scan(tmp_path, tmp_path_factory, gl, change):
    pub = scanned(tmp_path, tmp_path_factory, gl, worked_example())
    cls_path = pub.root / "classification.json"
    doc = json.loads(cls_path.read_bytes())
    if change == "stale":
        doc["scan_sha256"] = "0" * 64
    elif change == "unclassified":
        doc["items"] = {}
    elif change == "extra-key":
        doc["items"]["2"] = "synthetic-match"
    elif change == "bad-code":
        doc["items"]["1"] = "fine"
    if change == "missing":
        cls_path.unlink()
        assert_refused(pub, gl, "build: the scan or the classification cannot be read")
        return
    cls_path.write_bytes(canonical_dumps(doc))
    assert_refused(pub, gl, "build: the classification does not match the scan")


def test_refusal_5_a_changed_original_after_the_scan(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl, worked_example())
    s = json.loads(pub.read(f"run-{TWIN:04d}.summary.json"))
    s["next_steps"][0]["step"] = f"Ref: {MARKER} and {dbl.real_email()}"
    pub.tamper(f"run-{TWIN:04d}.summary.json", canonical_dumps(s))
    assert_refused(pub, gl, "build: the stored scan differs from a fresh scan")


@pytest.mark.parametrize("code", ["suspected-real-data", "suspected-credential"])
def test_refusal_6_an_item_classified_as_an_incident(tmp_path, tmp_path_factory, gl, code):
    pub = scanned(tmp_path, tmp_path_factory, gl, worked_example(), code=code)
    assert_refused(pub, gl, "build: an item is classified as an incident")


def test_refusal_7_a_placeholder_the_model_wrote_itself(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl, {2: steps("Already <<REDACTED:ipv4:1>> here")})
    assert_refused(pub, gl, "closure: run-0002.summary.json holds a placeholder at no listed pointer")


def test_refusal_7_the_scanners_report_on_the_public_copy(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl)
    gl.set(findings=[{"RuleID": "x"}], only="public.tmp")
    assert_refused(pub, gl, "closure: the secret scanner reports a finding")


def test_refusal_8_score_records_differ(tmp_path, tmp_path_factory, gl):
    # The only occurrence of the marker is inside the span, so redaction would change the score.
    pub = scanned(tmp_path, tmp_path_factory, gl, {TWIN: steps(f"Mail {MARKER}@corp-mail.net about the block")})
    assert_refused(pub, gl, "build: score records differ between the original and public copies")


def duplicate_occurrence():
    return {TWIN: steps(f"Ref: {MARKER}", f"Mail {MARKER}@corp-mail.net about the block")}


def test_refusal_9_the_duplicate_occurrence_variant(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl, duplicate_occurrence())
    assert_refused(pub, gl, f"markers: a redaction overlaps a marker (run-{TWIN:04d}.summary.json "
                            "/next_steps/1/step email)")


def test_check_8_alone_would_have_published_the_duplicate_occurrence(tmp_path, tmp_path_factory, gl, monkeypatch):
    pub = scanned(tmp_path, tmp_path_factory, gl, duplicate_occurrence())
    monkeypatch.setattr(evidence, "marker_overlap_problems", lambda *a: [])
    build(pub, gl)
    # Equal score records from both copies: only the marker check stops this pass.
    publish.run_verify(str(pub.clone.path), paths(pub), originals_hash(pub))


@pytest.mark.parametrize("change", ["freeze", "unit", "manager", "exec"])
def test_refusal_10_the_public_environment_fails_the_contract(tmp_path, tmp_path_factory, gl, change):
    pub = setup(tmp_path, tmp_path_factory, sequence="model", stop_after=3)
    env = json.loads(pub.read("environment.json"))
    if change == "freeze":
        env["python"]["freeze"].append("-e /home/someone/project")
    elif change == "unit":
        env["server"]["environment"].append("OLLAMA_MODELS=/srv/models")
    elif change == "manager":
        env["server"]["manager_environment"].append("HOME=/root")
    else:
        env["server"]["exec_start"] = {"path": "/usr/bin/env", "argv": ["/usr/bin/env", "ollama", "serve"]}
    pub.tamper("environment.json", canonical_dumps(env))
    scan(pub, gl)
    dbl.classify_all(pub)
    assert_refused(pub, gl, "build: the public environment.json fails the publication contract")


def test_the_originals_are_verified_again_after_the_build(tmp_path, tmp_path_factory, gl, monkeypatch):
    pub = scanned(tmp_path, tmp_path_factory, gl)
    real = publish._score_records
    calls = {"n": 0}

    def tamper_between(*args, **kwargs):
        calls["n"] += 1
        out = real(*args, **kwargs)
        if calls["n"] == 2:
            pub.tamper("run-0002.harness.json", pub.read("run-0002.harness.json") + b" ", relist=False)
        return out
    monkeypatch.setattr(publish, "_score_records", tamper_between)
    assert_refused(pub, gl, "hash list: run-0002.harness.json differs")


def test_labels_that_differ_from_the_manifest_refuse(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl)
    labels = pub.clone.path / "eval" / "labels.json"
    labels.write_bytes(labels.read_bytes().replace(b"Fixture label.", b"Changed label."))
    assert_refused(pub, gl, "inputs: eval/labels.json differs from its manifest entry")


# --- Markers -----------------------------------------------------------------------------------------

def overlap(text, span_text, markers=(MARKER,)):
    start = text.index(span_text)
    item = {"file": "run-0001.summary.json", "pointer": "/next_steps/0/step", "rule": "ipv4", "start": start,
            "end": start + len(span_text)}
    return evidence.marker_overlap_problems([item], list(markers), {(item["file"], item["pointer"]): text})


def test_a_span_covering_or_partly_overlapping_the_marker_refuses():
    assert overlap(f"Mail {MARKER}@corp-mail.net", f"{MARKER}@corp-mail.net")
    assert overlap(f"x{MARKER}y", f"{MARKER[-3:]}y")


def test_a_span_beside_the_marker_passes():
    ip = dbl.private_ipv4()
    assert overlap(f"Ref {MARKER} via {ip}", ip) == []


def test_another_cases_marker_is_protected_too():
    assert overlap(f"Mail {OTHER_MARKER}@corp-mail.net", f"{OTHER_MARKER}@corp-mail.net", (MARKER, OTHER_MARKER))


def test_a_marker_on_another_line_of_the_string_does_not_count():
    ip = dbl.private_ipv4()
    assert overlap(f"{MARKER}\nBlock {ip}", ip) == []


# --- Stage separation --------------------------------------------------------------------------------

def test_no_publication_tool_opens_an_original_for_writing(tmp_path, tmp_path_factory, gl, monkeypatch):
    pub = setup(tmp_path, tmp_path_factory, worked_example())
    original = os.path.realpath(pub.original)
    seen = []
    real_open, real_os_open = builtins.open, os.open

    def record(path, flags):
        text = os.fsdecode(path) if isinstance(path, (str, bytes, os.PathLike)) else ""
        if os.path.realpath(text).startswith(original + os.sep) or os.path.realpath(text) == original:
            seen.append(flags)

    def checked_open(file, mode="r", *args, **kwargs):
        record(file, mode)
        return real_open(file, mode, *args, **kwargs)

    def checked_os_open(path, flags, *args, **kwargs):
        if kwargs.get("dir_fd") is None:
            record(path, flags)
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", checked_open)
    monkeypatch.setattr(os, "open", checked_os_open)
    scan(pub, gl)
    dbl.classify_all(pub)
    build(pub, gl)
    publish.run_verify(str(pub.clone.path), paths(pub), originals_hash(pub))
    monkeypatch.undo()
    assert seen
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
    for flags in seen:
        if isinstance(flags, str):
            assert set(flags) <= {"r", "b"}
        else:
            assert flags & write_flags == 0


def test_a_second_scan_or_build_is_refused(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl)
    with pytest.raises(evidence.PublishRefused):
        scan(pub, gl)
    build(pub, gl)
    with pytest.raises(evidence.PublishRefused):
        build(pub, gl)


def test_the_classification_is_read_from_beside_scan_and_never_modified(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl, worked_example())
    before = (pub.root / "classification.json").read_bytes()
    build(pub, gl)
    assert (pub.root / "classification.json").read_bytes() == before
    assert sorted(os.listdir(pub.root / "scan")) == ["items.json", "items.private.jsonl"]


# --- The scan list ---------------------------------------------------------------------------------

def test_scan_needs_no_classification_and_writes_a_valid_item_list(tmp_path, tmp_path_factory, gl):
    pub = setup(tmp_path, tmp_path_factory, worked_example())
    count, digest = scan(pub, gl)
    data = (pub.root / "scan" / "items.json").read_bytes()
    assert count == 1 and digest == hashlib.sha256(data).hexdigest()
    records.ScanItems.model_validate(strict_loads(data))
    for name in ("items.json", "items.private.jsonl"):
        assert stat.S_IMODE(os.stat(pub.root / "scan" / name).st_mode) == 0o400
    assert not (pub.root / "classification.json").exists()


@pytest.mark.parametrize("bad", ["gap", "file", "pointer"])
def test_a_bad_generated_item_list_is_refused_and_nothing_is_written(tmp_path, tmp_path_factory, gl, monkeypatch, bad):
    pub = setup(tmp_path, tmp_path_factory, worked_example())
    real = evidence.scan

    def broken(directory):
        items, private = real(directory)
        item = dict(items[0])
        if bad == "gap":
            item["n"] = 2
        elif bad == "file":
            item["file"] = "run-0006.harness.json"
        else:
            item["pointer"] = "/asset/owner"
        return [item], private
    monkeypatch.setattr(evidence, "scan", broken)
    with pytest.raises(Exception):
        scan(pub, gl)
    assert not (pub.root / "scan").exists()


# --- The closure check's scanner inputs ---------------------------------------------------------------

@pytest.fixture
def built_tmp(tmp_path, tmp_path_factory, gl):
    """A pass with a public.tmp/ written by the build's writer, for direct closure checks."""
    pub = scanned(tmp_path, tmp_path_factory, gl, worked_example())
    p = paths(pub)
    items, private = evidence.scan(p.original)
    _, cls = records.load_scan((pub.root / "scan" / "items.json").read_bytes(),
                               (pub.root / "classification.json").read_bytes())
    red = publish._write_public_tmp(p, items, private, cls)
    return pub, p, red


def test_closure_runs_the_secret_scanner_on_the_public_copy_with_the_given_config(built_tmp, gl, tmp_path):
    pub, p, red = built_tmp
    config = str(pub.clone.path / ".gitleaks.toml")
    assert evidence.closure_problems(p.public_tmp, red, p.original, gitleaks_binary=gl.path,
                                     gitleaks_config=config) == []
    scan_call = gl.calls()[-1]["argv"]
    assert scan_call[1] == os.path.realpath(p.public_tmp) and scan_call[3] == os.path.realpath(config)


@pytest.mark.parametrize("config", [{"findings": [{"x": 1}]}, {"exit": 2}, {"report": "missing"},
                                    {"version": "1.0.0"}])
def test_any_scanner_failure_is_a_closure_problem(built_tmp, gl, config):
    pub, p, red = built_tmp
    gl.set(**config)
    problems = evidence.closure_problems(p.public_tmp, red, p.original, gitleaks_binary=gl.path,
                                         gitleaks_config=str(pub.clone.path / ".gitleaks.toml"))
    assert problems and problems[0].startswith("closure: the secret scanner")


def test_a_synthetic_data_flag_in_the_public_copy_is_a_closure_problem(built_tmp, gl):
    pub, p, red = built_tmp
    target = Path(p.public_tmp) / "run-0002.harness.json"
    target.write_bytes(target.read_bytes().replace(b'"pass_id"', b'"%s":1,"pass_id"' % dbl.private_ipv4().encode()))
    problems = evidence.closure_problems(p.public_tmp, red, p.original, gitleaks_binary=gl.path,
                                         gitleaks_config=str(pub.clone.path / ".gitleaks.toml"))
    assert "closure: the synthetic-data rules flag run-0002.harness.json" in problems


def test_closure_has_no_default_scanner():
    with pytest.raises(TypeError):
        evidence.closure_problems("a", [], "b")


# --- The verified named copy -------------------------------------------------------------------------

@pytest.fixture
def plain(tmp_path, tmp_path_factory):
    pub = setup(tmp_path, tmp_path_factory)
    return pub, evidence.parse_hash_list((pub.root / "files.original.sha256").read_bytes())


def test_the_copy_is_named_by_the_pass_id_private_and_removed(plain):
    pub, hashes = plain
    with evidence.named_copy(str(pub.original), pub.pass_id, hashes, public=False, positions=range(1, 16)) as d:
        assert os.path.basename(d) == pub.pass_id
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(os.path.dirname(d)).st_mode) == 0o700
        assert sorted(os.listdir(d)) == sorted(hashes)
        for name in os.listdir(d):
            assert stat.S_IMODE(os.stat(os.path.join(d, name)).st_mode) == 0o600
            assert Path(d, name).read_bytes() == pub.read(name)
        kept = os.path.dirname(d)
    assert not os.path.exists(kept)


def test_a_source_that_differs_from_its_verified_hash_is_refused(plain):
    pub, hashes = plain
    hashes = dict(hashes, **{"ledger.jsonl": "0" * 64})
    with pytest.raises(evidence.PublishRefused, match="copy: ledger.jsonl differs from its verified hash"):
        with evidence.named_copy(str(pub.original), pub.pass_id, hashes, public=False, positions=range(1, 16)):
            pass


def test_a_copy_that_differs_from_its_verified_hash_is_refused(plain, monkeypatch):
    pub, hashes = plain
    real = evidence.write_in

    def corrupting(fd, path, items, *, what):
        return real(fd, path, [(n, d + b" ") for n, d in items], what=what)
    monkeypatch.setattr(evidence, "write_in", corrupting)
    created = []
    real_mkdtemp = evidence.tempfile.mkdtemp
    monkeypatch.setattr(evidence.tempfile, "mkdtemp", lambda **k: created.append(real_mkdtemp(**k)) or created[-1])
    with pytest.raises(evidence.PublishRefused, match="copy: the copy of .* differs from its verified hash"):
        with evidence.named_copy(str(pub.original), pub.pass_id, hashes, public=False, positions=range(1, 16)):
            pass
    assert created and not os.path.exists(created[0])


def test_the_copy_needs_exactly_the_verified_file_set(plain):
    pub, hashes = plain
    fewer = {k: v for k, v in hashes.items() if k != "ledger.jsonl"}
    with pytest.raises(evidence.PublishRefused, match="copy: the file set differs"):
        with evidence.named_copy(str(pub.original), pub.pass_id, fewer, public=False, positions=range(1, 16)):
            pass


def test_a_symlink_in_the_source_is_refused(plain):
    pub, hashes = plain
    os.chmod(pub.original, 0o700)
    os.symlink("ledger.jsonl", pub.original / "run-0007.summary.json")
    with pytest.raises(evidence.PublishRefused, match="symlink"):
        with evidence.named_copy(str(pub.original), pub.pass_id, hashes, public=False, positions=range(1, 16)):
            pass


def test_a_copy_that_cannot_be_removed_is_reported(plain, monkeypatch):
    pub, hashes = plain
    real_rmtree = shutil.rmtree
    left = []

    def failing(path, *a, **k):
        left.append(path)
        raise OSError("busy")
    monkeypatch.setattr(evidence.shutil, "rmtree", failing)
    with pytest.raises(evidence.PublishRefused, match="copy: the temporary copy could not be removed"):
        with evidence.named_copy(str(pub.original), pub.pass_id, hashes, public=False, positions=range(1, 16)):
            pass
    real_rmtree(left[0])


def test_a_cleanup_failure_after_another_failure_is_reported_on_stderr(plain, monkeypatch, capsys):
    pub, hashes = plain
    real_rmtree = shutil.rmtree
    left = []
    monkeypatch.setattr(evidence.shutil, "rmtree", lambda p, *a, **k: left.append(p) or (_ for _ in ()).throw(OSError()))
    with pytest.raises(RuntimeError):
        with evidence.named_copy(str(pub.original), pub.pass_id, hashes, public=False, positions=range(1, 16)):
            raise RuntimeError("inner")
    assert "a temporary copy could not be removed" in capsys.readouterr().err
    real_rmtree(left[0])


# --- Instrument-generated files hold only allowed hashes -----------------------------------------------

HEXISH = re.compile(r"^(sha256:)?[0-9a-f]{40,64}$")
ALLOWED_HASH_KEYS = {
    "environment.json": {"merge_sha", "merge_tree", "head", "head_tree", "manifest_sha256", "digest",
                         "parameters_sha256", "template_sha256"},
    "ledger.jsonl": {"prev"},
    "harness": set(),
    "redactions.json": set(),
}


def _hash_keys(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and HEXISH.fullmatch(v):
                out.add(k)
            _hash_keys(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _hash_keys(v, out)


def test_every_hash_in_an_instrument_file_names_published_bytes_or_the_pinned_model(tmp_path, tmp_path_factory, gl):
    pub = scanned(tmp_path, tmp_path_factory, gl, worked_example(), sequence="baseline")
    build(pub, gl)
    public = pub.root / "public"
    for name in os.listdir(public):
        if name.endswith((".summary.json", ".audit.jsonl")) or name == "files.sha256":
            continue   # CLI output, and the public hash list of published files
        keys = set()
        for line in (public / name).read_bytes().splitlines():
            _hash_keys(json.loads(line), keys)
        kind = "harness" if name.endswith(".harness.json") else name
        assert keys <= ALLOWED_HASH_KEYS[kind], (name, keys)
    model = setup(tmp_path / "m", tmp_path_factory, sequence="model", stop_after=2)
    keys = set()
    _hash_keys(json.loads(model.read("environment.json")), keys)
    assert keys <= ALLOWED_HASH_KEYS["environment.json"] and {"digest", "parameters_sha256"} <= keys


# --- Creation modes -------------------------------------------------------------------------------------

def test_publication_creates_only_private_files_whatever_the_umask(tmp_path, tmp_path_factory, gl, monkeypatch):
    pub = setup(tmp_path, tmp_path_factory, worked_example())
    created = []
    real_open = os.open

    def recording(name, flags, mode=0o777, *, dir_fd=None):
        fd = real_open(name, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT and dir_fd is not None:
            created.append((mode, stat.S_IMODE(os.fstat(fd).st_mode)))
        return fd
    old = os.umask(0)
    monkeypatch.setattr(os, "open", recording)
    try:
        scan(pub, gl)
        dbl.classify_all(pub)
        build(pub, gl)
    finally:
        monkeypatch.undo()
        os.umask(old)
    assert created and all(entry == (0o600, 0o600) for entry in created)
    for root, dirs, _ in os.walk(pub.root / "public"):
        assert stat.S_IMODE(os.stat(root).st_mode) == 0o700


# --- The real pinned binary (run during implementation with EVAL_GITLEAKS_BINARY) -------------------------

@pytest.mark.skipif(not os.environ.get("EVAL_GITLEAKS_BINARY"), reason="needs the pinned gitleaks binary")
def test_positive_control_with_the_real_binary(tmp_path, tmp_path_factory):
    binary = os.path.realpath(os.environ["EVAL_GITLEAKS_BINARY"])
    pub = setup(tmp_path, tmp_path_factory)
    config = str(pub.clone.path / ".gitleaks.toml")
    ss = evidence.load_secret_scan()
    h2 = load_h2()
    assert evidence.gitleaks_findings(binary, str(pub.original), config) == 0
    for name in sorted(os.listdir(pub.original)):
        assert evidence.h2_problems(name, pub.read(name)) == []
    kinds = ["run-0002.summary.json", "run-0002.audit.jsonl", "run-0002.harness.json", "ledger.jsonl",
             "environment.json"]
    for name in kinds:
        work = tmp_path / f"control-{name}"
        shutil.copytree(pub.original, work)
        os.chmod(work, 0o700)
        target = work / name
        os.chmod(target, 0o600)
        data = target.read_bytes()
        token = ss.token("github-pat")
        target.write_bytes(data.replace(b"\n", f' "{token}"\n'.encode(), 1) if not name.endswith(".jsonl")
                           else data + f'{{"note":"{token}"}}\n'.encode())
        assert evidence.gitleaks_findings(binary, str(work), config) >= 1, name
        target.write_bytes(data + f"{dbl.private_ipv4()}\n".encode())
        assert evidence.h2_problems(name, target.read_bytes()), name
