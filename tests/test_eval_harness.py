"""The pass runner: layout, classification of every ending, check failures, the store, and write order."""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import threading

import pytest

import test_eval_doubles as dbl
from evaluation import classify, evidence, harness, probe, records, scorer
from evaluation.common import canonical_dumps
from triage.agent import Limits

ollama_stub = dbl.ollama_stub

FAKE_CHILD = r'''
import os, sys, time
mode, scratch = sys.argv[1], sys.argv[2]
rest = sys.argv[3:]
def hits():
    with open(os.path.join(scratch, "hits.json"), "w") as f:
        f.write('{"calls":0,"run_id":null,"runbook_hits":null}\n')
if mode == "exit":
    hits(); sys.exit(int(rest[0]))
if mode == "stderr":
    hits(); sys.stderr.write(rest[1] + "\n"); sys.exit(int(rest[0]))
if mode == "audit":
    hits()
    with open(os.path.join(scratch, "audit.jsonl"), "w") as f:
        f.write('{"event.name":"triage.run","gen_ai.conversation.id":"x"}\n')
    sys.exit(int(rest[0]))
if mode == "invalid0":
    hits(); sys.stdout.write("not a summary\n"); sys.exit(0)
if mode == "nohits":
    sys.exit(int(rest[0]))
if mode == "badhits":
    with open(os.path.join(scratch, "hits.json"), "w") as f:
        f.write("{")
    sys.exit(1)
if mode == "signal":
    os.kill(os.getpid(), 9)
if mode == "hang":
    time.sleep(60)
if mode == "flood":
    sys.stdout.buffer.write(b"x" * (2 << 20)); sys.stdout.flush(); sys.exit(0)
'''


class Injector:
    """A spawn hook: positions listed get a fake child, all others the real one."""

    def __init__(self, behaviours: dict[int, tuple], before=None):
        self.behaviours = behaviours
        self.before = before or {}
        self.spawned: list[int] = []

    def __call__(self, argv, env, scratch):
        position = int(os.path.basename(scratch).split("-")[1])
        self.spawned.append(position)
        if position in self.before:
            self.before[position]()
        if position not in self.behaviours:
            # A real child may only run the heuristic backend: no test runs the Ollama backend.
            assert env["TRIAGE_BACKEND"] == "heuristic"
            return harness.default_spawn(argv, env, scratch)
        mode, *rest = self.behaviours[position]
        return subprocess.Popen([sys.executable, "-I", "-c", FAKE_CHILD, mode, scratch, *map(str, rest)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                cwd=scratch, start_new_session=True)


@pytest.fixture
def clone(tmp_path, tmp_path_factory, monkeypatch):
    """One test case, so a baseline pass is three runs: warm-up, scored, determinism."""
    monkeypatch.setenv("OLLAMA_HOST", "127.0.0.1:11434")
    return dbl.make_clone(tmp_path, tmp_path_factory, n_tests=1)


@pytest.fixture
def clone2(tmp_path, tmp_path_factory, monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "127.0.0.1:11434")
    return dbl.make_clone(tmp_path, tmp_path_factory, n_tests=2)


@pytest.fixture
def store(tmp_path):
    return dbl.private_dir(tmp_path / "store")


def run_pass(clone, store, pass_id="baseline-001", **hook_kwargs):
    hooks = clone.hooks(**hook_kwargs)
    return harness.execute_pass(str(clone.path), str(store), pass_id, clone.merge_sha, clone.merge_tree,
                                hooks=hooks)


def original(store, pass_id="baseline-001"):
    return store / pass_id / "original"


def h_record(store, position, pass_id="baseline-001"):
    return json.loads((original(store, pass_id) / f"run-{position:04d}.harness.json").read_bytes())


def ledger(store, pass_id="baseline-001"):
    return records.verify_ledger((original(store, pass_id) / "ledger.jsonl").read_bytes())


def empty_scan(tmp_path):
    out = dbl.private_dir(tmp_path / "scan-inputs")
    scan = canonical_dumps({"version": 1, "items": []})
    (out / "items.json").write_bytes(scan)
    import hashlib
    (out / "classification.json").write_bytes(canonical_dumps(
        {"version": 1, "scan_sha256": hashlib.sha256(scan).hexdigest(), "items": {}}))
    return out / "items.json", out / "classification.json"


# --- End to end ---------------------------------------------------------------------------

def test_a_baseline_pass_gives_the_layout_and_scores_without_a_defect(clone2, store, tmp_path):
    clone = clone2
    assert run_pass(clone, store) == "complete"
    names = sorted(os.listdir(original(store)))
    expected = ["environment.json", "ledger.jsonl"] + [f"run-{p:04d}.{k}" for p in range(1, 6)
                                                       for k in ("audit.jsonl", "harness.json", "summary.json")]
    assert names == sorted(expected)
    assert sorted(os.listdir(store / "baseline-001")) == ["files.original.sha256", "original"]
    assert evidence.file_problems(str(original(store)), range(1, 6), public=False) == []
    registry, labels, order = clone.models()
    hashes = evidence.parse_hash_list((store / "baseline-001" / "files.original.sha256").read_bytes())
    scan_items, classification = empty_scan(tmp_path)
    with evidence.named_copy(str(original(store)), "baseline-001", hashes, public=False,
                             positions=range(1, 6)) as copy_dir:
        data = records.load_pass(copy_dir, registry=registry, labels=labels, order=order, sequence="baseline",
                                 public=False, scan_items=scan_items, classification=classification)
    assert data.defects == () and data.pass_class == "complete"
    assert len(scorer.score_pass(data, records.case_views(registry, labels))) == 5
    env = json.loads((original(store) / "environment.json").read_bytes())
    assert list(env) == ["version", "pass_id", "backend", "merge_sha", "merge_tree", "head", "head_tree",
                         "manifest_sha256", "python", "embedder", "ollama", "server", "server_restarts",
                         "started_at", "ended_at", "end_check"]
    assert env["end_check"] == "ok" and env["ollama"] is None and env["head"] == clone.merge_sha


# --- Classification of every ending --------------------------------------------------------

ROWS = [
    # behaviour at position 2, run class, reason, pass class, runs started
    (("exit", 1), "no_output", "exit", "complete", 3),
    (("exit", 2), "no_output", "exit", "complete", 3),
    (("exit", 3), "no_output", "exit", "complete", 3),
    (("exit", 4), "no_output", "exit", "complete", 3),
    (("exit", 5), "no_output", "exit", "complete", 3),
    (("exit", 130), "no_output", "exit", "complete", 3),
    (("exit", 70), "no_output", "exit", "defective", 2),
    (("exit", 6), "no_output", "exit", "defective", 2),
    (("exit", 0), "no_output", "exit", "defective", 2),
    (("invalid0",), "no_output", "exit", "defective", 2),
    (("nohits", 1), "no_output", "exit", "defective", 2),
    (("badhits",), "no_output", "exit", "defective", 2),
    (("signal",), "no_output", "signal", "complete", 3),
    (("hang",), "no_output", "deadline", "complete", 3),
    (("flood",), "no_output", "signal", "defective", 2),
]


@pytest.mark.parametrize("behaviour, run_class, reason, pass_class, started", ROWS, ids=lambda x: str(x))
def test_each_ending_is_classified_and_never_retried(clone, store, behaviour, run_class, reason, pass_class, started):
    injector = Injector({2: behaviour, 3: ("exit", 1)})
    result = run_pass(clone, store, spawn=injector, deadline_s=1.0)
    assert result == pass_class
    assert injector.spawned == list(range(1, started + 1))
    h = h_record(store, 2)
    assert (h["class"], h["reason"]) == (run_class, reason)
    entries = ledger(store)
    assert [e.position for e in entries if e.event == "run_start"] == list(range(1, started + 1))
    assert [e.class_ for e in entries if e.event == "run_end" and e.position == 2] == [run_class]
    assert entries[-1].class_ == pass_class
    assert not (original(store) / "run-0002.summary.json").exists()


def observed(**kwargs):
    base = {"exit_status": 1, "signal": None, "deadline": False, "interrupted": False, "stdout": b"",
            "hits": {"calls": 0, "run_id": None, "runbook_hits": None}, "runner_error": False}
    return classify.Observed(**{**base, **kwargs})


@pytest.mark.parametrize("kwargs, expected", [
    ({"runner_error": True}, ("no_output", "exit", "defective")),
    ({"runner_error": True, "exit_status": None, "signal": 9}, ("no_output", "signal", "defective")),
    ({"interrupted": True, "exit_status": None, "signal": 15}, ("no_output", "interrupted", "incomplete")),
    ({"deadline": True, "exit_status": None, "signal": 15}, ("no_output", "deadline", None)),
    ({"exit_status": None, "signal": 9}, ("no_output", "signal", None)),
    ({"exit_status": 70}, ("no_output", "exit", "defective")),
    ({"exit_status": 6}, ("no_output", "exit", "defective")),
    ({"exit_status": 1, "hits": None}, ("no_output", "exit", "defective")),
    ({"exit_status": 0, "stdout": b"not a summary\n"}, ("no_output", "exit", "defective")),
    ({"exit_status": 3}, ("no_output", "exit", None)),
    ({"exit_status": 130}, ("no_output", "exit", None)),
])
def test_each_classification_row_gives_its_run_class_and_pass_cause(kwargs, expected):
    result = classify.classify(observed(**kwargs))
    assert (result.run_class, result.reason, result.pass_cause) == expected


def test_a_no_output_run_keeps_the_audit_it_wrote(clone, store):
    run_pass(clone, store, spawn=Injector({2: ("audit", 1), 3: ("exit", 1)}))
    h = h_record(store, 2)
    assert h["files"] == {"summary": False, "audit": True}
    assert stat.S_IMODE(os.stat(original(store) / "run-0002.audit.jsonl").st_mode) == 0o400


def test_the_cli_message_is_kept_only_when_it_is_a_known_message(clone, store):
    known = "alert-triage: error: alert input is not a valid sigma alert"
    injector = Injector({2: ("stderr", 3, known), 3: ("stderr", 3, "free text " + dbl.private_ipv4())})
    assert run_pass(clone, store, spawn=injector) == "complete"
    assert h_record(store, 2)["cli_message"] == known and h_record(store, 2)["stderr_nonempty"] is True
    assert h_record(store, 3)["cli_message"] is None and h_record(store, 3)["stderr_nonempty"] is True
    assert (h_record(store, 3)["class"], h_record(store, 3)["reason"]) == ("no_output", "exit")


def test_an_operator_interrupt_ends_the_run_and_the_pass(clone, store):
    def interrupt():
        threading.Timer(0.5, lambda: os.kill(os.getpid(), signal.SIGTERM)).start()
    injector = Injector({2: ("hang",)}, before={2: interrupt})
    assert run_pass(clone, store, spawn=injector) == "incomplete"
    h = h_record(store, 2)
    assert (h["class"], h["reason"]) == ("no_output", "interrupted")
    assert injector.spawned == [1, 2]
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL


def test_each_run_is_in_the_ledger_before_its_child_starts(clone, store):
    seen = {}

    def look(position):
        def check():
            data = (original(store) / "ledger.jsonl").read_bytes()
            seen[position] = json.loads(data.splitlines()[-1])
        return check
    run_pass(clone, store, spawn=Injector({}, before={p: look(p) for p in (1, 2, 3)}))
    for position, line in seen.items():
        assert (line["event"], line["position"]) == ("run_start", position)


def test_the_child_environment_is_built_from_nothing(clone, store, monkeypatch):
    for name, value in (("PYTHONPATH", "/elsewhere"), ("TRIAGE_DATA_DIR", "/elsewhere"), ("OLLAMA_MODEL", "x"),
                        ("HTTPS_PROXY", "http://proxy.invalid:3128"), ("LANG", "de_DE.UTF-8")):
        monkeypatch.setenv(name, value)
    envs = []

    class Recording(Injector):
        def __call__(self, argv, env, scratch):
            envs.append(dict(env))
            return super().__call__(argv, env, scratch)
    run_pass(clone, store, spawn=Recording({2: ("exit", 1), 3: ("exit", 1)}))
    scratch = str(store / "baseline-001" / "scratch-0001")
    assert envs[0] == {"PATH": "/usr/bin:/bin", "HOME": scratch, "LANG": "C.UTF-8", "TZ": "UTC",
                       "PYTHONHASHSEED": "0", "TRIAGE_BACKEND": "heuristic", "TRIAGE_EMBEDDER": "hashing",
                       "OLLAMA_HOST": "http://127.0.0.1:11434"}


def flaky_root(clone, bad_calls):
    """A package-resolution hook that answers wrongly on the listed calls, rightly otherwise."""
    real = os.path.realpath(clone.path)
    calls = {"n": 0}

    def resolved_root(name):
        if name == "triage":
            calls["n"] += 1
        return "/elsewhere" if calls["n"] in bad_calls else real
    return resolved_root, calls


def test_a_transient_later_code_failure_still_voids_the_pass(clone, store):
    root, _ = flaky_root(clone, {2})
    injector = Injector({p: ("exit", 1) for p in range(2, 4)})
    assert run_pass(clone, store, resolved_root=root, spawn=injector) == "void"
    assert injector.spawned == [1]


def test_the_code_check_is_never_retried(clone, store):
    root, calls = flaky_root(clone, {1})
    assert run_pass(clone, store, resolved_root=root, sleep=lambda s: None) == "incomplete"
    assert [e.event for e in ledger(store)] == ["pass_start", "check_failed", "pass_end"]
    assert calls["n"] == 2   # the failed first check, then the end-of-pass re-check


def test_the_deadline_is_the_agent_timeout_plus_two_minutes():
    assert harness.RUN_DEADLINE_S == Limits().run_timeout_s + 120


# --- Check failures -----------------------------------------------------------------------------

def test_a_first_code_check_failure_leaves_the_pass_incomplete(clone, store):
    (clone.path / "untracked.txt").write_text("x")
    assert run_pass(clone, store) == "incomplete"
    entries = ledger(store)
    assert [(e.event, e.position) for e in entries] == [("pass_start", None), ("check_failed", 1),
                                                         ("pass_end", None)]


def test_a_later_code_check_failure_voids_the_pass(clone, store):
    injector = Injector({}, before={1: lambda: (clone.path / "untracked.txt").write_text("x")})
    assert run_pass(clone, store, spawn=injector) == "void"
    assert injector.spawned == [1]
    assert [e.event for e in ledger(store)][-2:] == ["check_failed", "pass_end"]


def test_other_checks_are_retried_three_times_then_the_pass_is_incomplete(clone, store):
    sleeps = []
    assert run_pass(clone, store, freeze=lambda: "changed==1\n", sleep=sleeps.append, retry_wait_s=60.0) \
        == "incomplete"
    assert sleeps == [60.0, 60.0]
    assert [e.event for e in ledger(store)] == ["pass_start", "check_failed", "pass_end"]


def test_a_check_that_passes_on_a_retry_records_its_attempts(clone, store):
    calls = {"n": 0}
    good = dbl.freeze_text(clone.path)

    def flaky():
        calls["n"] += 1
        return good if calls["n"] >= 3 else "changed==1\n"
    injector = Injector({p: ("exit", 1) for p in range(2, 4)})
    assert run_pass(clone, store, freeze=flaky, sleep=lambda s: None, spawn=injector) == "complete"
    assert h_record(store, 1)["checks"]["attempts"] == 3 and h_record(store, 2)["checks"]["attempts"] == 1


def test_an_end_of_pass_check_failure_voids_the_pass(clone, store):
    calls = {"n": 0}
    good = dbl.freeze_text(clone.path)

    def last_fails():
        calls["n"] += 1
        return good if calls["n"] <= 3 else "changed==1\n"
    injector = Injector({p: ("exit", 1) for p in range(2, 4)})
    assert run_pass(clone, store, freeze=last_fails, spawn=injector) == "void"
    assert json.loads((original(store) / "environment.json").read_bytes())["end_check"] == "python"


# --- Model passes (stub server and fake service manager; children injected) ---------------------

@pytest.fixture
def model_setup(tmp_path, tmp_path_factory, ollama_stub, monkeypatch):
    exe = dbl.execution_dict(tmp_path / "clone")
    exe["ollama"] = probe.ollama_identity(ollama_stub.endpoint(), "qwen3:8b")
    clone = dbl.make_clone(tmp_path, tmp_path_factory, execution=exe, n_tests=1)
    monkeypatch.setenv("OLLAMA_HOST", f"127.0.0.1:{ollama_stub.port}")
    return clone, dbl.make_systemctl(tmp_path / "bin")


def test_a_model_pass_counts_server_restarts_without_failing(model_setup, store, ollama_stub):
    clone, fake = model_setup
    injector = Injector({p: ("exit", 1) for p in range(1, 5)}, before={3: lambda: fake.set(main_pid=777)})
    assert run_pass(clone, store, "model-001", spawn=injector, systemctl=fake.path) == "complete"
    assert h_record(store, 2, "model-001")["server_restarts"] == 0
    assert h_record(store, 4, "model-001")["server_restarts"] == 1
    env = json.loads((original(store, "model-001") / "environment.json").read_bytes())
    assert env["server_restarts"] == 1 and env["server"]["unit"] == "ollama.service"
    assert ollama_stub.other_requests == 0 and injector.spawned == [1, 2, 3, 4]


def test_a_model_pass_cannot_fall_through_to_a_real_ollama_child(model_setup, store, ollama_stub):
    clone, fake = model_setup
    injector = Injector({1: ("exit", 1)})   # positions 2 to 4 are not covered
    with pytest.raises(AssertionError):
        run_pass(clone, store, "model-001", spawn=injector, systemctl=fake.path)
    assert injector.spawned == [1, 2]
    assert ollama_stub.model_calls() == []


@pytest.mark.parametrize("when, expected", [("first", "incomplete"), ("later-transient", "incomplete"),
                                            ("later-persistent", "void"), ("end", "void")])
def test_a_server_settings_failure_gives_the_class_for_when_it_happened(model_setup, store, when, expected):
    # A later pre-run failure stops the pass as incomplete; if the change is
    # still there at the end-of-pass re-check, the pass is void as well.
    clone, fake = model_setup
    before = {}
    if when == "first":
        fake.set(active="inactive")
    elif when == "later-transient":
        before = {2: lambda: fake.set(fail_calls=3)}
    elif when == "later-persistent":
        before = {2: lambda: fake.set(environment=["OLLAMA_HOST=127.0.0.1:11434"])}
    else:
        before = {4: lambda: fake.set(active="inactive")}
    injector = Injector({p: ("exit", 1) for p in range(1, 5)}, before=before)
    assert run_pass(clone, store, "model-001", spawn=injector, systemctl=fake.path, sleep=lambda s: None) == expected


def test_an_ollama_identity_change_gives_the_class_for_when_it_happened(model_setup, store, ollama_stub):
    clone, fake = model_setup
    injector = Injector({p: ("exit", 1) for p in range(1, 5)},
                        before={4: lambda: ollama_stub.identity.update(version="9.9.9")})
    assert run_pass(clone, store, "model-001", spawn=injector, systemctl=fake.path) == "void"
    env = json.loads((original(store, "model-001") / "environment.json").read_bytes())
    assert env["end_check"] == "ollama"


# --- The store ----------------------------------------------------------------------------------

def test_the_store_is_refused_inside_the_clone(clone):
    inside = dbl.private_dir(clone.path / "store")
    with pytest.raises(harness.HarnessRefused):
        harness.execute_pass(str(clone.path), str(inside), "baseline-001", clone.merge_sha, clone.merge_tree,
                             hooks=clone.hooks())
    assert list(inside.iterdir()) == []


def test_a_symlinked_store_is_refused(clone, store, tmp_path):
    os.symlink(store, tmp_path / "link")
    with pytest.raises(harness.HarnessRefused):
        run_pass_at(clone, tmp_path / "link")


def run_pass_at(clone, store, pass_id="baseline-001"):
    return harness.execute_pass(str(clone.path), str(store), pass_id, clone.merge_sha, clone.merge_tree,
                                hooks=clone.hooks())


@pytest.mark.parametrize("mode", [0o750, 0o705, 0o770, 0o777])
def test_a_group_or_world_accessible_store_is_refused(clone, store, mode):
    os.chmod(store, mode)
    with pytest.raises(harness.HarnessRefused):
        run_pass_at(clone, store)
    assert list(store.iterdir()) == []


@pytest.mark.skipif(os.geteuid() != 0, reason="needs a directory owned by another user")
def test_another_users_store_is_refused(clone, store):
    os.chown(store, 12345, 12345)
    with pytest.raises(harness.HarnessRefused):
        run_pass_at(clone, store)


@pytest.mark.parametrize("pass_id", ["baseline-002", "baseline-000", "model-002", "baseline-1", "other-001"])
def test_a_pass_id_out_of_sequence_is_refused(clone, store, pass_id):
    with pytest.raises(harness.HarnessRefused):
        run_pass_at(clone, store, pass_id)
    assert list(store.iterdir()) == []


def test_an_existing_pass_is_never_reused(clone, store):
    (store / "baseline-001").mkdir(mode=0o700)
    with pytest.raises(harness.HarnessRefused):
        run_pass_at(clone, store, "baseline-001")
    with pytest.raises(harness.HarnessRefused):
        run_pass_at(clone, store, "baseline-003")


# --- Pass-end order, read-only originals and creation modes ----------------------------------------

def test_pass_end_writes_in_order_and_leaves_read_only_originals(clone, store):
    order = []
    injector = Injector({p: ("exit", 1) for p in range(2, 4)})
    run_pass(clone, store, writer=order.append, spawn=injector)
    assert order == ["environment.json", "pass_end", "files.original.sha256"]
    listed = evidence.parse_hash_list((store / "baseline-001" / "files.original.sha256").read_bytes())
    assert sorted(listed) == sorted(os.listdir(original(store)))
    assert evidence.hash_list_problems(str(original(store)), evidence.hash_list(str(original(store)))) == []
    for name in os.listdir(original(store)):
        assert stat.S_IMODE(os.stat(original(store) / name).st_mode) == 0o400
    assert stat.S_IMODE(os.stat(original(store)).st_mode) == 0o500
    assert stat.S_IMODE(os.stat(store / "baseline-001" / "files.original.sha256").st_mode) == 0o400


def test_every_file_and_directory_is_created_private_whatever_the_umask(clone, store, monkeypatch):
    created_files, created_dirs = [], []
    real_open, real_mkdir = os.open, os.mkdir

    def recording_open(name, flags, mode=0o777, *, dir_fd=None):
        fd = real_open(name, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT:
            created_files.append((mode, stat.S_IMODE(os.fstat(fd).st_mode)))
        return fd

    def recording_mkdir(path, mode=0o777, *, dir_fd=None):
        created_dirs.append(mode)
        return real_mkdir(path, mode, dir_fd=dir_fd)

    old = os.umask(0)
    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "mkdir", recording_mkdir)
    try:
        run_pass(clone, store, spawn=Injector({p: ("exit", 1) for p in range(2, 4)}))
    finally:
        monkeypatch.undo()
        os.umask(old)
    assert created_files and all(entry == (0o600, 0o600) for entry in created_files)
    assert created_dirs and all(mode == 0o700 for mode in created_dirs)
