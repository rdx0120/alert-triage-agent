"""Test doubles for the evaluation harness tests, and tests of the doubles themselves.

Nothing here is committed data: scratch clones, cases, labels, orders,
manifests, fake executables and every value that must be flagged are built
at test run time in temporary directories. The only server is a stub bound
to 127.0.0.1 on a free port.

Other test_eval_* modules import this one as `import test_eval_doubles`.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from evaluation import identity, manifest, order as order_mod, records
from evaluation.common import canonical_dumps
from triage.ingest import load_alert

REPO = Path(__file__).resolve().parent.parent
GIT_IDENTITY = ("-c", "user.name=eval-test", "-c", "user.email=eval-test@example.invalid",
                "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main")
SEED = "5" * 64
WARMUP = "dev-password-spray"
SIGMA = REPO / "samples" / "alerts" / "sigma"
TEST_SOURCES = ("password_spray", "suspicious_encoded_powershell", "mail_forwarding_rule_created",
                "edr_agent_tampering")
RUNBOOK = {"password_spray": "password_spray.md", "suspicious_encoded_powershell": "suspicious_encoded_powershell.md",
           "mail_forwarding_rule_created": "mail_forwarding_rule_created.md",
           "edr_agent_tampering": "edr_agent_tampering.md"}


def git(repo: Path | str, *args: str) -> str:
    with identity._private_home() as home:
        proc = subprocess.run(["git", *GIT_IDENTITY, "-C", str(repo), *args], env=identity.git_env(home),
                              capture_output=True, text=True, check=True)
    return proc.stdout


def worktree_files() -> list[str]:
    """The repository's tracked and new, non-ignored files: the code under test, as on disk."""
    out = git(REPO, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return sorted(p for p in out.split("\0") if p and (REPO / p).is_file() and not (REPO / p).is_symlink())


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return Path(os.path.realpath(path))


# --- Execution identity and the scratch clone ------------------------------------------

def freeze_text(clone: Path) -> str:
    """A fixed package list for the clone, standing in for pip freeze (whose editable line points elsewhere)."""
    return f"annotated-types==0.7.0\n-e {os.path.realpath(clone)}\npydantic==2.9.2\n"


def ollama_identity(model: str = "qwen3:8b") -> dict:
    return {"version": "0.12.3", "model": model, "digest": "sha256:" + "a" * 64,
            "parameters_sha256": hashlib.sha256(b"temperature 0").hexdigest(),
            "template_sha256": hashlib.sha256(b"{{ .Prompt }}").hexdigest(),
            "format": "gguf", "family": "qwen3", "parameter_size": "8.2B", "quantization_level": "Q4_K_M"}


def server_settings() -> dict:
    return {"unit": "ollama.service",
            "environment": ["OLLAMA_HOST=127.0.0.1:11434", "OLLAMA_CONTEXT_LENGTH=8192"],
            "manager_environment": ["LANG=C.UTF-8", "PATH=/usr/local/bin:/usr/bin:/bin"],
            "exec_start": {"path": "/usr/bin/ollama", "argv": ["/usr/bin/ollama", "serve"]}}


def execution_dict(clone: Path, *, embedder: str = "hashing") -> dict:
    import platform
    return {"python": {"version": sys.version, "cache_tag": sys.implementation.cache_tag,
                       "machine": platform.machine(),
                       "freeze": identity.normalize_freeze(freeze_text(clone), str(clone))},
            "embedder": embedder, "think": False, "ollama": ollama_identity(), "server": server_settings()}


def alert_facts(raw: bytes) -> tuple[str, str]:
    alert = load_alert(raw, fmt="sigma")
    return alert.alert_id, alert.rule_level


def registry_doc(tests: list[tuple[str, str]]) -> tuple[dict, dict[str, bytes]]:
    """The registry and the generated test-case files. tests is [(case_id, sample stem)]."""
    raw_dev = (SIGMA / "password_spray.json").read_bytes()
    dev_id, dev_level = alert_facts(raw_dev)
    cases = [{"case_id": WARMUP, "family": "dev", "format": "sigma", "path": "samples/alerts/sigma/password_spray.json",
              "clean_twin": None, "phrasing": None, "alert_id": dev_id, "rule_level": dev_level}]
    files = {}
    for cid, stem in tests:
        doc = json.loads((SIGMA / f"{stem}.json").read_text(encoding="utf-8"))
        doc["alert_id"] = f"eval-{cid}"
        data = (json.dumps(doc, indent=2) + "\n").encode("ascii")
        path = f"eval/cases/test/{cid}.json"
        files[path] = data
        alert_id, level = alert_facts(data)
        cases.append({"case_id": cid, "family": "A", "format": "sigma", "path": path, "clean_twin": None,
                      "phrasing": None, "alert_id": alert_id, "rule_level": level})
    return {"version": 1, "cases": cases}, files


def labels_doc(registry: dict, stems: dict[str, str], rubric: bytes) -> dict:
    entries = []
    for case in registry["cases"]:
        stem = stems.get(case["case_id"], "password_spray")
        entries.append({"case_id": case["case_id"], "expected_severity": case["rule_level"],
                        "acceptable_techniques": [], "expected_status": "triaged",
                        "expected_runbook": RUNBOOK[stem], "expected_flagged": None, "objectives": None,
                        "rationale": [{"field": "alert.rule_level", "note": "Generated test label."}]})
    return {"version": 1, "rubric_sha256": hashlib.sha256(rubric).hexdigest(), "cases": entries}


@dataclass
class Clone:
    path: Path
    merge_sha: str
    merge_tree: str
    registry: dict
    labels: dict
    order: dict
    manifest_bytes: bytes
    extra: dict = field(default_factory=dict)

    def hooks(self, **kwargs):
        from evaluation.harness import Hooks
        real = os.path.realpath(self.path)
        kwargs.setdefault("freeze", lambda: freeze_text(self.path))
        kwargs.setdefault("resolved_root", lambda name: real)
        return Hooks(**kwargs)

    def models(self):
        registry = records.Registry.model_validate(self.registry)
        return registry, records.Labels.model_validate(self.labels), records.Order.model_validate(self.order)


_TEMPLATE: dict[str, Path] = {}


def _template(tmp_factory) -> Path:
    if "path" not in _TEMPLATE:
        root = Path(tmp_factory.mktemp("clone-template"))
        for rel in worktree_files():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / rel, target)
        _TEMPLATE["path"] = root
    return _TEMPLATE["path"]


def make_clone(root: Path, tmp_factory, *, n_tests: int = 2, embedder: str = "hashing",
               execution: dict | None = None, extra_files: dict[str, bytes] | None = None,
               inputs: tuple[dict, dict, dict] | None = None) -> Clone:
    """A committed scratch clone with generated (or given) cases, labels, order, and a manifest."""
    path = Path(os.path.realpath(root)) / "clone"
    shutil.copytree(_template(tmp_factory), path)
    if inputs is None:
        tests = [(f"test-{TEST_SOURCES[i].replace('_', '-')}", TEST_SOURCES[i]) for i in range(n_tests)]
        registry, files = registry_doc(tests)
        stems = {cid: stem for cid, stem in tests}
        labels = labels_doc(registry, stems, (path / "eval" / "rubric.md").read_bytes())
        order = order_mod.generate(records.Registry.model_validate(registry), SEED, WARMUP)
    else:
        (registry, labels, order), files = inputs, {}
    for rel, data in {**files, **(extra_files or {})}.items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        (path / rel).write_bytes(data)
    (path / "eval" / "cases.json").write_bytes(canonical_dumps(registry))
    (path / "eval" / "labels.json").write_bytes(canonical_dumps(labels))
    (path / "eval" / "order.json").write_bytes(canonical_dumps(order))
    git(path, "init", "-q")
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "scratch")
    exe = manifest.Execution.model_validate(execution or execution_dict(path, embedder=embedder))
    data = manifest.build(str(path), exe)
    (path / "eval" / "manifest.json").write_bytes(data)
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "manifest")
    head = git(path, "rev-parse", "HEAD").strip()
    tree = git(path, "rev-parse", "HEAD^{tree}").strip()
    return Clone(path, head, tree, registry, labels, order, data)


# --- Production-shaped passes for the publication tests ----------------------------------

def production_doc() -> dict:
    """The 1a aggregation fixture with production-shaped case IDs (k = 3)."""
    import test_eval_aggregate
    return test_eval_aggregate.production_doc()


def environment_doc(clone: Clone, pass_id: str, *, execution: dict | None = None) -> dict:
    exe = execution or execution_dict(clone.path)
    model = pass_id.startswith("model-")
    return {"version": 1, "pass_id": pass_id, "backend": "ollama" if model else "heuristic",
            "merge_sha": clone.merge_sha, "merge_tree": clone.merge_tree, "head": clone.merge_sha,
            "head_tree": clone.merge_tree, "manifest_sha256": hashlib.sha256(clone.manifest_bytes).hexdigest(),
            "python": exe["python"], "embedder": exe["embedder"], "ollama": exe["ollama"] if model else None,
            "server": exe["server"] if model else None, "server_restarts": 0 if model else None,
            "started_at": "2026-01-01T00:00:00.000Z", "ended_at": "2026-01-01T00:10:00.000Z", "end_check": "ok"}


@dataclass
class Published:
    clone: Clone
    store: Path
    pass_id: str
    doc: dict
    runs: list

    @property
    def root(self) -> Path:
        return self.store / self.pass_id

    @property
    def original(self) -> Path:
        return self.root / "original"

    def tamper(self, name: str, data: bytes, *, relist: bool = True) -> None:
        """Replace an original (and, unless told not to, its hash-list line), as an attacker with write access could.

        The modes in force before the edit are put back afterwards (a new file
        gets the completed-original 0400), so the edit itself changes no mode,
        and a mode a test changed on purpose is never hidden.
        """
        dir_mode = stat.S_IMODE(os.stat(self.original).st_mode)
        target = self.original / name
        existed = target.exists()
        file_mode = stat.S_IMODE(os.stat(target).st_mode) if existed else 0o400
        os.chmod(self.original, 0o700)
        if existed:
            os.chmod(target, 0o600)
        target.write_bytes(data)
        os.chmod(target, file_mode)
        os.chmod(self.original, dir_mode)
        if relist:
            from evaluation import evidence
            self.rewrite_listing(evidence.hash_list(str(self.original)))

    def rewrite_listing(self, data: bytes) -> None:
        """Replace files.original.sha256, keeping its mode."""
        listing = self.root / "files.original.sha256"
        mode = stat.S_IMODE(os.stat(listing).st_mode)
        os.chmod(listing, 0o600)
        listing.write_bytes(data)
        os.chmod(listing, mode)

    def read(self, name: str) -> bytes:
        return (self.original / name).read_bytes()


def production_pass(tmp_path: Path, tmp_factory, *, specs: dict | None = None, stop_after: int = 6,
                    sequence: str = "baseline", end_class: str = "incomplete", environment: dict | None = None
                    ) -> Published:
    """A pass in the store layout, built with the 1a fixture builder from the renamed aggregation fixture."""
    import test_eval_fixtures as fx
    from evaluation import evidence
    doc = production_doc()
    clone = make_clone(tmp_path, tmp_factory, inputs=(doc["registry"], doc["labels"], doc["order"]))
    store = private_dir(tmp_path / "store")
    pass_id = f"{sequence}-001"
    base = fx.scorer_doc()["base"]
    cases = {c["case_id"]: c for c in doc["registry"]["cases"]}
    entries = doc["order"][sequence][:stop_after]
    runs = [fx.build_run(base, cases, pass_id, sequence, e, (specs or {}).get(e["position"], {})) for e in entries]
    orig = store / pass_id / "original"
    os.makedirs(orig, mode=0o700)
    os.chmod(store / pass_id, 0o700)
    for run in runs:
        stem = orig / f"run-{run.position:04d}"
        Path(f"{stem}.harness.json").write_bytes(canonical_dumps(run.h))
        if run.s is not None:
            Path(f"{stem}.summary.json").write_bytes(canonical_dumps(run.s))
        if run.audit is not None:
            Path(f"{stem}.audit.jsonl").write_bytes(b"".join(canonical_dumps(r) for r in run.audit))
    (orig / "ledger.jsonl").write_bytes(fx.ledger_bytes(runs, end_class))
    (orig / "environment.json").write_bytes(canonical_dumps(environment or environment_doc(clone, pass_id)))
    (store / pass_id / "files.original.sha256").write_bytes(evidence.hash_list(str(orig)))
    for name in os.listdir(orig):
        os.chmod(orig / name, 0o400)
    os.chmod(store / pass_id / "files.original.sha256", 0o400)
    os.chmod(orig, 0o500)
    return Published(clone, store, pass_id, doc, runs)


def classify_all(published: Published, code: str = "model-real-looking") -> bytes:
    """The owner's classification of every scan item, written beside scan/."""
    scan = (published.root / "scan" / "items.json").read_bytes()
    items = json.loads(scan)["items"]
    data = canonical_dumps({"version": 1, "scan_sha256": hashlib.sha256(scan).hexdigest(),
                            "items": {str(i["n"]): code for i in items}})
    (published.root / "classification.json").write_bytes(data)
    return data


# --- The Ollama stub -------------------------------------------------------------------

class OllamaStub:
    """Answers only the three identity requests; anything else is a 404 and is counted."""

    def __init__(self, model: str = "qwen3:8b") -> None:
        self.identity = {"version": "0.12.3", "model": model, "digest": "a" * 64,
                         "parameters": "temperature 0", "template": "{{ .Prompt }}",
                         "details": {"format": "gguf", "family": "qwen3", "parameter_size": "8.2B",
                                     "quantization_level": "Q4_K_M"},
                         "extra_tags": []}
        self.other_requests = 0
        self.requests: list[tuple[str, str]] = []
        self.override: dict[str, bytes] = {}
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, body: bytes, status: int = 200):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                stub.requests.append(("GET", self.path))
                ident = stub.identity
                if self.path in stub.override:
                    return self._send(stub.override[self.path])
                if self.path == "/api/version":
                    return self._send(json.dumps({"version": ident["version"]}).encode())
                if self.path == "/api/tags":
                    models = [{"name": ident["model"], "digest": ident["digest"]}] + ident["extra_tags"]
                    return self._send(json.dumps({"models": models}).encode())
                stub.other_requests += 1
                self._send(b"{}", 404)

            def do_POST(self):
                stub.requests.append(("POST", self.path))
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                if self.path in stub.override:
                    return self._send(stub.override[self.path])
                if self.path == "/api/show" and body.get("model") == stub.identity["model"]:
                    ident = stub.identity
                    return self._send(json.dumps({"parameters": ident["parameters"], "template": ident["template"],
                                                  "details": ident["details"], "modelfile": "FROM /x",
                                                  "model_info": {}}).encode())
                stub.other_requests += 1
                self._send(b"{}", 404)

            def do_DELETE(self):
                stub.requests.append(("DELETE", self.path))
                stub.other_requests += 1
                self._send(b"{}", 404)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()

    def endpoint(self):
        from evaluation.endpoint import Endpoint
        return Endpoint("127.0.0.1", self.port)

    MODEL_CALL_PATHS = ("/api/chat", "/api/generate", "/api/embed", "/api/embeddings")

    def model_calls(self) -> list[tuple[str, str]]:
        return [r for r in self.requests if r[1].split("?")[0] in self.MODEL_CALL_PATHS]

    def assert_no_model_calls(self) -> None:
        calls = self.model_calls()
        assert not calls, f"the Ollama stub received {len(calls)} model call(s)"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def ollama_stub():
    stub = OllamaStub()
    yield stub
    try:
        # No test may run the Ollama backend: a model call reaching the stub fails the test.
        stub.assert_no_model_calls()
    finally:
        stub.close()


# --- Fake executables ---------------------------------------------------------------------

FAKE_SYSTEMCTL = '''#!{python} -I
import json, os, sys
here = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(here, "argv.log"), "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
state = json.load(open(os.path.join(here, "state.json")))
if sys.argv[1:2] == ["show"] and state.get("fail_calls", 0) > 0:
    state["fail_calls"] -= 1
    json.dump(state, open(os.path.join(here, "state.json"), "w"))
    state = dict(state, active="failed")
if sys.argv[1:2] == ["show-environment"]:
    sys.stdout.write("".join(line + "\\n" for line in state["manager"]))
    sys.exit(state.get("exit", 0))
if "raw_show" in state:
    sys.stdout.write(state["raw_show"])
    sys.exit(state.get("exit", 0))
exec_start = "{{ path=%s ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; pid=%d ; code=(null) ; status=0/0 }}" % (
    state["exec_path"], " ".join(state["exec_argv"]), state["main_pid"])
lines = ["ActiveState=" + state["active"], "MainPID=%d" % state["main_pid"],
         "ExecMainStartTimestampMonotonic=%d" % state["start"], "Environment=" + " ".join(state["environment"]),
         "EnvironmentFiles=" + state["environment_files"], "ExecStart=" + exec_start]
sys.stdout.write("".join(line + "\\n" for line in lines))
sys.exit(state.get("exit", 0))
'''

FAKE_GITLEAKS = '''#!{python} -I
import json, os, sys
here = os.path.dirname(os.path.realpath(__file__))
config = json.load(open(os.path.join(here, "gitleaks.json")))
with open(os.path.join(here, "gitleaks.log"), "a") as log:
    log.write(json.dumps({{"argv": sys.argv[1:], "env": dict(os.environ), "cwd": os.getcwd()}}) + "\\n")
if sys.argv[1:] == ["version"]:
    print(config.get("version", "8.30.1"))
    sys.exit(0)
report = sys.argv[sys.argv.index("--report-path") + 1]
mode = config.get("report", "list")
findings = config.get("findings", [])
if config.get("only") and not sys.argv[2].endswith(config["only"]):
    findings = []
if mode == "list":
    with open(report, "w") as out:
        json.dump(findings, out)
elif mode == "garbage":
    with open(report, "w") as out:
        out.write("not json")
sys.exit(config.get("exit", 1 if findings else 0))
'''


@dataclass
class FakeSystemctl:
    path: str
    state_file: Path
    log: Path

    def set(self, **changes) -> None:
        state = json.loads(self.state_file.read_text())
        state.update(changes)
        self.state_file.write_text(json.dumps(state))

    def argvs(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []


def default_unit_state() -> dict:
    s = server_settings()
    return {"active": "active", "main_pid": 4242, "start": 1000, "environment": list(s["environment"]),
            "environment_files": "", "exec_path": s["exec_start"]["path"], "exec_argv": list(s["exec_start"]["argv"]),
            "manager": list(s["manager_environment"])}


def make_systemctl(directory: Path) -> FakeSystemctl:
    directory = private_dir(directory)
    script = directory / "systemctl"
    script.write_text(FAKE_SYSTEMCTL.format(python=sys.executable))
    script.chmod(0o700)
    (directory / "state.json").write_text(json.dumps(default_unit_state()))
    return FakeSystemctl(str(script), directory / "state.json", directory / "argv.log")


@dataclass
class FakeGitleaks:
    path: str
    config: Path
    log: Path

    def set(self, **config) -> None:
        self.config.write_text(json.dumps(config))

    def calls(self) -> list[dict]:
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []


def make_gitleaks(directory: Path) -> FakeGitleaks:
    directory = private_dir(directory)
    script = directory / "gitleaks"
    script.write_text(FAKE_GITLEAKS.format(python=sys.executable))
    script.chmod(0o700)
    fake = FakeGitleaks(str(script), directory / "gitleaks.json", directory / "gitleaks.log")
    fake.set()
    return fake


# --- Values that must be flagged, built at run time -----------------------------------------

def private_ipv4() -> str:
    return ".".join(("10", "20", "30", "40"))


def real_email() -> str:
    return "alice" + "@" + "corp-mail" + ".net"


def phone_number() -> str:
    return "-".join(("212", "867", "5309"))


# --- Tests of the doubles ----------------------------------------------------------------------

def test_a_model_call_to_the_stub_fails_the_check():
    stub = OllamaStub()
    try:
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", stub.port, timeout=5)
        conn.request("POST", "/api/chat", body=b"{}")
        assert conn.getresponse().status == 404
        conn.close()
        with pytest.raises(AssertionError, match="model call"):
            stub.assert_no_model_calls()
    finally:
        stub.close()


def test_the_stub_answers_only_its_three_requests(ollama_stub):
    from evaluation import probe
    ident = probe.ollama_identity(ollama_stub.endpoint(), "qwen3:8b")
    assert ident["digest"] == "sha256:" + "a" * 64
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", ollama_stub.port, timeout=5)
    conn.request("POST", "/api/pull", body=b"{}")
    assert conn.getresponse().status == 404
    conn.close()
    assert ollama_stub.other_requests == 1


def test_the_fake_systemctl_prints_its_state_and_records_its_argv(tmp_path):
    fake = make_systemctl(tmp_path / "bin")
    state = identity.read_unit("ollama.service", fake.path)
    assert state.active_state == "active" and state.exec_argv == ("/usr/bin/ollama", "serve")
    assert identity.manager_environment(fake.path) == server_settings()["manager_environment"]
    assert fake.argvs()[0][:2] == ["show", "ollama.service"]


def test_the_fake_gitleaks_writes_its_report_and_records_its_argv(tmp_path):
    fake = make_gitleaks(tmp_path / "bin")
    fake.set(findings=[{"RuleID": "x"}])
    report = tmp_path / "r.json"
    proc = subprocess.run([fake.path, "dir", "x", "--report-path", str(report)], capture_output=True)
    assert proc.returncode == 1 and json.loads(report.read_text()) == [{"RuleID": "x"}]
    assert fake.calls()[0]["argv"][0] == "dir"


def test_a_scratch_clone_is_committed_clean_and_matches_its_manifest(tmp_path, tmp_path_factory):
    clone = make_clone(tmp_path, tmp_path_factory)
    m = manifest.load_manifest(clone.manifest_bytes)
    assert identity.code_problems(str(clone.path), [f.model_dump() for f in m.files], clone.merge_sha,
                                  clone.merge_tree, resolved_root=lambda name: os.path.realpath(clone.path)) == []
    assert records.order_problems(clone.order, records.Registry.model_validate(clone.registry)) == []


def test_flagged_values_are_flagged_by_the_synthetic_data_rules():
    from evaluation.common import load_h2
    h2 = load_h2()
    for value in (private_ipv4(), real_email(), phone_number()):
        assert h2._line_rules(f"x {value} y", h2.DATA, h2.FileRules())
