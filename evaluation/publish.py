"""Publication of a pass: scan the originals, build the public copy, verify the originals.

    python -s -B -P <clone>/evaluation/publish.py scan --clone PATH --store PATH --pass PASS_ID --gitleaks BIN
    python -s -B -P <clone>/evaluation/publish.py build --clone PATH --store PATH --pass PASS_ID --gitleaks BIN
    python -s -B -P <clone>/evaluation/publish.py verify-original --clone PATH --store PATH --pass PASS_ID
        --recorded HEX64

The stages never write into an earlier stage's files: scan writes scan/,
the owner writes classification.json beside it, and build writes
public.tmp/ and renames it to public/ only after every check passes. Every
file under original/ is opened read-only, and the original hash list is
verified before and after the build. The registry, labels and order are read
from the clone at fixed paths, each bound to the manifest by its hash.
"""

from __future__ import annotations

if __name__ == "__main__":
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.realpath(__file__))))

import os
import re
import shutil
import sys

from triage import files as tfiles

from evaluation import evidence, identity, manifest as manifest_mod, records, scorer
from evaluation.common import (
    CLASSIFICATION_CODES, EvaluationError, canonical_dumps, read_regular, sha256_hex, strict_loads,
)
from evaluation.evidence import PublishRefused
from evaluation.harness import store_problems
from evaluation.ledger import write_in

HEX64 = re.compile(r"^[0-9a-f]{64}$")
INCIDENT_CODES = ("suspected-real-data", "suspected-credential")


class Paths:
    def __init__(self, store: str, pass_id: str) -> None:
        if records.PASS_ID_RE.fullmatch(pass_id) is None:
            raise identity.UsageRefused("invalid pass ID")
        self.pass_id = pass_id
        self.sequence = pass_id.split("-")[0]
        self.root = os.path.join(store, pass_id)
        self.original = os.path.join(self.root, "original")
        self.hash_list = os.path.join(self.root, "files.original.sha256")
        self.scan = os.path.join(self.root, "scan")
        self.scan_items = os.path.join(self.scan, "items.json")
        self.private_items = os.path.join(self.scan, "items.private.jsonl")
        self.classification = os.path.join(self.root, "classification.json")
        self.public_tmp = os.path.join(self.root, "public.tmp")
        self.public = os.path.join(self.root, "public")


def frozen_inputs(clone: str):
    """Registry, labels and order from the clone, each equal by hash to its manifest entry."""
    eval_dir = os.path.join(clone, "eval")
    manifest = manifest_mod.load_manifest(read_regular(os.path.join(eval_dir, "manifest.json")))
    listed = {f.path: f.sha256 for f in manifest.files}
    for rel in ("eval/cases.json", "eval/labels.json", "eval/order.json"):
        if listed.get(rel) != sha256_hex(read_regular(os.path.join(clone, rel))):
            raise PublishRefused(f"inputs: {rel} differs from its manifest entry")
    registry = records.load_registry(os.path.join(eval_dir, "cases.json"))
    labels = records.load_labels(os.path.join(eval_dir, "labels.json"))
    order = records.load_order(os.path.join(eval_dir, "order.json"), registry)
    return registry, labels, order


def verify_originals(paths: Paths) -> dict[str, str]:
    """The original hash list verifies and the ledger chain holds. Returns the verified hashes."""
    try:
        data = read_regular(paths.hash_list)
    except EvaluationError:
        raise PublishRefused("originals: the hash list cannot be read") from None
    problems = evidence.hash_list_problems(paths.original, data)
    if problems:
        raise PublishRefused(problems[0])
    try:
        records.verify_ledger(read_regular(os.path.join(paths.original, "ledger.jsonl")))
    except EvaluationError:
        raise PublishRefused("originals: the ledger chain does not verify") from None
    return evidence.parse_hash_list(data)


def _positions(order, sequence: str) -> list[int]:
    return [e.position for e in order.sequence(sequence)]


def _store_ok(store: str, clone: str) -> None:
    problems = store_problems(store, clone)
    if problems:
        raise identity.UsageRefused(problems[0])


def _make_private_dir(path: str) -> int:
    if os.path.lexists(path):
        raise PublishRefused("store: an output directory already exists")
    return tfiles.open_private_dir(path, what="output", create=True)


def _set_read_only(dir_fd: int, name: str) -> None:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        os.fchmod(fd, 0o400)
    finally:
        os.close(fd)


# --- scan -------------------------------------------------------------------------------------

def run_scan(clone: str, paths: Paths, gitleaks: str) -> tuple[int, str]:
    registry, labels, order = frozen_inputs(clone)
    verify_originals(paths)
    problems = evidence.file_problems(paths.original, _positions(order, paths.sequence), public=False)
    if problems:
        raise PublishRefused(problems[0])
    config = os.path.join(clone, ".gitleaks.toml")
    if evidence.gitleaks_findings(gitleaks, paths.original, config):
        raise PublishRefused("scan: the secret scanner reports a finding in the originals")
    items, private = evidence.scan(paths.original)
    data = evidence.scan_items_bytes(items)
    private_data = b"".join(canonical_dumps(p) for p in private)
    fd = _make_private_dir(paths.scan)
    try:
        write_in(fd, paths.scan, [("items.json", data), ("items.private.jsonl", private_data or b"")],
                 what="scan")
        _set_read_only(fd, "items.json")
        _set_read_only(fd, "items.private.jsonl")
    finally:
        os.close(fd)
    return len(items), sha256_hex(data)


# --- build ------------------------------------------------------------------------------------

def _load_private(paths: Paths) -> list[dict]:
    data = read_regular(paths.private_items)
    out = []
    for line in data.split(b"\n"):
        if line:
            out.append(strict_loads(line))
    return out


def _score_records(directory: str, paths: Paths, hashes: dict[str, str], *, public: bool, registry, labels,
                   order, positions) -> bytes:
    """Score records read through a verified named copy of the directory (load_pass needs the pass ID name)."""
    with evidence.named_copy(directory, paths.pass_id, hashes, public=public, positions=positions) as copy_dir:
        if public:
            data = records.load_pass(copy_dir, registry=registry, labels=labels, order=order,
                                     sequence=paths.sequence, public=True,
                                     redactions=os.path.join(copy_dir, "redactions.json"))
        else:
            data = records.load_pass(copy_dir, registry=registry, labels=labels, order=order,
                                     sequence=paths.sequence, public=False, scan_items=paths.scan_items,
                                     classification=paths.classification)
        return scorer.records_jsonl(scorer.score_pass(data, records.case_views(registry, labels)))


def _write_public_tmp(paths: Paths, items: list[dict], private: list[dict], classification) -> list[dict]:
    """Copies, redacted summaries and withheld audit lines; returns the redactions.json items."""
    by_file: dict[str, list[dict]] = {}
    for p in private:
        by_file.setdefault(p["file"], []).append(p)
    first_code: dict[str, str] = {}
    for item in items:
        run = item["file"].split(".")[0]
        first_code.setdefault(run, classification.items[str(item["n"])])
    h2_items = [{"file": i["file"], "pointer": i["pointer"], "rule": i["rule"], "n": i["n"],
                 "classification": classification.items[str(i["n"])]} for i in items]
    withheld: list[dict] = []
    outputs: list[tuple[str, bytes]] = []
    for name in sorted(os.listdir(paths.original)):
        data = read_regular(os.path.join(paths.original, name))
        run = name.split(".")[0]
        if name in by_file:
            data = evidence.redact_summary(data, by_file[name])
        elif name.endswith(".audit.jsonl") and run in first_code:
            data, more = evidence.withhold_digests(name, data, first_code[run])
            withheld += more
        outputs.append((name, data))
    key_order = {k: i for i, k in enumerate(evidence.DIGEST_KEYS)}
    withheld.sort(key=lambda w: (w["file"], int(w["pointer"][1:].split("/")[0]),
                                 key_order[w["pointer"].split("/", 1)[1]]))
    numbered = []
    for n, w in enumerate(withheld, start=len(h2_items) + 1):
        numbered.append({"file": w["file"], "pointer": w["pointer"], "rule": "withheld-digest", "n": n,
                         "classification": w["classification"]})
    red_items = h2_items + numbered
    red_bytes = canonical_dumps({"version": 1, "items": red_items})
    records.load_redactions(red_bytes)
    fd = _make_private_dir(paths.public_tmp)
    try:
        write_in(fd, paths.public_tmp, outputs + [("redactions.json", red_bytes)], what="public copy")
    finally:
        os.close(fd)
    return red_items


def run_build(clone: str, paths: Paths, gitleaks: str) -> int:
    registry, labels, order = frozen_inputs(clone)
    positions = _positions(order, paths.sequence)
    config = os.path.join(clone, ".gitleaks.toml")
    if os.path.lexists(paths.public) or os.path.lexists(paths.public_tmp):
        raise PublishRefused("build: a public copy already exists")
    try:
        hashes = verify_originals(paths)
        problems = evidence.file_problems(paths.original, positions, public=False)
        if problems:
            raise PublishRefused(problems[0])
        if evidence.gitleaks_findings(gitleaks, paths.original, config):
            raise PublishRefused("build: the secret scanner reports a finding in the originals")
        items, private = evidence.scan(paths.original)
        fresh = evidence.scan_items_bytes(items)
        try:
            stored = read_regular(paths.scan_items)
            cls_bytes = read_regular(paths.classification)
        except EvaluationError:
            raise PublishRefused("build: the scan or the classification cannot be read") from None
        if fresh != stored:
            raise PublishRefused("build: the stored scan differs from a fresh scan")
        try:
            _, classification = records.load_scan(stored, cls_bytes)
        except EvaluationError:
            raise PublishRefused("build: the classification does not match the scan") from None
        if any(code in INCIDENT_CODES for code in classification.items.values()):
            raise PublishRefused("build: an item is classified as an incident")
        stored_private = _load_private(paths)
        if [{k: p[k] for k in ("n", "file", "pointer", "rule")} for p in stored_private] != items \
                or stored_private != private:
            raise PublishRefused("build: the private scan list differs from a fresh scan")
        red_items = _write_public_tmp(paths, items, private, classification)
        problems = evidence.closure_problems(paths.public_tmp, red_items, paths.original,
                                             gitleaks_binary=gitleaks, gitleaks_config=config)
        if problems:
            raise PublishRefused(problems[0])
        public_hashes = evidence.file_hashes(paths.public_tmp)
        original_records = _score_records(paths.original, paths, hashes, public=False, registry=registry,
                                          labels=labels, order=order, positions=positions)
        public_records = _score_records(paths.public_tmp, paths, public_hashes, public=True, registry=registry,
                                        labels=labels, order=order, positions=positions)
        if original_records != public_records:
            raise PublishRefused("build: score records differ between the original and public copies")
        strings = {}
        for p in private:
            obj = strict_loads(read_regular(os.path.join(paths.original, p["file"])))
            strings[(p["file"], p["pointer"])] = evidence._value(obj, p["pointer"])[1]
        markers = [c.objectives.marker for c in labels.cases if c.objectives is not None]
        problems = evidence.marker_overlap_problems(private, markers, strings)
        if problems:
            raise PublishRefused(problems[0])
        env = strict_loads(read_regular(os.path.join(paths.public_tmp, "environment.json")))
        if not _environment_publishable(env):
            raise PublishRefused("build: the public environment.json fails the publication contract")
        if verify_originals(paths) != hashes:
            raise PublishRefused("build: the originals changed during the build")
        fd = tfiles.open_private_dir(paths.public_tmp, what="public copy", create=False)
        try:
            write_in(fd, paths.public_tmp, [("files.sha256", evidence.hash_list(paths.public_tmp))],
                     what="public copy")
        finally:
            os.close(fd)
        os.rename(paths.public_tmp, paths.public)
    except BaseException:
        if os.path.lexists(paths.public_tmp):
            shutil.rmtree(paths.public_tmp)
        raise
    return len(red_items)


def _environment_publishable(env) -> bool:
    """The identity values of a public environment.json pass the publication contract."""
    try:
        execution = {"python": env["python"], "server": env["server"]}
        return not identity.execution_contract_problems(execution)
    except (KeyError, TypeError, AttributeError):
        return False


# --- verify-original -----------------------------------------------------------------------

def run_verify(clone: str, paths: Paths, recorded: str) -> tuple[int, dict[str, int]]:
    if HEX64.fullmatch(recorded) is None:
        raise identity.UsageRefused("--recorded must be 64 lowercase hex digits")
    registry, labels, order = frozen_inputs(clone)
    positions = _positions(order, paths.sequence)
    data = read_regular(paths.hash_list)
    if sha256_hex(data) != recorded:
        raise PublishRefused("verify: the original hash list differs from the recorded hash")
    hashes = verify_originals(paths)
    public_list = read_regular(os.path.join(paths.public, "files.sha256"))
    problems = evidence.hash_list_problems(paths.public, public_list, exclude=("files.sha256",))
    if problems:
        raise PublishRefused(problems[0])
    public_hashes = evidence.parse_hash_list(public_list)
    original_records = _score_records(paths.original, paths, hashes, public=False, registry=registry,
                                      labels=labels, order=order, positions=positions)
    public_records = _score_records(paths.public, paths, public_hashes, public=True, registry=registry,
                                    labels=labels, order=order, positions=positions)
    if original_records != public_records:
        raise PublishRefused("verify: score records differ between the original and public copies")
    _, classification = records.load_scan(read_regular(paths.scan_items), read_regular(paths.classification))
    counts = {code: sum(1 for c in classification.items.values() if c == code) for code in CLASSIFICATION_CODES}
    return len(classification.items), counts


def _body(argv) -> int:
    parser = identity.Parser(prog="evaluation/publish.py", allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=identity.Parser)
    for name in ("scan", "build", "verify-original"):
        cmd = sub.add_parser(name, allow_abbrev=False)
        for flag in ("--clone", "--store", "--pass"):
            cmd.add_argument(flag, required=True)
        cmd.add_argument("--recorded" if name == "verify-original" else "--gitleaks", required=True)
    args = parser.parse_args(argv)
    if not identity.clone_ok(args.clone, __file__):
        raise identity.UsageRefused("--clone must be the clone this tool runs from")
    _store_ok(args.store, args.clone)
    paths = Paths(args.store, args.__dict__["pass"])
    try:
        if args.command == "scan":
            count, digest = run_scan(args.clone, paths, args.gitleaks)
            print(f"publish: scan items {count}, scan sha256 {digest}")
        elif args.command == "build":
            count = run_build(args.clone, paths, args.gitleaks)
            print(f"publish: public copy built with {count} redaction items")
        else:
            count, counts = run_verify(args.clone, paths, args.recorded)
            listed = ", ".join(f"{code} {n}" for code, n in counts.items())
            print(f"publish: originals verified; redactions {count}; {listed}")
    except PublishRefused as error:
        print(f"publish: error: {error}", file=sys.stderr)
        return 3
    return 0


def main(argv=None) -> int:
    return identity.run_cli("publish", _body, sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())
