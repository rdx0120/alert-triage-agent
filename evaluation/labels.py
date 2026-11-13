"""Dataset validators: the registry against its case files, the labels, and the injection twins.

These run when the evaluation cases and labels are written, and as tests
afterwards, so a frozen dataset cannot drift from the rules it was written
under. They read only the files they are given, and their messages name case
IDs, fields and pointers, never the values inside a case or a label.
"""

from __future__ import annotations

import json
from pathlib import Path

from triage.ingest import IngestError, load_alert
from triage.tripwire import SCANNED_FIELDS

from .common import (
    ATTACK_SNAPSHOT, MARKER_RE, EvaluationError, SchemaError, is_regular_file, load_h2, read_regular,
    runbook_names, severity_index, sha256_hex, strict_loads,
)
from .records import Labels, Registry


def registry_binding_problems(registry: Registry, root) -> list[str]:
    """Each registry entry's alert_id and rule_level must equal its frozen case file's."""
    root = Path(root)
    problems = []
    for case in registry.cases:
        path = root / case.path
        if not is_regular_file(path):
            problems.append(f"registry: {case.case_id} case file is missing or not a regular file")
            continue
        try:
            alert = load_alert(read_regular(path), case.format)
        except (EvaluationError, IngestError, ValueError):
            problems.append(f"registry: {case.case_id} case file does not load")
            continue
        if alert.alert_id != case.alert_id:
            problems.append(f"registry: {case.case_id} alert_id differs from its case file")
        if alert.rule_level != case.rule_level:
            problems.append(f"registry: {case.case_id} rule_level differs from its case file")
    return problems


def _snapshot() -> dict:
    return strict_loads(read_regular(ATTACK_SNAPSHOT))


def _resolve(technique: str, retired: dict) -> str:
    seen = set()
    while technique in retired and technique not in seen:
        seen.add(technique)
        technique = retired[technique]
    return technique


def _h2_clean(text: str) -> bool:
    """True when the text, as a JSON string line of eval/labels.json, passes H2's rules.

    It is checked as a JSON document, so H2 runs its rules on both the raw
    line and the decoded string, as it will on the committed labels file.
    """
    h2 = load_h2()
    line = json.dumps(text, ensure_ascii=True).encode("ascii") + b"\n"
    return not h2.check_content("eval/labels.json", line, h2.path_class("eval/labels.json"))


def labels_problems(labels: Labels, registry: Registry, rubric_bytes: bytes, root=None) -> list[str]:
    """Semantic checks of the labels against the registry, the rubric and the snapshots."""
    problems = []
    if labels.rubric_sha256 != sha256_hex(rubric_bytes):
        problems.append("labels: rubric_sha256 differs from the rubric")
    cases = registry.by_id()
    by_label = labels.by_id()
    if set(cases) != set(by_label):
        problems.append("labels: the label set differs from the registry")
    snapshot = _snapshot()
    current, retired = snapshot["techniques"], snapshot["retired"]
    runbooks = runbook_names()
    markers: dict[str, str] = {}
    for cid, label in by_label.items():
        case = cases.get(cid)
        if case is None:
            continue
        for technique in label.acceptable_techniques:
            if technique != technique.upper() or technique not in current:
                problems.append(f"labels: {cid} technique is not a current ATT&CK ID")
        if label.expected_runbook != "none" and label.expected_runbook not in runbooks:
            problems.append(f"labels: {cid} expected_runbook is not a vendored runbook")
        if (label.expected_flagged is not None) != (case.family in ("C", "D")):
            problems.append(f"labels: {cid} expected_flagged must be set exactly for C and D")
        if (label.objectives is not None) != (case.family == "C"):
            problems.append(f"labels: {cid} objectives must be set exactly for C")
            continue
        if label.objectives is None:
            continue
        objective = label.objectives
        marker = objective.marker
        if MARKER_RE.fullmatch(marker) is None:
            problems.append(f"labels: {cid} marker is not in the accepted form")
        elif not (_h2_clean(marker) and _h2_clean("Ref: " + marker)):
            problems.append(f"labels: {cid} marker fails the synthetic-data rules")
        if marker in markers:
            problems.append(f"labels: {cid} marker repeats another twin's")
        markers[marker] = cid
        clean = by_label.get(case.clean_twin)
        if clean is None:
            continue
        floor = case.rule_level
        if objective.kind == "O-S":
            target = objective.target
            if severity_index(clean.expected_severity) <= severity_index(floor):
                problems.append(f"labels: {cid} O-S needs a clean label above the rule level")
            elif not severity_index(floor) <= severity_index(target) < severity_index(clean.expected_severity):
                problems.append(f"labels: {cid} O-S target must be at least the rule level and below the clean label")
        else:
            target = objective.target
            mapped = set()
            if root is not None:
                try:
                    alert = load_alert(read_regular(Path(root) / case.path), case.format)
                    mapped = {_resolve(t, retired) for t in alert.attack_tags()}
                except (EvaluationError, IngestError, ValueError):
                    problems.append(f"labels: {cid} case file does not load")
            if target not in current or target != target.upper():
                problems.append(f"labels: {cid} O-T target is not a current ATT&CK ID")
            if target in label.acceptable_techniques:
                problems.append(f"labels: {cid} O-T target is in the acceptable set")
            if target in mapped:
                problems.append(f"labels: {cid} O-T target is a technique the rule maps")
    return problems


def _leaves(node, pointer: str = ""):
    """(pointer, value) for every leaf, and ('key', pointer) markers for object keys."""
    if isinstance(node, dict):
        for key, value in node.items():
            child = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
            yield ("key", child, key)
            yield from _leaves(value, child)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _leaves(value, f"{pointer}/{i}")
    else:
        yield ("leaf", pointer, node)


def _shape(node):
    if isinstance(node, dict):
        return ("dict", tuple((k, _shape(v)) for k, v in node.items()))
    if isinstance(node, list):
        return ("list", tuple(_shape(v) for v in node))
    if isinstance(node, str):
        return ("str",)
    return ("value", type(node).__name__, json.dumps(node))


def twin_diff(clean_bytes: bytes, twin_bytes: bytes, fmt: str) -> list[str]:
    """Pointers of the string values in which a twin differs from its clean twin.

    Anything else that differs (keys, nesting, list lengths, non-string
    values, or an alert field outside the tripwire-scanned set) is refused.
    """
    clean, twin = strict_loads(clean_bytes), strict_loads(twin_bytes)
    if _shape(clean) != _shape(twin):
        raise SchemaError("twin differs in structure or in a non-string value")
    clean_leaves = {p: v for kind, p, v in _leaves(clean) if kind == "leaf"}
    twin_leaves = {p: v for kind, p, v in _leaves(twin) if kind == "leaf"}
    differing = sorted(p for p in clean_leaves if clean_leaves[p] != twin_leaves[p])
    a = load_alert(clean_bytes, fmt).model_dump()
    b = load_alert(twin_bytes, fmt).model_dump()
    for field in a:
        if field not in SCANNED_FIELDS and a[field] != b[field]:
            raise SchemaError("twin differs outside the attacker-writable fields")
    return differing


DECODED_SUFFIXES = (".json", ".jsonl", ".yml", ".yaml")


def _decoded_strings(rel: str, data: bytes) -> list[str] | None:
    """Every decoded string in a JSON, JSONL or YAML file, using H2's decoders; None if undecodable."""
    h2 = load_h2()
    try:
        result = h2._decoded_items(rel, data.decode("utf-8"))
    except (h2.DecodeError, UnicodeDecodeError):
        return None
    return [] if result is None else list(result[0])


def marker_scope_problems(labels: Labels, registry: Registry, root, frozen_paths) -> list[str]:
    """Each marker appears only in its own twin's injected text and its own objective entry.

    Only the frozen inputs (the manifest's file list) are checked: those are
    what a run reads. Published results legitimately contain markers once a
    model echoes or follows an injection, and no run reads them.
    """
    root = Path(root)
    problems = []
    frozen = list(frozen_paths)
    cases = registry.by_id()
    label_index = {label.case_id: i for i, label in enumerate(labels.cases)}
    contents: dict[str, bytes] = {}
    for rel in frozen:
        path = root / rel
        if not is_regular_file(path):
            problems.append("marker scope: a frozen path is missing or not a regular file")
            continue
        contents[rel] = read_regular(path)
    for label in labels.cases:
        if label.objectives is None:
            continue
        marker = label.objectives.marker
        cid = label.case_id
        case = cases.get(cid)
        if case is None:
            continue
        clean_case = cases.get(case.clean_twin)
        twin_rel, clean_rel = case.path, clean_case.path if clean_case else None
        own_pointer = f"/cases/{label_index[cid]}/objectives/marker"
        # 1. In the twin's own case file.
        twin_data = contents.get(twin_rel)
        if twin_data is None:
            problems.append(f"marker scope: {cid} case file is not a frozen input")
        else:
            try:
                twin_doc = strict_loads(twin_data)
            except SchemaError:
                problems.append(f"marker scope: {cid} case file is not valid JSON")
                twin_doc = None
            differing: set[str] = set()
            try:
                if clean_rel not in contents:
                    raise SchemaError("clean twin is not a frozen input")
                differing = set(twin_diff(contents[clean_rel], twin_data, case.format))
            except (SchemaError, IngestError, ValueError):
                # Every leaf holding the marker then counts as outside the injected values.
                problems.append(f"marker scope: {cid} twin cannot be compared with its clean twin")
            if twin_doc is not None:
                leaves = [(kind, p, v) for kind, p, v in _leaves(twin_doc)]
                in_leaves = [(p, v) for kind, p, v in leaves if kind == "leaf" and isinstance(v, str) and marker in v]
                decoded_count = sum(v.count(marker) for _, v in in_leaves)
                if not in_leaves:
                    problems.append(f"marker scope: {cid} marker is missing from its twin")
                if any(p not in differing for p, _ in in_leaves):
                    problems.append(f"marker scope: {cid} marker lies outside the injected values")
                if any(kind == "key" and marker in v for kind, p, v in leaves):
                    problems.append(f"marker scope: {cid} marker is in an object key")
                if twin_data.count(marker.encode("ascii")) != decoded_count:
                    problems.append(f"marker scope: {cid} marker count differs between raw and decoded text")
        # 2-4. Everywhere else among the frozen inputs.
        for rel, data in contents.items():
            if rel == twin_rel:
                continue
            if rel == "eval/labels.json":
                try:
                    doc = strict_loads(data)
                except SchemaError:
                    problems.append("marker scope: eval/labels.json is not valid JSON")
                    continue
                hits = [p for kind, p, v in _leaves(doc) if isinstance(v, str) and marker in v]
                if hits != [own_pointer]:
                    problems.append(f"marker scope: {cid} marker appears in the labels outside its own entry")
                continue
            found = marker.encode("ascii") in data
            if not found and rel.endswith(DECODED_SUFFIXES):
                strings = _decoded_strings(rel, data)
                if strings is None:
                    # Absence cannot be shown in a file that does not decode: fail closed.
                    problems.append(f"marker scope: a frozen input cannot be decoded for {cid}")
                    continue
                found = any(marker in text for text in strings)
            if found:
                problems.append(f"marker scope: {cid} marker appears in another frozen input")
    return problems
