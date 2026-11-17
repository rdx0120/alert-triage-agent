"""The frozen manifest: what the evaluation is allowed to run, and the tool that writes it.

The manifest lists every tracked file with its mode and SHA-256 (apart from
itself and provenance.json, which change after the freeze), and the
execution identity: the interpreter, the complete installed-package list,
the embedder, the model and the model server's service configuration. The
runner compares all of it with what it observes before every run.

Every identity value is published in clear, so the builder refuses any value
that fails the publication contract instead of freezing it.
"""

from __future__ import annotations

if __name__ == "__main__":
    import os as _os
    import sys as _sys
    # Started as a script with -P: put the clone root first, as the runner does.
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.realpath(__file__))))

import os
import sys
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, ValidationError

from triage.backends.ollama import MODEL_NAME_PATTERN

from evaluation import identity, probe
from evaluation.common import EvalModel, EvaluationError, SchemaError, canonical_dumps, strict_loads
from evaluation.endpoint import parse_endpoint
from evaluation.ledger import write_private

HEX64 = r"^[0-9a-f]{64}$"
FIELD = r"^[A-Za-z0-9._:+-]{1,64}$"
EXCLUDED = list(identity.EXCLUDED)


class ManifestRefused(EvaluationError):
    """The manifest or an execution identity cannot be built or accepted."""


def _false(value: bool) -> bool:
    if value is not False:
        raise ValueError("think must be false")
    return value


def _model_field(value: str) -> str:
    import re
    if re.fullmatch(FIELD, value) is None:
        raise ValueError("model field")
    return value


class PythonIdentity(EvalModel):
    version: str
    cache_tag: str
    machine: str
    freeze: list[str]


class OllamaIdentity(EvalModel):
    version: str = Field(pattern=FIELD)
    model: Annotated[str, AfterValidator(_model_field)] = Field(pattern=MODEL_NAME_PATTERN)
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    parameters_sha256: str = Field(pattern=HEX64)
    template_sha256: str = Field(pattern=HEX64)
    format: str = Field(pattern=FIELD)
    family: str = Field(pattern=FIELD)
    parameter_size: str = Field(pattern=FIELD)
    quantization_level: str = Field(pattern=FIELD)


class ExecStart(EvalModel):
    path: str
    argv: list[str]


class ServerSettings(EvalModel):
    unit: str = Field(pattern=identity.UNIT_RE.pattern)
    environment: list[str]
    manager_environment: list[str]
    exec_start: ExecStart


class Execution(EvalModel):
    python: PythonIdentity
    embedder: Literal["minilm", "hashing"]
    think: Annotated[bool, AfterValidator(_false)]
    ollama: OllamaIdentity
    server: ServerSettings


class FileEntry(EvalModel):
    path: str
    mode: Literal["100644", "100755"]
    sha256: str = Field(pattern=HEX64)


def _excluded(value: list[str]) -> list[str]:
    if value != EXCLUDED:
        raise ValueError("excluded must be exactly the two paths")
    return value


def _version(value: int) -> int:
    if value != 1:
        raise ValueError("version")
    return value


class Manifest(EvalModel):
    version: Annotated[int, AfterValidator(_version)]
    excluded: Annotated[list[str], AfterValidator(_excluded)]
    files: list[FileEntry]
    execution: Execution


def contract_problems(execution: Execution) -> list[str]:
    return identity.execution_contract_problems(execution.model_dump())


def build(clone: str, execution: Execution) -> bytes:
    """The manifest for the clone's committed tree. Refuses an unpublishable identity or a dirty tree."""
    problems = contract_problems(execution) + identity.clean_tree_problems(clone)
    if problems:
        raise ManifestRefused(problems[0])
    try:
        files = [{"path": p, "mode": m, "sha256": h} for p, m, h in identity.tracked_files(clone)
                 if p not in identity.EXCLUDED]
    except identity.CheckRefused as error:
        raise ManifestRefused(str(error)) from None
    doc = {"version": 1, "excluded": list(EXCLUDED), "files": files, "execution": execution.model_dump()}
    Manifest.model_validate(doc)
    return canonical_dumps(doc)


def load_manifest(data: bytes) -> Manifest:
    try:
        obj = strict_loads(data)
        manifest = Manifest.model_validate(obj)
    except (SchemaError, ValidationError):
        raise ManifestRefused("manifest does not match its schema") from None
    if canonical_dumps(obj) != data:
        raise ManifestRefused("manifest is not in canonical form")
    paths = [f.path for f in manifest.files]
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise ManifestRefused("manifest files must be sorted and unique")
    if set(paths) & set(EXCLUDED):
        raise ManifestRefused("manifest lists an excluded path")
    return manifest


def load_execution(data: bytes) -> Execution:
    try:
        obj = strict_loads(data)
        execution = Execution.model_validate(obj)
    except (SchemaError, ValidationError):
        raise ManifestRefused("execution does not match its schema") from None
    if canonical_dumps(obj) != data:
        raise ManifestRefused("execution is not in canonical form")
    return execution


def file_problems(clone: str, manifest: Manifest) -> list[str]:
    return identity.file_problems(clone, [f.model_dump() for f in manifest.files])


def observe(clone: str, *, unit: str, model: str, embedder: str, endpoint, freeze=None,
            systemctl: str = identity.SYSTEMCTL) -> Execution:
    """The execution identity, observed by the same functions the runner checks with."""
    python = identity.python_identity(clone, freeze=freeze)
    ollama = probe.ollama_identity(endpoint, model)
    state = identity.read_unit(unit, systemctl)
    manager = identity.manager_environment(systemctl)
    doc = {"python": python, "embedder": embedder, "think": False, "ollama": ollama,
           "server": {"unit": unit, "environment": list(state.environment), "manager_environment": manager,
                      "exec_start": {"path": state.exec_path, "argv": list(state.exec_argv)}}}
    try:
        execution = Execution.model_validate(doc)
    except ValidationError:
        raise ManifestRefused("observed identity does not match the schema") from None
    problems = contract_problems(execution)
    if state.active_state != "active":
        problems.append("server: unit is not active")
    if state.environment_files != "":
        problems.append("server: unit lists an environment file")
    if problems:
        raise ManifestRefused(problems[0])
    return execution


def _body(argv) -> int:
    from evaluation.common import read_regular
    parser = identity.Parser(prog="evaluation/manifest.py", allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=identity.Parser)
    obs = sub.add_parser("observe", allow_abbrev=False)
    for name in ("--clone", "--unit", "--model", "--out"):
        obs.add_argument(name, required=True)
    obs.add_argument("--embedder", required=True, choices=["minilm", "hashing"])
    bld = sub.add_parser("build", allow_abbrev=False)
    for name in ("--clone", "--execution", "--out"):
        bld.add_argument(name, required=True)
    args = parser.parse_args(argv)
    if not identity.clone_ok(args.clone, __file__):
        raise identity.UsageRefused("--clone must be the clone this tool runs from")
    if args.command == "observe":
        endpoint = parse_endpoint(os.environ.get("OLLAMA_HOST"))
        execution = observe(args.clone, unit=args.unit, model=args.model, embedder=args.embedder,
                            endpoint=endpoint)
        write_private(args.out, canonical_dumps(execution.model_dump()), what="execution")
        print("manifest: execution identity written")
        return 0
    try:
        data = read_regular(args.execution)
    except EvaluationError:
        raise ManifestRefused("execution file cannot be read") from None
    write_private(args.out, build(args.clone, load_execution(data)), what="manifest")
    print("manifest: manifest written")
    return 0


def main(argv=None) -> int:
    return identity.run_cli("manifest", _body, sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())
