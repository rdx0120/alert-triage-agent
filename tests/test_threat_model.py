"""Keep the threat model's citations and statuses consistent with the repository.

docs/threat-model.md claims that each control is backed by named tests, files
or written policy, and gives each threat a status that depends on that
evidence. Those claims rot silently: a test is renamed, a file moves, a status
is upgraded without a test behind it, or a framework identifier is mistyped.
This test fails when that happens, so the document cannot drift out of step
with the code without someone noticing.

It checks references and structure only. It does not check that a cited test
proves what the document says it proves; that remains a review question. It
parses cited test files with ast and never imports or runs them, and it checks
cited paths on disk rather than with git, because CI checks out only tracked
files and an untracked citation should fail there too.
"""

import ast
import re
from pathlib import Path, PurePosixPath

import pytest

from triage.config import REPO_ROOT

DOCUMENT = REPO_ROOT / "docs" / "threat-model.md"

STATUSES = frozenset({"Mitigated", "Partial", "Open", "Accepted", "Not applicable"})
EVIDENCE_CLASSES = frozenset({"test", "config", "policy"})
FIELDS = ("- Status: ", "- Boundary: ", "- Frameworks: ", "- Threat: ", "- Controls:", "- Residual: ")
NO_FRAMEWORK = "none applies directly."

LLM_2026 = frozenset(f"LLM{n:02d}:2026" for n in range(1, 11))
LLM_2025 = frozenset(f"LLM{n:02d}:2025" for n in range(1, 11))
ASI_IDS = frozenset(f"ASI{n:02d}" for n in range(1, 11))
# The ATLAS IDs the threat model may cite, each checked against MITRE ATLAS
# release 2026.09. Citing a new one means adding it here deliberately.
ATLAS_IDS = frozenset({
    "AML.T0010.001", "AML.T0010.002", "AML.T0010.003", "AML.T0011.000", "AML.T0029",
    "AML.T0034.002", "AML.T0051.001", "AML.T0053", "AML.T0056", "AML.T0057",
    "AML.T0066", "AML.T0067.000", "AML.T0068", "AML.T0070", "AML.T0077",
    "AML.T0086", "AML.T0101",
})

# Backticked paths are checked only under these prefixes or with these exact
# names. logs/ is deliberately absent: the default audit log is not tracked.
PATH_PREFIXES = ("triage/", "tests/", "scripts/", "data/", "docs/", "requirements/", ".github/", "vendor/")
ROOT_FILES = frozenset({"README.md", "CLAUDE.md", "pyproject.toml", ".gitignore", ".env.example", "LICENSE"})

THREAT_HEADING = re.compile(r"### (T\d+) ")
CONTROL_CLASS = re.compile(r"  - \[([^\]\n]*)\]")
BACKTICKED = re.compile(r"`([^`\n]+)`")
TEST_REF = re.compile(r"tests/(\w+\.py)::(\w+(?:::\w+)?)", re.ASCII)
# Loose on purpose, so a malformed identifier is found and then rejected.
LLM_TOKEN = re.compile(r"\bLLM\d+(?::\d*)?")
ASI_TOKEN = re.compile(r"\bASI\d+")
ATLAS_TOKEN = re.compile(r"\bAML\.T\d+(?:\.\d+)?")


def threat_sections(lines: list[str]) -> list[tuple[str, list[str]]]:
    """(threat ID, its lines) per section; a section ends at the next threat or `## ` heading."""
    found, current = [], None
    for line in lines:
        heading = THREAT_HEADING.match(line)
        if heading:
            current = []
            found.append((heading.group(1), current))
        elif line.startswith("## "):
            current = None
        elif current is not None:
            current.append(line)
    return found


def is_path(token: str) -> bool:
    if TEST_REF.fullmatch(token) or any(c in token for c in " <>*"):
        return False
    return token.startswith(PATH_PREFIXES) or token in ROOT_FILES


def defined_tests(source: str) -> set[str]:
    """Module-level test functions, and test methods of module-level Test classes, as `Class::method`."""
    names = set()
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            names.add(node.name)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test"):
                    names.add(f"{node.name}::{item.name}")
    return names


def path_problem(token: str, root: Path) -> str | None:
    parts = PurePosixPath(token).parts
    if ".." in parts:
        return f"path {token} has a .. component"
    # Every component is checked, so a linked directory cannot lead outside root.
    if any((root / Path(*parts[:i])).is_symlink() for i in range(1, len(parts) + 1)):
        return f"path {token} is a symlink"
    if not (root / token).exists():
        return f"path {token} does not exist"
    return None


def section_problems(tid: str, lines: list[str]) -> list[str]:
    found = []
    for field in FIELDS:
        count = sum(line.startswith(field) for line in lines)
        if count != 1:
            found.append(f"{tid}: {count} lines start with '{field.strip()}'")

    statuses = [line[len("- Status: "):] for line in lines if line.startswith("- Status: ")]
    for status in statuses:
        if status not in STATUSES:
            found.append(f"{tid}: unknown status")

    controls = [line for line in lines if line.startswith("  - [")]
    if not controls:
        found.append(f"{tid}: no control lines")
    classes = []
    for number, line in enumerate(controls, start=1):
        match = CONTROL_CLASS.match(line)
        cls = match.group(1) if match else None
        classes.append(cls)
        if cls not in EVIDENCE_CLASSES:
            found.append(f"{tid}: control {number} has an unknown evidence class")
        tokens = BACKTICKED.findall(line)
        if cls == "test" and not any(TEST_REF.fullmatch(t) for t in tokens):
            found.append(f"{tid}: [test] control {number} cites no test")
        if cls == "config" and not any(is_path(t) for t in tokens):
            found.append(f"{tid}: [config] control {number} cites no path")

    if len(statuses) == 1:
        if statuses[0] == "Mitigated" and (not classes or any(c != "test" for c in classes)):
            found.append(f"{tid}: Mitigated needs every control to be [test]")
        if statuses[0] == "Partial" and "test" not in classes:
            found.append(f"{tid}: Partial needs at least one [test] control")

    for line in lines:
        value = line[len("- Frameworks: "):] if line.startswith("- Frameworks: ") else None
        if value is not None and value != NO_FRAMEWORK:
            for token in LLM_TOKEN.findall(value):
                if token not in LLM_2026:
                    found.append(f"{tid}: {token} is not an LLM 2026 identifier")
    return found


def problems(text: str, root: Path) -> list[str]:
    """One short message per problem; messages name IDs and paths, never other document text."""
    found = []
    lines = text.split("\n")

    for number, line in enumerate(lines, start=1):
        for ch in line:
            if ord(ch) >= 0x80 or ord(ch) < 0x20:
                found.append(f"line {number}: character U+{ord(ch):04X} is not allowed")

    sections = threat_sections(lines)
    if not sections:
        found.append("no threat sections")
    for index, (tid, section) in enumerate(sections, start=1):
        if tid != f"T{index:02d}":
            found.append(f"threat {tid}: expected T{index:02d}")
        found.extend(section_problems(tid, section))

    parsed: dict[str, set[str] | None] = {}
    for token in BACKTICKED.findall(text):
        ref = TEST_REF.fullmatch(token)
        if ref:
            file, name = ref.groups()
            if file not in parsed:
                path = root / "tests" / file
                if path.is_symlink() or not path.is_file():
                    parsed[file] = None
                else:
                    try:
                        parsed[file] = defined_tests(path.read_text(encoding="utf-8"))
                    except (SyntaxError, UnicodeDecodeError):
                        parsed[file] = set()
            if parsed[file] is None:
                found.append(f"tests/{file} does not exist")
            elif name not in parsed[file]:
                found.append(f"tests/{file}::{name} is not defined")
        elif is_path(token):
            problem = path_problem(token, root)
            if problem:
                found.append(problem)

    for token in LLM_TOKEN.findall(text):
        if not re.fullmatch(r"LLM\d+:\d{4}", token):
            found.append(f"{token} has no year")
        elif token not in LLM_2026 and token not in LLM_2025:
            found.append(f"{token} is not a known LLM identifier")
    for token in ASI_TOKEN.findall(text):
        if token not in ASI_IDS:
            found.append(f"{token} is not a known ASI identifier")
    for token in ATLAS_TOKEN.findall(text):
        if token not in ATLAS_IDS:
            found.append(f"{token} is not a known ATLAS identifier")
    return found


def read_document() -> str:
    # Decoded from bytes, so a carriage return is kept and reported, and a bad
    # byte becomes U+FFFD and is reported instead of raising.
    return DOCUMENT.read_bytes().decode("utf-8", errors="replace")


def test_threat_model_matches_the_repository():
    """A cited test or path is missing, a status breaks its rule, or an identifier is unknown."""
    assert problems(read_document(), REPO_ROOT) == []


MUTATIONS = {
    "duplicate threat id": ("### T02 ", "### T01 "),
    "unknown status": ("- Status: Partial", "- Status: Mostly fine"),
    "misspelled cited test": ("test_injection_phrases_match", "test_injection_phrases_matches"),
    "misspelled atlas id": ("AML.T0051.001", "AML.T0051.009"),
    "non ascii character": ("# Threat model", "# Threat model" + chr(0x2014)),
    "mitigated with a config control": ("- Status: Partial\n- Boundary: TB2. Elements: P6.", "- Status: Mitigated\n- Boundary: TB2. Elements: P6."),
    "partial without a test control": ("  - [test] A minimum similarity score", "  - [policy] A minimum similarity score"),
    "misspelled cited path": ("`vendor/sigma-detection-pack/SOURCE.md`", "`vendor/sigma-detection-pack/SOURCES.md`"),
    "llm id without a year": ("LLM01:2026; Agentic", "LLM01; Agentic"),
    "llm 2025 id in the register": ("- Frameworks: LLM06:2026; ATLAS 2026.09: AML.T0029", "- Frameworks: LLM10:2025; ATLAS 2026.09: AML.T0029"),
    "two status lines": ("- Status: Open\n", "- Status: Open\n- Status: Open\n"),
    "test control without its citation": (": `tests/test_audit_files.py::test_log_ending_without_newline_refused`", ""),
}


@pytest.mark.parametrize("name", list(MUTATIONS))
def test_mutation_is_reported(name):
    """A deliberate error in a copy of the document goes unreported."""
    old, new = MUTATIONS[name]
    text = read_document()
    assert old in text
    assert problems(text.replace(old, new, 1), REPO_ROOT) != []
