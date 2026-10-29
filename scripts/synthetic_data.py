"""Synthetic-or-public data rules for tracked files (DD-028, threat T30).

CLAUDE.md rule 1 says the repository holds synthetic or public data only. This
module turns that into checks a test can run. It cannot prove that no real
data exists: a real name or a real clinical note looks like any other text.
What it does is make the forms real data most often takes (routable IP
addresses, real email domains, real hosts in URLs, phone and SSN shapes) fail
unless they are in a documentation or reserved range, and bind every
data-bearing file to an exact, reviewed provenance entry.

The rules are a pure function of (path, content bytes, path class), so they can
run on the git index (tests/test_synthetic_data.py) or on files that are not
committed yet. Nothing here reads the working tree on its own.

Usage:
    python scripts/synthetic_data.py --update-hashes PATH...   # refresh sha256 only
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROVENANCE = "provenance.json"

# Path classes. Every tracked file is in exactly one, decided by path alone.
DATA = "data"                 # strict rules and a per-file provenance entry
REFERENCE = "reference"       # as DATA, but URLs may use REFERENCE_HOSTS
METADATA = "metadata"         # provenance.json only: bound by its commit, never by itself
EVAL_OUTPUT = "eval-output"   # reserved for evaluation results; rejected until E1b
OTHER = "other"               # code, tests, docs: IP and email rules only

DATA_PREFIXES = ("data/", "samples/", "tests/data/", "vendor/sigma-detection-pack/fixtures/", "eval/")
REFERENCE_PREFIXES = ("vendor/sigma-detection-pack/rules/", "vendor/sigma-detection-pack/runbooks/")
EVAL_OUTPUT_PREFIX = "eval/results/"

# Public hosts reference content (the vendored rules and runbooks) may link to.
# Each is a public reference or a project's own source host.
REFERENCE_HOSTS = {
    "attack.mitre.org": "MITRE ATT&CK technique pages",
    "github.com": "source repositories",
    "api.github.com": "GitHub REST API documentation and endpoints",
    "raw.githubusercontent.com": "raw files of public repositories",
    "www.first.org": "EPSS documentation",
    "api.first.org": "EPSS API",
    "download.pytorch.org": "CPU-only PyTorch wheel index",
    "huggingface.co": "embedding model source",
    "docs.astral.sh": "uv documentation",
    "mail.google.com": "Gmail settings referenced by mail runbooks",
}

# Reserved names (RFC 2606, RFC 6761). A host is reserved if it equals one of
# RESERVED_NAMES or ends with "." plus one of them or with a reserved TLD.
RESERVED_TLDS = ("test", "example", "invalid", "localhost")
RESERVED_NAMES = ("example.com", "example.net", "example.org", "localhost")

ALLOWED_IPV4 = tuple(ipaddress.ip_network(n) for n in
                     ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8", "0.0.0.0/32"))
ALLOWED_IPV6 = tuple(ipaddress.ip_network(n) for n in ("2001:db8::/32", "::1/128", "::/128"))

# Built from parts so this file does not itself contain the forbidden marker.
INLINE_ALLOW = "gitleaks" + ":allow"

IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.]*\d)")
# Candidate IPv6 text: hex groups and colons with at least two colons. Parsed
# with ipaddress; anything that does not parse is not an address.
IPV6_RE = re.compile(r"(?<![\w:.])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![\w:])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://([^/\s\"'<>)\]`]+)")
# North American numbers: "(212)867-5309", "(212) 867-5309", "212-867-5309",
# "212.867.5309", optionally after "+1". The area code is either in
# parentheses (a separator after it is optional) or followed by a separator.
PHONE_RE = re.compile(r"(?<!\d)(?:\+?1[ .-]?)?(?:\((\d{3})\)[ .-]?|(\d{3})[ .-])(\d{3})[ .-](\d{4})(?!\d)")
SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
HOST_KEYS = frozenset({"host", "hostname", "domain", "fqdn"})


def path_class(path: str) -> str:
    """The class of a repository-relative POSIX path."""
    if path == PROVENANCE:
        return METADATA
    if path.startswith(EVAL_OUTPUT_PREFIX):
        return EVAL_OUTPUT
    if path.startswith(REFERENCE_PREFIXES):
        return REFERENCE
    if path.startswith(DATA_PREFIXES):
        return DATA
    return OTHER


def is_reserved_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host in RESERVED_NAMES or host in RESERVED_TLDS:
        return True
    return any(host.endswith("." + n) for n in RESERVED_NAMES + RESERVED_TLDS)


@dataclass
class FileRules:
    """What a file's provenance entry allows beyond the class rules."""
    permitted_hosts: frozenset[str] = field(default_factory=frozenset)


def _host_of(netloc: str) -> str:
    host = netloc.rsplit("@", 1)[-1]
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.split(":", 1)[0]


def _host_ok(host: str, cls: str, rules: FileRules) -> bool:
    host = host.lower().rstrip(".")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        # An address is judged by the address ranges, whatever text it came
        # from (a URL, a host field, a decoded JSON escape).
        return _ipv4_ok(host) if addr.version == 4 else _ipv6_ok(host)
    if is_reserved_host(host) or host in rules.permitted_hosts:
        return True
    return cls in (REFERENCE, METADATA) and host in REFERENCE_HOSTS


def _ipv4_ok(text: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        return True   # not an address (an octet above 255, a version string)
    return any(addr in net for net in ALLOWED_IPV4)


def _ipv6_ok(text: str) -> bool:
    try:
        addr = ipaddress.IPv6Address(text)
    except ValueError:
        return True
    return any(addr in net for net in ALLOWED_IPV6)


class DecodeError(Exception):
    """A structured file could not be decoded, so its escaped text cannot be checked."""


class _Pairs(list):
    """A JSON object kept as its (key, value) pairs, so a repeated key hides nothing."""


def _decoded_json(text: str):
    # object_pairs_hook keeps every pair: json.loads would otherwise keep only
    # the last value of a repeated key, and an earlier one would go unchecked.
    return json.loads(text, object_pairs_hook=_Pairs)


def _json_items(doc, strings: list[str], hosts: list[str]) -> None:
    """Every string (keys included) and every host-field value, walked iteratively."""
    stack = [doc]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, _Pairs):
            for k, v in value:
                strings.append(k)
                if k.lower() in HOST_KEYS and isinstance(v, str):
                    hosts.append(v)
                stack.append(v)
        elif isinstance(value, list):
            stack.extend(value)


def _yaml_items(text: str, strings: list[str], hosts: list[str]) -> None:
    """Every scalar and host-field value of every YAML document, from the node graph.

    The composed node graph keeps every key of a mapping, repeated ones
    included, and holds each scalar with its escapes already decoded. Nodes
    are visited once each, so an alias that refers back to its own anchor
    cannot loop. Binary scalars are rejected: their content is encoded.
    """
    import yaml   # dev dependency; the tests that call this run with it installed
    seen: set[int] = set()
    stack = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.ScalarNode):
            if node.tag == "tag:yaml.org,2002:binary":
                raise DecodeError("binary YAML scalar")
            strings.append(node.value)
        elif isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if (isinstance(key, yaml.ScalarNode) and isinstance(value, yaml.ScalarNode)
                        and key.value.lower() in HOST_KEYS):
                    hosts.append(value.value)
                stack.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)


def _decoded_items(path: str, text: str) -> tuple[list[str], list[str]] | None:
    """(strings, host-field values) of a JSON, JSONL or YAML file; None for other types.

    Raises DecodeError when such a file cannot be decoded completely.
    """
    strings: list[str] = []
    hosts: list[str] = []
    try:
        if path.endswith(".json"):
            _json_items(_decoded_json(text), strings, hosts)
        elif path.endswith(".jsonl"):
            for line in text.splitlines():
                if line.strip():
                    _json_items(_decoded_json(line), strings, hosts)
        elif path.endswith((".yml", ".yaml")):
            _yaml_items(text, strings, hosts)
        else:
            return None
    except DecodeError:
        raise
    except ImportError:
        raise DecodeError("YAML support is not installed") from None
    except (ValueError, RecursionError) as error:   # json errors and nesting too deep
        raise DecodeError(type(error).__name__) from None
    except Exception as error:
        # yaml.YAMLError and anything else a parser raises: never let a
        # malformed file stop the check, and never let it pass unchecked.
        raise DecodeError(type(error).__name__) from None
    return strings, hosts


def _line_rules(line: str, cls: str, rules: FileRules) -> list[str]:
    """Rule messages for one line of text. Messages never include the matched value."""
    found = []
    if INLINE_ALLOW in line:
        found.append("inline scanner allow comment")
    for m in IPV4_RE.finditer(line):
        if not _ipv4_ok(m.group(1)):
            found.append("IPv4 address outside documentation and loopback ranges")
    for m in IPV6_RE.finditer(line):
        if not _ipv6_ok(m.group(1)):
            found.append("IPv6 address outside 2001:db8::/32 and loopback")
    for m in EMAIL_RE.finditer(line):
        if not is_reserved_host(m.group(1)):
            found.append("email address outside reserved domains")
    if cls not in (DATA, REFERENCE, METADATA):
        return found
    for m in URL_RE.finditer(line):
        host = _host_of(m.group(1))
        if host and not _host_ok(host, cls, rules):
            found.append("URL host not reserved or permitted")
    for m in PHONE_RE.finditer(line):
        exchange, number_part = m.group(3), int(m.group(4))
        if not (exchange == "555" and 100 <= number_part <= 199):
            found.append("phone number outside 555-0100 to 555-0199")
    if SSN_RE.search(line):
        found.append("SSN-shaped number")
    return found


def check_content(path: str, data: bytes, cls: str, rules: FileRules | None = None) -> list[str]:
    """Rule violations for one file, as "path:line: rule (detail)" strings.

    The detail never quotes surrounding text, so a violation in a real file
    does not copy that file's content into a test log.
    """
    rules = rules or FileRules()
    found: list[str] = []
    name = path.rsplit("/", 1)[-1]
    if name == ".gitattributes":
        # Diff attributes apply to all of history in git log -p: one line can
        # hide every file of a type from the secret scan (H2 amendment A, A2).
        found.append(f"{path}: gitattributes file is not allowed")
    if cls == EVAL_OUTPUT:
        # Reserved for E1b, which must implement the eval-output class first.
        found.append(f"{path}: eval-output class is reserved and not yet implemented")
        return found
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        if cls in (DATA, REFERENCE, METADATA):
            found.append(f"{path}: binary or non-UTF-8 content in a data-bearing path")
        return found

    strict = cls in (DATA, REFERENCE, METADATA)
    for number, line in enumerate(text.split("\n"), start=1):
        found += [f"{path}:{number}: {message}" for message in _line_rules(line, cls, rules)]

    # Escapes such as \u0038 in JSON or YAML hide a value from the line rules,
    # so the same rules also run on every decoded string. A rule already
    # reported for this file from the raw text is not repeated: the file fails
    # either way. A JSON, JSONL or YAML file that cannot be decoded completely
    # fails in every class, since its escaped text cannot be checked.
    try:
        items = _decoded_items(path, text)
    except DecodeError:
        found.append(f"{path}: structured file cannot be decoded, so escaped text cannot be checked")
        items = None
    if items is not None:
        strings, hosts = items
        raw = {f.split(": ", 1)[1] for f in found if ": " in f}
        decoded = []
        for value in strings:
            for line in value.split("\n"):
                decoded += [m for m in _line_rules(line, cls, rules) if m not in raw and m not in decoded]
        found += [f"{path}: {message} (in a decoded string)" for message in decoded]
        if strict:
            for host in hosts:
                if "." in host and not _host_ok(host, cls, rules):
                    found.append(f"{path}: host field not reserved or permitted")
    return found


# --- Provenance --------------------------------------------------------------

ENTRY_KEYS = frozenset({"path", "sha256", "class", "source", "permitted_hosts", "unknown_hosts", "notes"})
ENTRY_CLASSES = frozenset({"synthetic", "public", "eval-output"})
SHA256_RE = re.compile(r"[0-9a-f]{64}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def schema_problems(doc) -> list[str]:
    """Structural problems in a parsed provenance document."""
    if not isinstance(doc, dict) or set(doc) != {"version", "files"} or doc.get("version") != 1:
        return ["provenance: top level must be exactly {\"version\": 1, \"files\": [...]}"]
    if not isinstance(doc["files"], list):
        return ["provenance: files must be a list"]
    problems = []
    seen = set()
    for i, entry in enumerate(doc["files"]):
        where = f"provenance entry {i}"
        if not isinstance(entry, dict):
            problems.append(f"{where}: not an object")
            continue
        extra = set(entry) - ENTRY_KEYS
        if extra:
            problems.append(f"{where}: unknown keys {sorted(extra)}")
        path = entry.get("path")
        if not isinstance(path, str) or not path or any(c in path for c in "*?[]") or path.startswith("/"):
            problems.append(f"{where}: path must be an exact relative path")
            continue
        where = f"provenance {path}"
        if path in seen:
            problems.append(f"{where}: duplicate entry")
        seen.add(path)
        if path == PROVENANCE:
            problems.append(f"{where}: the provenance file must not declare itself")
        if not isinstance(entry.get("sha256"), str) or not SHA256_RE.fullmatch(entry["sha256"]):
            problems.append(f"{where}: sha256 must be 64 lowercase hex characters")
        cls = entry.get("class")
        if cls not in ENTRY_CLASSES:
            problems.append(f"{where}: class must be one of {sorted(ENTRY_CLASSES)}")
        if cls in ("public", "eval-output") and not (isinstance(entry.get("source"), str) and entry["source"]):
            problems.append(f"{where}: a {cls} entry needs a source")
        for key in ("permitted_hosts", "unknown_hosts"):
            if key in entry and not (isinstance(entry[key], list) and all(isinstance(h, str) and h for h in entry[key])):
                problems.append(f"{where}: {key} must be a list of names")
        if "notes" in entry and not isinstance(entry["notes"], str):
            problems.append(f"{where}: notes must be a string")
    return problems


def provenance_problems(doc, files: dict[str, bytes]) -> list[str]:
    """Problems binding provenance to the tracked files (path -> content)."""
    problems = schema_problems(doc)
    if problems:
        return problems
    entries = {e["path"]: e for e in doc["files"]}
    needed = {p for p in files if path_class(p) in (DATA, REFERENCE)}
    for path in sorted(needed - entries.keys()):
        problems.append(f"{path}: no provenance entry")
    for path in sorted(entries.keys() - files.keys()):
        problems.append(f"provenance {path}: names a file that is not tracked")
    for path in sorted(entries.keys() & files.keys()):
        if path not in needed:
            problems.append(f"provenance {path}: file is not in a data-bearing or reference path")
        elif entries[path]["sha256"] != sha256(files[path]):
            problems.append(f"provenance {path}: sha256 does not match the file")
    return problems


def file_rules(entry: dict | None) -> FileRules:
    if entry is None:
        return FileRules()
    return FileRules(permitted_hosts=frozenset(h.lower() for h in entry.get("permitted_hosts", [])))


def update_hashes(doc: dict, files: dict[str, bytes]) -> dict:
    """A copy of doc with sha256 refreshed for the given existing entries only.

    Never adds an entry and never touches class, source or any other field:
    declaring what a file is stays a reviewed, manual change.
    """
    out = json.loads(json.dumps(doc))
    by_path = {e["path"]: e for e in out["files"]}
    for path, data in files.items():
        if path not in by_path:
            raise KeyError(f"{path}: no provenance entry; add one by hand with its class and source")
        by_path[path]["sha256"] = sha256(data)
    return out


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update-hashes", nargs="+", metavar="PATH", required=True,
                        help="repository-relative paths whose provenance sha256 to refresh")
    args = parser.parse_args(argv)
    prov = REPO_ROOT / PROVENANCE
    doc = json.loads(prov.read_text(encoding="utf-8"))
    files = {p: (REPO_ROOT / p).read_bytes() for p in args.update_hashes}
    prov.write_text(render(update_hashes(doc, files)), encoding="utf-8")
    print(f"refreshed {len(files)} provenance hashes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
