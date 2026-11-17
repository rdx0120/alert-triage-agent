"""The seeded run order.

Each round is a Fisher-Yates shuffle driven by SHA-256 of the seed, the
sequence name, the round and the step, so the order is reproducible from the
seed alone and does not depend on Python's random module or its version.
The result must pass the same validator the scorer uses.
"""

from __future__ import annotations

if __name__ == "__main__":
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.realpath(__file__))))

import hashlib
import os
import re
import sys

from evaluation import identity, records
from evaluation.common import PRODUCTION_K, EvaluationError, canonical_dumps
from evaluation.ledger import write_private

SEED_RE = re.compile(r"^[0-9a-f]{64}$")


class OrderRefused(EvaluationError):
    """The order cannot be generated."""


def permutation(ids: list[str], seed_hex: str, sequence: str, round_: int) -> list[str]:
    out = list(ids)
    seed = bytes.fromhex(seed_hex)
    for i in range(len(out) - 1, 0, -1):
        step = len(out) - 1 - i
        digest = hashlib.sha256(seed + sequence.encode("ascii") + round_.to_bytes(4, "big")
                                + step.to_bytes(4, "big")).digest()
        j = int.from_bytes(digest, "big") % (i + 1)
        out[i], out[j] = out[j], out[i]
    return out


def generate(registry: records.Registry, seed: str, warmup: str) -> dict:
    if SEED_RE.fullmatch(seed) is None:
        raise OrderRefused("order: seed must be 64 lowercase hex digits")
    tests = [c.case_id for c in registry.test_cases()]

    def sequence(name: str, roles: list[str]) -> list[dict]:
        entries = [{"position": 1, "case_id": warmup, "role": "warmup", "repeat": 1}]
        for r, role in enumerate(roles, start=1):
            for cid in permutation(tests, seed, name, r):
                entries.append({"position": len(entries) + 1, "case_id": cid, "role": role, "repeat": r})
        return entries

    doc = {"version": 1, "seed": seed, "k": PRODUCTION_K,
           "baseline": sequence("baseline", ["scored", "determinism"]),
           "model": sequence("model", ["scored"] * PRODUCTION_K)}
    problems = records.order_problems(doc, registry)
    if problems:
        raise OrderRefused(problems[0])
    return doc


def _body(argv) -> int:
    parser = identity.Parser(prog="evaluation/order.py", allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=identity.Parser)
    gen = sub.add_parser("generate", allow_abbrev=False)
    for name in ("--clone", "--seed", "--warmup", "--out"):
        gen.add_argument(name, required=True)
    args = parser.parse_args(argv)
    if not identity.clone_ok(args.clone, __file__):
        raise identity.UsageRefused("--clone must be the clone this tool runs from")
    registry = records.load_registry(os.path.join(args.clone, "eval", "cases.json"))
    write_private(args.out, canonical_dumps(generate(registry, args.seed, args.warmup)), what="order")
    print("order: order written")
    return 0


def main(argv=None) -> int:
    return identity.run_cli("order", _body, sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())
