"""The seeded order generator: deterministic, valid, and independent of Python's random module."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest

from evaluation import order, records

SEED = "ab" * 32


def registry(n_tests: int = 5) -> records.Registry:
    cases = [{"case_id": "dev-warm", "family": "dev", "format": "sigma", "path": "samples/alerts/sigma/x.json",
              "clean_twin": None, "phrasing": None, "alert_id": "dev-warm", "rule_level": "high"}]
    for i in range(n_tests):
        cases.append({"case_id": f"test-c{i}", "family": "A", "format": "sigma", "path": f"eval/cases/test/c{i}.json",
                      "clean_twin": None, "phrasing": None, "alert_id": f"c{i}", "rule_level": "low"})
    return records.Registry.model_validate({"version": 1, "cases": cases})


def reference_permutation(ids, seed, sequence, round_):
    """An independent restatement of the shuffle, written from the specification."""
    items = list(ids)
    n = len(items)
    for step in range(n - 1):
        i = n - 1 - step
        material = bytes.fromhex(seed) + sequence.encode() + round_.to_bytes(4, "big") + step.to_bytes(4, "big")
        j = int(hashlib.sha256(material).hexdigest(), 16) % (i + 1)
        items[i], items[j] = items[j], items[i]
    return items


def test_a_known_seed_gives_the_stated_order():
    ids = [f"test-c{i}" for i in range(5)]
    doc = order.generate(registry(), SEED, "dev-warm")
    assert [e["case_id"] for e in doc["baseline"][1:6]] == reference_permutation(ids, SEED, "baseline", 1)
    assert [e["case_id"] for e in doc["baseline"][6:]] == reference_permutation(ids, SEED, "baseline", 2)
    for r in (1, 2, 3):
        block = doc["model"][1 + (r - 1) * 5: 1 + r * 5]
        assert [e["case_id"] for e in block] == reference_permutation(ids, SEED, "model", r)
        assert {e["repeat"] for e in block} == {r} and {e["role"] for e in block} == {"scored"}


def test_the_order_is_valid_deterministic_and_seed_dependent():
    reg = registry()
    a = order.generate(reg, SEED, "dev-warm")
    assert a == order.generate(reg, SEED, "dev-warm")
    assert records.order_problems(a, reg) == []
    assert a["baseline"][0] == {"position": 1, "case_id": "dev-warm", "role": "warmup", "repeat": 1}
    assert [e["role"] for e in a["baseline"][6:]] == ["determinism"] * 5
    assert [e["position"] for e in a["model"]] == list(range(1, 17))
    b = order.generate(reg, "cd" * 32, "dev-warm")
    assert a["model"] != b["model"]


@pytest.mark.parametrize("seed", ["AB" * 32, "ab" * 31, "zz" * 32, ""])
def test_a_bad_seed_is_refused(seed):
    with pytest.raises(order.OrderRefused):
        order.generate(registry(), seed, "dev-warm")


def test_a_warm_up_that_is_not_a_development_case_is_refused():
    with pytest.raises(order.OrderRefused):
        order.generate(registry(), SEED, "test-c0")


def test_the_generator_does_not_use_the_random_module():
    tree = ast.parse((Path(order.__file__)).read_text())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert "random" not in imported and "secrets" not in imported
