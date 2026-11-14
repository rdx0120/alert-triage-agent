"""The model endpoint grammar: loopback literals and a port only, one canonical form for every child."""

from __future__ import annotations

import pytest

import test_eval_doubles as dbl
from evaluation import endpoint, harness

REFUSED = [
    None, "", "localhost:11434", "http://localhost:11434", "ollama.example:11434", "192.0.2.1:11434",
    "127.0.0.2:11434", "127.1.2.3:11434", "0177.0.0.1:11434", "2130706433:11434", "127.1:11434",
    "[::" + "ffff:127.0.0.1]:11434", "::" + "ffff:127.0.0.1:11434", "127.0.0.1:11434/", "127.0.0.1:11434/api",
    "https://127.0.0.1:11434", "http://user@127.0.0.1:11434", "http://user:pw@127.0.0.1:11434", "127.0.0.1",
    "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:011434", "127.0.0.1:65536", "127.0.0.1:+80", "[::1]", "::1:11434",
    " 127.0.0.1:11434", "127.0.0.1:11434 ", "HTTP://127.0.0.1:11434", "http://[::1]:11434/",
]


@pytest.mark.parametrize("value", REFUSED)
def test_every_other_form_is_refused(value):
    with pytest.raises(endpoint.EndpointRefused) as info:
        endpoint.parse_endpoint(value)
    if value:
        assert value.strip() not in str(info.value)


@pytest.mark.parametrize("value, url", [
    ("127.0.0.1:11434", "http://127.0.0.1:11434"), ("http://127.0.0.1:11434", "http://127.0.0.1:11434"),
    ("[::1]:11434", "http://[::1]:11434"), ("http://[::1]:11434", "http://[::1]:11434"),
    ("127.0.0.1:1", "http://127.0.0.1:1"), ("127.0.0.1:65535", "http://127.0.0.1:65535"),
])
def test_loopback_literals_are_accepted_and_made_canonical(value, url):
    assert endpoint.canonical_url(endpoint.parse_endpoint(value)) == url


def test_the_server_side_grammar_has_no_scheme():
    assert endpoint.server_host_ok("127.0.0.1:11434") and endpoint.server_host_ok("[::1]:11434")
    for value in ("http://127.0.0.1:11434", "0.0.0.0:11434", "localhost:11434", "127.0.0.1:99999"):
        assert not endpoint.server_host_ok(value)


@pytest.mark.parametrize("value", ["localhost:11434", "192.0.2.1:11434", None])
def test_a_refused_endpoint_creates_no_pass_and_no_ledger(tmp_path, tmp_path_factory, monkeypatch, value):
    clone = dbl.make_clone(tmp_path, tmp_path_factory)
    store = dbl.private_dir(tmp_path / "store")
    if value is None:
        monkeypatch.delenv("OLLAMA_HOST", raising=False)
    else:
        monkeypatch.setenv("OLLAMA_HOST", value)
    with pytest.raises(harness.HarnessRefused):
        harness.execute_pass(str(clone.path), str(store), "baseline-001", clone.merge_sha, clone.merge_tree,
                             hooks=clone.hooks())
    assert list(store.iterdir()) == []


def test_the_harness_command_refuses_a_bad_endpoint_with_exit_2(tmp_path, tmp_path_factory):
    import os
    import subprocess
    import sys
    clone = dbl.make_clone(tmp_path, tmp_path_factory)
    store = dbl.private_dir(tmp_path / "store")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "OLLAMA_HOST": "localhost:11434"}
    proc = subprocess.run([sys.executable, "-s", "-B", "-P", str(clone.path / "evaluation" / "harness.py"), "run",
                           "--clone", os.path.realpath(clone.path), "--store", str(store), "--pass", "baseline-001",
                           "--merge-sha", clone.merge_sha, "--merge-tree", clone.merge_tree],
                          env=env, capture_output=True, text=True)
    assert proc.returncode == 2
    assert proc.stderr == "harness: error: model endpoint must be a loopback literal and port\n"
    assert list(store.iterdir()) == []
