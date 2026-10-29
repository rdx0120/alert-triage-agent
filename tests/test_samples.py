"""Sample alerts: every file loads, generated files have not drifted, and the
deliberate edge cases (stale technique, uninventoried host) stay deliberate."""

import hashlib
import importlib.util
import json

import pytest

from triage.config import REPO_ROOT
from triage.ingest import load_alert

SAMPLES = REPO_ROOT / "samples" / "alerts"
PACK = REPO_ROOT / "vendor" / "sigma-detection-pack"
DATA = REPO_ROOT / "data"
ALL_SAMPLES = sorted(SAMPLES.glob("*/*.json"))

STALE_SAMPLE, STALE_TECHNIQUE = "edr_tampering.json", "T1562.001"
UNKNOWN_HOST_SAMPLE = "unknown_host_powershell.json"
WORKSPACE_SAMPLES = {
    "mail_forwarding_rule_created.json",
    "new_oauth_app_authorized.json",
    "password_spray.json",
    "super_admin_role_granted.json",
}


def load_sample(path):
    return load_alert(path.read_text(encoding="utf-8"), fmt=path.parent.name)


def test_sample_folders():
    assert {p.parent.name for p in ALL_SAMPLES} == {"wazuh", "sigma"}
    assert len(list((SAMPLES / "sigma").glob("*.json"))) == 6
    assert len(list((SAMPLES / "wazuh").glob("*.json"))) == 4


@pytest.mark.parametrize("path", ALL_SAMPLES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_sample_loads_with_folder_format(path):
    assert load_sample(path).source == path.parent.name


def test_sigma_samples_match_generator():
    spec = importlib.util.spec_from_file_location("build_sample_alerts", REPO_ROOT / "scripts" / "build_sample_alerts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    built = module.build_sigma_samples(PACK / "rules", PACK / "fixtures")
    committed = {p.stem: p.read_text(encoding="utf-8") for p in (SAMPLES / "sigma").glob("*.json")}
    assert {stem: module.render(s) for stem, s in built.items()} == committed


def test_sample_build_refreshes_only_provenance_hashes(tmp_path):
    """The generator may refresh a sample's sha256, never its class, source or other fields (DD-028)."""
    spec = importlib.util.spec_from_file_location("build_sample_alerts", REPO_ROOT / "scripts" / "build_sample_alerts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "a.json").write_text("{}\n", encoding="utf-8")
    entry = {"path": "samples/a.json", "sha256": "0" * 64, "class": "synthetic", "notes": "kept"}
    other = {"path": "data/b.json", "sha256": "1" * 64, "class": "public", "source": "kept"}
    provenance = tmp_path / "provenance.json"
    provenance.write_text(json.dumps({"version": 1, "files": [entry, other]}), encoding="utf-8")
    module.refresh_provenance(provenance, tmp_path, ["samples/a.json"])
    doc = json.loads(provenance.read_text(encoding="utf-8"))
    digest = hashlib.sha256(b"{}\n").hexdigest()
    assert doc == {"version": 1, "files": [{**entry, "sha256": digest}, other]}
    (tmp_path / "samples" / "new.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(KeyError):   # a new sample needs a hand-written entry first
        module.refresh_provenance(provenance, tmp_path, ["samples/new.json"])


@pytest.fixture(scope="module")
def attack():
    return json.loads((DATA / "attack_techniques.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", ALL_SAMPLES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_sample_techniques_are_current(path, attack):
    techniques = load_sample(path).attack_tags()
    if path.name == STALE_SAMPLE:
        # Deliberately stale: present, and retired in the ATT&CK snapshot.
        assert STALE_TECHNIQUE in techniques
        assert STALE_TECHNIQUE not in attack["techniques"]
        assert STALE_TECHNIQUE in attack["retired"]
        techniques = [t for t in techniques if t != STALE_TECHNIQUE]
    stale = [t for t in techniques if t not in attack["techniques"]]
    assert not stale


@pytest.mark.parametrize("path", ALL_SAMPLES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_sample_hosts_are_inventoried(path):
    inventory = {a["host"] for a in json.loads((DATA / "assets.json").read_text(encoding="utf-8"))["assets"]}
    host = load_sample(path).host
    if path.name in WORKSPACE_SAMPLES:
        assert host is None
    elif path.name == UNKNOWN_HOST_SAMPLE:
        # Deliberately uninventoried: a valid hostname that is not in the asset list.
        assert host == "WS-UNMANAGED-07"
        assert host not in inventory
    else:
        assert host in inventory
