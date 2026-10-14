"""Check the vendored Sigma rules against current ATT&CK.

If a rule tags a technique ATT&CK has since revoked, the agent's technique
validation would reject the rule's own mapping. This test makes that drift
visible instead of letting it surface as a confusing eval miss.
"""

import re

from triage.config import REPO_ROOT, get_settings
from triage.tools.attack import load_attack

RULES = REPO_ROOT / "vendor" / "sigma-detection-pack" / "rules"

# Known stale tags. Fix upstream in sigma-detection-pack, re-vendor, then remove from here.
KNOWN_STALE = {"T1562.001"}  # revoked in ATT&CK, replaced by T1685 (as of v20.0)


def rule_techniques() -> dict[str, list[str]]:
    out = {}
    for f in sorted(RULES.glob("*.yml")):
        tags = re.findall(r"^\s*-\s*attack\.(t\d{4}(?:\.\d{3})?)\s*$", f.read_text(), flags=re.M)
        out[f.name] = [t.upper() for t in tags]
    return out


def test_every_rule_has_a_technique_tag():
    assert all(rule_techniques().values())


def test_rule_tags_are_current_attack_ids():
    attack = load_attack(get_settings().data_dir / "attack_techniques.json")
    stale = {t for tags in rule_techniques().values() for t in tags if t not in attack["techniques"]}
    assert stale == KNOWN_STALE, f"stale ATT&CK tags in vendored rules: {sorted(stale)}"
