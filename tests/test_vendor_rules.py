"""Check the vendored Sigma rules against current ATT&CK.

If a rule tag or runbook header uses a technique ATT&CK has since revoked,
the agent's technique validation would reject the rule's own mapping. These
tests make that drift visible instead of letting it surface as a confusing
eval miss.
"""

import re

from triage.config import REPO_ROOT, get_settings
from triage.tools.attack import load_attack

RULES = REPO_ROOT / "vendor" / "sigma-detection-pack" / "rules"


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
    assert not stale, f"stale ATT&CK tags in vendored rules: {sorted(stale)}"


def test_runbook_attack_headers_are_current_ids():
    # Runbook text is returned to the model, so a retired ID here would be repeated in its output.
    attack = load_attack(get_settings().data_dir / "attack_techniques.json")
    runbooks = RULES.parent / "runbooks"
    stale = {}
    for f in sorted(runbooks.glob("*.md")):
        header = re.search(r"^\*\*ATT&CK:\*\*(.*)$", f.read_text(), flags=re.M)
        ids = re.findall(r"T\d{4}(?:\.\d{3})?", header.group(1)) if header else []
        bad = [t for t in ids if t not in attack["techniques"]]
        if bad:
            stale[f.name] = bad
    assert not stale, f"retired ATT&CK IDs in runbook headers: {stale}"
