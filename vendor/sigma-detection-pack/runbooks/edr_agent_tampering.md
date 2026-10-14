# Runbook: EDR Agent Stopped, Uninstalled, or Suppressed

**Rule:** `rules/endpoint/edr_agent_tampering.yml`
**Severity:** Critical
**ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools

## What this means

A command was observed attempting to stop, kill, or uninstall the
Bitdefender GravityZone agent or its protected service. Attackers
routinely disable endpoint protection immediately before deploying a
secondary payload or ransomware — this event should be treated as
critical and time-sensitive even before its cause is confirmed.

## Triage steps

1. **Immediately check whether the agent actually went offline** in
   the GravityZone console for this endpoint — confirm the tampering
   succeeded, not just that it was attempted (tamper protection may
   have blocked it).
2. **Identify who/what ran the command.** A logged-in IT admin
   performing planned maintenance vs. an unexpected service account or
   unattended process are very different scenarios.
3. **Check for a change ticket** matching a planned agent
   upgrade/reinstall/decommission.
4. **Check what else happened on the endpoint immediately before and
   after** — this is very often paired with other activity (new
   scheduled task, new service install, suspicious PowerShell — see
   `suspicious_encoded_powershell`).

## Response actions

- **Unplanned/unexplained:** Treat as an active incident. Isolate the
  endpoint at the network level (UniFi) immediately, since EDR
  visibility on it may now be degraded or gone. Do not wait for full
  confirmation before isolating — the cost of a false positive here
  (a few minutes of user disruption) is far lower than the cost of a
  missed ransomware precursor.
- **Planned maintenance:** Confirm against the change ticket, document,
  and close.

## Known false positives

- Planned agent upgrade or reinstall performed by IT.
- Vendor-authorized uninstall during endpoint decommissioning.

## Tuning notes

Do not raise this rule's severity threshold or add broad suppressions.
If planned maintenance triggers this rule frequently, the correct fix
is a change-ticket cross-reference step in triage, not silencing the
rule.
