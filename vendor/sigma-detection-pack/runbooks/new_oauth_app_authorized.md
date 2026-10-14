# Runbook: New Third-Party OAuth Application Authorized

**Rule:** `rules/identity/new_oauth_app_authorized.yml`
**Severity:** Medium
**ATT&CK:** T1550 / T1528 — Use of Application Access Token

## What this means

A user granted a third-party application OAuth access to their Google
Workspace account/data, and the application's client ID is not on the
known-good allowlist. This does not require a password and does not
trigger MFA, making it a favored persistence mechanism after phishing
or account compromise — the attacker doesn't need to keep stealing the
password; the token keeps working until manually revoked.

## Triage steps

1. **Identify the app and requested scopes.** Full mail access
   (`https://mail.google.com/`) or Drive access is high risk; a narrow
   read-only calendar scope is lower risk.
2. **Check the user's recent activity.** Did this follow a suspicious
   login (check `impossible_travel_workspace_login` and
   `password_spray` alerts for the same user around this time)?
3. **Ask the user directly** if they recognize and intentionally
   authorized the app — this is often the fastest path to resolution
   for genuine false positives.
4. **Check the app's reputation** — is it a known legitimate SaaS
   product, or does it look auto-generated / suspicious?

## Response actions

- **If unrecognized or high-risk scope:** Revoke the app's access
  immediately via Workspace Admin Console → Security → API Controls →
  App Access Control. Force a password reset and MFA re-enrollment for
  the user as a precaution.
- **If legitimate and desired going forward:** Add the client ID to
  `filter_known_good` in the rule so future authorizations of the same
  app don't re-alert.
- Document the decision either way — this is an audit-relevant event.

## Known false positives

- Legitimate adoption of a new IT-approved SaaS tool not yet added to
  the allowlist. This should shrink over time as the allowlist matures.

## Tuning notes

This rule is intentionally biased toward over-alerting rather than
under-alerting: a maintained allowlist is a deliberate ongoing cost
accepted in exchange for not missing a real token-abuse persistence
event.
