# Runbook: Email Forwarding Rule Created

**Rule:** `rules/identity/mail_forwarding_rule_created.yml`
**Severity:** High
**ATT&CK:** T1114.003 — Email Collection: Email Forwarding Rule

## What this means

A mailbox auto-forwarding rule was created. This is one of the most
common Business Email Compromise (BEC) persistence techniques: an
attacker who briefly accesses a mailbox (via phishing, password spray,
or a leaked credential) sets up silent forwarding so they keep reading
mail even after the password is reset and MFA is re-enrolled.

## Triage steps

1. **Identify the destination address.** Internal/known address = low
   risk. External/unknown domain = high risk, escalate immediately.
2. **Check for correlated indicators** on the same account: a recent
   `password_spray` hit, an `impossible_travel_workspace_login` alert,
   or a `new_oauth_app_authorized` event. Any of these alongside a new
   forwarding rule strongly indicates active compromise.
3. **Review what mail has already been forwarded**, if the destination
   is confirmed malicious — this determines the scope of data exposure
   (patient scheduling info, billing info, etc. — HIPAA-relevant).

## Response actions

- **Confirmed malicious:** Disable the forwarding rule immediately.
  Force password reset + MFA re-enrollment. Review account activity for
  the full compromise window. If PHI was forwarded, this becomes a
  HIPAA breach-assessment question — follow the incident response plan's
  breach notification decision tree.
- **Legitimate:** Document and close. No allowlist needed for this rule
  — every forwarding rule creation should continue to alert, since the
  cost of missing a real one is high and the volume is naturally low.

## Known false positives

- A user legitimately forwarding work mail to a secondary work address
  or personal address with manager approval.
- IT-configured shared-mailbox forwarding during onboarding — check the
  change-management log for a matching planned change before treating
  as an anomaly.

## Tuning notes

Deliberately no allowlist/suppression on this rule — the base rate of
legitimate forwarding-rule creation in this environment is low enough
that every instance warrants a human look.
