# Runbook: Password Spray Against Multiple Accounts

**Rule:** `rules/identity/password_spray.yml`
**Severity:** High
**ATT&CK:** T1110.003 — Brute Force: Password Spraying

## What this means

A single source IP (or small cluster of IPs) generated failed login
attempts against more than 10 distinct Google Workspace accounts within
a 10-minute window, with a low per-account attempt count. This pattern
(many accounts, few attempts each) is characteristic of password
spraying — an attacker trying a small list of common/leaked passwords
across many accounts to avoid per-account lockout thresholds.

## Triage steps

1. **Confirm the pattern.** Pull the raw events for the source IP over
   the alert window. Verify: distinct target count, attempt count per
   target, and whether any attempts *succeeded*.
2. **Check for a successful login among the failures.** This is the
   single most important check — a spray followed by one success means
   an account is compromised. Escalate immediately if found.
3. **Identify the source.** Is the IP a known VPN/proxy egress point
   used by staff (check against the network inventory)? Is it a known
   malicious IP (check against threat intel / AbuseIPDB)?
4. **Check for a temporal pattern.** Off-hours (e.g., 2–4 AM local time)
   increases suspicion; spraying during business hours from a
   recognized location decreases it.

## Response actions

- **If no successful login found:** Block the source IP at the
  firewall/UniFi level. Notify affected users to change passwords as a
  precaution if the list is small. Document as a contained attempt.
- **If a successful login is found:** Treat as a confirmed compromise.
  Force password reset + re-enroll MFA for the affected account.
  Review the account's recent activity for the OAuth-app and
  mail-forwarding indicators in this same pack (`new_oauth_app_authorized`,
  `mail_forwarding_rule_created`) — these are the most common next steps
  an attacker takes after a successful spray hit.
- Add the source IP to the long-term blocklist if not already covered
  by an upstream feed.

## Known false positives

- Shared NAT/corporate egress IPs with many legitimate users behind
  them can trip the distinct-account threshold. Cross-check against
  the known egress IP list before escalating.
- Misconfigured mobile devices retrying cached bad credentials against
  their own account repeatedly — this shows up as low distinct-account
  count and should not match this rule's threshold, but verify if in
  doubt.

## Tuning notes

Threshold (`> 10` distinct accounts in `10m`) was chosen as a starting
point balancing sensitivity against a ~100-employee-equivalent org
size. If false positives from shared egress IPs become frequent,
consider excluding known-good source IPs via an explicit allowlist
rather than raising the threshold, which would reduce sensitivity to
real slow-and-low sprays.
