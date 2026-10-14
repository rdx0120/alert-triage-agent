# Runbook: Super-Admin Role Granted

**Rule:** `rules/identity/super_admin_role_granted.yml`
**Severity:** Critical
**ATT&CK:** T1098 — Account Manipulation

## What this means

A user was granted the Super Admin role (or another highly privileged
admin role matching this pattern) in Google Workspace. This is one of
the highest-value events in the entire environment — Super Admin can
reset any password, read any mailbox, and disable any security control.
Every instance of this event should be reviewed regardless of who
performed the grant, including planned/legitimate ones.

## Triage steps

1. **Was this planned?** Check the change log / ticket queue for a
   corresponding approved change (new IT hire onboarding, scheduled
   admin rotation, break-glass procedure).
2. **Who performed the grant, and from where?** Correlate the actor's
   recent login activity against `impossible_travel_workspace_login`
   and `password_spray` alerts.
3. **Is the target account expected to hold this role?** A grant to an
   unexpected or dormant account is an immediate red flag.

## Response actions

- **Unplanned or unexplained:** Treat as a confirmed incident. Revoke
  the role immediately. Force password reset + MFA re-enrollment for
  BOTH the actor and target accounts. Begin full incident response —
  a rogue Super Admin grant is one of the most severe events this
  environment can produce.
- **Planned and verified:** Document the approval reference and close.

## Known false positives

- Legitimate onboarding of new IT staff.
- Scheduled admin role rotation as part of break-glass credential
  procedures.

## Tuning notes

Do not suppress or allowlist this rule under any circumstances — the
volume of legitimate Super Admin grants in a 5-clinic org should be
low enough (a handful per year) that manual review of every instance
is sustainable, and the cost of missing a real one is severe.
