# Runbook: Google Workspace Impossible Travel Login

**Rule:** `rules/identity/impossible_travel_workspace_login.yml`
**Severity:** High
**ATT&CK:** T1078 — Valid Accounts

## Why this rule needs an enrichment script, not just a Sigma query

Sigma's native detection language matches fields on a single event. It
cannot natively express "compare this login's location and time to the
user's previous login" — that's a stateful, cross-event correlation.
The `.yml` file documents the intent, required fields, and false
positive profile; the actual logic runs as a small enrichment script
(or a scheduled Wazuh/Elastic query) alongside it. This split is
intentional and documented here rather than hidden — a reviewer should
be able to tell at a glance which rules are simple field matches and
which require additional logic.

## Enrichment logic (reference implementation)

```
for each successful Workspace login event:
    user = event.actor.email
    new_location = geoip_lookup(event.source.ip)
    new_time = event.time

    last = get_last_successful_login(user)   # from a small state store
                                              # (Elasticsearch index or Redis)
    if last exists:
        distance_km = haversine(last.location, new_location)
        hours_elapsed = (new_time - last.time).hours
        implied_speed_kmh = distance_km / max(hours_elapsed, 0.01)

        if implied_speed_kmh > 1100:   # ~700 mph, generous commercial flight speed
            fire_alert(rule="impossible_travel_workspace_login", user=user,
                       from_location=last.location, to_location=new_location,
                       implied_speed_kmh=implied_speed_kmh)

    update_last_successful_login(user, new_location, new_time)
```

## Triage steps

1. **Check both locations.** Is either one a known corporate VPN
   egress point? VPN use is the single most common false-positive
   cause for this rule.
2. **Ask the user** if travel or VPN use explains the pattern — fastest
   path to resolution.
3. **Check for correlated indicators** — a password spray or new OAuth
   app authorization around the same time significantly raises
   suspicion of genuine compromise.

## Response actions

- **No innocent explanation found:** Force password reset + MFA
  re-enrollment. Review recent account activity for forwarding rules,
  new OAuth grants, and admin role changes.
- **VPN or travel confirmed:** Document and close; consider adding the
  VPN's known egress IPs to a geo-lookup exception list to reduce
  future noise.

## Known false positives

- Legitimate corporate VPN or proxy use that changes apparent
  geo-location.
- Traveling users with cloud-synced sessions across regions.
- Mobile carrier IP reassignment misreporting geo-location — carrier
  NAT can occasionally jump between coarse regional geo-IP blocks.

## Tuning notes

The 1100 km/h threshold is deliberately generous (above real commercial
flight speed) to reduce false positives from geo-IP database
imprecision. Lowering it increases sensitivity but will increase VPN-
driven noise — tune only after establishing a baseline of the
organization's actual VPN egress patterns.
