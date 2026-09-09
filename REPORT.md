# SSH Authentication Incident Report

**Generated:** 2026-09-08T01:22:09+00:00
**Log source:** `ssh_attempts.csv`
**Analysis window:** 2026-09-05T23:16:26+00:00 to 2026-09-08T00:13:36+00:00
**Enrichment:** IP reputation enrichment via AbuseIPDB (enriched_ips.csv)

## Executive Summary

Analysis of `ssh_attempts.csv` covering 2026-09-05T23:16:26+00:00 to 2026-09-08T00:13:36+00:00 identified 494 SSH authentication attempts from 11 distinct source IPs, of which 464 failed and 30 succeeded. Automated detection flagged 2 source IP(s) as exhibiting brute-force or credential-stuffing behavior, together accounting for 345 attempts (69.8% of all traffic analyzed). The highest-volume offender, `91.92.40.29`, generated 189 attempts against 100 distinct usernames.

## Traffic Summary

| Metric | Value |
|---|---|
| Total login attempts analyzed | 494 |
| Failed attempts | 464 |
| Successful attempts | 30 |
| Distinct source IPs | 11 |
| Source IPs flagged as suspicious | 2 |
| Attempts attributable to flagged IPs | 345 (69.8%) |

## Findings: Top 2 Flagged Source IPs

| # | Source IP | Total | Failed | Distinct Users | Max Failed / Window | Flagged For | Abuse Score | Country |
|---|---|---|---|---|---|---|---|---|
| 1 | `91.92.40.29` | 189 | 189 | 100 | 24 | Burst of failed logins, Username enumeration | 100 | NL |
| 2 | `195.178.110.218` | 156 | 156 | 105 | 4 | Username enumeration | 100 | NL |

## Detection Methodology

Source IPs are flagged when either of the following heuristics is met:

1. **Burst of failed logins** — more than **10** failed
   authentication attempts occur within any **5-minute** sliding
   window, indicating automated password-guessing rather than manual login attempts.
2. **Username enumeration** — the source IP attempts more than
   **3** distinct usernames, indicating credential-stuffing
   or account-discovery behavior rather than a legitimate user mistyping their own
   username.

These thresholds are configurable in `detect.py` and were not altered for this report.
IP reputation scores and country of origin were retrieved from AbuseIPDB to corroborate the local detections.

## Recommended Actions

- Block or rate-limit the flagged source IPs above at the network perimeter (firewall / fail2ban).
- Confirm none of the flagged IPs correspond to successful authentications; if any do, treat the associated account as compromised and rotate its credentials immediately.
- Verify `PasswordAuthentication` is disabled and key-based auth is enforced for all accounts, including `root`, to neutralize this entire attack class going forward.
- Re-run this pipeline periodically (e.g., via a scheduled job) to catch new offenders as they appear.
