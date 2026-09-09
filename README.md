# SSH Auth Log Analyzer & Brute-Force Detector

A four-stage Python pipeline that parses real SSH authentication logs, detects brute-force
and credential-stuffing patterns, enriches flagged IPs with threat intelligence, and generates
a SOC-style incident report — built and tested against a live, internet-facing hardened Linux server.

## Why I built this

I wanted hands-on reps at the core SOC analyst workflow: take raw logs, find the signal in
the noise, confirm it against real threat intel, and write it up the way an actual analyst
would. Rather than using a canned sample log, I ran this against my own hardened server's
live SSH traffic — meaning every flagged IP in this repo's example output is a real internet
scanner that actually tried to break in.

## Pipeline

| Stage | Script | What it does |
|---|---|---|
| 1 | `parser.py` | Reads `/var/log/auth.log` (falls back to `journalctl -u ssh`), extracts every login attempt into structured records (timestamp, source IP, username, success/fail) → `ssh_attempts.csv` |
| 2 | `detect.py` | Flags suspicious IPs using two rules: (1) >10 failed attempts in any 5-minute window, (2) >3 distinct usernames tried → `flagged_ips.csv` |
| 3 | `enrich.py` | Looks up each flagged IP against the AbuseIPDB API (free tier), adds abuse confidence score + country → `enriched_ips.csv` |
| 4 | `report.py` | Generates `REPORT.md` — a clean, SOC-style incident report with executive summary, findings table, and detection methodology |

## Detection logic

- **Burst rule:** more than 10 failed logins from one IP within any 5-minute sliding window — catches automated password guessing even if paced to avoid simple rate limits
- **Username enumeration rule:** an IP trying more than 3 distinct usernames — a stronger signal of credential stuffing than one IP retrying a single account
- Both thresholds are configurable variables at the top of `detect.py`

## Real results from this run

- **494** total SSH attempts analyzed
- **464** failed / **30** succeeded
- **2 of 11** unique source IPs flagged as suspicious
- Those 2 IPs accounted for **345 attempts (69.8%)** of all traffic
- Both flagged IPs confirmed via AbuseIPDB with an abuse confidence score of **100**, geolocated to the Netherlands

*(See `REPORT.md` in this repo for the full example report)*

## Setup

