#!/usr/bin/env python3
"""Generate a SOC-style incident report (REPORT.md) from the SSH log pipeline.

Reads ssh_attempts.csv (parser.py) for overall traffic stats, and
enriched_ips.csv (enrich.py) if present -- falling back to flagged_ips.csv
(detect.py) if enrichment was skipped -- for the flagged-IP findings table.
Detection thresholds are pulled directly from detect.py so the report can
never drift out of sync with the rules that actually produced the data.
"""

import csv
import sys
from datetime import datetime
from pathlib import Path

import detect

SSH_ATTEMPTS_CSV = Path("ssh_attempts.csv")
FLAGGED_CSV = Path("flagged_ips.csv")
ENRICHED_CSV = Path("enriched_ips.csv")
OUTPUT_MD = Path("REPORT.md")

TOP_N = 10

REASON_LABELS = {
    "burst_failed_logins": "Burst of failed logins",
    "many_usernames": "Username enumeration",
}


def load_csv_rows(path):
    with path.open("r", newline="") as f:
        return list(csv.DictReader(f))


def summarize_attempts(rows):
    total = len(rows)
    failed = sum(1 for r in rows if r["status"] == "failed")
    succeeded = total - failed
    unique_ips = {r["source_ip"] for r in rows}
    timestamps = [datetime.fromisoformat(r["timestamp"]) for r in rows]
    start = min(timestamps) if timestamps else None
    end = max(timestamps) if timestamps else None
    return {
        "total": total,
        "failed": failed,
        "succeeded": succeeded,
        "unique_ips": len(unique_ips),
        "start": start,
        "end": end,
    }


def format_reasons(raw):
    labels = [REASON_LABELS.get(r, r) for r in raw.split(";") if r]
    return ", ".join(labels) if labels else "-"


def build_findings_table(flagged_rows, has_enrichment):
    top = sorted(flagged_rows, key=lambda r: int(r["total_attempts"]), reverse=True)[:TOP_N]

    headers = ["#", "Source IP", "Total", "Failed", "Distinct Users", "Max Failed / Window", "Flagged For"]
    if has_enrichment:
        headers += ["Abuse Score", "Country"]

    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] * len(headers)) + "|",
    ]
    for i, row in enumerate(top, start=1):
        cells = [
            str(i),
            f"`{row['source_ip']}`",
            row["total_attempts"],
            row["failed_attempts"],
            row["distinct_usernames"],
            row["max_failed_in_window"],
            format_reasons(row["reasons"]),
        ]
        if has_enrichment:
            score = row.get("abuse_confidence_score", "")
            country = row.get("country", "")
            cells += [score if score else "n/a", country if country else "n/a"]
        lines.append("| " + " | ".join(cells) + " |")

    return "\n".join(lines), top


def main():
    if not SSH_ATTEMPTS_CSV.exists():
        sys.exit(f"{SSH_ATTEMPTS_CSV} not found. Run parser.py first.")

    if ENRICHED_CSV.exists():
        flagged_rows = load_csv_rows(ENRICHED_CSV)
        has_enrichment = True
        source_note = f"IP reputation enrichment via AbuseIPDB ({ENRICHED_CSV})"
    elif FLAGGED_CSV.exists():
        flagged_rows = load_csv_rows(FLAGGED_CSV)
        has_enrichment = False
        source_note = f"IP reputation enrichment was not performed ({FLAGGED_CSV} used as-is)"
    else:
        sys.exit(f"Neither {ENRICHED_CSV} nor {FLAGGED_CSV} found. Run detect.py first.")

    attempts = load_csv_rows(SSH_ATTEMPTS_CSV)
    stats = summarize_attempts(attempts)

    findings_table, top = build_findings_table(flagged_rows, has_enrichment)

    flagged_attempt_total = sum(int(r["total_attempts"]) for r in flagged_rows)
    flagged_share = (flagged_attempt_total / stats["total"] * 100) if stats["total"] else 0

    worst = top[0] if top else None

    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    window = (
        f"{stats['start'].isoformat()} to {stats['end'].isoformat()}"
        if stats["start"] and stats["end"]
        else "n/a"
    )

    executive_summary = (
        f"Analysis of `{SSH_ATTEMPTS_CSV}` covering {window} identified "
        f"{stats['total']} SSH authentication attempts from {stats['unique_ips']} "
        f"distinct source IPs, of which {stats['failed']} failed and "
        f"{stats['succeeded']} succeeded. Automated detection flagged "
        f"{len(flagged_rows)} source IP(s) as exhibiting brute-force or "
        f"credential-stuffing behavior, together accounting for "
        f"{flagged_attempt_total} attempts ({flagged_share:.1f}% of all traffic analyzed)."
    )
    if worst:
        executive_summary += (
            f" The highest-volume offender, `{worst['source_ip']}`, generated "
            f"{worst['total_attempts']} attempts against {worst['distinct_usernames']} "
            f"distinct usernames."
        )

    report = f"""# SSH Authentication Incident Report

**Generated:** {generated_at}
**Log source:** `{SSH_ATTEMPTS_CSV}`
**Analysis window:** {window}
**Enrichment:** {source_note}

## Executive Summary

{executive_summary}

## Traffic Summary

| Metric | Value |
|---|---|
| Total login attempts analyzed | {stats['total']} |
| Failed attempts | {stats['failed']} |
| Successful attempts | {stats['succeeded']} |
| Distinct source IPs | {stats['unique_ips']} |
| Source IPs flagged as suspicious | {len(flagged_rows)} |
| Attempts attributable to flagged IPs | {flagged_attempt_total} ({flagged_share:.1f}%) |

## Findings: Top {min(TOP_N, len(top))} Flagged Source IPs

{findings_table if top else "*No source IPs met the detection thresholds for this analysis window.*"}

## Detection Methodology

Source IPs are flagged when either of the following heuristics is met:

1. **Burst of failed logins** — more than **{detect.FAILED_ATTEMPTS_THRESHOLD}** failed
   authentication attempts occur within any **{detect.WINDOW_MINUTES}-minute** sliding
   window, indicating automated password-guessing rather than manual login attempts.
2. **Username enumeration** — the source IP attempts more than
   **{detect.USERNAME_THRESHOLD}** distinct usernames, indicating credential-stuffing
   or account-discovery behavior rather than a legitimate user mistyping their own
   username.

These thresholds are configurable in `detect.py` and were not altered for this report.
{"IP reputation scores and country of origin were retrieved from AbuseIPDB to corroborate the local detections." if has_enrichment else "IP reputation enrichment (AbuseIPDB) was not available for this run; findings below rely solely on local log analysis."}

## Recommended Actions

- Block or rate-limit the flagged source IPs above at the network perimeter (firewall / fail2ban).
- Confirm none of the flagged IPs correspond to successful authentications; if any do, treat the associated account as compromised and rotate its credentials immediately.
- Verify `PasswordAuthentication` is disabled and key-based auth is enforced for all accounts, including `root`, to neutralize this entire attack class going forward.
- Re-run this pipeline periodically (e.g., via a scheduled job) to catch new offenders as they appear.
"""

    OUTPUT_MD.write_text(report)
    print(f"Wrote report to {OUTPUT_MD}")


if __name__ == "__main__":
    main()
