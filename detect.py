#!/usr/bin/env python3
"""Flag suspicious SSH source IPs from ssh_attempts.csv using two heuristics:

1. More than FAILED_ATTEMPTS_THRESHOLD failed logins within any
   WINDOW_MINUTES-wide window (a burst of guesses).
2. More than USERNAME_THRESHOLD distinct usernames tried (username
   enumeration / credential stuffing).

Reads ssh_attempts.csv (as produced by parser.py) and writes a ranked list
of flagged IPs to flagged_ips.csv.
"""

import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# --- Thresholds: tune these to adjust sensitivity ---
FAILED_ATTEMPTS_THRESHOLD = 10  # flag if more than this many failed attempts land in one window
WINDOW_MINUTES = 5              # width of the sliding window used for the burst rule
USERNAME_THRESHOLD = 3          # flag if an IP tries more than this many distinct usernames

INPUT_CSV = Path("ssh_attempts.csv")
OUTPUT_CSV = Path("flagged_ips.csv")


def load_attempts(path):
    with path.open("r", newline="") as f:
        return [
            {
                "timestamp": datetime.fromisoformat(row["timestamp"]),
                "source_ip": row["source_ip"],
                "username": row["username"],
                "status": row["status"],
            }
            for row in csv.DictReader(f)
        ]


def max_failed_in_window(failed_timestamps, window_minutes):
    """Largest number of failed attempts that fall within any single
    window_minutes-wide span, via a sliding window over sorted timestamps."""
    times = sorted(failed_timestamps)
    window = timedelta(minutes=window_minutes)
    left = 0
    best = 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def main():
    if not INPUT_CSV.exists():
        sys.exit(f"{INPUT_CSV} not found. Run parser.py first.")

    attempts = load_attempts(INPUT_CSV)

    by_ip = defaultdict(list)
    for attempt in attempts:
        by_ip[attempt["source_ip"]].append(attempt)

    flagged = []
    for ip, records in by_ip.items():
        failed_times = [r["timestamp"] for r in records if r["status"] == "failed"]
        usernames = {r["username"] for r in records}
        burst = max_failed_in_window(failed_times, WINDOW_MINUTES)

        reasons = []
        if burst > FAILED_ATTEMPTS_THRESHOLD:
            reasons.append("burst_failed_logins")
        if len(usernames) > USERNAME_THRESHOLD:
            reasons.append("many_usernames")

        if reasons:
            flagged.append({
                "source_ip": ip,
                "total_attempts": len(records),
                "failed_attempts": len(failed_times),
                "distinct_usernames": len(usernames),
                "max_failed_in_window": burst,
                "reasons": ";".join(reasons),
            })

    flagged.sort(key=lambda r: r["total_attempts"], reverse=True)

    with OUTPUT_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "source_ip",
                "total_attempts",
                "failed_attempts",
                "distinct_usernames",
                "max_failed_in_window",
                "reasons",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(flagged)

    print(f"Flagged {len(flagged)} of {len(by_ip)} source IPs; wrote results to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
