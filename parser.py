#!/usr/bin/env python3
"""Extract SSH login attempts from auth logs into a CSV of structured records.

Reads /var/log/auth.log by default. If that file does not exist (e.g. on a
systemd-journal-only host), falls back to `journalctl -u ssh` (and `sshd`).

For each login attempt found, records: timestamp, source_ip, username, status
(success/failed). Output is written to ssh_attempts.csv in the current
directory.
"""

import csv
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

AUTH_LOG_PATH = Path("/var/log/auth.log")
OUTPUT_CSV = Path("ssh_attempts.csv")

# Process name is "sshd" on most systems, but OpenSSH's privilege-separation
# re-exec (9.8+) logs the per-connection process as "sshd-session" instead.
SSHD_PROC_RE = r"sshd(?:-session)?(?:\[\d+\])?"

# Traditional syslog prefix, e.g.:
#   "Jan 15 10:23:45 myhost sshd[1234]: Accepted password for bob from 1.2.3.4 port 51000 ssh2"
# Note: this format has no year, so we infer it (see parse_syslog_timestamp).
SYSLOG_LINE_RE = re.compile(
    rf"^(?P<ts>[A-Z][a-z]{{2}}\s+\d{{1,2}}\s+\d{{2}}:\d{{2}}:\d{{2}})\s+\S+\s+{SSHD_PROC_RE}:\s+(?P<msg>.*)$"
)

# journalctl --output=short-iso prefix, e.g.:
#   "2026-09-05T22:51:35+00:00 myhost sshd-session[1191]: Failed password for root from 1.2.3.4 port 51000 ssh2"
# (the UTC offset may or may not include a colon depending on journalctl version)
ISO_LINE_RE = re.compile(
    rf"^(?P<ts>\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}[+-]\d{{2}}:?\d{{2}})\s+\S+\s+{SSHD_PROC_RE}:\s+(?P<msg>.*)$"
)

ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\da-fA-F:.]+) port \d+"
)
FAILED_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\da-fA-F:.]+) port \d+"
)


def parse_syslog_timestamp(ts_str, reference=None):
    """Traditional syslog timestamps omit the year, so assume the current
    year unless that would place the entry in the future (handles logs that
    span a New Year's boundary)."""
    reference = reference or datetime.now()
    dt = datetime.strptime(f"{reference.year} {ts_str}", "%Y %b %d %H:%M:%S")
    if dt > reference:
        dt = dt.replace(year=reference.year - 1)
    return dt


def parse_iso_timestamp(ts_str):
    return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S%z")


def iter_log_lines():
    """Yield raw log lines from auth.log, or journalctl as a fallback."""
    if AUTH_LOG_PATH.exists():
        with AUTH_LOG_PATH.open("r", errors="replace") as f:
            for line in f:
                yield line.rstrip("\n")
        return

    print(f"{AUTH_LOG_PATH} not found; falling back to journalctl.", file=sys.stderr)
    for unit in ("ssh", "sshd"):
        try:
            result = subprocess.run(
                ["journalctl", "-u", unit, "-o", "short-iso", "--no-pager"],
                capture_output=True,
                text=True,
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        if result.stdout.strip():
            yield from result.stdout.splitlines()
            return

    print("No auth.log file found and journalctl returned no ssh/sshd data.", file=sys.stderr)


def parse_line(line):
    """Return a record dict for a login-attempt line, or None otherwise."""
    m = SYSLOG_LINE_RE.match(line)
    if m:
        ts = parse_syslog_timestamp(m.group("ts"))
        msg = m.group("msg")
    else:
        m = ISO_LINE_RE.match(line)
        if not m:
            return None
        ts = parse_iso_timestamp(m.group("ts"))
        msg = m.group("msg")

    accepted = ACCEPTED_RE.match(msg)
    if accepted:
        return {
            "timestamp": ts.isoformat(),
            "source_ip": accepted.group("ip"),
            "username": accepted.group("user"),
            "status": "success",
        }

    failed = FAILED_RE.match(msg)
    if failed:
        return {
            "timestamp": ts.isoformat(),
            "source_ip": failed.group("ip"),
            "username": failed.group("user"),
            "status": "failed",
        }

    return None


def main():
    records = [r for line in iter_log_lines() if (r := parse_line(line))]

    with OUTPUT_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["timestamp", "source_ip", "username", "status"],
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(records)

    print(f"Wrote {len(records)} SSH login attempts to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
