#!/usr/bin/env python3
"""Enrich flagged_ips.csv with AbuseIPDB abuse-confidence score and country.

Requires a (free tier is fine) AbuseIPDB API key in the ABUSEIPDB_API_KEY
environment variable -- get one at https://www.abuseipdb.com/account/api.
The key is never hardcoded here; export it before running, e.g.:

    export ABUSEIPDB_API_KEY=your-key-here
    python3 enrich.py

Reads flagged_ips.csv (as produced by detect.py), looks each source_ip up
against AbuseIPDB's /check endpoint, and writes every original column plus
abuse_confidence_score and country to enriched_ips.csv.
"""

import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

INPUT_CSV = Path("flagged_ips.csv")
OUTPUT_CSV = Path("enriched_ips.csv")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90           # how far back AbuseIPDB should look for reports
REQUEST_TIMEOUT = 10        # seconds, per HTTP request
MAX_RETRIES = 5             # retries for a single IP on 429 / transient errors
BASE_BACKOFF_SECONDS = 5    # backoff used when the API gives no Retry-After hint
REQUEST_DELAY_SECONDS = 1   # pause between successful lookups to stay under rate limits


def get_api_key():
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        sys.exit(
            "ABUSEIPDB_API_KEY environment variable is not set.\n"
            "Get a free API key at https://www.abuseipdb.com/account/api "
            "and export it, e.g.:\n"
            "  export ABUSEIPDB_API_KEY=your-key-here"
        )
    return api_key


def lookup_ip(ip, api_key):
    """Query AbuseIPDB for one IP. Returns (score, country_code); either may
    be None if the lookup ultimately fails after retries."""
    url = f"{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays={MAX_AGE_DAYS}"

    for attempt in range(1, MAX_RETRIES + 1):
        request = urllib.request.Request(
            url,
            headers={"Key": api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as resp:
                payload = json.load(resp)
                data = payload.get("data", {})
                return data.get("abuseConfidenceScore"), data.get("countryCode")
        except urllib.error.HTTPError as e:
            if e.code == 429:
                retry_after = e.headers.get("Retry-After")
                wait = float(retry_after) if retry_after else BASE_BACKOFF_SECONDS * attempt
                print(
                    f"  [{ip}] rate limited (429), waiting {wait:.0f}s "
                    f"before retry {attempt}/{MAX_RETRIES}...",
                    file=sys.stderr,
                )
                time.sleep(wait)
                continue
            if e.code in (401, 403):
                sys.exit(f"AbuseIPDB rejected the API key ({e.code}). Check ABUSEIPDB_API_KEY.")
            print(f"  [{ip}] HTTP error {e.code}, giving up on this IP.", file=sys.stderr)
            return None, None
        except (urllib.error.URLError, TimeoutError) as e:
            wait = BASE_BACKOFF_SECONDS * attempt
            print(
                f"  [{ip}] network error ({e}), retrying in {wait:.0f}s "
                f"({attempt}/{MAX_RETRIES})...",
                file=sys.stderr,
            )
            time.sleep(wait)

    print(f"  [{ip}] giving up after {MAX_RETRIES} attempts.", file=sys.stderr)
    return None, None


def main():
    if not INPUT_CSV.exists():
        sys.exit(f"{INPUT_CSV} not found. Run detect.py first.")

    api_key = get_api_key()

    with INPUT_CSV.open("r", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        input_fieldnames = reader.fieldnames or []

    fieldnames = input_fieldnames + ["abuse_confidence_score", "country"]

    for i, row in enumerate(rows):
        ip = row["source_ip"]
        print(f"Looking up {ip} ({i + 1}/{len(rows)})...")
        score, country = lookup_ip(ip, api_key)
        row["abuse_confidence_score"] = score if score is not None else ""
        row["country"] = country if country is not None else ""
        if i < len(rows) - 1:
            time.sleep(REQUEST_DELAY_SECONDS)

    with OUTPUT_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} enriched rows to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
