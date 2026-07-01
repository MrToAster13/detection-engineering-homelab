#!/usr/bin/env python3
"""
analyze_rdp_log.py - summarize RDP brute-force activity from a Kibana CSV export.

Usage:
    python3 analyze_rdp_log.py evidence/rdp_failed_activity.csv
    python3 analyze_rdp_log.py evidence/rdp_failed_activity.csv --iocs evidence/iocs.csv

Input is the Kibana "Discover" export of failed RDP logon events with columns:
    @timestamp, agent.name, user.name, source.ip, source.geo.country_name

Reports total attempts, unique source IPs, the attack window, the top attacking
IPs, the most-targeted usernames, and the top source countries. Run it against
the real export in evidence/ to reproduce the numbers in the README.
"""
import argparse
import csv
import os
import re
import sys
from collections import Counter
from datetime import datetime

# Kibana Discover timestamps look like "Jun 15, 2026 @ 17:34:47.381".
# Parse them explicitly (not via strptime's %b) so month matching is
# locale-independent, and make the fractional-seconds part optional.
_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
_TS_RE = re.compile(
    r"^([A-Za-z]{3}) (\d{1,2}), (\d{4}) @ (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$")


def parse_ts(value):
    """Parse a Kibana timestamp into a datetime, or None if it doesn't match."""
    m = _TS_RE.match((value or "").strip())
    if not m:
        return None
    mon, day, year, hh, mm, ss, frac = m.groups()
    month = _MONTHS.get(mon)
    if month is None:
        return None
    micro = int(frac.ljust(6, "0")[:6]) if frac else 0
    return datetime(int(year), month, int(day), int(hh), int(mm), int(ss), micro)


def _resolve(path):
    """Normalized real path for same-file comparison (handles symlinks + case)."""
    return os.path.normcase(os.path.realpath(path))


def analyze(path):
    ips, users, countries = Counter(), Counter(), Counter()
    ip_country = {}
    total = 0
    ts_unparsed = 0  # non-empty @timestamp values that did not match the format
    timestamps = []
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            total += 1
            ip = (row.get("source.ip") or "").strip()
            user = (row.get("user.name") or "").strip()
            country = (row.get("source.geo.country_name") or "").strip()
            if ip:
                ips[ip] += 1
                if country:
                    ip_country.setdefault(ip, country)
            if user:
                users[user] += 1
            if country:
                countries[country] += 1
            ts_raw = (row.get("@timestamp") or "").strip()
            if ts_raw:
                ts = parse_ts(ts_raw)
                if ts:
                    timestamps.append(ts)
                else:
                    ts_unparsed += 1
    return {
        "total": total,
        "ips": ips,
        "users": users,
        "countries": countries,
        "ip_country": ip_country,
        "first": min(timestamps, default=None),
        "last": max(timestamps, default=None),
        "ts_unparsed": ts_unparsed,
    }


def write_iocs(path, ips, ip_country):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["source_ip", "failed_attempts", "country"])
        for ip, count in ips.most_common():
            writer.writerow([ip, count, ip_country.get(ip, "")])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_file")
    ap.add_argument("--iocs", help="write unique attacking IPs to this CSV path")
    args = ap.parse_args()

    # Guard: --iocs must not clobber the evidence file we're analyzing. Compare
    # resolved paths so a symlink or a differently-cased spelling (Windows) of
    # the input can't slip past the check.
    if args.iocs and _resolve(args.iocs) == _resolve(args.csv_file):
        sys.exit(f"refusing to overwrite the input file with IOCs: {args.iocs}")

    r = analyze(args.csv_file)
    if not r["total"]:
        sys.exit("no rows parsed - is this the Kibana CSV export?")

    first, last = r["first"], r["last"]
    span = f"{first:%b %d %H:%M} -> {last:%b %d %H:%M}" if first and last else "unknown"
    print(f"Total failed attempts : {r['total']:,}")
    print(f"Unique source IPs     : {len(r['ips'])}")
    print(f"Attack window         : {span}")
    if r["ts_unparsed"]:
        # Only counts non-empty timestamps that failed to parse, so this flags
        # genuine format drift rather than merely-blank cells.
        print(f"  note: {r['ts_unparsed']:,} of {r['total']:,} rows had an "
              f"unrecognized @timestamp and were skipped")

    print("\nTop 10 attacking IPs:")
    for ip, c in r["ips"].most_common(10):
        print(f"  {ip:<18} {c:>6,}  {r['ip_country'].get(ip, '')}")
    print("\nTargeted usernames:")
    for u, c in r["users"].most_common(10):
        print(f"  {u:<18} {c:>6,}")
    print("\nTop 10 source countries:")
    for country, c in r["countries"].most_common(10):
        print(f"  {country:<22} {c:>6,}")

    if args.iocs:
        write_iocs(args.iocs, r["ips"], r["ip_country"])
        print(f"\nWrote {len(r['ips'])} IOCs -> {args.iocs}")


if __name__ == "__main__":
    main()
