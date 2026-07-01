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
import sys
from collections import Counter
from datetime import datetime

TS_FORMAT = "%b %d, %Y @ %H:%M:%S.%f"


def parse_ts(value):
    try:
        return datetime.strptime(value.strip(), TS_FORMAT)
    except (ValueError, AttributeError):
        return None


def analyze(path):
    ips, users, countries = Counter(), Counter(), Counter()
    ip_country = {}
    total = 0
    timestamps = []
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
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
            ts = parse_ts(row.get("@timestamp", ""))
            if ts:
                timestamps.append(ts)
    return {
        "total": total,
        "ips": ips,
        "users": users,
        "countries": countries,
        "ip_country": ip_country,
        "first": min(timestamps, default=None),
        "last": max(timestamps, default=None),
        "ts_parsed": len(timestamps),
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

    # Guard: --iocs must not clobber the evidence file we're analyzing.
    if args.iocs and os.path.abspath(args.iocs) == os.path.abspath(args.csv_file):
        sys.exit(f"refusing to overwrite the input file with IOCs: {args.iocs}")

    r = analyze(args.csv_file)
    if not r["total"]:
        sys.exit("no rows parsed - is this the Kibana CSV export?")

    first, last = r["first"], r["last"]
    span = f"{first:%b %d %H:%M} -> {last:%b %d %H:%M}" if first and last else "unknown"
    print(f"Total failed attempts : {r['total']:,}")
    print(f"Unique source IPs     : {len(r['ips'])}")
    print(f"Attack window         : {span}")
    if r["ts_parsed"] < r["total"]:
        # Surface format drift instead of silently degrading the window to "unknown".
        print(f"  note: only {r['ts_parsed']:,}/{r['total']:,} timestamps parsed - "
              f"TS_FORMAT {TS_FORMAT!r} may not match this export")

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
