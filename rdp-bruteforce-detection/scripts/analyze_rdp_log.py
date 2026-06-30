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
    first = last = None
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
                first = ts if first is None or ts < first else first
                last = ts if last is None or ts > last else last
    return total, ips, users, countries, ip_country, first, last


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

    total, ips, users, countries, ip_country, first, last = analyze(args.csv_file)
    if not total:
        sys.exit("no rows parsed - is this the Kibana CSV export?")

    span = f"{first:%b %d %H:%M} -> {last:%b %d %H:%M}" if first and last else "unknown"
    print(f"Total failed attempts : {total:,}")
    print(f"Unique source IPs     : {len(ips)}")
    print(f"Attack window         : {span}")
    print("\nTop 10 attacking IPs:")
    for ip, c in ips.most_common(10):
        print(f"  {ip:<18} {c:>6,}  {ip_country.get(ip, '')}")
    print("\nTargeted usernames:")
    for u, c in users.most_common(10):
        print(f"  {u:<18} {c:>6,}")
    print("\nTop 10 source countries:")
    for country, c in countries.most_common(10):
        print(f"  {country:<22} {c:>6,}")

    if args.iocs:
        write_iocs(args.iocs, ips, ip_country)
        print(f"\nWrote {len(ips)} IOCs -> {args.iocs}")


if __name__ == "__main__":
    main()
