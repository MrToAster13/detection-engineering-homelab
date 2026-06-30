#!/usr/bin/env python3
"""
analyze_auth_log.py — summarize SSH brute-force activity from a captured auth.log.

Usage:
    python3 analyze_auth_log.py evidence/auth_failed.txt

Parses 'Failed password' lines, then reports total attempts, unique source IPs,
the top attacking IPs, and the most-targeted usernames. Run against the real
auth.log capture in evidence/ to reproduce the numbers in the README.
"""
import re
import sys
from collections import Counter

IP_RE = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")
USER_RE = re.compile(r"for (?:invalid user )?([A-Za-z0-9_.-]+) from")


def analyze(path):
    ips, users = Counter(), Counter()
    total = 0
    first = last = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if "Failed password" not in line:
                continue
            total += 1
            if first is None:
                first = line[:15]
            last = line[:15]
            if (m := IP_RE.search(line)):
                ips[m.group(1)] += 1
            if (u := USER_RE.search(line)):
                users[u.group(1)] += 1
    return total, ips, users, first, last


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <auth_log_file>")
    total, ips, users, first, last = analyze(sys.argv[1])
    print(f"Total failed attempts : {total:,}")
    print(f"Unique source IPs     : {len(ips)}")
    print(f"Window                : {first} -> {last}")
    print("\nTop 10 attacking IPs:")
    for ip, c in ips.most_common(10):
        print(f"  {ip:<18} {c:,}")
    print("\nTop 10 targeted usernames:")
    for u, c in users.most_common(10):
        print(f"  {u:<18} {c:,}")


if __name__ == "__main__":
    main()
