# RDP Brute-Force — Analysis Summary

> **Draft.** Numbers below are generated from real captured data
> (`rdp_failed_activity.csv`, a Kibana export of Windows event 4625 from
> `Win10-2022-SOC`). Prose is first-pass and pending my own edit.

Generated with [`scripts/analyze_rdp_log.py`](../scripts/analyze_rdp_log.py).

## Headline numbers

- **Total failed RDP logon attempts:** 4,558
- **Unique attacking source IPs:** 176
- **Attack window:** Jun 13 20:11 → Jun 15 17:34 (~44 hours)
- **Targeted account:** `Administrator` (the only account sprayed)
- **Successful unauthorized logins:** 0

## Top 10 attacking IPs

| Source IP | Failed attempts | Country |
|---|---|---|
| 185.118.79.30 | 909 | Latvia |
| 139.59.104.66 | 604 | Singapore |
| 94.26.68.54 | 179 | Bulgaria |
| 109.205.211.117 | 146 | Azerbaijan |
| 152.53.143.216 | 104 | Austria |
| 98.101.34.22 | 94 | United States |
| 152.53.140.132 | 93 | Austria |
| 152.53.141.28 | 83 | Austria |
| 31.58.236.3 | 74 | Türkiye |
| 112.213.120.167 | 60 | Hong Kong |

## Top 10 source countries

| Country | Attempts |
|---|---|
| Latvia | 909 |
| Singapore | 693 |
| Vietnam | 357 |
| China | 339 |
| Hong Kong | 286 |
| Austria | 280 |
| United States | 276 |
| India | 237 |
| Bulgaria | 214 |
| Azerbaijan | 146 |

## A note on case (real finding)

The export shows the target account in two casings — `Administrator` (2,571) and
`ADMINISTRATOR` (1,987). The detection rule pins `user.name : "Administrator"`,
and KQL keyword matching is **case-sensitive**, so as written the rule would miss
the ~1,987 differently-cased events. This is the RDP analogue of the SSH rule's
single-account/case gap and is the first thing to fix in a v2 rule. See
[`../detection/rule-explained.md`](../detection/rule-explained.md).
