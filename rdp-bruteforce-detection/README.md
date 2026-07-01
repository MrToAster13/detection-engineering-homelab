# RDP Brute-Force Detection & Triage — Elastic SIEM

> **Status: draft / work-in-progress.** The detection rule and the evidence are
> real and complete; the written analysis is a first pass generated from the
> captured data and is pending my own rewrite. Structure mirrors the
> [SSH brute-force project](../ssh-bruteforce-detection/README.md).

Detecting and triaging an RDP brute-force campaign against an internet-facing
Windows host (`Win10-2022-SOC`), using the same self-hosted Elastic Stack SOC lab
as the SSH project.

## TL;DR

- Windows host shipping Security event logs into Elastic via Fleet-managed Elastic Agent.
- Authored a **Threshold detection rule** that fires on ≥5 failed `Administrator`
  logons (event 4625) per source IP.
- Attack: **4,558** failed attempts, **176** unique IPs, over ~44 hours
  (Jun 13 → Jun 15). Top source `185.118.79.30` (Latvia, 909 attempts).
- **No** successful unauthorized logon occurred.
- Documented a real rule gap: the account name appears in two casings and the
  case-sensitive match misses ~1,987 attempts (see below).

## The detection rule

Exported rule: [`detection/rdp_bruteforce_rule.ndjson`](detection/rdp_bruteforce_rule.ndjson) ·
Plain-English breakdown: [`detection/rule-explained.md`](detection/rule-explained.md)

| Field | Value |
|---|---|
| Name | RDP Bruteforce Attempt |
| Type | Threshold |
| Query (KQL) | `event.code : 4625 and agent.name : "Win10-2022-SOC" and user.name : "Administrator"` |
| Threshold | group by `user.name`, `source.ip` — fire at **≥ 5** |
| Runs every | 1 min (6-min look-back) |
| Risk score / severity | 47 / Medium |

## What the data showed

Full numbers: [`evidence/analysis_summary.md`](evidence/analysis_summary.md) ·
Raw evidence: [`evidence/rdp_failed_activity.csv`](evidence/rdp_failed_activity.csv) ·
IOC list: [`evidence/iocs.csv`](evidence/iocs.csv)

- **4,558** failed `Administrator` logon events, **Jun 13 20:11 → Jun 15 17:34**.
- **176** unique source IPs — a distributed campaign across many countries
  (Latvia, Singapore, Vietnam, China, Hong Kong, …).
- Single targeted account (`Administrator`), unlike the SSH username spray.

## Honest limitations

- **Case-sensitive single-account match.** The rule matches `Administrator` only;
  the data also contains `ADMINISTRATOR` (~1,987 events) that this rule misses.
  This is the first fix for a v2 rule.
- **Detection only.** No automated response (no account-lockout/SOAR) wired up.
- **Analysis prose is draft.** Numbers are real and reproducible; the narrative
  is pending my own edit.

## Reproduce the analysis

```bash
python3 scripts/analyze_rdp_log.py evidence/rdp_failed_activity.csv
```

## Repo contents

```
detection/
  rdp_bruteforce_rule.ndjson   # the real exported Elastic rule (SOC IP redacted)
  rule-explained.md            # plain-English breakdown of the logic
evidence/
  rdp_failed_activity.csv      # real failed-logon events (Kibana export)
  analysis_summary.md          # headline stats, top IPs, top countries
  iocs.csv                     # attacking source IPs as IOCs (generated)
scripts/
  analyze_rdp_log.py           # regenerates the summary + IOCs from the CSV
blog/
  blog-post-draft.md           # longer-form narrative (draft — pending edit)
```
