# Detection rule — plain-English breakdown

> **Draft.** Accurate to the exported rule; prose pending my own edit.

**Rule:** RDP Bruteforce Attempt · **Type:** Threshold · **Language:** KQL (kuery)

## The query

```
event.code : 4625
  and agent.name : "Win10-2022-SOC"
  and user.name : "Administrator"
```

Read left to right:

| Clause | Meaning |
|---|---|
| `event.code : 4625` | Windows Security **failed-logon** event (4625 = an account failed to log on) |
| `agent.name : "Win10-2022-SOC"` | only events from the target Windows host |
| `user.name : "Administrator"` | only attempts against the `Administrator` account |

## The threshold

```
group by: user.name, source.ip
fire when count >= 5
```

A match means the **same source IP failed to log on as `Administrator` 5 or more
times**. One alert is raised per `(user.name, source.ip)` group, so 176 attacking
IPs produce on the order of 176 alerts — not 4,558. The grouping turns a flood of
individual failures into one actionable signal per attacker.

## Schedule

- Runs every **1 minute**, with a **6-minute** look-back window.
- Risk score / severity: **47 / Medium**.

## Known gap (be ready to explain this in an interview)

KQL keyword matching is **case-sensitive** and this rule pins
`user.name : "Administrator"`. The captured data contains the account in two
casings (`Administrator` and `ADMINISTRATOR`); as written, the rule fires on only
one of them and **misses ~1,987 of the 4,558 attempts**. It is also scoped to a
single account. A production version would normalize case (or match both casings)
and broaden beyond a single account — or pivot to "failed-logon volume per source
IP regardless of username."
