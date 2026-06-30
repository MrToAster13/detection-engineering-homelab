# Detection rule — plain-English breakdown

**Rule:** SSH Bruteforce Attempt · **Type:** Threshold · **Language:** KQL (kuery)

## The query

```
system.auth.ssh.event : *
  and agent.name : "Linux-Ubuntu24-ssh"
  and system.auth.ssh.event : "Failed"
  and user.name : "root"
```

Read left to right:

| Clause | Meaning |
|---|---|
| `system.auth.ssh.event : *` | the event is an SSH auth event (field exists) |
| `agent.name : "Linux-Ubuntu24-ssh"` | only events from the target host |
| `system.auth.ssh.event : "Failed"` | only **failed** authentications |
| `user.name : "root"` | only attempts against the `root` account |

## The threshold

```
group by: user.name, source.ip
fire when count >= 5
```

A match means: **the same source IP failed to log in as `root` 5 or more times.**
One alert is raised per `(user.name, source.ip)` group, so 82 attacking IPs
produce on the order of 82 alerts — not 47,212. That grouping is the whole point:
it turns a flood of individual failures into one actionable signal per attacker.

## Schedule

- Runs every **1 minute**, with a **6-minute** look-back window, so short bursts
  between runs are still caught.

## Known gap (be ready to explain this in an interview)

KQL matching on the `user.name` keyword field is **case-sensitive**, and the
rule pins `user.name : "root"`. It is also scoped to a single account. It will
**not** fire on attempts against `admin`, `user`, or other sprayed usernames,
nor on a different-cased variant of the account. Scoped to root deliberately as
the highest-value target; a production version would broaden the match or pivot
to "failed-attempt volume per source IP regardless of username."
