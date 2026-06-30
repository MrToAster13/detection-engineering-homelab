# SSH Brute-Force — Analysis Summary

Generated from `auth_failed.txt` (real `/var/log/auth.log` data, Linux-Ubuntu24-ssh).

## Headline numbers

- **Total failed password attempts:** 47,212
- **Unique attacking source IPs:** 82
- **Attack window:** Jun 28 00:00:06 → Jun 30 00:00:21 (~48 hours)
- **Successful unauthorized logins:** 0 (lone `Accepted` event traced to administrator — see Triage)

## Top 10 attacking IPs

| Source IP | Failed attempts |
|---|---|
| 87.106.13.39 | 29,867 |
| 118.117.167.156 | 8,982 |
| 117.50.89.245 | 995 |
| 45.156.87.216 | 761 |
| 45.153.34.161 | 761 |
| 91.92.42.227 | 761 |
| 91.92.40.151 | 761 |
| 176.65.139.247 | 761 |
| 60.165.119.59 | 390 |
| 91.92.40.46 | 246 |

## Top 10 targeted usernames

| Username | Attempts |
|---|---|
| `root` | 42,545 |
| `admin` | 486 |
| `user` | 328 |
| `ubuntu` | 240 |
| `debian` | 128 |
| `test` | 117 |
| `deploy` | 105 |
| `ftpuser` | 67 |
| `oracle` | 64 |
| `pi` | 60 |

> `root` is the overwhelming majority — the basis for the detection's `user.name : "root"` scope. See README for the stated limitation.
