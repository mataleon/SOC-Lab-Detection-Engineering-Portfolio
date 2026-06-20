# IR-002 — Brute Force Attack Against Active Directory

| Field | Value |
|---|---|
| Incident ID | IR-002 |
| Date | June 13, 2026 |
| Severity | High |
| Status | Closed |
| Analyst | Leon Kiyonga Ddungu |
| MITRE Tactic | Credential Access |
| MITRE Technique | T1110 — Brute Force |

---

## Executive Summary

At approximately 04:01 AM a brute force credential
attack was detected against the SOC.lab Active
Directory domain controller. The attack originated
from internal host 192.168.254.131 targeting domain
user account jsmith using the netexec tool over SMB
port 445. Nine failed authentication attempts were
recorded before the account lockout policy triggered
after 5 failures. No successful logons occurred
before containment. The attack was detected via
Windows Event ID 4625 threshold breach in Microsoft
Sentinel within 60 seconds of the first attempt.

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 04:01:57 | netexec brute force initiated from 192.168.254.131 |
| 04:01:58 | First Event ID 4625 recorded against jsmith |
| 04:01:59 | Account lockout triggered — 5 failed attempts |
| 04:02:00 | Sentinel analytics rule fired — High severity |
| 04:02:05 | Analyst investigation initiated |
| 04:07:19 | 9 Event ID 4625 events confirmed in Sentinel |
| 04:10:00 | Source host identified and isolated |
| 04:15:00 | Incident confirmed — brute force attack |
| 04:30:00 | Incident report drafted |

---

## Technical Details
