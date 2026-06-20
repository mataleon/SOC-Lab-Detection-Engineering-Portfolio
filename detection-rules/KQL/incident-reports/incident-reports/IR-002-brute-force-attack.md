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
---

## Detection Method

**Platform:** Microsoft Sentinel
**Rule:** Brute Force Attack — Multiple Failed Logons
**Trigger:** 5+ Event ID 4625 from same source IP
in 5-minute window
**Severity:** High
**Detection Latency:** Less than 60 seconds

**KQL Query Used:**

```kql
Event
| where EventID == 4625
| where TimeGenerated > ago(5m)
| extend SourceIP = extract(
    @"Source Network Address:\s+(\S+)",
    1, RenderedDescription)
| summarize FailedAttempts=count()
    by SourceIP, Computer
| where FailedAttempts >= 5
```

---

## IOCs

| Type | Value | Source |
|---|---|---|
| Source IP | 192.168.254.131 | Event ID 4625 |
| Target Account | SOC.lab\jsmith | Event ID 4625 |
| Auth Package | NTLM | Event ID 4625 |
| Failure Code | 0xC000006D | Event ID 4625 |
| Tool | netexec | Process analysis |
| Port | 445 (SMB) | Network log |

---

## Containment Actions

---

## Root Cause

Unauthorized Kali Linux machine operating on
internal network segment VMnet8 (192.168.254.0/24)
with unrestricted SMB access to domain controller
port 445. No internal network segmentation between
attack VM and domain controller.

---

## Wazuh Finding — Log Pipeline Issue

During the attack the Wazuh agent buffer was flooded:

**Impact:** Wazuh dropped events during peak attack
volume. Azure Monitor Agent captured events
independently and delivered them to Sentinel.

**Finding:** AMA should be treated as the authoritative
log pipeline during high-volume security events.
Wazuh provides complementary behavioral detection
but can be overwhelmed by flood attacks.

---

## Detection Improvements

| # | Improvement | Priority |
|---|---|---|
| 1 | Increase Wazuh agent buffer size | High |
| 2 | Implement internal network segmentation — isolate Kali from DC | High |
| 3 | Restrict SMB port 445 to authorized hosts only | Medium |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Brute Force | T1110 | Credential Access |
| Valid Accounts | T1078 | Initial Access |
| Network Service Scanning | T1046 | Reconnaissance |

---

## Lessons Learned

1. Account lockout policy (5 attempts/30 min) worked
   as designed — contained the attack automatically

2. Dual-pipeline log collection is essential —
   Wazuh alone would have missed events during
   the buffer flood

3. East-west traffic between internal VMs requires
   internal network segmentation — perimeter
   controls alone are insufficient

4. Detection latency under 60 seconds meets
   operational requirements for this threat type

---

*This incident report was produced as part of the
SOC Lab Detection Engineering curriculum.
All activity was performed in a controlled
lab environment.*

