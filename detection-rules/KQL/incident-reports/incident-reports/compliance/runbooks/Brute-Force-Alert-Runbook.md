# SOC Runbook — Brute Force Attack Alert
## Alert: Multiple Failed Logon Attempts Detected

**Runbook ID:** RB-001  
**Author:** Leon Kiyonga Ddungu  
**Date:** June 2026  
**Version:** 1.0  
**Platform:** Microsoft Sentinel + Wazuh  
**MITRE Technique:** T1110 — Brute Force  

---

## Alert Description

This alert fires when Microsoft Sentinel detects
5 or more Windows Event ID 4625 (failed logon)
events from the same source IP address within
a 5-minute window against any domain-joined system.

**Severity:** High  
**Expected Response Time:** 15 minutes to triage  
**Escalation Time:** 30 minutes if not resolved  

---

## Detection Rule

```kql
Event
| where EventID == 4625
| where TimeGenerated > ago(5m)
| extend SourceIP = extract(
    @"Source Network Address:\s+(\S+)",
    1, RenderedDescription)
| extend TargetAccount = extract(
    @"Account Name:\s+(\S+)\s+Account Domain",
    1, RenderedDescription)
| where SourceIP != "-" and SourceIP != ""
| summarize
    FailedAttempts=count(),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    Accounts=make_set(TargetAccount)
    by SourceIP, Computer
| where FailedAttempts >= 5
```
Check the source IP address:
INTERNAL IP (10.x.x.x, 192.168.x.x, 172.16-31.x.x):

→ Attack originates from inside the network

→ Higher priority — attacker already has access

→ Possible compromised internal host

→ Possible insider threat

→ Possible authorized pen test (verify first)
EXTERNAL IP:

→ Attack from internet

→ Check if RDP or VPN is exposed

→ Block IP at perimeter firewall

→ Verify no successful logons occurred
---

## Triage Steps — First 15 Minutes

### Step 1 — Identify the Source (2 minutes)

**Sentinel query to identify source:**

```kql
Event
| where EventID == 4625
| where TimeGenerated > ago(30m)
| extend SourceIP = extract(
    @"Source Network Address:\s+(\S+)",
    1, RenderedDescription)
| summarize count() by SourceIP
| order by count_ desc
```

---

### Step 2 — Check for Successful Logons (3 minutes)

**This is the most critical step.**

If the attacker successfully authenticated
before lockout occurred the incident severity
escalates to Critical immediately.

```kql
Event
| where EventID == 4624
| where TimeGenerated > ago(1h)
| extend SourceIP = extract(
    @"Source Network Address:\s+(\S+)",
    1, RenderedDescription)
| extend LogonType = extract(
    @"Logon Type:\s+(\d+)",
    1, RenderedDescription)
| where SourceIP == "REPLACE_WITH_ATTACKER_IP"
| project TimeGenerated, Computer,
    SourceIP, LogonType
| order by TimeGenerated asc
```
RESULT: No successful logons found

→ Attacker did not get in

→ Continue standard triage
RESULT: Successful logon found BEFORE failures

→ ESCALATE IMMEDIATELY

→ Attacker may have valid credentials

→ Check what they did after logon (Step 6)

→ Notify senior analyst
---

### Step 3 — Identify Target Account (2 minutes)

SERVICE ACCOUNT indicators:

→ Account name ends in $ or SVC or SVC_

→ Failures occur at regular intervals

→ Source is a known server or application

→ Time pattern is consistent (every X minutes)

→ ACTION: Likely misconfiguration — investigate

the source system, not an attacker
USER ACCOUNT indicators:

→ Account name is a person (jsmith, adavis)

→ Failures are rapid (seconds apart)

→ Source is unusual or unknown

→ Time is outside business hours

→ ACTION: Likely brute force — escalate

---

### Step 4 — Check Account Status (1 minute)

Verify account lockout on domain controller:
PowerShell on SOC-DC01:

net user [username]
Look for:

Account active: Locked    ← lockout triggered

Account active: Yes       ← still active (attack ongoing)
If still active and attack ongoing:

→ Manually lock account immediately

→ net user [username] /active:no

---

### Step 5 — Verify Authorized Testing (2 minutes)

Before containing — verify this is not

authorized penetration testing:
CHECK:

→ Is there an open change management ticket

for security testing today?

→ Is the source IP a known security testing host?

→ Was the security team notified of a test?

→ Contact the source host owner if internal
If authorized testing:

→ Document in alert — false positive

→ Add source IP to suppression list

→ Close alert with notes
If not authorized:

→ Proceed to containment

---

### Step 6 — Timeline Reconstruction (5 minutes)

```kql
Event
| where TimeGenerated > ago(24h)
| where RenderedDescription contains
    "REPLACE_WITH_ATTACKER_IP"
| project TimeGenerated, EventID,
    RenderedDescription
| order by TimeGenerated asc
```

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where TimeGenerated > ago(2h)
| extend CommandLine = extract(
    @"CommandLine: (.+?)(?:\r|\n)",
    1, RenderedDescription)
| where CommandLine has_any (
    "netexec", "crackmapexec", "hydra",
    "medusa", "ncrack", "spray")
| project TimeGenerated, Computer,
    CommandLine
```

---

## Containment Actions

### If Attack is Confirmed Malicious

ACTION 1 — Isolate source host (if internal)

Method: Wazuh active response OR

network-level isolation via

firewall rule blocking source IP
ACTION 2 — Block source IP at perimeter

pfSense: Firewall → Rules → Add block rule

Source: [attacker IP]

Destination: Any

Action: Block

Log: Yes
ACTION 3 — Verify account status

Confirm lockout or manually disable:

net user [username] /active:no
ACTION 4 — Preserve logs

Export relevant Sentinel logs before

any system changes

Screenshot the incident timeline
ACTION 5 — Notify account owner

If real user account targeted:

→ Notify user their account was locked

→ Instruct them not to unlock until

investigation complete

→ Verify they did not share credentials

---

## Escalation Criteria

**Escalate to senior analyst immediately if:**

→ Successful logon occurred before lockout

→ Source IP is unknown and external

→ Multiple accounts targeted simultaneously

→ Activity on privileged accounts

(Domain Admin, service accounts)

→ Attack continues after containment

→ Evidence of lateral movement after

any successful logon

→ FTI systems are targeted

(EDD-specific — triggers IRS 1075

notification assessment)

---

## Documentation Requirements

For every brute force alert create:

MINIMUM DOCUMENTATION:

□ Source IP address

□ Target account(s)

□ Number of failed attempts

□ Time window of attack

□ Successful logons — yes or no

□ Account lockout — yes or no

□ Containment actions taken

□ Authorized testing — yes or no

□ Final disposition — true positive or false positive

---

## False Positive Scenarios

| Scenario | Indicator | Action |
|---|---|---|
| User forgot password | Single account, business hours, known source | Verify with user, unlock, document |
| Service account misconfiguration | Regular intervals, known source host | Fix service config, suppress rule for source |
| Authorized pen test | Change ticket exists, known tester IP | Document, suppress for test window |
| Backup/sync job | Consistent timing, server source | Verify with IT, whitelist if legitimate |

---

*This runbook was developed based on real
brute force simulation experience in the
SOC Lab environment (IR-002). It follows
NIST 800-61 incident handling methodology.*







