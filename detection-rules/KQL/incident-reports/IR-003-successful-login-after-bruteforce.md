# IR-003 — Successful Login After Brute Force

| Field | Value |
|---|---|
| Incident ID | IR-003 |
| Sentinel Incident # | 295 |
| Date | May 24, 2026 |
| Severity | High |
| Status | Closed |
| Analyst | Leon Kiyonga Ddungu |
| MITRE Tactic | Initial Access, Credential Access |
| MITRE Technique | T1110.001 — Password Guessing |

---

## Executive Summary

A correlation-based detection rule identified a
confirmed credential compromise — not merely an
attempted brute force, but a successful
authentication immediately following a pattern of
5 or more failed logon attempts from the same
source IP address. This represents a higher-severity
finding than a standard brute force alert because
it indicates the attacker did not just attempt
access — they obtained it. The detection correlated
11 total events (failed and successful logons)
within a 1-hour window and fired a High severity
incident in Microsoft Sentinel.

---

## Why This Incident Matters More Than a Standard Brute Force Alert

# IR-003 — Successful Login After Brute Force

| Field | Value |
|---|---|
| Incident ID | IR-003 |
| Sentinel Incident # | 295 |
| Date | May 24, 2026 |
| Severity | High |
| Status | Closed |
| Analyst | Leon Kiyonga Ddungu |
| MITRE Tactic | Initial Access, Credential Access |
| MITRE Technique | T1110.001 — Password Guessing |

---

## Executive Summary

A correlation-based detection rule identified a
confirmed credential compromise — not merely an
attempted brute force, but a successful
authentication immediately following a pattern of
5 or more failed logon attempts from the same
source IP address. This represents a higher-severity
finding than a standard brute force alert because
it indicates the attacker did not just attempt
access — they obtained it. The detection correlated
11 total events (failed and successful logons)
within a 1-hour window and fired a High severity
incident in Microsoft Sentinel.

---

## Why This Incident Matters More Than a Standard Brute Force Alert


A standard brute force rule tells you an attack is
happening. This rule tells you the attack worked.
That distinction changes the entire incident
response posture — from "monitor and contain" to
"assume breach and investigate scope."

---

## Detection Logic

**Platform:** Microsoft Sentinel
**Rule Name:** Successful Login After Brute Force
**Table:** SecurityEvent
**Trigger:** 5+ Event ID 4625 from an IP, followed
by Event ID 4624 from that same IP, within 1 hour
**Severity:** High
**Query Frequency:** Every 5 minutes
**Lookback Window:** 5 minutes (scheduling) / 1 hour (query logic)

**KQL Query:**

```kql
let FailedLogins = SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailCount = count() by IpAddress, TargetAccount;
SecurityEvent
| where EventID == 4624
| where TimeGenerated > ago(1h)
| join kind=inner FailedLogins on IpAddress
| where FailCount >= 5
| project TimeGenerated, IpAddress, TargetAccount, FailCount
| sort by FailCount desc
```

**How it works:**

First subquery (FailedLogins) builds a table

of every IP address that generated 5+ failed

logon attempts (Event ID 4625) in the last hour,

grouped by source IP and target account
Main query pulls all successful logons

(Event ID 4624) in the same time window
The join correlates the two — finding any

successful logon from an IP address that ALSO

appears in the failed logon table with 5+ failures
Result: a list of confirmed compromises where

brute force preceded success

---

## Incident Detail — #295


Incident Number:    295

Title:               Successful Login After Brute Force

Description:         T1110.001 — Password Guessing

Credential Access

Severity:             High

Status:               New (at time of review)

Owner:                Unassigned

Events:               11

Alerts:               1

Bookmarks:            0

Creation Time:        05/24/2026, 03:31:36 AM

Last Update Time:     05/24/2026, 03:31:36 AM

Tactics:              Initial Access

---

## Investigation Finding — Entity Mapping Gap

When this incident first fired, the Entities
panel showed **"No entities found"** despite the
underlying query correctly identifying an
`IpAddress` and `TargetAccount` for the
correlated event.

**Root cause:** The analytics rule's Entity
Mapping configuration had not been set. Sentinel
does not automatically infer entity types (IP,
Account, Host) from query output columns — this
must be explicitly configured in the rule, even
when the underlying detection logic is correct.

**This is a meaningful finding on its own** — a
detection rule can be functionally correct (it
fired, the logic worked, the alert triggered) while
still being operationally incomplete (no entity
context for the analyst reviewing it). A rule
without entity mapping fires correctly but gives
the investigating analyst no immediately actionable
IP or account to pivot on — they would have to dig
into the raw query results manually.

**Remediation applied:**

Entity Mapping configured:

Entity Type: IP      → Identifier: Address  → Column: IpAddress

Entity Type: Account → Identifier: Name     → Column: TargetAccount

Full details documented separately in
RCA-002-Sentinel-Entity-Mapping-Gap.md

---

## IOCs

| Type | Value | Source |
|---|---|---|
| Detection Pattern | 5+ failed logons → 1 successful logon, same IP | SecurityEvent join |
| Event IDs Correlated | 4625 (failure), 4624 (success) | SecurityEvent |
| MITRE Technique | T1110.001 | Password Guessing |

---

## Containment Actions

Reviewed correlated events to identify

source IP and target account
Verified incident severity classification

(High — appropriate given confirmed access)
Identified entity mapping gap preventing

immediate IOC visibility in incident panel
Corrected entity mapping configuration
Documented finding as RCA-002 for future

rule deployment standard


---

## Detection Improvements

| # | Improvement | Priority | Status |
|---|---|---|---|
| 1 | Add entity mapping to all custom analytics rules | High | ✅ Complete |
| 2 | Standardize on `Event` table vs `SecurityEvent` table across all rules | Medium | Planned |
| 3 | Add automated response — disable account on trigger | Medium | Planned |
| 4 | Extend lookback window validation against rule scheduling interval | Low | Planned |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Password Guessing | T1110.001 | Credential Access |
| Valid Accounts | T1078 | Initial Access |

---

## Lessons Learned


Correlation rules (failed → successful logon)

provide significantly higher-fidelity detection

than threshold-only rules — they distinguish

"attempted" from "confirmed" compromise
A functionally correct KQL query is not the

same as an operationally complete analytics

rule — entity mapping is a required step, not

an optional enhancement
Always validate the Entities panel after

deploying a new analytics rule, even when

the query itself returns expected results
Mixed table usage (SecurityEvent vs Event)

across different rules in the same workspace

should be standardized to avoid confusion

during future rule development and maintenance

---

*This incident report was produced as part of the
SOC Lab Detection Engineering curriculum. It
documents both the security detection finding and
the operational engineering gap identified and
corrected during investigation.*

