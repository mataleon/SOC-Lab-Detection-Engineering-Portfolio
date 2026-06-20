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
