# NIST 800-53 Security Control Mapping
## SOC Lab — Home Security Operations Environment

**Author:** Leon Kiyonga Ddungu  
**Date:** June 2026  
**Version:** 1.0  
**Status:** Active — updated as lab expands  

---

## Purpose

This document maps security controls implemented
in the SOC lab environment to NIST SP 800-53
Revision 5 control families. It demonstrates
how the lab architecture satisfies federal
security control requirements and identifies
gaps where controls are planned but not yet
implemented.

This mapping methodology is directly applicable
to enterprise environments including state
agencies operating under NIST 800-53 baselines
such as those required by IRS Publication 1075
and FIPS Publication 199.

---

## System Description

**System Name:** SOC Lab Detection Engineering Environment  
**System Owner:** Leon Kiyonga Ddungu  
**FIPS 199 Categorization:** Moderate  
**Operating Environment:** On-premises hybrid
with Azure cloud integration  

---

## Control Family: AC — Access Control

---

### AC-2 — Account Management

**Control Requirement:**
Manage system accounts including establishing,
activating, modifying, reviewing, disabling,
and removing accounts.

**Lab Implementation:**
**Status:** Implemented ✅  
**Gap:** No automated account review process —
planned for future implementation  

---

### AC-3 — Access Enforcement

**Control Requirement:**
Enforce approved authorizations for logical
access to information and system resources.

**Lab Implementation:**

**Status:** Implemented ✅  
**Gap:** No Privileged Identity Management —
permanent admin access rather than
just-in-time elevation  

---

### AC-17 — Remote Access

**Control Requirement:**
Establish and document usage restrictions
and implementation guidance for remote
access to the system.

**Lab Implementation:**

**Status:** Partial ⚠️  
**Gap:** No VPN — direct RDP exposure on
internal network segment  

---

## Control Family: AU — Audit and Accountability

---

### AU-2 — Event Logging

**Control Requirement:**
Identify the types of events that the system
is capable of logging in support of the
audit function.

**Lab Implementation:**

**Status:** Implemented ✅  

---

### AU-3 — Content of Audit Records

**Control Requirement:**
Ensure audit records contain sufficient
information to establish what events
occurred, when, where, who, and the outcome.

**Lab Implementation:**

**Status:** Implemented ✅  

---

### AU-6 — Audit Record Review

**Control Requirement:**
Review and analyze system audit records
for indications of inappropriate activity
and report findings.

**Lab Implementation:**

**Status:** Implemented ✅  

---

### AU-9 — Protection of Audit Information

**Control Requirement:**
Protect audit information and tools from
unauthorized access, modification, and deletion.

**Lab Implementation:**

**Status:** Partial ⚠️  
**Gap:** Formal retention policy needed  

---

### AU-12 — Audit Record Generation

**Control Requirement:**
Provide audit record generation capability
for defined auditable events and allow
designated personnel to select which
events are audited.

**Lab Implementation:**

**Status:** Implemented ✅  

---

## Control Family: IR — Incident Response

---

### IR-4 — Incident Handling

**Control Requirement:**
Implement an incident handling capability
including preparation, detection, analysis,
containment, eradication, recovery, and
user coordination.

**Lab Implementation:**

**Status:** Implemented ✅  

---

### IR-5 — Incident Monitoring

**Control Requirement:**
Track and document system security incidents.

**Lab Implementation:**

**Status:** Implemented ✅  

---

### IR-6 — Incident Reporting

**Control Requirement:**
Report security incidents to designated
authorities within organization-defined
time periods.

**Lab Implementation:**

**Status:** Partial ⚠️  
**Gap:** No escalation chain in lab —
not applicable to single-analyst environment  

---

## Control Family: SI — System and Information Integrity

---

### SI-3 — Malware Protection

**Control Requirement:**
Implement malicious code protection
mechanisms at appropriate system locations.

**Lab Implementation:**

**Status:** Partial ⚠️  
**Gap:** No enterprise EDR — mitigated by
Sysmon + Wazuh combination  

---

### SI-4 — System Monitoring

**Control Requirement:**
Monitor the system to detect attacks and
indicators of potential attacks.

**Lab Implementation:**

**Status:** Implemented ✅  

---

## Control Family: CA — Assessment, Authorization, Monitoring

---

### CA-7 — Continuous Monitoring

**Control Requirement:**
Develop a continuous monitoring strategy
and implement a continuous monitoring
program.

**Lab Implementation:**

**Status:** Implemented ✅  

---

## Control Mapping Summary

| Control | Family | Status |
|---|---|---|
| AC-2 | Account Management | ✅ Implemented |
| AC-3 | Access Enforcement | ✅ Implemented |
| AC-17 | Remote Access | ⚠️ Partial |
| AU-2 | Event Logging | ✅ Implemented |
| AU-3 | Content of Audit Records | ✅ Implemented |
| AU-6 | Audit Record Review | ✅ Implemented |
| AU-9 | Protection of Audit Information | ⚠️ Partial |
| AU-12 | Audit Record Generation | ✅ Implemented |
| IR-4 | Incident Handling | ✅ Implemented |
| IR-5 | Incident Monitoring | ✅ Implemented |
| IR-6 | Incident Reporting | ⚠️ Partial |
| SI-3 | Malware Protection | ⚠️ Partial |
| SI-4 | System Monitoring | ✅ Implemented |
| CA-7 | Continuous Monitoring | ✅ Implemented |

**Implemented:** 10 of 14 controls (71%)  
**Partial:** 4 of 14 controls (29%)  
**Not Implemented:** 0  

---

## Gap Remediation Roadmap

| Gap | Control | Remediation | Timeline |
|---|---|---|---|
| No PIM/JIT access | AC-3 | Azure PIM deployment | Q3 2026 |
| No VPN | AC-17 | pfSense OpenVPN | Q3 2026 |
| Log retention policy | AU-9 | Define 90-day retention | Q3 2026 |
| No enterprise EDR | SI-3 | Defender for Endpoint trial | Q4 2026 |

---

*This control mapping was produced as part of
the SOC Lab Detection Engineering portfolio.
Methodology follows NIST SP 800-53 Revision 5.*
