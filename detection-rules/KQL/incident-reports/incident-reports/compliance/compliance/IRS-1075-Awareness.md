# IRS Publication 1075 — Security Awareness Document
## Relevance to State Agency Security Operations

**Author:** Leon Kiyonga Ddungu  
**Date:** June 2026  
**Purpose:** Pre-interview research and awareness  
**Applicability:** California EDD and other state
agencies receiving Federal Tax Information  

---

## What Is IRS Publication 1075

IRS Publication 1075 establishes the standards
that federal, state, and local agencies must
follow to protect Federal Tax Information (FTI)
received from the Internal Revenue Service.

It is not optional. Any agency that receives
FTI from the IRS as part of their operations
must comply with IRS 1075 or risk losing access
to that federal data.

EDD receives FTI as part of administering
unemployment insurance and other workforce
programs. This makes IRS 1075 compliance
a core operational requirement for EDD's
IT security team.

---

## What Is Federal Tax Information (FTI)

FTI is any return or return information received
from the IRS or secondary sources that is
protected under Internal Revenue Code Section 6103.

EXAMPLES OF FTI AT EDD:

→ Income data used to verify unemployment

insurance eligibility

→ Wage and earnings information

→ Taxpayer identification numbers (SSN/EIN)

→ Tax return data used in benefit calculations

→ Any derivative data created from IRS records

**Key point:** FTI does not stop being FTI
just because it has been processed or combined
with other data. Once data originates from
IRS records it retains FTI status and must
be protected accordingly.



---

## Why IRS 1075 Matters to a Security Operations Team

Every security decision in an environment
that handles FTI must account for IRS 1075
requirements. This affects:

---
SIEM OPERATIONS:

→ Audit logs must capture all access to

systems containing FTI

→ Log retention periods specified

→ Unauthorized access must be reported

to IRS within specific timeframes
FIREWALL AND NETWORK SECURITY:

→ FTI must be encrypted in transit

→ Network access to FTI systems must

be controlled and documented

→ Firewall rules affecting FTI systems

require documented justification
INCIDENT RESPONSE:

→ Any incident involving potential FTI

exposure triggers federal notification

requirements — not just state protocols

→ IRS must be notified of FTI breaches

→ Notification timelines are strict
ACCESS CONTROL:

→ Access to FTI is need-to-know only

→ Background checks required for personnel

with access to FTI systems

→ Access must be logged and auditable

## IRS 1075 Security Requirements — Summary

---

### Requirement 1 — Audit Controls

REQUIREMENT:

Implement hardware software and procedural

mechanisms that record and examine activity

in systems that contain or use FTI.
WHAT THIS MEANS OPERATIONALLY:

→ Every access to FTI systems must be logged

→ Logs must identify who accessed what and when

→ Logs must be protected from modification

→ Logs must be reviewed regularly
LAB PARALLEL:

In my SOC lab I implement this via:

→ Windows Security Event ID 4624 (all logons)

→ Sysmon Event ID 1 (all process execution)

→ Azure Monitor Agent delivering logs to

tamper-resistant cloud storage (Sentinel)

→ Automated analytics rules reviewing logs

every 5 minutes

---

### Requirement 2 — Access Controls

REQUIREMENT:

Limit access to FTI to authorized personnel

on a need-to-know basis.
WHAT THIS MEANS OPERATIONALLY:

→ Role-based access control enforced

→ Least privilege applied to all accounts

→ Privileged access requires justification

→ Access reviews conducted regularly
LAB PARALLEL:

In my SOC lab I implement this via:

→ Active Directory role-based groups

→ Separate OU structure by department

→ Domain Admin rights restricted to

single privileged account (madmin)

→ Event ID 4672 monitoring for all

privileged logons

---

### Requirement 3 — Transmission Security
REQUIREMENT:

Protect FTI during electronic transmission.
WHAT THIS MEANS OPERATIONALLY:

→ All FTI transmitted over encrypted channels

→ TLS 1.2 minimum for data in transit

→ No FTI transmitted over unencrypted protocols
LAB PARALLEL:

→ Azure Monitor Agent uses HTTPS for

all log transmission to Sentinel

→ Azure Arc uses TLS for management

communications

→ Wazuh agent uses AES encryption for

event forwarding (port 1514)

---

### Requirement 4 — Incident Response

REQUIREMENT:

Establish procedures to address security

incidents involving FTI including notification

to IRS within specified timeframes.
NOTIFICATION REQUIREMENTS:

→ Suspected or actual FTI breach must be

reported to IRS within 24 hours of discovery

→ Initial report must include:

Date and time of discovery
Nature of the incident
FTI involved
Number of individuals affected
Corrective actions taken

WHAT THIS MEANS OPERATIONALLY:

→ IR procedures must include FTI-specific

notification steps

→ Incident reports must document whether

FTI was involved or at risk

→ Breach notification workflow must be

defined and tested
LAB PARALLEL:

My IR-002 incident report format includes:

→ Executive summary for non-technical leadership

→ Timeline of events

→ Scope of data affected

→ Containment actions

→ This structure maps directly to FTI

breach notification requirements

---

### Requirement 5 — Personnel Security

REQUIREMENT:

Conduct background investigations for personnel

with access to FTI.
WHAT THIS MEANS OPERATIONALLY:

→ Background checks required before granting

access to FTI systems

→ EDD IT Associate position requires

fingerprinting and background check

(confirmed in position requirements)

→ Ongoing personnel security monitoring
NOTE: The EDD IT Associate position statement

explicitly requires fingerprinting and

background check — this is the IRS 1075

personnel security requirement in action

---

### Requirement 6 — Annual Self-Assessment

REQUIREMENT:

Conduct annual self-assessments of FTI

safeguards and submit results to IRS.
WHAT THIS MEANS OPERATIONALLY:

→ Annual review of all IRS 1075 controls

→ Documentation of compliance status

→ Gap identification and remediation planning

→ Formal submission to IRS
THIS IS WHY:

Documentation discipline is critical in

EDD's security operations. The annual

self-assessment requires the same

structured approach as the NIST 800-53

control mapping in this portfolio.

---

## Comparison: IRS 1075 vs 42 CFR Part 2

My background includes operating under
42 CFR Part 2 — the federal regulation
governing substance use disorder treatment
records. This provides direct preparation
for IRS 1075 compliance.

| Requirement | IRS 1075 (FTI) | 42 CFR Part 2 (SUD Records) |
|---|---|---|
| Disclosure restrictions | Strict — IRC 6103 | Strict — explicit consent required |
| Audit logging | Required | Required |
| Breach notification | 24-hour to IRS | Required |
| Access controls | Need-to-know | Need-to-know |
| Background checks | Required | Required |
| Annual review | Self-assessment | Policy review |
| Criminal penalties | Yes | Yes |

**Key insight:** Operating under 42 CFR Part 2
at behavioral health facilities provided direct
experience with federal data protection frameworks
that carry criminal penalties. The discipline of
treating data protection as non-negotiable —
not a compliance checkbox — translates directly
to an IRS 1075 environment.

---

## Security Operations Implications for EDD

As a member of EDD's Security Operations Group
every operational decision must account for
IRS 1075:
SIEM ALERT INVOLVING FTI SYSTEM:

→ Standard IR process applies PLUS

→ Determine if FTI was accessed or exposed

→ If yes — 24-hour IRS notification clock starts

→ Document everything with more detail than

a standard incident
FIREWALL CHANGE REQUEST FOR FTI SYSTEM:

→ Standard triage process applies PLUS

→ Higher scrutiny — any change affecting

FTI system access requires additional

justification

→ Least privilege applied more strictly
VULNERABILITY IN FTI SYSTEM:

→ Standard remediation process applies PLUS

→ Expedited timeline — FTI systems cannot

remain vulnerable

→ IRS notification may be required if

exploitation is suspected

---

## Summary

IRS Publication 1075 is not an abstract
compliance framework. It is the operational
reality of every security decision made
in EDD's environment. Understanding it
before joining the team means contributing
from day one rather than learning it
on the job.

My preparation for this environment includes:
- Direct experience with comparable federal
  data protection frameworks (42 CFR Part 2)
- NIST 800-53 control implementation in lab
- Incident response documentation aligned
  to breach notification requirements
- Access control and audit logging as
  core architectural principles

---

*This document was produced as pre-interview
research for the EDD Information Technology
Associate position (JC-517445).
All IRS 1075 information sourced from
IRS Publication 1075 — Tax Information
Security Guidelines for Federal, State
and Local Agencies.*








