# RCA-001 — Wazuh Agent Buffer Flood During Brute Force Attack

| Field | Value |
|---|---|
| RCA ID | RCA-001 |
| Date | June 13, 2026 |
| Analyst | Leon Kiyonga Ddungu |
| Severity | High |
| Status | Resolved |
| Related Incident | IR-002 — Brute Force Attack |

---

## Problem Statement

During Project 03 brute force attack simulation
using netexec against Active Directory, the Wazuh
agent on SOC-DC01 flooded its event buffer and
began dropping security events. Critical Event ID
4625 failed logon records were lost during the
period of highest attack volume, creating a
detection blind spot in the XDR platform.

---

## Timeline

| Time | Event |
|---|---|
| 04:01:57 | netexec brute force initiated |
| 04:01:58 | First Event ID 4625 generated |
| 04:01:59 | Wazuh buffer warnings begin |
| 04:02:00 | WARNING: Agent buffer is full — Events may be lost |
| 04:02:08 | WARNING: Agent buffer is flooded — Producing too many events |
| 04:02:23 | WARNING: Agent buffer is full — Events may be lost |
| 04:05:47 | INFO: Agent buffer is under 70% — Working properly again |
| 04:06:25 | WARNING: Agent buffer at 90% |
| 04:06:29 | WARNING: Agent buffer is full — Events may be lost |
| 04:06:44 | WARNING: Agent buffer is flooded |
| 04:09:07 | WARNING: Target agent message queue is full (1024) — Log lines may be lost |
| 04:15:00 | Attack stopped — buffer recovered |

---

## Evidence


2026/06/13 01:21:42 wazuh-agent: WARNING:

Agent buffer is full: Events may be lost.
2026/06/13 01:22:23 wazuh-agent: WARNING:

Agent buffer is flooded: Producing too many events.
2026/06/13 01:29:07 wazuh-agent: WARNING:

Target agent message queue is full (1024).
<img width="1917" height="1010" alt="wazuh buffer warning" src="https://github.com/user-attachments/assets/1ef7cf12-2e15-4407-bf86-cd393d40de61" />


Log lines may be lost.

## Root Cause Analysis

**Primary Root Cause:**

The Wazuh agent default internal buffer and
message queue sizes are insufficient for
high-volume attack scenarios. The default
queue size of 1024 messages was exhausted
within seconds of the brute force attack
beginning.

netexec attempted thousands of authentication
requests per minute against SOC-DC01. Each
failed attempt generated multiple Windows
Security events including Event ID 4625
(failed logon) and associated authentication
audit events. The combined event rate exceeded
the Wazuh agent's queuing capacity.

**Contributing Factors:**

Factor 1: Default Wazuh configuration

The default ossec.conf does not tune

the agent buffer for high-volume scenarios.
Factor 2: Single collection pipeline

At the time of the attack Wazuh was the

primary event collection mechanism for

Windows Security events. No redundant

pipeline existed to catch dropped events.
Factor 3: Attack tool velocity

netexec is designed for high-speed

credential testing. The tool's default

speed generates event volume that

overwhelms agent-based collectors.

---

## Impact Assessment

Events affected:    Unknown — buffer overflow

means exact count unavailable
Detection impact:   Wazuh dashboard showed no

brute force activity during

peak attack period
Investigation impact: Analyst relying on Wazuh

alone would have incomplete

timeline reconstruction
Sentinel impact:    NONE — Azure Monitor Agent

captured events independently

via separate pipeline

---

## Resolution

**Immediate Resolution:**

Azure Monitor Agent (AMA) was confirmed as an
independent collection pipeline that delivered
all events to Microsoft Sentinel without loss.
AMA operates at the OS level and is not subject
to the same queue limitations as the Wazuh agent.

Sentinel query confirmed 9 Event ID 4625 records
captured during the attack:

```kql
Event
| where EventID == 4625
| where TimeGenerated > ago(2h)
| where Computer == "SOC-DC01.SOC.lab"
| where RenderedDescription contains "jsmith"
| summarize count()
// Result: 9 events
```

**Architectural Resolution:**

Dual-pipeline log collection architecture
formally documented and validated:

Pipeline 1 — Wazuh (XDR/behavioral)

Purpose: Real-time behavioral detection

and active response

Limitation: Buffer can be exhausted by

high-volume attacks

Use case: Standard operational monitoring
Pipeline 2 — AMA + Sentinel (authoritative)

Purpose: Complete, tamper-resistant log

delivery to cloud SIEM

Limitation: Higher latency than Wazuh

local alerting

Use case: Authoritative record of all events

Investigation and forensics

High-volume attack scenarios

---

## Lessons Learned

Lesson 1: Agent-based collectors can be weaponized

High-volume attacks can deliberately exhaust

agent buffers to create detection blind spots.

This is a known attacker evasion technique.

Defenders must maintain independent collection

pipelines that cannot be affected by endpoint

event volume.
Lesson 2: Dual-pipeline is not optional

A single collection pipeline creates a single

point of failure. AMA and Wazuh serve different

purposes and both are necessary.
Lesson 3: Validate under load not just at rest

Pipeline testing should include high-volume

scenarios not just baseline connectivity checks.
Lesson 4: Buffer warnings are detection signals

Wazuh buffer warnings in the agent log are

themselves an indicator of a high-volume

attack. Add monitoring for these warnings

as an alert trigger.

---

## Corrective Actions

| Action | Priority | Status |
|---|---|---|
| Document AMA as authoritative pipeline | High | ✅ Complete |
| Increase Wazuh agent buffer in ossec.conf | High | Planned |
| Add Wazuh buffer warning to alert runbook | Medium | Planned |
| Add buffer monitoring detection rule | Medium | Planned |
| Test pipeline under simulated flood conditions | Medium | Planned |

---

## Wazuh Buffer Configuration Fix

To increase Wazuh agent buffer (planned):

Edit on SOC-DC01:

Add inside client section:
```xml
<client_buffer>
  <disabled>no</disabled>
  <queue_size>10000</queue_size>
  <events_per_second>500</events_per_second>
</client_buffer>
```

**Note:** Even with increased buffer size AMA
should remain the authoritative pipeline.
Buffer tuning reduces but does not eliminate
the risk of event loss during extreme
volume attacks.

---

## MITRE ATT&CK Relevance

T1562.006 — Impair Defenses: Indicator Blocking

Attackers may deliberately generate high

event volume to exhaust agent buffers and

create blind spots during an attack.

This RCA demonstrates awareness of this

technique and the architectural response.

---

*This root cause analysis was produced as part
of the SOC Lab Detection Engineering curriculum.
The finding and resolution are documented here
for portfolio and reference purposes.*























Wazuh agent log entries observed:
