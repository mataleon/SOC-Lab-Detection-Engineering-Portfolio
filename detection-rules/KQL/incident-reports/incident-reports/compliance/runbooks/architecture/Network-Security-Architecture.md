# Network Security Architecture
## SOC Lab — Defense in Depth Design

**Author:** Leon Kiyonga Ddungu  
**Date:** June 2026  
**Version:** 1.0  
**Status:** Active — updated as lab expands  

---

## Architecture Philosophy

The SOC lab network is designed around the
principle of defense in depth — multiple
independent security controls layered so
that failure of any single control does
not result in complete compromise.

LAYER 1 — PERIMETER

pfSense firewall + Snort IDS
LAYER 2 — NETWORK

VMnet segmentation
LAYER 3 — ENDPOINT

Sysmon + Wazuh agents
LAYER 4 — IDENTITY

Active Directory + Account lockout policy
LAYER 5 — CLOUD

Azure Monitor Agent + Sentinel

---

## Network Topology

INTERNET

|

| (VMnet0 — Bridged)

|

[pfSense WAN — 192.168.254.171]

|

[pfSense Firewall + Snort IDS]

|

[pfSense LAN — 192.168.254.100]

|

|————————————————————————————|

|     VMnet8 NAT               |

|     192.168.254.0/24         |

|                              |

[Ubuntu]   [SOC-DC01]  [Wazuh]   [Kali]

[.10]      [.20]       [.30]     [.131]

|           |            |

| Azure Arc  | Azure Arc  |

|————————————|            |

|                    |

[Log Analytics Workspace]     |

[SOC-Lab-LAW — West US]       |

|                    |

[Microsoft Sentinel] ←————————|

(Wazuh syslog)

---

## Security Zones

---

### Zone 1 — WAN / Internet Edge

**Network:** VMnet0 (Bridged)  
**Interface:** pfSense WAN (192.168.254.171)  

**Security Controls:**

→ pfSense stateful packet inspection firewall

→ Default deny all inbound policy

→ Snort IDS monitoring all inbound traffic

Rule sets: ET Open (malware + scanning)

GPLv2 Community Rules

Feodo Tracker Botnet C2

→ Syslog forwarding to Zone 3 forwarder

**Traffic Policy:**

Inbound:  Deny all (default)

Outbound: Allow all (lab requires internet

access for Azure connectivity)

**Known Limitations:**

→ Snort only sees WAN traffic

→ East-west internal traffic not inspected

at this layer (documented gap — see below)

---

### Zone 2 — Internal Lab Network

**Network:** VMnet8 NAT (192.168.254.0/24)  
**Gateway:** pfSense LAN (192.168.254.100)  

**Assets in Zone:**

| Host | IP | Role | Sensitivity |
|---|---|---|---|
| Ubuntu Forwarder | 192.168.254.10 | Syslog + AMA | Medium |
| SOC-DC01 | 192.168.254.20 | Active Directory | High |
| Wazuh Server | 192.168.254.30 | XDR Platform | High |
| Kali Linux | 192.168.254.131 | Attack Simulation | High |

**Known Gap — East-West Blind Spot:**

ISSUE: Traffic between VMs on VMnet8 does

not cross the pfSense WAN interface.

Snort only monitors WAN interface.

Therefore Snort cannot see:

→ Kali scanning SOC-DC01 (internal)

→ Lateral movement between lab VMs
DETECTION LESSON LEARNED:

Nmap scan from Kali to SOC-DC01 was

completely invisible to Snort.

Detected only after enabling Windows

Firewall logging on SOC-DC01 and

configuring Wazuh to ingest it.
MITIGATION IN PLACE:

→ Windows Firewall logging on SOC-DC01

→ Wazuh ingesting pfirewall.log

→ Sentinel collecting Windows Security events
PLANNED REMEDIATION:

→ Deploy Snort or Suricata on internal

interface for east-west visibility

→ Security Onion with network TAP

for full packet capture

---

## Firewall Rule Documentation

### pfSense WAN Rules

| Rule | Source | Destination | Port | Action | Justification |
|---|---|---|---|---|---|
| Default deny | Any | Any | Any | Block | Default deny inbound |

### pfSense LAN Rules

| Rule | Source | Destination | Port | Action | Justification |
|---|---|---|---|---|---|
| Allow LAN to WAN | 192.168.254.0/24 | Any | 80,443 | Allow | Internet access for updates and Azure |
| Allow DNS | 192.168.254.0/24 | Any | 53 | Allow | DNS resolution |
| Allow NTP | 192.168.254.0/24 | Any | 123 | Allow | Time synchronization |

### Windows Firewall — SOC-DC01

Logging enabled:

→ Allowed connections: Yes

→ Dropped connections: Yes

→ Log file: C:\Windows\System32

LogFiles\Firewall\pfirewall.log
Key rules monitored:

→ RDP (3389) — enabled for admin access

Monitor: Event ID 4624 Logon Type 10

→ SMB (445) — enabled for domain function

Monitor: East-west connections from

unexpected sources

→ Kerberos (88) — enabled for AD auth

Monitor: 4768/4769 for anomalies

---

## Snort IDS Configuration

**Platform:** pfSense 2.7.2  
**Interface:** WAN (VMnet0)  

**Rule Sets Deployed:**

| Rule Set | Category | Reason Selected |
|---|---|---|
| ET Open — Malware | Malware signatures | High signal C2 and download detection |
| ET Open — Scanning | Scan detection | Port scan and recon detection |
| GPLv2 Community | Known exploits | Cisco Talos maintained signatures |
| Feodo Tracker | Botnet C2 IPs | Known botnet infrastructure |

**Rule Sets Rejected:**

| Rule Set | Reason Rejected |
|---|---|
| Full ET Open | Memory exhaustion — 30,000+ rules crashed Snort silently |
| ET Open Policy | High false positive rate for lab traffic |

**Memory Finding — Critical:**

ISSUE: Loading all ET Open categories on

a 4GB VM caused Snort to crash silently.

The pfSense GUI showed Snort as stopped

with no error message visible in standard

log view.
LESSON: Always verify Snort process is

actually running after rule updates.

Monitor memory consumption incrementally

when adding new rule sets.
MITIGATION: Load rule sets incrementally.

Test one category at a time.

**Alert Forwarding:**
Snort alerts → pfSense syslog

→ UDP 514 → Ubuntu rsyslog (192.168.254.10)

→ Azure Monitor Agent

→ Microsoft Sentinel Syslog table

---

## Detection Coverage Map

| Attack Type | Detection Layer | Tool | Event/Alert |
|---|---|---|---|
| External port scan | Perimeter | Snort | ET SCAN rule |
| Internal port scan | Endpoint | Windows Firewall | pfirewall.log |
| Brute force — AD | Endpoint | Windows Security | Event 4625/4740 |
| Brute force — Sentinel | Cloud SIEM | Sentinel | Analytics rule |
| Encoded PowerShell | Endpoint | Sysmon | Event ID 1 |
| Registry persistence | Endpoint | Sysmon | Event ID 13 |
| DNS C2 | Endpoint | Sysmon | Event ID 22 |
| Lateral movement | Endpoint | Windows Security | Event 4624 Type 3 |

---

## Baseline vs Target Architecture

### Current State — June 2026
STRENGTHS:

✅ Full logging pipeline operational

✅ Sysmon telemetry in Sentinel

✅ Brute force detection validated

✅ Dual-pipeline collection (Wazuh + AMA)

✅ pfSense perimeter with Snort IDS

✅ Active Directory with audit logging
GAPS:

❌ East-west traffic not fully monitored

❌ No Splunk (dual-SIEM not deployed)

❌ No Security Onion

❌ No internal network IDS

❌ No Zero Trust Conditional Access

### Target State — December 2026

ADDITIONS PLANNED:

→ Splunk as secondary SIEM

→ Security Onion for network monitoring

→ Suricata on internal VMnet8 interface

→ Windows 10 endpoint VM

→ Azure Entra ID sync for Zero Trust

→ 20%+ MITRE ATT&CK technique coverage

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Detected |
|---|---|---|---|
| Reconnaissance | Network Service Scanning | T1046 | Partial |
| Credential Access | Brute Force | T1110 | ✅ Yes |
| Execution | PowerShell | T1059.001 | ✅ Yes |
| Defense Evasion | Obfuscated Files | T1027 | ✅ Yes |
| Persistence | Registry Run Keys | T1547.001 | ✅ Yes |
| Credential Access | OS Credential Dumping | T1003 | Planned |
| Lateral Movement | Remote Services | T1021 | Planned |

**Current coverage:** 4 techniques fully detected  

---

*This architecture document is maintained as
a living reference updated with each lab
expansion. It serves as both a technical
reference and a portfolio artifact demonstrating
security architecture design and documentation
skills.*











