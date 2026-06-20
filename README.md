# SOC Lab — Detection Engineering Portfolio

**Leon Kiyonga Ddungu**
Sacramento, CA | leonmata55@gmail.com
LinkedIn: linkedin.com/in/leon-kiyonga-ddungu

---

## What This Is

A fully operational home SOC environment built
to develop and demonstrate enterprise-level
security operations capabilities including:

- Attack simulation and detection engineering
- Microsoft Sentinel KQL analytics rules
- Incident response documentation
- Architecture decision records
- Threat hunting queries

---

## Lab Infrastructure

| Component | IP | Role |
|---|---|---|
| pfSense 2.7.2 + Snort IDS | 192.168.254.100 | Perimeter firewall + IDS |
| Ubuntu Server 22.04 LTS | 192.168.254.10 | Syslog forwarder + Azure Arc |
| Windows Server 2022 (SOC-DC01) | 192.168.254.20 | Active Directory domain controller |
| Wazuh 4.9.2 | 192.168.254.30 | XDR + HIDS platform |
| Kali Linux | 192.168.254.131 | Attack simulation |
| Microsoft Sentinel | Azure West US | Primary SIEM |

**Host machine:** Lenovo ThinkCentre M920 Tiny
64GB RAM | 2TB SSD | VMware Workstation Pro 17

---

## Detection Pipeline
