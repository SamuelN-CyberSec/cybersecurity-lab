# SOC Analyst Lab

> **Executive Summary:** A hands-on SOC (Security Operations Center) lab for practicing threat detection, log analysis, incident response, and SIEM operations. This lab simulates real-world SOC workflows using open-source tools.

---

## 🎯 Purpose

Build practical SOC experience by:
- Deploying and configuring a SIEM (Wazuh)
- Creating custom detection rules (Sigma → Wazuh)
- Simulating attacks and generating alerts
- Writing incident response playbooks
- Mapping detections to MITRE ATT&CK

---

## 🛠️ Tools Used

| Tool | Purpose | Type |
|------|---------|------|
| **Wazuh** | SIEM + XDR | Open Source |
| **TheHive** | Incident Response Case Management | Open Source |
| **Shuffle** | SOAR Automation | Open Source |
| **Kali Linux** | Attack Simulation | Offensive |
| **Metasploitable 2** | Vulnerable Target | Training |
| **Atomic Red Team** | Attack Simulation | Open Source |
| **Velociraptor** | Endpoint Detection & Response | Open Source |

---

## 📂 Lab Structure

```
01_SOC_ANALYST_LAB/
├── README.md
├── SIEM_SETUP/
│   ├── WAZUH_INSTALLATION.md
│   ├── AGENT_DEPLOYMENT.md
│   └── LOG_SOURCES.md
├── DETECTION_RULES/
│   ├── sigma_rules/
│   ├── custom_wazuh_rules.xml
│   └── MITRE_MAPPING.csv
├── THREAT_HUNTING_PLAYBOOKS/
│   ├── ransomware_hunt.md
│   ├── lateral_movement_hunt.md
│   └── data_exfil_hunt.md
└── INCIDENT_RESPONSE_PLAYBOOKS/
    ├── phishing_ir.md
    ├── ransomware_ir.md
    └── unauthorized_access_ir.md
```

---

## 🚀 Quick Start

### Prerequisites
- **System:** 8GB+ RAM, 4 CPU cores, 50GB storage
- **Hypervisor:** VirtualBox or VMware
- **OS:** Ubuntu Server 22.04 LTS for SIEM

### Step 1: Deploy Wazuh SIEM
```bash
# One-liner installation (Wazuh 4.x)
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
bash wazuh-install.sh -a
```

### Step 2: Deploy Agents
```bash
# Linux Agent
curl -sO https://packages.wazuh.com/4.x/wazuh-agent/
sudo WAZUH_MANAGER='<SIEM_IP>' bash wazuh-agent-install.sh
```

### Step 3: Simulate Attacks
```bash
# Using Atomic Red Team (Windows)
Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')
Install-AtomicRedTeam -GetPrereqs
Invoke-AtomicTest T1059.001 -ShowDetails
```

---

## 📊 Sample Detection Rule (Sigma → Wazuh)

```yaml
# sigma_rules/win_powershell_suspicious_download.yml
title: Suspicious PowerShell Download
id: 12345678-abcd-1234-abcd-123456789abc
status: experimental
description: Detects suspicious PowerShell download patterns
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 
      - 'Invoke-WebRequest'
      - 'Net.WebClient'
      - 'DownloadString'
  condition: selection
falsepositives:
  - Administrative scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

---

## 📌 Learning Progression

| Level | Skill | Lab Activity |
|-------|-------|-------------|
| L1 | Log Analysis | Parse 100 alerts, classify severity |
| L2 | Alert Triage | Respond to simulated phishing alert |
| L3 | Threat Hunting | Hunt for lateral movement in logs |
| L4 | IR Lead | Lead full incident from detection to report |

---

**Resume Value:** A documented SOC lab demonstrates hands-on capability without requiring enterprise access. "Built a fully functional SOC homelab with Wazuh SIEM, created 15+ custom detection rules mapped to MITRE ATT&CK."
