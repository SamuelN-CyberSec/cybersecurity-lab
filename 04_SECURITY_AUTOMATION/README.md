# Security Automation

> **Executive Summary:** Python-based security automation scripts for log analysis, alert aggregation, API integrations, and security operations workflows. Designed to save 10+ hours per week on repetitive tasks.

---

## 🎯 Purpose

Automate key security operations tasks:
- Parse and analyze security logs (firewall, IDS, Windows Events)
- Aggregate alerts from multiple sources into unified format
- Integrate with security APIs (VirusTotal, Shodan, AlienVault OTX)
- Automate incident enrichment and triage
- Schedule and orchestrate security tasks

---

## 📂 Module Structure

```
04_SECURITY_AUTOMATION/
├── README.md
├── LOG_ANALYZER/
│   ├── log_parser.py          # Generic log parser (JSON, CSV, Syslog)
│   ├── firewall_log_analyzer.py
│   ├── windows_event_analyzer.py
│   └── ioc_extractor.py       # Extract IPs, domains, hashes from logs
├── ALERT_AGGREGATOR/
│   ├── alert_collector.py     # Collect alerts from multiple sources
│   ├── alert_normalizer.py    # Normalize to common format
│   ├── alert_deduplicator.py  # Remove duplicate alerts
│   └── alert_enricher.py      # Enrich with threat intelligence
├── API_INTEGRATIONS/
│   ├── virustotal_api.py      # VirusTotal API wrapper
│   ├── shodan_api.py          # Shodan API wrapper
│   ├── otx_api.py             # AlienVault OTX API wrapper
│   └── abuseipdb_api.py       # AbuseIPDB API wrapper
└── ORCHESTRATION/
    ├── playbook_runner.py     # Execute automated playbooks
    ├── scheduled_tasks.py     # Task scheduling
    └── notification_manager.py # Email, Slack, Teams alerts
```

---

## 🐍 Sample Automation Script: IOC Extractor

```python
#!/usr/bin/env python3
"""
IOC Extractor — Extract Indicators of Compromise from log files.
Usage: python ioc_extractor.py --input security.log --output iocs.json
"""

import re
import json
import argparse
from typing import List, Dict

class IOCExtractor:
    def __init__(self):
        self.iocs = {
            'ip_addresses': set(),
            'domains': set(),
            'urls': set(),
            'email_addresses': set(),
            'md5_hashes': set(),
            'sha256_hashes': set()
        }
    
    # IP: 0.0.0.0 - 255.255.255.255
    IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    # Domain: example.com
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    # URL: http:// or https://
    URL_PATTERN = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    # MD5: 32 hex characters
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    # SHA256: 64 hex characters
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    
    def extract(self, text: str) -> Dict[str, list]:
        self.iocs['ip_addresses'] = set(re.findall(self.IP_PATTERN, text))
        self.iocs['domains'] = set(re.findall(self.DOMAIN_PATTERN, text))
        self.iocs['urls'] = set(re.findall(self.URL_PATTERN, text))
        self.iocs['md5_hashes'] = set(re.findall(self.MD5_PATTERN, text))
        self.iocs['sha256_hashes'] = set(re.findall(self.SHA256_PATTERN, text))
        return {k: list(v) for k, v in self.iocs.items()}

def main():
    parser = argparse.ArgumentParser(description='Extract IOCs from log files')
    parser.add_argument('--input', required=True, help='Input log file')
    parser.add_argument('--output', required=True, help='Output JSON file')
    args = parser.parse_args()
    
    with open(args.input, 'r') as f:
        content = f.read()
    
    extractor = IOCExtractor()
    iocs = extractor.extract(content)
    
    with open(args.output, 'w') as f:
        json.dump(iocs, f, indent=2)
    
    print(f"[+] Extracted IOCs saved to {args.output}")
    print(f"    IPs: {len(iocs['ip_addresses'])}")
    print(f"    Domains: {len(iocs['domains'])}")
    print(f"    URLs: {len(iocs['urls'])}")
    print(f"    MD5s: {len(iocs['md5_hashes'])}")
    print(f"    SHA256s: {len(iocs['sha256_hashes'])}")

if __name__ == '__main__':
    main()
```

---

## 🚀 Quick Start

```bash
# Extract IOCs from firewall logs
python 04_SECURITY_AUTOMATION/LOG_ANALYZER/ioc_extractor.py \
  --input firewall.log --output iocs.json

# Enrich IPs with VirusTotal
python 04_SECURITY_AUTOMATION/API_INTEGRATIONS/virustotal_api.py \
  --input iocs.json --output enriched_iocs.json

# Aggregate and deduplicate alerts
python 04_SECURITY_AUTOMATION/ALERT_AGGREGATOR/alert_collector.py \
  --sources wazuh,cloudtrail,guardduty
```

---

## 📌 Learning Progression

| Level | Skill | Activity |
|-------|-------|----------|
| L1 | Log Parsing | Write regex-based log parser |
| L2 | IOC Extraction | Build multi-format IOC extractor |
| L3 | API Integration | Connect to VirusTotal, Shodan |
| L4 | Orchestration | Build automated triage playbooks |

---

**Resume Value:** "Automated security operations workflows using Python, reducing manual log analysis time by 80% and enabling real-time threat enrichment from 5+ intelligence sources."
