#!/usr/bin/env python3
"""
Alert Manager — Alert aggregation, normalization, deduplication, and enrichment.
Usage: python alert_manager.py --config alerts_config.yml --output enriched_alerts.json

Author: Samuel Nwokemodo
GitHub: Cybersecurity Lab
"""

import json
import argparse
import datetime
import os
import hashlib
from typing import List, Dict, Optional, Set
from collections import defaultdict, Counter

class AlertManager:
    """Enterprise alert aggregation and management system."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.alerts = []
        self.enriched_alerts = []
        self.deduplication_cache: Set[str] = set()
        self.statistics = {
            'total_alerts': 0,
            'unique_alerts': 0,
            'duplicates_removed': 0,
            'severity_counts': Counter(),
            'source_counts': Counter(),
            'type_counts': Counter()
        }
        
        self.severity_order = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
    
    def load_alerts(self, filepath: str) -> List[Dict]:
        """Load alerts from JSON file."""
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return []
        
        with open(filepath, 'r') as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    self.alerts = data
                elif isinstance(data, dict):
                    self.alerts = data.get('alerts', [data])
                else:
                    print(f"[!] Unknown data format in {filepath}")
                    return []
                
                print(f"[+] Loaded {len(self.alerts)} alerts from {filepath}")
                self.statistics['total_alerts'] = len(self.alerts)
                return self.alerts
            except json.JSONDecodeError as e:
                print(f"[!] JSON parse error: {e}")
                return []
    
    def add_alert(self, alert: Dict) -> None:
        """Add single alert to the collection."""
        self.alerts.append(alert)
        self.statistics['total_alerts'] += 1
    
    def normalize_alert(self, alert: Dict) -> Dict:
        """
        Normalize alert to standard schema.
        
        Standard schema:
        - id: Unique identifier
        - timestamp: ISO 8601 format
        - source: Source system (e.g., 'wazuh', 'guardduty', 'custom')
        - title: Alert title/summary
        - description: Detailed description
        - severity: critical/high/medium/low/info
        - event_type: Type of security event
        - source_ip: Originating IP
        - destination_ip: Target IP
        - source_hostname: Source host
        - destination_hostname: Target host
        - raw: Original alert data
        """
        normalized = {
            'id': alert.get('id', alert.get('alert_id', 
                     hashlib.md5(json.dumps(alert, sort_keys=True).encode()).hexdigest()[:12])),
            'timestamp': alert.get('timestamp', alert.get('time', alert.get('@timestamp', 
                         datetime.datetime.now().isoformat()))),
            'source': alert.get('source', alert.get('vendor', 'unknown')),
            'title': alert.get('title', alert.get('name', alert.get('alert_title', 'Untitled Alert'))),
            'description': alert.get('description', alert.get('message', alert.get('desc', ''))),
            'severity': self._normalize_severity(alert.get('severity', alert.get('level', 'medium'))),
            'event_type': alert.get('event_type', alert.get('type', alert.get('category', 'unknown'))),
            'source_ip': alert.get('source_ip', alert.get('src_ip', alert.get('sourceAddress', ''))),
            'destination_ip': alert.get('destination_ip', alert.get('dst_ip', alert.get('destAddress', ''))),
            'source_hostname': alert.get('source_hostname', alert.get('src_host', alert.get('host', ''))),
            'destination_hostname': alert.get('destination_hostname', alert.get('dst_host', '')),
            'status': alert.get('status', 'new'),
            'tags': alert.get('tags', []),
            'raw': alert
        }
        
        return normalized
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to standard levels."""
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info',
            'informational': 'info',
            '1': 'critical',
            '2': 'high',
            '3': 'medium',
            '4': 'low',
            '5': 'info',
            'emergency': 'critical',
            'alert': 'high',
            'warning': 'medium',
            'notice': 'low',
            'debug': 'info'
        }
        
        normalized = severity_map.get(str(severity).lower(), 'medium')
        return normalized
    
    def deduplicate(self) -> List[Dict]:
        """
        Remove duplicate alerts based on content fingerprint.
        Returns deduplicated list.
        """
        unique_alerts = []
        
        for alert in self.alerts:
            # Create fingerprint from key fields
            fingerprint_data = {
                'title': alert.get('title', ''),
                'source': alert.get('source', ''),
                'event_type': alert.get('event_type', ''),
                'source_ip': alert.get('source_ip', ''),
                'description': alert.get('description', '')[:100]  # Truncate for dedup
            }
            
            fingerprint = hashlib.sha256(
                json.dumps(fingerprint_data, sort_keys=True).encode()
            ).hexdigest()
            
            if fingerprint not in self.deduplication_cache:
                self.deduplication_cache.add(fingerprint)
                unique_alerts.append(alert)
            else:
                self.statistics['duplicates_removed'] += 1
        
        self.alerts = unique_alerts
        self.statistics['unique_alerts'] = len(self.alerts)
        
        print(f"[+] Deduplication: {self.statistics['duplicates_removed']} duplicates removed")
        print(f"[+] Unique alerts: {self.statistics['unique_alerts']}")
        
        return self.alerts
    
    def enrich_alert(self, alert: Dict) -> Dict:
        """
        Enrich alert with additional context and metadata.
        
        Adds:
        - enrichment_timestamp: When enrichment was performed
        - risk_score: Computed risk score
        - mitre_attack: MITRE ATT&CK mappings
        - severity_score: Numeric severity for sorting
        """
        enriched = dict(alert)
        
        # Add enrichment metadata
        enriched['enrichment_timestamp'] = datetime.datetime.now().isoformat()
        enriched['severity_score'] = self.severity_order.get(enriched.get('severity', 'medium'), 2)
        
        # Compute risk score based on severity and other factors
        risk_score = self._compute_risk_score(enriched)
        enriched['risk_score'] = risk_score
        
        # Add priority label
        if risk_score >= 8:
            enriched['priority'] = 'P1 - Immediate Response Required'
        elif risk_score >= 6:
            enriched['priority'] = 'P2 - Respond within 1 hour'
        elif risk_score >= 4:
            enriched['priority'] = 'P3 - Respond within 4 hours'
        elif risk_score >= 2:
            enriched['priority'] = 'P4 - Respond within 24 hours'
        else:
            enriched['priority'] = 'P5 - Monitor / Low Priority'
        
        # MITRE ATT&CK mapping suggestions
        enriched['mitre_mappings'] = self._suggest_mitre_mapping(enriched)
        
        # Suggested actions
        enriched['suggested_actions'] = self._suggest_actions(enriched)
        
        return enriched
    
    def _compute_risk_score(self, alert: Dict) -> float:
        """Compute risk score based on various factors."""
        score = 0.0
        
        # Base score from severity
        severity_scores = {
            'critical': 8.0,
            'high': 6.0,
            'medium': 4.0,
            'low': 2.0,
            'info': 0.5
        }
        score += severity_scores.get(alert.get('severity', 'medium'), 2.0)
        
        # Source type bonus
        source_bonus = {
            'wazuh': 0.5,
            'guardduty': 0.5,
            'crowdstrike': 0.5,
            'sentinel': 0.3,
            'custom': 0.0
        }
        score += source_bonus.get(alert.get('source', ''), 0.0)
        
        # Event type bonus
        critical_events = ['ransomware', 'lateral_movement', 'exfiltration', 
                          'privilege_escalation', 'command_and_control']
        if any(event in str(alert.get('event_type', '')).lower() for event in critical_events):
            score += 2.0
        
        # Cap at 10
        return min(score, 10.0)
    
    def _suggest_mitre_mapping(self, alert: Dict) -> List[Dict]:
        """Suggest MITRE ATT&CK mappings based on alert type."""
        event_type = str(alert.get('event_type', '')).lower()
        
        mapping_rules = {
            'ransomware': [{'tactic': 'Impact', 'technique': 'T1486', 'name': 'Data Encrypted for Impact'}],
            'phishing': [{'tactic': 'Initial Access', 'technique': 'T1566', 'name': 'Phishing'}],
            'authentication': [{'tactic': 'Credential Access', 'technique': 'T1110', 'name': 'Brute Force'}],
            'port_scan': [{'tactic': 'Discovery', 'technique': 'T1046', 'name': 'Network Service Scanning'}],
            'malware': [{'tactic': 'Execution', 'technique': 'T1204', 'name': 'User Execution'}],
            'firewall': [{'tactic': 'Defense Evasion', 'technique': 'T1562', 'name': 'Impair Defenses'}],
            'privilege': [{'tactic': 'Privilege Escalation', 'technique': 'T1068', 'name': 'Exploitation for Privilege Escalation'}],
            'lateral': [{'tactic': 'Lateral Movement', 'technique': 'T1021', 'name': 'Remote Services'}],
            'exfil': [{'tactic': 'Exfiltration', 'technique': 'T1048', 'name': 'Exfiltration Over Alternative Protocol'}],
            'c2': [{'tactic': 'Command and Control', 'technique': 'T1071', 'name': 'Application Layer Protocol'}]
        }
        
        for key, mapping in mapping_rules.items():
            if key in event_type:
                return mapping
        
        return [{'tactic': 'Unknown', 'technique': 'N/A', 'name': 'Unclassified Event'}]
    
    def _suggest_actions(self, alert: Dict) -> List[str]:
        """Suggest response actions based on alert type and severity."""
        severity = alert.get('severity', 'medium')
        event_type = str(alert.get('event_type', '')).lower()
        
        actions = []
        
        if severity in ('critical', 'high'):
            actions.append("IMMEDIATE: Escalate to senior analyst / incident response team")
            actions.append("IMMEDIATE: Isolate affected systems if active threat detected")
        
        if 'ransomware' in event_type:
            actions.extend([
                "IMMEDIATE: Disconnect affected systems from network",
                "IMMEDIATE: Preserve forensic evidence (memory capture, disk imaging)",
                "Identify patient zero and infection vector",
                "Check backup integrity before restoration"
            ])
        elif 'phishing' in event_type:
            actions.extend([
                "Block sender domain/IP at email gateway",
                "Check if other users received similar emails",
                "Reset affected user's credentials",
                "Conduct user awareness training"
            ])
        elif 'authentication' in event_type:
            actions.extend([
                "Verify if authentication was successful vs failed",
                "Check source IP against threat intelligence",
                "Enforce MFA if not already enabled",
                "Consider temporary account lockout"
            ])
        elif 'malware' in event_type:
            actions.extend([
                "Isolate affected host from network",
                "Run full EDR scan on affected system",
                "Check for lateral movement indicators",
                "Review recent process executions"
            ])
        else:
            actions.extend([
                "Review alert details and correlate with other sources",
                "Determine if alert is true positive or false positive",
                "Document findings for future reference",
                "Update detection rules if needed"
            ])
        
        return actions
    
    def process_pipeline(self) -> List[Dict]:
        """Run full processing pipeline: normalize → deduplicate → enrich."""
        print("\n[*] Starting alert processing pipeline...")
        
        # Step 1: Normalize
        print("[*] Step 1/3: Normalizing alerts...")
        normalized_alerts = [self.normalize_alert(a) for a in self.alerts]
        self.alerts = normalized_alerts
        
        # Step 2: Deduplicate
        print("[*] Step 2/3: Deduplicating alerts...")
        self.deduplicate()
        
        # Step 3: Enrich
        print("[*] Step 3/3: Enriching alerts...")
        self.enriched_alerts = [self.enrich_alert(a) for a in self.alerts]
        
        # Update statistics
        for alert in self.enriched_alerts:
            self.statistics['severity_counts'][alert.get('severity', 'unknown')] += 1
            self.statistics['source_counts'][alert.get('source', 'unknown')] += 1
            self.statistics['type_counts'][alert.get('event_type', 'unknown')] += 1
        
        print(f"[+] Pipeline complete: {len(self.enriched_alerts)} enriched alerts")
        return self.enriched_alerts
    
    def export_alerts(self, filepath: str, format: str = 'json') -> None:
        """Export processed alerts to file."""
        output = {
            'metadata': {
                'generated_at': datetime.datetime.now().isoformat(),
                'total_alerts': len(self.enriched_alerts),
                'statistics': dict(self.statistics)
            },
            'alerts': self.enriched_alerts
        }
        
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        
        print(f"[+] Exported {len(self.enriched_alerts)} alerts to {filepath}")
    
    def print_alert_summary(self, limit: int = 10) -> None:
        """Print summary of processed alerts."""
        if not self.enriched_alerts:
            print("[!] No alerts to display. Run process_pipeline() first.")
            return
        
        # Sort by risk score (highest first)
        sorted_alerts = sorted(self.enriched_alerts, 
                              key=lambda x: x.get('risk_score', 0), reverse=True)
        
        print("\n" + "="*80)
        print("ALERT SUMMARY — Top Priority Alerts")
        print("="*80)
        print(f"Total Alerts: {len(self.enriched_alerts)}")
        print(f"Critical: {self.statistics['severity_counts'].get('critical', 0)}  "
              f"High: {self.statistics['severity_counts'].get('high', 0)}  "
              f"Medium: {self.statistics['severity_counts'].get('medium', 0)}")
        print("="*80)
        
        for i, alert in enumerate(sorted_alerts[:limit]):
            print(f"\n[{i+1}] {alert.get('title', 'Untitled')}")
            print(f"    Priority: {alert.get('priority', 'N/A')}")
            print(f"    Risk: {alert.get('risk_score', 0):.1f}/10  |  "
                  f"Severity: {alert.get('severity', 'N/A').upper()}  |  "
                  f"Source: {alert.get('source', 'N/A')}")
            print(f"    Type: {alert.get('event_type', 'N/A')}")
            print(f"    Source IP: {alert.get('source_ip', 'N/A')}")
            
            if alert.get('suggested_actions'):
                print(f"    Suggested Action: {alert['suggested_actions'][0][:80]}...")
        
        print("\n" + "="*80)

def main():
    parser = argparse.ArgumentParser(description='Enterprise Alert Manager')
    parser.add_argument('--input', required=True, help='Input alerts JSON file')
    parser.add_argument('--output', default='enriched_alerts.json', help='Output file')
    parser.add_argument('--limit', type=int, default=10, help='Summary display limit')
    
    args = parser.parse_args()
    
    manager = AlertManager()
    manager.load_alerts(args.input)
    manager.process_pipeline()
    manager.export_alerts(args.output)
    manager.print_alert_summary(args.limit)

if __name__ == '__main__':
    main()
