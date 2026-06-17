#!/usr/bin/env python3
"""
Log Parser — Multi-format log parser with IOC extraction and threat enrichment.
Usage: python log_parser.py --input firewall.log --format syslog --output parsed_logs.json

Author: Samuel Nwokemodo
GitHub: Cybersecurity Lab
"""

import re
import json
import argparse
import csv
import datetime
import os
from typing import List, Dict, Optional
from collections import Counter

class LogParser:
    """Multi-format security log parser."""
    
    def __init__(self):
        self.parsed_entries = []
        self.statistics = {
            'total_lines': 0,
            'parsed_lines': 0,
            'error_lines': 0,
            'severity_counts': Counter(),
            'source_counts': Counter(),
            'event_counts': Counter()
        }
    
    def parse_file(self, filepath: str, log_format: str = 'auto') -> List[Dict]:
        """
        Parse log file based on format.
        
        Supported formats: syslog, json, csv, apache, windows_event, firewall, auto
        """
        if not os.path.exists(filepath):
            print(f"[!] File not found: {filepath}")
            return []
        
        if log_format == 'auto':
            log_format = self._detect_format(filepath)
        
        parsers = {
            'syslog': self._parse_syslog,
            'json': self._parse_json_log,
            'csv': self._parse_csv_log,
            'apache': self._parse_apache_log,
            'firewall': self._parse_syslog,  # Many firewall logs use syslog format
        }
        
        parser = parsers.get(log_format, self._parse_syslog)
        
        print(f"[*] Parsing {filepath} as {log_format} format...")
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                self.statistics['total_lines'] += 1
                line = line.strip()
                if not line:
                    continue
                
                try:
                    entry = parser(line, line_num)
                    if entry:
                        self.parsed_entries.append(entry)
                        self.statistics['parsed_lines'] += 1
                        
                        # Update statistics
                        severity = entry.get('severity', 'unknown')
                        self.statistics['severity_counts'][severity] += 1
                        
                        source = entry.get('source_ip', entry.get('hostname', 'unknown'))
                        self.statistics['source_counts'][source] += 1
                        
                        event = entry.get('event_type', entry.get('event_id', 'unknown'))
                        self.statistics['event_counts'][event] += 1
                except Exception as e:
                    self.statistics['error_lines'] += 1
                    if line_num <= 5:  # Show first 5 errors only
                        print(f"[!] Parse error line {line_num}: {e}")
        
        print(f"[+] Parsed {self.statistics['parsed_lines']}/{self.statistics['total_lines']} lines")
        return self.parsed_entries
    
    def _detect_format(self, filepath: str) -> str:
        """Auto-detect log format from file extension and content."""
        ext = os.path.splitext(filepath)[1].lower()
        
        if ext == '.json':
            return 'json'
        elif ext == '.csv':
            return 'csv'
        
        # Read first few lines to detect format
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            sample = [next(f).strip() for _ in range(5) if f.readline()]
        
        for line in sample:
            if line.startswith('{') or line.startswith('['):
                return 'json'
            elif re.match(r'\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}', line):
                return 'syslog'
            elif re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line):
                return 'firewall'
            elif ' - - [' in line:
                return 'apache'
        
        return 'syslog'
    
    def _parse_syslog(self, line: str, line_num: int) -> Optional[Dict]:
        """Parse syslog format: <timestamp> <hostname> <process>[<pid>]: <message>"""
        pattern = r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$'
        match = re.match(pattern, line)
        
        if match:
            timestamp, hostname, process, pid, message = match.groups()
            
            entry = {
                'timestamp': timestamp,
                'hostname': hostname,
                'process': process,
                'pid': pid,
                'message': message,
                'severity': self._infer_severity(message),
                'event_type': self._infer_event_type(message),
                'line_number': line_num,
                'raw': line
            }
            
            # Extract potential IOCs
            iocs = self._extract_iocs(message)
            entry.update(iocs)
            
            return entry
        
        return None
    
    def _parse_json_log(self, line: str, line_num: int) -> Optional[Dict]:
        """Parse JSON format log entry."""
        try:
            entry = json.loads(line)
            entry['line_number'] = line_num
            entry['raw'] = line
            
            if 'message' in entry:
                iocs = self._extract_iocs(str(entry['message']))
                entry.update(iocs)
            
            return entry
        except json.JSONDecodeError:
            return None
    
    def _parse_csv_log(self, line: str, line_num: int) -> Optional[Dict]:
        """Parse CSV format log entry."""
        # Handle CSV with potential quoted fields
        reader = csv.reader([line])
        fields = next(reader)
        
        entry = {
            'fields': fields,
            'line_number': line_num,
            'raw': line,
            'severity': 'info',
            'event_type': 'csv_entry'
        }
        
        # Concatenate all fields for IOC extraction
        combined = ' '.join(fields)
        iocs = self._extract_iocs(combined)
        entry.update(iocs)
        
        return entry
    
    def _parse_apache_log(self, line: str, line_num: int) -> Optional[Dict]:
        """Parse Apache access log format."""
        pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\S+)'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp, request, status, size = match.groups()
            
            entry = {
                'source_ip': ip,
                'timestamp': timestamp,
                'request': request,
                'status_code': int(status),
                'size': size if size != '-' else 0,
                'severity': 'critical' if int(status) >= 500 else 'error' if int(status) >= 400 else 'info',
                'event_type': f'http_{status}',
                'line_number': line_num,
                'raw': line
            }
            
            iocs = self._extract_iocs(line)
            entry.update(iocs)
            
            return entry
        
        return None
    
    def _infer_severity(self, message: str) -> str:
        """Infer severity from log message content."""
        message_lower = message.lower()
        
        critical_indicators = ['critical', 'emergency', 'panic', 'intrusion', 'exploit']
        error_indicators = ['error', 'failed', 'failure', 'denied', 'blocked', 'attack']
        warning_indicators = ['warn', 'warning', 'unusual', 'suspicious']
        
        for indicator in critical_indicators:
            if indicator in message_lower:
                return 'critical'
        for indicator in error_indicators:
            if indicator in message_lower:
                return 'error'
        for indicator in warning_indicators:
            if indicator in message_lower:
                return 'warning'
        
        return 'info'
    
    def _infer_event_type(self, message: str) -> str:
        """Infer event type from log message."""
        message_lower = message.lower()
        
        if any(w in message_lower for w in ['login', 'authentication', 'auth', 'password']):
            return 'authentication'
        elif any(w in message_lower for w in ['firewall', 'blocked', 'dropped', 'denied']):
            return 'firewall_block'
        elif any(w in message_lower for w in ['malware', 'virus', 'trojan', 'ransomware']):
            return 'malware_detection'
        elif any(w in message_lower for w in ['scan', 'port', 'nmap']):
            return 'port_scan'
        elif any(w in message_lower for w in ['error', 'exception', 'crash']):
            return 'system_error'
        else:
            return 'informational'
    
    def _extract_iocs(self, text: str) -> Dict:
        """Extract Indicators of Compromise from text."""
        iocs = {}
        
        # IP addresses (IPv4)
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        if ips:
            iocs['ioc_ips'] = list(set(ips))
        
        # Domains
        domains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', text)
        if domains:
            iocs['ioc_domains'] = list(set(domains))
        
        # URLs
        urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', text)
        if urls:
            iocs['ioc_urls'] = list(set(urls))
        
        # MD5 hashes
        md5 = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
        if md5:
            iocs['ioc_md5'] = list(set(md5))
        
        # SHA256 hashes
        sha256 = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
        if sha256:
            iocs['ioc_sha256'] = list(set(sha256))
        
        return iocs
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate analysis report from parsed logs."""
        report = {
            'statistics': {
                'total_lines': self.statistics['total_lines'],
                'parsed_lines': self.statistics['parsed_lines'],
                'error_count': self.statistics['error_lines'],
                'parse_success_rate': f"{(self.statistics['parsed_lines'] / max(self.statistics['total_lines'], 1)) * 100:.1f}%"
            },
            'severity_breakdown': dict(self.statistics['severity_counts']),
            'top_sources': dict(self.statistics['source_counts'].most_common(10)),
            'top_events': dict(self.statistics['event_counts'].most_common(10)),
            'critical_events': [e for e in self.parsed_entries if e.get('severity') == 'critical'],
            'iocs_found': self._aggregate_iocs()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Report saved to {output_file}")
        
        return report
    
    def _aggregate_iocs(self) -> Dict:
        """Aggregate all IOCs found across all parsed entries."""
        all_iocs = {
            'ip_addresses': set(),
            'domains': set(),
            'urls': set(),
            'md5_hashes': set(),
            'sha256_hashes': set()
        }
        
        for entry in self.parsed_entries:
            for key in all_iocs:
                ioc_key = f'ioc_{key.replace("_hashes", "").replace("_addresses", "s")}'
                if ioc_key in entry:
                    all_iocs[key].update(entry[ioc_key])
        
        return {k: list(v)[:100] for k, v in all_iocs.items() if v}

def main():
    parser = argparse.ArgumentParser(description='Multi-format Security Log Parser')
    parser.add_argument('--input', required=True, help='Input log file')
    parser.add_argument('--format', choices=['auto', 'syslog', 'json', 'csv', 'apache', 'firewall'],
                       default='auto', help='Log format (auto-detect by default)')
    parser.add_argument('--output', default='parsed_report.json', help='Output report file')
    
    args = parser.parse_args()
    
    log_parser = LogParser()
    entries = log_parser.parse_file(args.input, args.format)
    
    print(f"\n[*] Generating analysis report...")
    report = log_parser.generate_report(args.output)
    
    print("\n" + "="*60)
    print("PARSING SUMMARY")
    print("="*60)
    print(f"Total Lines:     {report['statistics']['total_lines']}")
    print(f"Parsed:          {report['statistics']['parsed_lines']}")
    print(f"Errors:          {report['statistics']['error_count']}")
    print(f"Success Rate:    {report['statistics']['parse_success_rate']}")
    print(f"\nSeverity Breakdown:")
    for severity, count in report['severity_breakdown'].items():
        print(f"  {severity.capitalize():10}: {count}")
    
    if report['iocs_found']:
        print(f"\nIOCs Extracted:")
        for ioc_type, iocs in report['iocs_found'].items():
            if iocs:
                print(f"  {ioc_type.replace('_', ' ').title():15}: {len(iocs)} found")
    
    print("="*60)

if __name__ == '__main__':
    main()
