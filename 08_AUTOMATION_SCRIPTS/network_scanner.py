#!/usr/bin/env python3
"""
Network Scanner — Automated Nmap wrapper for vulnerability assessment.
Usage: python network_scanner.py --target 10.0.0.0/24 --output scan_results.json

Author: Samuel Nwokemodo
GitHub: Cybersecurity Lab
"""

import subprocess
import json
import argparse
import xml.etree.ElementTree as ET
import datetime
import os
from typing import List, Dict

class NetworkScanner:
    def __init__(self, target: str, output_dir: str = "./scan_results"):
        self.target = target
        self.output_dir = output_dir
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def run_nmap_scan(self, scan_type: str = "quick") -> str:
        """
        Run Nmap scan based on type.
        
        Args:
            scan_type: 'quick' - top ports, 'full' - all ports, 
                      'vuln' - vulnerability scripts, 'os' - OS detection
        
        Returns:
            Path to output XML file
        """
        output_file = f"{self.output_dir}/scan_{self.timestamp}.xml"
        
        scan_profiles = {
            'quick': ['-T4', '--top-ports', '1000', '--open'],
            'full': ['-T4', '-p-', '--open', '--min-rate', '1000'],
            'vuln': ['-T4', '--top-ports', '1000', '--open', '-sV', '--script', 'vuln'],
            'os': ['-T4', '--top-ports', '1000', '--open', '-O', '-sV'],
            'stealth': ['-sS', '-T2', '--top-ports', '500'],
        }
        
        if scan_type not in scan_profiles:
            print(f"[!] Unknown scan type: {scan_type}. Using 'quick'.")
            scan_type = 'quick'
        
        cmd = ['nmap', '-oX', output_file] + scan_profiles[scan_type] + [self.target]
        
        print(f"[*] Running {scan_type} scan on {self.target}...")
        print(f"[*] Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            if result.returncode != 0:
                print(f"[!] Nmap error: {result.stderr}")
                return None
            
            print(f"[+] Scan complete. Results saved to {output_file}")
            return output_file
        
        except subprocess.TimeoutExpired:
            print("[!] Scan timed out after 30 minutes.")
            return None
        except FileNotFoundError:
            print("[!] Nmap not found. Please install Nmap first.")
            return None
    
    def parse_nmap_xml(self, xml_file: str) -> List[Dict]:
        """
        Parse Nmap XML output to structured JSON.
        
        Returns:
            List of host dictionaries with open ports and services
        """
        hosts = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                host_info = {
                    'ip': None,
                    'hostname': None,
                    'state': None,
                    'os': None,
                    'ports': [],
                    'vulnerabilities': []
                }
                
                # IP Address
                address = host.find('address')
                if address is not None:
                    host_info['ip'] = address.get('addr')
                
                # Hostnames
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    for hostname in hostnames.findall('hostname'):
                        host_info['hostname'] = hostname.get('name')
                
                # Status
                status = host.find('status')
                if status is not None:
                    host_info['state'] = status.get('state')
                
                # OS Detection
                os_elem = host.find('os')
                if os_elem is not None:
                    for os_match in os_elem.findall('osmatch'):
                        if host_info['os'] is None:
                            host_info['os'] = os_match.get('name')
                
                # Open Ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_info = {
                            'port': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'state': None,
                            'service': None,
                            'version': None
                        }
                        
                        state = port.find('state')
                        if state is not None:
                            port_info['state'] = state.get('state')
                        
                        service = port.find('service')
                        if service is not None:
                            port_info['service'] = service.get('name')
                            port_info['version'] = f"{service.get('product', '')} {service.get('version', '')}".strip()
                        
                        # Vulnerability scripts
                        for script in port.findall('script'):
                            port_info.setdefault('scripts', []).append({
                                'id': script.get('id'),
                                'output': script.get('output')
                            })
                        
                        host_info['ports'].append(port_info)
                
                hosts.append(host_info)
        
        except ET.ParseError as e:
            print(f"[!] XML parsing error: {e}")
        except FileNotFoundError:
            print(f"[!] XML file not found: {xml_file}")
        
        return hosts
    
    def generate_report(self, hosts: List[Dict], output_format: str = "json"):
        """Generate scan report."""
        
        report = {
            'scan_metadata': {
                'target': self.target,
                'timestamp': self.timestamp,
                'total_hosts': len(hosts),
                'total_open_ports': sum(len(h['ports']) for h in hosts)
            },
            'hosts': hosts,
            'summary': {
                'hosts_up': len([h for h in hosts if h['state'] == 'up']),
                'hosts_down': len([h for h in hosts if h['state'] == 'down']),
                'total_ports_found': sum(len(h['ports']) for h in hosts),
                'services_found': list(set(
                    p['service'] for h in hosts for p in h['ports'] if p['service']
                ))
            }
        }
        
        if output_format == "json":
            output_file = f"{self.output_dir}/report_{self.timestamp}.json"
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] JSON report saved to {output_file}")
        
        return report
    
    def print_summary(self, report: Dict):
        """Print scan summary to console."""
        summary = report['summary']
        
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target:        {self.target}")
        print(f"Timestamp:     {self.timestamp}")
        print(f"Hosts Found:   {summary['hosts_up']} up / {summary['hosts_down']} down")
        print(f"Open Ports:    {summary['total_ports_found']}")
        print(f"Services:      {', '.join(summary['services_found'][:10])}")
        
        if len(summary['services_found']) > 10:
            print(f"  ... and {len(summary['services_found']) - 10} more")
        
        print("="*60)
        
        # Show top findings
        print("\nOPEN PORTS BY HOST:")
        for host in report['hosts']:
            if host['ports']:
                print(f"\n  {host['ip']} ({host.get('hostname', 'N/A')})")
                for port in host['ports'][:10]:
                    print(f"    {port['port']}/{port['protocol']}  {port['state']:8}  {port['service']} {port.get('version', '')}")
                if len(host['ports']) > 10:
                    print(f"    ... and {len(host['ports']) - 10} more ports")

def main():
    parser = argparse.ArgumentParser(description='Automated Network Scanner (Nmap Wrapper)')
    parser.add_argument('--target', required=True, help='Target IP, CIDR, or range')
    parser.add_argument('--type', choices=['quick', 'full', 'vuln', 'os', 'stealth'],
                       default='quick', help='Scan type')
    parser.add_argument('--output', default='./scan_results', help='Output directory')
    parser.add_argument('--format', choices=['json'], default='json', help='Output format')
    
    args = parser.parse_args()
    
    scanner = NetworkScanner(args.target, args.output)
    
    print(f"[*] Network Scanner Starting...")
    print(f"[*] Target: {args.target}")
    print(f"[*] Type: {args.type}")
    
    xml_file = scanner.run_nmap_scan(args.type)
    
    if xml_file:
        hosts = scanner.parse_nmap_xml(xml_file)
        report = scanner.generate_report(hosts, args.format)
        scanner.print_summary(report)
    else:
        print("[!] Scan failed. Check Nmap installation and target.")

if __name__ == '__main__':
    main()
