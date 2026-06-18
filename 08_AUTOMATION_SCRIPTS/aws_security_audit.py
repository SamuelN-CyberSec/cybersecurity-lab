#!/usr/bin/env python3
"""
AWS Security Auditor — Automated security audit for AWS environments.
Audits: S3, IAM, Security Groups, CloudTrail, GuardDuty, Config, Encryption
Usage: python aws_security_audit.py --profile production --region us-east-1

Author: Samuel Nwokemodo
GitHub: Cybersecurity Lab
"""

import json
import argparse
import datetime
import os
import sys
from typing import Dict, List, Optional, Any

class AWSSecurityAuditor:
    """AWS security configuration auditor."""
    
    def __init__(self, profile: str = 'default', region: str = 'us-east-1'):
        self.profile = profile
        self.region = region
        self.findings = []
        self.compliance_score = {
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0
        }
        
        # Check if boto3 is available
        try:
            import boto3
            self.boto3 = boto3
            self.session = boto3.Session(profile_name=profile, region_name=region)
            self.client_cache = {}
            self.offline_mode = False
            print(f"[*] AWS session initialized for profile '{profile}' in {region}")
        except ImportError:
            print("[!] boto3 not installed. Install with: pip install boto3")
            print("[!] Running in offline/demo mode with simulated checks.")
            self.boto3 = None
            self.session = None
            self.offline_mode = True
    
    def _get_client(self, service: str):
        """Get or cache AWS client."""
        if self.session is None:
            return None
        if service not in self.client_cache:
            self.client_cache[service] = self.session.client(service)
        return self.client_cache[service]
    
    def _add_finding(self, service: str, check: str, status: str, 
                     severity: str, details: str, resource_id: str = None):
        """Add a security finding."""
        finding = {
            'service': service,
            'check': check,
            'status': status,
            'severity': severity,
            'details': details,
            'resource_id': resource_id,
            'timestamp': datetime.datetime.now().isoformat(),
            'remediation': self._get_remediation(service, check, status)
        }
        self.findings.append(finding)
        
        self.compliance_score['total_checks'] += 1
        if status == 'PASS':
            self.compliance_score['passed'] += 1
        elif status == 'FAIL':
            self.compliance_score['failed'] += 1
        else:
            self.compliance_score['warnings'] += 1
    
    def _get_remediation(self, service: str, check: str, status: str) -> str:
        """Get remediation guidance."""
        if status == 'PASS':
            return "No action required."
        
        remediations = {
            'S3': {
                'public_access': "Enable S3 Block Public Access at account level. Review bucket policies.",
                'encryption': "Enable default encryption (SSE-S3 or SSE-KMS) on all buckets.",
                'logging': "Enable S3 server access logging on all buckets.",
                'versioning': "Enable versioning for data protection and recovery."
            },
            'IAM': {
                'root_keys': "Delete root user access keys. Use IAM roles instead.",
                'mfa': "Enable MFA on root account and all privileged users.",
                'unused_keys': "Rotate or remove unused access keys.",
                'overly_permissive': "Review and restrict IAM policies to least privilege.",
                'password_policy': "Enforce strong password policy with expiration."
            },
            'CloudTrail': {
                'disabled': "Enable CloudTrail in all regions. Enable log file validation.",
                'not_logging': "Verify CloudTrail is actively logging to S3/CloudWatch."
            },
            'GuardDuty': {
                'disabled': "Enable GuardDuty in all regions for threat detection.",
                'not_finding': "Review GuardDuty findings regularly."
            },
            'Config': {
                'disabled': "Enable AWS Config for compliance monitoring.",
                'no_rules': "Add AWS managed Config rules (e.g., CIS benchmarks)."
            },
            'EC2': {
                'sg_public_ssh': "Restrict Security Group SSH (22) to specific IPs only.",
                'sg_public_rdp': "Restrict Security Group RDP (3389) to specific IPs only.",
                'unencrypted_volume': "Enable EBS volume encryption.",
                'public_instance': "Move instance to private subnet or review justification."
            }
        }
        
        service_remediation = remediations.get(service, {})
        return service_remediation.get(check, "Review AWS documentation for remediation steps.")
    
    def audit_s3(self) -> None:
        """Audit S3 bucket security."""
        print("[*] Auditing S3...")
        
        if self.offline_mode:
            self._add_finding('S3', 'public_access', 'FAIL', 'HIGH',
                            '[SIMULATED] S3 Block Public Access not enabled at account level')
            self._add_finding('S3', 'encryption', 'PASS', 'INFO',
                            '[SIMULATED] Default encryption enabled on all buckets')
            self._add_finding('S3', 'logging', 'FAIL', 'MEDIUM',
                            '[SIMULATED] Server access logging not enabled on 3 of 5 buckets')
            return
        
        client = self._get_client('s3')
        if not client:
            return
        
        try:
            # Check account-level public access block
            try:
                public_access = client.get_public_access_block()
                config = public_access.get('PublicAccessBlockConfiguration', {})
                if not all([
                    config.get('BlockPublicAcls', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('RestrictPublicBuckets', False)
                ]):
                    self._add_finding('S3', 'public_access', 'FAIL', 'HIGH',
                                    'S3 Block Public Access not fully enabled at account level')
                else:
                    self._add_finding('S3', 'public_access', 'PASS', 'INFO',
                                    'S3 Block Public Access enabled at account level')
            except Exception as e:
                self._add_finding('S3', 'public_access', 'FAIL', 'HIGH',
                                f'Could not verify public access block: {str(e)}')
            
            # List and check buckets
            buckets = client.list_buckets().get('Buckets', [])
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    # Check encryption
                    client.get_bucket_encryption(Bucket=bucket_name)
                except:
                    self._add_finding('S3', 'encryption', 'FAIL', 'HIGH',
                                    f'Bucket {bucket_name} does not have default encryption enabled',
                                    bucket_name)
        
        except Exception as e:
            self._add_finding('S3', 'audit_error', 'WARN', 'MEDIUM',
                            f'Error during S3 audit: {str(e)}')
    
    def audit_iam(self) -> None:
        """Audit IAM security."""
        print("[*] Auditing IAM...")
        
        if self.offline_mode:
            self._add_finding('IAM', 'root_keys', 'FAIL', 'CRITICAL',
                            '[SIMULATED] Root user has active access keys — delete immediately')
            self._add_finding('IAM', 'mfa', 'FAIL', 'HIGH',
                            '[SIMULATED] MFA not enabled on root account')
            self._add_finding('IAM', 'password_policy', 'FAIL', 'MEDIUM',
                            '[SIMULATED] Password policy does not meet security requirements (no expiration, no complexity)')
            return
        
        client = self._get_client('iam')
        if not client:
            return
        
        try:
            # Check password policy
            try:
                password_policy = client.get_account_password_policy()
                policy = password_policy.get('PasswordPolicy', {})
                issues = []
                if not policy.get('RequireUppercaseCharacters', False):
                    issues.append("No uppercase requirement")
                if not policy.get('RequireLowercaseCharacters', False):
                    issues.append("No lowercase requirement")
                if not policy.get('RequireNumbers', False):
                    issues.append("No number requirement")
                if not policy.get('RequireSymbols', False):
                    issues.append("No symbol requirement")
                if policy.get('MaxPasswordAge', 90) > 90:
                    issues.append(f"Password expiry: {policy.get('MaxPasswordAge', 0)} days")
                if issues:
                    self._add_finding('IAM', 'password_policy', 'FAIL', 'MEDIUM',
                                    f'Password policy issues: {"; ".join(issues)}')
                else:
                    self._add_finding('IAM', 'password_policy', 'PASS', 'INFO',
                                    'Password policy meets security requirements')
            except client.exceptions.NoSuchEntityException:
                self._add_finding('IAM', 'password_policy', 'FAIL', 'HIGH',
                                'No password policy configured')
        
        except Exception as e:
            self._add_finding('IAM', 'audit_error', 'WARN', 'MEDIUM',
                            f'Error during IAM audit: {str(e)}')
    
    def audit_security_groups(self) -> None:
        """Audit EC2 Security Groups for overly permissive rules."""
        print("[*] Auditing Security Groups...")
        
        if self.offline_mode:
            self._add_finding('EC2', 'sg_public_ssh', 'FAIL', 'CRITICAL',
                            '[SIMULATED] Security Group "web-sg" allows SSH (22) from 0.0.0.0/0')
            self._add_finding('EC2', 'sg_public_rdp', 'FAIL', 'CRITICAL',
                            '[SIMULATED] Security Group "admin-sg" allows RDP (3389) from 0.0.0.0/0')
            return
        
        client = self._get_client('ec2')
        if not client:
            return
        
        try:
            sgs = client.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                sg_name = sg['GroupName']
                sg_id = sg['GroupId']
                for permission in sg.get('IpPermissions', []):
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = permission.get('FromPort', 'all')
                            if from_port in (22, '22'):
                                self._add_finding('EC2', 'sg_public_ssh', 'FAIL', 'CRITICAL',
                                                f'SG "{sg_name}" ({sg_id}) allows SSH from 0.0.0.0/0', sg_id)
                            elif from_port in (3389, '3389'):
                                self._add_finding('EC2', 'sg_public_rdp', 'FAIL', 'CRITICAL',
                                                f'SG "{sg_name}" ({sg_id}) allows RDP from 0.0.0.0/0', sg_id)
        except Exception as e:
            self._add_finding('EC2', 'sg_audit_error', 'WARN', 'MEDIUM',
                            f'Error auditing security groups: {str(e)}')
    
    def audit_cloudtrail(self) -> None:
        """Audit CloudTrail configuration."""
        print("[*] Auditing CloudTrail...")
        
        if self.offline_mode:
            self._add_finding('CloudTrail', 'disabled', 'FAIL', 'HIGH',
                            '[SIMULATED] CloudTrail not enabled or not logging to S3')
            return
        
        client = self._get_client('cloudtrail')
        if not client:
            return
        
        try:
            trails = client.describe_trails()['trailList']
            if not trails:
                self._add_finding('CloudTrail', 'disabled', 'FAIL', 'HIGH',
                                'No CloudTrail trails configured')
                return
            for trail in trails:
                if not trail.get('IsMultiRegionTrail', False):
                    self._add_finding('CloudTrail', 'multi_region', 'WARN', 'MEDIUM',
                                    f'Trail "{trail["Name"]}" is not multi-region')
                if not trail.get('LogFileValidationEnabled', False):
                    self._add_finding('CloudTrail', 'validation', 'WARN', 'MEDIUM',
                                    f'Trail "{trail["Name"]}" does not have log file validation')
        except Exception as e:
            self._add_finding('CloudTrail', 'audit_error', 'WARN', 'MEDIUM',
                            f'Error auditing CloudTrail: {str(e)}')
    
    def audit_guardduty(self) -> None:
        """Audit GuardDuty configuration."""
        print("[*] Auditing GuardDuty...")
        
        if self.offline_mode:
            self._add_finding('GuardDuty', 'disabled', 'FAIL', 'HIGH',
                            '[SIMULATED] GuardDuty not enabled in this region')
            return
        
        client = self._get_client('guardduty')
        if not client:
            return
        
        try:
            detectors = client.list_detectors()
            if not detectors.get('DetectorIds', []):
                self._add_finding('GuardDuty', 'disabled', 'FAIL', 'HIGH',
                                'GuardDuty not enabled in this region')
            else:
                detector_id = detectors['DetectorIds'][0]
                detector = client.get_detector(DetectorId=detector_id)
                if detector.get('Status') == 'ENABLED':
                    self._add_finding('GuardDuty', 'enabled', 'PASS', 'INFO',
                                    'GuardDuty is enabled')
                else:
                    self._add_finding('GuardDuty', 'suspended', 'FAIL', 'HIGH',
                                    'GuardDuty detector exists but is not enabled')
        except Exception as e:
            self._add_finding('GuardDuty', 'audit_error', 'WARN', 'MEDIUM',
                            f'Error auditing GuardDuty: {str(e)}')
    
    def run_full_audit(self) -> Dict:
        """Run all security audits."""
        print(f"\n{'='*60}")
        print(f"AWS SECURITY AUDIT")
        print(f"Profile: {self.profile}  |  Region: {self.region}")
        print(f"Mode: {'Offline (Simulated)' if self.offline_mode else 'Live AWS'}")
        print(f"{'='*60}\n")
        
        self.audit_s3()
        self.audit_iam()
        self.audit_security_groups()
        self.audit_cloudtrail()
        self.audit_guardduty()
        
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate comprehensive audit report."""
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        
        sorted_findings = sorted(self.findings, 
                                key=lambda x: severity_order.get(x['severity'], 99))
        
        report = {
            'metadata': {
                'profile': self.profile,
                'region': self.region,
                'timestamp': datetime.datetime.now().isoformat(),
                'mode': 'offline_simulated' if self.offline_mode else 'live',
                'total_findings': len(self.findings)
            },
            'compliance_summary': {
                'total_checks': self.compliance_score['total_checks'],
                'passed': self.compliance_score['passed'],
                'failed': self.compliance_score['failed'],
                'warnings': self.compliance_score['warnings'],
                'pass_rate': f"{(self.compliance_score['passed'] / max(self.compliance_score['total_checks'], 1)) * 100:.1f}%"
            },
            'findings_by_severity': {
                'critical': [f for f in self.findings if f['severity'] == 'CRITICAL'],
                'high': [f for f in self.findings if f['severity'] == 'HIGH'],
                'medium': [f for f in self.findings if f['severity'] == 'MEDIUM'],
                'low': [f for f in self.findings if f['severity'] == 'LOW'],
            },
            'all_findings': sorted_findings
        }
        
        return report
    
    def print_report(self, report: Dict = None):
        """Print audit report to console."""
        if report is None:
            report = self.generate_report()
        
        print("\n" + "="*65)
        print("AWS SECURITY AUDIT REPORT")
        print("="*65)
        print(f"Profile:     {report['metadata']['profile']}")
        print(f"Region:      {report['metadata']['region']}")
        print(f"Mode:        {report['metadata']['mode']}")
        print(f"Timestamp:   {report['metadata']['timestamp']}")
        print(f"\nCompliance:  {report['compliance_summary']['pass_rate']} pass rate")
        print(f"  Passed:    {report['compliance_summary']['passed']}")
        print(f"  Failed:    {report['compliance_summary']['failed']}")
        print(f"  Warnings:  {report['compliance_summary']['warnings']}")
        print("="*65)
        
        for severity in ['critical', 'high', 'medium', 'low']:
            findings = report['findings_by_severity'].get(severity, [])
            if findings:
                icon = {'critical': '>>', 'high': '>>', 'medium': '>>', 'low': '>>'}
                print(f"\n{icon.get(severity, '>')} {severity.upper()} ({len(findings)}):")
                for f in findings[:5]:
                    print(f"  - [{f['service']}] {f['details'][:100]}")
                    print(f"    Fix: {f['remediation'][:80]}")
        
        print("\n" + "="*65)

def main():
    parser = argparse.ArgumentParser(description='AWS Security Auditor')
    parser.add_argument('--profile', default='default', help='AWS CLI profile name')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--output', help='Output report file (JSON)')
    
    args = parser.parse_args()
    
    auditor = AWSSecurityAuditor(args.profile, args.region)
    report = auditor.run_full_audit()
    auditor.print_report(report)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Full report saved to {args.output}")

if __name__ == '__main__':
    main()
