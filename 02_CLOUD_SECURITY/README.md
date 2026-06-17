# Cloud Security — AWS Security Architecture

> **Executive Summary:** Secure AWS cloud architecture designs, IAM policies, GuardDuty detection engineering, Terraform IaC modules, and compliance automation. All designs follow AWS Well-Architected Framework security pillar.

---

## 🎯 Purpose

Build enterprise-grade cloud security capability by:
- Designing secure multi-tier AWS architectures
- Implementing least privilege IAM policies
- Configuring GuardDuty + CloudTrail for threat detection
- Automating compliance checks with AWS Config + Lambda
- Deploying infrastructure as code (Terraform)

---

## 📂 Module Structure

```
02_CLOUD_SECURITY/
├── README.md
├── SECURE_AWS_ARCHITECTURE/
│   ├── 3-TIER_ARCHITECTURE.md
│   ├── NETWORK_ACL_DESIGN.md
│   └── VPC_DESIGN.md
├── IAM_POLICIES/
│   ├── least_privilege_policies.json
│   ├── role_based_access.json
│   └── iam_audit_script.py
├── CLOUDTRAIL_GUARDDUTY/
│   ├── guardduty_detection_rules.md
│   ├── cloudtrail_log_analysis.py
│   └── threat_detection_alerts.md
├── TERRAFORM_IAC/
│   ├── modules/
│   │   ├── vpc/
│   │   ├── ec2/
│   │   ├── s3/
│   │   └── iam/
│   ├── environments/
│   │   ├── dev/
│   │   └── prod/
│   └── main.tf
└── COMPLIANCE_AUTOMATION/
    ├── aws_config_rules/
    ├── lambda_compliance_checks/
    └── CIS_BENCHMARK_CHECKS.md
```

---

## 🏗️ Reference Architecture: Secure 3-Tier Web App

```
                       ┌─────────────┐
                       │  CloudFront  │
                       │  (WAF)       │
                       └──────┬──────┘
                              │
                       ┌──────▼──────┐
                       │  ALB (HTTPS)│
                       │  (SSL Term) │
                       └──────┬──────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
       ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
       │  Web Tier   │ │  Web Tier   │ │  Web Tier   │
       │  (AutoScale)│ │  (AutoScale)│ │  (AutoScale)│
       └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
              │               │               │
              └───────────────┼───────────────┘
                              │
                       ┌──────▼──────┐
                       │  Internal    │
                       │  ALB         │
                       └──────┬──────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
       ┌──────▼──────┐ ┌──────▼──────┐       │
       │  App Tier   │ │  App Tier   │       │
       │  (Private)  │ │  (Private)  │       │
       └──────┬──────┘ └──────┬──────┘       │
              │               │               │
              └───────────────┼───────────────┘
                              │
                       ┌──────▼──────┐
                       │  RDS (Multi-│
                       │  AZ, Encrypt)│
                       │  (Private)   │
                       └─────────────┘
```

### Security Controls Applied:
- ✅ VPC with public/private subnets across 3 AZs
- ✅ Security Groups (stateful, least privilege)
- ✅ NACLs (stateless, subnet-level defense)
- ✅ S3 Block Public Access (all buckets)
- ✅ IAM Roles (no access keys on EC2)
- ✅ CloudTrail (multi-region, log file validation)
- ✅ GuardDuty (enabled all regions)
- ✅ AWS Config (recording all resources)
- ✅ KMS encryption at rest
- ✅ WAF (SQL injection + XSS rules)

---

## 🔒 IAM Principle: Least Privilege Example

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::company-logs",
                "arn:aws:s3:::company-logs/*"
            ],
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": "10.0.0.0/16"
                }
            }
        }
    ]
}
```

---

## 🚀 Quick Start: Terraform Deployment

```bash
# Clone and deploy secure VPC
cd 02_CLOUD_SECURITY/TERRAFORM_IAC/environments/dev
terraform init
terraform plan
terraform apply
```

---

## 📌 Learning Progression

| Level | Skill | Activity |
|-------|-------|----------|
| L1 | IAM Security | Write least privilege policies |
| L2 | Detection | Configure GuardDuty + CloudTrail |
| L3 | Compliance | Automate CIS Benchmarks checks |
| L4 | Architecture | Design secure multi-account setup |

---

**Resume Value:** "Designed and deployed a secure AWS 3-tier architecture with GuardDuty, CloudTrail, and automated compliance checks using Terraform and Lambda."
