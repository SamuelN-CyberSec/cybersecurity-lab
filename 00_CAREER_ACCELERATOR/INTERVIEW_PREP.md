# Interview Preparation — Samuel Nwokemodo

> **Target Roles:** SOC Analyst, Cloud Security Analyst, Vulnerability Management Analyst

---

## 📋 TIER 1: SOC ANALYST INTERVIEW

### Common Questions & Answers

#### Q1: Walk me through the incident response process.
**Answer Framework (NIST 800-61):**
1. **Preparation** — Tools, playbooks, communication channels ready
2. **Detection & Analysis** — Alert triggers, verify with logs, determine scope
3. **Containment, Eradication & Recovery** — Isolate affected systems, remove threat, restore
4. **Post-Incident Activity** — Lessons learned, documentation, process improvement

**Samuel's Answer Example:**
> "I follow the NIST 800-61 framework. First, I validate the alert by correlating logs from the SIEM, endpoint, and network sources. Once confirmed, I contain the threat — for example, isolating a compromised host via the EDR tool. I then analyze root cause, eradicate the threat, and restore services. Finally, I document findings, update playbooks, and recommend preventive controls."

#### Q2: How do you prioritize alerts in a SOC?
**Answer:**
- **Criticality** — Is it a critical asset? (Domain controller, database server)
- **Confidence** — How reliable is the detection? (Correlated vs single source)
- **Impact** — Potential data loss, ransomware, lateral movement
- **MITRE ATT&CK Mapping** — Is this a known TTP?

> "I use a risk-based approach. A single failed login on a user workstation is different from 50 failed logins on a domain controller followed by a successful admin login. I prioritize alerts that indicate active compromise, lateral movement, or data exfiltration."

#### Q3: You see a spike in failed logins from an IP address. What do you do?
**Answer Steps:**
1. Check if the IP is known (threat intelligence feeds)
2. Correlate with successful logins from same IP
3. Check if targeted accounts are privileged
4. Review recent user activity post-login
5. If malicious — block IP, reset affected credentials, investigate further

#### Q4: What's the difference between a SIEM and a SOAR?
- **SIEM** (e.g., Wazuh, Splunk) — Aggregates logs, generates alerts, provides visualization
- **SOAR** (e.g., Shuffle, Splunk SOAR) — Automates response actions based on alerts

> "SIEM tells you something happened. SOAR does something about it automatically."

---

## 📋 TIER 2: CLOUD SECURITY INTERVIEW

### Common Questions & Answers

#### Q1: Explain the Shared Responsibility Model.
- **AWS** manages security **OF** the cloud (physical infrastructure, hardware)
- **Customer** manages security **IN** the cloud (IAM, data, configurations)

#### Q2: How would you secure an S3 bucket?
- Block public access by default
- Enable S3 Block Public Access at account level
- Use IAM policies with least privilege
- Enable S3 server access logging + CloudTrail
- Enable S3 Object Lock for compliance
- Encrypt data at rest (SSE-S3, SSE-KMS) and in transit

#### Q3: What's a common AWS misconfiguration you've seen?
> "Publicly accessible S3 buckets with sensitive data, overly permissive IAM roles (AdministratorAccess), and Security Groups allowing 0.0.0.0/0 on critical ports like 22 (SSH) or 3389 (RDP)."

#### Q4: How do you detect threats in AWS?
- **CloudTrail** — API activity monitoring
- **GuardDuty** — Threat detection (crypto mining, unusual traffic)
- **AWS Config** — Compliance checks
- **VPC Flow Logs** — Network traffic analysis
- **Security Hub** — Aggregated findings

---

## 📋 TIER 3: VULNERABILITY MANAGEMENT INTERVIEW

### Common Questions & Answers

#### Q1: Describe your vulnerability management process.
1. **Discovery** — Asset inventory + scanning (Nmap, OpenVAS, Nessus)
2. **Identification** — Map CVEs to assets with CVSS scoring
3. **Prioritization** — Risk-based (CVSS + exploitability + asset criticality)
4. **Remediation** — Patching, compensating controls, risk acceptance
5. **Verification** — Rescan to confirm fix
6. **Reporting** — Metrics, trends, SLA compliance

#### Q2: How do you deal with a critical vulnerability that can't be patched?
> "I evaluate compensating controls — can we isolate the system, restrict network access, or add WAF rules? If not, we document formal risk acceptance with sign-off from the asset owner and track it for the next remediation window."

---

## 🎤 BEHAVIORAL QUESTIONS (STAR Method)

| Question | Situation | Task | Action | Result |
|----------|-----------|------|--------|--------|
| Tell me about a time you handled a security incident | *[Your real experience]* | | | |
| Describe a time you automated a process | *[Python automation example]* | | | |
| How do you stay updated on threats? | *[Blogs, podcasts, labs]* | | | |
| Conflict with a colleague on security priority | *[Risk-based conversation]* | | | |

---

## 📚 RESOURCES TO WATCH BEFORE INTERVIEWS

- **John Hammond** — SOC/defensive content
- **I.T. Career Questions** (YouTube) — Interview tips
- **Cyber Mentor** — Practical pentesting/TJNull's list
- **David Bombal** — General cybersecurity

---

## 📌 PRE-INTERVIEW CHECKLIST

1. [ ] Research company — products, recent news, security breaches
2. [ ] Review job description — match keywords to your experience
3. [ ] Prepare 3 stories using STAR method
4. [ ] Test your mic/camera (if remote interview)
5. [ ] Prepare 3 questions to ask them (e.g., "What does a typical day look like?", "What tools does the SOC use?")
6. [ ] Have your GitHub portfolio ready to share

---

**Portfolio Value:** Structured interview prep turns nerves into confidence. Save this and practice one question daily.
