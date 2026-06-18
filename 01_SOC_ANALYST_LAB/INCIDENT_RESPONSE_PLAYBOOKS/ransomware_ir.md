# Incident Response Playbook: Ransomware

> **Severity:** CRITICAL
> **SLA:** Immediate Response (P1)
> **MITRE ATT&CK:** T1486 (Data Encrypted for Impact)

---

## 1. DETECTION

### Indicators
- File extensions changing (`.encrypted`, `.lock`, `.xyz`)
- Ransom notes dropped (`README.txt`, `HOW_TO_DECRYPT.html`)
- High CPU/disk activity on multiple endpoints
- SMB/CIFS traffic spikes (encrypting network shares)
- Windows Defender/EDR alerts: ransomware behavior detected

### Initial Triage Questions
1. How many endpoints are affected?
2. Are network shares/backups encrypted?
3. Has the attacker established persistence?
4. Is this a known ransomware variant?

---

## 2. CONTAINMENT

### Immediate Actions
```bash
# 1. Isolate affected endpoints from network
# EDR: Initiate host isolation
# Manual: Disconnect network cable or disable NIC
netsh interface set interface "Ethernet" admin=disable

# 2. Disable SMBv1 to prevent worm-like propagation
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# 3. Block known C2 domains at firewall
# Add to firewall blocklist
New-NetFirewallRule -DisplayName "Block C2" -Direction Outbound -RemoteAddress <C2_IP> -Action Block

# 4. Disable local admin accounts across environment
net user administrator /active:no
```

---

## 3. ERADICATION

```bash
# 1. Kill ransomware processes
taskkill /F /IM ransomware.exe /T

# 2. Remove scheduled tasks created by ransomware
schtasks /DELETE /TN "ransom_task" /F

# 3. Clean registry run keys
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ransom" /f

# 4. Remove persistence mechanisms
wmic process where name="malicious.exe" delete
```

---

## 4. RECOVERY

```bash
# 1. Verify backup integrity (do NOT restore until confirmed clean)
# 2. Restore from clean backup
# 3. Reset all affected user credentials
# 4. Apply patches before reconnecting
```

---

## 5. POST-INCIDENT

### Documentation Required
- [ ] Timeline of events
- [ ] Affected systems and data
- [ ] IOCs extracted (IPs, hashes, domains)
- [ ] Root cause analysis
- [ ] Lessons learned

### Preventative Measures
- [ ] Enable MFA across all accounts
- [ ] Implement least privilege access
- [ ] Enable email filtering for phishing
- [ ] Deploy endpoint detection and response (EDR)
- [ ] Regular offline backup testing

---

**Portfolio Value:** "Developed enterprise-grade ransomware response playbook following NIST 800-61 framework with containment, eradication, recovery, and lessons learned phases."
