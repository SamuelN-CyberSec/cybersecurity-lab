# Wazuh SIEM Installation Guide

> **Purpose:** Deploy a production-like Wazuh SIEM for SOC lab operations
> **Difficulty:** Intermediate | **Time:** 30-45 minutes

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 8 GB | 16 GB |
| CPU | 4 cores | 8 cores |
| Storage | 50 GB | 100 GB |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |

---

## Step 1: Deploy Wazuh Server (All-in-One)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Download Wazuh installation script
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh.asc

# Verify the script (optional but recommended)
sudo bash wazuh-install.sh -a

# After completion, note the admin password shown in output
# Default: admin / <generated_password>
```

---

## Step 2: Access Wazuh Dashboard

```
https://<SIEM_SERVER_IP>:443
Username: admin
Password: <generated_password>
```

---

## Step 3: Deploy Wazuh Agents

### Linux Agent
```bash
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Install agent
sudo apt update
sudo WAZUH_MANAGER="<SIEM_IP>" apt install wazuh-agent

# Start agent
sudo systemctl start wazuh-agent
sudo systemctl enable wazuh-agent
```

### Windows Agent (PowerShell as Admin)
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi WAZUH_MANAGER="<SIEM_IP>" /q
```

---

## Step 4: Verify Agent Connection

```bash
# Check agent status on endpoint
sudo systemctl status wazuh-agent

# Check in Wazuh dashboard
# Agents → Summary → Active agents should show your endpoint
```

---

## Step 5: Add Custom Detection Rules

Create custom rules at `/var/ossec/etc/rules/local_rules.xml` on the Wazuh server:

```xml
<group name="custom_bruteforce">
  <rule id="100001" level="10">
    <decoded_as>ssh</decoded_as>
    <match>Failed password</match>
    <description>SSH Brute Force Attempt Detected</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <rule id="100002" level="12" frequency="5" timeframe="60">
    <if_matched_sid>100001</if_matched_sid>
    <same_source_ip />
    <description>Multiple SSH Failed Logins - Brute Force in Progress</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

```bash
# Restart Wazuh to apply rules
sudo systemctl restart wazuh-manager
```

---

## ✅ Verification Checklist

- [ ] Wazuh dashboard accessible via HTTPS
- [ ] At least 1 agent connected and showing "Active"
- [ ] Security events appearing in dashboard
- [ ] Custom rules loaded (check: `/var/ossec/bin/wazuh-logtest`)
- [ ] Alerts generating for simulated attacks

---

**Portfolio Value:** "Deployed and configured Wazuh SIEM with custom detection rules mapped to MITRE ATT&CK, integrated endpoint agents across Linux and Windows environments."
