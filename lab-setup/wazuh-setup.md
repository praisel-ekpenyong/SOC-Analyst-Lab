# Wazuh EDR Setup and Configuration

## Overview

Wazuh is an open-source Enterprise Detection and Response (EDR) platform that provides:
- File Integrity Monitoring (FIM)
- Rootkit and malware detection
- Security configuration assessment
- Vulnerability detection
- Compliance monitoring (PCI-DSS, HIPAA, GDPR)
- Active response (automated threat containment)

**Architecture:**
- Wazuh Manager on Ubuntu Server (10.0.0.30)
- Wazuh Agents on Windows endpoints
- Dashboard for visualization and alert management

## Part 1: Install Wazuh Manager on Ubuntu Server

### Prerequisites

- Ubuntu Server 22.04 LTS
- 2 GB RAM minimum (4 GB recommended)
- 20 GB free disk space
- Static IP: 10.0.0.30

**Note:** Wazuh Manager and Splunk will coexist on the same server.

### Step 1: Install Dependencies

SSH to Ubuntu Server:
```bash
ssh adminuser@10.0.0.30
```

Update system:
```bash
sudo apt update && sudo apt upgrade -y
```

Install curl and required packages:
```bash
sudo apt install curl apt-transport-https lsb-release gnupg2 -y
```

### Step 2: Install Wazuh Manager

Run Wazuh installation script (all-in-one deployment):
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

**This installs:**
- Wazuh Manager (log analysis and correlation)
- Wazuh Indexer (Elasticsearch-based data storage)
- Wazuh Dashboard (Kibana-based web UI)

Installation takes 5-10 minutes.

**Save credentials displayed at end:**
```
Admin credentials:
  Username: admin
  Password: <random_password>
```

### Step 3: Access Wazuh Dashboard

From host machine browser:
```
https://10.0.0.30:443
```

**Note:** Browser will warn about self-signed certificate. Proceed anyway (this is a lab environment).

Login with credentials from installation.

### Step 4: Verify Wazuh Manager Status

Check services are running:
```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

All should show `active (running)`.

### Step 5: Configure Firewall (if UFW enabled)

```bash
sudo ufw allow 443/tcp    # Dashboard
sudo ufw allow 1514/udp   # Agent communication (logs)
sudo ufw allow 1515/tcp   # Agent registration
sudo ufw allow 55000/tcp  # API
sudo ufw reload
```

## Part 2: Install Wazuh Agent on Windows 10

### Download Wazuh Agent

On Windows 10 workstation (10.0.0.20):

Download from:
```
https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html
```

Or directly:
```
https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi
```

### Install Wazuh Agent

Run the `.msi` installer:

1. Accept license
2. **Wazuh Manager IP:** `10.0.0.30`
3. **Agent Name:** `WS-FIN-PC01` (or leave default)
4. **Agent Groups:** (leave default)
5. Click "Install"

Installation path: `C:\Program Files (x86)\ossec-agent\`

### Start Wazuh Agent

Open PowerShell as Administrator:
```powershell
# Start service
Start-Service WazuhSvc

# Verify running
Get-Service WazuhSvc
```

**Expected Output:**
```
Status   Name       DisplayName
------   ----       -----------
Running  WazuhSvc   Wazuh Agent
```

### Verify Agent Connection

Check agent status:
```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
```

Look for: `INFO: Connected to the server`

## Part 3: Verify Agent Registration in Dashboard

### Check Agent Status in Wazuh Dashboard

1. Login to https://10.0.0.30:443
2. Navigate to: **Agents** (left menu)
3. You should see agent listed:
   - **ID:** 001
   - **Name:** WS-FIN-PC01
   - **IP:** 10.0.0.20
   - **Status:** Active (green)

If status is "Never connected" or "Disconnected", wait 1-2 minutes and refresh.

### Manually Register Agent (if needed)

If agent doesn't auto-register:

**On Wazuh Manager (Ubuntu):**
```bash
sudo /var/ossec/bin/manage_agents
```

Select:
- (A)dd agent
- **Name:** WS-FIN-PC01
- **IP:** 10.0.0.20
- Copy the key shown

**On Windows Agent:**
```powershell
cd "C:\Program Files (x86)\ossec-agent"
.\manage_agents.exe
```

Select:
- (I)mport key
- Paste the key
- Restart service: `Restart-Service WazuhSvc`

## Part 4: Configure File Integrity Monitoring (FIM)

FIM monitors critical directories for unauthorized changes.

### Edit Agent Configuration

On Windows agent, edit:
```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Add FIM directories in `<syscheck>` section:

```xml
<syscheck>
  <frequency>300</frequency>  <!-- Check every 5 minutes -->
  
  <!-- Monitor Windows directories -->
  <directories check_all="yes" realtime="yes">C:\Windows\System32\drivers</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\System32\config</directories>
  <directories check_all="yes" realtime="yes">C:\Program Files</directories>
  
  <!-- Monitor user startup folder -->
  <directories check_all="yes" realtime="yes">C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</directories>
  
  <!-- Monitor registry (Windows) -->
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
  
  <!-- Ignore Windows Update files (reduce noise) -->
  <ignore>C:\Windows\System32\catroot2</ignore>
  <ignore>C:\Windows\SoftwareDistribution</ignore>
</syscheck>
```

Restart agent:
```powershell
Restart-Service WazuhSvc
```

### Test FIM

Create a test file:
```powershell
New-Item "C:\Windows\System32\drivers\test_file.txt" -ItemType File
```

In Wazuh Dashboard:
- Navigate to: **File Integrity Monitoring** module
- Filter by agent: WS-FIN-PC01
- You should see alert for new file creation

## Part 5: Enable Sysmon Integration

Wazuh automatically collects Windows Event Logs including Sysmon.

### Verify Sysmon Events in Wazuh

In Wazuh Dashboard:
```
Security Events → Query bar:
data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"
```

You should see Sysmon Event IDs (1, 3, 10, 13, 22, etc.).

### Create Custom Rule for Sysmon

On Wazuh Manager, edit local rules:
```bash
sudo vi /var/ossec/etc/rules/local_rules.xml
```

Add custom rule:
```xml
<group name="sysmon,">
  <!-- Alert on PowerShell encoded commands -->
  <rule id="100001" level="12">
    <if_sid>61603</if_sid>  <!-- Sysmon Event 1 -->
    <field name="win.eventdata.image">powershell.exe</field>
    <field name="win.eventdata.commandLine">-enc|-encodedcommand</field>
    <description>PowerShell executed with encoded command</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

Restart Wazuh Manager:
```bash
sudo systemctl restart wazuh-manager
```

## Part 6: Active Response Configuration

Active Response allows Wazuh to automatically respond to threats.

### Example: Block IP After Brute Force

Edit on Wazuh Manager:
```bash
sudo vi /var/ossec/etc/ossec.conf
```

Add in `<ossec_config>`:
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5763</rules_id>  <!-- Windows logon failure -->
  <timeout>1800</timeout>     <!-- Block for 30 minutes -->
</active-response>
```

**Available commands:**
- `firewall-drop` - Block IP at Windows Firewall
- `disable-account` - Disable compromised account
- `restart-wazuh` - Restart agent
- `host-deny` - Add to hosts.deny (Linux)

**Caution:** Test active response carefully to avoid locking yourself out.

## Part 7: Vulnerability Detection

Wazuh can scan for known CVEs in installed software.

### Enable Vulnerability Detector

Edit Wazuh Manager config:
```bash
sudo vi /var/ossec/etc/ossec.conf
```

Enable vulnerability detector:
```xml
<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>24h</interval>
  <run_on_start>yes</run_on_start>
  
  <provider name="canonical">
    <enabled>yes</enabled>
    <os>Ubuntu</os>
  </provider>
  
  <provider name="microsoft">
    <enabled>yes</enabled>
  </provider>
</vulnerability-detector>
```

Restart:
```bash
sudo systemctl restart wazuh-manager
```

### View Vulnerabilities

In Wazuh Dashboard:
- Navigate to: **Vulnerabilities** module
- Filter by agent
- View detected CVEs with severity ratings

## Part 8: Essential Wazuh Features

### Security Configuration Assessment (SCA)

Checks system compliance against CIS benchmarks, PCI-DSS, etc.

View in Dashboard:
- Navigate to: **Security Configuration Assessment**
- Select agent
- View passed/failed checks by policy

**Example policies:**
- CIS Microsoft Windows 10 Enterprise
- CIS Microsoft Windows Server 2019
- PCI-DSS v3.2.1

### Regulatory Compliance

Map alerts to compliance frameworks:
- Navigate to: **Regulatory Compliance**
- View compliance status for PCI-DSS, GDPR, HIPAA, NIST 800-53

### MITRE ATT&CK Mapping

Wazuh automatically maps alerts to MITRE ATT&CK:
- Navigate to: **MITRE ATT&CK**
- View heatmap of detected techniques
- Identify coverage gaps

## Part 9: Repeat for Domain Controller

Install Wazuh Agent on Windows Server 2019 (DC01):

1. Download same `.msi` package
2. Install pointing to `10.0.0.30`
3. Verify connection in Wazuh Dashboard
4. Configure FIM for critical AD files:
   - `C:\Windows\NTDS\` (AD database)
   - `C:\Windows\SYSVOL\`

## Part 10: Integration with Splunk (Optional)

Forward Wazuh alerts to Splunk for centralized analysis.

### Configure Syslog Output

On Wazuh Manager:
```bash
sudo vi /var/ossec/etc/ossec.conf
```

Add:
```xml
<syslog_output>
  <server>10.0.0.30</server>
  <port>514</port>
  <format>json</format>
</syslog_output>
```

### Configure Splunk to Receive Syslog

On Splunk server:
```bash
sudo /opt/splunk/bin/splunk add udp 514 -sourcetype wazuh -index wazuh -auth admin:YourPassword
```

Restart both:
```bash
sudo systemctl restart wazuh-manager
sudo systemctl restart Splunk
```

Verify in Splunk:
```spl
index=wazuh
| stats count by rule.description
```

## Troubleshooting

### Issue: Agent shows "Disconnected"

**Check network connectivity:**
```powershell
Test-NetConnection -ComputerName 10.0.0.30 -Port 1514
Test-NetConnection -ComputerName 10.0.0.30 -Port 1515
```

**Check agent log:**
```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
```

Look for connection errors.

**Restart agent:**
```powershell
Restart-Service WazuhSvc
```

### Issue: No FIM alerts

**Verify FIM is enabled:**
```xml
<!-- In ossec.conf -->
<syscheck>
  <disabled>no</disabled>
```

**Force FIM scan:**
```powershell
# Create file to trigger alert
New-Item "C:\Program Files\test.txt" -ItemType File

# Check agent log
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" | Select-String -Pattern "syscheck"
```

### Issue: Dashboard not accessible

**Check services:**
```bash
sudo systemctl status wazuh-dashboard
sudo systemctl status wazuh-indexer
```

**Check firewall:**
```bash
sudo ufw status
```

**View logs:**
```bash
sudo tail -f /var/log/wazuh-indexer/wazuh-cluster.log
```

## Wazuh Alert Levels

| Level | Severity | Description |
|-------|----------|-------------|
| 0-3 | Low | Informational, routine events |
| 4-7 | Medium | Notable events requiring attention |
| 8-11 | High | Security violations, policy violations |
| 12-15 | Critical | Confirmed attacks, malware, compromise |

**Default alert threshold:** Level 3+ (configurable)

## Key Wazuh Rules

| Rule ID | Description | ATT&CK |
|---------|-------------|--------|
| 5710 | Multiple Windows Logon Failures | T1110 |
| 60103 | New user created | T1136 |
| 61603 | Sysmon Event 1 (Process Create) | T1059 |
| 92552 | File Integrity Monitoring | Various |
| 87104 | Malware detected (VirusTotal) | T1204 |

View all rules:
```bash
sudo cat /var/ossec/ruleset/rules/*.xml | grep '<rule id='
```

## Next Steps

1. Configure custom rules for lab-specific detections
2. Test FIM by modifying monitored files
3. Integrate Wazuh with Atomic Red Team tests
4. Review compliance dashboards
5. Explore active response capabilities

## References

- Wazuh Documentation: https://documentation.wazuh.com/
- Wazuh Ruleset: https://github.com/wazuh/wazuh-ruleset
- Wazuh Blog: https://wazuh.com/blog/
- MITRE ATT&CK with Wazuh: https://wazuh.com/blog/mitre-attck-with-wazuh/
