# Splunk SIEM Setup and Configuration

## Overview

Splunk is a powerful SIEM (Security Information and Event Management) platform used for searching, monitoring, and analyzing machine-generated data. In this lab, we use **Splunk Free** (500 MB/day limit) for centralized log collection and security event correlation.

**Architecture:**
- Splunk Enterprise (Free license) on Ubuntu Server (10.0.0.30)
- Splunk Universal Forwarder on Windows endpoints
- Custom indexes for different log types
- SPL (Search Processing Language) queries for detection

## Part 1: Install Splunk Enterprise on Ubuntu Server

### Prerequisites

- Ubuntu Server 22.04 LTS
- 4 GB RAM minimum (6 GB recommended)
- 50 GB free disk space
- Static IP: 10.0.0.30

### Step 1: Download Splunk

SSH to Ubuntu Server:
```bash
ssh adminuser@10.0.0.30
```

Download Splunk Free (Linux 64-bit .deb package):
```bash
cd /tmp
wget -O splunk-9.1.2-b6b9c8185839-linux-2.6-amd64.deb \
  'https://download.splunk.com/products/splunk/releases/9.1.2/linux/splunk-9.1.2-b6b9c8185839-linux-2.6-amd64.deb'
```

*Note: Check https://www.splunk.com/en_us/download/splunk-enterprise.html for the latest version*

### Step 2: Install Splunk

```bash
sudo dpkg -i splunk-9.1.2-b6b9c8185839-linux-2.6-amd64.deb
```

Splunk installs to `/opt/splunk`

### Step 3: Start Splunk and Accept License

```bash
cd /opt/splunk/bin
sudo ./splunk start --accept-license
```

**During first start, you'll be prompted to:**
- Create admin username: `admin`
- Set admin password: (choose strong password, min 8 characters)

Splunk will start on port 8000.

### Step 4: Enable Splunk to Start on Boot

```bash
sudo /opt/splunk/bin/splunk enable boot-start -user splunk -systemd-managed 1
```

This creates systemd service.

### Step 5: Configure Firewall (if UFW enabled)

```bash
sudo ufw allow 8000/tcp   # Web UI
sudo ufw allow 9997/tcp   # Splunk forwarder receiving
sudo ufw reload
```

### Step 6: Access Splunk Web UI

From your host machine, open browser:
```
http://10.0.0.30:8000
```

Login with `admin` and the password you created.

### Step 7: Configure Receiving Port

In Splunk Web UI:
1. Settings → Forwarding and receiving
2. Click "Configure receiving"
3. Click "New Receiving Port"
4. Port: `9997`
5. Click "Save"

Or via CLI:
```bash
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:YourPassword
```

Verify:
```bash
sudo netstat -tuln | grep 9997
```

## Part 2: Create Custom Indexes

Indexes organize data for faster searching and role-based access control.

### Via Web UI

1. Settings → Indexes
2. Click "New Index" for each:

| Index Name | Purpose | Max Size |
|------------|---------|----------|
| `windows_security` | Windows Security Event Log | 5 GB |
| `windows_sysmon` | Sysmon operational logs | 10 GB |
| `windows_system` | Windows System Event Log | 2 GB |
| `firewall` | Firewall/network logs | 5 GB |
| `wazuh` | Wazuh alerts | 3 GB |

Settings for each index:
- **Max Size:** (as above)
- **Frozen Path:** (leave default)
- **Home Path:** `/opt/splunk/var/lib/splunk/windows_security/db` (auto)
- **Cold Path:** `/opt/splunk/var/lib/splunk/windows_security/colddb` (auto)

### Via CLI

```bash
# Create indexes via CLI
sudo /opt/splunk/bin/splunk add index windows_security -auth admin:YourPassword
sudo /opt/splunk/bin/splunk add index windows_sysmon -auth admin:YourPassword
sudo /opt/splunk/bin/splunk add index windows_system -auth admin:YourPassword
sudo /opt/splunk/bin/splunk add index firewall -auth admin:YourPassword
sudo /opt/splunk/bin/splunk add index wazuh -auth admin:YourPassword
```

Verify:
```bash
sudo /opt/splunk/bin/splunk list index -auth admin:YourPassword
```

## Part 3: Install Splunk Universal Forwarder on Windows

The Universal Forwarder is a lightweight agent that sends logs to Splunk Enterprise.

### Download Universal Forwarder

On Windows 10 workstation (10.0.0.20):

Download from:
```
https://www.splunk.com/en_us/download/universal-forwarder.html
```

Choose: **Windows 64-bit .msi**

### Install Universal Forwarder

Run the `.msi` installer:

1. Accept license
2. Username: `admin`
3. Generate random password (save it)
4. **Deployment Server:** Leave blank
5. **Receiving Indexer:** `10.0.0.30:9997`
6. Click "Install"

Installation path: `C:\Program Files\SplunkUniversalForwarder\`

### Verify Service is Running

Open PowerShell as Administrator:
```powershell
Get-Service SplunkForwarder
```

**Expected Output:**
```
Status   Name               DisplayName
------   ----               -----------
Running  SplunkForwarder    SplunkForwarder
```

## Part 4: Configure Log Forwarding (inputs.conf)

Edit the inputs configuration to specify which logs to forward.

### Create inputs.conf

Navigate to:
```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\
```

Create file `inputs.conf` (or edit if exists):

```ini
# Windows Security Event Log
[WinEventLog://Security]
disabled = 0
index = windows_security
renderXml = true

# Windows System Event Log
[WinEventLog://System]
disabled = 0
index = windows_system
renderXml = true

# Sysmon Operational Log
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows_sysmon
renderXml = true

# PowerShell Operational Log (includes Script Block Logging)
[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows_sysmon
renderXml = true

# Windows Defender
[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = windows_security
renderXml = true
```

**Key Parameters:**
- `disabled = 0`: Enable log collection
- `index = <name>`: Send logs to specified index on Splunk server
- `renderXml = true`: Preserve XML structure for better field extraction

### Restart Splunk Universal Forwarder

```powershell
Restart-Service SplunkForwarder
```

### Verify Logs in Splunk

In Splunk Web UI, search:
```spl
index=windows_security
| head 10
```

**You should see Windows Security Event Logs.** If not, wait 1-2 minutes for initial data ingestion.

Search for Sysmon:
```spl
index=windows_sysmon EventCode=1
| head 10
```

## Part 5: Verification and Testing

### Check Forwarder Connection

On Splunk server, verify forwarders are connected:

Settings → Forwarding and receiving → Receive data → Configured receiving

You should see: `10.0.0.20:xxxxx` (Windows workstation)

### Check Data Ingestion

```spl
| tstats count WHERE index=* BY index
| sort -count
```

**Expected indexes with data:**
- windows_security
- windows_sysmon  
- windows_system

### Test Real-Time Monitoring

Open PowerShell on Windows 10, run:
```powershell
whoami
```

In Splunk, search:
```spl
index=windows_sysmon EventCode=1 Image="*powershell.exe" CommandLine="*whoami*"
| table _time, ComputerName, User, CommandLine
```

You should see your command logged within seconds.

## Part 6: Essential Splunk SPL Queries

### Basic Search Syntax

**Search all events in an index:**
```spl
index=windows_security
```

**Time range:**
```spl
index=windows_security earliest=-1h
```

**Filter by Event Code:**
```spl
index=windows_security EventCode=4624
```

**Filter with wildcards:**
```spl
index=windows_sysmon Image="*powershell.exe"
```

### Common Commands

**`stats` - Aggregate data:**
```spl
index=windows_security EventCode=4624
| stats count by Account_Name
| sort -count
```

**`table` - Display specific fields:**
```spl
index=windows_sysmon EventCode=1
| table _time, Computer, User, Image, CommandLine
```

**`eval` - Create calculated field:**
```spl
index=windows_security EventCode=4625
| eval hour=strftime(_time, "%H")
| stats count by hour
```

**`where` - Filter results:**
```spl
index=windows_security EventCode=4625
| stats count as failures by src_ip
| where failures > 10
```

**`top` - Most common values:**
```spl
index=windows_security EventCode=4624
| top limit=10 Account_Name
```

### Field Extraction

Splunk auto-extracts many fields from Windows Event Logs. Key fields:

**Windows Security Events:**
- `EventCode` - Event ID (4624, 4625, etc.)
- `Account_Name` - Username
- `src_ip` or `Source_Network_Address` - Source IP
- `Logon_Type` - Type of logon (2=Interactive, 3=Network, 10=RDP)

**Sysmon Events:**
- `EventCode` - Event ID (1, 3, 10, 13, etc.)
- `Image` - Process executable path
- `CommandLine` - Full command line
- `ParentImage` - Parent process
- `TargetFilename` - File created/modified
- `DestinationIp`, `DestinationPort` - Network connections

Check available fields:
```spl
index=windows_security
| fields + *
| head 1
```

## Part 7: Create Saved Searches / Alerts

### Via Web UI

1. Run a search query
2. Click "Save As" → "Alert"
3. **Title:** "Brute Force - 10+ Failed Logins"
4. **Alert Type:** "Real-time" or "Scheduled" (every 5 minutes)
5. **Trigger Conditions:** "Number of Results > 0"
6. **Actions:** Email, Run a script, etc.
7. Save

### Example Alert Query

**Brute Force Detection:**
```spl
index=windows_security EventCode=4625
| stats count as failures by src_ip, Account_Name
| where failures > 10
| sort -failures
```

Set to run every 5 minutes.

## Part 8: Repeat for Domain Controller

Install Splunk Universal Forwarder on Windows Server 2019 (DC01 - 10.0.0.10):

1. Download same `.msi` package
2. Install pointing to `10.0.0.30:9997`
3. Create same `inputs.conf` configuration
4. Restart SplunkForwarder service

Verify both hosts are forwarding:
```spl
index=* 
| stats count by host
```

**You should see:**
- `DC01` or `10.0.0.10`
- `WS-FIN-PC01` or `10.0.0.20`

## Troubleshooting

### Issue: No data appearing in Splunk

**Check forwarder is connected:**
```powershell
# On Windows forwarder
Test-NetConnection -ComputerName 10.0.0.30 -Port 9997
```

**Check forwarder logs:**
```
C:\Program Files\SplunkUniversalForwarder\var\log\splunk\splunkd.log
```

Search for "ERROR" or "WARN"

**Check inputs.conf syntax:**
```powershell
# Test config
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk.exe btool inputs list --debug
```

### Issue: Splunk license exceeded

Free license limit: 500 MB/day

**Check usage:**
```spl
index=_internal source=*license_usage.log type="Usage"
| stats sum(b) as bytes by idx
| eval MB=round(bytes/1024/1024,2)
| sort -MB
```

**Reduce volume:**
- Filter noisy Event IDs in inputs.conf
- Disable unnecessary logs (Application, Setup)
- Add blacklists for routine events

### Issue: Slow searches

**Optimize:**
- Use specific time ranges (`earliest=-1h`)
- Filter by index first (`index=windows_security`)
- Avoid `index=*` searches
- Use tstats for count/stats operations

## Performance Tuning

**Optimize Splunk server:**
```bash
# Edit server.conf
sudo vi /opt/splunk/etc/system/local/server.conf
```

Add:
```ini
[general]
serverName = SIEM01

[diskUsage]
minFreeSpace = 5000
```

**Set index retention:**
```bash
# Keep 30 days of data
sudo /opt/splunk/bin/splunk edit index windows_security -maxTotalDataSizeMB 5000 -auth admin:YourPassword
```

## Next Steps

1. Install Atomic Red Team on Windows 10
2. Generate test attacks
3. Build detection rules (see [detection-rules/](../detection-rules/))
4. Create dashboards for SOC monitoring
5. Integrate Wazuh alerts into Splunk

## Splunk Free vs Enterprise

**Splunk Free limitations:**
- 500 MB/day indexing limit
- No authentication (single user)
- No distributed search
- No alerting features
- No role-based access control

**For this lab:** Free version is sufficient for learning and portfolio demonstration.

## References

- Splunk Installation Manual: https://docs.splunk.com/Documentation/Splunk/latest/Installation
- Universal Forwarder Manual: https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Abouttheuniversalforwarder
- SPL Reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference
- Boss of the SOC (Splunk CTF): https://www.splunk.com/en_us/blog/conf-splunklive/bots.html
