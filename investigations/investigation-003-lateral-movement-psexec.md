# Investigation 003: Lateral Movement via PsExec

## Alert Details

- **Date:** 2026-01-22
- **Alert Source:** Splunk SIEM
- **Alert Name:** Lateral Movement - PsExec Service Installation
- **Severity:** Critical
- **MITRE ATT&CK:** Lateral Movement — Remote Services: SMB/Windows Admin Shares (T1021.002)
- **Affected Hosts:** WS-IT-PC03 (10.0.0.21), WS-IT-PC04 (10.0.0.22), WS-HR-PC02 (10.0.0.23)
- **Compromised Account:** t.williams (IT Admin / Domain Admin)
- **Source Host:** External VPN Connection (172.16.50.88)
- **Attack Origin:** Previously compromised admin credentials

## Executive Summary

An attacker leveraged compromised Domain Admin credentials to perform lateral movement across multiple workstations using PsExec, a legitimate Windows Sysinternals tool commonly abused by threat actors. The attack originated from a VPN connection established using stolen credentials of an IT administrator. The attacker deployed PSEXESVC service to three workstations, executing reconnaissance commands and attempting to establish persistent access. Detection occurred when the SIEM correlated multiple PSEXESVC service installations across the network within a short timeframe. Investigation revealed the VPN session originated from an unauthorized geographic location. Immediate credential rotation and session termination contained the incident before data exfiltration or ransomware deployment.

## Timeline of Events

| Time (UTC) | Event | Source | Details |
|------------|-------|--------|---------|
| 2026-01-22 14:32:18 | VPN Authentication | VPN Gateway Logs | User t.williams authenticated from IP 203.98.45.123 (Singapore) - anomalous location |
| 2026-01-22 14:32:45 | VPN Session Established | VPN Gateway | SSL VPN session established, assigned internal IP 172.16.50.88 |
| 2026-01-22 14:35:12 | SMB Connection | Windows Security (Event 5140) | Remote share access from 172.16.50.88 to \\\\WS-IT-PC03\\ADMIN$ |
| 2026-01-22 14:35:28 | PsExec Binary Copied | Sysmon (Event 11) | PSEXEC.exe copied to \\\\WS-IT-PC03\\ADMIN$\\System32\\ |
| 2026-01-22 14:35:35 | Service Installation | Windows Security (Event 4697) | Service "PSEXESVC" installed on WS-IT-PC03 by t.williams |
| 2026-01-22 14:35:38 | Remote Command Execution | Sysmon (Event 1) | cmd.exe spawned by PSEXESVC.exe with command: "whoami /all" |
| 2026-01-22 14:36:02 | Domain Enumeration | Sysmon (Event 1) | net.exe command executed: "net group 'Domain Admins' /domain" |
| 2026-01-22 14:36:45 | Second Target - WS-IT-PC04 | Windows Security (Event 5140) | SMB connection to \\\\WS-IT-PC04\\ADMIN$ from 172.16.50.88 |
| 2026-01-22 14:36:58 | PsExec Service Install | Windows Security (Event 4697) | PSEXESVC installed on WS-IT-PC04 |
| 2026-01-22 14:37:12 | Process Discovery | Sysmon (Event 1) | tasklist.exe executed remotely on WS-IT-PC04 |
| 2026-01-22 14:37:48 | Network Share Enumeration | Sysmon (Event 1) | net.exe command: "net view \\\\fileserver /all" |
| 2026-01-22 14:38:23 | Third Target - WS-HR-PC02 | Windows Security (Event 5140) | SMB connection to \\\\WS-HR-PC02\\ADMIN$ from 172.16.50.88 |
| 2026-01-22 14:38:35 | PsExec Service Install | Windows Security (Event 4697) | PSEXESVC installed on WS-HR-PC02 |
| 2026-01-22 14:38:52 | File System Enumeration | Sysmon (Event 1) | dir command executed: "dir C:\Users /s /b" |
| 2026-01-22 14:39:15 | Credential Dumping Attempt | Sysmon (Event 10) | lsass.exe process access detected from suspicious process |
| 2026-01-22 14:39:28 | **Alert Fired** | Splunk Alert | Detection rule "Multiple PSEXESVC Service Installations" triggered |
| 2026-01-22 14:40:45 | Analyst Response Begin | SOC Action Log | Senior analyst initiated investigation |
| 2026-01-22 14:42:10 | VPN Session Terminated | VPN Gateway | Admin terminated t.williams VPN session (IP 172.16.50.88) |
| 2026-01-22 14:43:35 | Account Disabled | Active Directory | Domain Admin account t.williams disabled |
| 2026-01-22 14:44:50 | Services Stopped | Remote PowerShell | PSEXESVC services stopped and removed from all three workstations |
| 2026-01-22 14:48:00 | Containment Complete | SOC Action Log | All attacker access terminated, forensics underway |

## Investigation Steps

### Step 1: Alert Analysis & Initial Scope

**Alert Triggered:** Splunk detection rule "Multiple PSEXESVC Service Installations" fired at 14:39:28 UTC.

**Alert Details:**
```
Detection Logic: 3+ PSEXESVC service installations within 10-minute window
Affected Hosts: WS-IT-PC03, WS-IT-PC04, WS-HR-PC02
Installing User: t.williams (Domain Admin)
Source IP: 172.16.50.88 (VPN Pool)
Time Span: 4 minutes 17 seconds
```

**Initial Assessment:** Critical severity due to:
- Lateral movement across multiple hosts
- Domain Admin account involved
- PsExec commonly used in ransomware attacks for rapid deployment
- Short time window suggests automated or scripted attack
- VPN source indicates potential remote attacker access

**Immediate Questions:**
1. Is t.williams session legitimate or compromised?
2. What commands were executed on target systems?
3. Are additional hosts affected?
4. Has credential dumping or data exfiltration occurred?

### Step 2: VPN Session Analysis

**Query: Analyze VPN authentication and session**
```spl
index=vpn user="t.williams" earliest="2026-01-22T14:00:00" latest="2026-01-22T15:00:00"
| table _time, action, src_ip, src_country, assigned_ip, auth_method
```

**VPN Session Details:**
```
Authentication Time: 14:32:18 UTC
Source IP: 203.98.45.123
Geolocation: Singapore (SG)
ISP: Digital Ocean LLC
Authentication Method: Username + Password (no MFA)
Assigned VPN IP: 172.16.50.88
Session Duration: 15 minutes 42 seconds (before termination)
```

**Anomaly Indicators:**
- **Geographic Anomaly:** User t.williams typically logs in from United States (IP range 72.x.x.x)
- **ISP Anomaly:** Connection from cloud hosting provider (Digital Ocean) - not residential/corporate ISP
- **Time Anomaly:** Login occurred at 10:32 PM Singapore time (unusual hour)
- **No MFA:** Account should require MFA per policy, but was bypassed
- **Impossible Travel:** Last legitimate login 6 hours prior from US office (no time for physical travel)

**User Contact Attempt:**
```
14:41:00 UTC - SOC called t.williams mobile: No answer
14:41:30 UTC - SOC called t.williams desk phone: No answer
14:42:00 UTC - SOC contacted IT Manager: Confirmed t.williams on vacation, not working
```

**Verdict:** Account confirmed compromised - legitimate user not responsible for activity.

### Step 3: Lateral Movement & PsExec Analysis

**Query: Document all PsExec activity**
```spl
index=windows_security (EventCode=5140 OR EventCode=4697) src_ip="172.16.50.88"
| table _time, EventCode, dest_host, Account_Name, Share_Name, Service_Name, Service_File_Name
| sort _time
```

**PsExec Attack Chain:**

**Target 1: WS-IT-PC03 (10.0.0.21)**
```
14:35:12 - SMB connection to ADMIN$ share
14:35:28 - PSEXEC.exe copied to remote system
14:35:35 - PSEXESVC service installed
14:35:38 - Command executed: whoami /all
14:36:02 - Command executed: net group "Domain Admins" /domain
```

**Target 2: WS-IT-PC04 (10.0.0.22)**
```
14:36:45 - SMB connection to ADMIN$ share
14:36:58 - PSEXESVC service installed
14:37:12 - Command executed: tasklist
14:37:48 - Command executed: net view \\fileserver /all
```

**Target 3: WS-HR-PC02 (10.0.0.23)**
```
14:38:23 - SMB connection to ADMIN$ share
14:38:35 - PSEXESVC service installed
14:38:52 - Command executed: dir C:\Users /s /b
14:39:15 - Attempted LSASS access (credential dumping)
```

**Analysis:**
- Attacker performed reconnaissance on each system
- Enumerated domain admin accounts and network shares
- Attempted credential harvesting on final target
- Pattern consistent with pre-ransomware reconnaissance
- Attack contained before ransomware deployment or data staging

### Step 4: Command Execution Reconstruction

**Query: Retrieve all commands executed via PsExec**
```spl
index=windows_sysmon EventCode=1 ParentImage="*PSEXESVC.exe" earliest="2026-01-22T14:35:00" latest="2026-01-22T14:40:00"
| table _time, ComputerName, CommandLine, User
| sort _time
```

**Commands Executed:**

| Time | Host | Command | Purpose |
|------|------|---------|---------|
| 14:35:38 | WS-IT-PC03 | whoami /all | Verify privilege level and context |
| 14:36:02 | WS-IT-PC03 | net group "Domain Admins" /domain | Enumerate Domain Admin members |
| 14:36:02 | WS-IT-PC03 | net group "Enterprise Admins" /domain | Enumerate Enterprise Admin members |
| 14:37:12 | WS-IT-PC04 | tasklist | Enumerate running processes (AV/EDR detection) |
| 14:37:28 | WS-IT-PC04 | query user | Identify logged-on users |
| 14:37:48 | WS-IT-PC04 | net view \\\\fileserver /all | Map file server shares |
| 14:38:52 | WS-HR-PC02 | dir C:\Users /s /b | Enumerate user directories |
| 14:39:03 | WS-HR-PC02 | reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" | Enumerate installed software |
| 14:39:15 | WS-HR-PC02 | procdump.exe -accepteula -ma lsass.exe lsass.dmp | Credential dumping (failed - blocked by EDR) |

**Attack Objectives Identified:**
1. ✅ Domain enumeration (successful)
2. ✅ Privilege verification (successful)
3. ✅ Security tool detection (successful)
4. ✅ Network mapping (successful)
5. ❌ Credential harvesting (blocked by EDR)
6. ❌ Ransomware deployment (prevented by containment)

### Step 5: Credential Compromise Investigation

**Query: Trace t.williams account compromise origin**
```spl
index=windows_security Account_Name="t.williams" (EventCode=4624 OR EventCode=4625) earliest="2026-01-15T00:00:00"
| table _time, EventCode, src_ip, Logon_Type, Status
| sort _time
```

**Authentication Timeline:**

| Date | Time | Event | Source IP | Location | Status |
|------|------|-------|-----------|----------|--------|
| 2026-01-19 | 08:15:23 | Login | 10.0.0.50 | Office | Success (legitimate) |
| 2026-01-19 | 17:32:10 | Logout | 10.0.0.50 | Office | Success |
| 2026-01-20 | Failed VPN | 185.220.101.42 | Russia | Failed (wrong password) |
| 2026-01-20 | Failed VPN | 185.220.101.42 | Russia | Failed (wrong password) |
| 2026-01-21 | 03:45:12 | VPN Login | 45.142.122.94 | Netherlands | Success - **First Compromise** |
| 2026-01-21 | 04:12:00 | VPN Logout | 45.142.122.94 | Netherlands | Success |
| 2026-01-22 | 14:32:18 | VPN Login | 203.98.45.123 | Singapore | Success - **This Incident** |

**Compromise Analysis:**
- Initial compromise occurred 2026-01-21 at 03:45:12 UTC (1 day before this incident)
- Attacker tested access briefly (27-minute session) before main attack
- Multiple source IPs suggest use of VPN/proxy infrastructure
- Credential stuffing or password spray likely origin (failed attempts from Russian IP)

**Query: Check for phishing emails to t.williams**
```spl
index=email recipient="t.williams@soclab.local" earliest="2026-01-15T00:00:00"
| search attachment_type IN ("*.zip", "*.html", "*.pdf") OR link_count>5
| table _time, sender, subject, attachment_name, link_count
```

**Result:** 
- Email received 2026-01-18 from "admin@microsoftsecurityteam[.]com"
- Subject: "Urgent: Password Expiration Notice"
- Contained link to credential harvesting page
- User likely entered credentials on fake Microsoft login page

**Root Cause:** Phishing attack leading to credential compromise.

## Indicators of Compromise (IOCs)

| Type | Value | Source | Verdict |
|------|-------|--------|---------|
| IPv4 | 203.98.45.123 | VPN Logs | Malicious - Attacker VPN source (Singapore) |
| IPv4 | 45.142.122.94 | VPN Logs | Malicious - Attacker VPN source (Netherlands) |
| IPv4 | 185.220.101.42 | Windows Security | Suspicious - Failed authentication attempts (Russia) |
| Domain | microsoftsecurityteam[.]com | Email Gateway | Malicious - Phishing domain |
| Account | t.williams | Active Directory | Compromised - Domain Admin credentials stolen |
| Service | PSEXESVC | Windows Event Logs | Suspicious in this context - Lateral movement tool |
| File | PSEXEC.exe | Sysmon File Events | Legitimate tool used maliciously |
| File | procdump.exe | Sysmon Event 1 | Suspicious - Credential dumping attempt |
| File | lsass.dmp | Sysmon Event 11 (attempted) | Malicious - Credential dump file (creation blocked) |

## Verdict

**True Positive — Confirmed Lateral Movement with Compromised Domain Admin**

**Confidence Level:** Very High (100%)

**Evidence:**
1. Domain Admin account confirmed compromised via phishing
2. Authentication from anomalous geographic locations
3. Documented PsExec deployment across multiple hosts
4. Reconnaissance commands consistent with pre-ransomware activity
5. User confirmed not responsible for activity
6. Attempted credential dumping detected
7. Clear attack timeline with correlated logs across systems

**Attack Success:** Partial
- Initial credential compromise successful (phishing)
- Lateral movement to 3 workstations achieved
- Domain reconnaissance successful
- However, credential dumping blocked by EDR
- No ransomware deployed (detected before final stage)
- No data exfiltration occurred
- Contained within 9 minutes of detection

**Threat Actor Assessment:**
- Sophisticated attack (not opportunistic)
- Targeted Domain Admin credentials
- Used legitimate tools (PsExec) to evade detection
- Likely ransomware gang or access broker
- Methodical reconnaissance before payload deployment
- Attack contained before final objectives achieved

## Response Actions Taken

### Immediate Containment (14:40 - 14:48 UTC)

1. **Terminated VPN Session**
   ```bash
   # VPN admin terminated active session
   vpn-cli disconnect-session --user t.williams --session-id 8847392
   ```

2. **Disabled Compromised Account**
   ```powershell
   # Disabled Domain Admin account
   Disable-ADAccount -Identity "t.williams"
   
   # Reset password
   Set-ADAccountPassword -Identity "t.williams" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempP@ssw0rd2026!!" -Force)
   ```

3. **Removed PsExec Services**
   ```powershell
   # Connected to each affected workstation
   $computers = @("WS-IT-PC03", "WS-IT-PC04", "WS-HR-PC02")
   
   foreach ($computer in $computers) {
       Invoke-Command -ComputerName $computer -ScriptBlock {
           Stop-Service -Name "PSEXESVC" -Force
           sc.exe delete PSEXESVC
           Remove-Item "C:\Windows\PSEXESVC.exe" -Force -ErrorAction SilentlyContinue
       }
   }
   ```

4. **Revoked All Active Sessions**
   ```powershell
   # Revoked Kerberos tickets for t.williams
   Get-ADUser t.williams | Set-ADUser -Replace @{msDS-User-Account-Control-Computed=0}
   
   # Forced logoff from all systems
   $sessions = qwinsta /server:* | Select-String "t.williams"
   # Manually terminated 2 active sessions found
   ```

5. **Network Segmentation**
   ```
   # Isolated affected workstations via VLAN ACL
   WS-IT-PC03: Moved to quarantine VLAN
   WS-IT-PC04: Moved to quarantine VLAN
   WS-HR-PC02: Moved to quarantine VLAN
   ```

### Eradication & Investigation (Same Day)

6. **Forensic Data Collection**
   ```powershell
   # Collected memory dumps from all 3 affected systems
   Get-ForensicMemoryDump -ComputerName "WS-IT-PC03" -OutputPath "\\forensics\2026-01-22\WS-IT-PC03.dmp"
   Get-ForensicMemoryDump -ComputerName "WS-IT-PC04" -OutputPath "\\forensics\2026-01-22\WS-IT-PC04.dmp"
   Get-ForensicMemoryDump -ComputerName "WS-HR-PC02" -OutputPath "\\forensics\2026-01-22\WS-HR-PC02.dmp"
   
   # Exported event logs
   wevtutil epl Security \\forensics\2026-01-22\{hostname}_Security.evtx /r:{hostname}
   wevtutil epl System \\forensics\2026-01-22\{hostname}_System.evtx /r:{hostname}
   ```

7. **Malware Scan**
   ```powershell
   # Full EDR scan on all 3 systems
   # Result: No malware or ransomware detected
   # Attacker used only Living Off the Land techniques
   ```

8. **Credential Audit**
   ```powershell
   # Identified all systems where t.williams had recently authenticated
   Get-ADComputer -Filter * | ForEach-Object {
       Get-WinEvent -ComputerName $_.Name -FilterHashtable @{
           LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-7)
       } | Where-Object {$_.Properties[5].Value -eq 't.williams'}
   }
   
   # Found 8 additional systems with cached credentials
   # Forced credential clear on all systems
   ```

### Recovery & Hardening (14:48 - EOD)

9. **Privileged Account Security**
   ```powershell
   # Enabled MFA for all Domain Admin accounts
   Set-ADUser -Identity "t.williams" -Replace @{strongAuthenticationRequirements='MFA'}
   
   # Implemented Privileged Access Workstation (PAW) requirement
   # Domain Admin accounts can only log in from designated secure workstations
   
   # Set up admin account monitoring
   New-GPO -Name "Admin Account Restrictions" | Set-GPLink -Target "OU=Domain Admins,DC=soclab,DC=local"
   ```

10. **VPN Security Enhancements**
    ```
    # Enforced MFA for all VPN connections (no exceptions)
    # Implemented geographic restrictions (block connections from high-risk countries)
    # Enabled anomaly detection for VPN authentications
    # Set up alerting for impossible travel scenarios
    ```

11. **PsExec Monitoring**
    ```spl
    # Enhanced detection rule for PsExec usage
    index=windows_security EventCode=4697 Service_Name="PSEXESVC"
    | eval suspicious=if(Account_Name NOT IN ("approved_admin1", "approved_admin2"), "YES", "NO")
    | where suspicious="YES"
    | table _time, ComputerName, Account_Name, Service_File_Name
    ```

12. **Enhanced Logging**
    ```powershell
    # Enabled PowerShell script block logging
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    
    # Enabled process command line auditing
    auditpol /set /subcategory:"Process Creation" /success:enable
    
    # Enabled SMB share access auditing
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable
    ```

### User Remediation

13. **User Security Review**
    - Met with t.williams to review phishing incident
    - Reviewed suspicious email and fake login page
    - Mandatory security awareness training assigned
    - Password manager deployed to prevent credential reuse
    - Reported phishing domain to authorities and domain registrar

14. **Organization-Wide Actions**
    - Security alert sent to all staff about phishing campaign
    - All Domain Admin credentials rotated as precaution
    - Phishing email indicators distributed to email gateway
    - Increased phishing detection sensitivity on email gateway

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence |
|--------|-----------|-------------|----------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Credential harvesting via fake Microsoft login page |
| Initial Access | Valid Accounts: Domain Accounts | T1078.002 | Compromised t.williams Domain Admin credentials used |
| Persistence | Valid Accounts | T1078 | Maintained access via stolen legitimate credentials |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | PsExec leveraged ADMIN$ shares for remote execution |
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 | VPN access with compromised credentials |
| Execution | System Services: Service Execution | T1569.002 | PSEXESVC service used for remote command execution |
| Discovery | Account Discovery: Domain Account | T1087.002 | Enumerated Domain Admin and Enterprise Admin groups |
| Discovery | Network Share Discovery | T1135 | Enumerated network shares on fileserver |
| Discovery | Process Discovery | T1057 | Used tasklist to enumerate running processes |
| Discovery | System Information Discovery | T1082 | Used whoami and registry queries for system info |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Attempted procdump of lsass.exe (blocked by EDR) |
| Defense Evasion | Valid Accounts | T1078 | Used legitimate Domain Admin account to evade detection |
| Defense Evasion | Use Alternate Authentication Material | T1550 | Leveraged stolen credentials from phishing |

## Lessons Learned

### What Went Well
- Detection rule triggered rapidly (4 minutes after first PsExec deployment)
- Correlation of multiple service installations across hosts enabled quick detection
- Rapid response and containment within 9 minutes
- EDR successfully blocked credential dumping attempt
- Comprehensive logging enabled full attack reconstruction
- Impossible travel detection validated during investigation

### What Could Be Improved
- **MFA Not Enforced:** Domain Admin account accessed without MFA despite policy
- **Phishing Susceptibility:** IT administrator fell victim to credential phishing
- **Delayed Detection:** Initial compromise occurred 1 day before lateral movement detected
- **VPN Security:** Geographic restrictions not enforced on VPN
- **PsExec Usage:** No baseline of legitimate PsExec usage to distinguish malicious activity
- **Privileged Account Monitoring:** No real-time alerting on Domain Admin authentications from unusual locations

### Actions Taken Post-Incident
1. ✅ MFA enforced for all Domain Admin accounts (no exceptions)
2. ✅ VPN geographic restrictions implemented (block high-risk countries)
3. ✅ Impossible travel alerting enabled for privileged accounts
4. ✅ PsExec usage whitelist created (alert on non-approved use)
5. ✅ Privileged Access Workstation (PAW) policy implemented
6. ✅ Real-time alerting on Domain Admin authentications
7. ✅ Enhanced email anti-phishing controls (URL rewriting, link sandboxing)
8. ✅ Quarterly credential phishing simulations for IT staff
9. ✅ Password manager mandatory for all privileged accounts
10. ✅ Credential stuffing detection enabled on VPN gateway

### New Detection Rules Created
- Alert on PSEXESVC service installation from non-whitelisted accounts
- Alert on multiple SMB ADMIN$ share connections within short timeframe
- Alert on Domain Admin authentication from external/VPN sources
- Alert on impossible travel (geographically impossible login timeline)
- Alert on procdump.exe execution or LSASS process access
- Alert on net.exe commands enumerating Domain Admins group

### Metrics
- **Mean Time to Detect (MTTD):** 4 minutes 13 seconds (first PsExec to alert)
- **Mean Time to Contain (MTTC):** 8 minutes 32 seconds (alert to VPN termination)
- **Initial Compromise to Detection:** 1 day 10 hours 54 minutes (phishing to lateral movement alert)
- **Total Active Threat Time:** 15 minutes 42 seconds (VPN session duration)
- **Systems Affected:** 3 workstations (lateral movement targets)
- **Accounts Compromised:** 1 Domain Admin account
- **Data Exfiltrated:** 0 bytes
- **Ransomware Deployed:** No (prevented)
- **Business Impact:** Low (brief disruption, no data loss)

### Follow-up Actions
- [ ] Implement Privileged Identity Management (PIM) with Just-In-Time access
- [ ] Deploy hardware security keys (YubiKey) for all Domain Admins
- [ ] Conduct red team exercise simulating ransomware attack
- [ ] Review and reduce number of Domain Admin accounts
- [ ] Implement tiered admin model (separate admin accounts per privilege level)
- [ ] Schedule annual penetration test focusing on lateral movement
- [ ] Establish formal PAW deployment for all privileged users
