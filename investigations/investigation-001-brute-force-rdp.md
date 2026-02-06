# Investigation 001: RDP Brute Force Attack

## Alert Details

- **Date:** 2025-10-15
- **Alert Source:** Splunk SIEM
- **Alert Name:** Brute Force - Multiple Failed Logins
- **Severity:** Critical
- **MITRE ATT&CK:** Credential Access — Brute Force: Password Guessing (T1110.001)
- **Affected Host:** DC01 (10.0.0.10 - Domain Controller)
- **Affected User:** j.martinez (IT Department)
- **Attacker IP:** 185.220.101.42

## Executive Summary

An external threat actor successfully compromised the domain controller through RDP brute force attack, gaining access with IT user credentials. The attacker created a rogue administrator account and added it to the Domain Admins group, establishing persistent administrative access to the entire domain. Immediate containment prevented further compromise. All affected credentials have been reset and the rogue account removed.

## Timeline of Events

| Time (UTC) | Event | Source | Details |
|------------|-------|--------|---------|
| 2026-01-15 06:14:22 | Brute Force Begins | Windows Security Log | Initial failed RDP attempt from 185.220.101.42 targeting "administrator" account |
| 2026-01-15 06:15:03 - 08:22:47 | Failed Login Attempts | Windows Security (Event 4625) | 847 failed login attempts targeting multiple accounts (administrator, admin, j.martinez, t.williams, root, user, test) |
| 2026-01-15 08:22:51 | Successful Authentication | Windows Security (Event 4624) | Logon Type 10 (RDP) for account "j.martinez" from 185.220.101.42 - password successfully guessed |
| 2026-01-15 08:23:18 | RDP Session Established | Sysmon (Event 3) | Network connection from j.martinez context to external session |
| 2026-01-15 08:24:05 | Account Enumeration | Windows Security (Event 4798) | User j.martinez enumerated Domain Admin group membership |
| 2026-01-15 08:25:42 | Rogue Account Created | Windows Security (Event 4720) | New local account "svc_backup" created by j.martinez |
| 2026-01-15 08:26:19 | Privilege Escalation | Windows Security (Event 4732) | Account "svc_backup" added to local Administrators group |
| 2026-01-15 08:27:03 | Domain Admin Added | Windows Security (Event 4728) | Account "svc_backup" added to Domain Admins group - full domain control achieved |
| 2026-01-15 08:28:31 | Persistence Attempt | Sysmon (Event 13) | Registry Run key modification detected for svc_backup account |
| 2026-01-15 08:29:44 | **Alert Fired** | Splunk Alert | Brute force detection rule triggered on 847 failed attempts |
| 2026-01-15 08:31:00 | Analyst Response Begin | SOC Action Log | Senior analyst began investigation |
| 2026-01-15 08:35:12 | Containment Started | SOC Action Log | Attacker IP 185.220.101.42 blocked at firewall |
| 2026-01-15 08:37:29 | Account Disabled | Active Directory | Compromised account j.martinez disabled |
| 2026-01-15 08:38:45 | Rogue Account Removed | Active Directory | Malicious account svc_backup deleted from AD |
| 2026-01-15 08:42:00 | Incident Contained | SOC Action Log | All attacker access terminated, investigation ongoing |

## Investigation Steps

### Step 1: Initial Alert Review

**Alert Triggered:** Splunk rule "Brute Force - Multiple Failed Logins" fired at 08:29:44 UTC.

**Alert Details:**
```
Source IP: 185.220.101.42
Target Accounts: Multiple (administrator, admin, j.martinez, t.williams)
Failed Attempts: 847
Time Window: 2 hours 8 minutes
Target System: DC01 (Domain Controller)
```

**Initial Assessment:** Critical severity due to:
- High volume of failed attempts (847)
- Targeting domain controller
- External source IP
- Multiple accounts targeted

### Step 2: SIEM Query & Log Analysis

**Query 1: Verify failed login attempts**
```spl
index=windows_security EventCode=4625 src_ip="185.220.101.42" earliest="2026-01-15T06:00:00" latest="2026-01-15T09:00:00"
| stats count by Account_Name
| sort -count
```

**Results:**
- administrator: 312 failures
- admin: 198 failures
- j.martinez: 319 failures (eventually successful)
- t.williams: 18 failures

**Query 2: Check for successful authentication**
```spl
index=windows_security EventCode=4624 src_ip="185.220.101.42" earliest="2025-10-15T06:00:00"
| table _time, Account_Name, Logon_Type, Workstation_Name
```

**Critical Finding:** Event 4624 at 08:22:51 UTC - j.martinez successfully authenticated via RDP (Logon Type 10) from 185.220.101.42.

**Query 3: Post-authentication activity**
```spl
index=windows_security ComputerName="DC01" Account_Name="j.martinez" earliest="2025-10-15T08:22:51"
| table _time, EventCode, Activity, Target_Account
```

**Findings:**
- Event 4798: Group enumeration (Domain Admins)
- Event 4720: New account "svc_backup" created
- Event 4732: svc_backup added to local Administrators
- Event 4728: svc_backup added to Domain Admins

### Step 3: Endpoint Analysis

**Sysmon Analysis:**
```spl
index=windows_sysmon ComputerName="DC01" User="j.martinez" earliest="2025-10-15T08:22:51" latest="2025-10-15T08:30:00"
| table _time, EventCode, Image, CommandLine, TargetObject
| sort _time
```

**Findings:**
- No suspicious process execution detected (attacker used native tools only)
- Registry modification (Event 13): Run key added for svc_backup
- No malware dropped or executed
- Attack used Living Off the Land (LOtL) techniques

**Network Connections:**
```spl
index=windows_sysmon EventCode=3 ComputerName="DC01" earliest="2025-10-15T08:22:51" latest="2025-10-15T08:30:00"
| table _time, Image, DestinationIp, DestinationPort
```

**Findings:**
- RDP session maintained from 185.220.101.42
- No additional outbound connections (no C2)
- No lateral movement to other internal systems

### Step 4: Threat Intelligence Enrichment

**IP Address Analysis: 185.220.101.42**

**AbuseIPDB Results:**
- Abuse Confidence Score: 100%
- Total Reports: 1,247
- Country: Russia
- ISP: Unknown VPS provider
- Recent Activity: RDP brute force, SSH brute force
- Active on: 342 blacklists

**VirusTotal Results:**
- 18/89 security vendors flagged as malicious
- Categories: Malicious activity, brute force source
- Associated domains: None
- No malware distribution detected

**Shodan Results:**
- Open Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 8080 (HTTP-Proxy)
- Services: OpenSSH 7.4, Apache
- Banner: Generic Linux server
- Assessment: Likely compromised VPS used for attacks

**Threat Actor Assessment:**
- Unsophisticated attacker (simple brute force, no evasion)
- Opportunistic attack (no targeted reconnaissance)
- Goal: Establish persistent access for potential ransomware, crypto mining, or access brokering
- Likely part of automated botnet scanning internet for open RDP

### Step 5: Scope Assessment

**Question: Were other hosts affected?**
```spl
index=windows_security src_ip="185.220.101.42" ComputerName!=DC01
| stats count by ComputerName
```

**Result:** No activity on other internal systems. Attack focused solely on domain controller.

**Question: Did attacker access sensitive data?**
```spl
index=windows_security ComputerName="DC01" EventCode=4663 Account_Name="j.martinez" earliest="2025-10-15T08:22:51"
| table _time, Object_Name, Access_Mask
```

**Result:** No file access events logged during compromised session. Attacker focused on account creation and privilege escalation only.

**Question: Was lateral movement attempted?**
```spl
index=windows_security EventCode=4624 Account_Name="j.martinez" OR Account_Name="svc_backup" ComputerName!=DC01
| table _time, ComputerName, src_ip, Logon_Type
```

**Result:** No lateral movement detected. Incident contained to single DC.

## Indicators of Compromise (IOCs)

| Type | Value | Source | Verdict |
|------|-------|--------|---------|
| IPv4 | 185.220.101.42 | Windows Security Logs | Malicious - Confirmed attacker IP |
| Account | svc_backup | Active Directory | Malicious - Rogue administrator account |
| Account | j.martinez | Active Directory | Compromised - Weak password |
| Registry Key | HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate | Sysmon Event 13 | Malicious - Persistence mechanism |
| Technique | RDP Brute Force | Attack Pattern | T1110.001 |
| Technique | Account Creation | Attack Pattern | T1136.001 |

## Verdict

**True Positive — Confirmed Successful Brute Force with Post-Exploitation**

**Confidence Level:** Very High (100%)

**Evidence:**
1. 847 documented failed login attempts from single external IP
2. Successful authentication after failed attempts
3. Malicious post-compromise activity (account creation, privilege escalation)
4. External IP confirmed malicious by multiple threat intelligence sources
5. Clear attack timeline with correlated logs

**Attack Success:** Partial
- Attacker gained Domain Admin level access
- However, detected and contained within 10 minutes of successful login
- No data exfiltration occurred
- No lateral movement achieved
- No ransomware or malware deployed

## Response Actions Taken

### Immediate Containment (08:31 - 08:42 UTC)

1. **Blocked Attacker IP**
   ```powershell
   # Added firewall rule
   New-NetFirewallRule -DisplayName "Block Attacker 185.220.101.42" `
       -Direction Inbound -RemoteAddress 185.220.101.42 -Action Block
   ```

2. **Disabled Compromised Account**
   ```powershell
   Disable-ADAccount -Identity "j.martinez"
   ```

3. **Terminated Active RDP Session**
   ```powershell
   query session /server:DC01
   logoff <session_id> /server:DC01
   ```

4. **Removed Rogue Administrator Account**
   ```powershell
   Remove-ADUser -Identity "svc_backup" -Confirm:$false
   ```

5. **Removed Persistence Mechanism**
   ```powershell
   Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate"
   ```

### Eradication & Recovery (Same Day)

6. **Password Reset for Compromised Account**
   - j.martinez password reset to complex 16-character password
   - User contacted and informed of compromise
   - Mandatory password change enforced

7. **Security Audit**
   ```powershell
   # Verified no additional rogue accounts
   Get-ADUser -Filter * -Properties Created, PasswordLastSet | 
       Where-Object {$_.Created -gt (Get-Date).AddDays(-1)} |
       Select-Object Name, Created, Enabled
   
   # Verified Domain Admins group membership
   Get-ADGroupMember -Identity "Domain Admins"
   ```

8. **Restricted RDP Access**
   ```powershell
   # Configured Group Policy to allow RDP only from internal IPs
   # Disabled RDP on domain controller from internet
   # Implemented RDP Gateway with MFA for remote access
   ```

9. **Enhanced Logging**
   ```powershell
   # Enabled account lockout policy
   Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 `
       -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00
   
   # Enabled advanced audit policies
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
   ```

### Lessons Learned & Prevention

10. **Implemented Immediate Improvements**
    - RDP port 3389 closed to internet on firewall
    - VPN with MFA required for all remote access
    - Geographic IP blocking enabled (blocked Russia, China, North Korea)
    - Fail2Ban deployed to auto-block brute force attempts
    - All user accounts scanned for weak passwords

11. **Created New Detection Rule**
    ```spl
    # Alert on ANY external RDP connection attempt
    index=windows_security EventCode=4625 Logon_Type=10
    | eval src_external=if(like(src_ip, "10.%") OR like(src_ip, "192.168.%"), "no", "yes")
    | where src_external="yes"
    | table _time, src_ip, Account_Name, ComputerName
    ```

12. **User Awareness**
    - Security awareness email sent to all staff
    - IT department briefed on password security
    - Password policy updated: minimum 14 characters, complexity required
    - Passwordstate password manager deployed for IT team

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence |
|--------|-----------|-------------|----------|
| Initial Access | Valid Accounts | T1078 | Successful authentication with compromised credentials |
| Credential Access | Brute Force: Password Guessing | T1110.001 | 847 failed login attempts, eventually successful |
| Persistence | Account Manipulation: Additional Windows Credentials | T1098 | Rogue account "svc_backup" created |
| Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 | Registry Run key modification for persistence |
| Privilege Escalation | Valid Accounts: Domain Accounts | T1078.002 | svc_backup added to Domain Admins group |
| Defense Evasion | Valid Accounts | T1078 | Used legitimate credentials to avoid detection |

## Lessons Learned

### What Went Well
- Detection rule triggered within 7 minutes of successful compromise
- Rapid containment (11 minutes from alert to full containment)
- No data loss or lateral movement occurred
- Comprehensive logging enabled full attack reconstruction
- Clear escalation procedures followed

### What Could Be Improved
- **Prevention Gap:** RDP should never have been exposed to internet
- **Password Weakness:** User password was susceptible to brute force (likely common password)
- **Detection Delay:** 847 attempts occurred before detection (threshold too high)
- **No MFA:** Multi-factor authentication would have prevented compromise even with correct password
- **Monitoring Gap:** Real-time alerting on account creation/modification not configured

### Actions Taken Post-Incident
1. ✅ RDP internet exposure eliminated
2. ✅ VPN with MFA implemented
3. ✅ Account lockout policy enforced (5 attempts, 30-minute lockout)
4. ✅ Geographic IP blocking enabled
5. ✅ Failed login threshold reduced to 10 attempts for alerting
6. ✅ Real-time alerting on privileged group modifications
7. ✅ Password policy strengthened (14 chars minimum)
8. ✅ Quarterly password audits scheduled
9. ✅ Incident response playbook updated
10. ✅ Monthly security awareness training implemented

### New Detection Rules Created
- Alert on external RDP connection attempts (any source outside 10.0.0.0/8)
- Alert on new account added to privileged groups (Domain Admins, Enterprise Admins)
- Alert on account lockouts exceeding 3 within 1 hour
- Alert on successful login after 5+ failed attempts from same source

### Metrics
- **Mean Time to Detect (MTTD):** 7 minutes 9 seconds (from successful login to alert)
- **Mean Time to Contain (MTTC):** 11 minutes 18 seconds (from alert to containment)
- **Total Incident Duration:** 18 minutes 27 seconds (successful login to full containment)
- **Systems Affected:** 1 (DC01)
- **Accounts Compromised:** 1 (j.martinez)
- **Data Exfiltrated:** 0 bytes
- **Business Impact:** Minimal (no downtime, no data loss)

### Follow-up Actions
- [ ] Penetration test scheduled to validate RDP controls (30 days)
- [ ] Quarterly security assessment of all internet-facing services
- [ ] Security awareness training completion tracking
- [ ] Password manager adoption rate monitoring
- [ ] Implement Privileged Access Management (PAM) solution for admin accounts
