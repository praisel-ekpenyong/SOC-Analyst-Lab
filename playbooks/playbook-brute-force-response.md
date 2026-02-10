# PB-002: Brute Force / Account Compromise Response Playbook

## Playbook Metadata

- **Playbook ID:** PB-002
- **Title:** Brute Force / Account Compromise Response
- **Version:** 1.0
- **Severity:** High to Critical (depending on success and target)
- **Owner:** SOC Tier 1 Team
- **Last Updated:** 2026-02-10
- **Review Cycle:** Quarterly
- **MITRE ATT&CK:** Credential Access - Brute Force (T1110), T1110.001 (Password Guessing), T1110.003 (Password Spraying)

## Purpose

This playbook provides standardized procedures for responding to brute force attacks and account compromise incidents. It guides SOC analysts through detection, triage, containment, and investigation to prevent unauthorized access and mitigate credential-based attacks.

## Trigger Conditions

This playbook should be initiated when:

- **SIEM Alert:** Multiple failed login attempts from single source IP within short timeframe
- **Account Lockout Alert:** Multiple accounts locked out in short period
- **Authentication Alert:** Successful authentication after multiple failures
- **Impossible Travel:** User login from geographically impossible locations
- **EDR Alert:** Pass-the-hash or credential dumping detection
- **User Report:** User reports unexpected account lockout or suspicious login notifications
- **IDS/IPS Alert:** Brute force signature match on authentication services

## Scope

**In Scope:**
- Password guessing attacks (targeted brute force)
- Password spraying attacks (low-and-slow across many accounts)
- Credential stuffing (using leaked credentials)
- SSH/RDP/VPN brute force attempts
- Web application authentication attacks
- Post-compromise account activity
- Lateral movement using compromised credentials

**Out of Scope:**
- Social engineering credential theft - Use phishing playbook
- Physical access credential theft - Escalate to physical security
- Insider threat credential abuse - Escalate to insider threat team
- Password reset fraud - Escalate to identity management team

## Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Successful compromise of privileged account (admin, service account), evidence of data exfiltration, multiple accounts compromised, ransomware deployment |
| **High** | Successful authentication after brute force, executive account targeted, VPN/remote access compromised, lateral movement detected |
| **Medium** | Failed brute force attempts only, single account lockout, suspicious geolocation, known scanner IP |
| **Low** | Single failed login, no pattern detected, benign explanation confirmed |

## Investigation Steps

### Step 1: Initial Triage (5 minutes)

**Objective:** Determine if alert is legitimate brute force activity.

**Actions:**
1. Review the triggering alert details:
   - **Source IP Address:** Where is attack coming from?
   - **Target Account(s):** Which user(s) are being targeted?
   - **Time Range:** When did activity occur?
   - **Failure Count:** How many failed attempts?
   - **Success Count:** Were any attempts successful?
   - **Service:** SSH, RDP, VPN, web app, other?

2. Document initial observations:
   - Is this single IP or distributed attack?
   - Is this targeting single user or password spray?
   - Is source IP internal or external?
   - Are there any successful authentications?

**Splunk Query - Recent Failed Logins:**
```spl
index=windows_security EventCode=4625 earliest=-1h
| stats count by src_ip, Account_Name, Logon_Type, Failure_Reason
| where count > 10
| sort -count
```

**Splunk Query - Linux Failed Logins:**
```spl
index=linux_auth "Failed password" earliest=-1h
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip, user
| where count > 10
| sort -count
```

**Splunk Query - VPN Failed Authentications:**
```spl
index=vpn_logs action="failed" OR status="failure" earliest=-1h
| stats count by src_ip, username, reason
| where count > 5
| sort -count
```

### Step 2: Source IP Analysis (5 minutes)

**Objective:** Determine if source IP is malicious and understand attack origin.

**Actions:**

1. **Extract and Defang Source IP:**
   - Example: `192.168.1.100` → `192[.]168[.]1[.]100`
   - For multiple IPs, prioritize those with most attempts or successful auth

2. **Determine IP Type:**
   - **Internal IP:** RFC1918 ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
   - **External IP:** Public Internet address
   - **Cloud Provider:** AWS, Azure, GCP ranges
   - **VPN/Proxy:** Corporate VPN exit nodes

3. **AbuseIPDB Lookup:**
   - URL: https://www.abuseipdb.com/
   - Check Abuse Confidence Score
   - Review categories (brute force, bad web bot, port scan)
   - Check recent reports and timeframe
   - **Verdict Criteria:**
     - Score >80% = Known malicious, likely botnet
     - Score 50-80% = Suspicious, compromised host
     - Score <50% = Unknown or low confidence

4. **VirusTotal IP Lookup:**
   - URL: https://www.virustotal.com/
   - Check detection ratio
   - Review WHOIS information (ASN, country, org)
   - Check for malware communication history
   - **Verdict Criteria:**
     - 3+ vendors flagging = Malicious
     - 1-2 vendors = Suspicious
     - 0 vendors = Unknown

5. **Geolocation Check:**
   - Use MaxMind, IP2Location, or built-in SIEM lookup
   - Compare to user's known locations
   - Look for red flag countries (if org has no presence there)
   - Check for data center IPs (common for VPS-based attacks)

**Splunk Query - IP History Check:**
```spl
index=* src_ip="192[.]168[.]1[.]100" earliest=-30d
| stats count by index, sourcetype, action, user
| sort -count
```

**Splunk Query - Check if IP Previously Successful:**
```spl
index=windows_security (EventCode=4624 OR EventCode=4625) src_ip="192.168.1.100" earliest=-7d
| stats count by EventCode, Account_Name, _time
| eval status=if(EventCode=4624, "Success", "Failure")
| table _time, status, Account_Name, count
| sort _time
```

### Step 3: Target Account Analysis (10 minutes)

**Objective:** Identify targeted accounts and assess compromise risk.

**Actions:**

1. **Identify Attack Pattern:**
   - **Brute Force (Vertical):** Many attempts against single account
   - **Password Spray (Horizontal):** Few attempts against many accounts
   - **Credential Stuffing:** Known username/password pairs

2. **Document Target Accounts:**
   - List all accounts with failed login attempts
   - Identify privileged accounts (administrators, service accounts)
   - Check for default usernames (admin, administrator, root, test)
   - Note accounts with successful login after failures

3. **Check Account Status:**
   - Is account currently locked out?
   - Is account disabled?
   - Is account privileged or standard user?
   - When was password last changed?
   - Is MFA enabled for account?

4. **Review Account Activity:**
   - Check recent successful logins
   - Review resource access patterns
   - Look for unusual behavior

**Splunk Query - Account Activity Timeline:**
```spl
index=windows_security Account_Name="targeted_user" (EventCode=4624 OR EventCode=4625 OR EventCode=4740) earliest=-24h
| eval event_type=case(
    EventCode=4624, "Successful Login",
    EventCode=4625, "Failed Login",
    EventCode=4740, "Account Lockout")
| table _time, event_type, src_ip, Logon_Type, Workstation_Name
| sort _time
```

**Splunk Query - Privileged Account Login Check:**
```spl
index=windows_security EventCode=4672 earliest=-24h
| eval Account_Name=mvindex(split(Account_Name, "@"), 0)
| stats count by Account_Name, src_ip, _time
| sort -_time
```

**Splunk Query - Account Lockout Events:**
```spl
index=windows_security EventCode=4740 earliest=-24h
| table _time, Account_Name, caller_computer, src_ip
| sort -_time
```

### Step 4: Check for Successful Authentication (10 minutes)

**Objective:** Determine if any brute force attempts were successful.

**⚠️ CRITICAL: Successful authentication after multiple failures indicates likely compromise.**

**Actions:**

1. **Search for Successful Logins:**
   - Check if any accounts had successful login from source IP
   - Look at timeframe: during or after failed attempts?
   - Identify logon type (network, interactive, RDP, service)

2. **Successful Login Indicators:**
   - Windows Event ID 4624 (Successful logon)
   - Linux `/var/log/auth.log` "Accepted password"
   - VPN logs: "Connection established" or "Authenticated"
   - Web app logs: HTTP 200 response to /login

3. **Logon Type Analysis (Windows):**
   - **Type 2:** Interactive (console login)
   - **Type 3:** Network (SMB file share)
   - **Type 7:** Unlock (screen unlock)
   - **Type 10:** RemoteInteractive (RDP/TS)
   - **Type 4/5:** Batch/Service (automated tasks)

**Splunk Query - Successful Auth After Failures:**
```spl
(index=windows_security (EventCode=4624 OR EventCode=4625) earliest=-24h)
| stats count(eval(EventCode=4625)) as failures, 
        count(eval(EventCode=4624)) as successes,
        values(_time) as times
  by src_ip, Account_Name
| where failures > 10 AND successes > 0
| sort -failures
```

**Splunk Query - Successful RDP Logins:**
```spl
index=windows_security EventCode=4624 Logon_Type=10 earliest=-24h
| table _time, Account_Name, src_ip, ComputerName, Logon_Process
| sort -_time
```

**Splunk Query - VPN Successful Connections:**
```spl
index=vpn_logs (action="success" OR status="connected") earliest=-24h
| table _time, username, src_ip, connection_duration, bytes_transferred
| sort -_time
```

**Splunk Query - SSH Successful Logins:**
```spl
index=linux_auth "Accepted password" OR "Accepted publickey" earliest=-24h
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time, user, src_ip, host
| sort -_time
```

### Step 5: Post-Compromise Activity Check (15 minutes)

**Objective:** If compromise confirmed, identify what attacker did after gaining access.

**⚠️ Execute this step ONLY if successful authentication was identified.**

**Actions:**

1. **Identify Compromised System(s):**
   - Hostname where successful login occurred
   - Services accessed (file shares, databases, applications)
   - Duration of access

2. **Check for Lateral Movement:**
   - Did attacker move to other systems?
   - Were additional accounts accessed?
   - Were credentials used on multiple systems?

3. **Check for Privilege Escalation:**
   - Did attacker gain admin rights?
   - Were admin tools executed?
   - Were new accounts created?

4. **Check for Data Access:**
   - What files/folders were accessed?
   - Were files downloaded or exfiltrated?
   - Were databases queried?

5. **Check for Persistence:**
   - Were scheduled tasks created?
   - Were services installed?
   - Were registry keys modified?
   - Were SSH keys added?

**Splunk Query - Commands Executed by Compromised Account:**
```spl
index=windows_sysmon EventCode=1 User="compromised_user" earliest=-24h
| table _time, ComputerName, Image, CommandLine, ParentImage
| sort -_time
```

**Splunk Query - File Access by Compromised Account:**
```spl
index=windows_security EventCode=4663 Account_Name="compromised_user" earliest=-24h
| where Object_Type="File"
| stats count by Object_Name, Access_Mask
| sort -count
```

**Splunk Query - Network Connections from Compromised System:**
```spl
index=windows_sysmon EventCode=3 ComputerName="compromised_host" earliest=-24h
| table _time, Image, DestinationIp, DestinationPort, DestinationHostname
| sort -_time
```

**Splunk Query - Lateral Movement Detection (RDP):**
```spl
index=windows_security EventCode=4624 Logon_Type=10 Account_Name="compromised_user" earliest=-24h
| stats dc(ComputerName) as unique_systems, values(ComputerName) as systems by Account_Name, src_ip
| where unique_systems > 1
```

**Splunk Query - New Account Creation:**
```spl
index=windows_security EventCode=4720 earliest=-24h
| table _time, Account_Name, Creator_Account, ComputerName
| sort -_time
```

**Splunk Query - Account Added to Privileged Group:**
```spl
index=windows_security EventCode=4728 OR EventCode=4732 OR EventCode=4756 earliest=-24h
| eval group_name=case(
    EventCode=4728, "Security-Enabled Global Group",
    EventCode=4732, "Security-Enabled Local Group", 
    EventCode=4756, "Security-Enabled Universal Group")
| table _time, Member_Name, Group_Name, Changed_By
| sort -_time
```

**Splunk Query - Scheduled Task Creation:**
```spl
index=windows_security EventCode=4698 earliest=-24h
| table _time, Task_Name, Account_Name, ComputerName
| sort -_time
```

**Splunk Query - Service Installation:**
```spl
index=windows_security EventCode=7045 earliest=-24h
| table _time, Service_Name, Service_File_Name, Account_Name, ComputerName
| sort -_time
```

### Step 6: Threat Intelligence Enrichment (5 minutes)

**Objective:** Gather additional context about the threat actor and TTPs.

**Actions:**

1. **Check Threat Intelligence Platforms:**
   - **AlienVault OTX:** Check for IP/domain reputation
   - **ThreatCrowd:** Check for associated infrastructure
   - **GreyNoise:** Determine if IP is mass internet scanner

2. **Search for Known Attack Campaigns:**
   - Check if source IP part of known botnet
   - Look for associated malware families
   - Review recent security advisories

3. **Check for Similar Historical Incidents:**
   - Search incident tickets for same source IP
   - Look for patterns in targeted accounts
   - Review resolution of similar past incidents

**Splunk Query - Historical Incidents from Same IP:**
```spl
index=incident_tracking src_ip="192[.]168[.]1[.]100" OR source_ip="192.168.1.100"
| table _time, incident_id, title, severity, status, resolution
| sort -_time
```

### Step 7: Determine Verdict (5 minutes)

**Objective:** Make final determination on the incident severity and next steps.

**Verdict Categories:**

**1. CRITICAL - ACTIVE COMPROMISE**
- Successful authentication confirmed
- Post-compromise activity detected
- Privileged account compromised
- Data exfiltration suspected
- Multiple systems affected

**Action:** Immediate containment, escalate to Tier 2/3, activate incident response team

---

**2. HIGH - SUCCESSFUL AUTHENTICATION**
- Successful login after brute force
- No post-compromise activity detected (yet)
- Standard user account
- Single system access

**Action:** Immediate containment, reset credentials, continue monitoring

---

**3. MEDIUM - FAILED BRUTE FORCE**
- Multiple failed authentication attempts
- No successful authentications
- Known malicious source IP
- Automated attack (botnet, scanner)

**Action:** Block source IP, monitor for recurrence, notify user if account locked

---

**4. LOW - FALSE POSITIVE**
- Single or few failed attempts
- Legitimate user with wrong password
- Known corporate IP address
- User confirms they forgot password

**Action:** Close ticket, document for tracking, no containment needed

---

**5. ONGOING - PASSWORD SPRAY**
- Low volume attempts across many accounts
- Difficult to detect individual threshold
- May indicate APT or sophisticated attacker

**Action:** Enhance monitoring, implement additional controls, threat hunt

## Containment Actions

### Immediate Actions (Within 15 minutes):

1. **Block Source IP Address:**
   - Add to firewall deny list
   - Add to IPS/IDS block signatures
   - Add to proxy/VPN block list

   ```bash
   # Linux iptables - Block IP
   iptables -A INPUT -s 192.168.1.100 -j DROP
   iptables -A OUTPUT -d 192.168.1.100 -j DROP
   
   # Palo Alto - Add to block list
   set address malicious-ip-192-168-1-100 ip-netmask 192.168.1.100/32
   set rulebase security rules BLOCK_MALICIOUS_IP source malicious-ip-192-168-1-100 action deny
   
   # Cisco ASA - Block IP
   access-list OUTSIDE_IN deny ip host 192.168.1.100 any
   ```

2. **Disable Compromised Account(s):**
   - Immediately disable any confirmed compromised accounts
   - Prevent further unauthorized access

   ```powershell
   # Active Directory - Disable account
   Disable-ADAccount -Identity compromised_user
   
   # Linux - Lock account
   usermod -L compromised_user
   passwd -l compromised_user
   ```

3. **Terminate Active Sessions:**
   - Kill any active sessions for compromised accounts
   - Force logoff from all systems

   ```powershell
   # Windows - Query and terminate sessions
   query user compromised_user
   logoff [session_id]
   
   # Or force disconnect RDP session
   qwinsta /server:servername
   rwinsta [session_id] /server:servername
   ```

   ```bash
   # Linux - Kill user sessions
   pkill -KILL -u compromised_user
   
   # Or force logout
   who | grep compromised_user
   skill -KILL -u compromised_user
   ```

### Short-term Actions (Within 1 hour):

4. **Force Password Reset:**
   - Reset password for compromised account(s)
   - Use strong, randomly generated password
   - Require password change at next logon

   ```powershell
   # Active Directory - Force password reset
   $newPassword = ConvertTo-SecureString "T3mp0r@ry!P@ssw0rd#2026" -AsPlainText -Force
   Set-ADAccountPassword -Identity compromised_user -NewPassword $newPassword -Reset
   Set-ADUser -Identity compromised_user -ChangePasswordAtLogon $true
   ```

5. **Revoke Tokens and Sessions:**
   - Revoke OAuth/API tokens
   - Invalidate session cookies
   - Clear cached credentials

   ```powershell
   # Azure AD - Revoke user sessions
   Revoke-AzureADUserAllRefreshToken -ObjectId user@domain.com
   
   # Microsoft 365 - Revoke sessions
   Revoke-SPOUserSession -User user@domain.com
   ```

6. **Enable/Verify MFA:**
   - Ensure MFA is enabled for account
   - Reset MFA tokens/devices
   - Verify phone numbers and backup codes

   ```powershell
   # Azure AD - Check MFA status
   Get-MsolUser -UserPrincipalName user@domain.com | Select-Object DisplayName, StrongAuthenticationRequirements
   
   # Azure AD - Enable MFA
   $mfa = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
   $mfa.RelyingParty = "*"
   $mfa.State = "Enabled"
   Set-MsolUser -UserPrincipalName user@domain.com -StrongAuthenticationRequirements $mfa
   ```

7. **Check for Mailbox Rules/Forwarding:**
   - Review inbox rules (may auto-delete/forward emails)
   - Check for email forwarding to external addresses
   - Look for delegated access changes

   ```powershell
   # Check inbox rules
   Get-InboxRule -Mailbox compromised_user | Format-Table Name, Description, Enabled, Priority
   
   # Check forwarding
   Get-Mailbox -Identity compromised_user | Select-Object ForwardingSMTPAddress, DeliverToMailboxAndForward
   
   # Check mailbox delegation
   Get-MailboxPermission -Identity compromised_user | Where-Object {$_.IsInherited -eq $false}
   ```

### If Lateral Movement Detected:

8. **Isolate Affected Systems:**
   - Use EDR to network-isolate compromised hosts
   - Disconnect from network if EDR unavailable
   - Prevent further spread

9. **Reset Credentials for All Accessed Accounts:**
   - Identify all accounts used on compromised system
   - Reset passwords for all potentially compromised accounts
   - Review service account credentials

10. **Scan for Malware/Persistence:**
    - Run full AV/EDR scan on affected systems
    - Check for backdoors, rootkits, persistence mechanisms
    - Review scheduled tasks, services, startup items

**Splunk Query - Identify All Accounts on Compromised System:**
```spl
index=windows_security EventCode=4624 ComputerName="compromised_host" earliest=-7d
| stats count by Account_Name, Logon_Type
| sort -count
```

## Eradication

1. **Remove Attacker Persistence:**
   - Delete malicious scheduled tasks
   - Remove unauthorized services
   - Delete backdoor accounts
   - Remove SSH authorized_keys entries
   - Clear registry persistence keys

   ```powershell
   # Windows - Remove scheduled task
   Get-ScheduledTask -TaskName "SuspiciousTask" | Unregister-ScheduledTask -Confirm:$false
   
   # Remove service
   Stop-Service -Name "MaliciousService" -Force
   sc.exe delete "MaliciousService"
   ```

   ```bash
   # Linux - Remove cron jobs
   crontab -u compromised_user -r
   
   # Remove SSH keys
   rm /home/compromised_user/.ssh/authorized_keys
   
   # Remove systemd service
   systemctl stop malicious.service
   systemctl disable malicious.service
   rm /etc/systemd/system/malicious.service
   ```

2. **Update Detection Rules:**
   - Add source IPs to threat intelligence feeds
   - Update SIEM correlation rules for similar patterns
   - Enhance authentication monitoring

   ```spl
   # Add to threat intelligence lookup
   | inputlookup brute_force_iocs.csv
   | append [| makeresults 
       | eval src_ip="192[.]168[.]1[.]100", 
              ioc_type="ip_address", 
              threat_name="Brute Force Campaign 2026-02-10",
              confidence="high",
              first_seen="2026-02-10",
              last_seen="2026-02-10"]
   | outputlookup brute_force_iocs.csv
   ```

3. **Patch Vulnerabilities (if applicable):**
   - If attack exploited weak passwords, enforce password policy
   - If attack bypassed MFA, review MFA implementation
   - Update authentication services to latest versions
   - Disable legacy authentication protocols (NTLMv1, SSHv1)

4. **Remove Malware (if applicable):**
   - Use EDR remediation tools
   - Manual removal if needed
   - Restore from clean backup if heavily compromised

## Recovery

1. **Re-enable Account (when safe):**
   - After password reset and verification
   - After MFA reconfiguration
   - After confirming no persistence remains

   ```powershell
   # Active Directory - Re-enable account
   Enable-ADAccount -Identity compromised_user
   ```

2. **User Notification Template:**
   ```
   Subject: Security Alert - Account Security Incident
   
   Dear [User Name],
   
   Our security team has detected and responded to a security incident involving your account:
   
   Account: [username]
   Incident Type: Unauthorized access attempt / Brute force attack
   Date/Time: [YYYY-MM-DD HH:MM UTC]
   Source: [Defanged IP / Geographic location]
   
   ACTIONS TAKEN:
   - Your account password has been reset
   - Active sessions have been terminated
   - Multi-factor authentication has been enabled/reset
   - Source IP address has been blocked
   
   REQUIRED ACTIONS:
   1. Change your password immediately using the reset link below
   2. Choose a strong, unique password (minimum 12 characters)
   3. Reconfigure multi-factor authentication
   4. Review recent account activity for unauthorized actions
   5. Report any suspicious emails or activities
   
   WHAT TO LOOK FOR:
   - Unexpected password reset emails
   - Unrecognized login location notifications
   - Missing or moved files/emails
   - Inbox rules you didn't create
   - Emails you didn't send
   
   If you notice any of the above, contact security immediately.
   
   Password Reset Link: [Include secure reset link]
   
   Questions? Contact: security@company.com or ext. 5555
   
   Thank you for your cooperation,
   Security Operations Center
   ```

3. **Enhanced Monitoring (30 days):**
   - Flag account for enhanced authentication logging
   - Alert on any authentication from new locations
   - Monitor for unusual resource access
   - Watch for account privilege changes

   **Splunk Alert - Enhanced Monitoring:**
   ```spl
   index=windows_security Account_Name="previously_compromised_user" EventCode=4624
   | stats count by src_ip, Logon_Type, ComputerName
   | eval alert_condition="Monitor for 30 days"
   ```

4. **Review and Update Security Controls:**
   - Assess effectiveness of current controls
   - Implement additional protections:
     - Account lockout policies
     - Password complexity requirements
     - Rate limiting on authentication endpoints
     - Geographic access restrictions
     - Conditional access policies
   - Consider implementing CAPTCHA for repeated failures

## Escalation Criteria

**Escalate to Tier 2/3 if:**
- Privileged account successfully compromised
- Evidence of lateral movement or persistence
- Multiple accounts compromised in coordinated attack
- Attacker still has active access despite containment attempts
- APT indicators or sophisticated attacker TTPs
- Data exfiltration confirmed
- Ransomware deployment detected
- Critical system (domain controller, database server) compromised

**Escalate to Management if:**
- C-level or executive account compromised
- Customer data accessed or exfiltrated
- Business-critical system compromised
- Regulatory reporting required (PCI-DSS, HIPAA, GDPR)
- Media/PR response needed
- Potential financial fraud

**Escalate to Law Enforcement if:**
- Nation-state actor suspected
- Organized cybercrime group identified
- Losses exceed organizational threshold (e.g., >$50,000)
- Required by regulation or legal counsel

**Escalate to External IR Firm if:**
- Organization lacks capability to contain
- Advanced forensics required
- Legal hold and evidence preservation needed
- Scope exceeds internal team capacity

## Documentation Requirements

**Minimum Required Documentation:**
- Alert details and triggering conditions
- Source IP addresses (defanged) and geolocation
- Target accounts and authentication timeline
- Successful vs. failed authentication counts
- Verdict and confidence assessment
- All containment actions taken with timestamps
- Post-compromise activity observed (if any)
- User notification records
- IOC list (IPs, accounts, systems)
- Lessons learned and recommendations

**Incident Ticket Template:**
```
Incident ID: INC-2026-XXXXX
Title: Brute Force Attack - [Brief Description]
Severity: [Critical/High/Medium/Low]
Date Opened: 2026-02-10 09:15 UTC
Analyst: [Your Name]

ALERT DETAILS:
- Alert Source: [SIEM/IDS/User Report]
- Alert Name: [Multiple Failed Logins / Account Lockout]
- Alert Time: [YYYY-MM-DD HH:MM UTC]
- Detection Method: [Failed login threshold / Correlation rule]

ATTACK DETAILS:
- Attack Type: [Brute Force / Password Spray / Credential Stuffing]
- Source IP(s): [Defanged IP list]
- Source Geolocation: [Country, City, ASN]
- Target Account(s): [username1, username2, ...]
- Service(s): [SSH/RDP/VPN/Web App]
- Failed Attempts: [Count]
- Time Range: [Start - End]

SOURCE IP ANALYSIS:
- AbuseIPDB Score: [X%] - [Verdict]
- VirusTotal: [X/Y vendors flagged]
- IP Type: [Residential/Datacenter/VPN/Tor]
- Known Threat Actor: [Yes/No - Name if known]

COMPROMISE ASSESSMENT:
- Successful Authentication: [Yes/No]
- Compromised Account(s): [List or "None"]
- Systems Accessed: [List or "None"]
- Post-Compromise Activity: [Yes/No - Details]
- Lateral Movement: [Yes/No]
- Data Exfiltration: [Yes/No/Unknown]
- Persistence Established: [Yes/No]

VERDICT: [Critical/High/Medium/Low]
CONFIDENCE: [High/Medium/Low]

CONTAINMENT ACTIONS:
- [ ] Source IP(s) blocked at firewall
- [ ] Source IP(s) blocked at IDS/IPS
- [ ] Compromised account(s) disabled
- [ ] Active sessions terminated
- [ ] Password(s) reset
- [ ] MFA enabled/reset
- [ ] Mailbox rules reviewed/removed
- [ ] Affected systems isolated (if needed)
- [ ] Persistence mechanisms removed (if found)

INVESTIGATION QUERIES EXECUTED:
- [ ] Failed login analysis
- [ ] Successful authentication check
- [ ] Post-compromise activity review
- [ ] Lateral movement analysis
- [ ] Persistence mechanism search

IOCS:
- Source IP(s): [Defanged list]
- Compromised Account(s): [List]
- Affected Systems: [Hostnames]
- Suspicious File Hashes: [If malware involved]
- C2 Domains/IPs: [If applicable]

USER NOTIFICATION:
- User(s) Notified: [List]
- Notification Method: [Email/Phone/In-person]
- Notification Time: [YYYY-MM-DD HH:MM UTC]

TIMELINE:
[YYYY-MM-DD HH:MM UTC] - Initial alert triggered
[YYYY-MM-DD HH:MM UTC] - Triage began
[YYYY-MM-DD HH:MM UTC] - Compromise confirmed
[YYYY-MM-DD HH:MM UTC] - Containment actions initiated
[YYYY-MM-DD HH:MM UTC] - Source IP blocked
[YYYY-MM-DD HH:MM UTC] - Account disabled
[YYYY-MM-DD HH:MM UTC] - Password reset
[YYYY-MM-DD HH:MM UTC] - User notified
[YYYY-MM-DD HH:MM UTC] - Incident closed

OUTCOME: [Brief summary of resolution]

LESSONS LEARNED:
- [What went well]
- [What could be improved]
- [Recommendations for prevention]
```

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Detection Method |
|--------|-----------|--------------|------------------|
| Credential Access | Brute Force | T1110 | Failed login monitoring, account lockout alerts |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Multiple failures against single account |
| Credential Access | Brute Force: Password Spraying | T1110.003 | Low-volume attempts across many accounts |
| Credential Access | Brute Force: Password Cracking | T1110.002 | Offline attack, hash dumps detected |
| Initial Access | Valid Accounts | T1078 | Successful auth after brute force |
| Initial Access | Valid Accounts: Default Accounts | T1078.001 | Login attempts against admin, root, test accounts |
| Defense Evasion | Valid Accounts | T1078 | Legitimate credentials, hard to distinguish |
| Persistence | Valid Accounts | T1078 | Compromised account retains access |
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 | RDP login after compromise |
| Lateral Movement | Remote Services: SSH | T1021.004 | SSH login to additional systems |
| Lateral Movement | Use Alternate Authentication Material | T1550 | Pass-the-hash, pass-the-ticket |
| Collection | Email Collection | T1114 | Mailbox access post-compromise |
| Collection | Data from Network Shared Drive | T1039 | File share access post-compromise |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Data sent to attacker C2 |

## Decision Tree

```
┌─────────────────────────┐
│  Brute Force Alert      │
│  Triggered              │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Step 1: Initial Triage  │
│ Multiple failed logins? │
└────────────┬────────────┘
             │
         Yes │ No → [False Positive]
             ▼        Close ticket
┌─────────────────────────┐
│ Step 2: Source IP       │
│ Analysis                │
└────────────┬────────────┘
             │
      ┌──────┴───────┐
      │  Malicious   │
      │  IP found?   │
      └──────┬───────┘
         Yes │ No
             ▼  └→ [Check user error]
┌─────────────────────────┐
│ Step 3: Target Account  │
│ Analysis                │
└────────────┬────────────┘
             │
      ┌──────┴────────┐
      │ Single account│
      │ or many?      │
      └──────┬────────┘
    Single   │   Many
    (Brute   │   (Password
     Force)  │    Spray)
             ▼
┌─────────────────────────┐
│ Step 4: Check for       │
│ Successful Auth         │
└────────────┬────────────┘
             │
      ┌──────┴──────┐
      │ Success     │
      │ found?      │
      └──────┬──────┘
         Yes │ No
             │  └→ [Block IP]
             │     [Monitor]
             ▼     [Close]
┌─────────────────────────┐
│ ⚠️ COMPROMISE CONFIRMED │
│ Step 5: Post-Compromise │
│ Activity Check          │
└────────────┬────────────┘
             │
      ┌──────┴──────────┐
      │ Lateral movement│
      │ detected?       │
      └──────┬──────────┘
         Yes │ No
             │  └→ [Containment]
             │     [Password Reset]
             ▼     [Monitor 30d]
┌─────────────────────────┐
│ 🚨 CRITICAL INCIDENT    │
│ - Isolate systems       │
│ - Disable accounts      │
│ - Hunt for persistence  │
│ - Escalate to Tier 2/3  │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Eradication & Recovery  │
│ - Remove persistence    │
│ - Reset credentials     │
│ - Restore systems       │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Documentation &         │
│ Lessons Learned         │
└─────────────────────────┘
```

## Lessons Learned

**Common Mistakes to Avoid:**
- Not checking for successful authentication after failures (missing compromise)
- Blocking too broadly (legitimate users locked out)
- Only disabling account without resetting password (attacker may have cached creds)
- Not checking for lateral movement (missing scope of compromise)
- Forgetting to check mailbox rules (attacker maintains access via forwarding)
- Not defanging IPs in documentation
- Re-enabling account too quickly without full investigation
- Not implementing enhanced monitoring after incident

**Best Practices:**
- Always check for successful logins after failed attempts
- Look for password spray patterns (low and slow across many accounts)
- Reset password AND revoke all sessions/tokens
- Check post-compromise activity immediately
- Monitor for 30 days after incident
- Implement MFA if not already enabled
- Use strong, randomly generated temporary passwords
- Document complete timeline of attacker actions
- Conduct post-incident review and improve controls
- Update detection thresholds based on lessons learned

**Detection Improvements:**
- Lower threshold for privileged accounts
- Implement user behavior analytics (UBA)
- Alert on authentication from new geolocations
- Correlate with threat intelligence feeds
- Monitor for impossible travel scenarios
- Alert on successful auth after lockout
- Detect password spray patterns (low attempts across many accounts)
- Monitor service accounts (should have stable auth patterns)

**Prevention Measures:**
- Enforce strong password policy (length, complexity, history)
- Implement MFA for all accounts (especially privileged)
- Use account lockout policies (but beware of DoS)
- Implement rate limiting on authentication services
- Use CAPTCHA after X failed attempts
- Deploy conditional access policies (geolocation, device compliance)
- Disable legacy authentication protocols
- Monitor and rotate service account credentials
- Implement privileged access management (PAM)
- Use password managers (prevent password reuse)
- Conduct security awareness training
- Deploy honeypot accounts to detect attackers

## References

- **NIST SP 800-63B:** Digital Identity Guidelines - Authentication and Lifecycle Management
- **NIST SP 800-61 Rev. 2:** Computer Security Incident Handling Guide
- **MITRE ATT&CK:** Credential Access Techniques - https://attack.mitre.org/tactics/TA0006/
- **OWASP Authentication Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **CIS Control 6:** Access Control Management
- **SANS Reading Room:** Detecting and Responding to Brute Force Attacks
- **Microsoft Security:** Protecting Against Password Spray Attacks

---

**Version History:**
- v1.0 (2026-02-10): Initial playbook creation

**Next Review Date:** 2026-05-10
