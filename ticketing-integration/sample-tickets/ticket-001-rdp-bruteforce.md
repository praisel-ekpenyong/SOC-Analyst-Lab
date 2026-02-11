# Sample Ticket 001: RDP Brute Force Attack

## Ticket Overview

| Field | Value |
|-------|-------|
| **Ticket Number** | #123456 |
| **Priority** | Critical |
| **Status** | Closed |
| **Department** | Tier 1 Analysts → Tier 2 Analysts |
| **Help Topic** | Brute Force Attack |
| **Created** | 2026-01-15 08:29:44 UTC |
| **Closed** | 2026-01-15 11:42:00 UTC |
| **Resolution Time** | 3 hours 12 minutes |
| **SLA Status** | Met (Target: 4 hours) |

## Ticket Details

### Subject
[Splunk Alert - CRITICAL] Brute Force - Multiple Failed Logins on DC01

### Custom Fields

| Field | Value |
|-------|-------|
| **Affected System** | DC01 (10.0.0.10 - Domain Controller) |
| **Affected User** | j.martinez (IT Department) |
| **MITRE ATT&CK Technique** | T1110.001 - Brute Force: Password Guessing |
| **Alert Source** | Splunk SIEM |
| **Investigation Status** | Closed - Incident Resolved |
| **Incident Severity** | Critical - Domain Admin Compromise |

### Indicators of Compromise (IOCs)

```
Source IP: 185.220.101.42
Country: Germany (Tor Exit Node)
Target Accounts: j.martinez, administrator, admin, t.williams
Failed Attempts: 847
Rogue Account Created: svc_backup
Persistence: Registry Run Key modification
```

---

## Ticket Timeline

### [2026-01-15 08:29:44 UTC] - TICKET CREATED (Automated - Splunk)

**Initial Alert Message:**
```
=== SPLUNK SIEM ALERT ===

Alert Name: Brute Force - Multiple Failed Logins
Severity: CRITICAL
Trigger Time: 2026-01-15 08:29:44 UTC
Alert URL: http://splunk.lab.local:8000/app/search/brute_force_alert_123

=== AFFECTED SYSTEMS ===
Hostname: DC01
Source IP: 185.220.101.42
Destination IP: 10.0.0.10
User Account: Multiple (j.martinez, administrator, admin, t.williams)

=== ALERT DETAILS ===
Event Count: 847 failed login attempts
Time Range: 2026-01-15 06:14:22 to 08:22:47 UTC
Duration: 2 hours 8 minutes

=== INDICATORS OF COMPROMISE ===
Source IP: 185.220.101.42
Failed Attempts: 847
Successful Authentication: EventCode 4624 at 08:22:51 UTC
Account: j.martinez
Logon Type: 10 (RDP)

=== RECOMMENDED ACTIONS ===
1. Review alert in Splunk immediately
2. Check for successful authentication
3. Verify domain controller status
4. Block source IP at firewall
5. Follow Brute Force Response Playbook

This ticket was automatically created by Splunk integration.
Analyst: Please acknowledge and begin triage within 15 minutes (Critical SLA).
```

### [2026-01-15 08:31:00 UTC] - Ticket Claimed by Senior Analyst

**Internal Note - Sarah Chen (Tier 1 → Tier 2 promoted for Critical):**
```
=== INITIAL TRIAGE ===
Analyst: Sarah Chen (Tier 2)
Time: 2026-01-15 08:31:00 UTC

Alert Review:
- TRUE POSITIVE - CONFIRMED SUCCESSFUL COMPROMISE
- Severity Assessment: CRITICAL
- Activity Status: Successful authentication detected - ONGOING THREAT

Affected Assets:
- Systems: DC01 (Domain Controller) - CRITICAL ASSET
- Users: j.martinez (compromised), administrator (targeted), admin (targeted)
- Data: Full domain access potentially compromised

Preliminary Findings:
Splunk alert shows 847 failed RDP attempts from external IP 185.220.101.42 
targeting multiple accounts over 2+ hours. CRITICAL: Event 4624 shows 
successful authentication for j.martinez at 08:22:51 UTC via RDP. 
Domain controller is actively compromised.

Immediate Actions Required:
- Block source IP at firewall IMMEDIATELY
- Check for post-compromise activity
- Verify no lateral movement
- Disable compromised account

Recommended Action: IMMEDIATE CONTAINMENT REQUIRED
Escalation: Self-handling as Tier 2 on-call for critical incident

Next Steps:
- Execute containment actions NOW
- Query for post-authentication activity
- Check for privilege escalation
- Notify SOC Manager
```

### [2026-01-15 08:33:15 UTC] - SIEM Investigation

**Internal Note - Sarah Chen:**
```
=== SIEM INVESTIGATION ===
Time: 2026-01-15 08:33:15 UTC

Query 1: Verify Successful Authentication
SPL: index=windows_security EventCode=4624 src_ip="185.220.101.42"

RESULTS:
✓ CONFIRMED: Successful logon Event 4624 at 08:22:51 UTC
  - Account: j.martinez
  - Logon Type: 10 (RDP)
  - Source: 185.220.101.42
  - Workstation: DC01

Query 2: Post-Authentication Activity
SPL: index=windows_security ComputerName="DC01" Account_Name="j.martinez" 
     earliest="2026-01-15T08:22:51"

CRITICAL FINDINGS:
⚠ Event 4798 (08:24:05): Domain Admins group enumeration
⚠ Event 4720 (08:25:42): NEW ACCOUNT CREATED - "svc_backup"
⚠ Event 4732 (08:26:19): svc_backup added to LOCAL ADMINISTRATORS
⚠ Event 4728 (08:27:03): svc_backup added to DOMAIN ADMINS
⚠ Event 13 (08:28:31): Registry Run key modification for persistence

THREAT ASSESSMENT:
This is NOT just a brute force - this is a successful domain compromise 
with privilege escalation and persistence. Attacker has DOMAIN ADMIN access.

IMMEDIATE ESCALATION TO INCIDENT RESPONSE MODE.
```

### [2026-01-15 08:35:12 UTC] - CONTAINMENT ACTIONS INITIATED

**Internal Note - Sarah Chen:**
```
=== CONTAINMENT IN PROGRESS ===
Time: 2026-01-15 08:35:12 UTC
Status: CRITICAL - Executing Emergency Containment

Actions Taken:
✓ 08:35:12 - Source IP 185.220.101.42 blocked at perimeter firewall
✓ 08:35:30 - Contacted Network Admin (John) - firewall rule confirmed active
✓ 08:36:00 - Verified no active RDP sessions from 185.220.101.42
✓ 08:36:45 - Checked for additional external connections - NONE found

Actions In Progress:
⏳ Disabling compromised account j.martinez
⏳ Removing rogue account svc_backup
⏳ Terminating any active sessions

EDR Check:
- Opening Wazuh console for DC01 endpoint status check
```

### [2026-01-15 08:37:29 UTC] - CONTAINMENT: Account Actions

**Internal Note - Sarah Chen:**
```
=== ACCOUNT CONTAINMENT ===
Time: 2026-01-15 08:37:29 UTC

Active Directory Actions:
✓ Account "j.martinez" DISABLED (08:37:29)
  - Method: Active Directory Users and Computers
  - Verified: Account login now fails
  
✓ Password RESET for j.martinez (08:37:45)
  - New temporary password set
  - Requires change on next login (when re-enabled)
  
Session Termination:
✓ All RDP sessions for j.martinez terminated (08:38:00)
  - Verified via Task Manager on DC01
  - No active sessions remain

Current Status:
- Attacker access via j.martinez account: BLOCKED
- Investigating rogue svc_backup account now
```

### [2026-01-15 08:38:45 UTC] - CONTAINMENT: Rogue Account Removal

**Internal Note - Sarah Chen:**
```
=== ROGUE ACCOUNT REMEDIATION ===
Time: 2026-01-15 08:38:45 UTC

Rogue Account: svc_backup
Created: 2026-01-15 08:25:42 UTC by j.martinez (attacker)
Privileges: Local Admin + Domain Admin

Actions Taken:
✓ Removed svc_backup from Domain Admins group (08:38:45)
✓ Removed svc_backup from Local Administrators (08:39:00)
✓ DELETED account svc_backup from Active Directory (08:39:15)

Verification:
✓ Account no longer exists in AD
✓ Group memberships verified removed
✓ No active sessions under this account

Persistence Mechanism Check:
⏳ Checking for registry Run key modifications
⏳ Scanning for scheduled tasks
⏳ Verifying no backdoors installed
```

### [2026-01-15 08:42:00 UTC] - CONTAINMENT COMPLETE

**Internal Note - Sarah Chen:**
```
=== CONTAINMENT COMPLETE ===
Time: 2026-01-15 08:42:00 UTC
Status: Threat Contained - Continuing Investigation

Containment Summary:
✓ Source IP blocked at firewall
✓ Compromised account disabled and password reset
✓ Rogue administrator account deleted
✓ All attacker sessions terminated
✓ No lateral movement detected
✓ Persistence mechanisms removed

Current Threat Level: CONTAINED
- Attacker has NO access to environment
- No ongoing malicious activity detected
- Domain admin privileges revoked

Next Phase: ERADICATION & VALIDATION
- Verify no additional persistence
- Check all domain controllers for signs of compromise
- Review security logs for missed activity
- Validate clean state
```

### [2026-01-15 08:50:00 UTC] - PERSISTENCE INVESTIGATION

**Internal Note - Sarah Chen:**
```
=== PERSISTENCE MECHANISM ANALYSIS ===
Time: 2026-01-15 08:50:00 UTC

Registry Investigation:
Query: index=windows_sysmon EventCode=13 Account_Name="svc_backup" OR Account_Name="j.martinez"

Findings:
⚠ Registry modification detected (EventCode 13)
  - Time: 08:28:31 UTC
  - Target: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
  - Value: C:\ProgramData\svchost32.exe
  - Note: Attempted persistence via Run key

File System Check:
⚠ File NOT FOUND: C:\ProgramData\svchost32.exe
  - Attacker likely did not have time to upload payload
  - Registry key created but no file placed
  
Action Taken:
✓ Deleted registry Run key (manual cleanup)
✓ Verified no malicious files in ProgramData
✓ Scanned DC01 with updated antivirus - CLEAN

Assessment:
Attacker attempted to establish persistence but was detected and contained 
before payload could be deployed. Rapid detection prevented backdoor installation.
```

### [2026-01-15 09:15:00 UTC] - SCOPE VERIFICATION

**Internal Note - Sarah Chen:**
```
=== SCOPE ASSESSMENT ===
Time: 2026-01-15 09:15:00 UTC

Lateral Movement Check:
Query: index=windows_security EventCode=4624 Account_Name="j.martinez" OR Account_Name="svc_backup"
       Logon_Type IN (3,10) ComputerName!="DC01"

Result: NO lateral movement detected
- No successful logins to other systems
- Attacker activity confined to DC01 only
- Time window was ~6 minutes (08:22:51 to 08:29:44 detection)

Data Exfiltration Check:
Query: index=firewall src_ip="10.0.0.10" dest_ip!="10.0.0.0/24" bytes_out>1000000

Result: NO large data transfers detected
- No unusual outbound traffic from DC01
- No evidence of data staging or exfiltration
- Attacker focused on establishing persistence, not data theft

Additional Account Compromise Check:
Query: index=windows_security EventCode=4624 src_ip="185.220.101.42" Account_Name!="j.martinez"

Result: NO other successful authentications
- Only j.martinez account was compromised
- 847 failed attempts on other accounts
- No other user credentials obtained

SCOPE CONCLUSION:
✓ Single system: DC01 (Domain Controller)
✓ Single account: j.martinez
✓ No lateral movement
✓ No data exfiltration
✓ No additional compromised accounts
✓ Containment was successful and complete
```

### [2026-01-15 09:45:00 UTC] - THREAT INTELLIGENCE ENRICHMENT

**Internal Note - Sarah Chen:**
```
=== THREAT INTELLIGENCE RESEARCH ===
Time: 2026-01-15 09:45:00 UTC

Source IP Analysis: 185.220.101.42

VirusTotal:
- Known malicious: Yes (12/89 security vendors flag as malicious)
- Associated with: Brute force attacks, credential stuffing
- Recent activity: Active in past 48 hours

AbuseIPDB:
- Confidence Score: 98% (Very High)
- Total Reports: 347 reports in past 30 days
- Categories: Brute Force, SSH attacks, Port Scan
- Most Recent: 2026-01-14 (1 day ago)
- Country: Germany
- ISP: Tor Exit Node

ThreatFox (abuse.ch):
- IOC Type: IP Address
- Threat Type: Brute Force Botnet
- Confidence: High
- Tags: tor_exit_node, credential_access

Shodan:
- Open Ports: 443, 9001 (Tor)
- Services: Tor Exit Node confirmed
- First Seen: 2026-01-10

Assessment:
This is a known malicious Tor exit node actively used for brute force attacks 
against multiple organizations. Not targeted attack - opportunistic scanning 
of internet-facing RDP services. Recommend blocking all Tor exit nodes at firewall.

Recommended Actions:
1. Block all known Tor exit nodes at perimeter
2. Implement geo-blocking for high-risk countries (if feasible)
3. Disable internet-facing RDP or implement MFA
4. Deploy RDP gateway with MFA for remote access
```

### [2026-01-15 10:30:00 UTC] - RECOVERY ACTIONS

**Internal Note - Sarah Chen:**
```
=== RECOVERY PHASE ===
Time: 2026-01-15 10:30:00 UTC
Status: Eradication Complete - Beginning Recovery

Validation Checks Complete:
✓ Full antivirus scan of DC01 - CLEAN
✓ File integrity monitoring review - No unauthorized changes
✓ All Domain Admin accounts reviewed - No unauthorized accounts
✓ Group Policy Objects reviewed - No modifications
✓ DNS records checked - No malicious entries
✓ Scheduled tasks reviewed - No suspicious tasks

Account Recovery:
⏳ Meeting with j.martinez (user) scheduled for 11:00 UTC
   - Will explain incident
   - Verify account ownership
   - Security awareness reminder
   - Re-enable account with new password

Action Items:
1. Re-enable j.martinez account after user verification
2. Require password change on next login
3. Monitor j.martinez account for 48 hours
4. Document lessons learned
5. Update detection rules

User Interview Notes (11:00 UTC):
- Met with Jorge Martinez (j.martinez)
- Confirmed he is legitimate user
- Explained his weak password was compromised
- Password policy review conducted
- New strong password set: 16 characters, complexity requirements
- User educated on password best practices
- Account re-enabled: 11:05 UTC
```

### [2026-01-15 11:15:00 UTC] - ROOT CAUSE ANALYSIS

**Internal Note - Sarah Chen:**
```
=== ROOT CAUSE ANALYSIS ===
Time: 2026-01-15 11:15:00 UTC

How did this happen?

1. WEAK PASSWORD
   - j.martinez used weak password: "Password123!"
   - Password met minimum requirements but was in common wordlists
   - Brute forced after 319 attempts

2. INTERNET-FACING RDP
   - Domain Controller RDP accessible from internet
   - Port 3389 exposed on firewall
   - No MFA or IP whitelisting

3. DELAYED DETECTION
   - Attack began at 06:14:22 UTC
   - Not detected until 08:29:44 UTC (2h 15min delay)
   - Detection rule threshold too high (>1000 failures)

4. IT ACCOUNT PRIVILEGES
   - j.martinez had unnecessary Domain Admin rights
   - Violation of least privilege principle
   - Should be standard user with elevated access only when needed

Why was containment successful?

1. RAPID RESPONSE
   - Senior analyst on-call responded in 1 minute
   - Containment executed within 6 minutes of detection
   - Limited attacker dwell time to ~6 minutes

2. GOOD DETECTION RULE
   - Splunk alert triggered appropriately
   - Automated ticket creation via API
   - All relevant context provided

3. CLEAR PLAYBOOK
   - Brute Force Response Playbook followed
   - Systematic containment approach
   - No confusion about actions to take
```

### [2026-01-15 11:30:00 UTC] - PREVENTIVE MEASURES

**Internal Note - Sarah Chen:**
```
=== PREVENTIVE MEASURES IMPLEMENTED ===
Time: 2026-01-15 11:30:00 UTC

Immediate Actions (COMPLETED):
✓ Disabled internet-facing RDP on Domain Controller
✓ Configured RDP Gateway with MFA for remote access
✓ Blocked all known Tor exit nodes at firewall (1,200+ IPs)
✓ Implemented geo-blocking for non-business countries
✓ Removed Domain Admin rights from j.martinez
✓ Added j.martinez to "IT-Elevated-Access" group (JIT access only)

Short-Term Actions (Next 7 Days):
⏳ Audit all accounts with Domain Admin privileges
⏳ Implement mandatory password complexity requirements
⏳ Deploy password filter to block common passwords
⏳ Configure account lockout after 5 failed attempts
⏳ Implement alert for failed login threshold >10 (reduced from 1000)

Long-Term Actions (Next 30 Days):
⏳ Implement MFA for all privileged accounts
⏳ Deploy Privileged Access Workstation (PAW) for Domain Admin tasks
⏳ Implement Just-In-Time (JIT) admin access
⏳ Deploy Azure AD Password Protection
⏳ Conduct security awareness training for all IT staff

Detection Improvements:
⏳ Create additional alert for failed logins >10 (early warning)
⏳ Alert on any successful authentication after 5+ failures
⏳ Alert on any new Domain Admin account creation
⏳ Alert on registry Run key modifications
⏳ Create dashboard for authentication monitoring
```

### [2026-01-15 11:42:00 UTC] - INCIDENT CLOSURE

**Internal Note - Sarah Chen:**
```
=== INCIDENT CLOSURE ===
Analyst: Sarah Chen (Tier 2)
Time: 2026-01-15 11:42:00 UTC
Resolution: Resolved - True Positive - Domain Compromise Contained

Final Summary:
External threat actor successfully compromised Domain Controller through 
RDP brute force attack against weak password. Attacker gained Domain Admin 
privileges via compromised IT account, created rogue admin account, and 
attempted to establish persistence. Rapid detection and containment within 
6 minutes of alert prevented lateral movement, data exfiltration, and 
persistent access. All malicious accounts removed, compromised account 
secured, and multiple preventive measures implemented.

Incident Metrics:
- Detection Time: 2h 15min from attack start (needs improvement)
- Response Time: 1 minute from alert (excellent)
- Containment Time: 6 minutes from response (excellent)
- Total Resolution Time: 3h 12min (within SLA)
- Attacker Dwell Time: ~6 minutes (excellent)

Systems Affected:
- DC01 (Domain Controller) - Fully recovered and validated clean

Users Affected:
- j.martinez - Account compromised, recovered, educated

IOCs Documented:
- Source IP: 185.220.101.42 (blocked)
- Rogue Account: svc_backup (deleted)
- Registry Key: HKCU\...\Run\WindowsUpdate (removed)
- 847 failed login attempts (logged)

Root Cause:
1. Weak password on IT account
2. Internet-facing RDP on critical infrastructure
3. Excessive privileges (Domain Admin for standard IT tasks)

Preventive Measures:
1. Internet-facing RDP disabled on DC
2. RDP Gateway with MFA deployed
3. Tor exit nodes blocked
4. Domain Admin privileges removed from j.martinez
5. Password policy strengthened
6. Account lockout policy implemented
7. Detection thresholds lowered

Lessons Learned:
1. Detection threshold of 1000 failures is too high - reduced to 10
2. IT accounts should not have standing Domain Admin rights
3. Critical infrastructure should never be directly internet-accessible
4. Password complexity requirements should include ban on common passwords
5. MFA for all privileged access is essential
6. Rapid response and clear playbooks enabled successful containment

Detection Rule Feedback:
✓ Brute force detection rule worked but threshold too high
✓ Need additional rule for <10 failures with successful auth
✓ Need alert for Domain Admin group modifications
✓ Need alert for new account creation

Reference Investigation:
See detailed investigation: [Investigation 001: RDP Brute Force Attack](../../investigations/investigation-001-brute-force-rdp.md)

Status: CLOSED
Time to Resolution: 3 hours 12 minutes
SLA Status: MET (Target: 4 hours for Critical)
```

---

## Ticket Closure Details

### Final Status
- **Status:** Closed
- **Resolution:** Resolved - True Positive
- **Resolution Category:** Security Incident - Brute Force Attack
- **Closure Code:** Successfully Contained and Remediated

### Customer Satisfaction
- **User Notified:** Yes (j.martinez educated on incident)
- **Impact to Business:** Minimal (rapid containment prevented widespread impact)
- **User Feedback:** N/A (internal security incident)

### Follow-Up Actions
- [ ] Weekly monitoring of j.martinez account (assigned to SOC Team)
- [ ] 30-day review of authentication alerts (assigned to Detection Engineering)
- [ ] Password policy audit completion (assigned to IT Security Manager)
- [ ] MFA implementation for all Domain Admins (assigned to IT Director)

### Related Tickets
- Ticket #123457: Network Team - Configure RDP Gateway with MFA
- Ticket #123458: IT Security - Audit Domain Admin Accounts
- Ticket #123459: Detection Engineering - Tune Brute Force Detection Rule

### Metrics Summary
- **MTTA (Mean Time to Acknowledge):** 1 minute (Target: 15 min) ✓ EXCELLENT
- **MTTR (Mean Time to Resolve):** 3h 12min (Target: 4 hours) ✓ MET SLA
- **Containment Time:** 6 minutes from response ✓ EXCELLENT
- **Business Impact:** Low (rapid containment)
- **Detection Quality:** Good (but threshold needs tuning)

---

## Key Takeaways from This Ticket

This sample ticket demonstrates:

1. **Complete Lifecycle:** From automated alert creation through resolution
2. **Rapid Response:** 1-minute acknowledgment, 6-minute containment
3. **Thorough Documentation:** Every action timestamped and explained
4. **Systematic Approach:** Following incident response methodology
5. **Root Cause Analysis:** Understanding why it happened
6. **Preventive Measures:** Actions to prevent recurrence
7. **Lessons Learned:** Continuous improvement mindset
8. **Professional Communication:** Clear, concise, actionable notes
9. **Metrics Tracking:** MTTA, MTTR, containment time
10. **Integration:** Reference to detailed investigation document

**Link to Full Investigation:** [Investigation 001: RDP Brute Force Attack](../../investigations/investigation-001-brute-force-rdp.md)

---

*This sample ticket showcases professional SOC incident management from automated alert detection through complete resolution with comprehensive documentation, meeting all SLA targets and implementing effective preventive measures.*
