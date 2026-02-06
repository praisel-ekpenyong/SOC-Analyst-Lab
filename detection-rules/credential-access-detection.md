# Credential Access Detection Rules

## Overview

Credential access techniques allow attackers to steal usernames, passwords, and authentication tokens to gain access to additional accounts and systems. These rules detect LSASS memory dumping and SAM database access - two critical credential theft methods.

---

## Rule 1: LSASS Memory Access (Credential Dumping)

### Description
Detects suspicious processes accessing LSASS (Local Security Authority Subsystem Service) memory, the primary method for extracting credentials from Windows systems.

### MITRE ATT&CK Mapping
- **Tactic:** Credential Access
- **Technique:** T1003.001 (OS Credential Dumping: LSASS Memory)

### Splunk SPL Query

```spl
index=windows_sysmon EventCode=10 TargetImage="*lsass.exe"
| eval source_process=SourceImage
| eval granted_access=GrantedAccess
| where granted_access="0x1010" OR granted_access="0x1410" OR granted_access="0x1438" OR granted_access="0x143a" OR granted_access="0x1fffff"
| where source_process!="*svchost.exe" AND source_process!="*csrss.exe" AND source_process!="*wininit.exe" AND source_process!="*wmiprvse.exe" AND source_process!="*services.exe"
| table _time, ComputerName, User, source_process, TargetImage, granted_access, CallTrace
| eval severity="Critical"
| sort -_time
```

### Query Explanation

- `EventCode=10` - Sysmon Process Access event (requires Sysmon configuration)
- `TargetImage="*lsass.exe"` - Focus on LSASS process access
- `GrantedAccess` - Access rights requested:
  - `0x1010` - PROCESS_VM_READ (read memory)
  - `0x1410` - PROCESS_VM_READ + PROCESS_QUERY_INFORMATION
  - `0x1438` - Full memory read permissions
  - `0x143a` - Extended memory access
  - `0x1fffff` - PROCESS_ALL_ACCESS
- Filters out legitimate system processes that normally access LSASS
- `CallTrace` helps identify techniques (direct, via debug API, etc.)

### True Positive Indicators

**Credential dumping characteristics:**
- **Source Process:** Suspicious executables, PowerShell, cmd, rundll32, custom tools
- **Location:** User temp folders, Downloads, Public, Desktop
- **Access Rights:** Memory read permissions (0x1010, 0x1410, 0x1438)
- **User Context:** Regular user dumping LSASS (requires debug privilege or admin)
- **Timing:** During or immediately after initial compromise
- **Associated Activity:** Often followed by lateral movement

**Common Credential Dumping Tools:**
- Mimikatz (standalone or in-memory)
- Procdump.exe (Sysinternals tool abused)
- Custom PowerShell scripts
- Cobalt Strike beacon modules
- Empire framework modules
- comsvcs.dll via rundll32

**Example True Positive:**
```
_time: 2026-01-15 09:42:18
ComputerName: WS-FIN-PC02
User: m.johnson
source_process: C:\Users\m.johnson\Downloads\procdump.exe
TargetImage: C:\Windows\System32\lsass.exe
granted_access: 0x1fffff
```

Procdump from Downloads folder accessing LSASS = clear credential theft.

### False Positive Scenarios

**Legitimate LSASS access:**
- Security software (antivirus, EDR) scanning LSASS
- Windows Defender memory scans
- Some backup/monitoring agents
- Legitimate use of Procdump by IT for troubleshooting

**Mitigation:**
- Whitelist known security software paths
- Whitelist admin workstations for legitimate troubleshooting
- Still investigate all LSASS access from user-writable directories

### Response Actions

**CRITICAL ALERT - IMMEDIATE RESPONSE REQUIRED**

1. **Immediate Isolation:**
   - Isolate compromised system from network immediately
   - Prevent further lateral movement
   - Kill suspicious process if still running

2. **Identify Dumping Method:**
   - Check source process name and path
   - Determine tool used (Mimikatz, Procdump, PowerShell script)
   - Look for dump file creation (Sysmon Event 11):
     ```spl
     index=windows_sysmon EventCode=11 TargetFilename="*lsass*.dmp" OR TargetFilename="*.kirbi" OR TargetFilename="*credentials*"
     | table _time, ComputerName, Image, TargetFilename
     ```

3. **Assess Credential Exposure:**
   - Determine which user was logged in when dumped
   - Check for active admin sessions
   - Identify cached credentials potentially stolen
   - Assume all logged-in accounts are compromised

4. **Scope Lateral Movement:**
   ```spl
   index=windows_security ComputerName="affected_host" EventCode=4624 Logon_Type=3
   | stats count by Account_Name, src_ip
   ```

   Look for authentication to other systems after credential theft.

5. **Containment:**
   - Disable all user accounts that were logged into affected system
   - Force password reset for all potentially compromised accounts
   - Reset Kerberos krbtgt account twice (if domain-wide compromise suspected)
   - Block any external C2 infrastructure identified

6. **Forensic Analysis:**
   - Locate and secure dump file (evidence)
   - Check for malware/backdoors
   - Review all process execution since initial compromise
   - Identify initial access vector

7. **Eradication:**
   - Remove credential dumping tool
   - Remove any malware/backdoors
   - Patch vulnerabilities exploited for initial access
   - Consider full system re-image for critical systems

### Advanced Detection - Comsvcs.dll Abuse

Attackers often use rundll32 with comsvcs.dll to dump LSASS:

```spl
index=windows_sysmon EventCode=1 Image="*rundll32.exe" CommandLine="*comsvcs.dll*" CommandLine="*MiniDump*"
| table _time, ComputerName, User, CommandLine
```

**Malicious Command:**
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\dump.dmp full
```

This is stealthy because rundll32 and comsvcs.dll are legitimate Windows components.

### Prevention

1. **Credential Guard:** Isolates LSASS in virtual container (Windows 10+ Enterprise)
2. **Protected Process Light:** Makes LSASS harder to access
3. **WDigest Disabled:** Prevents cleartext password storage in memory (Windows 8.1+)
4. **LSA Protection:** Registry key to enable enhanced LSASS protection
5. **Restrict Debug Privileges:** Limit SeDebugPrivilege to only necessary accounts
6. **EDR with Memory Protection:** Blocks memory dumping attempts

### Testing

**WARNING: Only test in isolated lab environment**

```powershell
# Download Procdump from Sysinternals
# Execute (requires admin):
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Should trigger alert immediately. **Delete dump file after testing.**

---

## Rule 2: SAM Database Access

### Description
Detects attempts to access or copy the SAM (Security Account Manager) and SYSTEM registry hives, which contain local account password hashes.

### MITRE ATT&CK Mapping
- **Tactic:** Credential Access
- **Technique:** T1003.002 (OS Credential Dumping: Security Account Manager)

### Splunk SPL Query

```spl
index=windows_sysmon EventCode=1 
| eval cmdline_lower=lower(CommandLine)
| where (match(cmdline_lower, "reg save") OR match(cmdline_lower, "reg.exe save")) AND 
        (match(cmdline_lower, "hklm\\sam") OR match(cmdline_lower, "hklm\\system") OR match(cmdline_lower, "hklm\\security"))
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| eval severity="Critical"
| sort -_time
```

### Query Explanation

- `EventCode=1` - Process creation (captures reg.exe execution)
- Detects `reg save` command targeting SAM/SYSTEM/SECURITY hives
- These hives contain local password hashes
- Attackers export these, then crack offline
- `ParentImage` shows what launched reg.exe (important context)

### True Positive Indicators

**SAM dumping characteristics:**
- **Command:** `reg save HKLM\SAM C:\temp\sam.save`
- **User:** Non-admin attempting SAM access (suspicious)
- **Output Location:** Temp folders, removable media, network shares
- **Timing:** During active compromise
- **Multiple Hives:** Exporting SAM, SYSTEM, and SECURITY together (needed for offline cracking)

**Attack Process:**
1. Attacker gains admin privileges
2. Exports SAM and SYSTEM hives
3. Transfers files off system
4. Cracks hashes offline with hashcat/John
5. Uses recovered credentials for lateral movement

**Example:**
```
CommandLine: reg.exe save HKLM\SAM C:\Users\Public\sam.hive
User: a.chen
ParentImage: C:\Windows\System32\cmd.exe
```

### False Positive Scenarios

**Legitimate SAM access:**
- System backups using Windows Backup
- Forensic investigations by IR team
- Some management/deployment tools
- Legitimate system migration/recovery operations

**Note:** This activity is rare in normal operations. Investigate every occurrence.

### Response Actions

1. **Identify Export Location:**
   - Check command line for output path
   - Locate exported hive files
   - Determine if files were transferred off-system

2. **Check for Exfiltration:**
   ```spl
   index=windows_sysmon EventCode=11 (TargetFilename="*.hive" OR TargetFilename="*.save" OR TargetFilename="*sam*")
   | table _time, ComputerName, Image, TargetFilename
   ```

   ```spl
   index=windows_sysmon EventCode=3 DestinationPort=445 OR DestinationPort=22 OR DestinationPort=21
   | stats count by DestinationIp, Image
   ```

3. **Verify Legitimacy:**
   - Contact user to confirm if legitimate
   - Check change management for approved activity
   - Review if IR or backup operation

4. **If Malicious:**
   - Isolate affected system
   - Locate and delete exported hive files
   - Check network logs for file transfers
   - If files exfiltrated, assume all local accounts compromised

5. **Mitigation:**
   - Reset all local administrator passwords
   - Disable local accounts not needed
   - Check for rogue local admin accounts created by attacker
   - Implement LAPS for local admin password management

6. **Investigate Initial Access:**
   - How did attacker gain admin privileges?
   - Check for privilege escalation exploits
   - Review recent authentication events

### Alternative Detection - File System Access

Monitor direct file access to SAM database:

```spl
index=windows_security EventCode=4663 Object_Name="*\\SAM" OR Object_Name="*\\SYSTEM" OR Object_Name="*\\SECURITY"
| where AccessMask!="0x1" AND Process_Name!="*services.exe" AND Process_Name!="*lsass.exe"
| table _time, ComputerName, Account_Name, Process_Name, Object_Name, AccessMask
```

Detects direct attempts to read SAM file from `C:\Windows\System32\config\`.

### Tools That Dump SAM

**Common tools:**
- `reg.exe` - Built-in Windows tool (most common)
- PowerShell `Save-RegistryKey` function
- Mimikatz `lsadump::sam` command
- Volume Shadow Copy access then copy SAM
- secretsdump.py (Impacket toolkit)

### Prevention

1. **Restrict Registry Access:** Group Policy to limit who can access SAM hive
2. **Monitor Registry Operations:** Enable Object Access auditing
3. **LAPS Deployment:** Randomizes local admin passwords
4. **Least Privilege:** Minimize accounts with admin rights
5. **Disable Local Accounts:** Use domain accounts only when possible

### Testing

```powershell
# Test SAM export (requires admin)
reg save HKLM\SAM C:\temp\sam_test.hive
reg save HKLM\SYSTEM C:\temp\system_test.hive

# Clean up
Remove-Item C:\temp\sam_test.hive
Remove-Item C:\temp\system_test.hive
```

Should trigger alert immediately.

---

## Summary

These credential access detection rules identify critical credential theft methods:

1. **LSASS Memory Dumping:** Extracts credentials from active memory
2. **SAM Database Access:** Steals local account password hashes

**Combined Coverage:**
- Domain credentials (LSASS)
- Local credentials (SAM)
- Both online and offline attack methods

**Response Priority:**
Both are **CRITICAL** alerts requiring immediate investigation and response.

**Credential Theft Attack Chain:**
1. Initial Compromise → 2. Privilege Escalation → 3. Credential Dumping (these rules) → 4. Lateral Movement → 5. Domain Dominance

**Preventing Credential Theft:**
- Enable Credential Guard (LSASS isolation)
- Deploy LAPS (local admin passwords)
- Implement tiered admin model
- Use Protected Users security group
- Minimize cached credentials
- Monitor and alert on all credential access

**Key Metrics:**
- Credential dumping attempts per month
- Success rate (actual dumps created)
- Time to detection (LSASS access to alert)
- Time to containment (alert to isolation)
- Accounts compromised per incident
- Lateral movement following credential theft

**Investigation Checklist:**
- [ ] Identify compromised system and user
- [ ] Determine credential theft method
- [ ] List all potentially compromised accounts
- [ ] Search for lateral movement activity
- [ ] Check for data exfiltration
- [ ] Identify initial access vector
- [ ] Reset all compromised credentials
- [ ] Remove attacker persistence mechanisms
- [ ] Document lessons learned and improve detections
