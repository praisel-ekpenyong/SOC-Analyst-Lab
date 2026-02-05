# Lateral Movement Detection Rules

## Overview

Lateral movement occurs when attackers, after initial compromise, move between systems within a network to reach high-value targets or expand their access. These rules detect common lateral movement techniques including PsExec, RDP abuse, and Pass-the-Hash attacks.

---

## Rule 1: PsExec Usage Detection

### Description
Detects execution of PsExec or PSEXESVC service, commonly used for remote command execution and lateral movement across Windows networks.

### MITRE ATT&CK Mapping
- **Tactic:** Lateral Movement
- **Technique:** T1021.002 (Remote Services: SMB/Windows Admin Shares)

### Splunk SPL Query

```spl
index=windows_sysmon 
(EventCode=1 (Image="*PsExec.exe" OR Image="*PsExec64.exe" OR Image="*PSEXESVC.exe")) OR
(EventCode=13 TargetObject="*\\Services\\PSEXESVC*")
| eval detection_type=case(
    EventCode=1 AND match(Image, "PsExec"), "PsExec Execution",
    EventCode=1 AND match(Image, "PSEXESVC"), "PsExec Service Running",
    EventCode=13, "PsExec Service Registry Key",
    true(), "Other")
| table _time, ComputerName, User, EventCode, detection_type, Image, CommandLine, TargetObject
| eval severity="High"
| sort -_time
```

### Query Explanation

- `EventCode=1` - Process creation for PsExec binary or PSEXESVC service executable
- `EventCode=13` - Registry value set when PSEXESVC service is created
- Detects both execution of PsExec tool and installation of its service component
- `TargetObject="*\\Services\\PSEXESVC*"` - Registry key for service installation

### True Positive Indicators

**Malicious PsExec characteristics:**
- Executed by compromised admin account
- Source: Non-admin workstation or suspicious directory
- Targets: Multiple systems in rapid succession
- Command line: Launching cmd, PowerShell, or malware
- Time: Outside business hours or maintenance windows

**Example Attack Scenario:**
```
User: t.williams (compromised admin)
Source: WS-FIN-PC02 (compromised workstation)
CommandLine: PsExec.exe \\WS-FIN-PC03 -u SOCLAB\t.williams -p <password> cmd.exe
Detection: Lateral movement to additional workstations
```

**Attack Chain with PsExec:**
1. Attacker compromises admin credentials
2. Uses PsExec to execute commands on remote systems
3. Typically copies additional tools or malware
4. Establishes persistence on new systems
5. Continues lateral movement

### False Positive Scenarios

**Legitimate PsExec usage:**
- IT administrators remotely managing systems
- Automated deployment scripts
- Incident response activities
- Managed service providers (MSPs)

**Mitigation:**
- Whitelist IT admin workstations: `| where ComputerName!="IT-MGMT-WS01"`
- Whitelist service accounts used for automation
- Require change requests for PsExec usage
- Log all legitimate PsExec use for baseline

### Response Actions

1. **Verify Legitimacy:**
   - Contact the user account executing PsExec
   - Check change management system for approved activity
   - Verify execution comes from authorized IT workstation

2. **If Malicious - Immediate Actions:**
   - Disable compromised user account
   - Isolate source and target systems
   - Check for malware deployment via PsExec
   - Review all systems accessed by compromised account

3. **Investigation Queries:**
   ```spl
   # Find all systems accessed via PsExec
   index=windows_sysmon Image="*PsExec*" OR Image="*PSEXESVC*"
   | stats count by ComputerName, User
   | sort -count
   
   # Check what was executed
   index=windows_sysmon EventCode=1 ParentImage="*PSEXESVC.exe"
   | table _time, ComputerName, User, Image, CommandLine
   ```

4. **Eradication:**
   - Stop PSEXESVC service on all affected systems
   - Remove PsExec binaries
   - Search for payloads deployed via PsExec
   - Reset compromised credentials

### Testing

```powershell
# From Kali or admin workstation
# Download PsExec from Sysinternals
.\PsExec64.exe \\WS-FIN-PC01 -u SOCLAB\Administrator cmd.exe /c "whoami"
```

Should trigger alert immediately.

---

## Rule 2: Unusual RDP Login Patterns

### Description
Detects Remote Desktop Protocol (RDP) logins that may indicate lateral movement, particularly multiple RDP sessions from single source or RDP to non-standard targets.

### MITRE ATT&CK Mapping
- **Tactic:** Lateral Movement
- **Technique:** T1021.001 (Remote Services: Remote Desktop Protocol)

### Splunk SPL Query

```spl
index=windows_security EventCode=4624 Logon_Type=10
| eval src_ip=coalesce(Source_Network_Address, IpAddress, "local")
| eval account=coalesce(Account_Name, TargetUserName, "unknown")
| eval dest_host=coalesce(ComputerName, Computer, "unknown")
| stats count as rdp_count, 
        values(dest_host) as destinations, 
        dc(dest_host) as unique_hosts,
        earliest(_time) as first_login,
        latest(_time) as last_login
        by src_ip, account
| where rdp_count > 1 OR unique_hosts > 2
| eval duration_hours=round((last_login-first_login)/3600, 2)
| eval severity=case(unique_hosts>5, "Critical", unique_hosts>2, "High", true(), "Medium")
| table src_ip, account, rdp_count, unique_hosts, destinations, first_login, last_login, duration_hours, severity
| sort -unique_hosts
```

### Query Explanation

- `EventCode=4624` - Successful logon
- `Logon_Type=10` - Remote Interactive (RDP) logons
- `dc(dest_host)` - Distinct count of destination hosts (lateral movement indicator)
- `where rdp_count > 1` - Multiple RDP sessions (normal users rarely RDP hop)
- Alert triggers when single source/account RDPs to multiple systems

### True Positive Indicators

**Lateral movement via RDP:**
- Single account RDP to 3+ different systems rapidly
- RDP from workstation to workstation (not typical)
- RDP from external IP to multiple internal systems
- RDP sessions outside normal admin hours
- Non-admin accounts using RDP
- Geographic anomalies (IP from unexpected location)

**Example:**
```
src_ip=10.0.0.20 | account=t.williams | unique_hosts=5 
destinations=[DC01, WS-FIN-PC01, WS-FIN-PC02, WS-HR-PC01, WS-EXEC-PC01]
duration_hours=0.5
```

Compromised admin account rapidly accessing multiple systems via RDP = clear lateral movement.

### False Positive Scenarios

- System administrators performing legitimate multi-system management
- Help desk staff assisting multiple users via RDP
- Automated tools connecting to multiple systems (monitoring, backup)

### Response Actions

1. **Verify Account Activity:**
   - Contact account owner to confirm activity
   - Check if account should have RDP access to those systems
   - Review source IP legitimacy

2. **Investigate RDP Sessions:**
   ```spl
   index=windows_security EventCode=4624 Logon_Type=10 Account_Name="suspicious_account"
   | table _time, ComputerName, src_ip, Logon_Process
   | sort _time
   ```

3. **Check for Malicious Activity:**
   - Review process creation on RDP'd systems
   - Check for file transfers (net use, copy commands)
   - Look for credential dumping attempts
   - Verify no persistence mechanisms created

4. **If Malicious:**
   - Terminate all RDP sessions for compromised account
   - Disable account immediately
   - Isolate all accessed systems for forensics
   - Reset credentials

### Prevention

- Restrict RDP access via firewall rules
- Require RDP through VPN or jump box
- Implement RDP Gateway with MFA
- Disable RDP on workstations (only enable on servers)
- Use just-in-time admin access

### Testing

```powershell
# Simulate lateral movement via RDP
# Log into WS-FIN-PC01 via RDP
mstsc /v:10.0.0.20

# Then from that system, RDP to another
mstsc /v:10.0.0.10  # DC01

# Repeat for multiple systems
```

Alert should fire showing multiple RDP destinations.

---

## Rule 3: Pass-the-Hash Detection

### Description
Detects Logon Type 9 (NewCredentials) with NTLM authentication, which may indicate Pass-the-Hash attack where attacker uses stolen NTLM hash to authenticate without knowing plaintext password.

### MITRE ATT&CK Mapping
- **Tactic:** Lateral Movement
- **Technique:** T1550.002 (Use Alternate Authentication Material: Pass the Hash)

### Splunk SPL Query

```spl
index=windows_security EventCode=4624 Logon_Type=9 Authentication_Package=NTLM
| eval src_ip=coalesce(Source_Network_Address, IpAddress, "unknown")
| eval account=coalesce(Account_Name, TargetUserName, "unknown")
| eval dest_host=coalesce(ComputerName, Computer, "unknown")
| where src_ip!="-" AND src_ip!="::1" AND src_ip!="127.0.0.1"
| table _time, src_ip, account, dest_host, Workstation_Name, Logon_Process, Process_Name
| eval severity="Critical"
| sort -_time
```

### Query Explanation

- `Logon_Type=9` - NewCredentials logon (RunAs /netonly, or explicit credentials)
- `Authentication_Package=NTLM` - NTLM used instead of Kerberos (suspicious for domain)
- Normal domain auth uses Kerberos; NTLM with Type 9 often indicates Pass-the-Hash
- Filters out localhost logins (src_ip validation)

### True Positive Indicators

**Pass-the-Hash characteristics:**
- NTLM used instead of Kerberos in domain environment
- Logon Type 9 from unexpected source
- Account accessing systems it normally doesn't
- Multiple systems accessed in succession
- Activity outside normal hours
- Often follows credential dumping (LSASS access detection)

**Attack Flow:**
1. Attacker compromises system
2. Dumps credentials (mimikatz, procdump on LSASS)
3. Extracts NTLM hashes
4. Uses hash to authenticate to other systems (Pass-the-Hash)
5. Moves laterally without needing plaintext password

### False Positive Scenarios

- Legitimate use of `runas /netonly` by administrators
- Some applications explicitly using NTLM
- Legacy systems requiring NTLM
- Service accounts configured for NTLM

**Note:** This rule has low false positive rate because Logon Type 9 + NTLM in domain is uncommon.

### Response Actions

1. **Immediate Investigation:**
   - Determine source system and account
   - Check for recent credential dumping attempts on source:
     ```spl
     index=windows_sysmon EventCode=10 ComputerName="source_host" TargetImage="*lsass.exe"
     ```

2. **Scope Assessment:**
   - Identify all systems accessed via Pass-the-Hash
   - Check for privilege escalation attempts
   - Look for persistence mechanisms on accessed systems

3. **Containment:**
   - Disable compromised account
   - Isolate source system (credential theft occurred here)
   - Isolate all systems accessed via Pass-the-Hash
   - Force password reset for compromised account
   - **Important:** Password reset may not fully mitigate - consider disabling and recreating account

4. **Investigation:**
   - How were credentials initially stolen?
   - What tools were used? (mimikatz, procdump, etc.)
   - What data was accessed on target systems?
   - Were domain admin credentials compromised?

5. **Remediation:**
   - Enable Credential Guard on all Windows 10+ systems
   - Implement Protected Users security group for high-value accounts
   - Enable Restricted Admin mode for RDP
   - Deploy LAPS (Local Administrator Password Solution)

### Enhanced Detection

Correlate with LSASS access:

```spl
# Find LSASS access followed by Type 9 NTLM logins
index=windows_sysmon EventCode=10 TargetImage="*lsass.exe"
| eval source_host=ComputerName
| eval lsass_time=_time
| append [
    search index=windows_security EventCode=4624 Logon_Type=9 Authentication_Package=NTLM
    | eval source_host=ComputerName
    | eval pth_time=_time
]
| stats values(lsass_time) as lsass_access, values(pth_time) as pth_attempt by source_host
| where isnotnull(lsass_access) AND isnotnull(pth_attempt)
```

Shows credential dumping followed by Pass-the-Hash - high confidence attack.

### Testing

Testing Pass-the-Hash requires specialized tools like mimikatz and is complex. For lab:

```powershell
# Simulate Type 9 logon (safe test)
runas /netonly /user:SOCLAB\test.user1 "cmd.exe"
```

This generates Logon Type 9 but with Kerberos in domain. To force NTLM (more complex):
- Disable Kerberos on test account
- Or test from non-domain system

**Note:** Actual Pass-the-Hash testing should use isolated test environment.

---

## Summary

These lateral movement detection rules provide visibility into adversary movement across the network:

1. **PsExec Detection:** Remote execution tool abuse
2. **RDP Pattern Analysis:** Multiple system access via RDP
3. **Pass-the-Hash Detection:** NTLM hash abuse for authentication

**Detection Strategy:**
- Focus on credential abuse (Pass-the-Hash)
- Monitor remote access tools (PsExec, RDP)
- Baseline normal admin activity
- Alert on deviations from normal patterns

**Key Metrics:**
- Lateral movement attempts per week
- Most accessed systems (potential high-value targets)
- Accounts involved in lateral movement
- Success rate of lateral movement attempts

**Prevention Best Practices:**
- Implement least privilege
- Use jump boxes for admin access
- Enable Credential Guard
- Deploy LAPS for local admin passwords
- Segment network to limit lateral movement
- Monitor and alert on admin account usage
