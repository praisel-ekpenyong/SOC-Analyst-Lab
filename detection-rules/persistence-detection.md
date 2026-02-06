# Persistence Detection Rules

## Overview

Persistence mechanisms allow attackers to maintain access to compromised systems across reboots and maintain long-term presence. These rules detect common Windows persistence techniques including scheduled tasks, registry run keys, and new service creation.

---

## Rule 1: New Scheduled Task Created

### Description
Detects creation of new scheduled tasks by non-system accounts, a common persistence mechanism used by attackers to ensure malware runs automatically.

### MITRE ATT&CK Mapping
- **Tactic:** Persistence, Privilege Escalation
- **Technique:** T1053.005 (Scheduled Task/Job: Scheduled Task)

### Splunk SPL Query

```spl
index=windows_security EventCode=4698
| eval task_creator=coalesce(Account_Name, SubjectUserName, "unknown")
| eval task_name=coalesce(Task_Name, TaskName, "unknown")
| eval task_content=coalesce(Task_Content, TaskContent, "N/A")
| where task_creator!="SYSTEM" AND task_creator!="LOCAL SERVICE" AND task_creator!="NETWORK SERVICE"
| table _time, ComputerName, task_creator, task_name, task_content
| eval severity="Medium"
| sort -_time
```

### Query Explanation

- `EventCode=4698` - Scheduled task created (requires advanced audit policy)
- Filters out system-created tasks (legitimate Windows updates, maintenance)
- `Task_Content` contains XML definition including what executes and when
- User-created tasks are suspicious and warrant investigation

### True Positive Indicators

**Malicious scheduled task characteristics:**
- **Task Name:** Random characters or mimics legitimate task
- **Creator:** Compromised user account
- **Action:** Executes PowerShell, cmd, or suspicious binary
- **Trigger:** Runs at logon, daily, or every few hours
- **Location:** Task stored in user-controlled directory
- **Privilege:** Runs as SYSTEM or high-privilege account

**Example Malicious Task:**
```
task_name: \Microsoft\Windows\UpdateCheck  (trying to blend in)
task_creator: a.chen
task_content: <Exec><Command>powershell.exe</Command><Arguments>-W Hidden -Enc JAB...</Arguments></Exec>
<Trigger><LogonTrigger>...</LogonTrigger></Trigger>
```

### False Positive Scenarios

- Software installers creating legitimate scheduled tasks
- IT administrators creating maintenance tasks
- User-installed applications scheduling updates
- Backup software scheduling jobs

**Mitigation:**
- Baseline normal task creation in environment
- Whitelist known software installation patterns
- Focus on tasks executing scripts or suspicious binaries

### Response Actions

1. **Parse Task XML:**
   - Extract executable path, arguments, trigger schedule
   - Identify if task executes script, PowerShell, or binary
   - Check task privilege level (RunLevel)

2. **Validate Task Legitimacy:**
   - Contact user who created task
   - Check if related to recent software installation
   - Verify executable path and signature

3. **If Malicious:**
   ```powershell
   # Disable task
   Disable-ScheduledTask -TaskName "\Microsoft\Windows\UpdateCheck"
   
   # Export for forensics
   Export-ScheduledTask -TaskName "\Microsoft\Windows\UpdateCheck" | Out-File C:\forensics\malicious_task.xml
   
   # Delete task
   Unregister-ScheduledTask -TaskName "\Microsoft\Windows\UpdateCheck" -Confirm:$false
   ```

4. **Check Payload:**
   - Locate and analyze executable/script referenced in task
   - Submit to sandbox/AV scanning
   - Remove malicious payload

### Testing

```powershell
# Create test scheduled task
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-c Write-Host 'Test'"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "TestPersistence" -Action $action -Trigger $trigger -Description "Test task for detection"
```

Should trigger alert in Splunk.

---

## Rule 2: Registry Run Key Modification

### Description
Detects modification of Windows Registry Run keys, which automatically execute programs at system startup - a classic and widely-used persistence mechanism.

### MITRE ATT&CK Mapping
- **Tactic:** Persistence, Privilege Escalation
- **Technique:** T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)

### Splunk SPL Query

```spl
index=windows_sysmon EventCode=13
| eval reg_path=lower(TargetObject)
| where match(reg_path, "\\currentversion\\run\\") OR 
        match(reg_path, "\\currentversion\\runonce\\") OR
        match(reg_path, "\\currentversion\\runonceex\\")
| eval reg_value=Details
| eval modifying_process=Image
| table _time, ComputerName, User, TargetObject, reg_value, modifying_process, ProcessId
| eval severity="High"
| sort -_time
```

### Query Explanation

- `EventCode=13` - Sysmon Registry Value Set event
- Monitors multiple Run key locations:
  - `Run` - Executes every boot
  - `RunOnce` - Executes once then removes itself
  - `RunOnceEx` - Extended RunOnce functionality
- Both HKLM (system-wide) and HKCU (user-specific) locations monitored
- `Details` field contains the executable/command being added

### True Positive Indicators

**Malicious Run key additions:**
- **Process:** PowerShell, cmd, suspicious process adding key
- **Value:** Points to temp directories, AppData, Downloads
- **Binary:** Unsigned, from non-standard locations
- **Timing:** Added during or after suspicious activity
- **User:** Non-admin user modifying HKLM Run keys (privilege escalation)

**Common Malicious Patterns:**
```
TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate
Details: C:\Users\Public\svchost.exe
modifying_process: powershell.exe
```

Fake name ("SecurityUpdate"), suspicious location (Users\Public), added by PowerShell = high confidence malicious.

### False Positive Scenarios

- Software installations adding legitimate startup entries
- User-installed applications (Dropbox, OneDrive, etc.)
- Corporate software deployment
- Some drivers and system utilities

**Mitigation:**
- Whitelist known good software paths
- Focus on unusual locations (temp, Downloads, Public)
- Correlate with recent installs
- Verify digital signatures of added executables

### Response Actions

1. **Examine Registry Value:**
   ```powershell
   # Check what's in the Run key
   Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
   Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
   ```

2. **Analyze Added Binary:**
   - Check file location and signature
   - Submit hash to VirusTotal
   - Review file creation time (Sysmon Event 11)

3. **Remove Malicious Entry:**
   ```powershell
   # Remove registry value
   Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate"
   
   # Delete malicious file
   Remove-Item "C:\Users\Public\svchost.exe" -Force
   ```

4. **Investigation:**
   - How was entry added? (malware, user action, exploit)
   - Check for additional persistence mechanisms
   - Review recent process creation events
   - Scan system for malware

### Testing

```powershell
# Add benign test entry
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestPersist" -Value "C:\Windows\System32\notepad.exe"
```

Should trigger alert immediately.

---

## Rule 3: New Windows Service Created

### Description
Detects installation of new Windows services, which run with SYSTEM privileges and persist across reboots, making them attractive for attackers.

### MITRE ATT&CK Mapping
- **Tactic:** Persistence, Privilege Escalation
- **Technique:** T1543.003 (Create or Modify System Process: Windows Service)

### Splunk SPL Query

```spl
index=windows_security EventCode=7045
| eval service_name=coalesce(Service_Name, ServiceName, "unknown")
| eval service_file=coalesce(Service_File_Name, ImagePath, "unknown")
| eval service_account=coalesce(Account_Name, ServiceAccount, "unknown")
| eval service_type=coalesce(Service_Type, ServiceType, "unknown")
| table _time, ComputerName, service_name, service_file, service_type, Service_Start_Type, service_account
| eval severity="High"
| sort -_time
```

### Query Explanation

- `EventCode=7045` - New service installed
- Captures service name, binary path, start type, and account it runs under
- All new services logged, including legitimate and malicious
- `Service_Start_Type` indicates when service starts (Auto, Manual, Disabled)

### True Positive Indicators

**Malicious service characteristics:**
- **Name:** Random characters or mimics Windows services
- **Binary Path:** Temp folders, AppData, unusual locations
- **Account:** LocalSystem (highest privilege) for unknown service
- **Start Type:** Automatic (starts at boot)
- **Binary:** Unsigned, low/no prevalence, recent compilation
- **Creation Time:** Outside maintenance windows, during incident

**Example Malicious Service:**
```
service_name: WindowsUpdate  (typosquatting)
service_file: C:\Users\Public\system32.exe
service_account: LocalSystem
Service_Start_Type: Auto Start
```

**PsExec Creates Service:**
```
service_name: PSEXESVC
service_file: C:\Windows\PSEXESVC.exe
```

This is lateral movement indicator (see lateral-movement-detection.md Rule 1).

### False Positive Scenarios

- Legitimate software installations (drivers, monitoring agents, antivirus)
- Windows updates installing services
- IT-deployed software via SCCM/Intune
- Security tools (EDR, DLP) installing service components

**Mitigation:**
- Baseline all legitimate services in environment
- Whitelist known software vendors
- Require change management for service installations
- Focus on unusual binary paths and unsigned executables

### Response Actions

1. **Check Service Details:**
   ```powershell
   Get-Service | Where-Object {$_.Name -eq "WindowsUpdate"}
   Get-WmiObject Win32_Service | Where-Object {$_.Name -eq "WindowsUpdate"} | Select-Object *
   ```

2. **Analyze Service Binary:**
   - Check file path: `(Get-Service "WindowsUpdate").BinaryPathName`
   - Verify signature: `Get-AuthenticodeSignature "C:\path\to\service.exe"`
   - Submit to VirusTotal
   - Review file metadata (creation time, version info)

3. **If Malicious:**
   ```powershell
   # Stop service
   Stop-Service -Name "WindowsUpdate" -Force
   
   # Delete service
   sc.exe delete "WindowsUpdate"
   
   # Remove binary
   Remove-Item "C:\Users\Public\system32.exe" -Force
   ```

4. **Investigate Installation:**
   - Who/what installed service?
   - Check Event ID 4688 (process creation) around same timeframe
   - Look for service installer (.exe or .msi)
   - Determine initial access vector

5. **Check for Additional Persistence:**
   - Scan for other malicious services
   - Check registry Run keys
   - Review scheduled tasks
   - Search for malware across system

### Enhanced Detection

Correlate service creation with process execution:

```spl
index=windows_security EventCode=7045
| eval service_file=Service_File_Name
| join type=left service_file [
    search index=windows_sysmon EventCode=1
    | eval service_file=Image
    | stats count as executions by service_file
]
| table _time, ComputerName, Service_Name, service_file, executions
| fillnull value=0 executions
```

Shows if service binary has executed (executions=0 might be staging before activation).

### Testing

```powershell
# Create test service
New-Service -Name "TestService" -BinaryPathName "C:\Windows\System32\svchost.exe" -DisplayName "Test Service" -StartupType Manual

# Verify creation
Get-Service "TestService"

# Clean up
Remove-Service -Name "TestService"
```

Should trigger alert on creation.

---

## Summary

These persistence detection rules identify common mechanisms attackers use to maintain access:

1. **Scheduled Tasks:** Time-based or event-triggered execution
2. **Registry Run Keys:** Startup execution via registry
3. **Windows Services:** Privileged execution as system services

**Persistence Detection Strategy:**
- Monitor all common persistence locations
- Baseline legitimate persistence in environment
- Alert on deviations from baseline
- Correlate with other suspicious activity

**Key Indicators Across All Rules:**
- Executables in temp/AppData/Public folders
- Unsigned or suspicious binaries
- Created during/after suspicious activity
- Mimic legitimate Windows names
- Execute PowerShell or command shells

**Response Priorities:**
- **Critical:** Service or task executing from temp folder with SYSTEM privileges
- **High:** Registry Run key pointing to unsigned executable
- **Medium:** User-created scheduled task requiring investigation

**Prevention Best Practices:**
- Implement application whitelisting (AppLocker, WDAC)
- Use Attack Surface Reduction rules
- Restrict administrative privileges
- Enable tamper protection on security tools
- Deploy EDR with anti-persistence capabilities
- Regular baseline audits of persistence locations

**Metrics to Track:**
- Persistence attempts per week
- Most common persistence type used
- Detection rate (how many caught vs missed)
- Dwell time before detection
- False positive rate per rule
