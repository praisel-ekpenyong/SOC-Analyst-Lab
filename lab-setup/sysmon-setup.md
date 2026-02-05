# Sysmon Setup and Configuration

## Overview

Sysmon (System Monitor) is a Windows system service that logs detailed system activity to the Windows Event Log. It provides visibility into process creation, network connections, file creation, registry modifications, and other critical events that standard Windows Event Logs don't capture.

For SOC operations, Sysmon is essential for:
- Detecting malicious process execution
- Tracking lateral movement via network connections
- Identifying persistence mechanisms (registry, scheduled tasks)
- Forensic investigation and timeline reconstruction

## Prerequisites

- Windows 10 or Windows Server 2019
- Administrator privileges
- PowerShell 5.1 or later

## Download Sysmon

### Step 1: Download Sysmon Binary

Download from Microsoft Sysinternals:
```
https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
```

Or download directly using PowerShell:
```powershell
# Create temp directory
New-Item -Path "C:\Temp\Sysmon" -ItemType Directory -Force

# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile "C:\Temp\Sysmon\Sysmon.zip"

# Extract
Expand-Archive -Path "C:\Temp\Sysmon\Sysmon.zip" -DestinationPath "C:\Temp\Sysmon"
```

### Step 2: Download SwiftOnSecurity Configuration

The SwiftOnSecurity Sysmon configuration is a community-maintained, high-quality config that provides comprehensive logging while minimizing noise.

```powershell
# Download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile "C:\Temp\Sysmon\sysmonconfig-export.xml"
```

Or manually download from:
```
https://github.com/SwiftOnSecurity/sysmon-config
```

## Installation

### Install Sysmon with Configuration

Open PowerShell as Administrator and run:

```powershell
# Navigate to Sysmon directory
cd C:\Temp\Sysmon

# Install Sysmon with config (64-bit)
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

**Expected Output:**
```
System Monitor v15.0 - System activity monitor
Copyright (C) 2014-2023 Mark Russinovich and Thomas Garnier
Sysinternals - www.sysinternals.com

Sysmon64 installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon64..
Sysmon64 started.
```

### Verify Installation

Check if Sysmon service is running:

```powershell
Get-Service Sysmon64
```

**Expected Output:**
```
Status   Name               DisplayName
------   ----               -----------
Running  Sysmon64           Sysmon64
```

Verify Sysmon driver is loaded:
```powershell
Get-Service SysmonDrv
```

Check Sysmon Event Log exists:
```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
```

## Key Sysmon Event IDs

Sysmon generates events in the `Microsoft-Windows-Sysmon/Operational` log with the following critical Event IDs:

| Event ID | Event Type | Description | ATT&CK Relevance |
|----------|------------|-------------|------------------|
| **1** | Process Create | New process created (includes command line, parent process, hashes) | Execution, Lateral Movement, Persistence |
| **2** | File Creation Time Changed | File creation time was modified (timestomping) | Defense Evasion |
| **3** | Network Connection | Process initiated network connection (includes dest IP/port) | Command & Control, Exfiltration |
| **5** | Process Terminated | Process terminated | N/A (cleanup detection) |
| **6** | Driver Loaded | Driver loaded (kernel-level) | Persistence, Privilege Escalation |
| **7** | Image Loaded | DLL/module loaded by process | Execution, Defense Evasion |
| **8** | CreateRemoteThread | Process created thread in another process | Defense Evasion, Privilege Escalation |
| **10** | ProcessAccess | Process accessed another process memory (e.g., LSASS dumping) | Credential Access |
| **11** | FileCreate | File created or overwritten | Execution, Persistence |
| **12** | Registry Object Create/Delete | Registry key or value created/deleted | Persistence, Defense Evasion |
| **13** | Registry Value Set | Registry value modified | Persistence, Defense Evasion |
| **14** | Registry Object Renamed | Registry key renamed | Defense Evasion |
| **15** | FileCreateStreamHash | NTFS alternate data stream created | Defense Evasion |
| **17** | Pipe Created | Named pipe created | Lateral Movement (IPC) |
| **18** | Pipe Connected | Named pipe connection | Lateral Movement |
| **19** | WMI Event Filter | WMI event filter registered | Persistence |
| **20** | WMI Event Consumer | WMI event consumer registered | Persistence |
| **21** | WMI Event Consumer To Filter | WMI consumer bound to filter | Persistence |
| **22** | DNS Query | DNS query performed by process | Command & Control, Discovery |
| **23** | FileDelete | File deleted (archived to EvtxDataStream) | Defense Evasion |
| **24** | Clipboard Change | Clipboard contents changed | Collection |
| **25** | ProcessTampering | Process memory/image tampered with | Defense Evasion |
| **26** | FileDeleteDetected | File delete detected (logged but not captured) | Defense Evasion |
| **27** | FileBlockExecutable | Executable file blocked from loading | Defense Evasion |
| **28** | FileBlockShredding | File shredding detected | Defense Evasion |
| **29** | FileExecutableDetected | Executable file detected (useful for monitoring dirs) | Execution |

## Configuration Overview

The SwiftOnSecurity configuration provides:

**Strengths:**
- Comprehensive process creation logging (Event ID 1)
- Network connection tracking (Event ID 3)
- Registry modification monitoring for persistence (Event ID 13)
- DNS query logging for C2 detection (Event ID 22)
- DLL load tracking (Event ID 7)
- Process memory access for credential dumping detection (Event ID 10)

**Noise Reduction:**
- Filters out known-good Microsoft processes
- Excludes routine system operations
- Balances visibility with performance

**Example Filters in Config:**
```xml
<!-- Exclude Chrome/Edge network connections to reduce noise -->
<NetworkConnect onmatch="exclude">
    <Image condition="contains">chrome.exe</Image>
    <Image condition="contains">msedge.exe</Image>
</NetworkConnect>

<!-- Monitor PowerShell execution closely -->
<ProcessCreate onmatch="include">
    <Image condition="contains">powershell.exe</Image>
    <Image condition="contains">pwsh.exe</Image>
</ProcessCreate>
```

## Integration with Splunk

### Configure Universal Forwarder to Send Sysmon Logs

Edit `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows_sysmon
renderXml = true
```

Restart Splunk Universal Forwarder:
```powershell
Restart-Service SplunkForwarder
```

### Verify in Splunk

Search for Sysmon logs:
```spl
index=windows_sysmon
| stats count by EventCode
| sort -count
```

**Expected Event IDs:**
- Event 1 (Process Create) should have the highest count
- Event 3 (Network Connection) should be frequent
- Event 13 (Registry Set) should be common

## Integration with Wazuh

Wazuh automatically ingests Sysmon logs from the Windows Event Log.

### Verify in Wazuh Dashboard

Navigate to: Security Events → Filter by `data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"`

Or via Wazuh agent on Windows:
```powershell
# Check Wazuh agent is collecting Sysmon
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" | Select-String -Pattern "Sysmon"
```

## Updating Sysmon Configuration

To update Sysmon configuration without reinstalling:

```powershell
# Download updated config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile "C:\Temp\Sysmon\sysmonconfig-export-updated.xml"

# Apply updated config
.\Sysmon64.exe -c sysmonconfig-export-updated.xml
```

Check current configuration:
```powershell
.\Sysmon64.exe -c
```

## Uninstall Sysmon (if needed)

```powershell
.\Sysmon64.exe -u
```

## Example Detection Use Cases

### 1. Detect PowerShell Encoded Commands (Event ID 1)

Sysmon logs full command line:
```spl
index=windows_sysmon EventCode=1 Image="*powershell.exe" CommandLine="*-enc*"
| table _time, Computer, User, CommandLine, ParentImage
```

### 2. Detect LSASS Memory Access (Event ID 10)

Credential dumping attempts:
```spl
index=windows_sysmon EventCode=10 TargetImage="*lsass.exe"
| where SourceImage!="*svchost.exe" AND SourceImage!="*csrss.exe"
| table _time, Computer, SourceImage, GrantedAccess
```

### 3. Detect PsExec Usage (Event ID 1 + 13)

```spl
index=windows_sysmon (EventCode=1 Image="*PsExec*") OR (EventCode=13 TargetObject="*PSEXESVC*")
| table _time, Computer, User, Image, CommandLine
```

### 4. Detect DNS C2 Beaconing (Event ID 22)

Repeated DNS queries to suspicious domains:
```spl
index=windows_sysmon EventCode=22
| stats count by QueryName, Image, Computer
| where count > 50
| sort -count
```

### 5. Detect Registry Run Key Persistence (Event ID 13)

```spl
index=windows_sysmon EventCode=13 
    (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*")
| table _time, Computer, User, TargetObject, Details, Image
```

## Performance Considerations

**Disk Space:**
- Sysmon logs can grow to several GB per day on busy systems
- Monitor `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`
- Configure log rotation in Event Viewer (right-click log → Properties)
- Recommended: 1 GB max size with "Overwrite events as needed"

**CPU Impact:**
- Minimal (<1-2% on most systems)
- Slightly higher during intensive disk/network operations

**Splunk Licensing:**
- Sysmon Event ID 1 (Process Create) generates most data
- Expect 50-200 MB/day per endpoint depending on activity
- Event ID 3 (Network) also high-volume (filter browser traffic)

## Troubleshooting

**Issue: Sysmon service won't start**
```powershell
# Check event viewer for errors
Get-WinEvent -LogName "System" -MaxEvents 50 | Where-Object {$_.ProviderName -eq "Service Control Manager" -and $_.Message -match "Sysmon"}

# Verify driver signature
Get-AuthenticodeSignature "C:\Windows\Sysmon64.exe"
```

**Issue: No logs appearing**
```powershell
# Verify config is valid XML
[xml]$config = Get-Content "C:\Temp\Sysmon\sysmonconfig-export.xml"

# Check Sysmon operational log exists
Get-WinEvent -ListLog "*Sysmon*"

# Manually trigger event by opening notepad
notepad.exe

# Then search for Event ID 1
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.Id -eq 1}
```

**Issue: Too many events (performance impact)**
- Implement additional filters in config
- Exclude noisy processes (web browsers, Windows Update)
- Focus on high-value Event IDs (1, 3, 10, 13, 22)

## Alternative Configurations

While SwiftOnSecurity is recommended for this lab, other popular configs:

- **Olaf Hartong's Sysmon Modular:** https://github.com/olafhartong/sysmon-modular
  - More aggressive logging, higher fidelity
  - Better for threat hunting, higher volume

- **Ion-Storm:** https://github.com/ion-storm/sysmon-config
  - Balanced approach similar to SwiftOnSecurity
  - Good for production with log management

- **Microsoft Sysinternals Default:** Minimal config (logs almost everything)
  - Use for testing, not production

## Next Steps

After Sysmon is installed and logs are flowing to Splunk/Wazuh:

1. Review [Detection Rules](../detection-rules/README.md) that leverage Sysmon
2. Test with Atomic Red Team to generate Sysmon events
3. Create custom alerts based on Sysmon Event IDs
4. Tune configuration to reduce false positives

## References

- Official Sysmon Documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- SwiftOnSecurity Config: https://github.com/SwiftOnSecurity/sysmon-config
- Sysmon Event ID Reference: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx
- TrustedSec Sysmon Community Guide: https://www.trustedsec.com/blog/sysmon-101/
