# Detection Rules Overview

This directory contains custom Splunk detection rules developed for the SOC Analyst lab environment. Each rule is mapped to the MITRE ATT&CK framework and has been tested using Atomic Red Team to ensure accurate detection of malicious activity.

## Detection Rule Catalog

| Rule Name | ATT&CK Tactic | ATT&CK Technique | Severity | Description |
|-----------|---------------|------------------|----------|-------------|
| **Brute Force Detection** |
| Multiple Failed Login Attempts | Credential Access | T1110.001 | High | Detects 10+ failed login attempts from same source |
| Brute Force with Success | Credential Access | T1110.001 | Critical | Failed logins followed by successful authentication |
| Account Lockout Spike | Credential Access | T1110.001 | Medium | Multiple account lockouts indicating password spray |
| **PowerShell Abuse Detection** |
| Encoded PowerShell Commands | Execution | T1059.001 | High | Base64 encoded PowerShell command execution |
| PowerShell Download Cradle | Command & Control | T1105 | High | PowerShell downloading content from internet |
| Office Spawning PowerShell | Execution | T1204.002 | Critical | Microsoft Office spawning PowerShell/cmd |
| **Lateral Movement Detection** |
| PsExec Execution | Lateral Movement | T1021.002 | High | PsExec or PSEXESVC detected on endpoint |
| Abnormal RDP Login Pattern | Lateral Movement | T1021.001 | Medium | Unusual Remote Desktop connections |
| Pass-the-Hash Detection | Lateral Movement | T1550.002 | Critical | NTLM authentication with Logon Type 9 |
| **Persistence Detection** |
| New Scheduled Task | Persistence | T1053.005 | Medium | Scheduled task created by non-system account |
| Registry Run Key Modified | Persistence | T1547.001 | High | AutoRun registry key modification detected |
| New Windows Service Created | Persistence | T1543.003 | High | New service installed on system |
| **Credential Access Detection** |
| LSASS Memory Access | Credential Access | T1003.001 | Critical | Suspicious process accessing LSASS memory |
| SAM Database Dumping | Credential Access | T1003.002 | Critical | Registry command targeting SAM/SYSTEM hives |
| **Data Exfiltration Detection** |
| Large Outbound Transfer | Exfiltration | T1048 | High | Unusually large data transfer to external IP |
| DNS Tunneling Detected | Exfiltration | T1048.003 | High | Abnormally long DNS query strings |

## Testing Methodology

All detection rules were tested using **Atomic Red Team** (ART), an open-source testing framework that simulates adversary techniques mapped to MITRE ATT&CK.

**Testing Process:**
1. Identify ATT&CK technique to detect
2. Develop SPL query in Splunk
3. Execute corresponding Atomic test on Windows 10 workstation
4. Verify alert triggers correctly in Splunk
5. Document true positive characteristics and potential false positives
6. Tune query to reduce noise

**Example Atomic Red Team Test:**
```powershell
# Test T1059.001 - PowerShell encoded command
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

This executes a benign encoded PowerShell command that should trigger the detection rule.

## Rule Development Process

Each detection rule follows this development lifecycle:

1. **Threat Research:** Study real-world attack technique
2. **Log Source Identification:** Determine which logs capture the activity (Sysmon Event ID 1, Security Event 4624, etc.)
3. **Query Development:** Build SPL query to identify the behavior
4. **Testing:** Use Atomic Red Team to generate test events
5. **Tuning:** Adjust query to balance detection vs false positives
6. **Documentation:** Record query, rationale, and response procedures
7. **Validation:** Re-test after any changes

## SPL Query Best Practices

**Performance Optimization:**
- Always specify index: `index=windows_security`
- Use specific time ranges: `earliest=-1h`
- Filter early in pipeline before stats operations
- Avoid wildcard searches at beginning of strings

**Field Extraction:**
- Use `eval` for calculated fields
- Leverage `rex` for custom field extraction
- Test field names with: `| fieldsummary`

**Statistical Analysis:**
- Use `stats` for aggregation
- Use `rare` and `top` for anomaly detection
- Use `eventstats` to add stats to every event

## Alert Configuration

Detection rules should be configured as Splunk alerts with:

**Trigger Conditions:**
- Real-time: For critical threats (LSASS access, brute force success)
- Scheduled (5-15 min): For medium threats
- Scheduled (hourly): For low/informational

**Actions:**
- Log to alert index
- Send email to SOC team
- Create ticket in ticketing system (if integrated)
- Trigger automated response (block IP, isolate host)

**Throttling:**
- Suppress duplicate alerts (e.g., same src_ip for 10 minutes)
- Prevents alert fatigue

## False Positive Management

Common false positive sources and mitigation:

| Rule Type | Common FP | Mitigation |
|-----------|-----------|------------|
| Failed Logins | User typos, expired passwords | Threshold >10 attempts |
| PowerShell | Admin scripts, legitimate automation | Whitelist known admin hosts |
| Registry Changes | Software installations, updates | Exclude known good processes |
| Network Connections | Legitimate tools (browsers, updaters) | Filter destination IPs/domains |
| Service Creation | Software installers | Validate service binary location |

**Whitelisting Example:**
```spl
index=windows_sysmon EventCode=1 Image="*powershell.exe"
| where Computer!="ADMIN-WS-01" AND Computer!="IT-MGMT-01"
```

## Detection Coverage Gaps

**Known Limitations:**
- Encrypted C2 traffic (HTTPS) - Hard to detect without SSL inspection
- Living off the Land Binaries (LOLBins) - Legitimate tools used maliciously
- Fileless malware - Resides only in memory, minimal disk artifacts
- Zero-day exploits - No known signatures

**Compensating Controls:**
- Behavioral analysis (unusual process relationships)
- Anomaly detection (baseline normal, alert on deviations)
- Network traffic analysis (volume, timing patterns)
- Threat intelligence integration (known malicious IPs/domains)

## MITRE ATT&CK Coverage

This rule set provides detection coverage for the following tactics:

- ✅ **Initial Access:** Limited (phishing detection separate)
- ✅ **Execution:** PowerShell, macros, scripting
- ⚠️ **Persistence:** Registry, scheduled tasks, services
- ✅ **Privilege Escalation:** Covered via persistence techniques
- ⚠️ **Defense Evasion:** Encoded commands, timestomping
- ✅ **Credential Access:** LSASS dumping, SAM access, brute force
- ⚠️ **Discovery:** Limited coverage (process/network discovery)
- ✅ **Lateral Movement:** PsExec, RDP, Pass-the-Hash
- ⚠️ **Collection:** Limited (clipboard, data staging)
- ✅ **Command & Control:** PowerShell download cradles, DNS tunneling
- ✅ **Exfiltration:** Large transfers, DNS tunneling

Legend: ✅ Good coverage | ⚠️ Partial coverage | ❌ No coverage

## Continuous Improvement

**Monthly Review:**
- Analyze false positive rate for each rule
- Review missed detections (incidents that didn't trigger alerts)
- Update queries based on new attack techniques
- Test rules against updated Atomic Red Team tests

**Threat Intelligence Integration:**
- Subscribe to threat feeds (CISA alerts, vendor bulletins)
- Update rules to detect emerging techniques
- Add IOCs to watchlists

**Metrics Tracking:**
- Alert volume per rule
- True positive rate
- Mean time to detect (MTTD)
- False positive rate

## Additional Resources

- **Splunk SPL Reference:** https://docs.splunk.com/Documentation/Splunk/latest/SearchReference
- **MITRE ATT&CK:** https://attack.mitre.org/
- **Atomic Red Team:** https://github.com/redcanaryco/atomic-red-team
- **Sigma Rules (alternative format):** https://github.com/SigmaHQ/sigma
- **Splunk Security Essentials App:** Pre-built security content for Splunk

## Rule Navigation

- [Brute Force Detection](brute-force-detection.md)
- [PowerShell Abuse Detection](powershell-abuse-detection.md)
- [Lateral Movement Detection](lateral-movement-detection.md)
- [Persistence Detection](persistence-detection.md)
- [Credential Access Detection](credential-access-detection.md)
- [Data Exfiltration Detection](data-exfiltration-detection.md)
