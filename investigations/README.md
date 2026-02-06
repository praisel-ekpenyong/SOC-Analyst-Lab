# Security Investigations Overview

This directory contains detailed incident response investigations conducted in the SOC Analyst lab environment. Each investigation demonstrates end-to-end analysis from initial alert through containment, eradication, and lessons learned.

## Investigation Catalog

| ID | Title | Date | Severity | ATT&CK Technique | Verdict |
|----|-------|------|----------|------------------|---------|
| 001 | RDP Brute Force Attack | 2025-10-15 | Critical | T1110.001 - Brute Force | True Positive |
| 002 | Malware Execution via Macro | 2025-10-18 | Critical | T1204.002 - Malicious File | True Positive |
| 003 | Lateral Movement with PsExec | 2025-10-22 | High | T1021.002 - SMB/Admin Shares | True Positive |
| 004 | Suspicious PowerShell Activity | 2025-10-25 | High | T1059.001 - PowerShell | True Positive |
| 005 | Data Exfiltration | 2025-10-28 | Critical | T1048 - Exfiltration | True Positive |

## Investigation Methodology

Each investigation follows the NIST Incident Response lifecycle:

### 1. Preparation
- Detection rules configured and tested
- Response playbooks documented
- Tools and access ready (SIEM, EDR, forensic tools)
- Team trained and on-call rotation established

### 2. Detection & Analysis
- Alert triggers in SIEM or EDR
- Initial triage and severity assessment
- Log analysis using Splunk SPL queries
- Timeline reconstruction
- Scope determination

### 3. Containment
- Short-term: Isolate affected systems, block malicious IPs
- Long-term: Apply patches, strengthen configurations

### 4. Eradication
- Remove malware and attacker access
- Eliminate persistence mechanisms
- Close vulnerabilities exploited

### 5. Recovery
- Restore systems to normal operation
- Verify no attacker presence
- Monitor for reinfection
- Reset compromised credentials

### 6. Post-Incident Activity
- Lessons learned meeting
- Detection rule improvements
- Documentation updates
- Metrics analysis

## Key Investigation Components

Each investigation document includes:

**Alert Details**
- Initial alert source, name, and severity
- MITRE ATT&CK mapping
- Affected systems and users

**Executive Summary**
- High-level incident overview for management
- Business impact assessment
- Concise 2-3 sentences

**Timeline of Events**
- Chronological reconstruction of attack
- Timestamped events from multiple log sources
- Attack progression visualization

**Investigation Steps**
- Detailed analysis methodology
- SIEM queries executed
- EDR findings
- Threat intelligence enrichment
- Scope assessment

**Indicators of Compromise (IOCs)**
- IP addresses
- Domain names
- File hashes (MD5, SHA256)
- URLs
- Registry keys
- Malware signatures

**Verdict**
- True Positive or False Positive determination
- Confidence level
- Evidence supporting verdict

**Response Actions Taken**
- Containment measures
- Eradication steps
- Recovery procedures
- Stakeholder communication

**MITRE ATT&CK Mapping**
- Full tactic and technique coverage
- Evidence for each mapped technique
- Attack path visualization

**Lessons Learned**
- What went well
- What could improve
- New detection rules created
- Process improvements
- Training recommendations

## MITRE ATT&CK Coverage

These investigations demonstrate detection and response across multiple ATT&CK tactics:

- **Initial Access:** Brute Force (T1110)
- **Execution:** PowerShell (T1059.001), User Execution (T1204.002)
- **Persistence:** Registry Run Keys (T1547), Scheduled Tasks (T1053)
- **Privilege Escalation:** Valid Accounts (T1078)
- **Defense Evasion:** Obfuscated Files (T1027)
- **Credential Access:** LSASS Memory (T1003.001)
- **Discovery:** System Information Discovery (T1082)
- **Lateral Movement:** Remote Services (T1021), PsExec (T1021.002)
- **Collection:** Data from Local System (T1005)
- **Command and Control:** Ingress Tool Transfer (T1105)
- **Exfiltration:** Exfiltration Over Alternative Protocol (T1048)

## Investigation Tools Used

**SIEM (Splunk)**
- Log correlation and analysis
- Timeline reconstruction
- Anomaly detection
- Threat hunting queries

**EDR (Wazuh)**
- Endpoint telemetry
- Process execution tracking
- File integrity monitoring
- Real-time alerts

**Network Analysis**
- Firewall logs
- DNS logs
- NetFlow analysis (if available)

**Threat Intelligence**
- VirusTotal - File and IP reputation
- AbuseIPDB - IP reputation and abuse reports
- URLScan.io - URL analysis and screenshots
- MISP - Threat intelligence sharing platform
- Shodan - Internet-connected device search

**Forensic Tools**
- Event log analysis (Event Viewer, PowerShell)
- Sysmon log review
- Registry analysis
- File system timeline analysis
- Memory forensics (if needed)

## Metrics Tracked

**Detection Metrics:**
- Mean Time to Detect (MTTD)
- Detection source (SIEM rule, EDR alert, user report)
- Alert volume per investigation type

**Response Metrics:**
- Mean Time to Respond (MTTR)
- Mean Time to Contain (MTTC)
- Mean Time to Recover (MTTR-full)
- Escalation rate

**Impact Metrics:**
- Systems affected
- Accounts compromised
- Data accessed/exfiltrated
- Downtime duration
- Business impact severity

## Common Attack Patterns

### Pattern 1: External Brute Force → Lateral Movement
1. External attacker brute forces RDP/SSH
2. Gains initial foothold with compromised credentials
3. Enumerates domain environment
4. Moves laterally using PsExec or RDP
5. Escalates to Domain Admin
6. Deploys ransomware or exfiltrates data

**Investigations:** 001, 003

### Pattern 2: Phishing → Malware → C2 → Exfiltration
1. User receives phishing email with malicious attachment
2. Opens document and enables macros
3. Macro downloads and executes malware
4. Malware establishes C2 communication
5. Attacker performs reconnaissance
6. Exfiltrates sensitive data

**Investigations:** 002, 004, 005

### Pattern 3: Credential Theft → Privilege Escalation → Persistence
1. Initial compromise of low-privilege account
2. Credential dumping (LSASS, SAM)
3. Privilege escalation with stolen admin credentials
4. Install persistence mechanisms
5. Long-term access for future operations

**Investigations:** 002, 003

## Continuous Improvement

After each investigation:

**Detection Tuning:**
- Analyze why detection triggered
- Reduce false positive rate
- Improve alert fidelity
- Add new detection rules for gaps

**Process Improvement:**
- Update response playbooks
- Document new procedures
- Improve tool integration
- Streamline workflows

**Training:**
- Share lessons learned
- Conduct tabletop exercises
- Update training materials
- Cross-train team members

**Prevention:**
- Patch vulnerabilities
- Implement security controls
- User awareness training
- Security architecture improvements

## Investigation Templates

Standard templates used for consistency:

**Initial Alert Email Template:**
```
Subject: [CRITICAL] Investigation 00X - [Title]
- Alert Time: [timestamp]
- Affected System: [hostname]
- Affected User: [username]
- Initial Severity: [Critical/High/Medium]
- Assigned Analyst: [name]
- Status: Investigation In Progress
```

**Status Update Template:**
```
Investigation Update - [timestamp]
- Current Status: [In Progress/Contained/Eradicated]
- Key Findings: [bullet points]
- Actions Taken: [bullet points]
- Next Steps: [bullet points]
- ETA for Resolution: [timeframe]
```

**Executive Summary Template:**
```
Incident: [title]
Date: [date]
Severity: [level]
Impact: [description]
Status: [Resolved/Ongoing]
Summary: [2-3 sentences]
Business Impact: [description]
Recommendations: [bullet points]
```

## External Resources

- **NIST Incident Response Guide:** SP 800-61 Rev. 2
- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **SANS Incident Handler's Handbook:** https://www.sans.org/reading-room/whitepapers/incident/
- **Incident Response Consortium:** https://www.incidentresponse.com/
- **FIRST (Forum of Incident Response Teams):** https://www.first.org/

## Investigation Navigation

- [Investigation 001: RDP Brute Force Attack](investigation-001-brute-force-rdp.md)
- [Investigation 002: Malware Execution via Macro](investigation-002-malware-execution.md)
- [Investigation 003: Lateral Movement with PsExec](investigation-003-lateral-movement-psexec.md)
- [Investigation 004: Suspicious PowerShell Activity](investigation-004-suspicious-powershell.md)
- [Investigation 005: Data Exfiltration](investigation-005-data-exfiltration.md)
