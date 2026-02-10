# Incident Response Playbooks

This directory contains comprehensive SOC Tier 1 incident response playbooks designed for common security scenarios. Each playbook provides step-by-step procedures to ensure consistent, effective incident response across the Security Operations Center.

## Purpose

Incident response playbooks serve as standardized procedures that:
- Ensure consistent response to security incidents
- Reduce response time through pre-defined workflows
- Minimize errors through structured procedures
- Enable junior analysts to handle complex scenarios
- Provide clear escalation criteria
- Document institutional knowledge
- Facilitate team training and onboarding

## Playbook Catalog

| ID | Title | Severity | MITRE ATT&CK | Last Updated |
|----|-------|----------|--------------|--------------|
| PB-001 | Phishing Response | Medium-High | T1566 | 2026-02-10 |
| PB-002 | Brute Force / Account Compromise | High | T1110 | 2026-02-10 |
| PB-003 | Malware Infection Response | Critical | T1204, T1059 | 2026-02-10 |
| PB-004 | Suspicious Network Activity | Medium-High | T1071, T1048 | 2026-02-10 |

## Available Playbooks

### [PB-001: Phishing Response](playbook-phishing-response.md)
**Use Case:** Email gateway alert, user report of suspicious email, SIEM correlation on phishing indicators

**Key Steps:**
- Email artifact collection (headers, sender, attachments, URLs)
- Header analysis (SPF/DKIM/DMARC)
- Sender and IP reputation check
- URL and attachment analysis
- Verdict determination
- Containment and user notification

**Common Scenarios:**
- Credential harvesting pages
- Malicious attachments (macros, executables)
- Business email compromise (BEC)
- Brand impersonation

---

### [PB-002: Brute Force / Account Compromise](playbook-brute-force-response.md)
**Use Case:** SIEM alert on multiple failed logins, account lockout alerts, successful auth after failures

**Key Steps:**
- Verify failed login attempts
- Identify source IP and target accounts
- Check for successful authentication
- Assess post-compromise activity
- Contain compromised accounts
- Block attacker source

**Common Scenarios:**
- RDP brute force
- SSH brute force
- Web application login attacks
- Password spray attacks

---

### [PB-003: Malware Infection Response](playbook-malware-response.md)
**Use Case:** EDR alert, AV detection, SIEM process anomaly alert, user report

**Key Steps:**
- Identify affected host and process
- Isolate endpoint from network
- Analyze file hash and process tree
- Block C2 infrastructure
- Remove malware and persistence
- Recovery and credential reset

**Common Scenarios:**
- Trojan/RAT infections
- Ransomware
- Cryptocurrency miners
- Info stealers

---

### [PB-004: Suspicious Network Activity](playbook-suspicious-network-activity.md)
**Use Case:** IDS/IPS alert, beaconing detection, DNS anomalies, unusual traffic volume

**Key Steps:**
- Identify traffic characteristics
- Capture and analyze with Wireshark
- Check for beaconing patterns
- Perform threat intelligence enrichment
- Contain affected systems
- Block malicious infrastructure

**Common Scenarios:**
- Command and Control (C2) beaconing
- DNS tunneling
- Data exfiltration
- Port scanning

---

## SOC Playbook Methodology

### Playbook Structure

Each playbook follows a standardized structure:

1. **Metadata**
   - Playbook ID, title, version
   - Severity classification
   - Owner and review cycle
   - Last updated date

2. **Trigger Conditions**
   - What alerts or events initiate this playbook
   - Detection rule names
   - User report scenarios

3. **Initial Triage**
   - Quick assessment steps
   - Severity validation
   - Scope determination

4. **Investigation Steps**
   - Detailed analysis procedures
   - SIEM queries (Splunk SPL)
   - Log sources to review
   - Tool-specific commands

5. **Containment**
   - Immediate actions to limit impact
   - Isolation procedures
   - Blocking actions

6. **Eradication**
   - Remove threat from environment
   - Eliminate persistence mechanisms
   - Patch vulnerabilities

7. **Recovery**
   - Restore normal operations
   - Credential resets
   - User notifications

8. **Escalation Criteria**
   - When to escalate to Tier 2/3
   - When to involve management
   - When to contact external parties (legal, law enforcement)

9. **Documentation Requirements**
   - Ticket template
   - Required evidence
   - Timeline documentation

10. **MITRE ATT&CK Mapping**
    - Relevant tactics and techniques
    - Detection and response coverage

### Playbook Usage Guidelines

**When to Use a Playbook:**
- Alert matches playbook trigger conditions
- User reports incident matching playbook scope
- Proactive threat hunting identifies applicable scenario

**How to Use a Playbook:**
1. Identify the appropriate playbook based on alert/incident type
2. Follow steps sequentially unless conditions require deviation
3. Document all actions taken in the incident ticket
4. Use provided SIEM queries and commands as templates
5. Adjust queries for your specific environment
6. Escalate when criteria are met
7. Complete post-incident documentation

**Playbook Customization:**
- Adapt IP ranges, hostnames, and account names to your environment
- Modify SIEM queries for your log sources and field names
- Update contact information for escalation
- Adjust severity thresholds based on organizational risk

### Playbook Maintenance

**Review Cycle:**
- All playbooks reviewed quarterly
- Post-incident reviews after major incidents
- Annual comprehensive audit

**Update Triggers:**
- New threat intelligence or TTPs
- Tool or technology changes
- Process improvements identified
- False positive/negative findings

**Version Control:**
- All changes tracked in git repository
- Version number updated with each change
- Change log maintained in playbook

### Severity Classification

| Severity | Criteria | Response Time | Escalation |
|----------|----------|---------------|------------|
| **Critical** | Active exploitation, data breach, ransomware, Domain Admin compromise | Immediate (5 min) | Immediate to Tier 2, CISO notification |
| **High** | Successful account compromise, malware infection, C2 communication | 15 minutes | Escalate if not contained in 1 hour |
| **Medium** | Suspicious activity, policy violations, failed exploitation attempts | 30 minutes | Escalate if anomalies persist |
| **Low** | Reconnaissance, scanning, low-risk policy violations | 1 hour | Escalate if part of larger campaign |

### Escalation Criteria

**Escalate to Tier 2/3 when:**
- Incident exceeds Tier 1 skill level or authority
- Advanced forensics required
- Multiple systems compromised
- Data exfiltration confirmed
- Ransomware or destructive malware
- Attack is ongoing and containment unsuccessful
- Executive or critical system affected
- Regulatory reporting may be required

**Escalate to Management when:**
- Critical or high severity incident
- Potential data breach
- Service disruption
- Reputational risk
- Legal or regulatory implications
- Media attention expected

**External Escalation when:**
- Law enforcement notification required
- Cyber insurance claim needed
- Third-party forensics required
- Breach notification laws triggered

### Documentation Standards

**Required Documentation:**
- Initial alert details and timestamp
- All investigative steps taken with timestamps
- SIEM queries executed and results
- IOCs identified
- Systems and accounts affected
- Actions taken (containment, eradication, recovery)
- Escalations and notifications
- Incident timeline
- Root cause analysis
- Lessons learned

**Ticket Template:**
```
Incident ID: INC-YYYY-XXXXX
Title: [Brief description]
Severity: [Critical/High/Medium/Low]
Status: [New/In Progress/Contained/Eradicated/Resolved/Closed]
Assigned To: [Analyst name]
Date Opened: [YYYY-MM-DD HH:MM UTC]
Date Closed: [YYYY-MM-DD HH:MM UTC]

ALERT DETAILS:
- Source: [SIEM/EDR/User Report]
- Alert Name: [Name]
- Alert Time: [YYYY-MM-DD HH:MM UTC]

AFFECTED ASSETS:
- Host(s): [List]
- User(s): [List]
- IP(s): [List]

SUMMARY:
[Brief description of incident]

INVESTIGATION FINDINGS:
[Key findings from investigation]

IOCS:
[List of indicators]

ACTIONS TAKEN:
[All response actions]

OUTCOME:
[Verdict and resolution]

LESSONS LEARNED:
[Improvements identified]
```

## Tools and Resources

**SIEM (Splunk):**
- Log correlation and analysis
- Timeline reconstruction
- Threat hunting
- Alert management

**EDR (Wazuh):**
- Endpoint telemetry
- Process monitoring
- File integrity monitoring
- Endpoint isolation

**Threat Intelligence:**
- VirusTotal - File and IP reputation
- AbuseIPDB - IP reputation
- URLScan.io - URL analysis
- Any.Run - Malware sandbox
- Hybrid-Analysis - File analysis

**Email Analysis:**
- Email header analysis tools
- SPF/DKIM/DMARC validators
- URL defanging tools

**Network Analysis:**
- Wireshark - Packet capture analysis
- tcpdump - Traffic capture
- Firewall logs
- DNS logs

**Forensics:**
- Event log analysis
- Registry analysis
- Memory forensics
- Disk forensics

## Training and Exercises

**Recommended Training:**
- Playbook walkthrough sessions
- Tabletop exercises for each scenario
- Red team/Blue team exercises
- Incident simulation drills

**Exercise Schedule:**
- Monthly tabletop exercise (rotate playbooks)
- Quarterly full simulation
- Annual comprehensive drill with management

**Continuous Improvement:**
- Post-incident reviews
- Playbook feedback from analysts
- Metrics analysis (MTTD, MTTR)
- Detection rule tuning

## Metrics and KPIs

**Response Metrics:**
- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- Mean Time to Contain (MTTC)
- Mean Time to Recover (MTTR-full)

**Quality Metrics:**
- True Positive Rate
- False Positive Rate
- Escalation Rate
- Playbook adherence rate

**Efficiency Metrics:**
- Average incident resolution time
- Playbook completion time
- Analyst utilization

## References

- **NIST SP 800-61 Rev. 2:** Computer Security Incident Handling Guide
- **SANS Incident Handler's Handbook:** https://www.sans.org/reading-room/whitepapers/incident/
- **MITRE ATT&CK Framework:** https://attack.mitre.org/
- **CISA Incident Response Resources:** https://www.cisa.gov/incident-response

## Playbook Navigation

- [Phishing Response Playbook](playbook-phishing-response.md)
- [Brute Force Response Playbook](playbook-brute-force-response.md)
- [Malware Response Playbook](playbook-malware-response.md)
- [Suspicious Network Activity Playbook](playbook-suspicious-network-activity.md)

---

*These playbooks are living documents and should be continuously updated based on lessons learned, new threats, and organizational changes.*
