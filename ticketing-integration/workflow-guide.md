# SOC Ticket Workflow Guide

## Introduction

This guide defines the complete SOC ticket lifecycle, from initial alert creation through final resolution and closure. It establishes clear procedures for triage, investigation, escalation, documentation, and closure, ensuring consistent incident handling across all security alerts.

Following a structured workflow is critical for SOC operations, enabling:
- **Accountability:** Clear ownership at each stage
- **Consistency:** Standardized response to similar incidents
- **Metrics:** Measurable performance (MTTA, MTTR)
- **Compliance:** Audit trail for regulatory requirements
- **Continuous Improvement:** Lessons learned from historical tickets

## Ticket Lifecycle Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Ticket Lifecycle Stages                       │
└─────────────────────────────────────────────────────────────────┘

    ┌──────────┐
    │   NEW    │ ◄─── Alert created (Splunk, Manual, User Report)
    └────┬─────┘
         │
         │ Analyst Claims Ticket
         │ Status: Open
         v
    ┌──────────┐
    │   OPEN   │ ◄─── Assigned to analyst for triage
    └────┬─────┘      SLA Timer Starts
         │
         │ Initial Triage Complete
         │ Investigation Status: Investigating
         v
    ┌─────────────┐
    │ INVESTIGATING│ ◄─── Active analysis and evidence gathering
    └────┬─────────┘      Queries, log analysis, IOC research
         │
         ├──────────────────┐
         │                  │
         │                  │ Escalation Required?
         │                  │ Yes → Transfer to Tier 2/3
         │                  │
         v                  v
    ┌──────────┐      ┌──────────┐
    │CONTAINMENT│      │ ESCALATED│
    └────┬─────┘      └────┬─────┘
         │                  │
         │ Threat          │ Higher tier
         │ Contained       │ investigates
         │                 │
         v                 v
    ┌─────────────┐   ┌─────────────┐
    │ ERADICATION │   │   RESOLVED  │
    └────┬────────┘   └─────┬───────┘
         │                  │
         │ Threat          │ Issue fixed
         │ Removed         │ or FP confirmed
         │                 │
         v                 v
    ┌──────────┐      ┌──────────┐
    │ RECOVERY │      │  CLOSED  │
    └────┬─────┘      └──────────┘
         │
         │ Systems
         │ Restored
         │
         v
    ┌──────────┐
    │  CLOSED  │ ◄─── Final state, incident resolved
    └──────────┘      Documentation complete
                      Lessons learned captured
```

## Ticket Status Definitions

### Status 1: New
- **Description:** Ticket just created, not yet reviewed by any analyst
- **Duration:** Should be minimal (<5 minutes during business hours)
- **Next Action:** Analyst claims ticket and moves to "Open"
- **Owner:** Unassigned (in queue)

### Status 2: Open
- **Description:** Ticket assigned to analyst, initial triage in progress
- **Duration:** 5-30 minutes (varies by priority)
- **Next Action:** Complete initial triage, move to "Investigating" or "Closed" (if false positive)
- **Owner:** Assigned analyst

### Status 3: Investigating
- **Description:** Active investigation, gathering evidence, analyzing logs
- **Duration:** 30 minutes to several hours (priority-dependent)
- **Next Action:** Determine scope and impact, escalate if needed, or move to containment
- **Owner:** Assigned analyst or escalated team

### Status 4: Containment
- **Description:** Threat confirmed, containment actions being executed
- **Duration:** Immediate to 1 hour
- **Actions:** 
  - Isolate affected systems
  - Block malicious IPs/domains
  - Disable compromised accounts
  - Prevent lateral movement
- **Owner:** Tier 2/3 analyst or incident responder

### Status 5: Eradication
- **Description:** Removing threat from environment
- **Duration:** 1-4 hours
- **Actions:**
  - Remove malware
  - Delete rogue accounts
  - Patch vulnerabilities
  - Reset compromised credentials
- **Owner:** Tier 2/3 analyst with system administrator support

### Status 6: Recovery
- **Description:** Restoring normal operations
- **Duration:** Varies (1 hour to days for major incidents)
- **Actions:**
  - Restore systems from backup
  - Verify system integrity
  - Monitor for reinfection
  - Return to production
- **Owner:** System administrators with SOC monitoring

### Status 7: Resolved
- **Description:** Incident fully resolved, awaiting final validation
- **Duration:** 24 hours (monitoring period)
- **Next Action:** If no recurrence, close ticket
- **Owner:** Original analyst

### Status 8: Closed
- **Description:** Ticket complete, all actions documented
- **Final Actions:**
  - Root cause analysis documented
  - Lessons learned captured
  - Metrics recorded
  - Detection rules updated if needed
- **Owner:** Closed by original analyst or supervisor

## SLA Targets

### Mean Time to Acknowledge (MTTA)

Time from ticket creation to analyst acknowledgment:

| Priority | MTTA Target | Alert Type | Business Hours | After Hours |
|----------|-------------|------------|----------------|-------------|
| **Critical** | 15 minutes | Active breach, ransomware, data exfiltration | 15 minutes | 15 minutes |
| **High** | 30 minutes | Confirmed malware, successful intrusion | 30 minutes | 1 hour |
| **Medium** | 1 hour | Suspicious activity, policy violations | 1 hour | 4 hours |
| **Low** | 4 hours | Informational, potential false positives | 4 hours | Next business day |

**SLA Monitoring:**
- Tickets exceeding MTTA automatically escalate to supervisor
- Dashboard displays overdue tickets with color coding
- Analysts receive email notifications at 75% of MTTA threshold

### Mean Time to Resolve (MTTR)

Time from ticket creation to full resolution:

| Priority | MTTR Target | Notes |
|----------|-------------|-------|
| **Critical** | 4 hours | May extend to 24 hours for complex incidents |
| **High** | 8 hours | Escalation to Tier 2/3 typically required |
| **Medium** | 24 hours | Standard investigation and remediation |
| **Low** | 72 hours | Lower priority, batch processed |

**MTTR Factors:**
- Incident complexity
- Availability of affected systems
- Need for external vendor support
- Change management approval requirements

## Tier 1 Analyst Responsibilities

### Role Overview
Tier 1 analysts serve as the front line of SOC operations, handling initial triage of all security alerts and resolving straightforward incidents.

### Primary Responsibilities

#### 1. Ticket Triage (First 15 minutes)
**Objective:** Determine if alert is true positive, false positive, or requires escalation

**Steps:**
1. **Claim Ticket**
   - Click "Claim" on new ticket
   - Update status to "Open"
   - Add internal note: "Triage in progress - [Your Name]"

2. **Review Alert Details**
   - Read Splunk alert description
   - Note affected system, user, and IOCs
   - Check MITRE ATT&CK classification

3. **Verify Alert in SIEM**
   - Open Splunk alert link from ticket
   - Review raw events and event timeline
   - Check for additional related events

4. **Initial Assessment**
   ```
   Questions to answer:
   - Is this a true positive or false positive?
   - What systems/users are affected?
   - Is the activity still ongoing?
   - What is the potential business impact?
   - Can I resolve this, or does it need escalation?
   ```

5. **Document Initial Findings**
   ```
   Internal Note Template:
   === INITIAL TRIAGE ===
   True Positive: [Yes/No/Unknown]
   Activity Status: [Ongoing/Stopped/Historical]
   Affected Systems: [List]
   Affected Users: [List]
   Preliminary Assessment: [1-2 sentences]
   Recommended Action: [Investigate further / Escalate / Close as FP]
   ```

#### 2. Investigation (If Not Escalating)
**Objective:** Gather evidence and determine scope

**Standard Investigation Steps:**

**A. SIEM Queries**
```spl
# Query 1: Check for additional activity from same source
index=* (src_ip="<IOC>" OR src="<IOC>") earliest=-24h
| stats count by index, sourcetype, dest, action
| sort -count

# Query 2: Check for activity on affected user account
index=* (user="<username>" OR Account_Name="<username>") earliest=-24h
| table _time, index, ComputerName, EventCode, Activity
| sort -_time

# Query 3: Check for lateral movement indicators
index=windows_security EventCode=4624 Logon_Type=3 Account_Name="<username>"
| stats count by src_ip, ComputerName
| where count > 1
```

**B. EDR Investigation**
- Open Wazuh dashboard for affected endpoint
- Check recent alerts and processes
- Review file integrity monitoring events
- Check for suspicious network connections

**C. Threat Intelligence Enrichment**
- Check IOCs in VirusTotal
- Check IPs in AbuseIPDB
- Check domains in URLScan.io
- Review MITRE ATT&CK technique details

**D. Timeline Construction**
```
Document in ticket:
- First observed activity
- Sequence of events
- Last observed activity
- Related events discovered
```

#### 3. Documentation Requirements

**Required Updates Every 30 Minutes:**
```
Status Update Template:
Time: [HH:MM]
Status: [Investigating]
Progress:
- [Action taken]
- [Findings discovered]
- [Next steps planned]
ETA: [Estimated completion time]
```

**Minimum Documentation:**
- Initial triage findings
- SIEM queries executed
- EDR checks performed
- IOC enrichment results
- Timeline of events
- Scope determination (systems/users affected)
- Actions taken
- Final resolution or escalation reason

#### 4. Containment Actions (If Authorized)

Tier 1 analysts can perform these containment actions WITHOUT escalation:

**Approved Tier 1 Containment:**
- ✅ Block single malicious IP at firewall (via ticket to network team)
- ✅ Disable single user account (temporary, pending Tier 2 review)
- ✅ Submit malware to antivirus quarantine
- ✅ Isolate single workstation from network
- ✅ Reset user password

**Requires Escalation:**
- ❌ Disable service accounts
- ❌ Isolate servers or critical systems
- ❌ Block entire IP ranges or domains
- ❌ Modify firewall rules beyond single IP
- ❌ Any action affecting multiple systems
- ❌ System reimaging or data recovery

#### 5. False Positive Handling

**Process for False Positives:**

1. **Verify it's truly a false positive**
   - Check with senior analyst if uncertain
   - Document why it's a false positive

2. **Document Root Cause**
   ```
   False Positive Analysis:
   - Why did the alert trigger? [Explain detection logic]
   - Why is this benign activity? [Explain business justification]
   - Recommended Fix: [Detection rule tuning suggestion]
   - Prevent Future FPs: [Whitelist entry, threshold adjustment, etc.]
   ```

3. **Submit Detection Rule Feedback**
   - Create internal ticket for detection engineering team
   - Provide details for rule tuning
   - Include sample events

4. **Close Ticket**
   - Set status: Closed
   - Set resolution: False Positive
   - Include full documentation in final note

### Escalation Criteria

**Escalate to Tier 2 when:**
- Confirmed malware infection
- Suspected data breach or exfiltration
- Lateral movement detected
- Privilege escalation identified
- Multiple systems affected
- Advanced persistent threat (APT) indicators
- Incident requires containment beyond Tier 1 authority
- Investigation time exceeds 2 hours without resolution
- Uncertainty about incident severity
- Business-critical system affected

**Escalation Process:**
1. Add internal note: "=== ESCALATING TO TIER 2 ==="
2. Document reason for escalation
3. Summarize all findings to date
4. List all evidence collected
5. Transfer ticket to "Tier 2 Analysts" department
6. Update Investigation Status: "Escalated - Tier 2 Review Required"
7. Notify Tier 2 on-call via phone/Slack for critical incidents

## Tier 2 Analyst Responsibilities

### Role Overview
Tier 2 analysts handle escalated incidents, perform deep-dive investigations, coordinate containment and remediation, and provide guidance to Tier 1.

### Key Responsibilities

#### 1. Escalated Ticket Review
- Review all Tier 1 documentation
- Validate Tier 1 findings
- Determine incident severity and scope
- Develop investigation and response plan

#### 2. Advanced Investigation
- Perform memory forensics if needed
- Conduct malware analysis
- Deep-dive log analysis across multiple systems
- Threat hunting for related activity
- Coordinate with threat intelligence team

#### 3. Incident Response Leadership
- Lead containment efforts
- Coordinate with system administrators
- Approve high-impact containment actions
- Manage stakeholder communication
- Document detailed incident timeline

#### 4. Remediation Oversight
- Develop remediation plan
- Verify threat eradication
- Oversee system recovery
- Conduct post-incident validation

#### 5. Closure and Lessons Learned
- Complete root cause analysis
- Document lessons learned
- Recommend detection rule improvements
- Update playbooks based on findings

## Tier 3 Responsibilities

### Role Overview
Tier 3 engineers handle the most complex incidents, perform threat hunting, develop detection content, and provide architectural guidance.

### Key Areas
- Advanced malware reverse engineering
- Threat hunting campaigns
- Detection engineering
- SOC process improvement
- Vendor coordination for critical incidents
- Post-incident forensics

## Ticket Prioritization Matrix

### Priority Assignment Logic

| Finding | Impact | Priority | Response |
|---------|--------|----------|----------|
| Active data exfiltration | Confidential data | **Critical** | Immediate containment |
| Domain admin compromise | Full domain control | **Critical** | Immediate isolation |
| Ransomware execution | Business operations | **Critical** | Emergency response |
| Confirmed malware | Single workstation | **High** | 30-min response |
| Successful brute force | Standard user account | **High** | 30-min response |
| Lateral movement | Multiple systems | **High** | Immediate escalation |
| Suspicious PowerShell | Potential compromise | **Medium** | 1-hour response |
| Policy violation | Security baseline | **Medium** | Standard investigation |
| Single failed attack | No successful compromise | **Low** | Monitor and document |
| Informational alert | Context for awareness | **Low** | Review and close |

### Dynamic Priority Adjustment

Priorities can be escalated based on:
- **Business Impact:** Affecting critical systems or VIPs
- **Data Sensitivity:** Involving regulated or confidential data
- **Attack Progression:** Indicators of advanced or targeted attack
- **Compliance Requirements:** Regulatory reporting obligations
- **Public Relations:** Potential for public disclosure or reputational damage

## Communication Guidelines

### Internal Communication (Within Ticket)

**Internal Notes (Analysts Only):**
- Use for investigation details
- Document evidence and findings
- Coordinate between analysts
- Record technical details

**Format:**
```
[YYYY-MM-DD HH:MM] - [Analyst Name]
=== [Activity Description] ===

[Detailed notes, queries, findings]

Next Steps:
- [Action item 1]
- [Action item 2]
```

### External Communication (To Users/Stakeholders)

**User Notification Template (when user is affected):**
```
Subject: Security Incident Notification - Ticket #[NUMBER]

Dear [User Name],

Our Security Operations Center has detected [brief description of incident] 
involving your user account or workstation.

Current Status: [Investigating / Contained / Resolved]

Actions Taken:
- [List actions]

Required Actions from You:
- [List any user actions needed]

Impact to You:
- [Describe user impact]

Timeline:
- We expect to have this resolved by [timeframe]

If you have any questions or concerns, please reply to this ticket.

Thank you for your cooperation.

SOC Team
Ticket #[NUMBER]
```

### Management Escalation

**Criteria for Management Notification:**
- Critical severity incidents
- Confirmed data breach
- Potential regulatory reporting requirement
- Extended outage of business-critical systems
- High-profile user affected (C-level)
- Incident likely to reach media

**Management Summary Template:**
```
EXECUTIVE SUMMARY - SECURITY INCIDENT

Incident: [One-line description]
Severity: [Critical/High/Medium/Low]
Status: [Investigating/Contained/Resolved]

Impact:
- Systems Affected: [Count and description]
- Users Affected: [Count]
- Business Operations: [Impact description]
- Data Exposure: [Yes/No/Unknown - details]

Timeline:
- Detection: [Time]
- Containment: [Time or "In Progress"]
- Estimated Resolution: [Timeframe]

Actions Taken:
- [Key action 1]
- [Key action 2]
- [Key action 3]

Next Steps:
- [Next action 1]
- [Next action 2]

SOC Lead: [Name]
Ticket: [Number]
```

## Best Practices for Ticket Management

### 1. Documentation Quality

**Good Documentation Includes:**
- ✅ Clear, concise writing
- ✅ Timestamps for all actions
- ✅ Specific details (IP addresses, hostnames, usernames)
- ✅ SIEM queries used (with results summary)
- ✅ Analyst reasoning and decision-making process
- ✅ Evidence screenshots or log excerpts
- ✅ Complete IOC list

**Poor Documentation:**
- ❌ Vague descriptions ("Checked logs, looks fine")
- ❌ Missing timestamps
- ❌ No queries or evidence provided
- ❌ Conclusions without supporting evidence
- ❌ Incomplete timeline

### 2. Ticket Hygiene

**Daily Ticket Review:**
- Review all open tickets at start of shift
- Update stale tickets (no activity >4 hours)
- Close resolved tickets waiting for closure
- Escalate overdue tickets
- Prioritize tickets approaching SLA breach

**Before End of Shift:**
- Add handoff note to any ongoing investigations
- Update status on all tickets touched during shift
- Document next steps for incoming shift
- Escalate anything requiring urgent attention

### 3. Quality Assurance

**Supervisor Review:**
- Random sampling of closed tickets
- Review of all critical/high priority tickets
- Feedback to analysts on documentation quality
- Identification of training needs

**Metrics Tracking:**
- MTTA by analyst and priority
- MTTR by analyst and priority
- False positive rate
- Escalation rate
- Reopened ticket rate
- Customer satisfaction (if applicable)

## SOC Metrics and KPIs

### Primary Metrics

#### Mean Time to Acknowledge (MTTA)
```
MTTA = Total time from ticket creation to first analyst action
       / Number of tickets

Target MTTA by Priority:
- Critical: 15 minutes
- High: 30 minutes
- Medium: 1 hour
- Low: 4 hours
```

#### Mean Time to Resolve (MTTR)
```
MTTR = Total time from ticket creation to closure
       / Number of tickets

Target MTTR by Priority:
- Critical: 4 hours
- High: 8 hours
- Medium: 24 hours
- Low: 72 hours
```

#### True Positive Rate
```
TP Rate = (True Positives / Total Tickets) × 100%

Target: >60% (indicates good detection rule quality)
<40% suggests excessive false positives requiring tuning
```

#### Escalation Rate
```
Escalation Rate = (Tickets escalated to Tier 2 / Total Tickets) × 100%

Target: 20-30% (indicates appropriate Tier 1 capability)
>50% suggests Tier 1 needs more training or authority
<10% suggests Tier 1 may be handling issues they shouldn't
```

### Secondary Metrics

- **Tickets Per Analyst Per Day:** Workload distribution
- **After-Hours Response Rate:** Off-hours coverage effectiveness
- **Reopened Ticket Rate:** Quality of initial resolution
- **Customer Satisfaction Score:** User feedback on ticket handling
- **SLA Compliance Rate:** Percentage of tickets meeting SLA

### Dashboard Widgets

**Recommended osTicket Dashboard:**
- Open tickets by priority (pie chart)
- Tickets aging report (overdue in red)
- MTTA by priority (bar chart)
- MTTR by priority (bar chart)
- Tickets by help topic (bar chart)
- Top analysts by ticket volume (leaderboard)
- SLA compliance meter (percentage gauge)
- Trend: Tickets created per day (line chart - last 30 days)

## Continuous Improvement

### Weekly SOC Meeting
- Review metrics and trends
- Discuss challenging tickets
- Share lessons learned
- Identify detection rule gaps
- Review false positives for tuning opportunities

### Monthly Process Review
- Analyze MTTA/MTTR trends
- Review escalation patterns
- Identify training needs
- Update playbooks based on new threat patterns
- Assess tool effectiveness

### Quarterly Assessments
- Comprehensive metrics review
- Analyst performance evaluations
- SOC capability assessment
- Technology stack evaluation
- Budget and resource planning

## Integration with Existing Processes

### Playbook Integration
Every ticket should reference appropriate playbook:
- [Brute Force Response Playbook](../playbooks/playbook-brute-force-response.md)
- [Malware Response Playbook](../playbooks/playbook-malware-response.md)
- [Phishing Response Playbook](../playbooks/playbook-phishing-response.md)
- [Suspicious Network Activity Playbook](../playbooks/playbook-suspicious-network-activity.md)

**In Ticket:**
```
Investigation Approach: Following Brute Force Response Playbook
Link: [playbook-brute-force-response.md](../playbooks/playbook-brute-force-response.md)
```

### Investigation Documentation
For significant incidents, create detailed investigation document:
- Link ticket to investigation document
- Reference ticket number in investigation
- Investigation provides deep-dive details
- Ticket provides operational tracking

**Example:**
```
Ticket #12345 → Investigation 008: Advanced Persistent Threat
Investigation document: /investigations/investigation-008-apt-campaign.md
```

### Detection Rule Feedback Loop
- Document detection rule effectiveness in tickets
- Flag false positives for rule tuning
- Suggest new detection opportunities
- Track detection gaps discovered during investigations

## Appendix: Ticket Templates

### Template A: Initial Triage Note
```
=== INITIAL TRIAGE ===
Analyst: [Your Name]
Time: [YYYY-MM-DD HH:MM UTC]

Alert Review:
- True Positive / False Positive / Unknown
- Severity Assessment: [Critical/High/Medium/Low]
- Activity Status: [Ongoing/Stopped/Historical]

Affected Assets:
- Systems: [List]
- Users: [List]
- Data: [Describe if applicable]

Preliminary Findings:
[1-2 paragraph summary of what you've found so far]

Recommended Action:
[Continue investigation / Escalate / Close as FP]

Next Steps:
- [Specific action 1]
- [Specific action 2]
```

### Template B: Investigation Update
```
=== INVESTIGATION UPDATE ===
Time: [YYYY-MM-DD HH:MM UTC]
Status: Investigating

Actions Completed:
- [Action 1 with outcome]
- [Action 2 with outcome]

Key Findings:
- [Finding 1]
- [Finding 2]

Evidence Collected:
- SIEM Query Results: [Summary]
- EDR Investigation: [Summary]
- Threat Intelligence: [Summary]

Current Assessment:
[Updated understanding of incident]

Next Steps:
- [Next action 1]
- [Next action 2]

ETA for Update: [Timeframe]
```

### Template C: Escalation Note
```
=== ESCALATING TO TIER 2 ===
Analyst: [Your Name]
Time: [YYYY-MM-DD HH:MM UTC]

Escalation Reason:
[Why this requires Tier 2 involvement]

Summary of Investigation:
[Comprehensive summary of all findings to date]

Evidence Package:
- SIEM Queries: [List with links]
- EDR Data: [Summary]
- IOCs Identified: [List]
- Timeline: [Key events]

Containment Status:
[What containment actions have been taken]

Recommended Next Steps:
- [Suggestion 1]
- [Suggestion 2]

Urgency: [Immediate/High/Standard]
```

### Template D: Closure Note
```
=== INCIDENT CLOSURE ===
Analyst: [Your Name]
Time: [YYYY-MM-DD HH:MM UTC]

Resolution: [Resolved - True Positive / Closed - False Positive / Resolved - Escalated]

Root Cause:
[Explanation of what caused the alert and why]

Actions Taken:
- [Action 1]
- [Action 2]
- [Action 3]

Systems/Users Affected:
[Final list with impact assessment]

IOCs Documented:
[Complete list of indicators]

Preventive Measures:
[What was done to prevent recurrence]

Lessons Learned:
[What we learned from this incident]

Detection Rule Feedback:
[Suggestions for rule improvements or new detections]

Time to Resolution: [X hours Y minutes]
```

## Related Documentation

- **[osTicket Setup Guide](osticket-setup.md)** - Installation and configuration
- **[Splunk Integration](splunk-integration.md)** - Automated ticket creation
- **[Sample Tickets](sample-tickets/)** - Real-world examples
- **[Incident Response Playbooks](../playbooks/README.md)** - Response procedures
- **[Investigations](../investigations/README.md)** - Detailed incident documentation

---

*This workflow guide establishes professional SOC operational procedures aligned with industry best practices and ITIL service management frameworks. Following these procedures ensures consistent, high-quality incident response.*
