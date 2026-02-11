# Ticketing System Integration - osTicket

## Introduction

Incident ticketing is a critical component of Security Operations Center (SOC) operations, providing structured case management from initial alert detection through resolution. This integration demonstrates a complete incident management workflow using **osTicket**, an open-source ticketing system, connected to the lab's Splunk SIEM for automated ticket creation and tracking.

In real-world SOC environments, every security alert, investigation, and incident requires proper documentation, tracking, assignment, escalation, and closure. A ticketing system serves as the single source of truth for incident handling, ensuring accountability, enabling metrics tracking, and maintaining compliance with service level agreements (SLAs).

## Why osTicket?

osTicket was chosen for this portfolio lab for several reasons:

- **Open Source & Free:** No licensing costs, perfect for home lab environments
- **Production-Grade Features:** Supports all core ITSM requirements including SLA management, escalation rules, custom fields, and API integration
- **API Support:** RESTful API enables automated ticket creation from SIEM alerts
- **Customizable:** Fully customizable fields, workflows, and departments to mirror enterprise SOC operations
- **Industry Relevant:** Demonstrates understanding of ticketing systems used in real SOC environments (ServiceNow, Jira Service Desk, osTicket)
- **ITSM Fundamentals:** Aligns with IT Service Management best practices and ServiceNow concepts

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         SOC Incident Management Flow                      │
└─────────────────────────────────────────────────────────────────────────┘

    ┌─────────────┐         ┌──────────────┐         ┌─────────────┐
    │   Splunk    │         │  osTicket    │         │ SOC Analyst │
    │    SIEM     │         │   Server     │         │   Triage    │
    └──────┬──────┘         └──────┬───────┘         └──────┬──────┘
           │                       │                        │
           │ 1. Alert Triggered    │                        │
           │    (Brute Force,      │                        │
           │     Malware, etc.)    │                        │
           │                       │                        │
           │ 2. Webhook/API Call   │                        │
           │───────────────────────>                        │
           │    Create Ticket      │                        │
           │                       │                        │
           │                       │ 3. Email Notification  │
           │                       │───────────────────────>│
           │                       │    New Ticket          │
           │                       │                        │
           │                       │ 4. Analyst Opens       │
           │                       │<───────────────────────│
           │                       │    Ticket & Triages    │
           │                       │                        │
           │ 5. Query SIEM         │                        │
           │<───────────────────────────────────────────────│
           │    for Evidence       │                        │
           │                       │                        │
           │ 6. Update Ticket      │                        │
           │                       │<───────────────────────│
           │    with Findings      │                        │
           │                       │                        │
           │                       │ 7. Escalate if needed  │
           │                       │    (Tier 2/3)          │
           │                       │                        │
           │                       │ 8. Document Response   │
           │                       │    Actions             │
           │                       │                        │
           │                       │ 9. Resolve & Close     │
           │                       │    Ticket              │
           │                       │                        │
           v                       v                        v
    
    ┌──────────────────────────────────────────────────────────────┐
    │  Metrics Dashboard: MTTA, MTTR, Ticket Volume, Resolution %  │
    └──────────────────────────────────────────────────────────────┘
```

**Integration Flow:**
1. **Detection:** Splunk detection rules trigger on suspicious activity
2. **Ticket Creation:** Automated ticket creation via osTicket API or email
3. **Assignment:** Ticket auto-assigned to SOC Tier 1 queue based on priority
4. **Triage:** Analyst investigates using SIEM queries and EDR tools
5. **Escalation:** Complex incidents escalated to Tier 2/Tier 3 analysts
6. **Documentation:** All findings, actions, and communications logged in ticket
7. **Resolution:** Incident resolved and ticket closed with root cause analysis
8. **Metrics:** Track MTTA (Mean Time to Acknowledge), MTTR (Mean Time to Resolve), and SLA compliance

## Prerequisites

Before implementing this integration, ensure you have:

### Lab Infrastructure
- **Ubuntu Server VM** (22.04 LTS recommended) for osTicket hosting
  - 2 vCPUs, 4GB RAM minimum
  - 20GB storage
  - Static IP address on lab network
- **Splunk SIEM** - Already configured and collecting logs
- **Active Directory** - For authentication and user data
- **Network connectivity** between Splunk and osTicket server

### Software Requirements
- **Web Server:** Apache2 or Nginx
- **Database:** MySQL 5.5+ or MariaDB
- **PHP:** 7.3 or higher with required extensions (mysqli, gd, imap, xml, mbstring)
- **osTicket:** Latest stable release (v1.18+)

### Knowledge Prerequisites
- Linux system administration (Ubuntu/Debian)
- Web server configuration (Apache/Nginx)
- MySQL database management
- Splunk alert configuration
- Basic Python scripting (for API integration)

## Quick Start Guide

### 1. Install osTicket
Follow the detailed setup guide: **[osTicket Setup Guide](osticket-setup.md)**

This covers:
- Ubuntu Server preparation
- LAMP stack installation
- osTicket download and configuration
- Database setup
- Initial admin configuration

### 2. Configure SOC Departments & Priorities
Set up organizational structure:
- **Departments:** SOC Team, Tier 1 Analysts, Tier 2 Analysts, Tier 3 Engineers
- **Priorities:** Low, Medium, High, Critical
- **Help Topics:** Security Alert, Brute Force, Malware, Phishing, Data Exfiltration, Suspicious Activity

### 3. Create Custom Fields for SOC Operations
Configure SOC-specific ticket fields:
- Affected System/Hostname
- Affected User
- MITRE ATT&CK Technique
- Indicators of Compromise (IOCs)
- Alert Source (Splunk, Wazuh, Manual)
- Investigation Status
- Incident Severity

### 4. Set Up Splunk Integration
Follow the integration guide: **[Splunk Integration Guide](splunk-integration.md)**

This covers:
- Configuring osTicket API keys
- Creating Splunk alert actions
- Python script for webhook-to-API ticket creation
- Testing automated ticket creation

### 5. Implement SOC Workflows
Review the workflow documentation: **[Workflow Guide](workflow-guide.md)**

This covers:
- Ticket lifecycle stages
- Tier 1/2/3 responsibilities
- SLA targets and escalation procedures
- Documentation requirements
- Best practices for ticket management

### 6. Review Sample Tickets
Examine real-world examples: **[Sample Tickets](sample-tickets/)**

Three detailed sample tickets demonstrate:
- **Ticket 001:** RDP Brute Force - Complete workflow from detection to resolution
- **Ticket 002:** Malware Execution - Tier 1 to Tier 2 escalation
- **Ticket 003:** Suspicious PowerShell - Automated ticket creation from Splunk alert

## Skills Demonstrated

This ticketing integration showcases critical SOC and IT Service Management skills:

### Incident Ticketing & Case Management
- Structured incident tracking from detection through resolution
- Proper ticket documentation with timeline, evidence, and actions taken
- Ticket prioritization based on severity and business impact
- Multi-tier escalation workflows

### IT Service Management (ITSM)
- Service desk operations aligned with ITIL/ITSM best practices
- SLA definition and tracking (MTTA: 15 minutes, MTTR: varies by severity)
- Incident categorization and prioritization matrix
- Stakeholder communication and status updates
- Change management coordination for remediation actions

### Security Operations Automation
- SIEM-to-ticketing system integration via API
- Automated ticket creation from security alerts
- Field mapping from alert data to ticket attributes
- Webhook configuration and testing
- Python scripting for API integration

### Process & Procedure Development
- Documented SOC workflows and standard operating procedures
- Escalation criteria and handoff procedures
- Quality assurance checks for ticket documentation
- Metrics and KPI tracking for continuous improvement

### Technical Documentation
- Comprehensive setup and configuration guides
- Architecture diagrams and data flow documentation
- Troubleshooting guides and FAQ
- Sample tickets demonstrating real-world scenarios

### Cross-Tool Integration
- Bridging SIEM (Splunk), ticketing (osTicket), and EDR (Wazuh) systems
- Unified incident response workflow across multiple tools
- Correlation of data from multiple sources in ticket context
- Single pane of glass for incident management

## Integration Benefits

### For SOC Operations
- **Accountability:** Every alert has an assigned owner and tracked status
- **Audit Trail:** Complete documentation of investigation steps and decisions
- **Metrics:** Track MTTA, MTTR, ticket volume, and analyst performance
- **Compliance:** Meet audit requirements for incident documentation
- **Knowledge Base:** Historical tickets serve as reference for future incidents

### For This Portfolio
- **Completeness:** Demonstrates end-to-end incident management workflow
- **Real-World Alignment:** Mirrors enterprise SOC operations
- **ITSM Knowledge:** Shows understanding of service desk operations
- **Automation Skills:** Demonstrates API integration and scripting
- **Professional Readiness:** Experience with ticketing systems required for SOC roles

## Documentation Structure

```
ticketing-integration/
├── README.md                              # This file - overview and introduction
├── osticket-setup.md                      # Installation and configuration guide
├── splunk-integration.md                  # Automated ticket creation from Splunk
├── workflow-guide.md                      # SOC ticket lifecycle and procedures
└── sample-tickets/
    ├── ticket-001-rdp-bruteforce.md       # Sample: RDP brute force incident
    ├── ticket-002-malware-execution.md    # Sample: Malware infection with escalation
    └── ticket-003-suspicious-powershell.md # Sample: Automated ticket from alert
```

## Real-World Alignment

This integration demonstrates understanding of enterprise SOC ticketing practices:

- **ServiceNow/Jira Concepts:** Departments, priorities, custom fields, SLAs, escalation rules
- **ITIL Framework:** Incident management, problem management, change management
- **SOC Workflows:** Triage → Investigation → Containment → Eradication → Recovery → Lessons Learned
- **Metrics & Reporting:** KPIs for SOC performance measurement
- **Integration Patterns:** SIEM-to-ITSM integration common in enterprise environments

## Next Steps

1. **Deploy osTicket:** Follow [osTicket Setup Guide](osticket-setup.md)
2. **Configure Integration:** Implement [Splunk Integration](splunk-integration.md)
3. **Test Workflow:** Use [Workflow Guide](workflow-guide.md) to process test tickets
4. **Review Examples:** Study [Sample Tickets](sample-tickets/) for best practices
5. **Generate Metrics:** Track MTTA, MTTR, and ticket volume over time
6. **Continuous Improvement:** Refine workflows based on metrics and lessons learned

## Related Documentation

- **[Lab Setup](../lab-setup/README.md)** - Lab infrastructure and tool deployment
- **[Detection Rules](../detection-rules/README.md)** - Splunk detection rules that trigger tickets
- **[Investigations](../investigations/README.md)** - Detailed incident investigations referenced in sample tickets
- **[Playbooks](../playbooks/README.md)** - Response procedures used during ticket resolution

---

*This integration demonstrates production-ready incident management practices suitable for enterprise SOC environments. All examples are based on real investigations conducted in this lab environment.*
