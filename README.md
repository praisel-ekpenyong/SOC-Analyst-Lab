# IT Support & SOC Analyst Lab Portfolio

## Introduction

I am an entry-level IT professional building hands-on experience through a home lab. This repository highlights practical skills across IT support (help desk, Active Directory, networking, PowerShell) and security operations (SIEM, incident response, threat detection, phishing analysis).

---

## 👔 Hiring Manager Quick Start

> **If you only have 5 minutes**, here is what to review first:

### IT Support Portfolio
| What to See | Link |
|---|---|
| **Skills Matrix** | [docs/skills-matrix.md](docs/skills-matrix.md) |
| **Resume Bullets** | [docs/resume-bullets.md](docs/resume-bullets.md) |
| **Sample Ticket (Account Lockout)** | [tickets/ticket-002.md](tickets/ticket-002.md) |
| **Incident Report (DNS Failure)** | [incidents/incident-002.md](incidents/incident-002.md) |
| **PowerShell Script** | [scripts/Get-DiskSpaceReport.ps1](scripts/Get-DiskSpaceReport.ps1) |
| **osTicket Lab** | [labs/lab-04-osticket/README.md](labs/lab-04-osticket/README.md) |

### SOC Analyst Portfolio
| What to See | Link |
|---|---|
| **Investigation** | [RDP Brute Force Investigation](investigations/investigation-001-brute-force-rdp.md) |
| **Detection Rule** | [Data Exfiltration Detection](detection-rules/data-exfiltration-detection.md) |
| **Phishing Report** | [Credential Harvesting Analysis](phishing-analysis/phishing-001-credential-harvesting.md) |

---

## 📋 Table of Contents

### IT Support Portfolio
1. [IT Support Labs](#it-support-labs)
2. [Sample Tickets](#sample-tickets)
3. [Simulated Incidents](#simulated-incidents)
4. [PowerShell Scripts](#powershell-scripts)
5. [Hiring Assets](#hiring-assets)

### SOC Analyst Portfolio
6. [Lab Environment Setup](#lab-environment-setup)
7. [Detection Rules](#detection-rules)
8. [Security Investigations](#security-investigations)
9. [Incident Response Playbooks](#incident-response-playbooks)
10. [Ticketing System Integration](#ticketing-system-integration)
11. [Phishing Analysis](#phishing-analysis)
12. [Tools & Technologies](#tools--technologies)
13. [Skills Demonstrated](#skills-demonstrated)
14. [Certifications](#certifications)
15. [Contact](#contact)

---

## 🖥️ IT Support Labs

Five hands-on labs covering core IT support skills:

| Lab | Topic | Key Skills |
|---|---|---|
| [Lab 01](labs/lab-01-active-directory/README.md) | Active Directory Basics | AD DS, DNS, GPO, file shares, domain join |
| [Lab 02](labs/lab-02-networking/README.md) | Networking Basics | IP addressing, subnetting, ping, nslookup, tracert |
| [Lab 03](labs/lab-03-windows-troubleshooting/README.md) | Windows Troubleshooting | Event Viewer, SFC, DISM, printers, remote support |
| [Lab 04](labs/lab-04-osticket/README.md) | osTicket Help Desk | LAMP, osTicket, SLA, tickets, canned responses |
| [Lab 05](labs/lab-05-powershell/README.md) | PowerShell Basics | Scripts, disk reports, event logs, password reset |

---

## 🎫 Sample Tickets

12 real-world IT support tickets with full troubleshooting documentation:

| Ticket | Issue | Lab Link |
|---|---|---|
| [Ticket-001](tickets/ticket-001.md) | Password Reset | Lab 01 |
| [Ticket-002](tickets/ticket-002.md) | Account Lockout | Lab 01 |
| [Ticket-003](tickets/ticket-003.md) | No Internet (DNS Forwarder) | Lab 02 |
| [Ticket-004](tickets/ticket-004.md) | DNS Domain Login Failure | Lab 02 |
| [Ticket-005](tickets/ticket-005.md) | Printer Driver Regression | Lab 03 |
| [Ticket-006](tickets/ticket-006.md) | Slow PC (Low Disk Space) | Lab 05 |
| [Ticket-007](tickets/ticket-007.md) | Software Install Request | Lab 01 |
| [Ticket-008](tickets/ticket-008.md) | Monitor Not Detected | Lab 03 |
| [Ticket-009](tickets/ticket-009.md) | VPN Access Onboarding | Lab 01 |
| [Ticket-010](tickets/ticket-010.md) | Mobile Email Not Syncing | Lab 01 |
| [Ticket-011](tickets/ticket-011.md) | Windows Update Failure | Lab 03 |
| [Ticket-012](tickets/ticket-012.md) | New User Onboarding | Lab 01 |

---

## 🚨 Simulated Incidents

4 incident writeups with root cause analysis, timelines, and customer communications:

| Incident | Theme | Severity |
|---|---|---|
| [Incident-001](incidents/incident-001.md) | Account Lockouts After GPO Change | SEV-C |
| [Incident-002](incidents/incident-002.md) | DNS Resolution Failure | SEV-B |
| [Incident-003](incidents/incident-003.md) | Printer Not Printing After Driver Update | SEV-C |
| [Incident-004](incidents/incident-004.md) | Slow PC Due to Low Disk Space | SEV-C |

---

## ⚙️ PowerShell Scripts

3 practical IT support scripts:

| Script | Purpose |
|---|---|
| [Get-DiskSpaceReport.ps1](scripts/Get-DiskSpaceReport.ps1) | Report free/used space on all local drives |
| [Export-EventLogs.ps1](scripts/Export-EventLogs.ps1) | Export System/Application event logs to CSV |
| [Reset-LocalPassword.ps1](scripts/Reset-LocalPassword.ps1) | Reset local account password (safe demo with warnings) |

---

## 📄 Hiring Assets

| Asset | Link |
|---|---|
| Skills Matrix | [docs/skills-matrix.md](docs/skills-matrix.md) |
| Resume Bullets | [docs/resume-bullets.md](docs/resume-bullets.md) |
| STAR Stories (4 behavioral interview answers) | [docs/star-stories.md](docs/star-stories.md) |
| Evidence Checklist | [docs/evidence-checklist.md](docs/evidence-checklist.md) |
| Templates | [templates/](templates/) |

---

## 🔐 SOC Analyst Portfolio

---

## 🏗️ Lab Environment Setup

Build and configuration documentation for the lab:

- [Lab Setup Overview](lab-setup/README.md)
- [Network Architecture Diagram](lab-setup/architecture-diagram.md)
- [Sysmon Setup](lab-setup/sysmon-setup.md)
- [Splunk SIEM Setup](lab-setup/splunk-setup.md)
- [Wazuh EDR Setup](lab-setup/wazuh-setup.md)
- [Active Directory Setup](lab-setup/active-directory-setup.md)

**Core lab components:**
- Windows Server 2019 (Domain Controller)
- Windows 10 endpoints
- Ubuntu Server (Splunk + Wazuh)
- Kali Linux (attack simulation)
- Internal network: `10.0.0.0/24`

## 🔍 Detection Rules

Custom Splunk detection content mapped to MITRE ATT&CK:

- [Detection Rules Overview](detection-rules/README.md)
- [Brute Force Detection](detection-rules/brute-force-detection.md)
- [PowerShell Abuse Detection](detection-rules/powershell-abuse-detection.md)
- [Lateral Movement Detection](detection-rules/lateral-movement-detection.md)
- [Persistence Detection](detection-rules/persistence-detection.md)
- [Credential Access Detection](detection-rules/credential-access-detection.md)
- [Data Exfiltration Detection](detection-rules/data-exfiltration-detection.md)

## 📊 Security Investigations

End-to-end investigations showing triage and response workflow:

- [Investigations Overview](investigations/README.md)
- [Investigation 001: RDP Brute Force Attack](investigations/investigation-001-brute-force-rdp.md)
- [Investigation 002: Malware Execution via Macro](investigations/investigation-002-malware-execution.md)
- [Investigation 003: Lateral Movement with PsExec](investigations/investigation-003-lateral-movement-psexec.md)
- [Investigation 004: Suspicious PowerShell Activity](investigations/investigation-004-suspicious-powershell.md)
- [Investigation 005: Data Exfiltration](investigations/investigation-005-data-exfiltration.md)

Each investigation includes timeline, SIEM queries, IOCs, MITRE ATT&CK mapping, and response recommendations.

## 📋 Incident Response Playbooks

Tier 1 SOC response procedures for common scenarios:

- [Playbooks Overview](playbooks/README.md)
- [Phishing Response Playbook](playbooks/playbook-phishing-response.md)
- [Brute Force Response Playbook](playbooks/playbook-brute-force-response.md)
- [Malware Response Playbook](playbooks/playbook-malware-response.md)

## 🎫 Ticketing System Integration

osTicket integration for incident lifecycle management:

- [Ticketing Integration Overview](ticketing-integration/README.md)
- [osTicket Setup Guide](ticketing-integration/osticket-setup.md)
- [Splunk Integration](ticketing-integration/splunk-integration.md)
- [Workflow Guide](ticketing-integration/workflow-guide.md)
- [Sample Tickets](ticketing-integration/sample-tickets/)

## 📧 Phishing Analysis

Practical analysis reports for common phishing techniques:

- [Phishing Analysis Overview](phishing-analysis/README.md)
- [Phishing 001: Credential Harvesting](phishing-analysis/phishing-001-credential-harvesting.md)
- [Phishing 002: Malicious Attachment](phishing-analysis/phishing-002-malicious-attachment.md)
- [Phishing 003: Business Email Compromise](phishing-analysis/phishing-003-business-email-compromise.md)

## 🛠️ Tools & Technologies

**Infrastructure**
- VirtualBox
- Windows Server 2019
- Windows 10 Pro
- Ubuntu Server 22.04
- Kali Linux

**Security stack**
- Splunk Free (SIEM)
- Wazuh (EDR)
- osTicket (ticketing)
- Sysmon (endpoint logging)
- Atomic Red Team (attack simulation)
- Wireshark (network analysis)

## 💡 Skills Demonstrated

- SIEM operations and SPL query development
- Log analysis and telemetry correlation
- Incident triage, investigation, and containment
- SOC playbook and workflow design
- Ticketing and SLA-based case management
- MITRE ATT&CK mapping
- IOC extraction and threat intelligence enrichment
- Phishing and malware analysis
- Endpoint and network security monitoring
- Technical documentation and reporting

## 🎓 Certifications

- CompTIA Security+
- Splunk Core Certified User
- Google Cybersecurity Certificate
- Azure Fundamentals (AZ-900)
- ServiceNow Certified System Administrator (in progress)

## 📫 Contact

- **LinkedIn:** [linkedin.com/in/praiselekpenyong](https://linkedin.com/in/praiselekpenyong)
- **Email:** ekpenyongpraisel@gmail.com
- **GitHub:** [github.com/praisel-ekpenyong](https://github.com/praisel-ekpenyong)

---

*This portfolio is actively maintained as new lab scenarios are completed. All indicators of compromise (IOCs) are simulated and defanged for educational use.*
