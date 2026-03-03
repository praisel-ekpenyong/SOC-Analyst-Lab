# SOC Analyst Lab Portfolio

## Introduction

I am an entry-level SOC Analyst building hands-on experience through a home lab. This repository highlights practical skills in security monitoring, incident response, threat detection, and phishing analysis.

## 🚀 Start Here (Quick Review)

If you only have a few minutes, start with these:

- **Investigation:** [RDP Brute Force Investigation](investigations/investigation-001-brute-force-rdp.md)
- **Detection Rule:** [Data Exfiltration Detection](detection-rules/data-exfiltration-detection.md)
- **Phishing Report:** [Credential Harvesting Analysis](phishing-analysis/phishing-001-credential-harvesting.md)
- **Sample Ticket:** [RDP Brute Force Ticket](ticketing-integration/sample-tickets/ticket-001-rdp-bruteforce.md)

## 📋 Table of Contents

1. [Lab Environment Setup](#lab-environment-setup)
2. [Detection Rules](#detection-rules)
3. [Security Investigations](#security-investigations)
4. [Incident Response Playbooks](#incident-response-playbooks)
5. [Ticketing System Integration](#ticketing-system-integration)
6. [Phishing Analysis](#phishing-analysis)
7. [🤖 AI Projects](#-ai-projects)
8. [Tools & Technologies](#tools--technologies)
9. [Skills Demonstrated](#skills-demonstrated)
10. [Certifications](#certifications)
11. [Contact](#contact)

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

## 🤖 AI Projects

Practical AI and ML implementations demonstrating modern SOC workflows:

- [AI Projects Overview](AI-Projects/README.md)
- **[01 — LLM-Powered Alert Triage Assistant](AI-Projects/01-AI-Alert-Triage/)**: Uses OpenAI API or local ollama to classify SIEM alerts as True/False Positive, generate analyst summaries, and recommend next actions.
- **[02 — ML-Based Log Anomaly Detection](AI-Projects/02-Log-Anomaly-Detection/)**: Applies Isolation Forest (scikit-learn) to Windows Event Log data to surface anomalous entries without labelled training data.
- **[03 — GenAI Incident Report Generator](AI-Projects/03-Incident-Report-Generator/)**: Takes structured incident JSON and generates a professional Markdown incident report — including Executive Summary, Timeline, IOCs, Root Cause, and Remediation — in under 60 seconds.
- **[04 — AI-Generated SOAR Playbook Builder](AI-Projects/04-SOAR-Playbook-Automation/)**: Generates complete, MITRE-aligned SOAR playbooks (Detection → Containment → Eradication → Recovery) for any alert type on demand.

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

**AI / ML**
- Python 3 (scripting)
- OpenAI API (GPT-4o-mini / GPT-4o)
- ollama + llama3 (local LLM, free alternative)
- scikit-learn (Isolation Forest anomaly detection)
- pandas / numpy (data processing)

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
- AI-assisted alert triage (LLM / OpenAI API)
- ML-based anomaly detection (Isolation Forest / scikit-learn)
- GenAI incident report generation
- AI-generated SOAR playbook automation

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
