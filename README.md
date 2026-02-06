# SOC Analyst Lab Portfolio

## Introduction

I am an entry-level SOC Analyst building hands-on experience through a comprehensive home lab environment. This repository showcases my practical skills in security monitoring, incident response, threat detection, and analysis—core competencies required for modern Security Operations Center roles.

This portfolio demonstrates my ability to deploy, configure, and operate industry-standard security tools, develop detection rules mapped to the MITRE ATT&CK framework, conduct thorough security investigations, and analyze phishing campaigns.

## 📋 Table of Contents

1. [Lab Environment Setup](#lab-environment-setup)
2. [Detection Rules](#detection-rules)
3. [Security Investigations](#security-investigations)
4. [Phishing Analysis](#phishing-analysis)
5. [Tools & Technologies](#tools--technologies)
6. [Skills Demonstrated](#skills-demonstrated)
7. [Certifications](#certifications)
8. [Contact](#contact)

## 🏗️ Lab Environment Setup

Complete documentation of my virtualized SOC lab infrastructure:

- **[Lab Architecture Overview](lab-setup/README.md)** - Prerequisites, hardware requirements, build order
- **[Network Architecture Diagram](lab-setup/architecture-diagram.md)** - Visual representation of all systems and network topology
- **[Sysmon Configuration](lab-setup/sysmon-setup.md)** - Advanced Windows logging with SwiftOnSecurity config
- **[Splunk SIEM Setup](lab-setup/splunk-setup.md)** - Free Splunk deployment, data ingestion, and index configuration
- **[Wazuh EDR Setup](lab-setup/wazuh-setup.md)** - Open-source endpoint detection and response platform
- **[Active Directory Configuration](lab-setup/active-directory-setup.md)** - Enterprise domain environment with realistic OU structure

**Lab Components:**
- Windows Server 2019 (Active Directory Domain Controller)
- Windows 10 Workstations (with Sysmon, Splunk UF, Wazuh Agent)
- Ubuntu Server (Splunk Free, Wazuh Manager)
- Kali Linux (Simulated attacker for testing)
- Internal Network: 10.0.0.0/24

## 🔍 Detection Rules

Collection of custom detection rules developed using Splunk SPL, each mapped to MITRE ATT&CK techniques:

- **[Detection Rules Overview](detection-rules/README.md)** - Complete catalog of all detection rules
- **[Brute Force Detection](detection-rules/brute-force-detection.md)** - Failed login attempts, account lockouts
- **[PowerShell Abuse Detection](detection-rules/powershell-abuse-detection.md)** - Encoded commands, download cradles, suspicious parent-child relationships
- **[Lateral Movement Detection](detection-rules/lateral-movement-detection.md)** - PsExec, RDP abuse, Pass-the-Hash
- **[Persistence Detection](detection-rules/persistence-detection.md)** - Scheduled tasks, registry run keys, new services
- **[Credential Access Detection](detection-rules/credential-access-detection.md)** - LSASS dumping, SAM database access
- **[Data Exfiltration Detection](detection-rules/data-exfiltration-detection.md)** - Unusual outbound traffic, DNS tunneling

All detection rules were tested using **Atomic Red Team** to ensure accuracy and validate true positive alerts.

## 📊 Security Investigations

End-to-end incident response investigations demonstrating my analytical process:

- **[Investigation Overview](investigations/README.md)** - Summary of all investigations
- **[Investigation 001: RDP Brute Force Attack](investigations/investigation-001-brute-force-rdp.md)** - External threat actor successfully compromised domain controller via brute force
- **[Investigation 002: Malware Execution via Macro](investigations/investigation-002-malware-execution.md)** - User opened malicious Excel file resulting in C2 beacon
- **[Investigation 003: Lateral Movement with PsExec](investigations/investigation-003-lateral-movement-psexec.md)** - Compromised admin account used for lateral movement
- **[Investigation 004: Suspicious PowerShell Activity](investigations/investigation-004-suspicious-powershell.md)** - Encoded PowerShell performing AD reconnaissance
- **[Investigation 005: Data Exfiltration](investigations/investigation-005-data-exfiltration.md)** - Confidential data exfiltrated to external cloud storage

Each investigation includes: timeline of events, SIEM queries used, IOC analysis, threat intelligence enrichment, MITRE ATT&CK mapping, and recommended response actions.

## 📧 Phishing Analysis

Comprehensive email threat analysis reports:

- **[Phishing Analysis Overview](phishing-analysis/README.md)** - Summary of all analyses
- **[Phishing 001: Credential Harvesting](phishing-analysis/phishing-001-credential-harvesting.md)** - Fake Microsoft 365 login page
- **[Phishing 002: Malicious Attachment](phishing-analysis/phishing-002-malicious-attachment.md)** - Macro-enabled Excel delivering malware
- **[Phishing 003: Business Email Compromise](phishing-analysis/phishing-003-business-email-compromise.md)** - CEO impersonation wire fraud attempt

Each analysis includes: email header analysis, SPF/DKIM/DMARC checks, URL reputation analysis, attachment sandbox analysis, IOC extraction, and recommended response actions.

## 🛠️ Tools & Technologies

**Virtualization & Infrastructure:**
- VirtualBox (Host-Only networking)
- Windows Server 2019
- Windows 10 Pro
- Ubuntu Server 22.04
- Kali Linux 2024

**Security Tools:**
- **SIEM:** Splunk Free (SPL query development)
- **EDR:** Wazuh Open Source
- **Endpoint Logging:** Sysmon (SwiftOnSecurity configuration)
- **Threat Simulation:** Atomic Red Team
- **Network Analysis:** Wireshark
- **Phishing Analysis:** Email headers, VirusTotal, URLScan.io, AbuseIPDB, Any.Run sandbox

**Attack Simulation:**
- Metasploit Framework
- Mimikatz (credential dumping)
- PsExec (lateral movement)
- Custom PowerShell scripts

## 💡 Skills Demonstrated

- **SIEM Operation:** Splunk query development (SPL), alert creation, dashboard building, log correlation
- **Log Analysis:** Windows Event Logs (Security, System), Sysmon telemetry interpretation, firewall log analysis
- **Incident Response:** Alert triage, investigation methodology, timeline reconstruction, IOC extraction, scope assessment
- **Threat Intelligence:** IOC enrichment using VirusTotal, AbuseIPDB, URLScan, threat actor TTPs
- **MITRE ATT&CK Framework:** Tactic and technique mapping, adversary emulation, detection gap analysis
- **Phishing Analysis:** Email header analysis, SPF/DKIM/DMARC validation, URL defanging, malware sandbox analysis
- **Endpoint Security:** EDR alert investigation, process tree analysis, memory forensics, persistence mechanism identification
- **Network Security:** Traffic analysis, protocol anomaly detection, data exfiltration patterns
- **Active Directory Security:** Domain controller monitoring, authentication attack detection, privileged account monitoring
- **Documentation:** Technical writing, executive summary creation, professional reporting

## 🎓 Certifications

- **Completed:** CompTIA Security+
- **Completed:** Splunk Fundamentals 1
- **Completed:** Google Cybersecurity Certificate

## 📫 Contact

- **LinkedIn:** [linkedin.com/in/praiselekpenyong](https://www.linkedin.com/in/praiselekpenyong)
- **Email:** ekpenyongpraisel@gmail.com
- **GitHub:** [github.com/praisel-ekpenyong](https://github.com/praisel-ekpenyong)

---

*This portfolio is continually updated as I expand my lab environment and tackle new security scenarios. All indicators of compromise (IOCs) used in this portfolio are simulated and defanged for educational purposes.*
