# 🤖 AI Projects — SOC Analyst Lab

## Introduction

This section of the SOC Analyst Lab portfolio demonstrates practical applications of **Artificial Intelligence and Machine Learning** in modern Security Operations Centre workflows. Each project is designed to be recruiter-ready and maps directly to real Tier 1 and Tier 2 analyst tasks.

AI is rapidly changing how SOC teams operate — from automating repetitive triage tasks to detecting anomalies that rules-based systems miss. These projects show hands-on proficiency with the tools and techniques that leading security teams are deploying today.

---

## Why AI Skills Matter for SOC Analysts

| Traditional SOC Challenge | AI Solution Demonstrated |
|---|---|
| Alert fatigue from thousands of daily alerts | LLM-powered triage classifies and prioritises automatically |
| Rules-based detection misses novel attacks | ML anomaly detection (Isolation Forest) catches statistical outliers |
| Writing incident reports takes hours | GenAI generates a professional report in under 60 seconds |
| Building new playbooks is slow and inconsistent | AI-generated SOAR playbooks are structured and MITRE-aligned in minutes |

Modern job postings for SOC Analysts increasingly list familiarity with **AI-assisted security tools**, **UEBA (User and Entity Behaviour Analytics)**, and **automated triage** as desired skills. This portfolio section directly targets those requirements.

---

## Projects

### 1. 🚨 [LLM-Powered Alert Triage Assistant](./01-AI-Alert-Triage/)

Uses the OpenAI API (or local **ollama** as a free alternative) to analyse SIEM alerts in JSON format and output:
- Alert classification: `True Positive`, `False Positive`, or `Needs Investigation`
- A concise analyst summary
- A recommended next action

Includes 5 realistic SOC alert examples (brute force, lateral movement, C2 beaconing, phishing, suspicious PowerShell) mapped to MITRE ATT&CK techniques.

**Tools**: Python, OpenAI API / ollama (llama3)

---

### 2. 📊 [ML-Based Log Anomaly Detection](./02-Log-Anomaly-Detection/)

Applies **Isolation Forest** (scikit-learn) to Windows Event Log / auth log CSV data to detect anomalous entries without labelled training data. Outputs a flagged anomaly report with scores for analyst review.

Includes a 100-row synthetic log dataset with injected anomalies (off-hours logins, external IPs, brute force, account creation).

**Tools**: Python, scikit-learn, pandas, numpy

---

### 3. 📝 [GenAI Incident Report Generator](./03-Incident-Report-Generator/)

Takes structured incident JSON data and uses an LLM to generate a complete, professional incident report in Markdown format — including Executive Summary, Timeline, IOC tables, Root Cause Analysis, MITRE mapping, and Remediation Steps.

Includes a pre-generated sample report for a ransomware incident.

**Tools**: Python, OpenAI API / ollama (llama3)

---

### 4. 🛡️ [AI-Generated SOAR Playbook Builder](./04-SOAR-Playbook-Automation/)

Takes an alert type and MITRE ATT&CK technique as input and uses an LLM to generate a complete SOAR playbook in Markdown format covering Detection, Triage, Containment, Eradication, Recovery, and Lessons Learned — with real SIEM queries and tool-specific steps.

Includes pre-generated playbooks for phishing, lateral movement, and ransomware.

**Tools**: Python, OpenAI API / ollama (llama3)

---

## Common Requirements

All projects share these dependencies (install all at once):

```bash
pip install openai requests scikit-learn pandas numpy
```

### Using the Free Local Alternative (No API Key Required)

All LLM-based projects support **ollama** as a free, locally-running alternative to OpenAI:

```bash
# 1. Install ollama (https://ollama.com)
# 2. Pull a model
ollama pull llama3

# 3. Start the server
ollama serve

# 4. Use --provider ollama flag with any script
python alert_triage.py --all --provider ollama
python generate_report.py --provider ollama
python playbook_generator.py --alert-type "Ransomware" --technique "T1486" --provider ollama
```

---

## MITRE ATT&CK Coverage

These projects collectively cover detection and response for:

| Technique ID | Name | Project |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Alert Triage |
| T1570 | Lateral Tool Transfer | Alert Triage, Playbook Builder |
| T1071.001 | Application Layer Protocol: Web Protocols | Alert Triage |
| T1566.001/002 | Phishing | Alert Triage, Playbook Builder |
| T1059.001 | PowerShell | Alert Triage, Incident Report |
| T1486 | Data Encrypted for Impact | Incident Report, Playbook Builder |
| T1021.002 | Remote Services: SMB | Incident Report, Playbook Builder |
| T1078 | Valid Accounts | Log Anomaly Detection |
| T1098 | Account Manipulation | Log Anomaly Detection |
| T1547.001 | Registry Run Keys Persistence | Incident Report, Playbook Builder |

---

*All sample data, IOCs, and scenario details are synthetic and defanged for educational use.*
