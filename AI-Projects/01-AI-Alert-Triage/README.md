# 01 — LLM-Powered Alert Triage Assistant

## Overview

This project demonstrates how a Tier 1 SOC Analyst can use a **Large Language Model (LLM)** to accelerate alert triage. Given a raw SIEM alert in JSON format, the script classifies the alert, generates a concise analyst summary, and recommends an immediate next action — all in seconds.

This maps directly to the first-response triage step in most SOC workflows, where analysts must quickly determine whether an alert is a **True Positive**, **False Positive**, or requires further investigation before escalation.

---

## Use Case

| Analyst Task | Manual Effort | With LLM Assistant |
|---|---|---|
| Read and parse alert fields | 2–5 min | Instant |
| Classify alert (TP / FP / Needs Investigation) | 5–10 min | ~5 seconds |
| Write analyst notes / summary | 5–15 min | ~5 seconds |
| Determine next action | 2–5 min | ~5 seconds |

---

## Requirements

```bash
pip install openai requests
```

### Environment Variables

| Variable | Required For | Description |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI provider | Your OpenAI API key |

For the **free local alternative** (ollama), no API key is needed — see instructions below.

---

## How to Run

### Option A — OpenAI API

```bash
export OPENAI_API_KEY="sk-..."

# Triage one specific alert
python alert_triage.py --alert-id ALERT-001

# Triage all sample alerts
python alert_triage.py --all

# Use a different OpenAI model
python alert_triage.py --all --model gpt-4o
```

### Option B — Local LLM via ollama (Free)

1. Install ollama: https://ollama.com
2. Pull a model:
   ```bash
   ollama pull llama3
   ```
3. Start the ollama server:
   ```bash
   ollama serve
   ```
4. Run the script with the `--provider ollama` flag:
   ```bash
   python alert_triage.py --all --provider ollama
   python alert_triage.py --alert-id ALERT-003 --provider ollama --model llama3
   ```

---

## Sample Output

```
======================================================================
  Alert ID : ALERT-005
  Type     : Suspicious PowerShell Execution
  Severity : Critical
  Host     : WKS-DEV01
  Timestamp: 2025-10-14T14:38:47Z
----------------------------------------------------------------------
  Classification : True Positive
  Confidence     : High
  MITRE Technique: T1059.001 - Command and Scripting Interpreter: PowerShell

  Analyst Summary:
    A highly obfuscated, base64-encoded PowerShell command was executed from
    WKS-DEV01 with the parent process WINWORD.EXE, indicating macro-delivered
    malware. Decoded command reveals a reverse TCP shell connecting outbound.
    This is a critical-severity true positive requiring immediate containment.

  Recommended Next Action:
    Isolate WKS-DEV01 from the network immediately. Collect a memory dump and
    preserve disk image. Escalate to Tier 2/IR team and open a P1 incident ticket.
    Check for lateral movement from this host in the last 24 hours.
======================================================================
```

---

## MITRE ATT&CK Mapping

| Alert Type | MITRE Technique | Technique Name |
|---|---|---|
| Brute Force Failed Logins | **T1110.001** | Brute Force: Password Guessing |
| Lateral Movement via PsExec | **T1570** | Lateral Tool Transfer |
| C2 Beaconing | **T1071.001** | Application Layer Protocol: Web Protocols |
| Phishing URL Click | **T1566.002** | Phishing: Spearphishing Link |
| Suspicious PowerShell | **T1059.001** | Command and Scripting Interpreter: PowerShell |

---

## How It Maps to Tier 1 Analyst Workflows

```
SIEM Alert Fires
      │
      ▼
alert_triage.py receives JSON alert
      │
      ▼
LLM classifies: True Positive / False Positive / Needs Investigation
      │
      ├─── False Positive ──► Close ticket with justification note
      │
      ├─── Needs Investigation ──► Assign to analyst for deeper review
      │
      └─── True Positive ──► Execute recommended next action
                              (isolate, escalate, block IP, etc.)
```

The LLM acts as a **second opinion** and **documentation accelerator**, not a replacement for analyst judgment. All LLM outputs should be reviewed before acting.

---

## Files

| File | Description |
|---|---|
| `alert_triage.py` | Main Python script |
| `sample_alerts.json` | 5 realistic SOC alert examples |
| `README.md` | This file |
