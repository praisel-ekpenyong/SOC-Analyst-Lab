# 04 — AI-Generated SOAR Playbook Builder

## Overview

SOAR (Security Orchestration, Automation, and Response) playbooks are the backbone of consistent, repeatable incident response. Building them from scratch is time-consuming and requires deep knowledge of multiple tools and frameworks. This project uses **Generative AI** to instantly create structured, actionable SOAR playbooks for any alert type and MITRE ATT&CK technique.

---

## Use Case

| Scenario | Manual Effort | With AI Builder |
|---|---|---|
| Write new playbook from scratch | 4–8 hours | ~1 minute |
| Adapt playbook for new technique | 1–2 hours | ~30 seconds |
| Add MITRE ATT&CK mapping | 30–60 min | ~30 seconds |
| Include relevant SIEM queries | 1–2 hours | ~30 seconds |

**How it improves detection engineering workflows:**

- **Rapid prototyping**: Generate a playbook draft in seconds, then refine it for your environment
- **Consistent structure**: Every playbook follows the same IR framework (Detection → Containment → Eradication → Recovery → Lessons Learned)
- **Reduced knowledge gaps**: Junior analysts get detailed, expert-level step-by-step guidance
- **MITRE alignment**: Every playbook is automatically mapped to ATT&CK techniques
- **On-call support**: Analysts can generate or refresh a playbook in real time during an incident

---

## Requirements

```bash
pip install openai requests
```

### Environment Variables

| Variable | Required For | Description |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI provider | Your OpenAI API key |

---

## How to Run

### Option A — OpenAI API

```bash
export OPENAI_API_KEY="sk-..."

# Generate a playbook for a specific scenario
python playbook_generator.py --alert-type "Phishing Email" --technique "T1566.001"

# Generate with severity and custom output path
python playbook_generator.py \
    --alert-type "Ransomware" \
    --technique "T1486" \
    --severity "Critical" \
    --output playbook_ransomware_custom.md

# Interactive mode (prompts for all inputs)
python playbook_generator.py --interactive
```

### Option B — Local LLM via ollama (Free)

```bash
# Install and start ollama
ollama pull llama3
ollama serve

# Generate with local LLM
python playbook_generator.py \
    --alert-type "Lateral Movement via PsExec" \
    --technique "T1570" \
    --provider ollama
```

---

## Sample Generated Playbooks

| File | Scenario | MITRE Technique |
|---|---|---|
| [`playbook_phishing.md`](playbook_phishing.md) | Phishing Email / Spearphishing | T1566 |
| [`playbook_lateral_movement.md`](playbook_lateral_movement.md) | Lateral Movement via Remote Services | T1021 |
| [`playbook_ransomware.md`](playbook_ransomware.md) | Ransomware / Data Encrypted for Impact | T1486 |

---

## Playbook Structure

Every generated playbook includes these sections:

| Section | Contents |
|---|---|
| **Metadata** | Playbook name, technique, severity, version |
| **Overview** | Threat description and trigger conditions |
| **Prerequisites** | Required tools, permissions, and access |
| **Detection** | SIEM queries (Splunk SPL), EDR checks, log sources |
| **Triage & Analysis** | Steps to confirm and scope the incident |
| **Containment** | Immediate actions to stop the spread |
| **Eradication** | Steps to remove the threat entirely |
| **Recovery** | Steps to restore normal operations |
| **Communication & Escalation** | Notification matrix and ticket requirements |
| **Lessons Learned** | Post-incident review checklist |
| **MITRE ATT&CK Mapping** | Full technique mapping for all phases |

---

## Files

| File | Description |
|---|---|
| `playbook_generator.py` | Main Python script |
| `playbook_phishing.md` | Sample generated playbook — Phishing |
| `playbook_lateral_movement.md` | Sample generated playbook — Lateral Movement |
| `playbook_ransomware.md` | Sample generated playbook — Ransomware |
| `README.md` | This file |
