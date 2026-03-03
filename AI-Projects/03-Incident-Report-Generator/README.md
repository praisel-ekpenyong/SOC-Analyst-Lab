# 03 — GenAI Incident Report Generator

## Overview

Writing incident reports is one of the most time-consuming tasks for SOC analysts. A thorough post-incident report can take **1–3 hours** to write manually — time that could be spent investigating the next alert.

This project uses a **Generative AI (LLM)** to transform structured incident JSON data into a polished, professional incident report in Markdown format, including an Executive Summary, Timeline, IOC tables, Root Cause Analysis, and Remediation Steps — in under 60 seconds.

---

## Use Case

| Task | Manual Effort | With GenAI |
|---|---|---|
| Write Executive Summary | 20–30 min | ~15 seconds |
| Format Timeline table | 15–20 min | ~15 seconds |
| Document IOCs with context | 20–30 min | ~15 seconds |
| Draft Root Cause Analysis | 20–30 min | ~15 seconds |
| Write Remediation Steps | 20–30 min | ~15 seconds |
| **Total** | **1.5–2.5 hours** | **~1 minute** |

> **Analyst value**: The analyst still reviews, edits, and signs off on the report. The LLM eliminates the blank-page problem and handles formatting — so analysts can focus on accuracy and judgment rather than structure and prose.

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

# Generate report with defaults
python generate_report.py

# Custom input/output paths
python generate_report.py --input incident_input.json --output my_report.md

# Use GPT-4o for higher quality
python generate_report.py --model gpt-4o
```

### Option B — Local LLM via ollama (Free)

```bash
# Install ollama: https://ollama.com
ollama pull llama3
ollama serve

# Run with ollama
python generate_report.py --provider ollama
python generate_report.py --provider ollama --model mistral
```

---

## Report Structure

The generated Markdown report includes these sections:

| Section | Contents |
|---|---|
| **Metadata header** | Incident ID, title, severity, date, analyst |
| **Executive Summary** | 2–3 paragraph non-technical overview for management |
| **Timeline of Events** | Chronological table of all incident events |
| **Indicators of Compromise** | Hashes, IPs, domains, registry keys, file paths |
| **Root Cause Analysis** | Technical explanation of how the incident occurred |
| **Recommended Remediation** | Prioritised, numbered action items |
| **MITRE ATT&CK Mapping** | Technique IDs mapped to observed activity |
| **Lessons Learned** | Process improvements and control gaps identified |

---

## How It Reduces Analyst Burnout

SOC analysts frequently report **documentation fatigue** — the mental exhaustion from writing repetitive reports during high-alert periods. This tool:

1. **Eliminates blank-page paralysis** — the LLM generates a full draft immediately
2. **Enforces report consistency** — every report follows the same structure and professional tone
3. **Accelerates shift handoffs** — on-call analysts can hand off a complete report rather than rough notes
4. **Scales with incident volume** — generate reports for 10 incidents in the time it used to take to write one

---

## Files

| File | Description |
|---|---|
| `generate_report.py` | Main Python script |
| `incident_input.json` | Sample ransomware incident input data |
| `incident_report_output.md` | Pre-generated sample report output |
| `README.md` | This file |
