#!/usr/bin/env python3
"""
AI-Generated SOAR Playbook Builder
=====================================
Takes an alert type and MITRE ATT&CK technique as input, uses an LLM to
generate a structured SOAR playbook in Markdown format covering:
  Detection → Containment → Eradication → Recovery → Lessons Learned

Dependencies:
    pip install openai requests

Usage:
    python playbook_generator.py --alert-type "Phishing Email" --technique "T1566.001"
    python playbook_generator.py --alert-type "Ransomware" --technique "T1486" --provider ollama
    python playbook_generator.py --interactive
"""

import argparse
import os
import re
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# LLM provider helpers
# ---------------------------------------------------------------------------

def call_openai(prompt: str, system_prompt: str, model: str = "gpt-4o-mini") -> str:
    """Send a prompt to the OpenAI Chat Completions API."""
    try:
        import openai
    except ImportError:
        print("ERROR: 'openai' package not installed. Run: pip install openai")
        sys.exit(1)

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY environment variable not set.")
        sys.exit(1)

    client = openai.OpenAI(api_key=api_key)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except openai.OpenAIError as exc:
        print(f"ERROR calling OpenAI API: {exc}")
        sys.exit(1)


def call_ollama(prompt: str, system_prompt: str, model: str = "llama3") -> str:
    """Send a prompt to a locally running ollama instance."""
    try:
        import requests
    except ImportError:
        print("ERROR: 'requests' package not installed. Run: pip install requests")
        sys.exit(1)

    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "system": system_prompt,
    }
    try:
        response = requests.post(url, json=payload, timeout=180)
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to ollama. Is it running? Start with: ollama serve")
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        print(f"ERROR calling ollama API: {exc}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Playbook generation
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a senior Security Operations Center (SOC) engineer and SOAR platform architect. "
    "You create detailed, actionable SOAR playbooks in Markdown format for SOC teams. "
    "Your playbooks are practical, tool-agnostic, and suitable for Tier 1 and Tier 2 analysts."
)

PLAYBOOK_PROMPT_TEMPLATE = """
Generate a complete SOAR playbook in Markdown format for the following scenario:

- **Alert Type**: {alert_type}
- **MITRE ATT&CK Technique**: {technique}
- **Severity**: {severity}
- **Environment**: Enterprise Windows environment with Splunk SIEM, Wazuh EDR, and osTicket

The playbook MUST include these sections (use ## for top-level headings):

## Playbook Metadata
(table with: Playbook Name, Alert Type, MITRE Technique, Severity, Version, Last Updated)

## Overview
(Brief description of the threat scenario and when this playbook is triggered)

## Prerequisites
(Tools, permissions, and information needed before starting)

## Detection
(Step-by-step detection steps including SIEM queries, EDR checks, log sources to review)

## Triage and Analysis
(Steps to determine if the alert is a true positive, what to look for, enrichment steps)

## Containment
(Immediate containment actions to stop the threat from spreading — numbered list)

## Eradication
(Steps to remove the threat from affected systems — numbered list)

## Recovery
(Steps to restore normal operations safely — numbered list)

## Communication and Escalation
(Who to notify, when to escalate, what information to include in the incident ticket)

## Lessons Learned
(Post-incident review checklist, detection improvement opportunities, control gaps to address)

## MITRE ATT&CK Reference
(Table mapping each phase to relevant ATT&CK techniques)

Make all steps specific, actionable, and reference real tools (Splunk SPL queries, PowerShell commands,
Windows Event IDs, etc.) where appropriate.
"""


def generate_playbook(alert_type: str, technique: str, severity: str,
                      provider: str, model: str) -> str:
    """Generate a SOAR playbook using the LLM."""
    prompt = PLAYBOOK_PROMPT_TEMPLATE.format(
        alert_type=alert_type,
        technique=technique,
        severity=severity,
    )

    if provider == "openai":
        return call_openai(prompt, SYSTEM_PROMPT, model=model)
    else:
        return call_ollama(prompt, SYSTEM_PROMPT, model=model)


def make_filename(alert_type: str, output_dir: str) -> str:
    """Convert alert type to a safe filename and return the full path."""
    safe_name = re.sub(r"[^\w\s-]", "", alert_type.lower())
    safe_name = re.sub(r"[\s]+", "_", safe_name.strip())
    filename = f"playbook_{safe_name}.md"
    return os.path.join(output_dir, filename)


def save_playbook(content: str, output_path: str, alert_type: str, technique: str) -> None:
    """Prepend generation metadata and save the playbook."""
    generated_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    header = (
        f"<!-- Generated by AI SOAR Playbook Builder on {generated_at} -->\n"
        f"<!-- Alert Type: {alert_type} | MITRE Technique: {technique} -->\n\n"
    )
    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(header + content)
        print(f"[+] Playbook saved to: {output_path}")
    except OSError as exc:
        print(f"ERROR writing playbook: {exc}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AI-Generated SOAR Playbook Builder"
    )
    parser.add_argument(
        "--alert-type",
        help='Alert type / scenario name (e.g. "Phishing Email", "Ransomware")',
    )
    parser.add_argument(
        "--technique",
        help="MITRE ATT&CK technique ID (e.g. T1566.001, T1486)",
    )
    parser.add_argument(
        "--severity",
        default="High",
        choices=["Low", "Medium", "High", "Critical"],
        help="Alert severity (default: High)",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to save the generated playbook (default: current directory)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Explicit output file path (overrides --output-dir auto-naming)",
    )
    parser.add_argument(
        "--provider",
        choices=["openai", "ollama"],
        default="openai",
        help="LLM provider to use (default: openai)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name override",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode (prompts for inputs)",
    )
    args = parser.parse_args()

    # Interactive mode
    if args.interactive:
        args.alert_type = input("Alert type (e.g. Phishing Email): ").strip()
        args.technique = input("MITRE ATT&CK technique (e.g. T1566.001): ").strip()
        args.severity = input("Severity [Low/Medium/High/Critical] (default: High): ").strip() or "High"
        provider_input = input("Provider [openai/ollama] (default: openai): ").strip()
        args.provider = provider_input if provider_input in ("openai", "ollama") else "openai"
    elif not args.alert_type or not args.technique:
        parser.print_help()
        sys.exit(1)

    if args.model is None:
        args.model = "gpt-4o-mini" if args.provider == "openai" else "llama3"

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        output_path = make_filename(args.alert_type, args.output_dir)

    print(f"\n[*] Generating SOAR playbook...")
    print(f"    Alert Type : {args.alert_type}")
    print(f"    Technique  : {args.technique}")
    print(f"    Severity   : {args.severity}")
    print(f"    Provider   : {args.provider.upper()} ({args.model})")

    playbook = generate_playbook(
        alert_type=args.alert_type,
        technique=args.technique,
        severity=args.severity,
        provider=args.provider,
        model=args.model,
    )

    save_playbook(playbook, output_path, args.alert_type, args.technique)


if __name__ == "__main__":
    main()
