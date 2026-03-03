#!/usr/bin/env python3
"""
LLM-Powered Alert Triage Assistant
====================================
Takes a SIEM alert as JSON input and uses an LLM (OpenAI API or local ollama)
to classify the alert, generate an analyst summary, and suggest a next action.

Dependencies:
    pip install openai requests

Usage:
    # Triage a single alert by ID from sample_alerts.json:
    python alert_triage.py --alert-id ALERT-001

    # Triage all alerts in the sample file:
    python alert_triage.py --all

    # Use local ollama instead of OpenAI:
    python alert_triage.py --all --provider ollama
"""

import argparse
import json
import os
import sys

# ---------------------------------------------------------------------------
# LLM provider helpers
# ---------------------------------------------------------------------------

def call_openai(prompt: str, model: str = "gpt-4o-mini") -> str:
    """Send a prompt to the OpenAI Chat Completions API and return the reply."""
    try:
        import openai  # imported lazily so the script runs without openai installed
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
                {
                    "role": "system",
                    "content": (
                        "You are an expert Tier 1 SOC Analyst. "
                        "Analyse the provided SIEM alert and respond ONLY with valid JSON."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content.strip()
    except openai.OpenAIError as exc:
        print(f"ERROR calling OpenAI API: {exc}")
        sys.exit(1)


def call_ollama(prompt: str, model: str = "llama3") -> str:
    """Send a prompt to a locally running ollama instance and return the reply."""
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
        "system": (
            "You are an expert Tier 1 SOC Analyst. "
            "Analyse the provided SIEM alert and respond ONLY with valid JSON."
        ),
    }
    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to ollama. Is it running? Start with: ollama serve")
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        print(f"ERROR calling ollama API: {exc}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Core triage logic
# ---------------------------------------------------------------------------

TRIAGE_PROMPT_TEMPLATE = """
You are analysing the following SIEM alert. Respond ONLY with a JSON object matching
this exact schema (no markdown fences, no extra text):

{{
  "classification": "<True Positive | False Positive | Needs Investigation>",
  "confidence": "<High | Medium | Low>",
  "analyst_summary": "<2-4 sentence summary of what happened and why it matters>",
  "next_action": "<specific, actionable next step for the Tier 1 analyst>",
  "mitre_technique": "<ATT&CK technique ID and name, e.g. T1059.001 - Command and Scripting Interpreter: PowerShell>"
}}

SIEM Alert:
{alert_json}
"""


def triage_alert(alert: dict, provider: str, model: str) -> dict:
    """Call the LLM to triage a single alert and return a parsed result dict."""
    prompt = TRIAGE_PROMPT_TEMPLATE.format(alert_json=json.dumps(alert, indent=2))

    if provider == "openai":
        raw_response = call_openai(prompt, model=model)
    else:
        raw_response = call_ollama(prompt, model=model)

    # Parse the JSON response from the LLM
    try:
        result = json.loads(raw_response)
    except json.JSONDecodeError:
        # If the LLM wrapped its response in markdown fences, strip them
        cleaned = raw_response.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        try:
            result = json.loads(cleaned)
        except json.JSONDecodeError:
            # Return raw text if parsing still fails
            result = {"raw_response": raw_response, "parse_error": True}

    return result


def print_triage_result(alert: dict, result: dict) -> None:
    """Pretty-print the triage result to stdout."""
    print("\n" + "=" * 70)
    print(f"  Alert ID : {alert.get('alert_id', 'N/A')}")
    print(f"  Type     : {alert.get('alert_type', 'N/A')}")
    print(f"  Severity : {alert.get('severity', 'N/A')}")
    print(f"  Host     : {alert.get('hostname', 'N/A')}")
    print(f"  Timestamp: {alert.get('timestamp', 'N/A')}")
    print("-" * 70)

    if result.get("parse_error"):
        print("  [LLM raw response - could not parse JSON]")
        print(result.get("raw_response", ""))
    else:
        print(f"  Classification : {result.get('classification', 'N/A')}")
        print(f"  Confidence     : {result.get('confidence', 'N/A')}")
        print(f"  MITRE Technique: {result.get('mitre_technique', 'N/A')}")
        print(f"\n  Analyst Summary:\n    {result.get('analyst_summary', 'N/A')}")
        print(f"\n  Recommended Next Action:\n    {result.get('next_action', 'N/A')}")
    print("=" * 70)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="LLM-Powered SOC Alert Triage Assistant"
    )
    parser.add_argument(
        "--alert-id",
        help="Triage a specific alert by its alert_id (e.g. ALERT-001)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Triage all alerts in the sample file",
    )
    parser.add_argument(
        "--alerts-file",
        default="sample_alerts.json",
        help="Path to the JSON file containing alerts (default: sample_alerts.json)",
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
        help="Model name override (default: gpt-4o-mini for OpenAI, llama3 for ollama)",
    )
    args = parser.parse_args()

    if not args.alert_id and not args.all:
        parser.print_help()
        sys.exit(1)

    # Resolve default model per provider
    if args.model is None:
        args.model = "gpt-4o-mini" if args.provider == "openai" else "llama3"

    # Load alerts from file
    try:
        with open(args.alerts_file, "r", encoding="utf-8") as fh:
            alerts = json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: Alerts file not found: {args.alerts_file}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Could not parse alerts file: {exc}")
        sys.exit(1)

    # Filter to the requested alert(s)
    if args.alert_id:
        alerts = [a for a in alerts if a.get("alert_id") == args.alert_id]
        if not alerts:
            print(f"ERROR: No alert found with id '{args.alert_id}'")
            sys.exit(1)

    print(f"\nUsing provider: {args.provider.upper()} | model: {args.model}")
    print(f"Triaging {len(alerts)} alert(s)...\n")

    for alert in alerts:
        result = triage_alert(alert, provider=args.provider, model=args.model)
        print_triage_result(alert, result)


if __name__ == "__main__":
    main()
