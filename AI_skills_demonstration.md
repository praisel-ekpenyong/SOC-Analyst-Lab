# Demonstrating AI Skills in SOC Alert Triage

This document explains how a small project can illustrate practical AI skills relevant to a Security Operations Center (SOC) analyst role. The goal is to build a structured prompt that converts an alert and a short set of log lines into a concise investigation summary.

## Prompt Design

Design a reusable prompt that takes the alert text and a sample of log lines as input and produces a formatted output with:
- A one‑paragraph summary of what happened.
- A hypothesis about the likely cause of the alert.
- Three recommended next checks.
- A proposed containment or remediation step.

The prompt should specify a consistent section order and instruct the model to flag when evidence is insufficient rather than invent details.

## Context Management

Provide the language model with the right context and constraints:
- Include the alert text and a limited number of log lines.
- Identify the environment (e.g. Windows server vs Linux host) so the model does not suggest incompatible tools.
- Restrict the model from citing information that is not present in the input.

This shows an understanding of how context affects model behaviour.

## Evaluation and Iteration

Run the prompt on multiple example alerts and track:
- Hallucinations or unsupported claims.
- Incorrect root cause hypotheses.
- Poor recommendations.

Iteratively refine the prompt to reduce these issues. Document changes and the improvement seen after each revision.

## Guardrails

Add explicit guardrails to make the workflow appropriate for security work:
- Require evidence for claims.
- Flag insufficient data.
- Separate assumptions from observations.
- Prevent the model from outputting secrets or full log content.

These controls demonstrate awareness of AI risk in incident response.

## Proof of Work

Produce three artefacts to demonstrate the project:
1. The final prompt template.
2. A set of three test cases showing the inputs and the model’s outputs.
3. A simple evaluation table that notes what the model got right and wrong and the prompt modifications made.

## Example Resume Bullet

> Built a structured LLM prompt that turns SOC alerts and log excerpts into a standardized summary, investigation hypothesis, next steps and containment guidance. Added guardrails for evidence‑based claims and iterated the template across multiple test cases to reduce hallucinations and improve investigation quality.
