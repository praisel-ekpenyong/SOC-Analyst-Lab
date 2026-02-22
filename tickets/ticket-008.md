# Ticket-008 – Hardware Issue: Monitor Not Detected

| Field | Value |
|---|---|
| **Title** | Second monitor not detected after desk move |
| **Date** | 2025-01-16 |
| **Requester** | Jane Doe (jane.doe@corp.local) |
| **Environment** | Windows 10, Dell OptiPlex 7060, Dual HP monitors |
| **Help Topic** | Hardware Issue |
| **SLA** | SEV-C (8 hours) |
| **Related Lab** | Lab 03 – Windows Troubleshooting |
| **Related Incident** | None |

## Problem Statement
After moving to a new desk, Jane Doe's second monitor is not being detected. Primary monitor works fine.

## Questions Asked
1. Are all cables securely connected? *(User checked – yes)*
2. Is the second monitor powered on? *(Yes)*
3. What cable type is being used? *(DisplayPort)*

## Troubleshooting Steps
1. Attempted **Win + P → Extend** – no change, second monitor not detected.
2. Right-clicked desktop → **Display Settings → Detect** – monitor not found.
3. Physically inspected connection – DisplayPort cable was not fully seated in GPU port.
4. Reseated DisplayPort cable – monitor detected immediately.
5. Configured as Extended display. Verified resolution set to native (1920×1080).

## Resolution
DisplayPort cable was not fully seated. Reseating the cable resolved the detection issue.

## Close Notes
Physical connection issue resolved on-site. User confirmed dual monitor setup working.

## Tags
`hardware` `monitor` `display` `cable`

## Time to Resolve
15 minutes
