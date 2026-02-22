# Ticket-009 – VPN Access Request

| Field | Value |
|---|---|
| **Title** | New employee needs VPN access for remote work |
| **Date** | 2025-01-17 |
| **Requester** | Sarah Kim (sarah.kim@corp.local) |
| **Environment** | Windows 10, Remote – Home Office |
| **Help Topic** | Other / General |
| **SLA** | SEV-C (8 hours) |
| **Related Lab** | Lab 01 – Active Directory Basics |
| **Related Incident** | None |

## Problem Statement
New employee Sarah Kim needs VPN client configured on her laptop to access corporate resources from her home office. She starts remote work next Monday.

## Questions Asked
1. Has your AD account been created and are you able to log in on-premises? *(Yes)*
2. Do you have the VPN client installer? *(No)*
3. Has your manager submitted a VPN access request? *(Yes – confirmed via ticketing system)*

## Troubleshooting Steps
1. Verified manager's VPN access request approved (Ticket-009 parent).
2. Sent Sarah the VPN client installer (OpenVPN / corporate package) via IT file share.
3. Sarah installed client and imported the company `.ovpn` profile.
4. Tested VPN connection – connected successfully; internal IP assigned.
5. Verified access to `\\DC01\ITShare` and corp.local intranet from VPN.
6. Sent user a VPN usage guide (PDF).

## Resolution
VPN client installed and profile configured. User confirmed successful connection to corporate network from home.

## Close Notes
Standard VPN onboarding completed. Access request documentation archived.

## Tags
`vpn` `remote-access` `onboarding` `new-employee`

## Time to Resolve
30 minutes
