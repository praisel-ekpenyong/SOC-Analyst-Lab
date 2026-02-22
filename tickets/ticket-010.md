# Ticket-010 – Email Not Syncing on Mobile

| Field | Value |
|---|---|
| **Title** | Corporate email not syncing on personal phone |
| **Date** | 2025-01-20 |
| **Requester** | Bob Jones (bjones@corp.local) |
| **Environment** | Android 13, Microsoft Outlook Mobile |
| **Help Topic** | Other / General |
| **SLA** | SEV-C (8 hours) |
| **Related Lab** | Lab 01 – Active Directory Basics |
| **Related Incident** | None |

## Problem Statement
Bob Jones reports his corporate email stopped syncing on his personal Android phone (Microsoft Outlook). Error: "Authentication failed."

## Questions Asked
1. When did this stop working? *(After I changed my domain password)*
2. Have you updated the password in the Outlook mobile app? *(No)*
3. Is MFA/Authenticator set up on this device? *(Yes)*

## Troubleshooting Steps
1. Root cause identified: Bob changed his domain password (per expiry policy) but did not update it in Outlook Mobile.
2. Guided Bob to: Outlook app → Settings → Account → Re-enter password.
3. MFA prompt appeared – Bob approved on Authenticator app.
4. Email synced successfully; inbox updated.

## Resolution
Updated password in Outlook mobile app and completed MFA challenge. Email sync restored.

## Close Notes
User education provided: after any password change, update credentials in all connected apps and devices.

## Tags
`email` `mobile` `password` `authentication`

## Time to Resolve
10 minutes
