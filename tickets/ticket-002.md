# Ticket-002 – Account Lockout

| Field | Value |
|---|---|
| **Title** | Account locked out – multiple failed login attempts |
| **Date** | 2025-01-08 |
| **Requester** | Mark Lee (mark.lee@corp.local) |
| **Environment** | Windows 10, corp.local domain |
| **Help Topic** | Account Lockout |
| **SLA** | SEV-C (8 hours) |
| **Related Lab** | Lab 01 – Active Directory Basics |
| **Related Incident** | Incident-001 – Account Lockouts After GPO Change |

## Problem Statement
User Mark Lee reported his account was locked and he could not log in. He stated he had tried multiple times after forgetting his password.

## Questions Asked
1. Did you recently change your password? *(No)*
2. Are you logged in anywhere else (phone, tablet)? *(Yes – mobile device with old credentials cached)*
3. Approximate time this started? *(About 30 minutes ago)*

## Troubleshooting Steps
1. Checked AD – account was locked; 8 failed attempts in 5 minutes.
2. Identified mobile device still attempting authentication with old password.
3. Instructed user to remove corp.local account from mobile device.
4. Unlocked account in ADUC: right-click → Properties → Account tab → Unlock.
5. Reset password per user request.

## Resolution
Unlocked account and reset password. User updated mobile device with new credentials. No further lockout occurred.

## Close Notes
Root cause: cached credentials on mobile device. User educated on updating saved passwords on all devices.

## Tags
`account-lockout` `active-directory` `gpo` `mobile-credentials`

## Time to Resolve
18 minutes
