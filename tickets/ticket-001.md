# Ticket-001 – Password Reset Request

| Field | Value |
|---|---|
| **Title** | User password expired – cannot log in |
| **Date** | 2025-01-06 |
| **Requester** | Jane Doe (jane.doe@corp.local) |
| **Environment** | Windows 10, corp.local domain |
| **Help Topic** | Password Reset |
| **SLA** | SEV-C (8 hours) |
| **Related Lab** | Lab 01 – Active Directory Basics |
| **Related Incident** | None |

## Problem Statement
User Jane Doe called the help desk reporting she could not log in to her domain workstation. Error message: "Your password has expired and must be changed."

## Questions Asked
1. Are you logging in at your usual workstation? *(Yes)*
2. Do you know your current password? *(Yes)*
3. Is the Caps Lock key off? *(Yes)*

## Troubleshooting Steps
1. Verified account in **AD Users & Computers** — password marked as expired per domain policy.
2. Confirmed account was not locked.
3. Reset password via ADUC: right-click user → Reset Password → set temporary password `Temp!Pass2025`.
4. Checked "User must change password at next logon."

## Resolution
Reset Jane Doe's password to a temporary value and instructed her to change it upon next login. User confirmed successful login.

## Close Notes
Password reset per user request. User confirmed able to log in and change password. No further issues reported.

## Tags
`password-reset` `active-directory` `account-management`

## Time to Resolve
12 minutes
