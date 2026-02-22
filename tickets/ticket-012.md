# Ticket-012 – New User Onboarding Setup

| Field | Value |
|---|---|
| **Title** | IT setup for new hire – account, workstation, access |
| **Date** | 2025-01-27 |
| **Requester** | HR Department (hr@corp.local) on behalf of Tom Brown |
| **Environment** | Windows 10, corp.local domain |
| **Help Topic** | Other / General |
| **SLA** | SEV-B (4 hours) |
| **Related Lab** | Lab 01 – Active Directory Basics |
| **Related Incident** | None |

## Problem Statement
HR submitted an onboarding ticket for new hire Tom Brown (Finance department, starting 2025-01-28). IT must create AD account, configure workstation, set up email, and provide access to Finance file shares.

## Questions Asked
1. Start date and department confirmed? *(2025-01-28, Finance)*
2. Manager name for approval? *(Carol White, Finance Manager)*
3. Any special access requirements? *(Finance shared drive, PDF tools)*

## Troubleshooting Steps
1. Created AD user account:
   ```powershell
   New-ADUser -Name "Tom Brown" -SamAccountName "tbrown" -UserPrincipalName "tbrown@corp.local" `
     -Path "OU=Finance,DC=corp,DC=local" `
     -AccountPassword (ConvertTo-SecureString "Welcome!2025" -AsPlainText -Force) `
     -Enabled $true -ChangePasswordAtLogon $true
   ```
2. Added to Finance group: `Add-ADGroupMember -Identity "Finance-Staff" -Members "tbrown"`.
3. Configured workstation: domain join, profile setup.
4. Mapped Finance share: `\\DC01\FinanceShare`.
5. Installed Adobe Acrobat Reader.
6. Set up Outlook profile with Exchange/IMAP settings.
7. Confirmed workstation login as `tbrown` with temp password.
8. Sent welcome email with IT Quick Start Guide to Tom Brown and his manager.

## Resolution
New user account created, workstation configured, email set up, and file share access granted. User ready for Day 1.

## Close Notes
Full onboarding completed per HR checklist. Workstation tagged and asset record updated.

## Tags
`onboarding` `new-user` `active-directory` `workstation-setup`

## Time to Resolve
90 minutes
