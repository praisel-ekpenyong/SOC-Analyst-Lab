# Ticket-007 – Software Installation Request

| Field | Value |
|---|---|
| **Title** | Request to install Adobe Acrobat Reader |
| **Date** | 2025-01-15 |
| **Requester** | Mark Lee (mark.lee@corp.local) |
| **Environment** | Windows 10, corp.local domain |
| **Help Topic** | Software Install |
| **SLA** | SEV-C (8 hours) |
| **Related Lab** | Lab 01 – Active Directory Basics |
| **Related Incident** | None |

## Problem Statement
Mark Lee submitted a ticket requesting installation of Adobe Acrobat Reader DC on his workstation. He needs it to open PDF files shared by Finance.

## Questions Asked
1. Do you have manager approval for this software? *(Yes – confirmed via email)*
2. Is this for personal or business use? *(Business – Finance PDF documents)*
3. Any specific version required? *(Latest free version)*

## Troubleshooting Steps
1. Verified approval email on file.
2. Checked software catalog – Adobe Acrobat Reader DC is pre-approved freeware.
3. Logged in as admin to workstation.
4. Downloaded latest Acrobat Reader from official Adobe site.
5. Installed silently:
   ```cmd
   AcroRdrDC_installer.exe /sAll /rs /msi EULA_ACCEPT=YES
   ```
6. Verified installation: Start → Adobe Acrobat Reader DC.
7. Opened a sample PDF to confirm functionality.

## Resolution
Adobe Acrobat Reader DC installed successfully. User confirmed PDF files open correctly.

## Close Notes
Standard software install per pre-approved catalog. No issues encountered.

## Tags
`software-install` `adobe` `user-request`

## Time to Resolve
20 minutes
