# Ticket-005 – Printer Not Printing

| Field | Value |
|---|---|
| **Title** | Printer stopped working after driver update |
| **Date** | 2025-01-13 |
| **Requester** | Mark Lee (mark.lee@corp.local) |
| **Environment** | Windows 10, HP LaserJet Pro M404dn |
| **Help Topic** | Printer Issue |
| **SLA** | SEV-C (8 hours) |
| **Related Lab** | Lab 03 – Windows Troubleshooting |
| **Related Incident** | Incident-003 – Printer Not Printing After Driver Update |

## Problem Statement
Mark Lee reports the office printer stopped working immediately after Windows pushed a printer driver update overnight. Print jobs are stuck in the queue.

## Questions Asked
1. When did the issue start? *(This morning after restart)*
2. Is the printer physically powered on and online? *(Yes)*
3. Are other users affected? *(Yes – 3 others in the Finance department)*

## Troubleshooting Steps
1. Opened **Print Management** – found 7 jobs stuck in queue, spooler in error state.
2. Stopped Print Spooler service:
   ```cmd
   net stop spooler
   ```
3. Cleared spool folder:
   ```cmd
   del /Q /F /S "%systemroot%\System32\spool\PRINTERS\*.*"
   ```
4. Started Print Spooler:
   ```cmd
   net start spooler
   ```
5. Printer still showed offline – rolled back driver via Device Manager.
6. Printer came online; test page printed successfully.
7. Updated all affected workstations (pushed Group Policy printer redeploy).

## Resolution
Cleared stuck print queue, rolled back problematic driver update. Printer restored to working state. All 4 affected users confirmed printing.

## Close Notes
Linked to Incident-003. Driver rollback resolved the issue. Automated driver updates for this printer model flagged for exclusion in WSUS.

## Tags
`printer` `driver` `print-spooler` `windows-update`

## Time to Resolve
35 minutes
