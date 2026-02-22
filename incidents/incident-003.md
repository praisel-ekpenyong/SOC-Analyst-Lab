# Incident-003 – Printer Not Printing After Driver Update

## Summary
An overnight Windows Update pushed a new printer driver for the HP LaserJet Pro M404dn shared printer, causing all print jobs to fail and the print spooler to enter an error state on 4 workstations in the Finance department.

## Severity
**SEV-C (Medium)** – 4 users affected; workaround (PDF) available; no data loss.

## Impact
- 4 Finance workstations unable to print
- Print queue accumulated 20+ stuck jobs
- Finance staff temporarily unable to print documents for morning meeting
- 2 tickets generated (Ticket-005 representative)

## Timeline

| Time | Event |
|---|---|
| 02:00 | Windows Update ran overnight; new HP printer driver installed automatically |
| 08:30 | First user (Mark Lee) reports printer not working (Ticket-005) |
| 08:35 | 3 additional users report same issue |
| 08:40 | Help desk identifies shared HP printer affected on all Finance workstations |
| 08:50 | Print spooler cleared; driver rollback initiated on first workstation |
| 09:05 | Driver rolled back on all 4 workstations |
| 09:10 | All workstations printing successfully |
| 09:15 | WSUS exclusion rule added for HP LaserJet driver updates |

## Detection
Ticket-005 submitted by Mark Lee at 08:30. Agent noticed multiple users reporting the same printer at the same time. Correlation with overnight Windows Update log confirmed driver update as the trigger.

## Triage
1. Confirmed all affected users share the same HP LaserJet Pro M404dn printer.
2. Checked Windows Update history on first affected machine — HP driver `hplenumx64.inf` updated at 02:14 AM.
3. Print spooler service was in a stopped/error state on all 4 machines.
4. Queue contained 7–20 stuck jobs per machine.

## Root Cause
Windows Update automatically deployed an incompatible HP LaserJet printer driver overnight. The new driver caused the Windows Print Spooler service to enter a crash loop, making all print jobs fail.

## Fix
On each affected workstation:
1. Stopped Print Spooler:
   ```cmd
   net stop spooler
   ```
2. Cleared spool folder:
   ```cmd
   del /Q /F /S "%systemroot%\System32\spool\PRINTERS\*.*"
   ```
3. Started Print Spooler:
   ```cmd
   net start spooler
   ```
4. Rolled back driver via Device Manager → Printers → HP LaserJet Pro M404dn → Properties → Driver → Roll Back Driver.
5. Verified printing with test page.

## Validation
- Test page printed successfully on all 4 workstations.
- Print Spooler service running on all machines.
- No new print-related tickets received after resolution.

## Preventive Actions
- [ ] Add HP LaserJet Pro M404dn driver to WSUS exclusion list
- [ ] Test printer driver updates on a single workstation before domain-wide deployment
- [ ] Document printer driver versions in hardware inventory
- [ ] Create runbook: "Clear print spooler and roll back driver" for Tier 1

## Customer Communication

> **From:** IT Help Desk  
> **To:** Finance Department  
> **Subject:** Resolved – Printer Issue This Morning  
>
> Dear Finance Team,
>
> The printer issue affecting the HP LaserJet Pro M404dn this morning has been fully resolved as of 9:10 AM.
>
> **Cause:** An overnight Windows Update installed a printer driver that was incompatible with the printer.  
> **Resolution:** We rolled back the driver update and cleared the print queue on all affected workstations.
>
> Your printers are now fully operational. Any print jobs you attempted this morning will need to be re-submitted.
>
> We apologize for the inconvenience and have taken steps to prevent similar issues in the future.
>
> — IT Help Desk

## Related Tickets
- [Ticket-005 – Printer Not Printing After Driver Update](../tickets/ticket-005.md)
