# Ticket-011 – Windows Update Failing

| Field | Value |
|---|---|
| **Title** | Windows Update stuck at 0% – KB5034441 failing |
| **Date** | 2025-01-21 |
| **Requester** | Mark Lee (mark.lee@corp.local) |
| **Environment** | Windows 10 22H2, Dell OptiPlex |
| **Help Topic** | Software Install |
| **SLA** | SEV-C (8 hours) |
| **Related Lab** | Lab 03 – Windows Troubleshooting |
| **Related Incident** | None |

## Problem Statement
Mark Lee reports Windows Update has been stuck trying to install KB5034441 for three days. It downloads but fails to install, reverting each time.

## Questions Asked
1. Any error code shown? *(Error 0x80070643)*
2. How much free space on C:? *(About 12 GB)*
3. Is the device managed by WSUS/Intune? *(WSUS, but we're testing locally)*

## Troubleshooting Steps
1. Ran Windows Update Troubleshooter: **Settings → Update & Security → Troubleshoot**.
2. Error persisted – reset Windows Update components:
   ```cmd
   net stop wuauserv
   net stop cryptsvc
   net stop bits
   ren C:\Windows\SoftwareDistribution SoftwareDistribution.bak
   ren C:\Windows\System32\catroot2 catroot2.bak
   net start wuauserv
   net start cryptsvc
   net start bits
   ```
3. Ran `sfc /scannow` – found and repaired 2 corrupted files.
4. Ran `DISM /Online /Cleanup-Image /RestoreHealth`.
5. Restarted and re-ran Windows Update – KB5034441 installed successfully.

## Resolution
Windows Update components reset and system file corruption repaired via SFC and DISM. Update installed successfully after repair.

## Close Notes
Standard Windows Update repair procedure. No recurring issues expected.

## Tags
`windows-update` `sfc` `dism` `update-failure`

## Time to Resolve
55 minutes
