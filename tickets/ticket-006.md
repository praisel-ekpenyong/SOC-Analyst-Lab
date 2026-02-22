# Ticket-006 – Slow PC Performance

| Field | Value |
|---|---|
| **Title** | Computer extremely slow – taking 10+ minutes to boot |
| **Date** | 2025-01-14 |
| **Requester** | Jane Doe (jane.doe@corp.local) |
| **Environment** | Windows 10, Dell OptiPlex 7060 |
| **Help Topic** | Slow Performance |
| **SLA** | SEV-C (8 hours) |
| **Related Lab** | Lab 05 – PowerShell Basics |
| **Related Incident** | Incident-004 – Slow PC Due to Low Disk Space |

## Problem Statement
Jane Doe reports her computer has been getting progressively slower over the past week. Boot time is now over 10 minutes and applications take a long time to open.

## Questions Asked
1. When did this start? *(About a week ago, getting worse each day)*
2. Have you installed any new software recently? *(No)*
3. Are you getting any error messages? *(Occasionally: "Low disk space")*

## Troubleshooting Steps
1. Opened Task Manager – CPU and RAM usage normal at idle.
2. Checked disk usage – **C: drive at 98% full (59.8 GB / 60 GB).**
3. Ran `Get-DiskSpaceReport.ps1` – confirmed 0.2 GB free.
4. Opened **Disk Cleanup** – found 8.5 GB of temporary files and Windows Update cleanup.
5. Ran Disk Cleanup as Administrator – selected all categories including System Files.
6. After cleanup: C: drive at 72% (17 GB free).
7. Reboot – boot time reduced to under 2 minutes.
8. Reviewed startup programs in Task Manager → disabled 4 unnecessary items.

## Resolution
Disk Cleanup removed 17 GB of temporary and update files. Startup programs reduced. PC performance restored.

## Close Notes
Linked to Incident-004. User educated on monitoring disk space. Recommended periodic Disk Cleanup and archive of old files to network share.

## Tags
`slow-performance` `disk-space` `disk-cleanup` `startup`

## Time to Resolve
45 minutes
