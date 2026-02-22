# Incident-004 – Slow PC Due to Low Disk Space

## Summary
A user's workstation became critically slow due to the C: drive being 98% full (59.8 GB used out of 60 GB). The root cause was months of accumulated temporary files, Windows Update cache, and browser caches that were never cleaned. Performance was fully restored after a Disk Cleanup and startup optimization.

## Severity
**SEV-C (Medium)** – Single user affected; workaround available; productivity impacted but no data loss.

## Impact
- User unable to work effectively for approximately 1 week (gradual degradation)
- Boot time: 10+ minutes
- Application open time: 3–5 minutes each
- 1 ticket generated (Ticket-006)

## Timeline

| Time | Event |
|---|---|
| 2025-01-07 | User first notices PC "getting slower" |
| 2025-01-10 | Occasional "Low disk space" balloon notifications begin appearing |
| 2025-01-14 | User submits Ticket-006 |
| 2025-01-14 09:00 | Technician connects and runs `Get-DiskSpaceReport.ps1` |
| 2025-01-14 09:05 | C: drive confirmed at 98% full (0.2 GB free) |
| 2025-01-14 09:10 | Disk Cleanup initiated (admin mode) |
| 2025-01-14 09:25 | Cleanup complete — 17 GB freed |
| 2025-01-14 09:30 | Startup programs optimized |
| 2025-01-14 09:35 | Reboot — boot time under 2 minutes |
| 2025-01-14 09:40 | User confirmed PC running normally |

## Detection
User submitted Ticket-006 after PC became "unusably slow." Technician immediately ran `Get-DiskSpaceReport.ps1` which revealed only 0.2 GB free on the C: drive. The `Get-DiskSpaceReport.ps1` PowerShell script from Lab 05 was used to quickly confirm and document the disk space situation.

## Triage
1. Task Manager: CPU normal (5%), RAM normal (3.2/8 GB used).
2. `Get-DiskSpaceReport.ps1` output:
   ```
   Drive  TotalGB  UsedGB  FreeGB  FreePercent
   C:     59.88    59.68   0.20    0.33%
   ```
3. Disk Cleanup preview revealed:
   - Temporary Internet Files: 2.1 GB
   - Windows Update Cleanup: 8.5 GB
   - Temporary Files: 4.3 GB
   - Recycle Bin: 2.1 GB
   - Total available: 17 GB

## Root Cause
No disk space management policy or alert was in place. The user's workstation accumulated Windows Update cleanup files, temporary files, and cached data over several months without any scheduled cleanup. The near-full disk caused severe virtual memory (page file) and OS performance degradation.

## Fix
1. Ran Disk Cleanup as Administrator on C: drive.
2. Selected all cleanup categories including "System Files" (Windows Update cleanup).
3. Deleted 17 GB of files.
4. Opened Task Manager → Startup tab → disabled 4 non-essential startup programs.
5. Restarted workstation.
6. Verified: C: drive at 28% full (17 GB free); boot time 1 minute 45 seconds.

## Validation
- `Get-DiskSpaceReport.ps1` post-cleanup:
  ```
  Drive  TotalGB  UsedGB  FreeGB  FreePercent
  C:     59.88    42.88   17.00   28.37%
  ```
- Boot time timed at 1 minute 45 seconds (vs 10+ minutes before).
- Application open times: normal (< 10 seconds).
- User confirmed satisfactory performance.

## Preventive Actions
- [ ] Deploy scheduled Disk Cleanup task via GPO (monthly, System Files included)
- [ ] Configure disk space monitoring: alert when C: drive exceeds 85% usage
- [ ] Educate users to move large files (photos, downloads) to network share
- [ ] Use `Get-DiskSpaceReport.ps1` as standard first-step diagnostic for slow PC tickets
- [ ] Consider upgrading workstations with < 128 GB SSD to larger storage

## Customer Communication

> **From:** IT Help Desk  
> **To:** Jane Doe  
> **Subject:** Resolved – Slow Computer Issue  
>
> Hi Jane,
>
> Great news — your computer has been fixed and should be running much faster now!
>
> **What was wrong:** Your computer's hard drive was almost completely full (less than 1% free space), which caused everything to slow down significantly.
>
> **What we did:** We ran a Disk Cleanup that freed up 17 GB of space (old temporary files, Windows updates, and cached data). We also optimized your startup programs.
>
> **What you can do to help:** Try to keep your Downloads folder cleaned out, and move large files (photos, videos) to the Finance network share (\\\\DC01\\FinanceShare) instead of saving them on your local C: drive.
>
> Your computer will now receive automated monthly cleanups. If you notice it slowing down again, please don't hesitate to contact us.
>
> — IT Help Desk

## Related Tickets
- [Ticket-006 – Slow PC Performance](../tickets/ticket-006.md)
