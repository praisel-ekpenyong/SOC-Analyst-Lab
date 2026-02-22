# Lab 03 – Windows Troubleshooting

## Objective
Use built-in Windows tools (Event Viewer, services.msc, Task Manager, SFC, DISM) to diagnose and resolve common issues. Practice a printer troubleshooting scenario and secure remote support procedures.

## Tools
- Windows 10 Pro VM
- Event Viewer (`eventvwr.msc`)
- Services (`services.msc`)
- Task Manager (`taskmgr`)
- System File Checker (`sfc`)
- DISM
- Print Management (`printmanagement.msc`)

## Diagram Description
```
[Helpdesk Technician]
        |
  [Windows 10 Client VM]
        |
  +-----+-------+----------+---------+
  |             |           |         |
Event Viewer  services.msc  Task Mgr  SFC/DISM
```

## Build Steps

### 1. Event Viewer Basics
1. Open `eventvwr.msc`.
2. Navigate: **Windows Logs → System** — look for Error/Warning events.
3. Navigate: **Windows Logs → Application** — application crashes.
4. Navigate: **Windows Logs → Security** — logon events (4624, 4625, 4648).
5. Filter: Right-click **System → Filter Current Log → Event level: Critical, Error**.

**Key Event IDs:**
| Event ID | Meaning |
|---|---|
| 41 | Unexpected shutdown (kernel power) |
| 7034 | Service crashed unexpectedly |
| 7036 | Service entered running/stopped state |
| 4625 | Failed logon |
| 6006 | Clean shutdown |

### 2. Services Management
```powershell
# View all services
Get-Service | Where-Object {$_.Status -eq "Stopped"}

# Restart a stopped service
Restart-Service -Name "Spooler"

# Set a service to automatic start
Set-Service -Name "Spooler" -StartupType Automatic
```

Or use `services.msc` GUI: right-click a service → Properties → Startup type → Automatic.

### 3. Task Manager – Performance and Processes
1. Open Task Manager → **Processes tab**: identify high CPU/memory consumers.
2. **Performance tab**: monitor CPU, RAM, disk, network in real time.
3. **Startup tab**: disable unnecessary startup programs.
4. **Services tab**: link to services.msc.

### 4. System File Checker and DISM
```cmd
# Run as Administrator
sfc /scannow
# Wait for completion; review log at C:\Windows\Logs\CBS\CBS.log

# If SFC cannot fix issues, run DISM first:
DISM /Online /Cleanup-Image /RestoreHealth
# Then re-run SFC
sfc /scannow
```

### 5. Printer Troubleshooting Scenario

**Scenario:** User reports "printer not printing after driver update."

**Step-by-step:**
1. **Check print queue:** `printmanagement.msc` → Open printer → View print queue.
2. **Clear stuck jobs:**
   ```cmd
   net stop spooler
   del /Q /F /S "%systemroot%\System32\spool\PRINTERS\*.*"
   net start spooler
   ```
3. **Roll back driver:**
   - Device Manager → Printers → Right-click printer → Properties → Driver → Roll Back Driver.
4. **Reinstall driver:**
   - Remove printer → Download manufacturer driver → Re-add printer.
5. **Check Event Viewer:** Application log for print spooler errors.
6. **Verify printer is shared/IP reachable:**
   ```cmd
   ping <printer-IP>
   ```

### 6. Secure Remote Support Checklist
When performing remote support sessions (TeamViewer, Quick Assist, Windows Remote Desktop):

- [ ] Verify caller identity before granting access (employee ID, callback).
- [ ] Use a session code; never give permanent remote access credentials.
- [ ] Inform the user: "I will be taking control of your screen."
- [ ] Do not access files or email unrelated to the ticket.
- [ ] Log the session in the ticketing system with session ID.
- [ ] End session immediately when issue is resolved.
- [ ] Confirm with the user the issue is resolved before disconnecting.
- [ ] Never store user credentials obtained during session.

## Validation Steps
- [ ] Event Viewer shows no unexpected system errors after troubleshooting
- [ ] `sfc /scannow` completes with "no integrity violations found" or "repairs completed"
- [ ] Stopped Print Spooler service restarted successfully
- [ ] Print queue cleared; test page prints successfully
- [ ] Disabled startup programs confirmed via Task Manager

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| SFC shows corrupt files | System corruption | Run DISM then SFC |
| Service won't start | Dependency missing | Check service dependencies in properties |
| Printer offline | Spooler stuck | Clear spool folder; restart Spooler |
| High CPU at startup | Too many startup items | Disable via Task Manager → Startup |
| DISM fails | No internet / WSUS | Use DISM with WIM source file |

## What You Learned
- Navigating Event Viewer to find root-cause events
- Managing Windows services via PowerShell and GUI
- Using SFC and DISM to repair system file corruption
- Resolving printer issues via spooler clear and driver rollback
- Best practices for secure remote support sessions

## Evidence Checklist
- [ ] Screenshot: Event Viewer filtered to Errors and Warnings
- [ ] Screenshot: `sfc /scannow` result
- [ ] Screenshot: DISM /RestoreHealth completed
- [ ] Screenshot: Print queue cleared and printer online
- [ ] Screenshot: Startup programs tab in Task Manager
