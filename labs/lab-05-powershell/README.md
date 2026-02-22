# Lab 05 – PowerShell Basics for IT Support

## Objective
Write and run three practical PowerShell scripts used in everyday IT support tasks. Understand how to run scripts safely, interpret output, and handle common errors.

## Tools
- Windows 10 or Windows Server 2019
- PowerShell 5.1 (built-in) or PowerShell 7.x

## Diagram Description
```
[IT Technician]
     |
[PowerShell ISE / Terminal]
     |
     +-- Get-DiskSpaceReport.ps1  --> CSV Report
     +-- Export-EventLogs.ps1     --> CSV Event Log Export
     +-- Reset-LocalPassword.ps1  --> Password Reset (Demo)
```

## Build Steps

### 1. Execution Policy Setup
Before running scripts, set the execution policy (once, as Admin):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 2. Script 1 – Get-DiskSpaceReport.ps1

**Purpose:** Reports free and used disk space on all local drives. Outputs to console and optional CSV.

**Location:** `/scripts/Get-DiskSpaceReport.ps1`

**How to run:**
```powershell
.\Get-DiskSpaceReport.ps1
.\Get-DiskSpaceReport.ps1 -ExportPath "C:\Reports\DiskReport.csv"
```

**Expected output:**
```
Drive  TotalGB  UsedGB  FreeGB  FreePercent
-----  -------  ------  ------  -----------
C:     59.88    22.14   37.74   63.03%
D:     99.99    45.00   54.99   55.00%
```

**Common errors:**
| Error | Cause | Fix |
|---|---|---|
| Access denied on export | No write permission to path | Run as Admin or change export path |
| No drives returned | Network drives excluded | Script targets local drives only |

### 3. Script 2 – Export-EventLogs.ps1

**Purpose:** Exports Windows Event Log entries (System and Application) from the past N days to a CSV file.

**Location:** `/scripts/Export-EventLogs.ps1`

**How to run:**
```powershell
.\Export-EventLogs.ps1 -Days 7 -ExportPath "C:\Reports\EventLogs.csv"
```

**Expected output:**
```
TimeCreated             Level    LogName      Id    Message
-------------------     -----    -------      --    -------
2025-01-15 08:32:11     Error    System       7034  The Print Spooler service terminated unexpectedly.
2025-01-15 09:01:44     Warning  Application  1001  Windows Error Reporting
```

**Common errors:**
| Error | Cause | Fix |
|---|---|---|
| Access denied reading Security log | Not running as admin | Run PowerShell as Administrator |
| Empty CSV | No events in date range | Adjust `-Days` parameter |

### 4. Script 3 – Reset-LocalPassword.ps1

**Purpose:** Resets a local user account password. Safe demo with warnings — do NOT use for domain accounts without change control.

**Location:** `/scripts/Reset-LocalPassword.ps1`

**How to run:**
```powershell
.\Reset-LocalPassword.ps1 -UserName "localuser" -NewPassword "TempP@ss123!"
```

**Expected output:**
```
[WARNING] This script resets LOCAL account passwords only.
[WARNING] Ensure this action is authorized and documented in your ticketing system.
[INFO] Resetting password for local user: localuser
[SUCCESS] Password reset successfully for: localuser
[INFO] Please instruct the user to change their password on next logon.
```

**Common errors:**
| Error | Cause | Fix |
|---|---|---|
| User not found | Wrong username | `Get-LocalUser` to list users |
| Password does not meet requirements | Complexity rules | Use a password meeting complexity policy |
| Access denied | Not running as admin | Run PowerShell as Administrator |

## Validation Steps
- [ ] All three scripts run without errors on test machine
- [ ] `Get-DiskSpaceReport.ps1` produces accurate drive data matching `Get-PSDrive`
- [ ] `Export-EventLogs.ps1` CSV contains timestamped events
- [ ] `Reset-LocalPassword.ps1` shows all warning messages and confirms success
- [ ] CSV files created at specified export paths

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "not digitally signed" error | Execution policy | `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| Script runs but outputs nothing | Logic issue / no data | Add `-Verbose` or debug with `Write-Host` |
| CSV file not created | Path does not exist | `New-Item -ItemType Directory -Path "C:\Reports"` |

## What You Learned
- Setting PowerShell execution policy safely
- Writing scripts with parameters, output formatting, and error handling
- Generating disk space reports and exporting event logs
- Safely resetting local passwords with appropriate warnings
- Practical IT support automation patterns

## Evidence Checklist
- [ ] Screenshot: `Get-DiskSpaceReport.ps1` output in terminal
- [ ] Screenshot: Exported CSV opened in Notepad or Excel
- [ ] Screenshot: `Export-EventLogs.ps1` CSV with events
- [ ] Screenshot: `Reset-LocalPassword.ps1` output with warning messages
