<#
.SYNOPSIS
    Exports Windows Event Log entries from System and Application logs to a CSV file.

.DESCRIPTION
    Retrieves Error and Warning events from the System and Application event logs
    for the specified number of past days. Outputs to console and exports to CSV.

.PARAMETER Days
    Number of days back to collect events. Default: 7.

.PARAMETER ExportPath
    Full path for the output CSV file.
    Default: "C:\Reports\EventLogs_<timestamp>.csv"

.PARAMETER LogName
    Comma-separated log names to query. Default: System,Application.

.EXAMPLE
    .\Export-EventLogs.ps1
    .\Export-EventLogs.ps1 -Days 3 -ExportPath "C:\Reports\EventLogs.csv"

.NOTES
    Run as Administrator to access all event logs including Security.
    Reading the Security log without admin rights will produce an access denied error.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$Days = 7,

    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [string[]]$LogName = @('System', 'Application')
)

$startTime = (Get-Date).AddDays(-$Days)

if (-not $ExportPath) {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $ExportPath = "C:\Reports\EventLogs_$timestamp.csv"
}

Write-Host "[INFO] Collecting events from the past $Days day(s)..." -ForegroundColor Cyan

$allEvents = foreach ($log in $LogName) {
    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = $log
            Level     = 1, 2, 3   # Critical, Error, Warning
            StartTime = $startTime
        } -ErrorAction SilentlyContinue |
        Select-Object -Property `
            @{Name = 'TimeCreated'; Expression = { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }},
            @{Name = 'Level';       Expression = { $_.LevelDisplayName }},
            @{Name = 'LogName';     Expression = { $_.LogName }},
            @{Name = 'Id';          Expression = { $_.Id }},
            @{Name = 'Message';     Expression = { ($_.Message -split "`n")[0] }}
    } catch {
        Write-Warning "Could not read log '$log': $_"
    }
}

if ($allEvents) {
    $allEvents | Format-Table -AutoSize

    try {
        $exportDir = Split-Path -Path $ExportPath -Parent
        if ($exportDir -and -not (Test-Path -Path $exportDir)) {
            New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
        }
        $allEvents | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "[INFO] Exported $($allEvents.Count) events to: $ExportPath" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export: $_"
    }
} else {
    Write-Host "[INFO] No matching events found for the specified time range and log names." -ForegroundColor Yellow
}
