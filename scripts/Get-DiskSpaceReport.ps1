<#
.SYNOPSIS
    Reports disk space usage for all local fixed drives.

.DESCRIPTION
    Retrieves disk space information (total, used, free) for all local fixed
    drives and displays a formatted report. Optionally exports the report to CSV.

.PARAMETER ExportPath
    Optional. Full path to export the report as a CSV file.
    Example: -ExportPath "C:\Reports\DiskReport.csv"

.EXAMPLE
    .\Get-DiskSpaceReport.ps1
    .\Get-DiskSpaceReport.ps1 -ExportPath "C:\Reports\DiskReport.csv"

.NOTES
    Safe for use in production environments.
    Run as standard user (no admin rights required for local drives).
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ExportPath
)

# Collect disk information
$diskData = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType = 3" |
    Select-Object -Property `
        @{Name = 'Drive';       Expression = { $_.DeviceID }},
        @{Name = 'TotalGB';     Expression = { [math]::Round($_.Size / 1GB, 2) }},
        @{Name = 'UsedGB';      Expression = { [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2) }},
        @{Name = 'FreeGB';      Expression = { [math]::Round($_.FreeSpace / 1GB, 2) }},
        @{Name = 'FreePercent'; Expression = {
            if ($_.Size -gt 0) {
                "{0:N2}%" -f (($_.FreeSpace / $_.Size) * 100)
            } else {
                "N/A"
            }
        }}

# Display to console
$diskData | Format-Table -AutoSize

# Export to CSV if path provided
if ($ExportPath) {
    try {
        $exportDir = Split-Path -Path $ExportPath -Parent
        if ($exportDir -and -not (Test-Path -Path $exportDir)) {
            New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
        }
        $diskData | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
        Write-Host "[INFO] Report exported to: $ExportPath" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to export report: $_"
    }
}
