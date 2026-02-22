<#
.SYNOPSIS
    Resets a local user account password on the current machine.

.DESCRIPTION
    SAFE DEMO SCRIPT – Resets a LOCAL (non-domain) user account password.
    This script is intended for authorized IT support use only.

    WARNING: Do NOT use this script for domain account password resets.
    Domain accounts must be managed through Active Directory (ADUC or PowerShell AD module).
    Always document password resets in your ticketing system before running this script.

.PARAMETER UserName
    The local username whose password will be reset.

.PARAMETER NewPassword
    The new password to set. Must meet local complexity requirements.
    If not provided, the script will prompt securely.

.PARAMETER ForceChangeAtLogon
    If specified, the user will be required to change their password at next logon.
    Note: This flag is informational only for local accounts on non-domain machines.

.EXAMPLE
    .\Reset-LocalPassword.ps1 -UserName "localuser" -NewPassword "TempP@ss123!"
    .\Reset-LocalPassword.ps1 -UserName "localuser"

.NOTES
    REQUIRES: Run as Administrator.
    AUTHORIZATION: Ensure this action is approved and logged in your ticketing system.
    SCOPE: Local accounts ONLY. Not for domain accounts.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$UserName,

    [Parameter(Mandatory = $false)]
    [string]$NewPassword,

    [Parameter(Mandatory = $false)]
    [switch]$ForceChangeAtLogon
)

# Security warnings
Write-Warning "This script resets LOCAL account passwords only."
Write-Warning "Ensure this action is authorized and documented in your ticketing system."
Write-Warning "Do NOT use for domain accounts — use Active Directory instead."
Write-Host ""

# Verify running as Administrator
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Please re-launch PowerShell as Admin."
    exit 1
}

# Verify the local user exists
try {
    $localUser = Get-LocalUser -Name $UserName -ErrorAction Stop
} catch {
    Write-Error "Local user '$UserName' not found. Use Get-LocalUser to list available users."
    exit 1
}

Write-Host "[INFO] Resetting password for local user: $UserName" -ForegroundColor Cyan

# If password not provided as parameter, prompt securely
if (-not $NewPassword) {
    $securePassword = Read-Host -Prompt "Enter new password for '$UserName'" -AsSecureString
} else {
    $securePassword = ConvertTo-SecureString -String $NewPassword -AsPlainText -Force
}

# Reset the password
try {
    if ($PSCmdlet.ShouldProcess($UserName, "Reset local account password")) {
        $localUser | Set-LocalUser -Password $securePassword
        Write-Host "[SUCCESS] Password reset successfully for: $UserName" -ForegroundColor Green

        if ($ForceChangeAtLogon) {
            Write-Host "[INFO] Note: ForceChangeAtLogon is set. Instruct the user to change their password on next logon." -ForegroundColor Yellow
        }

        Write-Host "[INFO] Please instruct the user to change their password on next logon." -ForegroundColor Yellow
        Write-Host "[INFO] Document this action in your ticketing system." -ForegroundColor Yellow
    }
} catch {
    Write-Error "Failed to reset password for '$UserName': $_"
    exit 1
}
