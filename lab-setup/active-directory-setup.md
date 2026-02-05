# Active Directory Domain Setup

## Overview

This document describes building a Windows Server 2019 Active Directory environment that simulates a small enterprise with realistic organizational units, users, and security policies. The domain serves as the authentication backbone for the lab and provides a target-rich environment for testing domain-based attacks.

## Domain Design

**Domain Name:** soclab.local  
**NetBIOS Name:** SOCLAB  
**Functional Level:** Windows Server 2016  
**Domain Controller:** DC01 (10.0.0.10)

## Initial Server Configuration

### Set Static IP and Hostname

After installing Windows Server 2019 with Desktop Experience:

Open PowerShell as Administrator and configure networking:

```powershell
# Configure static IP
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.0.0.10 -PrefixLength 24 -DefaultGateway 10.0.0.1

# Set DNS to point to self (will be DC)
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.10

# Rename computer
Rename-Computer -NewName "DC01" -Restart
```

After reboot, verify configuration:
```powershell
Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress, InterfaceAlias
```

## Promote to Domain Controller

### Install AD DS Role

```powershell
# Install Active Directory Domain Services
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

### Create New Forest

```powershell
# Import AD DS Deployment module
Import-Module ADDSDeployment

# Promote server to domain controller
Install-ADDSForest `
    -DomainName "soclab.local" `
    -DomainNetbiosName "SOCLAB" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -NoRebootOnCompletion:$false `
    -Force:$true
```

You'll be prompted for Safe Mode Administrator Password. Choose a strong password and save it securely.

Server will reboot automatically. After reboot, you now have a functioning domain controller.

### Verify Domain Services

```powershell
# Check ADDS service
Get-Service NTDS

# Verify domain
Get-ADDomain | Select-Object Name, DomainMode, Forest

# Check DNS zones
Get-DnsServerZone | Where-Object {$_.IsAutoCreated -eq $false}
```

## Organizational Unit Structure

Creating a realistic OU structure helps simulate enterprise environments where users have different access levels and group policies.

### Create Top-Level OUs

```powershell
# Create department OUs
New-ADOrganizationalUnit -Name "IT" -Path "DC=soclab,DC=local"
New-ADOrganizationalUnit -Name "Finance" -Path "DC=soclab,DC=local"
New-ADOrganizationalUnit -Name "HR" -Path "DC=soclab,DC=local"
New-ADOrganizationalUnit -Name "Executives" -Path "DC=soclab,DC=local"
New-ADOrganizationalUnit -Name "Contractors" -Path "DC=soclab,DC=local"

# Create sub-OUs for computers
New-ADOrganizationalUnit -Name "Workstations" -Path "DC=soclab,DC=local"
New-ADOrganizationalUnit -Name "Servers" -Path "DC=soclab,DC=local"
```

### Verify OU Structure

```powershell
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName | Sort-Object Name
```

## User Account Creation

Creating diverse user accounts with different privilege levels allows testing of privilege escalation, lateral movement, and account compromise scenarios.

### Create Standard Users

```powershell
# Finance Department Users
New-ADUser -Name "Alice Chen" -GivenName "Alice" -Surname "Chen" `
    -SamAccountName "a.chen" -UserPrincipalName "a.chen@soclab.local" `
    -Path "OU=Finance,DC=soclab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Finance2026!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $false

New-ADUser -Name "Robert Kim" -GivenName "Robert" -Surname "Kim" `
    -SamAccountName "r.kim" -UserPrincipalName "r.kim@soclab.local" `
    -Path "OU=Finance,DC=soclab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Finance2026!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $false

# HR Department Users
New-ADUser -Name "Maria Johnson" -GivenName "Maria" -Surname "Johnson" `
    -SamAccountName "m.johnson" -UserPrincipalName "m.johnson@soclab.local" `
    -Path "OU=HR,DC=soclab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "HumanRes2026!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $false

New-ADUser -Name "Sarah Martinez" -GivenName "Sarah" -Surname "Martinez" `
    -SamAccountName "s.martinez" -UserPrincipalName "s.martinez@soclab.local" `
    -Path "OU=HR,DC=soclab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "HumanRes2026!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $false

# IT Department Users
New-ADUser -Name "James Martinez" -GivenName "James" -Surname "Martinez" `
    -SamAccountName "j.martinez" -UserPrincipalName "j.martinez@soclab.local" `
    -Path "OU=IT,DC=soclab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "ITSupport2026!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $false

New-ADUser -Name "Thomas Williams" -GivenName "Thomas" -Surname "Williams" `
    -SamAccountName "t.williams" -UserPrincipalName "t.williams@soclab.local" `
    -Path "OU=IT,DC=soclab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "ITSupport2026!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $false

# Executive Users
New-ADUser -Name "David Roberts" -GivenName "David" -Surname "Roberts" `
    -SamAccountName "d.roberts" -UserPrincipalName "d.roberts@soclab.local" `
    -Path "OU=Executives,DC=soclab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Executive2026!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $false

New-ADUser -Name "Jennifer Lee" -GivenName "Jennifer" -Surname "Lee" `
    -SamAccountName "j.lee" -UserPrincipalName "j.lee@soclab.local" `
    -Path "OU=Executives,DC=soclab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Executive2026!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $false

# Additional users for attack simulation
New-ADUser -Name "Test User1" -GivenName "Test" -Surname "User1" `
    -SamAccountName "test.user1" -UserPrincipalName "test.user1@soclab.local" `
    -Path "OU=IT,DC=soclab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "TestPass123!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $false

New-ADUser -Name "Test User2" -GivenName "Test" -Surname "User2" `
    -SamAccountName "test.user2" -UserPrincipalName "test.user2@soclab.local" `
    -Path "OU=Finance,DC=soclab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "TestPass123!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $false
```

## Security Group Creation

### Create Department Groups

```powershell
# Department access groups
New-ADGroup -Name "Finance-Users" -GroupScope Global -GroupCategory Security `
    -Path "OU=Finance,DC=soclab,DC=local"

New-ADGroup -Name "HR-Users" -GroupScope Global -GroupCategory Security `
    -Path "OU=HR,DC=soclab,DC=local"

New-ADGroup -Name "IT-Support" -GroupScope Global -GroupCategory Security `
    -Path "OU=IT,DC=soclab,DC=local"

New-ADGroup -Name "IT-Administrators" -GroupScope Global -GroupCategory Security `
    -Path "OU=IT,DC=soclab,DC=local"

New-ADGroup -Name "Executive-Team" -GroupScope Global -GroupCategory Security `
    -Path "OU=Executives,DC=soclab,DC=local"
```

### Add Users to Groups

```powershell
# Add Finance users
Add-ADGroupMember -Identity "Finance-Users" -Members "a.chen","r.kim","test.user2"

# Add HR users
Add-ADGroupMember -Identity "HR-Users" -Members "m.johnson","s.martinez"

# Add IT users
Add-ADGroupMember -Identity "IT-Support" -Members "j.martinez","t.williams","test.user1"

# Add IT admin (elevated privileges)
Add-ADGroupMember -Identity "IT-Administrators" -Members "t.williams"
Add-ADGroupMember -Identity "Domain Admins" -Members "t.williams"

# Add Executives
Add-ADGroupMember -Identity "Executive-Team" -Members "d.roberts","j.lee"
```

### Verify Group Membership

```powershell
# Check who's in each group
Get-ADGroupMember -Identity "IT-Administrators" | Select-Object Name
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name
```

## Join Windows 10 to Domain

On Windows 10 workstation (WS-FIN-PC01):

### Configure DNS to Point to DC

```powershell
# Set DNS to domain controller
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.10

# Verify DNS resolution
nslookup soclab.local
```

Should return 10.0.0.10.

### Join Domain

```powershell
# Join to domain
Add-Computer -DomainName "soclab.local" -Credential (Get-Credential) -Restart
```

When prompted, enter Domain Admin credentials (Administrator@soclab.local).

After reboot, verify:
```powershell
(Get-WmiObject Win32_ComputerSystem).Domain
```

Should return: `soclab.local`

### Move Computer to Correct OU

On DC01:
```powershell
# Find computer object
Get-ADComputer -Identity "WS-FIN-PC01"

# Move to Workstations OU
Move-ADObject -Identity "CN=WS-FIN-PC01,CN=Computers,DC=soclab,DC=local" `
    -TargetPath "OU=Workstations,DC=soclab,DC=local"
```

## Advanced Audit Policy Configuration

Enhanced logging is critical for security monitoring.

### Enable Advanced Audit Policies

```powershell
# Enable comprehensive auditing
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable

# Verify settings
auditpol /get /category:*
```

### Enable PowerShell Script Block Logging

```powershell
# Create registry path if needed
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force

# Enable script block logging
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1
```

This logs all PowerShell commands executed on the system - essential for detecting malicious PowerShell usage.

## Create Shared Network Resources

Simulate file shares for testing lateral movement and data exfiltration.

### Create Shared Folders

```powershell
# Create directories
New-Item -Path "C:\Shares\Finance-Reports" -ItemType Directory
New-Item -Path "C:\Shares\HR-Documents" -ItemType Directory
New-Item -Path "C:\Shares\Executive-Reports" -ItemType Directory

# Create SMB shares
New-SmbShare -Name "Finance$" -Path "C:\Shares\Finance-Reports" `
    -FullAccess "SOCLAB\Finance-Users" -ReadAccess "SOCLAB\Executive-Team"

New-SmbShare -Name "HR$" -Path "C:\Shares\HR-Documents" `
    -FullAccess "SOCLAB\HR-Users"

New-SmbShare -Name "Executive$" -Path "C:\Shares\Executive-Reports" `
    -FullAccess "SOCLAB\Executive-Team" -ReadAccess "SOCLAB\IT-Administrators"

# Verify shares
Get-SmbShare | Where-Object {$_.Name -like "*$"}
```

### Test Share Access

From Windows 10 workstation, log in as a.chen and access:
```
\\DC01\Finance$
```

Should be accessible. Attempt to access `\\DC01\HR$` - should be denied.

## Security Hardening Recommendations

While this is a lab environment designed for attack testing, consider these production best practices:

### Password Policy

```powershell
# View current policy
Get-ADDefaultDomainPasswordPolicy

# Example hardening (not required for lab)
Set-ADDefaultDomainPasswordPolicy -Identity soclab.local `
    -MinPasswordLength 14 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge 90.00:00:00 `
    -MinPasswordAge 1.00:00:00 `
    -ComplexityEnabled $true
```

### Account Lockout Policy

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity soclab.local `
    -LockoutThreshold 5 `
    -LockoutDuration 00:30:00 `
    -LockoutObservationWindow 00:30:00
```

This will lock accounts after 5 failed attempts for 30 minutes - important for brute force testing.

## Verification Checklist

- [ ] DC01 responds to ping from workstation
- [ ] DNS resolution working: `nslookup soclab.local` returns 10.0.0.10
- [ ] Windows 10 successfully joined to domain
- [ ] Can log into Windows 10 with domain accounts (test with a.chen@soclab.local)
- [ ] Group Policy applied on workstation: `gpupdate /force`
- [ ] Network shares accessible from workstation
- [ ] Advanced audit policies enabled on both DC and workstation
- [ ] PowerShell logging configured
- [ ] At least 8 user accounts created across different OUs
- [ ] Security groups created and populated
- [ ] At least one user in Domain Admins for admin testing

## Attack Surface Summary

This domain configuration provides multiple attack vectors for testing:

**Credential Access:**
- Users with weak/common passwords (for brute force testing)
- Privileged account (t.williams) for privilege escalation scenarios

**Lateral Movement:**
- Multiple workstations (expand by adding more Windows 10 VMs)
- SMB shares with varying permissions
- RDP enabled for remote access testing

**Persistence:**
- Registry Run keys monitored
- Scheduled tasks capability
- GPO modification (for advanced scenarios)

**Discovery:**
- LDAP queries to enumerate users/groups
- Network share enumeration
- Domain trust relationships

## Backup and Snapshot

Before running attack simulations:

```powershell
# Create System State backup
wbadmin start systemstatebackup -backupTarget:C:\Backups
```

Or in VirtualBox: Take snapshot named "Clean Domain - Pre-Attack"

This allows quick restoration after destructive testing.

## Next Steps

1. Test domain authentication from workstation with various user accounts
2. Install Sysmon on DC01 to monitor domain controller activity
3. Configure Splunk Universal Forwarder on DC01
4. Begin testing detection rules with Atomic Red Team
5. Simulate attacks: brute force, pass-the-hash, Kerberoasting

## Common Issues

**Workstation can't join domain:**
- Verify DNS is set to 10.0.0.10, not ISP DNS
- Ping DC01 successfully
- Check firewall allows SMB (445) and RPC (135)

**Group Policy not applying:**
- Run `gpupdate /force` on workstation
- Check `gpresult /r` to see applied policies
- Verify workstation is in correct OU

**Can't log in with domain account:**
- Verify account is enabled: `Get-ADUser -Identity "a.chen"`
- Check account lockout status
- Review Security event log (Event ID 4625) for failure reason

## Reference

User Account Summary for easy reference during testing:

| Username | Department | Privileges | Password | Notes |
|----------|-----------|------------|----------|-------|
| a.chen | Finance | Standard | Finance2026! | Target for phishing |
| r.kim | Finance | Standard | Finance2026! | |
| m.johnson | HR | Standard | HumanRes2026! | Target for malware testing |
| s.martinez | HR | Standard | HumanRes2026! | |
| j.martinez | IT | Standard | ITSupport2026! | Target for credential theft |
| t.williams | IT | Domain Admin | ITSupport2026! | High-value target |
| d.roberts | Executive | Standard | Executive2026! | Data exfiltration scenario |
| j.lee | Executive | Standard | Executive2026! | |
| test.user1 | IT | Standard | TestPass123! | Attack testing |
| test.user2 | Finance | Standard | TestPass123! | Attack testing |
