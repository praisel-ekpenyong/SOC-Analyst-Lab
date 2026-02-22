# Lab 01 – Active Directory Basics

## Objective
Deploy a functional Windows Server Active Directory environment with DNS, OUs, users, groups, GPO, file shares, and a domain-joined Windows client. Practice troubleshooting common AD issues.

## Tools
- Windows Server 2019 (VirtualBox VM) — Domain Controller
- Windows 10 Pro (VirtualBox VM) — Client
- VirtualBox internal network: `192.168.10.0/24`

## Diagram Description
```
[Windows 10 Client] ----LAN (192.168.10.0/24)----> [Windows Server 2019 DC]
    192.168.10.20                                       192.168.10.10
    DNS: 192.168.10.10                                  AD DS + DNS + File Share
```

## Build Steps

### 1. Install Windows Server 2019
1. Create a VirtualBox VM (2 vCPU, 4 GB RAM, 60 GB disk).
2. Attach the Windows Server 2019 ISO and complete the installation.
3. Set a static IP: `192.168.10.10`, subnet `255.255.255.0`, DNS `127.0.0.1`.
4. Rename the server to `DC01`.

### 2. Install Active Directory Domain Services
```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "corp.local" -InstallDns
```
Reboot when prompted.

### 3. Create Organizational Units, Users, and Groups
```powershell
# OUs
New-ADOrganizationalUnit -Name "IT" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Finance" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "HR" -Path "DC=corp,DC=local"

# Users
New-ADUser -Name "Alice Smith" -SamAccountName "asmith" -UserPrincipalName "asmith@corp.local" `
  -Path "OU=IT,DC=corp,DC=local" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
  -Enabled $true

New-ADUser -Name "Bob Jones" -SamAccountName "bjones" -UserPrincipalName "bjones@corp.local" `
  -Path "OU=Finance,DC=corp,DC=local" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
  -Enabled $true

# Groups
New-ADGroup -Name "IT-Staff" -GroupScope Global -Path "OU=IT,DC=corp,DC=local"
Add-ADGroupMember -Identity "IT-Staff" -Members "asmith"
```

### 4. Configure GPO – Password and Lockout Policy
1. Open **Group Policy Management** (`gpmc.msc`).
2. Right-click the domain `corp.local` → **Create a GPO** → Name: `Password Policy`.
3. Edit the GPO:
   - **Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy**
     - Minimum password length: 10
     - Password complexity: Enabled
     - Maximum password age: 90 days
   - **Account Lockout Policy**
     - Lockout threshold: 5 invalid attempts
     - Lockout duration: 15 minutes
     - Observation window: 15 minutes
4. Link the GPO to the domain root.

### 5. Create a File Share
```powershell
New-Item -Path "C:\Shares\ITShare" -ItemType Directory
New-SmbShare -Name "ITShare" -Path "C:\Shares\ITShare" -FullAccess "IT-Staff" -ReadAccess "Everyone"
```

### 6. Join Windows 10 Client to Domain
1. Set client IP to `192.168.10.20`, DNS `192.168.10.10`.
2. **System Properties → Change → Domain → corp.local**.
3. Enter domain admin credentials and reboot.

## Validation Steps
- [ ] `Get-ADUser -Filter *` lists created users
- [ ] `Get-ADGroup -Filter *` lists created groups
- [ ] `Get-GPO -All` shows the Password Policy GPO
- [ ] `Get-SmbShare` shows ITShare
- [ ] Windows 10 client appears in **AD Users & Computers**
- [ ] Log in to Windows 10 as `asmith@corp.local`
- [ ] Access `\\DC01\ITShare` from the client

## Troubleshooting

| Symptom | Steps |
|---|---|
| DNS not resolving | `nslookup corp.local 192.168.10.10`; check DNS server is running on DC |
| Time sync failure | `w32tm /resync`; verify PDC emulator role |
| Domain join fails | Confirm DNS points to DC; check firewall on DC (ports 389, 445, 88) |
| Login failure | Reset password via ADUC; check account not locked/disabled |
| GPO not applying | `gpupdate /force`; `gpresult /h report.html` |

## What You Learned
- Deploying AD DS and DNS on Windows Server
- Creating OUs, users, and groups with PowerShell
- Configuring password and account lockout GPO
- Setting up SMB file shares with group permissions
- Joining a client to a domain and validating connectivity
- Diagnosing DNS, time sync, and login failures

## Evidence Checklist
- [ ] Screenshot: AD Users and Computers showing OUs and users
- [ ] Screenshot: GPO editor showing password policy settings
- [ ] Screenshot: SMB share properties
- [ ] Screenshot: Windows 10 System Properties showing domain membership
- [ ] Screenshot: Successful login as `asmith` on Windows 10 client
