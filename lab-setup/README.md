# Lab Setup Documentation

This section documents the complete build process for the SOC Analyst home lab environment. The lab simulates a small enterprise network with a domain controller, workstations, SIEM, EDR, and an isolated attack platform for testing detection rules.

## Prerequisites

### Hardware Requirements

**Minimum Specifications:**
- **CPU:** 4-core processor with virtualization support (Intel VT-x or AMD-V)
- **RAM:** 16 GB (32 GB recommended)
- **Storage:** 256 GB SSD (512 GB recommended)
- **Network:** Gigabit Ethernet recommended

**Resource Allocation per VM:**
| VM | CPU Cores | RAM | Disk Space |
|----|-----------|-----|------------|
| Windows Server 2019 (DC) | 2 | 4 GB | 60 GB |
| Windows 10 Workstation | 2 | 4 GB | 60 GB |
| Ubuntu Server (SIEM/EDR) | 2 | 6 GB | 100 GB |
| Kali Linux (Attacker) | 2 | 2 GB | 40 GB |

### Software Downloads

1. **VirtualBox** (Virtualization Platform)
   - Download: https://www.virtualbox.org/wiki/Downloads
   - Version: 7.0 or later

2. **Operating System ISOs**
   - Windows Server 2019: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019 (180-day evaluation)
   - Windows 10 Enterprise: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise (90-day evaluation)
   - Ubuntu Server 22.04 LTS: https://ubuntu.com/download/server
   - Kali Linux: https://www.kali.org/get-kali/#kali-virtual-machines (pre-built VirtualBox image)

3. **Security Tools**
   - Splunk Free: https://www.splunk.com/en_us/download/splunk-enterprise.html
   - Splunk Universal Forwarder: https://www.splunk.com/en_us/download/universal-forwarder.html
   - Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
   - Sysmon Config: https://github.com/SwiftOnSecurity/sysmon-config
   - Wazuh: https://documentation.wazuh.com/current/installation-guide/index.html
   - Atomic Red Team: https://github.com/redcanaryco/atomic-red-team

## Network Configuration

### VirtualBox Network Setup

**Create Host-Only Network:**
1. Open VirtualBox → File → Host Network Manager
2. Create new Host-Only network (vboxnet0)
3. Configure IPv4:
   - **IPv4 Address:** 10.0.0.1
   - **IPv4 Network Mask:** 255.255.255.0
4. **DHCP Server:** Disabled (static IPs used)

**IP Address Scheme:**
| Host | IP Address | Hostname | Purpose |
|------|------------|----------|---------|
| Domain Controller | 10.0.0.10 | DC01 | Active Directory, DNS |
| Windows Workstation | 10.0.0.20 | WS-FIN-PC01 | Domain-joined endpoint with monitoring |
| Ubuntu Server | 10.0.0.30 | SIEM01 | Splunk + Wazuh Manager |
| Kali Linux | 10.0.0.50 | KALI-ATK01 | Attack simulation platform |

### Network Architecture

See [architecture-diagram.md](architecture-diagram.md) for visual representation.

**Network Isolation:**
- All VMs use Host-Only adapter for internal communication
- No internet access by default (simulated environment)
- NAT adapter can be temporarily added for software downloads/updates

## Build Order

Follow this sequence to minimize configuration issues:

### Phase 1: Infrastructure (Days 1-2)

1. **VirtualBox Host-Only Network Setup** (15 minutes)
   - Configure vboxnet0 as described above

2. **Ubuntu Server Installation** (45 minutes)
   - Create VM: 2 CPU, 6 GB RAM, 100 GB disk
   - Install Ubuntu Server 22.04 LTS
   - Set static IP: 10.0.0.30
   - Install SSH for remote management
   - Update system: `sudo apt update && sudo apt upgrade -y`

3. **Windows Server 2019 Installation** (1 hour)
   - Create VM: 2 CPU, 4 GB RAM, 60 GB disk
   - Install Windows Server 2019 (Desktop Experience)
   - Set static IP: 10.0.0.10
   - Rename computer to DC01
   - **DO NOT** promote to Domain Controller yet

4. **Windows 10 Workstation Installation** (45 minutes)
   - Create VM: 2 CPU, 4 GB RAM, 60 GB disk
   - Install Windows 10 Enterprise
   - Set static IP: 10.0.0.20
   - Rename computer to WS-FIN-PC01

5. **Kali Linux Setup** (30 minutes)
   - Import pre-built VirtualBox image
   - Set static IP: 10.0.0.50
   - Update: `sudo apt update && sudo apt full-upgrade -y`

### Phase 2: Active Directory (Day 3)

6. **Active Directory Domain Services** (2 hours)
   - See [active-directory-setup.md](active-directory-setup.md) for detailed steps
   - Promote DC01 to domain controller
   - Domain: `soclab.local`
   - Create OUs, users, groups

7. **Join Windows 10 to Domain** (30 minutes)
   - Configure DNS to point to 10.0.0.10
   - Join WS-FIN-PC01 to soclab.local domain

### Phase 3: Monitoring & Logging (Days 4-5)

8. **Sysmon Deployment** (1 hour)
   - See [sysmon-setup.md](sysmon-setup.md)
   - Install on Windows 10 workstation
   - Install on Windows Server (DC)

9. **Splunk SIEM Setup** (3 hours)
   - See [splunk-setup.md](splunk-setup.md)
   - Install Splunk Free on Ubuntu Server
   - Install Universal Forwarder on Windows systems
   - Configure data ingestion

10. **Wazuh EDR Setup** (2 hours)
    - See [wazuh-setup.md](wazuh-setup.md)
    - Install Wazuh Manager on Ubuntu Server
    - Install Wazuh Agent on Windows systems

### Phase 4: Testing & Validation (Day 6)

11. **Atomic Red Team Installation** (1 hour)
    - Install on Windows 10 workstation
    - Verify attack simulations trigger alerts

12. **Detection Rule Development** (Ongoing)
    - Create custom Splunk alerts
    - Test with Atomic Red Team
    - Document in detection-rules/

## Verification Checklist

- [ ] All VMs can ping each other on 10.0.0.0/24 network
- [ ] Windows 10 successfully joined to soclab.local domain
- [ ] Domain users can log in to Windows 10 workstation
- [ ] Sysmon service running on all Windows systems
- [ ] Splunk receiving logs from Windows systems (verify in Search)
- [ ] Wazuh agents showing as "Active" in Wazuh dashboard
- [ ] Atomic Red Team can execute test techniques
- [ ] DNS resolution working (nslookup dc01.soclab.local returns 10.0.0.10)

## Troubleshooting

**Issue: VMs cannot communicate**
- Verify all VMs use Host-Only adapter (vboxnet0)
- Check Windows Firewall settings (allow ICMP for testing)
- Verify static IPs configured correctly

**Issue: Windows 10 cannot join domain**
- Ensure DNS is set to 10.0.0.10
- Verify domain controller is reachable: `ping dc01.soclab.local`
- Check Active Directory Domain Services is running on DC

**Issue: Splunk not receiving logs**
- Verify Universal Forwarder service is running on Windows
- Check inputs.conf configuration
- Verify Splunk receiving port 9997 is listening: `netstat -an | grep 9997`
- Review splunkd.log for errors

**Issue: Wazuh agent not connecting**
- Verify Wazuh Manager is running: `systemctl status wazuh-manager`
- Check agent ossec.conf points to 10.0.0.30
- Restart agent: `Restart-Service WazuhSvc` (PowerShell)

## Next Steps

After completing the lab setup:
1. Review [Detection Rules](../detection-rules/README.md) and implement in Splunk
2. Study [Investigation Write-ups](../investigations/README.md) to understand incident response methodology
3. Practice with [Phishing Analysis](../phishing-analysis/README.md) techniques
4. Run Atomic Red Team tests and validate detection coverage

## Maintenance

**Regular Tasks:**
- Update Windows systems: Monthly
- Update Ubuntu Server: Monthly
- Update Wazuh rules: Weekly
- Review Splunk license usage: Weekly
- Backup configurations: Monthly
- Snapshot VMs before major changes: Always

## Cost Analysis

**Total Cost: $0** (all tools are free/evaluation versions)

| Item | Cost | Notes |
|------|------|-------|
| VirtualBox | Free | Open source |
| Windows Server 2019 | Free | 180-day evaluation |
| Windows 10 Enterprise | Free | 90-day evaluation (renewable) |
| Ubuntu Server | Free | Open source |
| Kali Linux | Free | Open source |
| Splunk Free | Free | 500 MB/day limit |
| Wazuh | Free | Open source |
| Sysmon | Free | Microsoft Sysinternals |

**Note:** Windows evaluation licenses can be renewed or VMs can be reverted to snapshots to extend evaluation periods for lab purposes.
