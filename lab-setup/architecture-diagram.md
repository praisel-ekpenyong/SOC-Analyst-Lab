# Lab Network Architecture

## Network Topology Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         VirtualBox Host System                          │
│                    (Windows/Linux/macOS Host Machine)                   │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │              VirtualBox Host-Only Network (vboxnet0)              │ │
│  │                      Network: 10.0.0.0/24                         │ │
│  │                    Gateway: 10.0.0.1 (Host)                       │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                  │                                      │
│         ┌────────────────────────┼────────────────────────┐            │
│         │                        │                        │            │
│         ▼                        ▼                        ▼            │
│  ┌─────────────┐         ┌─────────────┐         ┌─────────────┐      │
│  │  Windows    │         │  Windows 10 │         │    Kali     │      │
│  │  Server     │         │  Workstation│         │    Linux    │      │
│  │   2019      │         │             │         │  (Attacker) │      │
│  │             │         │             │         │             │      │
│  │   DC01      │◄────────┤ WS-FIN-PC01 ├────────►│ KALI-ATK01  │      │
│  │             │   DNS   │             │ Attacks │             │      │
│  │ 10.0.0.10   │  Auth   │  10.0.0.20  │         │  10.0.0.50  │      │
│  │             │         │             │         │             │      │
│  │ [Roles]     │         │ [Software]  │         │ [Tools]     │      │
│  │ • AD DS     │         │ • Sysmon    │         │ • Metasploit│      │
│  │ • DNS       │         │ • Splunk UF │         │ • Mimikatz  │      │
│  │ • Sysmon    │         │ • Wazuh Agt │         │ • PsExec    │      │
│  │             │         │ • Atomic RT │         │ • nmap      │      │
│  └──────┬──────┘         └──────┬──────┘         └─────────────┘      │
│         │                       │                                      │
│         │    Logs (Port 9997)   │                                      │
│         │    Logs (Port 1514)   │                                      │
│         └───────────────────────┤                                      │
│                                 ▼                                      │
│                    ┌─────────────────────────┐                         │
│                    │    Ubuntu Server        │                         │
│                    │       SIEM01            │                         │
│                    │      10.0.0.30          │                         │
│                    │                         │                         │
│                    │  [Software Stack]       │                         │
│                    │  ┌──────────────────┐   │                         │
│                    │  │ Splunk Free      │   │                         │
│                    │  │ (SIEM)           │   │                         │
│                    │  │ • Port 8000 (UI) │   │                         │
│                    │  │ • Port 9997 (Rx) │   │                         │
│                    │  └──────────────────┘   │                         │
│                    │  ┌──────────────────┐   │                         │
│                    │  │ Wazuh Manager    │   │                         │
│                    │  │ (EDR Platform)   │   │                         │
│                    │  │ • Port 1514 (Rx) │   │                         │
│                    │  │ • Port 1515 (Reg)│   │                         │
│                    │  │ • Port 443 (UI)  │   │                         │
│                    │  └──────────────────┘   │                         │
│                    └─────────────────────────┘                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

            ┌────────────────────────────────────────┐
            │  Simulated Internet (No real internet) │
            │    All traffic is internal only        │
            └────────────────────────────────────────┘
```

## Component Descriptions

### Windows Server 2019 - Domain Controller (DC01)
**IP Address:** 10.0.0.10  
**Hostname:** DC01.soclab.local  
**Purpose:** Active Directory Domain Services, DNS, and enterprise authentication

**Key Services:**
- Active Directory Domain Services (AD DS)
- DNS Server (resolves soclab.local domain)
- Sysmon for advanced logging
- Group Policy management

**Logging:**
- Windows Security Event Log → Splunk
- Windows System Event Log → Splunk
- Sysmon Event Log → Splunk
- All logs → Wazuh Manager

**Security Monitoring:**
- Authentication events (4624, 4625, 4768, 4769, 4776)
- Account management (4720, 4722, 4726, 4728, 4732)
- Group Policy changes
- Sysmon Process Creation, Network Connections, Registry modifications

---

### Windows 10 Workstation (WS-FIN-PC01)
**IP Address:** 10.0.0.20  
**Hostname:** WS-FIN-PC01  
**Domain:** soclab.local  
**Purpose:** Standard user workstation with full monitoring stack

**Installed Software:**
- Sysmon (SwiftOnSecurity configuration)
- Splunk Universal Forwarder
- Wazuh Agent
- Atomic Red Team (for testing detections)
- Microsoft Office (for macro-based attack testing)

**Logging:**
- Windows Security Event Log → Splunk
- Windows System Event Log → Splunk
- Sysmon Event Log → Splunk
- PowerShell Script Block Logging → Splunk
- All logs → Wazuh Manager

**Test User Accounts:**
- a.chen (Finance department user)
- j.martinez (IT department user)
- m.johnson (HR department user)
- d.roberts (Executive user)

**Purpose in Lab:**
- Primary target for attack simulation
- Atomic Red Team execution platform
- Phishing email simulation recipient
- Lateral movement pivot point

---

### Ubuntu Server (SIEM01)
**IP Address:** 10.0.0.30  
**Hostname:** SIEM01  
**Purpose:** Centralized logging, SIEM, and EDR management platform

**Splunk Free Configuration:**
- **Web UI:** http://10.0.0.30:8000
- **Receiving Port:** 9997 (Splunk-to-Splunk protocol)
- **Indexes:**
  - `windows_security` - Windows Security Event Logs
  - `windows_sysmon` - Sysmon Event Logs
  - `windows_system` - Windows System Event Logs
  - `firewall` - Firewall logs
  - `wazuh` - Wazuh alerts and events

**Wazuh Manager Configuration:**
- **Dashboard UI:** https://10.0.0.30:443
- **Agent Communication:** Port 1514 (syslog)
- **Agent Registration:** Port 1515
- **Capabilities:**
  - File integrity monitoring (FIM)
  - Rootkit detection
  - Active response
  - Vulnerability detection
  - Compliance monitoring (PCI-DSS, HIPAA, GDPR)

**System Resources:**
- 2 CPU cores
- 6 GB RAM (4 GB Splunk + 2 GB Wazuh recommended)
- 100 GB disk (adequate for ~30 days of logs at moderate volume)

---

### Kali Linux (KALI-ATK01)
**IP Address:** 10.0.0.50  
**Hostname:** KALI-ATK01  
**Purpose:** Simulated adversary for testing detections

**Pre-installed Tools Used:**
- **Metasploit Framework** - Exploitation and post-exploitation
- **nmap** - Network reconnaissance
- **Hydra** - Brute force password attacks
- **Mimikatz** - Credential dumping
- **PsExec (Impacket)** - Lateral movement testing
- **PowerShell Empire** - Post-exploitation C2
- **Wireshark** - Traffic capture and analysis

**Use Cases:**
1. RDP brute force attacks against DC01
2. SMB/PsExec lateral movement testing
3. Password spraying against domain accounts
4. Simulated C2 beacon traffic
5. Data exfiltration testing
6. Network scanning and reconnaissance
7. Exploitation of vulnerable services

**Safety Note:** This VM is isolated on the Host-Only network with no real internet access to prevent actual attacks or malware distribution.

---

## Network Flows

### Authentication Flow
```
WS-FIN-PC01 → DC01 (Port 389/636 LDAP)
            → DC01 (Port 88 Kerberos)
            → DC01 (Port 445 SMB for GPO)
```

### Logging Flow - Splunk
```
WS-FIN-PC01 (Splunk UF) → SIEM01 (Port 9997) → Splunk Indexers
DC01 (Splunk UF)        → SIEM01 (Port 9997) → Splunk Indexers
```

### Logging Flow - Wazuh
```
WS-FIN-PC01 (Wazuh Agent) → SIEM01 (Port 1514) → Wazuh Manager
DC01 (Wazuh Agent)        → SIEM01 (Port 1514) → Wazuh Manager
```

### Attack Flow (Testing)
```
KALI-ATK01 → DC01 (Port 3389 RDP) - Brute force testing
KALI-ATK01 → WS-FIN-PC01 (Port 445 SMB) - PsExec lateral movement
KALI-ATK01 → DC01 (Port 445 SMB) - Share enumeration
```

## Network Segmentation

**Current State:** All devices on single flat network (10.0.0.0/24)

**Future Enhancement Ideas:**
- VLAN 10: User workstations (10.0.10.0/24)
- VLAN 20: Servers (DC, file servers) (10.0.20.0/24)
- VLAN 30: Management (SIEM, EDR) (10.0.30.0/24)
- VLAN 40: DMZ/Isolated (Attacker) (10.0.40.0/24)

This would better simulate enterprise environments and allow testing of network-based detection rules.

## Security Considerations

**Isolation:**
- Lab uses VirtualBox Host-Only network with NO internet access by default
- NAT adapter only temporarily attached for software downloads
- Prevents accidental exposure or real attacks

**Monitoring:**
- Comprehensive logging from all Windows systems
- Centralized in Splunk for correlation
- Real-time alerting via Wazuh
- All network traffic can be captured with tcpdump/Wireshark

**Attack Surface:**
- RDP enabled on DC01 for brute force testing
- SMB/445 open for lateral movement testing
- No production services exposed
- All passwords are test credentials

## Accessing the Lab

**From Host Machine:**

Access Splunk:
```
http://10.0.0.30:8000
Username: admin
Password: [set during installation]
```

Access Wazuh Dashboard:
```
https://10.0.0.30:443
Username: admin
Password: [set during installation]
```

RDP to Windows Systems:
```
mstsc /v:10.0.0.10  (Domain Controller)
mstsc /v:10.0.0.20  (Workstation)
```

SSH to Ubuntu Server:
```
ssh adminuser@10.0.0.30
```

SSH to Kali:
```
ssh kali@10.0.0.50
Default password: kali
```

## Expansion Opportunities

This lab can be expanded with:
- Additional Windows workstations (HR, IT, Executive networks)
- Windows file server with SMB shares
- Linux web server for web application attacks
- IDS/IPS (Suricata, Snort) for network-based detection
- Firewall VM (pfSense) for network segmentation and traffic control
- SIEM integration with threat intelligence feeds (MISP, STIX/TAXII)
- Velociraptor or OSQuery for additional endpoint visibility
- ELK Stack (Elasticsearch, Logstash, Kibana) as alternative SIEM

## Diagram Legend

```
┌─────────┐
│   VM    │  Virtual Machine
└─────────┘

    │       Network connection
    ▼       Traffic flow direction
    
    ◄──►    Bidirectional communication
    
[Roles]     Services/Roles installed
[Software]  Monitoring agents installed
[Tools]     Security testing tools
```
