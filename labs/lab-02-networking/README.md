# Lab 02 – Networking Basics

## Objective
Practice IP addressing, subnetting, and common Windows network diagnostics. Diagnose "no internet" and "DNS not resolving" scenarios using built-in tools.

## Tools
- Windows 10 Pro VM (VirtualBox)
- Windows Server 2019 VM (for DNS testing)
- Command Prompt / PowerShell

## Diagram Description
```
[Windows 10 Client]---[VirtualBox NAT/Internal]---[Windows Server DC]
  192.168.10.20                                      192.168.10.10
  Default Gateway: 192.168.10.1
  DNS: 192.168.10.10
```

## Build Steps

### 1. IP Addressing Basics

| Term | Definition |
|---|---|
| IP Address | Unique logical address for a device (e.g., `192.168.10.20`) |
| Subnet Mask | Defines network vs. host portion (e.g., `255.255.255.0` = `/24`) |
| Default Gateway | Router IP — traffic destination for outside the local network |
| DNS Server | Translates hostnames to IPs |

### 2. Subnetting Practice

| CIDR | Subnet Mask | Hosts per Subnet |
|---|---|---|
| /24 | 255.255.255.0 | 254 |
| /25 | 255.255.255.128 | 126 |
| /26 | 255.255.255.192 | 62 |
| /28 | 255.255.255.240 | 14 |

**Example:** You have `10.0.1.0/26`. How many usable hosts? **62** (64 − 2 for network and broadcast).

### 3. Core Diagnostic Commands

```cmd
ipconfig /all
ping 192.168.10.10
ping 8.8.8.8
tracert 8.8.8.8
nslookup corp.local
nslookup corp.local 192.168.10.10
```

### 4. Diagnose "No Internet" Scenario

**Symptoms:** Cannot browse websites; internal resources work.

**Checklist:**
1. `ipconfig /all` — verify IP, gateway, DNS assigned.
2. `ping 192.168.10.1` — can reach gateway?
3. `ping 8.8.8.8` — can reach internet by IP? (rules out routing)
4. `ping google.com` — DNS resolution working?
5. `nslookup google.com` — confirms DNS or shows failure.
6. `ipconfig /release && ipconfig /renew` — refresh DHCP lease.
7. `ipconfig /flushdns` — clear local DNS cache.
8. Check NIC settings for correct DNS server.

### 5. Diagnose "DNS Not Resolving" Scenario

**Symptoms:** Websites load by IP but not by name; domain login fails.

```cmd
nslookup corp.local
# Expected: returns 192.168.10.10
# Failure: server can't find corp.local

ipconfig /flushdns
ipconfig /registerdns
net stop dnscache && net start dnscache
```

**On DC:**
```powershell
Restart-Service DNS
Get-DnsServerZone
```

## Validation Steps
- [ ] `ipconfig /all` shows correct IP, gateway, DNS
- [ ] `ping DC01.corp.local` resolves and gets replies
- [ ] `tracert 8.8.8.8` shows hops to internet (if NAT enabled)
- [ ] `nslookup corp.local` returns correct IP
- [ ] After flushing DNS, `nslookup` still resolves correctly

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| APIPA address (169.254.x.x) | DHCP not reachable | Set static IP or fix DHCP scope |
| Gateway unreachable | Wrong gateway or NIC issue | Verify gateway IP; check NIC |
| DNS timeout | Wrong DNS server | Point DNS to `192.168.10.10` |
| Cache poisoning | Stale records | `ipconfig /flushdns` |

## What You Learned
- IP addressing and subnetting fundamentals
- Using `ipconfig`, `ping`, `tracert`, `nslookup` for diagnosis
- Diagnosing "no internet" using a layered approach
- Diagnosing DNS failures and clearing DNS cache

## Evidence Checklist
- [ ] Screenshot: `ipconfig /all` output showing full network config
- [ ] Screenshot: Successful `ping DC01.corp.local`
- [ ] Screenshot: `nslookup` resolving internal domain
- [ ] Screenshot: `tracert` output to 8.8.8.8
- [ ] Notes: Subnet practice table with your calculations
