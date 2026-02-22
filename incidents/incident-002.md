# Incident-002 – DNS Resolution Failure Affecting Logins and Web Access

## Summary
All workstations on the corp.local domain lost the ability to resolve external DNS names following an accidental removal of DNS forwarders from the domain controller. This caused both external website access failures and intermittent domain authentication issues.

## Severity
**SEV-B (High)** – All domain-connected users affected; productivity halted for ~25 minutes.

## Impact
- All 47 domain workstations lost external DNS resolution
- Domain logins intermittently failed (Kerberos relies on name resolution)
- Internet browsing completely down for all users
- 8 tickets opened during the incident

## Timeline

| Time | Event |
|---|---|
| 08:55 | First ticket received: "No internet" (Jane Doe – Ticket-003) |
| 09:00 | Second ticket: "Cannot log in to domain" (Bob Jones – Ticket-004) |
| 09:05 | Help desk begins receiving flood of similar complaints |
| 09:10 | Technician identifies DNS failure via `nslookup google.com` |
| 09:15 | DC01 DNS checked — forwarders list empty |
| 09:18 | `8.8.8.8` added back as DNS forwarder |
| 09:20 | DNS resolution restored across all workstations |
| 09:35 | All tickets resolved; incident declared closed |

## Detection
Multiple simultaneous tickets with "no internet" and "cannot log in to domain" symptoms triggered a pattern recognition by the Tier 1 agent. Running `nslookup google.com` on an affected workstation returned a timeout, pointing to DNS.

## Triage
1. Confirmed DNS failure was domain-wide (tested 3 different workstations).
2. Internal DNS (`nslookup corp.local`) worked — DC-to-DC resolution fine.
3. External DNS (`nslookup google.com`) failed from all clients.
4. Logged into DC01 — DNS Manager showed no DNS forwarders configured.
5. Reviewed recent DNS change log — forwarders were accidentally deleted during a routine DNS cleanup task.

## Root Cause
A technician performing routine DNS zone cleanup accidentally removed all DNS forwarder entries from the primary domain controller. This left the DNS server unable to resolve external names, causing both internet access and some domain authentication flows to fail.

## Fix
1. Opened DNS Manager on DC01.
2. Right-clicked **DNS Server → Properties → Forwarders tab**.
3. Added `8.8.8.8` and `1.1.1.1` as forwarders.
4. Clicked Apply.
5. Ran `ipconfig /flushdns` on affected workstations.
6. Confirmed restoration: `nslookup google.com` returned correct results.

## Validation
- `nslookup google.com` returns `142.250.x.x` from all tested workstations.
- All 8 open tickets confirmed resolved by users.
- Domain logins restored across all affected users.

## Preventive Actions
- [ ] Document DNS forwarder configuration in infrastructure runbook
- [ ] Require change approval for DNS modifications on domain controllers
- [ ] Add DNS forwarder monitoring check (alert if forwarders list becomes empty)
- [ ] Test DNS resolution after any DNS change before ending the change window

## Customer Communication

> **From:** IT Help Desk  
> **To:** All Staff  
> **Subject:** Resolved – Network and Login Issues This Morning  
>
> Dear Team,
>
> We are writing to inform you that the internet connectivity and domain login issues experienced this morning between approximately 8:55 AM and 9:20 AM have been fully resolved.
>
> **Cause:** A configuration change to our internal DNS server inadvertently removed external name resolution settings.  
> **Resolution:** Settings were restored and all services are now operating normally.
>
> We apologize for the disruption. If you experience any remaining issues, please contact the IT Help Desk.
>
> — IT Help Desk

## Related Tickets
- [Ticket-003 – No Internet Connectivity](../tickets/ticket-003.md)
- [Ticket-004 – DNS Login Failure](../tickets/ticket-004.md)
