# Ticket-003 – No Internet Connectivity

| Field | Value |
|---|---|
| **Title** | No internet access after morning startup |
| **Date** | 2025-01-09 |
| **Requester** | Jane Doe (jane.doe@corp.local) |
| **Environment** | Windows 10, corp.local domain |
| **Help Topic** | Network Connectivity |
| **SLA** | SEV-B (4 hours) |
| **Related Lab** | Lab 02 – Networking Basics |
| **Related Incident** | None |

## Problem Statement
User reports no internet access on her workstation after starting up this morning. Internal resources (file share, email) are accessible but external websites do not load.

## Questions Asked
1. Can you reach internal sites like the intranet? *(Yes)*
2. Can you ping the default gateway? *(Yes after checking)*
3. Has anything changed on the workstation recently? *(No)*

## Troubleshooting Steps
1. `ipconfig /all` – confirmed IP, gateway, and DNS all correct.
2. `ping 8.8.8.8` – **SUCCESS** (internet reachable by IP).
3. `ping google.com` – **FAILED** (DNS resolution failing for external names).
4. `nslookup google.com` – returned "DNS request timed out" from internal DNS server.
5. Checked internal DNS server — external forwarder `8.8.8.8` was removed from DNS forwarders list by mistake.
6. Re-added forwarder in DNS Manager on DC01.
7. `ipconfig /flushdns` on client workstation.
8. Re-tested: `ping google.com` — **SUCCESS**.

## Resolution
External DNS forwarder was missing from the internal DNS server. Re-added `8.8.8.8` as a forwarder. Cleared DNS cache on client. Internet access restored.

## Close Notes
Root cause: DNS forwarder misconfiguration on DC01. Affected all workstations using internal DNS — multiple users impacted (see Incident-002).

## Tags
`dns` `network` `internet-connectivity` `dns-forwarder`

## Time to Resolve
25 minutes
