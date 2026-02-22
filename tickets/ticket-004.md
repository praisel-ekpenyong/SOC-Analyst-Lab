# Ticket-004 – DNS Login Failure

| Field | Value |
|---|---|
| **Title** | Cannot log in to domain – DNS error |
| **Date** | 2025-01-09 |
| **Requester** | Bob Jones (bjones@corp.local) |
| **Environment** | Windows 10, corp.local domain |
| **Help Topic** | Account Lockout |
| **SLA** | SEV-B (4 hours) |
| **Related Lab** | Lab 02 – Networking Basics |
| **Related Incident** | Incident-002 – DNS Resolution Failure |

## Problem Statement
Bob Jones reports he cannot log in to the domain on his workstation. Error: "The domain corp.local is not available." He can see the network but cannot reach domain resources.

## Questions Asked
1. Are you using the correct credentials? *(Yes)*
2. Have you restarted your computer recently? *(Yes, after Windows Update)*
3. Does the error appear immediately or after a delay? *(After a delay)*

## Troubleshooting Steps
1. `nslookup corp.local` – returned timeout; DNS server not resolving.
2. `ipconfig /all` – DNS server: `192.168.10.10` (correct).
3. Tested from another machine – same DNS failure.
4. Logged into DC01 directly – DNS service was running.
5. Checked DNS forwarders – no external forwarders configured.
6. Re-added `8.8.8.8` as a DNS forwarder on DC01.
7. `nslookup corp.local` from client – **SUCCESS** immediately.
8. Bob Jones logged in successfully.

## Resolution
Missing DNS forwarder on DC01 prevented clients from resolving external names, which also impacted domain authentication in some cases. Re-adding the forwarder resolved the issue.

## Close Notes
Linked to Incident-002. Root cause corrected at DC01. All affected users confirmed restored access.

## Tags
`dns` `domain-login` `active-directory` `network`

## Time to Resolve
20 minutes
