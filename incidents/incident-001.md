# Incident-001 – Account Lockouts After GPO Change

## Summary
Multiple users across the Finance and HR departments were locked out of their domain accounts following a Group Policy update that lowered the account lockout threshold from 10 attempts to 5. Mobile and cached credentials caused rapid lockouts before users were notified of the change.

## Severity
**SEV-C (Medium)** – Affected 6 users; no data loss or security breach.

## Impact
- 6 users unable to log in for 15–45 minutes
- Finance department work disrupted during morning peak hours
- 6 help desk tickets generated (Ticket-002 representative)

## Timeline

| Time | Event |
|---|---|
| 07:00 | GPO change deployed overnight: lockout threshold changed from 10 to 5 |
| 08:05 | First lockout ticket received (Mark Lee) |
| 08:20 | 5 additional lockout tickets received |
| 08:25 | Pattern identified — all accounts in Finance/HR OUs |
| 08:30 | Notified AD admin; correlated with overnight GPO change |
| 08:45 | All 6 accounts unlocked; mobile credentials identified as trigger |
| 09:00 | User communication sent |
| 09:30 | All users confirmed resolved |

## Detection
Users called the help desk after receiving "Account is locked" error at login. Tier 1 agent noticed multiple simultaneous lockout tickets from the same OUs and escalated to Tier 2.

## Triage
- Checked AD audit logs: all accounts showed 5+ failed logins from mobile device IP addresses.
- Checked Group Policy change log — lockout threshold GPO was updated at 07:00.
- Confirmed: mobile devices still using old passwords after forced expiry + new stricter lockout policy combined to trigger lockouts.

## Root Cause
The account lockout threshold GPO was changed from 10 to 5 failed attempts without notifying users. Several users had mobile devices configured with cached credentials that generated repeated failed authentication attempts before users could update them.

## Fix
1. Unlocked all 6 affected accounts in Active Directory.
2. Reset passwords for users who had also expired passwords.
3. Sent a proactive communication to all domain users about the new lockout policy.
4. Created a procedure: all GPO changes must include a user communication notice sent 24 hours in advance.

## Validation
- All 6 accounts confirmed unlocked and accessible.
- No new lockout tickets received after user communication.
- `Get-ADUser -Filter {LockedOut -eq $true}` returns empty.

## Preventive Actions
- [ ] Document GPO changes in change management log before deployment
- [ ] Send user notification 24 hours before lockout policy changes
- [ ] Consider phased rollout for lockout policy changes
- [ ] Add lockout monitoring alert in SIEM/event log monitoring

## Customer Communication

> **From:** IT Help Desk  
> **To:** All Staff  
> **Subject:** Important – Updated Account Lockout Policy  
>
> Dear Team,
>
> We recently updated our account security policy. Your account will now be locked after **5 failed login attempts** (previously 10).
>
> **Action required:** If you have corporate email or other apps on a personal mobile device, please update your password in those apps now to avoid being locked out.
>
> If your account is already locked, please contact the IT Help Desk at extension 1000 or helpdesk@corp.local.
>
> We apologize for any inconvenience.
>
> — IT Help Desk

## Related Tickets
- [Ticket-002 – Account Locked Out](../tickets/ticket-002.md)
