# Evidence Checklist

Use this checklist to track evidence collected as you complete each lab. Check off each item once you have the screenshot or artifact saved in `docs/screenshots/`.

---

## Lab 01 – Active Directory Basics

- [ ] Screenshot: AD Users and Computers showing OUs and users
- [ ] Screenshot: GPO editor showing password and lockout policy
- [ ] Screenshot: SMB share properties (ITShare)
- [ ] Screenshot: Windows 10 System Properties – domain: corp.local
- [ ] Screenshot: Successful login as `asmith` on Windows 10

---

## Lab 02 – Networking Basics

- [ ] Screenshot: `ipconfig /all` output showing full network config
- [ ] Screenshot: Successful `ping DC01.corp.local` with replies
- [ ] Screenshot: `nslookup corp.local` returning correct IP
- [ ] Screenshot: `tracert 8.8.8.8` output
- [ ] Notes: Completed subnet practice table

---

## Lab 03 – Windows Troubleshooting

- [ ] Screenshot: Event Viewer filtered to Critical/Error/Warning
- [ ] Screenshot: `sfc /scannow` result (no violations or repairs completed)
- [ ] Screenshot: `DISM /Online /Cleanup-Image /RestoreHealth` completed
- [ ] Screenshot: Print queue cleared, printer online
- [ ] Screenshot: Task Manager → Startup tab showing disabled programs

---

## Lab 04 – osTicket

- [ ] Screenshot: osTicket installation success page
- [ ] Screenshot: Admin panel → Departments list (IT Support, Network Ops, HR)
- [ ] Screenshot: SLA Plans configured (SEV-A, SEV-B, SEV-C)
- [ ] Screenshot: Open tickets queue showing sample tickets
- [ ] Screenshot: Ticket closed with resolution notes

---

## Lab 05 – PowerShell Basics

- [ ] Screenshot: `Get-DiskSpaceReport.ps1` output in terminal
- [ ] Screenshot: Exported disk report CSV in Notepad/Excel
- [ ] Screenshot: `Export-EventLogs.ps1` CSV with events
- [ ] Screenshot: `Reset-LocalPassword.ps1` output with all warning messages

---

## Tickets Evidence

- [ ] All 12 ticket Markdown files present in `/tickets/` folder
- [ ] Each ticket linked to a lab and incident (where applicable)
- [ ] Tickets replicated in osTicket web UI (Lab 04)

---

## Incidents Evidence

- [ ] All 4 incident Markdown files present in `/incidents/` folder
- [ ] Each incident links to 1–3 related tickets
- [ ] Customer communication message included in each incident

---

## Hiring Assets Evidence

- [ ] Skills matrix (`docs/skills-matrix.md`) complete
- [ ] Resume bullets (`docs/resume-bullets.md`) – 6 bullets written
- [ ] STAR stories (`docs/star-stories.md`) – 4 stories written
