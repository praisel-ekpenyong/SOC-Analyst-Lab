# STAR Stories

Four STAR (Situation, Task, Action, Result) stories based on the simulated incidents in this portfolio. Use these to practice behavioral interview responses.

---

## STAR Story 1 – Account Lockouts After GPO Change
*(Based on Incident-001)*

**Question this answers:** *"Tell me about a time you had to solve a problem that affected multiple users."*

**Situation:**  
During morning peak hours, 6 users in the Finance and HR departments were suddenly unable to log into their domain accounts, generating multiple simultaneous help desk tickets.

**Task:**  
I needed to quickly identify the root cause, restore access for all affected users, and prevent the issue from recurring — all while managing multiple open tickets at once.

**Action:**  
I noticed a pattern: all locked accounts were in the Finance and HR OUs, and the lockouts all started at the same time. I checked the Active Directory audit logs and found that all accounts had 5+ failed login attempts from mobile device IP addresses. I then checked the Group Policy change log and found that the account lockout threshold had been lowered from 10 to 5 the previous night, without any user notification. I unlocked all 6 accounts, helped users update their mobile device credentials, and drafted an all-staff communication explaining the new policy and the action required.

**Result:**  
All 6 users regained access within 45 minutes of the first ticket. No additional lockouts occurred after the user communication was sent. I also proposed a change management procedure requiring user notification 24 hours before any lockout policy changes.

---

## STAR Story 2 – DNS Resolution Failure
*(Based on Incident-002)*

**Question this answers:** *"Describe a situation where you had to work under pressure to resolve a critical issue quickly."*

**Situation:**  
All 47 workstations on the corporate domain lost internet access and some users couldn't log in — all at the same time, during the start of the workday. Tickets were coming in rapidly.

**Task:**  
I needed to identify and resolve the root cause as quickly as possible to minimize productivity loss for the entire company.

**Action:**  
Rather than troubleshooting each ticket individually, I recognized the simultaneous nature of the complaints as a sign of a shared infrastructure problem. I ran `nslookup google.com` on an affected workstation and got a timeout, pointing to DNS. I checked `nslookup corp.local` — that worked, so internal DNS was fine but external resolution was broken. I logged into the domain controller and opened DNS Manager. The forwarders list was completely empty. I re-added `8.8.8.8` and `1.1.1.1`, clicked Apply, and within 30 seconds clients started resolving external names again.

**Result:**  
Full DNS resolution was restored within 25 minutes of the first ticket. I sent a company-wide communication explaining the cause and resolution. I also recommended adding DNS forwarder monitoring to prevent silent failures in the future.

---

## STAR Story 3 – Printer Not Printing After Driver Update
*(Based on Incident-003)*

**Question this answers:** *"Give an example of when you identified the root cause of a technical problem."*

**Situation:**  
Four users in the Finance department reported that the shared HP LaserJet printer stopped working at the start of the workday. Print jobs were stuck in the queue and the print spooler was in an error state.

**Task:**  
I needed to restore printing for 4 users as quickly as possible while identifying what caused the printer to fail so I could prevent it from happening again.

**Action:**  
I checked Windows Update history on the first affected machine and found a new HP printer driver had been automatically installed at 2:14 AM. I stopped the Print Spooler, cleared the spool folder, restarted the service, then rolled back the driver via Device Manager. The printer came back online immediately. I repeated this on all 4 workstations, then added the HP LaserJet driver to the WSUS exclusion list to block automatic future updates for that model.

**Result:**  
All 4 workstations were printing within 35 minutes. I sent a communication to the Finance team explaining the cause and asking them to resubmit their queued jobs. The WSUS exclusion prevents this model from being affected by automatic driver updates going forward.

---

## STAR Story 4 – Slow PC Due to Low Disk Space
*(Based on Incident-004)*

**Question this answers:** *"Tell me about a time you used a tool or script to diagnose a problem more efficiently."*

**Situation:**  
A user submitted a ticket reporting her computer had been getting progressively slower over the past week and now took over 10 minutes to boot. She had been seeing "Low disk space" notifications but hadn't reported it until the PC was nearly unusable.

**Task:**  
I needed to quickly identify the cause of the slowdown and restore normal performance, and also determine how to prevent the same issue in the future.

**Action:**  
Instead of manually checking each resource, I ran my `Get-DiskSpaceReport.ps1` PowerShell script, which immediately showed the C: drive at 98% full with only 0.2 GB remaining. I ran Disk Cleanup as Administrator, selected all categories including System Files (which included 8.5 GB of Windows Update cleanup), and freed 17 GB total. I then opened Task Manager's Startup tab and disabled 4 non-essential startup programs. After a reboot, the machine booted in under 2 minutes.

**Result:**  
PC performance was fully restored within 45 minutes. The user was educated on keeping the Downloads folder clean and moving large files to the network share. I recommended deploying a monthly Disk Cleanup scheduled task via GPO and a disk space monitoring alert to catch similar issues proactively before they impact users.
