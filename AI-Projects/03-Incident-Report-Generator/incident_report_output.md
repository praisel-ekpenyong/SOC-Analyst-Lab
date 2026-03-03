<!-- Pre-generated sample output for INC-2025-0042 -->
<!-- Incident: INC-2025-0042 - Ransomware Deployment via Phishing Email — Finance Department -->

---

| Field | Value |
|---|---|
| **Incident ID** | INC-2025-0042 |
| **Title** | Ransomware Deployment via Phishing Email — Finance Department |
| **Date Reported** | 2025-10-15 |
| **Severity** | 🔴 Critical |
| **Analyst** | Praisel Ekpenyong, Tier 1 SOC Analyst |
| **Report Generated** | 2025-10-15T10:30:00Z |

---

## Executive Summary

On 15 October 2025, a targeted spearphishing email was delivered to a finance department employee (`CORP\mwilson`) at 07:42 UTC, impersonating a known vendor with a malicious Word document attachment (`Invoice_8821.docx`). The user enabled macros in the document, triggering a PowerShell-based payload delivery chain that deployed a LockBit 3.0 ransomware variant on the affected workstation.

Within 12 minutes of initial infection, the ransomware had encrypted local files on two finance workstations (`WKS-FINANCE01`, `WKS-FINANCE03`) and propagated to the finance file server (`FS01`) via SMB using the compromised user's credentials, encrypting approximately 2,400 files across shared drives.

The SOC identified the incident at 07:58 UTC via Wazuh EDR alerting and contained affected systems by 08:05 UTC. No confirmed data exfiltration was observed at time of reporting. The incident has been escalated to the IR team and is classified **P1 – Critical**.

---

## Timeline of Events

| Time (UTC) | Event |
|---|---|
| `2025-10-15 07:42:11` | Phishing email received by `CORP\mwilson` from `accounts-payable@corp-invoices.net` with subject *"URGENT: Invoice #8821 requires approval"* and malicious attachment `Invoice_8821.docx` |
| `2025-10-15 07:45:03` | `mwilson` opened `Invoice_8821.docx` in Microsoft Word; accepted macro execution prompt |
| `2025-10-15 07:45:18` | Macro launched `powershell.exe` with base64-encoded command; payload (`p.exe`) downloaded from `hxxp://corp-invoices.net/p.exe` and executed |
| `2025-10-15 07:46:02` | Ransomware established persistence via registry Run key: `HKCU\...\Run\WindowsUpdate` |
| `2025-10-15 07:47:30` | File encryption began on `WKS-FINANCE01`; files renamed with `.lockbit3` extension |
| `2025-10-15 07:52:45` | Ransomware accessed `FS01` via SMB (port 445) using `mwilson`'s credentials; encrypted network shares began |
| `2025-10-15 07:58:11` | Wazuh EDR alert fired: mass file rename/encryption on `FS01`; SOC analyst notified |
| `2025-10-15 08:05:00` | `WKS-FINANCE01` and `WKS-FINANCE03` isolated via firewall rule; `FS01` taken offline manually |
| `2025-10-15 08:20:00` | Incident escalated to IR team; P1 ticket `INC-2025-0042` created in osTicket; `mwilson` and `tjones` accounts disabled |

---

## Indicators of Compromise (IOCs)

> ⚠️ All IOCs are defanged for safe sharing. Do not navigate to these URLs/IPs.

### File Hashes

| File | Hash Type | Value |
|---|---|---|
| `Invoice_8821.docx` | MD5 | `d8f2c3a1b4e5f67890abcdef12345678` |
| `p.exe` (LockBit dropper) | SHA-256 | `4a7b9c2d1e3f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5a6b7c8d9e0f` |

### Domains and IP Addresses

| Indicator | Type | Role |
|---|---|---|
| `corp-invoices[.]net` | Domain | Phishing sender / C2 / payload delivery |
| `accounts-payable@corp-invoices[.]net` | Email address | Phishing sender |
| `91.92.248[.]101` | IP Address | C2 server |
| `185.220.101[.]45` | IP Address | Payload download server |

### Registry Keys

| Key | Purpose |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate` | Ransomware persistence |

### File Paths

| Path | Description |
|---|---|
| `C:\Users\mwilson\AppData\Local\Temp\p.exe` | Ransomware dropper |
| `C:\Users\mwilson\Documents\Invoice_8821.docx` | Phishing document |

---

## Root Cause Analysis

The root cause of this incident was a **successful spearphishing attack** exploiting human trust and a gap in email gateway controls:

1. **Phishing bypass**: The attacker used a recently registered domain (`corp-invoices.net`) that had not yet been categorised by the email security gateway, allowing the email to reach the user's inbox.
2. **Macro-enabled execution**: Microsoft Office macro execution was not disabled by Group Policy for the finance department. The user, conditioned to accept prompts for legitimate finance documents, enabled the macro.
3. **Excessive credential permissions**: The compromised user account (`mwilson`) had write access to the finance file server's shared drives, enabling rapid lateral propagation without requiring privilege escalation.
4. **Delayed detection**: The Wazuh EDR alert for mass file encryption was triggered only after approximately 16 minutes of active encryption, allowing significant file loss before containment.

---

## Recommended Remediation Steps

1. **Immediate**: Restore `FS01` finance shares from the most recent clean backup (verify backup integrity before restoration).
2. **Immediate**: Reset passwords for all accounts in the Finance OU; re-enable accounts only after verification that associated workstations are clean.
3. **Short-term (within 24 hours)**: Deploy Group Policy to disable Office macro execution for all non-developer users across the domain (`User Configuration > Administrative Templates > Microsoft Office > Block macros from running in Office files from the Internet`).
4. **Short-term**: Add IOC block rules to the email gateway, web proxy, and EDR platform for all domains, IPs, and file hashes listed above.
5. **Short-term**: Conduct enterprise-wide scan for `.lockbit3` file extension and the ransomware dropper hash.
6. **Medium-term (within 1 week)**: Review and apply principle of least privilege to all finance user accounts — remove write access to file server shares where not operationally required.
7. **Medium-term**: Implement and test a real-time backup/snapshot solution for critical file servers (e.g., VSS snapshots every 15–30 minutes).
8. **Medium-term**: Tune Wazuh EDR to alert on mass file rename/encryption patterns within 2–3 minutes of onset (lower current detection threshold).
9. **Long-term**: Deliver targeted security awareness training to the Finance department focused on phishing identification and the dangers of enabling document macros.
10. **Long-term**: Evaluate deployment of an Attack Surface Reduction (ASR) rule set via Microsoft Defender to block `winword.exe` from spawning child processes.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Observed Activity |
|---|---|---|
| **T1566.001** | Phishing: Spearphishing Attachment | Malicious Word document delivered via targeted email |
| **T1059.001** | Command and Scripting Interpreter: PowerShell | Macro-spawned PowerShell with encoded payload download command |
| **T1105** | Ingress Tool Transfer | `p.exe` ransomware dropper downloaded from attacker-controlled server |
| **T1547.001** | Boot or Logon Autostart Execution: Registry Run Keys | Persistence established via `HKCU\...\Run\WindowsUpdate` |
| **T1486** | Data Encrypted for Impact | LockBit 3.0 encrypted ~2,400 files with `.lockbit3` extension |
| **T1021.002** | Remote Services: SMB/Windows Admin Shares | Lateral propagation to `FS01` via SMB using compromised credentials |

---

## Lessons Learned

- **Detection gap**: Real-time file encryption detection thresholds need tuning. A 16-minute window before alert is unacceptable for ransomware scenarios.
- **Email gateway coverage**: New or recently registered domains should trigger a higher-scrutiny category or temporary hold for analyst review.
- **Macro policy**: Macro execution should be blocked by default for all non-power-users via Group Policy; this is a low-cost, high-impact control.
- **Least privilege**: Routine access reviews for shared drive permissions would have limited the blast radius of this incident.
- **Backup validation**: Restore procedures should be tested quarterly; recovery time from backup in this incident is estimated at 4–6 hours — within acceptable SLA.

---

*This report was generated with the assistance of the GenAI Incident Report Generator (`generate_report.py`). All content has been reviewed and validated by the reporting analyst. IOCs are defanged and for educational/portfolio use only.*
