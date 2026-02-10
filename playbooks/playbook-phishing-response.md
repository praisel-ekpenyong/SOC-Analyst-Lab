# PB-001: Phishing Response Playbook

## Playbook Metadata

- **Playbook ID:** PB-001
- **Title:** Phishing Response
- **Version:** 1.0
- **Severity:** Medium to High (depending on payload type)
- **Owner:** SOC Tier 1 Team
- **Last Updated:** 2026-02-10
- **Review Cycle:** Quarterly
- **MITRE ATT&CK:** Initial Access - Phishing (T1566), T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link)

## Purpose

This playbook provides standardized procedures for responding to suspected phishing emails. It guides SOC analysts through email analysis, threat assessment, containment, and user notification to mitigate phishing threats.

## Trigger Conditions

This playbook should be initiated when:

- **Email Gateway Alert:** SEG (Secure Email Gateway) flags suspicious email
- **SIEM Correlation:** Splunk alert on phishing indicators (suspicious sender, malicious URL, known bad hash)
- **User Report:** User forwards suspicious email to security@company.com or IT helpdesk
- **Threat Intel Feed:** Automated feed identifies phishing campaign targeting organization
- **EDR Alert:** Attachment execution or URL click triggers endpoint alert

## Scope

**In Scope:**
- Email-based phishing attacks (credential harvesting, malware delivery, BEC)
- Spearphishing targeting specific users
- Mass phishing campaigns
- Email attachments (documents, executables, archives)
- Embedded URLs and links

**Out of Scope:**
- SMS phishing (smishing) - Use separate playbook
- Voice phishing (vishing) - Escalate to fraud team
- Compromised accounts sending internal phishing - Escalate to account compromise playbook

## Severity Classification

| Severity | Criteria |
|----------|----------|
| **Critical** | Malware executed, credentials entered, executive targeted, mass campaign affecting >100 users |
| **High** | Malicious attachment or URL, targeted spearphishing, brand impersonation |
| **Medium** | Suspicious but unverified, generic phishing, low sophistication |
| **Low** | Obvious spam, no malicious content, external sender only |

## Investigation Steps

### Step 1: Gather Email Artifacts (5 minutes)

**Objective:** Collect all relevant email data for analysis.

**Actions:**
1. Obtain full email with headers (`.eml` or `.msg` format preferred)
2. Document the following:
   - **Date/Time:** When email was received
   - **Recipient(s):** Who received the email
   - **Subject Line:** Email subject
   - **Sender Display Name:** What shows in "From" field
   - **Sender Email Address:** Actual email address
   - **Reply-To Address:** If different from sender
   - **Email Body:** Save screenshot or text
   - **Attachments:** List all file names, types, sizes
   - **URLs:** Extract all links (defang immediately)
   - **User Actions:** Did user click links or open attachments?

**Splunk Query - Check for similar emails:**
```spl
index=email_logs subject="*[subject keywords]*" earliest=-24h
| stats count by sender_address, recipient_address, subject
| sort -count
```

**Email Gateway Query:**
```spl
index=proofpoint OR index=mimecast earliest=-24h
| search sender_email="suspicious[.]sender@example[.]com"
| table _time, recipient, subject, action, threat_score
```

### Step 2: Analyze Email Headers (5 minutes)

**Objective:** Determine email authenticity and routing.

**Actions:**

1. **Extract Headers:**
   - Copy full headers from email client (View → Message Source)
   - Use header analysis tool: https://toolbox.googleapps.com/apps/messageheader/

2. **Check SPF (Sender Policy Framework):**
   ```
   Received-SPF: Pass / Fail / SoftFail / Neutral
   ```
   - **Pass:** Sending server authorized
   - **Fail:** Sending server NOT authorized (strong indicator of spoofing)
   - **SoftFail:** Questionable authorization
   - **Neutral:** Domain has no SPF record

3. **Check DKIM (DomainKeys Identified Mail):**
   ```
   Authentication-Results: dkim=pass / fail
   ```
   - **Pass:** Email signed and verified
   - **Fail:** Signature invalid or missing

4. **Check DMARC (Domain-based Message Authentication):**
   ```
   Authentication-Results: dmarc=pass / fail
   ```
   - **Pass:** SPF and/or DKIM aligned with From domain
   - **Fail:** Authentication mismatch

5. **Analyze Routing Path:**
   - Check `Received:` headers (read bottom to top)
   - Identify originating IP address
   - Look for suspicious mail servers or relay chains
   - Verify geography matches claimed sender

**Key Red Flags:**
- SPF/DKIM/DMARC all failing
- Mismatched From/Reply-To domains
- Suspicious originating IP (foreign country, VPS, Tor exit node)
- Multiple relay hops through unknown servers
- Recent domain registration (if header includes domain age)

**Example SPF Failure:**
```
Received-SPF: Fail (protection.outlook.com: domain of paypal.com does not designate 185.220.45.12 as permitted sender)
```

### Step 3: Check Sender Reputation (5 minutes)

**Objective:** Determine if sender IP/domain is known malicious.

**Actions:**

1. **Extract Originating IP:**
   - Find first external IP in `Received:` headers
   - Defang IP: `185.220.45.12` → `185[.]220[.]45[.]12`

2. **AbuseIPDB Lookup:**
   - URL: https://www.abuseipdb.com/
   - Check Abuse Confidence Score
   - Review recent reports
   - Check country of origin
   - **Verdict Criteria:**
     - Score >75% = High confidence malicious
     - Score 25-75% = Suspicious
     - Score <25% = Likely benign

3. **VirusTotal IP Lookup:**
   - URL: https://www.virustotal.com/
   - Check how many vendors flag as malicious
   - Review community comments
   - **Verdict Criteria:**
     - 5+ vendors flagging = Malicious
     - 1-4 vendors = Suspicious
     - 0 vendors = Unknown/Benign

4. **Sender Domain Analysis:**
   - WHOIS lookup for domain age and registrar
   - Check if domain is typosquatting (paypa1.com, micros0ft.com)
   - Look for recently registered domains (<30 days = high risk)

**Splunk Query - Check Sender History:**
```spl
index=email_logs sender_address="suspicious[.]sender@domain[.]com" earliest=-30d
| stats count by recipient_address, subject, action
| sort -count
```

### Step 4: Analyze URLs (10 minutes)

**Objective:** Determine if embedded URLs are malicious.

**⚠️ CRITICAL: Always defang URLs before sharing. Never click suspicious links directly.**

**Defanging Examples:**
- `https://malicious.com` → `hxxps://malicious[.]com`
- `http://evil.com/payload.exe` → `hxxp://evil[.]com/payload[.]exe`

**Actions:**

1. **Extract All URLs:**
   - Use text editor to find all `http://` and `https://` links
   - Check for hidden URLs (HTML inspect if needed)
   - Look for URL shorteners (bit.ly, tinyurl.com, goo.gl)

2. **URLScan.io Analysis:**
   - URL: https://urlscan.io/
   - Submit URL for automated scan
   - Review:
     - Page screenshot (visual confirmation)
     - Final destination (check for redirects)
     - External requests (scripts, iframes)
     - Certificate information
     - Verdict from scanner
   - **Verdict Criteria:**
     - Malicious verdict = Block immediately
     - Suspicious redirects = Investigate further
     - Certificate errors = High risk

3. **VirusTotal URL Lookup:**
   - Submit URL to VirusTotal
   - Check detection ratio (X/90 vendors)
   - **Verdict Criteria:**
     - 5+ detections = Malicious
     - 1-4 detections = Suspicious
     - 0 detections = Unknown (could be new threat)

4. **Any.Run Sandbox (if needed):**
   - URL: https://app.any.run/
   - Submit URL for dynamic analysis
   - Observe behavior in safe environment
   - Check for:
     - Fake login pages (credential harvesting)
     - Automatic downloads
     - Malicious redirects
     - Exploit kit delivery

5. **Manual URL Inspection (safe methods only):**
   - Check for typosquatting domains
   - Look for credential harvesting indicators:
     - Fake Microsoft/Google/Bank login pages
     - Forms requesting sensitive information
     - Poor spelling/grammar
     - Mismatched branding

**Common Phishing URL Patterns:**
- `https://microsoft-security-alert[.]com/verify`
- `https://paypal[.]account-suspended[.]tk/login`
- `https://sharepoint[.]file-share-93847[.]info/download`

**Splunk Query - Check if URL Visited:**
```spl
index=proxy_logs url="*malicious.com*" earliest=-7d
| table _time, user, src_ip, url, action, bytes_out
| sort _time
```

### Step 5: Analyze Attachments (10 minutes)

**Objective:** Determine if attachments are malicious.

**⚠️ WARNING: Never open suspicious attachments on production systems.**

**Actions:**

1. **Document Attachment Details:**
   - File name
   - File extension (.doc, .pdf, .exe, .zip, etc.)
   - File size
   - MD5 hash
   - SHA256 hash

2. **Calculate File Hash:**
   ```bash
   # Linux/Mac
   md5sum filename.doc
   sha256sum filename.doc
   
   # Windows PowerShell
   Get-FileHash -Algorithm MD5 filename.doc
   Get-FileHash -Algorithm SHA256 filename.doc
   ```

3. **VirusTotal Hash Lookup:**
   - Search by file hash (preferred - doesn't upload file)
   - If hash unknown, submit file for analysis
   - **Verdict Criteria:**
     - 5+ AV detections = Malicious
     - 1-4 detections = Suspicious
     - 0 detections = Unknown (could be new)

4. **File Type Analysis:**
   - **High Risk:**
     - Executables: .exe, .scr, .bat, .cmd, .ps1
     - Office docs with macros: .docm, .xlsm, .pptm
     - Script files: .vbs, .js, .jar
     - Archives: .zip, .rar, .7z (may contain above)
   - **Medium Risk:**
     - Office docs: .doc, .xls, .ppt (older formats)
     - PDFs: .pdf (can contain exploits)
   - **Low Risk:**
     - Modern Office: .docx, .xlsx, .pptx (no macros)
     - Text files: .txt, .csv
     - Images: .jpg, .png (unless using exploit)

5. **Sandbox Analysis (if needed):**
   - Use Any.Run or Hybrid-Analysis
   - Upload file for automated detonation
   - Observe:
     - Process execution
     - Network connections (C2 communication?)
     - File system changes
     - Registry modifications
     - Persistence mechanisms

6. **Static Analysis (if skillset permits):**
   - Check for embedded macros (olevba tool)
   - Look for obfuscated code
   - Search for known malicious patterns

**Splunk Query - Check for Attachment Execution:**
```spl
index=windows_sysmon EventCode=1 
| eval lower_image=lower(Image)
| search lower_image="*\\appdata\\*" OR lower_image="*\\temp\\*" OR lower_image="*\\downloads\\*"
| search ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*POWERPNT.EXE"
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time
```

### Step 6: Determine Verdict (5 minutes)

**Objective:** Make a final determination on the email's malicious nature.

**Verdict Categories:**

**1. MALICIOUS - HIGH CONFIDENCE**
- Malware detected by AV/sandbox
- Known malicious hash/URL/IP
- SPF/DKIM/DMARC all failing + suspicious content
- Credential harvesting page confirmed
- Active C2 communication observed

**Action:** Proceed to containment immediately

---

**2. SUSPICIOUS - MEDIUM CONFIDENCE**
- SPF failures but no other indicators
- Unknown file hash but suspicious file type
- Sender reputation questionable
- Typosquatting domain
- Social engineering tactics present

**Action:** Recommend caution, continue monitoring, advise users not to interact

---

**3. BENIGN - LOW RISK**
- All authentication checks pass
- No malicious indicators
- Legitimate business communication
- False positive from automated systems

**Action:** Notify user email is safe, update detection rules to reduce false positives

---

**4. INCONCLUSIVE - NEEDS ESCALATION**
- Conflicting evidence
- Advanced evasion techniques observed
- Targeted spearphishing of executive
- Requires deeper forensics

**Action:** Escalate to Tier 2/3

## Containment Actions

### If Verdict = MALICIOUS or SUSPICIOUS:

1. **Block Sender (Immediate):**
   ```powershell
   # Microsoft 365 - Block sender domain
   Set-HostedContentFilterPolicy -Identity Default -BlockedSenderDomains @{Add="malicious-domain.com"}
   ```

2. **Quarantine Similar Emails:**
   - Search email gateway for similar emails
   - Quarantine all matching messages
   - Prevent delivery to other users

   **Splunk Query:**
   ```spl
   index=email_logs sender_address="*@malicious-domain.com" earliest=-24h
   | table _time, recipient_address, subject, action
   ```

3. **Block URLs/Domains:**
   - Add malicious URLs to proxy/firewall block list
   - Add to DNS sinkhole
   - Update web filter categories

   ```bash
   # Palo Alto Firewall - Add to block list
   set profiles url-filtering [profile-name] block [URL]
   
   # Cisco Umbrella - Add to block list
   Add domain to blacklist via dashboard
   ```

4. **Block IP Addresses:**
   - Add malicious IPs to firewall rules
   - Add to IPS/IDS signatures

5. **Add IOCs to SIEM:**
   ```spl
   # Create lookup table for future detection
   | inputlookup phishing_iocs.csv
   | append [| makeresults | eval sender_address="malicious@domain.com", ioc_type="email", threat_name="Phishing Campaign XYZ", date_added="2026-02-10"]
   | outputlookup phishing_iocs.csv
   ```

### If User Clicked Link or Opened Attachment:

6. **Reset User Credentials:**
   - Force password reset for affected user
   - Revoke active sessions
   - Check for MFA bypass

   ```powershell
   # Active Directory - Force password reset
   Set-ADUser -Identity username -ChangePasswordAtLogon $true
   ```

7. **Check for Compromise:**
   - Review user's sent mail for forwarding rules
   - Check for suspicious login locations
   - Look for mailbox delegation changes
   - Review inbox rules for auto-deletion

   **Splunk Query - Check User Activity:**
   ```spl
   index=windows_security EventCode=4624 Account_Name="affected_user" earliest=-24h
   | table _time, src_ip, Logon_Type, Workstation_Name
   | sort -_time
   ```

8. **Isolate Endpoint (if malware executed):**
   - Use EDR to network-isolate affected system
   - Prevent lateral movement
   - Initiate malware response playbook

9. **Scan Endpoint:**
   ```bash
   # Force full AV scan
   # Wazuh agent - trigger scan
   /var/ossec/bin/agent_control -r -a
   ```

## Eradication

1. **Remove Phishing Emails from All Mailboxes:**
   ```powershell
   # Microsoft 365 - Search and delete
   New-ComplianceSearch -Name "Phishing Cleanup" -ExchangeLocation All -ContentMatchQuery 'subject:"Urgent: Verify Your Account"'
   Start-ComplianceSearch -Identity "Phishing Cleanup"
   
   # After confirming results:
   New-ComplianceSearchAction -SearchName "Phishing Cleanup" -Purge -PurgeType HardDelete
   ```

2. **Update Detection Rules:**
   - Add sender domains to block list
   - Update SIEM correlation rules
   - Add file hashes to EDR blocklist

3. **Remove Malware (if applicable):**
   - Follow malware response playbook
   - Remove persistence mechanisms
   - Restore from clean backup if needed

## Recovery

1. **User Notification Email Template:**
   ```
   Subject: Security Alert - Phishing Email Detected
   
   Dear [User Name],
   
   Our security team has identified a phishing email that was delivered to your mailbox:
   
   Subject: [Phishing Email Subject]
   From: [Sender Address]
   Received: [Date/Time]
   
   This email has been confirmed as malicious and has been removed.
   
   If you interacted with this email (clicked links or opened attachments):
   1. Your password has been reset as a precaution
   2. Check for unauthorized account activity
   3. Report any suspicious behavior immediately
   
   If you did NOT interact with this email:
   - No action required
   - Delete the email if still present
   
   Remember: IT will never ask for passwords via email.
   
   Questions? Contact: security@company.com
   
   Thank you,
   Security Operations Center
   ```

2. **Security Awareness Reminder:**
   - Send security tip to all employees
   - Highlight red flags from this specific phishing attempt
   - Reinforce reporting procedures

3. **Monitor for Recurrence:**
   - Watch for similar campaigns
   - Check for domain variations
   - Set up enhanced monitoring for 30 days

## Escalation Criteria

**Escalate to Tier 2/3 if:**
- Executive or high-value target affected
- Credentials were entered and account shows signs of compromise
- Malware executed and EDR containment unsuccessful
- Zero-day exploit suspected
- Advanced persistent threat (APT) indicators
- Widespread campaign affecting >100 users
- Business Email Compromise (BEC) with financial impact
- Ransomware payload detected

**Escalate to Management if:**
- C-level executive targeted
- Successful BEC with wire transfer
- Data breach suspected
- Regulatory reporting may be required

**Escalate to Law Enforcement if:**
- Financial fraud with losses >$10,000
- Nation-state actor suspected
- Criminal activity confirmed

## Documentation Requirements

**Minimum Required Documentation:**
- Email artifacts (headers, body, attachments, URLs)
- Analysis results (VirusTotal, URLScan, AbuseIPDB)
- Verdict and confidence level
- List of all affected users
- Actions taken (blocks, quarantines, resets)
- User notifications sent
- Timeline of events

**Incident Ticket Template:**
```
Incident ID: INC-2026-XXXXX
Title: Phishing Email - [Brief Description]
Severity: [Critical/High/Medium/Low]
Date Opened: 2026-02-10 14:23 UTC
Analyst: [Your Name]

ALERT DETAILS:
- Alert Source: [User Report/Email Gateway/SIEM]
- Alert Time: [YYYY-MM-DD HH:MM UTC]
- Report Method: [How was it reported?]

EMAIL DETAILS:
- Subject: [Email subject]
- Sender: [Display name] <email@domain.com>
- Recipient(s): [List]
- Date Received: [YYYY-MM-DD HH:MM UTC]
- Originating IP: [Defanged IP]

ANALYSIS RESULTS:
- SPF: [Pass/Fail]
- DKIM: [Pass/Fail]
- DMARC: [Pass/Fail]
- Sender IP Reputation: [Score/Verdict]
- URLs: [List defanged URLs with verdicts]
- Attachments: [List with hashes and verdicts]

VERDICT: [Malicious/Suspicious/Benign/Inconclusive]
CONFIDENCE: [High/Medium/Low]

USER ACTIONS:
- Did user click links? [Yes/No]
- Did user open attachments? [Yes/No]
- Did user enter credentials? [Yes/No]

RESPONSE ACTIONS:
- [ ] Sender blocked
- [ ] URLs/IPs blocked
- [ ] Similar emails quarantined
- [ ] User credentials reset (if needed)
- [ ] User notified
- [ ] IOCs added to SIEM

IOCS:
- Sender IP: [Defanged]
- Sender Domain: [Defanged]
- URLs: [List defanged]
- File Hashes: [List]

OUTCOME: [Brief summary of resolution]
```

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Detection Method |
|--------|-----------|--------------|------------------|
| Initial Access | Phishing | T1566 | Email gateway alerts, user reports |
| Initial Access | Spearphishing Attachment | T1566.001 | Email attachment analysis, EDR alerts |
| Initial Access | Spearphishing Link | T1566.002 | URL reputation checks, proxy logs |
| Execution | User Execution: Malicious File | T1204.002 | EDR process monitoring, Sysmon Event 1 |
| Credential Access | Input Capture: Credential API Hooking | T1056.004 | Fake login page analysis |
| Collection | Email Collection | T1114 | Mailbox rule monitoring |

## Decision Tree

```
┌─────────────────────────┐
│   Phishing Alert        │
│   Received              │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Step 1: Gather Email    │
│ Artifacts               │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Step 2: Analyze Headers │
│ SPF/DKIM/DMARC?         │
└────────────┬────────────┘
             │
         ┌───┴───┐
         │  All  │ Fail?
         │ Pass? │
         └───┬───┘
      Pass   │   Fail
        ▼    │    ▼
    [Lower   │   [Higher
     Risk]   │    Risk]
             ▼
┌─────────────────────────┐
│ Step 3: Check Sender    │
│ Reputation              │
└────────────┬────────────┘
             │
      Malicious?
         │
     Yes │ No
         ▼
┌─────────────────────────┐
│ Step 4: Analyze URLs    │
│ (if present)            │
└────────────┬────────────┘
             │
      Malicious?
         │
     Yes │ No
         ▼
┌─────────────────────────┐
│ Step 5: Analyze         │
│ Attachments (if present)│
└────────────┬────────────┘
             │
      Malicious?
         │
         ▼
┌─────────────────────────┐
│ Step 6: Determine       │
│ Verdict                 │
└────────────┬────────────┘
             │
      ┌──────┴──────┐
      │ Malicious?  │
      └──────┬──────┘
         Yes │ No
             ▼
    ┌────────────────┐
    │  Containment   │
    │  Actions       │
    └────────┬───────┘
             │
             ▼
    ┌────────────────┐
    │  Eradication   │
    │  & Recovery    │
    └────────┬───────┘
             │
             ▼
    ┌────────────────┐
    │  Documentation │
    │  & Closure     │
    └────────────────┘
```

## Lessons Learned

**Common Mistakes to Avoid:**
- Clicking suspicious links directly (always use URLScan.io)
- Opening attachments on production systems
- Forgetting to defang IOCs before sharing
- Not checking if user interacted with email
- Blocking too broadly (entire legitimate domains)
- Insufficient documentation

**Best Practices:**
- Always defang URLs and IPs in documentation
- Use sandbox environments for analysis
- Document every step taken
- Communicate clearly with affected users
- Update threat intelligence feeds
- Conduct post-incident review

## References

- **NIST SP 800-61 Rev. 2:** Incident Handling Guide
- **CISA Phishing Guidance:** https://www.cisa.gov/phishing
- **Anti-Phishing Working Group (APWG):** https://apwg.org/
- **RFC 7208:** SPF Protocol Specification
- **RFC 6376:** DKIM Protocol Specification
- **RFC 7489:** DMARC Protocol Specification

---

**Version History:**
- v1.0 (2026-02-10): Initial playbook creation

**Next Review Date:** 2026-05-10
