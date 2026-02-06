# Phishing Analysis Report: Case #001
## Credential Harvesting Campaign Targeting Microsoft 365 Users

**Analyst:** SOC Analyst  
**Date:** 2024-01-15  
**Severity:** HIGH  
**Case ID:** PHI-2024-001  

---

## Email Summary

| Field | Value |
|-------|-------|
| **From (Display Name)** | Microsoft 365 Admin |
| **From (Email Address)** | admin@micros0ft-365[.]com |
| **To** | user@soclab-corp.com |
| **Subject** | Urgent: Your Microsoft 365 Password Expires Today |
| **Date Received** | 2024-01-15 09:47:32 UTC |
| **Message-ID** | <7f8a9b2c.4d5e6f7g.8h9i0j1k@micros0ft-365[.]com> |
| **Return-Path** | bounce@micros0ft-365[.]com |

---

## Email Header Analysis

### Authentication Results

| Protocol | Result | Details |
|----------|--------|---------|
| **SPF** | ❌ FAIL | IP 196.251.87.44 not authorized for domain micros0ft-365[.]com |
| **DKIM** | ❌ FAIL | No valid DKIM signature present |
| **DMARC** | ❌ FAIL | Domain has no DMARC policy; SPF and DKIM failures |

### Routing Analysis

```
Received: from mail.micros0ft-365.com (unknown [196.251.87.44])
    by mx.soclab-corp.com (Postfix) with ESMTP id A7B3C2F401
    for <user@soclab-corp.com>; Mon, 15 Jan 2024 09:47:32 +0000 (UTC)
Received: from [196.251.87.44] (port=54327)
    by mail.micros0ft-365.com with esmtp (Exim 4.94.2)
    id 1rP2Qx-0003Dy-K7; Mon, 15 Jan 2024 09:47:28 +0000
```

**Analysis:**
- Originating IP: `196.251.87.44` (Lagos, Nigeria - AS37148)
- No legitimate Microsoft infrastructure in routing path
- Direct connection from suspicious IP to target mail server
- Missing typical Microsoft email gateway hops (protection.outlook.com)

---

## Email Body Content

### Social Engineering Techniques Observed

**Urgency & Fear Tactics:**
```
Subject: Urgent: Your Microsoft 365 Password Expires Today

Dear User,

Your Microsoft 365 password is set to expire in 2 hours. To prevent 
account suspension and loss of access to your emails, documents, and 
services, you must verify your account immediately.

Click the link below to verify and reset your password:

https://login-microsoftonline.com-verify.xyz/auth

Failure to complete this verification will result in:
• Immediate account lockout
• Loss of access to all Microsoft services
• Potential data loss

This is an automated message. Do not reply to this email.

Microsoft 365 Security Team
```

**Red Flags Identified:**
- Creates artificial urgency with "2 hours" deadline
- Threatens account suspension and data loss
- Generic greeting ("Dear User") instead of personalized
- Suspicious sender domain with zero instead of 'O' (micros0ft)
- Legitimate Microsoft never requests password verification via email links
- Poor grammar and formatting inconsistencies

---

## URL Analysis

| Field | Value |
|-------|-------|
| **Defanged URL** | hxxps://login-microsoftonline[.]com-verify[.]xyz/auth |
| **Actual Domain** | login-microsoftonline.com-verify.xyz |
| **Legitimate Domain** | login.microsoftonline.com |
| **IP Address** | 185.220.101.42 |
| **Registrar** | Namecheap Inc. |
| **Creation Date** | 2024-01-10 (5 days old) |
| **Hosting** | BulletProof Hosting, Netherlands |

### URL Reputation Analysis

**VirusTotal Results:**
- Detection: 8/90 vendors flagged as phishing
- Categories: Phishing, Credential Harvesting, Malicious
- Flagged by: Fortinet, Kaspersky, ESET, Sophos, BitDefender, Avira, GData, Trustwave

**URLScan.io Analysis:**
- Screenshot captured: Clone of Microsoft 365 login page
- Requests credentials: Username and password fields present
- Exfiltration observed: Form data POSTs to hxxps://login-microsoftonline[.]com-verify[.]xyz/submit.php
- Redirect after submission: Returns to legitimate microsoft.com (masking attack)
- Technologies detected: PHP 7.4, Apache 2.4, Bootstrap CSS (copied from real Microsoft page)

**PhishTank Status:**
- Verified phishing: YES
- Submissions: 14 reports
- Online status: Active (as of analysis)

### Domain Analysis - Typosquatting

**Malicious Domain Breakdown:**
```
login-microsoftonline.com-verify.xyz
└── Subdomain structure mimicking legitimate path
    └── Uses .xyz TLD (commonly abused for phishing)
        └── Includes "verify" to appear legitimate
```

**Legitimate Microsoft Domain:**
```
login.microsoftonline.com
└── Subdomain of microsoftonline.com (Microsoft-owned)
    └── Uses .com TLD
        └── No "verify" needed in URL structure
```

---

## Indicators of Compromise (IOCs)

| Type | Indicator | Context | Severity |
|------|-----------|---------|----------|
| **Email Address** | admin@micros0ft-365[.]com | Sender address (typosquatted) | HIGH |
| **Domain** | micros0ft-365[.]com | Malicious sender domain | HIGH |
| **Domain** | login-microsoftonline[.]com-verify[.]xyz | Phishing credential harvesting site | CRITICAL |
| **URL** | hxxps://login-microsoftonline[.]com-verify[.]xyz/auth | Credential harvesting page | CRITICAL |
| **URL** | hxxps://login-microsoftonline[.]com-verify[.]xyz/submit.php | Credential exfiltration endpoint | CRITICAL |
| **IP Address** | 196.251.87.44 | Originating mail server (Nigeria) | HIGH |
| **IP Address** | 185.220.101.42 | Phishing site hosting | CRITICAL |
| **Message-ID** | <7f8a9b2c.4d5e6f7g.8h9i0j1k@micros0ft-365[.]com> | Email message identifier | MEDIUM |

### Threat Intelligence Correlation

**AbuseIPDB - 196.251.87.44:**
- Abuse Confidence Score: 100%
- Total Reports: 247
- Categories: Email Spam, Phishing, Fraudulent Activity
- Country: Nigeria (NG)
- ISP: Cobranet Limited

**VirusTotal - 185.220.101.42:**
- Malicious votes: 6
- Community score: -12
- Associated domains: 23 (all suspicious)
- Recent activity: Hosting multiple phishing campaigns

---

## Attachment Analysis

**No attachments present in this email.**

---

## Verdict

### ⚠️ CONFIRMED PHISHING — CREDENTIAL HARVESTING

**Threat Classification:** Credential Phishing (MITRE ATT&CK: T1566.002 - Phishing: Spearphishing Link)

**Confidence Level:** 100%

**Summary:**
This email is a sophisticated credential harvesting phishing attack impersonating Microsoft 365. The threat actor employs typosquatting techniques with the sender domain (micros0ft-365[.]com using zero instead of 'O') and hosts a cloned Microsoft login page designed to steal user credentials. The email uses urgency and fear tactics to pressure users into clicking the malicious link without verifying authenticity.

**Attack Chain:**
1. ✅ Email sent from typosquatted domain (micros0ft-365[.]com)
2. ✅ Email fails SPF, DKIM, and DMARC authentication
3. ✅ User clicks malicious link believing it's legitimate Microsoft
4. ✅ User lands on fake Microsoft login page (perfect clone)
5. ✅ User enters credentials thinking they're securing their account
6. ✅ Credentials exfiltrated to attacker-controlled server
7. ✅ User redirected to real Microsoft site (covers tracks)
8. ⚠️ Attacker now has valid credentials for account takeover

**Risk Assessment:**
- **Immediate Risk:** Credential compromise leading to unauthorized account access
- **Secondary Risk:** Lateral movement within organization if compromised account has elevated privileges
- **Data Breach Risk:** Access to emails, documents, and sensitive company information
- **Financial Risk:** Potential BEC follow-on attacks using compromised account

---

## Recommended Actions

### Immediate Actions (0-1 Hour)

1. **Block IOCs at Perimeter:**
   - Add sender domain `micros0ft-365.com` to email gateway blocklist
   - Block URL `login-microsoftonline.com-verify.xyz` at web proxy/firewall
   - Block IP addresses `196.251.87.44` and `185.220.101.42`

2. **Quarantine Related Emails:**
   ```
   Search criteria:
   - From domain contains: "micros0ft-365.com"
   - Body contains URL: "login-microsoftonline.com-verify.xyz"
   - Subject contains: "Password Expires Today"
   - Date range: Last 7 days
   ```

3. **Identify Affected Users:**
   - Pull email gateway logs for recipients of this campaign
   - Check web proxy logs for any clicks on malicious URLs
   - Prioritize users who clicked link for immediate investigation

4. **Credential Reset for Compromised Users:**
   - Force password reset for any user who clicked the link
   - Revoke all active sessions and tokens
   - Enable MFA if not already configured
   - Review recent account activity for unauthorized access

### Short-term Actions (1-24 Hours)

5. **Forensic Investigation:**
   - Review Azure AD/O365 audit logs for compromised accounts:
     - Unusual login locations
     - Failed authentication attempts
     - Mailbox rule creations (forwarding rules)
     - Permission changes
   - Check for lateral movement indicators
   - Analyze email sent from compromised accounts

6. **Security Control Validation:**
   - Verify anti-phishing policies are enabled in email gateway
   - Confirm SafeLinks and SafeAttachments (O365) are active
   - Test DMARC enforcement for external domains impersonating internal users
   - Review and tune email authentication policies (SPF/DKIM/DMARC)

7. **User Notification:**
   - Send security advisory to all employees about this phishing campaign
   - Include screenshots of the phishing email (educational purpose)
   - Reinforce reporting procedures for suspicious emails
   - Remind users: Microsoft never requests passwords via email

### Long-term Actions (1-7 Days)

8. **Enhanced Security Controls:**
   - Implement URL rewriting/sandboxing for all inbound email links
   - Deploy Advanced Threat Protection (ATP) if not already in place
   - Configure conditional access policies requiring MFA for cloud apps
   - Enable passwordless authentication options (Windows Hello, FIDO2)

9. **Security Awareness Training:**
   - Conduct targeted phishing simulation using similar tactics
   - Schedule mandatory security awareness training for all staff
   - Focus training on:
     - Identifying typosquatted domains
     - Recognizing urgency/fear tactics
     - Verifying sender authenticity
     - Checking URLs before clicking
     - Reporting suspicious emails

10. **Threat Hunting:**
    - Search for other typosquatted domains targeting organization:
      - Variations of company domain
      - Microsoft/O365 lookalikes
      - Common business partner domains
    - Implement OSINT monitoring for organization domain mentions on:
      - Newly registered domain feeds
      - Phishing databases
      - Dark web forums

11. **Policy Updates:**
    - Update incident response playbook with lessons learned
    - Document this case for future reference and training
    - Share IOCs with industry ISACs/information sharing groups
    - Consider implementing email banner warnings for external emails

### Metrics and Reporting

**Track the following KPIs:**
- Time to detection: ~2 hours (first user report)
- Time to containment: ~30 minutes (IOC blocking)
- Total recipients: 147 users
- Click-through rate: 8 users (5.4%)
- Credential submission rate: 3 users (2.0%)
- All compromised accounts secured within 4 hours

**Report to:**
- CISO/Security Leadership
- IT Leadership
- Compliance/Legal (if regulated data accessed)
- Cyber Insurance provider (if applicable)

---

## Lessons Learned

**What Worked Well:**
- User reported suspicious email promptly
- Email gateway logged all delivery attempts
- Quick IOC blocking prevented wider impact

**Areas for Improvement:**
- Email gateway did not initially block sender (SPF fail should have quarantined)
- Some users clicked despite previous training
- MFA not enforced on all accounts (prevented account takeover for 2/3 compromised accounts)

**Recommendations Applied:**
- Tuned email gateway to quarantine all SPF/DKIM/DMARC failures from external senders
- Implemented mandatory MFA for all cloud application access
- Deployed browser isolation for email links

---

## References

- MITRE ATT&CK: T1566.002 - Phishing: Spearphishing Link
- NIST SP 800-61: Computer Security Incident Handling Guide
- Microsoft Security: Protect against phishing attacks
- VirusTotal Report: hxxps://login-microsoftonline[.]com-verify[.]xyz
- URLScan.io Report: https://urlscan.io/result/{scan-id}/
- AbuseIPDB Report: 196.251.87.44

---

**Report Classification:** TLP:AMBER (Shareable within organization and trusted partners)  
**Next Review:** 30 days (follow-up on remediation actions)
