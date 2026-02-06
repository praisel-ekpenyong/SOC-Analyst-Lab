# Phishing Analysis Report: Case #003
## Business Email Compromise (BEC) - CEO Impersonation Wire Fraud Attempt

**Analyst:** SOC Analyst  
**Date:** 2024-01-22  
**Severity:** CRITICAL  
**Case ID:** PHI-2024-003  

---

## Email Summary

| Field | Value |
|-------|-------|
| **From (Display Name)** | David Roberts, CEO |
| **From (Email Address)** | d.roberts@soclab-corp[.]com |
| **Reply-To** | d.r0berts.ceo@gmail[.]com |
| **To** | cfo@soclab.local |
| **Subject** | Re: Wire Transfer — Urgent |
| **Date Received** | 2024-01-22 16:47:09 UTC |
| **Message-ID** | <CAG8o=1a2b3c4d5e6f7g8h9i0j@mail.gmail[.]com> |
| **Return-Path** | d.r0berts.ceo@gmail[.]com |

---

## Email Header Analysis

### Authentication Results

| Protocol | Result | Details |
|----------|--------|---------|
| **SPF** | ✅ PASS | Gmail infrastructure authorized to send for gmail.com domain |
| **DKIM** | ✅ PASS | Valid DKIM signature from google.com |
| **DMARC** | ✅ PASS | Alignment passes for gmail.com (NOT soclab.local) |

### Routing Analysis

```
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
    by mx.soclab.local (Postfix) with ESMTPS id C9D4E4H603
    for <cfo@soclab.local>; Mon, 22 Jan 2024 16:47:09 +0000 (UTC)
Received: by mail-sor-f41.google.com with SMTP id 46e09a7af769-6d8f1a2b5e5so4312374a34.1
    for <cfo@soclab.local>; Mon, 22 Jan 2024 08:47:09 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=gmail.com; s=20230601;
    h=to:subject:message-id:date:from:mime-version:from:to:cc:subject:date;
    bh=Xp9c8bH3fG2eD1aF4bE5cA6hG7iJ8kL9mN0oP1qR2sT3uV4w=;
    b=K8J7i6H5g4F3e2D1c0B9a8Z7y6X5w4V3u2T1s0R9q8P7o6N5m4L3k2J1i0H9g8F7
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=1e100.net; s=20230601;
    h=to:subject:message-id:date:from:mime-version:x-gm-message-state:from:to:cc:subject:date;
    bh=Xp9c8bH3fG2eD1aF4bE5cA6hG7iJ8kL9mN0oP1qR2sT3uV4w=;
    b=M9n8L7k6J5i4H3g2F1e0D9c8B7a6Z5y4X3w2V1u0T9s8R7q6P5o4N3m2L1k0J9i8
X-Gm-Message-State: AOJu0Yx1y2Z3a4B5c6D7e8F9g0H1i2J3k4L5m6N7o8P9q0R1s2T3u4V5w6
Received: from [172.58.146.203] (cpe-172-58-146-203.nyc.res.rr.com. [172.58.146.203])
    by smtp.gmail.com with ESMTPSA id h13-20020a056402440d00b0053a1b8c7e4csm3456789edv.11.2024.01.22.08.47.07
    for <cfo@soclab.local>
    (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
    Mon, 22 Jan 2024 08:47:07 -0800 (PST)
X-Originating-IP: [172.58.146.203]
X-Mailer: Apple Mail (2.3903.0.127)
```

**Analysis - Critical Findings:**
- ✅ Email sent through legitimate Gmail infrastructure (not spoofed)
- ✅ SPF/DKIM/DMARC all pass **for gmail.com** (this is the deception!)
- ⚠️ **From address spoofs company domain:** d.roberts@soclab-corp[.]com
  - **Real company domain:** soclab.local
  - **Attacker domain:** soclab-corp.com (typosquatted lookalike)
- ⚠️ **Reply-To field redirects to personal Gmail:** d.r0berts.ceo@gmail[.]com
  - Note: Zero instead of 'O' in "r0berts"
- 🔴 Originating IP: `172.58.146.203` (New York, USA - Spectrum residential ISP)
  - Residential IP, not corporate infrastructure
  - Authenticated via Gmail using SMTP
- 🔴 X-Mailer indicates Apple Mail client (CEO uses Windows Outlook)
- 🔴 Email sent Monday 8:47 AM PST (4:47 PM EST) - CEO known to be in meeting per calendar

### Why Email Authentication Passed

**Critical Understanding for BEC Detection:**

Gmail's email authentication validates that:
1. The email truly came from Gmail servers (SPF passes for gmail.com) ✅
2. Gmail properly signed the email (DKIM passes) ✅
3. The "From" domain alignment matches Gmail's records (DMARC passes for gmail.com) ✅

**However, this does NOT validate:**
- Whether the sender has permission to use the display name "David Roberts, CEO"
- Whether d.roberts@soclab-corp.com is a legitimate company email
- Whether the sender actually works for the company

**The Deception:**
- Attacker registered lookalike domain: soclab-corp[.]com
- Set up Gmail forwarding or SMTP relay for that domain
- Used Gmail's infrastructure to send email
- Authentication validates Gmail (which is legitimate)
- But does NOT validate sender's authority to represent the CEO

**Why This Bypasses Traditional Filters:**
- No malicious URLs (social engineering only)
- No malicious attachments
- Passes SPF/DKIM/DMARC checks
- Grammar and spelling are perfect
- Sent from legitimate email platform (Gmail)

---

## Email Body Content

### Full Email Text

```
From: David Roberts, CEO <d.roberts@soclab-corp.com>
Reply-To: d.r0berts.ceo@gmail.com
To: Sarah Chen, CFO <cfo@soclab.local>
Subject: Re: Wire Transfer — Urgent
Date: Monday, January 22, 2024 4:47 PM EST

Sarah,

I hope this email finds you well.

I need your help with an urgent and confidential matter. We are in 
the final stages of acquiring a new vendor partnership that will be 
announced next month. The legal team has finalized the contract, but 
we need to process an immediate wire transfer to secure the agreement 
before the close of business today.

Due to the confidential nature of this acquisition, I'm handling this 
personally and cannot discuss it openly. The vendor requires payment 
of $47,500.00 to reserve manufacturing capacity for Q2.

Please process the wire transfer using the following details:

  Bank Name: First International Bank
  Account Name: Apex Solutions LLC
  Account Number: 4827-9364-1052
  Routing Number: 026009593
  SWIFT Code: FIBAUS33XXX
  Reference: Invoice #SOC-2024-Q2-001

This is time-sensitive as the vendor has other interested parties. 
Please confirm once the wire transfer is initiated. I'm currently in 
back-to-back meetings with potential investors and may not be able to 
respond immediately, but this needs to be completed before 5 PM EST 
today.

If you have any questions, please reply to this email or text me at 
the number I gave you last week. Do not call my office line as I'm 
offsite today.

I appreciate your prompt attention to this matter.

Best regards,

David Roberts
Chief Executive Officer
SOC Lab Corp
Mobile: +1 (347) 555-0198
"Innovation Through Security"
```

---

## Social Engineering Analysis

### Psychological Manipulation Tactics

**1. Authority Exploitation:**
- Impersonates CEO (highest authority in organization)
- Uses full title: "Chief Executive Officer"
- Includes company tagline to appear authentic
- Leverages CEO's authority to bypass normal approval processes

**2. Urgency & Time Pressure:**
- "Urgent and confidential matter"
- "Before close of business today"
- "This is time-sensitive"
- "Before 5 PM EST today"
- Creates artificial deadline to prevent verification

**3. Secrecy & Confidentiality:**
- "Confidential nature of this acquisition"
- "Cannot discuss it openly"
- "I'm handling this personally"
- Discourages CFO from consulting others or following normal procedures
- Makes CFO feel "special" or trusted with secret information

**4. Legitimacy Indicators:**
- Professional language and grammar (no obvious errors)
- Uses company name correctly
- Includes detailed banking information (appears legitimate)
- References company-style invoice number format
- Includes mobile number (appears to offer verification path)

**5. Isolation Tactics:**
- "Do not call my office line as I'm offsite today"
- "Reply to this email or text me"
- Directs communication away from verified channels
- Prevents CFO from verifying via normal corporate communication methods
- Reply-To field ensures responses go to attacker's Gmail

**6. Justification & Story:**
- Plausible business scenario (vendor acquisition)
- Explains why normal processes don't apply
- "Legal team has finalized the contract" (implies legitimacy)
- "Vendor has other interested parties" (fear of missing opportunity)

**7. Relationship Assumptions:**
- "I hope this email finds you well" (casual familiarity)
- References previous communication: "text me at the number I gave you last week"
- Creates false sense of established relationship
- Makes CFO hesitant to question authenticity

### Red Flags Identified

**Email Technical Indicators:**
- ⚠️ From domain typosquatting: soclab-corp[.]com vs soclab.local
- ⚠️ Reply-To redirects to personal Gmail account
- ⚠️ Reply-To has typo: r0berts (zero instead of 'o')
- ⚠️ Sent from residential IP, not corporate infrastructure
- ⚠️ X-Mailer shows Apple Mail (CEO uses Outlook)
- ⚠️ Sent during time CEO is in scheduled meeting

**Content Red Flags:**
- 🚩 Requests wire transfer via email (violates corporate policy)
- 🚩 Bypasses normal approval workflow for large payments
- 🚩 Demands secrecy and discourages verification
- 🚩 Creates artificial urgency and deadline
- 🚩 Directs communication away from corporate channels
- 🚩 CEO would never request CFO to text personal mobile for business transactions
- 🚩 Invoice number format is incorrect (should be INV-2024-Q1-XXXX based on company standards)
- 🚩 Amount $47,500 is just under typical dual-authorization threshold ($50,000)

**Business Logic Red Flags:**
- 🚩 No prior email thread (subject says "Re:" but this is first email)
- 🚩 No mention of specific vendor name (vague "Apex Solutions LLC")
- 🚩 No request for proper documentation (contract, invoice, W-9, etc.)
- 🚩 Payment described as "reserve manufacturing capacity" (unusual phrasing)
- 🚩 CEO handling vendor payments personally (not CFO's typical workflow)
- 🚩 Request violates corporate financial controls and dual-authorization policy

---

## URL Analysis

**No URLs present in email body.**

This is characteristic of sophisticated BEC attacks that rely purely on social engineering rather than technical exploits. The absence of malicious links or attachments allows the email to bypass URL reputation filters and sandboxing technologies.

---

## Attachment Analysis

**No attachments present in email.**

Pure social engineering BEC attack. No technical payload required. The attack relies entirely on manipulating the recipient into initiating the fraudulent wire transfer through legitimate banking channels.

---

## Domain Analysis

### Typosquatted Domain Investigation

**Malicious Domain:** soclab-corp[.]com  
**Legitimate Domain:** soclab.local (internal company domain)

| Field | Malicious Domain | Legitimate Domain |
|-------|------------------|-------------------|
| **Domain** | soclab-corp.com | soclab.local |
| **Registrar** | Namecheap, Inc. | N/A (internal Active Directory) |
| **Creation Date** | 2024-01-18 (4 days old) | 2019-03-15 (company founded) |
| **Registrant** | Privacy Protected (WhoisGuard) | SOC Lab Corp, New York, NY |
| **Name Servers** | ns1.namecheap.com, ns2.namecheap.com | Internal DNS servers |
| **Hosting** | None (Gmail forwarding only) | On-premises Exchange/Microsoft 365 |

**WHOIS Analysis - soclab-corp[.]com:**
```
Domain Name: SOCLAB-CORP.COM
Registry Domain ID: 2781653421_DOMAIN_COM-VRSN
Registrar: NAMECHEAP INC
Creation Date: 2024-01-18T14:23:11Z
Registry Expiry Date: 2025-01-18T14:23:11Z
Registrar Registration Expiration Date: 2025-01-18T14:23:11Z
Registrant Organization: Privacy Protected
Registrant State/Province: Iceland
Registrant Country: IS
Admin Email: abuse@namecheap.com
Tech Email: abuse@namecheap.com
Name Server: NS1.NAMECHEAP.COM
Name Server: NS2.NAMECHEAP.COM
DNSSEC: unsigned
```

**Key Findings:**
- Domain registered 4 days before phishing email sent (preparation phase)
- Privacy protection used to hide attacker identity
- Registrant country: Iceland (typical privacy haven)
- No website hosted on domain (email-only use)
- No MX records (using Gmail forwarding instead)

### Domain Reputation Analysis

**VirusTotal:**
- 0/92 vendors flag domain as malicious (too new)
- No associations with malicious files
- No community votes yet

**Cisco Umbrella (OpenDNS):**
- Domain Rank: N/A (too new)
- First seen: 2024-01-18
- Category: Uncategorized

**AlienVault OTX:**
- No threat intelligence pulses
- No indicators of compromise
- Domain not yet reported

**URLhaus / PhishTank:**
- No entries found

**Why No Detection:**
- Domain is too new (4 days old)
- No technical IOCs (no malware, no phishing sites)
- Pure social engineering attack
- Not yet reported to threat intelligence feeds

---

## Banking Information Analysis

**Provided Banking Details:**
```
Bank Name: First International Bank
Account Name: Apex Solutions LLC
Account Number: 4827-9364-1052
Routing Number: 026009593
SWIFT Code: FIBAUS33XXX
Reference: Invoice #SOC-2024-Q2-001
```

### Banking Details Verification

**Routing Number Analysis: 026009593**
- **Bank:** Bank of America, N.A.
- **Location:** New York, NY
- **Type:** Wire transfer routing number (valid format)
- ⚠️ **Mismatch:** Email claims "First International Bank" but routing number is Bank of America

**SWIFT Code Analysis: FIBAUS33XXX**
- **Format:** Valid SWIFT code structure
- ⚠️ **Verification:** FIBAUS33 is NOT a registered SWIFT code
- Legitimate SWIFT codes are publicly verifiable
- This appears fabricated to look legitimate

**Account Name: "Apex Solutions LLC"**
- Generic, professional-sounding business name
- Common tactic: Use vague LLC name that could belong to any industry
- No verifiable connection to any real vendor relationship
- Google search reveals multiple unrelated businesses with similar names

### Financial Fraud Indicators

**Amount: $47,500**
- Just below typical $50,000 dual-authorization threshold
- Attackers research company financial policies to stay under radar
- Large enough to be profitable but small enough to avoid extra scrutiny

**Payment Purpose: "Reserve manufacturing capacity"**
- Vague justification that sounds business-like
- No specific products or services mentioned
- Unusual for upfront payment without contract documentation

**Urgency: "Before 5 PM EST today"**
- Prevents time for verification through normal banking compliance checks
- Pressures CFO to use expedited wire transfer
- Doesn't allow overnight review or consultation with colleagues

---

## Threat Actor Analysis

### Attack Methodology - BEC Playbook

**Phase 1: Reconnaissance (Days/Weeks Before)**
```
Attacker researched:
- Company organizational structure (CEO name: David Roberts)
- Key personnel (CFO: Sarah Chen)
- Company email format (firstname@soclab.local)
- Corporate policies (under-$50k threshold doesn't require dual auth)
- CEO's schedule (knew about Monday meeting - possible LinkedIn reconnaissance)
- Company business model (security/SOC services)
```

**Sources for Reconnaissance:**
- LinkedIn profiles (organizational hierarchy, employee names)
- Company website (leadership bios, contact information)
- Job postings (reveal internal tools, processes, org structure)
- Social media (employee posts about company culture, events)
- Email harvesting (data breaches, publicly accessible emails)
- Prior compromises (possible access to corporate calendar/email)

**Phase 2: Infrastructure Setup**
- Registered typosquatted domain soclab-corp[.]com (Jan 18)
- Configured Gmail forwarding for d.roberts@soclab-corp.com
- Set up Reply-To Gmail account: d.r0berts.ceo@gmail.com
- Waited 4 days before attack (avoid immediate detection of new domain)

**Phase 3: Attack Execution**
- Sent BEC email on Monday during business hours (legitimate timing)
- Targeted CFO specifically (has authority for wire transfers)
- Exploited CEO-to-CFO relationship (authority + trust)
- Created urgency to prevent verification
- Directed responses to Gmail (under attacker control)

**Phase 4: Follow-Up (Expected)**
- If CFO replies, attacker responds quickly from Gmail address
- Provides additional "verification" details if questioned
- Escalates urgency if CFO hesitates
- May impersonate other executives if needed (lawyer, board member)
- Confirms wire transfer and provides fake "next steps"

**Phase 5: Money Movement (If Successful)**
- Receives wire transfer to compromised or mule account
- Immediately moves funds through multiple accounts (layering)
- Transfers to cryptocurrency or overseas accounts
- Funds typically unrecoverable within 24-48 hours

### Threat Actor Profile

**Likely Attribution:**
- **Type:** Financially motivated cybercriminal
- **Sophistication:** Medium-High
  - Professional-quality social engineering
  - Understanding of corporate financial processes
  - Domain typosquatting infrastructure
  - No technical malware (avoids detection)
- **Origin:** Likely West Africa or Eastern Europe (common BEC hubs)
  - Nigerian fraud groups (419 scams evolved to BEC)
  - Eastern European organized cybercrime
- **Prior Activity:** Likely serial BEC attacker targeting multiple organizations
- **Risk Assessment:** Will likely retry with different tactics after failed attempt

**Similar Campaigns:**
- FBI IC3 reports thousands of BEC cases annually ($2.4 billion losses in 2021)
- Common targets: Finance, real estate, healthcare, legal sectors
- Average loss per incident: $120,000 (this attempt: $47,500)

---

## Indicators of Compromise (IOCs)

| Type | Indicator | Context | Severity |
|------|-----------|---------|----------|
| **Domain** | soclab-corp[.]com | Typosquatted company domain | CRITICAL |
| **Email Address** | d.roberts@soclab-corp[.]com | Impersonated CEO email | CRITICAL |
| **Email Address** | d.r0berts.ceo@gmail[.]com | Reply-To address (zero in "r0berts") | CRITICAL |
| **IP Address** | 172.58.146.203 | Originating IP (NYC, Spectrum residential) | HIGH |
| **Bank Account** | 4827-9364-1052 | Fraudulent destination account | CRITICAL |
| **Routing Number** | 026009593 | Bank of America routing | HIGH |
| **Entity Name** | Apex Solutions LLC | Fake vendor name | MEDIUM |
| **Phone Number** | +1 (347) 555-0198 | Fake mobile number provided | MEDIUM |
| **Invoice Number** | SOC-2024-Q2-001 | Fake reference number | LOW |

**Note:** Unlike malware-based attacks, BEC IOCs are primarily identity and financial indicators rather than file hashes or malicious URLs.

---

## Verdict

### 🔴 CONFIRMED PHISHING — BUSINESS EMAIL COMPROMISE (BEC)

**Threat Classification:**
- MITRE ATT&CK: T1566.002 - Phishing: Spearphishing Link (social engineering variant)
- MITRE ATT&CK: T1534 - Internal Spearphishing (CEO to CFO targeting)
- FBI Classification: Business Email Compromise (BEC) - CEO Fraud variant

**Confidence Level:** 100%

**Summary:**
This is a sophisticated Business Email Compromise (BEC) attack employing CEO impersonation to defraud the company of $47,500. The attacker registered a typosquatted domain (soclab-corp[.]com) to impersonate the CEO and targeted the CFO with a convincing wire transfer request. The email employs advanced social engineering tactics including authority exploitation, urgency, confidentiality, and isolation to pressure the victim into bypassing normal financial controls.

**Why This Is Dangerous:**
Unlike malware-based phishing, BEC attacks:
- ✅ Pass email authentication (SPF/DKIM/DMARC)
- ✅ Contain no malicious URLs or attachments
- ✅ Use legitimate email platforms (Gmail)
- ✅ Bypass technical security controls
- ✅ Target humans, not systems
- ✅ Result in direct, immediate financial loss

**Attack Chain:**

```
┌─────────────────────────────────────────────────────────────────┐
│ Phase 1: Reconnaissance                                         │
│ Attacker researches company structure, personnel, policies     │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 2: Infrastructure Setup                                   │
│ Registers typosquatted domain soclab-corp[.]com               │
│ Sets up Gmail forwarding/relay for fake CEO email             │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 3: Social Engineering Email                              │
│ Sends convincing CEO impersonation email to CFO                │
│ Uses authority, urgency, secrecy to manipulate                │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────────┐
│ Phase 4: Victim Decision Point                                  │
│ CFO must decide: Process wire or verify authenticity?          │
│ ❌ If victim processes: $47,500 lost                           │
│ ✅ If victim verifies: Attack prevented (THIS CASE)            │
└────────────┬────────────────────────────────────────────────────┘
             │
             ▼ (Attack Failed - Verification Occurred)
┌─────────────────────────────────────────────────────────────────┐
│ Phase 5: Money Movement (Would Occur If Successful)            │
│ Funds transferred to compromised account                       │
│ Immediate movement through multiple accounts                   │
│ Conversion to cryptocurrency or overseas transfer              │
│ Funds become unrecoverable                                     │
└─────────────────────────────────────────────────────────────────┘
```

**Why Attack Failed:**
- CFO followed corporate policy requiring voice verification for wire transfers
- CFO called CEO's office line (not provided number) to confirm
- CEO confirmed he did not send any wire transfer request
- CFO immediately escalated to IT security team
- **Outcome:** $47,500 loss prevented ✅

**If Attack Had Succeeded:**
- Direct financial loss: $47,500
- Bank recovery likelihood: <5% (once wire processed, funds rarely recovered)
- Investigation costs: $15,000-30,000
- Reputational damage: Loss of stakeholder confidence
- Regulatory reporting: FBI IC3, potential SEC disclosure (if public company)
- Insurance claim complexity: Cyber insurance may have exclusions for social engineering

---

## Recommended Actions

### 🚨 CRITICAL - Immediate Response (0-1 Hour)

1. **Alert Financial Institutions:**
   ```
   Action: Contact all company banks immediately
   Purpose: Alert fraud departments to potential BEC targeting
   
   Message to banks:
   "Our organization is being targeted by a Business Email Compromise (BEC) 
   attack. Please flag our accounts for additional verification on any wire 
   transfer requests for the next 30 days. We will implement dual-factor 
   authentication via phone call to [designated security contact] before 
   processing any wires."
   
   Provide:
   - Fraudulent account details: 4827-9364-1052, Routing 026009593
   - Alert for any attempts to wire funds to this account
   ```

2. **Block Malicious Domain & Addresses:**
   ```
   Email Gateway Configuration:
   - Block domain: soclab-corp.com (all addresses)
   - Block specific addresses:
     • d.roberts@soclab-corp.com
     • d.r0berts.ceo@gmail.com (zero in r0berts)
   - Create alert rule for any email containing "soclab-corp.com"
   - Block any email with CEO name in From field but external domain
   ```

3. **Hunt for Similar Attempts:**
   ```
   Email Gateway Query - Last 90 Days:
   
   Search for:
   1. From display name contains: "David Roberts" OR "CEO"
      AND from domain NOT soclab.local
   
   2. Subject contains: "wire" OR "transfer" OR "urgent" OR "confidential"
      AND to: cfo@soclab.local OR finance@soclab.local
   
   3. Reply-To domain: gmail.com, yahoo.com, outlook.com
      AND From display name contains executive names
   
   4. Any email from domains similar to soclab.local:
      - soclab-corp.com ✓ (current)
      - soc-lab.com
      - soclab.com
      - soclabcorp.com
      - soc1ab.com (l → 1)
   ```

4. **Verify No Other Executives Impersonated:**
   ```
   Check for emails impersonating:
   - CEO: David Roberts
   - CFO: Sarah Chen
   - COO: [Name]
   - General Counsel: [Name]
   - VP Finance: [Name]
   
   Expand domain block list if other impersonations found
   ```

5. **Emergency Communication to Finance Team:**
   ```
   URGENT SECURITY ALERT - Send within 1 hour
   
   To: All Finance, Accounting, Treasury staff
   Subject: ACTIVE BEC ATTACK - Verify All Wire Requests
   
   Content:
   "A Business Email Compromise (BEC) attack is actively targeting our 
   organization. An attacker impersonated our CEO requesting a $47,500 
   wire transfer.
   
   IMMEDIATELY VERIFY any wire transfer, payment, or banking change requests
   received via email by:
   1. Calling the requester at their known office number (NOT number in email)
   2. Verifying in person if possible
   3. Never rely on email or phone numbers provided in suspicious messages
   
   Contact security@soclab.local if you receive any suspicious requests.
   
   Do not forward this alert externally - attackers may monitor our responses."
   ```

### 🔴 HIGH - Short-term Actions (1-24 Hours)

6. **Report to Authorities:**
   ```
   1. FBI Internet Crime Complaint Center (IC3)
      URL: https://www.ic3.gov/
      Report type: Business Email Compromise (BEC)
      Include: All email headers, domain details, banking information
   
   2. US Secret Service (if over $50,000 or ongoing targeting)
      Contact local field office
   
   3. Financial Fraud Enforcement Task Force
      Report fraudulent bank account details
   
   4. CISA (optional but recommended)
      Report domain: soclab-corp.com for threat intelligence sharing
   ```

8. **Domain Monitoring & Takedown:**
   ```
   Immediate:
   - File abuse report with Namecheap (domain registrar)
     Email: abuse@namecheap.com
     Subject: "Fraudulent Domain Registration - soclab-corp.com - BEC Attack"
     Include: Email evidence, CEO impersonation proof, request takedown
   
   - Report to Google (Gmail abuse)
     Email: phishing@google.com
     Report: d.r0berts.ceo@gmail.com used for BEC attack
     Request: Account suspension
   
   - Monitor for domain re-registration
     Set alert on domain monitoring services if taken down
   ```

9. **Executive Account Security Review:**
   ```
   For CEO and other C-level accounts:
   - Force password reset (in case of prior compromise)
   - Enable MFA if not already active (preferably hardware token)
   - Review email forwarding rules (check for unauthorized forwards)
   - Review email delegates and mailbox permissions
   - Audit recent sent items (verify no actual compromise)
   - Check for email auto-forwarding or SMTP relay rules
   - Review calendar sharing settings (attacker knew CEO's schedule)
   ```

10. **Enhanced Email Gateway Rules:**
    ```
    Deploy advanced BEC detection rules:
    
    Rule 1: Display Name Mismatch
    If: From display name matches executive name list
    AND: From domain ≠ soclab.local
    Then: Quarantine + Alert security team
    
    Rule 2: Reply-To Redirect
    If: Reply-To domain ≠ From domain
    AND: To address = finance team
    Then: Flag with warning banner or quarantine
    
    Rule 3: Financial Keywords + External Sender
    If: Body contains ("wire transfer" OR "bank account" OR "routing number")
    AND: From domain ≠ soclab.local
    AND: To = finance/accounting staff
    Then: Add warning banner: "⚠️ EXTERNAL - Verify via phone before processing"
    
    Rule 4: Look-alike Domain Detection
    If: From domain contains "soclab" 
    AND: From domain ≠ soclab.local
    Then: Quarantine + Alert
    
    Rule 5: Free Email Provider + Executive Name
    If: From domain = (gmail.com OR yahoo.com OR outlook.com OR hotmail.com)
    AND: Display name matches executive list
    Then: Quarantine + Alert
    ```

### ⚠️ MEDIUM - Tactical Improvements (1-7 Days)

11. **Implement Domain Monitoring:**
    ```
    Tools to deploy:
    - DomainTools Domain Monitor
    - Brandfetch domain monitoring
    - SecurityTrails brand monitoring
    - Custom WHOIS alerts
    
    Monitor for registrations containing:
    - soclab
    - soc-lab
    - soclabcorp
    - Any variation with number substitutions (0 for O, 1 for l)
    
    Alert threshold: Immediate notification for any match
    Response: Evaluate for typosquatting, file takedown if malicious
    ```

12. **Financial Controls Hardening:**
    ```
    Update corporate financial policy:
    
    MANDATORY REQUIREMENTS for ALL wire transfers:
    1. Dual authorization required (no exceptions based on amount)
    2. Voice verification via known phone number (in corporate directory)
    3. In-person verification for new vendors or changed bank accounts
    4. 24-hour waiting period for requests over $10,000
    5. Callback verification system:
       - Finance initiates call (never use number from email)
       - Uses corporate directory or HR-verified contact
       - Confirms via separate communication channel (Slack, Teams, in-person)
    
    For wire transfers requested via email:
    - ALWAYS require secondary verification
    - Document verification method in transaction notes
    - Flag any requests that claim urgency or confidentiality
    
    Implement wire transfer confirmation token system:
    - Use internal chat platform for secondary confirmation
    - CEO posts verification code in secure channel
    - Finance validates code before processing
    ```

13. **Vendor Management Process:**
    ```
    New/Changed Vendor Banking Information:
    - Require official vendor letterhead with banking changes
    - Verify via phone to vendor's main number (not email-provided)
    - Test transfer: Send $1 first, confirm receipt, then send balance
    - Maintain verified vendor contact list (phone, email, address)
    - Flag any rush requests or deviations from process
    
    Vendor Onboarding:
    - Collect W-9 form (IRS verification)
    - Verify business registration (state.gov database)
    - Request references and validate
    - Document expected payment amounts and frequency
    ```

14. **Employee Training - BEC Awareness:**
    ```
    Mandatory training for all employees within 48 hours:
    - Focus: Business Email Compromise tactics
    - Include this real incident as case study (anonymize if needed)
    
    Training topics:
    1. What is BEC and how it differs from traditional phishing
    2. Why email authentication (SPF/DKIM/DMARC) isn't sufficient
    3. Social engineering red flags:
       - Authority + Urgency + Secrecy = RED ALERT
    4. Verification procedures for financial requests
    5. How to spot display name spoofing
    6. What to do if you receive a suspicious request
    
    Special training for:
    - Finance/Accounting: 4-hour deep-dive on BEC, monthly refreshers
    - Executives: How their identity is used in attacks
    - IT/Security: Technical detection and response procedures
    
    Simulated BEC exercises:
    - Quarterly simulated BEC attempts (internal red team)
    - Test finance team response to fake CEO requests
    - Track metrics: Detection rate, reporting time, verification compliance
    - No penalties for failing simulation (learning opportunity)
    ```

15. **Email Security Enhancements:**
    ```
    Deploy external email warning banner:
    
    Automatically prepend to all external emails:
    ┌─────────────────────────────────────────────────────────────────┐
    │ ⚠️ EXTERNAL EMAIL - This email originated from outside our      │
    │ organization. Exercise caution with links, attachments, and    │
    │ requests for sensitive information or financial transactions.  │
    └─────────────────────────────────────────────────────────────────┘
    
    Advanced banner for finance team:
    If: To = finance/accounting staff
    AND: Body contains financial keywords
    AND: From = external
    Then: Add additional warning:
    ┌─────────────────────────────────────────────────────────────────┐
    │ 🛑 FINANCIAL REQUEST DETECTED - Before processing any payment,  │
    │ wire transfer, or bank account change, you MUST verify via     │
    │ phone call to a known number. Never use contact info from this │
    │ email. Contact security@soclab.local if anything seems unusual.│
    └─────────────────────────────────────────────────────────────────┘
    ```

16. **Implement DMARC for Company Domain:**
    ```
    Current status: Internal domain (soclab.local) not internet-facing
    
    Actions:
    1. Register public domain variant: soclab.com (if not owned)
       - Prevents attackers from registering it
       - Redirect to legitimate company site
    
    2. Publish DMARC record for all owned domains:
       TXT record: _dmarc.soclab.com
       Value: "v=DMARC1; p=reject; rua=mailto:dmarc@soclab.com; fo=1"
       
       This tells receiving servers:
       - Reject any email failing SPF/DKIM from our domains
       - Send reports of failed attempts to our team
       - Prevents attackers from using our actual domain
    
    3. Monitor DMARC reports:
       - Review weekly for spoofing attempts
       - Identify unauthorized sending sources
       - Fine-tune email authentication policies
    ```

### 📋 LONG-TERM - Strategic Improvements (7-30 Days)

17. **Executive Protection Program:**
    ```
    Implement executive identity protection:
    
    1. PII Reduction:
       - Audit executive information online (LinkedIn, company site, etc.)
       - Remove unnecessary personal details (phone, address, email)
       - Use generic contact forms instead of direct emails
       - Remove org charts showing hierarchy
    
    2. Social Media Hygiene:
       - Train executives on OPSEC (operational security)
       - Avoid posting schedules, locations, or sensitive info
       - Review privacy settings on personal accounts
       - Consider separate personal/professional accounts
    
    3. VIP Email Protection:
       - Dedicated security monitoring for executive accounts
       - Advanced threat protection licenses
       - Real-time alerts for unusual activity
       - Regular security assessments
    
    4. Calendar Security:
       - Limit calendar visibility to internal only
       - Don't share detailed meeting information publicly
       - Use generic descriptions for sensitive meetings
    ```

18. **Implement Email Authentication Visualization:**
    ```
    Deploy email client add-in/plugin showing:
    - Actual sender domain (highlighted if ≠ company domain)
    - Authentication results (SPF/DKIM/DMARC visual indicators)
    - Display name vs actual email address mismatch warnings
    - Risk score based on content and sender analysis
    
    Tools:
    - Custom Outlook add-in
    - Third-party: KnowBe4, Cofense, IronScales
    - Power Automate flow for flagging (if using Microsoft 365)
    ```

19. **Financial Transaction Automation:**
    ```
    Reduce email-based financial requests:
    
    - Implement vendor payment portal
    - Use accounting system's workflow approvals (not email)
    - Automated invoice matching and payment scheduling
    - Digital signatures with cryptographic verification
    - Blockchain-based transaction validation (for high-value)
    
    Policy: "No wire transfer requests via email will be processed"
    Exception process: In-person or video call verification only
    ```

20. **Cyber Insurance Review:**
    ```
    Review current policy for BEC coverage:
    - Social engineering coverage included?
    - Coverage limits for BEC losses
    - Exclusions for fund transfer fraud
    - Claims process for BEC incidents
    
    If inadequate:
    - Add social engineering rider to cyber insurance
    - Increase coverage limits based on risk assessment
    - Document security controls (may reduce premium)
    - Annual review of coverage adequacy
    ```

21. **Threat Intelligence Program:**
    ```
    Subscribe to BEC-focused threat intelligence:
    - FBI IC3 alerts
    - CISA advisories
    - Industry-specific ISACs
    - Commercial threat intel (Recorded Future, Flashpoint, etc.)
    
    Monitor for:
    - Company name mentioned in fraud forums
    - Executive names used in dark web marketplaces
    - Typosquatted domains registered with company name
    - Compromised credentials (Have I Been Pwned, etc.)
    
    Weekly review:
    - New domains registered containing company name
    - Industry BEC trends and tactics
    - Peer organization incidents (learn from others)
    ```

### 📊 Metrics & Monitoring (Ongoing)

22. **BEC-Specific Monitoring:**
    ```
    Deploy custom detection rules in SIEM/email gateway:
    
    Alert on:
    1. Email from external domain with executive display name
    2. Reply-To domain ≠ From domain + financial keywords
    3. Urgency keywords + payment keywords from external sender
    4. New domain (registered <30 days) sending to finance team
    5. Free email provider + executive name impersonation
    6. "Re:" in subject but no prior conversation thread
    7. Payment amount just under authorization threshold
    
    Daily reports:
    - Count of external emails to finance team with payment keywords
    - Display name vs sender domain mismatches
    - Reply-To redirects to free email providers
    
    Weekly executive briefing:
    - BEC attempts blocked
    - Social engineering trends observed
    - Employee reporting rate (are staff vigilant?)
    ```

23. **Success Metrics - Track Progress:**
    ```
    Measure effectiveness of BEC defenses:
    
    Prevention Metrics:
    - BEC emails blocked at gateway: Target 100%
    - Employee reporting rate: Target >80% of simulated BEC
    - Verification compliance: Target 100% of wire requests
    - Training completion: Target 100% within 30 days
    
    Detection Metrics:
    - Time to detect BEC attempt: Target <1 hour
    - Time to block IOCs: Target <15 minutes
    - False positive rate: Target <5%
    
    Financial Metrics:
    - Total value of prevented BEC losses: $47,500 (this incident)
    - Average attempted BEC amount: Track over time
    - Cost of BEC program vs prevented losses: Positive ROI target
    
    Incident Response Metrics:
    - CFO response (verification): Excellent - prevented loss ✅
    - Time from detection to executive notification: Track
    - Time from detection to IOC blocking: Track
    ```

---

## Lessons Learned

### What Worked Exceptionally Well:

1. **CFO Followed Corporate Policy ⭐⭐⭐⭐⭐**
   - Required voice verification before processing wire transfer
   - Called CEO's known office line (not number provided in email)
   - Escalated to security immediately when discrepancy discovered
   - **Result: $47,500 loss prevented**

2. **Strong Corporate Financial Controls**
   - Written policy requiring verbal verification for wire transfers
   - CFO trained to be suspicious of urgent email requests
   - Culture of "trust but verify" in finance department

3. **Rapid Incident Response**
   - Within 30 minutes of CFO verification, security team engaged
   - IOCs blocked organization-wide within 1 hour
   - Threat intelligence shared with peer organizations same day

### What Needs Improvement:

1. **Email Gateway Failed to Detect BEC**
   - No alert triggered despite:
     - Display name containing "CEO"
     - External domain impersonating internal sender
     - Financial keywords in body
     - Reply-To redirect to different domain
   - **Fix: Implemented advanced BEC detection rules (see recommendations)**

2. **No Domain Monitoring**
   - Typosquatted domain (soclab-corp.com) registered 4 days before attack
   - No proactive detection of lookalike domain registration
   - **Fix: Deployed domain monitoring with real-time alerts**

3. **Executive Digital Footprint**
   - LinkedIn profiles revealed organizational hierarchy
   - Company website listed executive names and titles
   - CEO's calendar visible to external meeting invitees (revealed meeting time)
   - **Fix: Initiated executive protection program (PII reduction)**

4. **Limited BEC-Specific Training**
   - General phishing awareness training covered malware/links
   - Insufficient focus on social engineering and BEC tactics
   - Finance team last trained 6 months ago
   - **Fix: Deployed mandatory BEC-specific training for all staff**

### Organizational Impact:

**Positive Outcomes:**
- ✅ Zero financial loss (attack prevented)
- ✅ Demonstrated effectiveness of verification procedures
- ✅ Identified gaps in email security controls
- ✅ Opportunity to strengthen defenses proactively
- ✅ Real-world incident used for staff training (increased awareness)

**Risks Identified:**
- Other executives may be targeted (expand monitoring)
- Attacker will likely retry with different tactics
- Employees outside finance may be less vigilant
- Technical controls alone insufficient for BEC prevention

**Business Value of Prevention:**
- Direct savings: $47,500 (wire transfer amount)
- Avoided costs:
  - Investigation and recovery: $15,000-30,000
  - Legal and compliance: $5,000-10,000
  - Reputational damage: Immeasurable
  - Lost productivity: 100+ hours
- **Total value delivered by security controls: $75,000+ prevented costs**

---

## Executive Summary for Leadership

**Incident:** Business Email Compromise (BEC) attack targeting CFO via CEO impersonation  
**Status:** ✅ PREVENTED - No financial loss, attack unsuccessful  
**Amount at Risk:** $47,500  

### What Happened:
An attacker registered a lookalike domain (soclab-corp.com) and impersonated our CEO in an email to the CFO requesting an urgent wire transfer of $47,500 to a fraudulent bank account. The email passed standard email security checks and appeared legitimate.

### Why the Attack Failed:
The CFO followed corporate policy by calling the CEO's office line to verbally verify the wire transfer request. The CEO confirmed he did not send the request. The CFO immediately escalated to security, preventing the loss.

### Actions Taken:
- Blocked attacker's domain and email addresses organization-wide
- Alerted all financial institutions of the targeting
- Reported to FBI and initiated domain takedown
- Deployed enhanced email security rules to detect future BEC attempts
- Emergency training sent to all finance staff

### Strategic Recommendations:
1. Implement domain monitoring for typosquatted company name variations
2. Enhance email gateway with BEC-specific detection rules
3. Mandatory BEC awareness training for all staff (especially finance)
4. Review and strengthen financial transaction verification procedures
5. Consider executive identity protection program

### Bottom Line:
This incident demonstrates both the sophistication of modern threats and the effectiveness of strong corporate policies. The CFO's adherence to verification procedures prevented a $47,500 loss. Technical controls alone cannot prevent BEC attacks—employee awareness and strong policies are our best defense.

**Recommendation:** Approve recommended security enhancements to prevent future attempts.

---

## References & Attribution

### MITRE ATT&CK Framework:
- T1566.002 - Phishing: Spearphishing Link (social engineering)
- T1534 - Internal Spearphishing
- T1586.002 - Compromise Accounts: Email Accounts

### FBI Resources:
- IC3 BEC/EAC Report 2021: $2.4B in losses from BEC attacks
- FBI BEC Advisory: https://www.fbi.gov/scams-and-safety/common-scams-and-crimes/business-email-compromise
- IC3 Filing: https://www.ic3.gov/

### Industry References:
- SANS Institute: Business Email Compromise - A CISO's Guide
- CISA Alert: Business Email Compromise
- ACFE (Association of Certified Fraud Examiners): Occupational Fraud Report
- Anti-Phishing Working Group (APWG): BEC Trends Report

### Technical Resources:
- DMARC.org: Email authentication standards
- Namecheap Abuse Reporting: abuse@namecheap.com
- Google Phishing Reporting: phishing@google.com

### Similar Incidents (Public):
- FACC AG (Austria): $50 million BEC loss (2016)
- Ubiquiti Networks: $46.7 million BEC loss (2015)
- Crelan Bank (Belgium): €70 million BEC loss (2016)
- Toyota Boshoku: $37 million BEC loss (2019)

---

**Report Classification:** TLP:AMBER (Shareable within organization and trusted partners)  
**Incident Status:** CLOSED - Attack prevented, enhanced monitoring active  
**Next Review:** 30 days (assess effectiveness of new controls)  
**Training Usage:** Approved for internal security awareness training (anonymize external sharing)

---

**Analyst Final Notes:**

This BEC attempt represents a sophisticated social engineering attack that bypassed all technical security controls. The attack failed solely due to strong corporate policy and employee vigilance. This incident should serve as a wake-up call that technical defenses (email gateways, antivirus, firewalls) cannot prevent BEC attacks. 

Our best defense against BEC is:
1. **Awareness** - Employees who recognize social engineering tactics
2. **Policy** - Mandatory verification procedures for financial transactions
3. **Culture** - Environment where questioning authority is encouraged and rewarded

The CFO should be commended for following procedure and preventing a significant financial loss. This incident demonstrates the value of security awareness training and strong corporate policies.

**Recommended Action:** Use this incident as a teaching moment. Share (appropriate) details with all staff to reinforce the reality of these threats and the importance of verification procedures.
