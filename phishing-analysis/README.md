# Phishing Analysis Reports

This directory contains comprehensive email threat analysis reports demonstrating phishing identification, technical analysis, and response procedures.

## Phishing Analysis Catalog

| ID | Subject Line | Type | Verdict | Risk Level |
|----|-------------|------|---------|------------|
| 001 | "Urgent: Your Microsoft 365 Password Expires Today" | Credential Harvesting | Phishing | High |
| 002 | "Invoice #INV-2026-4481 — Payment Overdue" | Malware Delivery | Malicious | Critical |
| 003 | "Re: Wire Transfer — Urgent" | Business Email Compromise | BEC/Phishing | High |

## Analysis Methodology

Each phishing analysis follows a systematic approach:

### 1. Email Acquisition
- Reported by user via phishing button
- Captured from email gateway
- Preserved with full headers

### 2. Header Analysis
- **Authentication Checks:** SPF, DKIM, DMARC validation
- **Routing Analysis:** Trace email path through Received headers
- **Source Identification:** Originating IP and sending infrastructure
- **Timestamp Correlation:** Verify time zones and delivery path consistency

### 3. Content Analysis
- **Visual Inspection:** Logos, formatting, branding consistency
- **Linguistic Analysis:** Grammar, spelling, tone, urgency indicators
- **Social Engineering Tactics:** Authority, urgency, fear, curiosity
- **Request Analysis:** What action is requested (click, download, send money)

### 4. URL Analysis
- **URL Extraction:** Identify all embedded links
- **Defanging:** Convert to safe format (hxxps://, [.])
- **Reputation Check:** VirusTotal, URLScan.io, Google Safe Browsing
- **Domain Analysis:** WHOIS lookup, registration date, registrar
- **Redirection Check:** Follow redirect chains safely
- **Landing Page Analysis:** Screenshot, HTML analysis (if safe)

### 5. Attachment Analysis
- **Static Analysis:** File type, size, metadata, hashes
- **Reputation Check:** VirusTotal, Hybrid Analysis
- **Sandbox Execution:** Any.Run, Joe Sandbox (if applicable)
- **Macro Extraction:** olevba tool for Office documents
- **Behavioral Analysis:** Network connections, file modifications, registry changes

### 6. Threat Intelligence
- **IP Reputation:** AbuseIPDB, IPVoid
- **Domain Reputation:** Multiple reputation services
- **Hash Search:** VirusTotal, Any.Run, Malware Bazaar
- **TTPs Mapping:** MITRE ATT&CK for phishing techniques
- **Campaign Attribution:** Link to known phishing campaigns

## Common Phishing Indicators

### Red Flags in Email Headers
- ❌ SPF/DKIM/DMARC failures
- ❌ Mismatch between From display and actual address
- ❌ Reply-To different from From address
- ❌ Originating from suspicious countries/IPs
- ❌ Unusual routing through multiple mail servers
- ❌ Recent domain registration (< 30 days)

### Red Flags in Email Content
- ❌ Urgent action required / account suspension threat
- ❌ Generic greetings ("Dear user", "Dear customer")
- ❌ Grammar and spelling errors
- ❌ Request for credentials or personal information
- ❌ Mismatched URLs (display text vs actual link)
- ❌ Unexpected attachments
- ❌ Too-good-to-be-true offers
- ❌ Impersonation of known brands/people

### Red Flags in URLs
- ❌ Typosquatting (micros0ft vs microsoft)
- ❌ Suspicious TLDs (.xyz, .top, .tk, .ml)
- ❌ IP address instead of domain name
- ❌ Long, obfuscated URLs
- ❌ URL shorteners (bit.ly, tinyurl)
- ❌ Misspelled legitimate domains
- ❌ Homograph attacks (using similar characters)

### Red Flags in Attachments
- ❌ Macro-enabled Office documents (.xlsm, .docm)
- ❌ Executable files (.exe, .scr, .bat)
- ❌ Double file extensions (invoice.pdf.exe)
- ❌ Archive files containing executables (.zip with .exe)
- ❌ ISO/IMG disk image files
- ❌ Script files (.vbs, .js, .ps1)

## Phishing Types Covered

### 1. Credential Harvesting (Phishing 001)
**Objective:** Steal usernames and passwords

**Technique:**
- Impersonate legitimate service (Microsoft 365, Gmail, bank)
- Urgent message about account expiration or security issue
- Link to fake login page that captures credentials
- May use legitimate-looking domain with typosquatting

**Example:** "Your account will be suspended unless you verify your password"

**Impact:** Account compromise, unauthorized access, potential lateral movement

### 2. Malware Delivery (Phishing 002)
**Objective:** Infect system with malware

**Technique:**
- Disguised as legitimate business document (invoice, shipping notice)
- Macro-enabled Office document or executable attachment
- Social engineering to convince user to enable macros
- Payload downloads additional malware from C2 server

**Example:** "Please review the attached invoice for immediate payment"

**Impact:** Malware infection, ransomware, data theft, persistent access

### 3. Business Email Compromise - BEC (Phishing 003)
**Objective:** Financial fraud through social engineering

**Technique:**
- Impersonate executive or business partner
- Request urgent wire transfer or sensitive information
- No malicious links or attachments (pure social engineering)
- Often uses look-alike domains or compromised accounts

**Example:** "CEO needs you to wire $50K to new vendor account immediately"

**Impact:** Direct financial loss, business disruption, reputational damage

## Analysis Tools

### Email Header Analysis
- **MXToolbox:** Header analysis and blacklist checking
- **Mail Header Analyzer:** Google Admin Toolbox
- **Message Header Analyzer:** Microsoft tool
- **Manual Review:** Reading Received headers bottom-to-top

### URL Analysis
- **VirusTotal:** Multi-engine URL scanning
- **URLScan.io:** Screenshot and analysis of URLs
- **Google Safe Browsing:** Check against Google's database
- **PhishTank:** Community phishing site database
- **Cisco Talos:** URL reputation
- **URLVoid:** Aggregated URL reputation

### Attachment Analysis
- **VirusTotal:** Multi-AV file scanning
- **Hybrid Analysis:** Automated malware analysis
- **Any.Run:** Interactive malware sandbox
- **Joe Sandbox:** Comprehensive malware analysis
- **olevba:** Extract and analyze VBA macros
- **PEStudio:** Static analysis of Windows executables

### IP/Domain Reputation
- **AbuseIPDB:** IP reputation and abuse reports
- **IPVoid:** Aggregated IP reputation
- **WHOIS Lookup:** Domain registration information
- **DNSdumpster:** DNS reconnaissance
- **Shodan:** Internet-connected device search

## Response Actions

### User-Reported Phishing

1. **Acknowledge Report**
   - Thank user for reporting
   - Do not confirm/deny if phishing (investigate first)
   - Advise user not to interact further with email

2. **Analyze Email**
   - Follow analysis methodology above
   - Document findings

3. **Determine Verdict**
   - Legitimate / Spam / Phishing / Malicious
   - Assess risk level

4. **Take Action Based on Verdict**
   - **If Phishing/Malicious:**
     - Block sender domain/IP at email gateway
     - Quarantine all instances of email
     - Check if others received (email logs)
     - Check if anyone clicked/opened (proxy logs, EDR)
     - If clicked: Isolate system, scan for malware, reset credentials
     - Alert all users via security awareness email
   - **If Legitimate/Spam:**
     - Update email filters
     - Notify user of findings
     - Use as training opportunity

5. **Documentation**
   - Complete analysis report
   - Add IOCs to threat intelligence platform
   - Update phishing statistics

6. **User Training**
   - Provide feedback to reporting user
   - Use as example in security awareness training
   - Monthly phishing simulation campaigns

## Phishing Simulation Program

**Purpose:** Train users to recognize and report phishing

**Frequency:** Monthly simulated phishing campaigns

**Metrics Tracked:**
- Click rate (clicked link in phishing email)
- Credential submission rate (entered credentials on fake page)
- Report rate (correctly reported phishing email)
- Time to report (how quickly user reported)
- Repeat offenders (users who fail multiple simulations)

**Progressive Difficulty:**
- Month 1-2: Obvious phishing (poor grammar, generic sender)
- Month 3-4: Moderate difficulty (brand impersonation, urgent requests)
- Month 5-6: Advanced (CEO impersonation, targeted content)

**Remediation:**
- Users who click: Immediate training module (10 minutes)
- Repeat offenders: One-on-one training with security team
- Departments with high click rates: Group training session

## Reporting to External Entities

### Report to Organizations

**Anti-Phishing Working Group (APWG):**
- Email: reportphishing@apwg.org

**US-CERT:**
- Email: phishing-report@us-cert.gov

**Microsoft (for Microsoft impersonation):**
- Email: phish@office365.microsoft.com

**Google (for Google impersonation):**
- Report via: https://safebrowsing.google.com/safebrowsing/report_phish/

### Request Takedown

**Domain Takedown:**
- Contact domain registrar (found via WHOIS)
- Contact hosting provider (found via IP lookup)
- Provide evidence of phishing activity

**URL Takedown:**
- Report to hosting provider
- Report to brand being impersonated
- Report to Google Safe Browsing / Microsoft SmartScreen

### Law Enforcement

**When to Involve:**
- Financial losses > $10,000
- Sensitive data compromised (PII, PHI, financial)
- Evidence of organized cybercrime campaign
- Business email compromise

**US Reporting:**
- FBI Internet Crime Complaint Center (IC3): https://www.ic3.gov/
- Local FBI field office for significant incidents
- Secret Service (for financial crimes)

## Key Metrics

**Email Security Metrics:**
- Total phishing emails received per month
- Phishing emails blocked by email gateway
- Phishing emails reported by users
- User click rate on phishing links
- Credential submission rate
- Time to detection (from delivery to blocking)
- Time to remediation (from detection to full remediation)

**User Awareness Metrics:**
- Training completion rate
- Simulation click rate trend (should decrease over time)
- Reporting rate (should increase over time)
- Time to report (should decrease over time)
- Department/user risk scores

## Continuous Improvement

**Monthly Review:**
- Analyze phishing trends (types, senders, tactics)
- Review detection effectiveness
- Update email gateway rules
- Adjust training based on common mistakes

**Quarterly Assessment:**
- Review phishing simulation results
- Update training content
- Assess email security controls
- Benchmark against industry standards

**Annual Review:**
- Full phishing program assessment
- Update policies and procedures
- Budget planning for security awareness tools
- Executive briefing on phishing risks

## External Resources

- **NIST Phishing Guide:** Special Publication 800-53
- **Anti-Phishing Working Group:** https://apwg.org/
- **PhishTank:** https://phishtank.org/
- **SANS Phishing Resources:** https://www.sans.org/security-awareness-training/resources/phishing
- **KnowBe4 Phishing Security Test:** Free phishing simulation tool

## Analysis Navigation

- [Phishing 001: Credential Harvesting](phishing-001-credential-harvesting.md)
- [Phishing 002: Malicious Attachment](phishing-002-malicious-attachment.md)
- [Phishing 003: Business Email Compromise](phishing-003-business-email-compromise.md)
