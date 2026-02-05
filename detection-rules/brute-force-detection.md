# Brute Force Detection Rules

## Overview

Brute force attacks attempt to gain unauthorized access by systematically trying multiple password combinations. These rules detect failed authentication patterns, successful compromises after multiple failures, and account lockout anomalies.

**Attack Scenario:** External threat actor or insider attempting to guess user credentials through repeated login attempts via RDP, SMB, or domain authentication.

---

## Rule 1: Multiple Failed Login Attempts

### Description
Detects when a single source IP or user account generates more than 10 failed login attempts within the search timeframe, indicating potential brute force activity.

### MITRE ATT&CK Mapping
- **Tactic:** Credential Access
- **Technique:** T1110.001 (Brute Force: Password Guessing)
- **Sub-Technique:** Password guessing against domain or local accounts

### Splunk SPL Query

```spl
index=windows_security EventCode=4625
| eval src_ip=coalesce(Source_Network_Address, IpAddress, "unknown")
| eval target_account=coalesce(Account_Name, TargetUserName, "unknown")
| stats count as failed_attempts by src_ip, target_account, ComputerName
| where failed_attempts > 10
| sort - failed_attempts
| eval severity="High"
| table src_ip, target_account, ComputerName, failed_attempts, severity
```

### Query Explanation

**Line by line breakdown:**

1. `index=windows_security EventCode=4625` - Searches Windows Security log for Event ID 4625 (failed logon attempts)
2. `eval src_ip=coalesce(...)` - Creates standardized source IP field, handling different field names across Windows versions
3. `eval target_account=coalesce(...)` - Creates standardized username field
4. `stats count as failed_attempts by src_ip, target_account, ComputerName` - Aggregates failed attempts grouped by source, target account, and affected computer
5. `where failed_attempts > 10` - Filters to show only sources with more than 10 failures
6. `sort - failed_attempts` - Sorts results with highest failure counts first
7. `eval severity="High"` - Tags alert severity
8. `table` - Displays relevant fields in clean table format

### True Positive Indicators

A **true positive** brute force attack typically shows:
- **Source IP:** Single external IP targeting multiple accounts
- **Failed attempts:** 50-1000+ within hours
- **Target accounts:** Common usernames (admin, administrator, root, user1, sa, etc.)
- **Time pattern:** Rapid succession (seconds between attempts) or distributed (evading rate limiting)
- **Geographic anomaly:** Source IP from country with no business relationship
- **Success after failures:** Eventually achieves successful login (see Rule 2)

**Example True Positive:**
```
src_ip=185.220.101.42 | target_account=administrator | ComputerName=DC01 | failed_attempts=847
src_ip=185.220.101.42 | target_account=admin | ComputerName=DC01 | failed_attempts=523
src_ip=185.220.101.42 | target_account=j.martinez | ComputerName=DC01 | failed_attempts=319
```

### False Positive Scenarios

**Common false positives:**
- **User password typos:** 3-5 failures, then success
- **Expired passwords:** User repeatedly enters old password
- **Service account misconfigurations:** Automated system using wrong credentials
- **VPN connection issues:** Legitimate user connection drops causing auth failures
- **Disabled/locked accounts:** Automated tools trying to use disabled accounts

**Mitigation:** Adjust threshold based on environment. Enterprise networks may use 15-20 as threshold. Home lab with few users can use 10.

### Response Actions

When this alert fires:

1. **Immediate Actions:**
   - Identify source IP and check threat intelligence (AbuseIPDB, VirusTotal)
   - Determine if any targeted accounts successfully authenticated (run Rule 2)
   - Block source IP at firewall if confirmed malicious
   - Check if source IP is internal (potential compromised host)

2. **Investigation Steps:**
   - Review all Event ID 4625 events from source IP
   - Check Event ID 4624 (successful logins) from same source
   - Query: `index=windows_security src_ip="X.X.X.X" (EventCode=4624 OR EventCode=4625) | table _time, EventCode, Account_Name, Logon_Type, Workstation_Name`
   - Identify timeframe of attack (start time, duration, end time)

3. **Containment:**
   - Block attacker IP at perimeter firewall
   - Consider blocking entire subnet if part of known botnet
   - Enable MFA for targeted accounts
   - Force password reset for accounts with successful login

4. **Recovery:**
   - Reset passwords for all targeted accounts (even if not compromised)
   - Review access logs for compromised accounts
   - Scan affected systems for malware/backdoors

5. **Lessons Learned:**
   - Implement account lockout policy if not present
   - Restrict RDP access to VPN only
   - Deploy geo-blocking for high-risk countries
   - Implement fail2ban or similar IP-based blocking

### Testing with Atomic Red Team

**Test Technique:** T1110.001

```powershell
# Install Atomic Red Team (if not already installed)
Install-Module -Name invoke-atomicredteam -Force

# Execute brute force simulation
Invoke-AtomicTest T1110.001 -TestNumbers 2
```

This generates failed authentication attempts against local accounts, triggering the detection rule.

**Manual Test (from Kali Linux):**
```bash
# RDP brute force test
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://10.0.0.10 -t 4
```

**Expected Result:** Alert fires in Splunk showing multiple failed attempts from Kali IP (10.0.0.50).

---

## Rule 2: Brute Force Success - Failures Followed by Success

### Description
Detects successful authentication (Event 4624) from a source that previously had multiple failed attempts (Event 4625), indicating a successful brute force compromise.

### MITRE ATT&CK Mapping
- **Tactic:** Credential Access
- **Technique:** T1110.001 (Brute Force: Password Guessing)
- **Sub-Technique:** Successful password guessing

### Splunk SPL Query

```spl
index=windows_security (EventCode=4625 OR EventCode=4624)
| eval src_ip=coalesce(Source_Network_Address, IpAddress, "unknown")
| eval account=coalesce(Account_Name, TargetUserName, "unknown")
| eval event_type=case(EventCode=4625, "failure", EventCode=4624, "success", true(), "other")
| stats count(eval(event_type="failure")) as failures, 
        count(eval(event_type="success")) as successes,
        earliest(_time) as first_seen,
        latest(_time) as last_seen
        by src_ip, account, ComputerName
| where failures > 10 AND successes > 0
| eval duration_minutes=round((last_seen-first_seen)/60, 2)
| eval severity="Critical"
| sort - failures
| table src_ip, account, ComputerName, failures, successes, first_seen, last_seen, duration_minutes, severity
```

### Query Explanation

1. `(EventCode=4625 OR EventCode=4624)` - Captures both failed and successful logins
2. `eval event_type=case(...)` - Categorizes each event as failure or success
3. `stats count(eval(...))` - Counts failures and successes separately per source/account combination
4. `earliest(_time)` and `latest(_time)` - Captures timeframe of attack
5. `where failures > 10 AND successes > 0` - Filters for successful compromise after many failures
6. `eval duration_minutes` - Calculates attack duration for analysis

### True Positive Indicators

**This is a CRITICAL alert** - it indicates a successful compromise:
- Source IP had 10+ failures then 1+ success
- Short duration (minutes to hours) suggests automated tool
- Multiple account successes from same IP = active attacker
- Success on privileged account (admin, domain admin) = severe impact

### Response Actions

**CRITICAL - IMMEDIATE RESPONSE REQUIRED:**

1. **Isolate Compromised Account:**
   ```powershell
   # Disable account immediately
   Disable-ADAccount -Identity "compromised_username"
   
   # Kill active sessions
   query session /server:DC01
   logoff <session_id> /server:DC01
   ```

2. **Block Attacker:**
   - Add IP to firewall block list
   - If internal IP: isolate host from network immediately

3. **Forensic Investigation:**
   - What did attacker do after login? Check Event ID 4688 (process creation), Sysmon Event 1
   - Were files accessed? Check object access logs (Event 4663)
   - Was malware dropped? Check Sysmon Event 11 (file creation)
   - Lateral movement? Check 4624 Logon Type 3 (network logon) to other hosts

4. **Scope Assessment:**
   ```spl
   index=windows_security src_ip="X.X.X.X" EventCode=4624
   | stats count by ComputerName, Account_Name, Logon_Type
   ```

5. **Eradication:**
   - Force password reset for compromised account
   - Search for persistence mechanisms (scheduled tasks, registry Run keys, services)
   - Check for new user accounts created by attacker
   - Scan systems for malware

### Testing

Manual test from Kali:
```bash
# First generate failures
hydra -l j.martinez -P short_wordlist.txt rdp://10.0.0.10 -t 4

# Then use correct password
xfreerdp /v:10.0.0.10 /u:j.martinez /p:ITSupport2026!
```

---

## Rule 3: Account Lockout Spike

### Description
Detects multiple account lockouts (Event 4740) in a short period, indicating password spray attack where attacker tries one password against many accounts.

### MITRE ATT&CK Mapping
- **Tactic:** Credential Access
- **Technique:** T1110.003 (Brute Force: Password Spraying)

### Splunk SPL Query

```spl
index=windows_security EventCode=4740
| eval locked_account=coalesce(TargetUserName, Account_Name, "unknown")
| eval caller_computer=coalesce(Caller_Computer_Name, WorkstationName, "unknown")
| stats count as lockout_count, values(locked_account) as affected_accounts by caller_computer
| where lockout_count > 3
| eval severity="Medium"
| eval affected_count=mvcount(affected_accounts)
| table caller_computer, lockout_count, affected_count, affected_accounts, severity
| sort - lockout_count
```

### Query Explanation

1. `EventCode=4740` - Account lockout events (triggered when bad password threshold reached)
2. `stats count...values(locked_account)` - Counts lockouts and collects list of affected accounts
3. `where lockout_count > 3` - More than 3 lockouts suggests attack not user error
4. `mvcount(affected_accounts)` - Counts how many unique accounts were locked

### True Positive Indicators

**Password spray attack pattern:**
- Multiple different accounts locked
- Short time window (minutes)
- Accounts from different OUs (not just IT, but Finance, HR, etc.)
- Same source IP or computer name
- Happens outside business hours

**Example:**
```
caller_computer=10.0.0.50 | lockout_count=12 | affected_accounts=[a.chen, r.kim, m.johnson, s.martinez, ...]
```

This indicates attacker trying common passwords (Password123!, Winter2026!, etc.) against many accounts.

### False Positive Scenarios

- User genuinely forgot password and locked themselves out repeatedly
- System account with misconfigured password
- Mobile device with cached old password repeatedly attempting auth

### Response Actions

1. **Identify Attack Pattern:**
   - Check which accounts were targeted
   - Look for password spray timeline
   - Determine source (internal workstation or external IP)

2. **Investigate Source:**
   ```spl
   index=windows_security EventCode=4625 Account_Name IN ("a.chen", "r.kim", "m.johnson")
   | stats count by src_ip
   ```

3. **Containment:**
   - Block source IP if external
   - If internal: isolate workstation, investigate for compromise
   - Unlock legitimate user accounts after confirming no compromise
   - Implement account lockout notification to users

4. **Prevention:**
   - Enforce password complexity
   - Implement smart lockout (cloud-based threat intelligence)
   - Deploy conditional access policies
   - User awareness training on password security

### Testing

```powershell
# Simulate password spray (will lock accounts - be careful!)
$users = @("test.user1", "test.user2", "a.chen")
$password = ConvertTo-SecureString "WrongPassword123!" -AsPlainText -Force

foreach ($user in $users) {
    1..5 | ForEach-Object {
        $cred = New-Object System.Management.Automation.PSCredential($user, $password)
        try {
            Start-Process powershell.exe -Credential $cred -ArgumentList "exit"
        } catch {
            Write-Host "Failed for $user"
        }
    }
}
```

**Note:** This will actually lock accounts. Use test accounts only!

---

## Summary

These three brute force detection rules provide layered defense:

1. **Rule 1:** Early warning - attack in progress
2. **Rule 2:** Compromise alert - successful breach
3. **Rule 3:** Password spray detection - distributed attack pattern

**Recommended Alert Configuration:**
- Rule 1: Alert every 5 minutes (real-time monitoring)
- Rule 2: Alert immediately (critical)
- Rule 3: Alert every 10 minutes

**Metrics to Track:**
- Brute force attempts per day
- Success rate (Rule 2 fires / Rule 1 fires)
- Most targeted accounts
- Most common source countries/IPs
