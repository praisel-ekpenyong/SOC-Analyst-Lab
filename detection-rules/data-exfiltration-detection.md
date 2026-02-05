# Data Exfiltration Detection Rules

## Overview

Data exfiltration is the unauthorized transfer of data from a computer system to an external destination. These rules detect unusually large data transfers and DNS tunneling - two common exfiltration techniques.

---

## Rule 1: Large Outbound Data Transfer

### Description
Detects abnormally large outbound data transfers that may indicate data exfiltration, backup of stolen data to attacker-controlled infrastructure, or ransomware preparation.

### MITRE ATT&CK Mapping
- **Tactic:** Exfiltration
- **Technique:** T1048 (Exfiltration Over Alternative Protocol)
- **Sub-Technique:** Various protocols (HTTPS, FTP, SMB, etc.)

### Splunk SPL Query

```spl
index=firewall action=allowed direction=outbound
| eval bytes_out_num=tonumber(bytes_out)
| stats sum(bytes_out_num) as total_bytes, 
        count as connections,
        dc(dest_port) as unique_ports,
        values(dest_port) as ports_used
        by src_ip, dest_ip, user
| where total_bytes > 104857600
| eval MB=round(total_bytes/1048576,2)
| eval GB=round(total_bytes/1073741824,2)
| eval severity=case(
    GB>5, "Critical",
    GB>1, "High",
    true(), "Medium")
| table src_ip, dest_ip, user, MB, GB, connections, unique_ports, ports_used, severity
| sort -total_bytes
```

### Query Explanation

- `index=firewall` - Assumes firewall logs indexed separately (adjust for your environment)
- `direction=outbound` - Focus on data leaving the network
- `stats sum(bytes_out_num)` - Aggregates total bytes transferred
- `where total_bytes > 104857600` - Threshold: 100 MB (adjust based on baseline)
- `dc(dest_port)` - Distinct count of destination ports (multiple ports may indicate tunneling)
- Converts to MB/GB for readability
- Dynamic severity based on data volume

**Alternative for Sysmon Event 3 (Network Connections):**
```spl
index=windows_sysmon EventCode=3 Initiated="true"
| eval dest_external=if(like(DestinationIp, "10.%") OR like(DestinationIp, "192.168.%") OR like(DestinationIp, "172.16.%"), "internal", "external")
| where dest_external="external"
| stats count as connection_count by ComputerName, Image, DestinationIp, DestinationPort, User
| where connection_count > 100
| sort -connection_count
```

This detects high-frequency connections which often correlate with large transfers.

### True Positive Indicators

**Data exfiltration characteristics:**
- **Destination:** Unknown external IPs, cloud storage (Dropbox, Mega, Google Drive)
- **Port:** 443 (HTTPS - encrypted, harder to inspect), 22 (SCP/SFTP), non-standard ports
- **Source:** Workstation (not server), user who normally doesn't transfer large files
- **Timing:** Outside business hours, during weekends
- **Tool:** Rclone, mega-sync, FTP clients, curl, PowerShell
- **Pattern:** Sustained transfer over hours (not single large file)
- **Context:** Following credential compromise or malware detection

**Example True Positive:**
```
src_ip: 10.0.0.20 (WS-EXEC-PC01)
dest_ip: 45.33.32.156 (Unknown external)
user: d.roberts
GB: 2.3
connections: 847
ports_used: 443
Tool detected: rclone.exe
```

Executive workstation transferring 2.3 GB to unknown IP via HTTPS = clear exfiltration.

### False Positive Scenarios

**Legitimate large transfers:**
- Cloud backup software (Carbonite, Backblaze)
- File sync services (OneDrive, Dropbox - if approved)
- Software downloads/updates
- Video uploads (YouTube, Vimeo)
- Large email attachments
- VPN traffic (all tunneled through single IP)

**Mitigation:**
- Baseline normal data transfer patterns per user/system
- Whitelist approved cloud services
- Adjust threshold based on user role (IT, executives transfer more data)
- Focus on transfers to unknown/suspicious IPs
- Correlate with file access logs (what files were accessed before transfer?)

### Response Actions

1. **Identify Transfer Details:**
   - Destination IP/domain and reputation check
   - Transferring process/tool
   - User account involved
   - Timeframe and data volume

2. **Check Destination Reputation:**
   ```
   # Check IP reputation
   - VirusTotal: https://www.virustotal.com/
   - AbuseIPDB: https://www.abuseipdb.com/
   - Threat intelligence feeds
   ```

3. **Determine What Was Transferred:**
   ```spl
   # Check file access before transfer
   index=windows_security EventCode=4663 Account_Name="d.roberts" earliest=-24h
   | where Object_Type="File"
   | stats count by Object_Name
   | sort -count
   ```

   ```spl
   # Check Sysmon file access
   index=windows_sysmon EventCode=23 User="d.roberts" earliest=-24h
   | table _time, TargetFilename, Image
   ```

4. **Identify Exfiltration Tool:**
   ```spl
   index=windows_sysmon EventCode=1 ComputerName="WS-EXEC-PC01" User="d.roberts"
   | table _time, Image, CommandLine
   | sort _time
   ```

   Look for: rclone, mega-sync, FTP clients, PowerShell with Net.WebClient

5. **Scope Assessment:**
   - Was data company confidential/sensitive?
   - What is business impact of exposure?
   - Were other users/systems affected?
   - How long has exfiltration been occurring?

6. **Immediate Containment:**
   - Block destination IP at firewall
   - Isolate source system from network
   - Disable compromised user account
   - Kill exfiltration process if still running

7. **Legal/Compliance Notification:**
   - Notify legal team immediately
   - Document for potential data breach reporting
   - Preserve evidence (logs, network captures, forensic images)
   - May require notification to customers, regulators (GDPR, HIPAA, etc.)

8. **Post-Incident:**
   - How did attacker gain access to sensitive data?
   - Were file permissions too permissive?
   - Was DLP (Data Loss Prevention) bypassed?
   - Update DLP policies
   - Implement egress filtering
   - User awareness training

### Enhanced Detection - File Access Correlation

Combine network transfer with file access:

```spl
index=windows_security EventCode=4663 earliest=-1h
| eval file_path=Object_Name
| stats count as file_accesses by Account_Name, file_path
| join Account_Name [
    search index=firewall direction=outbound earliest=-1h
    | stats sum(bytes_out) as total_bytes by user
    | rename user as Account_Name
]
| where total_bytes > 104857600 AND file_accesses > 50
| table Account_Name, file_accesses, file_path, total_bytes
```

Shows users accessing many files AND transferring large data volumes.

### Prevention

1. **DLP (Data Loss Prevention):** Monitor and block sensitive data transfers
2. **Egress Filtering:** Block outbound connections to known bad IPs/categories
3. **Cloud Access Security Broker (CASB):** Control cloud service usage
4. **File Classification:** Tag sensitive files, alert on external transfer
5. **Least Privilege:** Limit data access to only those who need it
6. **Network Segmentation:** Isolate sensitive data on separate network
7. **USB/Removable Media Controls:** Prevent offline exfiltration

### Testing

**Caution: Do not transfer actual sensitive data**

```powershell
# Generate large test file
fsutil file createnew C:\temp\testfile.dat 104857600  # 100 MB

# Simulate upload (to safe destination)
# Using PowerShell
$client = New-Object System.Net.WebClient
$client.UploadFile("https://httpbin.org/post", "C:\temp\testfile.dat")
```

Should trigger alert if exceeds threshold.

---

## Rule 2: DNS Tunneling Detection

### Description
Detects unusually long DNS query names which may indicate DNS tunneling - a technique to exfiltrate data or establish C2 communication through DNS queries.

### MITRE ATT&CK Mapping
- **Tactic:** Command and Control, Exfiltration
- **Technique:** T1048.003 (Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol)
- **Sub-Technique:** DNS protocol abuse

### Splunk SPL Query

```spl
index=windows_sysmon EventCode=22
| eval query_length=len(QueryName)
| where query_length > 50
| eval base_domain=replace(QueryName, "^[^.]+\.", "")
| stats count as query_count,
        avg(query_length) as avg_length,
        max(query_length) as max_length,
        values(QueryName) as queries,
        dc(QueryName) as unique_queries
        by base_domain, Image, ComputerName
| where query_count > 10 OR unique_queries > 10
| eval severity=case(
    max_length>100 AND unique_queries>50, "Critical",
    max_length>75 AND unique_queries>20, "High",
    true(), "Medium")
| table ComputerName, Image, base_domain, query_count, unique_queries, avg_length, max_length, severity
| sort -query_count
```

### Query Explanation

- `EventCode=22` - Sysmon DNS query events
- `len(QueryName)` - Calculates DNS query length (normal: 20-40 chars, tunneling: 60-250+ chars)
- `where query_length > 50` - Initial filter for long queries
- Groups by base domain to identify tunneling domains
- `dc(QueryName)` - Distinct count indicates many unique subdomains (data encoded in subdomain)
- Multiple long queries to same domain = high confidence tunneling

### How DNS Tunneling Works

**Normal DNS Query:**
```
www.example.com  (15 characters)
```

**DNS Tunneling:**
```
6461746131323334.attacker-domain.com  (hex-encoded data in subdomain)
YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw.evil.com  (Base64 in subdomain)
```

**Attack Process:**
1. Attacker controls DNS server for malicious domain
2. Malware on victim system encodes data into DNS queries
3. Queries sent to attacker's DNS server
4. Attacker decodes data from DNS queries
5. Can bi-directionally tunnel (queries for exfil, responses for C2)

### True Positive Indicators

**DNS tunneling characteristics:**
- **Query Length:** 60-250+ characters (normal: 15-40)
- **Pattern:** Many unique subdomains to same base domain
- **Encoding:** Hex, Base64, custom encoding in subdomain
- **Frequency:** High volume in short period
- **Source:** Unusual process (PowerShell, custom binary, malware)
- **Destination Domain:** Newly registered, suspicious TLD (.xyz, .top, .club)
- **Time Pattern:** Continuous or periodic queries

**Example:**
```
ComputerName: WS-FIN-PC01
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
base_domain: data-exfil-tunnel.xyz
query_count: 1,247
unique_queries: 1,247 (every query unique = data encoding)
avg_length: 87
max_length: 243
```

### False Positive Scenarios

**Legitimate long DNS queries:**
- CDNs (Content Delivery Networks) with long subdomains
- Some cloud services (AWS, Azure) with complex hostnames
- DGA (Domain Generation Algorithm) detection queries by security tools
- Legitimate software with long version strings in queries

**Mitigation:**
- Whitelist known CDN domains
- Whitelist approved cloud services
- Baseline normal DNS query lengths for environment
- Focus on domains with many unique subdomains

### Response Actions

1. **Identify Tunneling Domain:**
   - Extract base domain from queries
   - Check domain registration (WHOIS)
   - Check domain reputation
   - Identify domain creation date (recently registered = suspicious)

2. **Analyze Query Pattern:**
   ```spl
   index=windows_sysmon EventCode=22 QueryName="*suspicious-domain.com"
   | table _time, ComputerName, Image, QueryName
   | sort _time
   ```

   Export queries and attempt to decode:
   ```python
   # Python example to decode Base64 subdomains
   import base64
   subdomain = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"
   decoded = base64.b64decode(subdomain)
   print(decoded)
   ```

3. **Identify Source Process:**
   - What process is generating queries?
   - Is it malware or legitimate software?
   - Check process hash against threat intel

4. **Determine Data Exfiltrated:**
   - Decode DNS queries to see actual data
   - Identify files/information being stolen
   - Assess business impact

5. **Containment:**
   - Block tunneling domain at DNS resolver
   - Sinkhole domain (redirect to internal server)
   - Block at firewall if possible
   - Isolate affected system
   - Kill tunneling process

6. **Investigation:**
   - How did malware get installed?
   - What is full scope of compromise?
   - Were other systems infected?
   - Check for C2 communication via other protocols

7. **Eradication:**
   - Remove malware/tunneling tool
   - Remove persistence mechanisms
   - Patch vulnerabilities
   - Consider re-image

### DNS Tunneling Tools

**Common tools:**
- dnscat2 - Popular DNS tunneling tool
- Iodine - Creates IP tunnel through DNS
- DNSExfiltrator - PowerShell-based exfiltration tool
- Cobalt Strike - Has DNS beacon option
- Custom scripts - Easy to implement

### Enhanced Detection - Query Entropy

High entropy in DNS queries indicates encoding:

```spl
index=windows_sysmon EventCode=22
| rex field=QueryName "(?<subdomain>[^.]+)\."
| eval subdomain_length=len(subdomain)
| where subdomain_length > 30
| stats count by QueryName, Image, ComputerName
| where count > 5
```

Focus on long, random-looking subdomains.

### Prevention

1. **DNS Filtering:** Block known tunneling domains (threat intel feeds)
2. **DNS Query Length Limits:** Firewall/DNS server rules
3. **Egress Filtering:** Only allow DNS queries to approved DNS servers
4. **Monitor Query Volume:** Alert on excessive queries per host
5. **DNS Sinkholing:** Redirect malicious domains to sinkhole
6. **Network Segmentation:** Isolate critical systems
7. **DNS over HTTPS (DoH) Blocking:** Prevents bypassing DNS monitoring

### Testing

**Safe Test (benign data):**

```powershell
# Generate long DNS query (will fail but will be logged)
nslookup "this-is-a-very-long-test-query-that-exceeds-fifty-characters-for-detection-testing.test-domain.com"

# Multiple queries with unique subdomains
1..50 | ForEach-Object {
    $random = -join ((65..90) + (97..122) | Get-Random -Count 30 | ForEach-Object {[char]$_})
    nslookup "$random.test-domain.com"
}
```

Should trigger alert showing multiple long queries to same base domain.

---

## Summary

These data exfiltration detection rules identify two critical exfiltration methods:

1. **Large Outbound Transfers:** Volume-based detection
2. **DNS Tunneling:** Protocol abuse detection

**Combined Coverage:**
- Direct data transfer (FTP, HTTPS, SCP)
- Covert channels (DNS tunneling)
- Both high-bandwidth and low-and-slow exfiltration

**Exfiltration Kill Chain:**
1. Initial Access → 2. Privilege Escalation → 3. Lateral Movement → 4. Collection → 5. Exfiltration (these rules)

**Detection Strategy:**
- Monitor outbound network traffic volumes
- Baseline normal data transfer patterns
- Alert on anomalies and unusual destinations
- Correlate with file access logs
- Monitor DNS for tunneling indicators

**Response Priority:**
- **Critical:** Multi-GB transfer or confirmed DNS tunneling
- **High:** Large transfer to unknown destination
- **Medium:** Transfer requiring investigation

**Key Metrics:**
- Data exfiltration attempts per month
- Average exfiltrated data volume
- Detection methods (volume-based vs protocol abuse)
- Time to detection
- Prevented vs successful exfiltration
- Most targeted data types

**Prevention Best Practices:**
- Deploy DLP (Data Loss Prevention)
- Implement egress filtering
- Monitor and control cloud service usage
- Classify and tag sensitive data
- Restrict data access (least privilege)
- Network segmentation
- User awareness training on data handling
- Encrypt sensitive data at rest
- Monitor removable media usage
- Regular security audits of data access

**Legal/Compliance Considerations:**
- Data breach notification requirements (GDPR, CCPA, HIPAA)
- Evidence preservation for investigations
- Forensic chain of custody
- Attorney-client privilege (involve legal early)
- Cyber insurance notification
- Law enforcement coordination (if applicable)
