# Splunk to osTicket Integration Guide

## Introduction

This guide demonstrates how to automate ticket creation in osTicket directly from Splunk SIEM alerts. When Splunk detection rules trigger, tickets are automatically created with all relevant alert context, IOCs, and affected system information, ensuring no security alerts are missed and providing a complete audit trail.

This integration showcases critical SOC automation skills and demonstrates understanding of API-based system integration, a key requirement for modern security operations.

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Splunk Alert Workflow                         │
└─────────────────────────────────────────────────────────────────┘

    ┌───────────────┐
    │  Splunk SIEM  │
    │  Detection    │
    │     Rule      │
    └───────┬───────┘
            │
            │ 1. Alert Triggered
            │    (Event threshold met)
            │
            v
    ┌───────────────┐
    │  Alert Action │
    │   (Webhook)   │
    └───────┬───────┘
            │
            │ 2. Execute Python Script
            │    or Webhook Action
            │
            v
    ┌───────────────┐
    │  Python API   │
    │    Script     │◄────────── osTicket API Key
    │ osticket.py   │            Configuration
    └───────┬───────┘
            │
            │ 3. HTTP POST Request
            │    to osTicket API
            │
            v
    ┌───────────────┐
    │  osTicket API │
    │  /api/tickets │
    │    .json      │
    └───────┬───────┘
            │
            │ 4. Create Ticket
            │    Return Ticket ID
            │
            v
    ┌───────────────┐
    │ osTicket New  │
    │    Ticket     │
    │   Created     │
    └───────────────┘
            │
            │ 5. Email Notification
            │    to SOC Analysts
            │
            v
    ┌───────────────┐
    │ SOC Analyst   │
    │   Receives    │
    │ Notification  │
    └───────────────┘
```

## Prerequisites

Before configuring the integration:

### Required Components
- ✅ Splunk Enterprise or Free (with alert capability)
- ✅ osTicket installed and configured (see [osTicket Setup Guide](osticket-setup.md))
- ✅ osTicket API key created (Admin Panel → Manage → API Keys)
- ✅ Python 3.6+ installed on Splunk server
- ✅ Network connectivity between Splunk and osTicket servers

### Required Information
- osTicket URL: `http://osticket.lab.local` or `http://10.0.0.25`
- osTicket API Key: (from osTicket Admin Panel)
- osTicket Department ID: (SOC Team or Tier 1 Analysts)

## Integration Methods

This integration supports two methods for ticket creation:

### Method 1: API-Based Integration (Recommended)
- **Pros:** Full control, custom field mapping, error handling, structured data
- **Cons:** Requires Python script development and maintenance
- **Use Case:** Production environments requiring reliability and customization

### Method 2: Email-Based Integration
- **Pros:** Simple configuration, no scripting required
- **Cons:** Limited field mapping, potential email delivery issues
- **Use Case:** Quick setup or environments without scripting capability

**Recommendation:** Use API-based integration for production SOC operations.

## Method 1: API-Based Integration (Recommended)

### Step 1: Create Python Integration Script

Create a Python script on the Splunk server to handle API communication:

```bash
# Create directory for custom alert actions
sudo mkdir -p /opt/splunk/etc/apps/osticket_integration/bin

# Create Python script
sudo nano /opt/splunk/etc/apps/osticket_integration/bin/osticket.py
```

**osticket.py Script:**

```python
#!/usr/bin/env python3
"""
osTicket Integration Script for Splunk
Creates tickets in osTicket via API when Splunk alerts trigger
"""

import sys
import json
import requests
import time
from datetime import datetime

# Configuration
OSTICKET_URL = "http://10.0.0.25"  # Replace with your osTicket URL
OSTICKET_API_KEY = "1234567890ABCDEF1234567890ABCDEF"  # Replace with your API key
API_ENDPOINT = f"{OSTICKET_URL}/api/tickets.json"

# Priority mapping: Splunk severity to osTicket priority
PRIORITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Low",
    "informational": "Low"
}

# Help topic mapping: Alert type to osTicket help topic
HELP_TOPIC_MAP = {
    "brute_force": "Brute Force Attack",
    "malware": "Malware Detection",
    "phishing": "Phishing Email",
    "data_exfiltration": "Data Exfiltration",
    "lateral_movement": "Security Alert - General",
    "suspicious_activity": "Suspicious Activity",
    "default": "Security Alert - General"
}


def create_ticket(alert_data):
    """
    Create a ticket in osTicket via API
    
    Args:
        alert_data (dict): Alert information from Splunk
        
    Returns:
        dict: API response with ticket ID
    """
    
    # Extract alert details
    alert_name = alert_data.get('search_name', 'Splunk Alert')
    severity = alert_data.get('severity', 'medium').lower()
    alert_type = alert_data.get('alert_type', 'default')
    
    # Extract result fields (first result)
    results = alert_data.get('result', {})
    
    # Build ticket subject
    subject = f"[Splunk Alert] {alert_name}"
    
    # Build ticket message with all alert context
    message = f"""
=== SPLUNK SIEM ALERT ===

Alert Name: {alert_name}
Severity: {severity.upper()}
Trigger Time: {alert_data.get('trigger_time', datetime.now().isoformat())}
Alert URL: {alert_data.get('results_link', 'N/A')}

=== AFFECTED SYSTEMS ===
Hostname: {results.get('host', results.get('ComputerName', 'Unknown'))}
Source IP: {results.get('src_ip', results.get('src', 'N/A'))}
Destination IP: {results.get('dest_ip', results.get('dest', 'N/A'))}
User Account: {results.get('user', results.get('Account_Name', 'N/A'))}

=== ALERT DETAILS ===
Event Count: {results.get('count', alert_data.get('num_events', 'N/A'))}
Time Range: {alert_data.get('search_earliest_time', 'N/A')} to {alert_data.get('search_latest_time', 'N/A')}

=== RAW EVENT DATA ===
{results.get('_raw', 'No raw event data available')}

=== INDICATORS OF COMPROMISE ===
{extract_iocs(results)}

=== MITRE ATT&CK MAPPING ===
Technique: {results.get('mitre_technique', 'To be determined during investigation')}

=== RECOMMENDED ACTIONS ===
1. Review alert in Splunk: {alert_data.get('results_link', 'N/A')}
2. Verify affected system status in EDR
3. Check for related events in timeframe
4. Follow appropriate incident response playbook
5. Document findings in this ticket

=== SPLUNK QUERY ===
{alert_data.get('search', 'Query not available')}

This ticket was automatically created by Splunk integration.
Analyst: Please acknowledge and begin triage within SLA timeframe.
"""
    
    # Prepare API payload
    payload = {
        "alert": alert_name,
        "autorespond": False,  # Don't auto-respond to prevent email loops
        "source": "API",
        "name": "Splunk SIEM",
        "email": "soc-alerts@lab.local",
        "phone": "",
        "subject": subject,
        "message": message,
        "ip": results.get('src_ip', results.get('src', '0.0.0.0')),
        "topicId": get_help_topic_id(alert_type),
        "priority": PRIORITY_MAP.get(severity, "Medium"),
        
        # Custom fields (match osTicket custom field IDs)
        "affected_system": results.get('host', results.get('ComputerName', 'Unknown')),
        "affected_user": results.get('user', results.get('Account_Name', 'N/A')),
        "mitre_attack": results.get('mitre_technique', 'TBD'),
        "iocs": extract_iocs(results),
        "alert_source": "Splunk SIEM",
        "investigation_status": "New - Not Yet Triaged",
        "incident_severity": severity.capitalize()
    }
    
    # Make API request
    headers = {
        "X-API-Key": OSTICKET_API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            API_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 201:
            ticket_data = response.json()
            print(f"✓ Ticket created successfully: #{ticket_data.get('number', 'Unknown')}")
            return {
                "success": True,
                "ticket_id": ticket_data.get('id'),
                "ticket_number": ticket_data.get('number')
            }
        else:
            print(f"✗ Error creating ticket: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return {
                "success": False,
                "error": f"HTTP {response.status_code}",
                "details": response.text
            }
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Network error: {str(e)}")
        return {
            "success": False,
            "error": "Network error",
            "details": str(e)
        }


def extract_iocs(results):
    """Extract IOCs from alert results"""
    iocs = []
    
    # IP addresses
    if results.get('src_ip') or results.get('src'):
        iocs.append(f"Source IP: {results.get('src_ip', results.get('src'))}")
    if results.get('dest_ip') or results.get('dest'):
        iocs.append(f"Destination IP: {results.get('dest_ip', results.get('dest'))}")
    
    # Domains
    if results.get('domain'):
        iocs.append(f"Domain: {results.get('domain')}")
    if results.get('url'):
        iocs.append(f"URL: {results.get('url')}")
    
    # File hashes
    if results.get('md5'):
        iocs.append(f"MD5: {results.get('md5')}")
    if results.get('sha256'):
        iocs.append(f"SHA256: {results.get('sha256')}")
    
    # Process/file names
    if results.get('process_name'):
        iocs.append(f"Process: {results.get('process_name')}")
    if results.get('file_path'):
        iocs.append(f"File Path: {results.get('file_path')}")
    
    return "\n".join(iocs) if iocs else "No IOCs extracted - review raw event data"


def get_help_topic_id(alert_type):
    """Map alert type to osTicket help topic ID"""
    # Note: These IDs must match your osTicket help topic IDs
    # Check in osTicket: Admin Panel → Manage → Help Topics
    topic_ids = {
        "brute_force": "2",
        "malware": "3",
        "phishing": "4",
        "data_exfiltration": "5",
        "suspicious_activity": "6",
        "default": "1"
    }
    return topic_ids.get(alert_type, topic_ids["default"])


def main():
    """Main execution function"""
    
    # Read alert data from stdin (Splunk provides this)
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        # Read from stdin when executed by Splunk
        alert_data = json.loads(sys.stdin.read())
    else:
        # Test mode - use sample data
        print("Running in test mode with sample data...")
        alert_data = {
            "search_name": "Test Alert - API Integration",
            "severity": "medium",
            "alert_type": "default",
            "trigger_time": datetime.now().isoformat(),
            "results_link": "http://splunk.lab.local:8000/app/search",
            "search": "index=test | stats count",
            "result": {
                "host": "TEST-WS01",
                "src_ip": "192.168.1.100",
                "user": "test.user",
                "count": "1"
            }
        }
    
    # Create ticket
    result = create_ticket(alert_data)
    
    # Return result
    if result.get("success"):
        sys.exit(0)  # Success
    else:
        sys.exit(1)  # Failure


if __name__ == "__main__":
    main()
```

### Step 2: Configure Script Permissions

```bash
# Make script executable
sudo chmod +x /opt/splunk/etc/apps/osticket_integration/bin/osticket.py

# Change ownership to Splunk user
sudo chown -R splunk:splunk /opt/splunk/etc/apps/osticket_integration

# Install required Python packages
sudo -u splunk /opt/splunk/bin/splunk cmd python3 -m pip install requests
```

### Step 3: Test the Integration Script

Test the script manually before configuring Splunk alerts:

```bash
# Test script execution
cd /opt/splunk/etc/apps/osticket_integration/bin
sudo -u splunk python3 osticket.py

# Expected output:
# Running in test mode with sample data...
# ✓ Ticket created successfully: #123456
```

**Verify in osTicket:**
1. Log in to osTicket admin panel
2. Navigate to Tickets → Open Tickets
3. Confirm test ticket was created with all fields populated

### Step 4: Create Splunk Alert Action

**Option A: Using alerts.conf (Recommended for reproducibility)**

Create alert action configuration:

```bash
sudo mkdir -p /opt/splunk/etc/apps/osticket_integration/default
sudo nano /opt/splunk/etc/apps/osticket_integration/default/alert_actions.conf
```

**alert_actions.conf:**
```ini
[osticket]
is_custom = 1
label = Create osTicket Ticket
description = Creates a ticket in osTicket via API
icon_path = alert_ticket.png
payload_format = json
command = osticket.py --execute
track_alert = 1
ttl = 600
maxresults = 1
```

**Option B: Using Splunk Web UI**

1. Navigate to: **Settings → Alert Actions**
2. Click **New Alert Action**
3. Configure:
   ```
   Name: osticket
   Label: Create osTicket Ticket
   Command: osticket.py --execute
   Execute Command: On Splunk Server
   ```

### Step 5: Configure Detection Rules with osTicket Action

Now configure your existing detection rules to create tickets automatically.

#### Example 1: Brute Force Detection Alert

**Navigate to:** Search & Reporting → Settings → Searches, reports, and alerts

**Edit Alert:** "Brute Force - Multiple Failed Logins"

**Alert Actions Tab:**
```
✓ Create osTicket Ticket
  Severity: high
  Alert Type: brute_force
  
✓ Send Email (optional - for immediate notification)
  To: soc-team@lab.local
  Subject: ALERT: Brute Force Detection - Review Ticket
```

**Corresponding Splunk SPL Query:**
```spl
index=windows_security EventCode=4625 
| stats count as failed_attempts by src_ip, Account_Name, ComputerName 
| where failed_attempts > 10
| eval severity="high"
| eval alert_type="brute_force"
| eval mitre_technique="T1110.001 - Brute Force: Password Guessing"
| table src_ip, Account_Name, ComputerName, failed_attempts, severity, alert_type, mitre_technique
```

#### Example 2: PowerShell Abuse Detection Alert

**Alert Name:** "Suspicious PowerShell - Encoded Command"

**Alert Actions:**
```
✓ Create osTicket Ticket
  Severity: high
  Alert Type: suspicious_activity
```

**SPL Query:**
```spl
index=windows_sysmon EventCode=1 CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*"
| rex field=CommandLine "-(?:EncodedCommand|enc)\s+(?<encoded_cmd>\S+)"
| eval decoded_cmd=base64decode(encoded_cmd)
| eval severity="high"
| eval alert_type="suspicious_activity"
| eval mitre_technique="T1059.001 - PowerShell Execution"
| table _time, ComputerName, User, CommandLine, decoded_cmd, severity, alert_type, mitre_technique
```

#### Example 3: Malware Detection Alert

**Alert Name:** "Malware - Office Application Spawned PowerShell"

**Alert Actions:**
```
✓ Create osTicket Ticket
  Severity: critical
  Alert Type: malware
```

**SPL Query:**
```spl
index=windows_sysmon EventCode=1 
(ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\POWERPNT.EXE")
(Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\wscript.exe")
| eval severity="critical"
| eval alert_type="malware"
| eval mitre_technique="T1204.002 - Malicious File Execution"
| table _time, ComputerName, User, ParentImage, Image, CommandLine, severity, alert_type, mitre_technique
```

#### Example 4: Data Exfiltration Detection Alert

**Alert Name:** "Data Exfiltration - Large Outbound Transfer"

**Alert Actions:**
```
✓ Create osTicket Ticket
  Severity: critical
  Alert Type: data_exfiltration
```

**SPL Query:**
```spl
index=firewall action=allowed direction=outbound
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port, user
| where total_bytes > 100000000
| eval total_mb=round(total_bytes/1024/1024,2)
| eval severity="critical"
| eval alert_type="data_exfiltration"
| eval mitre_technique="T1048 - Exfiltration Over Alternative Protocol"
| table src_ip, dest_ip, dest_port, user, total_mb, severity, alert_type, mitre_technique
```

### Step 6: Configure Alert Scheduling

For each detection rule, configure appropriate scheduling:

**Real-Time Alerts (Critical):**
```
Alert Type: Real-time
Trigger Condition: Per-Result (create ticket for each result)
Throttle: 5 minutes (prevent duplicate tickets)
```

**Scheduled Alerts (High/Medium):**
```
Schedule: Every 5 minutes
Time Range: -5m to now
Trigger Condition: Number of Results > 0
Throttle: 15 minutes
```

### Step 7: Field Mapping Reference

Ensure your Splunk queries include fields that map to osTicket custom fields:

| Splunk Field | osTicket Field | Purpose |
|--------------|----------------|---------|
| `host` or `ComputerName` | Affected System | Target system identification |
| `user` or `Account_Name` | Affected User | User account involved |
| `src_ip` or `src` | IOCs | Source IP address |
| `dest_ip` or `dest` | IOCs | Destination IP |
| `md5`, `sha256` | IOCs | File hashes |
| `mitre_technique` | MITRE ATT&CK Technique | Technique classification |
| `severity` | Incident Severity | Alert priority |
| `alert_type` | Help Topic mapping | Alert categorization |

## Method 2: Email-Based Integration

### Step 1: Configure osTicket Email Piping

**Navigate to:** Admin Panel → Emails → Emails

**Add New Email:**
```
Email Address: soc-alerts@lab.local
Email Name: SOC Alerts
Department: Tier 1 Analysts
Priority: High
Status: Active
Auto-Response: Disabled
```

**Email Fetching (POP3/IMAP):**
```
Protocol: IMAP
Host: mail.lab.local
Port: 993
Username: soc-alerts@lab.local
Password: [email password]
Folder: INBOX
Fetch Frequency: Every 5 minutes
```

### Step 2: Configure Splunk Email Alert

For each detection rule:

**Alert Actions:**
```
✓ Send Email
  To: soc-alerts@lab.local
  Subject: [SPLUNK ALERT - $result.severity$] $name$
  Message: 
    Alert: $name$
    Severity: $result.severity$
    Time: $trigger_time$
    
    Affected System: $result.host$
    Source IP: $result.src_ip$
    User: $result.user$
    
    Event Count: $result.count$
    
    View in Splunk: $results_link$
    
    --- Raw Results ---
    $results$
```

**Priority Mapping:**
- Critical alerts → High priority tickets
- High alerts → Medium priority tickets  
- Medium alerts → Low priority tickets

### Step 3: Email Template Optimization

Create an email template that extracts well in osTicket:

```
Subject: [SPLUNK-$trigger_severity$] $alert_name$

Body:
ALERT INFORMATION
=================
Alert Name: $alert_name$
Severity: $trigger_severity$
Trigger Time: $trigger_time$
Splunk URL: $results_link$

AFFECTED SYSTEMS
================
Hostname: $result.ComputerName$
Source IP: $result.src_ip$
User Account: $result.user$

INDICATORS OF COMPROMISE
=========================
$result.iocs$

MITRE ATT&CK MAPPING
====================
Technique: $result.mitre_technique$

SPLUNK QUERY
============
$search$

RECOMMENDED ACTIONS
===================
1. Review alert in Splunk
2. Verify system status
3. Check for related events
4. Follow incident response playbook
5. Document findings in ticket
```

## Testing the Integration

### Test 1: Manual API Test

```bash
# From Splunk server
curl -X POST http://osticket.lab.local/api/tickets.json \
  -H "X-API-Key: YOUR-API-KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "alert": "Integration Test",
    "autorespond": false,
    "source": "API",
    "name": "Splunk SIEM",
    "email": "soc@lab.local",
    "subject": "[TEST] API Integration",
    "message": "This is a test ticket from the integration script.",
    "topicId": "1",
    "priority": "High"
  }'
```

**Expected Response:**
```json
{"ticket_id": 12345, "number": "123456"}
```

### Test 2: Trigger Test Alert in Splunk

Create a test search:

```spl
index=_internal 
| head 1
| eval severity="medium"
| eval alert_type="default"
| eval host="SPLUNK-SERVER"
| eval mitre_technique="TEST"
```

**Save as Alert:**
- Title: "Test - osTicket Integration"
- Alert Type: Scheduled
- Schedule: Run once
- Alert Action: Create osTicket Ticket

**Run Alert and Verify:**
1. Alert executes successfully
2. Ticket appears in osTicket
3. All fields populated correctly

### Test 3: End-to-End Test with Real Detection

Trigger an actual detection rule:

```bash
# From Windows workstation, generate failed RDP attempts
# This will trigger "Brute Force Detection" alert

# Monitor Splunk alert
# Monitor osTicket for new ticket creation
# Verify ticket contains correct alert data
```

## Troubleshooting

### Issue 1: Script Fails with Permission Error

**Symptom:** Alert fails with "Permission denied" error

**Solution:**
```bash
sudo chown splunk:splunk /opt/splunk/etc/apps/osticket_integration/bin/osticket.py
sudo chmod +x /opt/splunk/etc/apps/osticket_integration/bin/osticket.py
```

### Issue 2: API Returns 401 Unauthorized

**Symptom:** "Error creating ticket: HTTP 401"

**Solution:**
- Verify API key is correct in script
- Check API key is active in osTicket
- Confirm IP whitelist includes Splunk server IP
- Test API key with curl command

### Issue 3: Tickets Not Created

**Symptom:** Alert fires but no ticket appears in osTicket

**Solution:**
```bash
# Check Splunk alert execution logs
/opt/splunk/var/log/splunk/splunkd.log | grep osticket

# Check script output
sudo -u splunk /opt/splunk/etc/apps/osticket_integration/bin/osticket.py

# Verify network connectivity
curl -I http://osticket.lab.local
```

### Issue 4: Custom Fields Not Populating

**Symptom:** Ticket created but custom fields are empty

**Solution:**
- Verify field names in script match osTicket field variables
- Check Splunk query includes required fields
- Review osTicket API logs for field validation errors
- Ensure custom fields are set to "Agent Visible"

### Issue 5: Duplicate Tickets

**Symptom:** Multiple tickets created for same alert

**Solution:**
- Enable alert throttling in Splunk (5-15 minutes)
- Use "digest mode" for alert actions
- Implement deduplication logic in Python script
- Check alert scheduling frequency

## Alert Configuration Best Practices

### 1. Alert Throttling
```
Throttle: 15 minutes
Suppress Results: Yes
Fields: src_ip, host, alert_type
```

### 2. Result Limiting
```
Max Results: 100
Action: Create one ticket per result (for critical)
        Create one ticket with all results (for low priority)
```

### 3. Alert Scheduling
- **Critical Alerts:** Real-time or every 1-5 minutes
- **High Alerts:** Every 5-15 minutes
- **Medium Alerts:** Every 15-30 minutes
- **Low Alerts:** Hourly or daily digest

### 4. Field Enrichment

Always include these fields in detection rules:
```spl
| eval severity="high"
| eval alert_type="brute_force"
| eval mitre_technique="T1110.001"
| eval remediation="Block source IP, reset password"
```

### 5. Alert Prioritization

Configure priority matrix:
```
Critical: Active breach, ransomware, data exfiltration → Immediate ticket
High: Malware, successful intrusion, privilege escalation → 5-min ticket
Medium: Suspicious activity, policy violations → 15-min ticket  
Low: Informational, potential false positives → Hourly digest
```

## Monitoring and Metrics

### Track Integration Health

**Splunk Dashboard: osTicket Integration Metrics**

```spl
index=_internal source="*osticket*"
| stats count as total_tickets by severity, alert_type
| eval success_rate=round((successes/total_tickets)*100,2)
```

**Key Metrics:**
- Tickets created per day
- Success rate (tickets created vs alerts fired)
- Average ticket creation time
- Failed ticket creation attempts
- Most common alert types generating tickets

### osTicket Metrics

Monitor in osTicket dashboard:
- Tickets created from Splunk (source: API)
- Average time to first response (MTTA)
- Average time to resolution (MTTR)
- Tickets by priority distribution
- Tickets by help topic

## Advanced Configuration

### Deduplication Logic

Add deduplication to prevent duplicate tickets:

```python
def check_existing_ticket(subject, timeframe_hours=1):
    """Check if similar ticket exists within timeframe"""
    search_url = f"{OSTICKET_URL}/api/tickets.json?subject={subject}&hours={timeframe_hours}"
    # Implement API search
    # Return ticket ID if exists, None otherwise
    pass

# In create_ticket():
existing = check_existing_ticket(subject)
if existing:
    # Update existing ticket instead of creating new one
    return update_ticket(existing, new_data)
```

### Ticket Updates

Add functionality to update tickets when alerts repeat:

```python
def update_ticket(ticket_id, update_message):
    """Add internal note to existing ticket"""
    update_url = f"{OSTICKET_URL}/api/tickets/{ticket_id}/update"
    # Implementation
    pass
```

### Webhook Alternative

For lightweight integration without Python:

**Splunk Webhook Configuration:**
```
URL: http://osticket.lab.local/api/tickets.json
Method: POST
Headers:
  X-API-Key: YOUR-API-KEY
  Content-Type: application/json
Body:
{
  "subject": "$name$",
  "message": "$results$",
  "priority": "$result.severity$",
  "topicId": "1",
  "name": "Splunk SIEM",
  "email": "soc@lab.local"
}
```

## Next Steps

1. **Implement Workflow:** Review [Workflow Guide](workflow-guide.md)
2. **Review Examples:** Study [Sample Tickets](sample-tickets/)
3. **Create Playbooks:** Link tickets to incident response playbooks
4. **Monitor Metrics:** Track MTTA and MTTR
5. **Continuous Improvement:** Refine detection rules based on ticket feedback

---

*This integration guide demonstrates production-grade SIEM-to-ticketing automation used in enterprise SOC environments. The API-based approach provides reliable, structured ticket creation with full context preservation.*
