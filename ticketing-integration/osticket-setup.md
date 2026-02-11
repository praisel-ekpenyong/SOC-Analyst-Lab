# osTicket Setup Guide

## Introduction

This guide provides step-by-step instructions for installing and configuring osTicket on Ubuntu Server 22.04 for SOC incident management. The setup includes customizations specific to security operations, including custom fields for MITRE ATT&CK mapping, IOC tracking, and multi-tier analyst workflows.

## System Requirements

### Hardware Requirements
- **CPU:** 2 cores minimum (4 cores recommended)
- **RAM:** 4GB minimum (8GB recommended for production)
- **Storage:** 20GB minimum (50GB recommended with log retention)
- **Network:** Static IP address on lab network

### Software Requirements
- **Operating System:** Ubuntu Server 22.04 LTS
- **Web Server:** Apache 2.4+
- **Database:** MySQL 8.0+ or MariaDB 10.5+
- **PHP:** 7.4+ with required extensions
- **osTicket:** Version 1.18.1 (latest stable)

### Network Requirements
- **Inbound Access:** Port 80 (HTTP) and 443 (HTTPS)
- **Outbound Access:** Email server (port 25/587) for notifications
- **SIEM Integration:** Splunk can reach osTicket on port 80/443
- **DNS:** Optional but recommended for hostname resolution

## Installation Steps

### Step 1: Prepare Ubuntu Server

Update system packages and install prerequisites:

```bash
# Update package repository
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y apache2 mysql-server php php-mysql php-gd php-imap \
  php-xml php-mbstring php-intl php-apcu php-opcache unzip wget curl

# Enable required PHP extensions
sudo phpenmod mysqli gd imap xml mbstring intl apcu opcache

# Restart Apache to load PHP modules
sudo systemctl restart apache2

# Verify Apache and PHP are running
sudo systemctl status apache2
php -v
```

**Expected Output:**
```
PHP 8.1.x (cli) (built: ...)
Apache/2.4.x (Ubuntu) Server running
```

**Screenshot Description:** Terminal showing successful package installation and PHP version confirmation.

### Step 2: Configure MySQL Database

Secure MySQL installation and create osTicket database:

```bash
# Secure MySQL installation
sudo mysql_secure_installation

# Answer prompts:
# - Set root password: Yes (use strong password)
# - Remove anonymous users: Yes
# - Disallow root login remotely: Yes
# - Remove test database: Yes
# - Reload privilege tables: Yes

# Log in to MySQL as root
sudo mysql -u root -p

# Create osTicket database and user
CREATE DATABASE osticket CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'osticket_user'@'localhost' IDENTIFIED BY 'StrongPassword123!';
GRANT ALL PRIVILEGES ON osticket.* TO 'osticket_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

**Important:** Replace `StrongPassword123!` with a strong, unique password and document it securely.

### Step 3: Download and Extract osTicket

```bash
# Download osTicket latest release
cd /tmp
wget https://github.com/osTicket/osTicket/releases/download/v1.18.1/osTicket-v1.18.1.zip

# Extract to web directory
sudo unzip osTicket-v1.18.1.zip -d /var/www/
sudo mv /var/www/upload /var/www/osticket

# Set proper permissions
sudo chown -R www-data:www-data /var/www/osticket
sudo chmod -R 755 /var/www/osticket

# Copy sample configuration file
sudo cp /var/www/osticket/include/ost-sampleconfig.php /var/www/osticket/include/ost-config.php
sudo chmod 0666 /var/www/osticket/include/ost-config.php
```

### Step 4: Configure Apache Virtual Host

Create Apache configuration for osTicket:

```bash
# Create virtual host configuration
sudo nano /etc/apache2/sites-available/osticket.conf
```

**osticket.conf content:**
```apache
<VirtualHost *:80>
    ServerName osticket.lab.local
    ServerAlias osticket
    DocumentRoot /var/www/osticket

    <Directory /var/www/osticket>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/osticket_error.log
    CustomLog ${APACHE_LOG_DIR}/osticket_access.log combined

    # PHP settings for osTicket
    php_value upload_max_filesize 25M
    php_value post_max_size 25M
    php_value max_execution_time 300
</VirtualHost>
```

Enable the site and required Apache modules:

```bash
# Enable Apache modules
sudo a2enmod rewrite headers

# Enable osTicket site and disable default
sudo a2ensite osticket.conf
sudo a2dissite 000-default.conf

# Test Apache configuration
sudo apache2ctl configtest

# Restart Apache
sudo systemctl restart apache2
```

**Screenshot Description:** Browser showing Apache2 Ubuntu default page, then osTicket installation page.

### Step 5: Complete Web-Based Installation

Open web browser and navigate to: `http://[Ubuntu-Server-IP]/setup`

**Installation Wizard Steps:**

1. **System Check Page**
   - Verify all PHP extensions show green checkmarks
   - Ensure MySQL support is enabled
   - If any items are red, install missing extensions

2. **Basic Installation Information**
   ```
   Help Desk Name: SOC Analyst Lab - Incident Ticketing
   Default Email: soc@lab.local
   ```

3. **Admin User Creation**
   ```
   First Name: SOC
   Last Name: Administrator
   Email Address: socadmin@lab.local
   Username: socadmin
   Password: [Strong password]
   ```

4. **Database Configuration**
   ```
   MySQL Database: osticket
   MySQL Username: osticket_user
   MySQL Password: [Password created in Step 2]
   MySQL Hostname: localhost
   MySQL Table Prefix: ost_
   ```

5. **Click "Install Now"**

**Post-Installation Security:**

```bash
# Remove setup directory (CRITICAL for security)
sudo rm -rf /var/www/osticket/setup

# Set proper permissions on config file
sudo chmod 0644 /var/www/osticket/include/ost-config.php
```

**Screenshot Description:** osTicket installation success page with green checkmark and admin login button.

## Initial Configuration

### Step 6: Configure System Settings

Log in to osTicket Admin Panel: `http://[Ubuntu-Server-IP]/scp`

**Navigate to: Admin Panel → Settings → System**

#### Email Settings
```
Default System Email: soc@lab.local
Default Alert Email: soc-alerts@lab.local
Default Name: SOC Incident Ticketing
Default Signature: 
---
SOC Analyst Lab
Security Operations Center
Response Time: 15 minutes (Critical/High)
```

#### Ticket Settings
```
Default Ticket Queue: Open
Default Ticket Status: Open
Maximum Open Tickets: Unlimited
Agent Collision Avoidance: Enabled
```

**Screenshot Description:** Admin panel system settings page with email configuration fields.

### Step 7: Create Departments

**Navigate to: Admin Panel → Agents → Departments**

Create the following departments to mirror SOC organizational structure:

#### Department 1: SOC Team (Primary)
```
Name: SOC Team
Type: Public
Status: Active
SLA: Critical Incidents SLA (15 min response)
Manager: socadmin
```

#### Department 2: Tier 1 Analysts
```
Name: Tier 1 Analysts
Type: Public
Status: Active
SLA: Standard SLA (30 min response)
Parent Department: SOC Team
Description: Initial triage and investigation of security alerts
```

#### Department 3: Tier 2 Analysts
```
Name: Tier 2 Analysts
Type: Public
Status: Active
SLA: Standard SLA (1 hour response)
Parent Department: SOC Team
Description: Advanced investigation and incident response
```

#### Department 4: Tier 3 Engineers
```
Name: Tier 3 Engineers
Type: Private
Status: Active
SLA: Critical Incidents SLA (2 hour response)
Parent Department: SOC Team
Description: Complex investigations, malware analysis, threat hunting
```

**Screenshot Description:** Departments list showing all four SOC departments with hierarchical structure.

### Step 8: Configure Ticket Priorities

**Navigate to: Admin Panel → Manage → Priorities**

Configure priorities aligned with SOC incident severity ratings:

#### Priority 1: Critical
```
Priority Level: 4 (Highest)
Priority Color: #FF0000 (Red)
SLA Plan: Critical Incidents SLA
Description: Active breach, data exfiltration, domain admin compromise, ransomware
Priority Overdue: 15 minutes
```

#### Priority 2: High
```
Priority Level: 3
Priority Color: #FF6600 (Orange)
SLA Plan: High Priority SLA
Description: Confirmed malware, successful brute force, privilege escalation
Priority Overdue: 1 hour
```

#### Priority 3: Medium
```
Priority Level: 2
Priority Color: #FFCC00 (Yellow)
SLA Plan: Standard SLA
Description: Suspicious activity, potential compromise, policy violations
Priority Overdue: 4 hours
```

#### Priority 4: Low
```
Priority Level: 1 (Lowest)
Priority Color: #00CC00 (Green)
SLA Plan: Low Priority SLA
Description: Informational alerts, false positives, security questions
Priority Overdue: 24 hours
```

**Screenshot Description:** Priority configuration showing color-coded severity levels with SLA assignments.

### Step 9: Create Custom Fields for SOC Operations

**Navigate to: Admin Panel → Manage → Forms → Ticket Details**

Click "Add New Field" for each of the following custom fields:

#### Field 1: Affected System/Hostname
```
Label: Affected System/Hostname
Type: Text (Short Answer)
Visibility: Agents Only
Required: Yes
Hint: Enter hostname or IP address of affected system (e.g., WS-FIN-PC01, 10.0.0.15)
Configuration: 
  - Variable: affected_system
  - Placeholder: Hostname or IP Address
```

#### Field 2: Affected User
```
Label: Affected User
Type: Text (Short Answer)
Visibility: Agents Only
Required: No
Hint: Username of affected user account (e.g., j.martinez, a.chen)
Configuration:
  - Variable: affected_user
  - Placeholder: Domain\Username
```

#### Field 3: MITRE ATT&CK Technique
```
Label: MITRE ATT&CK Technique
Type: Text (Short Answer)
Visibility: Agents Only
Required: No
Hint: MITRE ATT&CK technique ID and name (e.g., T1110.001 - Brute Force: Password Guessing)
Configuration:
  - Variable: mitre_attack
  - Placeholder: T1XXX.XXX - Technique Name
```

#### Field 4: Indicators of Compromise (IOCs)
```
Label: Indicators of Compromise (IOCs)
Type: Text (Long Answer / Text Area)
Visibility: Agents Only
Required: No
Hint: List all IOCs: IP addresses, domains, file hashes, registry keys, etc.
Configuration:
  - Variable: iocs
  - Rows: 5
  - Placeholder: Enter IOCs (one per line)
```

#### Field 5: Alert Source
```
Label: Alert Source
Type: Dropdown / Choices
Visibility: Agents Only
Required: Yes
Choices:
  - Splunk SIEM
  - Wazuh EDR
  - Manual Observation
  - User Report
  - Threat Intelligence
  - Other
Configuration:
  - Variable: alert_source
  - Default: Splunk SIEM
```

#### Field 6: Investigation Status
```
Label: Investigation Status
Type: Dropdown / Choices
Visibility: Agents Only
Required: Yes
Choices:
  - New - Not Yet Triaged
  - Triage - Initial Review
  - Investigating - Active Analysis
  - Containment - Threat Being Contained
  - Eradication - Removing Threat
  - Recovery - Restoring Systems
  - Closed - Resolved
  - False Positive
Configuration:
  - Variable: investigation_status
  - Default: New - Not Yet Triaged
```

#### Field 7: Incident Severity (Business Impact)
```
Label: Incident Severity
Type: Dropdown / Choices
Visibility: Agents Only
Required: Yes
Choices:
  - Critical - Active data breach or domain compromise
  - High - Confirmed malware or successful attack
  - Medium - Suspicious activity requiring investigation
  - Low - Informational or potential false positive
Configuration:
  - Variable: incident_severity
  - Default: Medium - Suspicious activity requiring investigation
```

**Screenshot Description:** Custom fields form builder showing all seven SOC-specific fields configured.

### Step 10: Create Help Topics

**Navigate to: Admin Panel → Manage → Help Topics**

Create help topics aligned with common SOC alert types:

#### Help Topic 1: Security Alert - General
```
Topic: Security Alert - General
Status: Active
Type: Public
Department: Tier 1 Analysts
Priority: Medium
SLA Plan: Standard SLA
Auto-Response: Enabled
Form: Ticket Details (with custom fields)
```

#### Help Topic 2: Brute Force Attack
```
Topic: Brute Force Attack
Status: Active
Type: Public
Department: Tier 1 Analysts
Priority: High
SLA Plan: High Priority SLA
Auto-Response: Enabled
```

#### Help Topic 3: Malware Detection
```
Topic: Malware Detection
Status: Active
Type: Public
Department: Tier 2 Analysts
Priority: Critical
SLA Plan: Critical Incidents SLA
Auto-Response: Enabled
```

#### Help Topic 4: Phishing Email
```
Topic: Phishing Email
Status: Active
Type: Public
Department: Tier 1 Analysts
Priority: Medium
SLA Plan: Standard SLA
Auto-Response: Enabled
```

#### Help Topic 5: Data Exfiltration
```
Topic: Data Exfiltration
Status: Active
Type: Public
Department: Tier 2 Analysts
Priority: Critical
SLA Plan: Critical Incidents SLA
Auto-Response: Enabled
```

#### Help Topic 6: Suspicious Activity
```
Topic: Suspicious Activity
Status: Active
Type: Public
Department: Tier 1 Analysts
Priority: Low
SLA Plan: Low Priority SLA
Auto-Response: Enabled
```

**Screenshot Description:** Help topics list showing all six security-focused topics with priority assignments.

### Step 11: Configure SLA Plans

**Navigate to: Admin Panel → Manage → SLA Plans**

Create SLA plans for different severity levels:

#### SLA 1: Critical Incidents SLA
```
Name: Critical Incidents SLA
Grace Period: 15 minutes
Status: Active
Transient: No (applies 24/7)
Ticket Overdue Alerts: Enabled
  - Alert on overdue: Immediately
  - Send to: Department Manager + Assigned Agent
Schedule: 24/7 (Always Active)
```

#### SLA 2: High Priority SLA
```
Name: High Priority SLA
Grace Period: 1 hour
Status: Active
Transient: No
Ticket Overdue Alerts: Enabled
Schedule: Business Hours (Monday-Friday, 8 AM - 6 PM)
After Hours Grace: +2 hours
```

#### SLA 3: Standard SLA
```
Name: Standard SLA
Grace Period: 4 hours
Status: Active
Transient: No
Ticket Overdue Alerts: Enabled
Schedule: Business Hours
After Hours Grace: Next business day
```

#### SLA 4: Low Priority SLA
```
Name: Low Priority SLA
Grace Period: 24 hours
Status: Active
Transient: No
Ticket Overdue Alerts: Disabled
Schedule: Business Hours
```

**Screenshot Description:** SLA plans configuration showing grace periods and alert settings.

### Step 12: Configure Email Notifications

**Navigate to: Admin Panel → Emails → Settings**

#### Outgoing Email (SMTP Configuration)

If you have an SMTP server (e.g., Gmail, Office 365, or lab mail server):

```
Email Sending Method: SMTP
SMTP Hostname: smtp.gmail.com
SMTP Port: 587
SMTP Authentication: Required
SMTP Username: soc-alerts@yourdomain.com
SMTP Password: [App-specific password]
Encryption: TLS
```

**For Lab Environment Without Email:**
```
Email Sending Method: PHP Mail Function
Status: Enabled (for logging only)
Note: Emails will be logged but not sent
```

#### Email Templates

Customize email templates for SOC context:

**Navigate to: Admin Panel → Emails → Templates**

**New Ticket Alert Template:**
```
Subject: [SOC Alert #%{ticket.number}] %{ticket.subject}

Body:
A new security alert has been assigned to you.

Ticket #: %{ticket.number}
Priority: %{ticket.priority}
Department: %{ticket.dept}
Alert Source: %{ticket.alert_source}
Affected System: %{ticket.affected_system}
Created: %{ticket.create_date}

Subject: %{ticket.subject}

Please acknowledge and begin triage within SLA timeframe.

View Ticket: %{ticket.staff_url}

---
SOC Incident Ticketing System
```

**Screenshot Description:** Email template editor showing customized SOC alert notification.

### Step 13: Enable and Configure API

**Navigate to: Admin Panel → Manage → API Keys**

#### Create API Key for Splunk Integration

```
Name: Splunk SIEM Integration
Status: Active
IP Whitelist: [Splunk Server IP] (e.g., 10.0.0.20)
Notes: Used for automated ticket creation from Splunk alerts
```

Click "Add New API Key" and note the generated key:

```
API Key: 1234567890ABCDEF1234567890ABCDEF
```

**IMPORTANT:** Store this API key securely. You'll need it for the Splunk integration.

#### Test API Endpoint

```bash
# Test API connectivity from Splunk server
curl -X POST http://[osTicket-IP]/api/tickets.json \
  -H "X-API-Key: 1234567890ABCDEF1234567890ABCDEF" \
  -H "Content-Type: application/json" \
  -d '{
    "alert": "Test API Connection",
    "autorespond": false,
    "source": "API",
    "name": "Test User",
    "email": "test@lab.local",
    "phone": "",
    "subject": "Test Ticket from API",
    "message": "This is a test ticket created via osTicket API."
  }'
```

**Expected Response:**
```json
{
  "ticket_id": 12345,
  "number": "123456",
  "message": "Ticket created successfully"
}
```

**Screenshot Description:** Terminal showing successful API test with ticket ID returned.

### Step 14: Create Agent Accounts

**Navigate to: Admin Panel → Agents → Agents**

Create analyst accounts for SOC team members:

#### Tier 1 Analyst Account
```
Name: John Doe
Email: j.doe@lab.local
Username: jdoe
Department: Tier 1 Analysts
Role: Tier 1 Analyst
Permissions:
  - View tickets
  - Create tickets
  - Edit tickets
  - Post replies
  - Assign tickets (within department)
```

#### Tier 2 Analyst Account
```
Name: Jane Smith
Email: j.smith@lab.local
Username: jsmith
Department: Tier 2 Analysts
Role: Tier 2 Analyst
Permissions:
  - All Tier 1 permissions
  - Close tickets
  - Delete tickets
  - Edit ticket priority
  - Transfer tickets
  - Merge tickets
```

**Screenshot Description:** Agent profile creation form with permissions checkboxes.

## Post-Installation Configuration

### Step 15: Configure Ticket Workflows

**Navigate to: Admin Panel → Settings → Tickets**

```
Default Ticket Status: Open
Allow Client Updates: No (SOC tickets are analyst-only)
Require Help Topic: Yes
Claim Tickets on Response: Yes
Assigned Tickets: Answerable by Department Members
Auto-Claim on Assignment: Yes
Auto-Close Tickets: No (Manual closure required)
```

### Step 16: Set Up Canned Responses

**Navigate to: Admin Panel → Manage → Canned Responses**

Create templates for common SOC responses:

#### Canned Response 1: Initial Acknowledgment
```
Title: Initial Acknowledgment
Body:
Your security alert has been received and is currently being triaged by our SOC team.

Ticket #: {ticket.number}
Priority: {ticket.priority}
Assigned Analyst: {ticket.assignee}

We will provide an update within [SLA timeframe] as we investigate this incident.
```

#### Canned Response 2: Investigation In Progress
```
Title: Investigation In Progress
Body:
Investigation Update:

Current Status: Actively investigating
Next Steps: [Describe next investigation steps]
Estimated Resolution: [Timeframe]

We will provide further updates as the investigation progresses.
```

#### Canned Response 3: False Positive
```
Title: False Positive Closure
Body:
After thorough investigation, this alert has been determined to be a false positive.

Root Cause: [Explain why false positive]
Preventive Action: [Detection rule tuning or whitelist update]

No further action required. Ticket closed.
```

**Screenshot Description:** Canned responses list with SOC-specific templates.

### Step 17: Configure Dashboard and Reports

**Navigate to: Admin Panel → Dashboard**

Customize dashboard widgets for SOC metrics:

**Recommended Widgets:**
- Open Tickets by Priority
- Tickets by Department
- Tickets by Help Topic
- Overdue Tickets
- Average Response Time
- Average Resolution Time
- Tickets Closed This Week
- Top Agents by Tickets Resolved

**Screenshot Description:** Agent dashboard showing open tickets grouped by priority with color-coded severity.

## Testing and Validation

### Test 1: Manual Ticket Creation

1. Log in as SOC agent
2. Create new ticket: "Test - Manual Ticket Creation"
3. Fill in all custom fields:
   - Affected System: TEST-WS01
   - Alert Source: Manual Observation
   - Investigation Status: Triage - Initial Review
4. Verify ticket appears in queue
5. Add internal note and close ticket

### Test 2: API Ticket Creation

Run API test from Step 13 and verify:
- Ticket created successfully
- Custom fields populated
- Assigned to correct department
- SLA timer started

### Test 3: Email Notifications

Send test notification:
```bash
sudo /var/www/osticket/include/cli/test-email.php
```

Verify email delivery (check logs if SMTP not configured).

## Security Hardening

### SSL/TLS Configuration

Install Let's Encrypt SSL certificate (optional for production):

```bash
# Install Certbot
sudo apt install certbot python3-certbot-apache

# Obtain certificate
sudo certbot --apache -d osticket.lab.local

# Auto-renewal
sudo systemctl enable certbot.timer
```

### Firewall Configuration

```bash
# Configure UFW firewall
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp
sudo ufw enable
```

### File Permissions Audit

```bash
# Verify secure permissions
ls -l /var/www/osticket/include/ost-config.php
# Should show: -rw-r--r-- (644)

# Ensure setup directory was removed
ls /var/www/osticket/setup
# Should return: No such file or directory
```

## Backup and Maintenance

### Database Backup Script

Create automated backup script:

```bash
# Create backup script
sudo nano /usr/local/bin/osticket-backup.sh
```

**Script content:**
```bash
#!/bin/bash
BACKUP_DIR="/backup/osticket"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup MySQL database
mysqldump -u osticket_user -p'StrongPassword123!' osticket | gzip > $BACKUP_DIR/osticket_db_$TIMESTAMP.sql.gz

# Backup osTicket files
tar -czf $BACKUP_DIR/osticket_files_$TIMESTAMP.tar.gz /var/www/osticket

# Delete backups older than 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

echo "Backup completed: $TIMESTAMP"
```

Make executable and schedule:
```bash
sudo chmod +x /usr/local/bin/osticket-backup.sh
sudo crontab -e
# Add line: 0 2 * * * /usr/local/bin/osticket-backup.sh
```

### Update osTicket

```bash
# Backup before updating
/usr/local/bin/osticket-backup.sh

# Download new version
cd /tmp
wget https://github.com/osTicket/osTicket/releases/download/vX.XX.X/osTicket-vX.XX.X.zip

# Follow upgrade instructions from osTicket documentation
```

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: PHP Extensions Missing
**Symptom:** Red X marks on installation system check page

**Solution:**
```bash
sudo apt install php-mysqli php-gd php-imap php-xml php-mbstring
sudo systemctl restart apache2
```

#### Issue 2: Permission Denied Errors
**Symptom:** 500 Internal Server Error or permission denied in logs

**Solution:**
```bash
sudo chown -R www-data:www-data /var/www/osticket
sudo chmod -R 755 /var/www/osticket
```

#### Issue 3: API Key Not Working
**Symptom:** 401 Unauthorized when calling API

**Solution:**
- Verify IP whitelist includes Splunk server IP
- Check API key is active
- Ensure `X-API-Key` header is set correctly
- Verify URL: `/api/tickets.json` (not `/api/ticket.json`)

#### Issue 4: Tickets Not Appearing in Queue
**Symptom:** Ticket created but not visible to agents

**Solution:**
- Verify agent has access to department
- Check ticket status is "Open" not "Closed"
- Ensure agent role permissions include "View Tickets"

#### Issue 5: Email Not Sending
**Symptom:** No email notifications received

**Solution:**
```bash
# Check mail logs
sudo tail -f /var/log/mail.log

# Test PHP mail function
php -r "mail('test@example.com', 'Test', 'Test message');"

# Verify SMTP credentials if using SMTP
```

## Next Steps

Now that osTicket is installed and configured:

1. **Integrate with Splunk:** Proceed to [Splunk Integration Guide](splunk-integration.md)
2. **Define Workflows:** Review [Workflow Guide](workflow-guide.md)
3. **Study Examples:** Review [Sample Tickets](sample-tickets/)
4. **Test End-to-End:** Create test alert in Splunk and verify ticket creation
5. **Monitor Metrics:** Track MTTA and MTTR for continuous improvement

---

*This setup guide provides a production-ready osTicket deployment customized for SOC incident management. All configurations are based on industry best practices and real-world SOC operations.*
