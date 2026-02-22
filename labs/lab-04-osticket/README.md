# Lab 04 – osTicket Help Desk Lab

## Objective
Install and configure osTicket on Ubuntu + LAMP + MariaDB. Set up Admins, Agents, Users, Departments, Teams, Help Topics, SLA Plans, and Canned Responses. Create and close all 12 sample tickets.

## Tools
- Ubuntu Server 22.04 LTS (VirtualBox VM — 2 vCPU, 4 GB RAM, 40 GB disk)
- Apache2, PHP 8.1, MariaDB
- osTicket v1.18.x
- Web browser (from host or client VM)

## Diagram Description
```
[Browser Client]---HTTP/HTTPS--->[Ubuntu VM: 192.168.10.30]
                                        |
                              Apache2 + PHP 8.1
                                        |
                                    MariaDB
                                        |
                                 osTicket v1.18
```

## Build Steps

### 1. Prepare Ubuntu Server
```bash
sudo apt update && sudo apt upgrade -y
sudo hostnamectl set-hostname osticket-srv
```

Set static IP (edit `/etc/netplan/00-installer-config.yaml`):
```yaml
network:
  ethernets:
    enp0s3:
      dhcp4: no
      addresses: [192.168.10.30/24]
      routes:
        - to: default
          via: 192.168.10.1
      nameservers:
        addresses: [192.168.10.10, 8.8.8.8]
  version: 2
```
```bash
sudo netplan apply
```

### 2. Install LAMP Stack
```bash
sudo apt install apache2 mariadb-server php8.1 php8.1-{cli,gd,curl,intl,apcu,imap,xml,mbstring,mysql,zip} -y
sudo systemctl enable apache2 mariadb
```

### 3. Secure MariaDB
```bash
sudo mysql_secure_installation
# Set root password, remove anonymous users, disable remote root login, remove test database
```

Create the osTicket database:
```sql
sudo mysql -u root -p
CREATE DATABASE osticket_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'osticket_user'@'localhost' IDENTIFIED BY 'StrongP@ss123!';
GRANT ALL PRIVILEGES ON osticket_db.* TO 'osticket_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### 4. Install osTicket
```bash
cd /tmp
wget https://github.com/osTicket/osTicket/releases/download/v1.18.1/osTicket-v1.18.1.zip
sudo apt install unzip -y
unzip osTicket-v1.18.1.zip -d osticket
sudo cp -r osticket/upload/* /var/www/html/osticket/
sudo cp /var/www/html/osticket/include/ost-sampleconfig.php /var/www/html/osticket/include/ost-config.php
sudo chmod 0666 /var/www/html/osticket/include/ost-config.php
sudo chown -R www-data:www-data /var/www/html/osticket/
```

### 5. Configure Apache Virtual Host
```bash
sudo nano /etc/apache2/sites-available/osticket.conf
```
```apache
<VirtualHost *:80>
    ServerName osticket.corp.local
    DocumentRoot /var/www/html/osticket
    <Directory /var/www/html/osticket>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog ${APACHE_LOG_DIR}/osticket_error.log
    CustomLog ${APACHE_LOG_DIR}/osticket_access.log combined
</VirtualHost>
```
```bash
sudo a2ensite osticket.conf
sudo a2enmod rewrite
sudo systemctl restart apache2
```

### 6. Run Web Installer
1. Navigate to `http://192.168.10.30/osticket/setup/`.
2. Complete the form:
   - **Helpdesk Name:** Corp IT Help Desk
   - **Default Email:** helpdesk@corp.local
   - **Admin User:** `admin` / `P@ssword123!`
   - **Database:** `osticket_db`, user `osticket_user`, password `StrongP@ss123!`
3. Click **Install Now**.
4. After installation:
```bash
sudo rm -rf /var/www/html/osticket/setup/
sudo chmod 0644 /var/www/html/osticket/include/ost-config.php
```

### 7. Post-Install Configuration

**Admin Panel → Staff → Departments:**
- IT Support
- Network Operations
- HR / Facilities

**Admin Panel → Staff → Teams:**
- Tier 1 Support
- Tier 2 Escalation

**Admin Panel → Staff → Add Agents:**
| Agent | Department | Role |
|---|---|---|
| Alice Smith | IT Support | All Access |
| Bob Jones | Network Operations | Expanded Access |

**Admin Panel → Users → Add Users:**
| User | Email |
|---|---|
| Jane Doe | jane.doe@corp.local |
| Mark Lee | mark.lee@corp.local |

**Admin Panel → Manage → Help Topics:**
- Password Reset
- Hardware Issue
- Software Install
- Network Connectivity
- Printer Issue
- Account Lockout
- Slow Performance
- Other / General

**Admin Panel → Manage → SLA Plans:**
| Plan | Grace Period | Schedule |
|---|---|---|
| SEV-A (Critical) | 1 hour | 24/7 |
| SEV-B (High) | 4 hours | 24/7 |
| SEV-C (Normal) | 8 hours | Business hours |

**Admin Panel → Manage → Canned Responses:**
- **Ticket Received:** "Thank you for contacting IT Support. Your ticket #[ticket_id] has been received and will be addressed within [SLA time]. — IT Help Desk"
- **Awaiting User Info:** "We need additional information to proceed. Please reply with [details]. — IT Help Desk"
- **Issue Resolved:** "Your issue has been resolved. If you experience further problems, please open a new ticket. Thank you. — IT Help Desk"

### 8. Configure Cron Job for Email Fetch (Demo)
```bash
sudo crontab -u www-data -e
# Add:
*/5 * * * * php /var/www/html/osticket/api/cron.php
```

### 9. Create and Close All 12 Sample Tickets
See `/tickets/` folder for all 12 ticket Markdown files. Use the osTicket web UI to replicate each ticket:
1. Log in as a user and open a new ticket.
2. Fill in the Help Topic, Subject, and description.
3. Log in as an agent and respond with the canned response.
4. Work the ticket according to the ticket writeup.
5. Close the ticket and add close notes.

## Validation Steps
- [ ] osTicket web UI accessible at `http://192.168.10.30/osticket`
- [ ] Admin panel accessible at `http://192.168.10.30/osticket/scp`
- [ ] 3 departments created
- [ ] 2 teams created
- [ ] 2 agents created and can log in
- [ ] 2 users created and can submit tickets
- [ ] 8 help topics created
- [ ] 3 SLA plans created
- [ ] 3 canned responses created
- [ ] All 12 sample tickets created and closed

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| 500 error on install | PHP extension missing | `apt install php8.1-{intl,apcu,imap}` |
| DB connection failed | Wrong credentials | Verify MariaDB user/password |
| Permissions error | Wrong file ownership | `chown -R www-data:www-data /var/www/html/osticket` |
| Cron not running | Wrong user | Confirm `www-data` crontab; check PHP path |
| Email fetch fails | IMAP not configured | Lab uses cron fetch demo; no live mailbox required |
| Attachments blocked | PHP upload limit | Edit `php.ini`: `upload_max_filesize = 10M`, `post_max_size = 10M` |

## What You Learned
- Installing a LAMP stack on Ubuntu Server
- Configuring osTicket with departments, agents, SLA, and canned responses
- Creating and resolving help desk tickets end-to-end
- Setting up automated cron-based email fetch
- Troubleshooting common LAMP and osTicket issues

## Evidence Checklist
- [ ] Screenshot: osTicket installation success page
- [ ] Screenshot: Admin panel → Departments list
- [ ] Screenshot: SLA Plans configured
- [ ] Screenshot: Open tickets queue with sample tickets
- [ ] Screenshot: Ticket closed with resolution notes
