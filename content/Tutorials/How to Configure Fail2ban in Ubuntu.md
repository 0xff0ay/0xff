---
title: How to Configure Fail2ban in Ubuntu
description: Complete guide to installing, configuring, and hardening Fail2ban on Ubuntu with custom rules, firewall integration, database configuration, and password policies.
navigation:
  icon: i-lucide-shield
tags:
  - tutorial
---

## Overview

**Fail2ban** is an intrusion prevention software framework that protects Linux servers from brute-force attacks. It monitors log files for failed authentication attempts and automatically bans offending IP addresses by updating firewall rules.

> Fail2ban is one of the most effective first-line defenses against automated brute-force attacks on any Ubuntu server.

### How Fail2ban Works

::code-preview
---
class: "[&>div]:*:my-0"
---
Fail2ban attack prevention flow.

#code
```
Attack Flow Without Fail2ban:
┌──────────┐    SSH Brute Force     ┌──────────┐
│ Attacker │ ──── 1000 attempts ──► │  Server  │
└──────────┘                        └──────────┘

Attack Flow With Fail2ban:
┌──────────┐    5 failed attempts   ┌──────────┐
│ Attacker │ ──────────────────────►│ Fail2ban │
│          │                        │  Monitor │
│          │                        │  Logs    │
│          │                        └────┬─────┘
│          │     IP Banned               │
│          │ ◄───────────────────────────┘
│          │   iptables/ufw rule added
│          │   No more connections
└──────────┘
```
::

### Key Components

| Component        | Location                              | Purpose                              |
| ---------------- | ------------------------------------- | ------------------------------------ |
| `fail2ban.conf`  | `/etc/fail2ban/fail2ban.conf`         | Main configuration file              |
| `jail.conf`      | `/etc/fail2ban/jail.conf`             | Default jail definitions             |
| `jail.local`     | `/etc/fail2ban/jail.local`            | **Your custom overrides (use this)** |
| `filter.d/`      | `/etc/fail2ban/filter.d/`             | Filter rules (regex patterns)        |
| `action.d/`      | `/etc/fail2ban/action.d/`             | Ban/unban action definitions         |
| `jail.d/`        | `/etc/fail2ban/jail.d/`               | Individual jail config files         |
| Fail2ban DB      | `/var/lib/fail2ban/fail2ban.sqlite3`  | Ban history database                 |

---

## Installation

### Update System and Install

::code-preview
---
class: "[&>div]:*:my-0"
---
Install Fail2ban on Ubuntu.

#code
```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Install Fail2ban
sudo apt install fail2ban -y

# Verify installation
fail2ban-client --version

# Check service status
sudo systemctl status fail2ban

# Enable on boot
sudo systemctl enable fail2ban

# Start the service
sudo systemctl start fail2ban
```
::

### Verify Installation

::code-preview
---
class: "[&>div]:*:my-0"
---
Verify Fail2ban is running correctly.

#code
```bash
# Check if running
sudo systemctl is-active fail2ban

# Check Fail2ban version
fail2ban-client version

# Check active jails
sudo fail2ban-client status

# View all loaded jails
sudo fail2ban-client status | grep "Jail list"

# Check Fail2ban logs
sudo tail -f /var/log/fail2ban.log
```
::

---

## Basic Configuration

### Create jail.local (IMPORTANT)

::tip
Always create and edit `/etc/fail2ban/jail.local` instead of modifying `jail.conf` directly. The `jail.conf` file gets overwritten during package updates. Your `jail.local` settings always take priority.
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Create your custom configuration file.

#code
```bash
# Copy default config as your local config
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Or start fresh with a clean file
sudo nano /etc/fail2ban/jail.local

# Backup the original config
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.backup
```
::

### Global DEFAULT Section

::code-preview
---
class: "[&>div]:*:my-0"
---
Core global settings in jail.local.

#code
```ini
# /etc/fail2ban/jail.local

[DEFAULT]
# ============================================================
# BASIC SETTINGS
# ============================================================

# Ban duration (seconds) - 1 hour = 3600, 1 day = 86400
# -1 = permanent ban
bantime  = 3600

# Time window to count failures (seconds)
# 10 minutes = 600
findtime  = 600

# Number of failures before banning
maxretry = 5

# ============================================================
# BACKEND SETTINGS
# ============================================================

# Log monitoring backend
# auto     - Automatically select best available
# pyinotify - Fast, uses inotify (recommended for Linux)
# gamin    - Uses Gamin
# polling  - Uses polling (fallback)
# systemd  - Monitor systemd journal
backend = auto

# ============================================================
# IP WHITELIST (NEVER BAN THESE)
# ============================================================

# Space-separated list of trusted IPs/CIDRs
# 127.0.0.1 = localhost
# ::1       = IPv6 localhost
ignoreip = 127.0.0.1/8 ::1 192.168.1.0/24 10.0.0.0/8

# Use DNS to resolve hostnames in logs (warn = safer)
usedns = warn

# ============================================================
# BAN ACTION
# ============================================================

# Default ban action
# iptables-multiport = ban multiple ports at once
# iptables           = single port
# ufw                = Ubuntu UFW firewall
# iptables-allports  = ban all ports from offender
banaction = iptables-multiport

# Use iptables-allports to fully block an offending IP
# banaction = iptables-allports

# For UFW users (Ubuntu default firewall)
# banaction = ufw

# Action to perform on ban
# %(action_)s  = ban only
# %(action_mw)s = ban + send email with whois report
# %(action_mwl)s = ban + email + logs
action = %(action_)s

# ============================================================
# EMAIL NOTIFICATIONS (optional)
# ============================================================

# Set to your email for ban notifications
destemail = admin@yourdomain.com
sendername = Fail2ban Alert
mta = sendmail

# ============================================================
# LOGGING
# ============================================================

# Fail2ban log level
# CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG
loglevel = INFO

# Log file location
logtarget = /var/log/fail2ban.log

# Socket path
socket = /var/run/fail2ban/fail2ban.sock

# PID file path
pidfile = /var/run/fail2ban/fail2ban.pid

# ============================================================
# DATABASE
# ============================================================

# Fail2ban SQLite database for persistent bans
# File path to enable, "None" to disable
dbfile = /var/lib/fail2ban/fail2ban.sqlite3

# How long to keep ban records in database (seconds)
# 86400 = 1 day, 604800 = 7 days, -1 = forever
dbpurgeage = 86400

# Maximum number of matches stored in database per ticket
dbmaxmatches = 10
```
::

---

## Common Port Protection

### SSH Protection (Port 22)

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure SSH jail.

#code
```ini
# /etc/fail2ban/jail.local

[sshd]
# Enable this jail
enabled = true

# Port(s) to monitor
port    = ssh
# Or specify custom SSH port:
# port = 2222
# Or multiple ports:
# port = 22,2222

# Filter file to use
filter  = sshd

# Log file to monitor
logpath = %(sshd_log)s
# Explicit path:
# logpath = /var/log/auth.log        # Ubuntu/Debian
# logpath = /var/log/secure          # CentOS/RHEL

# Override global settings
bantime  = 7200       # 2 hours for SSH
findtime = 600        # 10 minutes window
maxretry = 3          # Only 3 attempts

# Use systemd backend (Ubuntu 20.04+)
backend = systemd
```
::

### Apache Web Server Protection

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Apache jails.

#code
```ini
# /etc/fail2ban/jail.local

# Apache - Brute Force
[apache-auth]
enabled  = true
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache2/error.log
maxretry = 5
bantime  = 3600
findtime = 600

# Apache - Bad Bots and Scrapers
[apache-badbots]
enabled  = true
port     = http,https
filter   = apache-badbots
logpath  = /var/log/apache2/access.log
maxretry = 2
bantime  = 86400

# Apache - DDoS Protection
[apache-limit-req]
enabled  = true
port     = http,https
filter   = apache-limit-req
logpath  = /var/log/apache2/error.log
maxretry = 3
bantime  = 7200

# Apache - Shellshock Attack Detection
[apache-shellshock]
enabled  = true
port     = http,https
filter   = apache-shellshock
logpath  = /var/log/apache2/error.log
maxretry = 1
bantime  = 86400

# Apache - Noscript Attack Detection
[apache-noscript]
enabled  = true
port     = http,https
filter   = apache-noscript
logpath  = /var/log/apache2/error.log
maxretry = 6
bantime  = 86400

# Apache - NoProxy Detection
[apache-noproxy]
enabled  = true
port     = http,https
filter   = apache-noproxy
logpath  = /var/log/apache2/access.log
maxretry = 2
bantime  = 7200
```
::

### Nginx Web Server Protection

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Nginx jails.

#code
```ini
# /etc/fail2ban/jail.local

# Nginx - HTTP Authentication
[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 3600
findtime = 600

# Nginx - Limit Requests (DDoS)
[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 10
bantime  = 3600

# Nginx - Bad Bots
[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = /var/log/nginx/access.log
maxretry = 2
bantime  = 86400

# Nginx - 4xx Errors (Scanning Detection)
[nginx-4xx]
enabled  = true
port     = http,https
filter   = nginx-4xx
logpath  = /var/log/nginx/access.log
maxretry = 30
bantime  = 3600
findtime = 600
```
::

### FTP Protection

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure FTP jails.

#code
```ini
# /etc/fail2ban/jail.local

# vsftpd
[vsftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = vsftpd
logpath  = /var/log/vsftpd.log
maxretry = 5
bantime  = 7200
findtime = 600

# ProFTPD
[proftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = proftpd
logpath  = /var/log/proftpd/proftpd.log
maxretry = 5
bantime  = 7200

# Pure-FTPd
[pure-ftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = pure-ftpd
logpath  = /var/log/syslog
maxretry = 5
bantime  = 7200
```
::

### Email Server Protection

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure email server jails.

#code
```ini
# /etc/fail2ban/jail.local

# Postfix SMTP
[postfix]
enabled  = true
port     = smtp,465,submission
filter   = postfix
logpath  = /var/log/mail.log
maxretry = 5
bantime  = 3600

# Postfix SASL Authentication
[postfix-sasl]
enabled  = true
port     = smtp,465,submission,imap,imaps,pop3,pop3s
filter   = postfix-sasl
logpath  = /var/log/mail.log
maxretry = 5
bantime  = 7200

# Dovecot (IMAP/POP3)
[dovecot]
enabled  = true
port     = pop3,pop3s,imap,imaps,submission,465,sieve
filter   = dovecot
logpath  = /var/log/mail.log
maxretry = 5
bantime  = 7200

# Courier Mail
[courier-smtp]
enabled  = true
port     = smtp,465,submission
filter   = couriersmtp
logpath  = /var/log/mail.log
maxretry = 5
bantime  = 3600
```
::

### DNS Server Protection

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure DNS server jails.

#code
```ini
# /etc/fail2ban/jail.local

# BIND9 DNS Server
[named-refused]
enabled  = true
port     = domain,953
filter   = named-refused
logpath  = /var/log/named/default
maxretry = 5
bantime  = 3600
```
::

---

## Database Protection

### MySQL / MariaDB

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure MySQL/MariaDB jail.

#code
```ini
# /etc/fail2ban/jail.local

[mysql-auth]
enabled  = true
port     = 3306
filter   = mysql-auth
logpath  = /var/log/mysql/error.log
maxretry = 5
bantime  = 7200
findtime = 600
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Create MySQL filter file.

#code
```bash
# Create custom MySQL filter
sudo nano /etc/fail2ban/filter.d/mysql-auth.conf
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
MySQL filter configuration.

#code
```ini
# /etc/fail2ban/filter.d/mysql-auth.conf

[Definition]

# Detect failed MySQL authentication attempts
failregex = ^%(__prefix_line)s\d{6}\s+\d+:\d+:\d+\s+\d+\s+Access denied for user '<F-USER>[^']+</F-USER>'@'<HOST>' \(using password: (YES|NO)\)$
            ^%(__prefix_line)sFailed \S+ for .* from <HOST>

ignoreregex =

[Init]
datepattern = %%Y%%m%%d %%H:%%M:%%S
```
::

### PostgreSQL

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure PostgreSQL jail.

#code
```ini
# /etc/fail2ban/jail.local

[postgresql]
enabled  = true
port     = 5432
filter   = postgresql
logpath  = /var/log/postgresql/postgresql-*.log
maxretry = 5
bantime  = 7200
findtime = 600
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Create PostgreSQL filter file.

#code
```bash
sudo nano /etc/fail2ban/filter.d/postgresql.conf
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
PostgreSQL filter configuration.

#code
```ini
# /etc/fail2ban/filter.d/postgresql.conf

[Definition]

# Detect failed PostgreSQL authentication
failregex = ^.*FATAL:\s+password authentication failed for user.*$
            ^.*FATAL:\s+no pg_hba.conf entry for host "<HOST>".*$
            ^.*FATAL:\s+role ".*" does not exist$
            ^.*FATAL:\s+database ".*" does not exist$
            ^.*FATAL:\s+connection rejected$

ignoreregex =
```
::

### MongoDB

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure MongoDB jail.

#code
```ini
# /etc/fail2ban/jail.local

[mongodb-auth]
enabled  = true
port     = 27017,27018,27019
filter   = mongodb-auth
logpath  = /var/log/mongodb/mongod.log
maxretry = 5
bantime  = 7200
findtime = 600
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Create MongoDB filter file.

#code
```bash
sudo nano /etc/fail2ban/filter.d/mongodb-auth.conf
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
MongoDB filter configuration.

#code
```ini
# /etc/fail2ban/filter.d/mongodb-auth.conf

[Definition]

# Detect failed MongoDB authentication
failregex = ^.*F\s+ACCESS.*Unauthorized.*client:<HOST>.*$
            ^.*SASL.*Authentication failed.*from client <HOST>.*$
            ^.* <HOST>:\d+ - (?:Message|Error).*authentication.*failed.*$

ignoreregex =
```
::

### Redis

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Redis jail.

#code
```ini
# /etc/fail2ban/jail.local

[redis-auth]
enabled  = true
port     = 6379,6380
filter   = redis-auth
logpath  = /var/log/redis/redis-server.log
maxretry = 5
bantime  = 7200
findtime = 600
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Create Redis filter file.

#code
```bash
sudo nano /etc/fail2ban/filter.d/redis-auth.conf
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Redis filter configuration.

#code
```ini
# /etc/fail2ban/filter.d/redis-auth.conf

[Definition]

# Detect failed Redis authentication attempts
failregex = ^.*\[.*\].*Client <HOST>.*-.*NOAUTH Authentication required.*$
            ^.*\[.*\].*ERR.*invalid password.*<HOST>.*$

ignoreregex =
```
::

### Elasticsearch

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Elasticsearch jail.

#code
```ini
# /etc/fail2ban/jail.local

[elasticsearch-auth]
enabled  = true
port     = 9200,9300
filter   = elasticsearch-auth
logpath  = /var/log/elasticsearch/*.log
maxretry = 5
bantime  = 7200
findtime = 600
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Elasticsearch filter configuration.

#code
```bash
sudo nano /etc/fail2ban/filter.d/elasticsearch-auth.conf
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Elasticsearch filter rules.

#code
```ini
# /etc/fail2ban/filter.d/elasticsearch-auth.conf

[Definition]

failregex = ^.*\[WARN\s*\].*\[authentication\].*authentication.*failed.*from\s+\[<HOST>\].*$
            ^.*security.*\[WARN\s*\].*authentication.*failed.*host=<HOST>.*$

ignoreregex =
```
::

---

## Custom Port Protection

### Custom Application Port

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure custom port jail.

#code
```ini
# /etc/fail2ban/jail.local

# Custom port jail example
[my-app-custom]
enabled  = true

# Specify custom port number(s)
port     = 8080
# Multiple ports:
# port     = 8080,8443,9000

# Use your custom filter
filter   = my-app-filter

# Custom log location
logpath  = /var/log/myapp/access.log

maxretry = 10
bantime  = 3600
findtime = 300
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Create a custom filter for your application.

#code
```bash
sudo nano /etc/fail2ban/filter.d/my-app-filter.conf
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Custom application filter configuration.

#code
```ini
# /etc/fail2ban/filter.d/my-app-filter.conf

[Definition]

# failregex matches patterns in your log file
# <HOST> is a Fail2ban placeholder for the IP address
failregex = ^.*\[ERROR\].*Failed login attempt from <HOST>.*$
            ^.*\[WARN\].*Invalid credentials.*ip=<HOST>.*$
            ^.*authentication failure.*from <HOST>.*$

# Patterns to ignore (won't trigger a ban)
ignoreregex = ^.*\[DEBUG\].*$
              ^.*healthcheck.*$

[Init]
# Optional: Custom date pattern
# datepattern = %%Y-%%m-%%d %%H:%%M:%%S
```
::

### Custom Port - Range of Ports

::code-preview
---
class: "[&>div]:*:my-0"
---
Protect multiple custom ports.

#code
```ini
# /etc/fail2ban/jail.local

[api-endpoints]
enabled  = true
port     = 3000,4000,5000,8080,8443
filter   = api-auth-filter
logpath  = /var/log/api/application.log
maxretry = 10
bantime  = 3600
findtime = 300

[microservices]
enabled  = true
port     = 8001:8010
# Ranges not directly supported, use comma-separated:
port     = 8001,8002,8003,8004,8005
filter   = microservice-filter
logpath  = /var/log/services/*.log
maxretry = 15
bantime  = 1800
```
::

### Custom SSH Port

::code-preview
---
class: "[&>div]:*:my-0"
---
Protect non-standard SSH port.

#code
```ini
# /etc/fail2ban/jail.local

# If you moved SSH to a different port
[sshd-custom]
enabled  = true
port     = 2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 86400
findtime = 600
backend  = systemd
```
::

---

## Firewall Integration

### Integration with UFW (Ubuntu Default)

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Fail2ban to use UFW.

#code
```bash
# First, ensure UFW is enabled
sudo ufw enable
sudo ufw status

# Enable SSH before applying UFW
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Fail2ban to use UFW banaction.

#code
```ini
# /etc/fail2ban/jail.local

[DEFAULT]
# Use UFW as the ban action
banaction = ufw

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
backend  = systemd
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Check the UFW action file.

#code
```bash
# View the UFW action file
cat /etc/fail2ban/action.d/ufw.conf

# Should contain:
# [Definition]
# actionstart =
# actionstop =
# actioncheck =
# actionban = ufw insert 1 deny from <ip> to any
# actionunban = ufw delete deny from <ip> to any
```
::

### Integration with iptables

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Fail2ban with iptables.

#code
```ini
# /etc/fail2ban/jail.local

[DEFAULT]
# iptables-multiport bans across multiple ports efficiently
banaction = iptables-multiport

# For complete IP block (all ports)
# banaction = iptables-allports

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
View iptables rules added by Fail2ban.

#code
```bash
# View iptables rules
sudo iptables -L -n -v

# View only Fail2ban chains
sudo iptables -L -n | grep -A 10 f2b

# View specific jail rules
sudo iptables -L f2b-sshd -n

# View with line numbers
sudo iptables -L -n --line-numbers

# View banned IPs in iptables
sudo iptables -L INPUT -n | grep DROP
sudo iptables -L f2b-sshd -n -v
```
::

### Integration with nftables (Modern)

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Fail2ban with nftables.

#code
```bash
# Install nftables
sudo apt install nftables -y
sudo systemctl enable nftables
sudo systemctl start nftables
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure nftables banaction.

#code
```ini
# /etc/fail2ban/jail.local

[DEFAULT]
# Use nftables for banning
banaction = nftables-multiport
banaction_allports = nftables-allports

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
```
::

### Firewall Action Comparison

| Action                   | Firewall    | Description                              |
| ------------------------ | ----------- | ---------------------------------------- |
| `ufw`                    | UFW         | Insert deny rule into UFW                |
| `iptables`               | iptables    | Ban single port                          |
| `iptables-multiport`     | iptables    | Ban multiple ports at once               |
| `iptables-allports`      | iptables    | Ban ALL ports for offending IP           |
| `iptables-ipset`         | iptables    | Use ipset for efficient banning          |
| `nftables-multiport`     | nftables    | Modern nftables multi-port ban           |
| `nftables-allports`      | nftables    | Modern nftables all-port ban             |
| `firewallcmd-multiport`  | firewalld   | CentOS/RHEL firewalld integration        |

---

## Password Policy Configuration

### PAM Authentication Failure Monitoring

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure PAM-based failure detection.

#code
```ini
# /etc/fail2ban/jail.local

# Monitor PAM authentication failures
# Covers su, sudo, login, and other PAM services
[pam-generic]
enabled  = true
filter   = pam-generic
banaction = iptables-multiport
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
findtime = 600

# Monitor sudo authentication failures
[sudo-auth]
enabled  = true
filter   = sudo
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
findtime = 600
port     = all
```
::

### Aggressive Ban Policy for Critical Services

::code-preview
---
class: "[&>div]:*:my-0"
---
Progressive ban escalation strategy.

#code
```ini
# /etc/fail2ban/jail.local

# Aggressive SSH jail - stricter settings
[sshd-aggressive]
enabled   = true
port      = ssh
filter    = sshd
logpath   = /var/log/auth.log
backend   = systemd

# Very strict settings
maxretry  = 2          # Only 2 attempts
findtime  = 60         # 1 minute window
bantime   = 86400      # 24 hour ban (very aggressive)

# recidive works on fail2ban's own log
# Re-ban IPs that were already banned multiple times
[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = %(action_mwl)s
bantime  = 604800       # 7 day ban for repeat offenders
findtime = 86400        # Within 24 hours
maxretry = 3            # If banned 3 times in 24h → 7 day ban
```
::

### Create Recidive Filter

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure the recidive filter.

#code
```bash
# Check if recidive filter already exists
cat /etc/fail2ban/filter.d/recidive.conf

# If it doesn't exist, create it
sudo nano /etc/fail2ban/filter.d/recidive.conf
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Recidive filter file content.

#code
```ini
# /etc/fail2ban/filter.d/recidive.conf

[Definition]

# Detect IPs that Fail2ban has already banned
failregex = ^(%(__prefix_line)s|\s+)Ban\s+<HOST>$

ignoreregex =

[Init]
# Match against Fail2ban log format
datepattern = ^%%Y-%%m-%%d %%H:%%M:%%S,%%f
```
::

### System Login Policy (Login Failure Monitoring)

::code-preview
---
class: "[&>div]:*:my-0"
---
Monitor system login failures.

#code
```ini
# /etc/fail2ban/jail.local

# Monitor failed su attempts
[su-auth]
enabled  = true
filter   = su
port     = all
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
findtime = 600

# Monitor failed sudo attempts
[sudo-auth]
enabled  = true
filter   = sudo
port     = all
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
findtime = 600

# Monitor cron authentication
[cron]
enabled  = true
filter   = cron
port     = all
logpath  = /var/log/syslog
maxretry = 5
bantime  = 3600

# Monitor TCP wrappers
[tcp-wrappers]
enabled  = true
filter   = sshd-ddos
port     = all
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 7200
findtime = 60
```
::

### Password Policy with fail2ban-client

::code-preview
---
class: "[&>div]:*:my-0"
---
Enforce account lockout via Fail2ban commands.

#code
```bash
# Manually ban an IP address
sudo fail2ban-client set sshd banip 192.168.1.100

# Manually unban an IP address
sudo fail2ban-client set sshd unbanip 192.168.1.100

# View current banned IPs for a jail
sudo fail2ban-client status sshd

# View all jails and their status
sudo fail2ban-client status

# Check if specific IP is banned
sudo fail2ban-client get sshd banned 192.168.1.100

# Get current maxretry setting
sudo fail2ban-client get sshd maxretry

# Change maxretry dynamically (without restart)
sudo fail2ban-client set sshd maxretry 3

# Change bantime dynamically
sudo fail2ban-client set sshd bantime 7200

# Get banned IP list
sudo fail2ban-client get sshd banned

# Flush all bans for a jail
sudo fail2ban-client set sshd unbanip $(sudo fail2ban-client get sshd banned | tr -d '[]' | tr ',' '\n')
```
::

---

## Complete Example Configuration

### Production-Ready jail.local

::code-preview
---
class: "[&>div]:*:my-0"
---
Complete production configuration file.

#code
```ini
# /etc/fail2ban/jail.local
# Production Fail2ban Configuration
# Last Updated: 2024
# ============================================================

[DEFAULT]
# ============================================================
# GLOBAL SETTINGS
# ============================================================

# Whitelist your trusted IPs - CRITICAL: Add your admin IP!
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

# Default ban duration: 1 hour
bantime  = 3600

# Detection window: 10 minutes
findtime = 600

# Failed attempts before ban: 5
maxretry = 5

# Backend: auto-detect best method
backend = auto

# DNS resolution: warn is safest
usedns = warn

# Firewall action (choose one below)
# For UFW (Ubuntu default)
banaction = ufw
# For iptables multi-port
# banaction = iptables-multiport
# For iptables all ports
# banaction = iptables-allports

# Email notifications (configure MTA first)
# destemail = admin@yourdomain.com
# sendername = Fail2ban Alert
# action = %(action_mwl)s

# ============================================================
# DATABASE SETTINGS
# ============================================================

dbfile          = /var/lib/fail2ban/fail2ban.sqlite3
dbpurgeage      = 604800    # Keep records 7 days
dbmaxmatches    = 10

# ============================================================
# LOGGING
# ============================================================

loglevel  = INFO
logtarget = /var/log/fail2ban.log

# ============================================================
# SSH PROTECTION
# ============================================================

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
backend  = systemd
maxretry = 3
bantime  = 7200       # 2 hours
findtime = 300        # 5 minutes

# ============================================================
# WEB SERVER PROTECTION
# ============================================================

[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 3600

[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 10
bantime  = 3600

[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = /var/log/nginx/access.log
maxretry = 2
bantime  = 86400

# Uncomment for Apache
# [apache-auth]
# enabled  = true
# port     = http,https
# filter   = apache-auth
# logpath  = /var/log/apache2/error.log
# maxretry = 5
# bantime  = 3600

# [apache-badbots]
# enabled  = true
# port     = http,https
# filter   = apache-badbots
# logpath  = /var/log/apache2/access.log
# maxretry = 2
# bantime  = 86400

# ============================================================
# MAIL SERVER PROTECTION
# ============================================================

[postfix]
enabled  = true
port     = smtp,465,submission
filter   = postfix
logpath  = /var/log/mail.log
maxretry = 5
bantime  = 3600

[postfix-sasl]
enabled  = true
port     = smtp,465,submission,imap,imaps,pop3,pop3s
filter   = postfix-sasl
logpath  = /var/log/mail.log
maxretry = 5
bantime  = 7200

[dovecot]
enabled  = true
port     = pop3,pop3s,imap,imaps,submission,465,sieve
filter   = dovecot
logpath  = /var/log/mail.log
maxretry = 5
bantime  = 7200

# ============================================================
# DATABASE PROTECTION
# ============================================================

[mysql-auth]
enabled  = true
port     = 3306
filter   = mysql-auth
logpath  = /var/log/mysql/error.log
maxretry = 5
bantime  = 7200

[postgresql]
enabled  = true
port     = 5432
filter   = postgresql
logpath  = /var/log/postgresql/postgresql-*.log
maxretry = 5
bantime  = 7200

[mongodb-auth]
enabled  = true
port     = 27017
filter   = mongodb-auth
logpath  = /var/log/mongodb/mongod.log
maxretry = 5
bantime  = 7200

[redis-auth]
enabled  = true
port     = 6379
filter   = redis-auth
logpath  = /var/log/redis/redis-server.log
maxretry = 5
bantime  = 7200

# ============================================================
# REPEAT OFFENDER PROTECTION
# ============================================================

[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
bantime  = 604800     # 7 day ban
findtime = 86400      # 24 hour detection window
maxretry = 3          # Banned 3 times → 7 day ban
action   = %(action_)s

# ============================================================
# PAM AUTHENTICATION
# ============================================================

[pam-generic]
enabled  = true
filter   = pam-generic
banaction = iptables-multiport
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600

# ============================================================
# FTP PROTECTION
# ============================================================

[vsftpd]
enabled  = true
port     = ftp,ftp-data,ftps,ftps-data
filter   = vsftpd
logpath  = /var/log/vsftpd.log
maxretry = 5
bantime  = 7200
```
::

---

## Fail2ban Management Commands

### Service Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage the Fail2ban service.

#code
```bash
# Start / Stop / Restart / Reload
sudo systemctl start fail2ban
sudo systemctl stop fail2ban
sudo systemctl restart fail2ban
sudo systemctl reload fail2ban

# Reload configuration without restart
sudo fail2ban-client reload

# Reload specific jail
sudo fail2ban-client reload sshd

# Check service status
sudo systemctl status fail2ban
sudo fail2ban-client ping

# Enable on boot
sudo systemctl enable fail2ban

# Disable on boot
sudo systemctl disable fail2ban
```
::

### Monitoring Commands

::code-preview
---
class: "[&>div]:*:my-0"
---
Monitor Fail2ban activity.

#code
```bash
# View all jails and status
sudo fail2ban-client status

# View specific jail status
sudo fail2ban-client status sshd
sudo fail2ban-client status nginx-http-auth
sudo fail2ban-client status mysql-auth

# Watch Fail2ban log in real-time
sudo tail -f /var/log/fail2ban.log

# View recent ban activity
sudo grep "Ban " /var/log/fail2ban.log

# Count total bans
sudo grep "Ban " /var/log/fail2ban.log | wc -l

# View most attacked IPs
sudo grep "Ban " /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -20

# View today's bans
sudo grep "Ban " /var/log/fail2ban.log | grep "$(date +%Y-%m-%d)"

# View banned IPs for all jails
sudo fail2ban-client get sshd banned
sudo fail2ban-client get nginx-http-auth banned

# Check Fail2ban log for errors
sudo grep -i "error" /var/log/fail2ban.log
```
::

### Ban Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage bans manually.

#code
```bash
# Ban an IP manually
sudo fail2ban-client set sshd banip 192.168.1.100
sudo fail2ban-client set nginx-http-auth banip 10.0.0.50

# Unban an IP
sudo fail2ban-client set sshd unbanip 192.168.1.100

# Unban all IPs in a jail
sudo fail2ban-client set sshd unbanip $(sudo fail2ban-client get sshd banned)

# Get currently banned IPs
sudo fail2ban-client get sshd banned

# Check if specific IP is banned
sudo fail2ban-client get sshd banned | grep "192.168.1.100"

# View banned IPs in iptables
sudo iptables -L f2b-sshd -n

# View banned IPs in UFW
sudo ufw status | grep -i deny
```
::

### Testing Your Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
Test filter rules and configuration.

#code
```bash
# Test a filter against a log file
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf

# Test filter with verbose output
sudo fail2ban-regex -v /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf

# Test a custom filter
sudo fail2ban-regex /var/log/myapp/app.log /etc/fail2ban/filter.d/my-app-filter.conf

# Test filter with specific log line
sudo fail2ban-regex "2024-01-01 12:00:00 Failed password for admin from 192.168.1.100 port 12345 ssh2" /etc/fail2ban/filter.d/sshd.conf

# Test systemd backend
sudo fail2ban-regex --journalmatch='_SYSTEMD_UNIT=sshd.service' /etc/fail2ban/filter.d/sshd.conf

# Check configuration syntax
sudo fail2ban-client --test

# Validate entire jail config
sudo fail2ban-client -d 2>&1 | head -50
```
::

---

## Fail2ban Database

### Database Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage the Fail2ban SQLite database.

#code
```bash
# Database location
ls -la /var/lib/fail2ban/fail2ban.sqlite3

# Connect to database
sudo sqlite3 /var/lib/fail2ban/fail2ban.sqlite3

# Inside SQLite shell:
# View all tables
.tables

# View schema
.schema

# View all bans
SELECT * FROM bans;

# View bans for specific jail
SELECT * FROM bans WHERE jail = 'sshd';

# View recent bans (last 24 hours)
SELECT * FROM bans
WHERE timeofban > (strftime('%s', 'now') - 86400);

# View most frequently banned IPs
SELECT ip, count(*) as ban_count, jail
FROM bans
GROUP BY ip, jail
ORDER BY ban_count DESC
LIMIT 20;

# View ban history for specific IP
SELECT * FROM bans WHERE ip = '192.168.1.100';

# Count total bans per jail
SELECT jail, count(*) as total_bans
FROM bans
GROUP BY jail
ORDER BY total_bans DESC;

# Delete old records
DELETE FROM bans
WHERE timeofban < (strftime('%s', 'now') - 604800);

# Exit
.quit
```
::

### Database Maintenance Script

::code-preview
---
class: "[&>div]:*:my-0"
---
Create a database maintenance script.

#code
```bash
sudo nano /usr/local/bin/fail2ban-db-maintenance.sh
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Database maintenance script content.

#code
```bash
#!/bin/bash
# /usr/local/bin/fail2ban-db-maintenance.sh
# Fail2ban Database Maintenance Script

DB="/var/lib/fail2ban/fail2ban.sqlite3"
LOG="/var/log/fail2ban-maintenance.log"
RETENTION_DAYS=30

echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting Fail2ban DB maintenance" >> $LOG

# Check database exists
if [ ! -f "$DB" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Database not found: $DB" >> $LOG
    exit 1
fi

# Get database size before
SIZE_BEFORE=$(du -sh "$DB" | cut -f1)

# Remove old records
DELETED=$(sqlite3 "$DB" "DELETE FROM bans WHERE timeofban < (strftime('%s', 'now') - $((RETENTION_DAYS * 86400))); SELECT changes();")

# Vacuum database to reclaim space
sqlite3 "$DB" "VACUUM;"

# Get database size after
SIZE_AFTER=$(du -sh "$DB" | cut -f1)

echo "$(date '+%Y-%m-%d %H:%M:%S') - Deleted $DELETED old records" >> $LOG
echo "$(date '+%Y-%m-%d %H:%M:%S') - DB size: $SIZE_BEFORE → $SIZE_AFTER" >> $LOG

# Print ban statistics
echo "$(date '+%Y-%m-%d %H:%M:%S') - === Ban Statistics ===" >> $LOG
sqlite3 "$DB" "SELECT jail, count(*) as bans FROM bans GROUP BY jail ORDER BY bans DESC;" >> $LOG

echo "$(date '+%Y-%m-%d %H:%M:%S') - Maintenance complete" >> $LOG
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Make the script executable and schedule it.

#code
```bash
# Make script executable
sudo chmod +x /usr/local/bin/fail2ban-db-maintenance.sh

# Add to crontab (run weekly)
sudo crontab -e

# Add this line to run every Sunday at 2 AM
0 2 * * 0 /usr/local/bin/fail2ban-db-maintenance.sh

# Run manually
sudo /usr/local/bin/fail2ban-db-maintenance.sh

# View maintenance log
cat /var/log/fail2ban-maintenance.log
```
::

### Database Configuration in jail.local

::code-preview
---
class: "[&>div]:*:my-0"
---
Database-related configuration options.

#code
```ini
# /etc/fail2ban/jail.local

[DEFAULT]
# ============================================================
# DATABASE CONFIGURATION
# ============================================================

# Path to SQLite database
# Use "None" to disable database (not recommended)
dbfile = /var/lib/fail2ban/fail2ban.sqlite3

# How long to keep records in the database
# This determines "memory" of past bans
# 86400   = 1 day
# 604800  = 7 days
# 2592000 = 30 days
# -1      = Forever (not recommended, database grows indefinitely)
dbpurgeage = 604800

# Maximum number of match entries to store per ticket
# Higher values = more memory/disk usage but better forensics
dbmaxmatches = 10
```
::

---

## Advanced Configuration

### Action with Email Notification

::code-preview
---
class: "[&>div]:*:my-0"
---
Setup email notifications for bans.

#code
```bash
# Install sendmail or postfix first
sudo apt install sendmail -y
# OR
sudo apt install postfix -y
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure email notifications in jail.local.

#code
```ini
# /etc/fail2ban/jail.local

[DEFAULT]
# Email settings
destemail = admin@yourdomain.com
sendername = Fail2ban on %(hostname)s
mta = sendmail

# Action levels:
# %(action_)s   = ban only (no email)
# %(action_mw)s = ban + email with whois info
# %(action_mwl)s = ban + email + relevant log lines
action = %(action_mwl)s

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
# Override action for SSH specifically
action = %(action_mwl)s
```
::

### IPv6 Support

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure Fail2ban for IPv6.

#code
```ini
# /etc/fail2ban/jail.local

[DEFAULT]
# Whitelist IPv6 localhost
ignoreip = 127.0.0.1/8 ::1

# For IPv6 ban support, use ip6tables
banaction     = iptables-multiport
banaction6    = ip6tables-multiport

[sshd]
enabled  = true
port     = ssh
filter   = sshd
# Monitor both IPv4 and IPv6
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
```
::

### Geolocation-Based Banning

::code-preview
---
class: "[&>div]:*:my-0"
---
Create custom action for geo-based banning.

#code
```bash
# Install geoip tools
sudo apt install geoip-bin -y

# Create geolocation action
sudo nano /etc/fail2ban/action.d/geoblock.conf
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Geo-blocking action configuration.

#code
```ini
# /etc/fail2ban/action.d/geoblock.conf

[Definition]

# Ban action with geolocation logging
actionban = geoiplookup <ip> | logger -t fail2ban-geo;
            iptables -I f2b-<name> 1 -s <ip> -j DROP

actionunban = iptables -D f2b-<name> -s <ip> -j DROP

actionstart = iptables -N f2b-<name>
              iptables -A INPUT -j f2b-<name>

actionstop = iptables -D INPUT -j f2b-<name>
             iptables -F f2b-<name>
             iptables -X f2b-<name>
```
::

---

## Monitoring and Reporting

### Real-Time Monitoring Script

::code-preview
---
class: "[&>div]:*:my-0"
---
Create a monitoring dashboard script.

#code
```bash
sudo nano /usr/local/bin/fail2ban-monitor.sh
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Monitoring script content.

#code
```bash
#!/bin/bash
# /usr/local/bin/fail2ban-monitor.sh
# Fail2ban Live Monitor

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

clear
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║        Fail2ban Security Monitor         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# Service status
STATUS=$(systemctl is-active fail2ban)
if [ "$STATUS" = "active" ]; then
    echo -e "Service Status: ${GREEN}● ACTIVE${NC}"
else
    echo -e "Service Status: ${RED}● INACTIVE${NC}"
fi

echo ""

# List all jails and their stats
echo -e "${YELLOW}═══ Active Jails ═══${NC}"
jails=$(fail2ban-client status | grep "Jail list" | sed -E 's/.*Jail list:\s+//' | sed 's/,//g')

for jail in $jails; do
    info=$(fail2ban-client status $jail 2>/dev/null)
    currently_failed=$(echo "$info" | grep "Currently failed" | awk '{print $NF}')
    total_failed=$(echo "$info" | grep "Total failed" | awk '{print $NF}')
    currently_banned=$(echo "$info" | grep "Currently banned" | awk '{print $NF}')
    total_banned=$(echo "$info" | grep "Total banned" | awk '{print $NF}')

    if [ "$currently_banned" -gt "0" ] 2>/dev/null; then
        echo -e "  ${RED}[$jail]${NC}"
    else
        echo -e "  ${GREEN}[$jail]${NC}"
    fi
    echo -e "    Failed: ${RED}$currently_failed${NC} now / $total_failed total"
    echo -e "    Banned: ${RED}$currently_banned${NC} now / $total_banned total"
    echo ""
done

# Recent bans
echo -e "${YELLOW}═══ Recent Bans (Last 10) ═══${NC}"
grep "Ban " /var/log/fail2ban.log | tail -10 | while read line; do
    echo -e "  ${RED}$line${NC}"
done

echo ""

# Top attacked IPs
echo -e "${YELLOW}═══ Top Offenders ═══${NC}"
grep "Ban " /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10 | while read count ip; do
    echo -e "  ${RED}$ip${NC} - Banned ${YELLOW}$count${NC} times"
done

echo ""
echo -e "${CYAN}Last updated: $(date)${NC}"
```
::

::code-preview
---
class: "[&>div]:*:my-0"
---
Run the monitoring script.

#code
```bash
# Make executable
sudo chmod +x /usr/local/bin/fail2ban-monitor.sh

# Run the monitor
sudo /usr/local/bin/fail2ban-monitor.sh

# Run every 30 seconds (live dashboard)
watch -n 30 sudo /usr/local/bin/fail2ban-monitor.sh
```
::

---

## Troubleshooting

### Common Issues and Solutions

::code-preview
---
class: "[&>div]:*:my-0"
---
Diagnose Fail2ban issues.

#code
```bash
# Issue 1: Fail2ban not starting
# Check the error
sudo systemctl status fail2ban -l
sudo journalctl -u fail2ban -n 50

# Issue 2: Config file syntax error
# Test configuration
sudo fail2ban-client --test
sudo fail2ban-server --test

# Issue 3: Jail not working
# Test your filter against log
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf -v

# Issue 4: IP not being banned
# Check if IP is whitelisted
sudo fail2ban-client get sshd ignoreip
cat /etc/fail2ban/jail.local | grep ignoreip

# Check filter is matching
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf

# Issue 5: Database issues
# Check database
sudo sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "SELECT count(*) FROM bans;"

# Repair database
sudo systemctl stop fail2ban
sudo sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "VACUUM;"
sudo systemctl start fail2ban

# Issue 6: Firewall rules not applied
# Check iptables
sudo iptables -L -n | grep f2b
# Check UFW
sudo ufw status verbose

# Issue 7: View Fail2ban debug log
sudo fail2ban-client set loglevel DEBUG
sudo tail -f /var/log/fail2ban.log
# Reset to normal
sudo fail2ban-client set loglevel INFO
```
::

### Log Analysis Commands

::code-preview
---
class: "[&>div]:*:my-0"
---
Analyze Fail2ban logs.

#code
```bash
# Count bans per jail
grep "Ban " /var/log/fail2ban.log | awk '{print $6}' | sort | uniq -c | sort -rn

# Count bans per day
grep "Ban " /var/log/fail2ban.log | awk '{print $1}' | sort | uniq -c

# Top 10 most banned IPs
grep "Ban " /var/log/fail2ban.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10

# View all actions (ban/unban) for a specific IP
grep "192.168.1.100" /var/log/fail2ban.log

# Count total bans today
grep "$(date +%Y-%m-%d)" /var/log/fail2ban.log | grep "Ban " | wc -l

# View failed attempts before ban
grep "Found" /var/log/fail2ban.log | tail -20

# Check for configuration reload events
grep "reload\|Reload" /var/log/fail2ban.log

# Count errors in log
grep -c "ERROR" /var/log/fail2ban.log

# View warning messages
grep "WARNING" /var/log/fail2ban.log | tail -20
```
::

---

## Complete Common Ports Reference

| Service                | Port(s)                         | Jail Name              | Log File                              |
| ---------------------- | -------------------------------- | ---------------------- | ------------------------------------- |
| SSH                    | 22 (or custom)                   | `sshd`                 | `/var/log/auth.log`                   |
| HTTP                   | 80                               | `nginx-http-auth`      | `/var/log/nginx/error.log`            |
| HTTPS                  | 443                              | `nginx-http-auth`      | `/var/log/nginx/error.log`            |
| FTP                    | 21                               | `vsftpd`               | `/var/log/vsftpd.log`                 |
| FTPS                   | 990                              | `vsftpd`               | `/var/log/vsftpd.log`                 |
| SMTP                   | 25                               | `postfix`              | `/var/log/mail.log`                   |
| SMTP Submission        | 587                              | `postfix`              | `/var/log/mail.log`                   |
| SMTPS                  | 465                              | `postfix`              | `/var/log/mail.log`                   |
| POP3                   | 110                              | `dovecot`              | `/var/log/mail.log`                   |
| POP3S                  | 995                              | `dovecot`              | `/var/log/mail.log`                   |
| IMAP                   | 143                              | `dovecot`              | `/var/log/mail.log`                   |
| IMAPS                  | 993                              | `dovecot`              | `/var/log/mail.log`                   |
| MySQL / MariaDB        | 3306                             | `mysql-auth`           | `/var/log/mysql/error.log`            |
| PostgreSQL             | 5432                             | `postgresql`           | `/var/log/postgresql/*.log`           |
| MongoDB                | 27017                            | `mongodb-auth`         | `/var/log/mongodb/mongod.log`         |
| Redis                  | 6379                             | `redis-auth`           | `/var/log/redis/redis-server.log`     |
| Elasticsearch          | 9200                             | `elasticsearch-auth`   | `/var/log/elasticsearch/*.log`        |
| DNS                    | 53                               | `named-refused`        | `/var/log/named/default`              |
| RDP                    | 3389                             | `rdp`                  | `/var/log/auth.log`                   |
| VNC                    | 5900-5909                        | custom                 | `/var/log/syslog`                     |
| SIP / VoIP             | 5060                             | `asterisk`             | `/var/log/asterisk/full`              |

---

## Quick Commands Cheatsheet

::code-preview
---
class: "[&>div]:*:my-0"
---
Essential Fail2ban commands at a glance.

#code
```bash
# ============ SERVICE CONTROL ============
sudo systemctl start fail2ban           # Start
sudo systemctl stop fail2ban            # Stop
sudo systemctl restart fail2ban         # Restart
sudo fail2ban-client reload             # Reload config

# ============ STATUS ============
sudo fail2ban-client status             # All jails
sudo fail2ban-client status sshd        # Specific jail
sudo fail2ban-client ping               # Test connection

# ============ BAN MANAGEMENT ============
sudo fail2ban-client set sshd banip <IP>         # Ban IP
sudo fail2ban-client set sshd unbanip <IP>       # Unban IP
sudo fail2ban-client get sshd banned             # List banned
sudo fail2ban-client get sshd ignoreip           # List whitelisted

# ============ TESTING ============
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf    # Test filter
sudo fail2ban-client --test                                                  # Syntax check

# ============ LOGGING ============
sudo tail -f /var/log/fail2ban.log              # Live log
sudo grep "Ban " /var/log/fail2ban.log          # All bans
sudo grep "Ban " /var/log/fail2ban.log | wc -l  # Count bans

# ============ FIREWALL ============
sudo iptables -L f2b-sshd -n            # View iptables bans
sudo ufw status                         # View UFW rules

# ============ DATABASE ============
sudo sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "SELECT * FROM bans ORDER BY timeofban DESC LIMIT 10;"
```
::

---

## References

- [Fail2ban Official Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [Fail2ban GitHub Repository](https://github.com/fail2ban/fail2ban)
- [Ubuntu Security Documentation](https://ubuntu.com/server/docs/security-fail2ban)
- [Fail2ban Wiki - Configuration](https://www.fail2ban.org/wiki/index.php/MANUAL_0_8)
- [DigitalOcean - How To Protect SSH with Fail2Ban](https://www.digitalocean.com/community/tutorials/how-to-protect-ssh-with-fail2ban-on-ubuntu-20-04)
- [Ubuntu Community Help - Fail2ban](https://help.ubuntu.com/community/Fail2ban)

::tip
**Remember:** Always add your own IP to `ignoreip` before enabling Fail2ban. A misconfigured rule could lock you out of your own server. Test all filters with `fail2ban-regex` before applying them in production.
::
