---
title: How to Protect Your VM Instance
description: A step-by-step tutorial to secure and protect your Virtual Machine on the 1CNG Portal — covering firewall rules, SSH hardening, snapshots, network isolation, and more.
navigation:
  icon: i-lucide-shield-check
  title: Protect Your VM
---

Deploying a VM is only the beginning. Without proper hardening, your instance is exposed to brute-force attacks, unauthorized access, and data loss. This guide walks you through every layer of protection available on the [1CNG Portal](https://docs.1cloudng.com/docs/).

::note
This tutorial assumes you already have a running VM instance. If not, follow the [Getting Started guide](https://docs.1cloudng.com/docs/) to create one first.
::

## Prerequisites

Before you begin, make sure you have the following ready:

::field-group
  ::field{name="1CNG Account" type="required"}
  An active account on the [1CNG Portal](https://docs.1cloudng.com/docs/) with access to at least one project.
  ::

  ::field{name="VM Instance" type="required"}
  A running Virtual Machine instance you want to protect.
  ::

  ::field{name="SSH Client" type="recommended"}
  A terminal or SSH client (e.g. OpenSSH, PuTTY) for remote access configuration.
  ::

  ::field{name="Basic Linux Knowledge" type="recommended"}
  Familiarity with Linux commands for OS-level hardening steps.
  ::
::

## Security Overview

Understanding the layers of protection available helps you build a defense-in-depth strategy.

::card-group
  ::card
  ---
  title: Network Security
  icon: i-lucide-network
  ---
  Firewall rules, security groups, and private networking to control traffic flow.
  ::

  ::card
  ---
  title: Access Control
  icon: i-lucide-key-round
  ---
  SSH key authentication, password policies, and role-based access on the portal.
  ::

  ::card
  ---
  title: Data Protection
  icon: i-lucide-database-backup
  ---
  Automated snapshots, backups, and disaster recovery strategies.
  ::

  ::card
  ---
  title: Monitoring & Response
  icon: i-lucide-activity
  ---
  Real-time alerts, logging, and incident response procedures.
  ::
::

## Step-by-Step Hardening

::steps{level="3"}

### Configure Firewall Rules

Firewall rules are your first line of defense. By default, the 1CNG Portal allows you to define inbound and outbound rules per instance.

::warning
Never leave all ports open. A common mistake is allowing `0.0.0.0/0` on all ports — this exposes your VM to the entire internet.
::

1. Navigate to **Compute** → **Instances** in the [1CNG Portal](https://docs.1cloudng.com/docs/)
2. Select your VM instance
3. Go to the **Firewall** or **Security Groups** tab
4. Create rules following the principle of least privilege

**Recommended baseline rules:**

| Direction | Protocol | Port Range | Source          | Purpose              |
| --------- | -------- | ---------- | --------------- | -------------------- |
| Inbound   | TCP      | `22`       | Your IP only    | SSH access           |
| Inbound   | TCP      | `443`      | `0.0.0.0/0`    | HTTPS traffic        |
| Inbound   | TCP      | `80`       | `0.0.0.0/0`    | HTTP traffic         |
| Outbound  | All      | All        | `0.0.0.0/0`    | Allow all outbound   |
| Inbound   | All      | All        | `0.0.0.0/0`    | :icon{name="i-lucide-x"} **Deny** |

::tip{to="https://docs.1cloudng.com/docs/"}
See the official 1CNG documentation for the full firewall rules API and advanced configuration options.
::

### Set Up SSH Key Authentication

Password-based SSH login is vulnerable to brute-force attacks. Switch to key-based authentication immediately.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Generate Key"}
  ```bash [Terminal]
  ssh-keygen -t ed25519 -C "your-email@example.com"
  ```

  This creates a key pair at `~/.ssh/id_ed25519` (private) and `~/.ssh/id_ed25519.pub` (public).
  :::

  :::tabs-item{icon="i-lucide-upload" label="Add to 1CNG Portal"}
  1. Go to **Settings** → **SSH Keys** in the [1CNG Portal](https://docs.1cloudng.com/docs/)
  2. Click **Add SSH Key**
  3. Paste the contents of your public key

  ```bash [Terminal]
  cat ~/.ssh/id_ed25519.pub
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="Apply to VM"}
  If your VM is already running, copy the key manually:

  ```bash [Terminal]
  ssh-copy-id -i ~/.ssh/id_ed25519.pub user@your-vm-ip
  ```
  :::
::

### Disable Password Authentication

Once SSH keys are configured, disable password login entirely.

```bash [/etc/ssh/sshd_config]
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
```

Restart the SSH service to apply changes:

::code-group
  ```bash [systemd]
  sudo systemctl restart sshd
  ```

  ```bash [service]
  sudo service sshd restart
  ```
::

::caution
Before closing your current SSH session, open a **new terminal** and verify you can log in with your key. Locking yourself out requires console access through the 1CNG Portal.
::

### Change the Default SSH Port

Moving SSH off port `22` reduces automated scan noise significantly.

```bash [/etc/ssh/sshd_config]
Port 2222
```

::warning
Remember to update your firewall rules in the [1CNG Portal](https://docs.1cloudng.com/docs/) to allow the new port **before** restarting SSH.
::

| Action                          | Status |
| ------------------------------- | ------ |
| Add firewall rule for port 2222 | Do first |
| Restart SSH service             | Do second |
| Remove firewall rule for port 22| Do last |

### Enable Automatic Security Updates

Keep your VM patched against known vulnerabilities.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Ubuntu / Debian"}
  ```bash [Terminal]
  sudo apt update && sudo apt install unattended-upgrades -y
  sudo dpkg-reconfigure -plow unattended-upgrades
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="CentOS / RHEL"}
  ```bash [Terminal]
  sudo yum install dnf-automatic -y
  sudo systemctl enable --now dnf-automatic-install.timer
  ```
  :::
::

### Set Up Fail2Ban

Fail2Ban monitors log files and bans IPs that show malicious signs like too many password failures.

```bash [Terminal]
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
```

Create a local configuration:

```ini [/etc/fail2ban/jail.local]
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port    = 2222
logpath = %(sshd_log)s
backend = %(sshd_backend)s
```

```bash [Terminal]
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

### Configure Private Networking

Isolate backend services using private networks available in the 1CNG Portal.

1. Navigate to **Networking** → **Private Networks** in the [1CNG Portal](https://docs.1cloudng.com/docs/)
2. Create a new private network
3. Attach your VM instances that need internal communication
4. Update application configurations to use private IPs

::tip
Database servers, cache layers, and internal APIs should **never** have public IP addresses. Use private networking to keep them isolated.
::

```text [Network Architecture]
┌─────────────────────────────────────────┐
│              Public Internet            │
└──────────────┬──────────────────────────┘
               │ :443, :80
        ┌──────▼──────┐
        │  Web Server │  ← Public IP
        │  (Frontend) │
        └──────┬──────┘
               │ Private Network (10.0.0.0/24)
        ┌──────▼──────┐    ┌──────────────┐
        │  App Server │────│   Database   │
        │  10.0.0.2   │    │   10.0.0.3   │
        └─────────────┘    └──────────────┘
                            ← No Public IP
```

### Create Regular Snapshots

Snapshots let you restore your VM to a known good state in case of compromise or failure.

1. Go to **Compute** → **Instances** in the [1CNG Portal](https://docs.1cloudng.com/docs/)
2. Select your instance
3. Navigate to the **Snapshots** tab
4. Click **Create Snapshot**
5. Set up a schedule for automated snapshots

::note
It is recommended to create snapshots **before** making any major configuration changes and on a regular schedule (daily or weekly depending on your workload).
::

| Snapshot Strategy    | Frequency | Retention | Use Case               |
| -------------------- | --------- | --------- | ---------------------- |
| Pre-change           | As needed | 7 days    | Before updates/changes |
| Daily automated      | Daily     | 7 days    | Production workloads   |
| Weekly automated     | Weekly    | 30 days   | Staging environments   |

### Configure UFW (Host-Level Firewall)

Add a second layer of firewall protection at the OS level, in addition to the 1CNG Portal firewall.

```bash [Terminal]
# Reset and set defaults
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow your SSH port
sudo ufw allow 2222/tcp comment 'SSH'

# Allow web traffic
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow 80/tcp comment 'HTTP'

# Enable the firewall
sudo ufw enable

# Verify status
sudo ufw status verbose
```

::code-collapse
```bash [Expected Output]
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
2222/tcp                   ALLOW IN    Anywhere          # SSH
443/tcp                    ALLOW IN    Anywhere          # HTTPS
80/tcp                     ALLOW IN    Anywhere          # HTTP
2222/tcp (v6)              ALLOW IN    Anywhere (v6)     # SSH
443/tcp (v6)               ALLOW IN    Anywhere (v6)     # HTTPS
80/tcp (v6)                ALLOW IN    Anywhere (v6)     # HTTP
```
::

### Enable Monitoring and Alerts

Use the 1CNG Portal monitoring tools to detect unusual activity.

1. Navigate to **Monitoring** in the [1CNG Portal](https://docs.1cloudng.com/docs/)
2. Enable metrics collection for your VM
3. Set up alert thresholds

**Recommended alert thresholds:**


  ::field{name="CPU Usage" type="threshold"}
  Alert when CPU exceeds **90%** for more than 5 minutes — may indicate a crypto-mining attack or DDoS.
  ::

  ::field{name="Network Inbound" type="threshold"}
  Alert on unusual spikes in inbound traffic — potential DDoS or scanning activity.
  ::

  ::field{name="Disk I/O" type="threshold"}
  Alert when disk I/O is abnormally high — may indicate ransomware or unauthorized data extraction.
  ::

  ::field{name="SSH Login Failures" type="log-based"}
  Monitor `/var/log/auth.log` for repeated failed login attempts.
  ::
::


## Security Checklist

Use this checklist to verify you have completed all hardening steps.

| Step | Task                                    | Status |
| ---- | --------------------------------------- | ------ |
| 1    | Firewall rules configured (portal)      | :icon{name="i-lucide-square"} |
| 2    | SSH key authentication enabled          | :icon{name="i-lucide-square"} |
| 3    | Password authentication disabled        | :icon{name="i-lucide-square"} |
| 4    | Default SSH port changed                | :icon{name="i-lucide-square"} |
| 5    | Automatic security updates enabled      | :icon{name="i-lucide-square"} |
| 6    | Fail2Ban installed and configured       | :icon{name="i-lucide-square"} |
| 7    | Private networking for backend services | :icon{name="i-lucide-square"} |
| 8    | Snapshot schedule configured            | :icon{name="i-lucide-square"} |
| 9    | UFW host-level firewall enabled         | :icon{name="i-lucide-square"} |
| 10   | Monitoring and alerts configured        | :icon{name="i-lucide-square"} |

## Quick Commands Reference

::code-group
  ```bash [Check Open Ports]
  sudo ss -tulnp
  ```

  ```bash [View Failed SSH Logins]
  sudo grep "Failed password" /var/log/auth.log | tail -20
  ```

  ```bash [Check Active Connections]
  sudo netstat -an | grep ESTABLISHED
  ```

  ```bash [View Fail2Ban Status]
  sudo fail2ban-client status sshd
  ```

  ```bash [Check UFW Status]
  sudo ufw status numbered
  ```
::

## Additional Resources

::card-group
  ::card
  ---
  title: 1CNG Official Documentation
  icon: i-lucide-book-open
  to: https://docs.1cloudng.com/docs/
  target: _blank
  ---
  Complete reference for all 1CNG Portal features, APIs, and services.
  ::

  ::card
  ---
  title: Networking Guide
  icon: i-lucide-globe
  to: https://docs.1cloudng.com/docs/
  target: _blank
  ---
  Learn about VPC, private networks, floating IPs, and load balancers.
  ::

  ::card
  ---
  title: Backup & Recovery
  icon: i-lucide-hard-drive-download
  to: https://docs.1cloudng.com/docs/
  target: _blank
  ---
  Set up automated backups, snapshots, and disaster recovery plans.
  ::

  ::card
  ---
  title: Account Security
  icon: i-lucide-lock
  to: https://docs.1cloudng.com/docs/
  target: _blank
  ---
  Enable two-factor authentication and manage API tokens securely.
  ::
::

::tip
Security is not a one-time task. Schedule regular reviews of your firewall rules, user access, and system logs. Revisit this guide monthly to ensure your VM remains hardened against evolving threats.
::