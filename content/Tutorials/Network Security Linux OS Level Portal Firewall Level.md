---
title: Network Security — Linux OS & Portal Firewall
description: Complete network security hardening guide covering Linux OS-level security (SSH, users, filesystem, kernel, firewall, fail2ban, SELinux, auditd, services) and portal firewall-level security (WAF, DDoS, geo-blocking, API security, CDN, security headers, logging).
navigation:
  icon: i-lucide-shield
  title: Network Security
---

## Architecture Overview

```text [Network Security Defense-in-Depth Architecture]

  ┌─────────────────────────────────────────────────────────────────────┐
  │                         INTERNET                                    │
  │                     👤 Users / 🤖 Bots / 💀 Attackers               │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────────────┐
  │  LAYER 1: CDN / Edge Protection                                     │
  │  ┌──────────────────────────────────────────────────────────────┐   │
  │  │  🌐 CloudFlare / AWS CloudFront / Akamai                     │   │
  │  │  • DDoS absorption        • Geo-blocking                    │   │
  │  │  • Bot mitigation          • Edge WAF                        │   │
  │  │  • SSL termination         • Rate limiting                   │   │
  │  └──────────────────────────────────────────────────────────────┘   │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────────────┐
  │  LAYER 2: Portal Firewall / WAF                                     │
  │  ┌──────────────────────────────────────────────────────────────┐   │
  │  │  🛡️ ModSecurity + OWASP CRS / Nginx WAF                     │   │
  │  │  • SQL injection blocking  • XSS prevention                 │   │
  │  │  • Path traversal block    • Security headers               │   │
  │  │  • API gateway security    • HTTP protocol validation       │   │
  │  └──────────────────────────────────────────────────────────────┘   │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────────────┐
  │  LAYER 3: Network Firewall                                          │
  │  ┌──────────────────────────────────────────────────────────────┐   │
  │  │  🔥 iptables / nftables / ufw                                │   │
  │  │  • Default deny all        • Stateful inspection            │   │
  │  │  • Port whitelisting       • Rate limiting                  │   │
  │  │  • Connection tracking     • Logging                        │   │
  │  └──────────────────────────────────────────────────────────────┘   │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────────────┐
  │  LAYER 4: Host Security                                             │
  │  ┌──────────────────────────────────────────────────────────────┐   │
  │  │  🐧 Linux OS Hardening                                       │   │
  │  │  • SSH hardened (keys, no root, custom port)                │   │
  │  │  • Fail2ban active          • SELinux/AppArmor enforcing    │   │
  │  │  • Kernel hardened (sysctl) • auditd monitoring             │   │
  │  │  • Minimal services         • File permissions locked       │   │
  │  │  • User RBAC (sudo)         • 2FA on SSH                   │   │
  │  └──────────────────────────────────────────────────────────────┘   │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────────────┐
  │  LAYER 5: Application & Data                                        │
  │  ┌──────────────────────────────────────────────────────────────┐   │
  │  │  💾 Application + Database                                    │   │
  │  │  • Parameterized queries    • Encryption at rest            │   │
  │  │  • Input validation         • TLS connections               │   │
  │  │  • Least privilege DB users • Audit logging                 │   │
  │  └──────────────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────────────┘
```

---

# Part 1 — Linux OS Level Security

---

## 1 — SSH Hardening

### Key-Based Authentication

::note
SSH key authentication is **exponentially more secure** than password authentication. A 256-bit Ed25519 key has more entropy than any human-memorable password, and it cannot be brute-forced over the network.
::

::steps{level="4"}

#### Generate SSH key pairs

```bash [Ed25519 — Recommended (fastest, most secure)]
ssh-keygen -t ed25519 -a 100 -C "admin@company.com" -f ~/.ssh/id_ed25519
# -t ed25519   : Algorithm (preferred — 256-bit, fastest, smallest key)
# -a 100       : KDF rounds (higher = more brute-force resistant)
# -C "comment" : Label for identification
# -f path      : Output file

# Enter a STRONG passphrase when prompted (protects the private key at rest)
```

```bash [RSA 4096 — Legacy Compatibility]
ssh-keygen -t rsa -b 4096 -a 100 -C "admin@company.com" -f ~/.ssh/id_rsa
# -b 4096 : Key size (minimum 3072 for modern standards, 4096 preferred)
```

```bash [ECDSA — Alternative]
ssh-keygen -t ecdsa -b 521 -C "admin@company.com" -f ~/.ssh/id_ecdsa
# -b 521 : NIST P-521 curve (384 and 256 also available)
```

```text [Algorithm Comparison]
Algorithm    Key Size     Security    Speed        Compatibility
─────────    ────────     ────────    ─────        ─────────────
Ed25519      256-bit      ★★★★★      Fastest      Modern systems (OpenSSH 6.5+)
RSA          4096-bit     ★★★★       Slow         Universal (all systems)
ECDSA        521-bit      ★★★★       Fast         Most systems (OpenSSH 5.7+)

Recommendation: Use Ed25519 for all new deployments.
                Use RSA-4096 only for legacy system compatibility.
```

#### Copy public key to remote servers

```bash [Using ssh-copy-id]
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@remote-server
# Automatically adds key to remote ~/.ssh/authorized_keys
```

```bash [Manual Method (when ssh-copy-id unavailable)]
cat ~/.ssh/id_ed25519.pub | ssh user@remote-server \
  'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
```

#### Set correct permissions

```bash [SSH Directory and File Permissions]
# On client
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_ed25519          # Private key — MUST be 600
chmod 644 ~/.ssh/id_ed25519.pub      # Public key
chmod 644 ~/.ssh/config              # Client config
chmod 644 ~/.ssh/known_hosts

# On server
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys     # MUST be 600 or SSH will refuse
chown -R $USER:$USER ~/.ssh          # Owned by the correct user
```

#### Configure ssh-agent for passphrase caching

```bash [SSH Agent Setup]
# Start the agent
eval "$(ssh-agent -s)"

# Add key (will prompt for passphrase once)
ssh-add ~/.ssh/id_ed25519

# Add with lifetime (auto-remove after 8 hours)
ssh-add -t 28800 ~/.ssh/id_ed25519

# List loaded keys
ssh-add -l

# Persist across sessions (add to ~/.bashrc or ~/.zshrc)
if [ -z "$SSH_AUTH_SOCK" ]; then
    eval "$(ssh-agent -s)"
    ssh-add ~/.ssh/id_ed25519
fi
```

#### Manage multiple keys for different servers

```bash [~/.ssh/config — Client Configuration]
# Default settings for all hosts
Host *
    AddKeysToAgent yes
    IdentitiesOnly yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
    HashKnownHosts yes

# Production servers
Host prod-*
    User deploy
    IdentityFile ~/.ssh/id_ed25519_prod
    Port 2222

Host prod-web1
    HostName 10.0.1.10

Host prod-web2
    HostName 10.0.1.11

Host prod-db
    HostName 10.0.1.20
    Port 3222

# Staging servers
Host staging-*
    User deploy
    IdentityFile ~/.ssh/id_ed25519_staging
    Port 2222

Host staging-web
    HostName 172.16.0.10

# Jump host / Bastion
Host bastion
    HostName bastion.example.com
    User admin
    IdentityFile ~/.ssh/id_ed25519_bastion
    Port 2222

# Access internal servers via bastion
Host internal-*
    User admin
    IdentityFile ~/.ssh/id_ed25519_internal
    ProxyJump bastion
    Port 22

Host internal-app
    HostName 10.100.0.10

Host internal-db
    HostName 10.100.0.20
```

::

### Complete sshd_config Hardening

```bash [/etc/ssh/sshd_config — Fully Hardened]
# ═══════════════════════════════════════════════════════════════
# SSH Server Configuration — Production Hardened
# ═══════════════════════════════════════════════════════════════

# ─── Network ───────────────────────────────────────────────────
Port 2222                              # Change from default 22
ListenAddress 0.0.0.0                  # Or specific IP: 10.0.0.10
AddressFamily inet                     # inet = IPv4 only, any = both

# ─── Protocol ─────────────────────────────────────────────────
Protocol 2                             # SSHv1 is broken — v2 only

# ─── Authentication ───────────────────────────────────────────
PermitRootLogin no                     # NEVER allow root SSH login
PubkeyAuthentication yes               # Enable key-based auth
PasswordAuthentication no              # Disable password auth entirely
PermitEmptyPasswords no                # Block empty passwords
ChallengeResponseAuthentication yes    # Required for 2FA (set 'no' if no 2FA)
KbdInteractiveAuthentication yes       # Required for 2FA
AuthenticationMethods publickey,keyboard-interactive  # Key + 2FA

# ─── Key Settings ─────────────────────────────────────────────
AuthorizedKeysFile .ssh/authorized_keys
PubkeyAcceptedAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# ─── Disable Legacy/Insecure Features ─────────────────────────
HostbasedAuthentication no             # Don't trust remote host
IgnoreRhosts yes                       # Don't read .rhosts files
IgnoreUserKnownHosts no
StrictModes yes                        # Check file permissions
UsePAM yes                             # Required for 2FA and account policies
X11Forwarding no                       # Disable X11 unless specifically needed
AllowAgentForwarding no                # Disable unless needed for jump hosts
AllowTcpForwarding no                  # Disable unless specifically needed
PermitTunnel no
GatewayPorts no
PrintMotd no                           # We handle MOTD separately
PrintLastLog yes                       # Show last login info

# ─── Access Control ───────────────────────────────────────────
AllowUsers deploy admin                # Whitelist specific users
# AllowGroups sshusers                 # OR whitelist by group
DenyUsers root guest nobody            # Explicitly deny dangerous users
MaxAuthTries 3                         # Lock after 3 failed attempts
MaxSessions 3                          # Max concurrent sessions per connection
MaxStartups 10:30:60                   # Rate limit: start:rate:full

# ─── Session Timeouts ─────────────────────────────────────────
LoginGraceTime 30                      # 30 seconds to complete login
ClientAliveInterval 300                # Check client every 5 minutes
ClientAliveCountMax 2                  # Disconnect after 2 missed checks
                                       # Total idle timeout: 10 minutes

# ─── Crypto — Strong Ciphers Only ─────────────────────────────
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# ─── Logging ──────────────────────────────────────────────────
SyslogFacility AUTH
LogLevel VERBOSE                       # VERBOSE logs key fingerprints

# ─── Banner ───────────────────────────────────────────────────
Banner /etc/ssh/banner                 # Legal warning banner

# ─── SFTP ─────────────────────────────────────────────────────
# Restrict SFTP users to their home directory
Subsystem sftp internal-sftp

Match Group sftponly
    ChrootDirectory /home/%u
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
```

```bash [Apply and Verify SSH Configuration]
# Validate configuration syntax
sudo sshd -t
# If no output, configuration is valid

# Restart SSH service
sudo systemctl restart sshd

# Verify SSH is listening on new port
sudo ss -tlnp | grep 2222

# Test connection before closing current session!
# Open a NEW terminal:
ssh -p 2222 -i ~/.ssh/id_ed25519 deploy@server-ip

# If using SELinux, allow custom port:
sudo semanage port -a -t ssh_port_t -p tcp 2222
```

### SSH Legal Banner

```text [/etc/ssh/banner]
╔══════════════════════════════════════════════════════════════════╗
║                    AUTHORIZED ACCESS ONLY                        ║
║                                                                  ║
║  This system is the property of [Company Name].                  ║
║  Unauthorized access is strictly prohibited and may result       ║
║  in criminal prosecution. All activities on this system are      ║
║  monitored and recorded. By continuing, you consent to such      ║
║  monitoring. If you are not an authorized user, disconnect       ║
║  immediately.                                                    ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## 2 — User Account Security

### Sudoers Configuration

```bash [/etc/sudoers — via visudo ONLY]
# ═══════════════════════════════════════════════════════════════
# Sudoers Configuration — Principle of Least Privilege
# Always edit with: sudo visudo
# ═══════════════════════════════════════════════════════════════

# ─── Defaults ──────────────────────────────────────────────────
Defaults    env_reset                    # Reset environment variables
Defaults    mail_badpass                 # Email on bad password attempts
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults    logfile="/var/log/sudo.log"  # Log all sudo usage
Defaults    log_input, log_output        # Log stdin/stdout (audit trail)
Defaults    iolog_dir="/var/log/sudo-io" # I/O log directory
Defaults    timestamp_timeout=5          # Re-auth after 5 minutes
Defaults    passwd_tries=3               # 3 password attempts
Defaults    insults                      # Fun error messages (optional)
Defaults    requiretty                   # Require terminal (blocks scripts without tty)
Defaults    use_pty                      # Run commands in pseudo-terminal
Defaults    !visiblepw                   # Don't echo password

# ─── User Aliases ──────────────────────────────────────────────
User_Alias  ADMINS      = alice, bob
User_Alias  WEBADMINS   = charlie, diana
User_Alias  DBADMINS    = eve, frank
User_Alias  DEPLOYERS   = deploy_user

# ─── Command Aliases ──────────────────────────────────────────
Cmnd_Alias  SERVICES    = /usr/bin/systemctl restart nginx, \
                          /usr/bin/systemctl reload nginx, \
                          /usr/bin/systemctl status nginx, \
                          /usr/bin/systemctl restart postgresql, \
                          /usr/bin/systemctl reload postgresql
Cmnd_Alias  NETWORKING  = /usr/sbin/iptables, /usr/sbin/ufw, /usr/bin/ss
Cmnd_Alias  MONITORING  = /usr/bin/htop, /usr/bin/journalctl, /usr/bin/tail
Cmnd_Alias  DEPLOY_CMDS = /usr/bin/docker, /usr/bin/docker-compose, \
                          /usr/local/bin/deploy.sh
Cmnd_Alias  DANGEROUS   = /usr/bin/su, /usr/sbin/visudo, /usr/bin/passwd root, \
                          /usr/bin/rm, /usr/sbin/fdisk, /usr/sbin/mkfs

# ─── Privilege Assignments ─────────────────────────────────────
# Full admins — must use password
ADMINS      ALL=(ALL:ALL) ALL
# Explicitly deny dangerous commands even for admins
ADMINS      ALL=(ALL:ALL) !DANGEROUS

# Web admins — only web service management
WEBADMINS   ALL=(ALL) SERVICES, MONITORING

# DB admins — service management + network tools
DBADMINS    ALL=(ALL) SERVICES, NETWORKING, MONITORING

# Deploy user — specific deploy commands without password
DEPLOYERS   ALL=(ALL) NOPASSWD: DEPLOY_CMDS

# Root user
root        ALL=(ALL:ALL) ALL

# Include modular configs
@includedir /etc/sudoers.d
```

```bash [Modular sudoers.d configuration]
# /etc/sudoers.d/webadmin (one file per role)
# Created with: sudo visudo -f /etc/sudoers.d/webadmin

charlie ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
charlie ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload nginx
charlie ALL=(ALL) NOPASSWD: /usr/bin/tail -f /var/log/nginx/*
```

### Password Policies (PAM)

```bash [/etc/pam.d/common-password — Password Complexity]
# Password quality enforcement
password    requisite     pam_pwquality.so retry=3 \
                          minlen=14 \
                          dcredit=-1 \
                          ucredit=-1 \
                          lcredit=-1 \
                          ocredit=-1 \
                          difok=4 \
                          reject_username \
                          enforce_for_root \
                          maxrepeat=3

# Password history (prevent reuse of last 12 passwords)
password    required      pam_pwhistory.so remember=12 use_authtok enforce_for_root

# Password hashing (yescrypt is strongest, sha512 is universal)
password    [success=1 default=ignore] pam_unix.so obscure yescrypt rounds=11
```

```bash [/etc/pam.d/common-auth — Account Lockout]
# Account lockout after 5 failed attempts for 15 minutes
auth    required    pam_faillock.so preauth silent audit deny=5 unlock_time=900 fail_interval=900
auth    [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900 fail_interval=900
auth    sufficient  pam_faillock.so authsucc audit deny=5 unlock_time=900

# In /etc/pam.d/common-account:
account required    pam_faillock.so
```

```bash [Password Aging — chage]
# Set password policy for existing user
sudo chage -M 90 -m 7 -W 14 -I 30 username
# -M 90   : Maximum password age (90 days)
# -m 7    : Minimum password age (7 days, prevents rapid cycling)
# -W 14   : Warning days before expiration
# -I 30   : Inactive days before account lock

# Set defaults for new users (/etc/login.defs)
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# View user password info
sudo chage -l username

# Lock inactive accounts
sudo useradd -e 2025-12-31 tempuser  # Expiration date
sudo usermod -L username              # Lock account immediately
sudo usermod -U username              # Unlock account
```

### Service Accounts

```bash [Create Secure Service Accounts]
# Create service account with no login shell and no home
sudo useradd \
  --system \
  --no-create-home \
  --shell /usr/sbin/nologin \
  --comment "Nginx Service Account" \
  nginx_svc

# Create service account with specific home (for applications)
sudo useradd \
  --system \
  --create-home \
  --home-dir /opt/myapp \
  --shell /usr/sbin/nologin \
  --comment "Application Service Account" \
  app_svc

# Lock service account password (cannot login with password)
sudo passwd -l nginx_svc
sudo passwd -l app_svc

# Verify service accounts cannot login
sudo su - nginx_svc
# Output: "This account is currently not available."
```

---

## 3 — File System Permissions

### Critical File Permissions

```bash [Set Correct Permissions on Critical Files]
# ═══════════════════════════════════════════
# System Configuration Files
# ═══════════════════════════════════════════
sudo chmod 644 /etc/passwd              # World-readable (needed by many tools)
sudo chmod 640 /etc/shadow              # Group shadow can read, no world access
sudo chmod 644 /etc/group
sudo chmod 640 /etc/gshadow
sudo chmod 440 /etc/sudoers             # Read-only by root and sudoers group
sudo chmod 600 /etc/ssh/sshd_config     # Only root can read/write
sudo chmod 600 /etc/ssh/ssh_host_*key   # Private host keys
sudo chmod 644 /etc/ssh/ssh_host_*key.pub  # Public host keys
sudo chmod 644 /etc/crontab
sudo chmod 700 /etc/cron.d
sudo chmod 700 /etc/cron.daily
sudo chmod 700 /etc/cron.hourly
sudo chmod 700 /etc/cron.weekly
sudo chmod 700 /etc/cron.monthly

# Ownership
sudo chown root:root /etc/passwd /etc/group /etc/crontab /etc/ssh/sshd_config
sudo chown root:shadow /etc/shadow /etc/gshadow
sudo chown root:root /etc/sudoers

# ═══════════════════════════════════════════
# Log Files
# ═══════════════════════════════════════════
sudo chmod 640 /var/log/auth.log
sudo chmod 640 /var/log/syslog
sudo chmod 640 /var/log/kern.log
sudo chown syslog:adm /var/log/auth.log /var/log/syslog

# ═══════════════════════════════════════════
# Web Server Files
# ═══════════════════════════════════════════
sudo chown -R www-data:www-data /var/www/html
sudo find /var/www/html -type d -exec chmod 755 {} \;
sudo find /var/www/html -type f -exec chmod 644 {} \;
# No write permission for web files (prevent web shell uploads)

# ═══════════════════════════════════════════
# Immutable Critical Files
# ═══════════════════════════════════════════
sudo chattr +i /etc/passwd              # Cannot be modified, even by root
sudo chattr +i /etc/shadow
sudo chattr +i /etc/group
sudo chattr +i /etc/gshadow
sudo chattr +i /etc/sudoers
# To modify later: sudo chattr -i /etc/passwd
```

### Permission Auditing Scripts

```bash [Audit File Permissions — Security Scan]
#!/bin/bash
# security_audit.sh — Find permission issues

echo "═══════════════════════════════════════════"
echo "  File Permission Security Audit"
echo "═══════════════════════════════════════════"

echo ""
echo "[1] World-writable files (CRITICAL):"
find / -xdev -type f -perm -0002 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null

echo ""
echo "[2] World-writable directories (without sticky bit):"
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null

echo ""
echo "[3] SUID files (potential privilege escalation):"
find / -xdev -type f -perm -4000 2>/dev/null

echo ""
echo "[4] SGID files:"
find / -xdev -type f -perm -2000 2>/dev/null

echo ""
echo "[5] Files with no owner:"
find / -xdev -nouser -o -nogroup 2>/dev/null

echo ""
echo "[6] Writable files in /etc:"
find /etc -xdev -type f -perm -0002 2>/dev/null

echo ""
echo "[7] SSH key permissions:"
find /home -name "authorized_keys" -exec ls -la {} \; 2>/dev/null
find /home -name "id_*" -not -name "*.pub" -exec ls -la {} \; 2>/dev/null

echo ""
echo "[8] Crontab files writable by non-root:"
find /etc/cron* /var/spool/cron -writable -not -user root 2>/dev/null

echo ""
echo "═══════════════════════════════════════════"
echo "  Audit complete."
echo "═══════════════════════════════════════════"
```

### Filesystem Mount Hardening

```bash [/etc/fstab — Secure Mount Options]
# ═══════════════════════════════════════════
# Secure mount options for partitions
# ═══════════════════════════════════════════

# /tmp — noexec prevents execution, nosuid prevents SUID, nodev prevents device files
tmpfs   /tmp        tmpfs   defaults,noexec,nosuid,nodev,size=2G   0 0

# /var/tmp — same restrictions
tmpfs   /var/tmp    tmpfs   defaults,noexec,nosuid,nodev,size=1G   0 0

# /dev/shm — shared memory
tmpfs   /dev/shm    tmpfs   defaults,noexec,nosuid,nodev           0 0

# /home — nosuid prevents SUID binaries in user homes
/dev/sda3  /home    ext4    defaults,nosuid,nodev                  0 2

# /var/log — append-only would be ideal
/dev/sda4  /var/log ext4    defaults,nosuid,noexec,nodev           0 2

# Apply changes
sudo mount -o remount /tmp
sudo mount -o remount /var/tmp
sudo mount -o remount /dev/shm
```

---

## 4 — Kernel Hardening (sysctl)

```bash [/etc/sysctl.d/99-security.conf — Complete Kernel Hardening]
# ═══════════════════════════════════════════════════════════════
# Kernel Security Parameters — CIS Benchmark Aligned
# Apply with: sudo sysctl -p /etc/sysctl.d/99-security.conf
# ═══════════════════════════════════════════════════════════════

# ─── Network Security ─────────────────────────────────────────

# Disable IP forwarding (unless this is a router/gateway)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source-routed packets (prevents IP spoofing routes)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP redirects (prevent MITM routing attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Enable SYN flood protection (SYN cookies)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# Enable reverse path filtering (prevents IP spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets (impossible source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcast requests (prevent Smurf attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# TCP hardening
net.ipv4.tcp_timestamps = 0            # Disable TCP timestamps (info leak)
net.ipv4.tcp_rfc1337 = 1               # Protect against TIME-WAIT attacks
net.ipv4.tcp_fin_timeout = 15          # Faster FIN-WAIT-2 timeout

# ─── Kernel Hardening ─────────────────────────────────────────

# Restrict kernel pointer exposure (prevents KASLR bypass)
kernel.kptr_restrict = 2

# Restrict dmesg access (prevents kernel info leak)
kernel.dmesg_restrict = 1

# Enable ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# Restrict ptrace (prevents process inspection attacks)
kernel.yama.ptrace_scope = 2

# Disable core dumps for SUID programs
fs.suid_dumpable = 0

# Restrict Magic SysRq key
kernel.sysrq = 0

# Restrict unprivileged user namespaces (container escape prevention)
kernel.unprivileged_userns_clone = 0

# Restrict BPF (prevents unprivileged eBPF attacks)
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Restrict performance events
kernel.perf_event_paranoid = 3

# Protect hard/symbolic links
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
```

```bash [Apply Kernel Parameters]
# Apply all sysctl settings
sudo sysctl -p /etc/sysctl.d/99-security.conf

# Verify specific settings
sudo sysctl net.ipv4.tcp_syncookies
sudo sysctl kernel.kptr_restrict
sudo sysctl net.ipv4.conf.all.rp_filter

# Show all current sysctl values
sudo sysctl -a | grep -E "forward|syncookies|rp_filter|kptr_restrict"
```

---

## 5 — Firewall Configuration

### iptables (Legacy)

```bash [iptables — Production Firewall Rules]
#!/bin/bash
# firewall-iptables.sh — Complete iptables firewall

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t mangle -F

# ─── Default Policies: DROP everything ───────────────
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT    # Allow outbound (restrict if needed)

# ─── Loopback ────────────────────────────────────────
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# ─── Established/Related Connections ─────────────────
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ─── Drop Invalid Packets ────────────────────────────
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# ─── Anti-Spoofing ───────────────────────────────────
iptables -A INPUT -s 10.0.0.0/8 -i eth0 -j DROP      # Drop private on public
iptables -A INPUT -s 172.16.0.0/12 -i eth0 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -i eth0 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -i eth0 -j DROP

# ─── SSH (custom port, rate limited) ─────────────────
iptables -A INPUT -p tcp --dport 2222 -m conntrack --ctstate NEW \
  -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 2222 -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 2222 -m conntrack --ctstate NEW -j ACCEPT

# ─── HTTP/HTTPS ──────────────────────────────────────
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# ─── ICMP (limited ping) ─────────────────────────────
iptables -A INPUT -p icmp --icmp-type echo-request \
  -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# ─── Monitoring (from internal only) ─────────────────
iptables -A INPUT -p tcp --dport 9090 -s 10.0.0.50/32 -j ACCEPT  # Prometheus
iptables -A INPUT -p tcp --dport 9100 -s 10.0.0.50/32 -j ACCEPT  # Node Exporter

# ─── Log and Drop Everything Else ────────────────────
iptables -A INPUT -m limit --limit 5/min -j LOG \
  --log-prefix "iptables-DROPPED: " --log-level 4
iptables -A INPUT -j DROP

# ─── Save Rules ──────────────────────────────────────
iptables-save > /etc/iptables/rules.v4

echo "[+] Firewall rules applied."
```

### nftables (Modern)

```bash [/etc/nftables.conf — Production Firewall]
#!/usr/sbin/nft -f

flush ruleset

table inet filter {

    # ─── Sets for Dynamic Management ─────────────────
    set trusted_ssh {
        type ipv4_addr
        flags interval
        elements = {
            10.0.0.5/32,        # Admin workstation
            10.0.0.0/24         # Management network
        }
    }

    set blocked_ips {
        type ipv4_addr
        flags interval, timeout
        timeout 24h             # Auto-expire after 24 hours
    }

    # ─── Input Chain ─────────────────────────────────
    chain input {
        type filter hook input priority 0; policy drop;

        # Drop blocked IPs immediately
        ip saddr @blocked_ips counter drop

        # Allow loopback
        iif lo accept

        # Allow established/related
        ct state established,related accept

        # Drop invalid
        ct state invalid counter drop

        # Rate-limited ICMP
        ip protocol icmp icmp type echo-request \
            limit rate 1/second burst 4 packets accept

        # SSH — only from trusted IPs, rate limited
        tcp dport 2222 ip saddr @trusted_ssh \
            ct state new \
            limit rate 10/minute burst 5 packets \
            counter accept comment "SSH access"

        # HTTP/HTTPS
        tcp dport { 80, 443 } \
            ct state new \
            counter accept comment "Web traffic"

        # Monitoring (internal only)
        tcp dport { 9090, 9100 } ip saddr 10.0.0.50 \
            counter accept comment "Monitoring"

        # Log dropped packets (rate limited)
        limit rate 5/minute burst 10 packets \
            log prefix "nft-dropped: " level warn

        # Everything else is dropped by policy
        counter comment "Total dropped packets"
    }

    # ─── Forward Chain ───────────────────────────────
    chain forward {
        type filter hook forward priority 0; policy drop;
        # No forwarding on this server
    }

    # ─── Output Chain ────────────────────────────────
    chain output {
        type filter hook output priority 0; policy accept;

        # Allow loopback
        oif lo accept

        # Allow established
        ct state established,related accept

        # Allow DNS, NTP, HTTPS (outbound)
        tcp dport { 53, 80, 443 } accept
        udp dport { 53, 123 } accept

        # Drop everything else (strict output control)
        # counter drop
    }
}
```

```bash [Apply nftables]
# Validate
sudo nft -c -f /etc/nftables.conf

# Apply
sudo nft -f /etc/nftables.conf

# Verify rules
sudo nft list ruleset

# Enable on boot
sudo systemctl enable nftables

# Dynamically add blocked IP
sudo nft add element inet filter blocked_ips { 203.0.113.50 }

# List blocked IPs
sudo nft list set inet filter blocked_ips
```

### ufw (Simplified)

```bash [ufw — Quick Setup]
# Reset to defaults
sudo ufw reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default deny routed

# Allow SSH (custom port, rate limited)
sudo ufw limit 2222/tcp comment 'SSH rate-limited'

# Allow web traffic
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'

# Allow from specific networks
sudo ufw allow from 10.0.0.0/24 to any port 9090 proto tcp comment 'Prometheus internal'

# Deny specific IPs
sudo ufw deny from 203.0.113.0/24

# Enable logging
sudo ufw logging medium

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose
sudo ufw status numbered
```

---

## 6 — Fail2ban

### Complete Fail2ban Configuration

```ini [/etc/fail2ban/jail.local]
# ═══════════════════════════════════════════════════════════════
# Fail2ban Configuration — Production Hardened
# ═══════════════════════════════════════════════════════════════

[DEFAULT]
# Global defaults
bantime = 3600                    # Ban for 1 hour
findtime = 600                    # Look at last 10 minutes
maxretry = 3                      # Ban after 3 failures
backend = systemd                 # Use systemd journal
banaction = nftables-multiport    # Use nftables (or iptables-multiport)
banaction_allports = nftables-allports

# Email alerts (optional)
# destemail = admin@company.com
# sender = fail2ban@company.com
# action = %(action_mwl)s          # Ban + email with whois + log

# Whitelist trusted IPs
ignoreip = 127.0.0.1/8 ::1 10.0.0.5/32

# ─── SSH Jail ──────────────────────────────────────────────────
[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
mode = aggressive                 # Catch more attack patterns

# ─── SSH DDoS (connection rate) ────────────────────────────────
[sshd-ddos]
enabled = true
port = 2222
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 6
bantime = 7200
findtime = 60

# ─── Recidive (repeat offenders) ──────────────────────────────
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
banaction = nftables-allports
maxretry = 3                      # 3 bans from other jails
bantime = 604800                  # Ban for 1 week
findtime = 86400                  # Within 24 hours

# ─── Nginx HTTP Auth ──────────────────────────────────────────
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

# ─── Nginx Bad Bots ───────────────────────────────────────────
[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 86400

# ─── Nginx Rate Limit (429 responses) ─────────────────────────
[nginx-limit-req]
enabled = true
port = http,https
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 3600

# ─── Nginx 404 Scanning ───────────────────────────────────────
[nginx-404]
enabled = true
port = http,https
filter = nginx-404
logpath = /var/log/nginx/access.log
maxretry = 10
bantime = 3600
findtime = 60
```

```ini [/etc/fail2ban/filter.d/nginx-404.conf — Custom Filter]
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD) .* HTTP/[0-9.]+" 404
ignoreregex = \.(?:ico|css|js|png|jpg|gif|svg|woff2?)
```

```bash [Fail2ban Management Commands]
# Check all jail status
sudo fail2ban-client status

# Check specific jail
sudo fail2ban-client status sshd

# View banned IPs for a jail
sudo fail2ban-client status sshd | grep "Banned IP"

# Manually ban an IP
sudo fail2ban-client set sshd banip 203.0.113.100

# Manually unban an IP
sudo fail2ban-client set sshd unbanip 203.0.113.100

# Test a filter against a log file
sudo fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf

# Reload configuration
sudo fail2ban-client reload

# Check fail2ban log
sudo tail -f /var/log/fail2ban.log
```

---

## 7 — SELinux / AppArmor

::tabs
  :::tabs-item{icon="i-lucide-shield" label="SELinux (RHEL/CentOS/Fedora)"}
  ```bash [SELinux Management Commands]
  # Check current mode
  getenforce
  # Enforcing, Permissive, or Disabled

  sestatus
  # Detailed status information

  # Set mode (temporary — reverts on reboot)
  sudo setenforce 1    # Enforcing
  sudo setenforce 0    # Permissive (logging only)

  # Set mode permanently
  sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config

  # ─── Context Management ────────────────────────────
  # View file contexts
  ls -Z /var/www/html/
  # -rw-r--r--. root root unconfined_u:object_r:httpd_sys_content_t:s0 index.html

  # View process contexts
  ps -eZ | grep nginx
  # system_u:system_r:httpd_t:s0  1234  nginx: master process

  # Restore default contexts
  sudo restorecon -Rv /var/www/html/

  # Change file context for custom web directory
  sudo semanage fcontext -a -t httpd_sys_content_t "/opt/webapp(/.*)?"
  sudo restorecon -Rv /opt/webapp/

  # ─── Port Management ───────────────────────────────
  # Allow custom SSH port
  sudo semanage port -a -t ssh_port_t -p tcp 2222

  # Allow custom HTTP port
  sudo semanage port -a -t http_port_t -p tcp 8080

  # List allowed ports for a service
  sudo semanage port -l | grep ssh_port_t
  sudo semanage port -l | grep http_port_t

  # ─── Booleans ──────────────────────────────────────
  # List all booleans
  sudo getsebool -a

  # Common booleans for web servers
  sudo setsebool -P httpd_can_network_connect on     # Nginx → upstream
  sudo setsebool -P httpd_can_network_connect_db on  # Nginx → database
  sudo setsebool -P httpd_use_nfs off                # Disable NFS access
  sudo setsebool -P httpd_enable_cgi off             # Disable CGI

  # ─── Troubleshooting ───────────────────────────────
  # View recent denials
  sudo ausearch -m avc -ts recent

  # Generate policy from denials
  sudo ausearch -m avc -ts recent | audit2allow -M mypolicy
  sudo semodule -i mypolicy.pp

  # Use sealert for friendly explanations (install setroubleshoot)
  sudo sealert -a /var/log/audit/audit.log
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="AppArmor (Ubuntu/Debian)"}
  ```bash [AppArmor Management Commands]
  # Check status
  sudo aa-status
  # Shows enforced, complain, and unconfined profiles

  # List all profiles
  sudo aa-status --verbose

  # ─── Profile Modes ────────────────────────────────
  # Set profile to enforce mode
  sudo aa-enforce /etc/apparmor.d/usr.sbin.nginx

  # Set profile to complain mode (learning mode)
  sudo aa-complain /etc/apparmor.d/usr.sbin.nginx

  # Disable a profile
  sudo ln -s /etc/apparmor.d/usr.sbin.nginx /etc/apparmor.d/disable/
  sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.nginx

  # ─── Generate New Profile ──────────────────────────
  # Interactive profile generation
  sudo aa-genprof /usr/sbin/nginx
  # 1. Start the application in another terminal
  # 2. Exercise all its functionality
  # 3. Return to aa-genprof and scan logs
  # 4. Accept/deny each access request
  # 5. Save the profile

  # Update profile from logs
  sudo aa-logprof

  # ─── Custom Profile Example ────────────────────────
  # /etc/apparmor.d/usr.local.bin.myapp
  cat > /etc/apparmor.d/usr.local.bin.myapp << 'EOF'
  #include <tunables/global>

  /usr/local/bin/myapp {
    #include <abstractions/base>
    #include <abstractions/nameservice>

    # Read configuration
    /etc/myapp/** r,

    # Write logs
    /var/log/myapp/** rw,
    /var/log/myapp/ rw,

    # Data directory
    /var/lib/myapp/** rw,

    # Network access
    network inet stream,
    network inet dgram,

    # Deny everything else
    deny /etc/shadow r,
    deny /etc/passwd w,
    deny /root/** rw,
  }
  EOF

  # Load the profile
  sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.myapp

  # Verify
  sudo aa-status | grep myapp
  ```
  :::
::

---

## 8 — Audit Logging (auditd)

```bash [/etc/audit/rules.d/hardened.rules — Complete Audit Rules]
# ═══════════════════════════════════════════════════════════════
# auditd Rules — CIS Benchmark Aligned
# Apply with: sudo augenrules --load
# ═══════════════════════════════════════════════════════════════

# Remove all existing rules
-D

# Set buffer size (increase for busy systems)
-b 8192

# Failure mode (1=printk, 2=panic — use 1 for production)
-f 1

# ─── Identity Changes ─────────────────────────────────────────
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# ─── Authentication Configuration ─────────────────────────────
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/login.defs -p wa -k login_config
-w /etc/securetty -p wa -k securetty

# ─── SSH Configuration ────────────────────────────────────────
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/ -p wa -k ssh_config

# ─── Sudoers Configuration ────────────────────────────────────
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# ─── Network Configuration ────────────────────────────────────
-w /etc/hosts -p wa -k network_config
-w /etc/sysconfig/network -p wa -k network_config
-w /etc/network/ -p wa -k network_config
-w /etc/netplan/ -p wa -k network_config

# ─── Cron Configuration ───────────────────────────────────────
-w /etc/crontab -p wa -k cron_config
-w /etc/cron.d/ -p wa -k cron_config
-w /etc/cron.daily/ -p wa -k cron_config
-w /etc/cron.hourly/ -p wa -k cron_config
-w /etc/cron.weekly/ -p wa -k cron_config
-w /etc/cron.monthly/ -p wa -k cron_config
-w /var/spool/cron/ -p wa -k cron_config

# ─── Firewall Configuration ───────────────────────────────────
-w /etc/nftables.conf -p wa -k firewall
-w /etc/iptables/ -p wa -k firewall
-w /etc/ufw/ -p wa -k firewall

# ─── System Time Changes ──────────────────────────────────────
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# ─── User/Group Modifications ─────────────────────────────────
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system_locale
-w /etc/hostname -p wa -k system_locale

# ─── Privileged Commands ──────────────────────────────────────
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# ─── Kernel Module Loading ────────────────────────────────────
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module -S delete_module -S finit_module -k kernel_modules

# ─── File Deletion by Users ───────────────────────────────────
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat \
  -F auid>=1000 -F auid!=4294967295 -k file_deletion

# ─── Unauthorized Access Attempts ─────────────────────────────
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EPERM -k access_denied

# ─── Make audit configuration immutable ───────────────────────
# MUST be last rule — requires reboot to change audit rules
-e 2
```

```bash [auditd Management Commands]
# Load rules
sudo augenrules --load

# Check rules
sudo auditctl -l

# Search audit logs
sudo ausearch -k identity -ts recent         # Identity changes
sudo ausearch -k sshd_config -ts today       # SSH config changes
sudo ausearch -k sudoers -ts this-week       # Sudoers changes
sudo ausearch -k privileged -ts today        # Privileged commands
sudo ausearch -m USER_LOGIN -ts today        # Login events
sudo ausearch -m USER_AUTH --success no      # Failed authentications

# Generate reports
sudo aureport --summary                       # Overall summary
sudo aureport --login --summary              # Login summary
sudo aureport --failed                       # All failures
sudo aureport --auth                         # Authentication report
sudo aureport --file --summary              # File access summary
sudo aureport --key --summary               # Events by key
```

---

## 9 — Service Minimization

```bash [Identify and Disable Unnecessary Services]
# ─── List All Running Services ───────────────────────
systemctl list-units --type=service --state=running

# ─── List All Listening Ports ────────────────────────
sudo ss -tulnp

# ─── Common Services to Disable on Servers ───────────

# Print services (not needed on servers)
sudo systemctl stop cups cups-browsed
sudo systemctl disable cups cups-browsed
sudo systemctl mask cups cups-browsed

# Bluetooth (not needed on servers)
sudo systemctl stop bluetooth
sudo systemctl disable bluetooth
sudo systemctl mask bluetooth

# Avahi/mDNS (not needed unless using Bonjour)
sudo systemctl stop avahi-daemon
sudo systemctl disable avahi-daemon
sudo systemctl mask avahi-daemon

# ModemManager (not needed on servers)
sudo systemctl stop ModemManager
sudo systemctl disable ModemManager

# Automatic updates GUI (use unattended-upgrades instead)
sudo systemctl stop packagekit
sudo systemctl disable packagekit

# ─── Verify Only Needed Services Remain ──────────────
echo "=== Running Services ==="
systemctl list-units --type=service --state=running --no-pager | grep -v "session\|user@"

echo ""
echo "=== Listening Ports ==="
sudo ss -tulnp | grep LISTEN

echo ""
echo "=== Expected ports only ==="
echo "Port 2222  : SSH"
echo "Port 80    : HTTP (nginx)"
echo "Port 443   : HTTPS (nginx)"
echo "Port 9100  : Node Exporter (monitoring)"
```

---

## 10 — Two-Factor Authentication for SSH

```bash [Google Authenticator 2FA Setup]
# Install PAM module
sudo apt install -y libpam-google-authenticator

# Configure for each user (run AS the user)
google-authenticator -t -d -f -r 3 -R 30 -w 3
# -t : Time-based TOTP
# -d : Disallow reuse of tokens
# -f : Force write to ~/.google_authenticator
# -r 3 -R 30 : Rate limit 3 logins per 30 seconds
# -w 3 : Allow 3 window codes (time skew tolerance)

# IMPORTANT: Save the emergency scratch codes!
```

```bash [/etc/pam.d/sshd — Add 2FA]
# Add this line AFTER @include common-auth:
auth required pam_google_authenticator.so nullok
# nullok allows users who haven't set up 2FA to still login
# Remove nullok after all users have configured 2FA
```

```bash [/etc/ssh/sshd_config — Enable 2FA]
# Enable keyboard-interactive for 2FA
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication yes
UsePAM yes

# Require both key AND 2FA
AuthenticationMethods publickey,keyboard-interactive

# Restart SSH
sudo systemctl restart sshd
```

```text [Login Flow with 2FA]
$ ssh -p 2222 user@server
Authenticated with partial success.     ← Key accepted
Verification code: ______               ← Enter 6-digit TOTP code
Welcome to Ubuntu 22.04.3 LTS           ← Access granted
```

---

# Part 2 — Portal Firewall Level Security

---

## 11 — Web Application Firewall (WAF)

### ModSecurity with Nginx

```bash [Install ModSecurity + OWASP CRS]
# Install ModSecurity for Nginx
sudo apt install -y libmodsecurity3 libmodsecurity-dev

# Clone OWASP Core Rule Set
sudo git clone https://github.com/coreruleset/coreruleset.git /etc/nginx/modsecurity/crs
cd /etc/nginx/modsecurity/crs
sudo cp crs-setup.conf.example crs-setup.conf

# Copy ModSecurity config
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/nginx/modsecurity/modsecurity.conf
```

```conf [/etc/nginx/modsecurity/modsecurity.conf — Key Settings]
# Enable ModSecurity engine
SecRuleEngine On                        # On, Off, DetectionOnly

# Request body handling
SecRequestBodyAccess On
SecRequestBodyLimit 13107200            # 12.5 MB max body
SecRequestBodyNoFilesLimit 131072       # 128 KB without files

# Response body (disable for performance in most cases)
SecResponseBodyAccess Off

# Audit logging
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogType Serial
SecAuditLog /var/log/nginx/modsec_audit.log

# Temp directory
SecTmpDir /tmp/modsecurity/tmp
SecDataDir /tmp/modsecurity/data

# Include OWASP CRS
Include /etc/nginx/modsecurity/crs/crs-setup.conf
Include /etc/nginx/modsecurity/crs/rules/*.conf
```

```nginx [Nginx — Enable ModSecurity]
server {
    listen 443 ssl http2;
    server_name example.com;

    # Enable ModSecurity
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity/modsecurity.conf;

    location / {
        proxy_pass http://backend;
        # ... proxy headers
    }
}
```

---

## 12 — DDoS Protection

```nginx [Nginx DDoS Protection Configuration]
# ═══════════════════════════════════════════════════════════════
# /etc/nginx/conf.d/ddos-protection.conf
# ═══════════════════════════════════════════════════════════════

# ─── Rate Limiting Zones ─────────────────────────────
limit_req_zone $binary_remote_addr zone=general:20m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api:20m rate=30r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=3r/m;    # 3 per MINUTE
limit_req_zone $binary_remote_addr zone=search:10m rate=5r/s;

# ─── Connection Limits ──────────────────────────────
limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;
limit_conn_zone $server_name zone=conn_total:10m;

# ─── Response Codes ──────────────────────────────────
limit_req_status 429;
limit_conn_status 429;

# ─── Slow Connection Mitigation ─────────────────────
client_body_timeout 10s;
client_header_timeout 10s;
send_timeout 10s;

# Request size limits
client_max_body_size 10M;
client_body_buffer_size 128k;
large_client_header_buffers 4 8k;
```

```bash [sysctl — SYN Flood Protection]
# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600

# Apply
sudo sysctl -p
```

---

## 13 — Geo-blocking & IP Reputation

```nginx [Nginx Geo-blocking with GeoIP2]
# Load GeoIP2 module (install: apt install libnginx-mod-http-geoip2)
geoip2 /usr/share/GeoIP/GeoLite2-Country.mmdb {
    auto_reload 60m;
    $geoip2_data_country_iso_code country iso_code;
}

# Define allowed/blocked countries
map $geoip2_data_country_iso_code $allowed_country {
    default     0;     # Block by default
    US          1;     # Allow USA
    CA          1;     # Allow Canada
    GB          1;     # Allow UK
    DE          1;     # Allow Germany
    FR          1;     # Allow France
    AU          1;     # Allow Australia
    # Add more as needed
}

server {
    listen 443 ssl http2;

    # Block disallowed countries
    if ($allowed_country = 0) {
        return 403;
    }

    # ... rest of config
}
```

```bash [IP Reputation — Automated Blocklist Updates]
#!/bin/bash
# update-blocklists.sh — Download and apply IP blocklists

BLOCKLIST_DIR="/etc/nginx/blocklists"
mkdir -p "$BLOCKLIST_DIR"

# Download Spamhaus DROP list
curl -s "https://www.spamhaus.org/drop/drop.txt" | \
    grep -v "^;" | awk '{print $1}' > "$BLOCKLIST_DIR/spamhaus-drop.txt"

# Download FireHOL Level 1
curl -s "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" | \
    grep -v "^#" > "$BLOCKLIST_DIR/firehol-l1.txt"

# Generate Nginx deny rules
echo "# Auto-generated blocklist - $(date)" > /etc/nginx/conf.d/blocklist.conf
while IFS= read -r ip; do
    [ -n "$ip" ] && echo "deny $ip;" >> /etc/nginx/conf.d/blocklist.conf
done < "$BLOCKLIST_DIR/spamhaus-drop.txt"

# Reload Nginx
nginx -t && nginx -s reload
echo "[+] Blocklists updated: $(wc -l < /etc/nginx/conf.d/blocklist.conf) rules"
```

---

## 14 — Security Headers

```nginx [/etc/nginx/conf.d/security-headers.conf]
# ═══════════════════════════════════════════════════════════════
# Security Headers — OWASP Recommended
# ═══════════════════════════════════════════════════════════════

# Hide server version
server_tokens off;
more_clear_headers Server;

# Prevent clickjacking
add_header X-Frame-Options "SAMEORIGIN" always;

# Prevent MIME type sniffing
add_header X-Content-Type-Options "nosniff" always;

# XSS Protection (legacy browsers)
add_header X-XSS-Protection "1; mode=block" always;

# Referrer policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# HSTS (only after confirming HTTPS works)
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# Content Security Policy
add_header Content-Security-Policy
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https://api.example.com; frame-ancestors 'self'; base-uri 'self'; form-action 'self';"
    always;

# Permissions Policy (replaces Feature-Policy)
add_header Permissions-Policy
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
    always;

# Cross-Origin policies
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;

# Prevent caching of sensitive pages
# (apply to specific locations, not globally)
# add_header Cache-Control "no-store, no-cache, must-revalidate" always;
# add_header Pragma "no-cache" always;
```

```bash [Verify Security Headers]
# Check headers with curl
curl -sI https://example.com | grep -iE "x-frame|x-content|x-xss|strict-transport|content-security|referrer|permissions"

# Use securityheaders.com
# https://securityheaders.com/?q=example.com

# Use Mozilla Observatory
# https://observatory.mozilla.org/
```

---

## 15 — API Gateway Security

```nginx [Nginx API Gateway — Secure Configuration]
# ─── API Rate Limiting ───────────────────────────────
limit_req_zone $http_x_api_key zone=api_key:10m rate=100r/m;
limit_req_zone $binary_remote_addr zone=api_ip:10m rate=30r/s;

# ─── API Authentication Validation ───────────────────
map $http_authorization $auth_valid {
    default         0;
    "~^Bearer .+"   1;    # Must have Bearer token
}

map $http_x_api_key $api_key_valid {
    default         0;
    "~^[a-zA-Z0-9]{32,}$"  1;   # Must be 32+ alphanumeric chars
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    # ─── API Endpoints ───────────────────────────────
    location /api/v1/ {
        # Rate limit per API key
        limit_req zone=api_key burst=20 nodelay;
        limit_req zone=api_ip burst=10 nodelay;

        # Require authentication header
        if ($auth_valid = 0) {
            return 401 '{"error":"Missing or invalid Authorization header"}';
        }

        # Block non-JSON content types for POST/PUT
        if ($request_method ~ ^(POST|PUT|PATCH)$) {
            set $check_ct 1;
        }
        if ($http_content_type !~ "application/json") {
            set $check_ct "${check_ct}1";
        }
        if ($check_ct = 11) {
            return 415 '{"error":"Content-Type must be application/json"}';
        }

        # Restrict HTTP methods
        if ($request_method !~ ^(GET|POST|PUT|PATCH|DELETE|OPTIONS)$) {
            return 405 '{"error":"Method not allowed"}';
        }

        # CORS headers
        add_header 'Access-Control-Allow-Origin' 'https://app.example.com' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type, X-API-Key' always;
        add_header 'Access-Control-Max-Age' '86400' always;

        if ($request_method = 'OPTIONS') {
            return 204;
        }

        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Block access to non-API paths
    location / {
        return 404 '{"error":"Not found"}';
    }
}
```

---

## 16 — Logging & Monitoring

### Centralized Logging Architecture

```text [Logging Flow]

  ┌──────────────────────────────────────────────────────────────┐
  │  Linux Servers                                                │
  │                                                              │
  │  📋 /var/log/auth.log      → Filebeat → Elasticsearch       │
  │  📋 /var/log/syslog        → Filebeat → Elasticsearch       │
  │  📋 /var/log/audit/audit.log → Filebeat → Elasticsearch     │
  │  📋 /var/log/fail2ban.log  → Filebeat → Elasticsearch       │
  │  📋 /var/log/nginx/*.log   → Filebeat → Elasticsearch       │
  │  📋 WAF audit log          → Filebeat → Elasticsearch       │
  │                                                              │
  │                     ▼                                        │
  │              ┌──────────────┐                                │
  │              │ Elasticsearch│──── Kibana ──── Dashboards     │
  │              │ (Index/Store)│        │                        │
  │              └──────────────┘        ├── 🚨 Alert: Failed    │
  │                                      │    SSH > 10/min       │
  │                                      ├── 🚨 Alert: WAF      │
  │                                      │    SQLi detected      │
  │                                      └── 🚨 Alert: New      │
  │                                           sudo user added    │
  └──────────────────────────────────────────────────────────────┘
```

```yaml [filebeat.yml — Ship All Security Logs]
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/auth.log
    fields:
      log_type: auth
    multiline.pattern: '^\w{3}\s+\d{1,2}'
    multiline.negate: true
    multiline.match: after

  - type: log
    enabled: true
    paths:
      - /var/log/fail2ban.log
    fields:
      log_type: fail2ban

  - type: log
    enabled: true
    paths:
      - /var/log/nginx/access.log
    fields:
      log_type: nginx_access

  - type: log
    enabled: true
    paths:
      - /var/log/nginx/error.log
      - /var/log/nginx/modsec_audit.log
    fields:
      log_type: nginx_security

  - type: log
    enabled: true
    paths:
      - /var/log/audit/audit.log
    fields:
      log_type: auditd

output.elasticsearch:
  hosts: ["https://elk.internal:9200"]
  ssl.certificate_authorities: ["/etc/filebeat/ca.pem"]
  username: "filebeat_writer"
  password: "${FILEBEAT_PASSWORD}"
```

---

## Security Checklists

### Linux OS Level

::collapsible

```text [Linux OS Security Checklist]
═══════════════════════════════════════════════════════════════
  LINUX OS LEVEL SECURITY CHECKLIST
═══════════════════════════════════════════════════════════════

  SSH HARDENING
  ─────────────
  ☐ Ed25519 key authentication enabled
  ☐ Password authentication disabled
  ☐ Root login disabled (PermitRootLogin no)
  ☐ Custom SSH port configured (not 22)
  ☐ Strong ciphers, MACs, and KEX algorithms only
  ☐ MaxAuthTries set to 3
  ☐ ClientAliveInterval/CountMax for idle timeout
  ☐ AllowUsers or AllowGroups whitelist configured
  ☐ SSH banner (legal warning) configured
  ☐ Two-factor authentication enabled
  ☐ X11 forwarding disabled
  ☐ Agent forwarding disabled (unless needed)
  ☐ Protocol 2 only
  ☐ StrictModes yes

  USER & ACCESS CONTROL
  ─────────────────────
  ☐ Sudo configured with least privilege
  ☐ No NOPASSWD except for deploy automation
  ☐ Sudo logging enabled (log_input, log_output)
  ☐ Anonymous/default users removed
  ☐ Service accounts use /usr/sbin/nologin
  ☐ Password complexity enforced (PAM)
  ☐ Password aging configured (chage)
  ☐ Account lockout after failed attempts (pam_faillock)
  ☐ Inactive accounts disabled

  FILE SYSTEM
  ───────────
  ☐ Critical file permissions verified
  ☐ /tmp mounted with noexec,nosuid,nodev
  ☐ No world-writable files in /etc
  ☐ SUID/SGID files audited and minimized
  ☐ Immutable flag on critical config files
  ☐ AIDE/Tripwire file integrity monitoring

  KERNEL HARDENING
  ────────────────
  ☐ IP forwarding disabled
  ☐ ICMP redirects disabled
  ☐ Source routing disabled
  ☐ SYN cookies enabled
  ☐ Reverse path filtering enabled
  ☐ ASLR enabled (randomize_va_space = 2)
  ☐ Kernel pointer hiding (kptr_restrict = 2)
  ☐ dmesg restricted
  ☐ Core dumps disabled for SUID
  ☐ ptrace restricted (yama.ptrace_scope = 2)

  FIREWALL
  ────────
  ☐ Default deny policy (INPUT DROP)
  ☐ Only required ports open
  ☐ Rate limiting on SSH
  ☐ Stateful connection tracking
  ☐ Anti-spoofing rules
  ☐ Logging of dropped packets
  ☐ IPv6 firewall configured (or IPv6 disabled)
  ☐ Rules saved and persistent across reboots

  FAIL2BAN
  ────────
  ☐ SSH jail enabled
  ☐ Recidive jail for repeat offenders
  ☐ Web application jails (nginx-http-auth, etc.)
  ☐ Trusted IPs whitelisted (ignoreip)
  ☐ Email alerts configured (optional)

  MANDATORY ACCESS CONTROL
  ────────────────────────
  ☐ SELinux in enforcing mode (RHEL) / AppArmor profiles enforced (Ubuntu)
  ☐ Custom contexts for non-standard paths
  ☐ Booleans configured for services
  ☐ Audit logs reviewed for denials

  AUDIT & LOGGING
  ───────────────
  ☐ auditd installed and running
  ☐ Critical file watches configured
  ☐ Privileged command execution logged
  ☐ User/group changes logged
  ☐ SSH config changes logged
  ☐ Firewall config changes logged
  ☐ Audit rules immutable (-e 2)
  ☐ Logs shipped to centralized SIEM
  ☐ Log rotation configured

  SERVICES
  ────────
  ☐ Only required services running
  ☐ Unnecessary services masked
  ☐ Listening ports verified (ss -tulnp)
  ☐ Auto-updates configured (unattended-upgrades)
  ☐ NTP configured for accurate timestamps
```

::

### Portal Firewall Level

::collapsible

```text [Portal Firewall Security Checklist]
═══════════════════════════════════════════════════════════════
  PORTAL FIREWALL LEVEL SECURITY CHECKLIST
═══════════════════════════════════════════════════════════════

  WAF
  ───
  ☐ ModSecurity enabled with OWASP CRS
  ☐ SQL injection rules active
  ☐ XSS detection rules active
  ☐ Path traversal rules active
  ☐ Command injection rules active
  ☐ Scanner/bot user-agent blocking
  ☐ False positive tuning completed
  ☐ WAF audit logging enabled

  DDOS PROTECTION
  ───────────────
  ☐ Rate limiting configured (general, API, login)
  ☐ Connection limits per IP
  ☐ SYN flood protection (sysctl)
  ☐ Slow connection timeouts configured
  ☐ Request body size limits set
  ☐ CDN/DDoS scrubbing service active (if applicable)

  GEO-BLOCKING
  ────────────
  ☐ GeoIP database installed and updated
  ☐ Allowed countries configured
  ☐ IP reputation blocklists active
  ☐ Blocklist auto-update scheduled

  SECURITY HEADERS
  ────────────────
  ☐ X-Frame-Options: SAMEORIGIN
  ☐ X-Content-Type-Options: nosniff
  ☐ Strict-Transport-Security (HSTS)
  ☐ Content-Security-Policy configured
  ☐ Permissions-Policy configured
  ☐ Referrer-Policy set
  ☐ Server header removed/hidden

  SSL/TLS
  ───────
  ☐ TLS 1.2+ only (1.0/1.1 disabled)
  ☐ Strong cipher suites configured
  ☐ Forward secrecy enabled
  ☐ OCSP stapling enabled
  ☐ HSTS preload submitted
  ☐ Certificate auto-renewal configured
  ☐ SSL tested (ssllabs.com Grade A+)

  API SECURITY
  ────────────
  ☐ Authentication required for all endpoints
  ☐ Rate limiting per API key
  ☐ Input validation on all parameters
  ☐ HTTP method whitelisting
  ☐ Content-Type enforcement
  ☐ CORS properly configured
  ☐ API versioning implemented

  LOGGING & MONITORING
  ────────────────────
  ☐ Access logs enabled with detailed format
  ☐ Error logs at appropriate verbosity
  ☐ WAF logs shipped to SIEM
  ☐ Failed login attempt alerting
  ☐ DDoS traffic alerting
  ☐ Certificate expiry monitoring
  ☐ Uptime monitoring
═══════════════════════════════════════════════════════════════
```

::

---

## Tool Resources

::card-group

::card
---
title: CIS Benchmarks
icon: i-lucide-shield-check
to: https://www.cisecurity.org/cis-benchmarks
target: _blank
---
Industry-standard security configuration guides for Ubuntu, RHEL, Debian, CentOS, and more. Free PDF downloads with step-by-step hardening instructions.
::

::card
---
title: Lynis
icon: i-simple-icons-github
to: https://github.com/CISOfy/lynis
target: _blank
---
Open-source security auditing tool for Linux. Performs comprehensive system scanning and provides hardening recommendations aligned with CIS and other benchmarks.
::

::card
---
title: OpenSSH
icon: i-simple-icons-openssh
to: https://www.openssh.com/
target: _blank
---
The SSH implementation used by virtually all Linux distributions. Understanding its configuration options is essential for SSH hardening.
::

::card
---
title: Fail2ban
icon: i-simple-icons-github
to: https://github.com/fail2ban/fail2ban
target: _blank
---
Intrusion prevention framework that scans log files and bans IPs showing malicious signs. Essential for SSH, web, and mail server protection.
::

::card
---
title: ModSecurity
icon: i-simple-icons-github
to: https://github.com/owasp-modsecurity/ModSecurity
target: _blank
---
Open-source WAF engine. Combined with OWASP Core Rule Set, provides comprehensive web application protection against OWASP Top 10 attacks.
::

::card
---
title: OWASP Core Rule Set
icon: i-simple-icons-owasp
to: https://coreruleset.org/
target: _blank
---
The standard WAF ruleset for ModSecurity. Protects against SQL injection, XSS, LFI, RCE, and more with minimal false positives when properly tuned.
::

::card
---
title: nftables Wiki
icon: i-simple-icons-linux
to: https://wiki.nftables.org/
target: _blank
---
Official documentation for nftables, the modern Linux firewall framework replacing iptables. Provides superior performance and cleaner syntax.
::

::card
---
title: Mozilla SSL Config Generator
icon: i-simple-icons-mozilla
to: https://ssl-config.mozilla.org/
target: _blank
---
Generate secure SSL/TLS configurations for Nginx, Apache, HAProxy, and more. Choose between Modern, Intermediate, and Old compatibility profiles.
::

::card
---
title: Security Headers Scanner
icon: i-lucide-scan
to: https://securityheaders.com/
target: _blank
---
Free online tool to check your website's security headers. Grades from A+ to F with specific recommendations for missing or misconfigured headers.
::

::card
---
title: Qualys SSL Labs
icon: i-lucide-lock
to: https://www.ssllabs.com/ssltest/
target: _blank
---
Comprehensive SSL/TLS testing service. Tests cipher suites, protocol versions, certificate chain, and known vulnerabilities. Aim for Grade A+.
::

::card
---
title: auditd Documentation
icon: i-simple-icons-linux
to: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening
target: _blank
---
Red Hat's comprehensive guide to Linux Audit System. Covers rule creation, log analysis, and compliance reporting with auditd.
::

::card
---
title: AIDE (File Integrity)
icon: i-simple-icons-github
to: https://aide.github.io/
target: _blank
---
Advanced Intrusion Detection Environment. Monitors file system changes by creating a database of file checksums and alerting on modifications.
::

::