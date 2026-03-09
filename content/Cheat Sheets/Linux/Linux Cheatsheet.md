---
title: Linux Cheatsheet
description: Comprehensive Linux command reference covering Kali Linux, Ubuntu, CentOS, and Red Hat for penetration testers, sysadmins, and power users.
navigation:
  icon: i-lucide-terminal
---

## Overview

This cheatsheet provides an in-depth reference for essential Linux commands across four major distributions: **Kali Linux**, **Ubuntu**, **CentOS**, and **Red Hat Enterprise Linux (RHEL)**. It covers system administration, networking, package management, user management, file operations, process handling, and security-specific commands.

> Linux is the backbone of modern cybersecurity, cloud infrastructure, and server environments. Mastering these commands across distributions is essential for any IT professional.

---

## Distribution Overview

| Feature             | Kali Linux                  | Ubuntu                        | CentOS                        | Red Hat (RHEL)                |
| ------------------- | --------------------------- | ----------------------------- | ----------------------------- | ----------------------------- |
| **Base**            | Debian                      | Debian                        | RHEL                          | Independent (upstream)        |
| **Package Manager** | APT / dpkg                  | APT / dpkg                    | YUM / DNF / rpm               | YUM / DNF / rpm               |
| **Purpose**         | Penetration Testing         | General / Desktop / Server    | Enterprise Server             | Enterprise Server             |
| **Default Shell**   | Bash / Zsh                  | Bash                          | Bash                          | Bash                          |
| **Init System**     | systemd                     | systemd                       | systemd                       | systemd                       |
| **Release Cycle**   | Rolling                     | Fixed (LTS every 2 years)     | Fixed (mirrors RHEL)          | Fixed (10-year lifecycle)     |
| **Default User**    | root (legacy) / kali        | Non-root user                 | Non-root user                 | Non-root user                 |
| **Firewall**        | iptables / nftables         | ufw / iptables                | firewalld / iptables          | firewalld / iptables          |
| **SELinux**         | Not default                 | AppArmor (default)            | SELinux (default)             | SELinux (default)             |

---

## System Information

### Kernel and OS Details

::code-preview
---
class: "[&>div]:*:my-0"
---
Display kernel and OS information.

#code
```bash
# Kernel version
uname -a
uname -r

# OS release information
cat /etc/os-release
cat /etc/*release*

# Distribution-specific
# Ubuntu / Kali
lsb_release -a

# CentOS / RHEL
cat /etc/redhat-release
cat /etc/centos-release
```
::

### Hardware Information

::code-preview
---
class: "[&>div]:*:my-0"
---
Gather hardware details.

#code
```bash
# CPU information
lscpu
cat /proc/cpuinfo
nproc

# Memory information
free -h
cat /proc/meminfo

# Disk information
lsblk
fdisk -l
df -h

# PCI devices
lspci

# USB devices
lsusb

# Full hardware summary
lshw -short
dmidecode
```
::

### System Uptime and Load

::code-preview
---
class: "[&>div]:*:my-0"
---
Check system uptime and load.

#code
```bash
# Uptime
uptime

# Load average
cat /proc/loadavg

# Who is logged in
w
who
last
```
::

### Hostname

::code-preview
---
class: "[&>div]:*:my-0"
---
View and set hostname.

#code
```bash
# View hostname
hostname
hostnamectl

# Set hostname (all distros with systemd)
sudo hostnamectl set-hostname newhostname

# Temporary change
sudo hostname newhostname
```
::

---

## Package Management

### APT (Kali Linux / Ubuntu)

::code-preview
---
class: "[&>div]:*:my-0"
---
APT package management commands.

#code
```bash
# Update package lists
sudo apt update

# Upgrade all packages
sudo apt upgrade -y

# Full upgrade (handles dependencies)
sudo apt full-upgrade -y

# Install a package
sudo apt install <package-name> -y

# Remove a package
sudo apt remove <package-name> -y

# Remove with configuration files
sudo apt purge <package-name> -y

# Remove unused dependencies
sudo apt autoremove -y

# Search for a package
apt search <keyword>

# Show package details
apt show <package-name>

# List installed packages
apt list --installed

# List upgradable packages
apt list --upgradable

# Download package without installing
apt download <package-name>

# Clean local cache
sudo apt clean
sudo apt autoclean

# Fix broken dependencies
sudo apt --fix-broken install

# Add a PPA repository (Ubuntu)
sudo add-apt-repository ppa:<repository-name>
sudo apt update
```
::

### dpkg (Kali Linux / Ubuntu)

::code-preview
---
class: "[&>div]:*:my-0"
---
dpkg low-level package management.

#code
```bash
# Install .deb package
sudo dpkg -i package.deb

# Remove a package
sudo dpkg -r <package-name>

# Purge a package
sudo dpkg -P <package-name>

# List installed packages
dpkg -l

# Search installed packages
dpkg -l | grep <keyword>

# Show package info
dpkg -s <package-name>

# List files in a package
dpkg -L <package-name>

# Find which package owns a file
dpkg -S /path/to/file

# Reconfigure a package
sudo dpkg-reconfigure <package-name>

# Extract .deb without installing
dpkg -x package.deb /destination/

# Fix broken dpkg
sudo dpkg --configure -a
```
::

### YUM (CentOS 7 / RHEL 7)

::code-preview
---
class: "[&>div]:*:my-0"
---
YUM package management commands.

#code
```bash
# Update all packages
sudo yum update -y

# Install a package
sudo yum install <package-name> -y

# Remove a package
sudo yum remove <package-name> -y

# Search for a package
yum search <keyword>

# Show package info
yum info <package-name>

# List installed packages
yum list installed

# List available packages
yum list available

# List all repos
yum repolist

# Clean cache
sudo yum clean all

# Check for updates
yum check-update

# Install from local RPM
sudo yum localinstall package.rpm

# Group install
sudo yum groupinstall "Development Tools"

# History
yum history
yum history undo <id>
```
::

### DNF (CentOS 8+ / RHEL 8+)

::code-preview
---
class: "[&>div]:*:my-0"
---
DNF package management commands.

#code
```bash
# Update all packages
sudo dnf update -y

# Install a package
sudo dnf install <package-name> -y

# Remove a package
sudo dnf remove <package-name> -y

# Search for a package
dnf search <keyword>

# Show package info
dnf info <package-name>

# List installed packages
dnf list installed

# List repositories
dnf repolist

# Clean cache
sudo dnf clean all

# Automatic updates
sudo dnf install dnf-automatic -y
sudo systemctl enable --now dnf-automatic.timer

# Module management (RHEL 8+)
dnf module list
dnf module enable <module>:<stream>
dnf module install <module>:<stream>

# History
dnf history
dnf history undo <id>
```
::

### RPM (CentOS / RHEL)

::code-preview
---
class: "[&>div]:*:my-0"
---
RPM low-level package management.

#code
```bash
# Install RPM package
sudo rpm -ivh package.rpm

# Upgrade RPM package
sudo rpm -Uvh package.rpm

# Remove RPM package
sudo rpm -e <package-name>

# Query installed packages
rpm -qa

# Search installed packages
rpm -qa | grep <keyword>

# Package info
rpm -qi <package-name>

# List files in package
rpm -ql <package-name>

# Find which package owns a file
rpm -qf /path/to/file

# Verify package integrity
rpm -V <package-name>

# Import GPG key
sudo rpm --import /path/to/RPM-GPG-KEY
```
::

### Package Management Quick Reference

| Task                  | APT (Kali/Ubuntu)              | YUM/DNF (CentOS/RHEL)          |
| --------------------- | ------------------------------ | ------------------------------- |
| Update repos          | `apt update`                   | `yum check-update` / `dnf check-update` |
| Upgrade packages      | `apt upgrade`                  | `yum update` / `dnf update`    |
| Install               | `apt install pkg`              | `yum install pkg` / `dnf install pkg` |
| Remove                | `apt remove pkg`               | `yum remove pkg` / `dnf remove pkg` |
| Search                | `apt search keyword`           | `yum search keyword` / `dnf search keyword` |
| Info                  | `apt show pkg`                 | `yum info pkg` / `dnf info pkg` |
| List installed        | `apt list --installed`         | `yum list installed` / `dnf list installed` |
| Clean cache           | `apt clean`                    | `yum clean all` / `dnf clean all` |
| Install local         | `dpkg -i pkg.deb`              | `rpm -ivh pkg.rpm`             |

---

## User Management

### User Operations

::code-preview
---
class: "[&>div]:*:my-0"
---
Create, modify, and delete users.

#code
```bash
# Create new user
sudo useradd <username>

# Create user with home directory
sudo useradd -m <username>

# Create user with specific shell
sudo useradd -m -s /bin/bash <username>

# Create user with specific UID
sudo useradd -u 1500 <username>

# Create user and add to groups
sudo useradd -m -G sudo,docker <username>

# Ubuntu/Kali interactive user creation
sudo adduser <username>

# Set password
sudo passwd <username>

# Modify user
sudo usermod -aG sudo <username>          # Add to sudo group
sudo usermod -s /bin/zsh <username>        # Change shell
sudo usermod -l <newname> <oldname>        # Rename user
sudo usermod -d /new/home <username>       # Change home dir
sudo usermod -L <username>                 # Lock account
sudo usermod -U <username>                 # Unlock account

# Delete user
sudo userdel <username>
sudo userdel -r <username>                 # Delete with home directory

# View user info
id <username>
whoami
finger <username>
cat /etc/passwd | grep <username>
```
::

### Group Operations

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage groups.

#code
```bash
# Create group
sudo groupadd <groupname>

# Create group with specific GID
sudo groupadd -g 2000 <groupname>

# Delete group
sudo groupdel <groupname>

# Add user to group
sudo usermod -aG <groupname> <username>

# Remove user from group
sudo gpasswd -d <username> <groupname>

# List groups for a user
groups <username>
id <username>

# List all groups
cat /etc/group

# Change primary group
sudo usermod -g <groupname> <username>
```
::

### Sudo Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure sudo access.

#code
```bash
# Edit sudoers file safely
sudo visudo

# Add user to sudo group
# Ubuntu / Kali
sudo usermod -aG sudo <username>

# CentOS / RHEL
sudo usermod -aG wheel <username>

# Allow passwordless sudo (add to /etc/sudoers)
# username ALL=(ALL) NOPASSWD: ALL

# Check sudo permissions
sudo -l
sudo -l -U <username>

# Run command as another user
sudo -u <username> <command>

# Switch to root
sudo su -
sudo -i
```
::

### Password Policy

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage password policies.

#code
```bash
# View password aging info
chage -l <username>

# Set password expiry (90 days)
sudo chage -M 90 <username>

# Force password change on next login
sudo chage -d 0 <username>

# Set minimum days between changes
sudo chage -m 7 <username>

# Set warning days before expiry
sudo chage -W 14 <username>

# Lock/Expire account
sudo chage -E 2024-12-31 <username>

# Password policy files
cat /etc/login.defs
cat /etc/pam.d/common-password     # Ubuntu/Kali
cat /etc/pam.d/system-auth         # CentOS/RHEL
```
::

---

## File and Directory Operations

### Basic File Operations

::code-preview
---
class: "[&>div]:*:my-0"
---
Essential file commands.

#code
```bash
# List files
ls
ls -la                    # Detailed with hidden
ls -lah                   # Human-readable sizes
ls -ltr                   # Sort by time (oldest first)
ls -lS                    # Sort by size

# Create directory
mkdir dirname
mkdir -p parent/child/grandchild      # Nested directories

# Copy
cp source destination
cp -r sourcedir destdir               # Recursive copy
cp -p source dest                     # Preserve permissions
cp -a source dest                     # Archive (preserve everything)

# Move / Rename
mv oldname newname
mv file /destination/

# Remove
rm file
rm -rf directory                      # Force recursive delete
rm -i file                            # Interactive (confirm)

# Create symbolic link
ln -s /path/to/target linkname

# Create hard link
ln /path/to/target linkname
```
::

### File Permissions

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage file permissions and ownership.

#code
```bash
# Change permissions (numeric)
chmod 755 file
chmod 644 file
chmod 600 file
chmod 777 file

# Change permissions (symbolic)
chmod u+x file                        # Add execute for owner
chmod g+w file                        # Add write for group
chmod o-r file                        # Remove read for others
chmod a+r file                        # Add read for all

# Recursive
chmod -R 755 directory

# Change ownership
chown user:group file
chown -R user:group directory

# Change group only
chgrp groupname file

# Set SUID
chmod u+s file
chmod 4755 file

# Set SGID
chmod g+s directory
chmod 2755 directory

# Set Sticky Bit
chmod +t directory
chmod 1755 directory

# View permissions
ls -la
stat file
```
::

### Permission Reference

| Permission | Numeric | Symbolic | Description              |
| ---------- | ------- | -------- | ------------------------ |
| Read       | 4       | r        | View file contents       |
| Write      | 2       | w        | Modify file contents     |
| Execute    | 1       | x        | Execute file / enter dir |
| SUID       | 4000    | s (user) | Execute as file owner    |
| SGID       | 2000    | s (group)| Execute as file group    |
| Sticky     | 1000    | t        | Only owner can delete    |

### Common Permission Combinations

| Numeric | Symbolic      | Use Case                      |
| ------- | ------------- | ----------------------------- |
| `755`   | `rwxr-xr-x`  | Directories, scripts          |
| `644`   | `rw-r--r--`  | Regular files                 |
| `600`   | `rw-------`  | Private files, SSH keys       |
| `700`   | `rwx------`  | Private directories           |
| `777`   | `rwxrwxrwx`  | Full access (avoid)           |
| `4755`  | `rwsr-xr-x`  | SUID executables              |
| `2755`  | `rwxr-sr-x`  | SGID directories              |
| `1777`  | `rwxrwxrwt`  | Shared directories (/tmp)     |

### File Search

::code-preview
---
class: "[&>div]:*:my-0"
---
Find files on the system.

#code
```bash
# Find by name
find / -name "filename" 2>/dev/null
find / -iname "filename" 2>/dev/null       # Case-insensitive

# Find by type
find / -type f -name "*.conf" 2>/dev/null  # Files
find / -type d -name "logs" 2>/dev/null    # Directories
find / -type l 2>/dev/null                 # Symlinks

# Find by permission
find / -perm -4000 2>/dev/null             # SUID files
find / -perm -2000 2>/dev/null             # SGID files
find / -perm -o+w 2>/dev/null              # World-writable

# Find by owner
find / -user root 2>/dev/null
find / -group admin 2>/dev/null
find / -nouser 2>/dev/null                 # No owner

# Find by size
find / -size +100M 2>/dev/null             # Larger than 100MB
find / -size -1k 2>/dev/null               # Smaller than 1KB

# Find by time
find / -mtime -7 2>/dev/null               # Modified in last 7 days
find / -atime +30 2>/dev/null              # Accessed more than 30 days ago
find / -ctime -1 2>/dev/null               # Changed in last 24 hours
find / -newer reference_file 2>/dev/null

# Find and execute
find / -name "*.log" -exec rm {} \;
find / -name "*.sh" -exec chmod +x {} \;
find / -name "*.txt" -exec grep -l "password" {} \;

# Locate (fast, uses database)
locate filename
sudo updatedb                              # Update locate database

# Which / Whereis
which python3
whereis nmap
```
::

### Text Processing

::code-preview
---
class: "[&>div]:*:my-0"
---
Process and manipulate text files.

#code
```bash
# View file content
cat file
less file
more file
head -n 20 file                  # First 20 lines
tail -n 20 file                  # Last 20 lines
tail -f file                     # Follow file changes (live)

# Search inside files
grep "pattern" file
grep -r "pattern" /directory/    # Recursive
grep -i "pattern" file           # Case-insensitive
grep -n "pattern" file           # Show line numbers
grep -v "pattern" file           # Invert match
grep -c "pattern" file           # Count matches
grep -l "pattern" *.txt          # List matching files
grep -E "regex" file             # Extended regex
grep -o "pattern" file           # Only matching part
grep -A 3 "pattern" file         # 3 lines after match
grep -B 3 "pattern" file         # 3 lines before match

# awk
awk '{print $1}' file            # Print first column
awk -F: '{print $1}' /etc/passwd # Custom delimiter
awk '{print NR, $0}' file        # Line numbers
awk '/pattern/ {print}' file     # Pattern matching

# sed
sed 's/old/new/g' file           # Replace all occurrences
sed -i 's/old/new/g' file        # In-place replacement
sed -n '5,10p' file              # Print lines 5-10
sed '/pattern/d' file            # Delete matching lines
sed '1i\Header' file             # Insert at beginning

# cut
cut -d: -f1 /etc/passwd          # Cut by delimiter
cut -c1-10 file                  # Cut by character position

# sort
sort file                        # Alphabetical sort
sort -n file                     # Numeric sort
sort -r file                     # Reverse sort
sort -u file                     # Unique sort
sort -t: -k3 -n /etc/passwd      # Sort by field

# uniq
sort file | uniq                 # Remove duplicates
sort file | uniq -c              # Count occurrences
sort file | uniq -d              # Show only duplicates

# wc
wc -l file                      # Count lines
wc -w file                      # Count words
wc -c file                      # Count bytes
wc -m file                      # Count characters

# tr
echo "HELLO" | tr 'A-Z' 'a-z'   # Convert to lowercase
echo "hello" | tr 'a-z' 'A-Z'   # Convert to uppercase
cat file | tr -d '\r'            # Remove carriage returns
cat file | tr -s ' '             # Squeeze spaces

# diff
diff file1 file2
diff -u file1 file2              # Unified format
diff -r dir1 dir2                # Compare directories
```
::

### File Compression and Archives

::code-preview
---
class: "[&>div]:*:my-0"
---
Compress and extract files.

#code
```bash
# tar
tar -cvf archive.tar files/            # Create tar
tar -xvf archive.tar                    # Extract tar
tar -czvf archive.tar.gz files/         # Create gzipped tar
tar -xzvf archive.tar.gz               # Extract gzipped tar
tar -cjvf archive.tar.bz2 files/       # Create bzip2 tar
tar -xjvf archive.tar.bz2             # Extract bzip2 tar
tar -tvf archive.tar                    # List contents

# gzip
gzip file                              # Compress
gunzip file.gz                         # Decompress
gzip -k file                           # Keep original
gzip -d file.gz                        # Decompress

# zip
zip archive.zip files
zip -r archive.zip directory/           # Recursive
zip -e archive.zip files                # Encrypt with password
unzip archive.zip
unzip -l archive.zip                    # List contents
unzip archive.zip -d /destination/

# 7zip
7z a archive.7z files
7z x archive.7z
7z l archive.7z                         # List contents

# xz
xz file
unxz file.xz
xz -d file.xz
```
::

---

## Networking

### Network Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
View and configure network interfaces.

#code
```bash
# IP address information
ip addr show
ip a
ifconfig                              # Legacy

# Specific interface
ip addr show eth0
ifconfig eth0

# Enable/Disable interface
sudo ip link set eth0 up
sudo ip link set eth0 down
sudo ifconfig eth0 up                 # Legacy
sudo ifconfig eth0 down               # Legacy

# Set static IP
sudo ip addr add 192.168.1.100/24 dev eth0

# Set default gateway
sudo ip route add default via 192.168.1.1

# View routing table
ip route show
route -n                              # Legacy
netstat -rn                           # Legacy

# DNS configuration
cat /etc/resolv.conf
systemd-resolve --status              # Ubuntu
resolvectl status                     # Ubuntu 20.04+

# MAC address
ip link show
macchanger -s eth0                    # Show MAC
sudo macchanger -r eth0              # Random MAC
sudo macchanger -m XX:XX:XX:XX:XX:XX eth0  # Set MAC
```
::

### Network Configuration Files

| File / Path                              | Distro        | Purpose                    |
| ---------------------------------------- | ------------- | -------------------------- |
| `/etc/network/interfaces`                | Kali / Ubuntu | Network interface config   |
| `/etc/netplan/*.yaml`                    | Ubuntu 18.04+ | Netplan configuration      |
| `/etc/sysconfig/network-scripts/ifcfg-*` | CentOS / RHEL | Interface configuration    |
| `/etc/NetworkManager/`                   | All           | NetworkManager config      |
| `/etc/resolv.conf`                       | All           | DNS resolver               |
| `/etc/hosts`                             | All           | Static hostname mappings   |
| `/etc/hostname`                          | All           | System hostname            |

### Network Diagnostics

::code-preview
---
class: "[&>div]:*:my-0"
---
Diagnose network issues.

#code
```bash
# Ping
ping -c 4 <target>
ping6 <ipv6-target>

# Traceroute
traceroute <target>
tracepath <target>

# DNS lookup
nslookup <domain>
dig <domain>
dig <domain> ANY
dig @8.8.8.8 <domain>
host <domain>

# Reverse DNS
dig -x <ip-address>
nslookup <ip-address>

# Test port connectivity
nc -zv <target> <port>
telnet <target> <port>

# Test HTTP
curl -I http://<target>
wget --spider http://<target>

# ARP table
arp -a
ip neigh show

# Network statistics
ss -tulnp                             # Modern
netstat -tulnp                         # Legacy

# Active connections
ss -t                                  # TCP connections
ss -u                                  # UDP connections
ss -l                                  # Listening sockets
ss -p                                  # Show process
ss -s                                  # Statistics summary
```
::

### Port and Connection Analysis

::code-preview
---
class: "[&>div]:*:my-0"
---
Analyze open ports and connections.

#code
```bash
# List all listening ports
ss -tulnp
netstat -tulnp

# List established connections
ss -t state established
netstat -an | grep ESTABLISHED

# Find process using specific port
ss -tulnp | grep :<port>
lsof -i :<port>
fuser <port>/tcp

# Kill process on a port
fuser -k <port>/tcp

# All network connections by process
lsof -i -P -n

# Watch connections in real-time
watch -n 1 'ss -tulnp'
```
::

### Firewall Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure firewalls across distributions.

#code
```bash
# ============ UFW (Ubuntu / Kali) ============
sudo ufw status
sudo ufw status verbose
sudo ufw enable
sudo ufw disable
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw deny 23/tcp
sudo ufw allow from 192.168.1.0/24
sudo ufw delete allow 80/tcp
sudo ufw reset
sudo ufw logging on

# ============ firewalld (CentOS / RHEL) ============
sudo systemctl start firewalld
sudo systemctl enable firewalld
sudo firewall-cmd --state
sudo firewall-cmd --list-all
sudo firewall-cmd --zone=public --list-ports
sudo firewall-cmd --zone=public --add-port=80/tcp --permanent
sudo firewall-cmd --zone=public --add-service=http --permanent
sudo firewall-cmd --zone=public --remove-port=80/tcp --permanent
sudo firewall-cmd --reload
sudo firewall-cmd --list-services
sudo firewall-cmd --get-zones

# ============ iptables (All Distros) ============
sudo iptables -L -n -v
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -j DROP
sudo iptables -D INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -F                        # Flush all rules
sudo iptables-save > /etc/iptables.rules
sudo iptables-restore < /etc/iptables.rules

# ============ nftables (Modern Replacement) ============
sudo nft list ruleset
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0 \; }
sudo nft add rule inet filter input tcp dport 22 accept
sudo nft add rule inet filter input drop
```
::

### Firewall Comparison

| Task              | UFW (Ubuntu/Kali)            | firewalld (CentOS/RHEL)                           | iptables (All)                          |
| ----------------- | ---------------------------- | -------------------------------------------------- | --------------------------------------- |
| Enable            | `ufw enable`                 | `systemctl start firewalld`                        | N/A (rules applied instantly)           |
| Status            | `ufw status`                 | `firewall-cmd --state`                             | `iptables -L`                           |
| Allow port        | `ufw allow 80/tcp`           | `firewall-cmd --add-port=80/tcp --permanent`       | `iptables -A INPUT -p tcp --dport 80 -j ACCEPT` |
| Block port        | `ufw deny 23/tcp`            | `firewall-cmd --remove-port=23/tcp --permanent`    | `iptables -A INPUT -p tcp --dport 23 -j DROP` |
| Reload            | N/A                          | `firewall-cmd --reload`                            | `iptables-restore`                      |

---

## Service Management (systemd)

All four distributions use **systemd** as the default init system.

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage services with systemctl.

#code
```bash
# Start / Stop / Restart
sudo systemctl start <service>
sudo systemctl stop <service>
sudo systemctl restart <service>
sudo systemctl reload <service>

# Enable / Disable on boot
sudo systemctl enable <service>
sudo systemctl disable <service>
sudo systemctl enable --now <service>    # Enable and start

# Status
sudo systemctl status <service>
sudo systemctl is-active <service>
sudo systemctl is-enabled <service>

# List all services
systemctl list-units --type=service
systemctl list-units --type=service --state=running
systemctl list-units --type=service --state=failed

# Mask / Unmask (prevent starting)
sudo systemctl mask <service>
sudo systemctl unmask <service>

# View logs for a service
journalctl -u <service>
journalctl -u <service> -f              # Follow
journalctl -u <service> --since today
journalctl -u <service> --since "1 hour ago"

# Reload systemd daemon
sudo systemctl daemon-reload

# System control
sudo systemctl reboot
sudo systemctl poweroff
sudo systemctl suspend
```
::

### Common Services

| Service         | Name                    | Default Port |
| --------------- | ----------------------- | ------------ |
| SSH             | `sshd`                  | 22           |
| Apache          | `apache2` / `httpd`     | 80/443       |
| Nginx           | `nginx`                 | 80/443       |
| MySQL           | `mysql` / `mysqld`      | 3306         |
| PostgreSQL      | `postgresql`            | 5432         |
| Firewall        | `ufw` / `firewalld`     | N/A          |
| Docker          | `docker`                | N/A          |
| NetworkManager  | `NetworkManager`        | N/A          |
| Cron            | `cron` / `crond`        | N/A          |
| DNS             | `named` / `bind9`       | 53           |

---

## Process Management

::code-preview
---
class: "[&>div]:*:my-0"
---
View and manage processes.

#code
```bash
# List processes
ps aux
ps -ef
ps aux --sort=-%mem                   # Sort by memory
ps aux --sort=-%cpu                   # Sort by CPU
ps -eo pid,user,%cpu,%mem,cmd --sort=-%cpu

# Process tree
pstree
pstree -p                             # Show PIDs

# Interactive process viewer
top
htop                                   # Enhanced (install separately)

# Find specific process
ps aux | grep <process-name>
pgrep <process-name>
pgrep -a <process-name>               # Show full command
pidof <process-name>

# Kill processes
kill <PID>
kill -9 <PID>                         # Force kill
kill -15 <PID>                        # Graceful termination
killall <process-name>
pkill <process-name>
pkill -u <username>                   # Kill all user processes

# Background / Foreground
command &                              # Run in background
jobs                                   # List background jobs
fg %1                                  # Bring to foreground
bg %1                                  # Send to background
disown %1                              # Detach from terminal
nohup command &                        # Persist after logout

# Nice / Priority
nice -n 10 command                    # Start with lower priority
renice -n 5 -p <PID>                 # Change priority
renice -n -5 -p <PID>               # Higher priority (root)

# Resource usage
/usr/bin/time -v command              # Detailed resource usage
```
::

---

## Disk Management

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage disks, partitions, and filesystems.

#code
```bash
# Disk usage
df -h                                 # Filesystem usage
df -i                                 # Inode usage
du -sh /path/                         # Directory size
du -sh /path/* | sort -hr             # Sorted directory sizes
du -ah /path/ | sort -rh | head -20   # Top 20 largest

# List block devices
lsblk
lsblk -f                              # Show filesystems
blkid                                 # Show UUIDs

# Partition management
sudo fdisk -l                          # List partitions
sudo fdisk /dev/sda                   # Interactive partitioning
sudo parted /dev/sda print            # View with parted
sudo cfdisk /dev/sda                  # TUI partitioning

# Mount / Unmount
sudo mount /dev/sda1 /mnt
sudo mount -t ntfs /dev/sdb1 /mnt     # Specific filesystem
sudo umount /mnt
mount | column -t                      # View mounted filesystems

# Permanent mount (fstab)
sudo nano /etc/fstab
# /dev/sda1  /mnt  ext4  defaults  0  2

# Filesystem creation
sudo mkfs.ext4 /dev/sda1
sudo mkfs.xfs /dev/sda1
sudo mkfs.ntfs /dev/sda1

# Filesystem check
sudo fsck /dev/sda1
sudo e2fsck -f /dev/sda1

# Swap
sudo mkswap /dev/sda2
sudo swapon /dev/sda2
sudo swapoff /dev/sda2
swapon --show
free -h
```
::

---

## Log Management

::code-preview
---
class: "[&>div]:*:my-0"
---
View and manage system logs.

#code
```bash
# journalctl (systemd)
journalctl                            # All logs
journalctl -f                         # Follow (live)
journalctl -b                         # Current boot
journalctl -b -1                      # Previous boot
journalctl --since today
journalctl --since "2024-01-01" --until "2024-01-02"
journalctl -p err                     # Errors only
journalctl -p crit                    # Critical only
journalctl -u sshd                    # Specific service
journalctl --disk-usage               # Log disk usage
sudo journalctl --vacuum-size=500M    # Clean old logs

# Traditional log files
tail -f /var/log/syslog               # Ubuntu / Kali
tail -f /var/log/messages             # CentOS / RHEL
tail -f /var/log/auth.log             # Ubuntu / Kali (auth)
tail -f /var/log/secure               # CentOS / RHEL (auth)
tail -f /var/log/kern.log             # Kernel logs
tail -f /var/log/dmesg                # Boot messages
tail -f /var/log/apache2/error.log    # Apache (Ubuntu)
tail -f /var/log/httpd/error_log      # Apache (CentOS)
tail -f /var/log/nginx/error.log      # Nginx

# dmesg
dmesg
dmesg | tail -20
dmesg -T                              # Human-readable timestamps
dmesg --level=err
```
::

### Important Log File Locations

| Log File                        | Distro           | Purpose                        |
| ------------------------------- | ---------------- | ------------------------------ |
| `/var/log/syslog`               | Ubuntu / Kali    | General system log             |
| `/var/log/messages`             | CentOS / RHEL    | General system log             |
| `/var/log/auth.log`             | Ubuntu / Kali    | Authentication logs            |
| `/var/log/secure`               | CentOS / RHEL    | Authentication logs            |
| `/var/log/kern.log`             | All              | Kernel messages                |
| `/var/log/dmesg`                | All              | Boot messages                  |
| `/var/log/cron`                 | CentOS / RHEL    | Cron job logs                  |
| `/var/log/boot.log`             | All              | Boot process log               |
| `/var/log/faillog`              | All              | Failed login attempts          |
| `/var/log/lastlog`              | All              | Last login information         |
| `/var/log/wtmp`                 | All              | Login records                  |
| `/var/log/btmp`                 | All              | Bad login attempts             |
| `/var/log/apache2/`             | Ubuntu / Kali    | Apache web server logs         |
| `/var/log/httpd/`               | CentOS / RHEL    | Apache web server logs         |
| `/var/log/nginx/`               | All              | Nginx web server logs          |
| `/var/log/audit/audit.log`      | CentOS / RHEL    | SELinux audit logs             |

---

## Cron Jobs and Scheduling

::code-preview
---
class: "[&>div]:*:my-0"
---
Schedule tasks with cron.

#code
```bash
# Edit user crontab
crontab -e

# List cron jobs
crontab -l

# List cron for specific user
sudo crontab -u <username> -l

# Remove all cron jobs
crontab -r

# Cron directories
ls /etc/cron.d/
ls /etc/cron.daily/
ls /etc/cron.hourly/
ls /etc/cron.weekly/
ls /etc/cron.monthly/

# System crontab
cat /etc/crontab
```
::

### Cron Syntax Reference

| Field        | Values        | Special Characters     |
| ------------ | ------------- | ---------------------- |
| Minute       | 0-59          | `*` `,` `-` `/`       |
| Hour         | 0-23          | `*` `,` `-` `/`       |
| Day of Month | 1-31          | `*` `,` `-` `/`       |
| Month        | 1-12          | `*` `,` `-` `/`       |
| Day of Week  | 0-7 (0,7=Sun) | `*` `,` `-` `/`       |

### Common Cron Examples

| Schedule                 | Expression          |
| ------------------------ | ------------------- |
| Every minute             | `* * * * *`         |
| Every 5 minutes          | `*/5 * * * *`       |
| Every hour               | `0 * * * *`         |
| Every day at midnight    | `0 0 * * *`         |
| Every Monday at 9 AM     | `0 9 * * 1`         |
| Every 1st of month       | `0 0 1 * *`         |
| Every weekday at 6 PM    | `0 18 * * 1-5`      |
| Twice a day (6AM, 6PM)   | `0 6,18 * * *`      |
| Every Sunday at 2:30 AM  | `30 2 * * 0`        |

---

## SSH Configuration

::code-preview
---
class: "[&>div]:*:my-0"
---
Configure and use SSH.

#code
```bash
# Generate SSH key pair
ssh-keygen -t rsa -b 4096
ssh-keygen -t ed25519

# Copy public key to server
ssh-copy-id user@<target-ip>

# Connect to remote host
ssh user@<target-ip>
ssh -p 2222 user@<target-ip>          # Custom port
ssh -i /path/to/key user@<target-ip>  # Specific key

# SSH tunneling
ssh -L 8080:localhost:80 user@<target-ip>    # Local forward
ssh -R 8080:localhost:80 user@<target-ip>    # Remote forward
ssh -D 9050 user@<target-ip>                  # SOCKS proxy

# SCP file transfer
scp file user@<target-ip>:/path/
scp user@<target-ip>:/path/file .
scp -r directory user@<target-ip>:/path/

# SFTP
sftp user@<target-ip>

# SSH configuration file
cat ~/.ssh/config
# Host myserver
#     HostName 192.168.1.100
#     User admin
#     Port 22
#     IdentityFile ~/.ssh/id_rsa

# SSH server configuration
sudo nano /etc/ssh/sshd_config
sudo systemctl restart sshd
```
::

### SSH Hardening Configuration

| Setting                     | Recommended Value     | Purpose                      |
| --------------------------- | --------------------- | ---------------------------- |
| `PermitRootLogin`           | `no`                  | Disable root SSH login       |
| `PasswordAuthentication`    | `no`                  | Force key-based auth         |
| `PubkeyAuthentication`      | `yes`                 | Enable key-based auth        |
| `MaxAuthTries`              | `3`                   | Limit login attempts         |
| `Port`                      | Non-standard          | Change default port          |
| `AllowUsers`                | Specific users        | Restrict SSH access          |
| `Protocol`                  | `2`                   | Use SSH protocol 2 only      |
| `X11Forwarding`             | `no`                  | Disable X11 forwarding       |
| `PermitEmptyPasswords`      | `no`                  | Disallow empty passwords     |
| `ClientAliveInterval`       | `300`                 | Timeout idle sessions        |

---

## SELinux (CentOS / RHEL)

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage SELinux security.

#code
```bash
# Check SELinux status
getenforce
sestatus

# Set SELinux mode
sudo setenforce 0                      # Permissive (temporary)
sudo setenforce 1                      # Enforcing (temporary)

# Permanent change
sudo nano /etc/selinux/config
# SELINUX=enforcing|permissive|disabled

# View file context
ls -Z /path/to/file

# Restore default context
sudo restorecon -Rv /path/

# Change file context
sudo chcon -t httpd_sys_content_t /var/www/html/

# Boolean management
getsebool -a
sudo setsebool -P httpd_can_network_connect on

# Troubleshooting
sudo ausearch -m avc --ts recent
sudo sealert -a /var/log/audit/audit.log
```
::

## AppArmor (Ubuntu / Kali)

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage AppArmor security.

#code
```bash
# Check AppArmor status
sudo apparmor_status
sudo aa-status

# Set profile to complain mode
sudo aa-complain /path/to/binary

# Set profile to enforce mode
sudo aa-enforce /path/to/binary

# Disable a profile
sudo ln -s /etc/apparmor.d/profile /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/profile

# Reload profiles
sudo systemctl reload apparmor
```
::

---

## Environment Variables

::code-preview
---
class: "[&>div]:*:my-0"
---
Manage environment variables.

#code
```bash
# View all variables
env
printenv
set

# View specific variable
echo $PATH
echo $HOME
echo $USER
echo $SHELL

# Set variable (current session)
export MYVAR="value"
export PATH=$PATH:/new/path

# Persistent variables
# User level
echo 'export MYVAR="value"' >> ~/.bashrc
echo 'export MYVAR="value"' >> ~/.bash_profile
source ~/.bashrc

# System level
sudo nano /etc/environment
sudo nano /etc/profile
sudo nano /etc/profile.d/custom.sh

# Unset variable
unset MYVAR
```
::

### Important Environment Files

| File                      | Scope          | When Loaded                |
| ------------------------- | -------------- | -------------------------- |
| `~/.bashrc`               | User           | Non-login interactive shell |
| `~/.bash_profile`         | User           | Login shell                |
| `~/.profile`              | User           | Login shell (if no .bash_profile) |
| `~/.bash_logout`          | User           | On logout                  |
| `/etc/environment`        | System-wide    | All users on login         |
| `/etc/profile`            | System-wide    | All login shells           |
| `/etc/profile.d/*.sh`     | System-wide    | All login shells           |
| `/etc/bash.bashrc`        | System-wide    | All interactive shells     |

---

## Useful One-Liners

::code-preview
---
class: "[&>div]:*:my-0"
---
Handy one-liner commands.

#code
```bash
# Find largest files on system
find / -type f -exec du -h {} + 2>/dev/null | sort -rh | head -20

# Find recently modified files (last 24 hours)
find / -type f -mtime -1 2>/dev/null

# Count files in directory recursively
find /path -type f | wc -l

# Get external IP
curl ifconfig.me
curl icanhazip.com
wget -qO- ifconfig.me

# Check all listening ports
ss -tulnp | grep LISTEN

# Monitor file changes in real-time
inotifywait -m -r /path/to/watch

# Generate random password
openssl rand -base64 32
cat /dev/urandom | tr -dc 'a-zA-Z0-9!@#$%' | fold -w 20 | head -1

# Base64 encode/decode
echo "text" | base64
echo "dGV4dAo=" | base64 -d

# Hex encode/decode
echo "text" | xxd
echo "74657874" | xxd -r -p

# Quick HTTP server
python3 -m http.server 8080

# Download file
wget http://url/file
curl -O http://url/file

# System resource snapshot
echo "=== CPU ===" && top -bn1 | head -5 && echo "=== MEM ===" && free -h && echo "=== DISK ===" && df -h
```
::

---

## References

- [Linux man pages](https://man7.org/linux/man-pages/)
- [Ubuntu Documentation](https://help.ubuntu.com/)
- [Red Hat Documentation](https://access.redhat.com/documentation/)
- [CentOS Documentation](https://docs.centos.org/)
- [Kali Linux Documentation](https://www.kali.org/docs/)
- [The Linux Command Line (Book)](https://linuxcommand.org/tlcl.php)
- [DigitalOcean Tutorials](https://www.digitalocean.com/community/tutorials)
- [Arch Wiki](https://wiki.archlinux.org/)
- [SS64 Bash Reference](https://ss64.com/bash/)
- [HackTricks Linux Hardening](https://book.hacktricks.xyz/)

::tip
Mastering commands across multiple distributions makes you adaptable in any environment — from **penetration testing** to **enterprise system administration** to **cloud infrastructure management**.
::
:::