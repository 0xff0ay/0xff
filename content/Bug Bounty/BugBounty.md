---
title: Bug Bounty Mindset 
description: What is Bug Bounty, how Bug Hunters think, the mindset, methodology, ideas, learning resources, and top YouTube channels to master the craft.
navigation:
  icon: i-lucide-bug
---

## What is Bug Bounty?

::card
---
icon: i-lucide-info
title: Bug Bounty Defined
---
A **Bug Bounty Program** is a deal offered by organizations, websites, and software developers that invites **ethical hackers (security researchers)** to discover and report vulnerabilities in their systems — in exchange for **monetary rewards, recognition, or both**. Instead of waiting for malicious hackers to exploit flaws, companies **pay good hackers** to find them first. It's a **win-win** — the company gets safer, and the hunter gets paid.
::

::callout
---
icon: i-lucide-lightbulb
color: primary
---
Bug Bounty is not just about technical skills — it's **80% mindset, curiosity, and persistence** and **20% technical execution**. The best hunters don't just scan — they **think**, **question**, and **explore** like detectives.
::

### How Bug Bounty Works

::steps{level="4"}

#### Company Creates a Program

```text
The organization defines:
─────────────────────────────────────────
→ Scope: What assets you CAN test (domains, apps, APIs)
→ Out of Scope: What you CANNOT test
→ Rules of Engagement: What methods are allowed
→ Reward Table: How much each vulnerability type pays
→ Safe Harbor: Legal protection for researchers
```

#### Hunter Finds a Vulnerability

```text
The researcher:
─────────────────────────────────────────
→ Reads the program scope and rules carefully
→ Performs reconnaissance and enumeration
→ Tests the application for vulnerabilities
→ Discovers a valid security issue
→ Verifies the impact and reproducibility
```

#### Hunter Submits a Report

```text
A quality report includes:
─────────────────────────────────────────
→ Clear title describing the vulnerability
→ Affected asset (URL, endpoint, parameter)
→ Step-by-step reproduction instructions
→ Proof of Concept (screenshots, video, code)
→ Impact assessment (what an attacker could do)
→ Suggested remediation
```

#### Company Triages & Rewards

```text
The company:
─────────────────────────────────────────
→ Reviews the report
→ Validates the vulnerability
→ Assigns severity (Critical, High, Medium, Low)
→ Fixes the vulnerability
→ Pays the bounty reward
→ Publicly acknowledges the researcher (Hall of Fame)
```

::

### Bug Bounty Reward Ranges

::collapsible

| Severity | CVSS Range | Typical Reward | Examples |
|----------|-----------|----------------|----------|
| **Critical** | 9.0 – 10.0 | $5,000 – $100,000+ | RCE, Auth Bypass, SQLi → full DB dump, Account Takeover (mass) |
| **High** | 7.0 – 8.9 | $1,000 – $15,000 | Stored XSS on admin, IDOR leaking PII, SSRF to internal services |
| **Medium** | 4.0 – 6.9 | $250 – $3,000 | Reflected XSS, CSRF on sensitive action, Information Disclosure |
| **Low** | 0.1 – 3.9 | $50 – $500 | Self-XSS, Missing headers, Verbose errors, Open redirect (limited) |
| **Informational** | 0.0 | $0 – $100 | Best practices, No direct security impact |

::

---

## The Bug Bounty Platforms

::card-group
  ::card
  ---
  icon: i-simple-icons-hackerone
  title: HackerOne
  to: https://hackerone.com
  target: _blank
  ---
  The **largest** bug bounty platform. Hosts programs for **US DoD, GitHub, Shopify, PayPal, Twitter/X, Coinbase**, and thousands more. Great for beginners with public programs and CTF-style challenges.
  ::

  ::card
  ---
  icon: i-simple-icons-bugcrowd
  title: Bugcrowd
  to: https://bugcrowd.com
  target: _blank
  ---
  Second largest platform. Hosts programs for **Mastercard, Tesla, Twitch, Pinterest, Atlassian**. Known for VRT (Vulnerability Rating Taxonomy) and researcher-friendly triage.
  ::

  ::card
  ---
  icon: i-lucide-shield
  title: Intigriti
  to: https://intigriti.com
  target: _blank
  ---
  European-based platform. Growing rapidly with programs for **Coca-Cola, Nokia, Deloitte**. Known for excellent researcher community and monthly challenges.
  ::

  ::card
  ---
  icon: i-lucide-trophy
  title: YesWeHack
  to: https://yeswehack.com
  target: _blank
  ---
  Europe's leading platform. Programs for **French government, OVH, La Poste**. Strong focus on compliance and GDPR-aware bounty hunting.
  ::

  ::card
  ---
  icon: i-lucide-code
  title: Open Bug Bounty
  to: https://openbugbounty.org
  target: _blank
  ---
  **Non-profit** platform focused on responsible disclosure. No registration required. Good for beginners to practice reporting XSS and other web vulnerabilities.
  ::

  ::card
  ---
  icon: i-lucide-globe
  title: Independent Programs
  to: https://github.com/projectdiscovery/public-bugbounty-programs
  target: _blank
  ---
  Many companies run **their own** bug bounty programs (Google, Apple, Microsoft, Facebook). Check `/security`, `/.well-known/security.txt`, or search "`company name` bug bounty."
  ::
::

---

## Bug Hunter Thinking — The Core Philosophy

::callout
---
icon: i-lucide-brain
color: primary
---
The difference between a **beginner** and a **top hunter** isn't tools — it's **how they think**. Bug hunting is a **creative, investigative process**. You must think like a **detective**, a **developer**, and an **attacker** simultaneously.
::

### The Three Thinking Modes

::card-group
  ::card
  ---
  icon: i-lucide-search
  title: "🔍 Detective Thinking"
  color: blue
  ---
  **"What is this application hiding?"**

  - Read the source code like a novel
  - Question every assumption the developer made
  - Look for what's **NOT** there — missing validation, missing auth checks, missing rate limits
  - Follow the data flow — where does user input go?
  - Ask: *"What happens if I do something the developer didn't expect?"*
  ::

  ::card
  ---
  icon: i-lucide-code
  title: "💻 Developer Thinking"
  color: green
  ---
  **"How would I have built this — and where would I have made mistakes?"**

  - Understand the technology stack (framework, language, database)
  - Think about common coding mistakes for that specific technology
  - Know how authentication/authorization is typically implemented
  - Understand API design patterns and where they break
  - Ask: *"If I were building this under a deadline, what would I skip?"*
  ::

  ::card
  ---
  icon: i-lucide-skull
  title: "☠️ Attacker Thinking"
  color: red
  ---
  **"How can I abuse this functionality to do something it wasn't designed to do?"**

  - Every feature is an attack surface
  - Every input is a potential injection point
  - Every trust boundary is a potential bypass
  - Every business logic assumption can be violated
  - Ask: *"What's the worst thing I could do with this access?"*
  ::
::

### The 10 Golden Questions Every Bug Hunter Asks

::accordion
  :::accordion-item
  ---
  icon: i-lucide-help-circle
  label: "1. What does this application DO?"
  ---
  Before hacking anything, **understand the application completely**. Use it like a normal user. Sign up, create content, make purchases, interact with every feature. You cannot break what you don't understand.

  ```text
  Map out:
  ─────────────────────────────────────────
  → What are ALL the features?
  → What user roles exist? (admin, user, guest, moderator)
  → What data does it handle? (PII, financial, health?)
  → What APIs does it expose?
  → What third-party integrations exist?
  → What's the tech stack?
  → Where does it store data?
  → How does authentication work?
  → How does authorization work?
  → What's the business logic flow?
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-help-circle
  label: "2. What is the ATTACK SURFACE?"
  ---
  Every input, endpoint, and interaction point is a potential vulnerability. Map **everything**.

  ```text
  Attack Surface Components:
  ─────────────────────────────────────────
  → URL parameters (?id=1, ?search=test)
  → POST body parameters (forms, JSON, XML)
  → HTTP headers (Host, Referer, X-Forwarded-For, User-Agent)
  → Cookies and session tokens
  → File upload functionality
  → API endpoints (REST, GraphQL, SOAP)
  → WebSocket connections
  → Email-based interactions
  → OAuth / SSO flows
  → Payment processing
  → Import/Export features (CSV, XML, PDF)
  → Forgotten/hidden endpoints
  → Mobile API endpoints
  → Admin panels and dashboards
  → Error pages and debug endpoints
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-help-circle
  label: "3. Where does USER INPUT go?"
  ---
  **Follow the data.** Trace every piece of user input from entry point to storage to display. This is where injection vulnerabilities live.

  ```text
  Input Flow:
  ─────────────────────────────────────────
  User Input → Frontend Validation (easily bypassed)
            → Backend Processing (parsing, sanitization?)
            → Database Query (SQL injection?)
            → File System (path traversal?)
            → Command Execution (command injection?)
            → HTML Rendering (XSS?)
            → Email System (header injection?)
            → Log Files (log injection?)
            → PDF/Report Generation (SSRF? injection?)
            → Third-party APIs (data forwarded unsanitized?)
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-help-circle
  label: "4. What TRUST BOUNDARIES exist?"
  ---
  Every point where the system transitions from one trust level to another is a potential vulnerability.

  ```text
  Trust Boundaries to Test:
  ─────────────────────────────────────────
  → Unauthenticated → Authenticated
  → Regular User → Admin
  → User A → User B (horizontal privilege)
  → Frontend → Backend
  → Application → Database
  → Application → Internal Services
  → Application → Third-party APIs
  → Public Network → Internal Network
  → Server → Cloud Metadata
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-help-circle
  label: "5. What happens when I BREAK the expected flow?"
  ---
  Developers build for the **happy path**. Bugs live in the **unhappy path**.

  ```text
  Things to try:
  ─────────────────────────────────────────
  → Skip steps in a multi-step process
  → Send requests out of order
  → Submit negative numbers, zero, huge numbers
  → Use special characters (', ", <, >, \, /, NULL)
  → Send empty values where values are expected
  → Send arrays where strings are expected (param[]=value)
  → Change HTTP method (GET→POST, POST→PUT)
  → Remove required parameters
  → Add unexpected parameters
  → Replay old requests with new session
  → Use expired tokens
  → Access API endpoints directly (skip frontend)
  → Change Content-Type (JSON→XML, form→JSON)
  → Race conditions (send same request 100 times simultaneously)
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-help-circle
  label: "6. What SENSITIVE DATA can I access?"
  ---
  The impact of a bug depends on what data it exposes. Always think about **what's at stake**.

  ```text
  High-Value Data:
  ─────────────────────────────────────────
  → User credentials (passwords, hashes, tokens)
  → Personal information (names, emails, addresses, phone)
  → Financial data (credit cards, bank accounts, transactions)
  → Health records (HIPAA-protected)
  → Session tokens / API keys
  → Internal system information
  → Source code
  → Database contents
  → Private messages / communications
  → Documents / files of other users
  → Admin functionality
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-help-circle
  label: "7. What did the developers ASSUME?"
  ---
  Every assumption is a potential vulnerability. **Challenge every assumption**.

  ```text
  Common Dangerous Assumptions:
  ─────────────────────────────────────────
  → "Users will only use our frontend" (API is directly accessible)
  → "This parameter is always a number" (no server-side validation)
  → "Only admins can reach this endpoint" (no auth check on backend)
  → "This field is hidden, so nobody will modify it" (hidden field tampering)
  → "Our CSRF token protects this" (but is it validated?)
  → "This function is only called internally" (but can be called externally)
  → "Rate limiting on frontend prevents abuse" (bypass via API)
  → "The user ID comes from the session" (but it's also in the request body)
  → "This file type is safe" (but is the content verified?)
  → "HTTPS means we're secure" (but the app logic is flawed)
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-help-circle
  label: "8. What's the BUSINESS LOGIC?"
  ---
  Business logic bugs are the **highest value** findings because **scanners can't find them**. Only a human who understands the application can.

  ```text
  Business Logic Bug Examples:
  ─────────────────────────────────────────
  → Apply discount code multiple times
  → Transfer negative money (receive instead of send)
  → Buy items with 0 or negative price
  → Skip payment step in checkout
  → Access premium features without subscription
  → Invite yourself as admin to another org
  → Manipulate vote/rating systems
  → Bypass KYC/verification by modifying workflow
  → Cancel order but keep the refund AND product
  → Race condition: use coupon twice simultaneously
  → Modify order after payment confirmation
  → Access features intended for different regions
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-help-circle
  label: "9. What's DIFFERENT about this target?"
  ---
  Don't follow the same script for every target. **Unique features = unique bugs**.

  ```text
  Questions for unique attack surface:
  ─────────────────────────────────────────
  → What features are UNIQUE to this application?
  → What's their CUSTOM code vs third-party?
  → What RECENTLY changed? (new features have more bugs)
  → What's their technology stack and what are ITS weaknesses?
  → Do they have a mobile app? (different API, different bugs)
  → Do they have integrations? (OAuth, webhooks, APIs)
  → What's their deployment model? (cloud, on-prem, hybrid)
  → What compliance requirements do they have? (PCI, HIPAA)
  → What do OTHER hunters keep finding? (read disclosed reports)
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-help-circle
  label: "10. What has EVERYONE ELSE already tried?"
  ---
  If you're testing the same things as everyone else, you'll only find duplicates. **Go deeper, go different.**

  ```text
  How to Find What Others Miss:
  ─────────────────────────────────────────
  → Test OLDER, forgotten subdomains and features
  → Test MOBILE APIs separately from web
  → Test with DIFFERENT user roles
  → Test COMBINATIONS of bugs (chain low-severity → critical)
  → Test during OFF-HOURS (maintenance modes, deployments)
  → Read JAVASCRIPT source code deeply
  → Test NEWLY launched features (fresh code = fresh bugs)
  → Look at ACQUISITIONS (merged code often has gaps)
  → Test EDGE CASES that require deep product knowledge
  → Focus on BUSINESS LOGIC (scanners can't find these)
  ```
  :::
::

---

## Bug Hunter Mindset

### The Success Formula

::callout
---
icon: i-lucide-zap
color: primary
---
**Success = Consistency × Curiosity × Patience × Knowledge**

Most beginners quit after 2 weeks of finding nothing. Top hunters hunted for **months** before their first valid finding. The difference is **persistence**.
::

### Mindset Principles

::card-group
  ::card
  ---
  icon: i-lucide-repeat
  title: "1. Embrace Failure"
  color: blue
  ---
  **90% of your submissions will be duplicates, informational, or invalid.** This is normal. Every "failure" teaches you something. Top hunters have hundreds of N/A reports behind their success.

  *"I have not failed. I've just found 10,000 ways that don't work."* — Thomas Edison
  ::

  ::card
  ---
  icon: i-lucide-clock
  title: "2. Be Patient"
  color: blue
  ---
  The best bugs come after **hours of understanding** the application, not minutes of scanning. Spend **70% of your time** on recon and understanding, **30%** on exploitation. Rushing leads to duplicates.
  ::

  ::card
  ---
  icon: i-lucide-book-open
  title: "3. Never Stop Learning"
  color: green
  ---
  New vulnerabilities, techniques, and bypasses emerge **daily**. Read writeups, follow researchers on Twitter/X, attend conferences, practice on labs. The moment you stop learning, you fall behind.
  ::

  ::card
  ---
  icon: i-lucide-target
  title: "4. Specialize First, Generalize Later"
  color: green
  ---
  Don't try to learn everything at once. **Master one vulnerability class** (e.g., XSS, IDOR, SSRF) deeply before moving to the next. Depth beats breadth for beginners.
  ::

  ::card
  ---
  icon: i-lucide-mountain
  title: "5. Hunt Where Others Don't"
  color: orange
  ---
  Everyone tests the login page and main website. **Go to the forgotten subdomain, the mobile API, the legacy feature, the PDF export function, the webhook endpoint.** That's where the gold is.
  ::

  ::card
  ---
  icon: i-lucide-link
  title: "6. Chain Low-Severity Bugs"
  color: orange
  ---
  A self-XSS alone is worthless. But **Self-XSS + Login CSRF = Account Takeover**. An open redirect alone is low. But **Open Redirect + OAuth = Token Theft**. Learn to **chain** bugs for maximum impact.
  ::

  ::card
  ---
  icon: i-lucide-pen-tool
  title: "7. Write Exceptional Reports"
  color: red
  ---
  A **great report** can turn a medium into a high bounty. A **bad report** can get a critical dismissed. Clear reproduction steps, impact analysis, and professional communication **multiply** your rewards.
  ::

  ::card
  ---
  icon: i-lucide-heart
  title: "8. Build Relationships"
  color: red
  ---
  Be **professional and respectful** with security teams. Thank them for their time. Accept triage decisions gracefully. Researchers who build good relationships get **invited to private programs** with higher bounties and less competition.
  ::
::

### The Bug Hunter's Daily Routine

::steps{level="4"}

#### Morning — Learn (1-2 hours)

```text
─────────────────────────────────────────
→ Read 2-3 bug bounty writeups (HackerOne Hacktivity, Medium, blogs)
→ Watch 1 YouTube tutorial or conference talk
→ Study one new technique or tool
→ Practice on CTF challenges or labs
→ Read changelogs/updates of your target programs
```

#### Afternoon — Hunt (3-5 hours)

```text
─────────────────────────────────────────
→ Pick ONE target (don't target-hop)
→ Spend first hour on recon and understanding
→ Map the attack surface thoroughly
→ Test methodically — don't random-spray
→ Take detailed notes of everything you find
→ Document interesting behaviors (even if not vuln yet)
```

#### Evening — Reflect & Report (1-2 hours)

```text
─────────────────────────────────────────
→ Write up any findings with clear PoC
→ Review your notes for missed angles
→ Plan tomorrow's hunting strategy
→ Engage with the community (Twitter, Discord, forums)
→ Update your methodology/cheat sheets
```

::

---

## Bug Bounty Ideas — Where to Find Bugs

::note
These are **proven areas** where experienced hunters consistently find vulnerabilities. Use this as a checklist and starting point.
::

### Top Vulnerability Ideas by Category

::tabs
  :::tabs-item{icon="i-lucide-key" label="Authentication & Session"}
  ```text
  ─── AUTHENTICATION BUGS ───
  ☐ Default credentials on admin panels
  ☐ Password reset poisoning (Host header injection)
  ☐ Password reset token leakage (Referer header, URL)
  ☐ Password reset token not expiring after use
  ☐ Password reset token brute-forceable (short/numeric)
  ☐ Login without verification (email, phone, 2FA bypass)
  ☐ 2FA bypass via backup codes, race condition, or direct API
  ☐ 2FA bypass by changing response from "false" to "true"
  ☐ Account lockout bypass via IP rotation or header manipulation
  ☐ OAuth misconfiguration (redirect_uri manipulation)
  ☐ OAuth token theft via open redirect
  ☐ SSO misconfiguration (SAML injection, signature bypass)
  ☐ JWT none algorithm / weak secret / key confusion
  ☐ Remember me token prediction/reuse
  ☐ Session fixation
  ☐ Session not invalidated after password change
  ☐ Session not invalidated after logout
  ☐ Concurrent session not limited
  ☐ Cookie without Secure/HttpOnly/SameSite flags
  ☐ Registration with existing email (case change, spaces, dots)
  ☐ Email verification bypass
  ☐ Phone verification bypass (voip, twilio)
  ```
  :::

  :::tabs-item{icon="i-lucide-shield-off" label="Authorization & Access Control"}
  ```text
  ─── IDOR (Insecure Direct Object Reference) ───
  ☐ Change user ID in URL/API to access other users' data
  ☐ Change object ID (invoice, order, message, file)
  ☐ IDOR in delete/update/export functions
  ☐ IDOR in API endpoints (different from web)
  ☐ IDOR via UUID enumeration (sequential? predictable?)
  ☐ IDOR via GraphQL node/id queries
  ☐ IDOR in file download (change filename/path)
  ☐ IDOR in mobile API (often less protected)

  ─── PRIVILEGE ESCALATION ───
  ☐ Horizontal: Access another user's resources
  ☐ Vertical: Regular user → Admin functions
  ☐ Change role parameter in request body (role=admin)
  ☐ Access admin API endpoints as regular user
  ☐ Modify hidden parameters (isAdmin=true, role=1)
  ☐ Access admin panel via direct URL
  ☐ Forced browsing to restricted endpoints
  ☐ Method-based access control bypass (GET vs POST)
  ☐ Parameter pollution for access control bypass
  ☐ Multi-tenancy access control bypass (org A → org B)
  ```
  :::

  :::tabs-item{icon="i-lucide-syringe" label="Injection Attacks"}
  ```text
  ─── SQL INJECTION ───
  ☐ Classic SQLi in search, filter, sort, ID parameters
  ☐ SQLi in login forms (auth bypass)
  ☐ SQLi in HTTP headers (X-Forwarded-For, Referer, User-Agent)
  ☐ SQLi in cookies
  ☐ Second-order SQLi (stored then executed later)
  ☐ SQLi in JSON/XML API bodies
  ☐ SQLi in order-by/sort parameters
  ☐ Blind SQLi (boolean and time-based)
  ☐ SQLi in import/export functions (CSV, XML)

  ─── XSS (Cross-Site Scripting) ───
  ☐ Reflected XSS in search, error messages, URL parameters
  ☐ Stored XSS in profile, comments, messages, filenames
  ☐ DOM-based XSS via fragment (#), postMessage, URL
  ☐ XSS in PDF/report generation
  ☐ XSS in email templates (HTML email injection)
  ☐ XSS via file upload (SVG, HTML files)
  ☐ XSS via filename/metadata
  ☐ XSS in markdown/rich text editors
  ☐ XSS in error pages (404, 500)
  ☐ XSS filter bypass (encoding, mutation, polyglots)

  ─── OTHER INJECTIONS ───
  ☐ Command injection (OS commands via user input)
  ☐ SSTI (Server-Side Template Injection)
  ☐ LDAP injection
  ☐ XML injection / XXE
  ☐ Header injection (CRLF → HTTP response splitting)
  ☐ Email header injection (CC, BCC injection)
  ☐ SSRF (Server-Side Request Forgery)
  ☐ CSS injection
  ☐ LaTeX injection
  ☐ GraphQL injection
  ```
  :::

  :::tabs-item{icon="i-lucide-lightbulb" label="Business Logic"}
  ```text
  ─── BUSINESS LOGIC BUGS ($$$ GOLDMINE $$$) ───
  ☐ Price manipulation (change price in request)
  ☐ Quantity manipulation (negative, zero, decimal)
  ☐ Currency confusion (pay in weak currency, receive in strong)
  ☐ Coupon/discount code abuse (reuse, stack, race condition)
  ☐ Free premium subscription (modify plan parameter)
  ☐ Trial extension (reset trial by email change)
  ☐ Referral system abuse (self-referral, infinite loop)
  ☐ Voting/rating manipulation (bypass limits)
  ☐ Skip steps in multi-step process (checkout, KYC)
  ☐ Cancel after refund processed (double refund)
  ☐ Transfer negative amount
  ☐ Mass assignment (add admin role via hidden param)
  ☐ Race condition in balance/inventory/votes
  ☐ Feature flag bypass
  ☐ Geo-restriction bypass
  ☐ Bypass rate limiting
  ☐ Abuse invite/share functionality
  ☐ Bypass account deletion (recover deleted account)
  ☐ Content access without payment
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="Recon-Based Findings"}
  ```text
  ─── RECONNAISSANCE FINDINGS ───
  ☐ Subdomain takeover (dangling CNAME)
  ☐ Exposed admin panels
  ☐ Exposed internal dashboards (Grafana, Kibana, Jenkins)
  ☐ Exposed .git/.svn/.env/.DS_Store
  ☐ Exposed debug/error pages with stack traces
  ☐ Exposed phpinfo()
  ☐ Exposed API documentation (Swagger, GraphQL Playground)
  ☐ Exposed source maps (.js.map files)
  ☐ Exposed backup files (.bak, .old, .sql, .zip)
  ☐ Exposed cloud storage (S3 bucket, Azure blob, GCS)
  ☐ Exposed credentials in JavaScript files
  ☐ Exposed API keys in client-side code
  ☐ Exposed internal IP addresses
  ☐ Exposed server version information
  ☐ Exposed .well-known/ configuration
  ☐ Directory listing enabled
  ☐ Outdated software with known CVEs
  ☐ CORS misconfiguration
  ☐ Missing security headers
  ☐ Open redirect
  ☐ HTTP request smuggling
  ☐ Clickjacking on sensitive pages
  ```
  :::
::

---

## The Bug Bounty Methodology

### Reconnaissance Workflow

::steps{level="4"}

#### Asset Discovery

```bash [Terminal]
# ─── SUBDOMAIN ENUMERATION ───
subfinder -d target.com -o subs.txt
amass enum -passive -d target.com -o amass.txt
assetfinder --subs-only target.com >> subs.txt
github-subdomains -d target.com -t TOKEN >> subs.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' >> subs.txt
cat subs.txt | sort -u > all_subs.txt

# ─── RESOLVE & PROBE ───
cat all_subs.txt | httpx -silent -status-code -title \
  -tech-detect -follow-redirects -o alive.txt

# ─── PORT SCANNING ───
naabu -l all_subs.txt -p - -silent -o ports.txt

# ─── SCREENSHOT ───
cat alive.txt | aquatone -out screenshots/
gowitness file -f alive.txt --screenshot-path screenshots/
```

#### Content Discovery

```bash [Terminal]
# ─── DIRECTORY BRUTE FORCE ───
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -k -t 50 -d 3 --smart

# ─── PARAMETER DISCOVERY ───
arjun -u https://target.com/endpoint -m GET,POST
paramspider -d target.com

# ─── JAVASCRIPT ANALYSIS ───
# Collect JS files
cat alive.txt | getJS --complete | sort -u > js_files.txt
# Extract endpoints from JS
cat js_files.txt | while read url; do
  curl -sk "$url" | grep -oE "(/[a-zA-Z0-9_\-/]+)" 
done | sort -u > js_endpoints.txt

# ─── WAYBACK MACHINE ───
waybackurls target.com | sort -u > wayback.txt
gau target.com | sort -u > gau.txt
```

#### Vulnerability Scanning

```bash [Terminal]
# ─── NUCLEI (Automated Scanning) ───
nuclei -l alive.txt -severity critical,high -o nuclei_critical.txt
nuclei -l alive.txt -tags cve,misconfig,exposure -o nuclei_all.txt

# ─── MANUAL TESTING (where the real bugs are) ───
# Open Burp Suite
# Browse every page, click every button
# Review Burp Sitemap
# Send interesting requests to Repeater
# Test each parameter manually
```

::

---

## Report Writing — The Art of Getting Paid

::warning
Your report is your **resume**. A poorly written report gets dismissed. A well-written report gets paid **more** and builds your reputation.
::

### Report Template

::code-collapse
```markdown [bug_bounty_report_template.md]
## Title
[Vulnerability Type] in [Feature/Endpoint] allows [Impact]

Example: "Stored XSS in User Profile Bio allows Account Takeover via Cookie Theft"

## Severity
Critical / High / Medium / Low

## Affected Asset
- URL: https://target.com/api/v1/user/profile
- Parameter: `bio`
- Endpoint: POST /api/v1/user/profile

## Description
A clear, concise explanation of the vulnerability in 2-3 sentences.
What it is, where it exists, and why it's dangerous.

## Steps to Reproduce
1. Log in to the application at https://target.com/login
2. Navigate to Profile Settings (https://target.com/settings/profile)
3. In the "Bio" field, enter the following payload:
   ```bash
   <img src=x onerror=alert(document.cookie)>
   ```
4. Click "Save Profile"
5. Visit the public profile page: https://target.com/user/attacker
6. Observe that the JavaScript executes, displaying the session cookie

## Proof of Concept
[Screenshots showing each step]
[Video recording of exploitation]
[curl command to reproduce]

```bash
curl -X POST 'https://target.com/api/v1/user/profile' \
  -H 'Cookie: session=abc123' \
  -H 'Content-Type: application/json' \
  -d '{"bio":"<img src=x onerror=alert(document.cookie)>"}'
```

## Impact
An attacker can:
1. Steal session cookies of any user who views the attacker's profile
2. Perform actions as the victim (account takeover)
3. Access private data of the victim
4. Modify the victim's account settings

This affects ALL users who visit the attacker's profile page.

## Remediation
1. Implement output encoding for all user-supplied content
2. Use Content-Security-Policy headers to mitigate XSS impact
3. Set HttpOnly flag on session cookies to prevent JavaScript access
4. Sanitize HTML input using a library like DOMPurify

## References
- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
```
::

### Report Do's and Don'ts

::card-group
  ::card
  ---
  icon: i-lucide-check
  title: "DO ✅"
  color: green
  ---
  - Write **clear, numbered** reproduction steps
  - Include **screenshots and/or video** PoC
  - Explain the **real-world impact**
  - Provide a **curl command** for quick reproduction
  - Suggest **remediation**
  - Be **professional and respectful**
  - **Test your own steps** before submitting
  - Respond promptly to triage questions
  ::

  ::card
  ---
  icon: i-lucide-x
  title: "DON'T ❌"
  color: red
  ---
  - Don't submit **scanner output** as a report
  - Don't write vague descriptions like "XSS found"
  - Don't exaggerate severity
  - Don't test on **production data** without permission
  - Don't submit **informational** findings as critical
  - Don't argue aggressively with triage team
  - Don't disclose publicly before resolution
  - Don't submit **duplicate** without checking Hacktivity
  ::
::

---

## Top Bug Bounty YouTube Channels

::note
These channels provide **free, high-quality** education from experienced bug hunters and security researchers. Subscribe to all of them.
::

### Tier 1 — Essential Channels (Must Subscribe)

::card-group
  ::card
  ---
  icon: i-simple-icons-youtube
  title: "NahamSec"
  to: https://youtube.com/@NahamSec
  target: _blank
  color: red
  ---
  **Ben Sadeghipour** — One of the most respected bug bounty educators. Former HackerOne employee, full-time bug hunter.

  - 🎯 **Best For:** Recon methodology, live hacking, beginner-friendly
  - 📺 **Key Series:** "Recon Streams", "Bug Bounty for Beginners", interviews with top hackers
  - 💰 **Earnings Shared:** $2M+ in bounties
  - 👥 **Subscribers:** 500K+
  - ⭐ **Must Watch:** "How to Get Started in Bug Bounties", "Recon Methodology"
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "STÖK"
  to: https://youtube.com/@STOKfredrik
  target: _blank
  color: red
  ---
  **Fredrik Alexandersson** — Swedish hacker with cinematic production quality. Makes bug bounty feel exciting and accessible.

  - 🎯 **Best For:** Motivation, methodology, hacker culture, tools
  - 📺 **Key Series:** "Bug Bounty Tips", "Hacker Tools", "Conference Talks"
  - 💰 **Style:** High-energy, visual, beginner-to-intermediate
  - 👥 **Subscribers:** 300K+
  - ⭐ **Must Watch:** "Bug Bounty Hunting Tips" series, "How I Hack"
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "InsiderPhD"
  to: https://youtube.com/@InsiderPhD
  target: _blank
  color: red
  ---
  **Katie Paxton-Fear** — PhD researcher and Bugcrowd Ambassador. One of the best educators for **absolute beginners**.

  - 🎯 **Best For:** Complete beginners, structured learning, academia meets hacking
  - 📺 **Key Series:** "Bug Bounty for Beginners", "Finding Your First Bug", "API Hacking"
  - 💰 **Style:** Calm, methodical, step-by-step
  - 👥 **Subscribers:** 200K+
  - ⭐ **Must Watch:** "How to Get Into Bug Bounties" playlist, "API Testing"
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "LiveOverflow"
  to: https://youtube.com/@LiveOverflow
  target: _blank
  color: red
  ---
  **LiveOverflow** — Deep technical content on hacking, CTF, and security research. More technical than most channels.

  - 🎯 **Best For:** Deep technical understanding, binary exploitation, web hacking theory
  - 📺 **Key Series:** "Web Hacking", "Browser Exploitation", "CTF Solutions"
  - 💰 **Style:** Technical, educational, whiteboard explanations
  - 👥 **Subscribers:** 800K+
  - ⭐ **Must Watch:** "How do Websites Get Hacked?" series, "XSS Explained"
  ::
::

### Tier 2 — Advanced & Specialized Channels

::card-group
  ::card
  ---
  icon: i-simple-icons-youtube
  title: "John Hammond"
  to: https://youtube.com/@_JohnHammond
  target: _blank
  color: orange
  ---
  **John Hammond** — Security researcher at Huntress. Prolific content creator covering CTFs, malware analysis, and bug bounty.

  - 🎯 **Best For:** CTF walkthroughs, malware analysis, diverse security topics
  - 📺 **Key Content:** CTF solutions, HackTheBox, TryHackMe, tool tutorials
  - 👥 **Subscribers:** 1.5M+
  - ⭐ **Must Watch:** "Hacking" playlist, "Capture The Flag" series
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "IppSec"
  to: https://youtube.com/@ippsec
  target: _blank
  color: orange
  ---
  **IppSec** — The **gold standard** for HackTheBox walkthroughs. Incredibly detailed, methodical approach to every machine.

  - 🎯 **Best For:** Penetration testing methodology, HackTheBox machines, deep technical skills
  - 📺 **Key Content:** HackTheBox walkthroughs, technique explanations
  - 👥 **Subscribers:** 700K+
  - ⭐ **Must Watch:** Any HackTheBox walkthrough matching your skill level
  - 🔧 **Pro Tip:** Use [ippsec.rocks](https://ippsec.rocks) to search for specific techniques across all videos
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "PwnFunction"
  to: https://youtube.com/@PwnFunction
  target: _blank
  color: orange
  ---
  **PwnFunction** — Beautifully animated explanations of web security concepts. Makes complex topics **visually intuitive**.

  - 🎯 **Best For:** Understanding vulnerability concepts deeply, visual learners
  - 📺 **Key Content:** XSS, CSRF, SSRF, CORS — all explained with animations
  - 👥 **Subscribers:** 300K+
  - ⭐ **Must Watch:** "Cross-Site Scripting Explained", "SSRF Explained"
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "Farah Hawa"
  to: https://youtube.com/@FarahHawa
  target: _blank
  color: orange
  ---
  **Farah Hawa** — Bug bounty hunter sharing real-world methodologies and findings with a focus on **practical techniques**.

  - 🎯 **Best For:** Practical bug hunting, real-world techniques, IDOR/access control
  - 📺 **Key Content:** Live hacking, vulnerability walkthroughs, methodology
  - 👥 **Subscribers:** 100K+
  - ⭐ **Must Watch:** "How I Find IDORs", "Bug Bounty Methodology"
  ::
::

### Tier 3 — Additional Valuable Channels

::card-group
  ::card
  ---
  icon: i-simple-icons-youtube
  title: "The Cyber Mentor (TCM)"
  to: https://youtube.com/@TCMSecurityAcademy
  target: _blank
  ---
  **Heath Adams** — CEO of TCM Security. Extensive free courses on ethical hacking, web app testing, and penetration testing. Created the PNPT certification.

  - 🎯 **Best For:** Structured courses, penetration testing, certification prep
  - 👥 **Subscribers:** 1M+
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "HackerSploit"
  to: https://youtube.com/@HackerSploit
  target: _blank
  ---
  **Alexis Ahmed** — Comprehensive tutorials on penetration testing tools, Linux security, and web application security. Very beginner-friendly.

  - 🎯 **Best For:** Tool tutorials, Linux security, structured learning paths
  - 👥 **Subscribers:** 800K+
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "Rana Khalil"
  to: https://youtube.com/@RanaKhalil101
  target: _blank
  ---
  **Rana Khalil** — Complete PortSwigger Web Security Academy walkthroughs. If you want to master **Burp Suite and web hacking**, this is your channel.

  - 🎯 **Best For:** PortSwigger labs, Burp Suite mastery, web app security
  - 👥 **Subscribers:** 150K+
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "Reconless"
  to: https://youtube.com/@reconless
  target: _blank
  ---
  **Reconless** — Focus on bug bounty automation, reconnaissance, and tooling. Great for efficiency-focused hunters.

  - 🎯 **Best For:** Automation, tooling, recon pipelines
  - 👥 **Subscribers:** 50K+
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "Hacking Simplified"
  to: https://youtube.com/@HackingSimplified
  target: _blank
  ---
  **Hacking Simplified** — Clear, concise tutorials on web vulnerabilities, tools, and bug bounty techniques.

  - 🎯 **Best For:** Quick, focused technique tutorials
  - 👥 **Subscribers:** 100K+
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "David Bombal"
  to: https://youtube.com/@davidbombal
  target: _blank
  ---
  **David Bombal** — Networking expert who covers hacking, security certifications, and interviews with industry professionals.

  - 🎯 **Best For:** Networking security, certifications, interviews
  - 👥 **Subscribers:** 2.5M+
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "Elevate Cyber"
  to: https://youtube.com/@yourfavhackerr
  target: _blank
  ---
  **Justin Gardner (rhynorater)** — Elite bug hunter sharing advanced techniques and critical thinking frameworks for finding high-severity bugs. Co-hosts Critical Thinking podcast.

  - 🎯 **Best For:** Advanced techniques, critical thinking, high-severity bugs
  - 👥 **Subscribers:** 30K+
  ::

  ::card
  ---
  icon: i-simple-icons-youtube
  title: "Bug Bounty Reports Explained"
  to: https://youtube.com/@BugBountyReportsExplained
  target: _blank
  ---
  **BBRE** — Analyzes real, disclosed bug bounty reports and explains the techniques used. Learn from real findings.

  - 🎯 **Best For:** Learning from real bugs, understanding report quality
  - 👥 **Subscribers:** 50K+
  ::
::

---

## Learning Resources & Platforms

### Free Practice Platforms

::card-group
  ::card
  ---
  icon: i-lucide-flask-conical
  title: "PortSwigger Web Security Academy"
  to: https://portswigger.net/web-security
  target: _blank
  ---
  **THE best** free resource for learning web security. 200+ labs covering every web vulnerability class. Created by the makers of Burp Suite. **Start here.**
  ::

  ::card
  ---
  icon: i-lucide-server
  title: "TryHackMe"
  to: https://tryhackme.com
  target: _blank
  ---
  Guided, gamified learning paths for beginners. Browser-based labs — no setup needed. Free tier available. Paths: "Web Fundamentals", "Jr Penetration Tester", "Bug Bounty Hunter."
  ::

  ::card
  ---
  icon: i-lucide-terminal
  title: "HackTheBox"
  to: https://hackthebox.com
  target: _blank
  ---
  More challenging than TryHackMe. Realistic machines and web challenges. Great for building real-world skills. Free tier with retired machines.
  ::

  ::card
  ---
  icon: i-lucide-bug
  title: "PentesterLab"
  to: https://pentesterlab.com
  target: _blank
  ---
  Progressive exercises from basic to advanced. Excellent for learning specific vulnerability classes step by step. Mix of free and paid content.
  ::

  ::card
  ---
  icon: i-lucide-code
  title: "OWASP WebGoat"
  to: https://owasp.org/www-project-webgoat/
  target: _blank
  ---
  Deliberately insecure application for learning web security. Self-hosted. Covers OWASP Top 10 with interactive lessons.
  ::

  ::card
  ---
  icon: i-lucide-trophy
  title: "CTFtime"
  to: https://ctftime.org
  target: _blank
  ---
  Calendar of Capture The Flag competitions worldwide. Great for sharpening skills competitively. Filter by "web" category for bug bounty relevant challenges.
  ::
::

### Essential Reading

::card-group
  ::card
  ---
  icon: i-lucide-book-open
  title: "Web Hacking 101 (Peter Yaworski)"
  to: https://leanpub.com/web-hacking-101
  target: _blank
  ---
  **The** book for bug bounty beginners. Real-world bug bounty reports explained. Learn from actual findings on HackerOne programs.
  ::

  ::card
  ---
  icon: i-lucide-book-open
  title: "The Web Application Hacker's Handbook"
  to: https://www.amazon.com/Web-Application-Hackers-Handbook-Exploiting/dp/1118026470
  target: _blank
  ---
  The **bible** of web application security. Comprehensive, deep, and authoritative. By the creators of Burp Suite.
  ::

  ::card
  ---
  icon: i-lucide-book-open
  title: "Bug Bounty Bootcamp (Vickie Li)"
  to: https://nostarch.com/bug-bounty-bootcamp
  target: _blank
  ---
  Modern, practical guide to bug bounty hunting. Covers recon, vulnerability types, and report writing. Excellent for intermediates.
  ::

  ::card
  ---
  icon: i-lucide-book-open
  title: "Real-World Bug Hunting (Peter Yaworski)"
  to: https://nostarch.com/bughunting
  target: _blank
  ---
  Field guide to finding web vulnerabilities. Based on real bug bounty reports. Great case studies for each vulnerability type.
  ::
::

### Blogs & Writeups

::card-group
  ::card
  ---
  icon: i-lucide-newspaper
  title: "HackerOne Hacktivity"
  to: https://hackerone.com/hacktivity
  target: _blank
  ---
  Real disclosed bug bounty reports from HackerOne programs. **Read at least 2-3 reports daily.** Filter by severity and program.
  ::

  ::card
  ---
  icon: i-lucide-newspaper
  title: "PortSwigger Research Blog"
  to: https://portswigger.net/research
  target: _blank
  ---
  Cutting-edge web security research from the Burp Suite team. Advanced techniques that lead to critical findings.
  ::

  ::card
  ---
  icon: i-lucide-newspaper
  title: "Medium Bug Bounty Writeups"
  to: https://medium.com/tag/bug-bounty
  target: _blank
  ---
  Community writeups from hunters worldwide. Search for specific vulnerability types or programs.
  ::

  ::card
  ---
  icon: i-lucide-newspaper
  title: "Pentester Land Writeups"
  to: https://pentester.land/writeups/
  target: _blank
  ---
  Curated list of **the best** bug bounty writeups organized by vulnerability type. Updated regularly.
  ::
::

### Community & Networking

::card-group
  ::card
  ---
  icon: i-simple-icons-x
  title: "Twitter / X — #BugBounty"
  to: https://twitter.com/search?q=%23bugbounty
  target: _blank
  ---
  The **primary** social platform for bug bounty hunters. Follow top hunters, security researchers, and program announcements. Use hashtags: `#bugbounty`, `#infosec`, `#bugbountytips`.
  ::

  ::card
  ---
  icon: i-simple-icons-discord
  title: "Bug Bounty Discord Servers"
  to: https://discord.gg/bugbounty
  target: _blank
  ---
  Active communities for bug bounty discussion, collaboration, and mentorship. Servers: **NahamSec**, **Bugcrowd**, **HackerOne**, **InsiderPhD**.
  ::

  ::card
  ---
  icon: i-simple-icons-reddit
  title: "r/bugbounty"
  to: https://reddit.com/r/bugbounty
  target: _blank
  ---
  Reddit community for bug bounty discussion, questions, tips, and writeup sharing.
  ::

  ::card
  ---
  icon: i-lucide-podcast
  title: "Critical Thinking Podcast"
  to: https://www.criticalthinkingpodcast.io/
  target: _blank
  ---
  **Justin Gardner & Joel Margolis** — Deep discussions on bug bounty methodology, mindset, and advanced techniques. Essential listening.
  ::
::

---

## People to Follow

::note
These are **active, respected** bug bounty hunters and security researchers who share knowledge publicly. Follow them on **Twitter/X** for daily insights.
::

::collapsible

| Hunter | Twitter/X | Known For |
|--------|-----------|-----------|
| **@NahamSec** | [@NahamSec](https://twitter.com/NahamSec) | Recon methodology, education, community building |
| **@staborttrap** | [@staborttrap](https://twitter.com/staborttrap) | STÖK — Motivation, methodology, visual content |
| **@InsiderPhD** | [@InsiderPhD](https://twitter.com/InsiderPhD) | Beginner education, API hacking, academic research |
| **@Jhaddix** | [@Jhaddix](https://twitter.com/Jhaddix) | Recon king, content discovery, tooling |
| **@toaborttrap** | [@toaborttrap](https://twitter.com/toaborttrap) | Deep web hacking research |
| **@albinowax** | [@albinowax](https://twitter.com/albinowax) | PortSwigger research, HTTP smuggling, deserialization |
| **@samwcyo** | [@samwcyo](https://twitter.com/samwcyo) | Sam Curry — massive critical findings, automotive hacking |
| **@rhynorater** | [@rhynorater](https://twitter.com/rhynorater) | Justin Gardner — advanced methodology, Critical Thinking podcast |
| **@rez0__** | [@rez0__](https://twitter.com/rez0__) | API hacking, deep technical research |
| **@0xdea** | [@0xdea](https://twitter.com/0xdea) | Exploit development, advanced techniques |
| **@Bugcrowd** | [@Bugcrowd](https://twitter.com/Bugcrowd) | Platform updates, researcher highlights |
| **@HackerOne** | [@HackerOne](https://twitter.com/HackerOne) | Platform updates, disclosed reports |
| **@pdiscoveryio** | [@pdaborttrap](https://twitter.com/pdiscoveryio) | ProjectDiscovery — Nuclei, httpx, subfinder |
| **@TomNomNom** | [@TomNomNom](https://twitter.com/TomNomNom) | Tool creator (gf, waybackurls, httprobe) |
| **@haaborttrap** | [@haborttrap](https://twitter.com/haaborttrap) | Hacker mindset, community |
| **@faborttrap** | [@faborttrap](https://twitter.com/faborttrap) | Farah Hawa — IDORs, access control, real-world techniques |
| **@infosec_au** | [@infosec_au](https://twitter.com/infosec_au) | Australian bug hunter, large bounties, recon |
| **@zaborttrap** | [@zaborttrap](https://twitter.com/zaborttrap) | Automation, tooling, efficiency |

::

---

## Common Mistakes & How to Avoid Them

::card-group
  ::card
  ---
  icon: i-lucide-alert-triangle
  title: "Mistake: Relying Only on Automation"
  color: red
  ---
  **Problem:** Running Nuclei/Burp Scanner and submitting findings without understanding them.

  **Fix:** Use automation for **recon** only. Manual testing is where real bugs are found. Understand every vulnerability you submit.
  ::

  ::card
  ---
  icon: i-lucide-alert-triangle
  title: "Mistake: Target Hopping"
  color: red
  ---
  **Problem:** Spending 30 minutes on a target, finding nothing, and switching to another. Repeat 10 times daily.

  **Fix:** Pick **ONE** target and commit to it for **at least 1-2 weeks**. Deep knowledge of a single target beats shallow knowledge of 20.
  ::

  ::card
  ---
  icon: i-lucide-alert-triangle
  title: "Mistake: Ignoring the Scope"
  color: red
  ---
  **Problem:** Testing out-of-scope assets, using prohibited techniques, causing disruption.

  **Fix:** **Read the program policy CAREFULLY** before testing. Violating scope can get you **banned** from the platform and potentially face legal action.
  ::

  ::card
  ---
  icon: i-lucide-alert-triangle
  title: "Mistake: Poor Report Quality"
  color: red
  ---
  **Problem:** Vague descriptions, no PoC, no impact assessment, automated scanner output copy-pasted.

  **Fix:** Follow the report template above. Include **clear steps**, **screenshots**, **curl commands**, and **impact analysis**. A great report = higher bounty.
  ::

  ::card
  ---
  icon: i-lucide-alert-triangle
  title: "Mistake: Comparing to Others"
  color: orange
  ---
  **Problem:** "That person earned $100K in 6 months, I've found nothing in 2 weeks. I should quit."

  **Fix:** Everyone's journey is different. Those top hunters **started exactly where you are**. Focus on **your own progress**, not others' highlight reels.
  ::

  ::card
  ---
  icon: i-lucide-alert-triangle
  title: "Mistake: Skipping Fundamentals"
  color: orange
  ---
  **Problem:** Trying advanced techniques (deserialization, race conditions) before understanding HTTP, cookies, sessions, and basic web architecture.

  **Fix:** **Master the basics first.** Understand how the web works at a fundamental level. Then layer advanced techniques on top.
  ::
::

---

## The 30-Day Bug Bounty Kickstart Plan

::tip
Follow this structured plan to go from **zero to first valid finding** in 30 days.
::

::steps{level="4"}

#### Week 1 — Foundations (Learn)

```text
Day 1-2: Understand HTTP, DNS, web architecture
  → Watch: NahamSec "Bug Bounty for Beginners"
  → Read: How the Web Works (MDN Web Docs)
  → Practice: Burp Suite setup, intercept requests

Day 3-4: Learn OWASP Top 10 vulnerabilities
  → Watch: PwnFunction vulnerability explainer videos
  → Read: OWASP Top 10 documentation
  → Practice: PortSwigger Academy (SQL Injection labs)

Day 5-7: Master one vulnerability deeply (XSS recommended)
  → Complete ALL PortSwigger XSS labs
  → Watch: Rana Khalil XSS walkthrough series
  → Read: 10 XSS bug bounty writeups on HackerOne Hacktivity
```

#### Week 2 — Tools & Recon (Setup)

```text
Day 8-9: Set up your toolkit
  → Install: Burp Suite, Firefox + FoxyProxy
  → Install: subfinder, httpx, nuclei, ffuf, feroxbuster
  → Configure: Burp extensions (Autorize, ActiveScan++)

Day 10-11: Learn reconnaissance methodology
  → Watch: NahamSec Recon Streams
  → Practice: Subdomain enumeration on a practice target
  → Build: Your own recon automation script

Day 12-14: Study real bug bounty reports
  → Read: 20+ disclosed reports on HackerOne Hacktivity
  → Analyze: What techniques did they use?
  → Note: What did the hunter know that led to the find?
```

#### Week 3 — Practice Hunting (Apply)

```text
Day 15-17: Practice on intentionally vulnerable apps
  → Complete: OWASP Juice Shop challenges
  → Complete: More PortSwigger labs (IDOR, CSRF, SSRF)
  → Complete: TryHackMe "Bug Bounty Hunter" path

Day 18-21: Pick your FIRST real target
  → Choose: A program on HackerOne/Bugcrowd with wide scope
  → Read: Program scope and rules carefully
  → Recon: Enumerate subdomains, directories, technologies
  → Map: Full attack surface
  → Test: Apply what you learned on real target
```

#### Week 4 — Hunt for Real (Execute)

```text
Day 22-25: Deep-dive on your chosen target
  → Spend 3-4 hours daily testing
  → Focus on one vulnerability class at a time
  → Take detailed notes on everything interesting
  → Don't rush — understand the application

Day 26-28: Expand your testing
  → Try different vulnerability classes
  → Test API endpoints separately from web UI
  → Check mobile app API (if in scope)
  → Look at forgotten/old features

Day 29-30: Report and reflect
  → Write up any findings with professional reports
  → Review what you learned
  → Plan your next month's targets and goals
  → Celebrate your progress (even without a bounty!)
```

::

---

## Final Words — The Hunter's Creed

::callout
---
icon: i-lucide-flame
color: primary
---

**"The best bug hunters aren't the ones with the most tools — they're the ones with the most curiosity."**

Bug bounty isn't a sprint. It's a marathon. There will be weeks of duplicates, frustration, and self-doubt. But every "N/A" report teaches you something. Every hour of recon sharpens your instincts. Every writeup you read adds to your mental library of patterns.

The hunter who **persists, learns daily, and stays curious** will eventually find that Critical vulnerability that changes everything.

**Start today. Stay consistent. Trust the process.**

::

---

::caution
**Legal & Ethical Reminder:** Only test systems you have **explicit authorization** to test — through a bug bounty program, a signed agreement, or your own systems. **Unauthorized testing is illegal.** Always follow the program's Rules of Engagement, respect scope boundaries, and practice **responsible disclosure**.
::